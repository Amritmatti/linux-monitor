// ---------------------------------------------------------------------------
// HTTP layer: authentication, the user-scoped JSON API, server-sent events and
// the static dashboard.
//
// Every API handler below receives an authenticated `user` and passes
// `user.id` into the data layer. There is no admin route, no impersonation and
// no cross-user read: the scope of a request is the identity that made it.
// ---------------------------------------------------------------------------

import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { waitForDatabase, migrate, close as closeDb } from './db/pool.mjs';
import { verifyKeyAvailable } from './crypto/secrets.mjs';
import * as auth from './auth/users.mjs';
import * as repo from './repo/servers.mjs';
import * as store from './store.mjs';
import { LIMITED_REASONS, LIMITED_FIX } from './ssh/probe.mjs';
import { RISKY_PORTS, THRESHOLDS } from './engine/checks.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(__dirname, '..', 'web');
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const COOKIE = 'vg_session';
const ALLOW_SIGNUP = process.env.VG_ALLOW_SIGNUP !== 'off';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.png': 'image/png',
};

/* -------------------------------------------------------------------------- */
/* plumbing                                                                    */
/* -------------------------------------------------------------------------- */

function sendJson(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      // Generous, because a pasted RSA-4096 key with a comment block is a few
      // kilobytes and nobody should hit a limit doing the normal thing.
      if (size > 512 * 1024) {
        reject(new Error('payload too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('invalid json'));
      }
    });
    req.on('error', reject);
  });
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function sessionCookie(token, maxAgeSeconds) {
  const secure = process.env.VG_SECURE_COOKIES === 'true';
  return (
    COOKIE + '=' + encodeURIComponent(token) +
    '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + maxAgeSeconds +
    (secure ? '; Secure' : '')
  );
}

function clearCookie() {
  return COOKIE + '=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0';
}

/** Same-origin check for mutating requests; SameSite=Lax plus this closes CSRF. */
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // same-origin fetches and curl send no Origin
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || null;
}

const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(s ?? ''));

/* -------------------------------------------------------------------------- */
/* serialisers                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * The limitations of a scan, expanded into something actionable.
 *
 * The product deliberately runs unprivileged, so limitations are the normal
 * case rather than an error - but a dashboard that quietly shows less than it
 * claims is worse than one that says what it cannot see.
 */
function explainLimited(limited = [], username = '<user>') {
  return limited.map((key) => ({
    key,
    reason: LIMITED_REASONS[key] ?? key,
    sudoers: LIMITED_FIX[key] ? LIMITED_FIX[key].replace('<user>', username) : null,
  }));
}

function serverOut(s) {
  return {
    id: s.id,
    name: s.name,
    host: s.host,
    port: s.port,
    username: s.username,
    tags: s.tags ?? [],
    status: s.status,
    lastError: s.last_error,
    lastScanAt: s.last_scan_at,
    createdAt: s.created_at,
    hostKeyFp: s.host_key_fp,
    hasPassphrase: s.has_passphrase,
    // Present for the fleet view; absent on a bare record.
    ...(s.summary !== undefined
      ? {
          scannedAt: s.scannedAt,
          scanOk: s.scanOk,
          scanError: s.scanError,
          critical: s.critical,
          warning: s.warning,
          info: s.info,
          summary: s.summary,
          limited: explainLimited(s.limited, s.username),
        }
      : {}),
  };
}

/* -------------------------------------------------------------------------- */
/* auth routes                                                                 */
/* -------------------------------------------------------------------------- */

async function handleAuth(req, res, url, user) {
  const path = url.pathname;

  if (path === '/api/auth/me' && req.method === 'GET') {
    if (!user) return sendJson(res, 401, { error: 'unauthenticated' });
    return sendJson(res, 200, { user: { id: user.id, email: user.email, name: user.name }, allowSignup: ALLOW_SIGNUP });
  }

  if (path === '/api/auth/signup' && req.method === 'POST') {
    if (!ALLOW_SIGNUP) return sendJson(res, 403, { error: 'signup_closed', message: 'Sign-up is closed on this instance.' });
    const body = await readBody(req);
    const emailBad = auth.emailProblem(body.email);
    if (emailBad) return sendJson(res, 400, { error: 'invalid_email', message: emailBad });
    const passwordBad = auth.passwordProblem(body.password);
    if (passwordBad) return sendJson(res, 400, { error: 'weak_password', message: passwordBad });
    if (!String(body.name ?? '').trim()) return sendJson(res, 400, { error: 'invalid_name', message: 'Enter your name' });

    if (await auth.findUserByEmail(body.email)) {
      return sendJson(res, 409, { error: 'email_taken', message: 'An account already exists for that email address.' });
    }

    const created = await auth.createUser({ email: body.email, name: body.name, password: body.password });
    const session = await auth.createSession(created.id, { ip: clientIp(req), userAgent: req.headers['user-agent'] });
    return sendJson(res, 201, { user: { id: created.id, email: created.email, name: created.name } }, {
      'set-cookie': sessionCookie(session.token, Math.floor((session.expires - Date.now()) / 1000)),
    });
  }

  if (path === '/api/auth/login' && req.method === 'POST') {
    const body = await readBody(req);
    const found = await auth.findUserByEmail(body.email ?? '');
    // The same answer and roughly the same work whether the address exists or
    // not, so this endpoint does not enumerate accounts.
    const ok = found && !found.disabled && (await auth.verifyPassword(String(body.password ?? ''), found.password_hash));
    if (!ok) {
      if (!found) await auth.hashPassword('timing-equaliser');
      return sendJson(res, 401, { error: 'invalid_credentials', message: 'That email and password do not match.' });
    }
    const session = await auth.createSession(found.id, { ip: clientIp(req), userAgent: req.headers['user-agent'] });
    await auth.audit(found.id, found.email, 'login', 'Signed in from ' + (clientIp(req) ?? 'unknown'));
    return sendJson(res, 200, { user: { id: found.id, email: found.email, name: found.name } }, {
      'set-cookie': sessionCookie(session.token, Math.floor((session.expires - Date.now()) / 1000)),
    });
  }

  if (path === '/api/auth/logout' && req.method === 'POST') {
    await auth.destroySession(parseCookies(req.headers.cookie)[COOKIE]);
    return sendJson(res, 200, { ok: true }, { 'set-cookie': clearCookie() });
  }

  if (path === '/api/auth/password' && req.method === 'POST') {
    if (!user) return sendJson(res, 401, { error: 'unauthenticated' });
    const body = await readBody(req);
    const found = await auth.findUserByEmail(user.email);
    if (!found || !(await auth.verifyPassword(String(body.currentPassword ?? ''), found.password_hash))) {
      return sendJson(res, 403, { error: 'wrong_password', message: 'Your current password is not correct.' });
    }
    const bad = auth.passwordProblem(body.newPassword);
    if (bad) return sendJson(res, 400, { error: 'weak_password', message: bad });
    await auth.changePassword(user.id, body.newPassword);
    // Every other session is invalidated, which is the point of changing it.
    await auth.destroyAllSessions(user.id);
    const session = await auth.createSession(user.id, { ip: clientIp(req), userAgent: req.headers['user-agent'] });
    await auth.audit(user.id, user.email, 'password-changed', 'Password changed; all other sessions signed out');
    return sendJson(res, 200, { ok: true }, { 'set-cookie': sessionCookie(session.token, Math.floor((session.expires - Date.now()) / 1000)) });
  }

  return false;
}

/* -------------------------------------------------------------------------- */
/* server routes                                                               */
/* -------------------------------------------------------------------------- */

/** Shared validation for create and update. */
function validateServer(body, { requireKey }) {
  const checks = [
    ['invalid_name', repo.nameProblem(body.name)],
    ['invalid_host', repo.hostProblem(body.host)],
    ['invalid_username', repo.usernameProblem(body.username)],
  ];
  for (const [error, message] of checks) if (message) return { error, message };

  const port = body.port === undefined || body.port === '' ? 22 : Number(body.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { error: 'invalid_port', message: 'The SSH port must be a number between 1 and 65535' };
  }

  if (requireKey || body.privateKey) {
    const keyBad = repo.keyProblem(body.privateKey, body.passphrase);
    if (keyBad) return { error: 'invalid_key', message: keyBad };
  }
  return null;
}

async function handleServers(req, res, url, user) {
  const path = url.pathname;
  const parts = path.split('/').filter(Boolean); // api, servers, :id, action

  if (path === '/api/servers' && req.method === 'GET') {
    const rows = await repo.listServers(user.id);
    return sendJson(res, 200, { items: rows.map(serverOut) });
  }

  if (path === '/api/servers' && req.method === 'POST') {
    const body = await readBody(req);
    const bad = validateServer(body, { requireKey: true });
    if (bad) return sendJson(res, 400, bad);

    const existing = (await repo.listServers(user.id)).find((s) => s.name.toLowerCase() === String(body.name).trim().toLowerCase());
    if (existing) return sendJson(res, 409, { error: 'name_taken', message: 'You already have a server called "' + body.name + '".' });

    const created = await repo.createServer(user.id, {
      name: body.name,
      host: body.host,
      port: body.port || 22,
      username: body.username,
      privateKey: body.privateKey,
      passphrase: body.passphrase,
      tags: Array.isArray(body.tags) ? body.tags.slice(0, 12).map(String) : [],
    });
    await auth.audit(user.id, user.email, 'server-added', body.name + ' (' + body.username + '@' + body.host + ')', { serverId: created.id });

    // The public half, so the UI can show exactly what to append to
    // authorized_keys if the login is not working yet.
    const publicKey = repo.publicKeyFor(body.privateKey, body.passphrase);
    return sendJson(res, 201, { server: serverOut(created), publicKey });
  }

  if (parts[1] !== 'servers' || !isUuid(parts[2])) return false;
  const id = parts[2];
  const action = parts[3];

  if (!action && req.method === 'GET') {
    const detail = await store.serverDetail(user.id, id);
    if (!detail) return sendJson(res, 404, { error: 'not_found' });
    return sendJson(res, 200, {
      ...detail,
      server: serverOut(detail.server),
      limited: explainLimited(detail.scan?.limited ?? [], detail.server.username),
    });
  }

  if (!action && req.method === 'PATCH') {
    const existing = await repo.getServer(user.id, id);
    if (!existing) return sendJson(res, 404, { error: 'not_found' });
    const body = await readBody(req);
    // Validated against the merged record, so a patch that changes only the
    // port is still checked against the name and host already stored.
    const bad = validateServer({ ...existing, ...body }, { requireKey: false });
    if (bad) return sendJson(res, 400, bad);
    const updated = await repo.updateServer(user.id, id, body);
    await auth.audit(user.id, user.email, 'server-updated', updated.name, { serverId: id, fields: Object.keys(body) });
    return sendJson(res, 200, { server: serverOut(updated) });
  }

  if (!action && req.method === 'DELETE') {
    const server = await repo.getServer(user.id, id);
    if (!server) return sendJson(res, 404, { error: 'not_found' });
    await repo.deleteServer(user.id, id);
    await auth.audit(user.id, user.email, 'server-removed', server.name + ' (' + server.host + ')', { serverId: id });
    return sendJson(res, 200, { ok: true });
  }

  if (action === 'scan' && req.method === 'POST') {
    const result = await store.scanServer(user.id, id, { actor: user.email });
    if (result.error === 'not_found') return sendJson(res, 404, { error: 'not_found' });
    const server = await repo.getServer(user.id, id);
    return sendJson(res, result.ok ? 200 : 502, {
      ok: result.ok,
      error: result.error ?? null,
      findings: result.findings ?? [],
      anomalies: result.anomalies ?? [],
      limited: explainLimited(result.limited ?? [], server?.username),
      durationMs: result.durationMs,
      server: server ? serverOut(server) : null,
    });
  }

  // Re-pinning is deliberately a separate, audited action rather than something
  // the scanner does when it notices a change.
  if (action === 'reset-host-key' && req.method === 'POST') {
    const server = await repo.getServer(user.id, id);
    if (!server) return sendJson(res, 404, { error: 'not_found' });
    await repo.updateServer(user.id, id, { resetHostKey: true });
    await auth.audit(user.id, user.email, 'host-key-reset', server.name + ' (' + server.host + '): pinned key cleared, will re-pin on next scan', {
      serverId: id,
      previous: server.host_key_fp,
    });
    return sendJson(res, 200, { ok: true });
  }

  if (action === 'ack' && req.method === 'POST') {
    const body = await readBody(req);
    if (!body.key) return sendJson(res, 400, { error: 'missing_key', message: 'Which finding?' });
    await store.acknowledge(user.id, id, String(body.key), {
      reason: body.reason ? String(body.reason).slice(0, 500) : null,
      value: Number(body.value),
      actor: user.email,
    });
    return sendJson(res, 200, { ok: true });
  }

  if (action === 'ack' && req.method === 'DELETE') {
    const key = url.searchParams.get('key');
    if (!key) return sendJson(res, 400, { error: 'missing_key' });
    await store.unacknowledge(user.id, id, key);
    return sendJson(res, 200, { ok: true });
  }

  return false;
}

/* -------------------------------------------------------------------------- */
/* fleet routes                                                                */
/* -------------------------------------------------------------------------- */

function matchesFilters(item, url) {
  const severity = url.searchParams.get('severity');
  const category = url.searchParams.get('category');
  const server = url.searchParams.get('server');
  const q = (url.searchParams.get('q') ?? '').toLowerCase().trim();
  const showAcked = url.searchParams.get('acked') === 'true';

  if (!showAcked && item.acked) return false;
  if (severity && item.severity !== severity) return false;
  if (category && item.category !== category) return false;
  if (server && item.serverId !== server) return false;
  if (q && !(item.title + ' ' + item.detail + ' ' + item.serverName).toLowerCase().includes(q)) return false;
  return true;
}

function facets(items, key) {
  const counts = new Map();
  for (const i of items) counts.set(i[key], (counts.get(i[key]) ?? 0) + 1);
  return [...counts.entries()].map(([k, count]) => ({ key: k, count })).sort((a, b) => b.count - a.count);
}

async function handleFleet(req, res, url, user) {
  const path = url.pathname;

  if (path === '/api/fleet' && req.method === 'GET') {
    const { servers, totals } = await store.fleet(user.id);
    return sendJson(res, 200, { servers: servers.map(serverOut), totals });
  }

  if (path === '/api/issues' && req.method === 'GET') {
    const { findings, anomalies } = await store.fleet(user.id);
    // One list. A disk that will be full on Thursday and a disk that is full
    // now belong on the same page, sorted by how much they matter - splitting
    // them by which engine produced them is an implementation detail nobody
    // triaging an estate cares about.
    const all = [...findings, ...anomalies];
    const items = all.filter((i) => matchesFilters(i, url));
    return sendJson(res, 200, {
      items,
      total: items.length,
      facets: {
        severity: facets(all.filter((i) => !i.acked), 'severity'),
        category: facets(all.filter((i) => !i.acked), 'category'),
        server: facets(all.filter((i) => !i.acked), 'serverName'),
      },
    });
  }

  if (path === '/api/anomalies' && req.method === 'GET') {
    const { anomalies } = await store.fleet(user.id);
    const items = anomalies.filter((i) => matchesFilters(i, url));
    return sendJson(res, 200, { items, total: items.length });
  }

  if (path === '/api/ports' && req.method === 'GET') {
    const inv = await store.inventory(user.id);
    const items = [];
    for (const entry of inv) {
      for (const p of entry.facts.ports ?? []) {
        const risky = RISKY_PORTS[p.port];
        items.push({
          serverId: entry.serverId,
          serverName: entry.serverName,
          serverHost: entry.serverHost,
          observedAt: entry.observedAt,
          ...p,
          risky: Boolean(risky && p.exposed),
          service: risky?.name ?? null,
          why: risky?.why ?? null,
          processVisible: Boolean(p.process),
        });
      }
    }
    items.sort((a, b) => Number(b.risky) - Number(a.risky) || Number(b.exposed) - Number(a.exposed) || a.port - b.port || a.serverName.localeCompare(b.serverName));
    return sendJson(res, 200, {
      items,
      totals: {
        listening: items.length,
        exposed: items.filter((i) => i.exposed).length,
        risky: items.filter((i) => i.risky).length,
        unnamed: items.filter((i) => !i.processVisible).length,
      },
    });
  }

  if (path === '/api/updates' && req.method === 'GET') {
    const inv = await store.inventory(user.id);
    const items = inv
      .filter((e) => e.facts.updates)
      .map((e) => ({
        serverId: e.serverId,
        serverName: e.serverName,
        serverHost: e.serverHost,
        observedAt: e.observedAt,
        manager: e.facts.updates.manager,
        total: e.facts.updates.total,
        security: e.facts.updates.security,
        securityPackages: e.facts.updates.securityPackages ?? [],
        packages: e.facts.updates.packages ?? [],
        truncated: e.facts.updates.truncated,
        listsAgeSeconds: e.facts.updates.listsAgeSeconds,
        securityKnown: e.facts.updates.securityKnown !== false,
        rebootRequired: e.facts.reboot?.required ?? false,
        rebootPackages: e.facts.reboot?.packages ?? [],
        runningKernel: e.facts.reboot?.runningKernel ?? null,
        latestKernel: e.facts.reboot?.latestKernel ?? null,
        kernelStale: e.facts.reboot?.kernelStale ?? false,
        os: e.facts.host?.os?.name ?? null,
      }));
    items.sort((a, b) => b.security - a.security || b.total - a.total || a.serverName.localeCompare(b.serverName));
    // Servers with no package manager we can read are reported separately
    // rather than counted as zero.
    const unknown = inv.filter((e) => !e.facts.updates).map((e) => ({ serverId: e.serverId, serverName: e.serverName }));
    return sendJson(res, 200, {
      items,
      unknown,
      totals: {
        security: items.reduce((a, i) => a + i.security, 0),
        total: items.reduce((a, i) => a + i.total, 0),
        reboots: items.filter((i) => i.rebootRequired).length,
        staleLists: items.filter((i) => Number.isFinite(i.listsAgeSeconds) && i.listsAgeSeconds > THRESHOLDS.packageListStaleDays * 86400).length,
      },
    });
  }

  if (path === '/api/disks' && req.method === 'GET') {
    const inv = await store.inventory(user.id);
    const items = [];
    for (const entry of inv) {
      for (const d of entry.facts.disks ?? []) {
        items.push({
          serverId: entry.serverId,
          serverName: entry.serverName,
          serverHost: entry.serverHost,
          observedAt: entry.observedAt,
          ...d,
        });
      }
    }
    items.sort((a, b) => (b.usedPct ?? 0) - (a.usedPct ?? 0) || a.serverName.localeCompare(b.serverName));
    return sendJson(res, 200, {
      items,
      totals: {
        filesystems: items.length,
        critical: items.filter((i) => i.usedPct >= THRESHOLDS.diskCritical).length,
        warning: items.filter((i) => i.usedPct >= THRESHOLDS.diskWarning && i.usedPct < THRESHOLDS.diskCritical).length,
        totalBytes: items.reduce((a, i) => a + (i.totalBytes ?? 0), 0),
        usedBytes: items.reduce((a, i) => a + (i.usedBytes ?? 0), 0),
      },
    });
  }

  if (path === '/api/scan' && req.method === 'POST') {
    // Deliberately not awaited: a fleet sweep can take minutes, and the browser
    // follows it on the event stream rather than holding a request open.
    store.scanAll(user.id, { actor: user.email }).catch((err) => console.error('[scan] sweep failed:', err.message));
    return sendJson(res, 202, { ok: true });
  }

  return false;
}

/* -------------------------------------------------------------------------- */
/* events                                                                      */
/* -------------------------------------------------------------------------- */

function handleEvents(req, res, user) {
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  });
  res.write('retry: 3000\n\n');

  const onEvent = (evt) => {
    // The bus is process-wide; a subscriber only ever sees its own events.
    if (evt.userId !== user.id) return;
    res.write('event: ' + evt.type + '\n');
    res.write('data: ' + JSON.stringify({ payload: evt.payload, at: evt.at }) + '\n\n');
  };

  store.events.on('event', onEvent);
  const keepAlive = setInterval(() => res.write(': keep-alive\n\n'), 25000);

  req.on('close', () => {
    clearInterval(keepAlive);
    store.events.off('event', onEvent);
  });
}

/* -------------------------------------------------------------------------- */
/* static                                                                      */
/* -------------------------------------------------------------------------- */

async function serveStatic(req, res, url) {
  let rel = decodeURIComponent(url.pathname);
  if (rel === '/') rel = '/index.html';
  if (rel === '/login') rel = '/login.html';

  const full = join(WEB_ROOT, normalize(rel));
  // normalize() collapses .., and this confirms the result is still inside the
  // web root - the two together are what stop /../../etc/passwd.
  if (!full.startsWith(WEB_ROOT)) {
    res.writeHead(403).end('Forbidden');
    return;
  }

  try {
    const info = await stat(full);
    if (!info.isFile()) throw new Error('not a file');
    const body = await readFile(full);
    res.writeHead(200, {
      'content-type': MIME[extname(full)] ?? 'application/octet-stream',
      'content-length': body.length,
      'cache-control': extname(full) === '.html' ? 'no-cache' : 'public, max-age=300',
    });
    res.end(body);
  } catch {
    // Unknown paths fall through to the SPA so deep links work on reload.
    if (!extname(rel)) {
      const shell = await readFile(join(WEB_ROOT, 'index.html'));
      res.writeHead(200, { 'content-type': MIME['.html'], 'content-length': shell.length, 'cache-control': 'no-cache' });
      res.end(shell);
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' }).end('Not found');
  }
}

/* -------------------------------------------------------------------------- */
/* router                                                                      */
/* -------------------------------------------------------------------------- */

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host ?? 'localhost'));

  try {
    if (url.pathname === '/api/health') {
      return sendJson(res, 200, { ok: true, at: new Date().toISOString() });
    }

    if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url);

    if (req.method !== 'GET' && !originAllowed(req)) {
      return sendJson(res, 403, { error: 'bad_origin', message: 'Cross-site request rejected.' });
    }

    const token = parseCookies(req.headers.cookie)[COOKIE];
    const user = await auth.resolveSession(token);

    const authHandled = await handleAuth(req, res, url, user);
    if (authHandled !== false) return;

    if (!user) return sendJson(res, 401, { error: 'unauthenticated' });

    if (url.pathname === '/api/events' && req.method === 'GET') return handleEvents(req, res, user);

    const serversHandled = await handleServers(req, res, url, user);
    if (serversHandled !== false) return;

    const fleetHandled = await handleFleet(req, res, url, user);
    if (fleetHandled !== false) return;

    return sendJson(res, 404, { error: 'not_found' });
  } catch (err) {
    if (err.message === 'invalid json' || err.message === 'payload too large') {
      return sendJson(res, 400, { error: 'bad_request', message: err.message });
    }
    console.error('[http] ' + req.method + ' ' + url.pathname + ':', err);
    if (!res.headersSent) sendJson(res, 500, { error: 'internal', message: 'Something went wrong handling that request.' });
  }
});

/* -------------------------------------------------------------------------- */
/* boot                                                                        */
/* -------------------------------------------------------------------------- */

async function boot() {
  await waitForDatabase();
  await migrate();
  // Fails loudly at boot rather than on the first server anyone adds.
  verifyKeyAvailable();

  await auth.purgeExpiredSessions();
  setInterval(() => auth.purgeExpiredSessions().catch(() => {}), 3600000).unref();

  store.startScheduler();

  server.listen(PORT, HOST, () => {
    console.log('[vigil] listening on http://' + HOST + ':' + PORT);
    if (!ALLOW_SIGNUP) console.log('[vigil] sign-up is closed (VG_ALLOW_SIGNUP=off)');
  });
}

async function shutdown(signal) {
  console.log('[vigil] ' + signal + ', shutting down');
  store.stopScheduler();
  server.close();
  await closeDb().catch(() => {});
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

boot().catch((err) => {
  console.error('[vigil] failed to start:', err);
  process.exit(1);
});
