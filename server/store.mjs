// ---------------------------------------------------------------------------
// Orchestration and aggregation.
//
// Scanning: fan out across a user's servers with a concurrency cap, persist one
// scan row each, and never let one unreachable host affect another. A scan that
// fails is recorded as a failed scan - it does not overwrite the last good
// picture with an empty one, because "we could not reach it" and "it has no
// listening ports any more" must never look the same on the dashboard.
//
// Reading: findings and anomalies are recomputed from stored facts on the way
// out, so improving a rule improves every historical scan rather than leaving
// the estate showing whatever the rules said last Tuesday.
// ---------------------------------------------------------------------------

import { EventEmitter } from 'node:events';
import { one, many, query } from './db/pool.mjs';
import * as repo from './repo/servers.mjs';
import { collect } from './ssh/probe.mjs';
import { evaluate, SEVERITY_RANK } from './engine/checks.mjs';
import { detect } from './engine/anomalies.mjs';
import { audit } from './auth/users.mjs';
import { prune as runPrune } from './ssh/prune.mjs';

export const events = new EventEmitter();
// One listener per connected browser tab; a fleet dashboard left open on a wall
// display plus a few laptops is normal and must not print a leak warning.
events.setMaxListeners(0);

/** How many hosts to hold connections to at once. */
const SCAN_CONCURRENCY = Number(process.env.VG_SCAN_CONCURRENCY || 8);
/** Scans kept per server. At 15-minute intervals this is a bit over three weeks. */
const SCAN_RETENTION = Number(process.env.VG_SCAN_RETENTION || 2000);
/** How much history the anomaly engine gets. */
const HISTORY_WINDOW = 40;

function emit(userId, type, payload = {}) {
  events.emit('event', { userId, type, payload, at: new Date().toISOString() });
}

/* -------------------------------------------------------------------- scanning */

/**
 * Scan one server: connect, collect, evaluate, store.
 *
 * Never throws for a host-level problem. An unreachable server is a fact about
 * the estate, not an error in the scanner, and a fleet sweep must not abort
 * halfway because one box is off.
 */
export async function scanServer(userId, serverId, { actor = 'scheduler' } = {}) {
  const server = await repo.getServer(userId, serverId);
  if (!server) return { error: 'not_found' };

  const startedAt = new Date();
  const creds = await repo.credentialsFor(userId, serverId);
  if (!creds?.privateKey) {
    await repo.recordScanResult(userId, serverId, { ok: false, error: 'No usable private key is stored for this server' });
    return { ok: false, error: 'No usable private key is stored for this server' };
  }

  let facts = null;
  let limited = [];
  let hostKeyFp = null;
  let error = null;
  let durationMs = 0;

  try {
    const result = await collect(creds);
    facts = result.facts;
    limited = result.limited;
    hostKeyFp = result.hostKeyFp;
    durationMs = result.durationMs;
  } catch (err) {
    error = err.message + (err.hint ? ' ' + err.hint : '');
    hostKeyFp = err.hostKeyFp ?? null;
    durationMs = Date.now() - startedAt.getTime();
    // A changed host key is a security event, not a connectivity blip, so it
    // goes in the append-only log whether or not anyone is watching the UI.
    if (err.code === 'HostKeyChanged') {
      await audit(userId, actor, 'host-key-changed', server.name + ' (' + server.host + '): ' + err.message, { serverId, fingerprint: err.hostKeyFp });
    }
  }

  let findings = [];
  let anomalies = [];
  if (facts) {
    findings = evaluate(facts);
    const history = await historyFacts(userId, serverId, HISTORY_WINDOW);
    anomalies = detect(facts, history);
  }

  const scan = await one(
    `INSERT INTO scans (server_id, user_id, started_at, finished_at, ok, error, duration_ms, facts, findings, anomalies, limited)
     VALUES ($1, $2, $3, now(), $4, $5, $6, $7, $8, $9, $10)
     RETURNING id, started_at, finished_at, ok, error, duration_ms`,
    [
      serverId,
      userId,
      startedAt,
      !error,
      error,
      durationMs,
      facts ? JSON.stringify(facts) : null,
      JSON.stringify(findings),
      JSON.stringify(anomalies),
      limited,
    ]
  );

  await repo.recordScanResult(userId, serverId, { ok: !error, error, hostKeyFp });
  await pruneScans(serverId);

  emit(userId, 'scan-finished', { serverId, ok: !error, findings: findings.length, anomalies: anomalies.length });
  return { ok: !error, error, scanId: scan.id, findings, anomalies, limited, facts, durationMs };
}

/** Scan every enabled server for a user, at most SCAN_CONCURRENCY at a time. */
export async function scanAll(userId, { actor = 'scheduler' } = {}) {
  const servers = (await repo.listServers(userId)).filter((s) => s.status !== 'disabled');
  if (!servers.length) return { scanned: 0, failed: 0 };

  emit(userId, 'scan-started', { total: servers.length });

  let index = 0;
  let failed = 0;
  const worker = async () => {
    while (index < servers.length) {
      const server = servers[index++];
      emit(userId, 'scan-progress', { serverId: server.id, name: server.name, done: index, total: servers.length });
      const res = await scanServer(userId, server.id, { actor });
      if (!res.ok) failed++;
    }
  };

  await Promise.all(Array.from({ length: Math.min(SCAN_CONCURRENCY, servers.length) }, worker));
  emit(userId, 'scan-complete', { scanned: servers.length, failed });
  return { scanned: servers.length, failed };
}

async function pruneScans(serverId) {
  await query(
    `DELETE FROM scans WHERE server_id = $1 AND id NOT IN (
       SELECT id FROM scans WHERE server_id = $1 ORDER BY started_at DESC LIMIT $2
     )`,
    [serverId, SCAN_RETENTION]
  );
}

/* --------------------------------------------------------------------- reading */

/** The most recent scan per server, successful or not. */
export function latestScans(userId) {
  return many(
    `SELECT DISTINCT ON (s.server_id) s.id, s.server_id, s.started_at, s.finished_at, s.ok, s.error,
            s.duration_ms, s.facts, s.findings, s.anomalies, s.limited
       FROM scans s
      WHERE s.user_id = $1
   ORDER BY s.server_id, s.started_at DESC`,
    [userId]
  );
}

export function latestScan(userId, serverId) {
  return one(
    `SELECT id, server_id, started_at, finished_at, ok, error, duration_ms, facts, findings, anomalies, limited
       FROM scans WHERE user_id = $1 AND server_id = $2 ORDER BY started_at DESC LIMIT 1`,
    [userId, serverId]
  );
}

/**
 * The most recent scan that actually succeeded.
 *
 * The dashboard shows this rather than the newest scan, so a host that went
 * offline an hour ago still displays what it looked like, clearly labelled as
 * stale, instead of collapsing to an empty card.
 */
export function lastGoodScan(userId, serverId) {
  return one(
    `SELECT id, started_at, facts, findings, anomalies, limited
       FROM scans WHERE user_id = $1 AND server_id = $2 AND ok ORDER BY started_at DESC LIMIT 1`,
    [userId, serverId]
  );
}

export function scanHistory(userId, serverId, limit = 100) {
  return many(
    `SELECT id, started_at, ok, error, duration_ms, findings, anomalies
       FROM scans WHERE user_id = $1 AND server_id = $2 ORDER BY started_at DESC LIMIT $3`,
    [userId, serverId, limit]
  );
}

/** Facts only, oldest first - the shape engine/anomalies.mjs expects. */
async function historyFacts(userId, serverId, limit) {
  const rows = await many(
    `SELECT started_at, facts FROM scans
      WHERE user_id = $1 AND server_id = $2 AND ok AND facts IS NOT NULL
      ORDER BY started_at DESC LIMIT $3`,
    [userId, serverId, limit]
  );
  return rows.reverse().map((r) => ({ startedAt: r.started_at, facts: r.facts }));
}

/** Metric series for the server detail charts. */
export async function timeseries(userId, serverId, limit = 200) {
  const rows = await historyFacts(userId, serverId, limit);
  return rows.map((r) => ({
    at: r.startedAt,
    load: r.facts?.cpu?.load15 ?? null,
    loadPerCore: r.facts?.cpu?.loadPerCore ?? null,
    memoryPct: r.facts?.memory?.usedPct ?? null,
    swapPct: r.facts?.memory?.swapUsedPct ?? null,
    ports: r.facts?.ports?.length ?? null,
    updates: r.facts?.updates?.total ?? null,
    security: r.facts?.updates?.security ?? null,
    disks: (r.facts?.disks ?? []).map((d) => ({ mount: d.mount, usedPct: d.usedPct })),
  }));
}

/* -------------------------------------------------------- acknowledgements */

export async function listAcks(userId) {
  const rows = await many(
    'SELECT server_id, finding_key, reason, value_at_ack, actor, acked_at FROM finding_acks WHERE user_id = $1',
    [userId]
  );
  const byServer = new Map();
  for (const r of rows) {
    if (!byServer.has(r.server_id)) byServer.set(r.server_id, new Map());
    byServer.get(r.server_id).set(r.finding_key, r);
  }
  return byServer;
}

export async function acknowledge(userId, serverId, findingKey, { reason, value, actor }) {
  await query(
    `INSERT INTO finding_acks (user_id, server_id, finding_key, reason, value_at_ack, actor)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (server_id, finding_key)
     DO UPDATE SET reason = EXCLUDED.reason, value_at_ack = EXCLUDED.value_at_ack, actor = EXCLUDED.actor, acked_at = now()`,
    [userId, serverId, findingKey, reason ?? null, Number.isFinite(value) ? value : null, actor]
  );
  emit(userId, 'ack-changed', { serverId, findingKey, acked: true });
}

export async function unacknowledge(userId, serverId, findingKey) {
  await query('DELETE FROM finding_acks WHERE user_id = $1 AND server_id = $2 AND finding_key = $3', [userId, serverId, findingKey]);
  emit(userId, 'ack-changed', { serverId, findingKey, acked: false });
}

/**
 * Has an acknowledged finding got materially worse than what was accepted?
 *
 * This is what makes an acknowledgement different from a mute. Someone accepts
 * a disk at 82%; at 91% it is a different problem and it comes back. Without
 * this, the first acknowledgement of a slowly-worsening condition would be the
 * last anyone ever heard of it.
 */
function ackStillHolds(ack, finding) {
  if (!ack) return false;
  if (!Number.isFinite(ack.value_at_ack) || !Number.isFinite(finding.value)) return true;
  const before = ack.value_at_ack;
  const now = finding.value;
  if (now <= before) return true;
  const growth = before === 0 ? Infinity : (now - before) / Math.abs(before);
  return growth < 0.1 && now - before < 8;
}

/* ------------------------------------------------------------------ dashboard */

/**
 * Everything the fleet view needs, in one query pass.
 *
 * @returns {Promise<{servers, findings, anomalies, totals}>}
 */
export async function fleet(userId) {
  const [servers, scans, acks] = await Promise.all([repo.listServers(userId), latestScans(userId), listAcks(userId)]);
  const scanByServer = new Map(scans.map((s) => [s.server_id, s]));

  const findings = [];
  const anomalies = [];
  const rows = [];

  for (const server of servers) {
    const scan = scanByServer.get(server.id);
    const serverAcks = acks.get(server.id) ?? new Map();

    const decorate = (item, list, kind) => {
      const ack = serverAcks.get(item.key);
      const acked = ackStillHolds(ack, item);
      list.push({
        ...item,
        kind,
        serverId: server.id,
        serverName: server.name,
        serverHost: server.host,
        observedAt: scan?.started_at ?? null,
        acked,
        ackReason: acked ? ack.reason : null,
        ackedBy: acked ? ack.actor : null,
        // An acknowledged finding that has since got worse comes back with the
        // history attached, so nobody has to wonder why it reappeared.
        reopenedFrom: ack && !acked ? ack.value_at_ack : null,
      });
    };

    for (const f of scan?.findings ?? []) decorate(f, findings, 'finding');
    for (const a of scan?.anomalies ?? []) decorate(a, anomalies, 'anomaly');

    const live = [...(scan?.findings ?? []), ...(scan?.anomalies ?? [])].filter((f) => !ackStillHolds(serverAcks.get(f.key), f));
    const facts = scan?.facts ?? null;

    rows.push({
      ...server,
      scannedAt: scan?.started_at ?? null,
      scanOk: scan?.ok ?? null,
      scanError: scan?.error ?? null,
      limited: scan?.limited ?? [],
      critical: live.filter((f) => f.severity === 'critical').length,
      warning: live.filter((f) => f.severity === 'warning').length,
      info: live.filter((f) => f.severity === 'info').length,
      // A compact summary so the fleet table can show the numbers people scan
      // for without shipping every fact for every host.
      summary: facts
        ? {
            os: facts.host?.os?.name ?? null,
            kernel: facts.host?.kernel ?? null,
            uptimeSeconds: facts.host?.uptimeSeconds ?? null,
            cores: facts.cpu?.cores ?? null,
            loadPerCore: facts.cpu?.loadPerCore ?? null,
            memoryPct: facts.memory?.usedPct ?? null,
            maxDiskPct: (facts.disks ?? []).reduce((a, d) => Math.max(a, d.usedPct ?? 0), 0) || null,
            diskCount: (facts.disks ?? []).length,
            ports: (facts.ports ?? []).length,
            exposedPorts: (facts.ports ?? []).filter((p) => p.exposed).length,
            updates: facts.updates?.total ?? null,
            security: facts.updates?.security ?? null,
            rebootRequired: facts.reboot?.required ?? false,
            failedUnits: (facts.services?.failed ?? []).length,
          }
        : null,
    });
  }

  const open = [...findings, ...anomalies].filter((f) => !f.acked);
  const withFacts = rows.filter((r) => r.summary);

  const totals = {
    servers: rows.length,
    healthy: rows.filter((r) => r.status === 'healthy').length,
    unreachable: rows.filter((r) => r.status === 'error').length,
    neverScanned: rows.filter((r) => !r.scannedAt).length,
    critical: open.filter((f) => f.severity === 'critical').length,
    warning: open.filter((f) => f.severity === 'warning').length,
    info: open.filter((f) => f.severity === 'info').length,
    acknowledged: [...findings, ...anomalies].filter((f) => f.acked).length,
    securityUpdates: withFacts.reduce((a, r) => a + (r.summary.security ?? 0), 0),
    pendingUpdates: withFacts.reduce((a, r) => a + (r.summary.updates ?? 0), 0),
    rebootsRequired: withFacts.filter((r) => r.summary.rebootRequired).length,
    exposedPorts: withFacts.reduce((a, r) => a + (r.summary.exposedPorts ?? 0), 0),
    failedUnits: withFacts.reduce((a, r) => a + (r.summary.failedUnits ?? 0), 0),
    disksAtRisk: open.filter((f) => f.category === 'Disk').length,
  };

  const bySeverity = (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || String(a.serverName).localeCompare(b.serverName);
  findings.sort(bySeverity);
  anomalies.sort(bySeverity);

  return { servers: rows, findings, anomalies, totals };
}

/** Everything for one server's detail page. */
export async function serverDetail(userId, serverId) {
  const server = await repo.getServer(userId, serverId);
  if (!server) return null;

  const [scan, lastGood, history, series, acks] = await Promise.all([
    latestScan(userId, serverId),
    lastGoodScan(userId, serverId),
    scanHistory(userId, serverId, 50),
    timeseries(userId, serverId, 200),
    listAcks(userId),
  ]);

  const serverAcks = acks.get(serverId) ?? new Map();
  const source = scan?.ok ? scan : lastGood;

  const mark = (item, kind) => {
    const ack = serverAcks.get(item.key);
    const acked = ackStillHolds(ack, item);
    return { ...item, kind, acked, ackReason: acked ? ack.reason : null, ackedBy: acked ? ack.actor : null };
  };

  return {
    server,
    scan: scan
      ? { id: scan.id, startedAt: scan.started_at, ok: scan.ok, error: scan.error, durationMs: scan.duration_ms, limited: scan.limited }
      : null,
    // Explicitly flagged so the UI can say "last seen 40 minutes ago" instead of
    // presenting stale facts as current.
    stale: Boolean(scan && !scan.ok && lastGood),
    factsFrom: source?.started_at ?? null,
    facts: source?.facts ?? null,
    findings: (source?.findings ?? []).map((f) => mark(f, 'finding')),
    anomalies: (source?.anomalies ?? []).map((a) => mark(a, 'anomaly')),
    history: history.map((h) => ({
      id: h.id,
      startedAt: h.started_at,
      ok: h.ok,
      error: h.error,
      durationMs: h.duration_ms,
      critical: (h.findings ?? []).filter((f) => f.severity === 'critical').length + (h.anomalies ?? []).filter((f) => f.severity === 'critical').length,
      warning: (h.findings ?? []).filter((f) => f.severity === 'warning').length + (h.anomalies ?? []).filter((f) => f.severity === 'warning').length,
    })),
    series,
  };
}

/**
 * Latest known facts per server, with the server metadata attached.
 *
 * Uses the last SUCCESSFUL scan rather than the last scan, so the ports, disks
 * and updates pages still describe a host that has since gone unreachable -
 * flagged stale, not silently dropped. A server that has never been scanned
 * successfully is absent, which is the honest answer for it.
 */
export async function inventory(userId) {
  const rows = await many(
    `SELECT DISTINCT ON (s.server_id)
            s.server_id, s.started_at, s.facts, s.limited,
            v.name, v.host, v.status
       FROM scans s
       JOIN servers v ON v.id = s.server_id
      WHERE s.user_id = $1 AND s.ok AND s.facts IS NOT NULL
   ORDER BY s.server_id, s.started_at DESC`,
    [userId]
  );
  return rows.map((r) => ({
    serverId: r.server_id,
    serverName: r.name,
    serverHost: r.host,
    status: r.status,
    observedAt: r.started_at,
    limited: r.limited ?? [],
    facts: r.facts,
  }));
}

/**
 * Run one allowlisted Docker cleanup against a server, then immediately
 * re-scan it.
 *
 * The re-scan is the point: without it the dashboard would keep showing the
 * space it just freed, and the person would have no way to tell whether the
 * cleanup did anything. It also means the audit trail has a before and an
 * after.
 */
export async function pruneDocker(userId, serverId, actionKey, { actor }) {
  const server = await repo.getServer(userId, serverId);
  if (!server) return { ok: false, error: 'not_found' };

  const before = (await lastGoodScan(userId, serverId))?.facts?.docker?.reclaimableBytes ?? null;
  const creds = await repo.credentialsFor(userId, serverId);
  if (!creds?.privateKey) return { ok: false, error: 'no_key', message: 'No usable private key is stored for this server' };

  const result = await runPrune(creds, actionKey).catch((err) => ({ ok: false, error: 'ssh_failed', message: err.message }));

  await audit(
    userId,
    actor,
    result.ok ? 'docker-prune' : 'docker-prune-failed',
    server.name + ' (' + server.host + '): ' + actionKey + (result.reclaimed ? ' reclaimed ' + result.reclaimed : '') + (result.message ? ' - ' + result.message : ''),
    { serverId, action: actionKey, command: result.command ?? null, reclaimed: result.reclaimed ?? null }
  );

  if (result.ok) await scanServer(userId, serverId, { actor });
  const after = (await lastGoodScan(userId, serverId))?.facts?.docker?.reclaimableBytes ?? null;

  emit(userId, 'docker-pruned', { serverId, action: actionKey, ok: result.ok });
  return { ...result, beforeBytes: before, afterBytes: after };
}

/* ------------------------------------------------------------------ scheduler */

let timer = null;

/**
 * Periodic sweep of every user's estate.
 *
 * Runs users in sequence rather than in parallel: the concurrency cap that
 * matters is on outbound SSH connections, and running ten users at once would
 * multiply it by ten.
 */
export function startScheduler({ minutes = Number(process.env.VG_SCAN_MINUTES || 15) } = {}) {
  if (timer) clearInterval(timer);
  if (!minutes || minutes <= 0) {
    console.log('[scan] scheduler disabled (VG_SCAN_MINUTES=0)');
    return;
  }

  const sweep = async () => {
    try {
      const users = await many('SELECT DISTINCT user_id FROM servers WHERE status <> $1', ['disabled']);
      for (const u of users) {
        try {
          await scanAll(u.user_id, { actor: 'scheduler' });
        } catch (err) {
          console.error('[scan] sweep failed for user ' + u.user_id + ':', err.message);
        }
      }
    } catch (err) {
      console.error('[scan] sweep failed:', err.message);
    }
  };

  timer = setInterval(sweep, minutes * 60000);
  console.log('[scan] scheduler running every ' + minutes + ' minutes');
  // A first sweep shortly after boot, so a restarted container does not leave
  // the dashboard blank for a quarter of an hour.
  setTimeout(sweep, 15000).unref?.();
}

export function stopScheduler() {
  if (timer) clearInterval(timer);
  timer = null;
}
