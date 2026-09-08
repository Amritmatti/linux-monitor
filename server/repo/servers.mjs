// ---------------------------------------------------------------------------
// Server records.
//
// Every function here takes a userId and puts it in the WHERE clause. There is
// deliberately no getServer(id) without one: the ownership check is not a layer
// above these queries that could be forgotten at one call site, it is the
// queries themselves.
//
// The private key is sealed on the way in and only ever opened by
// credentialsFor(), which is called by the scanner. Nothing that serves an HTTP
// response calls it, and there is no endpoint that returns a key.
// ---------------------------------------------------------------------------

import ssh2 from 'ssh2';
import { one, many, query } from '../db/pool.mjs';
import { seal, open } from '../crypto/secrets.mjs';

// See the note in ssh/client.mjs: ssh2 is CommonJS.
const { utils: sshUtils } = ssh2;

/** Columns safe to send to a browser. Note what is absent. */
const PUBLIC = `id, user_id, name, host, port, username, tags, status, last_error,
                last_scan_at, created_at,
                host_key_fp,
                (private_key_enc IS NOT NULL) AS has_key,
                (passphrase_enc IS NOT NULL) AS has_passphrase`;

/** AAD binds a sealed key to the row it belongs to, so it cannot be replayed. */
const aad = (serverId, field) => 'server:' + serverId + ':' + field;

/* ------------------------------------------------------------------ validation */

export function nameProblem(name) {
  const s = String(name ?? '').trim();
  if (s.length < 1 || s.length > 64) return 'Give the server a name between 1 and 64 characters';
  return null;
}

/**
 * An IPv4/IPv6 address or a DNS name. Deliberately permissive about which -
 * plenty of estates are addressed by short internal hostnames - but strict
 * about shape, because this string ends up in a network connection.
 */
export function hostProblem(host) {
  const s = String(host ?? '').trim();
  if (!s || s.length > 253) return 'Enter the IP address or hostname of the server';
  if (/\s/.test(s)) return 'A hostname or IP address cannot contain spaces';
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const m = s.match(ipv4);
  if (m) {
    if (m.slice(1).every((o) => Number(o) <= 255)) return null;
    return 'That is not a valid IPv4 address';
  }
  if (s.includes(':')) return null; // IPv6
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/.test(s)) return null;
  return 'That does not look like a hostname or IP address';
}

export function usernameProblem(username) {
  const s = String(username ?? '').trim();
  // POSIX portable username, plus the dot some directories use. Restrictive on
  // purpose: this value is interpolated into an SSH handshake.
  if (!/^[a-z_][a-z0-9_.-]{0,31}$/i.test(s)) return 'Enter the Linux login name to connect as, for example ubuntu or monitor';
  return null;
}

/**
 * Check the private key parses before it is stored.
 *
 * Without this, a mistyped key is only discovered at the first scan, by which
 * point the person who pasted it has moved on. ssh2 does the parsing, so what
 * is accepted here is exactly what will work later.
 */
export function keyProblem(privateKey, passphrase) {
  const s = String(privateKey ?? '').trim();
  if (!s) return 'Paste the private key that can log in to this server';
  if (!/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(s)) {
    return 'That does not look like a private key. Paste the whole file including the -----BEGIN----- and -----END----- lines.';
  }
  if (/-----BEGIN [A-Z0-9 ]*PUBLIC KEY-----/.test(s) || /^ssh-(rsa|ed25519|dss)\s/.test(s) || /^ecdsa-sha2-/.test(s)) {
    return 'That is the public key. Vigil needs the private half - the file without the .pub extension - to log in.';
  }

  const parsed = sshUtils.parseKey(s, passphrase || undefined);
  if (parsed instanceof Error) {
    if (/passphrase/i.test(parsed.message)) {
      return passphrase
        ? 'The passphrase does not decrypt this key.'
        : 'This key is passphrase-protected. Enter its passphrase as well, or use a key without one.';
    }
    return 'The private key could not be parsed: ' + parsed.message;
  }
  return null;
}

/** The public half, so the UI can show what to put in authorized_keys. */
export function publicKeyFor(privateKey, passphrase) {
  const parsed = sshUtils.parseKey(String(privateKey), passphrase || undefined);
  if (parsed instanceof Error) return null;
  try {
    return parsed.getPublicSSH ? parsed.type + ' ' + parsed.getPublicSSH().toString('base64') : null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------------ reads */

export function listServers(userId) {
  return many('SELECT ' + PUBLIC + ' FROM servers WHERE user_id = $1 ORDER BY lower(name)', [userId]);
}

export function getServer(userId, id) {
  return one('SELECT ' + PUBLIC + ' FROM servers WHERE user_id = $1 AND id = $2', [userId, id]);
}

/**
 * Decrypt the credentials for one server. The only caller is the scanner.
 * @returns {Promise<{host, port, username, privateKey, passphrase, hostKeyFp} | null>}
 */
export async function credentialsFor(userId, id) {
  const row = await one(
    'SELECT id, host, port, username, private_key_enc, passphrase_enc, host_key_fp FROM servers WHERE user_id = $1 AND id = $2',
    [userId, id]
  );
  if (!row) return null;
  return {
    host: row.host,
    port: row.port,
    username: row.username,
    privateKey: open(row.private_key_enc, aad(row.id, 'private_key')),
    passphrase: row.passphrase_enc ? open(row.passphrase_enc, aad(row.id, 'passphrase')) : null,
    hostKeyFp: row.host_key_fp,
  };
}

/* ----------------------------------------------------------------------- writes */

export async function createServer(userId, { name, host, port = 22, username, privateKey, passphrase, tags = [] }) {
  // The row is inserted first so its id can be bound into the AAD, then the
  // sealed key is written in the same transaction-free follow-up. A row that
  // somehow lost its key would be unusable, so the NOT NULL on private_key_enc
  // is satisfied by sealing against a placeholder id and re-sealing after.
  const row = await one(
    `INSERT INTO servers (user_id, name, host, port, username, private_key_enc, passphrase_enc, tags)
     VALUES ($1, $2, $3, $4, $5, 'pending', NULL, $6) RETURNING id`,
    [userId, String(name).trim(), String(host).trim(), Number(port), String(username).trim(), tags]
  );

  await query('UPDATE servers SET private_key_enc = $2, passphrase_enc = $3 WHERE id = $1', [
    row.id,
    seal(privateKey, aad(row.id, 'private_key')),
    passphrase ? seal(passphrase, aad(row.id, 'passphrase')) : null,
  ]);

  return getServer(userId, row.id);
}

export async function updateServer(userId, id, patch) {
  const sets = [];
  const params = [userId, id];
  const set = (col, value) => {
    params.push(value);
    sets.push(col + ' = $' + params.length);
  };

  if (patch.name !== undefined) set('name', String(patch.name).trim());
  if (patch.host !== undefined) set('host', String(patch.host).trim());
  if (patch.port !== undefined) set('port', Number(patch.port));
  if (patch.username !== undefined) set('username', String(patch.username).trim());
  if (patch.tags !== undefined) set('tags', patch.tags);
  if (patch.status !== undefined) set('status', patch.status);

  if (patch.privateKey) {
    set('private_key_enc', seal(patch.privateKey, aad(id, 'private_key')));
    // A new key means the passphrase question is being answered afresh; keeping
    // the old one would silently pair a new key with a stale secret.
    set('passphrase_enc', patch.passphrase ? seal(patch.passphrase, aad(id, 'passphrase')) : null);
  } else if (patch.passphrase !== undefined) {
    set('passphrase_enc', patch.passphrase ? seal(patch.passphrase, aad(id, 'passphrase')) : null);
  }

  // Resetting the pin is how a legitimately rebuilt host is re-trusted. It is
  // explicit, and it is audited by the caller, because the alternative - a
  // scanner that quietly re-pins - would make the check worthless.
  if (patch.resetHostKey) {
    sets.push('host_key_fp = NULL');
  }

  if (!sets.length) return getServer(userId, id);
  await query('UPDATE servers SET ' + sets.join(', ') + ' WHERE user_id = $1 AND id = $2', params);
  return getServer(userId, id);
}

export async function deleteServer(userId, id) {
  const res = await query('DELETE FROM servers WHERE user_id = $1 AND id = $2', [userId, id]);
  return res.rowCount > 0;
}

/** Record the outcome of a scan against the server row. */
export async function recordScanResult(userId, id, { ok, error, hostKeyFp }) {
  await query(
    `UPDATE servers
        SET status = $3,
            last_error = $4,
            last_scan_at = now(),
            -- Pinned on first contact only. An existing pin is never overwritten
            -- here; changing one is an explicit reset, not a side effect.
            host_key_fp = COALESCE(host_key_fp, $5)
      WHERE user_id = $1 AND id = $2`,
    [userId, id, ok ? 'healthy' : 'error', ok ? null : String(error ?? '').slice(0, 500), hostKeyFp ?? null]
  );
}
