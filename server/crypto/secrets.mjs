// ---------------------------------------------------------------------------
// Secret storage.
//
// SSH private keys never reach Postgres in plaintext. Each secret is sealed
// with AES-256-GCM under a key that lives outside the database, so a dump of
// the database - a backup, a replica, a leaked snapshot - yields nothing that
// can log in to one of your servers.
//
// The key comes from VG_ENCRYPTION_KEY (32 bytes, base64). If it is absent the
// process generates one and writes it to DATA_DIR/encryption.key with 0600 so a
// plain `docker compose up` works, and prints a loud warning: a key on the same
// volume as the data is convenience, not security. In production, supply it
// from your secret manager and mount nothing.
// ---------------------------------------------------------------------------

import { randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || join(__dirname, '..', '..', 'data');
const KEY_FILE = join(DATA_DIR, 'encryption.key');
const VERSION = 'v1';

let key = null;

function loadKey() {
  if (key) return key;

  const fromEnv = process.env.VG_ENCRYPTION_KEY;
  if (fromEnv) {
    const buf = Buffer.from(fromEnv, 'base64');
    if (buf.length !== 32) {
      throw new Error('VG_ENCRYPTION_KEY must be 32 bytes encoded as base64 (got ' + buf.length + ' bytes)');
    }
    key = buf;
    return key;
  }

  if (existsSync(KEY_FILE)) {
    key = Buffer.from(readFileSync(KEY_FILE, 'utf8').trim(), 'base64');
    if (key.length !== 32) throw new Error('Stored encryption key is malformed; remove ' + KEY_FILE + ' and re-add your servers');
    return key;
  }

  key = randomBytes(32);
  mkdirSync(DATA_DIR, { recursive: true });
  writeFileSync(KEY_FILE, key.toString('base64'), { mode: 0o600 });
  try {
    chmodSync(KEY_FILE, 0o600);
  } catch {
    /* some filesystems (bind mounts on Windows) do not support chmod */
  }
  console.warn(
    '[secrets] No VG_ENCRYPTION_KEY set. Generated one and stored it at ' + KEY_FILE + '.\n' +
      '[secrets] This is fine for local use. In production pass VG_ENCRYPTION_KEY from your secret manager:\n' +
      '[secrets]   VG_ENCRYPTION_KEY=' + key.toString('base64')
  );
  return key;
}

/**
 * Seal a secret. Returns "v1.<iv>.<tag>.<ciphertext>", all base64url.
 * `aad` binds the ciphertext to its context (org + field), so a value cannot be
 * lifted from one row and replayed into another.
 */
export function seal(plaintext, aad = '') {
  if (plaintext === null || plaintext === undefined || plaintext === '') return null;
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', loadKey(), iv, { authTagLength: 16 });
  if (aad) cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, iv.toString('base64url'), tag.toString('base64url'), ct.toString('base64url')].join('.');
}

export function open(sealed, aad = '') {
  if (!sealed) return null;
  const parts = String(sealed).split('.');
  if (parts.length !== 4 || parts[0] !== VERSION) throw new Error('Malformed sealed value');
  const [, ivB64, tagB64, ctB64] = parts;
  const decipher = createDecipheriv('aes-256-gcm', loadKey(), Buffer.from(ivB64, 'base64url'), { authTagLength: 16 });
  if (aad) decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64url')), decipher.final()]).toString('utf8');
}

/** Show enough of a credential to recognise it, never enough to use it. */
export function mask(value, keepStart = 4, keepEnd = 4) {
  if (!value) return null;
  const s = String(value);
  if (s.length <= keepStart + keepEnd) return '•'.repeat(s.length);
  return s.slice(0, keepStart) + '•'.repeat(Math.max(4, s.length - keepStart - keepEnd)) + s.slice(-keepEnd);
}

export function constantTimeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/** Called at boot so a bad key fails loudly at start, not on first use. */
export function verifyKeyAvailable() {
  const probe = seal('probe', 'boot');
  if (open(probe, 'boot') !== 'probe') throw new Error('Encryption self-test failed');
  return true;
}
