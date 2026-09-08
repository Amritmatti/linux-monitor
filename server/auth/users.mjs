// ---------------------------------------------------------------------------
// Users, passwords and sessions.
//
// Passwords are hashed with scrypt (node:crypto, no dependency) at the
// parameters OWASP suggests for interactive login. Session tokens are random
// 32-byte values; only their SHA-256 is stored, so a database dump cannot be
// replayed as a live session.
//
// There are no roles and no tenants here. A server belongs to the person who
// added it, and every query in the application is scoped by user_id - that is
// the only access rule this product has, which is why it fits in one file.
// ---------------------------------------------------------------------------

import { randomBytes, scrypt as scryptCb, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { one, query } from '../db/pool.mjs';

const scrypt = promisify(scryptCb);

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
const SESSION_DAYS = Number(process.env.VG_SESSION_DAYS || 14);

/* ------------------------------------------------------------------ passwords */

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 64 * 1024 * 1024 });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), derived.toString('base64')].join('$');
}

export async function verifyPassword(password, stored) {
  try {
    const [scheme, N, r, p, saltB64, hashB64] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const derived = await scrypt(password, salt, expected.length, { N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024 });
    return derived.length === expected.length && timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

export function passwordProblem(password) {
  if (typeof password !== 'string' || password.length < 10) return 'Password must be at least 10 characters';
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) return 'Password must contain a letter and a number';
  return null;
}

export function emailProblem(email) {
  if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return 'Enter a valid email address';
  if (email.length > 254) return 'Email address is too long';
  return null;
}

/* ---------------------------------------------------------------------- users */

const PUBLIC_USER = 'id, email, name, disabled, created_at, last_login_at';

export async function findUserByEmail(email) {
  return one('SELECT id, email, name, disabled, password_hash FROM users WHERE lower(email) = lower($1)', [email]);
}

export async function getUser(id) {
  return one('SELECT ' + PUBLIC_USER + ' FROM users WHERE id = $1', [id]);
}

export async function createUser({ email, name, password }) {
  const passwordHash = await hashPassword(password);
  const user = await one('INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING ' + PUBLIC_USER, [
    email.trim(),
    name.trim(),
    passwordHash,
  ]);
  await audit(user.id, email, 'user-created', name + ' <' + email + '> signed up');
  return user;
}

export async function changePassword(userId, password) {
  const passwordHash = await hashPassword(password);
  await query('UPDATE users SET password_hash = $2 WHERE id = $1', [userId, passwordHash]);
}

/* ------------------------------------------------------------------- sessions */

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

export async function createSession(userId, { ip, userAgent } = {}) {
  const token = randomBytes(32).toString('base64url');
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000);
  await query('INSERT INTO sessions (user_id, token_hash, expires_at, ip, user_agent) VALUES ($1, $2, $3, $4, $5)', [
    userId,
    hashToken(token),
    expires,
    ip ?? null,
    (userAgent ?? '').slice(0, 400),
  ]);
  await query('UPDATE users SET last_login_at = now() WHERE id = $1', [userId]);
  return { token, expires };
}

export async function resolveSession(token) {
  if (!token) return null;
  const row = await one(
    'SELECT s.id AS session_id, u.id, u.email, u.name, u.disabled FROM sessions s ' +
      'JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now()',
    [hashToken(token)]
  );
  if (!row || row.disabled) return null;
  return row;
}

export async function destroySession(token) {
  if (!token) return;
  await query('DELETE FROM sessions WHERE token_hash = $1', [hashToken(token)]);
}

export async function destroyAllSessions(userId) {
  await query('DELETE FROM sessions WHERE user_id = $1', [userId]);
}

export async function purgeExpiredSessions() {
  const res = await query('DELETE FROM sessions WHERE expires_at <= now()');
  return res.rowCount;
}

/* ---------------------------------------------------------------------- audit */

export async function audit(userId, actor, event, detail, meta = null) {
  await query('INSERT INTO audit_log (user_id, actor, event, detail, meta) VALUES ($1, $2, $3, $4, $5)', [
    userId ?? null,
    actor,
    event,
    detail,
    meta,
  ]);
}
