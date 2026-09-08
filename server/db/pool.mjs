// Postgres connection pool, schema bootstrap, and small query helpers.

import pg from 'pg';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Numeric columns come back as strings by default so that arbitrary precision
// survives. Every numeric here is a percentage, a byte count or a duration -
// all of which fit a double - so parse them once rather than scattering
// Number() through the query layer.
pg.types.setTypeParser(1700, (v) => (v === null ? null : Number(v)));
pg.types.setTypeParser(20, (v) => (v === null ? null : Number(v)));

const connectionString =
  process.env.DATABASE_URL ||
  'postgres://' +
    (process.env.PGUSER || 'vigil') + ':' +
    (process.env.PGPASSWORD || 'vigil') + '@' +
    (process.env.PGHOST || 'postgres') + ':' +
    (process.env.PGPORT || '5432') + '/' +
    (process.env.PGDATABASE || 'vigil');

export const pool = new pg.Pool({
  connectionString,
  max: Number(process.env.PGPOOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 8000,
  ssl: process.env.PGSSLMODE === 'require' ? { rejectUnauthorized: false } : undefined,
});

pool.on('error', (err) => {
  console.error('[db] idle client error:', err.message);
});

export function query(text, params) {
  return pool.query(text, params);
}

/** First row or null. */
export async function one(text, params) {
  const res = await pool.query(text, params);
  return res.rows[0] ?? null;
}

export async function many(text, params) {
  const res = await pool.query(text, params);
  return res.rows;
}

/** Run a function inside a transaction, rolling back on any throw. */
export async function transaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      /* the connection is already gone; the transaction is dead either way */
    }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Postgres in a compose stack is usually still starting when we are, so wait
 * for it rather than crash-looping the container.
 */
export async function waitForDatabase({ attempts = 30, delayMs = 1000 } = {}) {
  let lastError;
  for (let i = 1; i <= attempts; i++) {
    try {
      await pool.query('SELECT 1');
      if (i > 1) console.log('[db] connected after ' + i + ' attempts');
      return;
    } catch (err) {
      lastError = err;
      if (i === 1 || i % 5 === 0) console.log('[db] waiting for postgres (' + i + '/' + attempts + '): ' + err.message);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw new Error('Database unreachable after ' + attempts + ' attempts: ' + lastError?.message);
}

/** Apply schema.sql. It is written to be idempotent, so this runs on every boot. */
export async function migrate() {
  const sql = await readFile(join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(sql);
  console.log('[db] schema up to date');
}

export async function close() {
  await pool.end();
}
