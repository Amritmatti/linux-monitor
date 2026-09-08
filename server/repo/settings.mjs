// ---------------------------------------------------------------------------
// Per-user settings.
//
// Scanning cadence belongs to the person, not to the container: one estate of
// three laptops wants an hourly sweep and another of forty production hosts
// wants five minutes, and they can share an instance. VG_SCAN_MINUTES is now
// only the default a new account starts from.
// ---------------------------------------------------------------------------

import { one, query } from '../db/pool.mjs';

/** 0 means "never sweep on a timer" - scanning becomes something you trigger. */
export const SCAN_INTERVAL_CHOICES = [0, 5, 10, 15, 30, 60, 180, 360, 720, 1440];

const DEFAULT_SCAN_MINUTES = (() => {
  const n = Number(process.env.VG_SCAN_MINUTES ?? 15);
  return Number.isFinite(n) && n >= 0 && n <= 1440 ? Math.round(n) : 15;
})();

export function scanIntervalProblem(minutes) {
  const n = Number(minutes);
  if (!Number.isInteger(n)) return 'Choose one of the offered intervals';
  if (!SCAN_INTERVAL_CHOICES.includes(n)) {
    // Deliberately a fixed list rather than a free number: a 30-second sweep of
    // forty hosts would queue SSH connections faster than they complete, and
    // the failure mode is a dashboard that looks broken rather than one that
    // says "you asked for too much".
    return 'Choose one of the offered intervals';
  }
  return null;
}

/** Reads never fail: a user with no row yet gets the instance default. */
export async function getSettings(userId) {
  const row = await one('SELECT scan_minutes, updated_at FROM user_settings WHERE user_id = $1', [userId]);
  return {
    scanMinutes: row ? row.scan_minutes : DEFAULT_SCAN_MINUTES,
    updatedAt: row ? row.updated_at : null,
    isDefault: !row,
    defaultScanMinutes: DEFAULT_SCAN_MINUTES,
    choices: SCAN_INTERVAL_CHOICES,
  };
}

export async function setScanInterval(userId, minutes) {
  await query(
    `INSERT INTO user_settings (user_id, scan_minutes) VALUES ($1, $2)
     ON CONFLICT (user_id) DO UPDATE SET scan_minutes = EXCLUDED.scan_minutes, updated_at = now()`,
    [userId, Number(minutes)]
  );
  return getSettings(userId);
}

/**
 * Everyone with something to scan, their interval, and when they were last
 * swept.
 *
 * "Last swept" is derived from the newest scan rather than held in memory, so a
 * restart does not re-sweep the whole estate, and two app instances against one
 * database do not both decide it is time.
 */
export function schedulableUsers() {
  return query(
    `SELECT v.user_id,
            COALESCE(us.scan_minutes, $1) AS scan_minutes,
            (SELECT max(started_at) FROM scans s WHERE s.user_id = v.user_id) AS last_scan_at
       FROM (SELECT DISTINCT user_id FROM servers WHERE status <> 'disabled') v
       LEFT JOIN user_settings us ON us.user_id = v.user_id`,
    [DEFAULT_SCAN_MINUTES]
  ).then((res) => res.rows);
}

export { DEFAULT_SCAN_MINUTES };
