// ---------------------------------------------------------------------------
// Robust statistics.
//
// Every number here resists outliers, because on a server the outlier IS the
// event. A mean and a standard deviation over the last fortnight get dragged
// upwards by yesterday's incident, and the effect is that a machine which
// misbehaved once becomes progressively harder to alert on - exactly backwards.
//
// So: median instead of mean, median absolute deviation instead of standard
// deviation, and Theil-Sen instead of least squares for trends.
// ---------------------------------------------------------------------------

export function median(values) {
  const v = values.filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return null;
  const mid = v.length >> 1;
  return v.length % 2 ? v[mid] : (v[mid - 1] + v[mid]) / 2;
}

export function percentile(values, p) {
  const v = values.filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return null;
  const idx = Math.min(v.length - 1, Math.max(0, Math.ceil((p / 100) * v.length) - 1));
  return v[idx];
}

/**
 * Median absolute deviation, scaled so that for normally distributed data it
 * estimates the same thing as a standard deviation. That scaling is what lets
 * the threshold below be quoted in familiar sigma-like units.
 */
export function mad(values) {
  const m = median(values);
  if (m === null) return null;
  const deviations = values.filter((x) => Number.isFinite(x)).map((x) => Math.abs(x - m));
  const raw = median(deviations);
  return raw === null ? null : raw * 1.4826;
}

/**
 * How far outside its own history a value sits, in robust sigmas.
 *
 * Returns null when there is not enough history to say anything, which callers
 * must treat as "no opinion" rather than "normal" - a brand new server has no
 * baseline, and inventing one produces confident nonsense for its first day.
 */
export function robustZ(value, history, { minSamples = 8 } = {}) {
  const clean = history.filter((x) => Number.isFinite(x));
  if (!Number.isFinite(value) || clean.length < minSamples) return null;
  const m = median(clean);
  let spread = mad(clean);

  // A perfectly flat series has MAD 0, which would make every deviation
  // infinitely significant - one byte of movement on a idle disk would read as
  // an emergency. Fall back to a floor derived from the median's own scale.
  if (!spread || spread < 1e-9) {
    spread = Math.max(Math.abs(m) * 0.02, 0.5);
  }
  return (value - m) / spread;
}

/**
 * Theil-Sen slope: the median of the slopes between every pair of points.
 *
 * Chosen over least squares because a single scan taken during a log-rotation
 * blip should not be able to swing a disk-exhaustion forecast by weeks, and
 * with least squares it can. Tolerates up to ~29% corrupted points.
 *
 * @param {Array<{x: number, y: number}>} points
 * @returns {{slope: number, intercept: number} | null} slope in y-units per x-unit
 */
export function theilSen(points) {
  const pts = points.filter((p) => Number.isFinite(p.x) && Number.isFinite(p.y));
  if (pts.length < 3) return null;

  const slopes = [];
  for (let i = 0; i < pts.length; i++) {
    for (let j = i + 1; j < pts.length; j++) {
      const dx = pts[j].x - pts[i].x;
      if (dx === 0) continue;
      slopes.push((pts[j].y - pts[i].y) / dx);
    }
  }
  if (!slopes.length) return null;

  const slope = median(slopes);
  const intercept = median(pts.map((p) => p.y - slope * p.x));
  return { slope, intercept };
}

/**
 * When a series that is climbing will reach `limit`.
 *
 * @returns {{days: number, slopePerDay: number} | null} null when it is flat or falling
 */
export function projectToLimit(points, limit) {
  const fit = theilSen(points);
  if (!fit) return null;
  const last = points[points.length - 1];
  const slopePerDay = fit.slope * 86400000; // x is epoch ms
  if (!Number.isFinite(slopePerDay) || slopePerDay <= 0) return null;
  const remaining = limit - last.y;
  if (remaining <= 0) return { days: 0, slopePerDay };
  return { days: remaining / slopePerDay, slopePerDay };
}

export function round1(n) {
  return Math.round(n * 10) / 10;
}

export function round2(n) {
  return Math.round(n * 100) / 100;
}
