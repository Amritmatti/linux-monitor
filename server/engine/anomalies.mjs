// ---------------------------------------------------------------------------
// Anomaly detection.
//
// checks.mjs asks "is this value bad?" against fixed thresholds. This file asks
// a different and often more useful question: "is this value NORMAL FOR THIS
// MACHINE?"
//
// The two disagree constantly, and both disagreements matter:
//
//   A build server that sits at load 14 all day is not an incident. A threshold
//   alerts on it every minute until someone silences the whole rule, and the
//   day it hits 40 nobody is listening any more.
//
//   A database that has run at 30% disk for two years and is now at 47% is
//   nowhere near any threshold, and is also the most interesting thing on the
//   estate - because at that slope it hits 100% in nine days.
//
// So the signals here are all relative to the server's own history: what
// changed, what appeared, what is trending, and what sits outside its own
// normal range. Anything with fewer than MIN_SAMPLES scans behind it returns no
// opinion at all rather than a confident one from three data points.
// ---------------------------------------------------------------------------

import { robustZ, projectToLimit, median, round1, round2 } from './stats.mjs';
import { bytes, days, SEVERITY_RANK } from './checks.mjs';

/** Below this much history, "normal for this machine" is not yet a thing we know. */
const MIN_SAMPLES = 8;

/** Robust sigmas outside the median before a level counts as an excursion. */
const Z_THRESHOLD = 3.5;

/** A trend needs both enough points and enough elapsed time to mean anything. */
const TREND_MIN_POINTS = 5;
const TREND_MIN_HOURS = 6;

const DAY_MS = 86400000;

function anomaly(a) {
  return { evidence: [], kind: 'change', ...a };
}

const portKey = (p) => p.proto + '/' + p.port + ' on ' + p.address;

/* ------------------------------------------------------- what appeared, what went */

/**
 * A listening socket that was not there before.
 *
 * This is the highest-signal check in the file. Nothing opens a port on a
 * server by accident: it is a deploy, a config change, a package that enabled
 * itself on install - or it is someone else's shell. All four are things the
 * owner should find out about from here rather than later.
 */
function detectPortChanges(current, history, out) {
  if (!current.ports || history.length < 2) return;

  // Seen across the whole window, not just the previous scan: a service that
  // flaps between scans would otherwise raise "new port" every other run.
  const previous = new Map();
  for (const h of history) {
    for (const p of h.facts?.ports ?? []) {
      if (!previous.has(portKey(p))) previous.set(portKey(p), h.startedAt);
    }
  }

  for (const p of current.ports) {
    if (previous.has(portKey(p))) continue;
    out.push(
      anomaly({
        key: 'anomaly:new-port:' + p.proto + ':' + p.address + ':' + p.port,
        severity: p.exposed ? 'critical' : 'warning',
        category: 'Network',
        kind: 'appeared',
        title: 'New listening socket: ' + p.proto + '/' + p.port + (p.process ? ' (' + p.process + ')' : ''),
        detail:
          'Nothing was listening on ' + portKey(p) + ' in the previous ' + history.length + ' scans. ' +
          (p.exposed
            ? 'It is bound to an address reachable from off this host, so whatever opened it is now exposed to the network.'
            : 'It is bound to loopback, so it is only reachable from the machine itself.'),
        evidence: [
          { label: 'Socket', value: portKey(p) },
          { label: 'Process', value: p.process ? p.process + (p.pid ? ' (pid ' + p.pid + ')' : '') : 'not visible without sudo' },
          { label: 'Reachable off-host', value: p.exposed ? 'yes' : 'no' },
          { label: 'Window', value: history.length + ' previous scans' },
        ],
      })
    );
  }

  // A port that has been listening for the whole window and is now gone is a
  // service that stopped. Only raised when it was consistently present, so a
  // service that comes and goes by design stays quiet.
  const nowKeys = new Set(current.ports.map(portKey));
  const alwaysPresent = new Map();
  for (const p of history[0]?.facts?.ports ?? []) alwaysPresent.set(portKey(p), p);
  for (const h of history.slice(1)) {
    const keys = new Set((h.facts?.ports ?? []).map(portKey));
    for (const k of [...alwaysPresent.keys()]) if (!keys.has(k)) alwaysPresent.delete(k);
  }
  for (const [k, p] of alwaysPresent) {
    if (nowKeys.has(k)) continue;
    out.push(
      anomaly({
        key: 'anomaly:closed-port:' + p.proto + ':' + p.address + ':' + p.port,
        severity: 'warning',
        category: 'Network',
        kind: 'disappeared',
        title: 'Stopped listening on ' + p.proto + '/' + p.port + (p.process ? ' (' + p.process + ')' : ''),
        detail:
          'This socket was open in every one of the previous ' + history.length + ' scans and is not open now. Whatever was serving ' +
          'it has stopped, been reconfigured, or crashed.',
        evidence: [
          { label: 'Socket', value: k },
          { label: 'Last seen', value: 'previous scan' },
          { label: 'Was present for', value: history.length + ' scans' },
        ],
      })
    );
  }
}

/* --------------------------------------------------------------------- trends */

/**
 * Disk exhaustion forecast.
 *
 * The single most valuable thing history buys: a filesystem at 61% that is
 * climbing 4 points a day is a far more urgent problem than one that has sat at
 * 88% since it was provisioned, and no threshold can tell them apart.
 */
function detectDiskTrends(current, history, out) {
  if (!current.disks?.length) return;

  for (const disk of current.disks) {
    const points = [];
    for (const h of history) {
      const match = (h.facts?.disks ?? []).find((d) => d.mount === disk.mount);
      if (match && Number.isFinite(match.usedPct)) points.push({ x: new Date(h.startedAt).getTime(), y: match.usedPct });
    }
    points.push({ x: Date.now(), y: disk.usedPct });
    if (points.length < TREND_MIN_POINTS) continue;

    const spanHours = (points[points.length - 1].x - points[0].x) / 3600000;
    if (spanHours < TREND_MIN_HOURS) continue;

    const projection = projectToLimit(points, 100);
    if (!projection) continue; // flat or falling: nothing to forecast

    // Under a tenth of a point a day is noise on a live filesystem, and
    // projecting it produces "full in 900 days", which is not information.
    if (projection.slopePerDay < 0.1) continue;
    if (projection.days > 60) continue;

    const severity = projection.days <= 7 ? 'critical' : projection.days <= 30 ? 'warning' : 'info';
    const when = projection.days < 1 ? 'less than a day' : Math.round(projection.days) + ' days';

    out.push(
      anomaly({
        key: 'anomaly:disk-trend:' + disk.mount,
        severity,
        category: 'Disk',
        kind: 'trend',
        title: disk.mount + ' fills in about ' + when,
        detail:
          'Growing ' + round2(projection.slopePerDay) + ' percentage points a day over the last ' + Math.round(spanHours) + ' hours, ' +
          'from ' + round1(points[0].y) + '% to ' + round1(disk.usedPct) + '%. At that rate it reaches 100% in ' + when + '. ' +
          'The slope is a median over every pair of samples, so one bad reading cannot swing it.',
        evidence: [
          { label: 'Now', value: disk.usedPct + '% (' + bytes(disk.availBytes) + ' free)' },
          { label: 'Growth', value: round2(projection.slopePerDay) + ' points/day' },
          { label: 'Full in', value: when },
          { label: 'Samples', value: points.length + ' scans over ' + Math.round(spanHours) + 'h' },
        ],
        value: projection.days,
      })
    );
  }
}

/* ------------------------------------------------------------------ excursions */

/** A metric sitting far outside its own established range. */
function detectLevelShifts(current, history, out) {
  if (history.length < MIN_SAMPLES) return;

  const metrics = [
    {
      key: 'load',
      label: '15-minute load',
      category: 'CPU',
      now: current.cpu?.load15,
      series: history.map((h) => h.facts?.cpu?.load15),
      format: (v) => round2(v),
      // Only ever interesting upwards. A quiet server is not an anomaly worth
      // anyone's attention, and half of all excursions are quiet servers.
      direction: 'up',
      detail: 'Load is well above what this server normally runs at, regardless of whether it has crossed a fixed threshold.',
    },
    {
      key: 'memory',
      label: 'memory used',
      category: 'Memory',
      now: current.memory?.usedPct,
      series: history.map((h) => h.facts?.memory?.usedPct),
      format: (v) => round1(v) + '%',
      direction: 'up',
      detail: 'Memory usage has stepped outside its normal band for this host - the shape of a leak, or of a workload that changed.',
    },
    {
      key: 'auth-failures',
      label: 'failed SSH logins',
      category: 'Security',
      now: current.security?.authFailures24h,
      series: history.map((h) => h.facts?.security?.authFailures24h),
      format: (v) => Math.round(v).toLocaleString('en-US'),
      direction: 'up',
      detail: 'Failed login volume is far above this host\'s baseline, which is what the start of a targeted brute-force looks like.',
    },
    {
      key: 'process-count',
      label: 'process count',
      category: 'CPU',
      now: current.cpu?.processes,
      series: history.map((h) => h.facts?.cpu?.processes),
      format: (v) => Math.round(v).toLocaleString('en-US'),
      direction: 'up',
      detail: 'The number of processes is well outside normal for this host, which is the signature of a fork loop or a runaway supervisor.',
    },
  ];

  for (const m of metrics) {
    if (!Number.isFinite(m.now)) continue;
    const series = m.series.filter((v) => Number.isFinite(v));
    const z = robustZ(m.now, series, { minSamples: MIN_SAMPLES });
    if (z === null) continue;
    if (m.direction === 'up' && z < Z_THRESHOLD) continue;
    if (m.direction === 'down' && z > -Z_THRESHOLD) continue;

    const baseline = median(series);
    out.push(
      anomaly({
        key: 'anomaly:level:' + m.key,
        severity: Math.abs(z) >= Z_THRESHOLD * 2 ? 'critical' : 'warning',
        category: m.category,
        kind: 'excursion',
        title: m.label.charAt(0).toUpperCase() + m.label.slice(1) + ' is ' + round1(Math.abs(z)) + '× outside its normal range',
        detail: m.detail,
        evidence: [
          { label: 'Now', value: m.format(m.now) },
          { label: 'Normal for this host', value: m.format(baseline) },
          { label: 'Deviation', value: round1(z) + ' robust sigma' },
          { label: 'Baseline from', value: series.length + ' scans' },
        ],
        value: m.now,
      })
    );
  }
}

/* ------------------------------------------------------------- state transitions */

/** Things that were one way and are now another. */
function detectTransitions(current, history, out) {
  const prev = history[history.length - 1]?.facts;
  if (!prev) return;

  // Uptime going backwards is the only reliable reboot signal available to an
  // agentless collector.
  const nowUp = current.host?.uptimeSeconds;
  const prevUp = prev.host?.uptimeSeconds;
  if (Number.isFinite(nowUp) && Number.isFinite(prevUp) && nowUp < prevUp) {
    const kernelChanged = current.reboot?.runningKernel && prev.reboot?.runningKernel && current.reboot.runningKernel !== prev.reboot.runningKernel;
    out.push(
      anomaly({
        key: 'anomaly:rebooted',
        severity: 'info',
        category: 'Kernel',
        kind: 'transition',
        title: kernelChanged ? 'Rebooted into a new kernel' : 'Rebooted since the last scan',
        detail: kernelChanged
          ? 'Now running ' + current.reboot.runningKernel + ', previously ' + prev.reboot.runningKernel + '. Pending kernel fixes are now live.'
          : 'Uptime went backwards, so the machine restarted. If nobody scheduled that, find out why it went down.',
        evidence: [
          { label: 'Uptime now', value: days(nowUp) },
          { label: 'Uptime before', value: days(prevUp) },
          { label: 'Kernel', value: current.reboot?.runningKernel ?? '--' },
        ],
      })
    );
  }

  // A unit that was healthy and is now failed. checks.mjs already reports that
  // it is failed; the anomaly is that it changed, which dates the incident.
  const prevFailed = new Set((prev.services?.failed ?? []).map((u) => u.unit));
  for (const unit of current.services?.failed ?? []) {
    if (prevFailed.has(unit.unit)) continue;
    out.push(
      anomaly({
        key: 'anomaly:unit-failed:' + unit.unit,
        severity: 'warning',
        category: 'Services',
        kind: 'transition',
        title: unit.unit + ' failed since the last scan',
        detail: 'It was not in the failed list on the previous scan, so this is recent and the journal will still have it.',
        evidence: [
          { label: 'Unit', value: unit.unit },
          { label: 'Previous scan', value: new Date(history[history.length - 1].startedAt).toISOString() },
        ],
      })
    );
  }

  // A jump in the security backlog means an advisory landed for something on
  // this host, which is worth knowing on the day rather than at the next audit.
  const nowSec = current.updates?.security;
  const prevSec = prev.updates?.security;
  if (Number.isFinite(nowSec) && Number.isFinite(prevSec) && nowSec > prevSec) {
    out.push(
      anomaly({
        key: 'anomaly:security-backlog',
        severity: nowSec - prevSec >= 5 ? 'warning' : 'info',
        category: 'Updates',
        kind: 'change',
        title: nowSec - prevSec + ' new security update' + (nowSec - prevSec === 1 ? '' : 's') + ' published',
        detail: 'The security backlog went from ' + prevSec + ' to ' + nowSec + ' between scans, so new advisories now apply to this host.',
        evidence: [
          { label: 'Now', value: String(nowSec) },
          { label: 'Previous scan', value: String(prevSec) },
          { label: 'New packages', value: (current.updates?.securityPackages ?? []).slice(0, 6).join(', ') || '--' },
        ],
        value: nowSec,
      })
    );
  }
}

/* ------------------------------------------------------------------ entry point */

/**
 * @param {object} facts        the scan just taken
 * @param {Array}  history      previous scans, oldest first: [{ startedAt, facts }]
 * @returns {Array} anomalies, most severe first
 */
export function detect(facts, history = []) {
  const out = [];
  if (!facts) return out;

  // Only successful scans carry a comparable picture; a failed one would read
  // as "every port closed at once".
  const usable = history.filter((h) => h && h.facts).slice(-40);

  detectPortChanges(facts, usable, out);
  detectDiskTrends(facts, usable, out);
  detectLevelShifts(facts, usable, out);
  detectTransitions(facts, usable, out);

  out.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.category.localeCompare(b.category) || a.title.localeCompare(b.title));
  return out;
}

export { MIN_SAMPLES, Z_THRESHOLD };
