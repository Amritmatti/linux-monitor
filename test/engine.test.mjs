// Rules and anomaly-detection tests.
//
// These exist mostly to pin down the judgement calls: which things are critical
// rather than warnings, what must NOT fire, and where "unknown" has to stay
// distinct from "fine". A monitoring product earns its place by being quiet
// about the boring cases, so roughly half of these assert silence.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { evaluate } from '../server/engine/checks.mjs';
import { detect } from '../server/engine/anomalies.mjs';
import { robustZ, theilSen, projectToLimit, median, mad } from '../server/engine/stats.mjs';

const GiB = 1024 ** 3;

/** A healthy Ubuntu box. Every test starts here and breaks one thing. */
function healthy(overrides = {}) {
  return {
    collectedAt: new Date().toISOString(),
    host: {
      hostname: 'web-01',
      os: { id: 'ubuntu', version: '22.04', name: 'Ubuntu 22.04.4 LTS', idLike: ['debian'] },
      kernel: '5.15.0-92-generic',
      arch: 'x86_64',
      uptimeSeconds: 86400 * 30,
    },
    cpu: { cores: 4, load1: 0.4, load5: 0.5, load15: 0.6, loadPerCore: 0.15, runnable: 1, processes: 320 },
    memory: { total: 8 * GiB, available: 5 * GiB, used: 3 * GiB, usedPct: 37.5, cached: 2 * GiB, swapTotal: 2 * GiB, swapUsed: 0, swapUsedPct: 0 },
    disks: [{ filesystem: '/dev/sda1', mount: '/', totalBytes: 40 * GiB, usedBytes: 12 * GiB, availBytes: 28 * GiB, usedPct: 30, inodesUsedPct: 12, inodesTotal: 2621440, inodesUsed: 300000 }],
    ports: [
      { proto: 'tcp', address: '0.0.0.0', port: 22, process: 'sshd', pid: 812, exposed: true },
      { proto: 'tcp', address: '127.0.0.1', port: 5432, process: 'postgres', pid: 1122, exposed: false },
    ],
    services: { failed: [], systemState: 'running' },
    updates: { manager: 'apt', total: 0, security: 0, packages: [], securityPackages: [], listsAgeSeconds: 3600, securityKnown: true },
    reboot: { required: false, packages: [], runningKernel: '5.15.0-92-generic', latestKernel: '5.15.0-92-generic', kernelStale: false },
    security: { sshd: { permitrootlogin: 'prohibit-password', passwordauthentication: 'no' }, sshdSource: 'effective', authSource: 'journal', authFailures24h: 3, hasSudo: false, loggedInUsers: 1 },
    processes: { topCpu: [{ pid: 1, user: 'root', cpu: 0.1, mem: 0.1, command: 'systemd' }], topMem: [{ pid: 1122, user: 'postgres', cpu: 0.4, mem: 8, command: 'postgres' }], zombies: 0 },
    time: { ntpSynchronized: true, skewSeconds: 1 },
    ...overrides,
  };
}

const keys = (findings) => findings.map((f) => f.key);
const find = (findings, key) => findings.find((f) => f.key === key);

/* ------------------------------------------------------------- silence first */

test('a healthy server produces no findings at all', () => {
  assert.deepEqual(evaluate(healthy()), [], 'a clean box must be silent, or nobody reads the dashboard');
});

test('a database on loopback is not reported as exposed', () => {
  const f = evaluate(healthy());
  assert.equal(find(f, 'port:exposed:tcp:5432'), undefined);
});

test('SSH on 0.0.0.0 is normal and never flagged', () => {
  const f = evaluate(healthy());
  assert.equal(keys(f).some((k) => k.includes(':22')), false);
});

test('memory that is mostly page cache is not a warning', () => {
  // 200 MiB free but 5 GiB available: the healthy steady state of every Linux box.
  const f = evaluate(healthy({ memory: { total: 8 * GiB, free: 0.2 * GiB, available: 5 * GiB, usedPct: 37.5, cached: 4.5 * GiB, swapTotal: 0, swapUsed: 0, swapUsedPct: null } }));
  assert.equal(find(f, 'memory:available'), undefined);
});

/* ----------------------------------------------------------------- disks */

test('disk thresholds and their severities', () => {
  const warn = evaluate(healthy({ disks: [{ ...healthy().disks[0], usedPct: 84, availBytes: 6 * GiB }] }));
  assert.equal(find(warn, 'disk:usage:/').severity, 'warning');

  const crit = evaluate(healthy({ disks: [{ ...healthy().disks[0], usedPct: 93, availBytes: 2 * GiB }] }));
  assert.equal(find(crit, 'disk:usage:/').severity, 'critical');
  assert.equal(find(crit, 'disk:usage:/').value, 93, 'value drives acknowledgement re-opening');
});

test('inode exhaustion is raised even when the disk has plenty of space', () => {
  const f = evaluate(healthy({ disks: [{ ...healthy().disks[0], usedPct: 31, inodesUsedPct: 97, inodesUsed: 2500000 }] }));
  const inodes = find(f, 'disk:inodes:/');
  assert.equal(inodes.severity, 'critical');
  assert.equal(find(f, 'disk:usage:/'), undefined, 'space is fine and must not also be reported');
});

/* ---------------------------------------------------------------- updates */

test('security updates are critical; ordinary updates are informational', () => {
  const f = evaluate(healthy({ updates: { manager: 'apt', total: 12, security: 3, packages: [], securityPackages: ['libssl3'], listsAgeSeconds: 3600, securityKnown: true } }));
  assert.equal(find(f, 'updates:security').severity, 'critical');
  assert.equal(find(f, 'updates:available'), undefined, 'not both at once');

  const g = evaluate(healthy({ updates: { manager: 'apt', total: 12, security: 0, packages: [], securityPackages: [], listsAgeSeconds: 3600, securityKnown: true } }));
  assert.equal(find(g, 'updates:available').severity, 'info');
});

test('stale package lists are reported, because they make a green tick a lie', () => {
  const f = evaluate(healthy({ updates: { manager: 'apt', total: 0, security: 0, packages: [], securityPackages: [], listsAgeSeconds: 86400 * 40, securityKnown: true } }));
  const stale = find(f, 'updates:stale-lists');
  assert.equal(stale.severity, 'warning');
  assert.match(stale.detail, /floor, not a measurement/);
});

test('missing dnf security metadata is reported as unknown, not as zero', () => {
  const f = evaluate(healthy({ updates: { manager: 'dnf', total: 8, security: 0, packages: [], securityPackages: [], listsAgeSeconds: 600, securityKnown: false } }));
  assert.ok(find(f, 'updates:no-security-metadata'));
});

test('an unreadable package manager produces no update findings whatsoever', () => {
  const f = evaluate(healthy({ updates: null }));
  assert.equal(keys(f).some((k) => k.startsWith('updates:')), false);
});

/* ------------------------------------------------------------------ reboot */

test('a pending reboot escalates to critical when security updates are also waiting', () => {
  const base = { required: true, source: 'reboot-required', packages: ['linux-image-generic'], runningKernel: '5.15.0-91', latestKernel: '5.15.0-92', kernelStale: true };
  const warn = evaluate(healthy({ reboot: base }));
  assert.equal(find(warn, 'reboot:required').severity, 'warning');

  const crit = evaluate(healthy({
    reboot: base,
    updates: { manager: 'apt', total: 5, security: 2, packages: [], securityPackages: [], listsAgeSeconds: 600, securityKnown: true },
  }));
  assert.equal(find(crit, 'reboot:required').severity, 'critical');
});

/* ---------------------------------------------------------------- services */

test('a failed unit that matters is critical; a cosmetic one is a warning', () => {
  const important = evaluate(healthy({ services: { failed: [{ unit: 'nginx.service', active: 'failed', sub: 'failed', description: 'web server' }], systemState: 'degraded' } }));
  assert.equal(find(important, 'service:failed:nginx.service').severity, 'critical');

  const minor = evaluate(healthy({ services: { failed: [{ unit: 'motd-news.service', active: 'failed', sub: 'failed', description: 'message of the day' }], systemState: 'degraded' } }));
  assert.equal(find(minor, 'service:failed:motd-news.service').severity, 'warning');
});

/* ------------------------------------------------------------------- ports */

test('a risky service bound to the world is critical', () => {
  const f = evaluate(healthy({
    ports: [...healthy().ports, { proto: 'tcp', address: '0.0.0.0', port: 6379, process: null, pid: null, exposed: true }],
  }));
  const redis = find(f, 'port:exposed:tcp:6379');
  assert.equal(redis.severity, 'critical');
  assert.match(redis.title, /Redis/);
  assert.match(redis.evidence.find((e) => e.label === 'Process').value, /not visible without sudo/);
});

test('the same risky service on loopback is silent', () => {
  const f = evaluate(healthy({
    ports: [...healthy().ports, { proto: 'tcp', address: '127.0.0.1', port: 6379, process: 'redis-server', pid: 5, exposed: false }],
  }));
  assert.equal(find(f, 'port:exposed:tcp:6379'), undefined);
});

/* ---------------------------------------------------------------- security */

test('sshd posture', () => {
  const root = evaluate(healthy({ security: { ...healthy().security, sshd: { permitrootlogin: 'yes' } } }));
  assert.equal(find(root, 'security:permit-root-login').severity, 'critical');

  const pw = evaluate(healthy({ security: { ...healthy().security, sshd: { passwordauthentication: 'yes' } } }));
  assert.equal(find(pw, 'security:password-auth').severity, 'warning');
});

test('an absent sshd directive is never treated as if it were set', () => {
  // The config-file fallback cannot see compiled-in defaults, so silence is the
  // only honest answer here.
  const f = evaluate(healthy({ security: { ...healthy().security, sshd: {}, sshdSource: 'config' } }));
  assert.equal(keys(f).some((k) => k.startsWith('security:permit')), false);
  assert.equal(keys(f).some((k) => k.startsWith('security:password')), false);
});

test('brute-force volume escalates, and unreadable logs raise nothing', () => {
  const warn = evaluate(healthy({ security: { ...healthy().security, authFailures24h: 150 } }));
  assert.equal(find(warn, 'security:auth-failures').severity, 'warning');

  const crit = evaluate(healthy({ security: { ...healthy().security, authFailures24h: 4000 } }));
  assert.equal(find(crit, 'security:auth-failures').severity, 'critical');

  const unknown = evaluate(healthy({ security: { ...healthy().security, authFailures24h: null, authSource: 'none' } }));
  assert.equal(find(unknown, 'security:auth-failures'), undefined, 'null is not a big number');
});

test('an end-of-life release is critical regardless of its update count', () => {
  const f = evaluate(healthy({ host: { ...healthy().host, os: { id: 'ubuntu', version: '18.04', name: 'Ubuntu 18.04.6 LTS', idLike: ['debian'] } } }));
  assert.equal(find(f, 'platform:eol').severity, 'critical');
});

/* -------------------------------------------------------------------- clock */

test('clock skew escalates with size', () => {
  assert.equal(find(evaluate(healthy({ time: { ntpSynchronized: true, skewSeconds: 90 } })), 'time:skew').severity, 'warning');
  assert.equal(find(evaluate(healthy({ time: { ntpSynchronized: true, skewSeconds: -700 } })), 'time:skew').severity, 'critical');
});

/* ------------------------------------------------------------------ ordering */

test('findings come back most severe first', () => {
  const f = evaluate(healthy({
    disks: [{ ...healthy().disks[0], usedPct: 95, availBytes: 1 * GiB }],
    updates: { manager: 'apt', total: 30, security: 0, packages: [], securityPackages: [], listsAgeSeconds: 600, securityKnown: true },
    host: { ...healthy().host, uptimeSeconds: 86400 * 400 },
  }));
  const order = f.map((x) => x.severity);
  assert.deepEqual([...order].sort((a, b) => ({ critical: 0, warning: 1, info: 2 })[a] - ({ critical: 0, warning: 1, info: 2 })[b]), order);
});

/* ------------------------------------------------------------------- stats */

test('robust statistics ignore a single wild outlier', () => {
  const series = [10, 10, 11, 10, 9, 10, 11, 10, 900, 10];
  assert.equal(median(series), 10);
  assert.ok(mad(series) < 2, 'one spike must not inflate the spread');
});

test('robustZ declines to answer without enough history', () => {
  assert.equal(robustZ(50, [10, 11, 12]), null, 'three points is not a baseline');
  assert.ok(robustZ(50, [10, 10, 11, 10, 9, 10, 11, 10]) > 3.5);
});

test('a perfectly flat series does not make every wobble infinite', () => {
  const z = robustZ(10.2, [10, 10, 10, 10, 10, 10, 10, 10]);
  assert.ok(Number.isFinite(z) && Math.abs(z) < 3.5, 'z was ' + z);
});

test('Theil-Sen resists a corrupted sample that would swing least squares', () => {
  const points = [0, 1, 2, 3, 4, 5, 6].map((i) => ({ x: i, y: i * 2 }));
  points[3].y = 400; // one bad reading
  const fit = theilSen(points);
  assert.ok(Math.abs(fit.slope - 2) < 0.5, 'slope was ' + fit.slope);
});

test('disk exhaustion forecast', () => {
  const day = 86400000;
  const now = Date.now();
  // 2 points a day for a week, climbing 3 points of usage per day, ending at 80.
  const points = [];
  for (let i = 14; i >= 0; i--) points.push({ x: now - i * (day / 2), y: 80 - i * 1.5 });
  const p = projectToLimit(points, 100);
  assert.ok(Math.abs(p.slopePerDay - 3) < 0.3, 'slope/day was ' + p.slopePerDay);
  assert.ok(p.days > 5 && p.days < 8, 'days was ' + p.days);
  assert.equal(projectToLimit([{ x: 0, y: 50 }, { x: 1, y: 50 }, { x: 2, y: 50 }], 100), null, 'flat means no forecast');
});

/* --------------------------------------------------------------- anomalies */

function historyOf(count, factory) {
  const day = 86400000;
  const out = [];
  for (let i = count; i > 0; i--) out.push({ startedAt: new Date(Date.now() - i * (day / 4)).toISOString(), facts: factory(count - i) });
  return out;
}

test('a listening port that was never there before is an anomaly', () => {
  const history = historyOf(10, () => healthy());
  const now = healthy({ ports: [...healthy().ports, { proto: 'tcp', address: '0.0.0.0', port: 4444, process: null, pid: null, exposed: true }] });
  const a = detect(now, history);
  const newPort = a.find((x) => x.key === 'anomaly:new-port:tcp:0.0.0.0:4444');
  assert.ok(newPort, 'a new exposed socket is the highest-signal thing here');
  assert.equal(newPort.severity, 'critical');
});

test('a new loopback-only port is a warning, not a critical', () => {
  const history = historyOf(10, () => healthy());
  const now = healthy({ ports: [...healthy().ports, { proto: 'tcp', address: '127.0.0.1', port: 9000, process: 'app', pid: 7, exposed: false }] });
  assert.equal(detect(now, history).find((x) => x.key.includes('9000')).severity, 'warning');
});

test('an existing port is not reported as new', () => {
  const history = historyOf(10, () => healthy());
  assert.equal(detect(healthy(), history).some((x) => x.kind === 'appeared'), false);
});

test('a port that was always up and is now gone is reported', () => {
  const history = historyOf(10, () => healthy());
  const now = healthy({ ports: [healthy().ports[0]] }); // postgres stopped
  const gone = detect(now, history).find((x) => x.kind === 'disappeared');
  assert.ok(gone);
  assert.match(gone.title, /5432/);
});

test('a disk climbing steadily is forecast long before it crosses a threshold', () => {
  const day = 86400000;
  const history = [];
  for (let i = 12; i > 0; i--) {
    const usedPct = 40 + (12 - i) * 2; // 2 points a day
    history.push({
      startedAt: new Date(Date.now() - i * day).toISOString(),
      facts: healthy({ disks: [{ ...healthy().disks[0], usedPct }] }),
    });
  }
  const now = healthy({ disks: [{ ...healthy().disks[0], usedPct: 64 }] });
  const a = detect(now, history);
  const trend = a.find((x) => x.key === 'anomaly:disk-trend:/');
  assert.ok(trend, 'a disk at 64% is under every threshold and still the estate\'s biggest problem');
  assert.ok(trend.value > 12 && trend.value < 22, 'days was ' + trend.value);
  assert.equal(trend.severity, 'warning');

  // And it must stay quiet on a disk that is simply sitting still.
  const flat = historyOf(12, () => healthy());
  assert.equal(detect(healthy(), flat).some((x) => x.kind === 'trend'), false);
});

test('load far outside a machine\'s own normal range is an excursion', () => {
  const history = historyOf(12, () => healthy());
  const now = healthy({ cpu: { ...healthy().cpu, load15: 9.2, loadPerCore: 2.3 } });
  const a = detect(now, history);
  assert.ok(a.find((x) => x.key === 'anomaly:level:load'));
});

test('a busy machine that is always busy raises no excursion', () => {
  // Load 14 on 4 cores every single scan: checks.mjs will call this critical,
  // and the anomaly engine must stay silent, because it is normal here.
  const busy = () => healthy({ cpu: { cores: 4, load1: 14, load5: 14, load15: 14, loadPerCore: 3.5, runnable: 12, processes: 900 } });
  const a = detect(busy(), historyOf(12, busy));
  assert.equal(a.some((x) => x.key === 'anomaly:level:load'), false, 'the whole point of a per-machine baseline');
  // ...while the fixed rule still reports it, which is the intended division.
  assert.equal(evaluate(busy()).find((f) => f.key === 'cpu:load').severity, 'critical');
});

test('a reboot is detected from uptime going backwards', () => {
  const history = historyOf(4, () => healthy());
  const now = healthy({ host: { ...healthy().host, uptimeSeconds: 600 }, reboot: { ...healthy().reboot, runningKernel: '5.15.0-93-generic' } });
  const reboot = detect(now, history).find((x) => x.key === 'anomaly:rebooted');
  assert.ok(reboot);
  assert.match(reboot.title, /new kernel/);
});

test('a brand new server with no history produces no anomalies', () => {
  assert.deepEqual(detect(healthy(), []), [], 'no baseline means no opinion');
  assert.equal(detect(healthy(), historyOf(2, () => healthy())).length, 0);
});
