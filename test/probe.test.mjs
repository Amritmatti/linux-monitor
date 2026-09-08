// Fact-assembly tests.
//
// The probe's job is to turn one blob of shell output into a fact object, and
// the thing that matters most is what it does with the sections that came back
// EMPTY. A monitoring product that reads "we could not ask" as "the answer is
// zero" reports a healthy fleet right up until the incident, so most of these
// tests are about the gaps rather than the data.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { assembleFacts } from '../server/ssh/probe.mjs';

/** Build probe stdout from a { section: text } map. */
function probeOutput(sections) {
  return Object.entries(sections)
    .map(([k, v]) => '@@VG:' + k + '@@\n' + v)
    .join('\n');
}

/** A well-equipped Ubuntu host that answers everything. */
const FULL = {
  hostname: 'web-01.example.com',
  uname: 'Linux 5.15.0-92-generic x86_64',
  osrelease: 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nID=ubuntu\nVERSION_ID="22.04"\nID_LIKE=debian',
  virt: 'kvm',
  uptime: '864000.12 3456789.01',
  now: String(Math.floor(Date.now() / 1000)),
  ncpu: '4',
  loadavg: '3.10 3.40 3.60 4/512 9931',
  meminfo: 'MemTotal:        8039152 kB\nMemFree:          198684 kB\nMemAvailable:     410288 kB\nCached:          3103924 kB\nSwapTotal:       2097148 kB\nSwapFree:          87228 kB',
  df: 'Filesystem     1B-blocks        Used   Available Capacity Mounted on\n/dev/sda1    41028206592 38123456789   890749803      98% /\ntmpfs         4114505728           0  4114505728       0% /dev/shm',
  dfi: 'Filesystem      Inodes   IUsed   IFree IUse% Mounted on\n/dev/sda1      2621440  300000 2321440   12% /',
  ports:
    'tcp   LISTEN 0      4096   0.0.0.0:22    0.0.0.0:*    users:(("sshd",pid=812,fd=3))\n' +
    'tcp   LISTEN 0      511    0.0.0.0:6379  0.0.0.0:*',
  failedunits: 'nginx.service loaded failed failed A high performance web server',
  systemstate: 'degraded',
  pkgmgr: 'apt',
  aptupgrade:
    'Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])\n' +
    'Inst tzdata [2023c] (2024a Ubuntu:22.04/jammy-updates [all])',
  aptstamp: String(Math.floor(Date.now() / 1000) - 3600),
  rebootrequired: 'yes',
  rebootpkgs: 'linux-image-generic',
  kernelrunning: '5.15.0-92-generic',
  kernellatest: '5.15.0-94-generic',
  sshdsource: 'config',
  sshd: 'Port 22\nPermitRootLogin yes\nPasswordAuthentication yes',
  authsrc: 'authlog',
  authfail: '1483',
  sudo: 'no',
  who: 'ubuntu   pts/0        2024-04-01 09:12',
  pscpu: '    PID USER     %CPU %MEM COMMAND\n   1122 redis     91.2  4.1 redis-server',
  psmem: '    PID USER     %CPU %MEM COMMAND\n   1122 redis     91.2  4.1 redis-server',
  zombies: '2',
  ntp: 'yes',
};

test('a complete probe assembles into complete facts', () => {
  const { facts, limited } = assembleFacts(probeOutput(FULL));

  assert.equal(facts.host.hostname, 'web-01.example.com');
  assert.equal(facts.host.os.name, 'Ubuntu 22.04.4 LTS');
  assert.equal(facts.host.kernel, '5.15.0-92-generic');
  assert.equal(facts.host.virt, 'kvm');
  assert.equal(facts.host.uptimeSeconds, 864000);
  assert.ok(facts.host.bootedAt, 'boot time is derived from uptime');

  assert.equal(facts.cpu.cores, 4);
  assert.equal(facts.cpu.load15, 3.6);
  assert.equal(facts.cpu.loadPerCore, 0.9);

  assert.equal(facts.disks.length, 1, 'tmpfs is excluded');
  assert.equal(facts.disks[0].usedPct, 98);
  assert.equal(facts.disks[0].inodesUsedPct, 12, 'usage and inodes are merged per mount');

  assert.equal(facts.ports.length, 2);
  assert.equal(facts.services.failed.length, 1);
  assert.equal(facts.updates.security, 1);
  assert.equal(facts.updates.total, 2);
  assert.equal(facts.reboot.required, true);
  assert.equal(facts.reboot.kernelStale, true, 'a newer kernel is installed than is running');
  assert.equal(facts.security.authFailures24h, 1483);
  assert.equal(facts.security.hasSudo, false);
  assert.equal(facts.processes.zombies, 2);
  assert.equal(facts.time.ntpSynchronized, true);
  assert.ok(Math.abs(facts.time.skewSeconds) < 5, 'clock skew is measured against our own');

  // Root opened 6379, so ss could not name it: expected when unprivileged.
  assert.ok(limited.includes('port-process-names'));
  assert.ok(limited.includes('sshd-effective'), 'settings came from the config file, not sshd -T');
  assert.ok(!limited.includes('updates'));
});

test('an empty probe reports unknowns, never zeros', () => {
  const { facts, limited } = assembleFacts('');

  assert.equal(facts.updates, null, 'no package manager answered');
  assert.equal(facts.memory, null);
  assert.equal(facts.cpu.cores, null);
  assert.equal(facts.cpu.loadPerCore, null);
  assert.deepEqual(facts.disks, []);
  assert.deepEqual(facts.ports, []);
  assert.equal(facts.security.authFailures24h, null, 'not readable is not the same as none');
  assert.equal(facts.time.ntpSynchronized, null);

  for (const key of ['disks', 'ports', 'updates', 'failed-units', 'auth-failures', 'sshd-effective']) {
    assert.ok(limited.includes(key), 'expected "' + key + '" to be reported as limited');
  }
});

test('an unreadable auth log is null, while a readable one showing nothing is zero', () => {
  const none = assembleFacts(probeOutput({ ...FULL, authsrc: 'none', authfail: '0' }));
  assert.equal(none.facts.security.authFailures24h, null);
  assert.ok(none.limited.includes('auth-failures'));

  const quiet = assembleFacts(probeOutput({ ...FULL, authsrc: 'journal', authfail: '0' }));
  assert.equal(quiet.facts.security.authFailures24h, 0);
  assert.ok(!quiet.limited.includes('auth-failures'));
});

test('sudo lifts the port-naming limitation', () => {
  const named = probeOutput({
    ...FULL,
    ports:
      'tcp   LISTEN 0 4096 0.0.0.0:22   0.0.0.0:* users:(("sshd",pid=812,fd=3))\n' +
      'tcp   LISTEN 0 511  0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=1122,fd=6))',
    sshdsource: 'effective',
    sudo: 'yes',
  });
  const { facts, limited } = assembleFacts(named);
  assert.equal(facts.security.hasSudo, true);
  assert.ok(!limited.includes('port-process-names'));
  assert.ok(!limited.includes('sshd-effective'));
  assert.equal(facts.ports.find((p) => p.port === 6379).process, 'redis-server');
});

test('stale package lists are measured against the host clock, not ours', () => {
  const hostNow = Math.floor(Date.now() / 1000);
  const { facts } = assembleFacts(
    probeOutput({ ...FULL, now: String(hostNow), aptstamp: String(hostNow - 86400 * 30) })
  );
  assert.ok(facts.updates.listsAgeSeconds > 86400 * 29 && facts.updates.listsAgeSeconds < 86400 * 31);
});

test('a host with a badly skewed clock still reports a non-negative list age', () => {
  // The host thinks it is a week ago. Age must not come out negative.
  const hostNow = Math.floor(Date.now() / 1000) - 604800;
  const { facts } = assembleFacts(probeOutput({ ...FULL, now: String(hostNow), aptstamp: String(hostNow + 1000) }));
  assert.ok(facts.updates.listsAgeSeconds >= 0, 'age was ' + facts.updates.listsAgeSeconds);
  assert.ok(facts.time.skewSeconds > 600000, 'and the skew itself is reported');
});

test('dnf without advisory metadata marks security as unknown', () => {
  const { facts } = assembleFacts(
    probeOutput({
      ...FULL,
      pkgmgr: 'dnf',
      aptupgrade: '',
      dnfupdates: 'kernel.x86_64   5.14.0-427.el9   baseos\nopenssl.x86_64  1:3.0.7-27.el9   appstream',
      dnfsecurity: '',
    })
  );
  assert.equal(facts.updates.total, 2);
  assert.equal(facts.updates.security, 0);
  assert.equal(facts.updates.securityKnown, false, 'zero here means we could not tell, and the rules must know that');
});

test('a systemd-less host reports failed units as unknown rather than none', () => {
  const { facts, limited } = assembleFacts(probeOutput({ ...FULL, failedunits: '', systemstate: '' }));
  assert.deepEqual(facts.services.failed, []);
  assert.ok(limited.includes('failed-units'));
});

test('a TERMINATED-style host with no ss and no netstat is flagged, not silently empty', () => {
  const { facts, limited } = assembleFacts(probeOutput({ ...FULL, ports: '' }));
  assert.deepEqual(facts.ports, []);
  assert.ok(limited.includes('ports'));
});
