// Parser tests.
//
// Every fixture below is real output, kept verbatim including the ragged column
// widths and the trailing whitespace, because those are exactly what breaks a
// naive split(). If a parser is changed, these are the machines it must still
// understand.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseSections, parseOsRelease, parseUname, parseUptime, parseLoadavg, parseMeminfo,
  parseDf, parseDfInodes, parsePorts, parseAptUpgrade, parseDnfUpdates,
  parseFailedUnits, parseProcesses, parseSshd, isExposed,
} from '../server/ssh/parse.mjs';

/* ------------------------------------------------------------------ sections */

test('sections split on the marker and survive blank bodies', () => {
  const raw = [
    '@@VG:hostname@@',
    'web-01.example.com',
    '@@VG:virt@@',
    '',
    '@@VG:uname@@',
    'Linux 5.15.0-92-generic x86_64',
  ].join('\n');
  const s = parseSections(raw);
  assert.equal(s.hostname, 'web-01.example.com');
  assert.equal(s.virt, '');
  assert.equal(s.uname, 'Linux 5.15.0-92-generic x86_64');
});

test('output before the first marker is discarded', () => {
  const s = parseSections('motd banner junk\n@@VG:hostname@@\nweb-01');
  assert.equal(s.hostname, 'web-01');
  assert.equal(Object.keys(s).length, 1);
});

/* ------------------------------------------------------------------ identity */

test('os-release strips quotes and picks the pretty name', () => {
  const os = parseOsRelease(`PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian`);
  assert.equal(os.id, 'ubuntu');
  assert.equal(os.version, '22.04');
  assert.equal(os.name, 'Ubuntu 22.04.4 LTS');
  assert.deepEqual(os.idLike, ['debian']);
});

test('uname and uptime', () => {
  assert.deepEqual(parseUname('Linux 5.15.0-92-generic x86_64'), {
    kernelName: 'Linux',
    kernelRelease: '5.15.0-92-generic',
    arch: 'x86_64',
  });
  assert.equal(parseUptime('1234567.89 9876543.21'), 1234568);
  assert.equal(parseUptime(''), null);
});

test('loadavg including the runnable/total field', () => {
  const l = parseLoadavg('0.52 0.58 0.59 2/1043 28134');
  assert.equal(l.load1, 0.52);
  assert.equal(l.load15, 0.59);
  assert.equal(l.runnable, 2);
  assert.equal(l.processes, 1043);
});

/* -------------------------------------------------------------------- memory */

test('meminfo converts kB to bytes and prefers MemAvailable', () => {
  const m = parseMeminfo(`MemTotal:        8039152 kB
MemFree:          198684 kB
MemAvailable:    4310288 kB
Buffers:          142108 kB
Cached:          4103924 kB
SwapTotal:       2097148 kB
SwapFree:        1887228 kB`);
  assert.equal(m.total, 8039152 * 1024);
  assert.equal(m.available, 4310288 * 1024);
  // The point of MemAvailable: MemFree is 2.5% here but the machine is fine.
  assert.ok(m.usedPct > 45 && m.usedPct < 47, 'usedPct was ' + m.usedPct);
  assert.equal(m.swapTotal, 2097148 * 1024);
  assert.ok(m.swapUsedPct > 9 && m.swapUsedPct < 11);
});

test('meminfo without swap reports null rather than zero percent', () => {
  const m = parseMeminfo('MemTotal:  1000000 kB\nMemFree: 500000 kB\nMemAvailable: 800000 kB');
  assert.equal(m.swapTotal, 0);
  assert.equal(m.swapUsedPct, null);
});

/* --------------------------------------------------------------------- disks */

test('df in bytes, with pseudo-filesystems dropped', () => {
  const d = parseDf(`Filesystem         1B-blocks         Used    Available Capacity Mounted on
/dev/sda1        41028206592  35123456789   3904749803      91% /
tmpfs             4114505728            0   4114505728       0% /dev/shm
/dev/sdb1       107374182400  10737418240  96636764160      10% /var/lib/data
udev              4094820352            0   4094820352       0% /dev`);
  assert.equal(d.length, 2, 'tmpfs and udev must be excluded');
  assert.equal(d[0].mount, '/');
  assert.equal(d[0].usedPct, 91);
  assert.equal(d[0].availBytes, 3904749803);
  assert.equal(d[1].mount, '/var/lib/data');
});

test('df handles mount points containing spaces', () => {
  const d = parseDf(`Filesystem     1B-blocks   Used Available Capacity Mounted on
/dev/sdc1     1000000000 500000 999500000       1% /mnt/my backup`);
  assert.equal(d[0].mount, '/mnt/my backup');
});

test('inode exhaustion is visible even when space is free', () => {
  const i = parseDfInodes(`Filesystem       Inodes   IUsed    IFree IUse% Mounted on
/dev/sda1       2621440 2500000   121440   96% /
/dev/sdb1      13107200      45 13107155    1% /var/lib/data`);
  assert.equal(i[0].inodesUsedPct, 96);
  assert.equal(i[0].inodesUsed, 2500000);
});

test('btrfs reporting "-" for inodes is skipped, not parsed as zero', () => {
  const i = parseDfInodes(`Filesystem     Inodes IUsed IFree IUse% Mounted on
/dev/sda2           -     -     -     - /`);
  assert.equal(i, null);
});

/* --------------------------------------------------------------------- ports */

test('ss output: addresses, process names and exposure', () => {
  const p = parsePorts(`tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      511          127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=1122,fd=5))
tcp   LISTEN 0      511                *:80                 *:*    users:(("nginx",pid=990,fd=6))
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=765,fd=12))
tcp   LISTEN 0      4096            [::]:22            [::]:*    users:(("sshd",pid=812,fd=4))`);

  const ssh = p.find((x) => x.port === 22 && x.proto === 'tcp');
  assert.equal(ssh.process, 'sshd');
  assert.equal(ssh.pid, 812);
  assert.equal(ssh.exposed, true);

  const pg = p.find((x) => x.port === 5432);
  assert.equal(pg.exposed, false, 'postgres on loopback is not exposed');

  const nginx = p.find((x) => x.port === 80);
  assert.equal(nginx.address, '0.0.0.0', '* normalises to 0.0.0.0');
  assert.equal(nginx.exposed, true);

  const dns = p.find((x) => x.port === 53);
  assert.equal(dns.address, '127.0.0.53', 'the %lo scope id is stripped');
  assert.equal(dns.exposed, false);

  // tcp/22 on 0.0.0.0 and on [::] are the same socket to a person.
  assert.equal(p.filter((x) => x.port === 22).length, 2);
});

test('ss without -p permission leaves the process blank, not the row missing', () => {
  const p = parsePorts('tcp   LISTEN 0      4096   0.0.0.0:443   0.0.0.0:*');
  assert.equal(p.length, 1);
  assert.equal(p[0].port, 443);
  assert.equal(p[0].process, null);
});

test('netstat fallback, including udp rows that have no state column', () => {
  const p = parsePorts(`Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      1500/redis-server
udp        0      0 0.0.0.0:68              0.0.0.0:*                           640/dhclient`);
  assert.equal(p.length, 3);
  const redis = p.find((x) => x.port === 6379);
  assert.equal(redis.process, 'redis-server');
  assert.equal(redis.pid, 1500);
  assert.equal(redis.exposed, false);
  const dhcp = p.find((x) => x.port === 68);
  assert.equal(dhcp.proto, 'udp');
  assert.equal(dhcp.process, 'dhclient');
});

test('established connections are never reported as listening sockets', () => {
  const p = parsePorts(`tcp   ESTAB  0      0     10.0.0.5:22      10.0.0.9:51234
tcp   LISTEN 0      4096   0.0.0.0:22      0.0.0.0:*`);
  assert.equal(p.length, 1);
  assert.equal(p[0].port, 22);
});

test('exposure classification', () => {
  assert.equal(isExposed('0.0.0.0'), true);
  assert.equal(isExposed('::'), true);
  assert.equal(isExposed('127.0.0.1'), false);
  assert.equal(isExposed('127.0.0.53'), false);
  assert.equal(isExposed('::1'), false);
  assert.equal(isExposed('10.0.4.11'), true);
});

/* ------------------------------------------------------------------- updates */

test('apt simulation: security updates identified by their archive, not their name', () => {
  const u = parseAptUpgrade(`Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])
Inst tzdata [2023c-0ubuntu0.22.04.2] (2024a-0ubuntu0.22.04 Ubuntu:22.04/jammy-updates [all])
Inst linux-image-generic [5.15.0.91.88] (5.15.0.92.89 Ubuntu:22.04/jammy-security [amd64])
Conf libssl3 (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])`);
  assert.equal(u.total, 3, 'Conf lines are not updates');
  assert.equal(u.security, 2);
  assert.deepEqual(u.securityPackages, ['libssl3', 'linux-image-generic']);
  assert.equal(u.packages[0].currentVersion, '3.0.2-0ubuntu1.10');
  assert.equal(u.packages[0].newVersion, '3.0.2-0ubuntu1.15');
});

test('a fully patched apt host is zero updates, and an unreadable one is null', () => {
  assert.equal(parseAptUpgrade('').total, 0);
  assert.equal(parseAptUpgrade(null), null, 'unknown must never collapse to zero');
});

test('newly installed packages with no current version still parse', () => {
  const u = parseAptUpgrade('Inst linux-headers-5.15.0-92 (5.15.0-92.102 Ubuntu:22.04/jammy-security [amd64])');
  assert.equal(u.total, 1);
  assert.equal(u.security, 1);
  assert.equal(u.packages[0].currentVersion, null);
});

test('dnf updates cross-referenced against the security advisory list', () => {
  const u = parseDnfUpdates(
    `Last metadata expiration check: 0:12:33 ago on Mon 01 Apr 2024.
kernel.x86_64                 5.14.0-427.13.1.el9_4        baseos
openssl.x86_64                1:3.0.7-27.el9               appstream
vim-minimal.x86_64            2:8.2.2637-20.el9            appstream`,
    `RHSA-2024:1234 Important/Sec.  kernel-5.14.0-427.13.1.el9_4.x86_64
RHSA-2024:1300 Moderate/Sec.   openssl-1:3.0.7-27.el9.x86_64`
  );
  assert.equal(u.total, 3);
  assert.equal(u.security, 2);
  assert.ok(u.securityPackages.includes('kernel'));
  assert.ok(u.securityPackages.includes('openssl'));
  assert.ok(!u.securityPackages.includes('vim-minimal'));
});

/* ------------------------------------------------------------------ services */

test('failed units, with the summary line ignored', () => {
  const u = parseFailedUnits(`nginx.service            loaded failed failed A high performance web server
docker.socket            loaded failed failed Docker Socket for the API
2 loaded units listed.`);
  assert.equal(u.length, 2);
  assert.equal(u[0].unit, 'nginx.service');
  assert.equal(u[0].description, 'A high performance web server');
});

test('a host with no failed units is an empty list, not null', () => {
  assert.deepEqual(parseFailedUnits(''), []);
  assert.equal(parseFailedUnits(null), null, 'no systemd at all is unknown');
});

/* ----------------------------------------------------------------- processes */

test('ps output with commands that contain spaces', () => {
  const p = parseProcesses(`    PID USER     %CPU %MEM COMMAND
   1122 postgres 84.2 12.1 postgres: checkpointer
    990 www-data  2.0  0.4 nginx`);
  assert.equal(p.length, 2);
  assert.equal(p[0].pid, 1122);
  assert.equal(p[0].cpu, 84.2);
  assert.equal(p[0].command, 'postgres: checkpointer');
});

/* ---------------------------------------------------------------------- sshd */

test('sshd -T output is lowercased into a lookup', () => {
  const s = parseSshd(`port 22
permitrootlogin yes
passwordauthentication no
permitemptypasswords no`);
  assert.equal(s.permitrootlogin, 'yes');
  assert.equal(s.passwordauthentication, 'no');
});

test('sshd_config fallback: comments ignored, first occurrence wins', () => {
  const s = parseSshd(`# PermitRootLogin prohibit-password
PermitRootLogin yes
PasswordAuthentication yes    # temporary
PermitRootLogin no`);
  assert.equal(s.permitrootlogin, 'yes', 'sshd applies the first directive, so we must too');
  assert.equal(s.passwordauthentication, 'yes', 'trailing comments are stripped');
});
