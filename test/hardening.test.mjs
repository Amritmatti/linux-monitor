// Hardening audit tests.
//
// The judgement calls here are what matter: which SUID binaries are normal,
// which world-writable directories are fine, and - above all - that "we could
// not check" never renders as "this passed". A security page that quietly
// reports unknowns as clean is worse than no security page.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseSuid, parseWorldWritable, parseAccounts, parseGroups, parseFirewall, parseContainerPosture, parseStatLines } from '../server/ssh/parse.mjs';
import { assembleFacts, SCRIPT } from '../server/ssh/probe.mjs';
import { audit, coverage } from '../server/engine/hardening.mjs';

function probeOutput(sections) {
  return Object.entries(sections)
    .map(([k, v]) => '@@VG:' + k + '@@\n' + v)
    .join('\n');
}

const find = (f, key) => f.find((x) => x.key === key);
const area = (cov, id) => cov.find((c) => c.id === id);

/* ------------------------------------------------------------- the probe */

test('the hardening probe only ever reads', () => {
  // The product's central promise, asserted rather than documented. If a future
  // change adds a mutating verb to the script, this fails.
  const forbidden = /\b(rm|mv|cp|chmod|chown|dd|mkfs|tee|truncate|killall|pkill|useradd|usermod|systemctl (start|stop|restart|enable|disable)|apt-get (install|upgrade|remove)|dnf (install|update|remove))\b/;
  for (const line of SCRIPT.split('\n')) {
    // The remedy strings live in the engine, not the probe; the probe is only
    // allowed to look.
    if (forbidden.test(line)) assert.fail('probe line looks like it writes: ' + line.slice(0, 120));
  }
});

test('the filesystem walks are bounded and pruned', () => {
  // Only the two that start at / need pruning; the credential-file walk is
  // already confined to a handful of directories.
  const rootWalks = SCRIPT.split('\n').filter((l) => /find \/ -xdev/.test(l));
  assert.equal(rootWalks.length, 2, 'expected exactly the SUID and world-writable walks');
  for (const w of rootWalks) {
    assert.ok(w.includes('timeout'), 'a walk of / must be time-limited: ' + w.slice(0, 80));
    assert.ok(w.includes('-path /proc') && w.includes('-prune'), 'a walk of / must prune /proc');
    assert.ok(/head -\d+/.test(w), 'a walk of / must cap its output');
  }

  const scoped = SCRIPT.split('\n').filter((l) => /^S secretworld;/.test(l));
  assert.ok(scoped[0].includes('timeout') && /head -\d+/.test(scoped[0]), 'the credential walk is bounded too');
  assert.ok(!/find \/ /.test(scoped[0]), 'and it does not start at /');
});

test('nothing in the probe reads the contents of a credential file', () => {
  // The secret checks ask stat and find for paths and modes. A `cat`, `grep` or
  // `head` of one of these would be the same mistake the finding is about.
  const secretLines = SCRIPT.split('\n').filter((l) => /^S (secretperms|secretworld);/.test(l));
  assert.equal(secretLines.length, 2);
  for (const l of secretLines) {
    // `| head -N` caps the LIST of paths and is fine; anything that opens one
    // of those paths is not.
    const withoutListCap = l.replace(/\|\s*head -\d+/g, '');
    assert.ok(!/\b(cat|tail|grep|awk|sed|strings|head|xxd|od)\b/.test(withoutListCap), 'reads contents: ' + l.slice(0, 140));
  }
  assert.ok(SCRIPT.includes("stat -c '%n %a %U'"), 'permissions are what gets collected');
});

/* --------------------------------------------------------------- parsing */

test('SUID and SGID are told apart by their mode', () => {
  const s = parseSuid('4755 /usr/bin/sudo\n2755 /usr/bin/ssh-agent\n6755 /usr/bin/weird\nnot a line');
  assert.equal(s.length, 3);
  assert.equal(s[0].kind, 'suid');
  assert.equal(s[1].kind, 'sgid');
  assert.equal(s[2].kind, 'suid', 'setuid wins when a file is both');
});

test('sticky world-writable directories are not reported', () => {
  const w = parseWorldWritable(
    ['1777 directory /tmp', '1777 directory /var/tmp', '0777 directory /opt/shared', '0666 regular file /etc/app.conf', '0777 symbolic link /x'].join('\n')
  );
  assert.deepEqual(w.dirs.map((d) => d.path), ['/opt/shared'], '/tmp is sticky and correct');
  assert.deepEqual(w.files.map((f) => f.path), ['/etc/app.conf']);
});

test('accounts, and which of them can actually log in', () => {
  const a = parseAccounts(['root:0:0:/bin/bash', 'daemon:1:1:/usr/sbin/nologin', 'backdoor:0:0:/bin/bash', 'app:1001:1001:/bin/false'].join('\n'));
  assert.equal(a.length, 4);
  assert.equal(a.filter((x) => x.uid === 0).length, 2);
  assert.equal(a.find((x) => x.name === 'root').canLogin, true);
  assert.equal(a.find((x) => x.name === 'daemon').canLogin, false);
  assert.equal(a.find((x) => x.name === 'app').canLogin, false);
});

test('groups', () => {
  const g = parseGroups('sudo:x:27:alice,bob\ndocker:x:103:monitor\nwheel:x:10:');
  assert.deepEqual(g.sudo, ['alice', 'bob']);
  assert.deepEqual(g.docker, ['monitor']);
  assert.deepEqual(g.wheel, []);
});

test('firewall: unreadable is not the same as inactive', () => {
  const none = parseFirewall({});
  assert.equal(none.readable, false);
  assert.equal(none.active, null, 'null, not false - nobody looked');

  const ufw = parseFirewall({ ufw: 'Status: active\nDefault: deny (incoming), allow (outgoing)\nTo  Action  From\n22/tcp  ALLOW  Anywhere' });
  assert.equal(ufw.tool, 'ufw');
  assert.equal(ufw.active, true);
  assert.equal(ufw.defaultInbound, 'deny');

  const off = parseFirewall({ ufw: 'Status: inactive' });
  assert.equal(off.active, false);

  // An ACCEPT policy with no rules is an unconfigured firewall, not a running one.
  const bare = parseFirewall({ iptables: '-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT' });
  assert.equal(bare.tool, 'iptables');
  assert.equal(bare.active, false);
  assert.equal(bare.defaultInbound, 'allow');

  const real = parseFirewall({ iptables: '-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT' });
  assert.equal(real.active, true);
  assert.equal(real.defaultInbound, 'deny');
});

test('container posture', () => {
  const c = parseContainerPosture(
    [
      '/api|false|1000|/srv/data>/data;|;|true',
      '/build|true||/>/host;/var/run/docker.sock>/var/run/docker.sock;|SYS_ADMIN;|false',
    ].join('\n')
  );
  assert.equal(c[0].name, 'api');
  assert.equal(c[0].privileged, false);
  assert.equal(c[0].user, '1000');
  assert.equal(c[1].privileged, true);
  assert.equal(c[1].user, null, 'empty user means the image default, usually root');
  assert.equal(c[1].mounts.length, 2);
  assert.deepEqual(c[1].capAdd, ['SYS_ADMIN']);
});

/* ------------------------------------------------------------------ rules */

/** A believable, mostly-hardened Ubuntu host. */
const CLEAN = {
  uname: 'Linux 5.15.0-92-generic x86_64',
  osrelease: 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nID=ubuntu\nVERSION_ID="22.04"',
  ncpu: '4',
  loadavg: '0.1 0.1 0.1 1/200 900',
  meminfo: 'MemTotal: 8039152 kB\nMemAvailable: 6000000 kB',
  df: 'Filesystem 1B-blocks Used Available Capacity Mounted on\n/dev/sda1 41028206592 8123456789 30890000000 21% /',
  ports: 'tcp   LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))',
  pkgmgr: 'apt',
  aptupgrade: '',
  sshdsource: 'effective',
  sshd: 'permitrootlogin prohibit-password\npasswordauthentication no\npubkeyauthentication yes',
  authsrc: 'journal',
  authfail: '2',
  fwufw: 'Status: active\nDefault: deny (incoming), allow (outgoing)',
  macinstalled: 'apparmor',
  apparmor: 'enabled',
  accounts: 'root:0:0:/bin/bash\ndaemon:1:1:/usr/sbin/nologin\nmonitor:1000:1000:/bin/bash',
  privgroups: 'sudo:x:27:alice',
  fileperms: ['/etc/shadow 640 root shadow', '/etc/passwd 644 root root', '/etc/sudoers 440 root root', '/etc/environment 644 root root'].join('\n'),
  suidsgid: '4755 /usr/bin/sudo\n4755 /usr/bin/passwd\n2755 /usr/bin/ssh-agent',
  worldwritable: '1777 directory /tmp',
  cronfiles: '/etc/cron.d:\ntotal 4\n-rw-r--r-- 1 root root 201 Jan  8  2022 /etc/cron.d/e2scrub_all',
  secretperms: '',
  secretworld: '',
  findlimited: 'yes',
  // The daemon answered. Without this, container posture is unknown rather than
  // clean - which is the point of the check below.
  dockersrc: 'ok',
  dockerdf: 'Images\t1\t1\t10MB\t0B (0%)',
};

const factsFor = (overrides = {}) => assembleFacts(probeOutput({ ...CLEAN, ...overrides })).facts;

test('a hardened host produces no hardening findings', () => {
  assert.deepEqual(audit(factsFor()), [], 'a clean box must be silent here too');
});

test('a setuid shell is treated as a probable backdoor', () => {
  const f = audit(factsFor({ suidsgid: '4755 /usr/bin/sudo\n4755 /usr/bin/find\n4755 /usr/bin/python3' }));
  const d = find(f, 'harden:suid:dangerous');
  assert.equal(d.severity, 'critical');
  assert.match(d.detail, /published one-line escalation/);
  assert.match(d.remedy, /chmod u-s/);
});

test('stock setuid binaries raise nothing, and unusual ones are only informational', () => {
  assert.equal(find(audit(factsFor()), 'harden:suid:unexpected'), undefined);
  const f = audit(factsFor({ suidsgid: '4755 /usr/bin/sudo\n4755 /opt/vendor/agent' }));
  assert.equal(find(f, 'harden:suid:unexpected').severity, 'info');
});

test('a second UID 0 account is critical', () => {
  const f = audit(factsFor({ accounts: 'root:0:0:/bin/bash\ntoor:0:0:/bin/bash' }));
  const u = find(f, 'harden:accounts:uid0');
  assert.equal(u.severity, 'critical');
  assert.match(u.evidence.find((e) => e.label === 'Accounts').value, /toor/);
});

test('docker group membership is reported as the root equivalence it is', () => {
  const f = audit(factsFor({ privgroups: 'sudo:x:27:alice\ndocker:x:103:bob,carol' }));
  const d = find(f, 'harden:sudo:docker-group');
  assert.equal(d.severity, 'warning');
  assert.match(d.detail, /root-equivalent/);
});

test('an unreadable firewall raises nothing; an inactive one does', () => {
  const unknown = audit(factsFor({ fwufw: '' }));
  assert.equal(find(unknown, 'harden:firewall:inactive'), undefined, 'not readable must never render as not present');

  const off = audit(factsFor({ fwufw: 'Status: inactive' }));
  assert.ok(find(off, 'harden:firewall:inactive'));

  const permissive = audit(factsFor({ fwufw: 'Status: active\nDefault: allow (incoming), allow (outgoing)' }));
  assert.equal(find(permissive, 'harden:firewall:default-allow').severity, 'warning');
});

test('the SSH combination rule needs all three conditions', () => {
  // Passwords on, but a firewall is confirmed active: not this finding.
  const guarded = audit(factsFor({ sshd: 'passwordauthentication yes' }));
  assert.equal(find(guarded, 'harden:ssh:open-password'), undefined);

  const exposed = audit(factsFor({ sshd: 'passwordauthentication yes', fwufw: 'Status: inactive' }));
  assert.equal(find(exposed, 'harden:ssh:open-password').severity, 'critical');
});

test('world-readable /etc/shadow and writable /etc/environment', () => {
  const shadow = audit(factsFor({ fileperms: '/etc/shadow 644 root shadow' }));
  assert.equal(find(shadow, 'harden:permissions:shadow').severity, 'critical');

  // 644 on /etc/environment is the distribution default and must stay silent;
  // 646 means anyone can prepend a command to every login on the box.
  assert.equal(find(audit(factsFor()), 'harden:permissions:writable:/etc/environment'), undefined);
  const writable = audit(factsFor({ fileperms: '/etc/environment 646 root root' }));
  assert.match(find(writable, 'harden:permissions:writable:/etc/environment').detail, /sourced into every login/);
});

test('a private key with loose permissions is critical; a correct one is silent', () => {
  assert.equal(audit(factsFor({ secretperms: '/home/monitor/.ssh/id_ed25519 600 monitor' })).length, 0);
  const f = audit(factsFor({ secretperms: '/home/monitor/.ssh/id_ed25519 644 monitor' }));
  const k = find(f, 'harden:secrets:loose:/home/monitor/.ssh/id_ed25519');
  assert.equal(k.severity, 'critical');
  assert.equal(k.evidence.find((e) => e.label === 'Expected').value, '600');
});

test('exposed credential files are reported by path, never by content', () => {
  const f = audit(factsFor({ secretworld: '/srv/app/.env\n/opt/deploy/id_rsa' }));
  const s = find(f, 'harden:secrets:world-readable');
  assert.equal(s.severity, 'critical');
  assert.equal(s.evidence.find((e) => e.label === 'Contents read').value, 'no - never');
  assert.match(s.evidence.find((e) => e.label === 'Files').value, /\.env/);
});

test('a cron file anyone can edit is a scheduled root shell', () => {
  const f = audit(factsFor({ cronfiles: '-rw-rw-rw- 1 root root 201 Jan  8  2022 /etc/cron.d/backup' }));
  const c = find(f, 'harden:cron:writable');
  assert.equal(c.severity, 'critical');
  assert.match(c.detail, /runs as root/);
});

test('container escape routes are separated from container hygiene', () => {
  const f = audit(
    factsFor({
      dockerinspect: [
        '/api|false|1000|/srv/data>/data;|;|true',
        '/ci|true||/var/run/docker.sock>/var/run/docker.sock;|SYS_ADMIN;|false',
      ].join('\n'),
    })
  );
  assert.equal(find(f, 'harden:containers:privileged').area, 'escape');
  assert.equal(find(f, 'harden:containers:docker-sock').area, 'escape');
  assert.equal(find(f, 'harden:containers:caps').area, 'escape');
  // Running as root is a weaker layer, not an escape.
  assert.equal(find(f, 'harden:containers:root-user').area, 'containers');
  assert.equal(find(f, 'harden:containers:root-user').severity, 'warning');
});

test('SELinux and AppArmor: absent is not the same as disabled', () => {
  const none = audit(factsFor({ macinstalled: '', apparmor: '', selinux: '' }));
  assert.equal(none.filter((x) => x.area === 'mac').length, 0, 'a distro without either is not misconfigured');

  const off = audit(factsFor({ macinstalled: 'selinux', selinux: 'Disabled', apparmor: '' }));
  assert.equal(find(off, 'harden:mac:selinux').severity, 'warning');

  const permissive = audit(factsFor({ macinstalled: 'selinux', selinux: 'Permissive', apparmor: '' }));
  assert.equal(find(permissive, 'harden:mac:selinux').severity, 'info');
});

/* --------------------------------------------------------------- coverage */

test('coverage says what could not be looked at, per area', () => {
  const cov = coverage(factsFor());
  assert.equal(area(cov, 'firewall').state, 'checked');
  assert.equal(area(cov, 'suid').state, 'checked');

  const blind = coverage(factsFor({ fwufw: '', fwfirewalld: '', fwnft: '', fwiptables: '', macinstalled: '', apparmor: '' }));
  assert.equal(area(blind, 'firewall').state, 'unknown');
  assert.match(area(blind, 'firewall').note, /[Nn]eeds root/);
  assert.equal(area(blind, 'mac').state, 'not-applicable', 'nothing installed is not a blind spot');
});

test('command injection is declared out of scope rather than quietly passed', () => {
  const inj = area(coverage(factsFor()), 'injection');
  assert.equal(inj.state, 'not-applicable');
  assert.match(inj.note, /not checkable from outside the application/i);
});

test('sudo coverage is partial rather than unknown, because groups are always readable', () => {
  const cov = coverage(factsFor());
  assert.equal(area(cov, 'sudo').state, 'partial');
  assert.match(area(cov, 'sudo').note, /docker group/);
});

test('a host whose Docker daemon refused us reports unknown, not zero containers', () => {
  // The same distinction the rest of the product turns on: an empty answer from
  // a host nobody could look at must never render as a clean one.
  const refused = factsFor({ dockersrc: 'denied', dockerinspect: '' });
  assert.equal(refused.hardening.containers, null);
  assert.equal(area(coverage(refused), 'containers').state, 'unknown');
  assert.match(area(coverage(refused), 'containers').note, /refused/);

  const absent = factsFor({ dockersrc: 'none', dockerinspect: '', dockerdf: '' });
  assert.equal(area(coverage(absent), 'containers').state, 'not-applicable');

  const answered = factsFor({ dockerinspect: '/api|false|1000|;|;|true' });
  assert.equal(answered.hardening.containers.length, 1);
  assert.equal(area(coverage(answered), 'containers').state, 'checked');
});
