// ---------------------------------------------------------------------------
// The probe.
//
// One SSH session, one script, one round trip. Everything Vigil knows about a
// server comes from the script below, and every command in it only reads:
//
//   * `cat`, `ls`, `stat`, `df`, `ps`, `who`, `uname`, `date`
//   * `ss` / `netstat` with -n, which resolve nothing and change nothing
//   * `systemctl list-units` / `is-system-running`, both read-only verbs
//   * `apt-get -s`, which is the SIMULATION flag - it downloads nothing,
//     installs nothing and takes no lock; `dnf -C`, which reads the local
//     cache and will not touch the network
//
// There is no command here that writes, installs, restarts or removes. That is
// the product's central promise and this file is where it is kept, so a change
// to this script is a change to the security posture of the whole product.
//
// It is one script rather than twenty commands because twenty commands mean
// twenty round trips: on a 200 ms link that is four seconds per server before
// anything is parsed, and it multiplies by the size of the fleet.
// ---------------------------------------------------------------------------

import * as ssh from './client.mjs';
import * as p from './parse.mjs';

/**
 * The probe script. POSIX sh - no bashisms, because Debian's /bin/sh is dash
 * and Alpine's is busybox ash.
 *
 * Nothing in here may fail the script: every command is allowed to fail
 * silently and produce an empty section, which the parsers read as "unknown"
 * rather than as zero.
 */
const SCRIPT = [
  'LC_ALL=C; export LC_ALL',
  // ss, netstat and systemd-detect-virt live in sbin, which is not on a normal
  // user's PATH on Debian. Without this half the checks silently return empty.
  'PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"; export PATH',
  'S(){ printf "\\n@@VG:%s@@\\n" "$1"; }',
  'have(){ command -v "$1" >/dev/null 2>&1; }',

  /* ---- identity ---- */
  'S hostname; (hostname -f 2>/dev/null || hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null)',
  'S uname; uname -s -r -m 2>/dev/null',
  'S osrelease; head -20 /etc/os-release 2>/dev/null',
  'S virt; systemd-detect-virt 2>/dev/null',
  'S uptime; cat /proc/uptime 2>/dev/null',
  'S now; date +%s 2>/dev/null',

  /* ---- load and memory ---- */
  'S ncpu; (nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null)',
  'S loadavg; cat /proc/loadavg 2>/dev/null',
  'S meminfo; head -60 /proc/meminfo 2>/dev/null',

  /* ---- disks ---- */
  // The -x exclusions are a best effort: busybox df rejects them, so the
  // fallback asks for everything and parse.mjs filters pseudo-filesystems.
  'S df; (df -P -B1 -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -P -B1 2>/dev/null || df -P -k 2>/dev/null)',
  'S dfi; (df -P -i -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -P -i 2>/dev/null)',

  /* ---- listening sockets ---- */
  'S ports; (ss -H -tuln -p 2>/dev/null || netstat -tulnp 2>/dev/null || ss -H -tuln 2>/dev/null) | head -400',

  /* ---- services ---- */
  'S failedunits; systemctl list-units --state=failed --no-legend --plain --no-pager 2>/dev/null | head -60',
  'S systemstate; systemctl is-system-running 2>/dev/null',

  /* ---- packages and updates ---- */
  'S pkgmgr; if have apt-get; then echo apt; elif have dnf; then echo dnf; elif have yum; then echo yum; elif have apk; then echo apk; else echo unknown; fi',
  // -s is simulate. It reads the package lists already on disk, takes no lock
  // and needs no root.
  'S aptupgrade; if have apt-get; then apt-get -s -o Debug::NoLocking=true -q dist-upgrade 2>/dev/null | grep "^Inst" | head -400; fi',
  // How stale the package lists are. Without this, "0 security updates" on a
  // host that has not run `apt update` for six months reads as good news.
  'S aptstamp; if [ -f /var/lib/apt/periodic/update-success-stamp ]; then stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null; elif [ -d /var/lib/apt/lists ]; then stat -c %Y /var/lib/apt/lists 2>/dev/null; fi',
  // -C is cache-only: no network, no root, no surprises on a metered link.
  'S dnfupdates; if have dnf; then dnf -q -C list --upgrades 2>/dev/null | head -400; elif have yum; then yum -q -C check-update 2>/dev/null | head -400; fi',
  'S dnfsecurity; if have dnf; then dnf -q -C updateinfo list --security 2>/dev/null | head -400; fi',
  'S dnfstamp; if [ -d /var/cache/dnf ]; then stat -c %Y /var/cache/dnf 2>/dev/null; fi',
  'S apkupdates; if have apk; then apk version -l "<" 2>/dev/null | tail -n +2 | head -400; fi',

  /* ---- reboot ---- */
  'S rebootrequired; if [ -f /var/run/reboot-required ] || [ -f /run/reboot-required ]; then echo yes; else echo no; fi',
  'S rebootpkgs; head -40 /var/run/reboot-required.pkgs 2>/dev/null || head -40 /run/reboot-required.pkgs 2>/dev/null',
  'S needsrestart; if have needs-restarting; then needs-restarting -r >/dev/null 2>&1 && echo no || echo yes; fi',
  'S kernelrunning; uname -r 2>/dev/null',
  'S kernellatest; ls -1 /boot/vmlinuz-* 2>/dev/null | sed "s|.*/vmlinuz-||" | sort -V 2>/dev/null | tail -1',

  /* ---- security posture ---- */
  // sshd -T needs root. The fallback reads the config file, which is world
  // readable on every distribution that ships OpenSSH - see parseSshd for why
  // that difference matters to the rules.
  'S sshdsource; if sshd -T >/dev/null 2>&1; then echo effective; elif [ -r /etc/ssh/sshd_config ]; then echo config; else echo none; fi',
  'S sshd; (sshd -T 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null) | head -120',
  'S authsrc; if journalctl -q -n 1 -t sshd >/dev/null 2>&1; then echo journal; elif [ -r /var/log/auth.log ]; then echo authlog; elif [ -r /var/log/secure ]; then echo secure; else echo none; fi',
  'S authfail; (journalctl -q --since "-24 hours" -t sshd 2>/dev/null || tail -5000 /var/log/auth.log 2>/dev/null || tail -5000 /var/log/secure 2>/dev/null) | grep -c -E "Failed password|Invalid user|authentication failure" 2>/dev/null',
  'S sudo; if sudo -n true >/dev/null 2>&1; then echo yes; else echo no; fi',
  'S who; who 2>/dev/null | head -40',

  /* ---- processes ---- */
  'S pscpu; ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu 2>/dev/null | head -9',
  'S psmem; ps -eo pid,user,pcpu,pmem,comm --sort=-pmem 2>/dev/null | head -9',
  'S zombies; ps -eo stat= 2>/dev/null | grep -c "^Z"',

  /* ---- clock ---- */
  'S ntp; timedatectl show -p NTPSynchronized --value 2>/dev/null',
].join('\n');

/** Human labels for the checks that can degrade, used by the UI. */
export const LIMITED_REASONS = {
  'port-process-names':
    'Process names for listening sockets. `ss` only names processes the login owns, so ports opened by root show the port but not what opened it.',
  'auth-failures':
    'Failed SSH login counts. Neither the journal nor /var/log/auth.log is readable by this user, so a brute-force attempt would not be seen.',
  'sshd-effective':
    'Effective sshd configuration. `sshd -T` needs root, so settings are read from sshd_config - directives left at their compiled-in default are invisible.',
  'updates':
    'Pending package updates. No supported package manager answered, so update and security-update counts are unknown rather than zero.',
  'failed-units': 'Failed systemd units. This host does not run systemd, or systemctl is unavailable to this user.',
  'disks': 'Filesystem usage. df returned nothing usable.',
  'ports': 'Listening sockets. Neither ss nor netstat is installed.',
};

/**
 * The sudoers line that would lift each limitation, so the UI can tell someone
 * exactly what to add instead of "grant sudo".
 */
export const LIMITED_FIX = {
  'port-process-names': '<user> ALL=(root) NOPASSWD: /usr/bin/ss -H -tuln -p',
  'auth-failures': '<user> ALL=(root) NOPASSWD: /usr/bin/journalctl -q --since -24?hours -t sshd',
  'sshd-effective': '<user> ALL=(root) NOPASSWD: /usr/sbin/sshd -T',
};

const num = (v) => {
  const s = String(v ?? '').trim();
  // An absent section must not become 0: Number('') is 0, and that would turn
  // "we could not count failed logins" into "there were none", which is the
  // exact failure this whole module is written to avoid.
  if (!s) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
};

/**
 * Turn raw probe stdout into facts.
 *
 * Split out from collect() so the whole assembly - which is where "unknown"
 * has to stay distinct from "zero" - is testable against recorded output from
 * real machines, with no SSH and no network. See test/probe.test.mjs.
 *
 * @param {string} stdout
 * @returns {{facts: object, limited: string[]}}
 */
export function assembleFacts(stdout, { durationMs = 0 } = {}) {
  const s = p.parseSections(stdout);
  const limited = [];

  /* ---- identity ---- */
  const os = p.parseOsRelease(s.osrelease);
  const uname = p.parseUname(s.uname);
  const uptimeSeconds = p.parseUptime(s.uptime);
  const hostClock = num(s.now);

  /* ---- load and memory ---- */
  const cores = num(s.ncpu);
  const load = p.parseLoadavg(s.loadavg);
  const memory = p.parseMeminfo(s.meminfo);

  /* ---- disks: usage and inodes are two commands, one concept ---- */
  const df = p.parseDf(s.df);
  const inodes = p.parseDfInodes(s.dfi);
  if (!df) limited.push('disks');
  const inodeByMount = new Map((inodes ?? []).map((i) => [i.mount, i]));
  const disks = (df ?? []).map((d) => ({ ...d, ...(inodeByMount.get(d.mount) ?? { inodesTotal: null, inodesUsed: null, inodesUsedPct: null }) }));

  /* ---- ports ---- */
  const ports = p.parsePorts(s.ports);
  if (!ports) limited.push('ports');
  // Without sudo, `ss` names only the processes this login owns. If nothing
  // exposed has a name, we are looking through a keyhole and should say so
  // rather than render a table of blanks.
  const named = (ports ?? []).filter((x) => x.process).length;
  if (ports && ports.length > 0 && named < ports.length) limited.push('port-process-names');

  /* ---- services ---- */
  const failedUnits = p.parseFailedUnits(s.failedunits);
  const systemState = s.systemstate || null;
  if (failedUnits === null || (!systemState && !failedUnits?.length)) limited.push('failed-units');

  /* ---- updates ---- */
  const manager = s.pkgmgr || 'unknown';
  let updates = null;
  if (manager === 'apt') updates = p.parseAptUpgrade(s.aptupgrade ?? '');
  else if (manager === 'dnf' || manager === 'yum') updates = p.parseDnfUpdates(s.dnfupdates ?? '', s.dnfsecurity ?? '');

  if (updates) {
    updates.manager = manager;
    const stamp = num(s.aptstamp) ?? num(s.dnfstamp);
    // Measured against the host's own clock, so a skewed server does not
    // produce a negative age.
    updates.listsAgeSeconds = stamp && hostClock ? Math.max(0, hostClock - stamp) : null;
    // dnf's security metadata is a separate download that many minimal images
    // never fetch. Zero security updates from an empty advisory list is not a
    // measurement, and saying so is the difference between honest and useless.
    updates.securityKnown = manager === 'apt' ? true : Boolean(String(s.dnfsecurity ?? '').trim());
  } else {
    limited.push('updates');
  }

  /* ---- reboot ---- */
  const runningKernel = s.kernelrunning || uname?.kernelRelease || null;
  const latestKernel = s.kernellatest || null;
  const reboot = {
    required: s.rebootrequired === 'yes' || s.needsrestart === 'yes',
    source: s.rebootrequired === 'yes' ? 'reboot-required' : s.needsrestart === 'yes' ? 'needs-restarting' : null,
    packages: (s.rebootpkgs || '').split('\n').map((x) => x.trim()).filter(Boolean).slice(0, 40),
    runningKernel,
    latestKernel,
    // A kernel newer than the running one is installed and waiting for a boot.
    // This catches hosts where reboot-required was cleaned up but the reboot
    // never happened.
    kernelStale: Boolean(runningKernel && latestKernel && runningKernel !== latestKernel),
  };

  /* ---- security ---- */
  const sshdSource = s.sshdsource || 'none';
  if (sshdSource !== 'effective') limited.push('sshd-effective');
  const authSource = s.authsrc || 'none';
  if (authSource === 'none') limited.push('auth-failures');

  const security = {
    sshd: p.parseSshd(s.sshd),
    sshdSource,
    authSource,
    authFailures24h: authSource === 'none' ? null : num(s.authfail),
    hasSudo: s.sudo === 'yes',
    loggedInUsers: (s.who || '').split('\n').filter((l) => l.trim()).length,
  };

  /* ---- processes ---- */
  const processes = {
    topCpu: p.parseProcesses(s.pscpu) ?? [],
    topMem: p.parseProcesses(s.psmem) ?? [],
    zombies: num(s.zombies) ?? 0,
  };

  /* ---- clock ---- */
  // Our own clock is the reference. Both are UTC epoch seconds, so this is a
  // true skew and not a timezone artefact.
  const skewSeconds = hostClock ? Math.round(Date.now() / 1000) - hostClock : null;

  const facts = {
    collectedAt: new Date().toISOString(),
    durationMs,
    host: {
      hostname: s.hostname || null,
      os,
      kernel: uname?.kernelRelease ?? null,
      arch: uname?.arch ?? null,
      virt: s.virt || null,
      uptimeSeconds,
      bootedAt: uptimeSeconds ? new Date(Date.now() - uptimeSeconds * 1000).toISOString() : null,
    },
    cpu: {
      cores,
      load1: load?.load1 ?? null,
      load5: load?.load5 ?? null,
      load15: load?.load15 ?? null,
      loadPerCore: load && cores ? p.round2(load.load15 / cores) : null,
      runnable: load?.runnable ?? null,
      processes: load?.processes ?? null,
    },
    memory,
    disks,
    ports: ports ?? [],
    services: { failed: failedUnits ?? [], systemState },
    updates,
    reboot,
    security,
    processes,
    time: { ntpSynchronized: s.ntp === 'yes' ? true : s.ntp === 'no' ? false : null, skewSeconds },
  };

  return { facts, limited: [...new Set(limited)] };
}

/**
 * Collect one server: connect, run the probe, parse.
 *
 * @param {object} target host/port/username/privateKey/passphrase/hostKeyFp
 * @returns {Promise<{facts: object, limited: string[], hostKeyFp: string, durationMs: number}>}
 */
export async function collect(target) {
  const startedAt = Date.now();
  const res = await ssh.run(target, SCRIPT);
  const durationMs = Date.now() - startedAt;
  const { facts, limited } = assembleFacts(res.stdout, { durationMs });
  return { facts, limited, hostKeyFp: res.hostKeyFp, durationMs };
}

export { SCRIPT };
