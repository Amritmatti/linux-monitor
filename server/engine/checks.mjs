// ---------------------------------------------------------------------------
// The rules.
//
// facts -> findings. One question each, and every finding must carry three
// things or it does not get emitted:
//
//   * the measurement it is based on, so nobody has to trust the rule
//   * a severity that means something specific (see SEVERITY below)
//   * what to do about it, as a command where a command exists
//
// A finding whose remedy is "investigate" is a notification, not a finding, and
// this file does not raise those.
//
// `key` is stable across scans - it is what an acknowledgement is stored
// against - so it must be derived from identity (mount point, unit name, port)
// and never from a value that moves.
// ---------------------------------------------------------------------------

import { round1 } from './stats.mjs';

/**
 * critical - acting today is cheaper than acting tomorrow. Something is broken,
 *            exposed, or will break within days on the current trajectory.
 * warning  - real, wants scheduling, will not bite this week.
 * info     - context worth having on the page, not worth waking anyone for.
 */
export const SEVERITY = ['critical', 'warning', 'info'];
export const SEVERITY_RANK = { critical: 0, warning: 1, info: 2 };

/* ------------------------------------------------------------------ thresholds */

const T = {
  diskCritical: 90,
  diskWarning: 80,
  inodeCritical: 90,
  inodeWarning: 85,
  memCriticalAvailPct: 5,
  memWarningAvailPct: 10,
  swapWarningPct: 80,
  loadCriticalPerCore: 2,
  loadWarningPerCore: 1,
  authFailCritical: 500,
  authFailWarning: 100,
  clockCriticalSeconds: 300,
  clockWarningSeconds: 60,
  zombieWarning: 20,
  packageListStaleDays: 7,
  uptimeStaleDays: 365,
  dockerReclaimWarnBytes: 5 * 1024 ** 3,
  dockerReclaimCriticalBytes: 20 * 1024 ** 3,
  dockerExitedWarn: 5,
  dockerExitedCritical: 25,
};

/**
 * Ports that should essentially never face the internet. Each one is a service
 * that either holds data or grants execution, and most ship with no
 * authentication at all in their default configuration.
 */
const RISKY_PORTS = {
  23: { name: 'Telnet', why: 'credentials and session traffic are sent in clear text' },
  21: { name: 'FTP', why: 'credentials are sent in clear text' },
  111: { name: 'rpcbind', why: 'enumerates RPC services and is a known reflection amplifier' },
  135: { name: 'MSRPC', why: 'should never be reachable off a trusted network' },
  139: { name: 'NetBIOS', why: 'legacy file sharing, routinely exploited' },
  445: { name: 'SMB', why: 'file sharing; the vector for most worm families of the last decade' },
  1433: { name: 'Microsoft SQL Server', why: 'a database engine reachable from anywhere that can route to it' },
  2049: { name: 'NFS', why: 'file export, commonly with no authentication' },
  2375: { name: 'Docker API (plaintext)', why: 'unauthenticated root-equivalent execution on this host' },
  2376: { name: 'Docker API (TLS)', why: 'root-equivalent execution; safe only if client certificates are enforced' },
  2379: { name: 'etcd', why: 'holds cluster state and secrets, frequently unauthenticated' },
  3306: { name: 'MySQL / MariaDB', why: 'a database engine reachable from anywhere that can route to it' },
  3389: { name: 'RDP', why: 'a remote desktop; a perennial brute-force and exploit target' },
  4444: { name: 'Metasploit default handler', why: 'a listener on this port is a strong indicator of compromise' },
  5432: { name: 'PostgreSQL', why: 'a database engine reachable from anywhere that can route to it' },
  5672: { name: 'AMQP / RabbitMQ', why: 'message broker, often with the default guest account' },
  5900: { name: 'VNC', why: 'remote desktop, frequently with no password and no encryption' },
  5984: { name: 'CouchDB', why: 'a database with a history of unauthenticated remote access' },
  6379: { name: 'Redis', why: 'no authentication by default, and CONFIG SET gives file write' },
  9200: { name: 'Elasticsearch', why: 'no authentication in older defaults; full read and write of every index' },
  9300: { name: 'Elasticsearch transport', why: 'joins the cluster; reachable means it can be joined' },
  11211: { name: 'Memcached', why: 'no authentication, and a 50,000x UDP reflection amplifier' },
  15672: { name: 'RabbitMQ management UI', why: 'admin console, often with the default guest account' },
  27017: { name: 'MongoDB', why: 'the database behind more public data leaks than any other' },
  50070: { name: 'Hadoop NameNode', why: 'cluster filesystem administration' },
};

/** Failed units that mean the machine is meaningfully broken, not just untidy. */
const IMPORTANT_UNIT = /^(ssh|sshd|docker|containerd|kubelet|nginx|apache2|httpd|postgresql|mysql|mariadb|redis|firewalld|ufw|fail2ban|cron|crond|systemd-journald|systemd-networkd|networking|NetworkManager|chronyd|systemd-timesyncd|ntp)(@|\.|$)/;

/**
 * Releases past their final security update. A server on one of these is not
 * "a bit behind" - it is receiving no patches at all, which makes every other
 * update number on its page meaningless.
 */
const EOL_RELEASES = {
  'ubuntu:14.04': 'April 2019 (ESM aside)',
  'ubuntu:16.04': 'April 2021 (ESM aside)',
  'ubuntu:18.04': 'May 2023 (ESM aside)',
  'ubuntu:20.10': 'July 2021',
  'ubuntu:21.04': 'January 2022',
  'ubuntu:21.10': 'July 2022',
  'ubuntu:22.10': 'July 2023',
  'ubuntu:23.04': 'January 2024',
  'ubuntu:23.10': 'July 2024',
  'debian:8': 'June 2020',
  'debian:9': 'June 2022',
  'debian:10': 'June 2024',
  'centos:6': 'November 2020',
  'centos:7': 'June 2024',
  'centos:8': 'December 2021',
  'rhel:6': 'November 2020',
  'rhel:7': 'June 2024',
  'fedora:37': 'December 2023',
  'fedora:38': 'May 2024',
};

const DAY = 86400;

/* --------------------------------------------------------------------- helpers */

function bytes(n) {
  if (!Number.isFinite(n)) return '--';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return (n < 0 ? '-' : '') + (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
}

function days(seconds) {
  if (!Number.isFinite(seconds)) return '--';
  const d = seconds / DAY;
  if (d < 1) return Math.round(seconds / 3600) + ' hours';
  if (d < 60) return Math.round(d) + ' days';
  return round1(d / 30.44) + ' months';
}

function finding(f) {
  return { evidence: [], remedy: null, value: null, ...f };
}

/* ----------------------------------------------------------------------- rules */

function checkDisks(facts, out) {
  for (const d of facts.disks ?? []) {
    const free = bytes(d.availBytes);

    if (d.usedPct >= T.diskWarning) {
      const critical = d.usedPct >= T.diskCritical;
      out.push(
        finding({
          key: 'disk:usage:' + d.mount,
          severity: critical ? 'critical' : 'warning',
          category: 'Disk',
          title: d.mount + ' is ' + d.usedPct + '% full',
          detail:
            free + ' free of ' + bytes(d.totalBytes) + ' on ' + d.filesystem + '. ' +
            (critical
              ? 'At this level a log burst or a package upgrade can fill the filesystem, and a full root filesystem takes services down with it.'
              : 'Not urgent, but worth clearing before it becomes urgent.'),
          value: d.usedPct,
          evidence: [
            { label: 'Used', value: d.usedPct + '%' },
            { label: 'Free', value: free },
            { label: 'Size', value: bytes(d.totalBytes) },
            { label: 'Device', value: d.filesystem },
          ],
          remedy: 'du -xh --max-depth=1 ' + d.mount + ' 2>/dev/null | sort -h | tail -20',
        })
      );
    }

    // Inodes are the failure nobody predicts: df shows space free and writes
    // still fail. Almost always a directory full of small files - a mail spool,
    // a session store, an unrotated cache.
    if (Number.isFinite(d.inodesUsedPct) && d.inodesUsedPct >= T.inodeWarning) {
      out.push(
        finding({
          key: 'disk:inodes:' + d.mount,
          severity: d.inodesUsedPct >= T.inodeCritical ? 'critical' : 'warning',
          category: 'Disk',
          title: d.mount + ' has used ' + d.inodesUsedPct + '% of its inodes',
          detail:
            'The filesystem still reports ' + free + ' free, but it is running out of inodes, and when they are gone writes fail ' +
            'with "No space left on device" while df shows space available.',
          value: d.inodesUsedPct,
          evidence: [
            { label: 'Inodes used', value: d.inodesUsedPct + '%' },
            { label: 'Inodes', value: d.inodesUsed?.toLocaleString('en-US') + ' of ' + d.inodesTotal?.toLocaleString('en-US') },
            { label: 'Space used', value: d.usedPct + '%' },
          ],
          remedy: "find " + d.mount + " -xdev -type d -printf '%h\\n' 2>/dev/null | sort | uniq -c | sort -rn | head -20",
        })
      );
    }
  }
}

function checkMemory(facts, out) {
  const m = facts.memory;
  if (!m || !m.total) return;

  const availPct = round1((m.available / m.total) * 100);
  if (availPct <= T.memWarningAvailPct) {
    const critical = availPct <= T.memCriticalAvailPct;
    out.push(
      finding({
        key: 'memory:available',
        severity: critical ? 'critical' : 'warning',
        category: 'Memory',
        title: 'Only ' + availPct + '% of memory is available',
        detail:
          bytes(m.available) + ' available of ' + bytes(m.total) + '. ' +
          (critical
            ? 'The OOM killer becomes likely at this level, and it chooses what to kill by its own scoring, not by what matters to you.'
            : 'Headroom is thin enough that a traffic spike could push this host into swap.'),
        value: availPct,
        evidence: [
          { label: 'Available', value: bytes(m.available) },
          { label: 'Total', value: bytes(m.total) },
          // Reported because MemFree looks alarming on every healthy Linux box
          // and someone always asks about it.
          { label: 'Cached (reclaimable)', value: bytes(m.cached) },
          { label: 'Top consumer', value: facts.processes?.topMem?.[0] ? facts.processes.topMem[0].command + ' (' + facts.processes.topMem[0].mem + '%)' : '--' },
        ],
        remedy: 'ps -eo pid,user,pmem,rss,comm --sort=-rss | head -15',
      })
    );
  }

  if (m.swapTotal > 0 && m.swapUsedPct >= T.swapWarningPct) {
    out.push(
      finding({
        key: 'memory:swap',
        severity: 'warning',
        category: 'Memory',
        title: 'Swap is ' + round1(m.swapUsedPct) + '% used',
        detail:
          bytes(m.swapUsed) + ' of ' + bytes(m.swapTotal) + ' swap is in use. Once swap fills too, the next allocation failure ' +
          'is an OOM kill rather than a slowdown.',
        value: m.swapUsedPct,
        evidence: [
          { label: 'Swap used', value: bytes(m.swapUsed) + ' / ' + bytes(m.swapTotal) },
          { label: 'Memory available', value: bytes(m.available) },
        ],
        remedy: "for f in /proc/*/status; do awk '/^(Name|VmSwap)/{printf \"%s \", $2} END{print \"\"}' $f; done | sort -k2 -n | tail -15",
      })
    );
  }
}

function checkLoad(facts, out) {
  const c = facts.cpu;
  if (!c || !Number.isFinite(c.loadPerCore)) return;

  if (c.loadPerCore >= T.loadWarningPerCore) {
    const critical = c.loadPerCore >= T.loadCriticalPerCore;
    out.push(
      finding({
        key: 'cpu:load',
        severity: critical ? 'critical' : 'warning',
        category: 'CPU',
        title: '15-minute load is ' + round1(c.loadPerCore) + '× the core count',
        detail:
          'Load average ' + c.load15 + ' across ' + c.cores + ' cores. ' +
          (critical
            ? 'Sustained at twice the core count, work is queuing faster than it clears and latency is compounding.'
            : 'The machine is saturated: every runnable task is now waiting behind another.'),
        value: c.loadPerCore,
        evidence: [
          { label: 'Load 1 / 5 / 15m', value: c.load1 + ' / ' + c.load5 + ' / ' + c.load15 },
          { label: 'Cores', value: String(c.cores) },
          { label: 'Runnable now', value: c.runnable + ' of ' + c.processes + ' processes' },
          { label: 'Top consumer', value: facts.processes?.topCpu?.[0] ? facts.processes.topCpu[0].command + ' (' + facts.processes.topCpu[0].cpu + '%)' : '--' },
        ],
        remedy: 'ps -eo pid,user,pcpu,comm --sort=-pcpu | head -15',
      })
    );
  }

  if ((facts.processes?.zombies ?? 0) >= T.zombieWarning) {
    out.push(
      finding({
        key: 'cpu:zombies',
        severity: 'warning',
        category: 'CPU',
        title: facts.processes.zombies + ' zombie processes',
        detail:
          'Zombies hold a process table slot until their parent reaps them. This many means a parent process is not calling wait(), ' +
          'and the process table is a finite resource.',
        value: facts.processes.zombies,
        evidence: [{ label: 'Zombies', value: String(facts.processes.zombies) }],
        remedy: "ps -eo pid,ppid,stat,comm | awk '$3 ~ /^Z/'",
      })
    );
  }
}

function checkUpdates(facts, out) {
  const u = facts.updates;
  if (!u) return;

  if (u.security > 0) {
    const rebootToo = facts.reboot?.required;
    out.push(
      finding({
        key: 'updates:security',
        severity: 'critical',
        category: 'Updates',
        title: u.security + ' security update' + (u.security === 1 ? '' : 's') + ' pending',
        detail:
          'These are published fixes for known, catalogued vulnerabilities on a machine that is reachable enough for you to be ' +
          'monitoring it. ' + (rebootToo ? 'A reboot is also outstanding, so some already-installed fixes are not running either.' : ''),
        value: u.security,
        evidence: [
          { label: 'Security updates', value: String(u.security) },
          { label: 'All updates', value: String(u.total) },
          { label: 'Packages', value: (u.securityPackages ?? []).slice(0, 6).join(', ') || '--' },
          { label: 'Package manager', value: u.manager },
        ],
        remedy: u.manager === 'apt' ? 'sudo apt-get update && sudo apt-get -y upgrade' : 'sudo dnf -y update --security',
      })
    );
  }

  if (u.total > 0 && u.security === 0) {
    out.push(
      finding({
        key: 'updates:available',
        severity: 'info',
        category: 'Updates',
        title: u.total + ' package update' + (u.total === 1 ? '' : 's') + ' available',
        detail: 'None of them are flagged as security updates.',
        value: u.total,
        evidence: [{ label: 'Updates', value: String(u.total) }, { label: 'Package manager', value: u.manager }],
        remedy: u.manager === 'apt' ? 'sudo apt-get update && sudo apt-get -y upgrade' : 'sudo dnf -y update',
      })
    );
  }

  // The most quietly dangerous state in this whole file: counts computed from
  // package lists that have not been refreshed are not just stale, they are
  // reassuring. "0 security updates" from a six-month-old list is a lie the
  // dashboard would otherwise tell with a green tick.
  if (Number.isFinite(u.listsAgeSeconds) && u.listsAgeSeconds > T.packageListStaleDays * DAY) {
    out.push(
      finding({
        key: 'updates:stale-lists',
        severity: 'warning',
        category: 'Updates',
        title: 'Package lists were last refreshed ' + days(u.listsAgeSeconds) + ' ago',
        detail:
          'Every update count on this page is computed from those lists, so they are a floor, not a measurement. A security update ' +
          'published since then does not appear here at all.',
        value: u.listsAgeSeconds / DAY,
        evidence: [
          { label: 'Lists age', value: days(u.listsAgeSeconds) },
          { label: 'Reported security updates', value: String(u.security) },
        ],
        remedy: u.manager === 'apt' ? 'sudo apt-get update' : 'sudo dnf makecache',
      })
    );
  }

  if (u.securityKnown === false) {
    out.push(
      finding({
        key: 'updates:no-security-metadata',
        severity: 'warning',
        category: 'Updates',
        title: 'Security advisory metadata is not installed',
        detail:
          'dnf has no updateinfo data on this host, so security updates cannot be told apart from ordinary ones. The security count ' +
          'for this server is unknown, not zero.',
        evidence: [{ label: 'Total updates', value: String(u.total) }],
        remedy: 'sudo dnf install -y dnf-plugins-core && sudo dnf makecache',
      })
    );
  }
}

function checkReboot(facts, out) {
  const r = facts.reboot;
  if (!r) return;

  if (r.required) {
    const withSecurity = (facts.updates?.security ?? 0) > 0;
    out.push(
      finding({
        key: 'reboot:required',
        severity: withSecurity ? 'critical' : 'warning',
        category: 'Kernel',
        title: 'A reboot is required',
        detail:
          'Updated packages are installed but the running system is still using the old code. ' +
          (withSecurity ? 'With security updates also pending, this host is unpatched in both directions at once.' : ''),
        evidence: [
          { label: 'Signalled by', value: r.source ?? 'the system' },
          { label: 'Packages', value: (r.packages ?? []).slice(0, 6).join(', ') || '--' },
          { label: 'Uptime', value: days(facts.host?.uptimeSeconds) },
        ],
        remedy: 'sudo shutdown -r +5 "Scheduled reboot to apply updates"',
      })
    );
  }

  if (r.kernelStale) {
    out.push(
      finding({
        key: 'reboot:kernel',
        severity: 'warning',
        category: 'Kernel',
        title: 'Running an older kernel than the one installed',
        detail:
          'Kernel ' + r.latestKernel + ' is installed but the machine is running ' + r.runningKernel + '. Kernel fixes only take ' +
          'effect after a reboot, so any vulnerability patched in the newer build is still live here.',
        evidence: [
          { label: 'Running', value: r.runningKernel },
          { label: 'Installed', value: r.latestKernel },
          { label: 'Uptime', value: days(facts.host?.uptimeSeconds) },
        ],
        remedy: 'sudo shutdown -r +5 "Scheduled reboot to load kernel ' + r.latestKernel + '"',
      })
    );
  }
}

function checkServices(facts, out) {
  const failed = facts.services?.failed ?? [];
  for (const unit of failed) {
    const important = IMPORTANT_UNIT.test(unit.unit);
    out.push(
      finding({
        key: 'service:failed:' + unit.unit,
        severity: important ? 'critical' : 'warning',
        category: 'Services',
        title: unit.unit + ' has failed',
        detail:
          (unit.description ? unit.description + '. ' : '') +
          (important
            ? 'This unit is part of how the machine works or how you reach it, so a failure here is not cosmetic.'
            : 'systemd has given up restarting it.'),
        evidence: [
          { label: 'Unit', value: unit.unit },
          { label: 'State', value: unit.active + ' / ' + unit.sub },
        ],
        remedy: 'systemctl status ' + unit.unit + ' --no-pager -l && journalctl -u ' + unit.unit + ' -n 50 --no-pager',
      })
    );
  }

  if (facts.services?.systemState === 'maintenance') {
    out.push(
      finding({
        key: 'service:system-state',
        severity: 'critical',
        category: 'Services',
        title: 'systemd is in maintenance mode',
        detail: 'The machine did not finish booting into its normal target. It is up enough to answer SSH and not much else.',
        evidence: [{ label: 'State', value: 'maintenance' }],
        remedy: 'systemctl list-units --state=failed --no-pager',
      })
    );
  }
}

function checkPorts(facts, out) {
  for (const port of facts.ports ?? []) {
    if (!port.exposed) continue;
    const risky = RISKY_PORTS[port.port];
    if (!risky) continue;
    out.push(
      finding({
        key: 'port:exposed:' + port.proto + ':' + port.port,
        severity: 'critical',
        category: 'Network',
        title: risky.name + ' is listening on ' + port.address + ':' + port.port,
        detail:
          'Bound to ' + (port.address === '0.0.0.0' || port.address === '::' ? 'every interface' : port.address) +
          ', so it is reachable by anything that can route to this host - ' + risky.why + '.',
        evidence: [
          { label: 'Socket', value: port.proto + '/' + port.port + ' on ' + port.address },
          { label: 'Process', value: port.process ? port.process + (port.pid ? ' (pid ' + port.pid + ')' : '') : 'not visible without sudo' },
          { label: 'Service', value: risky.name },
        ],
        remedy: 'ss -tulnp | grep :' + port.port + '   # then bind it to 127.0.0.1, or put it behind the firewall',
      })
    );
  }
}

function checkSecurity(facts, out) {
  const s = facts.security;
  if (!s) return;
  const sshd = s.sshd ?? {};

  // Only ever acts on directives that are explicitly present. When the config
  // file is the source rather than `sshd -T`, an absent directive means "not
  // set here", not "off" - see parseSshd.
  if (sshd.permitrootlogin === 'yes') {
    out.push(
      finding({
        key: 'security:permit-root-login',
        severity: 'critical',
        category: 'Security',
        title: 'sshd permits direct root login with a password',
        detail:
          'PermitRootLogin is set to yes. Every SSH brute-force on the internet tries root first, and a success is an immediate, ' +
          'unattributable full compromise - there is no second account to trace.',
        evidence: [
          { label: 'PermitRootLogin', value: sshd.permitrootlogin },
          { label: 'Read from', value: s.sshdSource === 'effective' ? 'sshd -T (effective)' : '/etc/ssh/sshd_config' },
          { label: 'Failed logins (24h)', value: s.authFailures24h === null ? 'not readable' : String(s.authFailures24h) },
        ],
        remedy: "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd",
      })
    );
  }

  if (sshd.permitemptypasswords === 'yes') {
    out.push(
      finding({
        key: 'security:empty-passwords',
        severity: 'critical',
        category: 'Security',
        title: 'sshd accepts accounts with empty passwords',
        detail: 'PermitEmptyPasswords is set to yes. Any account on this host with a blank password is a login with no credential at all.',
        evidence: [{ label: 'PermitEmptyPasswords', value: 'yes' }],
        remedy: "sudo sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd",
      })
    );
  }

  if (sshd.passwordauthentication === 'yes') {
    out.push(
      finding({
        key: 'security:password-auth',
        severity: 'warning',
        category: 'Security',
        title: 'sshd accepts password authentication',
        detail:
          'Passwords can be guessed at scale and keys cannot. With this on, the security of every account on the host is whatever ' +
          'its weakest password is.',
        evidence: [
          { label: 'PasswordAuthentication', value: 'yes' },
          { label: 'Failed logins (24h)', value: s.authFailures24h === null ? 'not readable' : String(s.authFailures24h) },
        ],
        remedy: "sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd",
      })
    );
  }

  if (Number.isFinite(s.authFailures24h) && s.authFailures24h >= T.authFailWarning) {
    const critical = s.authFailures24h >= T.authFailCritical;
    out.push(
      finding({
        key: 'security:auth-failures',
        severity: critical ? 'critical' : 'warning',
        category: 'Security',
        title: s.authFailures24h.toLocaleString('en-US') + ' failed SSH logins in 24 hours',
        detail:
          (critical ? 'This is a sustained brute-force attempt, not background noise. ' : 'Elevated enough to be someone trying rather than someone fat-fingering. ') +
          (sshd.passwordauthentication === 'yes'
            ? 'Password authentication is enabled on this host, so these attempts can succeed.'
            : 'Password authentication is off, so they cannot succeed - but the log volume and the CPU cost are real.'),
        value: s.authFailures24h,
        evidence: [
          { label: 'Failures (24h)', value: s.authFailures24h.toLocaleString('en-US') },
          { label: 'Password auth', value: sshd.passwordauthentication ?? 'not set in config' },
          { label: 'Source', value: s.authSource },
        ],
        remedy: 'sudo apt-get install -y fail2ban   # or restrict port 22 to known source ranges',
      })
    );
  }
}

function checkPlatform(facts, out) {
  const os = facts.host?.os;
  if (os?.id && os?.version) {
    const eol = EOL_RELEASES[os.id + ':' + os.version];
    if (eol) {
      out.push(
        finding({
          key: 'platform:eol',
          severity: 'critical',
          category: 'Security',
          title: (os.name ?? os.id + ' ' + os.version) + ' is past end of life',
          detail:
            'Support ended ' + eol + '. No security patches are being published for this release, so every other update number on ' +
            'this page describes a queue that will never be filled.',
          evidence: [
            { label: 'Release', value: os.name ?? os.id + ' ' + os.version },
            { label: 'Support ended', value: eol },
            { label: 'Uptime', value: days(facts.host?.uptimeSeconds) },
          ],
          remedy: 'Plan an in-place release upgrade or a rebuild onto a supported release.',
        })
      );
    }
  }

  const uptime = facts.host?.uptimeSeconds;
  if (Number.isFinite(uptime) && uptime > T.uptimeStaleDays * DAY) {
    out.push(
      finding({
        key: 'platform:uptime',
        severity: 'info',
        category: 'Kernel',
        title: 'Up for ' + days(uptime) + ' without a reboot',
        detail:
          'Long uptime is not itself a fault, but it means no kernel patch has been loaded in that time, and it means nobody has ' +
          'proven this machine can boot unattended recently.',
        value: uptime / DAY,
        evidence: [
          { label: 'Uptime', value: days(uptime) },
          { label: 'Running kernel', value: facts.reboot?.runningKernel ?? '--' },
        ],
        remedy: null,
      })
    );
  }
}

function checkClock(facts, out) {
  const t = facts.time;
  if (!t) return;

  if (Number.isFinite(t.skewSeconds) && Math.abs(t.skewSeconds) >= T.clockWarningSeconds) {
    const critical = Math.abs(t.skewSeconds) >= T.clockCriticalSeconds;
    out.push(
      finding({
        key: 'time:skew',
        severity: critical ? 'critical' : 'warning',
        category: 'Time',
        title: 'Clock is ' + Math.abs(Math.round(t.skewSeconds)) + 's ' + (t.skewSeconds > 0 ? 'behind' : 'ahead'),
        detail:
          'Measured against this dashboard. ' +
          (critical
            ? 'At this drift TLS certificates can fail validation, Kerberos and TOTP stop working, and log timestamps no longer line up with any other host.'
            : 'Enough to make correlating this host\'s logs with another\'s misleading.'),
        value: Math.abs(t.skewSeconds),
        evidence: [
          { label: 'Skew', value: Math.round(t.skewSeconds) + 's' },
          { label: 'NTP synchronised', value: t.ntpSynchronized === null ? 'unknown' : t.ntpSynchronized ? 'yes' : 'no' },
        ],
        remedy: 'timedatectl status && sudo systemctl restart systemd-timesyncd',
      })
    );
  } else if (t.ntpSynchronized === false) {
    out.push(
      finding({
        key: 'time:ntp',
        severity: 'warning',
        category: 'Time',
        title: 'Clock is not synchronised to a time source',
        detail: 'The clock is close enough for now, but nothing is keeping it there, so the drift only goes one way.',
        evidence: [{ label: 'NTP synchronised', value: 'no' }, { label: 'Current skew', value: Math.round(t.skewSeconds ?? 0) + 's' }],
        remedy: 'sudo timedatectl set-ntp true',
      })
    );
  }
}

function checkDocker(facts, out) {
  const d = facts.docker;
  if (!d || !d.installed || !d.accessible) return;

  const c = d.containers;
  const reclaim = d.reclaimableBytes ?? 0;

  // A container stuck restarting is not untidiness, it is an outage that keeps
  // announcing itself. This is the most valuable thing on this page.
  if (c.restarting > 0) {
    const names = c.items.filter((x) => x.state === 'restarting');
    out.push(
      finding({
        key: 'docker:restarting',
        severity: 'critical',
        category: 'Docker',
        title: c.restarting + ' container' + (c.restarting === 1 ? ' is' : 's are') + ' stuck restarting',
        detail:
          'Docker is restarting ' + names.map((x) => x.name).slice(0, 4).join(', ') +
          ' over and over, which means whatever it serves is down or flapping, and the restart loop is burning CPU while it happens.',
        value: c.restarting,
        evidence: [
          { label: 'Containers', value: names.map((x) => x.name).slice(0, 6).join(', ') || '--' },
          { label: 'Last status', value: names[0]?.status ?? '--' },
          { label: 'Image', value: names[0]?.image ?? '--' },
        ],
        remedy: 'docker logs --tail 100 ' + (names[0]?.name ?? '<container>'),
      })
    );
  }

  if (c.unhealthy > 0) {
    const names = c.items.filter((x) => x.healthy === false);
    out.push(
      finding({
        key: 'docker:unhealthy',
        severity: 'critical',
        category: 'Docker',
        title: c.unhealthy + ' container' + (c.unhealthy === 1 ? ' is' : 's are') + ' failing their health check',
        detail:
          'The container is up, so nothing has restarted it, but its own health check says it is not working. ' +
          'This is the state that silently serves errors.',
        value: c.unhealthy,
        evidence: [
          { label: 'Containers', value: names.map((x) => x.name).slice(0, 6).join(', ') || '--' },
          { label: 'Status', value: names[0]?.status ?? '--' },
        ],
        remedy: 'docker inspect --format "{{json .State.Health}}" ' + (names[0]?.name ?? '<container>'),
      })
    );
  }

  // Reclaimable space is judged against the filesystem it actually sits on.
  // 30 GB of images matters enormously on a 40 GB root and not at all on a 4 TB
  // volume, and a fixed byte threshold cannot tell those apart.
  const rootDisk = d.rootDir
    ? (facts.disks ?? [])
        .filter((disk) => d.rootDir.startsWith(disk.mount))
        .sort((a, b) => b.mount.length - a.mount.length)[0]
    : null;
  const shareOfDisk = rootDisk && rootDisk.totalBytes ? reclaim / rootDisk.totalBytes : null;
  const wouldRelieve = rootDisk && rootDisk.usedPct >= T.diskWarning && reclaim > 0;

  if (reclaim >= T.dockerReclaimWarnBytes || wouldRelieve) {
    const critical =
      reclaim >= T.dockerReclaimCriticalBytes ||
      (shareOfDisk !== null && shareOfDisk >= 0.25) ||
      (rootDisk && rootDisk.usedPct >= T.diskCritical && reclaim > 1024 ** 3);

    out.push(
      finding({
        key: 'docker:reclaimable',
        severity: critical ? 'critical' : 'warning',
        category: 'Docker',
        title: bytes(reclaim) + ' of Docker data is reclaimable',
        detail:
          'Stopped containers, unused images and build cache that nothing references. ' +
          (rootDisk
            ? 'Docker stores this on ' + rootDisk.mount + ', which is ' + rootDisk.usedPct + '% full' +
              (shareOfDisk !== null ? ' - reclaiming it would give back ' + Math.round(shareOfDisk * 100) + '% of that filesystem.' : '.')
            : 'Docker\'s data directory could not be matched to a filesystem, so this is reported on size alone.'),
        value: reclaim / 1024 ** 3,
        evidence: [
          { label: 'Images', value: bytes(d.reclaimable.images) },
          { label: 'Stopped containers', value: bytes(d.reclaimable.containers) },
          { label: 'Build cache', value: bytes(d.reclaimable.buildCache) },
          { label: 'Docker root', value: (d.rootDir ?? '--') + (rootDisk ? ' on ' + rootDisk.mount + ' (' + rootDisk.usedPct + '% full)' : '') },
          // Called out separately, and never in the headline, because pruning
          // volumes deletes data rather than freeing waste.
          { label: 'Unused volumes (data!)', value: bytes(d.reclaimable.volumes) + ' in ' + d.volumes.dangling + ' volumes' },
        ],
        remedy: 'docker system prune -f          # containers, dangling images and build cache; leaves volumes alone',
      })
    );
  }

  if (c.exited >= T.dockerExitedWarn) {
    out.push(
      finding({
        key: 'docker:exited',
        severity: c.exited >= T.dockerExitedCritical ? 'warning' : 'info',
        category: 'Docker',
        title: c.exited + ' exited containers are still on disk',
        detail:
          'Each one keeps its writable layer and its logs until it is removed. Individually small, collectively the thing that fills ' +
          'a build host, and they make `docker ps -a` unreadable when you are trying to find a real problem.',
        value: c.exited,
        evidence: [
          { label: 'Exited', value: String(c.exited) },
          { label: 'Running', value: String(c.running) },
          { label: 'Reclaimable', value: bytes(d.reclaimable.containers) },
          { label: 'Oldest', value: c.items.filter((x) => x.state === 'exited').slice(-1)[0]?.status ?? '--' },
        ],
        remedy: 'docker container prune -f',
      })
    );
  }

  if (d.images.dangling > 0 && d.images.danglingBytes >= 1024 ** 3) {
    out.push(
      finding({
        key: 'docker:dangling-images',
        severity: 'info',
        category: 'Docker',
        title: d.images.dangling + ' dangling images holding ' + bytes(d.images.danglingBytes),
        detail:
          'Untagged layers left behind when an image was rebuilt under the same tag. Nothing references them and nothing ever will.',
        value: d.images.danglingBytes / 1024 ** 3,
        evidence: [
          { label: 'Dangling images', value: String(d.images.dangling) },
          { label: 'Size', value: bytes(d.images.danglingBytes) },
          { label: 'Total images', value: String(d.images.total) },
        ],
        remedy: 'docker image prune -f',
      })
    );
  }
}

/* ------------------------------------------------------------------ entry point */

/**
 * @param {object} facts   output of ssh/probe.mjs
 * @returns {Array} findings, most severe first
 */
export function evaluate(facts) {
  const out = [];
  if (!facts) return out;

  checkDisks(facts, out);
  checkMemory(facts, out);
  checkLoad(facts, out);
  checkUpdates(facts, out);
  checkReboot(facts, out);
  checkServices(facts, out);
  checkPorts(facts, out);
  checkSecurity(facts, out);
  checkPlatform(facts, out);
  checkClock(facts, out);
  checkDocker(facts, out);

  out.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.category.localeCompare(b.category) || a.title.localeCompare(b.title));
  return out;
}

export { RISKY_PORTS, T as THRESHOLDS, bytes, days };
