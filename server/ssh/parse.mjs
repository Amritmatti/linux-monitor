// ---------------------------------------------------------------------------
// Probe output parsers.
//
// Every function here is pure: text in, structure out. That is deliberate -
// it is the only way to test a collector against real machines you do not
// have, and test/parse.test.mjs feeds these the actual output of Ubuntu,
// Debian, RHEL and Alpine hosts.
//
// The rule throughout: a section that could not be read parses to null, never
// to zero. "No security updates" and "we could not ask about security updates"
// are different answers, and a monitoring product that confuses them is worse
// than no monitoring product.
// ---------------------------------------------------------------------------

/** The marker the probe script wraps each section in. */
export const SECTION = '@@VG:';

/** Split raw probe stdout into { sectionName: text }. */
export function parseSections(stdout) {
  const out = {};
  if (!stdout) return out;
  let current = null;
  let buf = [];
  for (const line of String(stdout).split('\n')) {
    const m = line.match(/^@@VG:([a-z0-9_]+)@@\s*$/i);
    if (m) {
      if (current) out[current] = buf.join('\n').trim();
      current = m[1];
      buf = [];
    } else if (current) {
      buf.push(line);
    }
  }
  if (current) out[current] = buf.join('\n').trim();
  return out;
}

const int = (v) => {
  const s = String(v ?? '').trim();
  // Empty is unknown, not zero. Number('') is 0, which would silently invent a
  // measurement out of a column that was not there.
  if (!s) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
};

const nonEmpty = (s) => (s && String(s).trim() ? String(s).trim() : null);

/* ------------------------------------------------------------------- identity */

/** /etc/os-release into a plain object, quotes stripped. */
export function parseOsRelease(text) {
  if (!nonEmpty(text)) return null;
  const out = {};
  for (const line of text.split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (!m) continue;
    out[m[1]] = m[2].replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
  }
  if (!Object.keys(out).length) return null;
  return {
    id: out.ID ?? null,
    idLike: out.ID_LIKE ? out.ID_LIKE.split(/\s+/) : [],
    name: out.PRETTY_NAME ?? out.NAME ?? null,
    version: out.VERSION_ID ?? null,
    // Debian and Ubuntu publish this; it is how "is this release still getting
    // security patches" gets answered without a network call from the host.
    versionCodename: out.VERSION_CODENAME ?? null,
  };
}

/** `uname -s -r -m` -> { kernelName, kernelRelease, arch }. */
export function parseUname(text) {
  const parts = nonEmpty(text)?.split(/\s+/) ?? [];
  if (parts.length < 3) return null;
  return { kernelName: parts[0], kernelRelease: parts[1], arch: parts[2] };
}

/** /proc/uptime -> seconds. */
export function parseUptime(text) {
  const first = nonEmpty(text)?.split(/\s+/)[0];
  const n = Number(first);
  return Number.isFinite(n) ? Math.round(n) : null;
}

/** /proc/loadavg -> { load1, load5, load15, runnable, total }. */
export function parseLoadavg(text) {
  const p = nonEmpty(text)?.split(/\s+/) ?? [];
  if (p.length < 3) return null;
  const procs = (p[3] ?? '').split('/');
  return {
    load1: Number(p[0]),
    load5: Number(p[1]),
    load15: Number(p[2]),
    runnable: int(procs[0]),
    processes: int(procs[1]),
  };
}

/* --------------------------------------------------------------------- memory */

/** /proc/meminfo -> bytes. Values in the file are kB. */
export function parseMeminfo(text) {
  if (!nonEmpty(text)) return null;
  const kv = {};
  for (const line of text.split('\n')) {
    const m = line.match(/^(\w+):\s+(\d+)(?:\s+kB)?/);
    if (m) kv[m[1]] = Number(m[2]) * 1024;
  }
  if (kv.MemTotal === undefined) return null;

  // MemAvailable is the kernel's own estimate of what a new workload could get
  // without swapping. It is the only honest "free memory" number on Linux -
  // MemFree looks alarming on every healthy machine because the page cache is
  // doing its job.
  const total = kv.MemTotal;
  const available = kv.MemAvailable ?? kv.MemFree ?? 0;
  const swapTotal = kv.SwapTotal ?? 0;
  const swapFree = kv.SwapFree ?? 0;
  return {
    total,
    free: kv.MemFree ?? 0,
    available,
    buffers: kv.Buffers ?? 0,
    cached: kv.Cached ?? 0,
    used: total - available,
    usedPct: total > 0 ? round2(((total - available) / total) * 100) : null,
    swapTotal,
    swapUsed: swapTotal - swapFree,
    swapUsedPct: swapTotal > 0 ? round2(((swapTotal - swapFree) / swapTotal) * 100) : null,
  };
}

/* ----------------------------------------------------------------------- disks */

// Pseudo-filesystems are always "100% full" or always empty and mean nothing.
// Reporting them is how a dashboard trains people to ignore disk alerts.
const IGNORED_FS = new Set([
  'tmpfs', 'devtmpfs', 'squashfs', 'overlay', 'aufs', 'devfs', 'proc', 'sysfs',
  'cgroup', 'cgroup2', 'ramfs', 'iso9660', 'efivarfs', 'autofs', 'nsfs', 'tracefs',
  'debugfs', 'mqueue', 'hugetlbfs', 'pstore', 'securityfs', 'configfs', 'fusectl',
  'binfmt_misc', 'rpc_pipefs', 'none',
]);

const IGNORED_MOUNT = /^\/(?:proc|sys|dev|run)(?:\/|$)|^\/snap\/|^\/var\/lib\/docker\/|^\/var\/snap\//;

function ignorable(filesystem, mount) {
  if (IGNORED_FS.has(filesystem)) return true;
  if (IGNORED_MOUNT.test(mount)) return true;
  return false;
}

/**
 * `df -P -B1` output. -P guarantees one record per line even when the device
 * name is long, which is the whole reason the probe asks for it.
 *
 * @returns {Array<{filesystem, mount, totalBytes, usedBytes, availBytes, usedPct}>}
 */
export function parseDf(text) {
  if (!nonEmpty(text)) return null;
  const out = [];
  const lines = text.split('\n');
  for (const line of lines.slice(1)) {
    const p = line.trim().split(/\s+/);
    if (p.length < 6) continue;
    const [filesystem, totalRaw, usedRaw, availRaw, capRaw] = p;
    const mount = p.slice(5).join(' ');
    const total = int(totalRaw);
    if (total === null || total <= 0) continue;
    if (ignorable(filesystem, mount)) continue;
    const used = int(usedRaw) ?? 0;
    const avail = int(availRaw) ?? 0;
    out.push({
      filesystem,
      mount,
      totalBytes: total,
      usedBytes: used,
      availBytes: avail,
      // df's own Capacity column rounds up and excludes reserved blocks, which
      // is what `df` shows a person, so it is what we report.
      usedPct: int(String(capRaw).replace('%', '')) ?? round2((used / total) * 100),
    });
  }
  return out.length ? out : null;
}

/** `df -P -i` output -> inode usage per mount. */
export function parseDfInodes(text) {
  if (!nonEmpty(text)) return null;
  const out = [];
  for (const line of text.split('\n').slice(1)) {
    const p = line.trim().split(/\s+/);
    if (p.length < 6) continue;
    const [filesystem, totalRaw, usedRaw, , capRaw] = p;
    const mount = p.slice(5).join(' ');
    const total = int(totalRaw);
    // Btrfs and ZFS report "-" for inodes because they do not have a fixed
    // table. Nothing to warn about, so nothing to report.
    if (total === null || total <= 0) continue;
    if (ignorable(filesystem, mount)) continue;
    out.push({
      filesystem,
      mount,
      inodesTotal: total,
      inodesUsed: int(usedRaw) ?? 0,
      inodesUsedPct: int(String(capRaw).replace('%', '')) ?? null,
    });
  }
  return out.length ? out : null;
}

/* ----------------------------------------------------------------------- ports */

/** "0.0.0.0:22" / "[::]:22" / "127.0.0.53%lo:53" / "*:80" -> { address, port }. */
function splitEndpoint(raw) {
  const s = String(raw);
  const idx = s.lastIndexOf(':');
  if (idx < 0) return null;
  let address = s.slice(0, idx);
  const port = int(s.slice(idx + 1));
  if (port === null) return null;
  address = address.replace(/%\w+$/, ''); // strip the %lo scope id
  if (address.startsWith('[') && address.endsWith(']')) address = address.slice(1, -1);
  if (address === '*' || address === '') address = '0.0.0.0';
  return { address, port };
}

/**
 * Is this socket reachable from off the machine?
 *
 * This is the single most important bit in the whole ports check: 5432 bound to
 * 127.0.0.1 is correct and normal, and 5432 bound to 0.0.0.0 may be a database
 * open to the internet. Treating them alike in either direction makes the check
 * useless.
 */
export function isExposed(address) {
  if (!address) return false;
  if (address === '0.0.0.0' || address === '::' || address === '*') return true;
  if (address === '127.0.0.1' || address === '::1' || address.startsWith('127.')) return false;
  // A specific address that is not loopback is still reachable by anything that
  // can route to it.
  return true;
}

/**
 * `ss -H -tulnp` first, `netstat -tulnp` as the fallback for hosts without
 * iproute2. Both formats are handled here because which one answered is an
 * accident of the distribution, not something the rest of the app should know.
 *
 * @returns {Array<{proto, address, port, process, pid, exposed}>}
 */
export function parsePorts(text) {
  if (!nonEmpty(text)) return null;
  const out = [];
  const seen = new Set();

  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    // netstat's header lines, and the "Active Internet connections" banner.
    if (/^(Proto|Active|Netid)\b/i.test(line)) continue;

    const p = line.split(/\s+/);
    const proto = (p[0] || '').toLowerCase();
    if (!/^(tcp|tcp6|udp|udp6)$/.test(proto)) continue;

    let endpoint = null;
    let procField = '';

    if (/^(LISTEN|UNCONN|ESTAB)$/i.test(p[1] || '')) {
      // ss: Netid State Recv-Q Send-Q Local Peer [users:(...)]
      if (!/^(LISTEN|UNCONN)$/i.test(p[1])) continue;
      endpoint = splitEndpoint(p[4]);
      procField = p.slice(6).join(' ');
    } else {
      // netstat: Proto Recv-Q Send-Q Local Foreign [State] PID/Program
      // UDP rows have no State column, which is why State is found by pattern
      // rather than by position.
      endpoint = splitEndpoint(p[3]);
      const stateIdx = p.findIndex((t, i) => i >= 5 && /^[A-Z_]+$/.test(t));
      if (proto.startsWith('tcp') && stateIdx >= 0 && p[stateIdx] !== 'LISTEN') continue;
      procField = p.slice(stateIdx >= 0 ? stateIdx + 1 : 5).join(' ');
    }
    if (!endpoint) continue;

    // ss:      users:(("sshd",pid=812,fd=3))
    // netstat: 812/sshd
    let processName = null;
    let pid = null;
    const ssMatch = procField.match(/\(\("([^"]+)",pid=(\d+)/);
    const netstatMatch = procField.match(/^(\d+)\/(\S+)/);
    if (ssMatch) {
      processName = ssMatch[1];
      pid = int(ssMatch[2]);
    } else if (netstatMatch) {
      pid = int(netstatMatch[1]);
      processName = netstatMatch[2];
    }

    const key = proto.replace('6', '') + ':' + endpoint.address + ':' + endpoint.port;
    if (seen.has(key)) continue;
    seen.add(key);

    out.push({
      proto: proto.startsWith('tcp') ? 'tcp' : 'udp',
      address: endpoint.address,
      port: endpoint.port,
      process: processName,
      pid,
      exposed: isExposed(endpoint.address),
    });
  }

  out.sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto) || a.address.localeCompare(b.address));
  return out;
}

/* --------------------------------------------------------------------- updates */

/**
 * `apt-get -s dist-upgrade` simulation lines.
 *
 * An update is a security update when its candidate came from an archive whose
 * name ends in -security. That is how apt itself decides, and it is why the
 * origin string in parentheses is parsed rather than the package name - there
 * is nothing about "libssl3" that says security, only about where the new
 * version is published from.
 */
export function parseAptUpgrade(text) {
  if (text === null || text === undefined) return null;
  const packages = [];
  for (const line of String(text).split('\n')) {
    const m = line.match(/^Inst\s+(\S+)\s+(?:\[([^\]]*)\]\s+)?\((\S+)\s+([^)]*)\)/);
    if (!m) continue;
    const [, name, currentVersion, newVersion, origin] = m;
    packages.push({
      name,
      currentVersion: currentVersion || null,
      newVersion,
      security: /-security/i.test(origin),
      origin: origin.trim(),
    });
  }
  return summariseUpdates(packages);
}

/**
 * `dnf -C list --upgrades` plus `dnf -C updateinfo list --security`.
 * The security advisory list names exact NEVRAs, so package identity is matched
 * on the base name rather than the full version string.
 */
export function parseDnfUpdates(listText, securityText) {
  if (listText === null || listText === undefined) return null;

  const securityNames = new Set();
  for (const line of String(securityText ?? '').split('\n')) {
    // RHSA-2024:1234 Important/Sec.  openssl-1:3.0.7-24.el9.x86_64
    const m = line.trim().match(/\s(\S+)\s*$/);
    if (!m) continue;
    const base = m[1].replace(/\.(x86_64|noarch|aarch64|i686|armv7hl|s390x|ppc64le)$/, '').replace(/-[^-]*-[^-]*$/, '');
    if (base) securityNames.add(base);
  }

  const packages = [];
  for (const line of String(listText).split('\n')) {
    const t = line.trim();
    if (!t || /^(Last metadata|Available Upgrades|Obsoleting)/i.test(t)) continue;
    const p = t.split(/\s+/);
    if (p.length < 2) continue;
    const nameArch = p[0];
    if (!/\.\w+$/.test(nameArch)) continue;
    const name = nameArch.replace(/\.(x86_64|noarch|aarch64|i686|armv7hl|s390x|ppc64le)$/, '');
    packages.push({
      name,
      currentVersion: null,
      newVersion: p[1],
      security: securityNames.has(name),
      origin: p[2] ?? null,
    });
  }
  return summariseUpdates(packages);
}

function summariseUpdates(packages) {
  const security = packages.filter((p) => p.security);
  return {
    total: packages.length,
    security: security.length,
    // Capped for storage: the count is what drives every rule, and nobody reads
    // the 400th package name. The counts above stay exact.
    packages: packages.slice(0, 60),
    securityPackages: security.slice(0, 60).map((p) => p.name),
    truncated: packages.length > 60,
  };
}

/* -------------------------------------------------------------------- services */

/** `systemctl list-units --state=failed --no-legend --plain`. */
export function parseFailedUnits(text) {
  if (text === null || text === undefined) return null;
  const out = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    if (!line || /^\d+ loaded units/.test(line)) continue;
    const p = line.split(/\s+/);
    // UNIT LOAD ACTIVE SUB DESCRIPTION
    if (p.length < 4) continue;
    if (!p[0].includes('.')) continue;
    out.push({ unit: p[0], load: p[1], active: p[2], sub: p[3], description: p.slice(4).join(' ') || null });
  }
  return out;
}

/* ------------------------------------------------------------------- processes */

/** `ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu`. */
export function parseProcesses(text) {
  if (!nonEmpty(text)) return null;
  const out = [];
  for (const line of text.split('\n').slice(1)) {
    const p = line.trim().split(/\s+/);
    if (p.length < 5) continue;
    const pid = int(p[0]);
    if (pid === null) continue;
    out.push({ pid, user: p[1], cpu: Number(p[2]), mem: Number(p[3]), command: p.slice(4).join(' ') });
  }
  return out.length ? out : null;
}

/* --------------------------------------------------------------------- sshd */

/**
 * Effective sshd settings. `sshd -T` needs root, so the fallback is the config
 * file itself - which means an unset directive reads as absent here even though
 * sshd would apply its compiled-in default. Anything derived from this must
 * therefore only act on directives that are explicitly present, never on
 * their absence.
 */
export function parseSshd(text) {
  if (!nonEmpty(text)) return null;
  const out = {};
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^(\w+)[\s=]+(.+)$/);
    if (!m) continue;
    const key = m[1].toLowerCase();
    if (out[key] === undefined) out[key] = m[2].trim().replace(/\s+#.*$/, '');
  }
  return Object.keys(out).length ? out : null;
}

/* ------------------------------------------------------------------- helpers */

function round2(n) {
  return Math.round(n * 100) / 100;
}

export { round2 };

/* --------------------------------------------------------------------- docker */

/**
 * Docker's own size strings: "1.2GB", "0B", "435.7MB", "1.09kB (virtual 72.8MB)".
 *
 * `docker system df` formats with base-1000 units (kB, MB, GB) while other
 * subcommands sometimes emit base-1024 (KiB, MiB, GiB). Both are handled, and
 * they are not the same number - reporting a 7% error on reclaimable space is
 * the sort of thing that makes someone stop trusting the page.
 */
export function parseDockerSize(text) {
  const m = String(text ?? '').trim().match(/^(-?[\d.]+)\s*([kKMGTP]?i?B)\b/);
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n)) return null;
  const unit = m[2];
  const base = /iB$/i.test(unit) ? 1024 : 1000;
  const power = { b: 0, k: 1, m: 2, g: 3, t: 4, p: 5 }[unit[0].toLowerCase()] ?? 0;
  return Math.round(n * base ** power);
}

/**
 * `docker system df --format '{{.Type}}\t{{.TotalCount}}\t{{.Active}}\t{{.Size}}\t{{.Reclaimable}}'`
 *
 * This is the authoritative reclaimable figure - it is what `docker system
 * prune` would actually free - so it is preferred over anything summed from the
 * per-object listings.
 */
export function parseDockerDf(text) {
  if (!nonEmpty(text)) return null;
  const out = {};
  for (const line of text.split('\n')) {
    const p = line.split('\t');
    if (p.length < 5) continue;
    const key = p[0].trim().toLowerCase().replace(/\s+/g, '-');
    out[key] = {
      total: int(p[1]) ?? 0,
      active: int(p[2]) ?? 0,
      bytes: parseDockerSize(p[3]) ?? 0,
      reclaimableBytes: parseDockerSize(p[4]) ?? 0,
    };
  }
  return Object.keys(out).length ? out : null;
}

/** Health and restart state live inside the Status string, not in State. */
function statusDetail(status) {
  const s = String(status ?? '');
  return {
    healthy: /\(healthy\)/i.test(s) ? true : /\(unhealthy\)/i.test(s) ? false : null,
    exitCode: (s.match(/Exited \((\d+)\)/) || [])[1] ?? null,
  };
}

/**
 * `docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.RunningFor}}\t{{.Size}}'`
 */
export function parseDockerContainers(text) {
  if (text === null || text === undefined) return null;
  const out = [];
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    const p = line.split('\t');
    if (p.length < 5) continue;
    const detail = statusDetail(p[4]);
    out.push({
      id: p[0].trim(),
      name: p[1].trim(),
      image: p[2].trim(),
      state: p[3].trim().toLowerCase(),
      status: p[4].trim(),
      age: (p[5] ?? '').trim() || null,
      // The writable layer only; the image underneath is counted separately.
      sizeBytes: parseDockerSize(p[6]) ?? 0,
      healthy: detail.healthy,
      exitCode: detail.exitCode === null ? null : Number(detail.exitCode),
    });
  }
  return out;
}

/** `docker images --format '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}'` */
export function parseDockerImages(text) {
  if (text === null || text === undefined) return null;
  const out = [];
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    const p = line.split('\t');
    if (p.length < 4) continue;
    const repo = p[1].trim();
    const tag = p[2].trim();
    out.push({
      id: p[0].trim(),
      repository: repo,
      tag,
      // Docker shows an untagged image as <none>:<none>; that is what dangling
      // means, and it is the bulk of what a build server wastes space on.
      dangling: repo === '<none>' || tag === '<none>',
      name: repo === '<none>' ? p[0].trim() : repo + ':' + tag,
      sizeBytes: parseDockerSize(p[3]) ?? 0,
      createdAt: (p[4] ?? '').trim() || null,
    });
  }
  return out;
}

/** `docker volume ls --format '{{.Name}}\t{{.Driver}}'` */
export function parseDockerVolumes(text) {
  if (text === null || text === undefined) return null;
  const out = [];
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    const p = line.split('\t');
    out.push({ name: p[0].trim(), driver: (p[1] ?? '').trim() || null });
  }
  return out;
}
