// ---------------------------------------------------------------------------
// The hardening audit.
//
// checks.mjs asks "is this machine healthy?". This file asks "is this machine
// defensible?" - the standard Linux exposure classes, each one checked against
// what the probe could actually see, and each finding carrying the command that
// fixes it.
//
// Two rules run through everything here:
//
//   Unknown is reported as unknown. Most of these checks need root, and Vigil
//   is designed to run without it. A firewall that could not be read is not
//   "no firewall", and rendering it as a green tick would be worse than not
//   checking at all.
//
//   Nothing reads a secret to prove a secret is exposed. The finding for a
//   world-readable credentials file is its path and its mode. Shipping the
//   contents to a dashboard to demonstrate the problem would be committing the
//   same mistake a second time.
// ---------------------------------------------------------------------------

/** The classes this audit covers, in the order the UI presents them. */
export const AREAS = [
  { id: 'packages', label: 'Patching', blurb: 'Known CVEs fixed upstream and not yet installed here.' },
  { id: 'ssh', label: 'SSH exposure', blurb: 'Who can log in, and with what.' },
  { id: 'accounts', label: 'Accounts & credentials', blurb: 'Who exists, who is root, and who can become root.' },
  { id: 'sudo', label: 'Privilege escalation', blurb: 'sudo rules and root-equivalent group membership.' },
  { id: 'suid', label: 'SUID / SGID binaries', blurb: 'Programs that run as someone other than the caller.' },
  { id: 'kernel', label: 'Kernel', blurb: 'The version actually running, versus the one installed.' },
  { id: 'ports', label: 'Exposed services', blurb: 'What is listening, and whether it should be.' },
  { id: 'firewall', label: 'Firewall', blurb: 'The host layer, underneath any cloud security group.' },
  { id: 'permissions', label: 'File permissions', blurb: 'World-writable paths and the files guarding credentials.' },
  { id: 'secrets', label: 'Exposed secrets', blurb: 'Credential files readable by more than their owner.' },
  { id: 'injection', label: 'Command injection', blurb: 'An application concern, not a host one - see below.' },
  { id: 'cron', label: 'Scheduled jobs', blurb: 'Root cron running scripts that others can edit.' },
  { id: 'containers', label: 'Container posture', blurb: 'Privilege, identity and host access of running containers.' },
  { id: 'escape', label: 'Container escape', blurb: 'The paths out of a container onto the host.' },
  { id: 'mac', label: 'SELinux / AppArmor', blurb: 'Mandatory access control, the layer that holds when an app is compromised.' },
];

/**
 * SUID/SGID binaries that ship this way on a normal distribution. Anything
 * outside this list is not necessarily wrong, but it was put there by somebody
 * and is worth a look.
 */
const EXPECTED_SUID = new Set([
  'su', 'sudo', 'passwd', 'chsh', 'chfn', 'gpasswd', 'newgrp', 'mount', 'umount', 'pkexec',
  'fusermount', 'fusermount3', 'ping', 'ping6', 'chage', 'expiry', 'crontab', 'at', 'wall',
  'write', 'ssh-agent', 'ssh-keysign', 'unix_chkpwd', 'pam_extrausers_chkpwd', 'dbus-daemon-launch-helper',
  'polkit-agent-helper-1', 'postdrop', 'postqueue', 'exim4', 'mount.nfs', 'umount.nfs', 'utempter',
  'dotlockfile', 'mlocate', 'locate', 'screen', 'sg', 'staprun', 'vmware-user-suid-wrapper', 'suexec',
  'newuidmap', 'newgidmap', 'agetty', 'login', 'chrome-sandbox', 'snap-confine',
]);

/**
 * Interpreters, shells and file-manipulation tools. Any of these carrying the
 * setuid bit is a direct, documented path to root - each one has a published
 * one-liner - so it is treated as a probable compromise rather than as untidy
 * packaging.
 */
const DANGEROUS_SUID = new Set([
  'bash', 'sh', 'dash', 'zsh', 'ksh', 'csh', 'tcsh', 'busybox',
  'python', 'python2', 'python3', 'perl', 'ruby', 'php', 'node', 'lua', 'tclsh',
  'vi', 'vim', 'nvim', 'nano', 'emacs', 'ed', 'less', 'more', 'man', 'awk', 'gawk', 'mawk', 'sed',
  'find', 'cp', 'mv', 'dd', 'tar', 'zip', 'unzip', 'rsync', 'nmap', 'socat', 'nc', 'ncat', 'netcat',
  'env', 'ftp', 'gdb', 'git', 'make', 'docker', 'systemctl', 'wget', 'curl', 'base64', 'xxd', 'openssl',
  'ionice', 'nice', 'taskset', 'flock', 'time', 'watch', 'xargs', 'strace', 'ltrace',
]);

/** Capabilities that hand a container most of the host. */
const DANGEROUS_CAPS = new Set(['SYS_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'SYS_RAWIO', 'NET_ADMIN', 'ALL']);

const base = (p) => String(p ?? '').split('/').pop();

function finding(f) {
  return { evidence: [], remedy: null, value: null, category: 'Hardening', ...f };
}

/* ------------------------------------------------------------------- 2. ssh */

function checkSsh(h, facts, out) {
  const sshd = facts.security?.sshd ?? {};
  // Only acts on directives that are explicitly present - see parseSshd. The
  // root-login and password-auth rules live in checks.mjs; this adds the two
  // that complete the picture.
  if (sshd.pubkeyauthentication === 'no') {
    out.push(
      finding({
        key: 'harden:ssh:no-pubkey',
        area: 'ssh',
        severity: 'critical',
        title: 'sshd has public key authentication turned off',
        detail:
          'PubkeyAuthentication is set to no, so keys cannot be used and every login must fall back to a password. That is the ' +
          'opposite of the recommended posture, and it is usually a mistake nobody noticed because password login kept working.',
        evidence: [
          { label: 'PubkeyAuthentication', value: 'no' },
          { label: 'PasswordAuthentication', value: sshd.passwordauthentication ?? 'not set in config' },
        ],
        remedy: "sudo sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd",
      })
    );
  }

  if (sshd.protocol === '1') {
    out.push(
      finding({
        key: 'harden:ssh:protocol1',
        area: 'ssh',
        severity: 'critical',
        title: 'sshd is configured for SSH protocol 1',
        detail: 'Protocol 1 is cryptographically broken and has been removed from OpenSSH. Anything still offering it is very old and unpatched.',
        evidence: [{ label: 'Protocol', value: '1' }],
        remedy: "sudo sed -i '/^Protocol 1/d' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd",
      })
    );
  }

  // The combination is what matters: SSH open to the world is normal; SSH open
  // to the world accepting passwords is what gets brute-forced.
  const sshOpen = (facts.ports ?? []).some((p) => p.port === 22 && p.exposed);
  if (sshOpen && sshd.passwordauthentication === 'yes' && (h.firewall?.active === false || h.firewall?.readable === false)) {
    out.push(
      finding({
        key: 'harden:ssh:open-password',
        area: 'ssh',
        severity: 'critical',
        title: 'SSH accepts passwords, is reachable off-host, and no host firewall is confirmed',
        detail:
          'Each of those alone is survivable. Together they are the exact configuration that credential-stuffing bots are looking ' +
          'for, and the only thing standing in the way is the strength of every password on the machine.',
        evidence: [
          { label: 'Port 22', value: 'reachable off-host' },
          { label: 'PasswordAuthentication', value: 'yes' },
          { label: 'Host firewall', value: h.firewall?.readable ? 'inactive' : 'not readable' },
          { label: 'Failed logins (24h)', value: facts.security?.authFailures24h === null ? 'not readable' : String(facts.security?.authFailures24h) },
        ],
        remedy: "sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload sshd",
      })
    );
  }
}

/* -------------------------------------------------------------- 3. accounts */

function checkAccounts(h, out) {
  const accounts = h.accounts;
  if (!accounts) return;

  const uid0 = accounts.filter((a) => a.uid === 0 && a.name !== 'root');
  if (uid0.length) {
    out.push(
      finding({
        key: 'harden:accounts:uid0',
        area: 'accounts',
        severity: 'critical',
        title: uid0.length + ' account' + (uid0.length === 1 ? '' : 's') + ' other than root has UID 0',
        detail:
          'UID 0 is root - the name is only a label. These accounts have full privilege without appearing in sudo logs or in any ' +
          'sudoers review, which is why backdoors are commonly installed this way.',
        value: uid0.length,
        evidence: [
          { label: 'Accounts', value: uid0.map((a) => a.name).join(', ') },
          { label: 'Shells', value: uid0.map((a) => a.shell).join(', ') },
        ],
        remedy: "awk -F: '$3 == 0 {print $1}' /etc/passwd    # then remove or re-number anything that is not root",
      })
    );
  }
}

/* ------------------------------------------------------------------ 4. sudo */

function checkSudo(h, out) {
  const groups = h.groups ?? {};

  // Membership of the docker group is not a Docker question, it is a privilege
  // question: it is equivalent to passwordless root, and it never shows up in a
  // sudoers review because it is not in sudoers.
  const dockerMembers = groups.docker ?? [];
  if (dockerMembers.length) {
    out.push(
      finding({
        key: 'harden:sudo:docker-group',
        area: 'sudo',
        severity: 'warning',
        title: dockerMembers.length + ' account' + (dockerMembers.length === 1 ? ' is' : 's are') + ' in the docker group',
        detail:
          'The docker group is root-equivalent: a member can start a container that mounts the host filesystem and read or write ' +
          'anything on it, with no password and no sudo entry to audit. Treat membership as if it were "NOPASSWD: ALL".',
        value: dockerMembers.length,
        evidence: [
          { label: 'Members', value: dockerMembers.join(', ') },
          { label: 'Equivalent to', value: 'passwordless root' },
        ],
        remedy: 'sudo gpasswd -d <user> docker    # or move them to a rootless Docker context',
      })
    );
  }

  if (h.sudo?.nopasswdAll) {
    out.push(
      finding({
        key: 'harden:sudo:nopasswd-all',
        area: 'sudo',
        severity: 'critical',
        title: 'This login has passwordless sudo to everything',
        detail:
          'The monitoring account itself can become root without a password. Anyone who obtains this key - including anyone who ' +
          'compromises the machine Vigil runs on - owns the host outright.',
        evidence: [{ label: 'sudo -l', value: '(ALL) NOPASSWD: ALL' }],
        remedy: 'sudo visudo    # narrow this account to the specific commands it needs, or remove its sudo entirely',
      })
    );
  }
}

/* ------------------------------------------------------------------ 5. suid */

function checkSuid(h, out) {
  const items = h.suid;
  if (!items?.length) return;

  const dangerous = items.filter((i) => i.kind === 'suid' && DANGEROUS_SUID.has(base(i.path)));
  if (dangerous.length) {
    out.push(
      finding({
        key: 'harden:suid:dangerous',
        area: 'suid',
        severity: 'critical',
        title: dangerous.length + ' interpreter or shell utility carries the setuid bit',
        detail:
          'These are not ordinary setuid programs. Each of ' + dangerous.map((d) => base(d.path)).slice(0, 5).join(', ') +
          ' has a published one-line escalation to root when it is setuid, so this is either a serious misconfiguration or a ' +
          'backdoor somebody left behind.',
        value: dangerous.length,
        evidence: [
          { label: 'Binaries', value: dangerous.map((d) => d.mode + ' ' + d.path).slice(0, 6).join('  ') },
          { label: 'Effect', value: 'local user to root' },
        ],
        remedy: 'sudo chmod u-s ' + dangerous.slice(0, 4).map((d) => d.path).join(' '),
      })
    );
  }

  const unexpected = items.filter((i) => !EXPECTED_SUID.has(base(i.path)) && !DANGEROUS_SUID.has(base(i.path)));
  if (unexpected.length) {
    out.push(
      finding({
        key: 'harden:suid:unexpected',
        area: 'suid',
        severity: 'info',
        title: unexpected.length + ' setuid/setgid binary is not part of a stock install',
        detail:
          'Not necessarily wrong - packages do add them - but each one runs with privileges the caller does not have, so each is ' +
          'worth confirming you meant.',
        value: unexpected.length,
        evidence: [
          { label: 'Binaries', value: unexpected.map((d) => d.mode + ' ' + d.path).slice(0, 8).join('  ') },
          { label: 'Total setuid/setgid', value: String(items.length) },
        ],
        remedy: 'find / -xdev -perm -4000 -type f -exec ls -l {} +    # confirm each one belongs to a package you installed',
      })
    );
  }
}

/* -------------------------------------------------------------- 8. firewall */

function checkFirewall(h, facts, out) {
  const fw = h.firewall;
  if (!fw) return;

  if (!fw.readable) {
    // Reported as a limitation rather than a finding, because "we could not
    // look" is not a security state.
    return;
  }

  const exposed = (facts.ports ?? []).filter((p) => p.exposed).length;

  if (fw.active === false) {
    out.push(
      finding({
        key: 'harden:firewall:inactive',
        area: 'firewall',
        severity: exposed > 2 ? 'critical' : 'warning',
        title: 'No host firewall is active',
        detail:
          exposed + ' socket' + (exposed === 1 ? ' is' : 's are') + ' reachable off this host with nothing filtering them locally. ' +
          'A cloud security group in front is a different layer and a different owner; when it is edited by someone else, the host ' +
          'has no second line.',
        evidence: [
          { label: 'Tool', value: fw.tool ?? 'none installed' },
          { label: 'Exposed sockets', value: String(exposed) },
        ],
        remedy: fw.tool === 'firewalld' ? 'sudo systemctl enable --now firewalld' : 'sudo ufw default deny incoming && sudo ufw allow 22/tcp && sudo ufw enable',
      })
    );
  } else if (fw.active && fw.defaultInbound === 'allow') {
    out.push(
      finding({
        key: 'harden:firewall:default-allow',
        area: 'firewall',
        severity: 'warning',
        title: 'The firewall is running but its default inbound policy is allow',
        detail:
          'Rules are being evaluated, but anything not explicitly denied gets through - so every service that starts in future is ' +
          'exposed by default. A deny-by-default policy inverts that.',
        evidence: [
          { label: 'Tool', value: fw.tool },
          { label: 'Default inbound', value: 'allow' },
          { label: 'Rules', value: String(fw.rules) },
        ],
        remedy: fw.tool === 'ufw' ? 'sudo ufw default deny incoming' : 'sudo iptables -P INPUT DROP    # after confirming an allow rule for SSH exists',
      })
    );
  }
}

/* ----------------------------------------------------------- 9. permissions */

function checkPermissions(h, out) {
  const perms = h.permissions ?? {};

  const shadow = perms['/etc/shadow'];
  if (shadow && /[2467]$/.test(shadow.mode)) {
    out.push(
      finding({
        key: 'harden:permissions:shadow',
        area: 'permissions',
        severity: 'critical',
        title: '/etc/shadow is readable by everyone on the system',
        detail:
          'Mode ' + shadow.mode + '. Every local account can copy the password hashes and crack them offline, at their leisure, ' +
          'with no failed-login trail on this machine at all.',
        evidence: [
          { label: 'Mode', value: shadow.mode },
          { label: 'Owner', value: shadow.owner + ':' + shadow.group },
          { label: 'Expected', value: '640 root:shadow, or 600 root:root' },
        ],
        remedy: 'sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow',
      })
    );
  }

  for (const path of ['/etc/passwd', '/etc/group', '/etc/sudoers', '/etc/environment', '/etc/crontab']) {
    const f = perms[path];
    if (f && /[2367]$/.test(f.mode)) {
      out.push(
        finding({
          key: 'harden:permissions:writable:' + path,
          area: 'permissions',
          severity: 'critical',
          title: path + ' is writable by non-root users',
          detail:
            'Mode ' + f.mode + '. ' +
            (path === '/etc/environment'
              ? 'This file is sourced into every login session, so anyone who can write it can put a command or a PATH entry in front of every user on the machine, root included.'
              : 'Anyone who can write this file can grant themselves root, directly and permanently.'),
          evidence: [{ label: 'Mode', value: f.mode }, { label: 'Owner', value: f.owner + ':' + f.group }],
          remedy: 'sudo chmod 644 ' + path + ' && sudo chown root:root ' + path,
        })
      );
    }
  }

  const ww = h.worldWritable;
  if (ww?.dirs?.length) {
    out.push(
      finding({
        key: 'harden:permissions:world-writable-dirs',
        area: 'permissions',
        severity: 'critical',
        title: ww.dirs.length + ' world-writable director' + (ww.dirs.length === 1 ? 'y has' : 'ies have') + ' no sticky bit',
        detail:
          'Any user can create, replace or delete files in these. Where anything privileged reads from one - a cron script, a ' +
          'config include, a binary on PATH - that is a direct escalation route. /tmp is excluded: it is sticky, which is the fix.',
        value: ww.dirs.length,
        evidence: [{ label: 'Directories', value: ww.dirs.map((d) => d.mode + ' ' + d.path).slice(0, 6).join('  ') }],
        remedy: 'sudo chmod o-w ' + ww.dirs.slice(0, 4).map((d) => d.path).join(' ') + '    # or +t if it must stay shared',
      })
    );
  }

  if (ww?.files?.length) {
    out.push(
      finding({
        key: 'harden:permissions:world-writable-files',
        area: 'permissions',
        severity: 'warning',
        title: ww.files.length + ' world-writable file' + (ww.files.length === 1 ? '' : 's'),
        detail: 'Any local user can rewrite these. If one is a script, a unit file or a config that root reads, it is an escalation path.',
        value: ww.files.length,
        evidence: [{ label: 'Files', value: ww.files.map((f) => f.mode + ' ' + f.path).slice(0, 6).join('  ') }],
        remedy: 'sudo chmod o-w ' + ww.files.slice(0, 4).map((f) => f.path).join(' '),
      })
    );
  }
}

/* --------------------------------------------------------------- 10. secrets */

function checkSecrets(h, out) {
  const exposed = h.secrets?.worldReadable ?? [];
  if (exposed.length) {
    out.push(
      finding({
        key: 'harden:secrets:world-readable',
        area: 'secrets',
        severity: 'critical',
        title: exposed.length + ' credential file' + (exposed.length === 1 ? ' is' : 's are') + ' readable by every user',
        detail:
          'Files named like keys, .env files or credentials, with the world-read bit set. Vigil reports the path and the mode and ' +
          'has deliberately not opened any of them - proving the contents are exposed by copying them into a dashboard would be the ' +
          'same mistake again.',
        value: exposed.length,
        evidence: [
          { label: 'Files', value: exposed.slice(0, 6).join('  ') },
          { label: 'Contents read', value: 'no - never' },
        ],
        remedy: 'sudo chmod 600 ' + exposed.slice(0, 4).join(' '),
      })
    );
  }

  // These are files whose entire purpose is to hold a credential, so anything
  // beyond owner-only is wrong. Files that are world-readable by design -
  // /etc/environment, /etc/passwd - are checked for WRITABILITY instead, over
  // in checkPermissions, because that is what would actually be a finding.
  for (const f of h.secrets?.sensitive ?? []) {
    const mode = String(f.mode ?? '').padStart(3, '0');
    const looseGroup = /[1-7]/.test(mode[mode.length - 2] ?? '0');
    const looseWorld = /[1-7]/.test(mode[mode.length - 1] ?? '0');
    if (!looseGroup && !looseWorld) continue;
    out.push(
      finding({
        key: 'harden:secrets:loose:' + f.path,
        area: 'secrets',
        severity: looseWorld ? 'critical' : 'warning',
        title: f.path.split('/').slice(-2).join('/') + ' is accessible beyond its owner',
        detail:
          'Mode ' + f.mode + ' on a file that exists to hold a credential. These must be 600 - OpenSSH refuses to use a private key ' +
          'with looser permissions at all, so a key like this is either unused or something is overriding the check.',
        evidence: [{ label: 'Mode', value: f.mode }, { label: 'Owner', value: f.owner }, { label: 'Expected', value: '600' }],
        remedy: 'chmod 600 ' + f.path,
      })
    );
  }
}

/* ------------------------------------------------------------------ 12. cron */

function checkCron(h, out) {
  const risky = (h.cron?.files ?? []).filter((f) => f.groupWritable || f.worldWritable);
  if (!risky.length) return;
  out.push(
    finding({
      key: 'harden:cron:writable',
      area: 'cron',
      severity: 'critical',
      title: risky.length + ' cron file' + (risky.length === 1 ? ' is' : 's are') + ' writable by non-root users',
      detail:
        'System cron runs as root. A cron file that a non-root user can edit is a scheduled root shell for whoever edits it, and it ' +
        'survives reboots and password changes.',
      value: risky.length,
      evidence: [{ label: 'Files', value: risky.map((f) => f.mode + ' ' + f.path).slice(0, 6).join('  ') }],
      remedy: 'sudo chmod 644 ' + risky.slice(0, 4).map((f) => f.path).join(' ') + ' && sudo chown root:root ' + risky.slice(0, 4).map((f) => f.path).join(' '),
    })
  );
}

/* ------------------------------------------------- 13/14. containers, escape */

function checkContainers(h, out) {
  const containers = h.containers ?? [];
  if (!containers.length) return;

  const privileged = containers.filter((c) => c.privileged);
  if (privileged.length) {
    out.push(
      finding({
        key: 'harden:containers:privileged',
        area: 'escape',
        severity: 'critical',
        title: privileged.length + ' container' + (privileged.length === 1 ? ' runs' : 's run') + ' privileged',
        detail:
          '--privileged disables essentially every isolation boundary: the container gets all capabilities, host devices and an ' +
          'unconfined seccomp profile. Compromising the process inside is equivalent to compromising the host.',
        value: privileged.length,
        evidence: [
          { label: 'Containers', value: privileged.map((c) => c.name).slice(0, 6).join(', ') },
          { label: 'Isolation', value: 'effectively none' },
        ],
        remedy: 'docker inspect --format "{{.HostConfig.Privileged}}" ' + privileged[0].name + '    # re-run with specific --cap-add instead',
      })
    );
  }

  const socketMounts = containers.filter((c) => c.mounts.some((m) => /docker\.sock$/.test(m.source ?? '')));
  if (socketMounts.length) {
    out.push(
      finding({
        key: 'harden:containers:docker-sock',
        area: 'escape',
        severity: 'critical',
        title: socketMounts.length + ' container has the Docker socket mounted',
        detail:
          'A process that can reach /var/run/docker.sock can start a new privileged container mounting the host filesystem. This is ' +
          'a full host takeover from inside the container, and it needs no exploit - just the API.',
        value: socketMounts.length,
        evidence: [
          { label: 'Containers', value: socketMounts.map((c) => c.name).join(', ') },
          { label: 'Effect', value: 'container to host root' },
        ],
        remedy: 'Remove the -v /var/run/docker.sock mount, or put a socket proxy with a restricted API in front of it.',
      })
    );
  }

  const hostMounts = containers.filter((c) =>
    c.mounts.some((m) => ['/', '/etc', '/root', '/home', '/var', '/usr', '/boot'].includes(m.source))
  );
  if (hostMounts.length) {
    out.push(
      finding({
        key: 'harden:containers:host-mounts',
        area: 'escape',
        severity: 'critical',
        title: hostMounts.length + ' container mounts a sensitive host directory',
        detail: 'Mounting a host root or system directory into a container gives the container read - and usually write - access to the host it runs on.',
        value: hostMounts.length,
        evidence: [
          {
            label: 'Mounts',
            value: hostMounts.flatMap((c) => c.mounts.filter((m) => m.source.length <= 6).map((m) => c.name + ': ' + m.source + ' → ' + m.destination)).slice(0, 5).join('  '),
          },
        ],
        remedy: 'Mount only the specific paths the workload needs, read-only where possible (`-v /srv/data:/data:ro`).',
      })
    );
  }

  const rootUser = containers.filter((c) => !c.user || c.user === 'root' || c.user === '0');
  if (rootUser.length) {
    out.push(
      finding({
        key: 'harden:containers:root-user',
        area: 'containers',
        severity: 'warning',
        title: rootUser.length + ' of ' + containers.length + ' containers run as root',
        detail:
          'Root in a container is not root on the host, but it removes a layer: a file-write bug becomes a container takeover, and it ' +
          'combines with any kernel or runtime flaw into a host one.',
        value: rootUser.length,
        evidence: [
          { label: 'Containers', value: rootUser.map((c) => c.name).slice(0, 6).join(', ') },
          { label: 'Running as', value: 'root (image default)' },
        ],
        remedy: 'Add a USER directive to the image, or run with --user 1000:1000.',
      })
    );
  }

  const caps = containers.filter((c) => c.capAdd.some((cap) => DANGEROUS_CAPS.has(String(cap).replace(/^CAP_/, ''))));
  if (caps.length) {
    out.push(
      finding({
        key: 'harden:containers:caps',
        area: 'escape',
        severity: 'warning',
        title: caps.length + ' container has been granted a dangerous capability',
        detail: 'SYS_ADMIN, SYS_MODULE, SYS_PTRACE and DAC_READ_SEARCH each provide a documented route out of the container.',
        value: caps.length,
        evidence: [{ label: 'Containers', value: caps.map((c) => c.name + ' (' + c.capAdd.join(', ') + ')').slice(0, 4).join('  ') }],
        remedy: 'docker run --cap-drop ALL --cap-add <only what is needed> …',
      })
    );
  }
}

/* -------------------------------------------------------------------- 15. mac */

function checkMac(h, out) {
  const mac = h.mac ?? {};
  const installed = mac.installed ?? [];

  // Neither framework present is a distribution choice, not a misconfiguration,
  // and it is reported as "not applicable" in the coverage rather than as a
  // finding here.
  if (!installed.length) return;
  if (mac.selinux === null && mac.apparmor === null) return;

  if (mac.selinux === 'Disabled' || mac.selinux === 'Permissive') {
    out.push(
      finding({
        key: 'harden:mac:selinux',
        area: 'mac',
        severity: mac.selinux === 'Disabled' ? 'warning' : 'info',
        title: 'SELinux is ' + mac.selinux.toLowerCase(),
        detail:
          mac.selinux === 'Disabled'
            ? 'Nothing is confining processes beyond standard file permissions, so a compromised service can reach everything its user can.'
            : 'Permissive logs violations but does not stop them. Useful while writing policy; not a control.',
        evidence: [{ label: 'getenforce', value: mac.selinux }],
        remedy: 'sudo setenforce 1 && sudo sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config',
      })
    );
  }

  if (mac.apparmor === 'disabled') {
    out.push(
      finding({
        key: 'harden:mac:apparmor',
        area: 'mac',
        severity: 'warning',
        title: 'AppArmor is installed but not enabled',
        detail: 'The profiles that would confine sshd, the browser sandboxes and any packaged daemons are not being enforced.',
        evidence: [{ label: 'aa-status', value: 'disabled' }],
        remedy: 'sudo systemctl enable --now apparmor',
      })
    );
  }
}

/* ------------------------------------------------------------------ coverage */

/**
 * What this audit could and could not look at, per area.
 *
 * The UI shows this alongside the findings, because "no findings" and "could
 * not check" look identical on a dashboard unless something says otherwise.
 */
export function coverage(facts) {
  const h = facts.hardening ?? {};
  const say = (id, state, note) => ({ id, state, note });

  return [
    say('packages', facts.updates ? 'checked' : 'unknown', facts.updates ? facts.updates.total + ' updates, ' + facts.updates.security + ' security' : 'No package manager answered'),
    say('ssh', facts.security?.sshd ? 'checked' : 'unknown', facts.security?.sshdSource === 'effective' ? 'Read from sshd -T' : 'Read from sshd_config: compiled-in defaults are invisible'),
    say('accounts', h.accounts ? 'checked' : 'unknown', h.accounts ? h.accounts.length + ' accounts, ' + h.accounts.filter((a) => a.canLogin).length + ' with a login shell' : '/etc/passwd unreadable'),
    say(
      'sudo',
      // Group membership is always readable, and it is where the docker-group
      // finding comes from, so this is never a total blind spot.
      h.sudo?.readable ? 'checked' : 'partial',
      h.sudo?.readable
        ? 'sudo -l for this account, plus privileged group membership'
        : 'Full sudoers needs root. Privileged group membership - including the root-equivalent docker group - was still checked.',
    ),
    say('suid', h.suid ? 'checked' : 'unknown', h.suid ? h.suid.length + ' setuid/setgid binaries found' + (h.scanTruncated ? ' (walk hit its time limit)' : '') : 'The filesystem walk returned nothing'),
    say('kernel', facts.reboot?.runningKernel ? 'checked' : 'unknown', facts.reboot?.kernelStale ? 'A newer kernel is installed than is running' : 'Running the newest installed kernel'),
    say('ports', facts.ports?.length ? 'checked' : 'unknown', (facts.ports ?? []).filter((p) => p.exposed).length + ' sockets reachable off-host'),
    say('firewall', h.firewall?.readable ? 'checked' : 'unknown', h.firewall?.readable ? h.firewall.tool + ', ' + (h.firewall.active ? 'active' : 'inactive') : 'Needs root: ufw, firewalld and iptables all refuse to report to an ordinary user'),
    say('permissions', h.permissions ? 'checked' : 'unknown', h.worldWritable ? (h.worldWritable.files.length + h.worldWritable.dirs.length) + ' world-writable paths outside /tmp' : 'The filesystem walk returned nothing'),
    say('secrets', h.secrets ? 'checked' : 'unknown', 'Paths and permissions only; no file contents are ever read'),
    // Stated plainly rather than quietly omitted: an agentless host scanner
    // cannot see how an application builds a shell command.
    say('injection', 'not-applicable', 'Not checkable from outside the application. Vigil reads the host, not your code paths - use SAST and input validation in the application itself.'),
    say('cron', h.cron ? 'checked' : 'unknown', h.cron ? h.cron.files.length + ' system cron files inspected' : '/etc/cron.d unreadable'),
    say('containers', h.containers ? 'checked' : facts.docker?.installed ? 'unknown' : 'not-applicable', h.containers ? h.containers.length + ' running containers inspected' : facts.docker?.installed ? 'The Docker daemon refused this login' : 'Docker is not installed'),
    say('escape', h.containers ? 'checked' : facts.docker?.installed ? 'unknown' : 'not-applicable', h.containers ? 'Privilege, mounts and capabilities checked' : facts.docker?.installed ? 'The Docker daemon refused this login' : 'Docker is not installed'),
    say(
      'mac',
      h.mac?.selinux || h.mac?.apparmor ? 'checked' : (h.mac?.installed ?? []).length ? 'unknown' : 'not-applicable',
      h.mac?.selinux
        ? 'SELinux ' + h.mac.selinux
        : h.mac?.apparmor
          ? 'AppArmor ' + h.mac.apparmor
          : (h.mac?.installed ?? []).length
            ? (h.mac.installed.join(' and ')) + ' is installed but would not report its state to this login'
            : 'Neither SELinux nor AppArmor is installed on this distribution',
    ),
  ];
}

/* ---------------------------------------------------------------- entry point */

/**
 * @param {object} facts output of ssh/probe.mjs
 * @returns {Array} hardening findings, each tagged with the area it belongs to
 */
export function audit(facts) {
  const out = [];
  if (!facts) return out;
  const h = facts.hardening;
  if (!h) return out;

  checkSsh(h, facts, out);
  checkAccounts(h, out);
  checkSudo(h, out);
  checkSuid(h, out);
  checkFirewall(h, facts, out);
  checkPermissions(h, out);
  checkSecrets(h, out);
  checkCron(h, out);
  checkContainers(h, out);
  checkMac(h, out);

  const rank = { critical: 0, warning: 1, info: 2 };
  out.sort((a, b) => rank[a.severity] - rank[b.severity] || a.area.localeCompare(b.area));
  return out;
}

export { EXPECTED_SUID, DANGEROUS_SUID };
