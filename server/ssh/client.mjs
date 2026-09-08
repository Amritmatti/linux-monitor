// ---------------------------------------------------------------------------
// SSH transport.
//
// Vigil is read-only. It opens one SSH session per scan, runs one script that
// only reads (`cat`, `df`, `ss`, `ps`, package-manager *simulations*), and
// closes. There is no code path in this repository that writes a file, installs
// a package, restarts a unit or opens a shell on a monitored host.
//
// Two things drive the design:
//
//   The private key never touches disk. It is decrypted into a string, handed
//   to ssh2 in memory, and dropped when the connection closes. Shelling out to
//   the openssh client would have meant writing it to a temp file or an agent
//   socket, which is exactly the thing this product must not do.
//
//   Host keys are pinned trust-on-first-use. The first successful connection
//   records the server's host key fingerprint; every later connection is
//   refused if it changes. Accepting any host key would make the encryption
//   decorative - anyone who can answer on port 22 could read the session.
// ---------------------------------------------------------------------------

// ssh2 is CommonJS: Node's named-export detection does not reliably see
// everything it exports, so the default export is destructured instead.
import ssh2 from 'ssh2';
import { createHash } from 'node:crypto';

const { Client } = ssh2;

const CONNECT_TIMEOUT_MS = Number(process.env.VG_SSH_CONNECT_TIMEOUT_MS || 12000);
const COMMAND_TIMEOUT_MS = Number(process.env.VG_SSH_COMMAND_TIMEOUT_MS || 45000);
/** A probe that returns more than this is malformed or hostile; stop reading. */
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;

/** OpenSSH's own format, so a fingerprint here is greppable in known_hosts. */
export function fingerprint(hostKey) {
  return 'SHA256:' + createHash('sha256').update(hostKey).digest('base64').replace(/=+$/, '');
}

export class SshError extends Error {
  constructor(message, { code, hint, hostKeyFp } = {}) {
    super(message);
    this.name = 'SshError';
    this.code = code ?? 'SshFailed';
    this.hint = hint;
    this.hostKeyFp = hostKeyFp;
  }
}

/**
 * Turn ssh2's terse errors into something a person can act on. The default
 * messages ("All configured authentication methods failed") send people to
 * search engines rather than to their authorized_keys file.
 */
function explain(err, { username, host }) {
  const msg = String(err?.message ?? err);

  if (/All configured authentication methods failed/i.test(msg)) {
    return new SshError('Authentication failed for ' + username + '@' + host, {
      code: 'AuthFailed',
      hint:
        'The public half of this key is probably not in ~' + username + '/.ssh/authorized_keys on the server, ' +
        'or that file has the wrong permissions (it must be 600, and ~/.ssh must be 700).',
    });
  }
  if (/Cannot parse privateKey|Unsupported key format|bad passphrase|Encrypted private OpenSSH key detected/i.test(msg)) {
    return new SshError('The private key could not be read: ' + msg, {
      code: 'BadKey',
      hint: 'Paste the whole key including the BEGIN and END lines. If it is passphrase-protected, supply the passphrase too.',
    });
  }
  if (/ECONNREFUSED/i.test(msg)) {
    return new SshError('Connection refused by ' + host, { code: 'Refused', hint: 'Nothing is listening on that port, or a firewall is rejecting the connection.' });
  }
  if (/ETIMEDOUT|Timed out while waiting for handshake/i.test(msg)) {
    return new SshError('Timed out connecting to ' + host, { code: 'Timeout', hint: 'A firewall or security group is most likely dropping the packets silently.' });
  }
  if (/ENOTFOUND|EAI_AGAIN/i.test(msg)) {
    return new SshError('Could not resolve ' + host, { code: 'DnsFailed', hint: 'Check the hostname, or use the IP address instead.' });
  }
  if (/EHOSTUNREACH|ENETUNREACH/i.test(msg)) {
    return new SshError(host + ' is unreachable from this container', { code: 'Unreachable', hint: 'Check routing and that the container network can reach the host.' });
  }
  return new SshError(msg, { code: 'SshFailed' });
}

/**
 * Open a connection, run one command, close.
 *
 * @param {object} target
 * @param {string} target.host
 * @param {number} target.port
 * @param {string} target.username
 * @param {string} target.privateKey   PEM/OpenSSH text, in memory only
 * @param {string} [target.passphrase]
 * @param {string} [target.hostKeyFp]  pinned fingerprint; null means first contact
 * @param {string} command
 * @returns {Promise<{stdout: string, stderr: string, code: number, hostKeyFp: string}>}
 */
export function run(target, command) {
  const { host, port = 22, username, privateKey, passphrase, hostKeyFp } = target;

  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    let seenFp = null;
    let stdout = '';
    let stderr = '';
    let truncated = false;

    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      try {
        conn.end();
      } catch {
        /* already gone */
      }
      fn(arg);
    };

    // A whole-operation deadline. ssh2's readyTimeout only covers the
    // handshake; a host that accepts the connection and then never answers the
    // command would otherwise hold the slot open indefinitely.
    const deadline = setTimeout(
      () => finish(reject, new SshError('Timed out after ' + Math.round(COMMAND_TIMEOUT_MS / 1000) + 's collecting from ' + host, { code: 'Timeout' })),
      COMMAND_TIMEOUT_MS
    );

    conn.on('ready', () => {
      conn.exec(command, { pty: false }, (err, stream) => {
        if (err) return finish(reject, explain(err, { username, host }));
        let code = 0;

        const append = (chunk, into) => {
          if (truncated) return into;
          const next = into + chunk;
          if (next.length > MAX_OUTPUT_BYTES) {
            truncated = true;
            return next.slice(0, MAX_OUTPUT_BYTES);
          }
          return next;
        };

        stream.on('data', (d) => {
          stdout = append(d.toString('utf8'), stdout);
        });
        stream.stderr.on('data', (d) => {
          stderr = append(d.toString('utf8'), stderr);
        });
        stream.on('exit', (c) => {
          code = typeof c === 'number' ? c : 0;
        });
        stream.on('close', () => finish(resolve, { stdout, stderr, code, hostKeyFp: seenFp, truncated }));
      });
    });

    conn.on('error', (err) => finish(reject, explain(err, { username, host })));

    conn.connect({
      host,
      port,
      username,
      privateKey,
      passphrase: passphrase || undefined,
      readyTimeout: CONNECT_TIMEOUT_MS,
      keepaliveInterval: 5000,
      // Nothing is ever forwarded, and no agent is used: the key in memory is
      // the only credential this connection has.
      agentForward: false,
      hostVerifier: (key) => {
        seenFp = fingerprint(key);
        if (!hostKeyFp) return true; // first contact: record it, trust it once
        if (hostKeyFp === seenFp) return true;
        // Returning false makes ssh2 emit a generic handshake error, so the
        // real reason is attached here and thrown from the error handler path.
        finish(
          reject,
          new SshError('Host key for ' + host + ' has changed since this server was added', {
            code: 'HostKeyChanged',
            hint:
              'Expected ' + hostKeyFp + ' but the host offered ' + seenFp + '. ' +
              'If you rebuilt or re-imaged this server, reset the pinned key on its settings page. If you did not, stop and investigate: ' +
              'something is answering on ' + host + ':' + port + ' that is not the machine you added.',
            hostKeyFp: seenFp,
          })
        );
        return false;
      },
    });
  });
}
