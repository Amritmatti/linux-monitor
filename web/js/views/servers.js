// The server list, and the add/edit form.
//
// The form is where the private key is entered, so the copy around it is doing
// real work: it has to be obvious which half of the key pair is wanted, and
// obvious what happens to it afterwards.

import { api } from '../api.js';
import { card, dataTable, emptyState, escapeHtml, statusBadge, healthBadge, meter, openDrawer, closeDrawer, toast, severityBadge } from '../ui.js';
import { relative, duration, num } from '../format.js';

export async function render(root, { app }) {
  const fleet = await api.fleet();
  app.fleet = fleet;
  const servers = fleet.servers.filter((s) =>
    !app.searchTerm || (s.name + ' ' + s.host + ' ' + (s.summary?.os ?? '')).toLowerCase().includes(app.searchTerm.toLowerCase())
  );

  const table = dataTable({
    columns: [
      {
        label: 'Server',
        render: (s) =>
          '<a href="#/servers/' + s.id + '"><b>' + escapeHtml(s.name) + '</b></a>' +
          '<div class="muted" style="font-size:11px;font-family:var(--mono)">' + escapeHtml(s.username) + '@' + escapeHtml(s.host) + (s.port !== 22 ? ':' + s.port : '') + '</div>',
      },
      { label: 'Connection', width: '132px', render: (s) => statusBadge(s.status, s.scanOk) },
      { label: 'Health', width: '124px', render: (s) => (s.summary ? healthBadge(s) : '<span class="muted">--</span>') },
      { label: 'OS', width: '150px', render: (s) => '<span class="muted">' + escapeHtml(s.summary?.os ?? '--') + '</span>' },
      { label: 'Load', width: '74px', align: 'right', render: (s) => (s.summary?.loadPerCore != null ? s.summary.loadPerCore.toFixed(2) + '×' : '<span class="muted">--</span>') },
      { label: 'Disk', width: '148px', render: (s) => (s.summary?.maxDiskPct != null ? meter(s.summary.maxDiskPct) : '<span class="muted">--</span>') },
      {
        label: 'Security',
        width: '92px',
        align: 'right',
        render: (s) =>
          s.summary?.security ? '<span style="color:var(--critical);font-weight:600">' + s.summary.security + '</span>' : '<span class="muted">' + (s.summary ? '0' : '--') + '</span>',
      },
      { label: 'Scanned', width: '96px', align: 'right', render: (s) => '<span class="muted">' + relative(s.scannedAt) + '</span>' },
      {
        label: '',
        width: '132px',
        align: 'right',
        render: (s) =>
          '<button class="btn btn-sm" data-scan="' + s.id + '">Scan</button> ' +
          '<button class="btn btn-sm" data-edit="' + s.id + '">Edit</button>',
      },
    ],
    rows: servers,
    empty: app.searchTerm ? 'No server matches that search' : 'No servers yet',
  });

  const unreachable = fleet.servers.filter((s) => s.status === 'error');

  root.innerHTML =
    '<div class="stack">' +
    (unreachable.length
      ? '<div class="callout critical"><span class="bar"></span><div><b>' + unreachable.length +
        (unreachable.length === 1 ? ' server is' : ' servers are') + ' unreachable.</b> ' +
        unreachable.map((s) => '<div class="muted" style="font-size:12px;margin-top:6px">' + escapeHtml(s.name) + ' — ' + escapeHtml(s.lastError ?? 'unknown error') + '</div>').join('') +
        '</div></div>'
      : '') +
    card({
      title: 'Servers',
      subtitle: fleet.servers.length + (fleet.servers.length === 1 ? ' server' : ' servers'),
      actions: '<button class="btn btn-sm btn-primary" id="add-server">Add server</button>',
      pad: false,
      body: fleet.servers.length
        ? table
        : emptyState(
            'No servers yet',
            'Vigil connects over SSH as an ordinary user, reads, and disconnects. Nothing is installed on the host and no sudo is needed.',
            '<button class="btn btn-primary" id="add-server-empty">Add a server</button>'
          ),
    }) +
    '</div>';

  const reload = () => render(root, { app });

  root.querySelector('#add-server')?.addEventListener('click', () => showForm(null, reload));
  root.querySelector('#add-server-empty')?.addEventListener('click', () => showForm(null, reload));

  root.querySelectorAll('[data-edit]').forEach((b) =>
    b.addEventListener('click', () => showForm(fleet.servers.find((s) => s.id === b.dataset.edit), reload))
  );

  root.querySelectorAll('[data-scan]').forEach((b) =>
    b.addEventListener('click', async () => {
      const label = b.textContent;
      b.disabled = true;
      b.textContent = 'Scanning…';
      try {
        const res = await api.scanServer(b.dataset.scan);
        if (res.ok) {
          const crit = res.findings.filter((f) => f.severity === 'critical').length;
          toast('Scan complete', crit ? crit + ' critical ' + (crit === 1 ? 'issue' : 'issues') + ' found' : 'No critical issues');
        } else {
          toast('Could not connect', res.error ?? 'unknown error', 'critical');
        }
      } catch (err) {
        toast('Scan failed', err.message, 'critical');
      } finally {
        b.disabled = false;
        b.textContent = label;
        reload();
      }
    })
  );
}

/* ------------------------------------------------------------------- form */

const field = (id, label, input, hint) =>
  '<div class="field"><label for="' + id + '">' + escapeHtml(label) + '</label>' + input +
  (hint ? '<div class="hint">' + hint + '</div>' : '') + '<div class="field-error" id="' + id + '-error" hidden></div></div>';

function showForm(server, onSaved) {
  const editing = Boolean(server);

  const body =
    '<div class="drawer-head"><div><b>' + (editing ? 'Edit ' + escapeHtml(server.name) : 'Add a server') + '</b></div>' +
    '<button class="icon-btn" data-close aria-label="Close"><svg viewBox="0 0 20 20" width="16" height="16"><path d="M5 5l10 10M15 5L5 15" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></button></div>' +

    '<div class="form-grid" style="margin-top:18px">' +
    field('f-name', 'Server name', '<input id="f-name" type="text" placeholder="web-01" value="' + escapeHtml(server?.name ?? '') + '" />', 'Whatever you call it. Only you see this.') +
    '<div class="form-row">' +
    field('f-host', 'IP address or hostname', '<input id="f-host" type="text" placeholder="10.0.4.11" value="' + escapeHtml(server?.host ?? '') + '" />') +
    field('f-port', 'SSH port', '<input id="f-port" type="number" min="1" max="65535" value="' + (server?.port ?? 22) + '" />') +
    '</div>' +
    field('f-username', 'Login user', '<input id="f-username" type="text" placeholder="ubuntu" value="' + escapeHtml(server?.username ?? '') + '" />',
      'An ordinary account. Vigil never needs sudo &mdash; where a check would benefit from it, the dashboard tells you which single command to allow.') +

    field(
      'f-key',
      editing ? 'Replace the private key' : 'Private key',
      '<textarea id="f-key" spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;b3BlbnNzaC1rZXktdjEAAAAABG5vbmU...&#10;-----END OPENSSH PRIVATE KEY-----"></textarea>',
      editing
        ? 'Leave blank to keep the key already stored. A key is stored for this server.'
        : 'The <b>private</b> half &mdash; the file <i>without</i> the <code>.pub</code> extension &mdash; whose public half is already in ' +
          '<code>~/.ssh/authorized_keys</code> on that server. It is sealed with AES-256-GCM before it is stored, is decrypted only in memory ' +
          'for the length of one connection, is never written to disk, and no page or API in Vigil can read it back.'
    ) +

    field('f-passphrase', 'Key passphrase', '<input id="f-passphrase" type="password" autocomplete="new-password" placeholder="' + (server?.hasPassphrase ? '••••••••  (stored)' : 'Only if the key is encrypted') + '" />',
      'Optional. Only needed if the private key itself is passphrase-protected.') +
    '</div>' +

    (editing && server.hostKeyFp
      ? '<div class="callout" style="margin-top:16px"><span class="bar"></span><div>' +
        '<b>Pinned host key</b><div class="fp" style="margin-top:5px">' + escapeHtml(server.hostKeyFp) + '</div>' +
        '<div class="muted" style="font-size:11.5px;margin-top:7px">Recorded on the first successful connection. If it changes, Vigil refuses to connect. ' +
        'Reset it only if you deliberately rebuilt this machine.</div>' +
        '<button class="btn btn-sm" style="margin-top:9px" data-reset-key>Reset pinned key</button>' +
        '</div></div>'
      : '') +

    '<div class="drawer-actions" style="margin-top:22px">' +
    (editing ? '<button class="btn" data-delete style="margin-right:auto;color:var(--critical)">Delete server</button>' : '') +
    '<button class="btn" data-close>Cancel</button>' +
    '<button class="btn btn-primary" data-save>' + (editing ? 'Save changes' : 'Add and scan') + '</button>' +
    '</div>';

  openDrawer(body, {
    onMount: (drawer) => {
      drawer.querySelector('#f-name').focus();

      const showError = (id, message) => {
        const el = drawer.querySelector('#' + id + '-error');
        if (!el) return;
        el.textContent = message;
        el.hidden = !message;
      };
      const clearErrors = () => ['f-name', 'f-host', 'f-port', 'f-username', 'f-key', 'f-passphrase'].forEach((id) => showError(id, ''));

      // Maps a server-side error code onto the field that caused it, so the
      // message lands next to the input rather than in a toast.
      const FIELD_FOR = {
        invalid_name: 'f-name', name_taken: 'f-name', invalid_host: 'f-host', invalid_port: 'f-port',
        invalid_username: 'f-username', invalid_key: 'f-key',
      };

      drawer.querySelector('[data-save]').addEventListener('click', async (e) => {
        clearErrors();
        const btn = e.currentTarget;
        const payload = {
          name: drawer.querySelector('#f-name').value.trim(),
          host: drawer.querySelector('#f-host').value.trim(),
          port: Number(drawer.querySelector('#f-port').value) || 22,
          username: drawer.querySelector('#f-username').value.trim(),
          passphrase: drawer.querySelector('#f-passphrase').value,
        };
        const key = drawer.querySelector('#f-key').value.trim();
        if (key) payload.privateKey = key;
        if (!editing && !key) {
          showError('f-key', 'Paste the private key that can log in to this server');
          return;
        }

        btn.disabled = true;
        btn.textContent = editing ? 'Saving…' : 'Adding…';
        try {
          const saved = editing ? await api.updateServer(server.id, payload) : await api.createServer(payload);
          closeDrawer();
          onSaved?.();
          const id = editing ? server.id : saved.server.id;
          toast(editing ? 'Saved' : 'Server added', editing ? payload.name + ' updated' : 'Connecting to ' + payload.host + '…');
          // A new server is scanned straight away: the first thing anyone wants
          // to know is whether the credentials actually work.
          const res = await api.scanServer(id);
          if (!res.ok) toast('Could not connect', res.error, 'critical');
          else toast('Connected', payload.name + ' scanned successfully');
          onSaved?.();
        } catch (err) {
          const target = FIELD_FOR[err.code];
          if (target) showError(target, err.message);
          else toast('Could not save', err.message, 'critical');
        } finally {
          btn.disabled = false;
          btn.textContent = editing ? 'Save changes' : 'Add and scan';
        }
      });

      drawer.querySelector('[data-reset-key]')?.addEventListener('click', async (e) => {
        e.currentTarget.disabled = true;
        await api.resetHostKey(server.id);
        toast('Pinned key cleared', 'The next successful scan will pin the key it sees.');
        closeDrawer();
        onSaved?.();
      });

      drawer.querySelector('[data-delete]')?.addEventListener('click', () => confirmDelete(server, onSaved));
    },
  });
}

function confirmDelete(server, onSaved) {
  const body =
    '<div class="drawer-head"><div><b>Delete server</b></div>' +
    '<button class="icon-btn" data-close aria-label="Close"><svg viewBox="0 0 20 20" width="16" height="16"><path d="M5 5l10 10M15 5L5 15" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></button></div>' +
    '<h2 style="font-size:16px;margin:14px 0 8px">Remove ' + escapeHtml(server.name) + '?</h2>' +
    '<p class="muted" style="font-size:12.5px;line-height:1.6">This deletes the stored key and every scan Vigil has taken of this host. ' +
    'Nothing changes on the server itself &mdash; if you want to fully revoke access, also remove the public key from ' +
    '<code>~' + escapeHtml(server.username) + '/.ssh/authorized_keys</code>.</p>' +
    '<div class="drawer-actions" style="margin-top:20px">' +
    '<button class="btn" data-close>Cancel</button>' +
    '<button class="btn btn-primary" data-confirm style="background:var(--critical);border-color:var(--critical)">Delete</button></div>';

  openDrawer(body, {
    onMount: (drawer) =>
      drawer.querySelector('[data-confirm]').addEventListener('click', async () => {
        try {
          await api.deleteServer(server.id);
          toast('Deleted', server.name + ' removed');
          closeDrawer();
          if (location.hash.includes(server.id)) location.hash = '#/servers';
          onSaved?.();
        } catch (err) {
          toast('Could not delete', err.message, 'critical');
        }
      }),
  });
}

export { showForm };
