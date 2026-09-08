// Account settings, and a plain statement of what the product does with the
// credentials it holds. That belongs in the app, not only in the README.

import { api } from '../api.js';
import { card, toast, escapeHtml } from '../ui.js';
import { dateTime } from '../format.js';

export async function render(root, { app }) {
  const fleet = app.fleet ?? (await api.fleet());

  const password = card({
    title: 'Change password',
    subtitle: 'Every other signed-in session is signed out when you do this.',
    body:
      '<div class="form-grid" style="max-width:420px">' +
      '<div class="field"><label for="pw-current">Current password</label><input id="pw-current" type="password" autocomplete="current-password" /></div>' +
      '<div class="field"><label for="pw-new">New password</label><input id="pw-new" type="password" autocomplete="new-password" />' +
      '<div class="hint">At least 10 characters, with a letter and a number.</div></div>' +
      '<div class="field"><label for="pw-confirm">Confirm new password</label><input id="pw-confirm" type="password" autocomplete="new-password" /></div>' +
      '<div><button class="btn btn-primary" id="pw-save">Change password</button></div>' +
      '</div>',
  });

  const privacy = card({
    title: 'What Vigil holds, and what it does with it',
    body:
      '<dl class="kv" style="max-width:640px">' +
      '<dt>Your servers</dt><dd>' + fleet.servers.length + '</dd>' +
      '<dt>Visible to</dt><dd>only you</dd>' +
      '<dt>Private keys</dt><dd>AES-256-GCM, key outside the database</dd>' +
      '<dt>Key readable by the UI</dt><dd>no — there is no endpoint that returns one</dd>' +
      '<dt>Written to disk on this host</dt><dd>never — decrypted in memory per connection</dd>' +
      '<dt>Commands run on your servers</dt><dd>read-only, one script, fixed at build time</dd>' +
      '</dl>' +
      '<p class="muted" style="font-size:12.5px;line-height:1.65;margin-top:14px;max-width:70ch">' +
      'Vigil connects, runs one script that only reads, and disconnects. There is no module in the codebase that can write a file, ' +
      'install a package, restart a unit or open an interactive shell on a monitored host. The suggested commands shown against each ' +
      'finding are for you to run yourself &mdash; nothing here executes them.' +
      '</p>' +
      '<p class="muted" style="font-size:12.5px;line-height:1.65;margin-top:12px;max-width:70ch">' +
      'Host keys are pinned on first contact. If a server ever presents a different host key, the scan fails loudly rather than ' +
      'connecting anyway, and the change is written to the audit log.' +
      '</p>',
  });

  const session = card({
    title: 'Session',
    body:
      '<dl class="kv" style="max-width:420px">' +
      '<dt>Signed in as</dt><dd>' + escapeHtml(app.me?.name ?? '') + '</dd>' +
      '<dt>Email</dt><dd>' + escapeHtml(app.me?.email ?? '') + '</dd>' +
      '</dl>' +
      '<div style="margin-top:16px"><button class="btn" id="sign-out">Sign out</button></div>',
  });

  root.innerHTML = '<div class="stack">' + session + password + privacy + '</div>';

  root.querySelector('#sign-out').addEventListener('click', async () => {
    await api.logout().catch(() => {});
    location.href = '/login';
  });

  root.querySelector('#pw-save').addEventListener('click', async (e) => {
    const current = root.querySelector('#pw-current').value;
    const next = root.querySelector('#pw-new').value;
    const confirm = root.querySelector('#pw-confirm').value;

    if (next !== confirm) return toast('Passwords do not match', 'Type the new password the same way twice.', 'critical');

    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = 'Changing…';
    try {
      await api.changePassword({ currentPassword: current, newPassword: next });
      toast('Password changed', 'Other sessions have been signed out.');
      root.querySelectorAll('#pw-current, #pw-new, #pw-confirm').forEach((i) => (i.value = ''));
    } catch (err) {
      toast('Could not change password', err.message, 'critical');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Change password';
    }
  });
}
