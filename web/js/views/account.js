// Account settings, and a plain statement of what the product does with the
// credentials it holds. That belongs in the app, not only in the README.

import { api } from '../api.js';
import { card, toast, escapeHtml } from '../ui.js';
import { dateTime, relative, duration } from '../format.js';

/** Labels for the fixed set of intervals the server accepts. */
const INTERVAL_LABEL = {
  0: 'Never - I will scan manually',
  5: 'Every 5 minutes',
  10: 'Every 10 minutes',
  15: 'Every 15 minutes',
  30: 'Every 30 minutes',
  60: 'Every hour',
  180: 'Every 3 hours',
  360: 'Every 6 hours',
  720: 'Every 12 hours',
  1440: 'Once a day',
};

export async function render(root, { app }) {
  const [fleet, settings] = await Promise.all([app.fleet ? Promise.resolve(app.fleet) : api.fleet(), api.settings()]);

  const options = settings.choices
    .map(
      (m) =>
        '<option value="' + m + '"' + (m === settings.scanMinutes ? ' selected' : '') + '>' +
        escapeHtml(INTERVAL_LABEL[m] ?? 'Every ' + m + ' minutes') +
        (m === settings.defaultScanMinutes ? ' (default)' : '') +
        '</option>'
    )
    .join('');

  const cadence =
    settings.scanMinutes > 0
      ? 'Each of your servers is contacted every ' + duration(settings.scanMinutes * 60) +
        (settings.nextScanAt ? '. Next sweep is due ' + relative(settings.nextScanAt).replace(' ago', ' ago (overdue)') : '.')
      : 'Automatic scanning is off. Nothing is contacted until you press Scan now.';

  const scanning = card({
    title: 'Scan interval',
    subtitle: 'How often Vigil logs in to each of your servers',
    body:
      '<div class="form-grid" style="max-width:420px">' +
      '<div class="field"><label for="scan-interval">Scan every</label>' +
      '<select id="scan-interval">' + options + '</select>' +
      '<div class="hint">' + escapeHtml(cadence) + '</div></div>' +
      '<div><button class="btn btn-primary" id="scan-save">Save interval</button></div>' +
      '</div>' +
      '<p class="muted" style="font-size:12px;line-height:1.65;margin-top:14px;max-width:70ch">' +
      'A sweep opens one SSH connection per server, up to ' + escapeHtml(String(fleet.servers.length ? Math.min(8, fleet.servers.length) : 0)) +
      ' at a time, and each one runs a single read-only script. Short intervals cost the monitored hosts almost nothing &mdash; but the ' +
      'anomaly baselines are built from scan history, so a longer interval means it takes proportionally longer before ' +
      '&ldquo;normal for this machine&rdquo; means anything.' +
      '</p>' +
      (settings.isDefault
        ? '<p class="muted" style="font-size:11.5px;margin-top:10px">Currently following the instance default (<code>VG_SCAN_MINUTES</code>).</p>'
        : '<p class="muted" style="font-size:11.5px;margin-top:10px">Set by you ' + escapeHtml(relative(settings.updatedAt)) + '.</p>'),
  });

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
      '<dt>Docker cleanup</dt><dd>' + (fleet.pruneEnabled ? 'enabled' : 'disabled') + '</dd>' +
      '</dl>' +
      '<p class="muted" style="font-size:12.5px;line-height:1.65;margin-top:14px;max-width:70ch">' +
      'Vigil connects, runs one script that only reads, and disconnects. Nothing in the codebase can write a file, install a package, ' +
      'restart a unit or open an interactive shell on a monitored host. The suggested commands shown against each finding are for you ' +
      'to run yourself &mdash; nothing here executes them.' +
      '</p>' +
      '<p class="muted" style="font-size:12.5px;line-height:1.65;margin-top:12px;max-width:70ch">' +
      'The one exception is Docker cleanup, which is off unless the instance sets <code>VG_ALLOW_DOCKER_PRUNE=on</code>. Even then it ' +
      'can only run a fixed list of <code>docker &hellip; prune -f</code> commands, cannot target a specific container or image, and ' +
      'writes every run to the audit log.' +
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

  root.innerHTML = '<div class="stack">' + session + scanning + password + privacy + '</div>';

  root.querySelector('#scan-save').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    const minutes = Number(root.querySelector('#scan-interval').value);
    btn.disabled = true;
    btn.textContent = 'Saving\u2026';
    try {
      const saved = await api.updateSettings({ scanMinutes: minutes });
      toast('Scan interval saved', saved.scanMinutes ? INTERVAL_LABEL[saved.scanMinutes] ?? saved.scanMinutes + ' minutes' : 'Automatic scanning is off');
      await render(root, { app });
      return;
    } catch (err) {
      toast('Could not save', err.message, 'critical');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Save interval';
    }
  });

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
