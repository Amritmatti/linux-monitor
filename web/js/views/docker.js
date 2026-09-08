// Docker: what is running, what is broken, and what is dead weight.
//
// The cleanup panel is the only place in Vigil that offers to change something
// on a host, so it is explicit about what each action removes, what it keeps,
// and which one deletes data. Nothing here runs without a confirmation naming
// the host and the exact command.

import { api } from '../api.js';
import {
  card, dataTable, emptyState, escapeHtml, severityBadge, statTile, meter,
  openDrawer, closeDrawer, toast, commandBlock, bytes, num,
} from '../ui.js';
import { relative } from '../format.js';

const STATE_TONE = { running: 'ok', restarting: 'critical', exited: 'muted', dead: 'critical', paused: 'warning', created: 'muted' };

export async function render(root, { app }) {
  const res = await api.docker();

  if (!res.items.length && !res.unavailable.length) {
    root.innerHTML = card({
      body: emptyState(
        'No Docker found',
        'None of your servers has Docker installed, or none has been scanned yet. Vigil detects it automatically — there is nothing to configure.'
      ),
    });
    return;
  }

  const t = res.totals;

  const tiles =
    '<div class="grid grid-4">' +
    statTile({
      label: 'Reclaimable',
      value: bytes(t.reclaimableBytes),
      tone: t.reclaimableBytes > 5 * 1024 ** 3 ? 'warning' : undefined,
      foot: '<span>stopped containers, unused images, build cache</span>',
      hint: 'Taken from docker system df, which accounts for layers shared between images. Summing image sizes would double-count them.',
    }) +
    statTile({
      label: 'Containers',
      value: num(t.containers),
      foot: '<span>' + num(t.running) + ' running · ' + num(t.exited) + ' exited</span>',
    }) +
    statTile({
      label: 'Restarting or unhealthy',
      value: num(t.restarting + t.unhealthy),
      tone: t.restarting + t.unhealthy ? 'critical' : 'good',
      foot: '<span>' + num(t.restarting) + ' looping · ' + num(t.unhealthy) + ' failing health checks</span>',
      href: '#/issues?category=Docker',
    }) +
    statTile({
      label: 'Dangling images',
      value: num(t.danglingImages),
      foot: '<span>' + num(t.danglingVolumes) + ' unused volumes (' + bytes(t.volumeBytes) + ')</span>',
    }) +
    '</div>';

  const problem = [];
  for (const h of res.items) {
    for (const c of h.containers.items ?? []) {
      if (c.state === 'restarting' || c.state === 'dead' || c.healthy === false) problem.push({ ...c, host: h });
    }
  }

  const problemCard = problem.length
    ? card({
        title: 'Containers needing attention',
        subtitle: escapeHtml(problem.length + ' restarting, dead, or failing their own health check'),
        pad: false,
        body: dataTable({
          columns: [
            { label: 'Container', render: (c) => '<b>' + escapeHtml(c.name) + '</b><div class="muted" style="font-size:11px;font-family:var(--mono)">' + escapeHtml(c.image) + '</div>' },
            { label: 'Server', width: '150px', render: (c) => '<a href="#/servers/' + c.host.serverId + '">' + escapeHtml(c.host.serverName) + '</a>' },
            { label: 'State', width: '120px', render: (c) => severityBadge(c.healthy === false ? 'critical' : STATE_TONE[c.state] ?? 'muted', c.healthy === false ? 'unhealthy' : c.state) },
            { label: 'Status', render: (c) => '<span class="muted">' + escapeHtml(c.status) + '</span>' },
          ],
          rows: problem,
          rowAttrs: () => 'class="issue-row is-critical"',
        }),
      })
    : '';

  const hostRows = dataTable({
    columns: [
      {
        label: 'Server',
        render: (h) =>
          '<a href="#/servers/' + h.serverId + '"><b>' + escapeHtml(h.serverName) + '</b></a>' +
          '<div class="muted" style="font-size:11px">Docker ' + escapeHtml(h.version ?? '?') + '</div>',
      },
      {
        label: 'Containers',
        width: '190px',
        render: (h) =>
          '<span class="port">' + h.containers.running + ' up</span> ' +
          (h.containers.exited ? '<span class="port">' + h.containers.exited + ' exited</span> ' : '') +
          (h.containers.restarting ? '<span class="port is-risky">' + h.containers.restarting + ' looping</span>' : ''),
      },
      { label: 'Images', width: '128px', align: 'right', render: (h) => num(h.images.total) + (h.images.dangling ? ' <span class="muted">(' + h.images.dangling + ' dangling)</span>' : '') },
      { label: 'Volumes', width: '120px', align: 'right', render: (h) => num(h.volumes.total) + (h.volumes.dangling ? ' <span class="muted">(' + h.volumes.dangling + ' unused)</span>' : '') },
      { label: 'Reclaimable', width: '116px', align: 'right', render: (h) => '<b>' + bytes(h.reclaimableBytes) + '</b>' },
      { label: 'Seen', width: '84px', align: 'right', render: (h) => '<span class="muted">' + relative(h.observedAt) + '</span>' },
      { label: '', width: '104px', align: 'right', render: (h) => '<button class="btn btn-sm" data-clean="' + h.serverId + '">Clean up…</button>' },
    ],
    rows: res.items,
    empty: 'No host is reporting Docker',
  });

  const disabledNote = !res.pruneEnabled
    ? '<div class="callout"><span class="bar"></span><div><b>Cleanup is disabled on this instance.</b> ' +
      '<span class="muted">Vigil is read-only by default and that is the recommended setting: the commands below are ready to copy and run yourself. ' +
      'To let Vigil run them for you, set <code>VG_ALLOW_DOCKER_PRUNE=on</code> — note that reaching the Docker socket is root-equivalent.</span>' +
      '</div></div>'
    : '';

  root.innerHTML =
    '<div class="stack">' +
    tiles +
    disabledNote +
    (res.unavailable.length
      ? '<div class="callout"><span class="bar"></span><div><b>' + res.unavailable.length + ' server' +
        (res.unavailable.length === 1 ? ' has' : 's have') + ' Docker installed but would not let Vigil talk to it.</b> ' +
        '<span class="muted">' + res.unavailable.map((u) => escapeHtml(u.serverName)).join(', ') +
        '. That is the expected result of an unprivileged login — the docker group is root-equivalent, so Vigil does not ask for it.</span></div></div>'
      : '') +
    problemCard +
    card({ title: 'Docker hosts', subtitle: res.items.length + ' reporting', pad: false, body: hostRows }) +
    '</div>';

  root.querySelectorAll('[data-clean]').forEach((b) =>
    b.addEventListener('click', () => showCleanup(res.items.find((h) => h.serverId === b.dataset.clean), res.actions, () => render(root, { app })))
  );
}

/* ------------------------------------------------------------------ cleanup */

function showCleanup(host, actions, onDone) {
  if (!host) return;

  const sizeFor = {
    'exited-containers': host.reclaimable.containers,
    'dangling-images': host.reclaimable.images,
    'unused-images': host.reclaimable.images,
    'build-cache': host.reclaimable.buildCache,
    'all-safe': host.reclaimableBytes,
    'unused-volumes': host.reclaimable.volumes,
  };

  const row = (a) =>
    '<div style="padding:13px 0;border-bottom:1px solid var(--hairline)">' +
    '<div class="row" style="justify-content:space-between;align-items:flex-start;gap:12px">' +
    '<div style="flex:1">' +
    '<b>' + escapeHtml(a.label) + '</b>' +
    (a.dataLoss ? ' ' + severityBadge('critical', 'deletes data') : '') +
    '<div class="muted" style="font-size:12px;margin-top:3px;line-height:1.55">' + escapeHtml(a.describes) + '</div>' +
    '<div class="muted" style="font-size:11.5px;margin-top:4px;line-height:1.5">' + escapeHtml(a.keeps) + '</div>' +
    (a.blockedBecause ? '<div class="muted" style="font-size:11.5px;margin-top:6px;color:var(--warning)">' + escapeHtml(a.blockedBecause) + '</div>' : '') +
    '</div>' +
    '<div style="text-align:right;white-space:nowrap">' +
    '<div class="num" style="font-size:14px;font-weight:600">' + bytes(sizeFor[a.key] ?? 0) + '</div>' +
    (a.allowed
      ? '<button class="btn btn-sm" style="margin-top:6px" data-run="' + a.key + '">Run</button>'
      : '<button class="btn btn-sm" style="margin-top:6px" data-copy="' + escapeHtml(a.command) + '">Copy</button>') +
    '</div></div>' +
    '<pre class="code" style="margin-top:9px">' + escapeHtml(a.command) + '</pre>' +
    '</div>';

  const body =
    '<div class="drawer-head"><div><b>Clean up ' + escapeHtml(host.serverName) + '</b></div>' +
    '<button class="icon-btn" data-close aria-label="Close"><svg viewBox="0 0 20 20" width="16" height="16"><path d="M5 5l10 10M15 5L5 15" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></button></div>' +
    '<h2 style="font-size:18px;margin:14px 0 4px">' + bytes(host.reclaimableBytes) + ' reclaimable</h2>' +
    '<p class="muted" style="font-size:12.5px;line-height:1.6">Docker root is <code>' + escapeHtml(host.rootDir ?? 'unknown') + '</code>. ' +
    'Every action below is a <code>prune</code>: Docker removes only what it considers unused, so a running container can never be caught by one.</p>' +
    '<div style="margin-top:16px">' + actions.map(row).join('') + '</div>' +
    '<div id="prune-result" style="margin-top:16px"></div>';

  openDrawer(body, {
    onMount: (drawer) => {
      drawer.querySelectorAll('[data-run]').forEach((b) =>
        b.addEventListener('click', () => confirmRun(host, actions.find((a) => a.key === b.dataset.run), onDone))
      );
    },
  });
}

function confirmRun(host, action, onDone) {
  const body =
    '<div class="drawer-head"><div><b>Confirm</b></div>' +
    '<button class="icon-btn" data-close aria-label="Close"><svg viewBox="0 0 20 20" width="16" height="16"><path d="M5 5l10 10M15 5L5 15" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></button></div>' +
    '<h2 style="font-size:17px;margin:14px 0 8px">' + escapeHtml(action.label) + '</h2>' +
    '<p class="muted" style="font-size:12.5px;line-height:1.6">Vigil will run this on <b>' + escapeHtml(host.serverName) + '</b> (' + escapeHtml(host.serverHost) + '):</p>' +
    commandBlock(action.command) +
    '<p class="muted" style="font-size:12.5px;line-height:1.6;margin-top:12px">' + escapeHtml(action.keeps) + '</p>' +
    (action.dataLoss
      ? '<div class="callout critical" style="margin-top:14px"><span class="bar"></span><div>' +
        '<b>This deletes data, not waste.</b> A volume whose container is merely stopped right now is indistinguishable from an abandoned one. ' +
        'Take a backup first if there is any doubt.</div></div>'
      : '') +
    '<p class="muted" style="font-size:11.5px;margin-top:12px">This is recorded in the audit log against your account, and the server is re-scanned straight afterwards.</p>' +
    '<div class="drawer-actions" style="margin-top:20px">' +
    '<button class="btn" data-close>Cancel</button>' +
    '<button class="btn btn-primary" data-confirm' + (action.dataLoss ? ' style="background:var(--critical);border-color:var(--critical)"' : '') + '>Run it</button>' +
    '</div>';

  openDrawer(body, {
    onMount: (drawer) => {
      drawer.querySelector('[data-confirm]').addEventListener('click', async (e) => {
        const btn = e.currentTarget;
        btn.disabled = true;
        btn.textContent = 'Running…';
        try {
          const res = await api.pruneDocker(host.serverId, action.key);
          toast(
            'Cleanup finished',
            res.reclaimed ? 'Reclaimed ' + res.reclaimed + ' on ' + host.serverName : 'Nothing to reclaim on ' + host.serverName
          );
          closeDrawer();
          onDone?.();
        } catch (err) {
          toast('Cleanup failed', err.message, 'critical');
          btn.disabled = false;
          btn.textContent = 'Run it';
        }
      });
    },
  });
}
