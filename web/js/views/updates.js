// Pending updates, security updates and outstanding reboots, per server.
//
// The distinction this page exists to make: an update that is available, an
// update that fixes a published vulnerability, and an update that is installed
// but is not running yet because nobody rebooted. All three are "not up to
// date" and only one of them is urgent.

import { api } from '../api.js';
import { card, dataTable, emptyState, escapeHtml, severityBadge, statTile, openDrawer, commandBlock } from '../ui.js';
import { num, relative, duration } from '../format.js';

export async function render(root, { app }) {
  const res = await api.updates();

  if (!res.items.length && !res.unknown.length) {
    root.innerHTML = card({ body: emptyState('Nothing collected yet', 'Scan a server and its pending updates appear here.') });
    return;
  }

  const tiles =
    '<div class="grid grid-4">' +
    statTile({
      label: 'Security updates',
      value: num(res.totals.security),
      tone: res.totals.security ? 'critical' : 'good',
      foot: '<span>fixes for published vulnerabilities</span>',
    }) +
    statTile({ label: 'All updates', value: num(res.totals.total), foot: '<span>across the estate</span>' }) +
    statTile({
      label: 'Reboots outstanding',
      value: num(res.totals.reboots),
      tone: res.totals.reboots ? 'warning' : 'good',
      foot: '<span>patched on disk, not in memory</span>',
    }) +
    statTile({
      label: 'Stale package lists',
      value: num(res.totals.staleLists),
      tone: res.totals.staleLists ? 'warning' : 'good',
      foot: '<span>counts below are a floor, not a total</span>',
      hint: 'A server whose package lists have not been refreshed reports fewer updates than it really has.',
    }) +
    '</div>';

  const table = dataTable({
    columns: [
      {
        label: 'Server',
        render: (u) =>
          '<a href="#/servers/' + u.serverId + '"><b>' + escapeHtml(u.serverName) + '</b></a>' +
          '<div class="muted" style="font-size:11px">' + escapeHtml(u.os ?? u.manager) + '</div>',
      },
      {
        label: 'Security',
        width: '104px',
        align: 'right',
        render: (u) =>
          !u.securityKnown
            ? severityBadge('warning', 'unknown')
            : u.security
              ? '<span style="color:var(--critical);font-weight:640;font-size:14px">' + u.security + '</span>'
              : '<span class="muted">0</span>',
      },
      { label: 'Total', width: '80px', align: 'right', render: (u) => num(u.total) },
      {
        label: 'Reboot',
        width: '112px',
        render: (u) =>
          u.rebootRequired ? severityBadge('warning', 'Required') : u.kernelStale ? severityBadge('warning', 'Kernel') : '<span class="muted">--</span>',
      },
      {
        label: 'Kernel',
        render: (u) =>
          '<span style="font-family:var(--mono);font-size:11px">' + escapeHtml(u.runningKernel ?? '--') + '</span>' +
          (u.kernelStale ? '<div class="muted" style="font-size:11px">' + escapeHtml(u.latestKernel) + ' installed</div>' : ''),
      },
      {
        label: 'Lists',
        width: '96px',
        align: 'right',
        render: (u) =>
          Number.isFinite(u.listsAgeSeconds)
            ? '<span class="' + (u.listsAgeSeconds > 604800 ? '' : 'muted') + '"' + (u.listsAgeSeconds > 604800 ? ' style="color:var(--warning)"' : '') + '>' +
              duration(u.listsAgeSeconds) + '</span>'
            : '<span class="muted">--</span>',
      },
      { label: '', width: '90px', align: 'right', render: (u) => (u.total ? '<button class="btn btn-sm" data-detail="' + u.serverId + '">Packages</button>' : '') },
    ],
    rows: res.items,
    empty: 'Nothing pending',
    rowAttrs: (u) => 'class="issue-row ' + (u.security ? 'is-critical' : u.rebootRequired || u.kernelStale ? 'is-warning' : '') + '"',
  });

  root.innerHTML =
    '<div class="stack">' +
    tiles +
    card({ title: 'By server', subtitle: res.items.length + ' servers reporting', pad: false, body: table }) +
    (res.unknown.length
      ? '<div class="callout"><span class="bar"></span><div><b>' + res.unknown.length + ' server' +
        (res.unknown.length === 1 ? '' : 's') + ' could not be asked about updates.</b> ' +
        '<span class="muted">No supported package manager answered on ' +
        res.unknown.map((u) => escapeHtml(u.serverName)).join(', ') +
        '. Their update counts are unknown, not zero.</span></div></div>'
      : '') +
    '</div>';

  root.querySelectorAll('[data-detail]').forEach((b) =>
    b.addEventListener('click', () => showPackages(res.items.find((i) => i.serverId === b.dataset.detail)))
  );
}

function showPackages(u) {
  if (!u) return;
  const rows = (u.packages ?? []).slice(0, 60);
  const body =
    '<div class="drawer-head"><div><b>' + escapeHtml(u.serverName) + '</b></div>' +
    '<button class="icon-btn" data-close aria-label="Close"><svg viewBox="0 0 20 20" width="16" height="16"><path d="M5 5l10 10M15 5L5 15" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></button></div>' +
    '<h2 style="font-size:17px;margin:14px 0 4px">' + u.security + ' security of ' + u.total + ' pending</h2>' +
    '<p class="muted" style="font-size:12.5px">' + escapeHtml(u.os ?? '') + ' · ' + escapeHtml(u.manager) +
    (Number.isFinite(u.listsAgeSeconds) ? ' · lists refreshed ' + duration(u.listsAgeSeconds) + ' ago' : '') + '</p>' +
    (u.rebootRequired
      ? '<div class="callout" style="margin-top:14px"><span class="bar"></span><div><b>Reboot required</b> ' +
        '<span class="muted">' + escapeHtml((u.rebootPackages ?? []).slice(0, 6).join(', ')) + '</span></div></div>'
      : '') +
    '<h4 class="section-label" style="margin-top:18px">Apply</h4>' +
    commandBlock(u.manager === 'apt' ? 'sudo apt-get update && sudo apt-get -y upgrade' : 'sudo dnf -y update --security') +
    '<h4 class="section-label" style="margin-top:18px">Packages</h4>' +
    (rows.length
      ? dataTable({
          columns: [
            { label: 'Package', render: (p) => '<span style="font-family:var(--mono);font-size:11.5px">' + escapeHtml(p.name) + '</span>' },
            { label: 'New version', render: (p) => '<span style="font-size:11.5px">' + escapeHtml(p.newVersion) + '</span>' },
            { label: '', width: '84px', align: 'right', render: (p) => (p.security ? severityBadge('critical', 'Security') : '') },
          ],
          rows,
        })
      : '<p class="muted">No package list was captured.</p>') +
    (u.truncated ? '<p class="muted" style="font-size:11.5px;margin-top:9px">Showing the first 60; the counts above are exact.</p>' : '');

  openDrawer(body);
}
