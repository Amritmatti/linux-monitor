// Every listening socket in the estate, riskiest first.
//
// The organising idea is exposure, not port number: 5432 on 127.0.0.1 is
// correct and 5432 on 0.0.0.0 may be a database open to the internet, and a
// table that sorts them together teaches people to skim past both.

import { api } from '../api.js';
import { card, dataTable, emptyState, escapeHtml, severityBadge, statTile } from '../ui.js';
import { num, relative } from '../format.js';

const state = { scope: 'all' };

export async function render(root, { app }) {
  const res = await api.ports();
  const search = (app.searchTerm ?? '').toLowerCase();

  let items = res.items;
  if (state.scope === 'risky') items = items.filter((i) => i.risky);
  else if (state.scope === 'exposed') items = items.filter((i) => i.exposed);
  else if (state.scope === 'local') items = items.filter((i) => !i.exposed);
  if (search) {
    items = items.filter((i) =>
      (i.serverName + ' ' + i.port + ' ' + (i.process ?? '') + ' ' + (i.service ?? '') + ' ' + i.address).toLowerCase().includes(search)
    );
  }

  if (!res.items.length) {
    root.innerHTML = card({ body: emptyState('Nothing collected yet', 'Scan a server and its listening sockets appear here.') });
    return;
  }

  const tiles =
    '<div class="grid grid-4">' +
    statTile({ label: 'Listening sockets', value: num(res.totals.listening), foot: '<span>across the estate</span>' }) +
    statTile({ label: 'Reachable off-host', value: num(res.totals.exposed), foot: '<span>bound to a routable address</span>', tone: res.totals.exposed ? 'warning' : 'good' }) +
    statTile({
      label: 'Exposed and risky',
      value: num(res.totals.risky),
      tone: res.totals.risky ? 'critical' : 'good',
      foot: '<span>databases, admin APIs, cleartext protocols</span>',
    }) +
    statTile({
      label: 'Process unknown',
      value: num(res.totals.unnamed),
      foot: '<span>owned by another user; needs sudo to name</span>',
      hint: 'ss only names processes the login owns. This is the expected cost of running unprivileged.',
    }) +
    '</div>';

  const chip = (value, label, count) =>
    '<button class="chip' + (state.scope === value ? ' active' : '') + '" data-scope="' + value + '">' +
    label + ' <span class="chip-count">' + count + '</span></button>';

  const filters =
    '<div class="filter-bar"><div class="filter-row">' +
    chip('all', 'All', res.totals.listening) +
    chip('risky', 'Risky', res.totals.risky) +
    chip('exposed', 'Reachable', res.totals.exposed) +
    chip('local', 'Loopback only', res.totals.listening - res.totals.exposed) +
    '</div></div>';

  const table = dataTable({
    columns: [
      {
        label: 'Port',
        width: '112px',
        render: (p) => '<span class="port' + (p.risky ? ' is-risky' : p.exposed ? ' is-exposed' : '') + '">' + p.proto + '/' + p.port + '</span>',
      },
      {
        label: 'Service',
        render: (p) =>
          (p.service ? '<b>' + escapeHtml(p.service) + '</b>' : p.process ? escapeHtml(p.process) : '<span class="muted">unidentified</span>') +
          (p.process && p.service ? ' <span class="muted">(' + escapeHtml(p.process) + ')</span>' : '') +
          (p.why ? '<div class="muted" style="font-size:11.5px;margin-top:2px">' + escapeHtml(p.why) + '</div>' : ''),
      },
      { label: 'Bound to', width: '140px', render: (p) => '<span style="font-family:var(--mono);font-size:11.5px">' + escapeHtml(p.address) + '</span>' },
      {
        label: 'Server',
        width: '160px',
        render: (p) => '<a href="#/servers/' + p.serverId + '">' + escapeHtml(p.serverName) + '</a>',
      },
      {
        label: 'Exposure',
        width: '118px',
        align: 'right',
        render: (p) => (p.risky ? severityBadge('critical', 'Risky') : p.exposed ? severityBadge('warning', 'Off-host') : severityBadge('ok', 'Loopback')),
      },
      { label: 'Seen', width: '84px', align: 'right', render: (p) => '<span class="muted">' + relative(p.observedAt) + '</span>' },
    ],
    rows: items,
    empty: 'No sockets match',
    rowAttrs: (p) => 'class="issue-row ' + (p.risky ? 'is-critical' : p.exposed ? 'is-warning' : '') + '"',
  });

  root.innerHTML =
    '<div class="stack">' +
    tiles +
    (res.totals.risky
      ? '<div class="callout critical"><span class="bar"></span><div><b>' + res.totals.risky +
        ' risky service' + (res.totals.risky === 1 ? ' is' : 's are') + ' reachable from off their host.</b> ' +
        '<span class="muted">Each one is on the Issues page as a critical finding with the command to check it.</span></div></div>'
      : '') +
    filters +
    card({ title: 'Listening sockets', subtitle: items.length + ' shown', pad: false, body: table }) +
    '</div>';

  root.querySelectorAll('[data-scope]').forEach((b) =>
    b.addEventListener('click', () => {
      state.scope = b.dataset.scope;
      render(root, { app });
    })
  );
}
