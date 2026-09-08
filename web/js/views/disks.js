// Every filesystem in the estate, fullest first, with the inode column beside
// the usage column — because the filesystem that takes a service down is
// usually the one with space free and no inodes left.

import { api } from '../api.js';
import { card, dataTable, emptyState, escapeHtml, meter, severityBadge, statTile } from '../ui.js';
import { bytes, num, relative } from '../format.js';

export async function render(root, { app }) {
  const [res, issues] = await Promise.all([api.disks(), api.issues({ category: 'Disk', acked: '' })]);
  const search = (app.searchTerm ?? '').toLowerCase();

  if (!res.items.length) {
    root.innerHTML = card({ body: emptyState('Nothing collected yet', 'Scan a server and its filesystems appear here.') });
    return;
  }

  const items = search
    ? res.items.filter((d) => (d.serverName + ' ' + d.mount + ' ' + d.filesystem).toLowerCase().includes(search))
    : res.items;

  // Forecasts come from the anomaly engine, and belong next to the disk they
  // are about rather than on a separate page.
  const trendByKey = new Map(
    issues.items.filter((i) => i.key.startsWith('anomaly:disk-trend:')).map((i) => [i.serverId + i.key.replace('anomaly:disk-trend:', ''), i])
  );

  const usedPct = res.totals.totalBytes ? (res.totals.usedBytes / res.totals.totalBytes) * 100 : 0;

  const tiles =
    '<div class="grid grid-4">' +
    statTile({ label: 'Filesystems', value: num(res.totals.filesystems), foot: '<span>across the estate</span>' }) +
    statTile({ label: 'Over 90% full', value: num(res.totals.critical), tone: res.totals.critical ? 'critical' : 'good', foot: '<span>a log burst fills these</span>' }) +
    statTile({ label: 'Over 80% full', value: num(res.totals.warning), tone: res.totals.warning ? 'warning' : 'good', foot: '<span>worth clearing soon</span>' }) +
    statTile({
      label: 'Total capacity',
      value: bytes(res.totals.totalBytes),
      foot: '<span>' + bytes(res.totals.usedBytes) + ' used (' + Math.round(usedPct) + '%)</span>',
    }) +
    '</div>';

  const table = dataTable({
    columns: [
      {
        label: 'Mount',
        render: (d) =>
          '<b style="font-family:var(--mono);font-size:12px">' + escapeHtml(d.mount) + '</b>' +
          '<div class="muted" style="font-size:11px">' + escapeHtml(d.filesystem) + '</div>',
      },
      {
        label: 'Server',
        width: '160px',
        render: (d) => '<a href="#/servers/' + d.serverId + '">' + escapeHtml(d.serverName) + '</a>',
      },
      { label: 'Usage', width: '190px', render: (d) => meter(d.usedPct) },
      { label: 'Free', width: '92px', align: 'right', render: (d) => bytes(d.availBytes) },
      { label: 'Size', width: '92px', align: 'right', render: (d) => bytes(d.totalBytes) },
      {
        label: 'Inodes',
        width: '160px',
        render: (d) => (Number.isFinite(d.inodesUsedPct) ? meter(d.inodesUsedPct, { warn: 85, crit: 90 }) : '<span class="muted">n/a</span>'),
      },
      {
        label: 'Forecast',
        width: '130px',
        align: 'right',
        render: (d) => {
          const t = trendByKey.get(d.serverId + d.mount);
          if (!t) return '<span class="muted">stable</span>';
          return severityBadge(t.severity, 'full in ' + (t.value < 1 ? '<1d' : Math.round(t.value) + 'd'));
        },
      },
      { label: 'Seen', width: '80px', align: 'right', render: (d) => '<span class="muted">' + relative(d.observedAt) + '</span>' },
    ],
    rows: items,
    empty: 'No filesystem matches',
    rowAttrs: (d) =>
      'class="issue-row ' + (d.usedPct >= 90 || d.inodesUsedPct >= 90 ? 'is-critical' : d.usedPct >= 80 || d.inodesUsedPct >= 85 ? 'is-warning' : '') + '"',
  });

  const filling = [...trendByKey.values()];

  root.innerHTML =
    '<div class="stack">' +
    tiles +
    (filling.length
      ? '<div class="callout"><span class="bar"></span><div><b>' + filling.length + ' filesystem' + (filling.length === 1 ? ' is' : 's are') +
        ' filling steadily.</b> <span class="muted">The forecast column is a median slope over every pair of recent scans, so one ' +
        'unusual reading cannot swing it. A disk that is only 60% full but climbing is often more urgent than one that has sat at 88% for a year.</span></div></div>'
      : '') +
    card({ title: 'Filesystems', subtitle: items.length + ' shown, fullest first', pad: false, body: table }) +
    '</div>';
}
