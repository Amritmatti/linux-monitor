// Overview: what is on fire, what is exposed, what is unpatched — in that order.

import { api } from '../api.js';
import { statTile, card, meter, healthBadge, statusBadge, emptyState, escapeHtml } from '../ui.js';
import { num, relative, duration } from '../format.js';
import { issueRows, wireIssueRows } from './shared.js';

export async function render(root, { app }) {
  const fleet = await api.fleet();
  app.fleet = fleet;
  const { servers, totals } = fleet;

  if (!servers.length) {
    root.innerHTML = card({
      body: emptyState(
        'No servers yet',
        'Add a Linux server and Vigil will log in over SSH, read what is there, and tell you what needs attention. Nothing is installed on the host.',
        '<a class="btn btn-primary" href="#/servers">Add your first server</a>'
      ),
    });
    return;
  }

  const issues = await api.issues({ acked: false });
  const critical = issues.items.filter((i) => i.severity === 'critical');
  const warnings = issues.items.filter((i) => i.severity === 'warning');

  const neverScanned = servers.filter((s) => !s.scannedAt).length;

  const tiles =
    '<div class="grid grid-4">' +
    statTile({
      label: 'Critical issues',
      value: num(totals.critical),
      tone: totals.critical ? 'critical' : 'good',
      foot: totals.critical ? '<span>across ' + num(new Set(critical.map((i) => i.serverId)).size) + ' servers</span>' : '<span>nothing needs you today</span>',
      href: '#/issues?severity=critical',
    }) +
    statTile({
      label: 'Warnings',
      value: num(totals.warning),
      tone: totals.warning ? 'warning' : 'good',
      foot: '<span>' + num(totals.acknowledged) + ' acknowledged</span>',
      href: '#/issues?severity=warning',
    }) +
    statTile({
      label: 'Security updates',
      value: num(totals.securityUpdates),
      tone: totals.securityUpdates ? 'critical' : 'good',
      foot: '<span>' + num(totals.pendingUpdates) + ' updates in total</span>',
      href: '#/updates',
      hint: 'Packages whose new version is published from a -security archive.',
    }) +
    statTile({
      label: 'Servers',
      value: num(totals.servers),
      tone: totals.unreachable ? 'warning' : undefined,
      foot: totals.unreachable
        ? '<span style="color:var(--critical)">' + num(totals.unreachable) + ' unreachable</span>'
        : neverScanned
          ? '<span>' + num(neverScanned) + ' never scanned</span>'
          : '<span>all reachable</span>',
      href: '#/servers',
    }) +
    '</div>';

  const secondary =
    '<div class="grid grid-4">' +
    statTile({ label: 'Reboots required', value: num(totals.rebootsRequired), tone: totals.rebootsRequired ? 'warning' : undefined, foot: '<span>installed but not running</span>', href: '#/updates' }) +
    statTile({ label: 'Exposed sockets', value: num(totals.exposedPorts), foot: '<span>reachable off-host</span>', href: '#/ports' }) +
    statTile({ label: 'Failed units', value: num(totals.failedUnits), tone: totals.failedUnits ? 'warning' : undefined, foot: '<span>systemd</span>', href: '#/issues?category=Services' }) +
    statTile({ label: 'Disk issues', value: num(totals.disksAtRisk), tone: totals.disksAtRisk ? 'warning' : undefined, foot: '<span>full, filling, or out of inodes</span>', href: '#/disks' }) +
    '</div>';

  const criticalCard = card({
    title: 'Needs attention now',
    subtitle: critical.length
      ? escapeHtml(critical.length + ' critical ' + (critical.length === 1 ? 'issue' : 'issues') + ' across the estate')
      : 'Nothing critical is open',
    actions: '<a class="btn btn-sm" href="#/issues">All issues</a>',
    pad: false,
    body: critical.length
      ? issueRows(critical.slice(0, 12))
      : emptyState('All clear', 'No critical issues on any server. Warnings and changes are on the Issues page.'),
  });

  const serverCards =
    '<div class="srv-grid">' +
    servers
      .map((s) => {
        const sum = s.summary;
        return (
          '<a class="srv-card" href="#/servers/' + s.id + '">' +
          '<div class="row" style="justify-content:space-between;align-items:flex-start;gap:8px">' +
          '<div><h4>' + escapeHtml(s.name) + '</h4><div class="host">' + escapeHtml(s.username) + '@' + escapeHtml(s.host) + '</div></div>' +
          healthBadge(s) +
          '</div>' +
          (sum
            ? '<div class="srv-metrics">' +
              '<div class="srv-metric"><span>Load</span><b>' + (sum.loadPerCore !== null ? sum.loadPerCore.toFixed(2) + '×' : '--') + '</b></div>' +
              '<div class="srv-metric"><span>Memory</span><b>' + (sum.memoryPct !== null ? Math.round(sum.memoryPct) + '%' : '--') + '</b></div>' +
              '<div class="srv-metric"><span>Disk</span><b>' + (sum.maxDiskPct !== null ? Math.round(sum.maxDiskPct) + '%' : '--') + '</b></div>' +
              '</div>' +
              '<div style="margin-top:11px">' + meter(sum.maxDiskPct) + '</div>' +
              '<div class="muted" style="font-size:11px;margin-top:9px">' +
              escapeHtml(sum.os ?? 'unknown OS') + ' · up ' + duration(sum.uptimeSeconds) +
              (sum.security ? ' · <span style="color:var(--critical)">' + sum.security + ' security updates</span>' : '') +
              '</div>'
            : '<div class="muted" style="font-size:11.5px;margin-top:14px">' +
              (s.scanError ? escapeHtml(truncate(s.scanError, 90)) : 'Not scanned yet') +
              '</div>') +
          '<div class="muted" style="font-size:11px;margin-top:7px">' + statusBadge(s.status, s.scanOk) + ' <span style="margin-left:6px">' + relative(s.scannedAt) + '</span></div>' +
          '</a>'
        );
      })
      .join('') +
    '</div>';

  root.innerHTML =
    '<div class="stack">' +
    tiles +
    secondary +
    criticalCard +
    (warnings.length
      ? card({
          title: 'Warnings',
          subtitle: escapeHtml(warnings.length + ' open'),
          actions: '<a class="btn btn-sm" href="#/issues?severity=warning">See all</a>',
          pad: false,
          body: issueRows(warnings.slice(0, 8)),
        })
      : '') +
    card({ title: 'Servers', subtitle: 'Last known state of each host', actions: '<a class="btn btn-sm" href="#/servers">Manage</a>', body: serverCards }) +
    '</div>';

  const all = [...critical, ...warnings];
  wireIssueRows(root, all, () => render(root, { app }));
}

function truncate(s, n) {
  const t = String(s ?? '');
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
}
