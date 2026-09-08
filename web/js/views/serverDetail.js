// One server, in full: what it is, what is wrong with it, and how it has been
// behaving.

import { api } from '../api.js';
import { card, dataTable, emptyState, escapeHtml, meter, severityBadge, statusBadge, sparkline, toast, wireCopy } from '../ui.js';
import { bytes, relative, duration, num, ms, dateTime } from '../format.js';
import { issueRows, wireIssueRows, limitedCallout } from './shared.js';
import { showForm } from './servers.js';

export async function render(root, { params, app }) {
  const d = await api.server(params.id);
  const { server, facts, findings, anomalies, series, history, limited } = d;

  document.getElementById('page-title').textContent = server.name;

  const header =
    '<div class="card" style="padding:17px 19px">' +
    '<div class="row" style="justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap">' +
    '<div>' +
    '<div class="row" style="gap:9px;align-items:center">' +
    '<h2 style="font-size:19px;letter-spacing:-.025em">' + escapeHtml(server.name) + '</h2>' +
    statusBadge(server.status, d.scan?.ok) +
    '</div>' +
    '<div class="muted" style="font-family:var(--mono);font-size:11.5px;margin-top:4px">' +
    escapeHtml(server.username) + '@' + escapeHtml(server.host) + (server.port !== 22 ? ':' + server.port : '') +
    '</div>' +
    (facts
      ? '<div class="muted" style="font-size:12px;margin-top:7px">' +
        escapeHtml(facts.host?.os?.name ?? 'unknown OS') + ' · kernel ' + escapeHtml(facts.host?.kernel ?? '?') +
        ' · ' + escapeHtml(facts.host?.arch ?? '?') +
        (facts.host?.virt && facts.host.virt !== 'none' ? ' · ' + escapeHtml(facts.host.virt) : '') +
        ' · up ' + duration(facts.host?.uptimeSeconds) +
        '</div>'
      : '') +
    '</div>' +
    '<div class="row" style="gap:8px">' +
    '<button class="btn btn-sm" id="edit-server">Edit</button>' +
    '<button class="btn btn-sm btn-primary" id="scan-server">Scan now</button>' +
    '</div></div></div>';

  // A failed scan never blanks the page: the last good picture stays, labelled.
  const staleBanner = d.stale
    ? '<div class="callout critical"><span class="bar"></span><div>' +
      '<b>This server is currently unreachable.</b> ' + escapeHtml(server.lastError ?? '') +
      '<div class="muted" style="font-size:11.5px;margin-top:6px">Everything below is from the last successful scan, ' +
      relative(d.factsFrom) + '.</div></div></div>'
    : '';

  const neverScanned = !facts
    ? card({
        body: emptyState(
          d.scan ? 'Could not connect' : 'Not scanned yet',
          d.scan?.error ?? 'Run a scan to collect this server\'s state for the first time.',
          '<button class="btn btn-primary" id="scan-empty">Scan now</button>'
        ),
      })
    : '';

  root.innerHTML =
    '<div class="stack">' +
    header +
    staleBanner +
    neverScanned +
    (facts ? limitedCallout(limited) : '') +
    (facts ? tiles(facts) : '') +
    (findings.length || anomalies.length
      ? card({
          title: 'Issues',
          subtitle: escapeHtml(
            findings.filter((f) => !f.acked).length + ' open, ' + anomalies.filter((a) => !a.acked).length + ' recent changes'
          ),
          pad: false,
          body: issueRows([...findings, ...anomalies].map((i) => ({ ...i, serverId: server.id, serverName: server.name, observedAt: d.factsFrom })), { showServer: false }),
        })
      : facts
        ? card({ title: 'Issues', body: emptyState('Clear', 'No findings or anomalies on this server.') })
        : '') +
    (facts ? trends(series) : '') +
    (facts ? disksCard(facts) : '') +
    (facts ? portsCard(facts) : '') +
    (facts ? updatesCard(facts) : '') +
    (facts ? servicesCard(facts) : '') +
    (facts ? securityCard(facts, server) : '') +
    historyCard(history, d.scan) +
    '</div>';

  const reload = () => render(root, { params, app });

  root.querySelector('#edit-server')?.addEventListener('click', () => showForm(server, reload));

  for (const id of ['#scan-server', '#scan-empty']) {
    root.querySelector(id)?.addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      btn.textContent = 'Scanning…';
      try {
        const res = await api.scanServer(server.id);
        if (!res.ok) toast('Could not connect', res.error, 'critical');
      } catch (err) {
        toast('Scan failed', err.message, 'critical');
      } finally {
        reload();
      }
    });
  }

  wireIssueRows(root, [...findings, ...anomalies].map((i) => ({ ...i, serverId: server.id, serverName: server.name })), reload);
  wireCopy(root);
}

/* ------------------------------------------------------------------- pieces */

function tiles(f) {
  const load = f.cpu?.loadPerCore;
  const mem = f.memory?.usedPct;
  const disk = (f.disks ?? []).reduce((a, d) => Math.max(a, d.usedPct ?? 0), 0);
  const sec = f.updates?.security;

  const tile = (label, value, sub, tone) =>
    '<div class="card stat"><div class="stat-label">' + label + '</div>' +
    '<div class="stat-value" style="color:' + (tone ?? 'inherit') + '">' + value + '</div>' +
    '<div class="stat-foot"><span>' + sub + '</span></div></div>';

  return (
    '<div class="grid grid-4">' +
    tile(
      'Load per core',
      load != null ? load.toFixed(2) + '×' : '--',
      f.cpu?.load1 + ' / ' + f.cpu?.load5 + ' / ' + f.cpu?.load15 + ' over ' + num(f.cpu?.cores) + ' cores',
      load >= 2 ? 'var(--critical)' : load >= 1 ? 'var(--warning)' : undefined
    ) +
    tile(
      'Memory used',
      mem != null ? Math.round(mem) + '%' : '--',
      bytes(f.memory?.available) + ' available of ' + bytes(f.memory?.total),
      mem >= 90 ? 'var(--critical)' : mem >= 85 ? 'var(--warning)' : undefined
    ) +
    tile('Fullest disk', disk ? Math.round(disk) + '%' : '--', num((f.disks ?? []).length) + ' filesystems', disk >= 90 ? 'var(--critical)' : disk >= 80 ? 'var(--warning)' : undefined) +
    tile(
      'Security updates',
      f.updates ? num(sec) : '--',
      f.updates ? num(f.updates.total) + ' updates pending' : 'no package manager readable',
      sec > 0 ? 'var(--critical)' : undefined
    ) +
    '</div>'
  );
}

/** Trend lines. Nothing is reachable only by hovering: the value is beside it. */
function trends(series) {
  if (series.length < 3) return '';
  const spark = (key, label, tone, fmt) => {
    const values = series.map((s) => s[key]).filter((v) => Number.isFinite(v));
    if (values.length < 3) return '';
    const last = values[values.length - 1];
    return (
      '<div>' +
      '<div class="row" style="justify-content:space-between;align-items:baseline">' +
      '<span class="stat-label">' + label + '</span>' +
      '<span class="num" style="font-size:13px;font-weight:600">' + fmt(last) + '</span></div>' +
      sparkline(values, { tone }) +
      '</div>'
    );
  };

  const body =
    '<div class="grid grid-3">' +
    spark('loadPerCore', 'Load per core', 'var(--s1)', (v) => v.toFixed(2) + '×') +
    spark('memoryPct', 'Memory used', 'var(--s2)', (v) => Math.round(v) + '%') +
    spark('security', 'Security updates', 'var(--critical)', (v) => num(v)) +
    '</div>';

  return card({
    title: 'Trend',
    subtitle: series.length + ' scans, ' + relative(series[0].at).replace(' ago', '') + ' of history',
    body,
  });
}

function disksCard(f) {
  const disks = f.disks ?? [];
  if (!disks.length) return '';
  return card({
    title: 'Filesystems',
    pad: false,
    body: dataTable({
      columns: [
        { label: 'Mount', render: (d) => '<b style="font-family:var(--mono);font-size:12px">' + escapeHtml(d.mount) + '</b><div class="muted" style="font-size:11px">' + escapeHtml(d.filesystem) + '</div>' },
        { label: 'Usage', width: '180px', render: (d) => meter(d.usedPct) },
        { label: 'Free', width: '96px', align: 'right', render: (d) => bytes(d.availBytes) },
        { label: 'Size', width: '96px', align: 'right', render: (d) => bytes(d.totalBytes) },
        {
          label: 'Inodes',
          width: '150px',
          render: (d) => (Number.isFinite(d.inodesUsedPct) ? meter(d.inodesUsedPct, { warn: 85, crit: 90 }) : '<span class="muted">n/a</span>'),
        },
      ],
      rows: disks,
    }),
  });
}

function portsCard(f) {
  const ports = f.ports ?? [];
  if (!ports.length) return '';
  const exposed = ports.filter((p) => p.exposed);
  return card({
    title: 'Listening sockets',
    subtitle: ports.length + ' listening, ' + exposed.length + ' reachable from off this host',
    pad: false,
    body: dataTable({
      columns: [
        { label: 'Port', width: '96px', render: (p) => '<span class="port' + (p.exposed ? ' is-exposed' : '') + '">' + p.proto + '/' + p.port + '</span>' },
        { label: 'Bound to', width: '150px', render: (p) => '<span style="font-family:var(--mono);font-size:11.5px">' + escapeHtml(p.address) + '</span>' },
        { label: 'Process', render: (p) => (p.process ? escapeHtml(p.process) + (p.pid ? ' <span class="muted">(' + p.pid + ')</span>' : '') : '<span class="muted">not visible without sudo</span>') },
        {
          label: 'Reachable',
          width: '116px',
          align: 'right',
          render: (p) => (p.exposed ? severityBadge('warning', 'Off-host') : severityBadge('ok', 'Loopback')),
        },
      ],
      rows: ports,
    }),
  });
}

function updatesCard(f) {
  const u = f.updates;
  if (!u) {
    return card({
      title: 'Updates',
      body: '<div class="callout"><span class="bar"></span><div><b>No supported package manager answered.</b> ' +
        '<span class="muted">Update counts for this host are unknown rather than zero.</span></div></div>',
    });
  }

  const rebootRow = f.reboot?.required
    ? '<div class="callout" style="margin-bottom:13px"><span class="bar"></span><div><b>Reboot required.</b> ' +
      escapeHtml((f.reboot.packages ?? []).slice(0, 5).join(', ') || 'updated packages are installed but not running') +
      '</div></div>'
    : '';

  const kernelRow =
    f.reboot?.kernelStale
      ? '<div class="callout"><span class="bar"></span><div><b>Kernel ' + escapeHtml(f.reboot.latestKernel) + ' is installed</b> but ' +
        escapeHtml(f.reboot.runningKernel) + ' is running.</div></div>'
      : '';

  const packages = (u.packages ?? []).slice(0, 30);

  return card({
    title: 'Updates',
    subtitle: u.security + ' security of ' + u.total + ' pending · ' + escapeHtml(u.manager) +
      (Number.isFinite(u.listsAgeSeconds) ? ' · lists refreshed ' + duration(u.listsAgeSeconds) + ' ago' : ''),
    body:
      rebootRow + kernelRow +
      (packages.length
        ? dataTable({
            columns: [
              { label: 'Package', render: (p) => '<span style="font-family:var(--mono);font-size:11.5px">' + escapeHtml(p.name) + '</span>' },
              { label: 'Current', render: (p) => '<span class="muted" style="font-size:11.5px">' + escapeHtml(p.currentVersion ?? '--') + '</span>' },
              { label: 'New', render: (p) => '<span style="font-size:11.5px">' + escapeHtml(p.newVersion) + '</span>' },
              { label: '', width: '86px', align: 'right', render: (p) => (p.security ? severityBadge('critical', 'Security') : '') },
            ],
            rows: packages,
          }) + (u.truncated ? '<p class="muted" style="font-size:11.5px;margin-top:9px">Showing the first 30; the counts above are exact.</p>' : '')
        : '<div class="empty" style="padding:24px"><h4>Fully up to date</h4></div>'),
    pad: true,
  });
}

function servicesCard(f) {
  const failed = f.services?.failed ?? [];
  if (!failed.length) return '';
  return card({
    title: 'Failed units',
    subtitle: 'systemd is ' + escapeHtml(f.services.systemState ?? 'unknown'),
    pad: false,
    body: dataTable({
      columns: [
        { label: 'Unit', render: (u) => '<b style="font-family:var(--mono);font-size:12px">' + escapeHtml(u.unit) + '</b>' },
        { label: 'Description', render: (u) => '<span class="muted">' + escapeHtml(u.description ?? '') + '</span>' },
        { label: 'State', width: '130px', align: 'right', render: (u) => severityBadge('critical', u.active + '/' + u.sub) },
      ],
      rows: failed,
    }),
  });
}

function securityCard(f, server) {
  const s = f.security ?? {};
  const sshd = s.sshd ?? {};
  const row = (k, v, tone) =>
    '<dt>' + escapeHtml(k) + '</dt><dd' + (tone ? ' style="color:' + tone + '"' : '') + '>' + escapeHtml(String(v)) + '</dd>';

  return card({
    title: 'Security posture',
    subtitle: 'sshd settings read from ' + (s.sshdSource === 'effective' ? 'sshd -T' : s.sshdSource === 'config' ? '/etc/ssh/sshd_config' : 'nowhere'),
    body:
      '<dl class="kv">' +
      row('Root login', sshd.permitrootlogin ?? 'not set in config', sshd.permitrootlogin === 'yes' ? 'var(--critical)' : undefined) +
      row('Password authentication', sshd.passwordauthentication ?? 'not set in config', sshd.passwordauthentication === 'yes' ? 'var(--warning)' : undefined) +
      row(
        'Failed logins (24h)',
        s.authFailures24h === null || s.authFailures24h === undefined ? 'log not readable' : num(s.authFailures24h),
        s.authFailures24h >= 100 ? 'var(--warning)' : undefined
      ) +
      row('Users logged in', num(s.loggedInUsers ?? 0)) +
      row('Clock synchronised', f.time?.ntpSynchronized === null ? 'unknown' : f.time?.ntpSynchronized ? 'yes' : 'no') +
      row('Clock skew', (f.time?.skewSeconds ?? 0) + 's') +
      row('Zombie processes', num(f.processes?.zombies ?? 0)) +
      '</dl>' +
      (server.hostKeyFp
        ? '<div style="margin-top:14px"><div class="stat-label">Pinned host key</div><div class="fp" style="margin-top:4px">' + escapeHtml(server.hostKeyFp) + '</div></div>'
        : ''),
  });
}

function historyCard(history, currentScan) {
  if (!history.length) return '';
  return card({
    title: 'Scan history',
    subtitle: 'The last ' + history.length + ' collections',
    pad: false,
    body: dataTable({
      columns: [
        { label: 'When', render: (h) => dateTime(h.startedAt) + ' <span class="muted">(' + relative(h.startedAt) + ')</span>' },
        { label: 'Result', width: '132px', render: (h) => (h.ok ? severityBadge('ok', 'OK') : severityBadge('critical', 'Failed')) },
        { label: 'Critical', width: '86px', align: 'right', render: (h) => (h.critical ? '<span style="color:var(--critical)">' + h.critical + '</span>' : '<span class="muted">0</span>') },
        { label: 'Warnings', width: '86px', align: 'right', render: (h) => (h.warning ? h.warning : '<span class="muted">0</span>') },
        { label: 'Took', width: '80px', align: 'right', render: (h) => '<span class="muted">' + ms(h.durationMs) + '</span>' },
        { label: 'Detail', render: (h) => (h.error ? '<span class="muted" style="font-size:11.5px">' + escapeHtml(h.error.slice(0, 90)) + '</span>' : '') },
      ],
      rows: history,
    }),
  });
}
