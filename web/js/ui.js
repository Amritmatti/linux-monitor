// Shared UI building blocks. Everything returns HTML strings except the pieces
// that need behaviour (drawer, toasts, chart cards), which take DOM nodes.

import { escapeHtml, money, moneyCompact, num, pct } from './format.js';

/* ----------------------------------------------------------------- badges */

export function riskBadge(band, score) {
  const cls = band === 'LOW' ? 'badge-low' : band === 'MEDIUM' ? 'badge-medium' : 'badge-high';
  const icon =
    band === 'LOW'
      ? '<svg viewBox="0 0 16 16" width="11" height="11"><path d="M3.5 8.5l3 3 6-7" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      : band === 'MEDIUM'
        ? '<svg viewBox="0 0 16 16" width="11" height="11"><path d="M8 2.5l6 11H2z" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linejoin="round"/><path d="M8 6.6v3.1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="8" cy="11.6" r="0.9" fill="currentColor"/></svg>'
        : '<svg viewBox="0 0 16 16" width="11" height="11"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.6" fill="none"/><path d="M8 4.6v4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><circle cx="8" cy="11.2" r="0.9" fill="currentColor"/></svg>';
  return '<span class="badge ' + cls + '">' + icon + band + (score !== undefined ? ' ' + score : '') + '</span>';
}

const STATUS_META = {
  pending: { cls: 'badge-neutral', label: 'Needs review' },
  accepted: { cls: 'badge-accent', label: 'To apply' },
  measuring: { cls: 'badge-accent', label: 'Measuring' },
  confirmed: { cls: 'badge-low', label: 'Confirmed' },
  done: { cls: 'badge-low', label: 'Done' },
  'not-detected': { cls: 'badge-medium', label: 'Not detected' },
  closed: { cls: 'badge-neutral', label: 'Closed' },
  rejected: { cls: 'badge-neutral', label: 'Rejected' },
  snoozed: { cls: 'badge-neutral', label: 'Snoozed' },
};

export function statusBadge(status) {
  const meta = STATUS_META[status] ?? { cls: 'badge-neutral', label: status };
  const live = status === 'measuring';
  return '<span class="badge ' + meta.cls + '">' + (live ? '<span class="dot dot-live" style="width:6px;height:6px"></span>' : '') + meta.label + '</span>';
}

export function policyBadge(action) {
  if (action === 'auto-approve') return '<span class="badge badge-low">Auto-file</span>';
  if (action === 'block') return '<span class="badge badge-serious">Frozen</span>';
  return '<span class="badge badge-neutral">Needs review</span>';
}

export function providerTag(provider) {
  const label = { aws: 'AWS', azure: 'Azure', gcp: 'GCP' }[provider] ?? provider;
  return '<span class="provider-tag provider-' + provider + '"><i></i>' + label + '</span>';
}

export function confidenceCell(value) {
  const p = Math.round(value * 100);
  const cls = p >= 90 ? 'good' : p >= 80 ? '' : 'warning';
  return (
    '<div class="row" style="gap:7px">' +
    '<div class="bar-track" style="width:44px"><div class="bar-value ' + cls + '" style="width:' + p + '%;background:' + (p >= 90 ? 'var(--good)' : p >= 80 ? 'var(--accent)' : 'var(--warning)') + '"></div></div>' +
    '<span class="num" style="font-size:11.5px">' + p + '%</span></div>'
  );
}

/* ------------------------------------------------------------------ tiles */

export function statTile({ label, value, delta, deltaLabel, deltaGood, foot, sparkId, hint }) {
  let deltaHtml = '';
  if (delta !== undefined && delta !== null) {
    const positive = delta >= 0;
    const good = deltaGood === undefined ? !positive : deltaGood;
    const arrow = positive
      ? '<svg viewBox="0 0 12 12" width="10" height="10"><path d="M6 2.5l4 5H2z" fill="currentColor"/></svg>'
      : '<svg viewBox="0 0 12 12" width="10" height="10"><path d="M6 9.5l-4-5h8z" fill="currentColor"/></svg>';
    deltaHtml =
      '<span class="stat-delta" style="color:' + (good ? 'var(--good-text)' : 'var(--critical)') + '">' + arrow + Math.abs(delta).toFixed(1) + '%</span>' +
      (deltaLabel ? '<span>' + escapeHtml(deltaLabel) + '</span>' : '');
  }
  return (
    '<div class="card stat">' +
    '<div class="stat-label">' + escapeHtml(label) + (hint ? ' <span class="muted" title="' + escapeHtml(hint) + '">&#9432;</span>' : '') + '</div>' +
    '<div class="stat-value">' + value + '</div>' +
    '<div class="stat-foot">' + deltaHtml + (foot ? '<span>' + foot + '</span>' : '') + '</div>' +
    (sparkId ? '<div class="stat-spark" id="' + sparkId + '"></div>' : '') +
    '</div>'
  );
}

/* ------------------------------------------------------------------ cards */

/**
 * A chart card with a chart/table toggle. Every chart in this product has a
 * table twin so no value is reachable only by hovering.
 */
export function chartCard({ id, title, subtitle, actions = '', legendHtml = '', tableHtml = '', height }) {
  return (
    '<section class="card">' +
    '<div class="card-head"><div><h3>' + escapeHtml(title) + '</h3>' + (subtitle ? '<p>' + subtitle + '</p>' : '') + '</div>' +
    '<div class="card-head-actions">' + actions +
    (tableHtml
      ? '<div class="chart-toggle" data-toggle="' + id + '"><button class="active" data-mode="chart">Chart</button><button data-mode="table">Table</button></div>'
      : '') +
    '</div></div>' +
    '<div class="card-body">' +
    '<div id="' + id + '" class="chart"' + (height ? ' style="min-height:' + height + 'px"' : '') + '></div>' +
    legendHtml +
    (tableHtml ? '<div id="' + id + '-table" hidden class="table-wrap" style="max-height:300px;overflow:auto">' + tableHtml + '</div>' : '') +
    '</div></section>'
  );
}

export function wireChartToggles(root) {
  root.querySelectorAll('.chart-toggle').forEach((group) => {
    const id = group.dataset.toggle;
    group.addEventListener('click', (e) => {
      const btn = e.target.closest('button');
      if (!btn) return;
      group.querySelectorAll('button').forEach((b) => b.classList.toggle('active', b === btn));
      const chart = document.getElementById(id);
      const table = document.getElementById(id + '-table');
      const showTable = btn.dataset.mode === 'table';
      if (chart) chart.hidden = showTable;
      const legendEl = chart?.parentElement?.querySelector('.legend');
      if (legendEl) legendEl.hidden = showTable;
      if (table) table.hidden = !showTable;
    });
  });
}

const SORT_ARROW = {
  asc: '<svg viewBox="0 0 12 12" width="9" height="9" aria-hidden="true"><path d="M6 2.5l3.5 5h-7z" fill="currentColor"/></svg>',
  desc: '<svg viewBox="0 0 12 12" width="9" height="9" aria-hidden="true"><path d="M6 9.5l-3.5-5h7z" fill="currentColor"/></svg>',
};

/**
 * @param {object} cfg
 * @param {Array} cfg.columns  a column carrying `sortKey` becomes a sort button
 * @param {string} [cfg.sort]  the sortKey currently ordering the table
 * @param {string} [cfg.dir]   'asc' | 'desc'
 */
export function dataTable({ columns, rows, empty = 'Nothing to show', rowAttrs, sort = null, dir = 'desc' }) {
  if (!rows.length) return '<div class="empty"><h4>' + escapeHtml(empty) + '</h4></div>';

  const head = columns
    .map((c) => {
      const active = !!c.sortKey && c.sortKey === sort;
      const cls = [c.align === 'right' ? 'num' : '', c.sortKey ? 'sortable' : '', active ? 'sorted' : ''].filter(Boolean).join(' ');
      const label = escapeHtml(c.label);
      // The arrow shows the direction the active column is ordered in. Inactive
      // columns keep theirs hidden until hover, so eight arrows do not all
      // compete for attention at once.
      const inner = c.sortKey
        ? '<button type="button" class="th-sort" data-sort="' + escapeHtml(c.sortKey) + '">' +
          label + '<span class="sort-arrow">' + (active ? SORT_ARROW[dir] ?? SORT_ARROW.desc : SORT_ARROW.desc) + '</span></button>'
        : label;
      return (
        '<th' + (cls ? ' class="' + cls + '"' : '') +
        (c.width ? ' style="width:' + c.width + '"' : '') +
        (active ? ' aria-sort="' + (dir === 'asc' ? 'ascending' : 'descending') + '"' : '') +
        '>' + inner + '</th>'
      );
    })
    .join('');
  const body = rows
    .map((r, i) => {
      const attrs = rowAttrs ? rowAttrs(r, i) : '';
      const cells = columns.map((c) => '<td' + (c.align === 'right' ? ' class="num"' : '') + '>' + c.render(r, i) + '</td>').join('');
      return '<tr ' + attrs + '>' + cells + '</tr>';
    })
    .join('');
  return '<table class="data"><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table>';
}

export function emptyState(title, detail) {
  return '<div class="empty"><h4>' + escapeHtml(title) + '</h4><p>' + escapeHtml(detail ?? '') + '</p></div>';
}

export function callout(kind, html) {
  return '<div class="callout ' + kind + '"><span class="bar"></span><div>' + html + '</div></div>';
}

/* ----------------------------------------------------------------- drawer */

let drawerCloser = null;

export function openDrawer(html, { onMount } = {}) {
  const drawer = document.getElementById('drawer');
  const scrim = document.getElementById('drawer-scrim');
  drawer.innerHTML = html;
  drawer.hidden = false;
  scrim.hidden = false;
  document.body.style.overflow = 'hidden';
  drawer.scrollTop = 0;

  const close = () => closeDrawer();
  scrim.onclick = close;
  drawer.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', close));
  drawerCloser = close;
  document.addEventListener('keydown', escHandler);
  onMount?.(drawer);
  return drawer;
}

export function updateDrawer(html, { onMount } = {}) {
  const drawer = document.getElementById('drawer');
  if (drawer.hidden) return;
  const scroll = drawer.scrollTop;
  drawer.innerHTML = html;
  drawer.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', closeDrawer));
  drawer.scrollTop = scroll;
  onMount?.(drawer);
}

function escHandler(e) {
  if (e.key === 'Escape') closeDrawer();
}

export function closeDrawer() {
  const drawer = document.getElementById('drawer');
  const scrim = document.getElementById('drawer-scrim');
  drawer.hidden = true;
  scrim.hidden = true;
  drawer.innerHTML = '';
  document.body.style.overflow = '';
  document.removeEventListener('keydown', escHandler);
  drawerCloser = null;
}

export function isDrawerOpen() {
  return !document.getElementById('drawer').hidden;
}

/* ----------------------------------------------------------------- toasts */

export function toast(title, detail, kind = '') {
  const host = document.getElementById('toasts');
  const node = document.createElement('div');
  node.className = 'toast ' + kind;
  node.innerHTML = '<span class="bar"></span><div><b>' + escapeHtml(title) + '</b><span class="muted">' + escapeHtml(detail ?? '') + '</span></div>';
  host.appendChild(node);
  setTimeout(() => {
    node.style.opacity = '0';
    node.style.transition = 'opacity .25s ease';
    setTimeout(() => node.remove(), 260);
  }, 4600);
}

/* --------------------------------------------------------------- skeleton */

export function skeleton(rows = 4) {
  let out = '<div class="stack">';
  out += '<div class="grid grid-4">' + Array.from({ length: 4 }, () => '<div class="card skeleton" style="height:104px"></div>').join('') + '</div>';
  for (let i = 0; i < rows; i++) out += '<div class="card skeleton" style="height:' + (i % 2 ? 180 : 260) + 'px"></div>';
  return out + '</div>';
}

/* --------------------------------------------------------------- exports */

export { money, moneyCompact, num, pct, escapeHtml };
