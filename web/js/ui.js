// Shared UI building blocks. Everything returns HTML strings except the pieces
// that need behaviour (drawer, toasts), which take DOM nodes.

import { escapeHtml, num, pct, bytes, relative } from './format.js';

/* ---------------------------------------------------------------- severity */

const SEV_LABEL = { critical: 'Critical', warning: 'Warning', info: 'Info', ok: 'OK' };

export function severityBadge(severity, label) {
  const s = SEV_LABEL[severity] ? severity : 'muted';
  return '<span class="sev sev-' + s + '"><i></i>' + escapeHtml(label ?? SEV_LABEL[severity] ?? severity) + '</span>';
}

/** Connection state of a server, which is not the same thing as its health. */
export function statusBadge(status, scanOk) {
  if (status === 'disabled') return severityBadge('muted', 'Paused');
  if (status === 'pending') return severityBadge('muted', 'Never scanned');
  if (status === 'error' || scanOk === false) return severityBadge('critical', 'Unreachable');
  return severityBadge('ok', 'Reachable');
}

/** Health rolled up from counts. Distinct from reachability on purpose. */
export function healthBadge({ critical = 0, warning = 0 }) {
  if (critical) return severityBadge('critical', critical + ' critical');
  if (warning) return severityBadge('warning', warning + ' warning' + (warning === 1 ? '' : 's'));
  return severityBadge('ok', 'Clear');
}

/* ------------------------------------------------------------------ meters */

/**
 * A usage bar. Colour comes from the same thresholds the rules use, so the bar
 * turning red and a finding appearing are always the same event.
 */
export function meter(value, { warn = 80, crit = 90, label } = {}) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return '<div class="meter"><div class="meter-track"></div><span class="meter-value">--</span></div>';
  }
  const cls = value >= crit ? 'critical' : value >= warn ? 'warning' : '';
  const width = Math.max(1.5, Math.min(100, value));
  return (
    '<div class="meter"><div class="meter-track"><div class="meter-fill ' + cls + '" style="width:' + width + '%"></div></div>' +
    '<span class="meter-value">' + (label ?? pct(value)) + '</span></div>'
  );
}

/* ------------------------------------------------------------------- tiles */

export function statTile({ label, value, foot, tone, href, hint }) {
  const toneColor = tone === 'critical' ? 'var(--critical)' : tone === 'warning' ? 'var(--warning)' : tone === 'good' ? 'var(--good-text)' : 'inherit';
  const inner =
    '<div class="stat-label">' + escapeHtml(label) + (hint ? ' <span class="muted" title="' + escapeHtml(hint) + '">&#9432;</span>' : '') + '</div>' +
    '<div class="stat-value" style="color:' + toneColor + '">' + value + '</div>' +
    '<div class="stat-foot">' + (foot ?? '') + '</div>';
  return href
    ? '<a class="card stat" href="' + href + '" style="text-decoration:none;color:inherit">' + inner + '</a>'
    : '<div class="card stat">' + inner + '</div>';
}

/* ------------------------------------------------------------------ tables */

export function dataTable({ columns, rows, empty = 'Nothing to show', rowAttrs }) {
  if (!rows.length) return '<div class="empty"><h4>' + escapeHtml(empty) + '</h4></div>';
  const head = columns
    .map((c) => '<th' + (c.align === 'right' ? ' class="num"' : '') + (c.width ? ' style="width:' + c.width + '"' : '') + '>' + escapeHtml(c.label) + '</th>')
    .join('');
  const body = rows
    .map((r, i) => {
      const attrs = rowAttrs ? rowAttrs(r, i) : '';
      const cells = columns.map((c) => '<td' + (c.align === 'right' ? ' class="num"' : '') + '>' + c.render(r, i) + '</td>').join('');
      return '<tr ' + attrs + '>' + cells + '</tr>';
    })
    .join('');
  return '<div class="table-wrap"><table class="data"><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table></div>';
}

export function emptyState(title, detail, action) {
  return (
    '<div class="empty"><h4>' + escapeHtml(title) + '</h4>' +
    (detail ? '<p>' + escapeHtml(detail) + '</p>' : '') +
    (action ? '<div style="margin-top:14px">' + action + '</div>' : '') +
    '</div>'
  );
}

export function callout(kind, html) {
  return '<div class="callout ' + kind + '"><span class="bar"></span><div>' + html + '</div></div>';
}

export function card({ title, subtitle, actions = '', body, pad = true }) {
  return (
    '<section class="card">' +
    (title
      ? '<div class="card-head"><div><h3>' + escapeHtml(title) + '</h3>' + (subtitle ? '<p>' + subtitle + '</p>' : '') + '</div>' +
        '<div class="card-head-actions">' + actions + '</div></div>'
      : '') +
    (pad ? '<div class="card-body">' + body + '</div>' : body) +
    '</section>'
  );
}

/* ---------------------------------------------------------------- evidence */

/** The measurements behind a finding, so nobody has to take the rule on trust. */
export function evidenceGrid(evidence = []) {
  if (!evidence.length) return '';
  return (
    '<dl class="evidence">' +
    evidence
      .map((e) => '<div><dt>' + escapeHtml(e.label) + '</dt><dd>' + escapeHtml(String(e.value ?? '--')) + '</dd></div>')
      .join('') +
    '</dl>'
  );
}

/** A shell command with a copy button. Advisory only - nothing is ever run. */
export function commandBlock(command, { label = 'Copy' } = {}) {
  if (!command) return '';
  return (
    '<div class="code-copy"><pre class="code">' + escapeHtml(command) + '</pre>' +
    '<button class="btn btn-sm" data-copy="' + escapeHtml(command) + '">' + label + '</button></div>'
  );
}

export function wireCopy(root) {
  root.querySelectorAll('[data-copy]').forEach((btn) =>
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.copy);
        const was = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(() => (btn.textContent = was), 1400);
      } catch {
        toast('Could not copy', 'Your browser blocked clipboard access; select the text instead.', 'warning');
      }
    })
  );
}

/* --------------------------------------------------------------- sparkline */

/**
 * A minimal trend line. No axes and no tooltips: it exists to show shape next
 * to a number that already gives the value, and anything more would be
 * decoration competing with the table underneath.
 */
export function sparkline(values, { tone = 'var(--accent)', height = 42, fill = true } = {}) {
  const points = values.filter((v) => Number.isFinite(v));
  if (points.length < 2) return '<div class="spark"></div>';

  const min = Math.min(...points);
  const max = Math.max(...points);
  const span = max - min;
  const w = 100;
  const h = height;
  const step = w / (points.length - 1);
  // A series that has not moved is drawn down the middle. Scaling it against a
  // span of zero would pin it to the floor of the box, which reads as "this
  // metric collapsed" rather than "this metric is steady".
  const y = (v) => (span === 0 ? h / 2 : h - 3 - ((v - min) / span) * (h - 6));

  const d = points.map((v, i) => (i === 0 ? 'M' : 'L') + (i * step).toFixed(2) + ' ' + y(v).toFixed(2)).join(' ');
  const area = d + ' L' + w + ' ' + h + ' L0 ' + h + ' Z';

  return (
    '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none" aria-hidden="true">' +
    (fill ? '<path d="' + area + '" fill="' + tone + '" opacity="0.1" />' : '') +
    '<path d="' + d + '" fill="none" stroke="' + tone + '" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" />' +
    '</svg>'
  );
}

/* ----------------------------------------------------------------- drawer */

export function openDrawer(html, { onMount } = {}) {
  const drawer = document.getElementById('drawer');
  const scrim = document.getElementById('drawer-scrim');
  drawer.innerHTML = html;
  drawer.hidden = false;
  scrim.hidden = false;
  document.body.style.overflow = 'hidden';
  drawer.scrollTop = 0;

  scrim.onclick = closeDrawer;
  drawer.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', closeDrawer));
  document.addEventListener('keydown', escHandler);
  wireCopy(drawer);
  onMount?.(drawer);
  return drawer;
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
  }, 5200);
}

/* --------------------------------------------------------------- skeleton */

export function skeleton(rows = 3) {
  let out = '<div class="stack">';
  out += '<div class="grid grid-4">' + Array.from({ length: 4 }, () => '<div class="card skeleton" style="height:104px"></div>').join('') + '</div>';
  for (let i = 0; i < rows; i++) out += '<div class="card skeleton" style="height:' + (i % 2 ? 180 : 260) + 'px"></div>';
  return out + '</div>';
}

export { escapeHtml, num, pct, bytes, relative };
