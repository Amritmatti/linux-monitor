// Every open finding and anomaly across the estate, with the filters someone
// triaging actually reaches for.

import { api } from '../api.js';
import { card, emptyState, escapeHtml, severityBadge } from '../ui.js';
import { issueRows, wireIssueRows } from './shared.js';

const state = { severity: '', category: '', server: '', acked: false };

/** Filters arriving as "#/issues?severity=critical" from a tile or a link. */
function readHashParams() {
  const q = location.hash.split('?')[1];
  if (!q) return;
  const sp = new URLSearchParams(q);
  if (sp.has('severity')) state.severity = sp.get('severity');
  if (sp.has('category')) state.category = sp.get('category');
  if (sp.has('server')) state.server = sp.get('server');
}

function chip(group, value, label, count, active) {
  return (
    '<button class="chip' + (active ? ' active' : '') + '" data-group="' + group + '" data-value="' + escapeHtml(value) + '">' +
    escapeHtml(label) + (count !== undefined ? ' <span class="chip-count">' + count + '</span>' : '') +
    '</button>'
  );
}

export async function render(root, { app }) {
  readHashParams();

  const res = await api.issues({ ...state, acked: state.acked ? 'true' : '', q: app.searchTerm });
  const { items, facets } = res;

  const severityChips =
    chip('severity', '', 'All', undefined, !state.severity) +
    ['critical', 'warning', 'info']
      .map((s) => {
        const f = facets.severity.find((x) => x.key === s);
        return f ? chip('severity', s, s[0].toUpperCase() + s.slice(1), f.count, state.severity === s) : '';
      })
      .join('');

  const categoryChips =
    chip('category', '', 'All areas', undefined, !state.category) +
    facets.category.map((f) => chip('category', f.key, f.key, f.count, state.category === f.key)).join('');

  const serverChips =
    facets.server.length > 1
      ? '<div class="filter-row">' +
        chip('server', '', 'All servers', undefined, !state.server) +
        facets.server
          .slice(0, 10)
          .map((f) => {
            // Facets key by name for display; the filter needs the id.
            const match = app.fleet?.servers.find((s) => s.name === f.key);
            return match ? chip('server', match.id, f.key, f.count, state.server === match.id) : '';
          })
          .join('') +
        '</div>'
      : '';

  const filters =
    '<div class="filter-bar">' +
    '<div class="filter-row">' + severityChips + '</div>' +
    '<div class="filter-row">' + categoryChips + '</div>' +
    serverChips +
    '<div class="filter-row" style="justify-content:space-between">' +
    '<label class="check"><input type="checkbox" id="show-acked"' + (state.acked ? ' checked' : '') + ' /> Show acknowledged</label>' +
    '<button class="btn btn-sm" data-clear>Clear filters</button>' +
    '</div>' +
    '</div>';

  const counts = {
    critical: items.filter((i) => i.severity === 'critical').length,
    warning: items.filter((i) => i.severity === 'warning').length,
    info: items.filter((i) => i.severity === 'info').length,
  };

  const summary =
    '<div class="row" style="gap:8px;align-items:center">' +
    (counts.critical ? severityBadge('critical', counts.critical + ' critical') : '') +
    (counts.warning ? severityBadge('warning', counts.warning + ' warning') : '') +
    (counts.info ? severityBadge('info', counts.info + ' info') : '') +
    (!items.length ? '<span class="muted">Nothing matches these filters</span>' : '') +
    '</div>';

  root.innerHTML =
    '<div class="stack">' +
    filters +
    card({
      title: 'Issues',
      subtitle: items.length + (items.length === 1 ? ' issue' : ' issues') + (app.searchTerm ? ' matching “' + escapeHtml(app.searchTerm) + '”' : ''),
      actions: summary,
      pad: false,
      body: items.length
        ? issueRows(items)
        : emptyState(
            state.severity || state.category || state.server || app.searchTerm ? 'Nothing matches' : 'Nothing open',
            state.severity || state.category || state.server || app.searchTerm
              ? 'Try clearing the filters.'
              : 'Every server is clear. New issues appear here as soon as a scan finds them.'
          ),
    }) +
    '</div>';

  root.querySelectorAll('[data-group]').forEach((btn) =>
    btn.addEventListener('click', () => {
      state[btn.dataset.group] = btn.dataset.value;
      // The query string has served its purpose; drop it so it cannot fight the
      // chips on the next render.
      if (location.hash.includes('?')) history.replaceState(null, '', '#/issues');
      render(root, { app });
    })
  );

  root.querySelector('#show-acked')?.addEventListener('change', (e) => {
    state.acked = e.target.checked;
    render(root, { app });
  });

  root.querySelector('[data-clear]')?.addEventListener('click', () => {
    Object.assign(state, { severity: '', category: '', server: '', acked: false });
    if (location.hash.includes('?')) history.replaceState(null, '', '#/issues');
    render(root, { app });
  });

  wireIssueRows(root, items, () => render(root, { app }));
}
