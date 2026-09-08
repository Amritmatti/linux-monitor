// Presentation shared by every page that shows findings or anomalies.
//
// Findings and anomalies are rendered by the same code on purpose. To the
// person triaging an estate, "this disk is 94% full" and "this disk will be
// full on Thursday" are the same kind of thing, and which engine produced them
// is an implementation detail. They differ only by a label.

import { api } from '../api.js';
import { severityBadge, evidenceGrid, commandBlock, openDrawer, closeDrawer, toast, escapeHtml, dataTable, emptyState } from '../ui.js';
import { relative } from '../format.js';

const KIND_LABEL = { anomaly: 'Changed', finding: null };

/** One row in an issue table. */
export function issueRows(items, { showServer = true } = {}) {
  return dataTable({
    columns: [
      {
        label: 'Severity',
        width: '104px',
        render: (i) => severityBadge(i.severity),
      },
      {
        label: 'Issue',
        render: (i) =>
          '<div><b>' + escapeHtml(i.title) + '</b>' +
          (KIND_LABEL[i.kind] ? ' <span class="badge badge-neutral">' + KIND_LABEL[i.kind] + '</span>' : '') +
          (i.acked ? ' <span class="badge badge-neutral">Acknowledged</span>' : '') +
          (i.reopenedFrom !== null && i.reopenedFrom !== undefined
            ? ' <span class="badge badge-medium">Reopened</span>'
            : '') +
          '</div><div class="muted" style="font-size:11.5px;margin-top:2px">' + escapeHtml(truncate(i.detail, 130)) + '</div>',
      },
      ...(showServer
        ? [{
            label: 'Server',
            width: '160px',
            render: (i) =>
              '<a href="#/servers/' + i.serverId + '" onclick="event.stopPropagation()">' + escapeHtml(i.serverName) + '</a>' +
              '<div class="muted" style="font-size:11px">' + escapeHtml(i.serverHost ?? '') + '</div>',
          }]
        : []),
      { label: 'Category', width: '96px', render: (i) => '<span class="badge badge-neutral">' + escapeHtml(i.category) + '</span>' },
      { label: 'Seen', width: '84px', align: 'right', render: (i) => '<span class="muted">' + relative(i.observedAt) + '</span>' },
    ],
    rows: items,
    empty: 'Nothing here',
    rowAttrs: (i) =>
      'class="issue-row is-' + i.severity + (i.acked ? ' is-acked' : '') + '" style="cursor:pointer" ' +
      'data-issue="' + escapeHtml(i.key) + '" data-server="' + i.serverId + '"',
  });
}

function truncate(s, n) {
  const t = String(s ?? '');
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
}

/** Click-through from a table row to the detail drawer. */
export function wireIssueRows(root, items, onChange) {
  root.querySelectorAll('[data-issue]').forEach((row) =>
    row.addEventListener('click', () => {
      const item = items.find((i) => i.key === row.dataset.issue && i.serverId === row.dataset.server);
      if (item) showIssue(item, onChange);
    })
  );
}

/** The full detail of one finding: what was measured, and what to do. */
export function showIssue(item, onChange) {
  const body =
    '<div class="drawer-head">' +
    '<div>' + severityBadge(item.severity) +
    (KIND_LABEL[item.kind] ? ' <span class="badge badge-neutral">' + KIND_LABEL[item.kind] + '</span>' : '') +
    ' <span class="badge badge-neutral">' + escapeHtml(item.category) + '</span></div>' +
    '<button class="icon-btn" data-close aria-label="Close">' +
    '<svg viewBox="0 0 20 20" width="16" height="16"><path d="M5 5l10 10M15 5L5 15" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></button>' +
    '</div>' +
    '<h2 style="font-size:18px;letter-spacing:-.02em;margin:14px 0 6px">' + escapeHtml(item.title) + '</h2>' +
    '<p class="muted" style="font-size:12.5px">on <a href="#/servers/' + item.serverId + '">' + escapeHtml(item.serverName ?? '') + '</a>' +
    (item.observedAt ? ' · observed ' + relative(item.observedAt) : '') + '</p>' +
    '<p style="font-size:13px;line-height:1.65;margin:16px 0">' + escapeHtml(item.detail) + '</p>' +
    (item.evidence?.length ? '<h4 class="section-label">Measurements</h4>' + evidenceGrid(item.evidence) : '') +
    (item.remedy
      ? '<h4 class="section-label" style="margin-top:18px">Suggested next step</h4>' +
        '<p class="muted" style="font-size:11.5px;margin-bottom:7px">Vigil never runs anything on your servers. Copy this and run it yourself.</p>' +
        commandBlock(item.remedy)
      : '') +
    (item.acked
      ? '<div class="callout" style="margin-top:18px"><span class="bar"></span><div>' +
        '<b>Acknowledged</b> by ' + escapeHtml(item.ackedBy ?? '') +
        (item.ackReason ? ' — ' + escapeHtml(item.ackReason) : '') +
        '<br><span class="muted" style="font-size:11.5px">It will come back on its own if it gets materially worse.</span>' +
        '</div></div>'
      : '') +
    '<div class="drawer-actions" style="margin-top:22px">' +
    (item.acked
      ? '<button class="btn" data-unack>Un-acknowledge</button>'
      : '<button class="btn" data-ack>Acknowledge…</button>') +
    '<a class="btn btn-primary" href="#/servers/' + item.serverId + '" data-close>Open server</a>' +
    '</div>';

  openDrawer(body, {
    onMount: (drawer) => {
      drawer.querySelector('[data-ack]')?.addEventListener('click', () => promptAck(item, onChange));
      drawer.querySelector('[data-unack]')?.addEventListener('click', async () => {
        await api.unacknowledge(item.serverId, item.key);
        toast('Un-acknowledged', item.title);
        closeDrawer();
        onChange?.();
      });
    },
  });
}

function promptAck(item, onChange) {
  const body =
    '<div class="drawer-head"><div><b>Acknowledge</b></div>' +
    '<button class="icon-btn" data-close aria-label="Close"><svg viewBox="0 0 20 20" width="16" height="16"><path d="M5 5l10 10M15 5L5 15" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></button></div>' +
    '<h2 style="font-size:16px;margin:14px 0 6px">' + escapeHtml(item.title) + '</h2>' +
    '<p class="muted" style="font-size:12.5px;line-height:1.6">This hides the issue from the dashboard. It is not a mute: if the ' +
    'measurement gets materially worse than it is now, it comes back on its own.</p>' +
    '<div class="field" style="margin-top:16px"><label for="ack-reason">Why is this acceptable?</label>' +
    '<input id="ack-reason" type="text" placeholder="Scheduled for the maintenance window on the 14th" />' +
    '<div class="hint">Optional, but the next person to look will thank you.</div></div>' +
    '<div class="drawer-actions" style="margin-top:20px">' +
    '<button class="btn" data-close>Cancel</button>' +
    '<button class="btn btn-primary" data-confirm>Acknowledge</button></div>';

  openDrawer(body, {
    onMount: (drawer) => {
      drawer.querySelector('#ack-reason').focus();
      drawer.querySelector('[data-confirm]').addEventListener('click', async () => {
        try {
          await api.acknowledge(item.serverId, item.key, drawer.querySelector('#ack-reason').value.trim(), item.value);
          toast('Acknowledged', item.title);
          closeDrawer();
          onChange?.();
        } catch (err) {
          toast('Could not acknowledge', err.message, 'critical');
        }
      });
    },
  });
}

/**
 * The "we could not see everything" note.
 *
 * Shown wherever a scan ran with reduced fidelity. The product is designed to
 * run unprivileged, so this is an expected state and not an error - but a
 * dashboard that shows less than it claims without saying so is the one thing
 * a monitoring tool must never do.
 */
export function limitedCallout(limited = []) {
  if (!limited.length) return '';
  const body =
    '<b>' + limited.length + ' check' + (limited.length === 1 ? '' : 's') + ' ran with reduced visibility.</b> ' +
    '<span class="muted">The login has no sudo, which is the recommended way to run Vigil — this is what it costs.</span>' +
    limited
      .map(
        (l) =>
          '<div class="limited-note" style="margin-top:10px">• ' + escapeHtml(l.reason) +
          (l.sudoers ? '<pre class="code" style="margin-top:6px">' + escapeHtml(l.sudoers) + '</pre>' : '') +
          '</div>'
      )
      .join('');
  return '<div class="callout"><span class="bar"></span><div>' + body + '</div></div>';
}

export { emptyState };
