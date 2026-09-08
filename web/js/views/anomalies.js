// What changed. Sockets that appeared, services that stopped, disks that are
// climbing, metrics outside their own normal range.

import { api } from '../api.js';
import { card, emptyState, escapeHtml, severityBadge } from '../ui.js';
import { issueRows, wireIssueRows } from './shared.js';

const KIND_COPY = {
  appeared: { title: 'Appeared', blurb: 'Sockets and services that were not here before.' },
  disappeared: { title: 'Gone', blurb: 'Things that were consistently present and have stopped.' },
  trend: { title: 'Trending', blurb: 'Measurements moving steadily towards a limit.' },
  excursion: { title: 'Outside normal range', blurb: 'Values far outside what is usual for that particular machine.' },
  transition: { title: 'State changes', blurb: 'Reboots, kernel changes and units that have newly failed.' },
  change: { title: 'Other changes', blurb: '' },
};

const ORDER = ['appeared', 'excursion', 'trend', 'transition', 'disappeared', 'change'];

export async function render(root, { app }) {
  const res = await api.anomalies({ acked: '' });
  const items = res.items;

  if (!items.length) {
    root.innerHTML = card({
      body: emptyState(
        'Nothing has changed',
        'Vigil compares every scan against this server\'s own history. Once there are a few scans behind each host, ' +
          'anything that appears, stops, climbs or steps outside its normal range shows up here.'
      ),
    });
    return;
  }

  const groups = ORDER.map((kind) => ({ kind, items: items.filter((i) => i.kind === kind) })).filter((g) => g.items.length);

  const counts =
    '<div class="row" style="gap:8px">' +
    ['critical', 'warning', 'info']
      .map((sev) => {
        const n = items.filter((i) => i.severity === sev).length;
        return n ? severityBadge(sev, n + ' ' + sev) : '';
      })
      .join('') +
    '</div>';

  root.innerHTML =
    '<div class="stack">' +
    '<div class="callout"><span class="bar"></span><div>' +
    '<b>These are relative to each machine, not to a threshold.</b> ' +
    '<span class="muted">A build server that always sits at load 14 raises nothing here; the same server at load 40 does. ' +
    'Fixed thresholds live on the Issues page.</span></div></div>' +
    groups
      .map((g) =>
        card({
          title: KIND_COPY[g.kind].title,
          subtitle: escapeHtml(KIND_COPY[g.kind].blurb),
          actions: g === groups[0] ? counts : '',
          pad: false,
          body: issueRows(g.items),
        })
      )
      .join('') +
    '</div>';

  wireIssueRows(root, items, () => render(root, { app }));
}
