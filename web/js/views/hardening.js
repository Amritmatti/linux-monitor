// The hardening audit: the standard Linux exposure classes, what was found in
// each, and — just as important — which ones could not be checked on which
// hosts.
//
// An area with no findings and an area nobody could look at render very
// differently here. That distinction is the whole reason this page exists as
// something other than a filtered view of Issues.

import { api } from '../api.js';
import { card, emptyState, escapeHtml, severityBadge, statTile, num } from '../ui.js';
import { issueRows, wireIssueRows } from './shared.js';

export async function render(root, { app }) {
  const res = await api.hardening();

  if (!res.perServer.length) {
    root.innerHTML = card({
      body: emptyState('Nothing collected yet', 'Scan a server and its hardening posture appears here.'),
    });
    return;
  }

  const t = res.totals;

  const tiles =
    '<div class="grid grid-4">' +
    statTile({
      label: 'Critical exposures',
      value: num(t.critical),
      tone: t.critical ? 'critical' : 'good',
      foot: '<span>across ' + num(t.servers) + ' servers</span>',
    }) +
    statTile({ label: 'Warnings', value: num(t.warning), tone: t.warning ? 'warning' : 'good', foot: '<span>worth scheduling</span>' }) +
    statTile({ label: 'Informational', value: num(t.info), foot: '<span>worth confirming you meant</span>' }) +
    statTile({
      label: 'Areas not visible',
      value: num(t.unknownAreas),
      tone: t.unknownAreas ? 'warning' : 'good',
      foot: '<span>need root on at least one host</span>',
      hint: 'An area nobody could check is not an area that passed. These are listed below with what would make them visible.',
    }) +
    '</div>';

  const areaCard = (a) => {
    const open = res.findings.filter((f) => f.area === a.id && !f.acked);
    const verdict =
      a.critical ? severityBadge('critical', a.critical + ' critical')
      : a.warning ? severityBadge('warning', a.warning + ' warning' + (a.warning === 1 ? '' : 's'))
      : a.info ? severityBadge('info', a.info + ' to review')
      : a.unknownOn === a.servers && a.servers > 0 ? severityBadge('warning', 'not visible')
      : a.partialOn === a.servers && a.servers > 0 ? severityBadge('ok', 'partly checked')
      : a.notApplicableOn === a.servers && a.servers > 0 ? severityBadge('muted', 'not applicable')
      : severityBadge('ok', 'clear');

    const coverageLine =
      a.checkedOn === a.servers
        ? 'Checked on all ' + a.servers + ' server' + (a.servers === 1 ? '' : 's') + '.'
        : 'Checked on ' + a.checkedOn + ' of ' + a.servers +
          (a.partialOn ? '; partly on ' + a.partialOn : '') +
          (a.unknownOn ? '; not visible on ' + a.unknownOn : '') +
          (a.notApplicableOn ? '; not applicable on ' + a.notApplicableOn : '') + '.';

    return (
      '<section class="card">' +
      '<div class="card-head"><div><h3>' + escapeHtml(a.label) + '</h3><p>' + escapeHtml(a.blurb) + '</p></div>' +
      '<div class="card-head-actions">' + verdict + '</div></div>' +
      (open.length ? issueRows(open) : '') +
      '<div class="card-body" style="padding-top:' + (open.length ? '13px' : '15px') + '">' +
      '<p class="muted" style="font-size:11.5px;line-height:1.6">' + escapeHtml(coverageLine) + '</p>' +
      a.notes.map((n) => '<p class="muted" style="font-size:11.5px;line-height:1.6;margin-top:4px">· ' + escapeHtml(n) + '</p>').join('') +
      '</div>' +
      '</section>'
    );
  };

  root.innerHTML =
    '<div class="stack">' +
    tiles +
    '<div class="callout"><span class="bar"></span><div>' +
    '<b>Read this as coverage, not as a score.</b> ' +
    '<span class="muted">Vigil runs unprivileged by design, and most of these checks want root. An area marked ' +
    '<em>not visible</em> has not passed — nobody looked. Each card says what it would take to see it.</span>' +
    '</div></div>' +
    res.areas.map(areaCard).join('') +
    '</div>';

  wireIssueRows(root, res.findings, () => render(root, { app }));
}
