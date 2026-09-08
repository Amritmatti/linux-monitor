// Application shell: session, navigation, routing, theme, live event wiring.

import { api, connectEvents, invalidate } from './api.js';
import { toast, skeleton, escapeHtml } from './ui.js';
import { relative } from './format.js';

import * as overview from './views/overview.js';
import * as issues from './views/issues.js';
import * as anomalies from './views/anomalies.js';
import * as servers from './views/servers.js';
import * as serverDetail from './views/serverDetail.js';
import * as ports from './views/ports.js';
import * as updates from './views/updates.js';
import * as disks from './views/disks.js';
import * as docker from './views/docker.js';
import * as account from './views/account.js';

const ICONS = {
  overview: '<svg viewBox="0 0 20 20" width="16" height="16"><path d="M2.5 11h3l2-5 3 9 2.5-6 1.5 2h3" stroke="currentColor" stroke-width="1.7" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  issues: '<svg viewBox="0 0 20 20" width="16" height="16"><path d="M10 2.5l8 14H2z" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linejoin="round"/><path d="M10 8v3.4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><circle cx="10" cy="14" r="0.95" fill="currentColor"/></svg>',
  anomalies: '<svg viewBox="0 0 20 20" width="16" height="16"><path d="M2.5 13l3.5-6 3 4 2.5-7 3 9 3-3" stroke="currentColor" stroke-width="1.7" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  servers: '<svg viewBox="0 0 20 20" width="16" height="16"><rect x="2.5" y="3" width="15" height="5" rx="1.5" stroke="currentColor" stroke-width="1.5" fill="none"/><rect x="2.5" y="12" width="15" height="5" rx="1.5" stroke="currentColor" stroke-width="1.5" fill="none"/><circle cx="5.5" cy="5.5" r="0.9" fill="currentColor"/><circle cx="5.5" cy="14.5" r="0.9" fill="currentColor"/></svg>',
  ports: '<svg viewBox="0 0 20 20" width="16" height="16"><path d="M8 12l4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M11.5 5.5l1-1a3.2 3.2 0 014.5 4.5l-1 1M8.5 14.5l-1 1a3.2 3.2 0 01-4.5-4.5l1-1" stroke="currentColor" stroke-width="1.7" fill="none" stroke-linecap="round"/></svg>',
  updates: '<svg viewBox="0 0 20 20" width="16" height="16"><path d="M10 2.5v9" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M6.5 8.5L10 12l3.5-3.5" stroke="currentColor" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/><path d="M3 14.5v1.5a1 1 0 001 1h12a1 1 0 001-1v-1.5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round"/></svg>',
  disks: '<svg viewBox="0 0 20 20" width="16" height="16"><ellipse cx="10" cy="5" rx="7" ry="2.5" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="M3 5v10c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V5" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="M3 10c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5" stroke="currentColor" stroke-width="1.5" fill="none"/></svg>',
  docker:
    '<svg viewBox="0 0 20 20" width="16" height="16"><rect x="2.5" y="9" width="3" height="3" stroke="currentColor" stroke-width="1.3" fill="none"/><rect x="6.2" y="9" width="3" height="3" stroke="currentColor" stroke-width="1.3" fill="none"/><rect x="9.9" y="9" width="3" height="3" stroke="currentColor" stroke-width="1.3" fill="none"/><rect x="6.2" y="5.6" width="3" height="3" stroke="currentColor" stroke-width="1.3" fill="none"/><path d="M2 12.5c0 3 2.4 4.6 5.6 4.6 4.6 0 7.7-2.2 8.6-5.6 1.2.3 2.3-.2 2.8-1-1-.6-2.2-.6-3.1-.1" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  account: '<svg viewBox="0 0 20 20" width="16" height="16"><circle cx="10" cy="7" r="3" stroke="currentColor" stroke-width="1.6" fill="none"/><path d="M4 17c0-3.1 2.7-5 6-5s6 1.9 6 5" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round"/></svg>',
};

const ROUTES = [
  { group: 'Monitor', id: 'overview', label: 'Overview', title: 'Overview', view: overview },
  { group: 'Monitor', id: 'issues', label: 'Issues', title: 'Critical issues & warnings', view: issues, badge: 'critical' },
  { group: 'Monitor', id: 'anomalies', label: 'Changes', title: 'Anomalies & changes', view: anomalies, badge: 'anomalies' },
  { group: 'Inspect', id: 'ports', label: 'Open ports', title: 'Listening sockets', view: ports },
  { group: 'Inspect', id: 'updates', label: 'Updates', title: 'Pending updates & reboots', view: updates },
  { group: 'Inspect', id: 'disks', label: 'Disks', title: 'Filesystem usage', view: disks },
  { group: 'Inspect', id: 'docker', label: 'Docker', title: 'Docker containers, images & cleanup', view: docker },
  { group: 'Estate', id: 'servers', label: 'Servers', title: 'Servers', view: servers },
  { group: 'Estate', id: 'account', label: 'Account', title: 'Account', view: account },
];

// Reached from the servers list rather than from the sidebar.
const DETAIL_ROUTE = { id: 'servers', title: 'Server', view: serverDetail };

export const app = {
  me: null,
  fleet: null,
  route: null,
  params: {},
  searchTerm: '',
};

/* ------------------------------------------------------------------ theme */

function initTheme() {
  const saved = localStorage.getItem('vg-theme');
  if (saved) document.documentElement.dataset.theme = saved;
  else if (window.matchMedia('(prefers-color-scheme: light)').matches) document.documentElement.dataset.theme = 'light';
  document.getElementById('theme-btn').addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('vg-theme', next);
    render(true);
  });
}

/* --------------------------------------------------------------------- nav */

function renderNav() {
  const nav = document.getElementById('nav');
  let html = '';
  let lastGroup = null;
  for (const r of ROUTES) {
    if (r.group !== lastGroup) {
      html += '<div class="nav-group">' + r.group + '</div>';
      lastGroup = r.group;
    }
    html +=
      '<button class="nav-item" data-route="' + r.id + '">' + ICONS[r.id] + '<span>' + r.label + '</span>' +
      '<span class="nav-badge" data-badge="' + r.id + '" hidden></span></button>';
  }
  nav.innerHTML = html;
  nav.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-route]');
    if (btn) location.hash = '#/' + btn.dataset.route;
  });
}

function updateNavBadges() {
  const t = app.fleet?.totals;
  const set = (id, count, tone) => {
    const el = document.querySelector('[data-badge="' + id + '"]');
    if (!el) return;
    el.hidden = !count;
    el.textContent = count > 99 ? '99+' : String(count);
    el.style.background = tone;
  };
  set('issues', t?.critical ?? 0, 'var(--critical)');
}

function renderUserCard() {
  const el = document.getElementById('user-card');
  if (!app.me) return;
  const initials = (app.me.name || app.me.email).split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((p) => p[0].toUpperCase()).join('');
  el.innerHTML =
    '<div class="user-card">' +
    '<span class="avatar">' + escapeHtml(initials) + '</span>' +
    '<span class="user-meta"><b>' + escapeHtml(app.me.name) + '</b><small>' + escapeHtml(app.me.email) + '</small></span>' +
    '<button class="icon-btn" id="logout-btn" title="Sign out" aria-label="Sign out">' +
    '<svg viewBox="0 0 20 20" width="15" height="15"><path d="M8 17H4.5A1.5 1.5 0 013 15.5v-11A1.5 1.5 0 014.5 3H8" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round"/><path d="M12.5 13.5L16 10l-3.5-3.5M16 10H7" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
    '</button></div>';
  document.getElementById('logout-btn').addEventListener('click', async () => {
    await api.logout().catch(() => {});
    location.href = '/login';
  });
}

/* ------------------------------------------------------------------ router */

/** "#/servers/uuid" -> { id: 'servers', params: { id: 'uuid' } } */
function parseHash() {
  // The query string carries filters for the view, not the route, so it is
  // stripped here - otherwise "#/issues?severity=critical" looks like a route
  // called "issues?severity=critical" and falls through to the default page.
  const raw = location.hash.replace(/^#\/?/, '').split('?')[0];
  const [id, ...rest] = raw.split('/').filter(Boolean);
  return { id: id || 'overview', params: { id: rest[0] ?? null } };
}

let currentRoute = null;
let renderToken = 0;

async function render(force = false) {
  const { id, params } = parseHash();
  const isDetail = id === 'servers' && params.id;
  const route = isDetail ? DETAIL_ROUTE : ROUTES.find((r) => r.id === id) ?? ROUTES[0];

  const changed = force || currentRoute?.view !== route.view || app.params.id !== params.id;
  currentRoute = route;
  app.route = route.id;
  app.params = params;

  document.querySelectorAll('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.route === route.id));
  document.getElementById('page-title').textContent = route.title;

  const view = document.getElementById('view');
  // A token guards against a slow request from a page the user has already
  // left painting over the page they are now on.
  const token = ++renderToken;
  if (changed) view.innerHTML = skeleton();

  try {
    await route.view.render(view, { params, app });
  } catch (err) {
    if (token !== renderToken) return;
    console.error(err);
    view.innerHTML =
      '<div class="callout critical"><span class="bar"></span><div><b>Could not load this page.</b><br>' +
      escapeHtml(err.message) + '</div></div>';
  }
}

/* ------------------------------------------------------------------ actions */

async function refreshFleet() {
  try {
    app.fleet = await api.fleet();
    updateNavBadges();
    updateSubtitle();
  } catch (err) {
    if (err.message !== 'Session expired') console.error(err);
  }
}

function updateSubtitle() {
  const el = document.getElementById('page-subtitle');
  const t = app.fleet?.totals;
  if (!t) return;
  if (!t.servers) {
    el.textContent = 'No servers yet — add one to get started';
    return;
  }
  const last = app.fleet.servers.map((s) => s.scannedAt).filter(Boolean).sort().pop();
  el.textContent =
    t.servers + (t.servers === 1 ? ' server' : ' servers') +
    ' · ' + t.critical + ' critical, ' + t.warning + ' warning' +
    (t.unreachable ? ' · ' + t.unreachable + ' unreachable' : '') +
    (last ? ' · scanned ' + relative(last) : '');
}

async function runScan(button) {
  const label = button.innerHTML;
  button.disabled = true;
  button.textContent = 'Scanning…';
  try {
    await api.scanAll();
    toast('Scan started', 'Connecting to every server; results appear as each one answers.');
  } catch (err) {
    toast('Could not start the scan', err.message, 'critical');
  } finally {
    // The sweep runs in the background, so the button comes back immediately
    // and progress arrives on the event stream.
    setTimeout(() => {
      button.disabled = false;
      button.innerHTML = label;
    }, 1200);
  }
}

function wireShell() {
  document.getElementById('menu-btn').addEventListener('click', () => document.getElementById('sidebar').classList.toggle('open'));
  document.getElementById('scan-btn').addEventListener('click', (e) => runScan(e.currentTarget));

  const search = document.getElementById('global-search');
  let timer;
  search.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      app.searchTerm = search.value.trim();
      if (app.searchTerm && !['issues', 'ports', 'servers'].includes(app.route)) location.hash = '#/issues';
      else render(true);
    }, 260);
  });

  window.addEventListener('hashchange', () => render());
}

/* -------------------------------------------------------------------- boot */

async function boot() {
  initTheme();

  try {
    const me = await api.me();
    app.me = me.user;
  } catch (err) {
    if (err.status !== 401 && err.message !== 'Session expired') console.error(err);
    location.href = '/login';
    return;
  }

  renderNav();
  renderUserCard();
  wireShell();
  await refreshFleet();

  if (!location.hash) location.hash = '#/overview';
  await render(true);

  connectEvents(
    (evt) => {
      if (evt.type === 'scan-progress') {
        const p = evt.payload ?? {};
        document.getElementById('page-subtitle').textContent = 'Scanning ' + (p.name ?? '') + ' — ' + p.done + ' of ' + p.total;
        return;
      }
      invalidate();
      refreshFleet().then(() => render());
      if (evt.type === 'scan-complete') {
        const p = evt.payload ?? {};
        toast(
          'Scan complete',
          p.scanned + (p.scanned === 1 ? ' server' : ' servers') + ' checked' + (p.failed ? ', ' + p.failed + ' unreachable' : ''),
          p.failed ? 'warning' : ''
        );
      }
    },
    (status) => {
      const dot = document.getElementById('live-dot');
      dot.classList.toggle('stale', status !== 'live');
      dot.title = status === 'live' ? 'Live connection' : 'Reconnecting…';
    }
  );

  setInterval(refreshFleet, 30000);
}

boot();
