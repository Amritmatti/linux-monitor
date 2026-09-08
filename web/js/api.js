// API client: a small cache, session handling, and the live event stream.

const cache = new Map();

async function request(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
  });

  if (res.status === 401 && !path.startsWith('/api/auth/')) {
    // The session went away underneath us; go back to sign-in rather than
    // leaving a dashboard full of stale numbers on screen.
    location.href = '/login';
    throw new Error('Session expired');
  }

  let body = null;
  try {
    body = await res.json();
  } catch {
    /* some responses have no body */
  }

  if (!res.ok) {
    const err = new Error(body?.message || body?.error || res.statusText);
    err.status = res.status;
    err.code = body?.error;
    err.body = body;
    throw err;
  }
  return body;
}

export function get(path, { fresh = false, ttl = 4000 } = {}) {
  const hit = cache.get(path);
  const now = Date.now();
  if (!fresh && hit && now - hit.at < ttl) return hit.promise;
  const promise = request(path).catch((err) => {
    cache.delete(path);
    throw err;
  });
  cache.set(path, { at: now, promise });
  return promise;
}

const mutate = (method) => (path, body) => {
  invalidate();
  return request(path, { method, body: JSON.stringify(body || {}) });
};

export const post = mutate('POST');
export const put = mutate('PUT');
export const patch = mutate('PATCH');

export function del(path) {
  invalidate();
  return request(path, { method: 'DELETE' });
}

export function invalidate() {
  cache.clear();
}

export function qs(params) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '' && v !== 'all') sp.set(k, v);
  }
  const s = sp.toString();
  return s ? '?' + s : '';
}

/* ---------------------------------------------------------------- endpoints */

export const api = {
  me: () => get('/api/auth/me', { ttl: 3000 }),
  logout: () => post('/api/auth/logout'),
  changePassword: (body) => post('/api/auth/password', body),
  settings: () => get('/api/settings', { ttl: 2000 }),
  updateSettings: (body) => put('/api/settings', body),

  fleet: () => get('/api/fleet', { ttl: 2500 }),
  issues: (params) => get('/api/issues' + qs(params), { ttl: 2000 }),
  anomalies: (params) => get('/api/anomalies' + qs(params), { ttl: 2000 }),
  ports: () => get('/api/ports', { ttl: 5000 }),
  updates: () => get('/api/updates', { ttl: 5000 }),
  disks: () => get('/api/disks', { ttl: 5000 }),
  docker: () => get('/api/docker', { ttl: 5000 }),
  hardening: () => get('/api/hardening', { ttl: 5000 }),

  servers: () => get('/api/servers', { ttl: 2000 }),
  server: (id) => get('/api/servers/' + encodeURIComponent(id), { ttl: 1500 }),
  createServer: (body) => post('/api/servers', body),
  updateServer: (id, body) => patch('/api/servers/' + encodeURIComponent(id), body),
  deleteServer: (id) => del('/api/servers/' + encodeURIComponent(id)),
  scanServer: (id) => post('/api/servers/' + encodeURIComponent(id) + '/scan'),
  resetHostKey: (id) => post('/api/servers/' + encodeURIComponent(id) + '/reset-host-key'),
  scanAll: () => post('/api/scan'),
  pruneDocker: (serverId, action) => post('/api/servers/' + encodeURIComponent(serverId) + '/docker-prune', { action }),

  acknowledge: (serverId, key, reason, value) => post('/api/servers/' + encodeURIComponent(serverId) + '/ack', { key, reason, value }),
  unacknowledge: (serverId, key) => del('/api/servers/' + encodeURIComponent(serverId) + '/ack?key=' + encodeURIComponent(key)),
};

/* ------------------------------------------------------------ live updates */

const EVENT_TYPES = ['scan-started', 'scan-progress', 'scan-finished', 'scan-complete', 'ack-changed', 'docker-pruned'];

export function connectEvents(onEvent, onStatus) {
  let source;
  let retry = 0;

  const open = () => {
    source = new EventSource('/api/events');
    source.onopen = () => {
      retry = 0;
      onStatus?.('live');
    };
    source.onerror = () => {
      onStatus?.('stale');
      source.close();
      // Backs off to about 5s rather than hammering a server that is restarting.
      retry = Math.min(retry + 1, 6);
      setTimeout(open, 800 * retry);
    };
    for (const type of EVENT_TYPES) {
      source.addEventListener(type, (e) => {
        // Progress ticks are noise for the cache; everything else changes data.
        if (type !== 'scan-progress') invalidate();
        try {
          onEvent({ type, ...JSON.parse(e.data) });
        } catch {
          onEvent({ type });
        }
      });
    }
  };

  open();
  return () => source?.close();
}
