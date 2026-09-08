// Formatting helpers. Money is the unit of this product, so it gets the most care.

export function money(n, opts = {}) {
  if (n === null || n === undefined || Number.isNaN(n)) return '--';
  const { decimals = 0, sign = false } = opts;
  const abs = Math.abs(n);
  const s = abs.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
  const prefix = n < 0 ? '-$' : sign ? '+$' : '$';
  return prefix + s;
}

/** Compact money for axis ticks and tiles: $1.2M, $48k, $940. */
export function moneyCompact(n) {
  if (n === null || n === undefined || Number.isNaN(n)) return '--';
  const abs = Math.abs(n);
  const sign = n < 0 ? '-' : '';
  if (abs >= 1e9) return sign + '$' + trim(abs / 1e9) + 'B';
  if (abs >= 1e6) return sign + '$' + trim(abs / 1e6) + 'M';
  if (abs >= 1e4) return sign + '$' + Math.round(abs / 1e3) + 'k';
  if (abs >= 1e3) return sign + '$' + trim(abs / 1e3) + 'k';
  return sign + '$' + Math.round(abs);
}

function trim(v) {
  const s = v.toFixed(v < 10 ? 1 : 0);
  return s.endsWith('.0') ? s.slice(0, -2) : s;
}

export function num(n, decimals = 0) {
  if (n === null || n === undefined || Number.isNaN(n)) return '--';
  return n.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
}

export function pct(n, decimals = 0) {
  if (n === null || n === undefined || Number.isNaN(n)) return '--';
  return n.toFixed(decimals) + '%';
}

export function signedPct(n, decimals = 1) {
  if (n === null || n === undefined || Number.isNaN(n)) return '--';
  return (n >= 0 ? '+' : '') + n.toFixed(decimals) + '%';
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export function shortDate(iso) {
  const d = new Date(iso.length <= 10 ? iso + 'T00:00:00Z' : iso);
  return d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()];
}

export function dateTime(iso) {
  const d = new Date(iso);
  return (
    d.getUTCDate() + ' ' + MONTHS[d.getUTCMonth()] + ' ' +
    String(d.getUTCHours()).padStart(2, '0') + ':' + String(d.getUTCMinutes()).padStart(2, '0')
  );
}

export function timeOnly(iso) {
  const d = new Date(iso);
  return String(d.getUTCHours()).padStart(2, '0') + ':' + String(d.getUTCMinutes()).padStart(2, '0') + ':' + String(d.getUTCSeconds()).padStart(2, '0');
}

export function relative(iso) {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const secs = Math.round((now - then) / 1000);
  if (secs < 60) return secs <= 3 ? 'just now' : secs + 's ago';
  const mins = Math.round(secs / 60);
  if (mins < 60) return mins + 'm ago';
  const hours = Math.round(mins / 60);
  if (hours < 24) return hours + 'h ago';
  const days = Math.round(hours / 24);
  if (days < 31) return days + 'd ago';
  const months = Math.round(days / 30.4);
  return months + 'mo ago';
}

export function duration(minutes) {
  if (minutes < 60) return minutes + ' min';
  const h = minutes / 60;
  if (h < 24) return (h % 1 === 0 ? h : h.toFixed(1)) + ' h';
  return Math.round(h / 24) + ' days';
}

export function titleCase(s) {
  return String(s).replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
