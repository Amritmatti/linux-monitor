// Formatting helpers. Bytes and elapsed time are the units of this product, so
// they get the most care.

export function num(n, decimals = 0) {
  if (n === null || n === undefined || Number.isNaN(n)) return '--';
  return n.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
}

export function pct(n, decimals = 0) {
  if (n === null || n === undefined || Number.isNaN(n)) return '--';
  return n.toFixed(decimals) + '%';
}

/**
 * Binary units, because that is what df, free and every other tool on the host
 * reports. Showing GB next to a number the server called GiB would make the
 * dashboard disagree with the terminal by 7%, and someone would spend an
 * afternoon on it.
 */
export function bytes(n, decimals) {
  if (n === null || n === undefined || Number.isNaN(n)) return '--';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const d = decimals !== undefined ? decimals : v >= 100 || i === 0 ? 0 : 1;
  return (n < 0 ? '-' : '') + v.toFixed(d) + ' ' + units[i];
}

/** Compact bytes for tiles and axis ticks. */
export function bytesCompact(n) {
  return bytes(n, n >= 1024 ** 3 ? 1 : 0);
}

/** A duration in seconds, at the precision a person would actually say it. */
export function duration(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return '--';
  const s = Math.abs(seconds);
  if (s < 60) return Math.round(s) + 's';
  if (s < 3600) return Math.round(s / 60) + 'm';
  if (s < 86400) {
    const h = Math.floor(s / 3600);
    const m = Math.round((s % 3600) / 60);
    return m ? h + 'h ' + m + 'm' : h + 'h';
  }
  const d = Math.floor(s / 86400);
  if (d < 60) {
    const h = Math.round((s % 86400) / 3600);
    return h ? d + 'd ' + h + 'h' : d + 'd';
  }
  if (d < 730) return Math.round(d / 30.44) + ' months';
  return (d / 365.25).toFixed(1) + ' years';
}

export function ms(n) {
  if (n === null || n === undefined || Number.isNaN(n)) return '--';
  return n < 1000 ? Math.round(n) + 'ms' : (n / 1000).toFixed(1) + 's';
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export function shortDate(iso) {
  if (!iso) return '--';
  const d = new Date(iso);
  return d.getDate() + ' ' + MONTHS[d.getMonth()];
}

export function dateTime(iso) {
  if (!iso) return '--';
  const d = new Date(iso);
  return (
    d.getDate() + ' ' + MONTHS[d.getMonth()] + ' ' +
    String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0')
  );
}

export function relative(iso) {
  if (!iso) return 'never';
  const then = new Date(iso).getTime();
  const secs = Math.round((Date.now() - then) / 1000);
  if (secs < 0) return 'just now';
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

export function titleCase(s) {
  return String(s).replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
