'use strict';
/* Logs, the panel (UX-30 of the UI audit of 2026-11-04): what hosts' journals said, as of each host's last scan. A time range, when each
   host was last collected, a bar chart of lines by level and hour, a unit filter, and a place in the URL for all of it. Nothing here tails
   or streams: a line arrives with the scan that reads it, and nothing refreshes by itself.

   Every value is a host's own text, so it is only ever put on the page with textContent and DOM calls, never as markup. The chart is
   SVG made with createElementNS. The server is asked through the kernel's getJSON() only. app.js calls loadHostLogs() when the panel
   opens and hlLinkEl() for the Logs link in a host's Details; router.js asks hlRouteParams() and tells hlTakeLink() what a URL said. */

/* ── what the panel is showing: the one place the controls and the URL are read from ── */
const HL_RANGES = [
  { key: 'hour', label: 'Last hour', secs: 3600 },
  { key: 'day', label: 'Last day', secs: 86400 },
  { key: 'week', label: 'Last 7 days', secs: 7 * 86400 },
  { key: 'month', label: 'Last 30 days', secs: 30 * 86400 },
  { key: 'custom', label: 'Custom', secs: 0 },
];
const HL_DEFAULT_RANGE = 'week';
const HL_PAGE = 100;
const HL = { host: '', range: HL_DEFAULT_RANGE, from: null, to: null, level: '', unit: '', q: '',          // from and to: seconds, for a custom range
             status: null, counts: null, offset: 0, typing: 0 };

/* A level on the chart is one of four bands, drawn from the bottom up as errors first so that their height is comparable from hour to
   hour. Colour is never the only cue: each band has its own fill pattern, and the legend and the table say the names and the numbers. */
const HL_BANDS = [
  { key: 'err', label: 'Errors or worse', levels: ['emerg', 'alert', 'crit', 'err'] },
  { key: 'warning', label: 'Warnings', levels: ['warning'] },
  { key: 'notice', label: 'Notices', levels: ['notice'] },
  { key: 'info', label: 'Info and debug', levels: ['info', 'debug'] },
];

const hlEl = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null && v !== false) { if (k === 'class') e.className = v; else e.setAttribute(k, v === true ? '' : v); }
  e.append(...kids.flat().filter((x) => x != null && x !== false));
  return e;
};
const hlSvg = (tag, attrs = {}, ...kids) => {
  const e = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) e.setAttribute(k, String(v));
  e.append(...kids.flat().filter((x) => x != null));
  return e;
};
const hlPlural = (n, one, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const hlWhen = (ts) => fmtTime(ts, { seconds: true });
const hlHourLabel = (ts) => `${fmtDate(ts).slice(5)} ${fmtClock(ts).slice(0, 5)}`;

/* ── the range ───────────────────────────────────────────────────── */
/* since and until, in seconds, for what is chosen now: a preset runs back from now and has no end; a custom range may leave either end open. */
function hlBounds() {
  if (HL.range === 'custom') return { since: HL.from, until: HL.to };
  const r = HL_RANGES.find((x) => x.key === HL.range) || HL_RANGES[2];
  return { since: Math.floor(Date.now() / 1000) - r.secs, until: null };
}
function hlRangeText() {
  if (HL.range !== 'custom') return (HL_RANGES.find((x) => x.key === HL.range) || HL_RANGES[2]).label.toLowerCase();
  const a = HL.from != null ? `from ${fmtTime(HL.from)}` : '', b = HL.to != null ? `to ${fmtTime(HL.to)}` : '';
  return [a, b].filter(Boolean).join(' ') || 'all stored time';
}
/* A custom end in a URL is UTC to the minute, 2026-11-06T09:30Z: a link means the same instant in every time zone. The date-time
   fields of the form are local time, which is what a person types. */
function hlUrlTime(secs) {
  if (secs == null) return '';
  const iso = new Date(secs * 1000).toISOString();
  return `${iso.slice(0, 16)}Z`;
}
function hlParseUrlTime(v) {
  if (!v) return null;
  const ms = Date.parse(/Z$|[+-]\d\d:\d\d$/.test(v) ? v : `${v}Z`);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}
const hlLocalField = (secs) => (secs == null ? '' : `${fmtDate(secs)}T${fmtClock(secs).slice(0, 5)}`);      // what <input type=datetime-local> holds
function hlParseField(v) {
  if (!v) return null;
  const ms = new Date(v).getTime();                          // no zone in the text: the browser reads it as local time
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
}

/* ── the URL ─────────────────────────────────────────────────────── */
/* router.js puts these after the global ?host=, and `lhost` is the host this panel filters on: the header's host and the Logs filter are
   different things, so a link from a host's Details sets both. */
function hlRouteParams() {
  const p = { lhost: HL.host, level: HL.level, unit: HL.unit, q: HL.q };
  if (HL.range !== HL_DEFAULT_RANGE) p.range = HL.range;
  if (HL.range === 'custom') { p.from = hlUrlTime(HL.from); p.to = hlUrlTime(HL.to); }
  return p;
}
function hlTakeLink(q) {
  HL.host = q.get('lhost') || '';
  const r = q.get('range');
  HL.range = HL_RANGES.some((x) => x.key === r) ? r : HL_DEFAULT_RANGE;
  HL.from = HL.range === 'custom' ? hlParseUrlTime(q.get('from')) : null;
  HL.to = HL.range === 'custom' ? hlParseUrlTime(q.get('to')) : null;
  const level = q.get('level') || '';
  HL.level = ['err', 'warning', 'notice'].includes(level) ? level : '';
  HL.unit = (q.get('unit') || '').slice(0, 200);
  HL.q = (q.get('q') || '').slice(0, 200);
  hlShow();
}
/* A link to the Logs panel for a host, in the form the router reads. It keeps the view the person is in. `q` and `unit` filter the lines,
   and `from` (seconds) starts a custom range there, open to now: a notification links to the lines since an hour before it opened. */
function hlLink(host, { q = '', unit = '', from = null } = {}) {
  const parts = [typeof T !== 'undefined' && T.mode ? T.mode : 'topo', 'hostlogs'];
  return sfFormatHash(parts, { host, lhost: host, unit, q, ...(from != null ? { range: 'custom', from: hlUrlTime(from) } : {}) });
}
function hlLinkEl(host, label = 'Logs', opts = {}) {
  const what = opts.q ? ` that mention ${opts.q}` : opts.unit ? ` from ${opts.unit}` : '';
  return hlEl('a', { class: opts.small ? 'btn ghost sm' : 'btn', href: hlLink(host, opts), title: `The lines of ${host}'s journal${what}` }, label);
}
/* The Logs link of a disk, a partition, a pool or a mount in the storage views: the host's lines that name it. A kernel names a disk or a
   partition by its device (sdb, sdb1, nvme0n1), ZFS and md a pool by its name, and a filesystem error names its device, so a mount is
   searched by the device it is mounted from when that is known and by its path when not. */
function hlDeviceWord(kind, name) {
  const v = String(name || '').trim();
  if (!v) return '';
  if (kind === 'mount' && !v.startsWith('/dev/')) return v;
  return v.replace(/^\/dev\/(mapper\/)?/, '').slice(0, 200);
}
function hlDeviceLinkEl(host, kind, name) {
  if (!host || typeof can !== 'function' || !can('hostlogs.view')) return null;
  const q = hlDeviceWord(kind, name);
  return q ? hlLinkEl(host, 'Logs', { q, small: true }) : null;
}
function hlSync(replace = false) { if (typeof routeSync === 'function') routeSync(replace); }

/* ── the controls follow the state, and the state follows the controls ── */
function hlShow() {
  if (!document.getElementById('hl-form')) return;
  document.querySelectorAll('#hl-range button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.range === HL.range)));
  document.getElementById('hl-custom').hidden = HL.range !== 'custom';
  document.getElementById('hl-from').value = hlLocalField(HL.from);
  document.getElementById('hl-to').value = hlLocalField(HL.to);
  const host = document.getElementById('hl-host');
  if (![...host.options].some((o) => o.value === HL.host)) host.append(Object.assign(hlEl('option', {}, HL.host), { value: HL.host }));      // a link names a host the list has not met
  host.value = HL.host;
  document.getElementById('hl-level').value = HL.level;
  // a field somebody is typing in is theirs: the address catches up to it after a pause, and writing the last applied text back would eat what they have typed
  for (const [id, v] of [['hl-unit', HL.unit], ['hl-q', HL.q]]) { const f = document.getElementById(id); if (f !== document.activeElement) f.value = v; }
}
function hlReadFilters() {
  HL.host = document.getElementById('hl-host').value;
  HL.level = document.getElementById('hl-level').value;
  HL.unit = document.getElementById('hl-unit').value.trim();
  HL.q = document.getElementById('hl-q').value.trim();
}
function hlQuery(withRange = true) {
  const q = new URLSearchParams();
  for (const [k, v] of [['host', HL.host], ['level', HL.level], ['unit', HL.unit], ['q', HL.q]]) if (v) q.set(k, v);
  if (withRange) {
    const { since, until } = hlBounds();
    if (since != null) q.set('since', String(since));
    if (until != null) q.set('until', String(until));
  }
  return q;
}

/* ── lines ───────────────────────────────────────────────────────── */
function hlEmpty() {
  const li = (msg, note) => hlEl('li', { class: 'muted' }, msg, note ? hlEl('span', { class: 'm' }, note) : null);
  const stored = (HL.status || []).filter((s) => !HL.host || s.host === HL.host).reduce((n, s) => n + s.lines, 0);
  const where = HL.host || 'any host';
  if (HL.status && !stored) {
    return li(`No lines match: nothing has been collected from ${where} yet.`, 'Scan the host, and its journal is collected with the scan. A host with no journal, or one the scan user cannot read, says so under Hosts.');
  }
  const total = HL.counts ? HL.counts.total : null;
  if (total === 0) {
    const s = (HL.status || []).filter((x) => x.newest && (!HL.host || x.host === HL.host));
    const newest = Math.max(0, ...s.map((x) => x.newest || 0)), oldest = Math.min(...s.map((x) => x.oldest || Infinity));
    return li(`No lines match: ${where} logged nothing ${hlRangeText()}.`,
              newest ? `${hlPlural(stored, 'line')} stored, from ${fmtTime(oldest)} to ${fmtTime(newest)}. Choose a longer range.` : 'Choose a longer range.');
  }
  if (total != null) {
    const what = [HL.level && 'level', HL.unit && 'unit', HL.q && 'text'].filter(Boolean).join(', ');
    return li(`No lines match these filters${what ? ` (${what})` : ''}.`, `${hlPlural(total, 'line')} ${total === 1 ? 'was' : 'were'} stored ${hlRangeText()}. Clear a filter to see them.`);
  }
  return li('No lines match. Newer lines arrive when a host is scanned.');
}
/* A line names its own program (ident), and anyone on a host can name any. journald's own account of the writer (comm, exe, uid) is said
   beside it when the two differ, and in full on hover. */
function hlBy(e) {
  const said = (e.ident || '').toLowerCase(), was = (e.comm || '').toLowerCase();
  return was && said && was !== said && !said.startsWith(was) && !was.startsWith(said) ? ` · written by ${e.comm}${e.uid != null ? ` (uid ${e.uid})` : ''}` : '';
}
/* How a host's lines come: pushed by its agent as they are written, in batches its key signed (with the delay and the numbers missing
   from the journal's own count), or collected by the scan over SSH, which signs nothing. */
function hlVia(s) {
  if (s.via !== 'agent') return 'collected by the scan over SSH, not signed';
  const delay = s.delay_ms != null ? `, ${(s.delay_ms / 1000).toFixed(1)} s behind` : '';
  const gaps = s.gaps ? `, ${hlPlural(s.gaps, 'line')} missing from the journal's count (deleted on the host, or lost)` : ', none missing';
  return `pushed by the agent, signed${delay}${gaps}`;
}
function hlWriter(e) {
  const parts = [fmtUtc(e.ts), e.signed ? 'pushed by the agent, signed' : e.via === 'netconsole' ? 'came over netconsole: UDP, not signed'
    : e.via === 'pstore' ? 'read from pstore, written by the kernel before a crash' : 'collected by a scan'];
  if (e.exe || e.comm) parts.push(`journald: ${e.exe || e.comm}${e.uid != null ? `, uid ${e.uid}` : ''}`);
  if (e.arrived) parts.push(`arrived ${fmtUtc(e.arrived)}`);
  return parts.join(' · ');
}

async function hlSearch(more) {
  const fresh = latest('hostlogs');
  HL.offset = more ? HL.offset + HL_PAGE : 0;
  const q = hlQuery();
  q.set('limit', String(HL_PAGE)); q.set('offset', String(HL.offset));
  const lines = document.getElementById('hl-lines');
  try {
    const { entries, more: hasMore } = await getJSON(`/api/hostlogs?${q}`);
    if (!fresh()) return;                         // a newer search was asked for while this one was on its way
    const rows = entries.map((e) => {
      const cls = e.priority <= 3 ? 'st-failed' : e.priority === 4 ? 'st-warn' : '';
      return hlEl('li', {}, hlEl('span', cls ? { class: cls } : {}, e.message),
        hlEl('span', { class: 'm', title: hlWriter(e) }, `${hlWhen(e.ts)} · ${e.host} · ${e.level} · ${e.unit || e.ident || '-'}${e.pid ? ` [${e.pid}]` : ''}${hlBy(e)}`));
    });
    let empty = null;
    if (!rows.length && !more) {                  // nothing collected, nothing in the range and nothing under these filters are three different answers
      if (HL.counts == null && HL.countsP) await HL.countsP;
      if (!fresh()) return;
      empty = hlEmpty();
    }
    if (more) lines.append(...rows);
    else lines.replaceChildren(...(rows.length ? rows : [empty]));
    document.getElementById('hl-more').hidden = !hasMore;
    const shown = lines.querySelectorAll('li').length;
    document.getElementById('hl-count').textContent = rows.length || more ? `${hlPlural(shown, 'line')} shown, newest first${hasMore ? '. Older ones follow.' : ''}` : '';
    const file = hlQuery(); file.set('format', 'csv');
    document.getElementById('hl-export').href = `/api/hostlogs/export?${file}`;
  } catch (err) {
    if (!fresh()) return;
    lines.replaceChildren(hlEl('li', { class: 'muted' }, err.message));
    document.getElementById('hl-more').hidden = true;
  }
}

/* ── the chart ───────────────────────────────────────────────────── */
const HL_W = 720, HL_H = 210, HL_L = 46, HL_R = 8, HL_T = 10, HL_B = 30;
function hlNiceMax(n) {
  const p = 10 ** Math.floor(Math.log10(Math.max(n, 1)));
  for (const m of [1, 2, 5, 10]) if (m * p >= n) return m * p;
  return 10 * p;
}
function hlBand(levels) {
  return HL_BANDS.map((b) => ({ ...b, n: b.levels.reduce((s, l) => s + (levels[l] || 0), 0) }));
}
function hlPatterns() {
  const mk = (key, ...shapes) => hlSvg('pattern', { id: `hl-pat-${key}`, width: 6, height: 6, patternUnits: 'userSpaceOnUse' }, ...shapes);
  const bg = (key, soft) => hlSvg('rect', { width: 6, height: 6, class: `hl-fill-${key}${soft ? ' hl-soft' : ''}` });
  return hlSvg('defs', {},
    mk('err', bg('err', false)),                                                                                     // solid
    mk('warning', bg('warning', true), hlSvg('path', { d: 'M-1 7L7 -1M-1 1L1 -1M5 7L7 5', class: 'hl-stroke-warning' })),          // diagonal stripes
    mk('notice', bg('notice', true), hlSvg('circle', { cx: 3, cy: 3, r: 1.6, class: 'hl-fill-notice' })),                           // dots
    mk('info', bg('info', true), hlSvg('rect', { x: 0, y: 2, width: 6, height: 1.5, class: 'hl-fill-info' })));                     // a horizontal line
}
function hlSwatch(key) {
  return hlSvg('svg', { class: 'hl-swatch', width: 16, height: 16, viewBox: '0 0 16 16', 'aria-hidden': 'true', focusable: 'false' },
    hlSvg('rect', { x: 0.5, y: 0.5, width: 15, height: 15, fill: `url(#hl-pat-${key})`, class: 'hl-swatch-box' }));
}
/* The hours drawn: every hour from the start of the range to its end, so that a quiet hour is a gap and not missing. The API sends only the
   hours that have lines, and at most 792 of them, newest first kept. */
function hlSlots(counts) {
  const hours = counts.by_hour.map((h) => ({ ...h, at: Date.parse(h.hour) / 3600000 }));
  const { since, until } = hlBounds();
  const last = hours.length ? hours[hours.length - 1].at : null;
  const nowHour = Math.floor(Date.now() / 3600000);
  let lo = since != null ? Math.floor(since / 3600) : hours.length ? hours[0].at : nowHour;
  let hi = until != null ? Math.floor(until / 3600) : Math.max(nowHour, last == null ? nowHour : last);
  if (hi < lo) hi = lo;
  if (hi - lo + 1 > 792) lo = hi - 791;
  const byAt = new Map(hours.map((h) => [h.at, h]));
  return Array.from({ length: hi - lo + 1 }, (_, i) => byAt.get(lo + i) || { at: lo + i, total: 0, levels: {} });
}
function hlDescribe(counts, slots) {
  const bands = hlBand(counts.by_level);
  const busiest = slots.reduce((a, b) => (b.total > a.total ? b : a), slots[0] || { total: 0 });
  const bandText = bands.map((b) => `${b.n.toLocaleString()} ${b.label.toLowerCase()}`).join(', ');
  return `${hlPlural(counts.total, 'line')} ${hlRangeText()}${HL.host ? ` on ${HL.host}` : ' on all hosts'}: ${bandText}. `
       + (busiest.total ? `The busiest hour was ${hlHourLabel(busiest.at * 3600)} with ${hlPlural(busiest.total, 'line')}.` : '');
}
function hlDrawChart(counts) {
  const box = document.getElementById('hl-chart');
  if (!counts.total) {
    box.replaceChildren(hlEl('p', { class: 'muted' }, `No lines to draw: ${HL.host || 'no host'} has none ${hlRangeText()}.`));
    return;
  }
  const slots = hlSlots(counts);
  const peak = Math.max(1, ...slots.map((s) => s.total));
  const top = hlNiceMax(peak);
  const plotW = HL_W - HL_L - HL_R, plotH = HL_H - HL_T - HL_B;
  const slotW = plotW / slots.length, barW = Math.max(slotW > 4 ? slotW - 1 : slotW, 0.6);
  const y = (n) => HL_T + plotH - (n / top) * plotH;
  const summary = hlDescribe(counts, slots);
  const svg = hlSvg('svg', { id: 'hl-svg', class: 'hl-svg', viewBox: `0 0 ${HL_W} ${HL_H}`, role: 'img', 'aria-labelledby': 'hl-svg-t hl-svg-d', focusable: 'false' },
    hlSvg('title', { id: 'hl-svg-t' }, 'Log lines by level and hour'),
    hlSvg('desc', { id: 'hl-svg-d' }, summary),
    hlPatterns());
  const ticks = top >= 2 ? [0, top / 2, top] : [0, top];
  for (const t of ticks) {
    svg.append(hlSvg('line', { x1: HL_L, x2: HL_W - HL_R, y1: y(t), y2: y(t), class: 'hl-grid' }),
               hlSvg('text', { x: HL_L - 5, y: y(t) + 3.5, class: 'hl-axis', 'text-anchor': 'end' }, Number.isInteger(t) ? t.toLocaleString() : String(t)));
  }
  const labels = Math.min(6, slots.length);
  const shown = new Set();
  for (let i = 0; i < labels; i++) shown.add(labels === 1 ? 0 : Math.round((i * (slots.length - 1)) / (labels - 1)));
  slots.forEach((s, i) => {
    const x = HL_L + i * slotW;
    const g = hlSvg('g', { class: 'hl-bar' });
    const bands = hlBand(s.levels);
    g.append(hlSvg('title', {}, s.total
      ? `${hlHourLabel(s.at * 3600)} (${fmtUtc(s.at * 3600)}): ${hlPlural(s.total, 'line')}. ${bands.filter((b) => b.n).map((b) => `${b.n.toLocaleString()} ${b.label.toLowerCase()}`).join(', ')}`
      : `${hlHourLabel(s.at * 3600)} (${fmtUtc(s.at * 3600)}): no lines`),
      hlSvg('rect', { x, y: HL_T, width: slotW, height: plotH, class: 'hl-hit' }));
    let base = 0;
    for (const b of bands) {
      if (!b.n) continue;
      const h = (b.n / top) * plotH;
      g.append(hlSvg('rect', { x: x + (slotW - barW) / 2, y: y(base + b.n), width: barW, height: Math.max(h, 0.8), fill: `url(#hl-pat-${b.key})`, class: `hl-seg hl-edge-${b.key}`, 'data-band': b.key }));
      base += b.n;
    }
    svg.append(g);
    if (shown.has(i)) {
      svg.append(hlSvg('line', { x1: x + slotW / 2, x2: x + slotW / 2, y1: HL_T + plotH, y2: HL_T + plotH + 4, class: 'hl-grid' }),
                 hlSvg('text', { x: x + slotW / 2, y: HL_H - 12, class: 'hl-axis', 'text-anchor': i === 0 && labels > 1 ? 'start' : i === slots.length - 1 && labels > 1 ? 'end' : 'middle' }, hlHourLabel(s.at * 3600)));
    }
  });
  svg.append(hlSvg('text', { x: HL_L, y: HL_H - 1, class: 'hl-axis' }, `One bar per UTC hour, drawn in your time zone. Lines per hour, up to ${top.toLocaleString()}.`));
  const legend = hlEl('ul', { class: 'hl-legend', 'aria-label': 'Levels' }, hlBand(counts.by_level).map((b) =>
    hlEl('li', {}, hlSwatch(b.key), hlEl('span', {}, `${b.label}: ${b.n.toLocaleString()}`))));
  const lines = slots.filter((s) => s.total).reverse();
  const table = sfMoreList(lines, (s) => hlEl('li', {}, `${hlHourLabel(s.at * 3600)} (${fmtUtc(s.at * 3600)}): ${hlPlural(s.total, 'line')}. `
    + hlBand(s.levels).filter((b) => b.n).map((b) => `${b.n.toLocaleString()} ${b.label.toLowerCase()}`).join(', ')), { limit: 24, label: 'hours', tag: 'ul', className: 'hl-hours' });
  box.replaceChildren(
    hlEl('p', { class: 'hl-summary', id: 'hl-summary' }, summary),
    hlEl('div', { class: 'hl-chartwrap' }, svg),
    legend,
    counts.truncated ? hlEl('p', { class: 'muted small' }, 'The chart shows the newest 792 hours (33 days) only; older hours are left out.') : null,
    hlEl('p', { class: 'muted small' }, 'The chart counts every line of the host in the range, whatever the level, unit or text chosen below.'),
    hlEl('details', { class: 'hl-alt' }, hlEl('summary', {}, 'The same numbers as a list'), table));
}
async function hlChart() {
  const fresh = latest('hostlogs-counts');
  const q = hlQuery(true);
  for (const k of ['level', 'unit', 'q']) q.delete(k);           // the API counts by host and range only
  const box = document.getElementById('hl-chart');
  HL.counts = null;
  HL.countsP = (async () => {
    try {
      const counts = await getJSON(`/api/hostlogs/counts?${q}`);
      if (!fresh()) return null;
      HL.counts = counts;
      hlDrawChart(counts);
      return counts;
    } catch (err) {
      if (fresh()) box.replaceChildren(hlEl('p', { class: 'muted' }, err.message));
      return null;
    }
  })();
  return HL.countsP;
}

/* ── units ───────────────────────────────────────────────────────── */
async function hlUnits() {
  const fresh = latest('hostlogs-units');
  const q = new URLSearchParams(); if (HL.host) q.set('host', HL.host);
  try {
    const { units } = await getJSON(`/api/hostlogs/units?${q}`);
    if (!fresh()) return;
    document.getElementById('hl-units').replaceChildren(...units.map((u) => Object.assign(hlEl('option', {}, `${hlPlural(u.lines, 'line')}`), { value: u.unit })));
  } catch { /* the field still takes a name typed in full */ }
}

/* ── hosts: when each was last collected ─────────────────────────── */
const HL_STATE = { side: 'only kernel messages from netconsole or pstore, no journal yet', ok: 'collected', partial: 'collected, but cut', limited: 'collected, the journal only in part', no_journal: 'no journal on this host', failed: 'the last try failed' };
function hlHostRows(names, status) {
  const by = new Map(status.map((s) => [s.host, s]));
  const rows = [...new Set([...names, ...by.keys()])].map((name) => ({ name, s: by.get(name) || null }));
  const trouble = (r) => !r.s || !!r.s.note || r.s.state !== 'ok';
  return rows.sort((a, b) => (trouble(b) - trouble(a)) || a.name.localeCompare(b.name));
}
function hlRenderHosts(names, status) {
  const rows = hlHostRows(names, status);
  const list = document.getElementById('hl-status');
  if (!rows.length) { list.replaceChildren(hlEl('li', { class: 'muted' }, 'No hosts yet.')); return; }
  const pick = (name) => {
    const b = hlEl('button', { type: 'button', class: 'btn ghost sm', title: `Show only ${name}'s lines` }, name);
    b.addEventListener('click', () => { document.getElementById('hl-host').value = name; hlApply(); document.getElementById('hl-host').focus(); });
    return b;
  };
  const render = ({ name, s }) => {
    if (!s) return hlEl('li', { class: 'hl-host' }, hlEl('span', { class: 'hl-hname' }, pick(name), hlEl('span', { class: 'st-warn' }, 'not collected')),
                       hlEl('span', { class: 'm' }, 'No journal has been collected from this host. Scan it to get one.'));
    const bad = s.state === 'failed' || s.state === 'no_journal' || s.state === 'limited';
    const label = hlEl('span', { class: bad || s.note ? 'st-warn' : 'st-ok' }, HL_STATE[s.state] || s.state);
    const when = hlEl('span', {}, s.state === 'failed' ? 'last tried ' : 'last collected ', timeEl(s.collected_at, { seconds: false }), ` (${fmtAgo(s.collected_at)})`);
    const kept = s.lines ? `${hlPlural(s.lines, 'line')} kept, from ${fmtTime(s.oldest)} to ${fmtTime(s.newest)}` : 'no lines kept';
    return hlEl('li', { class: 'hl-host' }, hlEl('span', { class: 'hl-hname' }, pick(name), label, when),
                hlEl('span', { class: 'm' }, `${kept}${s.state === 'failed' ? '' : `, ${hlPlural(s.new_lines, 'new line')} in the last pickup`}`),
                hlEl('span', { class: s.gaps ? 'm st-warn' : 'm' }, hlVia(s)),
                s.note ? hlEl('span', { class: 'm st-warn' }, s.note) : null);
  };
  list.replaceChildren(sfMoreList(rows, render, { limit: 12, label: 'hosts', tag: 'ul', className: 'list hl-hostlist' }));
}

/* ── monitoring: each host against its usual (logmonitor.py) ────── */
const HL_LEVEL_WORD = { crit: 'Critical', warn: 'Warning', info: 'Information' };
const hlN = (x) => (x == null ? '-' : Number(x) >= 10 || Number.isInteger(Number(x)) ? Math.round(Number(x)).toLocaleString() : Number(x).toFixed(1));
function hlRateText(r) {
  if (!r) return 'Nothing collected yet: no baseline.';
  if (r.known_until == null) return 'Nothing known of the last hour: the last scan failed, or was too long ago.';
  if (r.learning) return `Learning what is usual: a baseline needs two weeks of counts, ${r.learned_at ? `from ${fmtDate(r.learned_at)}` : 'once lines come'}.`;
  return `${hlPlural(r.hour || 0, 'line')} in the last hour, usually ${hlN(r.usual)} (the same hour of the last ${r.weeks} weeks).`;
}
function hlMonState(h) {
  if (h.silent) return hlEl('span', { class: h.pushed ? 'st-failed' : 'st-warn' }, 'stopped logging');
  if (h.alerts.some((a) => a.level === 'crit')) return hlEl('span', { class: 'st-failed' }, hlPlural(h.alerts.length, 'open log alert'));
  if (h.alerts.length) return hlEl('span', { class: 'st-warn' }, hlPlural(h.alerts.length, 'open log alert'));
  if (h.ingest.state === 'never') return hlEl('span', { class: 'st-warn' }, 'not collected');
  if (!h.rate || h.rate.learning || h.rate.known_until == null) return hlEl('span', {}, 'no baseline yet');
  return hlEl('span', { class: 'st-ok' }, 'as usual');
}
function hlIngestText(i) {
  if (i.state === 'never') return 'No journal has been collected from this host. Scan it to get one.';
  const parts = [i.via === 'agent' ? `pushed by the agent, signed${i.delay_ms != null ? `, ${(i.delay_ms / 1000).toFixed(1)} s behind` : ''}` : 'collected by the scan over SSH, not signed'];
  parts.push(i.last_line ? `last line ${fmtTime(i.last_line)}` : 'no line kept');
  if (i.last_arrival) parts.push(`last new line arrived ${fmtAgo(i.last_arrival)}`);
  parts.push(i.gaps ? `${hlPlural(i.gaps, 'line')} missing from the journal's count` : i.via === 'agent' ? 'none missing from the journal\'s count' : 'gaps not seen by scans');
  if (i.over_total) parts.push(`${hlPlural(i.over_total, 'line')} over the rate, counted and not kept`);
  return parts.join(' · ');
}
/* netconsole and pstore come beside the journal, and may come when there is no journal at all */
function hlSideText(i) {
  const parts = [];
  const nc = i.netconsole;
  if (nc) parts.push(`netconsole from ${nc.address} port ${nc.port}${nc.enabled ? '' : ' (off)'}, not signed: ${nc.last_at ? `last heard ${fmtAgo(nc.last_at)}` : 'nothing heard yet'}${nc.dropped ? `, ${hlPlural(nc.dropped, 'packet')} dropped` : ''}`);
  const p = i.pstore;
  if (p) parts.push(`pstore: ${hlPlural(p.records, 'crash record')}, the newest written ${fmtTime(p.at)}${p.read ? '' : `. ${p.note}`}`);
  return parts.join(' · ');
}
function hlMonHost(h) {
  const pick = hlEl('button', { type: 'button', class: 'btn ghost sm', title: `Show only ${h.host}'s lines` }, h.host);
  pick.addEventListener('click', () => { document.getElementById('hl-host').value = h.host; hlApply(); document.getElementById('hl-lines').scrollIntoView({ block: 'nearest' }); });
  const kids = [hlEl('span', { class: 'hl-hname' }, pick, hlMonState(h)), hlEl('span', { class: 'm' }, hlRateText(h.rate))];
  if (h.rate && h.rate.loud.length) {
    kids.push(hlEl('ul', { class: 'hl-mon-sub', 'aria-label': `Units on ${h.host} logging more than usual` }, h.rate.loud.map((u) =>
      hlEl('li', { class: 'st-warn' }, `${u.unit == null ? 'all of it' : u.unit || 'lines with no unit'}: ${hlPlural(u.lines, 'line')} in the last hour, usually ${hlN(u.usual)}`))));
  }
  if (h.silent) kids.push(hlEl('span', { class: h.pushed ? 'm st-failed' : 'm st-warn' }, `No new line since ${fmtTime(h.silent.since)}; it usually logs ${hlN(h.silent.usual)} lines in this part of the week.`));
  if (h.silent_units.length) {
    kids.push(hlEl('ul', { class: 'hl-mon-sub', 'aria-label': `Units on ${h.host} that stopped logging` }, h.silent_units.map((u) =>
      hlEl('li', { class: 'st-warn' }, `${u.unit} quiet since ${fmtTime(u.since)}, usually ${hlN(u.usual)} lines by now`))));
  }
  if (h.alerts.length) {
    kids.push(hlEl('ul', { class: 'hl-mon-sub', 'aria-label': `Open log alerts on ${h.host}` }, h.alerts.map((a) => {
      const go = hlEl('button', { type: 'button', class: 'btn ghost sm', title: 'Open the notification center' }, 'In the notification center');
      go.addEventListener('click', () => { if (typeof showTab === 'function') showTab('notifications'); });
      return hlEl('li', {}, hlEl('span', { class: a.level === 'crit' ? 'st-failed' : a.level === 'warn' ? 'st-warn' : '' }, `${HL_LEVEL_WORD[a.level]}: ${a.title}`),
        hlEl('span', { class: 'm' }, a.message), hlEl('span', { class: 'row' }, go));
    })));
  }
  const k = h.new_kinds;
  if (k.count) {
    kids.push(hlEl('details', { class: 'hl-alt' }, hlEl('summary', {}, `${hlPlural(k.count, 'new kind')} of line in the last day`),
      hlEl('ul', { class: 'hl-mon-sub' }, k.kinds.map((x) => hlEl('li', {}, hlEl('span', { class: x.priority <= 3 ? 'st-failed' : x.priority === 4 ? 'st-warn' : '' }, x.sample),
        hlEl('span', { class: 'm' }, `${x.level} · ${x.program || 'no program name'} · first ${fmtTime(x.first_at)} · ${hlPlural(x.lines, 'line')}`)))),
      k.count > k.kinds.length ? hlEl('p', { class: 'muted small' }, `The worst ${k.kinds.length} are shown.`) : null,
      k.over ? hlEl('p', { class: 'muted small' }, `${hlPlural(k.over, 'more kind')} were not kept: the host has as many as one host keeps.`) : null));
  } else if (h.ingest.state !== 'never') {
    kids.push(hlEl('span', { class: 'm' }, k.learning ? `New kinds of line are said from ${k.learned_at ? fmtDate(k.learned_at) : 'a week after the first line'}.` : 'No new kind of line in the last day.'));
  }
  kids.push(hlEl('span', { class: h.ingest.gaps ? 'm st-warn' : 'm' }, hlIngestText(h.ingest)));
  const side = hlSideText(h.ingest);
  if (side) kids.push(hlEl('span', { class: h.ingest.pstore ? 'm st-warn' : 'm' }, side));
  return hlEl('li', { class: 'hl-host', 'data-host': h.host }, ...kids);
}
async function hlMonitor() {
  const box = document.getElementById('hl-monitor');
  if (!box) return;
  const fresh = latest('hostlogs-monitor');
  try {
    const d = await getJSON('/api/hostlogs/monitor');
    if (!fresh()) return;
    const need = d.hosts.filter((h) => h.rank < 3).length;
    box.replaceChildren(
      hlEl('p', { class: 'muted small', id: 'hl-mon-sum' }, d.hosts.length ? (need ? `${hlPlural(need, 'host')} with something to look at, first.` : 'Every host is logging as usual, or has no baseline yet.') : 'No hosts yet.'),
      d.hosts.length ? sfMoreList(d.hosts, hlMonHost, { limit: 8, label: 'hosts', tag: 'ul', className: 'list hl-hostlist' }) : null);
  } catch (err) {
    if (fresh()) box.replaceChildren(hlEl('p', { class: 'muted' }, err.message));
  }
}

/* ── opening the panel, and what a change of control does ───────── */
function hlKnownHosts() { return [...document.querySelectorAll('#host option')].map((o) => o.value).filter(Boolean); }
async function loadHostLogs() {
  if (!can('hostlogs.view')) return;
  const fresh = latest('hostlogs-status');
  hlShow();
  let status = [];
  try {
    status = (await getJSON('/api/hostlogs/status')).hosts;
  } catch (err) {
    if (fresh()) document.getElementById('hl-status').replaceChildren(hlEl('li', { class: 'muted' }, err.message));
  }
  if (!fresh()) return;
  HL.status = status;
  const names = [...new Set([...hlKnownHosts(), ...status.map((s) => s.host)])].sort();
  const pick = document.getElementById('hl-host');
  pick.replaceChildren(Object.assign(hlEl('option', {}, 'All hosts'), { value: '' }), ...names.map((n) => Object.assign(hlEl('option', {}, n), { value: n })));
  hlShow();
  hlRenderHosts(names, status);
  await Promise.all([hlMonitor(), hlChart(), hlUnits(), hlSearch(false)]);
}
/* A change of host or range: the chart, the units and the lines are asked again. A change of level, unit or text asks for lines only. */
function hlApply({ push = true, chart = true } = {}) {
  hlReadFilters();
  if (HL.range === 'custom' && HL.from != null && HL.to != null && HL.from > HL.to) return hlCustomMsg('From is after To: nothing was searched.');
  hlCustomMsg('');
  hlSync(!push);
  if (chart) { hlChart(); hlUnits(); }
  return hlSearch(false);
}
function hlCustomMsg(msg) {
  const m = document.getElementById('hl-custom-msg');
  m.textContent = msg; m.hidden = !msg;
}
function hlSetRange(key) {
  HL.range = key;
  if (key === 'custom') {
    const now = Math.floor(Date.now() / 1000);
    if (HL.from == null && HL.to == null) { HL.to = now; HL.from = now - 86400; }            // a start to edit, not an empty form
  }
  hlShow();
  if (key === 'custom') { document.getElementById('hl-from').focus(); return; }
  hlApply();
}
function hlApplyCustom() {
  HL.from = hlParseField(document.getElementById('hl-from').value);
  HL.to = hlParseField(document.getElementById('hl-to').value);
  HL.range = 'custom';
  hlApply();
}

document.getElementById('hl-form').addEventListener('submit', (ev) => { ev.preventDefault(); hlApply({ chart: false }); });
for (const id of ['hl-level']) document.getElementById(id).addEventListener('change', () => hlApply({ chart: false }));
document.getElementById('hl-host').addEventListener('change', () => hlApply());
for (const id of ['hl-q', 'hl-unit']) {
  document.getElementById(id).addEventListener('input', () => {          // lines follow what is typed, after a short pause
    clearTimeout(HL.typing);
    HL.typing = setTimeout(() => hlApply({ push: false, chart: false }), 350);
  });
  document.getElementById(id).addEventListener('change', () => { clearTimeout(HL.typing); hlApply({ push: false, chart: false }); });
}
document.querySelectorAll('#hl-range button').forEach((b) => b.addEventListener('click', () => hlSetRange(b.dataset.range)));
document.getElementById('hl-custom').addEventListener('submit', (ev) => { ev.preventDefault(); hlApplyCustom(); });
document.getElementById('hl-more').addEventListener('click', () => hlSearch(true));

/* ── log rules (logrules.py): what raises a notification ─────────── */
const HL_SPAN = (secs) => (secs % 3600 === 0 ? `${secs / 3600} h` : `${Math.round(secs / 60)} min`);
const hlNum = (least, most, what) => (v) => (/^\d+$/.test(v) && Number(v) >= least && Number(v) <= most ? '' : `${what} is a whole number from ${least} to ${most}`);

async function hlRules() {
  const list = document.getElementById('hl-rules'), may = can('hostlogs.rules');
  document.getElementById('hl-rule-new').hidden = !may;
  let d;
  try { d = await getJSON('/api/hostlogs/rules'); } catch (e) { list.replaceChildren(hlEl('li', { class: 'st-failed' }, e.message)); return; }
  const again = async (work) => { try { await work(); } catch (e) { notify(e.message, 'error'); } hlRules(); };
  list.replaceChildren(...d.rules.map((r) => {
    const on = hlEl('input', { type: 'checkbox', 'aria-label': `${r.name}: on`, disabled: !may });
    on.checked = r.enabled;
    on.addEventListener('change', () => again(() => api(`/api/hostlogs/rules/${r.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...r, enabled: on.checked }) })));
    const means = [r.host !== '*' ? `host ${r.host}` : '', r.unit !== '*' ? `unit ${r.unit}` : '', r.program !== '*' ? `program ${r.program}` : '', r.min_level !== 'debug' ? `${r.min_level} or worse` : '',
                   r.text !== '*' ? `text ${r.text}` : ''].filter(Boolean).join(' · ');
    const edit = hlEl('button', { type: 'button', class: 'btn ghost sm' }, 'Change');
    edit.addEventListener('click', async () => {
      const f = await formDialog({ title: r.name, body: r.builtin ? 'A built-in rule: what it matches is StorageForge\'s, and follows the release. How many lines, in how long, and how loud are yours.' : means,
        fields: [{ name: 'threshold', label: 'Lines', value: r.threshold, inputmode: 'numeric', validate: hlNum(1, 1000000, 'Lines') },
                 { name: 'minutes', label: 'Within how many minutes', value: Math.round(r.window_secs / 60), inputmode: 'numeric', validate: hlNum(5, 10080, 'The window') },
                 { name: 'level', label: 'Raises: crit, warn or info', value: r.level, validate: (v) => (['crit', 'warn', 'info'].includes(v) ? '' : 'One of crit, warn, info') }] });
      if (f) again(() => api(`/api/hostlogs/rules/${r.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...r, threshold: Number(f.threshold), window_secs: Number(f.minutes) * 60, level: f.level }) }));
    });
    const del = hlEl('button', { type: 'button', class: 'btn ghost sm' }, 'Delete');
    del.addEventListener('click', async () => { if (await confirmDialog({ title: `Delete the rule "${r.name}"?`, confirm: 'Delete', danger: true })) again(() => api(`/api/hostlogs/rules/${r.id}`, { method: 'DELETE' })); });
    return hlEl('li', {}, hlEl('label', { class: 'row' }, on, hlEl('span', {}, r.name), r.builtin ? hlEl('span', { class: 'm' }, 'built in') : null),
      hlEl('span', { class: 'm' }, `${r.threshold} line${r.threshold === 1 ? '' : 's'} in ${HL_SPAN(r.window_secs)} raises ${{ crit: 'a critical notification', warn: 'a warning', info: 'information' }[r.level]}${r.enabled ? '' : ' · off'}`),
      hlEl('span', { class: 'm' }, means),
      may ? hlEl('span', { class: 'row' }, edit, r.builtin ? null : del) : null);
  }));
}

document.getElementById('hl-rules-box').addEventListener('toggle', (ev) => { if (ev.target.open) hlRules(); });
document.getElementById('hl-rule-new').addEventListener('click', async () => {
  const f = await formDialog({ title: 'New log rule', body: 'A pattern is text with * for anything and | between alternatives. Leave a field empty for any.',
    fields: [{ name: 'name', label: 'Name', required: true, maxlength: 100 }, { name: 'text', label: 'Text in the line', placeholder: '*PANIC*|*assertion failed*', maxlength: 600 },
             { name: 'unit', label: 'Unit', placeholder: 'smbd', maxlength: 600 }, { name: 'program', label: 'Program, as journald saw it', placeholder: 'smbd', maxlength: 600 },
             { name: 'min_level', label: 'Lowest level', value: 'warning', validate: (v) => (['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'].includes(v) ? '' : 'One of emerg, alert, crit, err, warning, notice, info, debug') },
             { name: 'threshold', label: 'Lines', value: 1, inputmode: 'numeric', validate: hlNum(1, 1000000, 'Lines') },
             { name: 'minutes', label: 'Within how many minutes', value: 60, inputmode: 'numeric', validate: hlNum(5, 10080, 'The window') },
             { name: 'level', label: 'Raises: crit, warn or info', value: 'warn', validate: (v) => (['crit', 'warn', 'info'].includes(v) ? '' : 'One of crit, warn, info') }], confirm: 'Add the rule' });
  if (!f) return;
  try { await postJSON('/api/hostlogs/rules', { name: f.name, text: f.text || '*', unit: f.unit || '*', program: f.program || '*', min_level: f.min_level, threshold: Number(f.threshold), window_secs: Number(f.minutes) * 60, level: f.level }); }
  catch (e) { notify(e.message, 'error'); }
  hlRules();
});

/* ── netconsole (netconsole.py): which address and port each host's kernel messages are taken from ── */
async function hlNetconsole() {
  const list = document.getElementById('hl-nc'), may = can('hostlogs.rules');
  document.getElementById('hl-nc-new').hidden = !may;
  let d;
  try { d = await getJSON('/api/hostlogs/netconsole'); } catch (e) { list.replaceChildren(hlEl('li', { class: 'st-failed' }, e.message)); return; }
  const r = d.receiver;
  document.getElementById('hl-nc-recv').textContent = r.listening ? `The controller listens on ${r.listening}. ${hlPlural(r.unknown, 'packet')} from addresses not listed here ${r.unknown === 1 ? 'was' : 'were'} dropped${r.last_unknown ? `, the last from ${r.last_unknown}` : ''}.`
    : r.error ? r.error : 'The controller does not listen for netconsole: set STORAGEFORGE_NETCONSOLE_LISTEN, such as 0.0.0.0:6666, and restart it.';
  HL.ncDefault = d.default_source_port;
  if (!d.sources.length) { list.replaceChildren(hlEl('li', { class: 'muted' }, 'No host sends netconsole here yet.')); return; }
  list.replaceChildren(...d.sources.map((s) => {
    const edit = hlEl('button', { type: 'button', class: 'btn ghost sm' }, 'Change');
    edit.addEventListener('click', () => hlNcEdit(s));
    const del = hlEl('button', { type: 'button', class: 'btn ghost sm' }, 'Remove');
    del.addEventListener('click', async () => {
      if (!await confirmDialog({ title: `Stop taking netconsole packets from ${s.host}?`, body: 'Packets from its address are dropped from then on. The host goes on sending until the netconsole step is undone there.', confirm: 'Remove', danger: true })) return;
      try { await api(`/api/hostlogs/netconsole/${encodeURIComponent(s.host)}`, { method: 'DELETE' }); } catch (e) { notify(e.message, 'error'); return; }
      hlNetconsole();
    });
    return hlEl('li', {}, hlEl('span', { class: s.enabled ? '' : 'muted' }, `${s.host}: ${s.address} port ${s.port}${s.enabled ? '' : ' (off)'}`),
      hlEl('span', { class: 'm' }, `${s.last_at ? `last heard ${fmtAgo(s.last_at)}` : 'nothing heard yet'} · ${hlPlural(s.packets, 'packet')} taken${s.dropped ? `, ${hlPlural(s.dropped, 'packet')} over the rate or too big` : ''}`),
      may ? hlEl('span', { class: 'row' }, edit, del) : null);
  }));
}
async function hlNcEdit(s = null) {
  const f = await formDialog({ title: s ? `Netconsole from ${s.host}` : 'Take netconsole packets from a host',
    body: 'Only packets from exactly this address and port are taken, and stored as the host\'s lines. UDP has no signature: anyone who can send from this address can write in the host\'s name.',
    fields: [...(s ? [] : [{ name: 'host', label: 'Host', required: true, maxlength: 200 }]),
             { name: 'address', label: 'The address it sends from', value: s ? s.address : '', required: true, maxlength: 64, placeholder: '10.42.0.7' },
             { name: 'port', label: 'The port it sends from', value: String(s ? s.port : HL.ncDefault || 6665), inputmode: 'numeric', validate: hlNum(1, 65535, 'The port') }],
    confirm: s ? 'Save' : 'Add' });
  if (!f) return;                                  // cancelled: nothing changed, so nothing is drawn again
  const host = s ? s.host : f.host.trim();
  try { await api(`/api/hostlogs/netconsole/${encodeURIComponent(host)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ address: f.address.trim(), port: Number(f.port), enabled: s ? s.enabled : true }) }); }
  catch (e) { notify(e.message, 'error'); return; }
  hlNetconsole();
}
document.getElementById('hl-nc-box').addEventListener('toggle', (ev) => { if (ev.target.open) hlNetconsole(); });
document.getElementById('hl-nc-new').addEventListener('click', () => hlNcEdit());
