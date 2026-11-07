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
/* A link to the Logs panel for a host, in the form the router reads. It keeps the view the person is in. */
function hlLink(host) {
  const parts = [typeof T !== 'undefined' && T.mode ? T.mode : 'topo', 'hostlogs'];
  return sfFormatHash(parts, { host, lhost: host });
}
function hlLinkEl(host, label = 'Logs') {
  const a = hlEl('a', { class: 'btn', href: hlLink(host), title: `What ${host}'s journal said, as of its last scan` }, label);
  return a;
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
        hlEl('span', { class: 'm', title: fmtUtc(e.ts) }, `${hlWhen(e.ts)} · ${e.host} · ${e.level} · ${e.unit || e.ident || '-'}${e.pid ? ` [${e.pid}]` : ''}`));
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
const HL_STATE = { ok: 'collected', partial: 'collected, but cut', limited: 'collected, the journal only in part', no_journal: 'no journal on this host', failed: 'the last try failed' };
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
                s.note ? hlEl('span', { class: 'm st-warn' }, s.note) : null);
  };
  list.replaceChildren(sfMoreList(rows, render, { limit: 12, label: 'hosts', tag: 'ul', className: 'list hl-hostlist' }));
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
  await Promise.all([hlChart(), hlUnits(), hlSearch(false)]);
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
