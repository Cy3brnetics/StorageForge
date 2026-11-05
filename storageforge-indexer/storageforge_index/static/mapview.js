'use strict';
/* Map view: hosts as frames holding their interfaces, listeners and workloads, joined through subnets and placeholders. Derived
   from what hosts report, and drawn with SVG and DOM APIs only. Dashed means inferred. Colour on a listener is who can reach it,
   per configuration. Positions, layers and the filter can be saved as a view; the facts always come from the index. */

const MP = { layers: new Set(['network', 'services', 'workloads', 'firewall', 'access', 'manual']), redact: false, filter: '', graph: null, sel: null, hover: null, mode: 'custom', at: null, group: 'host', scope: 'all', ghost: null, notes: [], coverage: null, trace: new Set(), collapsed: new Set(),
             view: { x: 0, y: 0, k: 1 }, positions: {}, exposed: false, loopback: false, neighbours: false, bridges: false, fitted: false, drag: null, rects: new Map(),
             open: {} };      // which cut lists are showing all their rows (see mapMore)
const MP_LAYERS = [['storage', 'Storage'], ['network', 'Network'], ['services', 'Services'], ['firewall', 'Firewall'], ['workloads', 'Workloads'], ['access', 'Access'], ['manual', 'Placed by hand']];
const MP_MODES = { network: { label: 'Network', layers: ['network', 'manual'] }, flow: { label: 'Flow', layers: ['network', 'services', 'firewall', 'access'] }, workloads: { label: 'Workloads', layers: ['workloads', 'services'] }, storage: { label: 'Storage only', layers: ['storage'] },
                   security: { label: 'Security', layers: ['services', 'firewall', 'workloads', 'storage'], exposed: true }, custom: { label: 'Custom', layers: null } };
const MP_LEVEL = { any: 'Any address', lan: 'Private networks', vpn: 'VPN only', blocked: 'Blocked', loopback: 'This machine only', unknown: 'Unknown' };
const SVGNS = 'http://www.w3.org/2000/svg';
const MP_ROW = 24, MP_W = 300, MP_GAP = 44;
const MP_SHOWN = { changes: 20, cover: 20, warn: 10, compare: 30 };      // rows a list shows before it says "+N more"

/* A list that shows its first rows says how many it leaves out, and the same button shows the rest and hides them again (UX-13).
   Returns [] or [button], so a caller can spread it into its rows. */
function mapMore(key, total, shown, redraw) {
  if (total <= shown) return [];
  const open = !!MP.open[key];
  const b = button(open ? 'Show fewer' : `+${total - shown} more`, () => {
    MP.open[key] = !open;
    Promise.resolve(redraw()).then(() => document.querySelector(`#mapview [data-more="${key}"]`)?.focus());
  }, 'btn small');
  b.setAttribute('aria-expanded', String(open));
  b.dataset.more = key;
  return [b];
}

function sv(tag, attrs = {}, ...kids) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== null && v !== undefined) e.setAttribute(k, v);
  e.append(...kids);
  return e;
}

async function loadMap() {
  const fresh = latest('map');                      // a slow answer must not draw over, or replace the state of, the one asked for after it (UX-12)
  const box = $('#mapview');
  if (!box.firstChild) mapShell(box);
  $('#mpcanvas').replaceChildren(text('p', 'Loading…', 'muted small'));
  try {
    const qs = new URLSearchParams({ layers: [...MP.layers].join(',') || 'network' });
    if (MP.redact) qs.set('redact', '1');
    if (MP.at) qs.set('at', String(MP.at));
    const graph = await getJSON('/api/map?' + qs);
    if (!fresh()) return;
    MP.graph = graph;
    mapGhostApply();
    let coverage = null, notes = [];
    if (can('security.view')) { try { coverage = await getJSON('/api/map/coverage'); } catch { coverage = null; } }
    try { notes = (await getJSON('/api/map/annotations')).annotations; } catch { notes = []; }
    if (!fresh()) return;
    MP.coverage = coverage; MP.notes = notes;
    MP.sel = null;
    MP.fitted = false;
    mapDraw();
    mapDetail();
    mapChanges();
    mapCoverage();
  } catch (err) { if (fresh()) $('#mpcanvas').replaceChildren(text('p', err.message, 'st-failed')); }
}

function mapSetMode(mode) {
  const m = MP_MODES[mode];
  MP.mode = mode;
  if (m.layers) MP.layers = new Set(m.layers);
  MP.exposed = !!m.exposed;
  $('#mapview').replaceChildren();
  MP.fitted = false;
  loadMap();
}

function mapShell(box) {
  const bar = el('div', { class: 'mpbar' });
  // two groups that name the same things (Network, Workloads, Storage): a preset picks layers, and each says which it is
  bar.append(el('span', { class: 'mpcap' }, 'Look at'),
    el('div', { class: 'mpmodes', role: 'group', 'aria-label': 'What to look at' }, ...Object.entries(MP_MODES).map(([k, m]) => { const b = button(m.label, () => mapSetMode(k), 'btn small'); b.dataset.mode = k; b.setAttribute('aria-pressed', String(MP.mode === k)); return b; })));
  const layers = el('div', { class: 'mplayers', role: 'group', 'aria-label': 'Layers' }, el('span', { class: 'mpcap' }, 'Layers'));
  for (const [id, label] of MP_LAYERS) {
    const c = el('input', { type: 'checkbox' }); c.checked = MP.layers.has(id);
    c.addEventListener('change', () => {
      MP.mode = 'custom'; if (c.checked) MP.layers.add(id); else MP.layers.delete(id);
      bar.querySelectorAll('.mpmodes button').forEach((m) => m.setAttribute('aria-pressed', String(m.dataset.mode === 'custom')));   // the preset no longer describes what is drawn
      loadMap();
    });
    layers.append(el('label', { class: 'small' }, c, ' ' + label));
  }
  bar.append(layers);
  const group = el('select', { 'aria-label': 'Group by' }, new Option('By host', 'host'), new Option('By subnet', 'subnet'), new Option('By runtime', 'runtime'));
  group.value = MP.group;
  group.addEventListener('change', () => { MP.group = group.value; MP.fitted = false; mapDraw(); });
  const scope = el('select', { 'aria-label': 'Reachable from' }, new Option('From anywhere it can be', 'all'), new Option('Reachable from the LAN', 'lan'), new Option('Reachable over the VPN', 'vpn'), new Option('Reachable from any address', 'any'));
  scope.value = MP.scope;
  scope.addEventListener('change', () => { MP.scope = scope.value; MP.fitted = false; mapDraw(); });
  bar.append(group, scope);
  const search = el('input', { type: 'search', placeholder: 'Filter by name, address or port', 'aria-label': 'Filter the map', id: 'mpfilter' });
  search.addEventListener('input', () => { MP.filter = search.value.trim().toLowerCase(); mapDraw(); });
  const exposed = el('input', { type: 'checkbox' }); exposed.checked = MP.exposed;
  exposed.addEventListener('change', () => { MP.exposed = exposed.checked; mapDraw(); });
  const redact = el('input', { type: 'checkbox' });
  redact.addEventListener('change', () => { MP.redact = redact.checked; loadMap(); });
  const toggle = (key, label) => { const c = el('input', { type: 'checkbox' }); c.addEventListener('change', () => { MP[key] = c.checked; MP.fitted = false; mapDraw(); }); return el('label', { class: 'small' }, c, label); };
  bar.append(search, toggle('loopback', ' This-machine-only ports'), toggle('bridges', ' Container networks'), toggle('neighbours', ' Devices nearby'), el('label', { class: 'small' }, exposed, ' Only what others can reach'), el('label', { class: 'small' }, redact, ' Hide names and addresses'));
  const fmts = el('select', { 'aria-label': 'Export as' }, new Option('Export…', ''), ...['json', 'mermaid', 'dot', 'svg', 'drawio', 'canvas'].map((f) => new Option(f.toUpperCase(), f)), new Option('PNG, as drawn', 'png'), new Option('SVG, as drawn', 'drawn'), new Option('PDF: print this', 'pdf'));
  fmts.addEventListener('change', () => {
    const f = fmts.value; fmts.value = '';
    if (f === 'png') mapSavePng();
    else if (f === 'drawn') mapSaveSvg();
    else if (f === 'pdf') window.print();
    else if (f) location.href = `/api/map/export?format=${f}&layers=${[...MP.layers].join(',')}${MP.redact ? '&redact=1' : ''}`;
  });
  bar.append(fmts, button('Fit', () => mapFit(0), 'btn small'), button('Clear pins', () => { MP.positions = {}; mapDraw(); }, 'btn small'));
  const canvas = el('div', { id: 'mpcanvas', class: 'mpcanvas' });
  const side = el('aside', { class: 'mpside' }, el('div', { id: 'mpdetail' }), el('div', { id: 'mpreach' }), el('div', { id: 'mpwhatif' }), el('div', { id: 'mpcover' }), el('div', { id: 'mpmanual' }), el('div', { id: 'mpdesigns' }), el('div', { id: 'mpviews' }), el('div', { id: 'mpchanges' }));
  box.append(bar, el('div', { class: 'mpbody' }, canvas, side));
  mapViews();
  mapReachPanel();
  mapWhatIfPanel();
  mapManualPanel();
  mapDesignsPanel();
}

function mapMatches(n) {
  if (!MP.filter) return true;
  return JSON.stringify([n.label, n.kind, n.host, n.props]).toLowerCase().includes(MP.filter);
}
function mapShown(n) {
  if (n.kind === 'Neighbour' && !MP.neighbours) return false;
  if (n.props.container_bridge && !MP.bridges) return false;
  if (n.kind === 'Listener' && n.props.exposure === 'loopback' && !MP.loopback) return false;
  if (!MP.exposed && MP.scope === 'all') return true;
  if (n.kind !== 'Listener') return n.kind === 'Host';
  // who can reach it from this scope. Unknown always counts: it might be
  return { all: ['any', 'lan', 'vpn', 'unknown'], lan: ['any', 'lan', 'unknown'], vpn: ['any', 'lan', 'vpn', 'unknown'], any: ['any', 'unknown'] }[MP.scope].includes(n.props.exposure);
}

// Frames in a grid, tallest first in each column's turn, and shared nodes in a band above them. Deterministic: the same graph draws the same.
function mapLayout(g) {
  const frames = new Map();
  const shared = [];
  const frameOf = (n) => {
    if (MP.group === 'runtime' && n.props.runtime) return `runtime: ${n.props.runtime}`;
    if (MP.group === 'subnet' && (n.props.addresses || [])[0]) return `subnet: ${mapSubnet(n.props.addresses[0])}`;
    return n.host;
  };
  for (const n of g.nodes) {
    if (!mapShown(n)) continue;
    if (n.host && n.kind !== 'Host') { const f = frameOf(n); if (!frames.has(f)) frames.set(f, []); frames.get(f).push(n); }
    else if (n.kind === 'Host') { if (!frames.has(n.label)) frames.set(n.label, []); }
    else shared.push(n);
  }
  const hosts = g.nodes.filter((n) => n.kind === 'Host');
  const rects = new Map();
  shared.sort((a, b) => (a.kind + a.label).localeCompare(b.kind + b.label));
  const perRow = Math.max(4, Math.ceil(Math.sqrt(shared.length * 3)));
  shared.forEach((n, i) => {
    const r = { x: 20 + (i % perRow) * 200, y: 20 + Math.floor(i / perRow) * 40, w: 184, h: 28, node: n };
    rects.set(n.id, r);
  });
  const top = shared.length ? 40 + Math.ceil(shared.length / perRow) * 40 : 20;
  const cols = Math.max(1, Math.min(4, Math.ceil(Math.sqrt(frames.size))));
  const heights = new Array(cols).fill(top);
  const out = [];
  const order = { NIC: 0, Bond: 0, Bridge: 0, VLAN: 0, VPNInterface: 0, FirewallPolicy: 1, Listener: 2, Container: 3, VM: 3, Instance: 3, StoragePool: 4, Filesystem: 4, MountPoint: 4, Symlink: 5 };
  for (const [host, items] of [...frames].sort((a, b) => a[0].localeCompare(b[0]))) {
    const col = heights.indexOf(Math.min(...heights));
    items.sort((a, b) => (order[a.kind] ?? 9) - (order[b.kind] ?? 9) || a.label.localeCompare(b.label));
    const x = 20 + col * (MP_W + MP_GAP), y = heights[col];
    const hostNode = hosts.find((n) => n.label === host);
    const pin = MP.positions[`frame:${host}`];
    const shut = MP.collapsed.has(host);
    const fx = pin ? pin.x : x, fy = pin ? pin.y : y;
    const frame = { x: fx, y: fy, w: MP_W, h: shut ? 44 : 44 + items.length * MP_ROW + 8, host, node: hostNode, count: items.length, shut };
    // semantic zoom: far out, or shut by hand, a host is one box, and lines to what is inside it go to the box
    if (!shut) items.forEach((n, i) => rects.set(n.id, { x: fx + 10, y: fy + 44 + i * MP_ROW, w: MP_W - 20, h: MP_ROW - 4, node: n }));
    else items.forEach((n) => rects.set(n.id, { x: fx, y: fy, w: MP_W, h: 36, node: n, inside: true }));
    if (hostNode) rects.set(hostNode.id, { x: fx, y: fy, w: MP_W, h: 36, node: hostNode, frame: true });
    out.push(frame);
    heights[col] = (pin ? y : y + frame.h + MP_GAP);
  }
  for (const [id, p] of Object.entries(MP.positions)) {       // a pinned shared node stays where it was put
    const r = rects.get(id);
    if (r && !r.node.host) { r.x = p.x; r.y = p.y; }
  }
  return { frames: out, rects };
}

function mapClass(n) {
  const cls = ['mpnode', `k-${n.kind.toLowerCase()}`];
  if (n.confidence === 'inferred') cls.push('inferred');
  if (n.confidence === 'manual') cls.push('confidence-manual');
  if (n.ghost) cls.push('ghost');
  if (n.gone) cls.push('gone');
  if (n.touched) cls.push('changed');
  if (MP.trace.has(n.id)) cls.push('trace');
  if ((MP.coverage?.coverage || []).some((c) => c.workload === n.label && c.host === n.host)) cls.push('unprotected');
  if (n.props.exposure) cls.push(`x-${n.props.exposure}`);
  if (n.props.placeholder) cls.push('placeholder');
  if ((n.props.findings || []).length) cls.push('flagged');
  return cls.join(' ');
}

function mapDraw() {
  const g = MP.graph;
  const canvas = $('#mpcanvas');
  if (!g) return;
  const unread = !g.nodes.some((n) => n.kind !== 'Host');
  if (!g.nodes.length || unread) {
    canvas.replaceChildren(text('p', g.nodes.length ? 'Nothing but hosts yet: network and workload readings come with the next scan of each host.' : 'No hosts yet.', 'muted'));
    return;
  }
  const { frames, rects } = mapLayout(g);
  MP.rects = rects;
  const root = sv('g', { id: 'mproot' });
  for (const f of frames) {
    const b = (f.node && f.node.props.security) || null;
    const t = [f.host];
    if (b) { if (b.holds) t.push(`🔒${b.holds}`); if (b.decoys) t.push(`🎯${b.decoys}`); if (b.quarantined) t.push(`⛔${b.quarantined}`); if (b.selinux) t.push(`SELinux ${b.selinux}`); }
    if (f.shut) t.push(`(${f.count} inside)`);
    const head = sv('text', { x: f.x + 12, y: f.y + 24, class: 'mphost' }); head.textContent = t.join('  ');
    root.append(sv('rect', { x: f.x, y: f.y, width: f.w, height: f.h, rx: 8, class: 'mpframe' }), head);
    const hit = sv('rect', { x: f.x, y: f.y, width: f.w, height: 36, class: 'mphit', ...(f.node ? { 'data-id': f.node.id } : {}), 'data-frame': f.host }); root.append(hit);
  }
  const edgeLayer = sv('g', { id: 'mpedges' });
  for (const e of g.edges) {
    const a = rects.get(e.src), b = rects.get(e.dst);
    if (!a || !b) continue;
    const ax = a.x + a.w / 2, ay = a.y + a.h / 2, bx = b.x + b.w / 2, by = b.y + b.h / 2;
    const my = (ay + by) / 2;
    const conf = (e.props || {}).confidence;
    if (a.inside && b.inside && a.x === b.x && a.y === b.y) continue;
    const trace = MP.trace.has(e.src) && MP.trace.has(e.dst);
    edgeLayer.append(sv('path', { d: `M${ax} ${ay} C${ax} ${my} ${bx} ${my} ${bx} ${by}`, class: `mpedge${conf === 'inferred' || conf === 'manual' ? ' inferred' : ''}${e.ghost ? ' ghost' : ''}${trace ? ' trace' : ''}`, 'data-src': e.src, 'data-dst': e.dst }));
  }
  root.append(edgeLayer);
  for (const r of rects.values()) {
    if (r.frame || r.inside) continue;
    const n = r.node;
    const label = sv('text', { x: r.x + 8, y: r.y + r.h / 2 + 4, class: 'mplabel' });
    label.textContent = mapText(n);
    const dim = !mapMatches(n);
    root.append(sv('g', { class: mapClass(n) + (dim ? ' dim' : ''), 'data-id': n.id }, sv('rect', { x: r.x, y: r.y, width: r.w, height: r.h, rx: 4 }), label));
  }
  for (const x of MP.notes) {
    const r = rects.get(x.target);
    if (r) { const t = sv('text', { x: r.x + r.w - 6, y: r.y - 2, class: 'mpnote', 'text-anchor': 'end' }); t.textContent = `✎ ${x.text.slice(0, 40)}`; root.append(t); }
  }
  const svg = sv('svg', { id: 'mpsvg', class: 'mpsvg', role: 'img', 'aria-label': 'Infrastructure map' }, root);
  canvas.replaceChildren(svg, mapLegend());
  svg.addEventListener('dblclick', (ev) => { const f = ev.target.closest('[data-frame]'); if (f) { const h = f.dataset.frame; if (MP.collapsed.has(h)) MP.collapsed.delete(h); else MP.collapsed.add(h); mapDraw(); } });
  svg.addEventListener('click', (ev) => { const t = ev.target.closest('[data-id]'); MP.sel = t ? t.dataset.id : null; mapDetail(); mapHighlight(MP.sel); });
  svg.addEventListener('mouseover', (ev) => { const t = ev.target.closest('[data-id]'); if (t) mapHighlight(t.dataset.id); });
  svg.addEventListener('mouseout', () => mapHighlight(MP.sel));
  svg.addEventListener('wheel', (ev) => { ev.preventDefault(); const f = ev.deltaY < 0 ? 1.15 : 0.87; MP.view.k = Math.min(3, Math.max(0.2, MP.view.k * f)); mapApply(); }, { passive: false });
  svg.addEventListener('pointerdown', (ev) => {
    const f = ev.target.closest('[data-frame]');
    if (f) { const fr = frames.find((x) => x.host === f.dataset.frame); MP.drag = { frame: fr.host, x: ev.clientX, y: ev.clientY, fx: fr.x, fy: fr.y, moved: false }; return; }
    if (!ev.target.closest('[data-id]')) MP.drag = { x: ev.clientX, y: ev.clientY, vx: MP.view.x, vy: MP.view.y };
  });
  svg.addEventListener('pointermove', (ev) => {
    if (!MP.drag) return;
    if (MP.drag.frame) {
      const dx = (ev.clientX - MP.drag.x) / MP.view.k, dy = (ev.clientY - MP.drag.y) / MP.view.k;
      if (Math.abs(dx) + Math.abs(dy) > 4) { MP.drag.moved = true; MP.positions[`frame:${MP.drag.frame}`] = { x: MP.drag.fx + dx, y: MP.drag.fy + dy }; }
      return;
    }
    MP.view.x = MP.drag.vx + ev.clientX - MP.drag.x; MP.view.y = MP.drag.vy + ev.clientY - MP.drag.y; mapApply();
  });
  svg.addEventListener('pointerup', () => { if (MP.drag?.moved) { MP.drag = null; mapDraw(); return; } MP.drag = null; });
  svg.addEventListener('pointerleave', () => { MP.drag = null; });
  if (MP.fitted) mapApply(); else { MP.fitted = true; mapFit(0.5); }
}

// Everything in view, but no smaller than `least`: past that, labels are gone, so it starts at the top instead.
function mapFit(least) {
  const root = $('#mproot'), svg = $('#mpsvg');
  if (!root) return;
  root.removeAttribute('transform');
  const b = root.getBBox(), w = svg.clientWidth || 800, h = svg.clientHeight || 600;
  const k = Math.max(least, Math.min(1, (w - 20) / (b.width + 1), (h - 20) / (b.height + 1)));
  MP.view = { k, x: 10 - b.x * k, y: 10 - b.y * k };
  mapApply();
}

function mapText(n) {
  const p = n.props;
  if (n.kind === 'Listener') return `${n.label} ${(p.process || []).join(',') || p.container || ''}`.slice(0, 40);
  if (['NIC', 'Bond', 'Bridge', 'VLAN', 'VPNInterface'].includes(n.kind)) return `${n.label} ${(p.addresses || []).slice(0, 1).join('')}`.slice(0, 40);
  if (['Container', 'VM', 'Instance'].includes(n.kind)) return `${n.kind === 'VM' ? 'VM ' : ''}${n.label}${p.state && p.state !== 'running' ? ` (${p.state})` : ''}`.slice(0, 40);
  if (n.kind === 'FirewallPolicy') return `Firewall: ${n.label}`.slice(0, 40);
  return n.label.slice(0, 40);
}

function mapApply() {
  const r = $('#mproot');
  if (r) {
    r.setAttribute('transform', `translate(${MP.view.x} ${MP.view.y}) scale(${MP.view.k})`);
    $('#mpsvg').classList.toggle('far', MP.view.k < 0.5);
    mapSemantic();
  }
}

function mapHighlight(id) {
  const svg = $('#mpsvg');
  if (!svg) return;
  svg.querySelectorAll('.mpedge').forEach((p) => { p.classList.toggle('on', !!id && (p.dataset.src === id || p.dataset.dst === id)); });
}

function mapLegend() {
  const l = el('div', { class: 'mplegend small' });
  for (const [k, v] of Object.entries(MP_LEVEL)) l.append(el('span', { class: `mpchip x-${k}` }, v));
  l.append(el('span', { class: 'muted' }, 'Dashed: inferred. Per configuration: nothing here was probed.'));
  return l;
}

function mapDetail() {
  const box = $('#mpdetail');
  if (!box || !MP.graph) return;
  const n = MP.graph.nodes.find((x) => x.id === MP.sel);
  if (!n) { box.replaceChildren(text('p', 'Select something to see what it is and how we know.', 'muted small')); return; }
  const rows = [text('h4', `${n.kind}: ${n.label}`)];
  rows.push(text('p', { certain: 'Read on the host.', confirmed: 'Confirmed across hosts.', inferred: 'Inferred, not confirmed.', manual: 'Placed by hand, not verified.' }[n.confidence] || '', 'muted small'));
  if (n.props.exposure) rows.push(text('p', `Who can reach it, per configuration: ${MP_LEVEL[n.props.exposure]}`, n.props.exposure === 'any' ? 'st-failed' : ''));
  if (n.props.rule) rows.push(text('p', `Decided by: ${n.props.rule}`, 'small'));
  for (const w of n.props.why || []) rows.push(text('p', w, 'st-warn small'));
  for (const f of n.props.findings || []) rows.push(text('p', f, 'st-warn small'));
  for (const [k, v] of Object.entries(n.props)) {
    if (['exposure', 'rule', 'why', 'findings', 'security'].includes(k)) continue;
    rows.push(el('div', { class: 'small' }, el('span', { class: 'muted' }, k + ': '), el('span', { class: 'mono' }, typeof v === 'object' ? JSON.stringify(v) : String(v))));
  }
  if (n.props.security) rows.push(el('div', { class: 'small' }, el('span', { class: 'muted' }, 'security: '), el('span', { class: 'mono' }, JSON.stringify(n.props.security))));
  const links = MP.graph.edges.filter((e) => e.src === n.id || e.dst === n.id);
  if (links.length) {
    rows.push(text('h4', 'Why these lines exist'));
    for (const e of links) rows.push(text('p', `${e.rel}: ${((e.props || {}).evidence || {}).source || 'from the scan'}`, 'small'));
  }
  if (n.confidence === 'manual') rows.push(el('div', { class: 'row wrap' }, text('p', 'Placed by hand. A scan will never confirm or change this.', 'muted small'), can('map.edit') ? button('Remove', async () => { await api(`/api/map/manual/${n.props.manual_id}`, { method: 'DELETE' }); loadMap(); }, 'btn small') : ''));
  if (n.props.placeholder) rows.push(el('div', { class: 'stack' }, text('p', `Not managed by StorageForge. Seen as ${n.props.seen_as || 'a neighbour'}${n.props.vendor ? `, made by ${n.props.vendor}` : ''}.`, 'muted small'),
    can('keys.manage') ? button('Promote to host', async () => { const r = await (await postJSON(`/api/map/placeholders/${encodeURIComponent(n.id)}/promote`, {})).json(); box.append(text('p', r.message, 'st-ok small')); }, 'btn small') : ''));
  const notes = MP.notes.filter((x) => x.target === n.id);
  for (const x of notes) rows.push(el('div', { class: 'row wrap small' }, text('span', `Note: ${x.text}`), can('map.edit') ? button('Remove', async () => { await api(`/api/map/annotations/${x.id}`, { method: 'DELETE' }); loadMap(); }, 'btn small') : ''));
  if (can('map.edit') && !MP.redact) {
    const t = el('input', { type: 'text', placeholder: 'Add a note', 'aria-label': 'Add a note' });
    rows.push(el('div', { class: 'row small' }, t, button('Add', async () => { await postJSON('/api/map/annotations', { target: n.id, text: t.value }); loadMap(); }, 'btn small')));
  }
  if (!MP.at && !MP.redact) rows.push(...mapActions(n));
  box.replaceChildren(...rows);
}

async function mapChanges() {
  const fresh = latest('mapchanges');
  const box = $('#mpchanges');
  try {
    const { changes } = await getJSON('/api/map/snapshots');
    if (!fresh()) return;
    const rows = [text('h4', 'What changed')];
    const real = changes.filter((c) => !c.first);
    if (changes.length) {
      const times = [...new Set(changes.map((c) => c.taken_at))].sort((a, b) => a - b);
      const slider = el('input', { type: 'range', class: 'mptime', min: '0', max: String(times.length), 'aria-label': 'Go back in time' }); slider.value = MP.at ? String(times.findIndex((t) => t >= MP.at)) : String(times.length);
      const when = text('span', MP.at ? new Date(MP.at * 1000).toLocaleString() : 'Now', 'small');
      slider.addEventListener('input', () => { when.textContent = Number(slider.value) >= times.length ? 'Now' : new Date(times[Number(slider.value)] * 1000).toLocaleString(); });
      slider.addEventListener('change', () => { MP.at = Number(slider.value) >= times.length ? null : times[Number(slider.value)]; MP.fitted = true; loadMap(); });
      rows.push(el('div', { class: 'stack small' }, text('span', 'Go back to an earlier reading. Storage is not kept: this shows the other layers as they stood.', 'muted'), slider, when));
    }
    if (!real.length) rows.push(text('p', 'Nothing since the first reading.', 'muted small'));
    for (const c of real.slice(0, MP.open.changes ? real.length : MP_SHOWN.changes)) {
      const short = (ids) => ids.map((i) => (MP.redact ? '…' : i.split(':').slice(2).join(':') || i)).join(', ');
      rows.push(text('p', `${MP.redact ? 'a host' : c.host}, ${new Date(c.taken_at * 1000).toLocaleString()}: ${[c.added.length ? `new ${short(c.added)}` : '', c.removed.length ? `gone ${short(c.removed)}` : '', c.changed.length ? `changed ${short(c.changed)}` : ''].filter(Boolean).join('; ')}`, 'small'));
    }
    rows.push(...mapMore('changes', real.length, MP_SHOWN.changes, mapChanges));
    box.replaceChildren(...rows);
  } catch { box.replaceChildren(); }
}

async function mapViews() {
  const box = $('#mpviews');
  if (!box) return;
  try {
    const { views } = await getJSON('/api/map/views');
    const rows = [text('h4', 'Saved views')];
    for (const v of views) {
      rows.push(el('div', { class: 'row small' }, button(v.name, () => {
        MP.layers = new Set(v.body.layers || []); MP.filter = v.body.filter || ''; MP.positions = v.body.positions || {}; MP.mode = v.body.mode || 'custom'; MP.group = v.body.group || 'host';
        const f = $('#mpfilter'); if (f) f.value = MP.filter;
        $('#mapview').replaceChildren(); loadMap();
      }, 'btn small'), can('map.edit') && v.mine ? button('Remove', async () => { await api(`/api/map/views/${v.id}`, { method: 'DELETE' }); mapViews(); }, 'btn small') : document.createTextNode('')));
    }
    if (can('map.edit')) {
      const name = el('input', { type: 'text', placeholder: 'Name this view', 'aria-label': 'View name' });
      const shared = el('input', { type: 'checkbox' }), said = el('span', { class: 'small st-failed' });
      rows.push(el('div', { class: 'row small' }, name, el('label', { class: 'small' }, shared, ' Share with everyone'), button('Save', async () => {
        try {
          await postJSON('/api/map/views', { name: name.value, layers: [...MP.layers], filter: MP.filter, positions: MP.positions, mode: MP.mode, group: MP.group, shared: shared.checked });
          mapViews();
        } catch (err) { said.textContent = err.message; }
      }, 'btn small'), said));
    }
    box.replaceChildren(...rows);
  } catch { box.replaceChildren(); }
}

function mapSaveSvg() {
  const svg = $('#mpsvg');
  if (!svg) return;
  const copy = svg.cloneNode(true);
  copy.setAttribute('xmlns', SVGNS);
  const box = svg.getBBox();
  copy.setAttribute('viewBox', `${box.x - 10} ${box.y - 10} ${box.width + 20} ${box.height + 20}`);
  const url = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(copy)], { type: 'image/svg+xml' }));
  const a = el('a', { href: url, download: 'storageforge-map.svg' });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function mapSubnet(cidr) {
  const [ip, len] = cidr.split('/');
  if (ip.includes(':')) return cidr;
  const n = ip.split('.').map(Number), bits = Number(len) || 32;
  const v = n.reduce((a, b) => (a * 256) + b, 0), mask = bits ? Math.floor(v / 2 ** (32 - bits)) * 2 ** (32 - bits) : 0;
  return `${[24, 16, 8, 0].map((s) => Math.floor(mask / 2 ** s) % 256).join('.')}/${bits}`;
}

// Past a certain distance a frame's rows are noise, and a thousand of them are slow. Frames stay, rows go.
function mapSemantic() {
  const svg = $('#mpsvg');
  if (!svg) return;
  const far = MP.view.k < 0.3;
  if (svg.dataset.far === String(far)) return;
  svg.dataset.far = String(far);
  svg.querySelectorAll('.mpnode').forEach((g) => { g.style.display = far && !g.classList.contains('trace') ? 'none' : ''; });
  svg.querySelectorAll('.mpedge').forEach((p) => { p.style.display = far && !p.classList.contains('trace') ? 'none' : ''; });
}

function mapSavePng() {
  const svg = $('#mpsvg');
  if (!svg) return;
  const copy = svg.cloneNode(true), box = svg.getBBox(), scale = 2;
  copy.setAttribute('xmlns', SVGNS);
  copy.setAttribute('viewBox', `${box.x - 10} ${box.y - 10} ${box.width + 20} ${box.height + 20}`);
  copy.setAttribute('width', box.width + 20); copy.setAttribute('height', box.height + 20);
  copy.querySelector('#mproot').removeAttribute('transform');
  const style = document.createElementNS(SVGNS, 'style');
  style.textContent = '.mpframe{fill:#f4f5f7;stroke:#99a}.mpnode rect{fill:#fff;stroke:#556}.mpedge{fill:none;stroke:#889}.mplabel,.mphost{font:11px sans-serif;fill:#123}.mpnode.x-any rect{fill:#f3c6c6}.mpnode.x-lan rect{fill:#f3e2c6}.mpnode.inferred rect{stroke-dasharray:4 3}.mphit{fill:transparent}';
  copy.prepend(style);
  const img = new Image();
  img.onload = () => {
    const c = el('canvas', {}); c.width = (box.width + 20) * scale; c.height = (box.height + 20) * scale;
    const x = c.getContext('2d'); x.fillStyle = '#fff'; x.fillRect(0, 0, c.width, c.height); x.scale(scale, scale); x.drawImage(img, 0, 0);
    c.toBlob((b) => { const a = el('a', { href: URL.createObjectURL(b), download: 'storageforge-map.png' }); a.click(); });
  };
  img.onerror = () => { $('#mpdetail').prepend(text('p', 'This browser would not draw the map as an image. The SVG export has the same picture.', 'st-failed small')); };
  // a data: address, because the page's CSP allows those for images, and not blob:
  img.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(new XMLSerializer().serializeToString(copy))}`;
}

/* ── can A reach B? ───────────────────────────────────────────────── */
function mapReachPanel() {
  const box = $('#mpreach');
  if (!box || !can('security.view')) return;
  const from = el('input', { type: 'text', placeholder: 'From: a host or address', 'aria-label': 'From' }), to = el('input', { type: 'text', placeholder: 'To: a host, address or container', 'aria-label': 'To' }), port = el('input', { type: 'text', placeholder: 'Port', 'aria-label': 'Port' });
  const proto = el('select', { 'aria-label': 'Protocol' }, new Option('tcp', 'tcp'), new Option('udp', 'udp')), out = el('div', { class: 'stack small' });
  box.append(text('h4', 'Can A reach B?'), el('div', { class: 'mpform' }, from, to, el('div', { class: 'row' }, port, proto), button('Work it out', async () => {
    try {
      const r = await getJSON('/api/map/reach?' + new URLSearchParams({ from: from.value.trim(), to: to.value.trim(), port: port.value.trim(), proto: proto.value }));
      MP.trace = new Set([`host:${r.from_host}`, `host:${r.to_host}`]);
      mapDraw();
      out.replaceChildren(text('p', { allowed: 'Allowed', blocked: 'Blocked', unknown: 'Not known' }[r.verdict], r.verdict === 'blocked' ? 'st-failed' : r.verdict === 'allowed' ? 'st-ok' : 'st-warn'),
        r.decided_by ? text('p', `Decided by: ${r.decided_by}`) : '', ...r.hops.map((h) => text('p', `${h.at}: ${h.what}${h.rule ? ` (${h.rule})` : ''}`, 'muted')), ...r.blind_spots.map((b) => text('p', `Out of sight: ${b}`, 'st-warn')), text('p', r.caveat, 'muted'));
    } catch (err) { out.replaceChildren(text('p', err.message, 'st-failed')); }
  }, 'btn small')), out);
}

/* ── staging from the map, and what it would do ───────────────────── */
MP.draft = [];

function mapActions(n) {
  const host = n.host || (n.kind === 'Host' ? n.label : null);
  if (!host || n.ghost || !can('plans.edit')) return [];
  const say = (label, type, params) => button(label, () => { MP.draft.push({ type, host, params }); mapWhatIf(); }, 'btn small');
  const acts = [];
  if (n.kind === 'Listener') {
    const [port, proto] = n.label.split('/');
    acts.push(say('Block it from everyone', 'fw-rule', { action: 'deny', proto, port, hook: n.props.container ? 'forward' : 'input', rollback: port === '22' ? '10' : '' }));
    const src = el('input', { type: 'text', placeholder: '10.0.20.0/24', 'aria-label': 'Allow from' });
    acts.push(el('div', { class: 'row small' }, src, button('Allow only from', () => { MP.draft.push({ type: 'fw-rule', host, params: { action: 'allow', proto, port, source: src.value.trim(), hook: n.props.container ? 'forward' : 'input' } }, { type: 'fw-rule', host, params: { action: 'deny', proto, port, hook: n.props.container ? 'forward' : 'input' } }); mapWhatIf(); }, 'btn small')));
  }
  if (['NIC', 'Bridge', 'Bond'].includes(n.kind)) {
    const mtu = el('input', { type: 'text', placeholder: '9000', 'aria-label': 'MTU' }), vid = el('input', { type: 'text', placeholder: 'VLAN id', 'aria-label': 'VLAN id' });
    acts.push(el('div', { class: 'row small' }, mtu, button('Set MTU', () => { MP.draft.push({ type: 'net-mtu', host, params: { iface: n.label, mtu: mtu.value.trim(), rollback: '10' } }); mapWhatIf(); }, 'btn small')), el('div', { class: 'row small' }, vid, button('Add a VLAN', () => { MP.draft.push({ type: 'net-vlan', host, params: { parent: n.label, vlan_id: vid.value.trim() } }); mapWhatIf(); }, 'btn small')));
  }
  if (['Container', 'VM', 'Instance'].includes(n.kind) && n.props.runtime && n.props.runtime !== 'proxmox') {
    for (const a of ['start', 'stop', 'restart', 'snapshot']) acts.push(say(a[0].toUpperCase() + a.slice(1), 'workload-action', { runtime: n.props.runtime, name: n.label, action: a }));
    acts.push(say('Remove (keeps its data)', 'workload-remove', { runtime: n.props.runtime, name: n.label }));
  }
  if (n.kind === 'VPNNetwork') {
    const key = el('input', { type: 'text', placeholder: 'public key', 'aria-label': 'Peer key' }), ips = el('input', { type: 'text', placeholder: '10.8.0.2/32', 'aria-label': 'Allowed' });
    acts.push(el('div', { class: 'mpform small' }, key, ips, button('Add a peer', () => { MP.draft.push({ type: 'wg-peer', host, params: { iface: n.label, pubkey: key.value.trim(), allowed: ips.value.trim() } }); mapWhatIf(); }, 'btn small')));
  }
  if (n.kind === 'Peer' && n.props.public_key) {
    const iface = n.id.split(':')[2];
    acts.push(say('Revoke this peer', 'wg-peer', { iface, pubkey: n.props.public_key, allowed: (n.props.allowed_ips || []).join(',') || '0.0.0.0/32', state: 'absent' }));
  }
  if (n.kind === 'Host') {
    const name = el('input', { type: 'text', placeholder: 'name', 'aria-label': 'Container name' }), image = el('input', { type: 'text', placeholder: 'image:tag', 'aria-label': 'Image' }), pub = el('input', { type: 'text', placeholder: '127.0.0.1:8080:80', 'aria-label': 'Publish' });
    const br = el('input', { type: 'text', placeholder: 'br0', 'aria-label': 'Bridge' }), cidr = el('input', { type: 'text', placeholder: '10.0.5.1/24', 'aria-label': 'Address' });
    acts.push(el('div', { class: 'mpform small' }, name, image, pub, button('Run a container here', () => { MP.draft.push({ type: 'container', host, params: { runtime: n.props.runtimes?.[0] || 'docker', name: name.value.trim(), image: image.value.trim(), publish: pub.value.trim() } }); mapWhatIf(); }, 'btn small')),
      el('div', { class: 'mpform small' }, br, cidr, button('Create a bridge', () => { MP.draft.push({ type: 'net-bridge', host, params: { name: br.value.trim(), address: cidr.value.trim() } }); mapWhatIf(); }, 'btn small')));
  }
  if (n.kind === 'FirewallPolicy') {
    const port = el('input', { type: 'text', placeholder: 'port', 'aria-label': 'Port' }), src = el('input', { type: 'text', placeholder: 'from', 'aria-label': 'From' });
    acts.push(el('div', { class: 'mpform small' }, port, src, el('div', { class: 'row' }, button('Allow', () => { MP.draft.push({ type: 'fw-rule', host, params: { action: 'allow', proto: 'tcp', port: port.value.trim(), source: src.value.trim() } }); mapWhatIf(); }, 'btn small'), button('Deny', () => { MP.draft.push({ type: 'fw-rule', host, params: { action: 'deny', proto: 'tcp', port: port.value.trim(), source: src.value.trim() } }); mapWhatIf(); }, 'btn small'))));
  }
  return acts.length ? [text('h4', 'Stage a step'), ...acts] : [];
}

function mapWhatIfPanel() { mapWhatIf(); }

function mapGhostApply() {
  const g = MP.graph, res = MP.ghost;
  if (!g) return;
  g.nodes = g.nodes.filter((n) => !n.ghost).map((n) => { delete n.gone; delete n.touched; return n; });
  g.edges = g.edges.filter((e) => !e.ghost);
  if (!res) return;
  for (const n of res.ghost.add) g.nodes.push({ ...n, ghost: true, layer: 'staged', confidence: 'certain' });
  for (const e of res.ghost.edges) g.edges.push({ ...e, ghost: true, props: {} });
  for (const r of res.ghost.remove) { const n = g.nodes.find((x) => x.id === r.id); if (n) n.gone = true; }
  for (const c of res.ghost.changed) { const n = g.nodes.find((x) => x.id === c.id); if (n) n.touched = true; }
}

async function mapWhatIf() {
  const box = $('#mpwhatif');
  if (!box) return;
  if (!MP.draft.length) { MP.ghost = null; box.replaceChildren(); mapGhostApply(); if ($('#mpsvg')) mapDraw(); return; }
  try {
    const res = await (await postJSON('/api/map/whatif', { tasks: MP.draft })).json();
    MP.ghost = res;
    mapGhostApply();
    mapDraw();
    const plan = el('input', { type: 'text', 'aria-label': 'Plan name', placeholder: 'From the map' });
    box.replaceChildren(text('h4', 'What this would do'), ...MP.draft.map((t, i) => el('div', { class: 'row small' }, text('span', `${t.host}: ${t.type}`), button('✕', () => { MP.draft.splice(i, 1); mapWhatIf(); }, 'btn small'))),
      ...res.conflicts.map((c) => text('p', c.text, c.level === 'crit' ? 'st-failed small' : 'st-warn small')),
      ...res.exposure.flatMap((h) => h.changes.map((c) => text('p', `${h.host} ${c.port}/${c.proto}: ${MP_LEVEL[c.before] || 'nothing'} to ${MP_LEVEL[c.after] || 'nothing'}${c.rule ? `, by ${c.rule}` : ''}`, c.wider ? 'st-warn small' : 'small'))),
      ...res.not_modelled.map((b) => text('p', `Not shown: ${b}`, 'muted small')), text('p', res.caveat, 'muted small'),
      el('div', { class: 'row small' }, plan, button('Stage in Changes', async () => {
        const r = await (await postJSON('/api/map/stage', { plan: plan.value.trim() || 'From the map', tasks: MP.draft })).json();
        MP.draft = []; mapWhatIf();
        box.replaceChildren(text('p', `In plan #${r.plan_id}: ${r.tasks} step(s). The Report on the host comes next, in Changes.`, 'st-ok small'), button('Open Changes', () => { showTab('changes'); }, 'btn small'));
      }, res.blocked ? 'btn small danger' : 'btn small pri'), button('Forget it', () => { MP.draft = []; mapWhatIf(); }, 'btn small')));
  } catch (err) {
    box.replaceChildren(text('p', err.body?.error || err.message, 'st-failed small'), button('Forget it', () => { MP.draft = []; mapWhatIf(); }, 'btn small'));
  }
}

/* ── placed by hand ───────────────────────────────────────────────── */
function mapManualPanel() {
  const box = $('#mpmanual');
  if (!box || !can('map.edit')) return;
  const kind = el('select', { 'aria-label': 'Kind' }, ...['Switch', 'Router', 'Modem', 'AccessPoint', 'Firewall', 'IoT', 'Server', 'Other'].map((k) => new Option(k, k))), label = el('input', { type: 'text', placeholder: 'Label', 'aria-label': 'Label' }), to = el('input', { type: 'text', placeholder: 'Links to: host:nas-01', 'aria-label': 'Links to' }), url = el('input', { type: 'text', placeholder: 'https://… (optional)', 'aria-label': 'Link' }), out = el('div', {});
  box.append(text('h4', 'Place something by hand'), text('p', 'Gear StorageForge has no access to. It stays marked as placed by hand.', 'muted small'), el('div', { class: 'mpform' }, kind, label, url, to, button('Place it', async () => {
    try { await postJSON('/api/map/manual', { kind: kind.value, label: label.value.trim(), url: url.value.trim(), links: to.value.trim() ? [{ to: to.value.trim() }] : [] }); label.value = ''; loadMap(); } catch (err) { out.replaceChildren(text('p', err.body?.error || err.message, 'st-failed small')); }
  }, 'btn small')), out);
}

/* ── design mode ──────────────────────────────────────────────────── */
async function mapDesignsPanel() {
  const box = $('#mpdesigns');
  if (!box) return;
  try {
    const { designs } = await getJSON('/api/map/designs');
    const name = el('input', { type: 'text', placeholder: 'Name', 'aria-label': 'Design name' }), doc = el('textarea', { rows: '6', class: 'mono small', spellcheck: 'false', 'aria-label': 'Design', placeholder: '{"hosts": [{"name": "nas-01", "networks": [], "workloads": [], "firewall": []}]}' }), out = el('div', { class: 'stack small' });
    const rows = designs.map((d) => el('div', { class: 'stack small' }, text('b', d.name), el('div', { class: 'row wrap' },
      button('Edit', async () => { const f = await getJSON(`/api/map/designs/${d.id}`); name.value = f.name; doc.value = JSON.stringify(f.doc, null, 1); }, 'btn small'),
      button('Compare', async () => {
        const c = await getJSON(`/api/map/designs/${d.id}/compare`);
        const row = (x, f) => text('p', `${x.host}: ${x.kind} ${x.what}${f ? f(x) : ''}`, 'muted small');
        const line = (head, items, f) => {         // the heading counts them all, so the cut says so and the button shows the rest (UX-13)
          if (!items.length) return [];
          const rest = items.slice(MP_SHOWN.compare);
          const more = rest.length ? [button(`+${rest.length} more`, (ev) => { const rows = rest.map((x) => row(x, f)); rows[0].tabIndex = -1; ev.currentTarget.replaceWith(...rows); rows[0].focus(); }, 'btn small')] : [];
          return [text('p', `${head}: ${items.length}`, 'small'), ...items.slice(0, MP_SHOWN.compare).map((x) => row(x, f)), ...more];
        };
        out.replaceChildren(text('h4', `${d.name} against what was read`), ...line('Missing', c.missing), ...line('Different', c.different, (x) => `: wanted ${x.want}, is ${x.have}`), ...line('Not in the design', c.extra), ...line('Not read, so not known', c.unknown, (x) => `: ${x.why}`), text('p', `In place: ${c.there.length}`, 'st-ok small'),
          can('plans.edit') && c.missing.length ? button('Stage what is missing', async () => { const r = await (await postJSON(`/api/map/designs/${d.id}/stage`, {})).json(); out.append(text('p', `In plan #${r.plan_id}: ${r.tasks} step(s).`, 'st-ok small')); }, 'btn small pri') : '');
      }, 'btn small'),
      ...['bash', 'ansible', 'terraform', 'puppet'].map((t) => el('a', { class: 'btn small', href: `/api/map/designs/${d.id}/export?target=${t}` }, t)),
      can('plans.edit') ? button('Remove', async () => { await api(`/api/map/designs/${d.id}`, { method: 'DELETE' }); mapDesignsPanel(); }, 'btn small') : '')));
    box.replaceChildren(text('h4', 'Designs'), text('p', 'What should be there, compared with what scans found. Exports go one way: nothing is read back from a script.', 'muted small'), ...rows,
      can('plans.edit') ? el('div', { class: 'mpform' }, name, doc, button('Save design', async () => { try { await postJSON('/api/map/designs', { name: name.value.trim(), doc: JSON.parse(doc.value) }); mapDesignsPanel(); } catch (err) { out.replaceChildren(text('p', err.body?.error || err.message, 'st-failed small')); } }, 'btn small')) : '', out);
  } catch { box.replaceChildren(); }
}

/* ── what security adds to the map ────────────────────────────────── */
function mapCoverage() {
  const box = $('#mpcover');
  if (!box) return;
  const c = MP.coverage;
  if (!c || (!c.coverage.length && !c.warnings.length)) { box.replaceChildren(); return; }
  const cov = c.coverage.slice(0, MP.open.cover ? c.coverage.length : MP_SHOWN.cover);
  const warn = c.warnings.slice(0, MP.open.warn ? c.warnings.length : MP_SHOWN.warn);
  box.replaceChildren(text('h4', 'Not covered'), ...cov.map((x) => text('p', `${x.host}: ${x.workload} on ${x.mount}: ${x.hold ? '' : 'no hold'}${!x.hold && !x.decoy ? ', ' : ''}${x.decoy ? '' : 'no decoy'}`, 'st-warn small')),
    ...mapMore('cover', c.coverage.length, MP_SHOWN.cover, mapCoverage),
    ...warn.map((w) => text('p', `An armed sentinel could cut off ${w.address}, ${w.why.join(', ')}. Put it on the exempt list.`, 'st-failed small')),
    ...mapMore('warn', c.warnings.length, MP_SHOWN.warn, mapCoverage));
}

/* deep links: /#view=map&layers=network,firewall&host=gw-01&from=a&to=b&port=445 */
function mapTakeLink(q) {
  if (q.get('layers')) MP.layers = new Set(q.get('layers').split(','));
  if (MP_MODES[q.get('mode')]) mapSetMode(q.get('mode'));
  if (q.get('filter')) MP.filter = q.get('filter');
}
