'use strict';
/* StorageForge graph UI (the column topology view is topology.js): force-directed canvas (charge, springs, collision, gravity),
   2-hop drill-down focus, 3-2-1 health colouring, file search and .canvas export.
   No third-party code, so it runs offline under a strict 'self' CSP. */

const $ = (s) => document.querySelector(s);
const KINDS = ['Host', 'StoragePool', 'Filesystem', 'MountPoint', 'Symlink'];
const RADIUS = { Host: 22, StoragePool: 16, Filesystem: 11, MountPoint: 9, Symlink: 8 };
const DIST = { CONTAINS: 70, MOUNTED_AT: 55, SYMLINK_TO: 75, REPLICATES_TO: 190 };
const HEALTH_TEXT = { protected: 'Protected', 'local-only': 'Local-only', broken: 'Broken / offline', unknown: 'No protection data' };

let COL = {};
function readColors() {
  const cs = getComputedStyle(document.documentElement);
  const v = (n) => cs.getPropertyValue(n).trim();
  COL = { protected: v('--protected'), 'local-only': v('--local-only'), broken: v('--broken'), unknown: v('--unknown'),
          fg: v('--fg'), muted: v('--muted'), line: v('--line-2'), accent: v('--accent'), fast: v('--fast'),
          bg: v('--bg'), panel: v('--panel') };
}
readColors();
matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => { readColors(); wake(); });
document.addEventListener('sf:prefs', () => { readColors(); wake(); });          // Preferences changed the theme (kernel.js)

/* api(), getJSON() and postJSON() are the kernel's (kernel.js), and so are the dialogs and the toast. */

/* ── state ───────────────────────────────────────────────────────── */
const S = { nodes: [], edges: [], byId: new Map(), adj: new Map(), visible: null, focus: null, selected: null,
            hover: null, host: '', hops: 2 };
const view = { x: 0, y: 0, k: 1 };
let alpha = 0;
let raf = 0;

const canvas = $('#graph');
const ctx = canvas.getContext('2d');
let W = 0, H = 0, DPR = 1;
let fitted = false, cold = false;
function resize() {
  const r = canvas.getBoundingClientRect();
  DPR = window.devicePixelRatio || 1;
  W = r.width; H = r.height;
  const cw = Math.round(W * DPR), ch = Math.round(H * DPR);
  if (canvas.width !== cw || canvas.height !== ch) { canvas.width = cw; canvas.height = ch; }   // resizing clears it
  if (!fitted && W && S.nodes.length) { fitted = true; fit(); }
  wake();
}
new ResizeObserver(resize).observe(canvas);

const active = (n) => !S.visible || S.visible.has(n.id);
const activeNodes = () => S.nodes.filter(active);
const activeEdges = () => S.edges.filter((e) => active(e.s) && active(e.t));

async function loadGraph() {
  const g = await getJSON('/api/graph' + (S.host ? `?host=${encodeURIComponent(S.host)}` : ''));
  const old = S.byId;
  S.byId = new Map(); S.adj = new Map();
  S.nodes = g.nodes.map((n, i) => {
    const o = old.get(n.id);
    const ring = 60 + KINDS.indexOf(n.kind) * 90;
    const a = i * 2.39996;
    Object.assign(n, o && isFinite(o.x) && isFinite(o.y) ? { x: o.x, y: o.y } : { x: Math.cos(a) * ring, y: Math.sin(a) * ring }, { vx: 0, vy: 0, r: RADIUS[n.kind] || 9 });
    n.deg = 0;
    S.byId.set(n.id, n); S.adj.set(n.id, []);
    return n;
  });
  S.edges = g.edges.filter((e) => S.byId.has(e.src) && S.byId.has(e.dst)).map((e) => {
    e.s = S.byId.get(e.src); e.t = S.byId.get(e.dst);
    S.adj.get(e.src).push({ e, other: e.t, out: true });
    S.adj.get(e.dst).push({ e, other: e.s, out: false });
    e.s.deg++; e.t.deg++;
    return e;
  });
  $('#empty').hidden = S.nodes.length > 0 || T.mode !== 'graph';
  if (S.focus && !S.byId.has(S.focus)) S.focus = null;
  if (S.selected && !S.byId.has(S.selected)) S.selected = null;
  applyFocus(false);
  if (!old.size) cold = true;                         // laid out when it is first shown: other views never pay for it
  alpha = Math.max(alpha, old.size ? 0.4 : 0.15);
  wake();
  renderSummary();
  if (T.mode === 'topo' && T.order.length) renderTopoSoon();   // refresh the health dots
}

/* ── physics ─────────────────────────────────────────────────────── */
function eachNear(ns, cell, visit) {                  // every pair closer than cell, from a grid instead of all n² pairs
  const grid = new Map();
  for (const a of ns) {
    const k = Math.floor(a.x / cell) * 65536 + Math.floor(a.y / cell);
    const c = grid.get(k);
    if (c) c.push(a); else grid.set(k, [a]);
  }
  for (const [k, c] of grid) {
    for (let i = 0; i < c.length; i++) for (let j = i + 1; j < c.length; j++) visit(c[i], c[j]);
    for (const step of [1, 65535, 65536, 65537]) {    // half the neighbours, so each pair of cells is seen once
      const o = grid.get(k + step);
      if (o) for (const a of c) for (const b of o) visit(a, b);
    }
  }
}
function repel(a, b) {                                // inverse-square, out to 600
  let dx = b.x - a.x, dy = b.y - a.y, d2 = dx * dx + dy * dy;
  if (d2 > 360000) return;
  if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
  const f = (-700 * alpha) / d2;
  a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
}
function charge(ns) {                                 // node by node next door; further away a cell of nodes acts as one
  const CELL = 150, grid = new Map();
  for (const a of ns) {
    const gx = Math.floor(a.x / CELL), gy = Math.floor(a.y / CELL), k = gx * 65536 + gy;
    let c = grid.get(k);
    if (!c) { c = { gx, gy, x: 0, y: 0, fx: 0, fy: 0, nodes: [] }; grid.set(k, c); }
    c.x += a.x; c.y += a.y; c.nodes.push(a);
  }
  const cells = [...grid.values()];
  for (const c of cells) { c.x /= c.nodes.length; c.y /= c.nodes.length; }
  for (let i = 0; i < cells.length; i++) {
    const c = cells[i];
    for (let p = 0; p < c.nodes.length; p++) for (let q = p + 1; q < c.nodes.length; q++) repel(c.nodes[p], c.nodes[q]);
    for (let j = i + 1; j < cells.length; j++) {
      const o = cells[j];
      if (Math.abs(c.gx - o.gx) <= 1 && Math.abs(c.gy - o.gy) <= 1) {
        for (const a of c.nodes) for (const b of o.nodes) repel(a, b);
        continue;
      }
      const dx = o.x - c.x, dy = o.y - c.y, d2 = dx * dx + dy * dy;
      if (d2 > 360000) continue;
      const f = (-700 * alpha) / d2;
      c.fx += dx * f * o.nodes.length; c.fy += dy * f * o.nodes.length;
      o.fx -= dx * f * c.nodes.length; o.fy -= dy * f * c.nodes.length;
    }
    for (const a of c.nodes) { a.vx += c.fx; a.vy += c.fy; }
  }
}
function tick() {
  const ns = activeNodes();
  charge(ns);
  // springs, scaled like d3-force: a hub with hundreds of links (a mount full of symlinks) would otherwise get
  // hundreds of full-strength pulls per tick, overshoot further every tick and fling the layout to infinity
  for (const e of activeEdges()) {
    const s = e.s, t = e.t, ds = e.s.deg || 1, dt = e.t.deg || 1;
    const dx = t.x - s.x, dy = t.y - s.y, d = Math.hypot(dx, dy) || 1;
    const k = ((d - (DIST[e.rel] + s.r + t.r)) / d) * 0.5 * alpha / Math.min(ds, dt);
    const bias = ds / (ds + dt);                      // the better-connected end moves less
    s.vx += dx * k * (1 - bias); s.vy += dy * k * (1 - bias); t.vx -= dx * k * bias; t.vy -= dy * k * bias;
  }
  for (const a of ns) {                               // gravity + integrate
    a.vx -= a.x * 0.004 * alpha; a.vy -= a.y * 0.004 * alpha;
    if (a.fixed) { a.vx = a.vy = 0; continue; }
    a.vx *= 0.62; a.vy *= 0.62;
    const sp = Math.hypot(a.vx, a.vy);
    if (!(sp <= 60)) { const f = sp > 0 && isFinite(sp) ? 60 / sp : 0; a.vx *= f; a.vy *= f; }   // speed cap, NaN guard
    a.x += a.vx; a.y += a.vy;
  }
  for (let pass = 0; pass < 2; pass++) {              // collision
    eachNear(ns, 2 * RADIUS.Host + 8, (a, b) => {
      const min = a.r + b.r + 8;
      const dx = b.x - a.x, dy = b.y - a.y, d2 = dx * dx + dy * dy;
      if (d2 >= min * min) return;
      const d = Math.sqrt(d2) || 0.01, push = (min - d) / d / 2;
      if (!a.fixed) { a.x -= dx * push; a.y -= dy * push; }
      if (!b.fixed) { b.x += dx * push; b.y += dy * push; }
    });
  }
  alpha = Math.max(0, alpha * 0.985 - 0.0005);
}
function warmUp() {
  alpha = 1;
  const until = performance.now() + 150;              // whatever fits before the first frame; the rest settles on screen
  for (let i = 0; i < 300 && performance.now() < until; i++) tick();
}
function wake() { if (!raf) raf = requestAnimationFrame(frame); }
function frame() {
  raf = 0;
  if (canvas.hidden) return;                          // topology view: resize() wakes it again
  if (cold && W) { cold = false; warmUp(); fitted = true; fit(); }
  if (alpha > 0.002) tick();
  draw();
  if (alpha > 0.002 || drag) wake();
}

/* ── drawing ─────────────────────────────────────────────────────── */
function shape(n) {
  const r = n.r;
  ctx.beginPath();
  switch (n.kind) {
    case 'Host': ctx.roundRect(n.x - r, n.y - r, r * 2, r * 2, 6); break;
    case 'StoragePool':
      for (let i = 0; i < 6; i++) { const a = Math.PI / 3 * i; ctx[i ? 'lineTo' : 'moveTo'](n.x + r * Math.cos(a), n.y + r * Math.sin(a)); }
      ctx.closePath(); break;
    case 'Symlink': ctx.moveTo(n.x, n.y - r * 1.2); ctx.lineTo(n.x + r * 1.2, n.y); ctx.lineTo(n.x, n.y + r * 1.2); ctx.lineTo(n.x - r * 1.2, n.y); ctx.closePath(); break;
    default: ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
  }
}
function neighbourhood(id) {
  if (!id) return null;
  const s = new Set([id]);
  for (const { other } of S.adj.get(id) || []) s.add(other.id);
  return s;
}
function draw() {
  ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  ctx.fillStyle = COL.bg; ctx.fillRect(0, 0, W, H);
  ctx.translate(W / 2 + view.x, H / 2 + view.y);
  ctx.scale(view.k, view.k);
  const near = neighbourhood(S.hover || S.selected);
  const batches = new Map();                          // one stroke per look: a canvas state change per edge is what costs
  for (const e of activeEdges()) {
    const lit = !near || (near.has(e.src) && near.has(e.dst) && (e.src === (S.hover || S.selected) || e.dst === (S.hover || S.selected)));
    const stroke = e.rel === 'MOUNTED_AT' ? (e.props.bind ? COL.fast : COL.accent)
      : e.rel === 'SYMLINK_TO' ? COL.fast
      : e.rel === 'REPLICATES_TO' ? (COL[e.props.health] || COL.muted) : COL.line;
    const look = `${lit}|${e.rel === 'REPLICATES_TO'}|${e.rel === 'SYMLINK_TO'}|${stroke}`;
    const b = batches.get(look);
    if (b) b.edges.push(e); else batches.set(look, { lit, rel: e.rel, stroke, edges: [e] });
  }
  for (const { lit, rel, stroke, edges } of batches.values()) {
    ctx.globalAlpha = lit ? 0.9 : 0.15;
    ctx.lineWidth = (rel === 'REPLICATES_TO' ? 2 : 1.3) / Math.sqrt(view.k);
    ctx.setLineDash(rel === 'SYMLINK_TO' || rel === 'REPLICATES_TO' ? [6, 4] : []);
    ctx.strokeStyle = stroke;
    ctx.beginPath();
    for (const e of edges) { ctx.moveTo(e.s.x, e.s.y); ctx.lineTo(e.t.x, e.t.y); }
    ctx.stroke();
    if (rel === 'REPLICATES_TO' || rel === 'SYMLINK_TO') { ctx.setLineDash([]); ctx.fillStyle = stroke; ctx.beginPath(); for (const e of edges) arrow(e); ctx.fill(); }
  }
  ctx.setLineDash([]);
  const ns = activeNodes();
  for (const n of ns) {
    ctx.globalAlpha = !near || near.has(n.id) ? 1 : 0.25;
    shape(n);
    ctx.fillStyle = COL[n.health] || COL.unknown;
    ctx.fill();
    ctx.lineWidth = n.kind === 'MountPoint' ? 3 : 1.5;
    ctx.strokeStyle = n.kind === 'MountPoint' ? COL.panel : COL.bg;
    ctx.stroke();
    if (n.props.external) { ctx.setLineDash([3, 3]); ctx.strokeStyle = COL.muted; ctx.lineWidth = 1.5; shape(n); ctx.stroke(); ctx.setLineDash([]); }
    if (n.id === S.selected || n.id === S.focus) {
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 6, 0, Math.PI * 2);
      ctx.strokeStyle = COL.accent; ctx.lineWidth = 2.5 / view.k; ctx.stroke();
    }
  }
  ctx.globalAlpha = 1;
  ctx.font = `${11 / Math.min(view.k, 1.4)}px ui-monospace, Menlo, Consolas, monospace`;
  ctx.textAlign = 'center'; ctx.textBaseline = 'top';
  const few = ns.length <= 60;
  for (const n of ns) {
    const show = n.kind === 'Host' || n.kind === 'StoragePool' || view.k > 1.15 || few || (near && near.has(n.id));
    if (!show) continue;
    const label = n.label.length > 34 ? '…' + n.label.slice(-33) : n.label;
    ctx.globalAlpha = !near || near.has(n.id) ? 1 : 0.3;
    ctx.lineWidth = 3 / view.k; ctx.strokeStyle = COL.bg; ctx.strokeText(label, n.x, n.y + n.r * 1.25 + 4);
    ctx.fillStyle = n.kind === 'Host' ? COL.fg : COL.muted; ctx.fillText(label, n.x, n.y + n.r * 1.25 + 4);
  }
  ctx.globalAlpha = 1;
}
function arrow(e) {
  const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y, d = Math.hypot(dx, dy) || 1;
  const ux = dx / d, uy = dy / d, tip = e.t.r + 4;
  const x = e.t.x - ux * tip, y = e.t.y - uy * tip, s = 7 / Math.sqrt(view.k);
  ctx.moveTo(x, y);
  ctx.lineTo(x - ux * s - uy * s * 0.6, y - uy * s + ux * s * 0.6);
  ctx.lineTo(x - ux * s + uy * s * 0.6, y - uy * s - ux * s * 0.6);
  ctx.closePath();
}
function fit() {
  const ns = activeNodes();
  if (!ns.length || !W) return;
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const n of ns) { x0 = Math.min(x0, n.x - n.r); y0 = Math.min(y0, n.y - n.r); x1 = Math.max(x1, n.x + n.r); y1 = Math.max(y1, n.y + n.r + 16); }
  view.k = Math.max(0.2, Math.min(2.2, Math.min(W / (x1 - x0 + 80), H / (y1 - y0 + 80))));
  view.x = -((x0 + x1) / 2) * view.k; view.y = -((y0 + y1) / 2) * view.k;
  wake();
}

/* ── focus & selection ───────────────────────────────────────────── */
function applyFocus(reheat = true) {
  if (!S.focus) { S.visible = null; $('#crumb').hidden = true; }
  else {
    const seen = new Set([S.focus]);
    let frontier = [S.focus];
    for (let h = 0; h < S.hops; h++) {
      const next = [];
      for (const id of frontier) for (const { other } of S.adj.get(id) || []) if (!seen.has(other.id)) { seen.add(other.id); next.push(other.id); }
      frontier = next;
    }
    S.visible = seen;
    const n = S.byId.get(S.focus);
    $('#crumb').hidden = false;
    $('#crumb').replaceChildren(text('span', `Focused on ${n.label} · ${S.hops} hop${S.hops > 1 ? 's' : ''} · ${seen.size} nodes`),
      button('Show all', () => setFocus(null)));
  }
  if (reheat) { alpha = 0.6; setTimeout(fit, 450); wake(); }
}
function setFocus(id) { S.focus = id; applyFocus(); }
function select(id, center = false) {
  if (typeof fmShowStructure === 'function') fmShowStructure();
  S.selected = id;
  const n = S.byId.get(id);
  if (n && center) { view.x = -n.x * view.k; view.y = -n.y * view.k; }
  renderDetails(n);
  showTab('details');
  wake();
}

/* ── pointer interaction ─────────────────────────────────────────── */
let drag = null;
const toWorld = (ev) => {
  const r = canvas.getBoundingClientRect();
  return { x: (ev.clientX - r.left - W / 2 - view.x) / view.k, y: (ev.clientY - r.top - H / 2 - view.y) / view.k };
};
function hit(p) {
  const ns = activeNodes();
  for (let i = ns.length - 1; i >= 0; i--) { const n = ns[i]; if (Math.hypot(n.x - p.x, n.y - p.y) <= n.r + 4) return n; }
  return null;
}
canvas.addEventListener('pointerdown', (ev) => {
  if (ev.button !== 0) return;                      // right-click opens the menu; it does not select or drag
  canvas.setPointerCapture(ev.pointerId);
  const p = toWorld(ev), n = hit(p);
  drag = { n, sx: ev.clientX, sy: ev.clientY, vx: view.x, vy: view.y, moved: false };
  if (n) { n.fixed = true; }
  canvas.classList.add('dragging');
});
canvas.addEventListener('pointermove', (ev) => {
  const p = toWorld(ev);
  if (drag) {
    if (Math.hypot(ev.clientX - drag.sx, ev.clientY - drag.sy) > 3) drag.moved = true;
    if (drag.n) { drag.n.x = p.x; drag.n.y = p.y; alpha = Math.max(alpha, 0.12); }
    else { view.x = drag.vx + ev.clientX - drag.sx; view.y = drag.vy + ev.clientY - drag.sy; }
    wake();
    return;
  }
  const n = hit(p);
  if ((n && n.id) !== S.hover) { S.hover = n ? n.id : null; tooltip(n, ev); wake(); }
  else if (n) tooltip(n, ev);
});
canvas.addEventListener('pointerup', (ev) => {
  if (!drag) return;
  canvas.classList.remove('dragging');
  if (drag.n && (ev.shiftKey || !drag.moved)) drag.n.fixed = false;   // a dropped node stays put; shift-drag lets it spring back
  if (!drag.moved) { if (drag.n) select(drag.n.id); else { S.selected = null; renderSummary(); wake(); } }
  drag = null;
});
canvas.addEventListener('pointerleave', () => { S.hover = null; $('#tip').hidden = true; wake(); });
canvas.addEventListener('dblclick', (ev) => { const n = hit(toWorld(ev)); if (n) { setFocus(n.id); select(n.id); } });
canvas._menu = (ev) => {
  const n = hit(toWorld(ev));
  if (!n) return [{ heading: 'Graph' }, { label: 'Fit to view', run: fit }, { label: 'Show all', run: () => setFocus(null), disabled: !S.focus },
    { label: 'Unpin all nodes', run: () => { for (const x of S.nodes) x.fixed = false; alpha = 0.5; wake(); } }];
  S.hover = null; $('#tip').hidden = true;
  const own = n.host && !n.props.external;
  const rest = (pre) => n.id.startsWith(`${pre}:${n.host}:`) ? n.id.slice(pre.length + n.host.length + 2) : null;
  const box = own && (rest('mnt') != null ? 'mnt:' + rest('mnt') : rest('pool') != null ? 'pool:' + rest('pool') : null);
  return [{ heading: `${n.kind} · ${n.label}` },
    { label: 'Details', run: () => select(n.id) }, { label: `Focus ${S.hops} hop${S.hops > 1 ? 's' : ''}`, run: () => { setFocus(n.id); select(n.id); } },
    { label: 'Center', run: () => select(n.id, true) },
    n.fixed ? { label: 'Unpin', run: () => { n.fixed = false; alpha = Math.max(alpha, 0.2); wake(); } } : null,
    box ? { label: 'Edit in the topology', run: () => showBox(n.host, box) } : null,
    n.kind === 'Symlink' && own ? { label: 'Ignore this link', run: () => fmIgnore(n.host, n.label) } : null,
    '-',
    n.kind === 'Host' && !n.props.external ? { label: 'Scan now', run: () => queueScan(n.label) } : null,
    n.kind === 'Host' && !n.props.external ? { label: 'Open in planner', run: () => { location.href = `/planner#overview@${encodeURIComponent(n.label)}`; } } : null,
    n.kind === 'MountPoint' && own ? { label: 'Browse folders', run: () => browseFolders(n.host, n.label, n.label) } : null,
    n.kind === 'MountPoint' && own ? { label: 'Largest files', run: () => runSearch({ under: n.label, host: n.host, size_gt: '1MiB' }) } : null,
    n.kind === 'MountPoint' && own ? { label: 'Move from here…', run: () => moveFrom(n.host, n.label) } : null,
    '-', { label: 'Copy name', run: () => copyText(n.label) }];
};
canvas.addEventListener('wheel', (ev) => {
  ev.preventDefault();
  const r = canvas.getBoundingClientRect();
  const mx = ev.clientX - r.left - W / 2, my = ev.clientY - r.top - H / 2;
  const dy = ev.deltaY * (ev.deltaMode === 1 ? 40 : ev.deltaMode === 2 ? H : 1);   // lines or pages → pixels
  const k = Math.max(0.15, Math.min(5, view.k * Math.exp(-dy * 0.0015)));
  view.x = mx - (mx - view.x) * (k / view.k); view.y = my - (my - view.y) * (k / view.k); view.k = k;
  wake();
}, { passive: false });
/* The global shortcuts are declared with sfShortcut(), which is the kernel's, and its one rule keeps them off a key somebody is typing (UX-40, UX-41). */
sfShortcut({ id: 'search-focus', key: '/', label: 'Go to the file search', run: (ev) => { ev.preventDefault(); $('#q').focus(); } });
sfShortcut({ id: 'clear-focus', key: 'Escape', mods: 'any', label: 'Clear the focus on a node', where: 'Graph', when: () => !!S.focus, run: () => { setFocus(null); } });
function tooltip(n, ev) {
  const tip = $('#tip');
  if (!n) { tip.hidden = true; return; }
  const r = canvas.getBoundingClientRect();
  tip.replaceChildren(text('b', n.label), document.createElement('br'), text('span', `${n.kind} · ${HEALTH_TEXT[n.health]}`));
  tip.style.left = `${Math.min(ev.clientX - r.left + 14, W - 280)}px`;
  tip.style.top = `${ev.clientY - r.top + 14}px`;
  tip.hidden = false;
}

/* ── panel rendering (DOM APIs only, never innerHTML with data) ──── */
function text(tag, t, cls) { const el = document.createElement(tag); el.textContent = t; if (cls) el.className = cls; return el; }
function button(label, fn, cls = '') { const b = text('button', label, cls); b.type = 'button'; return sfOnClick(b, fn); }      // busy while an async handler runs
function pill(h) { return text('span', HEALTH_TEXT[h] || h, `pill ${h}`); }
function fmtValue(k, v) {
  if (k.endsWith('_bytes')) return fmtBytes(v);
  if (k === 'last_scanned' && v) return fmtTime(v);
  if (Array.isArray(v)) return v.map((x) => (typeof x === 'object' ? JSON.stringify(x) : x)).join(', ');
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}
function renderDetails(n) {
  const box = $('#summary');
  if (!n) { renderSummary(); return; }
  const head = document.createElement('div'); head.className = 'node-head';
  head.append(text('span', n.kind + (n.props.external ? ' · external' : ''), 'muted'), text('h2', n.label), pill(n.health));
  const dl = document.createElement('dl'); dl.className = 'kv';
  if (n.host) dl.append(text('dt', 'host'), text('dd', n.host));
  for (const [k, v] of Object.entries(n.props)) dl.append(text('dt', k.replace(/_/g, ' ')), text('dd', fmtValue(k, v)));
  const actions = document.createElement('div'); actions.className = 'row';
  actions.append(button(`Focus ${S.hops} hops`, () => setFocus(n.id), 'btn'), button('Center', () => select(n.id, true), 'btn ghost'));
  if (n.kind === 'Host' && !n.props.external) actions.append(button('Scan now', () => queueScan(n.label), 'btn pri'));
  if (n.kind === 'Host' && !n.props.external && can('hostlogs.view') && typeof hlLinkEl === 'function') actions.append(hlLinkEl(n.label));
  if (n.kind === 'Host' && !n.props.external) actions.append(button('Open in planner', () => { location.href = `/planner#overview@${encodeURIComponent(n.label)}`; }, 'btn'));
  if (n.kind === 'MountPoint' && n.host) actions.append(button('Largest files', () => runSearch({ under: n.label, host: n.host, size_gt: '1MiB' }), 'btn'));
  if ((n.kind === 'Host' || n.kind === 'MountPoint') && typeof openGitForPath === 'function') {
    actions.append(button('Git repos…', () => openGitForPath(n.host || n.label, n.kind === 'MountPoint' ? n.label : '/'), 'btn ghost'));
  }
  const nb = document.createElement('ul'); nb.className = 'nbrs';
  for (const { e, other, out } of (S.adj.get(n.id) || []).slice().sort((a, b) => a.e.rel.localeCompare(b.e.rel))) {
    const li = document.createElement('li');
    const b = button('', () => select(other.id, true));
    const dot = text('i', ''); dot.className = `dot ${other.health}`;
    const extra = e.rel === 'REPLICATES_TO' ? ` (${e.props.mode || ''}${e.props.state ? ' · ' + e.props.state : ''})` : '';
    b.append(dot, text('span', `${out ? '→' : '←'} ${e.rel}`, 'rel'), text('span', other.label + extra, 'lbl'));
    li.append(b); nb.append(li);
  }
  const sections = [head, actions, text('h3', 'Properties'), dl, text('h3', `Connections (${nb.children.length})`), nb];

  // Surfaced Git Repos under this node (Host or MountPoint)
  if (window.GITV && GITV.data && GITV.data.repos) {
    const reposUnder = GITV.data.repos.filter((r) => {
      if (n.kind === 'Host') return r.host === n.label;
      if (n.kind === 'MountPoint') return r.host === n.host && (r.path === n.label || r.path.startsWith(n.label.replace(/\/$/, '') + '/'));
      return false;
    });
    if (reposUnder.length) {
      const gitUl = document.createElement('ul'); gitUl.className = 'nbrs';
      for (const r of reposUnder) {
        const li = document.createElement('li');
        const b = button('', () => { if (typeof openGitDrawer === 'function') openGitDrawer(r, 'status'); });
        const dot = text('i', ''); dot.className = `dot ${r.state === 'error' ? 'broken' : r.state === 'uncommitted' || r.state === 'unpushed' ? 'local-only' : 'protected'}`;
        b.append(dot, text('span', r.state, 'rel'), text('span', `${r.name} (${r.path})`, 'lbl'));
        li.append(b); gitUl.append(li);
      }
      sections.push(text('h3', `Git Repositories (${reposUnder.length})`), gitUl);
    }
  }

  box.replaceChildren(...sections);
}
const NEEDS_SHOWN = 12;
let needsAll = false;       // "Needs attention" lists the first twelve and says how many more there are: this shows them all
function renderSummary() {
  if (typeof fmPanel === 'function' && fmPanel()) return;
  // Map, Tasks and Scan have their own panels and draw no storage graph: its counts here described something that was not on screen (UX-14)
  if (T.mode === 'map' || T.mode === 'tasks' || T.mode === 'scan') { $('#summary').replaceChildren(); return; }
  if (S.selected) return;
  if (T.mode === 'topo' && T.sel) { renderEditor(); return; }
  const counts = {}; const health = {};
  for (const n of S.nodes) { counts[n.kind] = (counts[n.kind] || 0) + 1; health[n.health] = (health[n.health] || 0) + 1; }
  const dl = document.createElement('dl'); dl.className = 'kv';
  for (const k of KINDS) dl.append(text('dt', k), text('dd', String(counts[k] || 0)));
  const hl = document.createElement('dl'); hl.className = 'kv';
  for (const h of ['protected', 'local-only', 'broken', 'unknown']) hl.append(text('dt', HEALTH_TEXT[h]), text('dd', String(health[h] || 0)));
  const all = S.nodes.filter((n) => n.health === 'broken' && n.kind !== 'Host');
  const broken = needsAll ? all : all.slice(0, NEEDS_SHOWN);
  const ul = document.createElement('ul'); ul.className = 'nbrs';
  for (const n of broken) {
    const li = document.createElement('li'); const b = button('', () => { select(n.id, true); });
    const dot = text('i', ''); dot.className = 'dot broken';
    b.append(dot, text('span', n.kind, 'rel'), text('span', n.label, 'lbl')); li.append(b); ul.append(li);
  }
  let more = null;                                    // a list that is cut says so, and the same button shows the rest and hides it again (UX-13)
  if (all.length > NEEDS_SHOWN) {
    more = button(needsAll ? 'Show fewer' : `+${all.length - NEEDS_SHOWN} more`, () => { needsAll = !needsAll; renderSummary(); $('#needsmore')?.focus(); }, 'btn ghost sm');
    more.id = 'needsmore';
    more.setAttribute('aria-expanded', String(needsAll));
  }
  $('#summary').replaceChildren(text('h3', 'Nodes'), dl, text('h3', 'Health'), hl,
    ...(broken.length ? [text('h3', 'Needs attention'), ul, ...(more ? [more] : [])] : []),
    ...(S.host && can('hostlogs.view') && typeof hlLinkEl === 'function' ? [text('h3', 'Logs'), hlLinkEl(S.host, `${S.host}'s logs`)] : []),
    ...(S.host && can('console.open') ? [text('h3', 'Console'), el('div', { class: 'row wrap' }, button('Open console…', () => openConsole(S.host), 'btn ghost sm'))] : []),
    // whole-host steps: a VM on this libvirt host, or another host's packages here (docs/host-migration.md)
    ...(S.host && can('plans.edit') && typeof openTask === 'function' ? [text('h3', 'Plan a change'), el('div', { class: 'row wrap' },
      button('Create a VM here…', () => openTask('vm-create', S.host, {}), 'btn ghost sm'),
      button('Install the packages of another host…', () => openTask('packages', S.host, { apps: true }), 'btn ghost sm'))] : []));
}

/* ── right-click menus: an element with _menu(ev) returning items gets one ──
   item: { label, run, danger, disabled, checked } · '-' (separator) · { heading }.
   Shift+right-click, links, text fields and selected text keep the browser's own menu. */
let menuEl = null, menuKeyAt = 0;
function closeMenu(refocus = false) {
  if (!menuEl) return;
  const from = menuEl.from; menuEl.remove(); menuEl = null;
  from?.classList.remove('menu-open');
  if (refocus && from && from.isConnected && from.focus) from.focus();
}
function openMenu(items, x, y, from) {
  closeMenu();
  const list = [];
  for (const it of items) if (it && (it !== '-' || (list.length && list[list.length - 1] !== '-'))) list.push(it);
  while (list[list.length - 1] === '-') list.pop();
  const m = document.createElement('div'); m.className = 'ctxmenu'; m.setAttribute('role', 'menu'); m.from = from;
  for (const it of list) {
    if (it === '-') { m.append(document.createElement('hr')); continue; }
    if (it.heading) { m.append(text('div', it.heading, 'ctxh')); continue; }
    const b = text('button', '', `ctxi${it.danger ? ' danger' : ''}`); b.type = 'button'; b.disabled = !!it.disabled;
    b.setAttribute('role', it.checked == null ? 'menuitem' : 'menuitemradio');
    if (it.checked != null) b.setAttribute('aria-checked', String(!!it.checked));
    b.append(text('span', it.checked ? '✓' : '', 'tick'), text('span', it.label));
    b.addEventListener('click', () => { closeMenu(); it.run(); });
    m.append(b);
  }
  m.addEventListener('keydown', (ev) => {
    const bs = [...m.querySelectorAll('.ctxi:not(:disabled)')], i = bs.indexOf(document.activeElement);
    const go = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: bs.length - 1 }[ev.key];
    if (go != null) { ev.preventDefault(); bs[(go + bs.length) % bs.length]?.focus(); }
    else if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); closeMenu(true); }
    else if (ev.key === 'Tab') closeMenu();
  });
  m.style.visibility = 'hidden'; document.body.append(m);
  const w = m.offsetWidth, h = m.offsetHeight;
  m.style.left = `${Math.max(8, Math.min(x, innerWidth - w - 8))}px`;
  m.style.top = `${y + h > innerHeight - 8 ? Math.max(8, y - h) : y}px`;
  m.style.visibility = '';
  menuEl = m;
  if (from !== canvas) from?.classList.add('menu-open');
  m.querySelector('.ctxi:not(:disabled)')?.focus({ preventScroll: true });
}
function menuFor(t) { while (t && !t._menu) t = t.parentElement; return t; }
function menuAt(owner, ev) {
  const items = owner._menu(ev);
  if (!items || !items.length) return false;
  let x = ev.clientX, y = ev.clientY;
  if (owner !== canvas) {      // opened from the keyboard: under the element, not at the last pointer position
    const r = owner.getBoundingClientRect();
    if (ev.type === 'keydown' || x < r.left || x > r.right || y < r.top || y > r.bottom) { x = r.left + 12; y = Math.min(r.bottom - 6, innerHeight - 40); }
  }
  openMenu(items, x, y, owner);
  return true;
}
document.addEventListener('contextmenu', (ev) => {
  if (Date.now() - menuKeyAt < 400) { ev.preventDefault(); return; }       // the menu key already opened ours
  closeMenu();
  const t = ev.target.nodeType === 1 ? ev.target : ev.target.parentElement;
  if (ev.shiftKey || !t || t.closest('input, textarea, select, [contenteditable], a[href]')) return;
  const sel = getSelection();
  if (sel && !sel.isCollapsed && sel.containsNode(t, true)) return;          // copying text
  const owner = menuFor(t);
  if (owner && menuAt(owner, ev)) ev.preventDefault();
});
// the Menu key and Shift+F10 open the menu of the focused item, but not in a text field, which keeps the browser's own menu as right-click does; under a dialog they act, because the focused item is in it
const menuFromKey = (ev) => {
  const owner = menuFor(document.activeElement);
  if (owner && owner !== canvas && menuAt(owner, ev)) { ev.preventDefault(); menuKeyAt = Date.now(); return true; }
  return false;
};
sfShortcut({ id: 'context-menu', key: 'ContextMenu', mods: 'any', label: 'Open the menu of the focused item', dialogs: true, when: () => !menuEl, run: menuFromKey });
sfShortcut({ id: 'context-menu-f10', key: 'F10', mods: 'shift', label: 'Open the menu of the focused item', dialogs: true, when: () => !menuEl, run: menuFromKey });
document.addEventListener('pointerdown', (ev) => { if (menuEl && !menuEl.contains(ev.target)) closeMenu(); }, true);
document.addEventListener('scroll', (ev) => { if (menuEl && !menuEl.contains(ev.target)) closeMenu(); }, true);
window.addEventListener('resize', () => closeMenu());
window.addEventListener('blur', () => closeMenu());

function copyText(s, what = 'Copied') {
  const done = () => toast(`${what}: ${s}`);
  const ta = Object.assign(document.createElement('textarea'), { value: s, readOnly: true });   // works on plain http on the LAN too
  ta.style.cssText = 'position:fixed;opacity:0'; document.body.append(ta); ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch { /* fall through */ }
  ta.remove();
  if (ok) done();
  else if (navigator.clipboard && isSecureContext) navigator.clipboard.writeText(s).then(done, () => toast('Could not copy'));
  else toast('Could not copy');
}
const dirOf = (p) => p.replace(/\/[^/]*$/, '') || '/';

/* ── tabs, search, jobs, audit ───────────────────────────────────── */
let jobTimer = 0, followingScans = false;
/* The rail is one tab stop and takes arrow keys (UX-20): Up and Down move between the visible tabs, Home and End go to the first and the last, and
   Enter or Space opens the one that has focus, as its buttons do. It is the rail's own key handling, not a global shortcut. */
document.querySelector('.tabs').addEventListener('keydown', (ev) => {
  if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(ev.key) || ev.ctrlKey || ev.metaKey || ev.altKey) return;
  const tabs = [...document.querySelectorAll('.tabs button[role=tab]')].filter((b) => !b.hidden && b.offsetParent !== null);
  const at = tabs.indexOf(document.activeElement);
  if (at < 0) return;
  ev.preventDefault();
  const to = { ArrowDown: at + 1, ArrowUp: at - 1, Home: 0, End: tabs.length - 1 }[ev.key];
  const next = tabs[(to + tabs.length) % tabs.length];
  next.focus();
  next.scrollIntoView?.({ block: 'nearest' });
});
/* The skip links go to the view or the panel by moving focus there; they do not write the URL, which the router owns. */
document.querySelectorAll('.skip').forEach((a) => a.addEventListener('click', (ev) => {
  ev.preventDefault();
  const target = a.dataset.skip === 'panel' ? $('#panel') : $('#stage');
  if (a.dataset.skip === 'panel') setPanelOpen(true);
  target.focus();
}));

function showTab(name) {
  document.querySelectorAll('.tabs button').forEach((b) => {
    const on = b.dataset.tab === name;
    b.classList.toggle('on', on); b.setAttribute('aria-selected', on);
    b.tabIndex = on ? 0 : -1;                                              // one stop in the rail: arrow keys move inside it
    if (!on) return;
    b.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });        // a panel opened from a link must not sit below the fold of the rail
    $('#ptitle').textContent = b.querySelector('.lbl').textContent;
    let g = b.previousElementSibling;
    while (g && !g.classList.contains('rgroup')) g = g.previousElementSibling;
    $('#pgroup').textContent = g ? g.textContent : '';
  });
  document.querySelectorAll('.tab').forEach((t) => { t.hidden = t.id !== `tab-${name}`; });
  setPanelOpen(true);
  clearInterval(jobTimer);
  if (name === 'jobs') { loadJobs(); jobTimer = setInterval(loadJobs, 3000); }
  if (name === 'audit') loadAudit();
  if (name === 'hostlogs') loadHostLogs();
  if (name === 'keys') loadKeys();
  if (name === 'access') loadAccess();
  if (name === 'copies') loadCopies();
  if (name === 'malware') loadMalware();
  if (name === 'moves') loadMoves();
  if (name === 'changes') loadChanges();
  if (name === 'schedule' && typeof loadScheduler === 'function') loadScheduler();
  if (name === 'git') loadGit();
  if (name === 'rebuild') loadRebuild();
  if (name === 'docker') loadDocker();
  if (name === 'infra') loadInfra();
  if (name === 'deploy') loadDeploy();
  if (name === 'security' && typeof loadSecurity === 'function') loadSecurity();
  applyWide();
  routeSync();
}
/* The rail scrolls with its scrollbar hidden, so a fade and a chevron say that more of it is out of sight (UX-01). */
const railEl = $('.rail'), railMore = $('#railmore'), railNarrow = matchMedia('(max-width: 900px)');
function railHint() {
  const h = railNarrow.matches;
  const pos = h ? railEl.scrollLeft : railEl.scrollTop, size = h ? railEl.scrollWidth : railEl.scrollHeight, view = h ? railEl.clientWidth : railEl.clientHeight;
  const before = pos > 4, after = size - view - pos > 4;
  railEl.dataset.more = before && after ? 'both' : before ? 'before' : after ? 'after' : '';
  railMore.hidden = h || !after;
}
railEl.addEventListener('scroll', railHint, { passive: true });
new ResizeObserver(railHint).observe(railEl);
railNarrow.addEventListener('change', railHint);
railMore.addEventListener('click', () => railEl.scrollBy({ top: railEl.clientHeight * 0.8, behavior: sfReducedMotion() ? 'auto' : 'smooth' }));
const curTab = () => $('.tabs button.on')?.dataset.tab;
document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => {
  if (b.dataset.tab === curTab() && !panel.classList.contains('collapsed')) setPanelOpen(false);   // the open one again hides the panel
  else showTab(b.dataset.tab);
}));

/* ── side panel: collapse and resize, remembered per browser ─────── */
const panel = $('#panel');
const PW = { min: 300, def: 380, max: () => Math.max(300, Math.min(760, innerWidth - 420)) };
const prefs = (k, v) => { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch { /* storage blocked: the default is fine */ } return null; };
/* A panel that is about one host carries its own picker (UX-07), instead of telling a person to look at the top of the page. Choosing sets the page's
   host, as the one at the top does, and draws the panel again. `preferred` is the host to start on: the one with the most to look at. */
function needHost(box, what, redraw, preferred) {
  const hosts = [...$('#host').options].map((o) => o.value).filter(Boolean);
  if (!hosts.length) { box.replaceChildren(text('p', 'No host has been scanned yet.', 'muted')); return; }
  const start = hosts.includes(preferred) ? preferred : hosts[0];
  const pick = el('select', { 'aria-label': 'Host' }, hosts.map((h) => el('option', { value: h, selected: h === start }, h)));
  box.replaceChildren(text('p', `${what} is about one host at a time.`, 'muted'),
    el('div', { class: 'row' }, pick, button('Open', () => { const top = $('#host'); top.value = pick.value; top.dispatchEvent(new Event('change')); redraw(); }, 'btn pri sm')));
}
function setPanelWidth(w, save) {
  w = Math.round(Math.min(PW.max(), Math.max(PW.min, w)));
  panel.style.setProperty('--pw', `${w}px`);
  $('#pgrip').setAttribute('aria-valuenow', w);
  if (save) prefs('sf.panelw', w);
}
function setPanelOpen(open) {
  if (open === !panel.classList.contains('collapsed')) return;
  panel.classList.toggle('collapsed', !open);
  prefs('sf.panel', open ? 'open' : 'closed');
  if (!open && panel.contains(document.activeElement)) $('.tabs button.on')?.focus();
  applyWide();
}
/* A panel can have the whole page (UX-04): Security and the settings panels (the audit log with accounts and roles, keys, scans, scan access,
   host logs) open that way, and the button in the panel's header gives any other panel the same, remembered per panel. The view behind
   it keeps its place and comes back when the panel is narrow again. */
const WIDE_BY_DEFAULT = new Set(['security', 'audit', 'keys', 'jobs', 'access', 'hostlogs']);
function wantsWide(name) {
  const v = prefs(`sf.wide.${name}`);
  return v ? v === '1' : WIDE_BY_DEFAULT.has(name);
}
function applyWide() {
  const wide = wantsWide(routeTab()) && !panel.classList.contains('collapsed');
  document.querySelector('.layout').classList.toggle('wide', wide);
  $('#pwide').setAttribute('aria-pressed', String(wide));
  $('#pwide').title = wide ? 'Give the view its room back' : 'Use the whole page for this panel';
  $('#pwide').setAttribute('aria-label', $('#pwide').title);
}
$('#pwide').addEventListener('click', () => { prefs(`sf.wide.${routeTab()}`, wantsWide(routeTab()) ? '0' : '1'); applyWide(); });
$('#pclose').addEventListener('click', () => setPanelOpen(false));
const grip = $('#pgrip');
grip.addEventListener('pointerdown', (ev) => {
  ev.preventDefault(); grip.setPointerCapture(ev.pointerId); panel.classList.add('dragging');
  const x0 = ev.clientX, w0 = panel.querySelector('.pbody').offsetWidth;
  const move = (e) => setPanelWidth(w0 + x0 - e.clientX);
  const up = (e) => {
    grip.removeEventListener('pointermove', move); grip.removeEventListener('pointerup', up);
    panel.classList.remove('dragging'); setPanelWidth(w0 + x0 - e.clientX, true);
  };
  grip.addEventListener('pointermove', move); grip.addEventListener('pointerup', up);
});
grip.addEventListener('dblclick', () => setPanelWidth(PW.def, true));
grip.addEventListener('keydown', (ev) => {
  const d = { ArrowLeft: 24, ArrowRight: -24 }[ev.key];
  if (d) { ev.preventDefault(); setPanelWidth(panel.querySelector('.pbody').offsetWidth + d, true); }
});
grip.setAttribute('aria-valuemin', PW.min); grip.setAttribute('aria-valuemax', 760);
setPanelWidth(Number(prefs('sf.panelw')) || PW.def);
showTab('details');
if (prefs('sf.panel') === 'closed') setPanelOpen(false);
sfShortcut({ id: 'panel-toggle', key: '\\', label: 'Show or hide the panel', run: (ev) => { ev.preventDefault(); setPanelOpen(panel.classList.contains('collapsed')); } });

async function runSearch(params) {
  const fresh = latest('search');
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v));
  showTab('search');
  const ol = $('#results');
  ol.replaceChildren(text('li', 'Searching…', 'muted'));
  try {
    const { results } = await getJSON(`/api/search?${qs}`);
    if (!fresh()) return;
    $('#nres').textContent = results.length || '';
    ol.replaceChildren(...results.map((r) => {
      const li = document.createElement('li');
      const b = button('', () => {
        const id = `mnt:${r.host}:${r.mount}`;
        if (S.byId.has(id)) { setFocus(id); select(id); }
        else { b.querySelector('.m').textContent = `${r.mount} is not in the graph yet; rebuild it after the next scan`; }
      });
      b.append(text('span', r.path, 'p'), text('span', `${r.host} · ${fmtBytes(r.size)} · ${r.type} · ${fmtDate(r.modified_at)}`, 'm'));
      li.append(b);
      li._menu = () => resultMenu(r);
      return li;
    }));
    if (!results.length) ol.replaceChildren(text('li', 'No matches.', 'muted'));
  } catch (err) { if (fresh()) ol.replaceChildren(text('li', err.message, 'muted')); }
}
function resultMenu(r) {
  const dir = r.type === 'dir' ? r.path : dirOf(r.path), stage = (type, preset) => () => openTask(type, r.host, preset);
  return [{ heading: r.path },
    { label: 'Show its folder', run: () => browseFolders(r.host, dir, r.mount) },
    { label: 'Largest files in its folder', run: () => runSearch({ under: dir, host: r.host, size_gt: '1MiB' }) },
    { label: 'Copy path', run: () => copyText(r.path) },
    '-', { heading: 'Plan a change' },
    { label: 'Rename or move…', run: stage('rename', { path: r.path, dest: r.path }) },
    { label: 'Move to trash', run: stage('trash', { path: r.path }) },
    { label: 'Owner and permissions…', run: stage('perms', { path: r.path }) },
    { label: 'Copy its folder to another disk (Moves)…', run: () => moveFrom(r.host, dir) }];
}
let debounce = 0;
$('#q').addEventListener('input', () => {
  clearTimeout(debounce);
  const q = $('#q').value.trim();
  if (q.length < 2) return;
  debounce = setTimeout(() => runSearch({ q, host: S.host }), 300);
});
$('#searchform').addEventListener('submit', (ev) => { ev.preventDefault(); const q = $('#q').value.trim(); if (q) runSearch({ q, host: S.host }); });

async function loadJobs() {
  try {
    const { jobs } = await getJSON('/api/jobs');
    $('#jobs').replaceChildren(...jobs.map((j) => {
      const li = document.createElement('li');
      const r = j.result || {};
      const summary = r.error ? r.error : r.entries != null ? `${r.entries.toLocaleString()} entries · +${r.added} ~${r.modified} -${r.deleted}` : '';
      li.append(text('span', `#${j.job_id} ${j.host} · ${j.status}`, `st-${j.status}`),
        text('span', `${j.requested_by} · ${fmtTime(j.queued_at)}${summary ? ' · ' + summary : ''}`, 'm'));
      return li;
    }));
    if (!jobs.some((j) => j.status === 'queued' || j.status === 'running')) {
      clearInterval(jobTimer);
      if (followingScans) { followingScans = false; loadGraph(); loadDesigns(); }   // a long run outlasts the refresh below
    }
  } catch (err) { clearInterval(jobTimer); $('#jobs').replaceChildren(text('li', err.message, 'muted')); }
}
function followJobs() {
  followingScans = true;
  loadJobs(); clearInterval(jobTimer); jobTimer = setInterval(async () => { await loadJobs(); }, 3000);
  setTimeout(() => { loadGraph(); loadDesigns(); }, 15000);
}
async function queueScan(host) {
  showTab('jobs');
  try {
    await api('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host }) });
    followJobs();
  } catch (err) { $('#jobs').prepend(text('li', err.message, 'st-failed')); }
}
async function scanAll() {
  const btn = $('#scanall'), msg = $('#scanmsg'); btn.disabled = true; msg.hidden = true;
  const say = (m, cls) => { msg.textContent = m; msg.className = cls; msg.hidden = false; };   // loadJobs redraws #jobs
  showTab('jobs');
  try {
    const res = await api('/api/scan/all', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const { jobs } = await res.json();
    if (Object.keys(jobs).length) followJobs();
    else say('No hosts have a scan binding yet. Bind a key to a host in the Keys tab first.', 'muted');
  } catch (err) { say(err.message, 'st-failed'); }
  finally { btn.disabled = false; }
}
$('#scanall').addEventListener('click', scanAll);
$('#scanform').addEventListener('submit', (ev) => { ev.preventDefault(); const h = $('#scanhost').value.trim(); if (h) queueScan(h); });

/* ── keys: generate in the vault, install with ssh-copy-id ────────── */
function keyMsg(msg, ok) { const m = $('#instmsg'); m.hidden = false; m.textContent = msg; m.className = ok ? 'st-ok' : 'st-failed'; }
async function loadKeys(select) {
  try {
    const { keys, bindings } = await getJSON('/api/keys');
    const sel = $('#instkey'); const keep = select || sel.value;
    sel.replaceChildren(...keys.map((k) => new Option(`${k.name} · ${k.type}`, k.name)));
    if (keep) sel.value = keep;
    $('#keys').replaceChildren(...keys.map((k) => {
      const li = document.createElement('li');
      const pub = text('code', k.public_key, 'pub');
      li.append(text('span', `${k.name} · ${k.type} · ${k.origin} · ${k.bindings} binding${k.bindings === 1 ? '' : 's'}`),
        text('span', k.fingerprint, 'm'), pub,
        button('Copy public key', async (ev) => {
          try { await navigator.clipboard.writeText(k.public_key); ev.target.textContent = 'Copied'; }
          catch { getSelection().selectAllChildren(pub); }
        }, 'btn ghost sm'),
        k.bindings ? '' : button('Remove', () => removeVaultItem(`/api/keys/${encodeURIComponent(k.name)}`, `Remove key ${k.name}? It cannot be recovered.`), 'btn ghost sm danger'));
      return li;
    }));
    if (!keys.length) $('#keys').replaceChildren(text('li', 'No keys yet. Generate one above.', 'muted'));
    $('#bindings').replaceChildren(...bindings.map((b) => {
      const li = document.createElement('li');
      li.append(text('span', `${b.user}@${b.pattern}:${b.port} → ${b.key}`), text('span', `${b.kind} · ${b.actions}`, 'm'));
      if (b.kind === 'host') li.append(button('Scan now', () => queueScan(b.pattern), 'btn ghost sm'));
      li.append(button('Unbind', () => removeVaultItem(`/api/bindings/${b.binding_id}`, `Stop using ${b.key} for ${b.user}@${b.pattern}?`), 'btn ghost sm danger'));
      return li;
    }));
    if (!bindings.length) $('#bindings').replaceChildren(text('li', 'No bindings yet.', 'muted'));
  } catch (err) { $('#keys').replaceChildren(text('li', err.message, 'muted')); }
}
async function removeVaultItem(path, question) {
  if (!(await confirmDialog({ title: question, confirm: 'Remove', danger: true }))) return;
  try { await api(path, { method: 'DELETE' }); loadKeys(); }
  catch (err) { keyMsg(err.message, false); }
}
$('#genform').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const name = $('#genname').value.trim();
  try {
    await (await postJSON('/api/keys', { name, type: $('#gentype').value })).json();
    $('#genname').value = '';
    keyMsg(`Generated key "${name}". Now install it on a host.`, true);
    loadKeys(name);
  } catch (err) { keyMsg(err.message, false); }
});
$('#installform').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const body = { key: $('#instkey').value, host: $('#insthost').value.trim(), port: Number($('#instport').value),
                 user: $('#instuser').value.trim(), password: $('#instpw').value,
                 bind: $('#instbind').checked, checksum: $('#instsum').checked };
  $('#instpw').value = '';
  const btn = ev.submitter; btn.disabled = true;
  keyMsg(`Running ssh-copy-id for ${body.user}@${body.host}…`, true);
  try {
    const r = await (await postJSON('/api/keys/install', body)).json();
    keyMsg(`Installed "${body.key}" on ${body.user}@${body.host}` +
           (r.keys_added === 0 ? ' (it was already there)' : ', and key login works') +
           (r.binding_id ? ` and bound it for scans (binding #${r.binding_id}).` : '.'), true);
    loadKeys();
  } catch (err) { keyMsg(err.message, false); }
  finally { btn.disabled = false; }
});

/* ── what this account may do ────────────────────────────────────── */
let ME = null;
const can = (perm) => !!ME && ME.permissions.includes(perm);
// a console opens in a tab of its own (console.html): the terminal takes the window, and several can be open at once
function openConsole(host) { window.open(`/console#${encodeURIComponent(host)}`, '_blank', 'noopener'); }
const TAB_NEEDS = { search: 'search.files', changes: 'plans.view', moves: 'plans.view', schedule: 'plans.view', deploy: 'deploy.view',
                    docker: 'services.view', infra: 'workloads.view', git: 'services.view', rebuild: 'configs.view', copies: 'files.browse', malware: 'files.browse', access: 'keys.view',
                    security: 'security.view', jobs: 'scans.view', keys: 'keys.view', hostlogs: 'hostlogs.view' };
function applyPermissions(me) {          // only hides what would answer 403: the server decides
  ME = me;
  document.querySelectorAll('.tabs button[data-tab]').forEach((b) => { const need = TAB_NEEDS[b.dataset.tab]; b.hidden = !!need && !can(need); });
  document.querySelectorAll('.tabs .rgroup').forEach((g) => {
    let n = g.nextElementSibling, any = false;
    while (n && !n.classList.contains('rgroup')) { any = any || !n.hidden; n = n.nextElementSibling; }
    g.hidden = !any;
  });
  railHint();                              // fewer tabs for this account: the rail may now fit
  $('#searchform').hidden = !can('search.files');
  $('#verify').hidden = !can('audit.verify');
  $('#audit').hidden = !can('audit.view');
  $('#backupshead').hidden = $('#backupsbox').hidden = !can('backups.view');
}

const jsonOpts = (method, body) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const untilText = (t) => fmtTime(t);
function showLink(what, token) {
  $('#linkwhat').textContent = what;
  $('#linkurl').value = `${location.origin}/enroll#${token}`;
  $('#linkbox').hidden = false;
  $('#linkurl').select();
}
$('#linkcopy').addEventListener('click', async () => {
  $('#linkurl').select();
  try { await navigator.clipboard.writeText($('#linkurl').value); toast('Link copied'); } catch { toast('Copy it from the box'); }
});

let CATALOG = [];
async function loadUsers() {
  $('#userscard').hidden = !can('users.manage');
  $('#rolescard').hidden = !can('roles.manage');
  if ($('#userscard').hidden && $('#rolescard').hidden) return;
  try {
    const { roles, catalog } = await getJSON('/api/roles');
    CATALOG = catalog;
    const mine = roles.filter((r) => r.permissions.every((p) => ME.permissions.includes(p)));
    if (can('roles.manage')) renderRoles(roles, mine);
    if (!can('users.manage')) return;
    for (const sel of [$('#newuserrole'), $('#inviterole')]) {
      const was = sel.value;
      sel.replaceChildren(...mine.map((r) => new Option(r.name, r.name)));
      sel.value = was && mine.some((r) => r.name === was) ? was : 'viewer';
    }
    const [{ users }, { invites, now }] = await Promise.all([getJSON('/api/users'), getJSON('/api/invites')]);
    const change = async (u, body) => {
      try { await api(`/api/users/${encodeURIComponent(u)}`, jsonOpts('PUT', body)); }
      catch (err) { $('#usermsg').textContent = err.message; }
      loadUsers();
    };
    $('#userlist').replaceChildren(...users.map((u) => {
      const role = el('select', { 'aria-label': `Role of ${u.username}`, onchange: () => change(u.username, { role: role.value }) },
        ...roles.map((r) => new Option(r.name, r.name)));
      role.value = u.role;
      return el('li', {}, text('span', `${u.username}${u.disabled_at ? ' · disabled' : ''}`), role,
        button(u.disabled_at ? 'Enable' : 'Disable', () => change(u.username, { disabled: !u.disabled_at }), 'btn ghost sm'),
        button('Password reset link', async () => {
          try { showLink(`New password for ${u.username}, good for one day:`, (await (await postJSON(`/api/users/${encodeURIComponent(u.username)}/reset-link`, {})).json()).token); }
          catch (err) { $('#usermsg').textContent = err.message; }
        }, 'btn ghost sm'),
        button('Remove', async () => {
          if (!(await confirmDialog({ title: `Remove account ${u.username}?`, confirm: 'Remove account', danger: true }))) return;
          try { await api(`/api/users/${encodeURIComponent(u.username)}`, { method: 'DELETE' }); }
          catch (err) { $('#usermsg').textContent = err.message; }
          loadUsers();
        }, 'btn ghost sm danger'));
    }));
    $('#invitelist').replaceChildren(...invites.map((i) => {
      const open = !i.used_at && !i.revoked_at && i.expires_at > now;
      const state = i.used_at ? `used by ${i.used_by}` : i.revoked_at ? 'revoked' : open ? `open until ${untilText(i.expires_at)}` : 'expired';
      const what = i.reset_user ? `Password reset for ${i.reset_user}` : `${i.role}${i.note ? ` · ${i.note}` : ''}`;
      return el('li', {}, text('span', what), text('span', `${state} · made by ${i.created_by}`, 'm'),
        ...(open ? [button('Revoke', async () => {
          try { await api(`/api/invites/${i.invite_id}`, { method: 'DELETE' }); }
          catch (err) { $('#invitemsg').textContent = err.message; }
          loadUsers();
        }, 'btn ghost sm danger')] : []));
    }));
  } catch (err) { $('#usermsg').textContent = err.message; }
}

let editingRole = null;     // null: a new role
function checkRoleRisk() {
  const on = (p) => !!document.querySelector(`#roleperms input[value="${p}"]:checked`);
  $('#rolerisk').hidden = !(on('plans.edit') && (on('deploy.apply') || on('deploy.destructive')));
}
function openRoleForm(role) {
  editingRole = role ? role.name : null;
  $('#roleform').hidden = false;
  $('#rolename').value = role ? role.name : '';
  $('#rolename').disabled = !!role;
  $('#roledesc').value = role ? role.description : '';
  $('#rolemsg').textContent = '';
  $('#roleperms').replaceChildren(...CATALOG.map((g) => el('fieldset', { class: 'permgroup' }, text('legend', g.group),
    ...g.permissions.map((p) => {
      const box = el('input', { type: 'checkbox', value: p.name, onchange: checkRoleRisk });
      box.checked = !!role && role.permissions.includes(p.name);
      box.disabled = !can(p.name);       // nobody grants what they cannot do themselves
      return el('label', { class: 'perm', title: p.name }, box, text('span', p.text), ...(p.high_risk ? [text('span', 'high risk', 'st-warn small')] : []));
    }))));
  checkRoleRisk();
}
function renderRoles(roles, mine) {
  $('#rolelist').replaceChildren(...roles.map((r) => el('li', {},
    text('span', `${r.name}${r.builtin ? ' · built-in' : ''} · ${r.users} account${r.users === 1 ? '' : 's'}`),
    text('span', r.description || `${r.permissions.length} permissions`, 'm'),
    ...(r.builtin || !mine.includes(r) ? [] : [
      button('Edit', () => openRoleForm(r), 'btn ghost sm'),
      button('Remove', async () => {
        if (!(await confirmDialog({ title: `Remove role ${r.name}?`, confirm: 'Remove role', danger: true }))) return;
        try { await api(`/api/roles/${encodeURIComponent(r.name)}`, { method: 'DELETE' }); $('#rolemsg').textContent = ''; }
        catch (err) { notify(err.message, 'error'); }
        loadUsers();
      }, 'btn ghost sm danger')]))));
}
$('#rolenew').addEventListener('click', () => openRoleForm(null));
$('#rolecancel').addEventListener('click', () => { $('#roleform').hidden = true; });
$('#roleform').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const body = { name: $('#rolename').value.trim(), description: $('#roledesc').value.trim(),
                 permissions: [...document.querySelectorAll('#roleperms input:checked')].map((b) => b.value) };
  try {
    if (editingRole) await api(`/api/roles/${encodeURIComponent(editingRole)}`, jsonOpts('PUT', body));
    else await api('/api/roles', jsonOpts('POST', body));
    $('#roleform').hidden = true;
    loadUsers();
  } catch (err) { $('#rolemsg').textContent = err.message; }
});
$('#inviteform').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    const role = $('#inviterole').value;
    const r = await (await postJSON('/api/invites', { role, hours: Number($('#invitehours').value), note: $('#invitenote').value.trim() })).json();
    showLink(`Invite with the role ${role}:`, r.token);
    $('#invitenote').value = ''; $('#invitemsg').textContent = '';
  } catch (err) { $('#invitemsg').textContent = err.message; }
  loadUsers();
});
$('#pwform').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    await postJSON('/api/me/password', { password: $('#pwold').value, new_password: $('#pwnew').value });
    sfSignedOut('');
  } catch (err) { $('#pwmsg').textContent = err.message; }
});
$('#userform').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    await postJSON('/api/users', { username: $('#newuser').value.trim(), password: $('#newuserpw').value, role: $('#newuserrole').value });
    ev.target.reset(); $('#usermsg').textContent = '';
  } catch (err) { $('#usermsg').textContent = err.message; }
  loadUsers();
});
async function loadBackups() {
  const box = $('#backupsbox');
  try {
    const b = await getJSON('/api/backups');
    if (b.external) { box.replaceChildren(text('p', 'This database is PostgreSQL: StorageForge makes no backups of it. Use pg_dump, and keep the vault secret safe.', 'st-running')); return; }
    const newest = b.backups[0];
    const hours = newest ? (Date.now() / 1000 - newest.created) / 3600 : null;
    const host = el('input', { type: 'text', placeholder: 'host', 'aria-label': 'Copy backups to host' }); host.value = b.target?.host || '';
    const path = el('input', { type: 'text', class: 'mono', placeholder: '/srv/storageforge-backups', 'aria-label': 'Folder on that host' }); path.value = b.target?.path || '';
    const msg = text('span', '', 'muted');
    const when_ = (x) => fmtTime(x);
    box.replaceChildren(
      text('p', newest ? `Newest: ${newest.kind}, ${fmtBytes(newest.bytes)}, ${hours < 48 ? `${Math.round(hours)} h` : `${Math.round(hours / 24)} days`} ago. Runs nightly at ${b.hour}:00, keeps ${b.keep}.` : 'No backups yet.', newest && hours < 48 ? 'st-ok' : 'st-failed'),
      b.nightly ? text('p', `Last nightly: ${b.nightly.outcome}, ${when_(b.nightly.at)}`, `small st-${b.nightly.outcome}`) : '',
      b.copy ? text('p', `Last copy off this machine: ${b.copy.outcome}, ${when_(b.copy.at)}${b.copy.detail.error ? `: ${b.copy.detail.error}` : ''}`, `small st-${b.copy.outcome}`)
        : text('p', 'These backups sit on the same volume as the database. Add a host below so that losing the volume does not lose them too.', 'small st-running'),
      el('div', { class: 'row wrap' }, host, path,
        button('Save', async () => {
          try { await api('/api/backups/target', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host: host.value.trim(), path: path.value.trim() }) }); msg.textContent = 'Saved. It uses the key bound to that host for deploys.'; }
          catch (err) { msg.textContent = err.message; }
        }, 'btn ghost sm'),
        button('Back up now', async () => {
          try { await postJSON('/api/backups', { kind: 'essentials' }); loadBackups(); }
          catch (err) { msg.textContent = err.message; }
        }, 'btn sm'), msg));
  } catch (err) { box.replaceChildren(text('p', err.message, 'muted')); }
}
async function loadAudit() {
  loadUsers();
  if (can('backups.view')) loadBackups();
  if (!can('audit.view')) return;
  try {
    const { entries } = await getJSON('/api/audit?limit=100');
    $('#audit').replaceChildren(...entries.map((a) => {
      const li = document.createElement('li');
      li.append(text('span', `${a.action} · ${a.outcome}${a.host ? ' · ' + a.host : ''}`, `st-${a.outcome}`),
        Object.assign(text('span', `${fmtTime(a.ts, { seconds: true })} · ${a.actor}${a.key ? ' · ' + a.key : ''}`, 'm'), { title: fmtUtc(a.ts) }),
        ...(Object.keys(a.detail).length ? [text('span', JSON.stringify(a.detail), 'm')] : []));
      return li;
    }));
  } catch (err) { $('#audit').replaceChildren(text('li', err.message, 'muted')); }
}

/* Host logs are hostlogsview.js: loadHostLogs() opens the panel, hlLinkEl() is the link from a host. */
$('#verify').addEventListener('click', async () => {
  $('#verified').textContent = 'Checking…';
  try {
    const v = await getJSON('/api/audit/verify');
    const weak = v.unkeyed_after_keyed ? ` · ${v.unkeyed_after_keyed} later entries were written with the vault locked (no key): `
      + `whoever can write the database could have rewritten them, from #${v.first_unkeyed_after_keyed}` : '';
    $('#verified').textContent = (v.valid ? `Chain intact · ${v.entries_checked} entries` : `Chain broken at entry #${v.first_bad_id}`) + weak;
    $('#verified').className = !v.valid ? 'st-failed' : weak ? 'st-warn' : 'st-ok';
  } catch (err) { $('#verified').textContent = err.message; }
});

/* ── header controls ─────────────────────────────────────────────── */
const STALE_DAYS = 14;
async function loadHosts() {
  const { indexed, graph } = await getJSON('/api/hosts');
  const names = [...new Set([...graph, ...indexed.map((h) => h.hostname)])].sort();
  const sel = $('#host');
  const days = (h) => (h && h.last_scanned_at ? Math.floor((Date.now() / 1000 - h.last_scanned_at) / 86400) : 0);
  const age = new Map(indexed.map((h) => [h.hostname, days(h)]));
  const stale = (n) => (age.get(n) >= STALE_DAYS ? ` (not scanned for ${age.get(n)} days)` : '');
  sel.replaceChildren(new Option('All hosts', ''), ...names.map((n) => new Option(n + stale(n), n)));
  sel.value = S.host;
}
$('#host').addEventListener('change', () => { $('#toplanner').href = '/planner' + (S.host ? `#overview@${encodeURIComponent(S.host)}` : ''); });
$('#host').addEventListener('change', async () => { S.host = $('#host').value; S.focus = null; S.selected = null; S.byId = new Map(); T.sel = null; routeSync(); await Promise.all([loadGraph(), loadDesigns()]); });
$('#hops').addEventListener('change', () => { S.hops = Number($('#hops').value); if (S.focus) applyFocus(); });
$('#reset').addEventListener('click', () => { for (const n of S.nodes) n.fixed = false; alpha = 0.5; setFocus(null); S.selected = null; renderSummary(); fit(); });
$('#export').addEventListener('click', async () => {
  try {
    const res = await api('/api/canvas' + (S.host ? `?host=${encodeURIComponent(S.host)}` : ''));
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `storageforge-${S.host || 'network'}.canvas`;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (err) { alertPanel(err.message); }
});
function alertPanel(msg) { showTab('details'); $('#summary').prepend(text('p', msg, 'st-failed')); }

/* ── signed-in user (signing in happens on /login; session.js handles the session ending) ── */
let user = null;
function setUser(name, me = null) {
  user = name; sfUserName = name || '';
  $('#lock').textContent = name ? `Sign out ${name}` : 'Sign in';
  $('#lock').classList.toggle('locked', !name);
  $('#sessfield').hidden = !name;
  if (me) { $('#sesslen').value = String(me.session_minutes); sfSessionEnds(me.session_ends); }
}

$('#sesslen').addEventListener('change', async (ev) => {
  try {
    const me = await (await api('/api/me', { method: 'PUT', headers: { 'Content-Type': 'application/json' },
                                             body: JSON.stringify({ session_minutes: Number(ev.target.value) }) })).json();
    setUser(me.username, me);
    toast(`Sessions now last ${$('#sesslen').selectedOptions[0].textContent} after sign-in`);
  } catch (err) {
    const me = await getJSON('/api/me').catch(() => null);
    if (me) setUser(me.username, me);
    if (!/Sign in/.test(err.message)) notify(err.message, 'error');
  }
});
$('#lock').addEventListener('click', sfSignOut);
$('#cmdk').addEventListener('click', sfPalette);
$('#hmore').addEventListener('click', () => {          // on a tablet the header keeps its extra controls behind this button
  const open = $('.bar').dataset.more !== 'open';
  $('.bar').dataset.more = open ? 'open' : '';
  $('#hmore').setAttribute('aria-expanded', String(open));
  $('#hmore').textContent = open ? 'Fewer' : 'More';
});

/* The command palette (Ctrl+K) offers the views and the panels the router knows, and the Security sub-panels, to the account that may use them. */
const routeGo = (view, panel, params = {}) => () => {          // the router's own grammar and one step in the history; pushState fires no hashchange, so the page is told here
  sfPushHash(sfFormatHash([view, panel], { host: S.host, ...params }));
  routeApply(routeRead());
  routeSync(true);
};
sfPaletteSource(() => {
  if (!ME) return [];
  const views = [...document.querySelectorAll('#viewmode button[data-mode]')].map((b) => ({ label: `Go to ${b.textContent}`, hint: 'View', run: routeGo(b.dataset.mode, routeTab()) }));
  const panels = [...document.querySelectorAll('.tabs button[data-tab]')].filter((b) => !b.hidden && (!TAB_NEEDS[b.dataset.tab] || can(TAB_NEEDS[b.dataset.tab])))
    .map((b) => ({ label: `Go to ${b.querySelector('.lbl').textContent}`, hint: `Panel, ${b.previousElementSibling?.classList.contains('rgroup') ? b.previousElementSibling.textContent : 'rail'}`, run: routeGo(T.mode, b.dataset.tab) }));
  const sec = can('security.view') && typeof SEC_PANELS !== 'undefined' ? SEC_PANELS.filter(([id]) => id !== 'overview')
    .map(([id, name]) => ({ label: `Go to Security: ${name}`, hint: 'Security panel', run: routeGo(T.mode, 'security', { sec: id }) })) : [];
  return [...views, ...panels, ...sec];
});

// a link, or the URL the page was opened with, says where to be (router.js): #/graph/changes?host=nas-02, or the old #host=nas-02&tab=changes
const takeLink = routeTake;

function showSite(name) {   // on every page, so nobody acts on the wrong client
  if (!name) return;
  document.title = `${name} · StorageForge`;
  const b = $('#sitename'); b.textContent = name; b.hidden = false;
}

/* An empty install: three steps, each a link into the panel where it is done, ticked when they can be seen to be done. Gone once dismissed. */
async function firstRun(who) {
  const card = $('#firstrun');
  try {
    const { indexed, graph } = await getJSON('/api/hosts');
    if (indexed.length || graph.length) { card.hidden = true; return; }
    const ask = async (perm, path, done) => { try { return can(perm) ? done(await getJSON(path)) : false; } catch { return false; } };
    const [bound, scanned, alerting] = await Promise.all([
      ask('keys.view', '/api/keys', (d) => d.bindings.length > 0),
      ask('scans.view', '/api/jobs', (d) => d.jobs.some((j) => j.result && j.result.scan_id)),
      ask('settings.manage', '/api/deploy/settings', (d) => ['ntfy', 'gotify', 'webhook'].some((ch) => d.alerts?.[ch]?.url))]);
    const steps = [['keys.view', 'Enrol a host', 'Install a key on it, so scans can log in', '#/topo/keys', bound],
                   ['scans.view', 'Run the first scan', 'Scans reads its disks, mounts and files', '#/topo/jobs', scanned],
                   ['deploy.view', 'Set up a backup alert', 'Say where a failed or stale job is pushed', '#/topo/deploy', alerting]]
      .filter(([need]) => can(need)).map(([, label, detail, href, done]) => ({ label, detail, href, done }));
    sfFirstRun(card, { user: who, steps });
  } catch { card.hidden = true; }
}
async function boot() {
  try {
    const me = await getJSON('/api/me');
    setUser(me.username, me); applyPermissions(me); showSite(me.site); await loadHosts();
    const tab = takeLink();
    // the first setMode() ran before mapview.js and netscanview.js were loaded, so their views were shown empty (filemap.js
    // fills its own when it loads); a link that named another view has shown that one since, so only the one start-up chose is left
    if (T.mode === T.bootMode && ['map', 'scan'].includes(T.mode)) setMode(T.mode, false);
    await Promise.all([loadGraph(), loadDesigns()]);
    if (tab) showTab(tab);
    if (T.mode === 'tasks' && typeof loadTasks === 'function') loadTasks();
    firstRun(me.username);
  }
  catch (err) { if (!/Sign in/.test(err.message)) alertPanel(err.message); }
  finally { routeStart(); }
}
// boot() runs at the end of topology.js, once both scripts are loaded
