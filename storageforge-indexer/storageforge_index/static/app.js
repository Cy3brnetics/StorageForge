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

/* ── API (session cookie, set by /api/login) ─────────────────────── */
async function api(path, opts = {}) {
  const res = await fetch(path, { credentials: 'same-origin', ...opts });
  if (res.status === 401) { askLogin(); throw new Error('Sign in required'); }
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch { /* not JSON */ }
    throw new Error(msg);
  }
  return res;
}
const getJSON = async (p) => (await api(p)).json();

/* ── state ───────────────────────────────────────────────────────── */
const S = { nodes: [], edges: [], byId: new Map(), adj: new Map(), visible: null, focus: null, selected: null,
            hover: null, host: '', hops: 2 };
const view = { x: 0, y: 0, k: 1 };
let alpha = 0;
let raf = 0;

const canvas = $('#graph');
const ctx = canvas.getContext('2d');
let W = 0, H = 0, DPR = 1;
let fitted = false;
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
  if (!old.size) { warmUp(); if (W) { fitted = true; fit(); } }
  alpha = Math.max(alpha, old.size ? 0.4 : 0.15);
  wake();
  renderSummary();
  if (T.mode === 'topo' && T.order.length) renderTopo();   // refresh the health dots
}

/* ── physics ─────────────────────────────────────────────────────── */
function tick() {
  const ns = activeNodes();
  const n = ns.length;
  for (let i = 0; i < n; i++) {                       // charge (inverse-square repulsion)
    const a = ns[i];
    for (let j = i + 1; j < n; j++) {
      const b = ns[j];
      let dx = b.x - a.x, dy = b.y - a.y, d2 = dx * dx + dy * dy;
      if (d2 > 360000) continue;
      if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
      const f = (-700 * alpha) / d2;
      a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
    }
  }
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
    for (let i = 0; i < n; i++) {
      const a = ns[i];
      for (let j = i + 1; j < n; j++) {
        const b = ns[j];
        const min = a.r + b.r + 8;
        const dx = b.x - a.x, dy = b.y - a.y, d2 = dx * dx + dy * dy;
        if (d2 >= min * min) continue;
        const d = Math.sqrt(d2) || 0.01, push = (min - d) / d / 2;
        if (!a.fixed) { a.x -= dx * push; a.y -= dy * push; }
        if (!b.fixed) { b.x += dx * push; b.y += dy * push; }
      }
    }
  }
  alpha = Math.max(0, alpha * 0.985 - 0.0005);
}
function warmUp() {
  const n = Math.max(1, activeNodes().length);
  alpha = 1;
  const ticks = Math.min(300, Math.floor(4e7 / (n * n)));
  for (let i = 0; i < ticks; i++) tick();
}
function wake() { if (!raf) raf = requestAnimationFrame(frame); }
function frame() {
  raf = 0;
  if (canvas.hidden) return;                          // topology view: resize() wakes it again
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
  for (const e of activeEdges()) {
    const lit = !near || (near.has(e.src) && near.has(e.dst) && (e.src === (S.hover || S.selected) || e.dst === (S.hover || S.selected)));
    ctx.globalAlpha = lit ? 0.9 : 0.15;
    ctx.lineWidth = (e.rel === 'REPLICATES_TO' ? 2 : 1.3) / Math.sqrt(view.k);
    ctx.setLineDash(e.rel === 'SYMLINK_TO' || e.rel === 'REPLICATES_TO' ? [6, 4] : []);
    ctx.strokeStyle = e.rel === 'MOUNTED_AT' ? (e.props.bind ? COL.fast : COL.accent)
      : e.rel === 'SYMLINK_TO' ? COL.fast
      : e.rel === 'REPLICATES_TO' ? (COL[e.props.health] || COL.muted) : COL.line;
    ctx.beginPath(); ctx.moveTo(e.s.x, e.s.y); ctx.lineTo(e.t.x, e.t.y); ctx.stroke();
    if (e.rel === 'REPLICATES_TO' || e.rel === 'SYMLINK_TO') arrow(e);
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
  ctx.setLineDash([]);
  ctx.beginPath(); ctx.moveTo(x, y);
  ctx.lineTo(x - ux * s - uy * s * 0.6, y - uy * s + ux * s * 0.6);
  ctx.lineTo(x - ux * s + uy * s * 0.6, y - uy * s - ux * s * 0.6);
  ctx.closePath(); ctx.fillStyle = ctx.strokeStyle; ctx.fill();
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
canvas.addEventListener('wheel', (ev) => {
  ev.preventDefault();
  const r = canvas.getBoundingClientRect();
  const mx = ev.clientX - r.left - W / 2, my = ev.clientY - r.top - H / 2;
  const dy = ev.deltaY * (ev.deltaMode === 1 ? 40 : ev.deltaMode === 2 ? H : 1);   // lines or pages → pixels
  const k = Math.max(0.15, Math.min(5, view.k * Math.exp(-dy * 0.0015)));
  view.x = mx - (mx - view.x) * (k / view.k); view.y = my - (my - view.y) * (k / view.k); view.k = k;
  wake();
}, { passive: false });
document.addEventListener('keydown', (ev) => {
  if (ev.key === '/' && document.activeElement !== $('#q')) { ev.preventDefault(); $('#q').focus(); }
  if (ev.key === 'Escape' && S.focus) setFocus(null);
});
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
function button(label, fn, cls = '') { const b = text('button', label, cls); b.type = 'button'; b.addEventListener('click', fn); return b; }
function pill(h) { return text('span', HEALTH_TEXT[h] || h, `pill ${h}`); }
function fmtBytes(n) {
  if (n == null || n === '') return '—';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']; let v = Number(n), i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i < 2 ? 0 : 2)} ${u[i]}`;
}
function fmtValue(k, v) {
  if (k.endsWith('_bytes')) return fmtBytes(v);
  if (k === 'last_scanned' && v) return new Date(v * 1000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
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
  if (n.kind === 'Host' && !n.props.external) actions.append(button('Open in planner', () => { location.href = `/planner#overview@${encodeURIComponent(n.label)}`; }, 'btn'));
  if (n.kind === 'MountPoint' && n.host) actions.append(button('Largest files', () => runSearch({ under: n.label, host: n.host, size_gt: '1MiB' }), 'btn'));
  const nb = document.createElement('ul'); nb.className = 'nbrs';
  for (const { e, other, out } of (S.adj.get(n.id) || []).slice().sort((a, b) => a.e.rel.localeCompare(b.e.rel))) {
    const li = document.createElement('li');
    const b = button('', () => select(other.id, true));
    const dot = text('i', ''); dot.className = `dot ${other.health}`;
    const extra = e.rel === 'REPLICATES_TO' ? ` (${e.props.mode || ''}${e.props.state ? ' · ' + e.props.state : ''})` : '';
    b.append(dot, text('span', `${out ? '→' : '←'} ${e.rel}`, 'rel'), text('span', other.label + extra, 'lbl'));
    li.append(b); nb.append(li);
  }
  box.replaceChildren(head, actions, text('h3', 'Properties'), dl, text('h3', `Connections (${nb.children.length})`), nb);
}
function renderSummary() {
  if (S.selected) return;
  if (T.mode === 'topo' && T.sel) { renderEditor(); return; }
  const counts = {}; const health = {};
  for (const n of S.nodes) { counts[n.kind] = (counts[n.kind] || 0) + 1; health[n.health] = (health[n.health] || 0) + 1; }
  const dl = document.createElement('dl'); dl.className = 'kv';
  for (const k of KINDS) dl.append(text('dt', k), text('dd', String(counts[k] || 0)));
  const hl = document.createElement('dl'); hl.className = 'kv';
  for (const h of ['protected', 'local-only', 'broken', 'unknown']) hl.append(text('dt', HEALTH_TEXT[h]), text('dd', String(health[h] || 0)));
  const broken = S.nodes.filter((n) => n.health === 'broken' && n.kind !== 'Host').slice(0, 12);
  const ul = document.createElement('ul'); ul.className = 'nbrs';
  for (const n of broken) {
    const li = document.createElement('li'); const b = button('', () => { select(n.id, true); });
    const dot = text('i', ''); dot.className = 'dot broken';
    b.append(dot, text('span', n.kind, 'rel'), text('span', n.label, 'lbl')); li.append(b); ul.append(li);
  }
  $('#summary').replaceChildren(text('h3', 'Nodes'), dl, text('h3', 'Health'), hl,
    ...(broken.length ? [text('h3', 'Needs attention'), ul] : []));
}

/* ── tabs, search, jobs, audit ───────────────────────────────────── */
let jobTimer = 0;
function showTab(name) {
  document.querySelectorAll('.tabs button').forEach((b) => b.classList.toggle('on', b.dataset.tab === name));
  document.querySelectorAll('.tab').forEach((t) => { t.hidden = t.id !== `tab-${name}`; });
  clearInterval(jobTimer);
  if (name === 'jobs') { loadJobs(); jobTimer = setInterval(loadJobs, 3000); }
  if (name === 'audit') loadAudit();
  if (name === 'keys') loadKeys();
  if (name === 'access') loadAccess();
  if (name === 'copies') loadCopies();
  if (name === 'moves') loadMoves();
  if (name === 'changes') loadChanges();
  if (name === 'git') loadGit();
  if (name === 'docker') loadDocker();
}
document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));

async function runSearch(params) {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v));
  showTab('search');
  const ol = $('#results');
  ol.replaceChildren(text('li', 'Searching…', 'muted'));
  try {
    const { results } = await getJSON(`/api/search?${qs}`);
    $('#nres').textContent = results.length;
    ol.replaceChildren(...results.map((r) => {
      const li = document.createElement('li');
      const b = button('', () => {
        const id = `mnt:${r.host}:${r.mount}`;
        if (S.byId.has(id)) { setFocus(id); select(id); }
        else { b.querySelector('.m').textContent = `${r.mount} is not in the graph yet; rebuild it after the next scan`; }
      });
      b.append(text('span', r.path, 'p'), text('span', `${r.host} · ${fmtBytes(r.size)} · ${r.type} · ${new Date(r.modified_at * 1000).toISOString().slice(0, 10)}`, 'm'));
      li.append(b); return li;
    }));
    if (!results.length) ol.replaceChildren(text('li', 'No matches.', 'muted'));
  } catch (err) { ol.replaceChildren(text('li', err.message, 'muted')); }
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
        text('span', `${j.requested_by} · ${new Date(j.queued_at * 1000).toLocaleString()}${summary ? ' · ' + summary : ''}`, 'm'));
      return li;
    }));
    if (!jobs.some((j) => j.status === 'queued' || j.status === 'running')) { clearInterval(jobTimer); }
  } catch (err) { clearInterval(jobTimer); $('#jobs').replaceChildren(text('li', err.message, 'muted')); }
}
async function queueScan(host) {
  showTab('jobs');
  try {
    await api('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host }) });
    loadJobs(); clearInterval(jobTimer); jobTimer = setInterval(async () => { await loadJobs(); }, 3000);
    setTimeout(() => { loadGraph(); loadDesigns(); }, 15000);
  } catch (err) { $('#jobs').prepend(text('li', err.message, 'st-failed')); }
}
$('#scanform').addEventListener('submit', (ev) => { ev.preventDefault(); const h = $('#scanhost').value.trim(); if (h) queueScan(h); });

/* ── keys: generate in the vault, install with ssh-copy-id ────────── */
const postJSON = (path, body) => api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
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
      li.append(text('span', `${k.name} · ${k.type} · ${k.bindings} binding${k.bindings === 1 ? '' : 's'}`),
        text('span', k.fingerprint, 'm'), pub,
        button('Copy public key', async (ev) => {
          try { await navigator.clipboard.writeText(k.public_key); ev.target.textContent = 'Copied'; }
          catch { getSelection().selectAllChildren(pub); }
        }, 'btn ghost sm'));
      return li;
    }));
    if (!keys.length) $('#keys').replaceChildren(text('li', 'No keys yet. Generate one above.', 'muted'));
    $('#bindings').replaceChildren(...bindings.map((b) => {
      const li = document.createElement('li');
      li.append(text('span', `${b.user}@${b.pattern}:${b.port} → ${b.key}`), text('span', `${b.kind} · ${b.actions}`, 'm'));
      if (b.kind === 'host') li.append(button('Scan now', () => queueScan(b.pattern), 'btn ghost sm'));
      return li;
    }));
    if (!bindings.length) $('#bindings').replaceChildren(text('li', 'No bindings yet.', 'muted'));
  } catch (err) { $('#keys').replaceChildren(text('li', err.message, 'muted')); }
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

async function loadAudit() {
  try {
    const { entries } = await getJSON('/api/audit?limit=100');
    $('#audit').replaceChildren(...entries.map((a) => {
      const li = document.createElement('li');
      li.append(text('span', `${a.action} · ${a.outcome}${a.host ? ' · ' + a.host : ''}`, `st-${a.outcome}`),
        text('span', `${new Date(a.ts * 1000).toISOString().replace('T', ' ').slice(0, 19)} · ${a.actor}${a.key ? ' · ' + a.key : ''}`, 'm'),
        ...(Object.keys(a.detail).length ? [text('span', JSON.stringify(a.detail), 'm')] : []));
      return li;
    }));
  } catch (err) { $('#audit').replaceChildren(text('li', err.message, 'muted')); }
}
$('#verify').addEventListener('click', async () => {
  $('#verified').textContent = 'Checking…';
  try {
    const v = await getJSON('/api/audit/verify');
    $('#verified').textContent = v.valid ? `Chain intact · ${v.entries_checked} entries` : `Chain broken at entry #${v.first_bad_id}`;
    $('#verified').className = v.valid ? 'st-ok' : 'st-failed';
  } catch (err) { $('#verified').textContent = err.message; }
});

/* ── header controls ─────────────────────────────────────────────── */
async function loadHosts() {
  const { indexed, graph } = await getJSON('/api/hosts');
  const names = [...new Set([...graph, ...indexed.map((h) => h.hostname)])].sort();
  const sel = $('#host');
  sel.replaceChildren(new Option('All hosts', ''), ...names.map((n) => new Option(n, n)));
  sel.value = S.host;
}
$('#host').addEventListener('change', () => { $('#toplanner').href = '/planner' + (S.host ? `#overview@${encodeURIComponent(S.host)}` : ''); });
$('#host').addEventListener('change', async () => { S.host = $('#host').value; S.focus = null; S.selected = null; S.byId = new Map(); T.sel = null; await Promise.all([loadGraph(), loadDesigns()]); });
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

/* ── sign in ─────────────────────────────────────────────────────── */
const dlg = $('#logindlg');
let user = null;
function setUser(name) {
  user = name;
  $('#lock').textContent = name ? `Sign out ${name}` : 'Sign in';
  $('#lock').classList.toggle('locked', !name);
}
function askLogin(msg = '') {
  clearInterval(jobTimer);
  setUser(null);
  $('#loginmsg').hidden = !msg;
  $('#loginmsg').textContent = msg;
  if (!dlg.open) { $('#password').value = ''; dlg.showModal(); $('#username').value ? $('#password').focus() : $('#username').focus(); }
}
$('#loginform').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const body = JSON.stringify({ username: $('#username').value.trim(), password: $('#password').value });
  $('#password').value = '';
  try {
    const res = await fetch('/api/login', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { askLogin(data.error || res.statusText); return; }
    dlg.close(); setUser(data.username); boot();
  } catch (err) { askLogin(err.message); }
});
$('#logincancel').addEventListener('click', () => dlg.close());
$('#lock').addEventListener('click', async () => {
  if (!user) { askLogin(); return; }
  await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
  S.nodes = []; S.edges = []; S.byId = new Map(); S.adj = new Map(); S.selected = S.focus = null;
  T.docs = new Map(); T.order = []; T.sel = null; renderTopo();
  $('#summary').replaceChildren(); wake();
  askLogin();
});

async function boot() {
  try { setUser((await getJSON('/api/me')).username); await loadHosts(); await Promise.all([loadGraph(), loadDesigns()]); }
  catch (err) { if (!/Sign in/.test(err.message)) alertPanel(err.message); }
}
// boot() runs at the end of topology.js, once both scripts are loaded
