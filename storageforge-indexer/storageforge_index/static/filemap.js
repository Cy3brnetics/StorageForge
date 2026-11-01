'use strict';
/* Graph view, Files map: the folders that hold duplicates, as topology-style cards per host and mount, with lines
   between the folders that share copies. The side panel lists the files and stages "move to trash" tasks into the
   Changes plan, so nothing touches a host until that plan's script runs. System paths are hidden, and the list of
   ignored paths also quiets broken-link flags in the topology. "Structure" shows the force-directed graph.
   Loaded after changes.js; uses the shared helpers. DOM APIs only, never innerHTML. */

const FM = { sub: 'files', data: null, sel: null, view: { x: 0, y: 0, k: 1 }, minSize: '1MiB', scope: 'all', system: false, find: '', seq: 0, moved: false, comparing: false };
const fmBox = $('#filemap');
const fmKeyOf = (host, path) => `${host}\0${path}`;
const fmActive = () => T.mode === 'graph' && FM.sub === 'files';
const fmUnder = (p, dir) => p === dir || p.startsWith(dir.replace(/\/$/, '') + '/');
try { if (localStorage.getItem('sf.graphview') === 'structure') FM.sub = 'structure'; } catch { /* default */ }

/* ── which view is showing ───────────────────────────────────────── */
function fmSync() {
  const graph = T.mode === 'graph', files = fmActive();
  fmBox.hidden = !files;
  $('#stagebar').classList.toggle('low', files);
  $('#graphsub').hidden = !graph;
  document.querySelectorAll('#graphsub button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.sub === FM.sub)));
  for (const s of ['#graph', '.legend', '#hopsfield', '#reset']) document.querySelector(s).hidden = !graph || files;
  if (files) { $('#crumb').hidden = true; $('#empty').hidden = true; $('#detailshint').textContent = ''; }
  else if (graph) {
    $('#crumb').hidden = !S.focus;
    $('#detailshint').textContent = 'Select a node. Double-click one to focus on everything within the chosen number of hops; right-click it for its actions.';
    $('#empty').hidden = S.nodes.length > 0;
    resize();
  }
  if (files) { if (FM.data) { fmDraw(); fmPanel(); } else fmLoad(); }
}
function fmSetSub(sub) {
  FM.sub = sub;
  try { localStorage.setItem('sf.graphview', sub); } catch { /* storage blocked: the default is fine */ }
  S.selected = null;
  fmSync();
  if (sub === 'structure') renderSummary();
}
document.querySelectorAll('#graphsub button').forEach((b) => b.addEventListener('click', () => fmSetSub(b.dataset.sub)));
function fmShowStructure() { if (fmActive()) fmSetSub('structure'); }

/* ── data ────────────────────────────────────────────────────────── */
async function fmLoad() {
  const seq = ++FM.seq;
  const qs = new URLSearchParams({ min_size: FM.minSize });
  if (S.host) qs.set('host', S.host);
  if (FM.system) qs.set('system', '1');
  FM.comparing = true;
  try {
    const quick = await getJSON(`/api/filemap?${qs}`);    // checksums only: fast. Comparing folders can take a while
    if (seq !== FM.seq) return;
    fmTake(quick);
    qs.set('folders', '1');
    const full = await getJSON(`/api/filemap?${qs}`);
    if (seq !== FM.seq) return;
    FM.comparing = false;
    fmTake(full);
  } catch (err) {
    if (seq !== FM.seq) return;
    FM.comparing = false;
    if (!FM.data) FM.data = { folders: [], links: [], groups: [], folder_copies: [], hidden: { groups: 0, bytes: 0 }, broken_links: [], ignore: {}, reclaimable: 0, checksummed: 0, folders_total: 0, groups_total: 0 };
    FM.error = err.message; fmDraw();
  }
}
function fmTake(d) {
  FM.data = d; FM.error = '';
  if (FM.sel && FM.sel.type === 'folder' && !d.folders.some((f) => f.key === FM.sel.key)) FM.sel = null;
  if (FM.sel && FM.sel.type === 'link' && !d.links.some((l) => l.a === FM.sel.a && l.b === FM.sel.b)) FM.sel = null;
  fmDraw();
  fmPanel();
}
const fmFolder = (key) => FM.data.folders.find((f) => f.key === key);
function fmShownLinks() {
  const d = FM.data, shown = new Set(fmShownFolders().map((f) => f.key));
  return d.links.filter((l) => shown.has(l.a) && shown.has(l.b) && (FM.scope === 'all' || (FM.scope === 'same') === (l.scope === 'same host')));
}
function fmShownFolders() {
  const q = FM.find.toLowerCase(), d = FM.data;
  const scoped = FM.scope === 'all' ? null : new Set(d.links.filter((l) => (FM.scope === 'same') === (l.scope === 'same host')).flatMap((l) => [l.a, l.b]));
  return d.folders.filter((f) => (!q || f.path.toLowerCase().includes(q) || f.host.toLowerCase().includes(q)) && (!scoped || scoped.has(f.key)));
}

/* ── staging: trash goes through the Changes plan ────────────────── */
const fmStaged = (host, path) => CH.plan.tasks.find((t) => t.type === 'trash' && t.host === host && t.params.path === path);
const fmStagedAbove = (host, path) => CH.plan.tasks.some((t) => t.type === 'trash' && t.host === host && fmUnder(path, t.params.path));
function fmWouldEmpty(items) {     // refuses to stage the last visible copy of anything
  const gone = (c) => fmStagedAbove(c.host, c.path) || items.some((i) => i.host === c.host && fmUnder(c.path, i.path));
  const touched = (c) => items.some((i) => i.host === c.host && fmUnder(c.path, i.path));
  const all = [...FM.data.groups, ...FM.data.folder_copies];
  return all.filter((g) => g.copies.some(touched) && g.copies.every(gone));
}
async function fmTrash(items) {
  items = items.filter((i) => !fmStaged(i.host, i.path));
  if (!items.length) { toast('Already staged'); return; }
  const last = fmWouldEmpty(items);
  if (last.length) { toast(`Stopped: that would trash every copy of ${last.length === 1 ? 'a file' : `${last.length} files`}. Keep one.`); return; }
  const tasks = items.map((i) => ({ type: 'trash', host: i.host, params: { path: i.path } }));
  try { await postJSON('/api/changes/check', { name: 'check', tasks }); }
  catch (err) { toast(err.message); return; }
  const stamp = Date.now().toString(36);
  tasks.forEach((t, n) => CH.plan.tasks.push({ id: `t${stamp}${n}`, ...t }));
  chTouch();
  toast(`Staged ${items.length} for the trash. Nothing moves until you run the plan in Changes.`);
  fmPanel();
}
function fmDrawStaged() {
  if (!fmActive()) return;
  fmBox.querySelectorAll('.fmrow').forEach((r) => {
    const f = FM.data && fmFolder(r.dataset.key);
    if (f) r.classList.toggle('staged', fmStagedAbove(f.host, f.path) || FM.data.groups.some((g) => g.copies.some((c) => c.host === f.host && fmUnder(c.path, f.path) && fmStaged(c.host, c.path))));
  });
}

/* ── ignore list ─────────────────────────────────────────────────── */
async function fmSaveIgnore(host, paths) {
  await api('/api/files/ignore', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host, paths }) });
  FM.sel = null;
  await Promise.all([fmLoad(), loadGraph(), loadDesigns()]);
}
async function fmIgnore(host, path) {
  try {
    const { ignore } = await getJSON('/api/files/ignore');
    await fmSaveIgnore(host, [...(ignore[host] || []), path]);
    toast(`Ignoring ${path} on ${host}`);
  } catch (err) { toast(err.message); }
}
async function fmEditIgnore() {
  FM.sel = { type: 'ignore' };
  fmMark();
  showTab('details');
  const box = $('#summary');
  box.replaceChildren(text('p', 'Loading…', 'muted'));
  try {
    const r = await getJSON('/api/files/ignore');
    const host = S.host || '';
    const area = el('textarea', { class: 'fmignore', spellcheck: 'false', 'aria-label': 'Ignored paths' });
    area.value = (r.ignore[host || '*'] || []).join('\n');
    const msg = text('p', '', 'st-failed'); msg.hidden = true;
    box.replaceChildren(text('h2', `Ignored on ${host || 'all hosts'}`),
      text('p', 'One per line. A path hides that path and everything under it, anything else matches part of a path (Thumbs.db). Start a line with ! to show something that would be hidden. Broken links here stop being flagged in the topology.', 'muted small'),
      area, msg,
      el('div', { class: 'fmacts' },
        button('Save', async () => {
          try { await fmSaveIgnore(host, area.value.split('\n')); toast('Saved'); fmPanel(); }
          catch (err) { msg.hidden = false; msg.textContent = err.message; }
        }, 'btn pri sm'),
        button('Close', () => { FM.sel = null; fmPanel(); }, 'btn ghost sm')),
      el('details', {}, el('summary', {}, 'Hidden without asking'),
        text('p', `Folders: ${r.builtin_dirs.join(', ')}`, 'small muted mono'), text('p', `Any folder named: ${r.builtin_names.join(', ')}`, 'small muted mono')));
    area.focus();
  } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); }
}

/* ── canvas ──────────────────────────────────────────────────────── */
function fmBar() {
  const choice = (label, value, options, fn) => {
    const s = el('select', { 'aria-label': label, onchange: () => fn(s.value) }, ...options.map(([v, t]) => new Option(t, v)));
    s.value = value;
    return s;
  };
  const find = el('input', { type: 'search', placeholder: 'Filter folders…', 'aria-label': 'Filter folders', autocomplete: 'off', spellcheck: 'false', oninput: () => { FM.find = find.value; fmDraw(true); } });
  find.value = FM.find;
  const sys = el('input', { type: 'checkbox', onchange: () => { FM.system = sys.checked; FM.moved = false; fmLoad(); } });
  sys.checked = FM.system;
  return el('div', { class: 'ttools', role: 'toolbar', 'aria-label': 'File map' },
    choice('Smallest file', FM.minSize, [['1MiB', '≥ 1 MiB'], ['10MiB', '≥ 10 MiB'], ['100MiB', '≥ 100 MiB'], ['1GiB', '≥ 1 GiB']], (v) => { FM.minSize = v; FM.moved = false; fmLoad(); }),
    choice('Where the copies are', FM.scope, [['all', 'All copies'], ['same', 'Same host'], ['across', 'Across hosts']], (v) => { FM.scope = v; FM.moved = false; fmDraw(); }),
    el('label', { class: 'check small' }, sys, 'System files'),
    button('Ignored…', fmEditIgnore, 'btn ghost sm'), button('Fit', () => { FM.moved = false; fmFit(); }, 'btn ghost sm'), find);
}
function fmBrokenCard(list) {
  if (!list.length) return null;
  return el('section', { class: 'fmhost' }, el('h3', {}, text('span', 'Broken links'), text('span', String(list.length), 'muted small')),
    el('div', { class: 'fmcard' }, ...list.slice(0, 40).map((l) => {
      const r = button('', () => fmSelect({ type: 'broken', link: l }), 'fmrow');
      r.append(el('span', { class: 'p', title: l.path }, el('bdi', {}, l.path)), text('span', l.host, 'muted small'), text('span', `→ ${l.target || '?'}`, 'm'));
      r.dataset.broken = fmKeyOf(l.host, l.path);
      r._menu = () => fmBrokenMenu(l);
      return r;
    })));
}
function fmDraw(keepView = false) {
  if (!FM.data) return;
  const d = FM.data, list = fmShownFolders(), max = Math.max(1, ...list.map((f) => f.bytes));
  const hosts = new Map();
  for (const f of list) {
    const h = hosts.get(f.host) || new Map(); hosts.set(f.host, h);
    if (!h.has(f.mount)) h.set(f.mount, []);
    h.get(f.mount).push(f);
  }
  const row = (f) => {
    const r = button('', () => fmSelect({ type: 'folder', key: f.key }), 'fmrow');
    r.dataset.key = f.key;
    const rel = f.path === f.mount ? '.' : f.mount === '/' ? f.path : f.path.slice(f.mount.replace(/\/$/, '').length) || f.path;
    const bar = el('span', { class: 'fmbar' }, el('i', { style: `width:${Math.max(2, (f.bytes / max) * 100).toFixed(1)}%` }));
    r.append(el('span', { class: 'p', title: f.path }, el('bdi', {}, rel)), text('span', fmtBytes(f.bytes), 's'),
      text('span', f.whole ? `whole folder copy · ${f.files.toLocaleString()} files` : `${f.files.toLocaleString()} duplicated file${f.files === 1 ? '' : 's'}`, 'm'), bar);
    r._menu = () => fmFolderMenu(f);
    return r;
  };
  const cards = [...hosts].sort((a, b) => a[0].localeCompare(b[0])).map(([host, mounts]) => el('section', { class: 'fmhost' },
    el('h3', {}, text('span', host), text('span', fmtBytes([...mounts.values()].flat().reduce((n, f) => n + f.bytes, 0)), 'muted small')),
    ...[...mounts].sort((a, b) => a[0].localeCompare(b[0])).map(([mount, folders]) => {
      const node = S.byId.get(`mnt:${host}:${mount}`);
      return el('div', { class: 'fmcard' },
        el('header', {}, el('i', { class: `dot ${node ? node.health : 'unknown'}` }), el('span', { class: 'nm', title: mount }, el('bdi', {}, mount)),
          node?.props.use_pct != null ? text('span', `${Math.round(node.props.use_pct)}%`, 'muted small') : null),
        ...folders.sort((a, b) => b.bytes - a.bytes).map(row));
    })));
  const broken = fmBrokenCard(d.broken_links.filter((l) => !FM.find || l.path.toLowerCase().includes(FM.find.toLowerCase())));
  if (broken) cards.push(broken);
  FM.world = el('div', { class: 'fmworld' }, ...cards);
  FM.svg = svgEl('svg', { class: 'fmedges', 'aria-hidden': 'true' });
  FM.world.prepend(FM.svg);
  const stat = el('div', { class: 'fmstat', role: 'status' },
    el('span', {}, el('b', {}, fmtBytes(d.reclaimable)), ' reclaimable within hosts'),
    el('span', {}, `${(d.groups_total + d.folder_copies.length).toLocaleString()} duplicate sets`),
    d.folders_total > d.folders.length ? text('span', `largest ${d.folders.length} of ${d.folders_total} folders shown`) : null,
    d.hidden.groups ? text('span', `${d.hidden.groups.toLocaleString()} sets hidden as system or ignored`) : null,
    FM.comparing ? text('span', 'Comparing folders…') : null,
    el('span', {}, el('i', { class: 'k' }), 'same host'), el('span', {}, el('i', { class: 'k across' }), 'across hosts'));
  const kids = [FM.world, fmBar(), stat];
  if (!list.length && !broken) {
    const why = FM.error ? FM.error
      : FM.comparing ? 'Comparing folders…'
      : d.hidden.groups && !FM.system ? 'Every duplicate found is a system file or ignored. Tick System files to see them.'
      : !d.checksummed ? 'No file checksums in the index yet, so only whole-folder copies can show here. Run a scan with checksums on to find identical files.'
      : 'No duplicates at this size.';
    kids.push(el('div', { class: 'fmempty' }, text('h2', FM.error ? 'Could not load the file map' : 'Nothing to show'), text('p', why, 'muted')));
  }
  fmBox.replaceChildren(...kids);
  fmEdges();
  fmDrawStaged();
  fmMark();
  if (!FM.moved && !keepView && list.length) fmFit(); else fmApply();
}
function fmEdges() {
  const o = FM.world.getBoundingClientRect(), k = o.width / FM.world.offsetWidth;   // a new world has no transform yet
  const at = new Map();
  FM.world.querySelectorAll('.fmrow[data-key]').forEach((r) => {
    const b = r.getBoundingClientRect();
    at.set(r.dataset.key, { l: (b.left - o.left) / k, r: (b.right - o.left) / k, y: (b.top + b.height / 2 - o.top) / k });
  });
  const max = Math.max(1, ...FM.data.links.map((l) => l.bytes));
  const paths = [];
  for (const l of fmShownLinks()) {
    const a = at.get(l.a), b = at.get(l.b);
    if (!a || !b) continue;
    let d;
    if (Math.abs(a.l - b.l) < 1) {         // same column: an arc out of the right edge
      const out = 28 + Math.min(100, Math.abs(a.y - b.y) * 0.3);
      d = `M${a.r} ${a.y} C${a.r + out} ${a.y} ${b.r + out} ${b.y} ${b.r} ${b.y}`;
    } else {
      const [p, q] = a.l < b.l ? [a, b] : [b, a], mid = (q.l - p.r) / 2;
      d = `M${p.r} ${p.y} C${p.r + mid} ${p.y} ${q.l - mid} ${q.y} ${q.l} ${q.y}`;
    }
    const w = 1.5 + 4.5 * Math.sqrt(l.bytes / max);
    const line = svgEl('path', { d, class: `ln${l.scope === 'same host' ? '' : ' across'}`, 'stroke-width': w.toFixed(1) });
    line.dataset.a = l.a; line.dataset.b = l.b;
    const hit = svgEl('path', { d, class: 'hit' });
    hit.addEventListener('click', (ev) => { ev.stopPropagation(); fmSelect({ type: 'link', a: l.a, b: l.b }); });
    const title = svgEl('title', {}); title.textContent = `${l.files.toLocaleString()} files, ${fmtBytes(l.bytes)} in both`;
    hit.append(title);
    paths.push(line, hit);
  }
  FM.svg.replaceChildren(...paths);
}
function fmMark() {         // lights the selection and what it connects to
  if (!FM.world) return;
  const s = FM.sel, on = new Set();
  if (s?.type === 'folder') { on.add(s.key); for (const l of FM.data.links) { if (l.a === s.key) on.add(l.b); if (l.b === s.key) on.add(l.a); } }
  if (s?.type === 'link') { on.add(s.a); on.add(s.b); }
  const any = s?.type === 'folder' || s?.type === 'link';
  FM.world.querySelectorAll('.fmrow[data-key]').forEach((r) => {
    r.classList.toggle('on', any && (r.dataset.key === s.key || r.dataset.key === s.a || r.dataset.key === s.b));
    r.classList.toggle('dim', any && !on.has(r.dataset.key));
  });
  FM.svg.querySelectorAll('.ln').forEach((p) => {
    const lit = s?.type === 'folder' ? (p.dataset.a === s.key || p.dataset.b === s.key) : s?.type === 'link' && p.dataset.a === s.a && p.dataset.b === s.b;
    p.classList.toggle('lit', Boolean(lit)); p.classList.toggle('dim', Boolean(any && !lit));
  });
}
function fmSelect(sel) { FM.sel = sel; fmMark(); showTab('details'); fmPanel(); }
function fmApply() { if (FM.world) FM.world.style.transform = `translate(${FM.view.x}px, ${FM.view.y}px) scale(${FM.view.k})`; }
function fmFit() {
  if (!FM.world) return;
  const W = fmBox.clientWidth, w = FM.world.offsetWidth;
  if (!W || !w) return;
  const k = Math.max(0.6, Math.min(1, W / w));   // fits the width and scrolls down: a whole index at once is unreadable
  FM.view = { k, x: Math.max(0, (W - w * k) / 2), y: fmBox.querySelector('.ttools').offsetHeight + 16 };
  fmApply();
}
fmBox.addEventListener('wheel', (ev) => {
  if (ev.target.closest('.ttools')) return;
  ev.preventDefault();
  FM.moved = true;
  const r = fmBox.getBoundingClientRect(), v = FM.view, mx = ev.clientX - r.left, my = ev.clientY - r.top;
  if (!ev.ctrlKey && !ev.metaKey) { v.x -= ev.shiftKey ? ev.deltaY : ev.deltaX; v.y -= ev.shiftKey ? 0 : ev.deltaY; fmApply(); return; }   // wheel scrolls, ctrl+wheel zooms
  const k = Math.max(0.3, Math.min(2.5, v.k * Math.exp(-ev.deltaY * 0.0015)));
  v.x = mx - (mx - v.x) * (k / v.k); v.y = my - (my - v.y) * (k / v.k); v.k = k;
  fmApply();
}, { passive: false });
fmBox.addEventListener('pointerdown', (ev) => {
  if (ev.button !== 0 || ev.target.closest('.ttools, .fmrow, .hit')) return;
  const x0 = ev.clientX, y0 = ev.clientY, vx = FM.view.x, vy = FM.view.y;
  let moved = false;
  fmBox.setPointerCapture(ev.pointerId); fmBox.classList.add('panning');
  const move = (e) => { moved = moved || Math.hypot(e.clientX - x0, e.clientY - y0) > 3; FM.moved = FM.moved || moved; FM.view.x = vx + e.clientX - x0; FM.view.y = vy + e.clientY - y0; fmApply(); };
  const up = () => {
    fmBox.removeEventListener('pointermove', move); fmBox.removeEventListener('pointerup', up); fmBox.classList.remove('panning');
    if (!moved && FM.sel) { FM.sel = null; fmMark(); fmPanel(); }
  };
  fmBox.addEventListener('pointermove', move); fmBox.addEventListener('pointerup', up);
});
new ResizeObserver(() => { if (fmActive() && FM.world && !FM.moved) fmFit(); }).observe(fmBox);
$('#host').addEventListener('change', () => { FM.data = null; FM.sel = null; FM.moved = false; if (fmActive()) fmLoad(); });

/* ── right-click menus ───────────────────────────────────────────── */
function fmFolderMenu(f) {
  const stage = (type, preset) => () => openTask(type, f.host, preset);
  return [{ heading: f.path },
    { label: 'Show duplicates', run: () => fmSelect({ type: 'folder', key: f.key }) },
    { label: 'Browse folder', run: () => browseFolders(f.host, f.path, f.mount) },
    { label: 'Largest files here', run: () => runSearch({ under: f.path, host: f.host, size_gt: '1MiB' }) },
    { label: 'Copy path', run: () => copyText(f.path) },
    '-', { heading: 'Plan a change' },
    f.whole ? { label: 'Move this folder to trash', run: () => fmTrash([{ host: f.host, path: f.path }]) } : null,
    { label: 'Rename or move…', run: stage('rename', { path: f.path, dest: f.path }) },
    { label: 'Copy to another disk (Moves)…', run: () => moveFrom(f.host, f.path) },
    '-', { label: 'Ignore this folder', run: () => fmIgnore(f.host, f.path) }];
}
function fmBrokenMenu(l) {
  return [{ heading: l.path },
    { label: 'Point it somewhere else…', run: () => openTask('rename', l.host, { path: l.path, dest: l.path }) },
    { label: 'Move to trash', run: () => openTask('trash', l.host, { path: l.path }) },
    { label: 'Copy path', run: () => copyText(l.path) },
    '-', { label: 'Ignore this link', run: () => fmIgnore(l.host, l.path) }];
}

/* ── side panel ──────────────────────────────────────────────────── */
function fmPanel() {           // true when the file map owns the panel
  if (!fmActive()) return false;
  if (FM.sel?.type === 'ignore') return true;
  const box = $('#summary');
  if (!FM.data) { box.replaceChildren(text('p', 'Loading…', 'muted')); return true; }
  if (FM.sel?.type === 'folder') box.replaceChildren(...fmFolderPanel(fmFolder(FM.sel.key)));
  else if (FM.sel?.type === 'link') box.replaceChildren(...fmLinkPanel(FM.sel.a, FM.sel.b));
  else if (FM.sel?.type === 'broken') box.replaceChildren(...fmBrokenPanel(FM.sel.link));
  else box.replaceChildren(...fmOverview());
  return true;
}
function fmNote() {
  return text('p', 'Trash moves a file to .storageforge-trash on its own filesystem and stages it in Changes. The space comes back when you empty that folder. Hard links look like copies here, and trashing one frees nothing.', 'muted small');
}
function fmFileRow(g, c, checks) {        // one file, its size and where its other copies are
  const others = g.copies.filter((x) => x !== c).map((x) => `${x.host === c.host ? '' : x.host + ':'}${x.path}`);
  const staged = fmStaged(c.host, c.path);
  const box = el('input', { type: 'checkbox', 'aria-label': `Select ${c.path}` });
  box.disabled = Boolean(staged);
  if (checks) checks.push({ box, host: c.host, path: c.path });
  const li = el('li', {}, box, el('span', { class: 'p' }, c.path),
    staged ? button('Undo', () => { unstage(staged); fmPanel(); }, 'btn ghost sm') : button('Trash', () => fmTrash([{ host: c.host, path: c.path }]), 'btn ghost sm'),
    text('span', `${fmtBytes(g.size)} · also ${others.slice(0, 3).join(', ')}${others.length > 3 ? ` and ${others.length - 3} more` : ''}`, 'm'));
  li._menu = () => resultMenu({ host: c.host, mount: c.mount, path: c.path, type: 'file' });
  return li;
}
function fmChecked(checks) {
  return button('Trash selected', () => {
    const items = checks.filter((c) => c.box.checked).map(({ host, path }) => ({ host, path }));
    if (items.length) fmTrash(items); else toast('Tick some files first');
  }, 'btn sm');
}
const fmInFolder = (f, c) => c.host === f.host && (f.whole ? fmUnder(c.path, f.path) : dirOf(c.path) === f.path);
function fmFolderPanel(f) {
  if (!f) return [text('p', 'That folder is gone from the map.', 'muted')];
  const d = FM.data, checks = [];
  const groups = d.groups.filter((g) => g.copies.some((c) => fmInFolder(f, c)));
  const twins = d.folder_copies.filter((t) => t.copies.some((c) => c.host === f.host && c.path === f.path));
  const here = groups.flatMap((g) => g.copies.filter((c) => fmInFolder(f, c)).map((c) => ({ host: c.host, path: c.path })));
  const out = [el('div', { class: 'node-head' }, text('span', `${f.host} · ${fmtBytes(f.bytes)}`, 'muted'), text('h2', f.path)),
    el('div', { class: 'fmacts' },
      button('Browse', () => browseFolders(f.host, f.path, f.mount), 'btn ghost sm'),
      button('Move…', () => moveFrom(f.host, f.path), 'btn ghost sm'),
      button('Ignore', () => fmIgnore(f.host, f.path), 'btn ghost sm'))];
  for (const t of twins) {
    const others = t.copies.filter((c) => !(c.host === f.host && c.path === f.path));
    const staged = fmStaged(f.host, f.path);
    out.push(text('h3', `Whole folder copy · ${t.files.toLocaleString()} files · ${fmtBytes(t.bytes)}`),
      text('p', 'Same names and sizes in the same layout. A checksum scan confirms the content is identical.', 'muted small'),
      el('ul', { class: 'fmlist' }, ...others.map((c) => {
        const li = el('li', {}, text('span', ''), el('span', { class: 'p' }, `${c.host === f.host ? '' : c.host + ':'}${c.path}`),
          button('Trash that one', () => fmTrash([{ host: c.host, path: c.path }]), 'btn ghost sm'));
        return li;
      })),
      el('div', { class: 'fmacts' }, staged ? button('Undo trash of this folder', () => { unstage(staged); fmPanel(); }, 'btn ghost sm')
        : button('Trash this folder, keep the other', () => fmTrash([{ host: f.host, path: f.path }]), 'btn sm')));
  }
  if (groups.length) {
    out.push(text('h3', `Duplicated files (${groups.length})`),
      el('div', { class: 'fmacts' }, button(`Trash the ${here.length} here, keep the others`, () => fmTrash(here), 'btn sm'), fmChecked(checks)),
      el('ul', { class: 'fmlist' }, ...groups.flatMap((g) => g.copies.filter((c) => fmInFolder(f, c)).map((c) => fmFileRow(g, c, checks)))));
  }
  out.push(fmNote());
  return out;
}
function fmLinkPanel(aKey, bKey) {
  const a = fmFolder(aKey), b = fmFolder(bKey), d = FM.data, l = d.links.find((x) => x.a === aKey && x.b === bKey);
  if (!a || !b || !l) return [text('p', 'That line is gone from the map.', 'muted')];
  const pairs = d.groups.map((g) => ({ g, ca: g.copies.filter((c) => fmInFolder(a, c)), cb: g.copies.filter((c) => fmInFolder(b, c)) })).filter((p) => p.ca.length && p.cb.length);
  const twin = l.kind === 'folder';
  const keep = (f, other, list) => button(`Keep ${f.path}`, () => fmTrash(twin ? [{ host: other.host, path: other.path }] : list.map((c) => ({ host: c.host, path: c.path }))), 'btn sm');
  const checks = [];
  return [el('div', { class: 'node-head' }, text('span', `${l.scope} · ${l.files.toLocaleString()} file${l.files === 1 ? '' : 's'} · ${fmtBytes(l.bytes)}`, 'muted'), text('h2', twin ? 'Whole folder copy' : 'Files in both')),
    el('ul', { class: 'fmlist' }, ...[a, b].map((f) => el('li', {}, text('span', ''), el('span', { class: 'p' }, `${f.host}:${f.path}`), button('Show', () => fmSelect({ type: 'folder', key: f.key }), 'btn ghost sm')))),
    l.scope === 'across hosts' ? text('p', 'On different hosts this may be a backup. Check before you trash either side.', 'st-running small') : '',
    text('h3', 'Keep one side, trash the other'),
    el('div', { class: 'fmacts' }, keep(a, b, pairs.flatMap((p) => p.cb)), keep(b, a, pairs.flatMap((p) => p.ca))),
    ...(pairs.length ? [text('h3', `Files (${pairs.length})`), el('div', { class: 'fmacts' }, fmChecked(checks)),
      el('ul', { class: 'fmlist' }, ...pairs.flatMap((p) => [...p.ca, ...p.cb].map((c) => fmFileRow(p.g, c, checks))))] : []),
    fmNote()];
}
function fmBrokenPanel(l) {
  return [el('div', { class: 'node-head' }, text('span', `${l.host} · broken link`, 'muted'), text('h2', l.path)),
    el('dl', { class: 'kv' }, text('dt', 'points to'), text('dd', l.target || '?'), l.note ? text('dt', 'why') : '', l.note ? text('dd', l.note) : ''),
    el('div', { class: 'fmacts' },
      button('Ignore', () => fmIgnore(l.host, l.path), 'btn sm'),
      button('Move to trash…', () => openTask('trash', l.host, { path: l.path }), 'btn ghost sm'),
      button('Copy path', () => copyText(l.path), 'btn ghost sm'))];
}
function fmOverview() {
  const d = FM.data;
  const top = d.groups.slice(0, 12);
  const ul = el('ul', { class: 'nbrs' }, ...top.map((g) => {
    const c = g.copies[0];
    const key = fmKeyOf(c.host, dirOf(c.path));
    const b = button('', () => { if (fmFolder(key)) fmSelect({ type: 'folder', key }); });
    b.append(text('span', `${g.copies.length}×`, 'rel'), text('span', `${fmtBytes(g.size)} ${c.path.split('/').pop()}`, 'lbl'));
    return el('li', {}, b);
  }));
  return [text('p', 'Each row is a folder holding copies; a line joins folders that share them. Select a row or a line to see the files and trash the extras. Right-click for more.', 'muted'),
    text('h3', 'Duplicates'), el('dl', { class: 'kv' }, text('dt', 'Reclaimable within hosts'), text('dd', fmtBytes(d.reclaimable)),
      text('dt', 'Identical files'), text('dd', d.groups_total.toLocaleString()), text('dt', 'Whole folder copies'), text('dd', FM.comparing ? '…' : d.folder_copies.length.toLocaleString()),
      text('dt', 'Hidden, system or ignored'), text('dd', `${d.hidden.groups.toLocaleString()} sets, ${fmtBytes(d.hidden.bytes)}`)),
    ...(top.length ? [text('h3', 'Largest'), ul] : [])];
}
fmSync();
