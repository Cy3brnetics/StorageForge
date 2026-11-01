'use strict';
/* Graph view, Files map: the folders that hold duplicates, as an expandable node map per host, left to right,
   with lines joining cards that share copies; a collapsed folder gathers its children's lines. Whole-folder copies open from the index. The side panel lists the files and stages "move to trash" tasks into the
   Changes plan, so nothing touches a host until that plan's script runs. System paths are hidden, and the list of
   ignored paths also quiets broken-link flags in the topology. "Structure" shows the force-directed graph.
   Loaded after changes.js; uses the shared helpers. DOM APIs only, never innerHTML. */

const FM = { sub: 'files', data: null, sel: null, view: { x: 0, y: 0, k: 1 }, minSize: '1MiB', scope: 'all', system: false, find: '', seq: 0, comparing: false, open: new Set(), closed: new Set(), listed: new Map(), mountRows: new Set(), more: new Set(), loading: new Map(), byDir: new Map(), tree: null, world: null, view: { x: 0, y: 0, k: 1 }, moved: false };
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
  fmIndexCopies(d);
  FM.listed.clear();
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
  if (!fmActive() || !FM.tree) return;
  FM.tree.querySelectorAll('.fmrow').forEach((r) => {
    const n = r._node;
    r.classList.toggle('staged', Boolean(n.host && !n.brokenRoot && fmStagedAbove(n.host, n.path)));
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

/* ── the tree ────────────────────────────────────────────────────── */
const fmId = (root, host, path) => `${root}\0${host}\0${path}`;
function fmNode(root, host, path, name) {
  return { id: fmId(root, host, path), root, host, path, name, kids: new Map(), bytes: 0, files: 0, links: 0 };
}
function fmInsert(top, path, visit) {      // walks from a host's root to path, making the folders on the way
  let n = top;
  visit(n);
  for (const part of path.split('/').filter(Boolean)) {
    const p = n.path === '/' ? `/${part}` : `${n.path}/${part}`;
    if (!n.kids.has(part)) n.kids.set(part, fmNode(n.root, n.host, p, part));
    n = n.kids.get(part);
    visit(n);
  }
  return n;
}
function fmCompact(n, mounts) {            // /mnt/pool/photos stays one row until something branches
  for (const [k, kid] of [...n.kids]) {
    let c = kid, name = kid.name;
    while (c.kids.size === 1 && !c.folder && !c.link && !mounts.has(c.path)) {
      c = [...c.kids.values()][0];
      name += `/${c.name}`;
    }
    c.name = name;
    n.kids.set(k, c);
    fmCompact(c, mounts);
  }
}
function fmBuildTree() {
  const d = FM.data, tops = new Map(), mounts = new Map();
  for (const f of fmShownFolders()) {
    if (!tops.has(f.host)) { tops.set(f.host, Object.assign(fmNode('f', f.host, '/', f.host), { hostRoot: true })); mounts.set(f.host, new Set()); }
    mounts.get(f.host).add(f.mount);
    const leaf = fmInsert(tops.get(f.host), f.path, (n) => { n.bytes += f.bytes; n.files += f.files; });
    leaf.folder = f;
  }
  const out = [...tops.values()].sort((a, b) => a.name.localeCompare(b.name));
  for (const t of out) fmCompact(t, mounts.get(t.host));
  const q = FM.find.toLowerCase();
  const broken = d.broken_links.filter((l) => !q || l.path.toLowerCase().includes(q) || l.host.toLowerCase().includes(q));
  if (broken.length) {
    const top = Object.assign(fmNode('b', '', '/', 'Broken links'), { brokenRoot: true, links: broken.length });
    const hosts = new Map();
    for (const l of broken) {
      if (!hosts.has(l.host)) { hosts.set(l.host, Object.assign(fmNode('b', l.host, '/', l.host), { hostRoot: true })); top.kids.set(l.host, hosts.get(l.host)); }
      fmInsert(hosts.get(l.host), l.path, (n) => { n.links += 1; }).link = l;
    }
    for (const h of hosts.values()) fmCompact(h, new Set());
    out.push(top);
  }
  return out;
}
function fmIndexCopies(d) {                // host + folder → its duplicates, so a row never scans every group
  FM.byDir = new Map();
  for (const g of d.groups) {
    for (const c of g.copies) {
      const k = fmKeyOf(c.host, dirOf(c.path));
      if (!FM.byDir.has(k)) FM.byDir.set(k, []);
      FM.byDir.get(k).push({ g, c });
    }
  }
}
function fmFilesOf(n) {                    // the duplicates directly in a folder, as rows of their own
  const here = n.folder && FM.byDir.get(n.folder.key);
  if (!here) return [];
  return here.map(({ g, c }) => ({ id: fmId(n.root, c.host, c.path), root: n.root, host: c.host, path: c.path, name: c.path.split('/').pop(), group: g, copy: c, bytes: g.size, kids: new Map() }))
    .sort((a, b) => b.bytes - a.bytes);
}
function fmKids(n) {
  const dirs = [...n.kids.values()].sort((a, b) => (b.bytes + b.links) - (a.bytes + a.links));
  const listed = n.listed || [];           // read from the index when a whole-folder copy was opened
  const dupes = fmFilesOf(n), known = new Set([...dirs, ...dupes].map((k) => k.path));
  return [...dirs, ...dupes, ...listed.filter((x) => !known.has(x.path))];
}
const fmExpandable = (n) => n.kids.size > 0 || Boolean(n.folder) || Boolean(n.lazy);   // every folder row can open
const fmIsOpen = (n, depth) => FM.open.has(n.id) || (depth < 2 && !FM.closed.has(n.id)) || Boolean(FM.find && n.kids.size);
function fmLoadKids(n) {                   // anything under a whole-folder copy comes from the index, once, when opened
  if (FM.loading.has(n.id)) return FM.loading.get(n.id);
  const job = (async () => {
    let rows = [];                         // a failure is remembered too: the redraw after it must not ask again
    try {
      const r = await getJSON(`/api/fs/browse?host=${encodeURIComponent(n.host)}&path=${encodeURIComponent(n.path)}`);
      const row = (name, bytes, extra) => ({ id: fmId(n.root, n.host, joinPath(n.path, name)), root: n.root, host: n.host, path: joinPath(n.path, name), name, bytes, kids: new Map(), ...extra });
      rows = [...r.dirs.map((x) => row(x.name, x.bytes, { lazy: true })), ...r.files.map((x) => row(x.name, x.bytes, { plain: true }))];
    } catch (err) { toast(err.message); }
    FM.listed.set(n.id, rows);
    FM.loading.delete(n.id);
  })();
  FM.loading.set(n.id, job);
  return job;
}
function fmToggle(n, depth) {
  FM.anchor = n.id;
  FM.moved = true;
  const open = fmIsOpen(n, depth);
  if (open) { FM.open.delete(n.id); FM.closed.add(n.id); } else { FM.closed.delete(n.id); FM.open.add(n.id); }
  fmDraw();
}
function fmRowClick(n, depth) {
  FM.anchor = n.id;
  FM.moved = true;
  if (fmExpandable(n) && !fmIsOpen(n, depth)) { FM.closed.delete(n.id); FM.open.add(n.id); }
  if (n.brokenRoot) FM.sel = null;
  else if (n.link) FM.sel = { type: 'broken', link: n.link };
  else if (n.group) FM.sel = { type: 'group', id: n.id, group: n.group, copy: n.copy };
  else if (n.folder) { FM.sel = { type: 'folder', key: n.folder.key, id: n.id }; fmOpenPeers(n.folder.key); }
  else if (n.plain) FM.sel = { type: 'plain', id: n.id, node: n };
  else FM.sel = { type: 'dir', id: n.id, node: n };
  fmDraw(); showTab('details'); fmPanel();
  if (FM.view.k < 0.6) {                   // selected from far out: come close enough to read it
    const p = FM.pos.get(n.id);
    if (p) { FM.view.k = 0.8; FM.view.x = FM.tree.clientWidth / 2 - (p.x + FM_W / 2) * 0.8; FM.view.y = FM.tree.clientHeight / 2 - (p.y + FM_H / 2) * 0.8; fmApply(); }
  }
}
function fmOpenPeers(key) {                // selecting a folder opens the way to its other copies
  for (const l of FM.data.links) {
    const other = l.a === key ? l.b : l.b === key ? l.a : null;
    if (!other) continue;
    const [host, path] = other.split('\0');
    let p = path;
    FM.closed.delete(fmId('f', host, '/'));
    while (p && p !== '/') { p = dirOf(p); FM.open.add(fmId('f', host, p)); FM.closed.delete(fmId('f', host, p)); }
    // a compacted row's id is its deepest folder, so every folder on the way is listed
    let q = path;
    while (q && q !== '/') { FM.open.add(fmId('f', host, q)); FM.closed.delete(fmId('f', host, q)); q = dirOf(q); }
  }
}
const FM_W = 250, FM_H = 50, FM_GAP_X = 72, FM_GAP_Y = 8, FM_PAGE = 40;
function fmCard(n, depth, max) {
  if (n.more) {
    const m = el('div', { class: 'fmrow more', role: 'treeitem', tabindex: '-1', 'aria-level': String(depth + 1) }, text('span', n.name, 'nm'));
    m.dataset.id = n.id; m._node = n; m._depth = depth;
    m.addEventListener('click', () => { FM.more.add(n.owner); FM.anchor = n.id; fmDraw(); });
    return m;
  }
  const can = fmExpandable(n), open = can && fmIsOpen(n, depth);
  const node = FM.mountRows.has(`${n.host}\0${n.path}`) ? S.byId.get(`mnt:${n.host}:${n.path}`) : null;
  const note = n.brokenRoot ? `${n.links} to look at` : n.link ? `→ ${n.link.target || '?'}`
    : n.group ? `${n.group.copies.length} copies` : n.links ? `${n.links} broken`
    : n.folder?.whole ? `whole copy · ${n.folder.files.toLocaleString()} files` : n.folder ? `${n.folder.files.toLocaleString()} duplicate${n.folder.files === 1 ? '' : 's'}`
    : n.hostRoot ? 'host' : node ? 'mount' : n.plain ? 'file' : 'folder';
  const staged = !n.brokenRoot && n.host && fmStagedAbove(n.host, n.path);
  const kind = n.link || n.brokenRoot ? ' bad' : n.hostRoot ? ' host' : node ? ' mnt' : n.folder?.whole ? ' whole' : n.folder ? ' dup' : n.group ? ' dup file' : n.plain ? ' file' : '';
  const r = el('div', { class: `fmrow${kind}${staged ? ' staged' : ''}`, role: 'treeitem', tabindex: '-1', 'aria-level': String(depth + 1) },
    el('span', { class: 'hd' }, node ? el('i', { class: `dot ${node.health}` }) : null, el('span', { class: 'nm', title: n.path }, el('bdi', {}, n.name)),
      text('span', n.bytes ? fmtBytes(n.bytes) : '', 'sz')),
    text('span', note, 'nt'),
    el('span', { class: 'mb' }, n.bytes ? el('i', { style: `width:${Math.max(2, (n.bytes / max) * 100).toFixed(1)}%` }) : null),
    can ? el('button', { type: 'button', class: 'tw', tabindex: '-1', 'aria-label': open ? 'Collapse' : 'Expand', onclick: (ev) => { ev.stopPropagation(); fmToggle(n, depth); } }, open ? '−' : '+') : null);
  if (can) r.setAttribute('aria-expanded', String(open));
  r.dataset.id = n.id; r._node = n; r._depth = depth;
  r.addEventListener('click', () => fmRowClick(n, depth));
  r._menu = () => fmMenu(n);
  return r;
}
function fmVisibleKids(n) {                // big folders show a page at a time, so opening one stays quick
  const kids = fmKids(n);
  if (kids.length <= FM_PAGE || FM.more.has(n.id)) return kids;
  return [...kids.slice(0, FM_PAGE), { more: true, owner: n.id, id: `${n.id}\0more`, name: `+ ${kids.length - FM_PAGE} more`, kids: new Map() }];
}
function fmLayout(roots) {                 // left to right: each open folder sits centred on its children
  const pos = new Map(), cards = [], pending = [];
  let edges = '', y = 0, deep = 0;
  const max = Math.max(1, ...roots.map((r) => r.bytes));
  const place = (n, depth) => {
    const x = depth * (FM_W + FM_GAP_X);
    deep = Math.max(deep, depth);
    const i = cards.length;
    cards.push(null);
    let kids = [];
    if (!n.more && fmExpandable(n) && fmIsOpen(n, depth)) {
      if (n.folder?.whole || n.lazy) {
        if (FM.listed.has(n.id)) n.listed = FM.listed.get(n.id); else if (!FM.loading.has(n.id)) pending.push(n);
      }
      kids = fmVisibleKids(n);
    }
    let cy;
    if (kids.length) {
      const ys = kids.map((k) => place(k, depth + 1));
      cy = (ys[0] + ys[ys.length - 1]) / 2;
      const sx = x + FM_W, mid = sx + FM_GAP_X / 2, ex = x + FM_W + FM_GAP_X;
      for (const ky of ys) edges += `M${sx} ${cy + FM_H / 2}C${mid} ${cy + FM_H / 2} ${mid} ${ky + FM_H / 2} ${ex} ${ky + FM_H / 2}`;
    } else {
      cy = y;
      y += FM_H + FM_GAP_Y;
    }
    const card = fmCard(n, depth, max);
    card.style.transform = `translate(${x}px, ${cy}px)`;
    cards[i] = card;
    pos.set(n.id, { x, y: cy });
    return cy;
  };
  for (const r of roots) { place(r, 0); y += 22; }
  return { cards, pos, edges, pending, width: (deep + 1) * (FM_W + FM_GAP_X), height: y };
}
function fmDraw() {
  if (!FM.data) return;
  const d = FM.data;
  if (!FM.tree) {
    FM.world = el('div', { class: 'fmworld' });
    FM.tree = el('div', { class: 'fmtree', role: 'tree', 'aria-label': 'Folders holding duplicates', tabindex: '0', onkeydown: fmKey }, FM.world);
    FM.stat = el('div', { class: 'fmstat', role: 'status' });
    fmBox.replaceChildren(fmBar(), FM.tree, FM.stat);
    fmPanZoom();
  }
  FM.mountRows = new Set(d.folders.map((f) => `${f.host}\0${f.mount}`));
  const roots = fmBuildTree();
  const before = FM.anchor && FM.pos?.get(FM.anchor);
  const L = fmLayout(roots);
  FM.pos = L.pos; FM.size = [L.width, L.height];
  FM.edges = svgEl('path', { class: 'tr', d: L.edges });
  FM.svg = svgEl('svg', { class: 'fmedges', 'aria-hidden': 'true', width: L.width + 200, height: Math.max(L.height, 1) });
  FM.lines = svgEl('g', {});
  FM.svg.append(FM.edges, FM.lines);
  FM.world.replaceChildren(FM.svg, ...L.cards);
  FM.tree.querySelector('.fmempty')?.remove();
  if (!L.cards.length) {
    const why = FM.error ? FM.error
      : FM.comparing ? 'Comparing folders…'
      : d.hidden.groups && !FM.system ? 'Every duplicate found is a system file, a backup rotation or ignored. Tick System files to see them.'
      : !d.checksummed ? 'No file checksums in the index yet, so only whole-folder copies can show here. Run a scan with checksums on to find identical files.'
      : 'No duplicates at this size.';
    FM.tree.append(el('div', { class: 'fmempty' }, text('h2', FM.error ? 'Could not load the file map' : 'Nothing to show'), text('p', why, 'muted')));
  } else (L.cards.find((r) => r.dataset.id === FM.focusId) || L.cards[0]).tabIndex = 0;
  FM.stat.replaceChildren(
    el('span', {}, el('b', {}, fmtBytes(d.reclaimable)), ' reclaimable within hosts'),
    el('span', {}, `${(d.groups_total + d.folder_copies.length).toLocaleString()} duplicate sets`),
    d.folders_total > d.folders.length ? text('span', `largest ${d.folders.length} of ${d.folders_total} folders shown`) : '',
    d.hidden.groups ? text('span', `${d.hidden.groups.toLocaleString()} sets hidden as system, backups or ignored`) : '',
    FM.comparing ? text('span', 'Comparing folders…') : '',
    el('span', {}, el('i', { class: 'k' }), 'same host'), el('span', {}, el('i', { class: 'k across' }), 'across hosts'));
  const after = FM.anchor && L.pos.get(FM.anchor);
  if (before && after) {                   // what you clicked stays under the pointer while the map opens around it
    FM.view.x += (before.x - after.x) * FM.view.k;
    FM.view.y += (before.y - after.y) * FM.view.k;
  }
  FM.anchor = null;
  if (!FM.moved && L.cards.length) fmFit(); else fmApply();
  fmMark();
  if (L.pending.length) Promise.all(L.pending.map(fmLoadKids)).then(fmDraw);
}
function fmApply() { if (FM.world) FM.world.style.transform = `translate(${FM.view.x}px, ${FM.view.y}px) scale(${FM.view.k})`; }
function fmFit() {
  const W = FM.tree.clientWidth, H = FM.tree.clientHeight, [w, h] = FM.size;
  if (!W || !w) return;
  const k = Math.max(0.35, Math.min(1, (W - 48) / w, (H - 48) / h));
  FM.view = { k, x: Math.max(24, (W - w * k) / 2), y: Math.max(24, (H - h * k) / 2) };
  fmApply();
}
function fmZoom(f, mx = FM.tree.clientWidth / 2, my = FM.tree.clientHeight / 2) {
  const v = FM.view, k = Math.max(0.2, Math.min(2, v.k * f));
  v.x = mx - (mx - v.x) * (k / v.k); v.y = my - (my - v.y) * (k / v.k); v.k = k;
  FM.moved = true;
  fmApply();
}
function fmPanZoom() {
  const box = FM.tree;
  box.addEventListener('wheel', (ev) => {
    ev.preventDefault();
    const r = box.getBoundingClientRect();
    fmZoom(Math.exp(-ev.deltaY * (ev.deltaMode === 1 ? 40 : 1) * 0.0015), ev.clientX - r.left, ev.clientY - r.top);
  }, { passive: false });
  box.addEventListener('pointerdown', (ev) => {
    if (ev.button !== 0 || ev.target.closest('.fmrow, .hit')) return;
    const x0 = ev.clientX, y0 = ev.clientY, vx = FM.view.x, vy = FM.view.y;
    let moved = false;
    box.setPointerCapture(ev.pointerId); box.classList.add('panning');
    const move = (e) => {
      moved = moved || Math.hypot(e.clientX - x0, e.clientY - y0) > 3;
      if (moved) FM.moved = true;
      FM.view.x = vx + e.clientX - x0; FM.view.y = vy + e.clientY - y0;
      fmApply();
    };
    const up = () => {
      box.removeEventListener('pointermove', move); box.removeEventListener('pointerup', up); box.classList.remove('panning');
      if (!moved && FM.sel) { FM.sel = null; fmMark(); fmPanel(); }
    };
    box.addEventListener('pointermove', move); box.addEventListener('pointerup', up);
  });
  new ResizeObserver(() => { if (fmActive() && !FM.moved && FM.size) fmFit(); }).observe(box);
}
function fmBar() {
  const choice = (label, value, options, fn) => {
    const s = el('select', { 'aria-label': label, onchange: () => fn(s.value) }, ...options.map(([v, t]) => new Option(t, v)));
    s.value = value;
    return s;
  };
  const find = el('input', { type: 'search', placeholder: 'Filter folders…', 'aria-label': 'Filter folders', autocomplete: 'off', spellcheck: 'false', oninput: () => {
    clearTimeout(FM.findTimer);            // redraw when typing pauses, not on every key
    FM.findTimer = setTimeout(() => { FM.find = find.value; FM.moved = false; fmDraw(); }, 150);
  } });
  find.value = FM.find;
  const sys = el('input', { type: 'checkbox', onchange: () => { FM.system = sys.checked; FM.moved = false; fmLoad(); } });
  sys.checked = FM.system;
  return el('div', { class: 'ttools', role: 'toolbar', 'aria-label': 'File map' },
    choice('Smallest file', FM.minSize, [['1MiB', '≥ 1 MiB'], ['10MiB', '≥ 10 MiB'], ['100MiB', '≥ 100 MiB'], ['1GiB', '≥ 1 GiB']], (v) => { FM.minSize = v; FM.moved = false; fmLoad(); }),
    choice('Where the copies are', FM.scope, [['all', 'All copies'], ['same', 'Same host'], ['across', 'Across hosts']], (v) => { FM.scope = v; FM.moved = false; fmDraw(); }),
    el('label', { class: 'check small' }, sys, 'System files'),
    button('−', () => fmZoom(1 / 1.2), 'btn ghost sm'), button('+', () => fmZoom(1.2), 'btn ghost sm'),
    button('Fit', () => { FM.moved = false; fmFit(); }, 'btn ghost sm'),
    button('Expand all', () => { FM.moved = false; fmExpandAll(); }, 'btn ghost sm'), button('Collapse all', () => { FM.moved = false; fmCollapseAll(); }, 'btn ghost sm'),
    button('Ignored…', fmEditIgnore, 'btn ghost sm'), find);
}
function fmWalk(fn) {
  const go = (n) => { fn(n); n.kids.forEach(go); };
  fmBuildTree().forEach(go);
}
function fmExpandAll() {                   // the folders on the way, not the contents of every copy: those are one request each
  FM.closed.clear();
  fmWalk((n) => { if (n.kids.size) FM.open.add(n.id); else FM.open.delete(n.id); });
  fmDraw();
}
function fmCollapseAll() { FM.open.clear(); fmWalk((n) => { if (!n.hostRoot || n.root === 'b') FM.closed.add(n.id); }); fmDraw(); }
function fmKey(ev) {
  const rows = [...FM.tree.querySelectorAll('.fmrow')], cur = ev.target.closest?.('.fmrow') || rows[0];
  if (!cur) return;
  const i = rows.indexOf(cur), n = cur._node, d = cur._depth;
  const go = (r) => { if (r) { rows.forEach((x) => { x.tabIndex = -1; }); r.tabIndex = 0; r.focus({ preventScroll: true }); FM.focusId = r.dataset.id; fmReveal(r.dataset.id); } };
  const again = () => { FM.focusId = n.id; FM.tree.querySelector('.fmrow[tabindex="0"]')?.focus({ preventScroll: true }); };
  if (ev.key === 'ArrowDown') go(rows[i + 1]);
  else if (ev.key === 'ArrowUp') go(rows[i - 1]);
  else if (ev.key === 'ArrowRight') { if (!n.more && fmExpandable(n) && !fmIsOpen(n, d)) { FM.focusId = n.id; fmToggle(n, d); again(); } else go(rows[i + 1]); }
  else if (ev.key === 'ArrowLeft') {
    if (!n.more && fmExpandable(n) && fmIsOpen(n, d)) { FM.focusId = n.id; fmToggle(n, d); again(); }
    else { for (let k = i - 1; k >= 0; k--) if (rows[k]._depth < d) { go(rows[k]); break; } }
  } else if (ev.key === 'Enter' || ev.key === ' ') { FM.focusId = n.id; cur.click(); again(); }
  else return;
  ev.preventDefault();
}
function fmReveal(id) {                    // pans only if the card is off screen
  const p = FM.pos?.get(id);
  if (!p) return;
  const v = FM.view, W = FM.tree.clientWidth, H = FM.tree.clientHeight;
  const sx = p.x * v.k + v.x, sy = p.y * v.k + v.y;
  if (sx >= 0 && sy >= 0 && sx + FM_W * v.k <= W && sy + FM_H * v.k <= H) return;
  v.x = W / 2 - (p.x + FM_W / 2) * v.k; v.y = H / 2 - (p.y + FM_H / 2) * v.k;
  FM.moved = true;
  fmApply();
}
function fmMark() {         // the copy lines. A collapsed folder gathers its children's lines
  if (!FM.tree || !FM.lines) return;
  const s = FM.sel, peers = new Set();
  const rowId = (key) => { const [host, path] = key.split('\0'); return fmId('f', host, path); };
  let self = s?.id;
  if (s?.type === 'link') self = rowId(s.a);
  if (s?.type === 'broken') self = fmId('b', s.link.host, s.link.path);
  const visible = (key) => {              // the card showing this folder: itself, or the nearest collapsed parent
    const [host, start] = key.split('\0');
    for (let p = start; ; p = dirOf(p)) {
      const id = fmId('f', host, p);
      if (FM.pos.has(id)) return id;
      if (p === '/') return null;
    }
  };
  const lines = new Map();
  for (const l of fmShownLinks()) {
    const a = visible(l.a), b = visible(l.b);
    if (!a || !b || a === b) continue;
    const k = a < b ? `${a}|${b}` : `${b}|${a}`;
    const e = lines.get(k) || { a, b, bytes: 0, files: 0, across: l.scope !== 'same host', first: l, lit: false };
    e.bytes += l.bytes; e.files += l.files;
    if (s?.type === 'folder' && (l.a === s.key || l.b === s.key)) e.lit = true;
    if (s?.type === 'link' && l.a === s.a && l.b === s.b) e.lit = true;
    lines.set(k, e);
  }
  const max = Math.max(1, ...[...lines.values()].map((e) => e.bytes));
  const any = [...lines.values()].some((e) => e.lit);
  const paths = [];
  for (const e of [...lines.values()].sort((x, y) => Number(x.lit) - Number(y.lit))) {
    if (e.lit) { peers.add(e.a); peers.add(e.b); peers.delete(self); }
    const p = FM.pos.get(e.a), q = FM.pos.get(e.b);
    const [l, r] = p.x <= q.x ? [p, q] : [q, p];
    const ly = l.y + FM_H / 2, ry = r.y + FM_H / 2;
    let d;
    if (l.x === r.x) {                    // same column: out of the right edges and back
      const sx = l.x + FM_W, out = 18 + Math.min(FM_GAP_X * 2, Math.abs(ry - ly) * 0.25);
      d = `M${sx} ${ly}C${sx + out} ${ly} ${sx + out} ${ry} ${sx} ${ry}`;
    } else {
      const sx = l.x + FM_W, mid = (sx + r.x) / 2;
      d = `M${sx} ${ly}C${mid} ${ly} ${mid} ${ry} ${r.x} ${ry}`;
    }
    paths.push(svgEl('path', { d, class: `ln${e.across ? ' across' : ''}${e.lit ? ' lit' : any ? ' dim' : ''}`, 'stroke-width': (1.4 + 4.6 * Math.sqrt(e.bytes / max)).toFixed(1) }));
    const hit = svgEl('path', { d, class: 'hit' });
    hit.addEventListener('click', () => fmSelect({ type: 'link', a: e.first.a, b: e.first.b }));
    const title = svgEl('title', {}); title.textContent = `${e.files.toLocaleString()} files, ${fmtBytes(e.bytes)} in both${e.across ? ', on different hosts' : ''}`;
    hit.append(title);
    paths.push(hit);
  }
  if (s?.type === 'group') for (const c of s.group.copies) if (fmId('f', c.host, c.path) !== s.id) peers.add(fmId('f', c.host, c.path));
  FM.tree.querySelectorAll('.fmrow').forEach((r) => {
    r.classList.toggle('on', r.dataset.id === self);
    r.classList.toggle('peer', peers.has(r.dataset.id));
    r.classList.toggle('dim', Boolean(self) && (peers.size > 0) && r.dataset.id !== self && !peers.has(r.dataset.id));
  });
  FM.lines.replaceChildren(...paths);
}
function fmSelect(sel) {
  FM.sel = sel;
  if (sel.type === 'folder') { sel.id = fmId('f', ...sel.key.split('\0')); fmOpenPeers(sel.key); FM.open.add(sel.id); }
  FM.moved = true;
  fmDraw(); showTab('details'); fmPanel();
  const on = FM.tree?.querySelector('.fmrow.on');
  if (on) fmReveal(on.dataset.id);
}
$('#host').addEventListener('change', () => { FM.data = null; FM.sel = null; FM.tree = null; FM.world = null; FM.moved = false; if (fmActive()) fmLoad(); });

/* ── right-click menus ───────────────────────────────────────────── */
function fmMenu(n) {
  if (n.brokenRoot) return null;
  if (n.link) return fmBrokenMenu(n.link);
  if (n.folder) return fmFolderMenu(n.folder);
  if (n.group || n.plain) return resultMenu({ host: n.host, mount: mountFor(n.host, n.path), path: n.path, type: 'file' });
  if (n.hostRoot) return [{ heading: n.name }, { label: 'Only this host', run: () => { $('#host').value = n.host; $('#host').dispatchEvent(new Event('change')); } }];
  return [{ heading: n.path },
    { label: 'Browse folder', run: () => browseFolders(n.host, n.path, mountFor(n.host, n.path)) },
    { label: 'Largest files here', run: () => runSearch({ under: n.path, host: n.host, size_gt: '1MiB' }) },
    { label: 'Copy path', run: () => copyText(n.path) },
    '-', { label: 'Copy to another disk (Moves)…', run: () => moveFrom(n.host, n.path) },
    { label: n.links ? `Ignore this folder (${n.links} broken links)` : 'Ignore this folder', run: () => fmIgnore(n.host, n.path) }];
}
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
  else if (FM.sel?.type === 'group') box.replaceChildren(...fmGroupPanel(FM.sel.group));
  else if (FM.sel?.type === 'dir' || FM.sel?.type === 'plain') box.replaceChildren(...fmDirPanel(FM.sel.node));
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
  const peers = d.links.filter((l) => l.a === f.key || l.b === f.key);
  const out = [el('div', { class: 'node-head' }, text('span', `${f.host} · ${fmtBytes(f.bytes)}`, 'muted'), text('h2', f.path)),
    el('div', { class: 'fmacts' },
      button('Browse', () => browseFolders(f.host, f.path, f.mount), 'btn ghost sm'),
      button('Move…', () => moveFrom(f.host, f.path), 'btn ghost sm'),
      button('Ignore', () => fmIgnore(f.host, f.path), 'btn ghost sm'))];
  if (peers.length) {
    out.push(text('h3', `Shares copies with (${peers.length})`), el('ul', { class: 'fmlist' }, ...peers.map((l) => {
      const o = fmFolder(l.a === f.key ? l.b : l.a);
      return o ? el('li', {}, text('span', ''), el('span', { class: 'p' }, `${o.host === f.host ? '' : o.host + ':'}${o.path}`),
        button('Compare', () => fmSelect({ type: 'link', a: l.a, b: l.b }), 'btn ghost sm'), text('span', `${fmtBytes(l.bytes)} in both`, 'm')) : '';
    })));
  }
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
function fmGroupPanel(g) {
  const checks = [];
  return [el('div', { class: 'node-head' }, text('span', `${g.copies.length} copies · ${fmtBytes(g.size)} each`, 'muted'), text('h2', g.copies[0].path.split('/').pop())),
    el('div', { class: 'fmacts' }, fmChecked(checks)),
    el('ul', { class: 'fmlist' }, ...g.copies.map((c) => fmFileRow(g, c, checks))), fmNote()];
}
function fmDirPanel(n) {
  const broken = n.root === 'b';
  return [el('div', { class: 'node-head' }, text('span', `${n.host}${n.bytes ? ` · ${fmtBytes(n.bytes)}` : ''}${n.links ? ` · ${n.links} broken links` : ''}`, 'muted'), text('h2', n.path)),
    n.plain ? text('p', 'Part of a folder copy. Right-click for what you can do with it.', 'muted small')
      : text('p', broken ? 'Ignoring this folder stops every link under it being flagged.' : 'Holds folders with duplicates. Open it in the tree to see them.', 'muted small'),
    n.plain ? '' : el('div', { class: 'fmacts' },
      button('Browse', () => browseFolders(n.host, n.path, mountFor(n.host, n.path)), 'btn ghost sm'),
      button('Ignore this folder', () => fmIgnore(n.host, n.path), broken ? 'btn sm' : 'btn ghost sm'))];
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
  return [text('p', 'Open a card with + to see what is duplicated in it. Select one to see where its other copies are and trash the extras. Right-click for more.', 'muted'),
    text('h3', 'Duplicates'), el('dl', { class: 'kv' }, text('dt', 'Reclaimable within hosts'), text('dd', fmtBytes(d.reclaimable)),
      text('dt', 'Identical files'), text('dd', d.groups_total.toLocaleString()), text('dt', 'Whole folder copies'), text('dd', FM.comparing ? '…' : d.folder_copies.length.toLocaleString()),
      text('dt', 'Hidden, system or ignored'), text('dd', `${d.hidden.groups.toLocaleString()} sets, ${fmtBytes(d.hidden.bytes)}`)),
    ...(top.length ? [text('h3', 'Largest'), ul] : [])];
}
fmSync();
