'use strict';
/* The Workloads page (/workloads): every container and VM of the fleet as a left-to-right tree (fleet, host, runtime, workload) on a canvas
   that pans and zooms (canvas.js), with a side panel for what is selected. The tree (wlTree) and its layout (wlLayout) are pure functions of
   what GET /api/workloads returns and of which nodes are folded, so a test can run them without a page. The panel only builds the step
   object of an action ({type, host, params}) and hands it to WL.onAction; the wizard that checks and saves it fills that hook, and WL.onNew
   for + New. DOM APIs only (ui.js: el, text, button). Loaded after kernel.js, ui.js and canvas.js. */

const WL_RUNTIMES = ['docker', 'podman', 'libvirt', 'incus', 'lxc', 'proxmox'];
const WL_COL = 240, WL_ROW = 44, WL_W = 200, WL_H = 36, WL_MANY_HOSTS = 12;

const WL = {
  listing: null, root: null, index: new Map(), folded: new Set(), pinned: new Set(), q: '', sel: '', focus: '', view: { x: 0, y: 0, k: 1 }, cv: null, fitted: false,
  onAction: () => notify('Making a change from here comes with the review step of this page.', 'info'),      // Task 7 fills these two
  onNew: () => notify('Creating a workload from here comes with the wizard of this page.', 'info'),
};

/* ── the tree ─────────────────────────────────────────────────────── */
/* node: {id, kind: fleet | host | runtime | stack | workload | connections | note, label, data, children}. Ids are host:NAME, rt:NAME:RUNTIME,
   stack:NAME:RUNTIME:PROJECT and wl:NAME:RUNTIME:NAME; "note" is the line of a host nobody has read yet, and the entries a connection reads
   without an indexed host hang under connections ("Seen through connections"), one node per connection, read-only. */
function wlTree(listing) {
  const hosts = [...(listing.hosts || [])];
  for (const w of listing.workloads || []) if (w.source !== 'api' && w.host && !hosts.some((h) => h.name === w.host)) hosts.push({ name: w.host, runtimes: [] });      // a host the index does not list still shows its own
  hosts.sort((a, b) => String(a.name).localeCompare(String(b.name)));
  const known = new Set(hosts.map((h) => h.name));
  const seen = new Set();
  const mk = (id, kind, label, data = {}, children = []) => {
    let uid = id;
    for (let n = 2; seen.has(uid); n++) uid = `${id}#${n}`;             // two guests with one name stay two nodes
    seen.add(uid);
    return { id: uid, kind, label, data, children };
  };
  const byHost = new Map(hosts.map((h) => [h.name, []]));
  const loose = new Map();                                              // connection name → entries
  for (const w of listing.workloads || []) {
    if (byHost.has(w.host)) byHost.get(w.host).push(w);
    else if (w.source === 'api' || !w.host) {
      const c = (w.api && w.api.connection) || w.managed_by || 'a connection';
      loose.set(c, [...(loose.get(c) || []), w]);
    }
  }
  const leaf = (h, w) => mk(`wl:${h}:${w.runtime}:${w.name}`, 'workload', w.runtime === 'proxmox' && w.vmid != null ? `${w.vmid} ${w.name}` : String(w.name), { w, readOnly: w.source === 'api' });
  const hostNode = (h) => {
    const all = byHost.get(h.name);
    if (!h.containers_read_at && !h.measured_at && !all.length) return mk(`host:${h.name}`, 'host', h.name, { host: h }, [mk(`note:${h.name}`, 'note', 'not read yet: scan it', { host: h.name })]);
    const pve = new Set(all.filter((w) => w.runtime === 'proxmox').map((w) => String(w.vmid)));
    const mine = h.proxmox ? all.filter((w) => !(w.runtime === 'lxc' && pve.has(String(w.name)))) : all;      // pct guests are read as lxc too: the proxmox branch shows them
    const rts = WL_RUNTIMES.filter((r) => ((h.runtimes || []).includes(r) && !(h.proxmox && r === 'lxc')) || mine.some((w) => w.runtime === r));      // a node ships lxc-ls, but its containers are the proxmox branch's
    return mk(`host:${h.name}`, 'host', h.name, { host: h }, rts.map((r) => {
      const ws = mine.filter((w) => w.runtime === r).sort((a, b) => String(a.name).localeCompare(String(b.name), undefined, { numeric: true }));
      const stacks = [...new Set(ws.filter((w) => w.stack).map((w) => w.stack))].sort();
      const kids = [...stacks.map((s) => {
        const items = ws.filter((w) => w.stack === s);
        return mk(`stack:${h.name}:${r}:${s}`, 'stack', s, { host: h.name, runtime: r, items }, items.map((w) => leaf(h.name, w)));
      }), ...ws.filter((w) => !w.stack).map((w) => leaf(h.name, w))];
      return mk(`rt:${h.name}:${r}`, 'runtime', r, { host: h.name, runtime: r, count: ws.length }, kids);
    }));
  };
  const kids = hosts.map(hostNode);
  if (loose.size) {
    kids.push(mk('connections', 'connections', 'Seen through connections', { readOnly: true }, [...loose].sort(([a], [b]) => a.localeCompare(b)).map(([c, ws]) =>
      mk(`conn:${c}`, 'connections', c, { readOnly: true, connection: c }, ws.map((w) => leaf(c, w))))));
  }
  return mk('fleet', 'fleet', 'Fleet', { hosts: hosts.length, workloads: (listing.workloads || []).length }, kids);
}

/* A tidy tree, one column per depth (240 px) and 44 px for each leaf; a parent sits in the middle of its children, and a folded node counts
   as a leaf. Returns Map(id → {x, y}) of the nodes drawn, y being the top of the card. */
function wlLayout(root, folded = new Set()) {
  const pos = new Map();
  let row = 0;
  const walk = (n, depth) => {
    const kids = folded.has(n.id) ? [] : n.children;
    let y;
    if (!kids.length) y = WL_ROW * row++;
    else { const ys = kids.map((k) => walk(k, depth + 1)); y = (ys[0] + ys[ys.length - 1]) / 2; }
    pos.set(n.id, { x: depth * WL_COL, y });
    return y;
  };
  walk(root, 0);
  return pos;
}

/* id → {node, parent, depth} for the whole tree, folded or not */
function wlIndex(root) {
  const out = new Map();
  const walk = (n, parent, depth) => { out.set(n.id, { node: n, parent, depth }); n.children.forEach((k) => walk(k, n, depth + 1)); };
  walk(root, null, 0);
  return out;
}

const wlStateClass = (s) => (/^(running|up|active|online)\b/i.test(s || '') ? 'up' : /^(failed|dead|error|crashed|unhealthy)/i.test(s || '') ? 'bad'
  : /^(exited|stopped|shut|paused|created|off|inactive|frozen)/i.test(s || '') ? 'down' : '');

/* what the filter looks at: name, host, runtime and state of a workload; the label, host and runtime of the rest */
function wlHaystack(n) {
  const d = n.data;
  if (n.kind === 'workload') return [d.w.name, d.w.vmid, d.w.host, d.w.runtime, d.w.state, d.w.stack].join('\n');
  if (n.kind === 'stack') return [n.label, d.host, d.runtime].join('\n');
  return [n.label, d.host && d.host.name ? d.host.name : d.host, d.runtime].join('\n');
}
/* the ids that stay lit under a filter: each match and its ancestors; null when nothing is typed */
function wlLit(index, q) {
  const s = String(q || '').trim().toLowerCase();
  if (!s) return null;
  const lit = new Set();
  for (const [id, { node }] of index) {
    if (node.kind === 'fleet' || !wlHaystack(node).toLowerCase().includes(s)) continue;
    for (let at = index.get(id); at; at = at.parent && index.get(at.parent.id)) lit.add(at.node.id);
  }
  return lit;
}

/* ── what the person sees ─────────────────────────────────────────── */
/* the folded set as drawn: a filter opens the folds above its matches so they can be seen */
function wlOpenSet() {
  const lit = wlLit(WL.index, WL.q);
  if (!lit) return WL.folded;
  const open = new Set(WL.folded);
  lit.forEach((id) => { if (!WL.pinned.has(id) && WL.index.get(id).node.children.some((k) => lit.has(k.id))) open.delete(id); });
  return open;
}
function wlVisible(folded) {
  const out = [];
  const walk = (n) => { out.push(n); if (!folded.has(n.id)) n.children.forEach(walk); };
  walk(WL.root);
  return out;
}
function wlSub(n) {
  const d = n.data;
  if (n.kind === 'workload') return d.w.state || '';
  if (n.kind === 'runtime') return d.count ? String(d.count) : 'empty';
  if (n.kind === 'stack') return `${d.items.filter((w) => wlStateClass(w.state) === 'up').length}/${d.items.length} running`;
  if (n.kind === 'host') return d.host.proxmox ? 'Proxmox VE' : '';
  return '';
}

function wlDraw() {
  const folded = wlOpenSet(), pos = wlLayout(WL.root, folded), vis = wlVisible(folded), lit = wlLit(WL.index, WL.q);
  if (!pos.has(WL.focus)) WL.focus = WL.root.id;
  const nodes = vis.map((n) => {
    const p = pos.get(n.id), { depth } = WL.index.get(n.id), has = n.children.length > 0, sub = wlSub(n);
    const card = el('div', { role: 'treeitem', class: `wl-node k-${n.kind}${n.data.readOnly ? ' readonly' : ''}${lit && !lit.has(n.id) ? ' dim' : ''}`, 'data-id': n.id,
      'aria-level': String(depth + 1), 'aria-selected': String(n.id === WL.sel), tabindex: n.id === WL.focus ? '0' : '-1', style: `left:${p.x}px;top:${p.y}px`, title: `${n.label}${sub ? `: ${sub}` : ''}` });
    if (has) card.setAttribute('aria-expanded', String(!folded.has(n.id)));
    if (n.kind === 'workload') card.append(el('span', { class: `wl-dot ${wlStateClass(n.data.w.state)}`, 'aria-hidden': 'true' }));
    card.append(text('span', n.label, 'wl-lbl'));
    if (sub) card.append(text('span', sub, 'wl-sub'));
    if (has) card.append(el('button', { type: 'button', class: 'wl-fold', tabindex: '-1', 'aria-hidden': 'true', 'data-fold': n.id }, folded.has(n.id) ? '▸' : '▾'));
    return card;
  });
  const NS = 'http://www.w3.org/2000/svg';
  const edges = [];
  vis.forEach((n) => {
    if (folded.has(n.id)) return;
    const a = pos.get(n.id);
    n.children.forEach((k) => {
      const b = pos.get(k.id), x1 = a.x + WL_W, y1 = a.y + WL_H / 2, x2 = b.x, y2 = b.y + WL_H / 2, mx = (x1 + x2) / 2;
      const path = document.createElementNS(NS, 'path');
      path.setAttribute('d', `M${x1} ${y1} C${mx} ${y1} ${mx} ${y2} ${x2} ${y2}`);
      if (lit && !lit.has(k.id)) path.setAttribute('class', 'dim');
      edges.push(path);
    });
  });
  $('#wl-nodes').replaceChildren(...nodes);
  $('#wl-edges').replaceChildren(...edges);
  const hit = lit ? [...lit].filter((id) => WL.index.get(id).node.kind === 'workload').length : null;
  $('#wl-count').textContent = hit == null ? `${WL.index.size - 1} nodes` : `${hit} workload${hit === 1 ? '' : 's'} match`;
  WL.bounds = { x1: 0, y1: 0, x2: Math.max(...[...pos.values()].map((p) => p.x)) + WL_W, y2: Math.max(...[...pos.values()].map((p) => p.y)) + WL_H };
}

function wlPaint(v) {
  $('#wl-world').style.transform = `translate(${v.x}px, ${v.y}px) scale(${v.k})`;
  const c = $('#wl-canvas'), g = 24 * v.k;
  c.style.backgroundSize = `${g}px ${g}px`;
  c.style.backgroundPosition = `${v.x}px ${v.y}px`;
  $('#wl-pct').textContent = `${Math.round(v.k * 100)}%`;
}
const wlFit = () => WL.cv.fit(WL.bounds, { most: 1, least: 0.3, centre: false });

/* ── fold, focus, select, and the URL ─────────────────────────────── */
function wlHashSync() {
  const folded = [...WL.folded].filter((id) => WL.index.has(id)).join('|');
  sfReplaceHash(sfFormatHash([], { folded: folded || '-', q: WL.q.trim(), sel: WL.sel }));
}
function wlFromHash() {
  const p = sfParseHash().q;
  WL.q = p.get('q') || '';
  WL.sel = WL.index.has(p.get('sel')) ? p.get('sel') : '';
  if (p.has('folded')) WL.folded = new Set(p.get('folded') === '-' ? [] : p.get('folded').split('|'));
  else WL.folded = new Set((WL.listing.hosts || []).length > WL_MANY_HOSTS ? WL.root.children.filter((n) => n.kind === 'host').map((n) => n.id) : []);
  $('#wl-q').value = WL.q;
}
function wlFold(id, fold) {
  const n = WL.index.get(id) && WL.index.get(id).node;
  if (!n || !n.children.length) return;
  if (fold) { WL.folded.add(id); WL.pinned.add(id); } else { WL.folded.delete(id); WL.pinned.delete(id); }          // a fold the person makes beats the filter's opening
  wlDraw(); wlFocus(WL.focus); wlHashSync();
}
function wlFocus(id) {
  WL.focus = id;
  const card = $('#wl-nodes').querySelector(`[data-id="${CSS.escape(id)}"]`);
  if (!card) return;
  $('#wl-nodes').querySelectorAll('[role=treeitem]').forEach((c) => { c.tabIndex = c === card ? 0 : -1; });
  card.focus({ preventScroll: true });
  const a = card.getBoundingClientRect(), b = $('#wl-canvas').getBoundingClientRect();
  if (a.left < b.left || a.right > b.right || a.top < b.top || a.bottom > b.bottom) {          // keep the focused card on screen
    const v = WL.cv.view, left = parseFloat(card.style.left), top = parseFloat(card.style.top);
    WL.cv.centerOn(left + WL_W / 2, top + WL_H / 2, v.k);
  }
}
function wlSelect(id) {
  WL.sel = WL.index.has(id) ? id : '';
  let open = false;           // a card inside folded parents would not exist to see or focus: unfold the way to it
  for (let p = WL.sel && WL.index.get(WL.sel).parent; p; p = WL.index.get(p.id).parent) {
    if (WL.folded.delete(p.id)) open = true;
    WL.pinned.delete(p.id);
  }
  if (open) { wlDraw(); wlFocus(WL.sel); }
  $('#wl-nodes').querySelectorAll('[role=treeitem]').forEach((c) => c.setAttribute('aria-selected', String(c.dataset.id === WL.sel)));
  wlPanel();
  wlHashSync();
}
function wlKey(ev) {
  const card = ev.target.closest && ev.target.closest('[role=treeitem]');
  if (!card || ev.ctrlKey || ev.metaKey || ev.altKey) return;
  const folded = wlOpenSet(), vis = wlVisible(folded), at = vis.findIndex((n) => n.id === card.dataset.id), n = vis[at], info = WL.index.get(n.id);
  const to = (m) => { ev.preventDefault(); if (m) wlFocus(m.id); };
  if (ev.key === 'ArrowDown') to(vis[at + 1]);
  else if (ev.key === 'ArrowUp') to(vis[at - 1]);
  else if (ev.key === 'ArrowRight') {
    ev.preventDefault();
    if (n.children.length && folded.has(n.id)) wlFold(n.id, false); else if (n.children.length) wlFocus(n.children[0].id);
  } else if (ev.key === 'ArrowLeft') {
    ev.preventDefault();
    if (n.children.length && !folded.has(n.id)) wlFold(n.id, true); else if (info.parent) wlFocus(info.parent.id);
  } else if (ev.key === 'Enter') { ev.preventDefault(); if (n.kind === 'note') location.href = wlScanHref(n.data.host); else wlSelect(n.id); }
  else if (ev.key === '+' && (n.kind === 'host' || n.kind === 'runtime')) { ev.preventDefault(); wlNew(n); }
}
const wlScanHref = (host) => `/#/topo?host=${encodeURIComponent(host)}`;
function wlNew(n) { WL.onNew({ host: n.kind === 'host' ? n.data.host.name : n.data.host, runtime: n.kind === 'runtime' ? n.data.runtime : '' }); }

/* ── the panel ────────────────────────────────────────────────────── */
const wlAny = (x) => (x && typeof x === 'object' ? Object.values(x).filter((v) => v != null && v !== '' && typeof v !== 'object').join(' ') : String(x));
const wlHostOf = (name) => (WL.listing.hosts || []).find((h) => h.name === name);
const wlStep = (type, host, params) => ({ type, host, params });

/* the actions of one workload as {label, step, danger}, by runtime. Steps carry only the fields that identify the target: the wizard fills the rest */
function wlActions(w) {
  const { host, runtime: rt, name } = w, act = (label, action) => ({ label, step: wlStep('workload-action', host, { runtime: rt, name, action }) });
  const rm = (type, runtime = rt) => ({ label: 'Remove…', danger: true, step: wlStep(type, host, { runtime, name }) });
  if (rt === 'docker' || rt === 'podman') {
    return [act('Start', 'start'), act('Stop', 'stop'), act('Restart', 'restart'),
      ...(w.stack ? [{ label: 'Update images', step: wlStep('image-update', host, { runtime: rt, stack: w.stack }) }] : []), rm('workload-remove')];
  }
  if (rt === 'libvirt') {
    return [act('Start', 'start'), act('Stop', 'stop'), act('Force off', 'force-off'), act('Snapshot', 'snapshot'),
      { label: 'Edit…', step: wlStep('vm-edit', host, { name }) }, { label: 'Snapshots…', step: wlStep('vm-snapshot', host, { name }) }, rm('workload-remove')];
  }
  if (rt === 'incus') return [act('Start', 'start'), act('Stop', 'stop'), act('Restart', 'restart'), act('Force off', 'force-off'), rm('workload-remove')];
  if (rt === 'lxc') return [act('Start', 'start'), act('Stop', 'stop'), act('Restart', 'restart'), act('Force off', 'force-off'), act('Snapshot', 'snapshot'), rm('managed-workload-remove')];
  if (rt === 'proxmox') {
    const kind = w.kind === 'vm' ? 'qemu' : 'lxc', pve = (label, action) => ({ label, step: wlStep('pve-action', host, { kind, vmid: String(w.vmid), name, action }) });
    return [pve('Start', 'start'), pve('Shut down', 'shutdown'), pve('Stop', 'stop'), pve('Reboot', 'reboot'), pve('Snapshot', 'snapshot'),
      { label: 'Remove…', danger: true, step: wlStep('pve-remove', host, { kind, vmid: String(w.vmid), name }) }];
  }
  return [];
}

function wlButtons(list) {
  if (!can('plans.edit')) return text('p', 'Your account may look at workloads but not change them.', 'muted small');
  return el('div', { class: 'wl-actions' }, ...list.map((a) => button(a.label, () => WL.onAction(a.step), `btn sm${a.danger ? ' danger' : ''}`)));
}
function wlDl(rows) {
  return el('dl', {}, ...rows.filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && !v.length)).flatMap(([k, v]) => [text('dt', k), el('dd', {}, ...(Array.isArray(v) ? [el('ul', {}, ...v.map((x) => text('li', wlAny(x))))] : [String(v)]))]));
}
function wlReading(h) {
  if (!h) return [];
  return [['Read', h.containers_read_at ? fmtAgo(h.containers_read_at) : 'never'], ['Measured', h.measured_at ? `${fmtAgo(h.measured_at)}${h.measure_stale ? ' (old)' : ''}` : 'never']];
}
/* what the engine runs with: each value says whether daemon.json sets it or the engine's default holds. Podman has no daemon.json, so it is not marked. */
function wlEngineRows(runtime, s) {
  if (!s) return [];
  if (s.daemon_json_read === undefined && !s.storage_driver) return [['Engine settings', 'not read yet: scan this host again']];
  const dj = s.daemon_json || {}, docker = runtime === 'docker';
  const mark = (key, v) => (v == null || v === '' ? null : docker && s.daemon_json_read ? `${v} (${key in dj ? 'set in daemon.json' : 'default'})` : v);
  const opts = dj['log-opts'] && Object.entries(dj['log-opts']).map(([k, v]) => `${k}=${v}`).join(', ');
  const mirrors = (s.registry_mirrors || []).join(', ');
  return [['Data root', mark('data-root', s.root_dir)], ['Storage driver', mark('storage-driver', s.storage_driver)], ['Log driver', mark('log-driver', s.log_driver)],
    ['Log options', opts ? `${opts} (set in daemon.json)` : docker && s.daemon_json_read ? 'none (default)' : null],
    ...(docker ? [['Live restore', mark('live-restore', s.live_restore == null ? null : s.live_restore ? 'on' : 'off')], ['Registry mirrors', mirrors ? mark('registry-mirrors', mirrors) : docker && s.daemon_json_read ? 'none (default)' : null]] : []),
    ['Cgroup driver', s.cgroup_driver],
    ...(docker && !s.daemon_json_read ? [['daemon.json', 'not read: the scan user cannot open it, or it is over 64 KiB']] : []),
    ...(s.daemon_json_error ? [['daemon.json', `could not be used: ${s.daemon_json_error}`]] : [])];
}
const wlLink = (href, label) => el('a', { class: 'btn sm', href }, label);

function wlPanel() {
  const n = WL.sel && WL.index.get(WL.sel) ? WL.index.get(WL.sel).node : null, p = $('#wl-panel'), d = n && n.data;
  if (!n) { p.replaceChildren(text('h2', 'Nothing selected'), text('p', 'Pick a host, a runtime or a workload to see what the last scan read and what can be done with it. Arrow keys move, Enter opens.', 'muted')); return; }
  const out = [text('h2', n.label)];
  if (n.kind === 'fleet') out.push(wlDl([['Hosts', d.hosts], ['Workloads', d.workloads]]));
  else if (n.kind === 'host') {
    const h = d.host;
    out.push(wlDl([['Runtimes', (h.runtimes || []).join(', ') || 'none found'], ['Engine', h.engine], ...wlReading(h)]));
    if (h.measure_stale) out.push(text('p', 'The measurement of this host is old: scan it again for a current picture.', 'wl-warn'));
    if (can('plans.edit')) out.push(el('div', { class: 'wl-actions' }, button('+ New', () => WL.onNew({ host: h.name, runtime: '' }), 'btn sm pri'), ...(h.runtimes || []).map((r) => button(`+ New ${r}`, () => WL.onNew({ host: h.name, runtime: r }), 'btn sm'))));
    out.push(wlLink(wlScanHref(h.name), 'Open host'));
  } else if (n.kind === 'runtime') {
    out.push(wlDl([['Host', d.host], ['Workloads', d.count], ...wlReading(wlHostOf(d.host)),
      ...(d.runtime === 'docker' || d.runtime === 'podman' ? wlEngineRows(d.runtime, (wlHostOf(d.host) || {}).engine_settings) : [])]));
    // Podman keeps its storage in storage.conf, which this version only reads: no edit button for it
    if (can('plans.edit')) out.push(el('div', { class: 'wl-actions' }, button(`+ New ${d.runtime}`, () => WL.onNew({ host: d.host, runtime: d.runtime }), 'btn sm pri'),
      ...(d.runtime === 'docker' ? [button('Edit engine settings…', () => WL.onAction(wlStep('docker-daemon', d.host, {})), 'btn sm')] : [])));
  } else if (n.kind === 'stack') {
    out.push(wlDl([['Compose project', n.label], ['Host', d.host], ['Containers', d.items.map((w) => `${w.name}: ${w.state || '?'}`)]]));
    const warn = d.runtime !== 'proxmox' && wlManagedWarn(d.items);
    if (warn) out.push(warn);
    out.push(wlButtons([{ label: 'Update images', step: wlStep('image-update', d.host, { runtime: d.runtime, stack: n.label }) }]));
  } else if (n.kind === 'note') {
    out.push(text('p', 'Nothing has read this host yet, so there is nothing to draw.', 'muted'), wlLink(wlScanHref(d.host), 'Scan it'));
  } else if (n.kind === 'connections') {
    out.push(text('p', 'These come from a connection (an API), not from a host this controller scans. They are shown here and cannot be changed from this page.', 'muted'));
  } else wlWorkloadPanel(n, out);
  p.replaceChildren(...out);
}
function wlManagedWarn(ws) {
  const m = ws.map((w) => w.managed).find((x) => x && x.level !== 'ok');
  return m ? text('p', `Managed by ${m.by} (${m.how}): a change made here can be undone by it, or fight it. Change it there, or adopt it first.`, 'wl-warn') : null;
}
function wlWorkloadPanel(n, out) {
  const w = n.data.w, h = wlHostOf(w.host), m = w.managed;
  out.push(wlDl([['Runtime', `${w.runtime} · ${w.kind || ''}`], ['Host', w.host], ['State', w.state], ['Compose project', w.stack], ['VMID', w.vmid], ['Image', w.image],
    ['vCPUs', w.vcpus], ['Memory', w.memory_mib ? `${w.memory_mib} MiB` : ''], ['Mounts', (w.mounts || []).map((x) => (typeof x === 'object' ? `${x.source || '?'} → ${x.dest || '?'}${x.on ? ` (on ${wlAny(x.on)})` : ''}` : x))],
    ['Networks', (w.networks || []).map(wlAny)], ['Ports', (w.ports || []).map(wlAny)], ['Managed by', m ? `${m.by}: ${m.how}` : w.managed_by],
    ...(w.source === 'api' ? [['Read through', (w.api && w.api.connection) || w.managed_by]] : wlReading(h))]));
  if ((w.findings || []).length) out.push(text('h3', 'Findings'), el('ul', {}, ...w.findings.map((f) => text('li', f))));
  if (n.data.readOnly) {
    out.push(text('p', 'Seen only through a connection: this page reads it but cannot change it, because the steps need SSH to the host. Change it where the connection manages it.', 'muted'));
    if (h) {
      const own = [...WL.index.values()].find(({ node }) => node.kind === 'workload' && !node.data.readOnly && node.data.w.host === h.name && node.data.w.runtime === 'proxmox' && String(node.data.w.vmid) === String(w.vmid));
      const to = own ? own.node.id : `host:${h.name}`;
      out.push(button(own ? `Go to ${own.node.label} on ${h.name}` : `Go to ${h.name}`, () => { wlFocus(to); wlSelect(to); }, 'btn sm'));
    }
    return;
  }
  const warn = w.runtime !== 'proxmox' && wlManagedWarn([w]);
  if (warn) out.push(warn);
  out.push(wlButtons(wlActions(w)));
}

/* ── boot ─────────────────────────────────────────────────────────── */
function wlLoad(listing) {
  listing.hosts = (listing.hosts || []).map((h) => ({ ...h, name: h.name ?? h.host }));      // the API names a host's entry "host"; the tree and panel read "name"
  WL.listing = listing;
  WL.root = wlTree(listing);
  WL.index = wlIndex(WL.root);
  wlFromHash();
  if (WL.sel) WL.focus = WL.sel;
  wlDraw();
  wlPanel();
  if (!WL.fitted) { WL.fitted = true; wlFit(); }
}

function wlWire() {
  const canvas = $('#wl-canvas');
  WL.cv = sfCanvas(canvas, { view: WL.view, min: 0.2, max: 2.5, apply: wlPaint, ignore: '.wl-node', pannable: (t) => !t.closest('.wl-node') });
  $('#wl-nodes').addEventListener('keydown', wlKey);
  $('#wl-nodes').addEventListener('click', (ev) => {
    const card = ev.target.closest('[role=treeitem]');
    if (!card) return;
    const f = ev.target.closest('[data-fold]');
    if (card.dataset.id.startsWith('note:') && WL.index.get(card.dataset.id)) { location.href = wlScanHref(WL.index.get(card.dataset.id).node.data.host); return; }
    wlFocus(card.dataset.id);
    if (f) wlFold(f.dataset.fold, !wlOpenSet().has(f.dataset.fold)); else wlSelect(card.dataset.id);
  });
  $('#wl-q').addEventListener('input', (ev) => { WL.q = ev.target.value; WL.pinned.clear(); wlDraw(); wlHashSync(); });
  $('#wl-fold').addEventListener('click', () => { WL.folded = new Set([...WL.index.values()].filter(({ node, parent }) => parent && node.children.length).map(({ node }) => node.id)); WL.pinned.clear(); wlDraw(); wlFit(); wlHashSync(); });
  $('#wl-unfold').addEventListener('click', () => { WL.folded = new Set(); WL.pinned.clear(); wlDraw(); wlFit(); wlHashSync(); });
  $('#wl-in').addEventListener('click', () => WL.cv.zoomBy(1.25));
  $('#wl-out').addEventListener('click', () => WL.cv.zoomBy(1 / 1.25));
  $('#wl-fit').addEventListener('click', wlFit);
  window.addEventListener('hashchange', () => { if (WL.listing) { WL.pinned.clear(); wlFromHash(); wlDraw(); wlPanel(); } });
}

(async function wlBoot() {
  const root = $('#wl-root');
  try {
    const me = await getJSON('/api/me');
    setMe(me);
    if (me.site) document.title = `${me.site} · Workloads · StorageForge`;
    if (!can('workloads.view')) { root.replaceChildren(text('p', 'Your account cannot see workloads: it needs the workloads.view permission.', 'st-failed')); return; }
    wlWire();
    $('#wl-nodes').replaceChildren(text('p', 'Loading…', 'muted'));
    wlLoad(await getJSON('/api/workloads'));
  } catch (err) {
    root.replaceChildren(text('p', err.message || 'Could not read the workloads.', 'st-failed'));
  }
}());
