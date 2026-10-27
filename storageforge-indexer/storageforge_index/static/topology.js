'use strict';
/* Topology view: one column layout per host (devices → pools → datasets → mount points → links and exports), drawn
   from the host's storageforge/v1 design, the same document the planner edits. Select a box to edit what only the
   operator knows (tiers, 3-2-1 protection, links, exports) in the side panel; drag one mount point onto another to
   make it the backup target. Save stores the design and the server rebuilds the graph, so the health dots come back
   from the same rules the reports use. Loaded after app.js and uses its helpers. DOM APIs only, never innerHTML. */

const T = { mode: 'topo', docs: new Map(), order: [], sel: null, hover: null, drag: null, error: '' };
const TIERS = ['fast', 'mass', 'remote'];
const SYNC_STATES = ['None', 'Active Sync', 'Rsync Scheduled', 'Lagging', 'Disconnected'];
const SNAP_TOOLS = ['none', 'sanoid', 'zfs-auto-snapshot', 'snapper', 'btrbk', 'timeshift', 'lvm'];
const BACKUP_ENC = ['none', 'restic AES-256', 'borg repokey', 'age X25519', 'ZFS native aes-256-gcm', 'PBS AES-256-GCM'];
const EXPORT_PROTOS = ['NFSv4.2', 'NFSv3', 'SMB3', 'SFTP', 'S3'];
const LINK_KINDS = ['symlink', 'bind', 'hardlink'];
const COLS = ['Physical & network devices', 'Partitions · pools · arrays', 'Subvolumes & datasets', 'Mount points', 'Links & exports'];
const SVG_NS = 'http://www.w3.org/2000/svg';

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'dataset') Object.assign(e.dataset, v);
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  e.append(...kids.flat().filter((k) => k != null && k !== false));
  return e;
}
const fmtDec = (n) => {
  if (!n) return '—';
  const u = ['B', 'kB', 'MB', 'GB', 'TB', 'PB']; let v = Number(n), i = 0;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(i < 3 ? 0 : 1)} ${u[i]}`;
};
const bare = (d) => String(d || '').replace(/^\/dev\//, '');

/* ── loading and saving designs ──────────────────────────────────── */
async function loadDesigns() {
  if (T.mode !== 'topo') return;
  let hosts;
  try { ({ hosts } = await getJSON('/api/planner/hosts')); }
  catch (err) { T.error = err.message; renderTopo(); return; }
  const want = S.host ? hosts.filter((h) => h.host === S.host) : hosts;
  const docs = new Map();
  if (typeof loadAccess === 'function' && !ACCESS.hosts.length) loadAccess();
  if (typeof loadDocker === 'function' && !DK.usage.length) getJSON('/api/docker/usage').then((r) => { DK.usage = r.usage; renderTopo(); }).catch(() => {});
  await Promise.all(want.map(async (h) => {
    const keep = T.docs.get(h.host);
    if (keep && keep.dirty) { docs.set(h.host, keep); return; }      // unsaved edits survive a reload
    try {   // a scanned host: fresh hardware from the scan plus the intent in its saved design
      const r = await getJSON(`/api/planner/design?host=${encodeURIComponent(h.host)}${h.scanned ? '&source=scan' : ''}`);
      docs.set(h.host, { host: h.host, bp: r.blueprint, source: r.source, savedAt: r.saved_at, dirty: false, changed: new Set() });
    } catch (err) { docs.set(h.host, { host: h.host, error: err.message }); }
  }));
  T.docs = docs; T.order = want.map((h) => h.host); T.error = '';
  if (S.host && !want.length) T.error = `${S.host} has no design: it is not scanned and has no saved plan.`;
  if (T.sel && !(T.docs.get(T.sel.host) || {}).bp) T.sel = null;
  renderTopo();
  if (T.sel) renderEditor();
}
const dirtyDocs = () => [...T.docs.values()].filter((d) => d.dirty);
function touched(doc, key) {
  doc.dirty = true; doc.changed.add(key);
  renderTopo(); renderEditor();
}
async function saveDesigns() {
  const btn = $('#savedesigns'); btn.disabled = true;
  try {
    for (const doc of dirtyDocs()) {
      const bp = { ...doc.bp, metadata: { ...doc.bp.metadata, generated: new Date().toISOString().slice(0, 10) } };
      await api('/api/planner/design', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(bp) });
      doc.dirty = false; doc.changed.clear();
    }
    await loadGraph(); await loadDesigns();
  } catch (err) { $('#savemsg').textContent = err.message; $('#savemsg').className = 'st-failed'; }
  finally { btn.disabled = false; }
}
function discardDesigns() {
  for (const doc of dirtyDocs()) T.docs.delete(doc.host);
  loadDesigns();
}
function updateSavebar() {
  const n = dirtyDocs();
  $('#savebar').hidden = T.mode !== 'topo' || !n.length;
  const edits = n.reduce((a, d) => a + d.changed.size, 0);
  $('#savemsg').className = 'muted';
  $('#savemsg').textContent = `${edits} unsaved edit${edits === 1 ? '' : 's'} on ${n.map((d) => d.host).join(', ')}`;
}

/* ── a design as columns of boxes and the edges between them ─────── */
function protRow(doc, target, create) {
  const bp = doc.bp; bp.protection = bp.protection || [];
  let r = bp.protection.find((x) => x.path === target);
  if (!r && create) {
    r = { node: 'path:' + target, dataset: target, path: target, ephemeral: false };
    bp.protection.push(r);
  }
  if (r) {
    r.sync = { state: 'None', ...(r.sync || {}) };
    r.snapshots = { enabled: false, tool: 'none', policy: '', count: 0, overhead: 0, ...(r.snapshots || {}) };
    r.backup = { target: null, enc: 'none', ratio: 1, last: null, offsite: false, ...(r.backup || {}) };
  }
  return r;
}
function protText(r) {
  if (!r) return '';
  if (r.ephemeral) return 'excluded from 3-2-1';
  const bits = [];
  if (r.snapshots && r.snapshots.enabled) bits.push(`snap ${r.snapshots.tool}`);
  if (r.sync && r.sync.state !== 'None') bits.push(`sync ${(r.sync.target || r.sync.state).replace(/^.*(→|->)\s*/, '→ ')}`);
  if (r.backup && r.backup.target) bits.push(`backup ${r.backup.target.replace(/^.*(→|->)\s*/, '→ ')}`);
  return bits.join(' · ') || 'no snapshots, sync or backup';
}
function containing(path, mounts) {
  let best = null;
  for (const t of mounts) if ((path === t || path.startsWith(t === '/' ? '/' : t + '/')) && (!best || t.length > best.length)) best = t;
  return best;
}
function model(doc) {
  const bp = doc.bp;
  const nodes = new Map(), edges = [];
  const put = (key, col, kind, title, sub, tier, extra = {}) => {
    if (!nodes.has(key)) nodes.set(key, { key, col, kind, title, sub, tier, ...extra });
    return key;
  };
  const link = (a, b, cls = '') => { if (a && b && a !== b) edges.push([a, b, cls]); };
  const mountAt = (target, from, fs, opts, tier) => {
    if (!target || !String(target).startsWith('/')) return;
    const o = (opts || []).filter((x) => x && !/^(subvol|subvolid|rw$|relatime)/.test(x)).slice(0, 2).join(',');
    put('mnt:' + target, 3, 'mount', target, [fs, o].filter(Boolean).join(' · '), tier, { target });
    link(from, 'mnt:' + target);
  };
  const pools = bp.pools || [];
  const poolOf = new Map();
  for (const p of pools) for (const m of [...(p.members || []), ...(p.log || []), ...(p.cache || [])]) poolOf.set(bare(m), p.name);
  const cacheOf = new Set(pools.flatMap((p) => [...(p.log || []), ...(p.cache || [])].map(bare)));

  for (const tier of TIERS) {
    for (const d of (bp.devices || []).filter((x) => (x.tier || 'mass') === tier)) {
      const dev = bare(d.dev), dk = put('disk:' + dev, 0, 'disk', '/dev/' + dev,
        `${(d.model || 'unknown').split(' (')[0]} · ${fmtDec(d.sizeBytes)}`, tier, { ref: d, group: tier });
      if (d.member || poolOf.has(dev)) link(dk, 'pool:' + (d.member || poolOf.get(dev)), cacheOf.has(dev) ? 'cache' : '');
      for (const p of d.partitions || []) {
        if (p.member || poolOf.has(p.id)) { link(dk, 'pool:' + (p.member || poolOf.get(p.id)), cacheOf.has(p.id) ? 'cache' : ''); continue; }
        const pk = put('part:' + p.id, 1, 'part', p.id, `${p.fs || 'none'} · ${fmtBytes(p.sizeBytes)}`, tier, { ref: p, group: tier });
        link(dk, pk);
        for (const sv of p.subvolumes || []) {
          const sk = put(`sv:${p.id}/${sv.name}`, 2, 'subvol', sv.name, `btrfs subvol · ${p.label || p.id}`, tier, { ref: sv });
          link(pk, sk); mountAt(sv.mount, sk, 'btrfs', p.options, tier);
        }
        mountAt(p.mount, pk, p.fs, p.options, tier);
      }
    }
    if (tier === 'remote') for (const r of bp.remotes || []) {
      const from = shareSource(doc, r);
      const rk = put('rem:' + (r.name || r.endpoint), 0, 'remote', r.name || r.endpoint,
                     `${r.protocol || ''} via ${r.via || 'network'}${from ? ` · from ${from.host}` : ''}`,
                     'remote', { ref: r, group: 'remote', bad: r.status && r.status !== 'connected' });
      mountAt(r.mount, rk, r.protocol, r.options, 'remote');
    }
    for (const p of pools.filter((x) => (x.tier || 'mass') === tier)) {
      const kind = { zfs: 'zfs', btrfs: 'btrfs', mdadm: 'mdadm', lvm: 'LVM' }[p.type] || p.type;
      const legs = (p.members || []).length;
      const vgOnly = p.type === 'lvm' && !p.lv;
      const pk = put('pool:' + p.name, 1, 'pool', p.lv ? `${p.vg}/${p.lv}` : p.name,
                     (vgOnly ? `LVM volume group · ${legs} PV${legs === 1 ? '' : 's'} · ${(p.datasets || []).length} LVs`
                       : `${kind} ${p.level || ''}${legs > 1 ? ` · ${legs} ${p.type === 'lvm' ? 'legs' : 'members'}` : ''}`)
                     + `${p.usableBytes ? ' · ' + fmtBytes(p.usableBytes) + ' usable' : ''}${(p.levelSource || '').startsWith('inferred') ? ' · level inferred' : ''}`,
                     tier, { ref: p, group: tier });
      mountAt(p.mount, pk, p.fs || p.type, p.options, tier);
      for (const ds of p.datasets || []) {
        const dk = put(`ds:${p.name}/${ds.name}`, 2, 'dataset', `${p.name}/${ds.name}`,
                       p.type === 'lvm' ? `logical volume · ${ds.fs || 'no fs'}${ds.sizeBytes ? ' · ' + fmtBytes(ds.sizeBytes) : ''}`
                         : [ds.recordsize && 'rs=' + ds.recordsize, ds.compression].filter(Boolean).join(' · ') || 'dataset', tier, { ref: ds });
        link(pk, dk); mountAt(ds.mount, dk, p.type === 'lvm' ? ds.fs : 'zfs', [], tier);
      }
    }
  }
  const mounts = [...nodes.values()].filter((n) => n.kind === 'mount').map((n) => n.target);
  (bp.links || []).forEach((l, i) => {
    const k = put('link:' + i, 4, 'link', l.path, `${l.kind} → ${l.target}`, '', { ref: l, i, bad: l.health === 'crit' });
    const at = containing(String(l.target || ''), mounts);
    if (at) link('mnt:' + at, k);
  });
  (bp.exports || []).forEach((e, i) => {
    const k = put('exp:' + i, 4, 'export', `${e.protocol || e.proto} · ${e.name}`, `${e.path} · ${e.clients || 'no clients'}`, '', { ref: e, i, group: 'exports' });
    const at = containing(String(e.path || ''), mounts);
    if (at) link('mnt:' + at, k);
  });
  for (const n of nodes.values()) if (n.kind === 'mount') {
    const r = protRow(doc, n.target, false);
    n.prot = protText(r);
    n.containers = typeof containersOn === 'function' ? containersOn(doc.host, n.target, mounts) : [];
    const names = [...new Set(n.containers.map((u) => u.container))];
    if (names.length) n.prot = (n.prot ? n.prot + ' · ' : '') + `${names.length} container${names.length === 1 ? '' : 's'}`;
    n.health = (S.byId.get(`mnt:${doc.host}:${n.target}`) || {}).health;
  }
  return { nodes, edges: edges.filter(([a, b]) => nodes.has(a) && nodes.has(b)) };
}

/* ── rendering ───────────────────────────────────────────────────── */
function renderTopo() {
  updateSavebar();
  const box = $('#topo');
  if (T.mode !== 'topo') return;
  const keepScroll = box.scrollTop;
  const blocks = [el('div', { class: 'tlegend' },
    el('span', {}, el('i', { class: 'sw fast' }), 'fast tier'), el('span', {}, el('i', { class: 'sw mass' }), 'mass tier'),
    el('span', {}, el('i', { class: 'sw remote' }), 'remote / mesh'), el('span', {}, 'dashed edge = SLOG / L2ARC'),
    el('span', {}, el('i', { class: 'dot protected' }), el('i', { class: 'dot local-only' }), el('i', { class: 'dot broken' }), 'mount health'),
    el('span', { class: 'hint' }, 'Select a box to edit it. Drag a mount point onto another to back it up there.'))];
  if (T.error) blocks.push(el('p', { class: 'st-failed' }, T.error));
  if (!T.order.length && !T.error) blocks.push(el('p', { class: 'muted' }, 'No hosts yet. Scan one from the Scans tab, or plan one in the Planner.'));
  for (const host of T.order) {
    const doc = T.docs.get(host);
    const acc = (typeof ACCESS !== 'undefined' ? ACCESS.hosts : []).find((a) => a.host === host);
    const unreadable = acc && acc.access !== 'capability' ? acc.denied_total || acc.read_errors : 0;
    const head = el('div', { class: 'thead' }, el('h2', {}, host),
      unreadable ? button(`${unreadable} unreadable`, () => showTab('access'), 'badge warn') : null,
      serves(doc) ? el('span', { class: 'badge share', title: 'Shares this host serves, found by the scan' }, serves(doc)) : null,
      plannedShares(doc) ? button(`Deploy ${plannedShares(doc)} share${plannedShares(doc) === 1 ? '' : 's'}`, () => deployShares(doc), 'badge share deploy')
        : designedShares(doc).length ? button('Shares script', () => deployShares(doc), 'badge share deploy') : null,
      el('span', { class: doc.dirty ? 'dirty' : 'muted' }, doc.error ? doc.error : doc.dirty ? 'unsaved edits'
        : doc.source === 'scan' ? (doc.savedAt ? 'latest scan + saved design' : 'latest scan · no saved design yet') : 'saved design'),
      doc.bp ? el('span', { class: 'row' },
        button('+ Link', () => addLink(doc), 'btn ghost sm'), button('+ Export', () => addExport(doc), 'btn ghost sm'),
        el('a', { class: 'btn ghost sm', href: `/planner#topology@${encodeURIComponent(host)}` }, 'Planner')) : null);
    if (!doc.bp) { blocks.push(el('section', { class: 'tblock' }, head)); continue; }
    const m = doc.m = model(doc);
    const cols = COLS.map((h) => el('div', { class: 'tcol' }, el('div', { class: 'eyebrow' }, h)));
    const groupSeen = new Set();
    for (const n of m.nodes.values()) {
      const g = n.group && `${n.col}:${n.group}`;
      if (g && !groupSeen.has(g)) {
        groupSeen.add(g);
        cols[n.col].append(el('div', { class: `tgrp ${n.group}` },
          n.group === 'exports' ? 'Exports' : n.col === 0 ? { fast: 'Fast local', mass: 'Mass local', remote: 'Remote / mesh' }[n.group] : n.group + ' tier'));
      }
      const sel = T.sel && T.sel.host === host && T.sel.key === n.key;
      const card = el('div', {
        class: `tn ${n.tier || ''}${n.bad ? ' bad' : ''}${sel ? ' sel' : ''}${doc.changed.has(n.key) ? ' edited' : ''}${n.kind === 'export' ? ' exp' : ''}`,
        tabindex: '0', role: 'button', draggable: n.kind === 'mount' ? 'true' : null,
        dataset: { node: n.key, host }, 'aria-pressed': sel ? 'true' : 'false',
      }, el('b', {}, n.health ? el('i', { class: `dot ${n.health}`, title: HEALTH_TEXT[n.health] }) : null, n.title),
        n.sub ? el('span', {}, n.sub) : null, n.prot ? el('span', { class: 'prot' }, n.prot) : null);
      cols[n.col].append(card);
    }
    const svg = document.createElementNS(SVG_NS, 'svg'); svg.setAttribute('aria-hidden', 'true');
    const grid = el('div', { class: 'tgrid', dataset: { host } }, svg, ...cols);
    blocks.push(el('section', { class: 'tblock' }, head, el('div', { class: 'twrap' }, grid)));
  }
  box.replaceChildren(...blocks);
  box.scrollTop = keepScroll;
  requestAnimationFrame(drawTopoEdges);
}
/* ── shares: NFS/SMB mounts traced to the host and folder that serve them ── */
function hostIndex() {
  const idx = new Map();
  for (const d of T.docs.values()) {
    if (!d.bp) continue;
    const md = d.bp.metadata || {};
    for (const k of [d.host, d.host.split('.')[0], md.ip]) if (k) idx.set(String(k).toLowerCase(), d.host);
  }
  return idx;
}
function serves(doc) {
  const sc = (doc.bp && doc.bp.exports || []).filter((e) => e.fromScan);
  if (!sc.length) return '';
  const kinds = [...new Set(sc.map((e) => (e.protocol || '').startsWith('SMB') ? 'SMB' : 'NFS'))].sort().join(' + ');
  return `${kinds} server · ${sc.length} share${sc.length === 1 ? '' : 's'}`;
}
const under = (p, root) => root === '/' || p === root || p.startsWith(root + '/');
function shareSource(doc, r) {          // → { host, key: box in the server's block, path }
  const ep = String(r.endpoint || '');
  const smb = ep.startsWith('//');
  const name = smb ? ep.slice(2).split('/')[0] : ep.split(':')[0];
  const host = hostIndex().get(name.toLowerCase());
  const srv = host && host !== doc.host && T.docs.get(host);
  if (!srv || !srv.bp) return null;
  const exps = srv.bp.exports || [];
  let path, i = -1;
  if (smb) {
    const [, share, ...rest] = ep.slice(2).split('/');
    i = exps.findIndex((e) => (e.protocol || '').startsWith('SMB') && String(e.name).toLowerCase() === String(share).toLowerCase());
    if (i < 0) return { host, key: null, path: null };
    path = [exps[i].path, ...rest].join('/').replace(/\/+$/, '') || '/';
  } else {
    path = ep.slice(ep.indexOf(':') + 1) || '/';
    let best = -1;
    exps.forEach((e, j) => { if (!(e.protocol || '').startsWith('SMB') && under(path, e.path) && (best < 0 || e.path.length > exps[best].path.length)) best = j; });
    i = best;
  }
  if (i >= 0) return { host, key: 'exp:' + i, path };
  const mounts = srv.m ? [...srv.m.nodes.values()].filter((n) => n.kind === 'mount').map((n) => n.target) : [];
  const at = containing(path, mounts);
  return { host, key: at ? 'mnt:' + at : null, path };
}
function drawShareLines() {
  const box = $('#topo');
  let svg = box.querySelector(':scope > svg.shares');
  if (!svg) { svg = document.createElementNS(SVG_NS, 'svg'); svg.setAttribute('class', 'shares'); svg.setAttribute('aria-hidden', 'true'); box.prepend(svg); }
  const base = box.getBoundingClientRect();
  const at = (host, key) => box.querySelector(`.tn[data-host="${CSS.escape(host)}"][data-node="${CSS.escape(key)}"]`);
  const paths = [];
  for (const doc of T.docs.values()) {
    if (!doc.bp) continue;
    for (const r of doc.bp.remotes || []) {
      const from = shareSource(doc, r);
      const a = from && from.key && at(from.host, from.key), b = at(doc.host, 'rem:' + (r.name || r.endpoint));
      if (!a || !b) continue;
      const A = a.getBoundingClientRect(), B = b.getBoundingClientRect();
      const x1 = A.right - base.left + box.scrollLeft, y1 = A.top + A.height / 2 - base.top + box.scrollTop;
      const x2 = B.left - base.left + box.scrollLeft, y2 = B.top + B.height / 2 - base.top + box.scrollTop;
      const bend = Math.max(60, Math.abs(y2 - y1) / 3);
      const p = document.createElementNS(SVG_NS, 'path');
      p.setAttribute('class', 'edge share');
      p.dataset.a = `${from.host}|${from.key}`; p.dataset.b = `${doc.host}|rem:${r.name || r.endpoint}`;
      p.setAttribute('d', `M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`);
      const t = document.createElementNS(SVG_NS, 'title'); t.textContent = `${from.host}:${from.path} → ${doc.host}:${r.mount || ''}`;
      p.append(t); paths.push(p);
    }
  }
  svg.setAttribute('width', box.scrollWidth); svg.setAttribute('height', box.scrollHeight);
  svg.replaceChildren(...paths);
}
function drawTopoEdges() {
  drawShareLines();
  for (const grid of document.querySelectorAll('#topo .tgrid')) {
    const doc = T.docs.get(grid.dataset.host); if (!doc || !doc.m) continue;
    const svg = grid.querySelector('svg'), base = grid.getBoundingClientRect();
    const box = (k) => grid.querySelector(`.tn[data-node="${CSS.escape(k)}"]`);
    svg.setAttribute('width', grid.scrollWidth); svg.setAttribute('height', grid.scrollHeight);
    const paths = [];
    for (const [a, b, cls] of doc.m.edges) {
      const ea = box(a), eb = box(b); if (!ea || !eb) continue;
      const A = ea.getBoundingClientRect(), B = eb.getBoundingClientRect();
      const x1 = A.right - base.left, y1 = A.top + A.height / 2 - base.top, x2 = B.left - base.left, y2 = B.top + B.height / 2 - base.top;
      const dx = Math.max(24, (x2 - x1) / 2);
      const p = document.createElementNS(SVG_NS, 'path');
      p.setAttribute('class', `edge ${cls}`); p.dataset.a = a; p.dataset.b = b;
      p.setAttribute('d', `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`);
      paths.push(p);
    }
    svg.replaceChildren(...paths);
  }
}
function chainOf(doc, key) {         // everything upstream and downstream of a box
  const out = new Set([key]);
  for (const dir of [0, 1]) {
    const todo = [key];
    while (todo.length) {
      const k = todo.pop();
      for (const e of doc.m.edges) if (e[dir] === k && !out.has(e[1 - dir])) { out.add(e[1 - dir]); todo.push(e[1 - dir]); }
    }
  }
  return out;
}
function trace(card) {
  const box = $('#topo');
  box.querySelectorAll('.lit').forEach((x) => x.classList.remove('lit'));
  box.querySelectorAll('.tgrid.chain-on').forEach((x) => x.classList.remove('chain-on'));
  if (!card) return;
  const end = `${card.dataset.host}|${card.dataset.node}`;
  box.querySelectorAll('path.share').forEach((p) => { if (p.dataset.a === end || p.dataset.b === end) p.classList.add('lit'); });
  const grid = card.closest('.tgrid'), doc = T.docs.get(card.dataset.host);
  const set = chainOf(doc, card.dataset.node);
  grid.classList.add('chain-on');
  grid.querySelectorAll('.tn').forEach((x) => { if (set.has(x.dataset.node)) x.classList.add('lit'); });
  grid.querySelectorAll('path.edge').forEach((p) => { if (set.has(p.dataset.a) && set.has(p.dataset.b)) p.classList.add('lit'); });
}

/* ── editing ─────────────────────────────────────────────────────── */
function selectBox(host, key) {
  T.sel = { host, key };
  document.querySelectorAll('#topo .tn.sel').forEach((x) => { x.classList.remove('sel'); x.setAttribute('aria-pressed', 'false'); });
  const card = document.querySelector(`#topo .tn[data-host="${CSS.escape(host)}"][data-node="${CSS.escape(key)}"]`);
  if (card) { card.classList.add('sel'); card.setAttribute('aria-pressed', 'true'); }
  showTab('details');
  renderEditor();
}
function field(label, input, cls = '') { return el('label', { class: `field col ${cls}` }, el('span', {}, label), input); }
function choice(values, value, onchange) {
  const s = el('select', { onchange: () => onchange(s.value) }, ...values.map((v) => new Option(v, v)));
  if (value != null && !values.includes(value)) s.append(new Option(value, value));
  s.value = value ?? values[0];
  return s;
}
function entry(value, onchange, attrs = {}) {
  const i = el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', ...attrs, onchange: () => onchange(i.value.trim()) });
  i.value = value ?? '';
  return i;
}
function check(label, value, onchange) {
  const c = el('input', { type: 'checkbox', onchange: () => onchange(c.checked) }); c.checked = !!value;
  return el('label', { class: 'check' }, c, label);
}
function renderEditor() {
  if (T.mode !== 'topo' || !T.sel || S.selected) return;
  const doc = T.docs.get(T.sel.host);
  const n = doc && doc.m && doc.m.nodes.get(T.sel.key);
  if (!n) { T.sel = null; renderSummary(); return; }
  const set = (fn) => (v) => { fn(v); touched(doc, n.key); };
  const kids = [el('div', { class: 'node-head' }, el('span', { class: 'muted' }, `${n.kind} · ${doc.host}`), el('h2', {}, n.title),
    n.health ? pill(n.health) : null)];
  if (n.sub) kids.push(el('p', { class: 'muted mono' }, n.sub));
  const form = el('div', { class: 'stack editor' });

  if (n.kind === 'disk' || n.kind === 'pool') {
    form.append(field('Tier', choice(TIERS, n.ref.tier || 'mass', set((v) => { n.ref.tier = v; }))));
    if (n.kind === 'pool') form.append(field('Encryption', entry(n.ref.encryption, set((v) => { n.ref.encryption = v || null; }), { placeholder: 'e.g. ZFS native aes-256-gcm' })));
    form.append(el('p', { class: 'muted' }, 'Hardware details come from the scan; the tier is yours and survives rescans.'));
  } else if (n.kind === 'mount') {
    const r = protRow(doc, n.target, false);
    if (!r) {
      form.append(el('p', { class: 'muted' }, 'This mount is not tracked for 3-2-1 protection.'),
        el('div', { class: 'row' }, button('Track protection', () => { protRow(doc, n.target, true); touched(doc, n.key); }, 'btn')));
    } else {
      form.append(el('h3', {}, '3-2-1 protection'),
        check('Ephemeral: exclude from 3-2-1', r.ephemeral, set((v) => { r.ephemeral = v; })),
        check('Snapshots', r.snapshots.enabled, set((v) => { r.snapshots.enabled = v; if (v && r.snapshots.tool === 'none') r.snapshots.tool = n.sub.startsWith('zfs') ? 'sanoid' : 'snapper'; })),
        el('div', { class: 'row' },
          field('Tool', choice(SNAP_TOOLS, r.snapshots.tool, set((v) => { r.snapshots.tool = v; }))),
          field('Policy', entry(r.snapshots.policy, set((v) => { r.snapshots.policy = v; }), { placeholder: 'hourly 24 · daily 7' }), 'grow')),
        el('div', { class: 'row' },
          field('Sync', choice(SYNC_STATES, r.sync.state, set((v) => { r.sync.state = v; }))),
          field('Sync target', entry(r.sync.target, set((v) => { r.sync.target = v || undefined; }), { placeholder: 'syncoid → nas-02/media' }), 'grow')),
        field('Backup target', entry(r.backup.target, set((v) => { r.backup.target = v || null; }), { placeholder: 'restic → B2, or drag onto a mount' })),
        el('div', { class: 'row' },
          field('Last validated', entry(r.backup.last, set((v) => { r.backup.last = v || null; }), { type: 'date' })),
          field('Encryption', choice(BACKUP_ENC, r.backup.enc, set((v) => { r.backup.enc = v; })), 'grow')),
        check('Backup is offsite', r.backup.offsite, set((v) => { r.backup.offsite = v; })));
    }
    if (n.containers && n.containers.length) {
      form.append(el('h3', {}, 'Containers using this mount'), el('ul', { class: 'dklist' }, ...n.containers.map((u) =>
        el('li', {}, el('span', {}, el('b', {}, u.container), text('span', ` ${u.state}${u.stack ? ' · ' + u.stack : ''}`, 'muted')),
          el('span', { class: 'mono small' }, `${u.path} → ${u.dest}${u.rw ? '' : ' (read-only)'}`)))));
    }
    form.append(el('div', { class: 'row' },
      button('Move from here…', () => moveFrom(doc.host, n.target), 'btn ghost sm'),
      button('+ Export this', () => addExport(doc, n.target), 'btn ghost sm'),
      button('+ Link into this', () => addLink(doc, n.target), 'btn ghost sm')));
  } else if (n.kind === 'link') {
    const l = n.ref;
    if (l.fromScan) form.append(el('p', { class: 'muted' }, 'Found by the scan. Change it on the host; the next scan picks it up.'));
    else {
      form.append(field('Kind', choice(LINK_KINDS, l.kind, set((v) => { l.kind = v; }))),
        field('Path', entry(l.path, set((v) => { l.path = v; }))), field('Target', entry(l.target, set((v) => { l.target = v; }))),
        el('div', { class: 'row' }, button('Remove link', () => { doc.bp.links.splice(n.i, 1); T.sel = null; touched(doc, 'links'); }, 'btn ghost sm danger')));
    }
  } else if (n.kind === 'export' && n.ref.fromScan && !n.ref.designed) {
    const clients = [...T.docs.values()].flatMap((d) => (d.bp && d.bp.remotes || [])
      .filter((r) => { const f = shareSource(d, r); return f && f.host === doc.host && f.key === n.key; })
      .map((r) => `${d.host}:${r.mount}`));
    form.append(el('p', { class: 'muted' }, `Found by the scan in this host's ${n.ref.protocol === 'SMB' ? 'Samba config' : 'NFS exports'}. Change it on the host; the next scan picks it up.`),
      el('p', {}, el('b', {}, 'Mounted by: '), clients.length ? clients.join(', ') : 'no scanned host'));
  } else if (n.kind === 'export') {
    const e = n.ref;
    form.append(el('div', { class: 'row' },
        field('Protocol', choice(EXPORT_PROTOS, e.protocol || e.proto, set((v) => { e.protocol = v; delete e.proto; }))),
        field('Name', entry(e.name, set((v) => { e.name = v; })), 'grow')),
      field('Path', entry(e.path, set((v) => { e.path = v; }))),
      field('Clients', entry(e.clients, set((v) => { e.clients = v; }), { placeholder: '10.0.0.0/24 or @group' })),
      field('Options', entry(e.options, set((v) => { e.options = v; }), { placeholder: 'rw,sync,no_subtree_check' })),
      mountOnEditor(doc, e, n.key),
      el('div', { class: 'row' }, button('Remove export', () => { doc.bp.exports.splice(n.i, 1); T.sel = null; touched(doc, 'exports'); }, 'btn ghost sm danger')));
  } else {
    form.append(el('p', { class: 'muted' }, 'Comes from the scan. Layout changes (partitions, pools, datasets) are planned in the Planner.'));
  }
  const gid = n.kind === 'mount' ? `mnt:${doc.host}:${n.target}` : n.kind === 'pool' ? `pool:${doc.host}:${n.ref.name}` : null;
  const gnode = gid && S.byId.get(gid);
  const tail = gnode ? [el('div', { class: 'row' }, button('Show in graph', () => { setMode('graph'); select(gid, true); }, 'btn ghost sm'),
    ...(n.kind === 'mount' ? [button('Largest files', () => runSearch({ under: n.target, host: doc.host, size_gt: '1MiB' }), 'btn ghost sm')] : []))] : [];
  $('#summary').replaceChildren(...kids, form, ...tail);
}
function mountOnEditor(doc, e, key) {
  e.mounts = e.mounts || [];
  const others = [...T.docs.keys()].filter((h) => h !== doc.host);
  const rows = e.mounts.map((m, j) => {
    const host = el('select', { onchange: () => { m.host = host.value; touched(doc, key); } }, new Option('client host…', ''), ...others.map((h) => new Option(h, h)));
    host.value = m.host || '';
    const path = entry(m.path, (v) => { m.path = v; touched(doc, key); }, { placeholder: '/mnt/' + (e.name || 'share').replace(/^.*\//, ''), class: 'mono' });
    return el('div', { class: 'row' }, host, path, button('×', () => { e.mounts.splice(j, 1); touched(doc, key); }, 'btn ghost sm'));
  });
  return el('div', { class: 'mounton' }, el('span', { class: 'muted' }, 'Mount on (clients get an automount fstab line)'), ...rows,
    el('div', { class: 'row' }, button('+ Client', () => { e.mounts.push({ host: '', path: '' }); touched(doc, key); }, 'btn ghost sm')));
}
const designedShares = (doc) => (doc.bp && doc.bp.exports || []).filter((e) => (e.designed || !e.fromScan) && /^(NFS|SMB|CIFS)/i.test(e.protocol || e.proto || ''));
const plannedShares = (doc) => designedShares(doc).filter((e) => !e.fromScan).length;
async function deployShares(doc) {
  showTab('details');
  T.sel = null;
  const box = $('#summary');
  if (doc.dirty) { box.replaceChildren(text('p', `Save the design for ${doc.host} first: the script is built from the saved one.`, 'st-failed')); return; }
  box.replaceChildren(text('p', 'Checking…', 'muted'));
  try {
    const c = await getJSON(`/api/shares/check?host=${encodeURIComponent(doc.host)}`);
    const dl = button('Download deploy script', async () => {
      const res = await api(`/api/shares/script?host=${encodeURIComponent(doc.host)}`);
      const a = document.createElement('a'); a.href = URL.createObjectURL(await res.blob());
      a.download = `shares-${doc.host.split('.')[0].toLowerCase()}.sh`; document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    }, 'btn pri sm');
    box.replaceChildren(
      el('div', { class: 'node-head' }, el('span', { class: 'muted' }, 'share deployment'), el('h2', {}, doc.host)),
      ...c.exports.map((e, i) => el('section', { class: 'card' },
        el('b', {}, `${e.proto} ${e.proto === 'SMB' ? e.name : e.path}${e.deployed ? ' · deployed' : ''}`),
        el('span', { class: 'mono small' }, `${e.path} → ${e.clients || 'anyone'}`),
        el('ul', { class: 'mvcheck' }, ...c.items.filter((x) => x.export === i).map((x) => el('li', { class: `lv-${x.level}` }, x.text))))),
      el('p', { class: c.crit ? 'st-failed' : 'muted' }, c.crit ? `${c.crit} problem(s) to fix in the design first` :
        `Run it on ${doc.host} (read-only report first), then sudo … --apply; then on each client, or from here with --host.`),
      el('div', { class: 'row end' }, dl));
  } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); }
}
function addLink(doc, into = '') {
  const l = { kind: 'symlink', path: '', target: into || '/', health: 'ok' };
  (doc.bp.links = doc.bp.links || []).push(l);
  const key = 'link:' + (doc.bp.links.length - 1);
  T.sel = { host: doc.host, key };
  touched(doc, key);
  showTab('details');
  const first = $('#summary .editor input'); if (first) first.focus();
}
function addExport(doc, path = '') {
  const e = { protocol: 'NFSv4.2', name: (path.split('/').pop() || 'share'), path: path || '/', clients: '', options: '' };
  (doc.bp.exports = doc.bp.exports || []).push(e);
  const key = 'exp:' + (doc.bp.exports.length - 1);
  T.sel = { host: doc.host, key };
  touched(doc, key);
  showTab('details');
}
function backUpTo(src, dst) {
  const doc = T.docs.get(src.host);
  const r = protRow(doc, src.target, true);
  r.ephemeral = false;
  r.backup.target = `rsync → ${dst.host}${dst.target}`;           // graph.py reads the host before the first "/"
  r.backup.offsite = false;                                         // same site until the operator says otherwise
  T.sel = { host: src.host, key: 'mnt:' + src.target };
  touched(doc, T.sel.key);
  showTab('details');
}

/* ── events ──────────────────────────────────────────────────────── */
const topo = $('#topo');
topo.addEventListener('click', (ev) => {
  const card = cardOf(ev);
  if (card) selectBox(card.dataset.host, card.dataset.node);
});
topo.addEventListener('keydown', (ev) => {
  const card = cardOf(ev);
  if (card && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); selectBox(card.dataset.host, card.dataset.node); }
});
topo.addEventListener('mouseover', (ev) => { const card = cardOf(ev); if (card !== T.hover) { T.hover = card; trace(card); } });
topo.addEventListener('mouseleave', () => { T.hover = null; trace(null); });
topo.addEventListener('focusin', (ev) => trace(cardOf(ev)));
const cardOf = (ev) => (ev.target.nodeType === 1 ? ev.target : ev.target.parentElement)?.closest('.tn') || null;
const mountOf = (card) => card && card.dataset.node.startsWith('mnt:') ? { host: card.dataset.host, target: card.dataset.node.slice(4), card } : null;
topo.addEventListener('dragstart', (ev) => {
  T.drag = mountOf(cardOf(ev));
  if (!T.drag) { ev.preventDefault(); return; }
  ev.dataTransfer.effectAllowed = 'link';
  ev.dataTransfer.setData('text/plain', `${T.drag.host}:${T.drag.target}`);
  topo.classList.add('dragging');
});
topo.addEventListener('dragover', (ev) => {
  const to = mountOf(cardOf(ev));
  if (!T.drag || !to || to.card === T.drag.card) return;
  ev.preventDefault(); ev.dataTransfer.dropEffect = 'link';
  topo.querySelectorAll('.drop').forEach((x) => x !== to.card && x.classList.remove('drop'));
  to.card.classList.add('drop');
});
topo.addEventListener('dragleave', (ev) => { const c = cardOf(ev); if (c && !c.contains(ev.relatedTarget)) c.classList.remove('drop'); });
topo.addEventListener('drop', (ev) => {
  const to = mountOf(cardOf(ev));
  ev.preventDefault();
  if (T.drag && to && to.card !== T.drag.card) backUpTo(T.drag, to);
});
topo.addEventListener('dragend', () => { T.drag = null; topo.classList.remove('dragging'); topo.querySelectorAll('.drop').forEach((x) => x.classList.remove('drop')); });
new ResizeObserver(() => { if (T.mode === 'topo') drawTopoEdges(); }).observe(topo);
if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { if (T.mode === 'topo') drawTopoEdges(); });

$('#savedesigns').addEventListener('click', saveDesigns);
$('#discarddesigns').addEventListener('click', discardDesigns);
window.addEventListener('beforeunload', (ev) => { if (dirtyDocs().length) ev.preventDefault(); });

function setMode(mode, load = true) {
  T.mode = mode;
  try { localStorage.setItem('sf.view', mode); } catch { /* storage blocked: the default is fine */ }
  document.querySelectorAll('#viewmode button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mode === mode)));
  const graphOnly = ['#graph', '.legend', '#hopsfield', '#reset'];
  for (const s of graphOnly) document.querySelector(s).hidden = mode !== 'graph';
  topo.hidden = mode !== 'topo';
  $('#detailshint').textContent = mode === 'topo'
    ? 'Select a box to edit it. Tiers, protection, links and exports are yours; the rest comes from the scan.'
    : 'Select a node. Double-click one to focus on everything within the chosen number of hops.';
  $('#crumb').hidden = mode !== 'graph' || !S.focus;
  $('#empty').hidden = mode !== 'graph' || S.nodes.length > 0;
  if (mode === 'topo') { S.selected = null; if (load) loadDesigns(); }
  else { T.sel = null; renderSummary(); resize(); }
  updateSavebar();
}
document.querySelectorAll('#viewmode button').forEach((b) => b.addEventListener('click', () => setMode(b.dataset.mode)));
try { T.mode = localStorage.getItem('sf.view') === 'graph' ? 'graph' : 'topo'; } catch { /* default */ }

setMode(T.mode, false);
boot();
