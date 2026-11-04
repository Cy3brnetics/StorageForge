'use strict';
/* Topology view: a schema-designer canvas drawn from each host's storageforge/v1 design, the same document the
   planner edits. Each host is a frame; each disk, pool and remote is a table whose rows are what hangs off it
   (partitions, subvolumes, datasets, mount points), and lines join rows across tables: member partitions to pools,
   mount points to the links and exports inside them, exports to the clients that mount them. Pan, zoom and drag
   tables into the layout you want; positions save with the design. Select a row to edit what only the operator knows
   (tiers, 3-2-1 protection, links, exports) in the side panel; drag one mount point onto another to make it the
   backup target. Save stores the design and the server rebuilds the graph, so the health dots come back from the
   same rules the reports use. Loaded after app.js and uses its helpers. DOM APIs only, never innerHTML. */

const T = { mode: 'topo', docs: new Map(), order: [], sel: null, hover: null, drag: null, error: '' };
const TIERS = ['fast', 'mass', 'remote'];
const SYNC_STATES = ['None', 'Active Sync', 'Rsync Scheduled', 'Lagging', 'Disconnected'];
const SNAP_TOOLS = ['none', 'sanoid', 'zfs-auto-snapshot', 'snapper', 'btrbk', 'timeshift', 'lvm'];
const BACKUP_ENC = ['none', 'restic AES-256', 'borg repokey', 'age X25519', 'ZFS native aes-256-gcm', 'PBS AES-256-GCM'];
const EXPORT_PROTOS = ['NFSv4.2', 'NFSv3', 'SMB3', 'SFTP', 'S3'];
const LINK_KINDS = ['symlink', 'bind', 'hardlink'];
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
  const n = T.loadReq = (T.loadReq || 0) + 1;      // loads overlap (a save, a deploy's end, a scan's end): the last one started wins
  let hosts;
  if (typeof can === 'function' && can('security.view')) getJSON('/api/security/badges').then((b) => { T.security = b.mounts; renderTopoSoon(); }).catch(() => {});
  try { ({ hosts } = await getJSON('/api/planner/hosts')); }
  catch (err) { if (n === T.loadReq) { T.error = err.message; renderTopo(); } return; }
  const want = S.host ? hosts.filter((h) => h.host === S.host) : hosts;
  const docs = new Map();
  if (typeof loadAccess === 'function' && !ACCESS.hosts.length) loadAccess();
  if (typeof loadDocker === 'function' && !DK.usage.length) getJSON('/api/docker/usage').then((r) => { DK.usage = r.usage; renderTopoSoon(); }).catch(() => {});
  await Promise.all(want.map(async (h) => {
    const keep = T.docs.get(h.host);
    if (keep && keep.dirty) { docs.set(h.host, keep); return; }      // unsaved edits survive a reload
    try {   // a scanned host: fresh hardware from the scan plus the intent in its saved design
      const r = await getJSON(`/api/planner/design?host=${encodeURIComponent(h.host)}${h.scanned ? '&source=scan' : ''}`);
      docs.set(h.host, { host: h.host, bp: r.blueprint, source: r.source, savedAt: r.saved_at, sharesDeployed: r.shares_deployed, dirty: false, changed: new Set() });
    } catch (err) { docs.set(h.host, { host: h.host, error: err.message }); }
  }));
  if (n !== T.loadReq) return;
  for (const h of docs.keys()) if (T.docs.get(h)?.dirty) docs.set(h, T.docs.get(h));      // edited while this load was out
  T.docs = docs; T.order = want.map((h) => h.host); T.error = '';
  if (S.host && !want.length) T.error = `${S.host} has no design: it is not scanned and has no saved plan.`;
  if (T.sel && !(T.docs.get(T.sel.host) || {}).bp) T.sel = null;
  renderTopo();
  if (T.sel) renderEditor();
  if (typeof smLoad === 'function') smLoad();     // the shares manager lists these docs
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
        `${d.health && d.health.smart !== 'ok' ? `⚠ ${d.health.smart === 'fail' ? 'SMART failed' : 'bad sectors'} · ` : ''}${(d.model || 'unknown').split(' (')[0]} · ${fmtDec(d.sizeBytes)}`, tier, { ref: d, group: tier });
      if (d.member || poolOf.has(dev)) link(dk, 'pool:' + (d.member || poolOf.get(dev)), cacheOf.has(dev) ? 'cache' : '');
      for (const p of d.partitions || []) {
        if (p.member || poolOf.has(p.id)) {
          const pname = p.member || poolOf.get(p.id), pool = pools.find((x) => x.name === pname) || {};
          link(dk, 'pool:' + pname, cacheOf.has(p.id) ? 'cache' : '');
          for (const sv of p.subvolumes || []) {   // a multi-device btrfs records its subvolumes on its first member
            const ptier = pool.tier || tier;
            const sk = put(`sv:${p.id}/${sv.name}`, 2, 'subvol', sv.name, `btrfs subvol · ${pool.label || pname}`, ptier, { ref: sv, part: p, pool: pname });
            link('pool:' + pname, sk); mountAt(sv.mount, sk, 'btrfs', p.options, ptier);
          }
          continue;
        }
        const pk = put('part:' + p.id, 1, 'part', p.id, `${p.fs || 'none'}${p.btrfsProfile ? ' ' + p.btrfsProfile : ''} · ${fmtBytes(p.sizeBytes)}`, tier, { ref: p, group: tier, disk: d });
        link(dk, pk);
        for (const sv of p.subvolumes || []) {
          const sk = put(`sv:${p.id}/${sv.name}`, 2, 'subvol', sv.name, `btrfs subvol · ${p.label || p.id}`, tier, { ref: sv, part: p });
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
                       : `${kind} ${p.level || ''}${p.metaLevel && p.metaLevel !== p.level ? '/' + p.metaLevel : ''}${legs > 1 ? ` · ${legs} ${p.type === 'lvm' ? 'legs' : p.type === 'btrfs' ? 'devices' : 'members'}` : ''}`)
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
  // staged changes (changes.js): planned boxes are dashed; others mark the box they touch
  for (const t of (typeof tasksOn === 'function' ? tasksOn(doc.host) : [])) {
    const p = t.params || {};
    if (t.type === 'subvolume' || t.type === 'snapshot') {
      const path = p.path || p.dest, at = containing(path, mounts), mnode = at && nodes.get('mnt:' + at);
      const up = mnode && edges.find(([, b]) => b === mnode.key);
      const parent = up && (nodes.get(up[0]) || {}).kind === 'subvol' ? (edges.find(([, b]) => b === up[0]) || [])[0] : up && up[0];
      const key = put('plan:sv:' + path, 2, 'subvol', path.split('/').pop(), `planned ${t.type === 'snapshot' ? 'snapshot' : 'subvolume'} · ${path}`,
                      mnode ? mnode.tier : '', { planned: true, plannedPath: path });
      if (parent) link(parent, key, 'planned');
    } else if (t.type === 'mount' && !nodes.has('mnt:' + p.target)) {
      const key = put('mnt:' + p.target, 3, 'mount', p.target, `planned · ${p.fstype}${p.options ? ' · ' + p.options.split(',').slice(0, 2).join(',') : ''}`,
                      '', { target: p.target, planned: true });
      const uuid = (String(p.source).match(/^UUID=(.+)/) || [])[1];
      const from = (p.subvol && [...nodes.values()].find((x) => x.kind === 'subvol' && x.title.replace(/^\//, '') === p.subvol.replace(/^\//, '')))
        || (uuid && [...nodes.values()].find((x) => (x.kind === 'part' || x.kind === 'pool') && x.ref && x.ref.uuid === uuid));
      if (from) link(from.key, key, 'planned');
    } else if (t.type === 'unmount') {
      const nd = nodes.get('mnt:' + p.target); if (nd) nd.removing = true;
    } else if (['format', 'partition', 'btrfs-add'].includes(t.type)) {
      const dev = bare(p.device || p.disk), nd = nodes.get('part:' + dev) || nodes.get('disk:' + dev);
      if (nd) (nd.pending = nd.pending || []).push(t.type === 'format' ? `format ${p.fstype}` : t.type === 'partition' ? `partition${p.fstype ? ' + ' + p.fstype : ''}` : 'add to pool');
    } else {
      const path = p.path || p.target || p.source, at = path && containing(path, mounts), nd = at && nodes.get('mnt:' + at);
      if (nd) nd.staged = (nd.staged || 0) + 1;
    }
  }
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

/* ── the designer canvas: hosts are frames, disks/pools/remotes are tables ──
   A table's rows are what hangs off it (partitions, subvolumes, datasets, the mount points under them), indented
   like a schema tree. Lines run between rows of different tables only: a member partition (FK row) to its pool, a
   mount point to the links and exports inside it, an export to the client that mounts it. Positions live in world
   coordinates; the world div carries the pan and zoom, so nothing is measured against the viewport. */
const GRID = 20, SNAP = 10, PAD = 20, HEAD = 52, GAP_X = 110, GAP_Y = 26, SHELF = 3200, BIG = 30;
const ROOTS = new Set(['disk', 'pool', 'remote']);
const GLYPH = { disk: 'DSK', part: 'PRT', pool: 'POOL', subvol: 'SV', dataset: 'DS', mount: 'MNT', link: 'LNK', export: 'EXP', remote: 'NET' };
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage blocked: the default is fine */ } },
};
Object.assign(T, { view: store.get('sf.topo.view', null), fit: !store.get('sf.topo.view', null), collapsed: new Set(store.get('sf.topo.collapsed', [])), opened: new Set(store.get('sf.topo.opened', [])),
  tables: new Map(), rows: new Map(), frames: new Map(), lines: [], gesture: null, quiet: 0, hits: null });
const snap = (v) => Math.round(v / SNAP) * SNAP;
function svgEl(tag, attrs = {}) {
  const e = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}
const glyph = (n) => n.kind === 'dataset' && /^logical volume/.test(n.sub || '') ? 'LV' : GLYPH[n.kind] || '·';

function tablesOf(doc) {       // → tables keyed by their head node, owner: row key → table id, fk: 'disk>pool' → member rows
  const m = doc.m, tables = new Map(), owner = new Map(), kids = new Map(), parent = new Map(), fk = new Map();
  for (const [a, b] of m.edges) {
    const nb = m.nodes.get(b);
    if (ROOTS.has(nb.kind) || nb.kind === 'link' || nb.kind === 'export' || parent.has(b)) continue;
    parent.set(b, a);
    if (!kids.has(a)) kids.set(a, []);
    kids.get(a).push(b);
  }
  const walk = (t, key, depth) => {
    owner.set(key, t.id); t.rows.push({ key, depth });
    for (const k of kids.get(key) || []) if (!owner.has(k)) walk(t, k, depth + 1);
  };
  for (const n of m.nodes.values()) if (ROOTS.has(n.kind)) {
    const t = { id: n.key, head: n, rows: [], col: n.kind === 'disk' ? 0 : 1 };
    tables.set(t.id, t); owner.set(n.key, t.id);
    for (const k of kids.get(n.key) || []) walk(t, k, 0);
  }
  for (const [a, b, cls] of m.edges) {     // partitions that belong to a pool: FK rows on the disk's table
    const na = m.nodes.get(a), nb = m.nodes.get(b);
    if (na.kind !== 'disk' || nb.kind !== 'pool' || !nb.ref) continue;
    const ids = new Set([...(nb.ref.members || []), ...(nb.ref.log || []), ...(nb.ref.cache || [])].map(bare));
    const parts = (na.ref.partitions || []).filter((p) => p.member === nb.ref.name || ids.has(p.id));
    const t = tables.get(a), keys = [];
    for (const p of parts) {
      const key = `fk:${p.id}`;
      if (owner.has(key)) continue;
      t.rows.push({ key, depth: 0, fk: { title: p.id, to: b, from: a, cls,
        sub: `${cls === 'cache' ? 'cache/log of' : 'member of'} ${nb.title}${p.sizeBytes ? ' · ' + fmtBytes(p.sizeBytes) : ''}` } });
      owner.set(key, t.id); keys.push(key);
    }
    if (keys.length) fk.set(`${a}>${b}`, keys);
  }
  const loose = { id: 'loose', title: 'Unattached', sub: 'nothing above it in the design', rows: [], col: 1 };
  for (const n of m.nodes.values()) {
    if (owner.has(n.key) || n.kind === 'link' || n.kind === 'export' || (parent.has(n.key) && owner.has(parent.get(n.key)))) continue;
    if (!parent.has(n.key) || !m.nodes.has(parent.get(n.key))) walk(loose, n.key, 0);
  }
  for (const n of m.nodes.values()) if (!owner.has(n.key) && n.kind !== 'link' && n.kind !== 'export') walk(loose, n.key, 0);
  if (loose.rows.length) tables.set(loose.id, loose);
  const shares = { id: 'shares', title: 'Links & exports', sub: 'symlinks, binds and shares', rows: [], col: 2 };
  for (const n of m.nodes.values()) if (n.kind === 'link' || n.kind === 'export') { owner.set(n.key, shares.id); shares.rows.push({ key: n.key, depth: 0 }); }
  if (shares.rows.length) tables.set(shares.id, shares);
  return { tables, owner, fk };
}

function badges(doc, n) {
  const out = [];
  if (n.kind === 'mount' && !n.planned) {
    const r = protRow(doc, n.target, false);
    if (r && r.ephemeral) out.push(['eph', 'Excluded from 3-2-1', 'mut']);
    else if (r) {
      if (r.snapshots.enabled) out.push(['S', `Snapshots: ${r.snapshots.tool}${r.snapshots.policy ? ' · ' + r.snapshots.policy : ''}`, 'ok']);
      if (r.sync.state !== 'None') out.push(['R', `Sync: ${r.sync.target || r.sync.state}`, /Lagging|Disconnected/.test(r.sync.state) ? 'warn' : 'ok']);
      if (r.backup.target) out.push([r.backup.offsite ? 'B↗' : 'B', `Backup: ${r.backup.target}${r.backup.offsite ? ' (offsite)' : ''}`, 'ok']);
    }
    const c = new Set((n.containers || []).map((u) => u.container)).size;
    if (c) out.push([`C${c}`, `${c} container${c === 1 ? '' : 's'} use this mount`, 'info']);
    const sec = (T.security || {})[doc.host || doc.bp?.host || doc.name]?.[n.target];
    if (sec?.holds) out.push([`🔒${sec.holds}`, `${sec.holds} retention hold(s)${sec.expires_at ? `, the soonest ends ${new Date(sec.expires_at * 1000).toLocaleDateString()}` : ''}${sec.missing ? `. ${sec.missing} gone from the host` : ''}`, sec.missing ? 'warn' : 'ok']);
    if (sec?.decoys) out.push([`🎯${sec.decoys}`, `${sec.decoys} decoy file(s)${sec.tripped ? `, ${sec.tripped} tripped` : ''}`, sec.tripped ? 'warn' : 'ok']);
  }
  if (n.pending) out.push(['±', 'Staged: ' + n.pending.join(', '), 'plan']);
  if (n.removing) out.push(['−', 'Staged: unmount', 'plan']);
  if (n.staged) out.push([`+${n.staged}`, `${n.staged} staged change${n.staged === 1 ? '' : 's'} inside`, 'plan']);
  return out.map(([t, title, cls]) => el('span', { class: `bdg ${cls}`, title }, t));
}
const tip = (n) => [n.title, n.sub, n.prot, n.health && HEALTH_TEXT[n.health]].filter(Boolean).join('\n');
function rowEl(doc, n, tb, cls, kids) {
  const sel = T.sel && T.sel.host === doc.host && T.sel.key === n.key;
  const r = el('div', {
    class: `tr ${cls}${n.bad ? ' bad' : ''}${sel ? ' sel' : ''}${doc.changed.has(n.key) ? ' edited' : ''}${n.planned ? ' planned' : ''}${n.removing ? ' removing' : ''}`,
    tabindex: '0', role: 'button', draggable: n.kind === 'mount' ? 'true' : null, title: tip(n),
    dataset: { node: n.key, host: doc.host }, 'aria-pressed': sel ? 'true' : 'false',
  }, ...kids);
  r._menu = () => boxMenu(doc, n);
  T.rows.set(`${doc.host}|${n.key}`, { el: r, tb, node: n.key, text: `${n.title} ${n.sub || ''}`.toLowerCase() });
  return r;
}
const healthDot = (n) => n.health ? el('i', { class: `dot ${n.health}`, title: HEALTH_TEXT[n.health] }) : null;
function tableEl(doc, t, tb) {
  const fid = `${doc.host}|${t.id}`, shut = isShut(fid, t), h = t.head;
  const chev = el('button', { type: 'button', class: 'tchev', 'aria-expanded': String(!shut), title: shut ? 'Expand' : 'Collapse',
    onclick: (ev) => { ev.stopPropagation(); toggleTable(fid); } }, shut ? '▸' : '▾');
  const cnt = el('span', { class: 'tcnt' }, String(t.rows.length));
  const head = h
    ? rowEl(doc, h, tb, 'tth', [el('span', { class: 'tk' }, glyph(h)),
      el('span', { class: 'tht' }, el('b', {}, healthDot(h), h.title), el('small', {}, h.sub)), ...badges(doc, h), cnt, chev])
    : el('div', { class: 'tr tth' }, el('span', { class: 'tk' }, t.id === 'shares' ? 'SHR' : '?'),
      el('span', { class: 'tht' }, el('b', {}, t.title), el('small', {}, t.sub)), cnt, chev);
  if (!h) head._menu = () => t.id === 'shares' ? hostMenu(doc) : null;
  const pre = h && h.ref && h.ref.name ? h.ref.name + '/' : null;
  const rows = t.rows.map((r) => {
    if (r.fk) {
      const f = el('div', { class: `tr fk${r.fk.cls === 'cache' ? ' cache' : ''}`, tabindex: '0', role: 'button', title: `${r.fk.sub}\nSelect to jump to ${r.fk.to.replace(/^pool:/, '')}`,
        dataset: { jump: r.fk.to, host: doc.host } },
        el('span', { class: 'tk' }, 'FK'), el('span', { class: 'tn-n' }, r.fk.title), el('span', { class: 'tn-t' }, r.fk.sub));
      T.rows.set(`${doc.host}|${r.key}`, { el: f, tb, fk: r.fk, text: `${r.fk.title} ${r.fk.sub}`.toLowerCase() });
      return f;
    }
    const n = doc.m.nodes.get(r.key);
    const name = pre && n.kind === 'dataset' && n.title.startsWith(pre) ? n.title.slice(pre.length) : n.title;
    const nm = el('span', { class: 'tn-n' }, healthDot(n),     // long paths keep their tail: '…/certs/2ccbdda3.0'
      el('span', { class: `nm${n.kind === 'link' || n.title.length > 40 ? ' tail' : ''}` }, el('bdi', {}, name)));
    nm.style.paddingLeft = `${r.depth * 14}px`;
    nm.style.backgroundPosition = `${r.depth * 14 - 10}px 50%`;
    nm.style.backgroundPosition = `${r.depth * 14 - 10}px 50%`;
    if (r.depth) nm.classList.add('nest');
    return rowEl(doc, n, tb, `k-${n.kind}`, [el('span', { class: 'tk' }, glyph(n)), nm, ...badges(doc, n), el('span', { class: 'tn-t' }, n.sub || '')]);
  });
  return el('div', { class: `tt ${h ? h.tier || '' : t.id === 'shares' ? 'exp' : ''}${shut ? ' shut' : ''}`, dataset: { fid } },
    head, el('div', { class: 'tbody', hidden: shut }, ...rows));
}
function hostHead(doc) {
  const host = doc.host;
  const acc = (typeof ACCESS !== 'undefined' ? ACCESS.hosts : []).find((a) => a.host === host);
  const unreadable = acc && acc.access !== 'capability' ? acc.denied_total || acc.read_errors : 0;
  const head = el('div', { class: 'thead', title: 'Drag to move this host and its tables' }, el('h2', {}, host),
    unreadable ? button(`${unreadable} unreadable`, () => showTab('access'), 'badge warn') : null,
    serves(doc) ? el('span', { class: 'badge share', title: 'Shares this host serves, found by the scan' }, serves(doc)) : null,
    plannedShares(doc) ? button(`Deploy ${plannedShares(doc)} share${plannedShares(doc) === 1 ? '' : 's'}`, () => deployShares(doc), 'badge share deploy')
      : designedShares(doc).length ? button('Shares script', () => deployShares(doc), 'badge share deploy') : null,
    el('span', { class: doc.dirty ? 'dirty' : 'muted' }, doc.error ? doc.error : doc.dirty ? 'unsaved edits'
      : doc.source === 'scan' ? (doc.savedAt ? 'latest scan + saved design' : 'latest scan · no saved design yet') : 'saved design'),
    doc.bp ? el('span', { class: 'row' },
      button('+ Link', () => addLink(doc), 'btn ghost sm'), button('+ Export', () => addExport(doc), 'btn ghost sm'),
      el('a', { class: 'btn ghost sm', href: `/planner#topology@${encodeURIComponent(host)}` }, 'Planner')) : null);
  head._menu = () => hostMenu(doc);
  return head;
}

let topoSoon = 0;
function renderTopoSoon() {  // for data arriving in the background: the answers to a page load's requests share one render
  clearTimeout(topoSoon);
  topoSoon = setTimeout(renderTopo, 50);
}
function renderTopo() {
  clearTimeout(topoSoon);
  updateSavebar();
  if (T.mode !== 'topo') return;
  initCanvas();
  T.tables.clear(); T.rows.clear(); T.frames.clear(); T.lines = [];
  const note = T.error || (!T.order.length ? 'No hosts yet. Scan one from the Scans tab, or plan one in the Planner.' : '');
  T.note.textContent = note; T.note.hidden = !note; T.note.className = `tnote ${T.error ? 'st-failed' : 'muted'}`;
  const kids = [];
  for (const host of T.order) {
    const doc = T.docs.get(host);
    const f = { host, doc, el: el('div', { class: 'tframe', dataset: { host } }, hostHead(doc)), tbs: [], ox: 0, oy: 0 };
    kids.push(f.el);
    if (doc.bp) {
      doc.m = model(doc); doc.tt = tablesOf(doc);
      for (const t of doc.tt.tables.values()) {
        const tb = { host, id: t.id, t, f, x: 0, y: 0, w: 0, h: 0 };
        tb.el = tableEl(doc, t, tb);
        f.tbs.push(tb); kids.push(tb.el);
        T.tables.set(`${host}|${t.id}`, tb);
      }
    }
    T.frames.set(host, f);
  }
  T.world.replaceChildren(T.svg, ...kids);
  for (const f of T.frames.values()) for (const tb of f.tbs) { tb.w = tb.el.offsetWidth; tb.h = tb.el.offsetHeight; }
  placeAll();
  for (const f of T.frames.values()) {
    if (!f.doc.bp) continue;
    for (const [a, b, cls] of f.doc.m.edges) {
      if (f.doc.tt.owner.get(a) === f.doc.tt.owner.get(b)) continue;
      for (const ra of f.doc.tt.fk.get(`${a}>${b}`) || [a]) T.lines.push({ ha: f.host, a, ra, hb: f.host, b, rb: b, cls });
    }
    for (const r of f.doc.bp.remotes || []) {    // NFS/SMB mounts back to the export that serves them
      const from = shareSource(f.doc, r), key = 'rem:' + (r.name || r.endpoint);
      if (from && from.key) T.lines.push({ ha: from.host, a: from.key, ra: from.key, hb: f.host, b: key, rb: key, cls: 'share' });
    }
  }
  for (const f of T.frames.values()) sizeFrame(f);
  drawLines();
  $('#tcollapse').textContent = [...T.tables].some(([k, tb]) => !isShut(k, tb.t)) ? 'Collapse all' : 'Expand all';
  if (T.fit && T.frames.size) { T.fit = false; fitView(); } else applyView();     // first visit: everything on screen
  if (typeof renderStageBar === 'function') renderStageBar();
}

/* ── placement: saved positions from the design, the rest laid out in columns ── */
function autoPlace(f) {      // disks | pools, remotes, unattached | links & exports; disks sorted by the pool they feed
  const cols = [[], [], []];
  for (const tb of f.tbs) cols[tb.t.col].push(tb);
  const at = new Map(cols[1].map((tb, i) => [tb.id, i]));
  const feeds = (tb) => Math.min(Infinity, ...f.doc.m.edges.filter(([a, b]) => a === tb.id && at.has(b)).map(([, b]) => at.get(b)));
  cols[0] = cols[0].map((tb, i) => [feeds(tb), i, tb]).sort((p, q) => (p[0] === q[0] ? 0 : p[0] < q[0] ? -1 : 1) || p[1] - q[1]).map((p) => p[2]);
  let x = PAD;
  for (const col of cols) {
    if (!col.length) continue;
    let y = HEAD;
    for (const tb of col) {
      const fed = col === cols[1] ? cols[0].filter((d) => f.doc.m.edges.some(([a, b]) => a === d.id && b === tb.id)).map((d) => d.ay) : [];
      tb.ax = x; tb.ay = Math.max(y, fed.length ? Math.min(...fed) : y);     // line a pool up with its first disk
      y = tb.ay + tb.h + GAP_Y;
    }
    x += Math.max(...col.map((tb) => tb.w)) + GAP_X;
  }
}
function placeTables(f) {
  const saved = (f.doc.bp && f.doc.bp.layout && f.doc.bp.layout.tables) || {};
  autoPlace(f);
  const known = f.tbs.filter((tb) => Array.isArray(saved[tb.id]));
  if (!known.length) { for (const tb of f.tbs) { tb.rx = tb.ax; tb.ry = tb.ay; } return; }
  for (const tb of known) [tb.rx, tb.ry] = saved[tb.id];
  const below = Math.max(...known.map((tb) => tb.ry + tb.h)) + GAP_Y * 2, cursor = [below, below, below];
  for (const tb of f.tbs) if (!Array.isArray(saved[tb.id])) {     // new since the layout was saved: under the rest
    tb.rx = tb.ax; tb.ry = cursor[tb.t.col]; cursor[tb.t.col] += tb.h + GAP_Y;
  }
}
function placeAll() {        // hosts on shelves, left to right; a host with a saved place keeps it instead
  let x = 0, y = 0, rowH = 0;
  for (const f of T.frames.values()) {
    placeTables(f);
    const w = f.tbs.length ? Math.max(480, ...f.tbs.map((tb) => tb.rx + tb.w)) + PAD : 480;
    if (x && x + w > SHELF) { x = 0; y += rowH + 60; rowH = 0; }
    f.ox = x; f.oy = y; x += w + 60; rowH = Math.max(rowH, extent(f));
    const L = f.doc.bp && f.doc.bp.layout;
    if (L && Number.isFinite(L.x) && Number.isFinite(L.y)) { f.ox = L.x; f.oy = L.y; }
    for (const tb of f.tbs) put(tb, f.ox + tb.rx, f.oy + tb.ry);
  }
}
const extent = (f) => f.tbs.length ? Math.max(...f.tbs.map((tb) => tb.ry + tb.h)) + PAD : HEAD + 30;
function put(tb, x, y) { tb.x = x; tb.y = y; tb.el.style.left = `${x}px`; tb.el.style.top = `${y}px`; }
function sizeFrame(f) {
  const t = f.tbs;
  const x1 = t.length ? Math.min(...t.map((b) => b.x)) - PAD : f.ox, y1 = t.length ? Math.min(...t.map((b) => b.y)) - HEAD : f.oy;
  const x2 = Math.max(x1 + 480, ...t.map((b) => b.x + b.w + PAD)), y2 = Math.max(y1 + HEAD + 30, ...t.map((b) => b.y + b.h + PAD));
  Object.assign(f, { x1, y1, x2, y2 });
  Object.assign(f.el.style, { left: `${x1}px`, top: `${y1}px`, width: `${x2 - x1}px`, height: `${y2 - y1}px` });
}

/* ── relationship lines ──────────────────────────────────────────── */
function anchor(host, key) {
  const r = T.rows.get(`${host}|${key}`);
  if (!r) return null;
  const row = r.el.offsetParent ? r.el : r.tb.el.firstChild;     // a collapsed table: its heading
  return { tb: r.tb, y: r.tb.y + row.offsetTop + row.offsetHeight / 2 };
}
function drawLines() {
  const gs = [];
  for (const ln of T.lines) {
    const A = anchor(ln.ha, ln.ra), B = anchor(ln.hb, ln.rb);
    if (!A || !B || A.tb === B.tb) continue;
    const a = A.tb, b = B.tb;
    let s1 = 1, s2 = 1;                       // sides: facing tables join face to face, overlapping ones loop on the right
    if (b.x >= a.x + a.w + 24) s2 = -1;
    else if (a.x >= b.x + b.w + 24) s1 = -1;
    const x1 = s1 > 0 ? a.x + a.w : a.x, x2 = s2 > 0 ? b.x + b.w : b.x, y1 = A.y, y2 = B.y;
    let d;
    if (s1 === s2) { const cx = Math.max(x1, x2) + 48; d = `M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}`; }
    else { const k = Math.max(40, Math.abs(x2 - x1) / 2); d = `M${x1},${y1} C${x1 + s1 * k},${y1} ${x2 + s2 * k},${y2} ${x2},${y2}`; }
    const g = svgEl('g', { class: `ln ${ln.cls || ''}` });
    Object.assign(g.dataset, { ha: ln.ha, a: ln.a, hb: ln.hb, b: ln.b });
    g.append(svgEl('path', { d }), svgEl('circle', { cx: x1, cy: y1, r: 3 }), svgEl('circle', { cx: x2, cy: y2, r: 3.5, class: 'end' }));
    gs.push(g);
  }
  T.svg.replaceChildren(...gs);
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
function trace(row) {
  if (!T.world) return;
  T.world.querySelectorAll('.lit').forEach((x) => x.classList.remove('lit'));
  T.world.classList.remove('chain-on');
  const host = row && row.dataset.host, doc = host && T.docs.get(host);
  if (!doc || !doc.m || !row.dataset.node) return;
  const set = chainOf(doc, row.dataset.node), on = (h, k) => h === host && set.has(k);
  const light = (h, k) => { const r = T.rows.get(`${h}|${k}`); if (r) { r.el.classList.add('lit'); r.tb.el.classList.add('lit'); } };
  T.world.classList.add('chain-on');
  for (const [id, r] of T.rows) {
    if (r.tb.host !== host) continue;
    if (r.node ? set.has(r.node) : set.has(r.fk.from) && set.has(r.fk.to)) light(host, id.slice(host.length + 1));
  }
  for (const g of T.svg.children) {
    const { ha, a, hb, b } = g.dataset;
    const hit = g.classList.contains('share') ? on(ha, a) || on(hb, b) : on(ha, a) && on(hb, b);
    if (hit) { g.classList.add('lit'); light(ha, a); light(hb, b); }
  }
}

/* ── pan, zoom, fit, find ────────────────────────────────────────── */
function initCanvas() {
  if (T.world) return;
  T.world = el('div', { class: 'tworld' });
  T.svg = svgEl('svg', { class: 'tedges', 'aria-hidden': 'true' });
  T.zoomLbl = button('100%', () => zoomBy(1 / T.view.k), 'btn ghost sm tzoom');
  T.zoomLbl.title = 'Reset to 100% (0)';
  T.find = el('input', { type: 'search', placeholder: 'Find disk, pool, path…', 'aria-label': 'Find in the topology', autocomplete: 'off', spellcheck: 'false',
    oninput: () => { T.hits = null; T.findN.textContent = ''; },
    onkeydown: (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); findNext(ev.shiftKey); } else if (ev.key === 'Escape') { T.find.value = ''; T.hits = null; T.findN.textContent = ''; } } });
  T.findN = el('span', { class: 'muted small tfindn' });
  T.note = el('p', { class: 'tnote', hidden: true });
  const tool = (label, fn, title, id) => { const b = button(label, fn, 'btn ghost sm'); b.title = title; if (id) b.id = id; return b; };
  topo.append(T.world, T.note,
    el('div', { class: 'ttools', role: 'toolbar', 'aria-label': 'Canvas' },
      tool('−', () => zoomBy(1 / 1.2), 'Zoom out (−)'), T.zoomLbl, tool('+', () => zoomBy(1.2), 'Zoom in (+)'),
      tool('Fit', fitView, 'Fit everything on screen (F)'),
      tool('Auto-layout', autoLayout, 'Forget the saved positions and lay the tables out again'),
      tool('Collapse all', toggleAll, 'Collapse or expand every table', 'tcollapse'),
      tool('Shares', () => openSharesManager(), 'See, edit and remove the NFS and SMB shares on these hosts'),
      el('span', { class: 'tsep' }), T.find, T.findN),
    el('details', { class: 'tlegend' }, el('summary', {}, 'Legend'),
      el('div', { class: 'tleg' },
        el('span', {}, el('i', { class: 'sw fast' }), 'fast tier'), el('span', {}, el('i', { class: 'sw mass' }), 'mass tier'),
        el('span', {}, el('i', { class: 'sw remote' }), 'remote / mesh'), el('span', {}, el('i', { class: 'sw exp' }), 'links & exports'),
        el('span', {}, el('i', { class: 'dot protected' }), el('i', { class: 'dot local-only' }), el('i', { class: 'dot broken' }), 'mount health'),
        el('span', {}, el('i', { class: 'lnk' }), 'member · inside'), el('span', {}, el('i', { class: 'lnk cache' }), 'SLOG / L2ARC'),
        el('span', {}, el('i', { class: 'lnk share' }), 'NFS / SMB mount'), el('span', {}, el('i', { class: 'lnk planned' }), 'staged change'),
        el('span', {}, el('b', { class: 'bdg ok' }, 'S'), el('b', { class: 'bdg ok' }, 'R'), el('b', { class: 'bdg ok' }, 'B'), 'snapshots · sync · backup (↗ offsite)'),
        el('span', {}, el('b', { class: 'bdg info' }, 'C2'), 'containers'), el('span', {}, el('b', { class: 'bdg plan' }, '±'), 'staged'),
        el('span', {}, el('b', { class: 'tk' }, 'FK'), 'partition in a pool: select to jump')),
      el('p', { class: 'muted small' }, 'Scroll to pan, Ctrl+scroll or pinch to zoom, drag the background to pan. Drag a table or host by its heading; positions save with the design. Drag a mount point onto another to back it up there. Right-click anything for its actions.')));
}
function applyView() {
  const v = T.view || (T.view = { x: 40, y: 60, k: 1 });
  T.world.style.transform = `translate(${v.x}px, ${v.y}px) scale(${v.k})`;
  const g = GRID * v.k * (v.k < 0.5 ? 4 : 1);      // a coarser dot grid when zoomed out
  topo.style.backgroundSize = `${g}px ${g}px`;
  topo.style.backgroundPosition = `${v.x}px ${v.y}px`;
  T.zoomLbl.textContent = `${Math.round(v.k * 100)}%`;
  store.set('sf.topo.view', v);
}
function zoomAt(k, cx, cy) {
  const v = T.view; k = Math.max(0.2, Math.min(2.5, k));
  v.x = cx - (cx - v.x) * (k / v.k); v.y = cy - (cy - v.y) * (k / v.k); v.k = k;
  applyView();
}
const zoomBy = (f) => zoomAt(T.view.k * f, topo.clientWidth / 2, topo.clientHeight / 2);
function fitView() {
  const fs = [...T.frames.values()], W = topo.clientWidth, H = topo.clientHeight;
  if (!fs.length || !W) { applyView(); return; }
  const x1 = Math.min(...fs.map((f) => f.x1)), y1 = Math.min(...fs.map((f) => f.y1));
  const w = Math.max(...fs.map((f) => f.x2)) - x1, h = Math.max(...fs.map((f) => f.y2)) - y1;
  const k = Math.max(0.2, Math.min(1, (W - 48) / w, (H - 110) / h));
  T.view = { k, x: Math.max(24, (W - w * k) / 2) - x1 * k, y: Math.max(60, (H - h * k) / 2) - y1 * k };
  applyView();
}
function centerOn(x, y) {
  const v = T.view; if (v.k < 0.7) v.k = 0.9;
  v.x = topo.clientWidth / 2 - x * v.k; v.y = topo.clientHeight / 2 - y * v.k;
  applyView();
}
function reveal(host, key) {          // un-collapse its table, select it and bring it into view
  const r = T.rows.get(`${host}|${key}`);
  if (!r) return;
  if (isShut(`${host}|${r.tb.id}`, r.tb.t)) toggleTable(`${host}|${r.tb.id}`);
  const a = anchor(host, key);
  if (a) centerOn(a.tb.x + a.tb.w / 2, a.y);
}
function focusHost(host) {
  const f = T.frames.get(host);
  if (!f) return;
  const k = T.view.k, W = topo.clientWidth, H = topo.clientHeight;
  T.view.x = (f.x2 - f.x1) * k < W ? W / 2 - (f.x1 + f.x2) / 2 * k : 24 - f.x1 * k;
  T.view.y = (f.y2 - f.y1) * k < H - 80 ? H / 2 - (f.y1 + f.y2) / 2 * k : 60 - f.y1 * k;
  applyView();
}
function findNext(back) {
  const q = T.find.value.trim().toLowerCase();
  if (!q) return;
  if (!T.hits || T.hits.q !== q) T.hits = { q, i: -1, list: [...T.rows.entries()].filter(([, r]) => r.node && r.text.includes(q)).map(([k]) => k) };
  const h = T.hits;
  if (!h.list.length) { T.findN.textContent = 'no match'; return; }
  h.i = (h.i + (back ? -1 : 1) + h.list.length) % h.list.length;
  const id = h.list[h.i], r = T.rows.get(id);
  if (!r) { T.hits = null; return; }
  T.findN.textContent = `${h.i + 1}/${h.list.length}`;
  selectBox(r.tb.host, r.node);
  reveal(r.tb.host, r.node);
}
// a table with more than BIG rows starts collapsed; what the viewer opens or closes is remembered either way
const isShut = (fid, t) => T.collapsed.has(fid) || (t.rows.length > BIG && !T.opened.has(fid));
function setShut(fid, shut) {
  if (shut) { T.collapsed.add(fid); T.opened.delete(fid); } else { T.collapsed.delete(fid); T.opened.add(fid); }
}
function keepShut() { store.set('sf.topo.collapsed', [...T.collapsed]); store.set('sf.topo.opened', [...T.opened]); }
function toggleTable(fid) {
  const tb = T.tables.get(fid);
  setShut(fid, !(tb && isShut(fid, tb.t)));
  keepShut(); renderTopo();
}
function toggleAll() {
  const open = [...T.tables].some(([k, tb]) => !isShut(k, tb.t));
  for (const k of T.tables.keys()) setShut(k, open);
  keepShut(); renderTopo();
}
function autoLayout() {
  for (const host of T.order) {
    const doc = T.docs.get(host);
    if (doc && doc.bp && doc.bp.layout) { doc.bp.layout = null; doc.dirty = true; doc.changed.add('layout'); }
  }
  renderTopo(); fitView();
}
function commitLayout(f) {           // the first move stores every table of the host, so the others stay put
  const tables = {};
  for (const tb of f.tbs) tables[tb.id] = [Math.round(tb.x - f.ox), Math.round(tb.y - f.oy)];
  f.doc.bp.layout = { x: Math.round(f.ox), y: Math.round(f.oy), tables };
  touched(f.doc, 'layout');
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

/* ── editing ─────────────────────────────────────────────────────── */
function selectBox(host, key) {
  T.sel = { host, key };
  document.querySelectorAll('#topo .tr.sel').forEach((x) => { x.classList.remove('sel'); x.setAttribute('aria-pressed', 'false'); });
  const card = (T.rows.get(`${host}|${key}`) || {}).el;
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
    form.append(el('div', { class: 'row' }, ...mountActions(doc, n).map((a) => button(a.label, a.run, 'btn ghost sm'))));
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
      /^NFS/i.test(e.protocol || e.proto || '') ? rulesEditor(doc, e, n.key) : el('div', { class: 'stack' },
        field('Clients', entry(e.clients, set((v) => { e.clients = v; }), { placeholder: 'user names, @groups, or 10.0.0.0/24' })),
        field('Options', entry(e.options, set((v) => { e.options = v; }), { placeholder: 'ro for read-only' }))),
      mountOnEditor(doc, e, n.key),
      el('div', { class: 'row' }, typeof openShareWizard === 'function' ? button('Open in the share wizard', () => {
        if (doc.dirty) { toast(`Save or discard the edits on ${doc.host} first`); return; }
        openShareWizard({ host: doc.host, index: n.i, share: e });
      }, 'btn sm') : null,
      button('Remove export', () => { doc.bp.exports.splice(n.i, 1); T.sel = null; touched(doc, 'exports'); }, 'btn ghost sm danger')));
  } else if (n.planned) {
    form.append(el('p', { class: 'muted' }, 'Staged in the change plan, not on the host yet. Edit or remove it in the Changes tab.'),
      el('div', { class: 'row' }, button('Open the plan', () => showTab('changes'), 'btn sm')));
  } else {
    form.append(el('p', { class: 'muted' }, 'Comes from the scan. Stage changes below, or plan a new layout in the Planner.'));
  }
  if (!n.planned && typeof stageButtons === 'function') form.append(...stageButtons(doc, n));
  const gid = n.kind === 'mount' ? `mnt:${doc.host}:${n.target}` : n.kind === 'pool' ? `pool:${doc.host}:${n.ref.name}` : null;
  const gnode = gid && S.byId.get(gid);
  const tail = gnode ? [el('div', { class: 'row' }, button('Show in graph', () => { setMode('graph'); select(gid, true); }, 'btn ghost sm'),
    ...(n.kind === 'mount' ? [button('Largest files', () => runSearch({ under: n.target, host: doc.host, size_gt: '1MiB' }), 'btn ghost sm')] : []))] : [];
  $('#summary').replaceChildren(...kids, form, ...tail);
}
const mountActions = (doc, n) => {
  const fs = String((n.ref && (n.ref.fstype || n.ref.type)) || n.sub || '');
  return [
    { label: 'Move from here…', run: () => moveFrom(doc.host, n.target) },
    { label: 'Share this…', run: () => addExport(doc, n.target) },
    { label: '+ Link into this', run: () => addLink(doc, n.target) },
    { label: 'Git repos…', run: () => { if (typeof openGitForPath === 'function') openGitForPath(doc.host, n.target); } },
    typeof newTaskAt === 'function' ? { label: 'Back up with a task…', run: () => newTaskAt(doc.host, n.target, 'backup') } : null,
    typeof newTaskAt === 'function' && /btrfs|zfs/i.test(fs) ? { label: 'Snapshot with a task…', run: () => newTaskAt(doc.host, n.target, 'snapshot', fs) } : null].filter(Boolean);
};

/* ── right-click menus: what the editor offers, staged changes, copy ── */
function boxMenu(doc, n) {
  const h = doc.host, r = n.ref || {};
  const gid = n.kind === 'mount' ? `mnt:${h}:${n.target}` : n.kind === 'pool' ? `pool:${h}:${r.name}` : null;
  const items = [{ heading: `${n.kind} · ${n.title}` }, { label: n.planned ? 'Details' : 'Edit…', run: () => selectBox(h, n.key) },
    gid && S.byId.get(gid) ? { label: 'Show in graph', run: () => { setMode('graph'); select(gid, true); } } : null];
  const drop = (list, prefix) => () => {         // keys are list indexes: a removal shifts the ones after it
    doc.bp[list].splice(n.i, 1);
    if (T.sel && T.sel.host === h && T.sel.key.startsWith(prefix)) T.sel = null;
    touched(doc, list);
  };
  if ((n.kind === 'disk' || n.kind === 'pool') && n.ref) {
    items.push('-', ...TIERS.map((tier) => ({ label: `Tier: ${tier}`, checked: (r.tier || 'mass') === tier,
      run: () => { r.tier = tier; touched(doc, n.key); } })));
  } else if (n.kind === 'mount' && !n.planned) {
    items.push('-');
    if (!protRow(doc, n.target, false)) {
      items.push({ label: 'Track 3-2-1 protection', run: () => { protRow(doc, n.target, true); T.sel = { host: h, key: n.key }; touched(doc, n.key); showTab('details'); } });
    }
    items.push(...mountActions(doc, n), { label: 'Largest files', run: () => runSearch({ under: n.target, host: h, size_gt: '1MiB' }) });
  } else if (n.kind === 'link' && !r.fromScan) {
    items.push('-', n.bad ? { label: 'Ignore this link', run: () => fmIgnore(h, r.path) } : null, { label: 'Remove link', danger: true, run: drop('links', 'link:') });
  } else if (n.kind === 'link' && n.bad) {
    items.push('-', { label: 'Ignore this link', run: () => fmIgnore(h, r.path) });
  } else if (n.kind === 'export' && !(r.fromScan && !r.designed)) {
    items.push('-', designedShares(doc).includes(r) ? { label: 'Deploy shares…', run: () => deployShares(doc) } : null,
      { label: 'Remove export', danger: true, run: drop('exports', 'exp:') });
  }
  const staged = typeof stagedOn === 'function' ? stagedOn(doc, n) : [];
  if (staged.length) {
    items.push('-', { heading: `Staged here (${staged.length})` });
    for (const t of staged.slice(0, 3)) {
      items.push({ label: `Edit: ${taskTitle(t)}`, run: () => openTask(t.type, t.host, {}, t) },
        { label: `Unstage: ${taskTitle(t)}`, danger: true, run: () => unstage(t) });
    }
    if (staged.length > 3) items.push({ label: `All ${staged.length} in the Changes tab`, run: () => showTab('changes') });
  }
  const acts = !n.planned && typeof stageActions === 'function' ? stageActions(doc, n) : [];
  if (acts.length) items.push('-', { heading: 'Plan a change' }, ...acts);

  const dev = n.kind === 'disk' ? '/dev/' + bare(r.dev) : n.kind === 'part' ? '/dev/' + r.id : null;
  items.push('-', dev ? { label: 'Copy device', run: () => copyText(dev) }
    : n.kind === 'mount' || n.plannedPath ? { label: 'Copy path', run: () => copyText(n.target || n.plannedPath) }
      : { label: 'Copy name', run: () => copyText(n.title) });
  if (r.uuid) items.push({ label: 'Copy UUID', run: () => copyText(r.uuid, 'Copied UUID') });
  return items;
}
async function editSchedule(host) {
  const path = `/api/hosts/${encodeURIComponent(host)}/schedule`;
  try {
    const cur = await getJSON(path);
    const interval = prompt(`Scan ${host} how often? For example 90m, 6h or 1d. Empty uses the global interval.`, cur.interval ? `${Math.round(cur.interval / 60)}m` : '');
    if (interval === null) return;
    const quiet = prompt('Quiet hours, when no scheduled scan starts? For example 22-6. Empty means none.', cur.quiet_hours || '');
    if (quiet === null) return;
    await api(path, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ interval, quiet_hours: quiet }) });
  } catch (err) { alert(err.message); }
}
async function retireHost(host) {
  if (!confirm(`Retire ${host}? Its index, graph, scan history, bindings and design are removed, and a remote node's tunnel is cut. The audit log stays, and a new scan would add it back only with a new binding.`)) return;
  try {
    const res = await api(`/api/hosts/${encodeURIComponent(host)}`, { method: 'DELETE' });
    if (res?.removed?.still_on_host) alert(`${host}: ${res.removed.still_on_host}`);
    location.reload();
  } catch (err) { alert(err.message); }
}
function hostMenu(doc) {
  const h = doc.host;
  return [{ heading: h }, { label: 'Scan now', run: () => queueScan(h) }, { label: 'Scan schedule…', run: () => editSchedule(h) },
    doc.bp ? { label: '+ Link…', run: () => addLink(doc) } : null, doc.bp ? { label: '+ Export…', run: () => addExport(doc) } : null,
    doc.bp && (doc.bp.exports || []).length ? { label: 'Manage shares…', run: () => openSharesManager(h) } : null,
    doc.bp && designedShares(doc).length ? { label: 'Deploy shares…', run: () => deployShares(doc) } : null,
    doc.bp && typeof tasksOn === 'function' && tasksOn(h).length ? { label: `Review ${tasksOn(h).length} staged change${tasksOn(h).length === 1 ? '' : 's'}`, run: () => showTab('changes') } : null,
    { label: 'Open in planner', run: () => { location.href = `/planner#topology@${encodeURIComponent(h)}`; } },
    '-', { label: 'Copy hostname', run: () => copyText(h) }, { label: 'Retire…', danger: true, run: () => retireHost(h) }];
}
async function showBox(host, key) {     // from the graph: the same thing as a box in the topology
  T.sel = { host, key };
  setMode('topo', false);
  await loadDesigns();
  selectBox(host, key);
  reveal(host, key);
}
const NFS_PRESETS = { 'read-only': 'ro,sync,no_subtree_check', 'read-write': 'rw,sync,no_subtree_check',
  'read-write, root not squashed': 'rw,sync,no_subtree_check,no_root_squash',
  'all users as one owner': 'rw,sync,no_subtree_check,all_squash,anonuid=1000,anongid=1000' };
function rulesEditor(doc, e, key) {   // NFS: one rule per client or subnet, each with its own options
  if (!e.rules) e.rules = e.clients ? [{ clients: e.clients, options: e.options || NFS_PRESETS['read-write'] }] : [];
  const sync = () => { e.clients = e.rules.map((r) => r.clients).filter(Boolean).join(' '); touched(doc, key); };
  const rows = e.rules.map((r, j) => {
    const who = entry(r.clients, (v) => { r.clients = v; sync(); }, { placeholder: '10.42.0.0/24, a host, or @netgroup', class: 'mono' });
    const preset = el('select', { 'aria-label': 'Access', onchange: () => { if (preset.value) { r.options = NFS_PRESETS[preset.value]; sync(); } } },
      ...Object.keys(NFS_PRESETS).map((k) => new Option(k, k)), new Option('custom', ''));
    preset.value = Object.keys(NFS_PRESETS).find((k) => NFS_PRESETS[k] === r.options) || '';
    const opts = entry(r.options, (v) => { r.options = v; sync(); }, { placeholder: 'rw,sync,no_subtree_check', class: 'mono' });
    return el('div', { class: 'stack nfsrule' }, el('div', { class: 'row' }, who, preset, button('×', () => { e.rules.splice(j, 1); sync(); }, 'btn ghost sm')), opts);
  });
  return el('div', { class: 'mounton' }, el('span', { class: 'muted' }, 'Who may mount it (one rule per client or subnet)'), ...rows,
    el('div', { class: 'row' }, button('+ Rule', () => { e.rules.push({ clients: '', options: NFS_PRESETS['read-only'] }); sync(); }, 'btn ghost sm')));
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
const plannedShares = (doc) => (doc.sharesDeployed ? 0 : designedShares(doc).filter((e) => !e.fromScan).length);   // deployed, and the rescan has not said so yet: not planned any more
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
    }, 'btn ghost sm');
    box.replaceChildren(
      el('div', { class: 'node-head' }, el('span', { class: 'muted' }, 'share deployment'), el('h2', {}, doc.host)),
      ...c.exports.map((e, i) => el('section', { class: 'card' },
        el('b', {}, `${e.proto} ${e.proto === 'SMB' ? e.name : e.path}${e.deployed ? ' · deployed' : ''}`),
        el('span', { class: 'mono small' }, `${e.path} → ${e.clients || 'anyone'}`),
        el('ul', { class: 'mvcheck' }, ...c.items.filter((x) => x.export === i).map((x) => el('li', { class: `lv-${x.level}` }, x.text))))),
      el('p', { class: c.crit ? 'st-failed' : 'muted' }, c.crit ? `${c.crit} problem(s) to fix in the design first` :
        `Deploying runs a read-only report on ${doc.host} and its clients first. Or run the script yourself: read-only with no flags, then sudo … --apply.`),
      el('div', { class: 'row end' }, dl, button('Deploy (report first)…', () => startDeploy('shares', doc.host, 'report', `shares of ${doc.host}`), 'btn pri sm')));
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
async function addExport(doc, path = '') {    // the share wizard for scanned hosts; a planned host gets the inline form
  if (typeof openShareWizard === 'function' && await openShareWizard({ host: doc.host, path })) return;
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
const rowOf = (ev) => (ev.target.nodeType === 1 ? ev.target : ev.target.parentElement)?.closest('.tr[data-host]') || null;
topo.addEventListener('click', (ev) => {
  if (Date.now() - T.quiet < 250) return;                 // the click that ends a drag
  const row = rowOf(ev);
  if (!row) return;
  if (row.dataset.jump) { selectBox(row.dataset.host, row.dataset.jump); reveal(row.dataset.host, row.dataset.jump); }
  else if (row.dataset.node) selectBox(row.dataset.host, row.dataset.node);
});
topo.addEventListener('dblclick', (ev) => {
  const head = (ev.target.nodeType === 1 ? ev.target : ev.target.parentElement)?.closest('.tth');
  if (head && !ev.target.closest('button')) toggleTable(head.closest('.tt').dataset.fid);
});
topo.addEventListener('keydown', (ev) => {
  const row = rowOf(ev);
  if (row && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); row.click(); return; }
  if (ev.target.closest('input, select, textarea') || ev.ctrlKey || ev.metaKey || ev.altKey) return;
  const act = { '+': () => zoomBy(1.2), '=': () => zoomBy(1.2), '-': () => zoomBy(1 / 1.2), 0: () => zoomBy(1 / T.view.k), f: fitView,
    Escape: () => { T.sel = null; topo.querySelectorAll('.tr.sel').forEach((x) => x.classList.remove('sel')); renderSummary(); } }[ev.key];
  if (act) { ev.preventDefault(); act(); }
});
topo.addEventListener('mouseover', (ev) => {
  if (T.gesture && T.gesture.moved) return;
  const row = rowOf(ev);
  if (row !== T.hover) { T.hover = row; trace(row); }
});
topo.addEventListener('mouseleave', () => { T.hover = null; trace(null); });
topo.addEventListener('focusin', (ev) => trace(rowOf(ev)));
topo.addEventListener('wheel', (ev) => {
  if (ev.target.closest && ev.target.closest('.ttools, .tlegend')) return;
  ev.preventDefault();
  const px = ev.deltaMode === 1 ? 16 : ev.deltaMode === 2 ? topo.clientHeight : 1;
  if (ev.ctrlKey || ev.metaKey) {
    const r = topo.getBoundingClientRect();
    zoomAt(T.view.k * Math.exp(-ev.deltaY * px * 0.0025), ev.clientX - r.left, ev.clientY - r.top);
  } else { T.view.x -= ev.deltaX * px; T.view.y -= ev.deltaY * px; applyView(); }
}, { passive: false });

/* drag: the background pans, a table heading moves the table, a host heading moves the host with its tables */
topo.addEventListener('pointerdown', (ev) => {
  if (ev.button !== 0 && ev.button !== 1) return;
  const t = ev.target.nodeType === 1 ? ev.target : ev.target.parentElement;
  if (!t || t.closest('.ttools, .tlegend, input, select, textarea, a, button, .badge')) return;
  const tt = t.closest('.tth') && t.closest('.tt'), fh = t.closest('.tframe > .thead');
  let g = null;
  if (ev.button === 1 || (!t.closest('.tt') && !fh)) g = { kind: 'pan', vx: T.view.x, vy: T.view.y };
  else if (tt) { const tb = T.tables.get(tt.dataset.fid); if (tb) g = { kind: 'table', tb, rx: tb.x - tb.f.ox, ry: tb.y - tb.f.oy }; }
  else if (fh) { const f = T.frames.get(fh.parentElement.dataset.host); if (f && f.doc.bp) g = { kind: 'frame', f, ox: f.ox, oy: f.oy }; }
  if (!g) return;                                          // a row: click selects, a mount point drags natively
  if (ev.button === 1) ev.preventDefault();
  T.gesture = Object.assign(g, { sx: ev.clientX, sy: ev.clientY, id: ev.pointerId, moved: false, button: ev.button });
});
topo.addEventListener('pointermove', (ev) => {
  const g = T.gesture;
  if (!g || ev.pointerId !== g.id) return;
  const dx = ev.clientX - g.sx, dy = ev.clientY - g.sy;
  if (!g.moved) {
    if (Math.abs(dx) + Math.abs(dy) < 4) return;
    g.moved = true; topo.setPointerCapture(g.id); topo.classList.add(g.kind === 'pan' ? 'panning' : 'moving');
    T.hover = null; trace(null);
    if (g.tb) g.tb.el.classList.add('lifted');
  }
  if (g.kind === 'pan') { T.view.x = g.vx + dx; T.view.y = g.vy + dy; applyView(); return; }
  const wx = dx / T.view.k, wy = dy / T.view.k;
  if (g.kind === 'table') { put(g.tb, g.tb.f.ox + snap(g.rx + wx), g.tb.f.oy + snap(g.ry + wy)); sizeFrame(g.tb.f); }
  else {
    const f = g.f, nx = snap(g.ox + wx), ny = snap(g.oy + wy), mx = nx - f.ox, my = ny - f.oy;
    f.ox = nx; f.oy = ny;
    for (const tb of f.tbs) put(tb, tb.x + mx, tb.y + my);
    sizeFrame(f);
  }
  drawLines();
});
function endGesture(ev) {
  const g = T.gesture;
  if (!g || ev.pointerId !== g.id) return;
  T.gesture = null;
  topo.classList.remove('panning', 'moving');
  if (g.tb) g.tb.el.classList.remove('lifted');
  if (!g.moved) {
    if (g.kind === 'pan' && g.button === 0 && ev.type === 'pointerup' && T.sel) {
      T.sel = null; topo.querySelectorAll('.tr.sel').forEach((x) => { x.classList.remove('sel'); x.setAttribute('aria-pressed', 'false'); });
      renderSummary();
    }
    return;
  }
  T.quiet = Date.now();
  if (g.kind !== 'pan') commitLayout(g.tb ? g.tb.f : g.f);
}
topo.addEventListener('pointerup', endGesture);
topo.addEventListener('pointercancel', endGesture);

/* drag a mount point onto another to make it the backup target (native drag and drop) */
const mountOf = (row) => row && row.dataset.node && row.dataset.node.startsWith('mnt:') ? { host: row.dataset.host, target: row.dataset.node.slice(4), card: row } : null;
topo.addEventListener('dragstart', (ev) => {
  T.drag = mountOf(rowOf(ev));
  if (!T.drag) { ev.preventDefault(); return; }
  ev.dataTransfer.effectAllowed = 'link';
  ev.dataTransfer.setData('text/plain', `${T.drag.host}:${T.drag.target}`);
  topo.classList.add('dragging');
});
topo.addEventListener('dragover', (ev) => {
  const to = mountOf(rowOf(ev));
  if (!T.drag || !to || to.card === T.drag.card) return;
  ev.preventDefault(); ev.dataTransfer.dropEffect = 'link';
  topo.querySelectorAll('.drop').forEach((x) => x !== to.card && x.classList.remove('drop'));
  to.card.classList.add('drop');
});
topo.addEventListener('dragleave', (ev) => { const c = rowOf(ev); if (c && !c.contains(ev.relatedTarget)) c.classList.remove('drop'); });
topo.addEventListener('drop', (ev) => {
  const to = mountOf(rowOf(ev));
  ev.preventDefault();
  if (T.drag && to && to.card !== T.drag.card) backUpTo(T.drag, to);
});
topo.addEventListener('dragend', () => { T.drag = null; topo.classList.remove('dragging'); topo.querySelectorAll('.drop').forEach((x) => x.classList.remove('drop')); });
if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { if (T.mode === 'topo' && T.order.length) renderTopoSoon(); });

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
  $('#tasksview').hidden = mode !== 'tasks';
  $('#mapview').hidden = mode !== 'map';
  if (mode === 'map' && typeof loadMap === 'function') loadMap();
  $('#netscanview').hidden = mode !== 'scan';
  if (mode === 'scan' && typeof loadNetScan === 'function') loadNetScan();
  $('#detailshint').textContent = mode === 'topo'
    ? 'Select a box to edit it, or right-click it for its actions. Tiers, protection, links and exports are yours; the rest comes from the scan.'
    : 'Select a node. Double-click one to focus on everything within the chosen number of hops; right-click it for its actions.';
  $('#crumb').hidden = mode !== 'graph' || !S.focus;
  $('#empty').hidden = mode !== 'graph' || S.nodes.length > 0;
  if (mode === 'topo') { S.selected = null; if (load) loadDesigns(); }
  else { T.sel = null; renderSummary(); if (mode === 'graph') resize(); }
  if (mode === 'tasks' && load && typeof loadTasks === 'function' && !TK.loaded) loadTasks();
  updateSavebar();
  if (typeof renderStageBar === 'function') renderStageBar();
  if (typeof fmSync === 'function') fmSync();
}
document.querySelectorAll('#viewmode button').forEach((b) => b.addEventListener('click', () => setMode(b.dataset.mode)));
try { T.mode = ['graph', 'tasks', 'map', 'scan'].includes(localStorage.getItem('sf.view')) ? localStorage.getItem('sf.view') : 'topo'; } catch { /* default */ }

setMode(T.mode, false);
boot();
