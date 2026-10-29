'use strict';
/* File system browser over the index: the folders and files at a path, the mount each lives on, mounts below it,
   shares exported from it and shares other designs mount on it. Nothing here touches a host; a folder made since the
   last scan shows as "not in the index". Used by the share wizard, tasks and moves. Loaded after app.js and topology.js. */

const FS_KIND = { local: 'disk', nfs: 'NFS', smb: 'SMB', sshfs: 'SSHFS', rclone: 'rclone', virtfs: 'VM share', virtual: 'virtual', bind: 'bind' };
const FS_NET = new Set(['nfs', 'smb', 'sshfs', 'rclone']);
const joinPath = (a, b) => (a === '/' ? '' : a.replace(/\/$/, '')) + '/' + b;
const upPath = (p) => (p === '/' ? null : p.replace(/\/[^/]*$/, '') || '/');

function fsUsage(m) {
  if (!m || !m.total) return null;
  const pct = Math.min(100, Math.round(100 * (m.used || 0) / m.total));
  return el('span', { class: 'fsuse', title: `${fmtBytes(m.used || 0)} used of ${fmtBytes(m.total)}` },
    el('i', {}, el('span', { style: `width:${pct}%`, class: pct > 90 ? 'hot' : null })), text('b', `${fmtBytes(m.total - (m.used || 0))} free`));
}
function fsKindBadge(m) {
  if (!m) return null;
  return text('span', m.kind === 'local' ? m.fstype : `${FS_KIND[m.kind] || m.kind} · ${m.fstype}`, `fsk k-${m.kind}`);
}
function fsMountLine(m) {
  const r = m.remote;
  return r ? `${FS_KIND[m.kind]} from ${r.server}:${r.path || '/' + r.share}` : (m.source || m.fstype);
}

/* pick: 'folder' (a folder to use: share, copy from) or 'mount' (an empty folder to mount something on) */
function fsBrowser({ host, path = '/', pick = 'folder', onPick, onChange, pickLabel }) {
  const st = { host, path, data: null, filter: '', files: true, req: 0, mountsOpen: true };
  const box = el('div', { class: 'fsb', tabindex: '-1' });
  async function go(p) {
    st.path = p || '/';
    const n = ++st.req;
    box.classList.add('loading');
    try {
      const d = await getJSON(`/api/fs/browse?host=${encodeURIComponent(st.host)}&path=${encodeURIComponent(st.path)}`);
      if (n !== st.req) return;
      st.data = d; st.path = d.path;
    } catch (err) {
      if (n !== st.req) return;
      st.data = { error: err.message, path: st.path, dirs: [], files: [], mounts: [], crumbs: [] };
    }
    box.classList.remove('loading');
    render();
    if (onChange) onChange(st.path, st.data);
  }
  function verdict(d) {      // what the current folder means for the pick, before the server's full check
    const h = d.here || {}, m = h.mount, out = [];
    if (!m) out.push(['warn', 'not on a scanned mount']);
    else if (pick === 'mount') {
      if (h.is_mount) out.push(['crit', `${d.path} is a mount point already (${m.fstype})`]);
      else if (FS_NET.has(m.kind)) out.push(['crit', `inside the ${FS_KIND[m.kind]} mount ${m.target}`]);
      else if (h.entries) out.push(['warn', `holds ${h.entries.toLocaleString()} entries: they would be hidden`]);
      else out.push(['ok', h.exists === false ? 'not in the index: the folder is created' : 'empty: a good mount point']);
    } else {
      if (FS_NET.has(m.kind)) out.push(['warn', `this is the ${FS_KIND[m.kind]} mount from ${(m.remote || {}).server || 'another host'}`]);
      if (m.kind === 'virtual') out.push(['crit', `${m.fstype} is not stored on a disk`]);
      if (h.exists === false) out.push(['warn', 'not in the index (made since the last scan, or not there yet)']);
    }
    for (const e of d.exported_here || []) out.push(['note', `shared here as ${e.proto} ${e.name || ''}${e.planned ? ' (designed)' : ''}`]);
    for (const e of d.under_export || []) out.push(['note', `inside the ${e.proto} share ${e.name || e.path}`]);
    for (const x of (d.incoming || []).filter((x) => x.target === d.path)) out.push([pick === 'mount' ? 'warn' : 'note', `${x.server} ${x.proto} ${x.name || x.path} is designed to mount here`]);
    return out;
  }
  function render() {
    const d = st.data;
    const crumbs = el('nav', { class: 'fscrumbs', 'aria-label': 'Path' }, ...d.crumbs.map((c, i) => [
      i > 1 ? text('span', '/', 'sep') : null,
      el('button', { type: 'button', class: `crumb${c.mount ? ' mnt k-' + c.mount : ''}${i === d.crumbs.length - 1 ? ' cur' : ''}`,
        title: c.mount ? `${c.path} · ${c.fstype || FS_KIND[c.mount]} mount` : c.path, onclick: () => go(c.path) }, c.name)]));
    const filter = el('input', { type: 'search', placeholder: 'filter', 'aria-label': 'Filter this folder', value: st.filter,
      oninput: () => { st.filter = filter.value.toLowerCase(); drawList(); } });
    const filesToggle = el('label', { class: 'check small' }, el('input', { type: 'checkbox', checked: st.files, onchange: (ev) => { st.files = ev.target.checked; drawList(); } }), 'files');
    const m = d.here && d.here.mount;
    const here = el('div', { class: 'fshere' },
      m ? el('div', { class: 'row' }, text('span', 'On', 'muted small'), button(m.target, () => go(m.target), 'link mono'), fsKindBadge(m),
        text('span', fsMountLine(m), 'muted small mono'), fsUsage(m)) : null,
      d.size ? text('span', `${fmtBytes(d.size.bytes)} · ${d.size.files.toLocaleString()} files here and below`, 'muted small') : null,
      d.error ? text('p', d.error, 'st-failed') : null,
      el('ul', { class: 'mvcheck' }, ...verdict(d).map(([lv, t]) => text('li', t, `lv-${lv}`))));
    const list = el('ul', { class: 'fslist', role: 'listbox', 'aria-label': `Folders in ${d.path}` });
    function drawList() {
      const f = st.filter, kids = [];
      const up = upPath(d.path);
      if (up) kids.push(el('li', {}, el('button', { type: 'button', class: 'fsrow dir', onclick: () => go(up) }, text('span', '↰', 'ic'), text('span', '..', 'n'))));
      for (const x of d.dirs.filter((x) => !f || x.name.toLowerCase().includes(f))) {
        const kind = x.mount ? x.mount.kind : null;
        const badges = [x.mount ? fsKindBadge(x.mount) : null,
          ...(x.exports || []).map((e) => text('span', `${e.proto}${e.planned ? '*' : ''}`, 'fsk k-share', )),
          ...(x.planned_mounts || []).map((p) => text('span', `← ${p.server}`, 'fsk k-planned')),
          x.mounts_inside ? text('span', `${x.mounts_inside.length} mount${x.mounts_inside.length === 1 ? '' : 's'} inside`, 'fsk') : null];
        const full = joinPath(d.path, x.name);
        kids.push(el('li', {}, el('div', { class: `fsrow dir${kind ? ' mnt k-' + kind : ''}` },
          el('button', { type: 'button', class: 'fsopen', onclick: () => go(full), title: x.mount ? `${full}: ${fsMountLine(x.mount)}` : full },
            text('span', kind ? (FS_NET.has(kind) ? '⇄' : '◉') : '▸', 'ic'), text('span', x.name, 'n'), ...badges,
            text('span', x.bytes ? fmtBytes(x.bytes) : '', 's')),
          onPick ? button('Use', () => onPick(full), 'btn ghost sm use') : null)));
      }
      if (st.files) {
        for (const x of d.files.filter((x) => !f || x.name.toLowerCase().includes(f))) {
          kids.push(el('li', {}, el('div', { class: 'fsrow file' }, text('span', x.link ? '↪' : '·', 'ic'),
            text('span', x.name + (x.link ? ` → ${x.link}` : ''), 'n'), text('span', fmtBytes(x.bytes), 's'))));
        }
        if (d.more_files) kids.push(text('li', `… and ${d.more_files.toLocaleString()} more files`, 'muted small fsmore'));
      }
      if (!d.dirs.length && !d.files.length && !d.error) kids.push(text('li', d.here && d.here.indexed ? 'empty in the index' : 'not indexed: the scan skipped this mount', 'muted small fsmore'));
      list.replaceChildren(...kids);
    }
    drawList();
    const mounts = el('details', { class: 'fsmounts', open: st.mountsOpen, ontoggle: (ev) => { st.mountsOpen = ev.target.open; } },
      el('summary', {}, `Mounts on ${d.host || st.host}`),
      el('ul', {}, ...d.mounts.filter((x) => x.kind !== 'virtual').map((x) => el('li', {},
        el('button', { type: 'button', class: `fsmnt${x.target === (m && m.target) ? ' cur' : ''}`, onclick: () => go(x.target), title: fsMountLine(x) },
          el('span', { class: 'mono' }, x.target), fsKindBadge(x), text('span', fsMountLine(x), 'muted small mono'), fsUsage(x))))),
      (d.incoming || []).length ? el('div', { class: 'stack' }, text('b', 'Designed share mounts', 'small'),
        ...d.incoming.map((x) => el('button', { type: 'button', class: 'fsmnt planned', onclick: () => go(upPath(x.target) || '/') },
          el('span', { class: 'mono' }, x.target), text('span', `${x.proto} ${x.name || x.path} from ${x.server}`, 'muted small')))) : null,
      d.mounts.some((x) => x.kind === 'virtual') ? text('p', `${d.mounts.filter((x) => x.kind === 'virtual').length} virtual mounts hidden (tmpfs, proc, overlay…)`, 'muted small') : null);
    const typed = el('input', { type: 'text', class: 'mono', value: d.path, 'aria-label': 'Path', spellcheck: 'false',
      onkeydown: (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); go(typed.value.trim() || '/'); } } });
    const foot = el('div', { class: 'row fsfoot' }, typed, button('Go', () => go(typed.value.trim() || '/'), 'btn ghost sm'),
      onPick ? button(pickLabel || (pick === 'mount' ? 'Mount here' : 'Use this folder'), () => onPick(typed.value.trim() === d.path ? d.path : typed.value.trim()), 'btn pri sm') : null);
    box.replaceChildren(el('div', { class: 'row fstop' }, crumbs, el('span', { class: 'row fstools' }, filter, filesToggle)),
      here, el('div', { class: 'fsbody' }, list, mounts), foot);
  }
  box.append(text('p', 'Reading the index…', 'muted small'));
  box.go = go;
  box.state = st;
  box.setHost = (h, p = '/') => { st.host = h; go(p); };
  go(path);
  return box;
}

/* a modal folder picker: resolves to the chosen path, or null */
function pickPath(host, path, { title = 'Pick a folder', pick = 'folder', label } = {}) {
  return new Promise((resolve) => {
    if (!host) { toast('Pick the host first'); resolve(null); return; }
    const dlg = el('dialog', { class: 'fsdlg', 'aria-label': title });
    const done = (v) => { dlg.close(); dlg.remove(); resolve(v); };
    dlg.append(el('div', { class: 'row' }, el('h2', {}, title), text('span', host, 'fsk'), el('span', { class: 'grow' }),
      button('Cancel', () => done(null), 'btn ghost sm')),
      fsBrowser({ host, path: path || '/', pick, pickLabel: label, onPick: (p) => done(p) }));
    dlg.addEventListener('cancel', (ev) => { ev.preventDefault(); done(null); });
    document.body.append(dlg);
    dlg.showModal();
  });
}
