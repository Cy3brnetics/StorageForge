'use strict';
/* Staged change plans: folders, btrfs, mounts and drives. Tasks are staged from the topology view (actions on boxes
   and in the folder browser), reviewed and checked in the Changes tab, and downloaded as a Bash script or an Ansible
   playbook. Task forms are built from /api/changes/types. Loaded after moves.js; uses the shared helpers. */

const CH = { types: null, plans: [], plan: { name: '', tasks: [] }, dirty: false, result: null };
const CH_DRAFT = 'sf.changes.draft';
try { const d = JSON.parse(localStorage.getItem(CH_DRAFT) || 'null'); if (d && Array.isArray(d.tasks)) { CH.plan = d; CH.dirty = !!d.tasks.length; } } catch { /* no draft */ }

function chKeep() { try { localStorage.setItem(CH_DRAFT, JSON.stringify(CH.plan)); } catch { /* storage blocked */ } }
async function chTypes() { if (!CH.types) CH.types = (await getJSON('/api/changes/types')).types; return CH.types; }
function chTouch() { CH.dirty = true; CH.result = null; chKeep(); renderStageBar(); if (T.mode === 'topo') renderTopo(); }

function taskTitle(t) {
  const p = t.params || {};
  return ({
    dir: () => `Create folder ${p.path}`, rename: () => `Rename ${p.path} → ${p.dest}`, trash: () => `Move ${p.path} to the trash`,
    symlink: () => `Link ${p.path} → ${p.target}`, perms: () => `Owner and permissions of ${p.path}`,
    subvolume: () => `Create subvolume ${p.path}`, snapshot: () => `Snapshot ${p.source} → ${p.dest}`,
    'to-subvolume': () => `Turn ${p.path} into a subvolume`, 'btrfs-add': () => `Add ${p.device} to the pool at ${p.target}`,
    'btrfs-balance': () => `Convert ${p.target} to ${p.data}/${p.metadata}`, scrub: () => `Scrub ${p.target}`,
    mount: () => `Mount ${p.source}${p.subvol ? '[' + p.subvol + ']' : ''} at ${p.target}`,
    'mount-options': () => `Mount options of ${p.target}: ${p.options}`, unmount: () => `Unmount ${p.target}`,
    partition: () => `Partition ${p.disk}${p.fstype ? ' and format it ' + p.fstype : ''}`,
    format: () => `Format ${p.device} as ${p.fstype}`, label: () => `Label ${p.target} "${p.label}"`,
  }[t.type] || (() => t.type))();
}
const tasksOn = (host) => CH.plan.tasks.filter((t) => t.host === host);

/* ── staging from the topology ───────────────────────────────────── */
async function openTask(type, host, preset = {}, edit = null) {
  const types = await chTypes();
  const spec = types[type];
  showTab('details');
  const inputs = {};
  const fields = spec.fields.map((f) => {
    const v = edit ? edit.params[f.name] : preset[f.name] ?? f.default ?? '';
    let input;
    if (f.kind === 'bool') {
      input = el('input', { type: 'checkbox' }); input.checked = !!v;
      inputs[f.name] = () => input.checked;
      return el('label', { class: 'check' }, input, f.label);
    }
    if (f.kind === 'choice') {
      input = el('select', {}, ...f.options.map((o) => new Option(o || '(none)', o))); input.value = v || f.options[0];
    } else {
      input = el('input', { type: 'text', class: ['path', 'device', 'spec', 'options', 'confirm'].includes(f.kind) ? 'mono' : '',
                            placeholder: f.placeholder || (f.kind === 'confirm' ? 'e.g. /dev/sdc' : ''), autocomplete: 'off', spellcheck: 'false' });
      input.value = v;
    }
    inputs[f.name] = () => input.value.trim();
    return el('label', { class: 'field col' }, el('span', {}, f.label + (f.required ? '' : ' (optional)')), input);
  });
  const msg = el('p', { class: 'st-failed', hidden: true });
  const form = el('form', { class: 'stack card stageform' },
    el('div', { class: 'row' }, el('b', {}, spec.label), text('span', `${spec.group} · ${host}`, 'muted')),
    spec.help ? text('p', spec.help, 'muted small') : '',
    spec.destructive ? text('p', 'Destroys data on the device. The script only does this with --apply --destructive, and the Ansible playbook only with -e storageforge_destructive=true.', 'st-failed small') : '',
    ...fields, msg,
    el('div', { class: 'row end' }, button('Cancel', () => { if (T.sel) renderEditor(); else renderSummary(); }, 'btn ghost sm'),
      el('button', { type: 'submit', class: 'btn pri sm' }, edit ? 'Update task' : 'Stage it')));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const params = Object.fromEntries(Object.entries(inputs).map(([k, f]) => [k, f()]));
    const task = { type, host, params };
    try {   // validate on the server before staging: same rules the script and playbook are built with
      await postJSON('/api/changes/check', { name: 'check', tasks: [task] });
    } catch (err) { msg.hidden = false; msg.textContent = err.message; return; }
    if (edit) Object.assign(edit, { params }); else CH.plan.tasks.push({ id: 't' + Date.now().toString(36), ...task });
    chTouch();
    if (T.sel) renderEditor(); else showTab('changes');
  });
  $('#summary').replaceChildren(form);
  form.querySelector('input, select')?.focus();
}
function stageButtons(doc, n) {
  const h = doc.host, b = (label, type, preset) => button(label, () => openTask(type, h, preset), 'btn ghost sm');
  const btrfsMounts = [...doc.m.nodes.values()].filter((x) => x.kind === 'mount' && /btrfs/.test(x.sub || ''));
  const out = [];
  if (n.kind === 'disk') {
    const dev = '/dev/' + bare(n.ref.dev);
    out.push(b('Partition…', 'partition', { disk: dev }), b('Format whole disk…', 'format', { device: dev }));
    if (btrfsMounts.length) out.push(b('Add to a btrfs pool…', 'btrfs-add', { device: dev, target: btrfsMounts[0].target }));
  } else if (n.kind === 'part') {
    const dev = '/dev/' + n.ref.id, uuid = n.ref.uuid;
    out.push(b('Format…', 'format', { device: dev, fstype: n.ref.fs && n.ref.fs !== 'none' ? n.ref.fs : 'ext4' }),
      b('Label…', 'label', { target: n.ref.mount || dev, label: n.ref.label || '' }));
    if (!n.ref.mount && n.ref.fs && n.ref.fs !== 'none') out.push(b('Mount…', 'mount', { source: uuid ? 'UUID=' + uuid : dev, fstype: n.ref.fs, options: 'defaults,noatime,nofail' }));
    if (btrfsMounts.length && !n.ref.mount) out.push(b('Add to a btrfs pool…', 'btrfs-add', { device: dev, target: btrfsMounts[0].target }));
  } else if (n.kind === 'pool' && n.ref.type === 'btrfs') {
    const svs = doc.m.edges.filter(([a]) => a === n.key).map(([, c]) => c);
    const mounted = btrfsMounts.find((x) => doc.m.edges.some(([a, c]) => c === x.key && (a === n.key || svs.includes(a))));
    const at = mounted ? mounted.target : '';
    out.push(b('New subvolume…', 'subvolume', { path: at ? at + '/' : '' }),
      b('Convert profile…', 'btrfs-balance', { target: at, data: n.ref.level === 'single' ? 'raid1' : n.ref.level, metadata: n.ref.metaLevel || 'raid1' }),
      b('Add device…', 'btrfs-add', { target: at }), b('Scrub', 'scrub', { target: at }));
  } else if (n.kind === 'subvol') {
    const mnt = [...doc.m.nodes.values()].find((x) => x.kind === 'mount' && doc.m.edges.some(([a, c]) => a === n.key && c === x.key));
    const uuid = (n.part && n.part.uuid) || '';
    if (mnt) out.push(b('Snapshot…', 'snapshot', { source: mnt.target, dest: `${mnt.target}/.snapshots/${new Date().toISOString().slice(0, 10)}` }));
    out.push(b('Mount it (again)…', 'mount', { source: uuid ? 'UUID=' + uuid : '', subvol: n.ref.name, fstype: 'btrfs', options: 'noatime,nofail' }));
  } else if (n.kind === 'mount') {
    const btrfs = /btrfs/.test(n.sub || '');
    out.push(button('Browse folders', () => browseFolders(h, n.target, n.target), 'btn sm'),
      b('New folder…', 'dir', { path: n.target.replace(/\/$/, '') + '/' }));
    if (btrfs) out.push(b('New subvolume here…', 'subvolume', { path: n.target.replace(/\/$/, '') + '/' }),
      b('Snapshot…', 'snapshot', { source: n.target, dest: `${n.target.replace(/\/$/, '')}/.snapshots/${new Date().toISOString().slice(0, 10)}` }));
    const opts = (n.sub || '').split(' · ')[1] || '';
    out.push(b('Mount options…', 'mount-options', { target: n.target, options: opts }), b('Unmount…', 'unmount', { target: n.target }));
  }
  return out.length ? [el('h3', {}, 'Plan a change'), el('div', { class: 'row wrap' }, ...out)] : [];
}

/* ── folder browser: look around inside a mount and stage file changes ── */
async function browseFolders(host, path, mountTarget) {
  showTab('details');
  const box = el('div', { class: 'stack card' }, text('p', 'Reading the index…', 'muted'));
  $('#summary').replaceChildren(box);
  let r;
  try { r = await getJSON(`/api/browse?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}`); }
  catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); return; }
  const staged = tasksOn(host);
  const markFor = (p) => {
    const marks = [];
    for (const t of staged) {
      const q = t.params;
      if ((t.type === 'trash') && q.path === p) marks.push('to trash');
      if (t.type === 'rename' && q.path === p) marks.push('→ ' + q.dest);
      if (t.type === 'rename' && q.dest === p) marks.push('← ' + q.path);
      if (t.type === 'perms' && q.path === p) marks.push('owner/mode');
      if (t.type === 'to-subvolume' && q.path === p) marks.push('→ subvolume');
      if (t.type === 'symlink' && q.target === p) marks.push('linked from ' + q.path);
    }
    return marks;
  };
  const btrfs = /btrfs/.test(((T.docs.get(host) || {}).m?.nodes.get('mnt:' + mountTarget) || {}).sub || '');
  const base = r.path === '/' ? '' : r.path;
  const planned = staged.filter((t) => ['dir', 'subvolume', 'snapshot'].includes(t.type) && posixDir(t.params.path || t.params.dest) === r.path)
    .map((t) => ({ name: (t.params.path || t.params.dest).split('/').pop(), planned: t.type }));
  const rows = [...r.dirs.map((d) => ({ ...d })), ...planned.filter((p) => !r.dirs.some((d) => d.name === p.name))];
  const menu = (full) => {
    const s = el('select', { 'aria-label': `Change ${full}`, class: 'act' }, new Option('Change…', ''),
      new Option('Rename or move…', 'rename'), new Option('Move to trash', 'trash'), new Option('Owner and permissions…', 'perms'),
      new Option('Link to it from…', 'symlink'), ...(btrfs ? [new Option('Turn into a subvolume', 'to-subvolume'), new Option('Snapshot (if a subvolume)…', 'snapshot')] : []),
      new Option('Copy to another disk (Moves)…', 'moves'));
    s.addEventListener('change', () => {
      const v = s.value; s.value = '';
      if (v === 'moves') return moveFrom(host, full);
      const preset = { rename: { path: full, dest: full }, trash: { path: full }, perms: { path: full }, symlink: { path: '', target: full },
                       'to-subvolume': { path: full }, snapshot: { source: full, dest: full + '-snap' } }[v];
      openTask(v, host, preset);
    });
    return s;
  };
  const up = r.path !== mountTarget && r.path !== '/' ? r.path.replace(/\/[^/]*$/, '') || '/' : null;
  box.replaceChildren(
    el('div', { class: 'row' }, el('b', { class: 'mono' }, `${host}:${r.path}`),
      r.size ? text('span', `${fmtBytes(r.size.bytes)} · ${r.size.files.toLocaleString()} files`, 'muted') : ''),
    el('div', { class: 'row' }, up ? button('↑ Up', () => browseFolders(host, up, mountTarget), 'btn ghost sm') : '',
      button('+ New folder here', () => openTask('dir', host, { path: base + '/' }), 'btn ghost sm'),
      btrfs ? button('+ New subvolume here', () => openTask('subvolume', host, { path: base + '/' }), 'btn ghost sm') : '',
      button('Back to the box', () => { if (T.sel) renderEditor(); else renderSummary(); }, 'btn ghost sm')),
    el('ul', { class: 'fbrowse' }, ...rows.map((d) => {
      const full = `${base}/${d.name}`;
      const marks = d.planned ? [`planned ${d.planned === 'dir' ? 'folder' : d.planned}`] : markFor(full);
      return el('li', { class: marks.length ? 'staged' : '' },
        d.mount || d.planned ? el('span', { class: 'n mono' }, d.name) : button(d.name, () => browseFolders(host, full, mountTarget), 'n mono link'),
        text('span', d.mount ? `${d.mount} mount` : d.bytes ? fmtBytes(d.bytes) : '', 's'),
        marks.length ? text('span', marks.join(' · '), 'mark') : '',
        d.planned || d.mount ? '' : menu(full));
    })),
    rows.length ? '' : text('p', r.indexed ? 'No subfolders.' : 'This mount was not indexed.', 'muted'));
}
const posixDir = (p) => (p || '').replace(/\/[^/]*$/, '') || '/';

/* ── stage bar and the Changes tab ───────────────────────────────── */
function renderStageBar() {
  const bar = $('#stagebar');
  if (!bar) return;
  const n = CH.plan.tasks.length;
  bar.hidden = !n || T.mode !== 'topo';
  if (!n) return;
  bar.replaceChildren(text('span', `${CH.plan.name || 'Unnamed plan'} · ${n} staged change${n === 1 ? '' : 's'}${CH.dirty ? ' (not saved)' : ''}`),
    button('Review', () => showTab('changes'), 'btn pri sm'));
}
async function loadChanges(selectId) {
  try {
    await chTypes();
    CH.plans = (await getJSON('/api/changes')).plans;
    if (selectId) { CH.plan = await getJSON(`/api/changes/${selectId}`); CH.dirty = false; chKeep(); }
  } catch (err) { $('#changesbox').replaceChildren(text('p', err.message, 'st-failed')); return; }
  renderChanges();
}
function renderChanges() {
  const p = CH.plan;
  const pick = el('select', { 'aria-label': 'Change plan', onchange: async () => {
    if (CH.dirty && p.tasks.length && !confirm('Leave this plan? Its unsaved changes are lost.')) { pick.value = p.id || ''; return; }
    CH.result = null;
    if (pick.value) await loadChanges(pick.value); else { CH.plan = { name: '', tasks: [] }; CH.dirty = false; chKeep(); renderChanges(); renderStageBar(); }
  } }, new Option('New plan…', ''), ...CH.plans.map((x) => new Option(`${x.name} (${x.tasks})`, x.id)));
  pick.value = p.id || '';
  const name = el('input', { type: 'text', placeholder: 'plan name, e.g. Reorganise raid01', 'aria-label': 'Plan name',
    onchange: () => { p.name = name.value.trim(); chTouch(); } });
  name.value = p.name || '';
  const res = CH.result;
  const list = el('ol', { class: 'chtasks' }, ...p.tasks.map((t, i) => {
    const r = res && res.tasks[i];
    const worst = r ? (r.items.some((x) => x.level === 'crit') ? 'crit' : r.items.some((x) => x.level === 'warn') ? 'warn' : 'ok') : '';
    return el('li', { class: `card ${worst ? 'lv-border-' + worst : ''}` },
      el('div', { class: 'row' }, el('b', {}, `${i + 1}. ${taskTitle(t)}`),
        el('span', { class: 'row tools' },
          i ? button('↑', () => { [p.tasks[i - 1], p.tasks[i]] = [p.tasks[i], p.tasks[i - 1]]; chTouch(); renderChanges(); }, 'btn ghost sm') : '',
          i < p.tasks.length - 1 ? button('↓', () => { [p.tasks[i + 1], p.tasks[i]] = [p.tasks[i], p.tasks[i + 1]]; chTouch(); renderChanges(); }, 'btn ghost sm') : '',
          button('Edit', () => openTask(t.type, t.host, {}, t), 'btn ghost sm'),
          button('Remove', () => { p.tasks.splice(i, 1); chTouch(); renderChanges(); }, 'btn ghost sm danger'))),
      text('span', `${t.host}${(CH.types && CH.types[t.type] && CH.types[t.type].destructive) ? ' · destructive' : ''}`, 'muted small'),
      r ? el('ul', { class: 'mvcheck' }, ...r.items.map((x) => el('li', { class: `lv-${x.level}` }, x.text))) : '');
  }));
  const msg = el('p', { id: 'chmsg', class: 'muted', hidden: true });
  $('#changesbox').replaceChildren(
    el('div', { class: 'row' }, pick, name),
    p.tasks.length ? list : text('p', 'No changes staged. In the topology, select a disk, partition, pool, subvolume or mount and use "Plan a change", or browse a mount\'s folders.', 'muted'),
    res ? el('p', { class: res.crit ? 'st-failed' : res.warn ? 'st-running' : 'st-ok' }, `${res.crit} critical · ${res.warn} warning${res.warn === 1 ? '' : 's'}`) : '',
    el('div', { class: 'row end' },
      p.id ? button('Delete plan', chDelete, 'btn ghost sm danger') : '',
      button('Check', chCheck, 'btn sm'), button(CH.dirty ? 'Save*' : 'Save', chSave, 'btn sm'),
      button('Ansible playbook', () => chDownload('ansible'), 'btn sm'), button('Bash script', () => chDownload('script'), 'btn pri sm')),
    msg,
    el('details', { class: 'mvhelp' }, el('summary', {}, 'How to run it'),
      text('p', 'Bash: ./changes-<plan>.sh reports what is already done, what would change and what is blocked. sudo … --apply makes the changes in order and stops at the first failure; drive tasks also need --destructive. Add --host user@host to run it on that machine. Ansible: ansible-playbook -i inventory.ini changes-<plan>.yml --check --diff first; drive tasks need -e storageforge_destructive=true. The inventory lines are at the top of the playbook.', 'muted')));
}
function chMsg(text_, cls = 'st-failed') { const m = $('#chmsg'); if (m) { m.hidden = false; m.textContent = text_; m.className = cls; } }
async function chCheck() {
  try { CH.result = await (await postJSON('/api/changes/check', { ...CH.plan, name: CH.plan.name || 'unnamed' })).json(); renderChanges(); }
  catch (err) { chMsg(err.message); }
}
async function chSave() {
  const p = CH.plan;
  if (!p.name) { chMsg('Give the plan a name first'); return null; }
  try {
    const r = p.id ? await (await api(`/api/changes/${p.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(p) })).json()
      : await (await postJSON('/api/changes', p)).json();
    await loadChanges(r.id); renderStageBar(); chMsg('Saved.', 'st-ok');
    return r.id;
  } catch (err) { chMsg(err.message); return null; }
}
async function chDownload(kind) {
  const id = CH.dirty || !CH.plan.id ? await chSave() : CH.plan.id;
  if (!id) return;
  try {
    const res = await api(`/api/changes/${id}/${kind}`);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(await res.blob());
    a.download = (res.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || `changes.${kind === 'script' ? 'sh' : 'yml'}`;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    chMsg(`Downloaded ${a.download}.`, 'st-ok');
  } catch (err) { chMsg(err.message); }
}
async function chDelete() {
  if (!confirm(`Delete the plan "${CH.plan.name}"? Downloaded scripts keep working.`)) return;
  try { await api(`/api/changes/${CH.plan.id}`, { method: 'DELETE' }); CH.plan = { name: '', tasks: [] }; CH.dirty = false; chKeep(); renderStageBar(); loadChanges(); }
  catch (err) { chMsg(err.message); }
}
