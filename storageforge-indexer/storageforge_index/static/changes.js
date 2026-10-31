'use strict';
/* Staged change plans: folders, btrfs, mounts and drives. Tasks are staged from the topology view (actions on boxes
   and in the folder browser), reviewed and checked in the Changes tab, and downloaded as a Bash script or an Ansible
   playbook. Task forms are built from /api/changes/types. Loaded after moves.js; uses the shared helpers. */

const CH = { types: null, plans: [], plan: { name: '', tasks: [] }, dirty: false, result: null };
const CH_DRAFT = 'sf.changes.draft';
try {
  const d = JSON.parse(localStorage.getItem(CH_DRAFT) || 'null');
  if (d && Array.isArray(d.tasks)) {
    CH.plan = d;
    CH.dirty = Boolean(d.dirty);
  }
} catch { /* no draft */ }

function chKeep() {
  try {
    if (!CH.plan.tasks.length && !CH.plan.name && !CH.plan.id) {
      localStorage.removeItem(CH_DRAFT);
    } else {
      localStorage.setItem(CH_DRAFT, JSON.stringify({ ...CH.plan, dirty: CH.dirty }));
    }
  } catch { /* storage blocked */ }
}
async function chTypes() { if (!CH.types) CH.types = (await getJSON('/api/changes/types')).types; return CH.types; }
function chTouch() {
  CH.dirty = true;
  CH.result = null;
  if (CH.plan.ran_at) CH.plan.ran_at = null;
  chKeep();
  renderStageBar();
  if (T.mode === 'topo') renderTopo();
}

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
const tasksOn = (host) => (CH.plan.ran_at && !CH.dirty) ? [] : CH.plan.tasks.filter((t) => t.host === host);
function mountFor(host, path) {      // the mount a path is on, from the topology (the path itself when unknown)
  const m = (T.docs.get(host) || {}).m;
  return (m && containing(path, [...m.nodes.values()].filter((x) => x.kind === 'mount' && !x.planned).map((x) => x.target))) || path;
}

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
      input = el('input', { type: 'text', class: ['path', 'device', 'devices', 'dataset', 'name', 'size', 'host', 'spec', 'options', 'confirm'].includes(f.kind) ? 'mono' : '',
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
  const acts = stageActions(doc, n);
  return acts.length ? [el('h3', {}, 'Plan a change'), el('div', { class: 'row wrap' },
    ...acts.map((a) => button(a.label, a.run, a.primary ? 'btn sm' : 'btn ghost sm')))] : [];
}
function stageActions(doc, n) {
  const h = doc.host, b = (label, type, preset) => ({ label, run: () => openTask(type, h, preset) });
  const btrfsMounts = [...doc.m.nodes.values()].filter((x) => x.kind === 'mount' && /btrfs/.test(x.sub || ''));
  const out = [];
  if (n.kind === 'disk') {
    const dev = '/dev/' + bare(n.ref.dev);
    out.push(b('Partition…', 'partition', { disk: dev }), b('Format whole disk…', 'format', { device: dev }));
    if (btrfsMounts.length) out.push(b('Add to a btrfs pool…', 'btrfs-add', { device: dev, target: btrfsMounts[0].target }));
    out.push(b('New ZFS pool…', 'zfs-pool', { devices: dev }), b('New volume group…', 'lvm-vg', { devices: dev }), b('Add to a volume group…', 'lvm-vg-extend', { device: dev }));
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
  } else if (n.kind === 'pool' && n.ref.type === 'zfs') {
    out.push(b('New dataset…', 'zfs-dataset', { dataset: n.ref.name + '/' }), b('Snapshot…', 'zfs-snapshot', { dataset: n.ref.name, name: new Date().toISOString().slice(0, 10) }),
      b('Send a snapshot…', 'zfs-send', { dataset: n.ref.name }), b('Scrub', 'zfs-scrub', { pool: n.ref.name }));
  } else if (n.kind === 'pool' && n.ref.type === 'lvm') {
    const [vg, lv] = String(n.ref.name || '').split('/');
    out.push(b('New volume…', 'lvm-lv', { vg }), b('Grow…', 'lvm-extend', { vg, lv: lv || '' }), b('Snapshot…', 'lvm-snapshot', { vg, lv: lv || '', name: `${lv || 'lv'}-snap` }));
  } else if (n.kind === 'subvol') {
    const mnt = [...doc.m.nodes.values()].find((x) => x.kind === 'mount' && doc.m.edges.some(([a, c]) => a === n.key && c === x.key));
    const uuid = (n.part && n.part.uuid) || '';
    if (mnt) out.push(b('Snapshot…', 'snapshot', { source: mnt.target, dest: `${mnt.target}/.snapshots/${new Date().toISOString().slice(0, 10)}` }));
    out.push(b('Mount it (again)…', 'mount', { source: uuid ? 'UUID=' + uuid : '', subvol: n.ref.name, fstype: 'btrfs', options: 'noatime,nofail' }));
  } else if (n.kind === 'mount') {
    const btrfs = /btrfs/.test(n.sub || '');
    out.push({ label: 'Browse folders', run: () => browseFolders(h, n.target, n.target), primary: true },
      b('New folder…', 'dir', { path: n.target.replace(/\/$/, '') + '/' }));
    if (btrfs) out.push(b('New subvolume here…', 'subvolume', { path: n.target.replace(/\/$/, '') + '/' }),
      b('Snapshot…', 'snapshot', { source: n.target, dest: `${n.target.replace(/\/$/, '')}/.snapshots/${new Date().toISOString().slice(0, 10)}` }),
      b('Send a snapshot…', 'btrfs-send', { source: `${n.target.replace(/\/$/, '')}/.snapshots/` }));
    const opts = (n.sub || '').split(' · ')[1] || '';
    out.push(b('Mount options…', 'mount-options', { target: n.target, options: opts }), b('Unmount…', 'unmount', { target: n.target }));
  }
  return out;
}
/* tasks staged on a box: planned boxes are their task; a mount also owns what is staged inside it */
function stagedOn(doc, n) {
  const mounts = [...doc.m.nodes.values()].filter((x) => x.kind === 'mount').map((x) => x.target);
  return tasksOn(doc.host).filter((t) => {
    const p = t.params || {};
    if (n.plannedPath) return ['subvolume', 'snapshot'].includes(t.type) && (p.path || p.dest) === n.plannedPath;
    if (n.kind === 'mount' && n.planned) return t.type === 'mount' && p.target === n.target;
    if (n.kind === 'mount') {
      if (t.type === 'unmount' || t.type === 'mount') return t.type === 'unmount' && p.target === n.target;
      const path = p.path || p.dest || p.target || p.source;
      return !!path && path.startsWith('/') && !path.startsWith('/dev/') && containing(path, mounts) === n.target;
    }
    if (n.kind === 'disk' || n.kind === 'part') {
      const dev = bare(p.device || p.disk || (String(p.target || '').startsWith('/dev/') ? p.target : ''));
      return !!dev && (n.key === 'part:' + dev || n.key === 'disk:' + dev);
    }
    return false;
  });
}
function unstage(t) {
  const i = CH.plan.tasks.indexOf(t);
  if (i < 0) return;
  CH.plan.tasks.splice(i, 1);
  chTouch();
  if (!$('#tab-changes').hidden) renderChanges();
}
function folderActions(host, full, btrfs) {
  const go = (type, preset) => () => openTask(type, host, preset);
  return [{ label: 'Rename or move…', run: go('rename', { path: full, dest: full }) },
    { label: 'Move to trash', run: go('trash', { path: full }) },
    { label: 'Owner and permissions…', run: go('perms', { path: full }) },
    { label: 'Link to it from…', run: go('symlink', { path: '', target: full }) },
    ...(btrfs ? [{ label: 'Turn into a subvolume', run: go('to-subvolume', { path: full }) },
      { label: 'Snapshot (if a subvolume)…', run: go('snapshot', { source: full, dest: full + '-snap' }) }] : []),
    { label: 'Copy to another disk (Moves)…', run: () => moveFrom(host, full) }];
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
  const planned = staged.filter((t) => ['dir', 'subvolume', 'snapshot'].includes(t.type) && dirOf(t.params.path || t.params.dest || '') === r.path)
    .map((t) => ({ name: (t.params.path || t.params.dest).split('/').pop(), planned: t.type }));
  const rows = [...r.dirs.map((d) => ({ ...d })), ...planned.filter((p) => !r.dirs.some((d) => d.name === p.name))];
  const menu = (full) => {
    const acts = folderActions(host, full, btrfs);
    const s = el('select', { 'aria-label': `Change ${full}`, class: 'act' }, new Option('Change…', ''), ...acts.map((a, i) => new Option(a.label, i)));
    s.addEventListener('change', () => { const a = acts[s.value]; s.value = ''; if (a) a.run(); });
    return s;
  };
  const rowMenu = (d, full) => () => [{ heading: full },
    d.mount || d.planned ? null : { label: 'Open', run: () => browseFolders(host, full, mountTarget) },
    { label: 'Largest files in it', run: () => runSearch({ under: full, host, size_gt: '1MiB' }) },
    ...(d.planned || d.mount ? [] : ['-', { heading: 'Plan a change' }, ...folderActions(host, full, btrfs)]),
    ...staged.filter((t) => [t.params.path, t.params.dest, t.params.target].includes(full)).flatMap((t) =>
      [{ label: `Edit: ${taskTitle(t)}`, run: () => openTask(t.type, host, {}, t) }, { label: `Unstage: ${taskTitle(t)}`, danger: true, run: () => { unstage(t); browseFolders(host, r.path, mountTarget); } }]),
    '-', { label: 'Copy path', run: () => copyText(full) }];
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
      const li = el('li', { class: marks.length ? 'staged' : '' },
        d.mount || d.planned ? el('span', { class: 'n mono' }, d.name) : button(d.name, () => browseFolders(host, full, mountTarget), 'n mono link'),
        text('span', d.mount ? `${d.mount} mount` : d.bytes ? fmtBytes(d.bytes) : '', 's'),
        marks.length ? text('span', marks.join(' · '), 'mark') : '',
        d.planned || d.mount ? '' : menu(full));
      li._menu = rowMenu(d, full);
      return li;
    })),
    rows.length ? '' : text('p', r.indexed ? 'No subfolders.' : 'This mount was not indexed.', 'muted'));
}

/* ── stage bar and the Changes tab ───────────────────────────────── */
function renderStageBar() {
  const bar = $('#stagebar');
  if (!bar) return;
  const isRan = CH.plan.ran_at && !CH.dirty;
  const n = isRan ? 0 : CH.plan.tasks.length;
  bar.hidden = !n || T.mode !== 'topo';
  if (!n) return;
  bar.replaceChildren(text('span', `${CH.plan.name || 'Unnamed plan'} · ${n} staged change${n === 1 ? '' : 's'}${CH.dirty ? ' (not saved)' : ''}`),
    button('Review', () => showTab('changes'), 'btn pri sm'));
}
async function loadChanges(selectId) {
  try {
    await chTypes();
    CH.plans = (await getJSON('/api/changes')).plans;
    if (selectId) {
      CH.plan = await getJSON(`/api/changes/${selectId}`);
      CH.dirty = false;
      chKeep();
    } else if (CH.plan.id) {
      const match = CH.plans.find((x) => String(x.id) === String(CH.plan.id));
      if (match) {
        CH.plan.ran_at = match.ran_at;
        if (match.ran_at && !CH.dirty) {
          CH.plan = { name: '', tasks: [] };
          CH.dirty = false;
          CH.result = null;
          chKeep();
          renderStageBar();
          if (T.mode === 'topo') renderTopo();
        }
      }
    }
  } catch (err) { $('#changesbox').replaceChildren(text('p', err.message, 'st-failed')); return; }
  renderChanges();
}
/* an apply ended: a plan that finished is no longer staged, and moves to "Already ran" in the picker */
async function chApplied(id) {
  try { CH.plans = (await getJSON('/api/changes')).plans; } catch { return; }
  const ran = CH.plans.find((x) => String(x.id) === String(id))?.ran_at;
  if (ran && (String(CH.plan.id) === String(id) || !CH.plan.id)) {
    CH.plan = { name: '', tasks: [] };
    CH.dirty = false;
    CH.result = null;
    chKeep();
    renderStageBar();
    if (T.mode === 'topo') renderTopo();
  }
  renderChanges();
}
async function chUnstage() {
  if (CH.plan.id && (CH.result?.all_done || CH.plan.ran_at)) {
    try { await postJSON(`/api/changes/${CH.plan.id}/ran`, {}); } catch { /* ignore */ }
  }
  CH.plan = { name: '', tasks: [] };
  CH.dirty = false;
  CH.result = null;
  chKeep();
  renderStageBar();
  if (T.mode === 'topo') renderTopo();
  renderChanges();
  chMsg('Plan unstaged.', 'st-ok');
}
function renderChanges() {
  const p = CH.plan;
  const planOption = (x) => new Option(`${x.name} (${x.tasks})${x.ran_at ? ` · ran ${stamp(x.ran_at)}` : ''}`, x.id);
  const ran = CH.plans.filter((x) => x.ran_at);
  const pick = el('select', { 'aria-label': 'Change plan', onchange: async () => {
    if (CH.dirty && p.tasks.length && !confirm('Leave this plan? Its unsaved changes are lost.')) { pick.value = p.id || ''; return; }
    CH.result = null;
    if (pick.value) await loadChanges(pick.value); else { CH.plan = { name: '', tasks: [] }; CH.dirty = false; chKeep(); renderChanges(); renderStageBar(); }
  } }, new Option('New plan…', ''), ...CH.plans.filter((x) => !x.ran_at).map(planOption),
    ran.length ? el('optgroup', { label: 'Already ran' }, ...ran.map(planOption)) : '');
  pick.value = p.id || '';
  const name = el('input', { type: 'text', placeholder: 'plan name, e.g. Reorganise raid01', 'aria-label': 'Plan name',
    onchange: () => { p.name = name.value.trim(); chTouch(); } });
  name.value = p.name || '';
  const res = CH.result;
  const move = (i, j) => { [p.tasks[i], p.tasks[j]] = [p.tasks[j], p.tasks[i]]; chTouch(); renderChanges(); };
  const list = el('ol', { class: 'chtasks' }, ...p.tasks.map((t, i) => {
    const r = res && res.tasks[i];
    const worst = r ? (r.items.some((x) => x.level === 'crit') ? 'crit' : r.items.some((x) => x.level === 'warn') ? 'warn' : 'ok') : '';
    const li = el('li', { class: `card ${worst ? 'lv-border-' + worst : ''}` },
      el('div', { class: 'row' }, el('b', {}, `${i + 1}. ${taskTitle(t)}`),
        el('span', { class: 'row tools' },
          i ? button('↑', () => move(i, i - 1), 'btn ghost sm') : '',
          i < p.tasks.length - 1 ? button('↓', () => move(i, i + 1), 'btn ghost sm') : '',
          button('Edit', () => openTask(t.type, t.host, {}, t), 'btn ghost sm'),
          button('Remove', () => { p.tasks.splice(i, 1); chTouch(); renderChanges(); }, 'btn ghost sm danger'))),
      text('span', `${t.host}${(CH.types && CH.types[t.type] && CH.types[t.type].destructive) ? ' · destructive' : ''}${t.note ? ' · ' + t.note : ''}`, 'muted small'),
      // drive tasks staged from a planner design arrive unconfirmed: the server refuses them until the device is typed
      CH.types?.[t.type]?.destructive && t.params.confirm !== (t.params.device || t.params.disk || t.params.devices)
        ? text('p', `Not confirmed: Edit it and type ${t.params.device || t.params.disk} again. Until then the plan can't be checked or saved.`, 'st-failed small') : '',
      r ? el('ul', { class: 'mvcheck' }, ...r.items.map((x) => el('li', { class: `lv-${x.level}` }, x.text))) : '');
    li._menu = () => [{ heading: `${i + 1}. ${taskTitle(t)}` }, { label: 'Edit…', run: () => openTask(t.type, t.host, {}, t) },
      { label: 'Move up', disabled: !i, run: () => move(i, i - 1) }, { label: 'Move down', disabled: i === p.tasks.length - 1, run: () => move(i, i + 1) },
      { label: 'Move to the top', disabled: !i, run: () => { p.tasks.unshift(...p.tasks.splice(i, 1)); chTouch(); renderChanges(); } },
      { label: 'Duplicate', run: () => { p.tasks.splice(i + 1, 0, { ...structuredClone(t), id: 't' + Date.now().toString(36) }); chTouch(); renderChanges(); } },
      { label: `Show ${t.host} in the topology`, run: async () => {
        if (T.mode !== 'topo') { setMode('topo', false); await loadDesigns(); }
        focusHost(t.host);
      } },
      '-', { label: 'Remove', danger: true, run: () => { p.tasks.splice(i, 1); chTouch(); renderChanges(); } }];
    return li;
  }));
  const msg = el('p', { id: 'chmsg', class: 'muted', hidden: true });
  $('#changesbox').replaceChildren(
    el('div', { class: 'row' }, pick, name),
    p.ran_at && !CH.dirty ? text('p', `This plan ran on ${stamp(p.ran_at)}. Deploying it again is safe: tasks already done are left alone.`, 'st-ok small') : '',
    res?.all_done ? el('div', { class: 'card row wrap' },
      text('b', 'All changes in this plan already exist on the hosts.', 'st-ok'),
      button('Unstage plan', chUnstage, 'btn sm pri')) : '',
    p.tasks.length ? list : text('p', 'No changes staged. In the topology, select a disk, partition, pool, subvolume or mount and use "Plan a change", or browse a mount\'s folders.', 'muted'),
    res ? el('p', { class: res.crit ? 'st-failed' : res.warn ? 'st-running' : 'st-ok' }, `${res.crit} critical · ${res.warn} warning${res.warn === 1 ? '' : 's'}`) : '',
    el('div', { class: 'row end wrap' },
      p.id ? button('Delete plan', chDelete, 'btn ghost sm danger') : '',
      p.tasks.length ? button('Unstage', chUnstage, 'btn ghost sm') : '',
      button('Check', chCheck, 'btn sm'), button(CH.dirty ? 'Save*' : 'Save', chSave, 'btn sm'),
      button('Ansible playbook', () => chDownload('ansible'), 'btn sm'), button('Bash script', () => chDownload('script'), 'btn sm'),
      button('Deploy…', async () => {
        const id = CH.dirty || !CH.plan.id ? await chSave() : CH.plan.id;
        if (id) startDeploy('changes', id, 'report', `change plan "${CH.plan.name}"`);
      }, 'btn pri sm')),
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
