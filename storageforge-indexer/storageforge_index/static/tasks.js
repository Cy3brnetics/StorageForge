'use strict';
/* Tasks view: build storage tasks from blocks (rsync copies, rotating backups, snapshots, guards, if/try, commands),
   see each block checked against the index as you go, and install the task on its host as a systemd service + timer.
   Blocks come from the palette (drag, or click to add); drop them between blocks or into an If/Try. Each block shows
   its fields; collapse it to a one-line sentence. Ctrl+Z undoes. Loaded after app.js, topology.js and fsbrowse.js. */

const TK = { loaded: false, types: {}, cats: {}, templates: [], schedules: {}, installed: {}, list: [], hosts: [],
  task: null, dirty: false, check: null, error: '', undo: [], redo: [], drag: null, timer: 0, req: 0, target: null,
  shut: new WeakSet(), filter: '' };
const TK_ICON = { guard: '⛨', control: '⑂', copy: '⇉', snapshot: '◷', service: '⚙', other: '›' };

async function loadTasks(selectId) {
  const box = $('#tasksview');
  try {
    const [r, h] = await Promise.all([getJSON('/api/tasks'), getJSON('/api/hosts')]);
    Object.assign(TK, { loaded: true, types: r.types, cats: r.categories, templates: r.templates, schedules: r.schedules,
      installed: r.installed, list: r.tasks, hosts: h.indexed.map((x) => x.hostname).sort() });
    if (selectId) { TK.task = await getJSON(`/api/tasks/${selectId}`); TK.dirty = false; TK.undo = []; TK.redo = []; }
  } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed tkerr')); return; }
  if (!TK.task) TK.task = blankTask();
  renderTasks();
  tkCheckSoon(0);
}
const blankTask = (host = '') => ({ name: '', host: host || TK.hosts[0] || '', schedule: '', timeout_min: 0, blocks: [], on_fail: [] });
function newBlock(type, params = {}) {
  const t = TK.types[type], p = {};
  for (const s of t.params) p[s.name] = params[s.name] ?? (Array.isArray(s.default) ? [...s.default] : s.default ?? (s.kind === 'bool' ? false : ''));
  const b = { type, params: p, off: false };
  if (t.slots) b.slots = Object.fromEntries(t.slots.map((s) => [s, []]));
  return b;
}

/* ── edits, undo ─────────────────────────────────────────────────────── */
function tkEdit(fn, rerender = true) {
  TK.undo.push(JSON.stringify(TK.task)); if (TK.undo.length > 80) TK.undo.shift();
  TK.redo = [];
  fn();
  TK.dirty = true;
  if (rerender) renderTasks(); else tkHeadState();
  tkCheckSoon();
}
function tkRelabel() {      // after an edit that kept the DOM: refresh the one-line sentences
  for (const node of document.querySelectorAll('.tkb')) {
    const s = node.querySelector(':scope > .tkbh .tksent');
    if (s) s.textContent = tkLabel(node._block);
  }
}
function tkUndo(redo = false) {
  const from = redo ? TK.redo : TK.undo, to = redo ? TK.undo : TK.redo;
  if (!from.length) return;
  to.push(JSON.stringify(TK.task));
  TK.task = JSON.parse(from.pop());
  TK.dirty = true;
  renderTasks(); tkCheckSoon();
}
function tkCheckSoon(ms = 450) { clearTimeout(TK.timer); TK.timer = setTimeout(tkCheck, ms); }
async function tkCheck() {
  const n = ++TK.req;
  try {
    const r = await postJSON('/api/tasks/check', TK.task);
    const j = await r.json();
    if (n !== TK.req) return;
    TK.check = j; TK.error = '';
  } catch (err) { if (n !== TK.req) return; TK.check = null; TK.error = err.message; }
  tkPaintChecks();
}

/* ── layout ──────────────────────────────────────────────────────────── */
function renderTasks() {
  const box = $('#tasksview');
  if (!box || !TK.loaded) return;
  const scrollEl = box.querySelector('.tkcanvas'), keep = scrollEl ? scrollEl.scrollTop : 0;
  box.replaceChildren(tkSide(), el('section', { class: 'tkmain' }, tkHead(), tkCanvas()),
    el('datalist', { id: 'tkhosts' }, ...TK.hosts.map((h) => new Option(h, h))));
  const c = box.querySelector('.tkcanvas'); if (c) c.scrollTop = keep;
  tkPaintChecks();
}

function tkSide() {
  const t = TK.task;
  const items = TK.list.map((x) => {
    const inst = TK.installed[x.slug] || [];
    const state = !inst.length ? '' : inst.some((i) => i.hash !== x.hash) ? 'changed' : 'installed';
    return el('li', {}, el('button', { type: 'button', class: `tkitem${t.id === x.id ? ' cur' : ''}`, onclick: () => tkOpen(x.id) },
      text('b', x.name), text('span', `${x.host || '—'} · ${TK.schedules[x.schedule] || x.schedule || 'by hand'}`, 'muted small'),
      state ? text('span', state === 'installed' ? `installed on ${inst.map((i) => i.host).join(', ')}` : 'changed since install', `small ${state === 'installed' ? 'st-ok' : 'st-running'}`) : null));
  });
  const search = el('input', { type: 'search', placeholder: 'find a block', 'aria-label': 'Find a block', value: TK.filter,
    oninput: () => { TK.filter = search.value.toLowerCase(); drawPalette(); } });
  const pal = el('div', { class: 'tkpal' });
  const drawPalette = () => {
    const f = TK.filter;
    pal.replaceChildren(...Object.entries(TK.cats).map(([cat, label]) => {
      const types = Object.entries(TK.types).filter(([k, v]) => v.cat === cat && (!f || v.label.toLowerCase().includes(f) || k.includes(f)));
      if (!types.length) return null;
      return el('div', { class: 'tkpgroup' }, text('span', label, 'tkcat'), ...types.map(([k, v]) =>
        el('button', { type: 'button', class: `tkchip c-${cat}`, draggable: 'true', title: v.help || v.label,
          ondragstart: (ev) => { TK.drag = { make: k }; ev.dataTransfer.effectAllowed = 'copy'; ev.dataTransfer.setData('text/plain', k); document.body.classList.add('tkdragging'); },
          ondragend: tkDragEnd,
          onclick: () => tkAppend(newBlock(k)) }, text('span', TK_ICON[cat], 'ic'), v.label)));
    }).filter(Boolean));
  };
  drawPalette();
  return el('aside', { class: 'tkside' },
    el('div', { class: 'row' }, text('h3', 'Tasks'), el('span', { class: 'grow' }), button('+ New', () => tkNew(), 'btn sm')),
    el('ul', { class: 'tklist' }, ...items, TK.list.length ? null : text('li', 'No saved tasks yet.', 'muted small')),
    el('div', { class: 'row' }, text('h3', 'Blocks'), search),
    text('p', TK.target ? 'Click adds to the selected slot; drag to place anywhere.' : 'Click adds at the end; drag to place anywhere.', 'muted small'),
    pal);
}

function tkHead() {
  const t = TK.task;
  const name = el('input', { type: 'text', class: 'tkname', placeholder: 'Task name, e.g. Nightly photos backup', 'aria-label': 'Task name',
    value: t.name, onchange: () => tkEdit(() => { t.name = name.value.trim(); }, false) });
  const host = el('select', { 'aria-label': 'Runs on', onchange: () => tkEdit(() => { t.host = host.value; }) },
    new Option('host…', ''), ...TK.hosts.map((h) => new Option(h, h)));
  if (t.host && !TK.hosts.includes(t.host)) host.append(new Option(t.host, t.host));
  host.value = t.host || '';
  const known = Object.prototype.hasOwnProperty.call(TK.schedules, t.schedule || '');
  const custom = el('input', { type: 'text', class: 'mono', placeholder: 'Mon..Fri 22:00', 'aria-label': 'Custom schedule (systemd calendar)', hidden: known,
    value: known ? '' : t.schedule, onchange: () => tkEdit(() => { t.schedule = custom.value.trim(); }, false) });
  const sched = el('select', { 'aria-label': 'Schedule', onchange: () => {
    if (sched.value === '\u0000') { custom.hidden = false; custom.focus(); return; }
    custom.hidden = true; tkEdit(() => { t.schedule = sched.value; }, false);
  } }, ...Object.entries(TK.schedules).map(([v, l]) => new Option(l, v)), new Option('custom (systemd calendar)…', '\u0000'));
  sched.value = known ? t.schedule || '' : '\u0000';
  const inst = (TK.installed[t.slug || ''] || []);
  const deployMenu = (ev) => {
    const go = async (mode, extra, label) => {
      const id = await tkSave(true);
      if (id) startDeploy('tasks', id, mode, `${label} task "${TK.task.name}"`, extra);
    };
    const r = ev.currentTarget.getBoundingClientRect();
    openMenu([{ heading: `On ${t.host || 'its host'}` },
      { label: 'Dry run (report only)', run: () => go('report', {}, 'dry run of') },
      { label: t.schedule ? 'Install with its timer' : 'Install (run by hand)', run: () => go('apply', {}, 'install') },
      { label: 'Run now', run: async () => { if (await confirmDialog({ title: `Run “${t.name}” on ${t.host} now?`, body: 'This makes its changes for real.', confirm: 'Run now', danger: true })) go('apply', { run: true }, 'run'); } },
      '-', { label: 'Uninstall', danger: true, disabled: !inst.length, run: () => go('apply', { remove: true }, 'uninstall') }], r.left, r.bottom + 4, ev.currentTarget);
  };
  return el('header', { class: 'tkhead' },
    el('div', { class: 'row' }, name,
      field('Runs on', host), field('When', el('span', { class: 'row nowrap' }, sched, custom))),
    el('div', { class: 'row' },
      el('span', { id: 'tkstate', class: 'small' }),
      el('span', { class: 'grow' }),
      el('button', { id: 'tkundo', type: 'button', class: 'btn ghost sm', title: 'Undo (Ctrl+Z)', onclick: () => tkUndo(), disabled: !TK.undo.length }, '↶'),
      el('button', { id: 'tkredo', type: 'button', class: 'btn ghost sm', title: 'Redo (Ctrl+Shift+Z)', onclick: () => tkUndo(true), disabled: !TK.redo.length }, '↷'),
      t.id ? button('Delete', tkDelete, 'btn ghost sm danger') : null,
      button('Script', tkScript, 'btn sm'),
      el('button', { id: 'tksave', type: 'button', class: 'btn sm', onclick: () => tkSave() }, TK.dirty ? 'Save*' : 'Save'),
      el('button', { type: 'button', class: 'btn pri sm', onclick: deployMenu }, 'Deploy ▾')),
    inst.length ? text('p', `Installed on ${inst.map((i) => i.host).join(', ')}${inst.some((i) => i.hash !== t.hash) || TK.dirty ? ' · changed since: install again to update it' : ' · up to date'}`, `small ${inst.some((i) => i.hash !== t.hash) || TK.dirty ? 'st-running' : 'st-ok'}`) : null);
}
function tkHeadState() {
  const b = $('#tksave'); if (b) b.textContent = TK.dirty ? 'Save*' : 'Save';
  const u = $('#tkundo'), r = $('#tkredo');
  if (u) u.disabled = !TK.undo.length;
  if (r) r.disabled = !TK.redo.length;
  tkRelabel();
}

function tkCanvas() {
  const t = TK.task;
  const canvas = el('div', { class: 'tkcanvas', onclick: (ev) => { if (ev.target === ev.currentTarget) { TK.target = null; tkMarkTarget(); } } });
  if (!t.blocks.length && !t.on_fail.length) {
    canvas.append(el('div', { class: 'tkempty' },
      text('h3', 'Start from a template, or drag blocks in from the left'),
      el('div', { class: 'tktpls' }, ...TK.templates.map((tp) => el('button', { type: 'button', class: 'tktpl', onclick: () => tkEdit(() => {
        t.blocks = structuredClone(tp.blocks).map(tkFill); if (!t.schedule) t.schedule = tp.schedule; if (!t.name) t.name = tp.name;
      }) }, text('b', tp.name), text('span', tp.help, 'muted small'),
      el('span', { class: 'tkmini' }, ...tp.blocks.map((b) => text('i', TK.types[b.type].label, `c-${TK.types[b.type].cat}`))))))));
  }
  canvas.append(el('div', { class: 'tklane' }, el('div', { class: 'tklanehead' }, text('b', 'When it runs'), text('span', 'top to bottom; a failed block stops the task', 'muted small')),
    tkList(t.blocks)),
  el('div', { class: 'tklane fail' }, el('div', { class: 'tklanehead' }, text('b', 'If the task fails'), text('span', 'e.g. log it, or start a stopped stack again', 'muted small')),
    tkList(t.on_fail)));
  return canvas;
}
function tkFill(b) {           // template blocks: put the task's host into host fields left blank on purpose
  const out = newBlock(b.type, b.params);
  if (b.slots) for (const [s, kids] of Object.entries(b.slots)) out.slots[s] = kids.map(tkFill);
  return out;
}

/* a list of blocks with drop zones between them */
function tkList(list) {
  const box = el('div', { class: `tkblist${TK.target === list ? ' target' : ''}` });
  box._list = list;
  const zone = (i) => {
    const z = el('div', { class: 'tkdrop', ondragover: (ev) => { if (tkCanDrop(list)) { ev.preventDefault(); z.classList.add('over'); } },
      ondragleave: () => z.classList.remove('over'), ondrop: (ev) => { ev.preventDefault(); z.classList.remove('over'); tkDrop(list, i); } });
    return z;
  };
  box.append(zone(0));
  list.forEach((b, i) => { box.append(tkBlock(b, list, i), zone(i + 1)); });
  if (!list.length) box.append(el('div', { class: 'tkhint', onclick: () => { TK.target = list; tkMarkTarget(); } }, 'drop blocks here'));
  return box;
}
function tkCanDrop(list) {
  const d = TK.drag;
  if (!d) return false;
  if (d.block && tkContains(d.block, list)) return false;      // not into itself
  return true;
}
function tkContains(block, list) {
  for (const kids of Object.values(block.slots || {})) {
    if (kids === list) return true;
    if (kids.some((k) => tkContains(k, list))) return true;
  }
  return false;
}
function tkDrop(list, i) {
  const d = TK.drag; TK.drag = null; document.body.classList.remove('tkdragging');
  if (!d) return;
  tkEdit(() => {
    if (d.make) { list.splice(i, 0, newBlock(d.make)); return; }
    const from = d.from, j = from.indexOf(d.block);
    if (j < 0) return;
    from.splice(j, 1);
    list.splice(from === list && j < i ? i - 1 : i, 0, d.block);
  });
}
function tkDragEnd() { TK.drag = null; document.body.classList.remove('tkdragging'); document.querySelectorAll('.tkdrop.over').forEach((z) => z.classList.remove('over')); }
function tkAppend(b) { tkEdit(() => { (TK.target || TK.task.blocks).push(b); }); }
function tkMarkTarget() { document.querySelectorAll('.tkblist').forEach((x) => x.classList.toggle('target', x._list === TK.target)); renderTasksSideHint(); }
function renderTasksSideHint() { const p = document.querySelector('.tkside > p.muted'); if (p) p.textContent = TK.target ? 'Click adds to the selected slot; drag to place anywhere.' : 'Click adds at the end; drag to place anywhere.'; }

function tkLabel(b) {
  const t = TK.types[b.type], p = b.params;
  return t.text.replace(/\{(\w+)\}/g, (_m, k) => {
    let v = p[k];
    if ((k === 'src' || k === 'dst') && p[k + '_host']) v = `${p[k + '_host']}:${v || '…'}`;
    if (Array.isArray(v)) v = v.length;
    return v === '' || v == null ? '…' : String(v).split('\n')[0];
  });
}
function tkHostFor(b, spec) { return (spec.on && b.params[spec.on]) ? b.params[spec.on].split('@').pop() : TK.task.host; }

function tkVisible(b, s) {
  if (b.type !== 'if') return true;
  if (s.name === 'value') return b.params.cond === 'free below';
  return true;
}
function tkParam(b, s) {
  const p = b.params, set = (v, rerender = false) => tkEdit(() => { p[s.name] = v; }, rerender);
  const lbl = (input, cls = '') => el('label', { class: `field col tkf k-${s.kind} ${cls}` }, el('span', {}, s.label), input);
  if (s.kind === 'bool') {
    const c = el('input', { type: 'checkbox', onchange: () => set(c.checked) }); c.checked = !!p[s.name];
    return el('label', { class: 'check small tkbool' }, c, s.label);
  }
  if (s.kind === 'select') {
    const sel = el('select', { onchange: () => set(sel.value, true) }, ...s.choices.map((c) => new Option(c, c))); sel.value = p[s.name];
    return lbl(sel);
  }
  if (s.kind === 'host') {
    const sel = el('select', { onchange: async () => {
      if (sel.value === '\u0000') {
        const form = await formDialog({ title: 'Another host', body: 'A host that was not scanned.', confirm: 'Use it',
          fields: [{ name: 'target', label: 'user@host', value: p[s.name] || 'root@', validate: (v) => (/^[^@\s]+@[^@\s]+$/.test(v) ? '' : 'Write it as user@host.') }] });
        if (form) set(form.target, true); else sel.value = p[s.name] || '';
        return;
      }
      set(sel.value, true);
    } }, new Option(s.required ? 'pick a host…' : `this host (${TK.task.host || 'the task host'})`, ''), ...TK.hosts.filter((h) => h !== TK.task.host).map((h) => new Option(h, h)), new Option('other (user@host)…', '\u0000'));
    if (p[s.name] && ![...sel.options].some((o) => o.value === p[s.name])) sel.add(new Option(p[s.name], p[s.name]), sel.options.length - 1);
    sel.value = p[s.name] || '';
    return lbl(sel);
  }
  if (s.kind === 'lines' || s.kind === 'cmd') {
    const ta = el('textarea', { rows: s.kind === 'cmd' ? 2 : 2, class: 'mono', placeholder: s.placeholder || '', spellcheck: 'false',
      onchange: () => set(s.kind === 'lines' ? ta.value.split('\n').map((x) => x.trim()).filter(Boolean) : ta.value) });
    ta.value = Array.isArray(p[s.name]) ? p[s.name].join('\n') : p[s.name] || '';
    return lbl(ta, 'wide');
  }
  if (s.kind === 'int') {
    const n = el('input', { type: 'number', min: s.min ?? 0, max: s.max ?? '', value: p[s.name] ?? '', onchange: () => set(n.value === '' ? null : +n.value) });
    return lbl(n, 'narrow');
  }
  const isPath = s.kind === 'path' || (b.type === 'if' && s.name === 'arg' && ['mounted', 'exists', 'free below'].includes(p.cond));
  const isHost = b.type === 'if' && s.name === 'arg' && p.cond === 'host up';
  const ph = b.type === 'if' && s.name === 'arg'
    ? ({ mounted: '/mnt/backup', exists: '/mnt/backup/.ready', 'free below': '/mnt/backup', weekday: 'Sat,Sun', 'day of month': '1,15', 'host up': 'nas', 'command succeeds': 'ping -c1 nas' })[p.cond]
    : s.placeholder || '';
  const i = el('input', { type: 'text', class: isPath || s.kind !== 'text' ? 'mono' : '', placeholder: ph, spellcheck: 'false', value: p[s.name] ?? '',
    list: isHost ? 'tkhosts' : null, onchange: () => set(i.value.trim()) });
  if (!isPath) return lbl(i, s.kind === 'text' ? 'wide' : '');
  const browse = el('button', { type: 'button', class: 'btn ghost sm', title: 'Browse the index', onclick: async () => {
    const host = tkHostFor(b, s);
    const v = await pickPath(host, p[s.name] || '/', { title: `${s.label} on ${host}`, pick: b.type === 'mkdir' ? 'mount' : 'folder' });
    if (v) set(v, true);
  } }, '📁');
  return lbl(el('span', { class: 'row nowrap' }, i, browse), 'path');
}

function tkBlock(b, list, i) {
  const t = TK.types[b.type];
  const shut = TK.shut.has(b);
  const wrap = (type, slot, params = {}) => tkEdit(() => { const w = newBlock(type, params); w.slots[slot].push(b); list.splice(i, 1, w); });
  const menu = () => [{ heading: t.label },
    { label: shut ? 'Expand' : 'Collapse', run: () => { shut ? TK.shut.delete(b) : TK.shut.add(b); renderTasks(); } },
    { label: 'Duplicate', run: () => tkEdit(() => list.splice(i + 1, 0, structuredClone(b))) },
    { label: 'Move up', disabled: !i, run: () => tkEdit(() => { [list[i - 1], list[i]] = [list[i], list[i - 1]]; }) },
    { label: 'Move down', disabled: i === list.length - 1, run: () => tkEdit(() => { [list[i + 1], list[i]] = [list[i], list[i + 1]]; }) },
    { label: b.off ? 'Turn on' : 'Turn off (skip it)', run: () => tkEdit(() => { b.off = !b.off; }) },
    '-',
    { label: 'Wrap in Try', run: () => wrap('try', 'do') },
    { label: 'Wrap in If mounted', run: () => wrap('if', 'then', { cond: 'mounted', arg: b.params.path || b.params.dst || '' }) },
    t.slots ? { label: 'Unwrap (keep what is inside)', run: () => tkEdit(() => { list.splice(i, 1, ...Object.values(b.slots).flat()); }) } : null,
    '-', { label: 'Remove', danger: true, run: () => tkEdit(() => { list.splice(i, 1); }) }];
  const head = el('div', { class: 'tkbh', draggable: 'true',
    ondragstart: (ev) => { ev.stopPropagation(); TK.drag = { block: b, from: list }; ev.dataTransfer.effectAllowed = 'move'; ev.dataTransfer.setData('text/plain', b.type); document.body.classList.add('tkdragging'); },
    ondragend: tkDragEnd },
  text('span', '⋮⋮', 'grip'),
  el('button', { type: 'button', class: 'tkfold', 'aria-expanded': String(!shut), title: shut ? 'Expand' : 'Collapse', onclick: () => { shut ? TK.shut.delete(b) : TK.shut.add(b); renderTasks(); } }, shut ? '▸' : '▾'),
  text('span', TK_ICON[t.cat], 'ic'), text('b', t.label), text('span', tkLabel(b), 'tksent mono'),
  el('span', { class: 'grow' }), el('span', { class: 'tkdot' }),
  el('button', { type: 'button', class: 'tkmenu', 'aria-label': 'Block actions', onclick: (ev) => { const r = ev.currentTarget.getBoundingClientRect(); openMenu(menu(), r.right - 180, r.bottom + 4, ev.currentTarget); } }, '⋯'));
  const node = el('div', { class: `tkb c-${t.cat}${b.off ? ' off' : ''}${t.slots ? ' cblock' : ''}${shut ? ' shut' : ''}` }, head);
  node._block = b; node._menu = menu;
  if (!shut) {
    if (t.help) node.append(text('p', t.help, 'tkhelp muted small'));
    const ps = t.params.filter((s) => tkVisible(b, s));
    if (ps.length) node.append(el('div', { class: 'tkparams' }, ...ps.filter((s) => s.kind !== 'bool').map((s) => tkParam(b, s)),
      ps.some((s) => s.kind === 'bool') ? el('div', { class: 'row tkbools' }, ...ps.filter((s) => s.kind === 'bool').map((s) => tkParam(b, s))) : null));
  }
  node.append(el('ul', { class: 'mvcheck tkcheck' }));
  if (t.slots) {
    for (const s of t.slots) {
      node.append(el('div', { class: 'tkslot' }, el('button', { type: 'button', class: `tksl${TK.target === b.slots[s] ? ' cur' : ''}`, title: 'Select: clicking a block in the palette adds it here',
        onclick: () => { TK.target = TK.target === b.slots[s] ? null : b.slots[s]; tkMarkTarget(); } }, s), tkList(b.slots[s])));
    }
    node.append(el('div', { class: 'tkcap' }));
  }
  return node;
}

/* check results onto the blocks */
function tkPaintChecks() {
  const st = $('#tkstate');
  const c = TK.check;
  if (st) {
    st.className = 'small ' + (TK.error ? 'st-failed' : !c ? 'muted' : c.crit ? 'st-failed' : c.warn ? 'st-running' : 'st-ok');
    st.textContent = TK.error || (!c ? 'checking…' : c.crit ? `${c.crit} to fix · ${c.warn} warning${c.warn === 1 ? '' : 's'}` : c.warn ? `${c.warn} warning${c.warn === 1 ? '' : 's'}` : 'checks pass');
    if (c && c.general.length) st.title = c.general.map((x) => x.text).join('\n');
  }
  if (!c) return;
  const byBlock = new Map();
  for (const r of c.blocks) {
    let list = r.path[0] === 'on_fail' ? TK.task.on_fail : TK.task.blocks, b = null;
    const path = r.path[0] === 'on_fail' ? r.path.slice(1) : r.path;
    for (let k = 0; k < path.length && list; k++) {      // results may be from before the last edit: skip what moved
      if (typeof path[k] === 'number') b = list[path[k]];
      else list = b && b.slots ? b.slots[path[k]] : null;
    }
    if (b && list) byBlock.set(b, r.items);
  }
  for (const node of document.querySelectorAll('.tkb')) {
    const items = byBlock.get(node._block) || [];
    const ul = node.querySelector(':scope > .tkcheck');
    const worst = items.some((x) => x.level === 'crit') ? 'crit' : items.some((x) => x.level === 'warn') ? 'warn' : items.length ? 'ok' : '';
    node.querySelector(':scope > .tkbh .tkdot').className = `tkdot ${worst}`;
    const shown = TK.shut.has(node._block) ? items.filter((x) => x.level === 'crit' || x.level === 'warn') : items;
    ul.replaceChildren(...shown.map((x) => el('li', { class: `lv-${x.level}` }, x.text,
      x.fix ? button(`Add "${TK.types[x.fix.type].label} ${x.fix.params.path || ''}"`, () => tkFix(node._block, x.fix), 'btn ghost sm tkfix') : null)));
  }
  const gen = document.querySelector('.tkgeneral');
  if (gen) gen.remove();
  const crit = c.general.filter((x) => x.level !== 'note');
  if (crit.length) {
    const lane = document.querySelector('.tklane .tklanehead');
    if (lane) lane.after(el('ul', { class: 'mvcheck tkgeneral' }, ...crit.map((x) => text('li', x.text, `lv-${x.level}`))));
  }
}
function tkFix(block, fix) {
  const find = (list) => {
    const i = list.indexOf(block);
    if (i >= 0) return [list, i];
    for (const b of list) for (const kids of Object.values(b.slots || {})) { const r = find(kids); if (r) return r; }
    return null;
  };
  const at = find(TK.task.blocks) || find(TK.task.on_fail);
  if (at) tkEdit(() => at[0].splice(at[1], 0, newBlock(fix.type, fix.params)));
}

/* ── saving, scripts ─────────────────────────────────────────────────── */
async function tkSave(quiet = false) {
  const t = TK.task;
  if (!t.name) { toast('Give the task a name first'); $('.tkname')?.focus(); return null; }
  if (!TK.dirty && t.id) return t.id;
  try {
    const r = t.id
      ? await (await api(`/api/tasks/${t.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(t) })).json()
      : await (await postJSON('/api/tasks', t)).json();
    TK.dirty = false;
    await loadTasks(r.id);
    if (!quiet) toast('Saved');
    return r.id;
  } catch (err) { notify(err.message, 'error'); return null; }
}
async function tkOpen(id) {
  if (TK.dirty && !(await confirmDialog({ title: 'Discard unsaved changes to this task?', confirm: 'Discard', danger: true }))) return;
  TK.target = null;
  await loadTasks(id);
}
async function tkNew(host) {
  if (TK.dirty && !(await confirmDialog({ title: 'Discard unsaved changes to this task?', confirm: 'Discard', danger: true }))) return false;
  TK.task = blankTask(host); TK.dirty = false; TK.undo = []; TK.redo = []; TK.target = null; TK.check = null;
  renderTasks(); tkCheckSoon(0);
  return true;
}
async function tkDelete() {
  if (!(await confirmDialog({ title: `Delete the task “${TK.task.name}”?`, confirm: 'Delete task', danger: true }))) return;
  try { await api(`/api/tasks/${TK.task.id}`, { method: 'DELETE' }); TK.task = null; TK.dirty = false; loadTasks(); }
  catch (err) { notify(err.message, 'error'); }
}
async function tkScript() {
  try {
    const res = await postJSON('/api/tasks/script', TK.task);
    const body = await res.text();
    const name = (res.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'task.sh';
    const dlg = el('dialog', { class: 'fsdlg' });
    const close = () => { dlg.close(); dlg.remove(); };
    dlg.addEventListener('cancel', close);
    dlg.append(el('div', { class: 'row' }, el('h2', {}, name), el('span', { class: 'grow' }),
      button('Copy', () => {
        const ta = Object.assign(document.createElement('textarea'), { value: body, readOnly: true });
        ta.style.cssText = 'position:fixed;opacity:0'; dlg.append(ta); ta.select();
        let ok = false; try { ok = document.execCommand('copy'); } catch { /* below */ }
        ta.remove();
        if (ok) toast('Script copied');
        else if (navigator.clipboard && isSecureContext) navigator.clipboard.writeText(body).then(() => toast('Script copied'), () => toast('Could not copy'));
        else toast('Could not copy');
      }, 'btn ghost sm'),
      button('Download', () => {
        const a = el('a', { href: URL.createObjectURL(new Blob([body], { type: 'text/x-shellscript' })), download: name });
        document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      }, 'btn sm'), button('Close', close, 'btn ghost sm')),
    text('p', `./${name} reports what it would do; sudo ./${name} --run runs it; --install adds the systemd service${TK.task.schedule ? ' and timer' : ''}.`, 'muted small'),
    text('pre', body, 'script tkscript'));
    document.body.append(dlg); dlg.showModal();
  } catch (err) { notify(err.message, 'error'); }
}

/* from elsewhere: a new task with a first block at a folder of a host */
async function newTaskAt(host, path, kind = 'backup', fstype = '') {
  setMode('tasks');
  if (!TK.loaded) await loadTasks();
  if (!(await tkNew(host))) return;
  const name = path.split('/').pop() || host;
  tkEdit(() => {
    const t = TK.task;
    if (kind === 'snapshot' && /zfs/i.test(fstype)) {
      t.name = `${name} snapshots`; t.schedule = '*-*-* 02:30:00';
      t.blocks = [newBlock('zfs_snapshot', { prefix: 'daily' }), newBlock('zfs_prune', { prefix: 'daily', keep: 14 })];
    } else if (kind === 'snapshot') {
      t.name = `${name} snapshots`; t.schedule = 'hourly';
      t.blocks = [newBlock('btrfs_snapshot', { subvol: path, prefix: 'hourly' }), newBlock('btrfs_prune', { into: path.replace(/\/$/, '') + '/.snapshots', prefix: 'hourly', keep: 48 })];
    } else {
      t.name = `${name} backup`; t.schedule = '*-*-* 02:30:00';
      t.blocks = [newBlock('rsync', { src: path, dst: '', mode: 'copy' })];
    }
  });
}

sfShortcut({ id: 'tasks-undo', key: 'z', mods: 'mod', label: 'Undo, and with Shift redo', where: 'Tasks', when: () => T.mode === 'tasks', run: (ev) => { ev.preventDefault(); tkUndo(ev.shiftKey); } });
sfUnsaved({ id: 'task', label: 'the task you were editing', kept: false, dirty: () => !!TK.dirty });
