'use strict';
/* Rebuild → Desktop profiles: the profiles kept on the server, a form for the keys, the window rules and the displays of one (the
   displays for every host, or for one host in place of those), the text a compositor would get, save and delete. A profile reaches a
   host only through the desktop-profile step of a change plan. Loaded after osinstallview.js, which fetched the host names. */

const DESK = { list: [], compositors: [], edit: null, isNew: false, layout: '' };
const DESK_ACTIONS = { spawn: 'run a command', close: 'close the window', fullscreen: 'fullscreen', 'toggle-floating': 'float or tile', exit: 'leave the session',
  'focus-left': 'focus left', 'focus-right': 'focus right', 'focus-up': 'focus up', 'focus-down': 'focus down',
  'move-left': 'move left', 'move-right': 'move right', 'move-up': 'move up', 'move-down': 'move down', workspace: 'go to workspace', 'move-to-workspace': 'move to workspace' };
const DESK_TAKES = { spawn: 'a command, such as ghostty', workspace: '1 to 20', 'move-to-workspace': '1 to 20' };
const DESK_TRANSFORMS = ['normal', '90', '180', '270', 'flipped', 'flipped-90', 'flipped-180', 'flipped-270'];

function deskMsg(msg, ok) {
  const m = $('#deskmsg'); m.hidden = false; m.className = ok ? 'st-ok' : 'st-failed'; m.textContent = msg;
  announce(msg);
}
const deskCounts = (p) => {
  const n = (count, one, many) => `${count} ${count === 1 ? one : many}`;
  const own = Object.keys(p.hosts || {});
  return [n(p.binds.length, 'key', 'keys'), n(p.rules.length, 'window rule', 'window rules'), n(p.displays.length, 'display', 'displays'),
    own.length ? `own displays for ${own.join(', ')}` : null].filter(Boolean).join(' · ');
};
const deskInput = (label, value, onInput, attrs = {}) => sfNode('input', { type: 'text', class: 'mono', autocomplete: 'off', spellcheck: false, 'aria-label': label, value: value ?? '',
  oninput: (ev) => onInput(ev.target.value.trim()), ...attrs });
const deskCheck = (label, value, onChange) => sfNode('label', { class: 'field' }, sfNode('input', { type: 'checkbox', checked: !!value, onchange: (ev) => onChange(ev.target.checked) }), sfNode('span', {}, label));
const deskPick = (label, options, value, onChange, attrs = {}) => {
  const s = sfNode('select', { 'aria-label': label, onchange: (ev) => onChange(ev.target.value), ...attrs }, options.map(([v, t]) => sfNode('option', { value: v }, t)));
  s.value = value;
  return s;
};

/* One list of the form: its rows are drawn from the profile being edited, and adding or removing one draws that list again and nothing
   else, with focus on the new row or on the Add button. */
function deskRows(id, items, what, blank, rowOf) {
  const box = $(id);
  const draw = (focus, on = 'input, select') => {
    const add = button(`Add ${what}`, () => { items.push(blank()); draw(items.length - 1); }, 'btn ghost sm');
    const rows = items.map((item, i) => {
      const row = sfNode('li', { class: 'row deskrow' }, rowOf(item, i + 1, () => draw(i, 'select')));
      row.append(button('Remove', () => { items.splice(i, 1); draw('add'); }, 'btn ghost sm'));
      row.lastChild.setAttribute('aria-label', `Remove ${what.replace(/^an? /, '')} ${i + 1}`);
      return row;
    });
    box.replaceChildren(sfNode('ol', { class: 'list' }, rows.length ? rows : sfNode('li', { class: 'muted' }, 'None.')), add);
    if (focus === 'add') add.focus();
    else if (typeof focus === 'number') rows[focus]?.querySelector(on)?.focus();
  };
  draw();
}
function deskDrawBinds() {
  deskRows('#desk-binds', DESK.edit.binds, 'a key', () => ({ keys: '', action: 'spawn', arg: '' }), (b, n, redraw) => [
    deskInput(`Keys of key ${n}`, b.keys, (v) => { b.keys = v; }, { placeholder: 'mod+Return' }),
    deskPick(`What key ${n} does`, Object.entries(DESK_ACTIONS), b.action, (v) => { b.action = v; if (!DESK_TAKES[v]) b.arg = ''; redraw(); }),
    DESK_TAKES[b.action] ? deskInput(`${b.action === 'spawn' ? 'Command' : 'Workspace'} of key ${n}`, b.arg, (v) => { b.arg = v; }, { placeholder: DESK_TAKES[b.action] }) : null]);
}
function deskDrawRules() {
  deskRows('#desk-rules', DESK.edit.rules, 'a window rule', () => ({ app: '', title: '', workspace: '', floating: false, fullscreen: false }), (r, n) => [
    deskInput(`Application of rule ${n}`, r.app, (v) => { r.app = v; }, { placeholder: 'application, such as firefox' }),
    deskInput(`Title of rule ${n}`, r.title, (v) => { r.title = v; }, { placeholder: 'or a window title' }),
    deskInput(`Workspace of rule ${n}`, r.workspace, (v) => { r.workspace = v; }, { placeholder: 'workspace', inputmode: 'numeric', size: 9 }),
    deskCheck('floating', r.floating, (v) => { r.floating = v; }), deskCheck('fullscreen', r.fullscreen, (v) => { r.fullscreen = v; })]);
}
function deskDrawDisplays() {
  const p = DESK.edit, of = DESK.layout ? `on ${DESK.layout}` : 'for every host';
  const items = DESK.layout ? p.hosts[DESK.layout] : p.displays;
  deskRows('#desk-displays', items, 'a display', () => ({ output: '', mode: '', position: '', scale: '', transform: 'normal', enabled: true }), (d, n) => [
    deskInput(`Output of display ${n} ${of}`, d.output, (v) => { d.output = v; }, { placeholder: 'DP-1', size: 9 }),
    deskInput(`Mode of display ${n} ${of}`, d.mode, (v) => { d.mode = v; }, { placeholder: '2560x1440@144', size: 14 }),
    deskInput(`Position of display ${n} ${of}`, d.position, (v) => { d.position = v; }, { placeholder: '0,0', size: 8 }),
    deskInput(`Scale of display ${n} ${of}`, d.scale, (v) => { d.scale = v; }, { placeholder: '1', size: 4 }),
    deskPick(`Rotation of display ${n} ${of}`, DESK_TRANSFORMS.map((t) => [t, t]), d.transform || 'normal', (v) => { d.transform = v; }),
    deskCheck('on', d.enabled !== false, (v) => { d.enabled = v; })]);
}
function deskDrawLayouts(focus) {          // which displays the rows below are: the profile's own, or one host's in place of them
  const p = DESK.edit, own = Object.keys(p.hosts), known = (OS2.data?.hosts || []).map((h) => h.host).filter((h) => !own.includes(h));
  const pick = deskPick('Displays for', [['', 'Every host'], ...own.map((h) => [h, `${h} only, in place of those`])], DESK.layout, (v) => { DESK.layout = v; deskDrawLayouts('pick'); }, { id: 'desk-layout' });
  const row = sfNode('div', { class: 'row' }, sfNode('label', { class: 'field' }, sfNode('span', {}, 'Displays for'), pick));
  if (DESK.layout) {
    row.append(button(`Take away the displays of ${DESK.layout}`, () => { delete p.hosts[DESK.layout]; DESK.layout = ''; deskDrawLayouts('pick'); }, 'btn ghost sm'));
  } else if (known.length) {
    const host = deskPick('A host with displays of its own', known.map((h) => [h, h]), known[0], () => {}, { id: 'desk-addhost' });
    row.append(host, button('Give this host displays of its own', () => { p.hosts[host.value] = []; DESK.layout = host.value; deskDrawLayouts('pick'); }, 'btn ghost sm'));
  }
  $('#desk-layouts').replaceChildren(row);
  deskDrawDisplays();
  if (focus === 'pick') $('#desk-layout').focus();
}

function deskProfile() {          // the form as the server takes it: rows nobody filled in are left out
  const p = DESK.edit, shown = (d) => d.output;
  return { name: $('#desk-name').value.trim(), mod: $('#desk-mod').value, binds: p.binds.filter((b) => b.keys), rules: p.rules.filter((r) => r.app || r.title),
    displays: p.displays.filter(shown), hosts: Object.fromEntries(Object.entries(p.hosts).map(([h, d]) => [h, d.filter(shown)])) };
}
async function deskPreview() {
  const out = $('#desk-preview');
  try {
    const comp = $('#desk-comp').value, host = $('#desk-prevhost').value;
    // an account that may not change a profile reads the saved one as it is
    const r = can('plans.edit') ? await postJSON('/api/desktop/render', { profile: deskProfile(), compositor: comp, host: host || null })
      : await api(`/api/desktop/profiles/${encodeURIComponent(DESK.edit.name)}/render?compositor=${encodeURIComponent(comp)}${host ? `&host=${encodeURIComponent(host)}` : ''}`);
    out.textContent = await r.text(); out.hidden = false;
    $('#deskmsg').hidden = true;
    announce(`The profile as ${$('#desk-comp').value} would get it is shown.`);
  } catch (err) { out.hidden = true; deskMsg(err.message, false); }
}
async function deskSave() {
  const p = deskProfile();
  if (!p.name) { deskMsg('Give the profile a name.', false); $('#desk-name').focus(); return; }
  if (DESK.isNew && DESK.list.some((x) => x.name.toLowerCase() === p.name.toLowerCase())) { deskMsg(`There is a profile named ${p.name} already: edit that one.`, false); $('#desk-name').focus(); return; }
  try {
    await api(`/api/desktop/profiles/${encodeURIComponent(p.name)}`, jsonOpts('PUT', p));
    DESK.edit = null;
    await loadDesktop();
    deskMsg(`Profile ${p.name} saved. A host gets it when a plan with a desktop-profile step is run; a plan whose script was made before has the profile as it was.`, true);
    document.querySelector(`#deskbox [data-profile="${CSS.escape(p.name)}"] button`)?.focus();
  } catch (err) { deskMsg(err.message, false); }
}

function deskEditor() {
  const p = DESK.edit, hosts = (OS2.data?.hosts || []).map((h) => h.host);
  const name = sfNode('input', { id: 'desk-name', type: 'text', class: 'mono', autocomplete: 'off', spellcheck: false, value: p.name, readOnly: !DESK.isNew, maxlength: 63, placeholder: 'fleet' });
  const form = sfNode('form', { id: 'desk-editor', class: 'card', 'aria-label': DESK.isNew ? 'New desktop profile' : `Desktop profile ${p.name}` },
    sfNode('div', { class: 'row' },
      sfNode('label', { class: 'field' }, sfNode('span', {}, 'Name'), name),
      sfNode('label', { class: 'field' }, sfNode('span', {}, 'The mod key'), deskPick('The mod key', [['super', 'Super'], ['alt', 'Alt']], p.mod || 'super', () => {}, { id: 'desk-mod' }))),
    sfNode('h4', {}, 'Keys'),
    sfNode('p', { class: 'muted small' }, 'Keys are written as mod+shift+Return: mod, shift, ctrl and alt, then a key as xkb names it. A command is letters, digits and a few signs, with no quote, dollar sign or semicolon.'),
    sfNode('div', { id: 'desk-binds', class: 'stack' }),
    sfNode('h4', {}, 'Window rules'),
    sfNode('p', { class: 'muted small' }, 'A rule names an application or a title, and sends its windows to a workspace, floats them or makes them fullscreen.'),
    sfNode('div', { id: 'desk-rules', class: 'stack' }),
    sfNode('h4', {}, 'Displays'),
    sfNode('div', { id: 'desk-layouts' }),
    sfNode('div', { id: 'desk-displays', class: 'stack' }),
    sfNode('h4', {}, 'As a compositor would get it'),
    sfNode('div', { class: 'row' },
      sfNode('label', { class: 'field' }, sfNode('span', {}, 'Compositor'), deskPick('Compositor', DESK.compositors.map((c) => [c, c]), DESK.compositors[0], () => {}, { id: 'desk-comp' })),
      sfNode('label', { class: 'field' }, sfNode('span', {}, 'On'), deskPick('The host it is shown for', [['', 'any host'], ...hosts.map((h) => [h, h])], '', () => {}, { id: 'desk-prevhost' })),
      button('Show the text', deskPreview, 'btn sm')),
    sfNode('pre', { id: 'desk-preview', class: 'script', hidden: true, tabindex: 0, 'aria-label': 'The profile as the compositor would get it' }),
    sfNode('div', { class: 'row' },
      can('plans.edit') ? sfNode('button', { type: 'submit', class: 'btn pri sm', id: 'desk-save' }, 'Save the profile') : sfNode('span', { class: 'muted' }, 'Your account may read profiles and not change them.'),
      button('Close without saving', () => { const was = p.name; DESK.edit = null; deskRender(); (document.querySelector(`#deskbox [data-profile="${CSS.escape(was)}"] button`) || $('#desk-new'))?.focus(); }, 'btn ghost sm')));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const save = $('#desk-save');
    if (!save || save.getAttribute('aria-busy') === 'true') return;
    await withBusy(save, deskSave);
  });
  return form;
}
function deskOpen(profile, isNew) {
  DESK.edit = JSON.parse(JSON.stringify({ name: '', mod: 'super', binds: [], rules: [], displays: [], hosts: {}, ...profile }));
  DESK.isNew = isNew; DESK.layout = '';
  deskRender();
  $(isNew ? '#desk-name' : '#desk-mod').focus();
}

function deskRender() {
  const box = $('#deskbox'), edit = can('plans.edit');
  if (DESK.edit) {
    box.replaceChildren(deskEditor());
    deskDrawBinds(); deskDrawRules(); deskDrawLayouts();
    return;
  }
  const rows = DESK.list.map((p) => {
    const li = sfNode('li', { 'data-profile': p.name }, sfNode('span', {}, p.name), sfNode('span', { class: 'm' }, deskCounts(p)));
    const row = sfNode('div', { class: 'row' }, button(edit ? 'Edit' : 'Open', () => deskOpen(p, false), 'btn ghost sm'));
    row.firstChild.setAttribute('aria-label', `${edit ? 'Edit' : 'Open'} the profile ${p.name}`);
    if (edit) {
      const del = button('Delete', async () => {
        if (!(await confirmDialog({ title: `Delete the profile ${p.name}?`, confirm: 'Delete', danger: true,
          body: 'It is taken off the server. The configuration it wrote on hosts stays as it is, and a plan that names it can no longer be made into a script.' }))) return;          // cancelled: nothing is drawn again
        try {
          await api(`/api/desktop/profiles/${encodeURIComponent(p.name)}`, { method: 'DELETE' });
          await loadDesktop();
          deskMsg(`Profile ${p.name} deleted.`, true);
          $('#desk-new')?.focus();
        } catch (err) { deskMsg(err.message, false); }
      }, 'btn ghost sm danger');
      del.setAttribute('aria-label', `Delete the profile ${p.name}`);
      row.append(del);
    }
    li.append(row);
    return li;
  });
  box.replaceChildren(
    sfNode('ul', { class: 'list', id: 'desk-list' }, rows.length ? rows : sfNode('li', { class: 'muted' }, 'No profiles yet.')),
    edit ? sfNode('div', { class: 'row' }, Object.assign(button('New profile', () => deskOpen({}, true), 'btn sm'), { id: 'desk-new' })) : '');
}

async function loadDesktop() {
  if (!$('#deskbox')) return;
  let d;
  try { d = await getJSON('/api/desktop/profiles'); }
  catch (err) { $('#deskbox').replaceChildren(text('p', err.message, 'st-failed')); return; }
  DESK.list = d.profiles; DESK.compositors = d.compositors;
  if (OS2.data) { OS2.data.desktop.profiles = d.profiles.map((p) => p.name); os2ProfileOptions(); }
  if (!DESK.edit) deskRender();          // a profile that is open in the form stays as it is typed
}
