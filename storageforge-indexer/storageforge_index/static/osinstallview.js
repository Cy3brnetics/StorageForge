'use strict';
/* Rebuild → A second system beside the first: what a host has room for as its last scan saw it, a form that becomes a change plan,
   and starting or removing a system that is there. Nothing here reaches a host: every button saves a plan, and Changes checks and runs
   it. The desktop profiles below it are desktopview.js, which reads the hosts and profiles this file fetched. */

const OS2 = { data: null };
const OS2_TEXT = {
  sudo: { nopasswd: 'Without a password', none: 'None' },
  host_keys: { same: 'The same as this system: SSH clients see one machine', new: 'New ones: SSH clients warn at each switch' },
  network: { same: 'As this system has it: a fixed address stays fixed, DHCP stays DHCP', fixed: 'The address it has now, written as a fixed one', dhcp: 'DHCP on the first card' },
  carry: { mount: 'Mounted at the same places (what fstab names by UUID or label)', none: 'Not mounted' },
};
const os2Field = (label, control, hint) => sfNode('label', { class: 'field col' }, sfNode('span', {}, label), control, hint ? sfNode('small', { class: 'muted' }, hint) : null);
const os2Select = (id, options, value) => {
  const s = sfNode('select', { id }, options.map(([v, t]) => sfNode('option', { value: v }, t)));
  if (value != null) s.value = value;
  return s;
};
const os2Input = (id, attrs = {}) => sfNode('input', { id, type: 'text', class: 'mono', autocomplete: 'off', spellcheck: false, ...attrs });
const os2Host = () => OS2.data.hosts.find((h) => h.host === $('#os2-host').value);

function os2Msg(msg, ok, plans) {
  const m = $('#os2msg'); m.hidden = false; m.className = ok ? 'st-ok' : 'st-failed';
  m.replaceChildren(msg, ...(plans ? [' ', button('Open Changes', () => showTab('changes'), 'btn ghost sm')] : []));
  announce(msg);
}
async function os2Stage(body) {          // true when the plans were saved
  try {
    const r = await (await postJSON('/api/os-install/plan', body)).json();
    const names = r.plans.map((p) => `“${p.name}” (#${p.plan_id})`);
    os2Msg(`${names.length === 1 ? 'Plan' : 'Plans'} ${names.join(' and ')} saved. Nothing has run yet: read ${names.length === 1 ? 'it' : 'them'} in Changes.`, true, true);
    return true;
  } catch (err) { os2Msg(err.message, false); return false; }
}

function os2DiskText(d) {
  const room = d.blank ? 'blank disk' : d.free == null ? 'room not known' : `${fmtBytes(d.free)} unpartitioned`;
  return `${d.path} · ${fmtBytes(d.size)}${d.model ? ` · ${d.model}` : ''} · ${room}${d.running ? ' · this system runs from it' : ''}`;
}
function os2SystemRow(h, s, edit) {
  const li = sfNode('li', { 'data-system': s.name });
  li.append(sfNode('span', {}, s.name, s.running ? sfNode('span', { class: 'pill unknown' }, 'running now') : null),
    sfNode('span', { class: 'm' }, `${s.disk} · ${s.partitions} partition${s.partitions === 1 ? '' : 's'} · ${fmtBytes(s.size)}`));
  if (!edit) return li;
  const ask = (label, cls, dialog, body) => button(label, async () => {
    if (!(await confirmDialog(dialog))) return;          // cancelled: the page is as it was, and focus is back on this button
    await os2Stage({ host: h.host, name: s.name, ...body });
  }, cls);
  const row = sfNode('div', { class: 'row' });
  if (!s.running) {
    row.append(ask('Start once', 'btn ghost sm', { title: `Start ${s.name} at the next restart?`, confirm: 'Make the plan',
      body: `The plan sets the firmware's one-time start. The restart after that one is the system the boot order names, so a system that does not come up costs one restart.\n\nThe plan does not restart ${h.host}.` },
    { kind: 'boot', when: 'once', restart: 'no' }));
    row.append(ask('Start once and restart', 'btn ghost sm', { title: `Restart ${h.host} into ${s.name}?`, confirm: 'Make the plan', danger: true,
      body: `Running the plan restarts ${h.host} one minute later: everything running on it stops. If ${s.name} does not come up, the restart after that is the system the boot order names.` },
    { kind: 'boot', when: 'once', restart: 'yes' }));
  }
  row.append(ask('Make it the default', 'btn ghost sm', { title: `Make ${s.name} the system ${h.host} starts?`, confirm: 'Make the plan',
    body: `The plan puts ${s.name} first in the boot order. Do this only after it has been started once and reached.` },
  { kind: 'boot', when: 'always', restart: 'no' }));
  row.append(ask('Take it out of the boot order', 'btn ghost sm', { title: `Start ${s.name} only when asked?`, confirm: 'Make the plan',
    body: `The plan takes ${s.name} out of the boot order and clears a one-time start that names it. It stays installed.` },
  { kind: 'boot', when: 'never', restart: 'no' }));
  if (!s.running) {
    row.append(ask('Remove', 'btn ghost sm danger', { title: `Remove ${s.name} from ${h.host}?`, confirm: 'Make the plan', danger: true, typed: s.name,
      body: `Running the plan deletes the ${s.partitions} partition${s.partitions === 1 ? '' : 's'} of ${s.name} on ${s.disk} with everything on them, and its boot entry. It cannot be taken back.` },
    { kind: 'remove' }));
  }
  li.append(row);
  return li;
}

function os2HostPart(keep) {          // what changes with the host: its disks, the systems on it, and the account. keep: the same host, read again
  const h = os2Host(), edit = can('plans.edit');
  const usable = h.disks.filter((d) => d.usable), not = h.disks.filter((d) => !d.usable);
  const disk = $('#os2-disk'), was = disk.value;
  disk.replaceChildren(...(usable.length ? usable.map((d) => sfNode('option', { value: d.path }, os2DiskText(d)))
    : [sfNode('option', { value: '' }, h.read ? 'No disk the last scan saw has room' : 'This host has not been scanned')]));
  if (keep === true && usable.some((d) => d.path === was)) disk.value = was;
  else { $('#os2-user').value = h.user || ''; $('#os2-confirm').value = ''; }
  const facts = [];
  if (!h.read) facts.push(sfNode('p', { class: 'st-warn' }, `${h.host} has no scan with its disks in it. Scan it, and its disks appear here.`));
  else facts.push(sfNode('p', { class: 'muted small' }, 'Disks and room as the last scan saw them', h.scanned_at ? [' (', timeEl(h.scanned_at), ')'] : [], '. The step looks again on the host when it runs.'));
  facts.push(sfNode('p', { class: h.started_by === 'uefi' ? 'muted small' : 'st-warn' }, h.started_by === 'uefi'
    ? 'The last scan saw an EFI partition mounted, so this machine was started by UEFI.'
    : 'The last scan saw no EFI partition mounted. A second system needs UEFI: on a machine started by BIOS the step says so and changes nothing.'));
  if (not.length) {
    facts.push(sfNode('p', { class: 'muted small' }, 'Not offered:'),
      sfNode('ul', { class: 'copies small', id: 'os2-notdisks' }, not.map((d) => sfNode('li', {}, `${d.path} · ${fmtBytes(d.size)}: ${d.why}`))));
  }
  $('#os2-facts').replaceChildren(...facts);
  const list = $('#os2-systems');
  list.replaceChildren(...(h.systems.length ? h.systems.map((s) => os2SystemRow(h, s, edit))
    : [sfNode('li', { class: 'muted' }, 'None that the last scan saw. One installed since then appears after the next scan.')]));
}

function os2Body() {          // the form as the server takes it
  const v = (id) => $(id).value.trim();
  const body = { kind: 'install', host: v('#os2-host'), name: v('#os2-name'), image: v('#os2-image'), disk: v('#os2-disk'), confirm: v('#os2-confirm'), size_gb: v('#os2-size'),
    user: v('#os2-user'), ssh_key: v('#os2-key'), sudo: v('#os2-sudo'), host_keys: v('#os2-hostkeys'), network: v('#os2-network'), carry: v('#os2-carry'), start: v('#os2-start') };
  if (body.image === 'custom') Object.assign(body, { image_url: v('#os2-url'), image_sha: v('#os2-sha') });
  const desk = {};
  if ($('#os2-dux').checked) Object.assign(desk, { dux: true, compositor: v('#os2-compositor'), terminal: v('#os2-terminal'), version: v('#os2-duxver'), installer_sha: v('#os2-duxsha') });
  if (v('#os2-profile')) Object.assign(desk, { profile: v('#os2-profile'), profile_compositor: v('#os2-profcomp') });
  if (Object.keys(desk).length) body.desktop = desk;
  return body;
}

function os2ProfileOptions() {          // desktopview.js calls this after a profile is saved or deleted: the form keeps what was typed
  const pick = $('#os2-profile');
  if (!pick) return;
  const was = pick.value;
  pick.replaceChildren(sfNode('option', { value: '' }, 'No profile'), ...OS2.data.desktop.profiles.map((n) => sfNode('option', { value: n }, n)));
  pick.value = OS2.data.desktop.profiles.includes(was) ? was : '';
}

function os2Render() {
  const d = OS2.data, box = $('#os2box'), edit = can('plans.edit');
  if (!d.hosts.length) { box.replaceChildren(text('p', 'No scanned hosts yet.', 'muted')); return; }
  const choice = (id, name) => os2Select(id, d.choices[name].map((o) => [o, OS2_TEXT[name][o] || o]));
  const image = os2Select('os2-image', [...d.images.map((i) => [i.key, i.label]), ['custom', 'Another image, by its address']]);
  const imageInfo = sfNode('p', { id: 'os2-imageinfo', class: 'muted small mono' });
  const custom = sfNode('div', { id: 'os2-custom', class: 'stack', hidden: true },
    os2Field('Address of the image (https)', os2Input('os2-url', { placeholder: 'https://example.com/disk.qcow2' }), 'It needs cloud-init and an EFI partition.'),
    os2Field('Its SHA-256 or SHA-512', os2Input('os2-sha')));
  const showImage = () => {
    const i = d.images.find((x) => x.key === image.value);
    custom.hidden = !!i;
    imageInfo.textContent = i ? `${i.url}\nchecked on the host against ${i.checksums}` : 'Checked on the host against the checksum you give.';
  };
  image.addEventListener('change', showImage);
  const keypick = os2Select('os2-keypick', [['', 'A key pasted below'], ...d.keys.map((k) => [k.name, `${k.name} (kept in StorageForge)`])]);
  const key = os2Input('os2-key', { placeholder: 'ssh-ed25519 AAAA… you@laptop' });
  keypick.addEventListener('change', () => { const k = d.keys.find((x) => x.name === keypick.value); if (k) key.value = k.public_key; });
  key.addEventListener('input', () => { keypick.value = ''; });
  const dux = sfNode('input', { id: 'os2-dux', type: 'checkbox' });
  const duxPart = sfNode('div', { id: 'os2-duxpart', class: 'stack', hidden: true },
    os2Field('Compositor', os2Select('os2-compositor', d.desktop.compositors.map((c) => [c, c]))),
    os2Field('Terminal', os2Select('os2-terminal', d.desktop.terminals.map((c) => [c, c]))),
    os2Field('Dux release', os2Input('os2-duxver', { placeholder: 'v2.1.2' })),
    os2Field('SHA-256 of that release\'s installer', os2Input('os2-duxsha'), `The step runs that one file and no other. Releases: ${d.desktop.releases}. With these two left empty the plan can be made, and its check says which release is newest and the hash its project publishes.`));
  dux.addEventListener('change', () => { duxPart.hidden = !dux.checked; });
  const host = os2Select('os2-host', d.hosts.map((h) => [h.host, h.os ? `${h.host} · ${h.os}` : h.host]));
  const picked = $('#host')?.value;
  if (picked && d.hosts.some((h) => h.host === picked)) host.value = picked;
  host.addEventListener('change', () => os2HostPart());
  const form = sfNode('form', { id: 'os2-form', class: 'stack', autocomplete: 'off' },
    os2Field('Host', host),
    sfNode('div', { id: 'os2-facts', class: 'stack' }),
    sfNode('h4', {}, 'Second systems on it'),
    sfNode('ul', { id: 'os2-systems', class: 'list' }),
    sfNode('h4', {}, 'Install another'),
    os2Field('Distribution', image), imageInfo, custom,
    os2Field('Name of the new system: its host name and its boot entry', os2Input('os2-name', { placeholder: 'nas-fedora', maxlength: 40 })),
    os2Field('Disk', os2Select('os2-disk', []), 'It goes into the largest stretch of unpartitioned space, or onto a blank disk. Nothing is shrunk, and the partitions and the bootloader of the running system are not written to.'),
    os2Field('Type the disk again to confirm', os2Input('os2-confirm', { placeholder: '/dev/…' })),
    os2Field('Size of its root, GiB', os2Input('os2-size', { inputmode: 'numeric', placeholder: 'empty: all the free space' })),
    os2Field('Login account', os2Input('os2-user', { placeholder: 'admin' }), 'StorageForge reaches the new system at the same address. Give it the account that scans and plans log in with, or bind another afterwards.'),
    os2Field('SSH key for that account', keypick), os2Field('Its public key', key),
    os2Field('sudo for that account', choice('os2-sudo', 'sudo')),
    os2Field('SSH host keys', choice('os2-hostkeys', 'host_keys')),
    os2Field('Network', choice('os2-network', 'network')),
    os2Field('Data filesystems of this system', choice('os2-carry', 'carry')),
    os2Field('After it is installed', os2Select('os2-start', [['no', 'Leave it installed: start it from here later'], ['once', 'Start it once, at the next restart'], ['restart', 'Start it once, and restart the machine a minute after']])),
    sfNode('h4', {}, 'A desktop on it'),
    sfNode('p', { class: 'muted small' }, 'These become a second plan, for the new system under its own host name. Run it after the machine has been started into the new system and scanned: its first step stops it in any other.'),
    sfNode('label', { class: 'field' }, dux, sfNode('span', {}, 'Install Dux')), duxPart,
    os2Field('Desktop profile', os2Select('os2-profile', [])),
    os2Field('Written for', os2Select('os2-profcomp', d.desktop.profile_compositors.map((c) => [c, c])), 'The compositor the profile is written out for. Dux installs niri, Hyprland or mango; Sway is set up by hand.'),
    edit ? sfNode('div', { class: 'row' }, sfNode('button', { type: 'submit', class: 'btn pri sm', id: 'os2-make' }, 'Make the plan')) : sfNode('p', { class: 'muted' }, 'Your account may read plans and not make them.'));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const make = $('#os2-make');
    if (!make || make.getAttribute('aria-busy') === 'true') return;
    await withBusy(make, () => os2Stage(os2Body()));
  });
  box.replaceChildren(form);
  $('#os2-compositor').addEventListener('change', (ev) => { if (d.desktop.profile_compositors.includes(ev.target.value)) $('#os2-profcomp').value = ev.target.value; });
  showImage(); os2ProfileOptions(); os2HostPart();
}

async function loadOsInstall() {
  const part = $('#os2');
  if (!part) return;
  const may = can('plans.view');
  part.hidden = !may; $('#desk').hidden = !may;
  if (!may) return;
  let d;
  try { d = await getJSON('/api/os-install/offer'); }
  catch (err) { $('#os2box').replaceChildren(text('p', err.message, 'st-failed')); return; }
  // the panel was opened again: what is typed in the form stays, and only what a scan may have changed is drawn again
  const again = OS2.data && $('#os2-form') && d.hosts.some((h) => h.host === $('#os2-host').value);
  OS2.data = d;
  if (again) { os2ProfileOptions(); os2HostPart(true); } else os2Render();
  loadDesktop();
}
