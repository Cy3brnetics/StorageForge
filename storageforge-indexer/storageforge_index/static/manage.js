'use strict';
/* Management planner: every machine StorageForge manages, hosts and network devices alike, and one way to change them. Write in the one network language, see what it becomes on the
   target, ask what it would do to a path, and then report and apply: a device through its rollback timer, a Linux host through Changes and a signed deploy. DOM APIs only. */

const $ = (s) => document.querySelector(s);
const MG = { view: 'fleet', me: null, device: null, draft: '', target: null, platforms: {} };
const VIEWS = [['fleet', 'Fleet'], ['devices', 'Devices'], ['compose', 'Compose'], ['changes', 'Changes'], ['traffic', 'Traffic'], ['scanner', 'Scanner']];
const WANT = { fleet: 'devices.view', devices: 'devices.view', compose: 'devices.view', changes: 'devices.view', traffic: 'netscan.view', scanner: 'netscan.view' };
const TARGETS = ['routeros', 'nftables', 'iptables', 'firewalld', 'ufw', 'openwrt', 'pfsense', 'cisco', 'networkd', 'networkmanager'];
const can = (p) => (MG.me?.permissions || []).includes(p);

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k in e && k !== 'list') e[k] = v;
    else e.setAttribute(k, v);
  }
  e.append(...kids.flat().filter((x) => x !== null && x !== undefined && x !== false));
  return e;
}
const btn = (label, fn, cls = '') => el('button', { type: 'button', class: `mg-btn ${cls}`, onclick: fn }, label);
const when = (t) => (t ? new Date(t * 1000).toLocaleString() : 'not yet');

async function askPassword() {
  const dlg = $('#mgreauth');
  $('#mgreauthpw').value = ''; $('#mgreautherr').hidden = true;
  dlg.showModal();
  return new Promise((resolve) => {
    $('#mgreauthno').onclick = () => { dlg.close(); resolve(false); };
    $('#mgreauthform').onsubmit = async (ev) => {
      ev.preventDefault();
      const r = await fetch('/api/reauth', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: $('#mgreauthpw').value }) });
      if (r.ok) { dlg.close(); resolve(true); return; }
      const err = $('#mgreautherr'); err.textContent = 'That is not your password.'; err.hidden = false;
    };
  });
}

async function call(path, method = 'GET', body = undefined, again = true) {
  const res = await fetch(path, { method, credentials: 'same-origin', headers: body === undefined ? {} : { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 401) { sfSignedOut(); throw new Error('signed out'); }
  const data = await res.json().catch(() => ({}));
  if (res.status === 403 && data.reauth && again) {
    if (await askPassword()) return call(path, method, body, false);
    throw new Error('Not confirmed: nothing was done.');
  }
  if (!res.ok && res.status !== 409) throw new Error(data.error || `${res.status}`);
  if (res.status === 409) throw new Error(data.error || 'refused');
  return data;
}

function table(heads, rows, onpick) {
  return el('div', { class: 'mg-table' }, el('table', {},
    el('thead', {}, el('tr', {}, heads.map((h) => el('th', {}, h)))),
    el('tbody', {}, rows.map((r, i) => el('tr', onpick ? { class: 'pick', onclick: () => onpick(i) } : {}, r.map((c) => el('td', {}, c ?? '')))))));
}

function setView(view) {
  MG.view = view;
  const sub = { fleet: 'Every machine StorageForge knows, and how it stands.', devices: 'Routers, switches and firewalls.', compose: 'One language for every target. Nothing goes anywhere until you apply it.', changes: 'What was reported, applied, confirmed and rolled back.', traffic: 'Interface counters over time, from readings only.', scanner: 'The opt-in nmap scanner. It also has its own tab beside the map.' };
  $('#mgtitle').textContent = VIEWS.find((v) => v[0] === view)[1];
  $('#mgsub').textContent = sub[view];
  document.querySelectorAll('#mgnav button').forEach((b) => (b.dataset.v === view ? b.setAttribute('aria-current', 'page') : b.removeAttribute('aria-current')));
  const box = $('#mgview');
  box.replaceChildren(el('p', { class: 'muted' }, 'Loading…'));
  ({ fleet: viewFleet, devices: viewDevices, compose: viewCompose, changes: viewChanges, traffic: viewTraffic, scanner: viewScanner })[view](box).catch((err) => box.replaceChildren(el('p', { class: 'bad' }, err.message)));
}

// ── fleet ───────────────────────────────────────────────────────────
async function viewFleet(box) {
  const f = await call('/api/fleet');
  const devices = f.machines.filter((m) => m.kind === 'device');
  const stat = (n, label, cls) => el('div', { class: 'mg-stat' }, el('b', { class: cls || '' }, String(n)), el('span', {}, label));
  const exposed = f.machines.reduce((a, m) => a + (m.exposed || 0), 0);
  const kids = [el('div', { class: 'mg-stats' }, stat(f.machines.length - devices.length, 'Hosts'), stat(devices.length, 'Network devices'), stat(f.forwards.length, 'Port forwards'), stat(exposed, 'Exposed to any address', exposed ? 'warn' : ''), stat(f.pending.length, 'Changes on a timer', f.pending.length ? 'warn' : ''))];
  if (f.warnings.length) kids.push(el('div', { class: 'mg-card' }, el('h2', {}, 'Worth knowing'), f.warnings.map((w) => el('p', { class: w.level === 'warn' ? 'warn' : 'muted' }, w.text))));
  if (f.anomalies.length) kids.push(el('div', { class: 'mg-card' }, el('h2', {}, 'Traffic out of the ordinary'), f.anomalies.map((a) => el('p', { class: 'warn' }, `${a.host} ${a.iface}: ${a.text}`))));
  if (f.pending.length) kids.push(el('div', { class: 'mg-card' }, el('h2', {}, 'Changes on a timer'), pendingRows(f.pending)));
  kids.push(el('div', { class: 'mg-card' }, el('h2', {}, 'Machines'), table(['Name', 'Kind', 'System', 'Address', 'Firewall', 'Rules', 'Forwards', 'Exposed', 'Read', ''], f.machines.map((m) => [
    m.name, m.label, m.os || '', m.address || '', m.firewall_read ? (m.backends.join(', ') || 'none') : el('span', { class: 'warn' }, 'not read'), String(m.rules), String(m.nat), String(m.exposed ?? '-'), m.error ? el('span', { class: 'bad', title: m.error }, 'failed') : when(m.read_at),
    el('span', { class: 'mg-row' }, m.kind === 'device' ? btn('Open', (ev) => { ev.stopPropagation(); MG.device = m.name; setView('devices'); }) : el('a', { class: 'mg-btn', href: `/#host=${encodeURIComponent(m.name)}&tab=rebuild` }, 'Config'), btn('Compose', (ev) => { ev.stopPropagation(); MG.target = m.name; setView('compose'); })),
  ]))));
  if (f.forwards.length) kids.push(el('div', { class: 'mg-card' }, el('h2', {}, 'Port forwards'), table(['Router', 'From outside', 'To', 'Their rules', 'Named'], f.forwards.map((x) => [x.device, `${x.proto}/${x.outside_port}${x.from_wan ? '' : ' (not from the WAN)'}`, `${x.to_addr}:${x.to_port}`, el('span', { class: x.verdict === 'accept' ? 'warn' : 'muted' }, x.verdict === 'accept' ? 'lets it through' : x.verdict === 'drop' ? 'stops it' : 'could not be worked out'), x.nat_rule]))));
  box.replaceChildren(...kids);
}

function pendingRows(rows) {
  return table(['Change', 'Device', 'State', 'Goes back at', ''], rows.map((c) => [`#${c.id}`, c.device, c.status, c.rollback_at ? new Date(c.rollback_at * 1000).toLocaleTimeString() : '', c.status === 'unconfirmed' && can('devices.apply') ? btn('Keep it', async () => { await call(`/api/devices/changes/${c.id}/confirm`, 'POST', {}); setView(MG.view); }, 'pri') : '']));
}

// ── devices ─────────────────────────────────────────────────────────
async function viewDevices(box) {
  const [list] = await Promise.all([call('/api/devices')]);
  MG.platforms = list.platforms;
  const kids = [];
  if (MG.device) {
    try { kids.push(await deviceCard(MG.device)); } catch (err) { kids.push(el('p', { class: 'bad' }, err.message)); }
  }
  kids.push(el('div', { class: 'mg-card' }, el('h2', {}, 'Devices'), list.devices.length ? table(['Name', 'System', 'Address', 'Through', 'Last read', ''], list.devices.map((d) => [d.name, d.label, `${d.address}:${d.port}`, el('span', {}, d.transport === 'telnet' ? el('span', { class: 'chip bad' }, 'Telnet, unencrypted') : 'SSH', d.legacy ? el('span', { class: 'chip warn' }, 'old ciphers') : null), d.last_error ? el('span', { class: 'bad' }, d.last_error.slice(0, 80)) : when(d.last_read_at), btn('Open', (ev) => { ev.stopPropagation(); MG.device = d.name; setView('devices'); })]), (i) => { MG.device = list.devices[i].name; setView('devices'); }) : el('p', { class: 'muted' }, 'No devices yet. Add one below.')));
  if (can('devices.manage')) kids.push(addForm());
  box.replaceChildren(...kids);
}

function addForm() {
  const name = el('input', { placeholder: 'gw-01', 'aria-label': 'Name' });
  const address = el('input', { placeholder: '10.0.0.1', 'aria-label': 'Address', value: MG.addAddress || '' });
  const platform = el('select', { 'aria-label': 'System' }, Object.entries(MG.platforms).map(([k, v]) => el('option', { value: k }, v)));
  const transport = el('select', { 'aria-label': 'Through' }, el('option', { value: 'default' }, 'SSH'), el('option', { value: 'cli' }, 'SSH terminal'), el('option', { value: 'telnet' }, 'Telnet'));
  const user = el('input', { placeholder: 'from the key binding', 'aria-label': 'Read as' });
  const cred = el('input', { placeholder: 'none: use a key', 'aria-label': 'Stored credential' });
  const wan = el('input', { placeholder: 'worked out from its default route', 'aria-label': 'WAN interfaces' });
  const legacy = el('input', { type: 'checkbox', 'aria-label': 'Old SSH ciphers' });
  const msg = el('p', { class: 'small muted' }, 'Reading uses the `scan` key binding for this address, changing uses the `deploy` one: bind a read-only account to the first.');
  const fld = (label, input) => el('label', { class: 'fld' }, label, input);
  return el('div', { class: 'mg-card' }, el('h2', {}, 'Add a device'), el('div', { class: 'mg-row' }, fld('Name', name), fld('Address', address), fld('System', platform), fld('Through', transport), fld('Read as', user), fld('Stored credential', cred), fld('WAN interfaces', wan), fld('Old SSH ciphers', legacy),
    btn('Add', async () => {
      try {
        const d = await call('/api/devices', 'POST', { name: name.value.trim(), address: address.value.trim(), platform: platform.value, transport: transport.value, username: user.value.trim() || null, credential: cred.value.trim() || null, wan: wan.value.split(/[\s,]+/).filter(Boolean), legacy: legacy.checked });
        MG.device = d.name; MG.addAddress = ''; setView('devices');
      } catch (err) { msg.textContent = err.message; msg.className = 'small bad'; }
    }, 'pri')), msg);
}

async function deviceCard(name) {
  const data = await call(`/api/devices/${encodeURIComponent(name)}`);
  const d = data.device, net = data.network || {}, facts = data.facts || {}, fw = data.firewall;
  const out = el('p', { class: 'small muted' }, d.last_error ? `Last read failed: ${d.last_error}` : `Read ${when(d.last_read_at)}`);
  const head = el('div', { class: 'mg-row' },
    el('b', {}, d.name), el('span', { class: 'chip' }, d.label), facts.version ? el('span', { class: 'chip' }, facts.version) : null, !d.encrypted ? el('span', { class: 'chip bad' }, 'Telnet: unencrypted') : null,
    can('devices.manage') ? btn('Read now', async () => { out.textContent = 'Reading…'; try { await call(`/api/devices/${encodeURIComponent(d.name)}/read`, 'POST', {}); setView('devices'); } catch (err) { out.textContent = err.message; out.className = 'small bad'; } }, 'pri') : null,
    btn('Compose', () => { MG.target = d.name; setView('compose'); }),
    el('a', { class: 'mg-btn', href: `/#view=map&host=${encodeURIComponent(d.name)}` }, 'On the map'),
    can('devices.manage') ? btn('Remove', async () => { await call(`/api/devices/${encodeURIComponent(d.name)}`, 'DELETE'); MG.device = null; setView('devices'); }, 'danger') : null);
  const ifaces = table(['Interface', 'Kind', 'State', 'Addresses', 'MAC', 'In'], (net.interfaces || []).filter((i) => i.kind !== 'loopback').map((i) => [i.name, i.kind + (i.vlan_id ? ` ${i.vlan_id}` : ''), i.state, (i.addresses || []).filter((a) => a.scope !== 'link').map((a) => `${a.ip}/${a.prefix}`).join(', '), i.mac || '', i.master || '']));
  const routes = table(['To', 'Via', 'Interface', 'Distance'], (net.routes || []).filter((r) => r.family === 4).map((r) => [r.dst, r.via || 'attached', r.dev || '', String(r.metric ?? '')]));
  const seen = [...(facts.discovered || []).map((n) => [n.name || n.ip || '', n.ip || '', n.platform || '', n.via || '', 'discovery']), ...(facts.leases || []).map((n) => [n.name || '', n.ip || '', n.mac || '', '', n.static ? 'lease (static)' : 'lease'])];
  return el('div', { class: 'mg-card' }, head, out,
    el('div', { class: 'mg-cols' }, el('div', {}, el('h2', {}, 'Interfaces'), ifaces), el('div', {}, el('h2', {}, 'Routes'), routes)),
    seen.length ? el('div', {}, el('h2', {}, 'What it knows about'), table(['Name', 'Address', 'Detail', 'On', 'From'], seen)) : null,
    (net.unreadable || []).length ? el('p', { class: 'warn small' }, `Could not read: ${net.unreadable.join(', ')}`) : null,
    fw ? el('details', {}, el('summary', {}, `Firewall: ${(fw.rules || []).length} rules, ${(fw.nat || []).length} NAT`), table(['Chain', 'Verdict', 'Protocol', 'Port', 'From', 'To', 'In', 'Out', 'Named', ''], (fw.rules || []).map((r) => [r.chain, r.action || '', r.proto || '', (r.dports || []).map((p) => (Array.isArray(p) ? p.join('-') : p)).join(','), r.saddr || r.not_saddr && `not ${r.not_saddr}` || '', r.daddr || '', r.iif || '', r.oif || '', r.comment || '', (r.unmodelled || []).length ? el('span', { class: 'warn' }, 'not fully read') : '']))) : null,
    data.dsl ? el('details', {}, el('summary', {}, 'In the one language'), el('pre', {}, data.dsl)) : null,
    facts.config ? el('details', {}, el('summary', {}, 'Saved configuration'), el('pre', {}, facts.config)) : null);
}

// ── compose ─────────────────────────────────────────────────────────
const EXAMPLE = '# Allow web from the LAN into the DMZ, and forward HTTPS in from the WAN\n/ip firewall filter add chain=forward in-interface=ether3 out-interface=ether4 protocol=tcp dst-port=80 action=accept comment="LAN to DMZ web"\n/ip firewall nat add chain=dstnat in-interface=ether2 protocol=tcp dst-port=443 action=dst-nat to-addresses=10.77.20.80 to-ports=443 comment="DMZ HTTPS"\n';

async function viewCompose(box) {
  const f = await call('/api/fleet');
  const editor = el('textarea', { spellcheck: false, 'aria-label': 'Network language', value: MG.draft || EXAMPLE, oninput: () => { MG.draft = editor.value; } });
  const on = el('select', { 'aria-label': 'Machine' }, f.machines.map((m) => el('option', { value: m.name, selected: m.name === MG.target }, `${m.name} (${m.label})`)));
  const as = el('select', { 'aria-label': 'Show as' }, TARGETS.map((t) => el('option', { value: t }, t)));
  const native = el('pre', {}, ''); const notes = el('div', {});
  const machine = () => f.machines.find((m) => m.name === on.value);
  const syncTarget = () => { const m = machine(); if (m) as.value = m.target; };
  syncTarget();
  async function render() {
    notes.replaceChildren();
    try {
      const res = await call('/api/dsl/compile', 'POST', { dsl: editor.value, targets: [as.value] });
      const got = res.targets[as.value];
      native.textContent = got.text || '(nothing for this target)';
      notes.append(...(got.unsupported || []).map((u) => el('p', { class: 'warn small' }, `Line ${u.line} can't be written for ${as.value}: ${u.why}`)), ...(got.notes || []).map((n) => el('p', { class: 'muted small' }, n)));
    } catch (err) { native.textContent = ''; notes.replaceChildren(el('p', { class: 'bad' }, err.message)); }
  }
  on.addEventListener('change', () => { MG.target = on.value; syncTarget(); render(); });
  as.addEventListener('change', render);
  editor.addEventListener('input', () => { clearTimeout(MG.timer); MG.timer = setTimeout(render, 350); });

  const a = el('input', { placeholder: 'from', 'aria-label': 'From', size: 14 }), b = el('input', { placeholder: 'to', 'aria-label': 'To', size: 14 }), port = el('input', { placeholder: 'port', 'aria-label': 'Port', size: 6, inputmode: 'numeric' });
  const whatif = el('div', {});
  const verdict = (r) => el('span', { class: r.verdict === 'allowed' ? 'ok' : r.verdict === 'blocked' ? 'bad' : 'warn' }, r.verdict);
  const ask = btn('What would this do?', async () => {
    whatif.replaceChildren(el('p', { class: 'muted small' }, 'Working it out…'));
    try {
      const r = await call('/api/dsl/whatif', 'POST', { host: on.value, dsl: editor.value, from: a.value.trim(), to: b.value.trim(), port: Number(port.value) });
      const path = (q) => el('ol', { class: 'small' }, (q.hops || []).map((h) => el('li', {}, `${h.at}: ${h.what}${h.rule ? ` (${h.rule})` : ''}`)));
      whatif.replaceChildren(el('div', { class: 'mg-cols' }, el('div', {}, el('b', {}, 'Now: '), verdict(r.before), path(r.before)), el('div', {}, el('b', {}, 'After: '), verdict(r.after), path(r.after))), r.changed ? el('p', { class: 'warn' }, 'This changes the answer.') : el('p', { class: 'muted small' }, 'The answer stays the same.'), ...(r.after.blind_spots || []).map((s) => el('p', { class: 'muted small' }, s)));
    } catch (err) { whatif.replaceChildren(el('p', { class: 'bad' }, err.message)); }
  });

  const result = el('div', {});
  const secs = el('input', { type: 'number', min: 60, max: 3600, value: 180, 'aria-label': 'Rollback seconds', size: 6 });
  const hold = el('input', { type: 'checkbox', 'aria-label': 'Confirm it myself' });
  const go = btn('Report', async () => {
    result.replaceChildren(el('p', { class: 'muted small' }, 'Working it out…'));
    try {
      const m = machine();
      if (m.kind !== 'device') {
        const res = await call('/api/dsl/stage', 'POST', { host: m.name, dsl: editor.value });
        result.replaceChildren(el('p', { class: res.ok ? 'ok' : 'warn' }, res.ok ? `${res.tasks} steps are in Changes, in “Network: ${m.name}”, to check and deploy like any other.` : res.message), ...(res.left || []).map((x) => el('p', { class: 'warn small' }, `Not staged: ${x}`)), res.ok ? el('a', { class: 'mg-btn', href: `/#host=${encodeURIComponent(m.name)}&tab=changes` }, 'Open Changes') : '');
        return;
      }
      const rep = await call(`/api/devices/${encodeURIComponent(m.name)}/report`, 'POST', { dsl: editor.value });
      const parts = [el('h2', {}, `Report for ${m.name}`), el('pre', {}, rep.native)];
      if (rep.cuts_off?.cuts) parts.push(el('p', { class: 'bad' }, `This blocks the SSH StorageForge comes in on (${rep.cuts_off.rule}). The timer would take it back, and that is all that would.`));
      if (rep.cuts_off?.cuts === null) parts.push(el('p', { class: 'warn' }, `Whether this cuts StorageForge off can't be said: ${rep.cuts_off.why}.`));
      parts.push(...rep.unsupported.map((u) => el('p', { class: 'bad small' }, `Can't be written for this device: ${u.statement}. ${u.why}`)));
      const state = el('p', { class: 'small muted' });
      if (rep.can_apply && can('devices.apply')) {
        parts.push(el('div', { class: 'mg-row' }, el('label', { class: 'fld' }, 'Goes back after (seconds)', secs), el('label', { class: 'fld' }, 'I will confirm it myself', hold),
          btn('Apply', async () => {
            state.textContent = 'Planting the rollback and applying…';
            try {
              const r = await call(`/api/devices/changes/${rep.id}/apply`, 'POST', { rollback: Number(secs.value), hold: hold.checked });
              follow(rep.id, state);
              state.textContent = r.message || `Applied. It goes back at ${new Date(r.rollback_at * 1000).toLocaleTimeString()} unless confirmed.`;
            } catch (err) { state.textContent = err.message; state.className = 'small bad'; }
          }, rep.cuts_off?.cuts ? 'danger' : 'pri')), state);
      }
      result.replaceChildren(el('div', { class: 'mg-card' }, parts));
    } catch (err) { result.replaceChildren(el('p', { class: 'bad' }, err.message)); }
  }, 'pri');

  box.replaceChildren(
    el('div', { class: 'mg-card' }, el('div', { class: 'mg-row' }, el('label', { class: 'fld' }, 'On', on), el('label', { class: 'fld' }, 'Show as', as), go, btn('Load what it runs', async () => { try { const r = await call(`/api/dsl/of?host=${encodeURIComponent(on.value)}`); editor.value = r.dsl; MG.draft = r.dsl; render(); } catch (err) { notes.replaceChildren(el('p', { class: 'bad' }, err.message)); } })),
      el('p', { class: 'small muted' }, 'A device takes a report, then an apply with its own rollback timer. A Linux host’s rules become steps in Changes.')),
    el('div', { class: 'mg-cols' }, el('div', { class: 'mg-card' }, el('h2', {}, 'What you write'), editor), el('div', { class: 'mg-card' }, el('h2', {}, 'What it becomes'), native, notes)),
    result,
    el('div', { class: 'mg-card' }, el('h2', {}, 'Try a path'), el('div', { class: 'mg-row' }, a, b, port, ask), whatif));
  render();
}

function follow(id, state) {
  const tick = async () => {
    try {
      const c = await call(`/api/devices/changes/${id}`);
      const says = { confirmed: ['ok', 'It answers, so the change was kept.'], 'rolled-back': ['warn', 'The device went back to what it had, and answers again.'], 'rolling-back': ['warn', 'The device stopped answering: its timer will take it back.'], lost: ['bad', 'The device has not answered since its timer ran out. Go and look at it.'] };
      if (says[c.status]) { state.className = `small ${says[c.status][0]}`; state.textContent = says[c.status][1]; }
      if (['confirmed', 'rolled-back', 'lost'].includes(c.status)) return;
    } catch { /* it comes back */ }
    setTimeout(tick, 5000);
  };
  setTimeout(tick, 3000);
}

// ── changes ─────────────────────────────────────────────────────────
async function viewChanges(box) {
  const list = await call('/api/devices');
  const rows = [];
  for (const d of list.devices) rows.push(...(await call(`/api/devices/${encodeURIComponent(d.name)}`)).changes);
  rows.sort((a, b) => b.id - a.id);
  const cls = { confirmed: 'ok', 'rolled-back': 'warn', 'rolling-back': 'warn', unconfirmed: 'warn', lost: 'bad' };
  box.replaceChildren(el('div', { class: 'mg-card' }, rows.length ? table(['#', 'Device', 'State', 'By', 'Reported', 'What'], rows.map((c) => [String(c.id), c.device, el('span', { class: `chip ${cls[c.status] || ''}` }, c.status), c.actor || '', when(c.created_at), el('details', {}, el('summary', {}, `${(c.statements || []).length} statements`), el('pre', {}, (c.statements || []).join('\n')), c.output ? el('p', { class: 'small muted' }, c.output) : null)])) : el('p', { class: 'muted' }, 'No changes yet.')));
}

// ── traffic ─────────────────────────────────────────────────────────
function spark(series, key) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'spark'); svg.setAttribute('viewBox', '0 0 180 28'); svg.setAttribute('aria-hidden', 'true');
  if (series.length > 1) {
    const max = Math.max(...series.map((s) => s[key]), 1);
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', series.map((s, i) => `${i ? 'L' : 'M'}${(i / (series.length - 1) * 178 + 1).toFixed(1)} ${(26 - s[key] / max * 24).toFixed(1)}`).join(' '));
    svg.append(path);
  }
  return svg;
}
const rate = (v) => (v == null ? '' : v > 1048576 ? `${(v / 1048576).toFixed(1)} MiB/s` : `${(v / 1024).toFixed(1)} KiB/s`);

async function viewTraffic(box) {
  const t = await call('/api/traffic');
  const toggle = can('netscan.run') ? btn(t.enabled ? 'Turn off' : 'Turn on', async () => { await call('/api/traffic/settings', 'POST', { enabled: !t.enabled }); setView('traffic'); }, t.enabled ? '' : 'pri') : null;
  const kids = [el('div', { class: 'mg-card' }, el('div', { class: 'mg-row' }, el('b', {}, t.enabled ? 'Monitoring is on' : 'Monitoring is off'), toggle), el('p', { class: 'small muted' }, 'Sends nothing. Each number comes from a device’s own counters at an ordinary reading, every 5 minutes while this is on.'))];
  if (t.anomalies.length) kids.push(el('div', { class: 'mg-card' }, el('h2', {}, 'Out of the ordinary'), t.anomalies.map((a) => el('p', { class: 'warn' }, `${a.host} ${a.iface}: ${a.text}`))));
  if (t.interfaces.length) kids.push(el('div', { class: 'mg-card' }, table(['Machine', 'Interface', 'In', '', 'Out', '', 'Errors', 'Drops'], t.interfaces.map((i) => [i.host, i.iface, rate(i.latest?.rx_rate), spark(i.series, 'rx_rate'), rate(i.latest?.tx_rate), spark(i.series, 'tx_rate'), String(i.latest?.errors ?? ''), String(i.latest?.drops ?? '')]))));
  box.replaceChildren(...kids);
}

// ── scanner ─────────────────────────────────────────────────────────
async function viewScanner(box) {
  box.replaceChildren(el('div', { class: 'mg-card' }, el('p', {}, 'The scanner has its own tab beside the map, with its results linked back to each machine’s pages.'), el('a', { class: 'mg-btn pri', href: '/#view=scan' }, 'Open the Scan tab')));
}

// ── start ───────────────────────────────────────────────────────────
(async function start() {
  MG.me = await call('/api/me');
  const nav = $('#mgnav');
  for (const [id, label] of VIEWS) if (can(WANT[id])) { const b = el('button', { type: 'button', onclick: () => setView(id) }, label); b.dataset.v = id; nav.append(b); }
  const q = new URLSearchParams(location.hash.slice(1));
  if (q.get('device')) { MG.device = q.get('device'); setView('devices'); return; }
  if (q.get('add')) { MG.addAddress = q.get('add'); setView('devices'); return; }
  if (!VIEWS.some(([id]) => can(WANT[id]))) { $('#mgview').replaceChildren(el('p', { class: 'muted' }, 'This account has no network access.')); return; }
  setView(VIEWS.find(([id]) => can(WANT[id]))[0]);
})().catch((err) => $('#mgview').replaceChildren(el('p', { class: 'bad' }, err.message)));
