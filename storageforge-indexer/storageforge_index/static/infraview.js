'use strict';
/* Infrastructure tab: what runs on each host, its network, its firewall rules and who can reach what. Everything is read from
   the index and says how old it is. "Measure now" is the one action, and it only reads. DOM APIs only. Loaded after
   dockerview.js; uses the shared helpers. */

const INF = { view: 'workloads' };
const INF_VIEWS = [['workloads', 'Workloads'], ['exposure', 'Exposure'], ['network', 'Network'], ['firewall', 'Firewall']];
const INF_LEVEL = { any: 'Any address', lan: 'Private networks', vpn: 'VPN only', blocked: 'Blocked', loopback: 'This machine only', unknown: 'Unknown' };
const INF_CLASS = { any: 'st-failed', lan: 'st-warn', vpn: 'muted', blocked: 'muted', loopback: 'muted', unknown: 'st-warn' };

function infWhen(t) { return t ? fmtTime(t) : 'not read'; }
function infTable(heads, rows) {
  const table = document.createElement('table');
  const tr = document.createElement('tr');
  for (const h of heads) tr.append(text('th', h));
  const head = document.createElement('thead'); head.append(tr);
  const body = document.createElement('tbody');
  for (const row of rows) {
    const r = document.createElement('tr');
    for (const [i, c] of row.entries()) { const td = document.createElement('td'); td.dataset.label = heads[i]; td.append(c instanceof Node ? c : document.createTextNode(c == null ? '' : String(c))); r.append(td); }
    body.append(r);
  }
  table.append(head, body);
  const wrap = document.createElement('div'); wrap.className = 'inf-table'; wrap.append(table);
  return wrap;
}

async function loadInfra() {
  const box = $('#infrabox');
  const nav = document.createElement('div'); nav.className = 'seg sm'; nav.setAttribute('role', 'group');
  for (const [id, label] of INF_VIEWS) {
    if ((id === 'exposure' || id === 'firewall') && !can('security.view')) continue;
    if (id === 'network' && !can('map.view')) continue;
    const b = button(label, () => { INF.view = id; loadInfra(); }, INF.view === id ? 'on' : '');
    nav.append(b);
  }
  const content = document.createElement('div'); content.className = 'stack';
  content.append(text('p', 'Loading…', 'muted small'));
  box.replaceChildren(nav, content);
  try {
    await ({ workloads: infWorkloads, exposure: infExposure, network: infNetwork, firewall: infFirewall })[INF.view](content);
  } catch (err) { content.replaceChildren(text('p', err.message, 'st-failed')); }
}

function infMeasure(host, out) {
  if (!can('security.manage') || !host) return document.createTextNode('');
  return button('Measure now', async () => {
    out.replaceChildren(text('p', 'Reading the host…', 'muted small'));
    try {
      await postJSON('/api/infra/measure', { host });
      loadInfra();
    } catch (err) { out.replaceChildren(text('p', (err.body && err.body.error) || err.message, 'st-failed')); }
  }, 'btn');
}

function infNeedHost(content) {
  if (S.host) return false;
  needHost(content, 'This view', loadInfra);
  return true;
}

async function infWorkloads(content) {
  const qs = S.host ? `?host=${encodeURIComponent(S.host)}` : '';
  const [{ workloads, hosts }, lvs] = await Promise.all([getJSON('/api/workloads' + qs), getJSON('/api/workloads/libvirt' + qs).then((r) => r.hosts).catch(() => [])]);
  const out = document.createElement('div');
  const kids = [out];
  for (const h of hosts) {
    const mine = workloads.filter((w) => w.host === h.host);
    const head = document.createElement('div'); head.className = 'row';
    head.append(el('b', { class: 'mono' }, h.host), text('span', `containers read ${infWhen(h.containers_read_at)} · VMs and instances read ${infWhen(h.measured_at)}${h.measure_stale ? ' (old)' : ''}`, 'muted small'), infMeasure(h.host, out));
    kids.push(head);
    if (!h.measured_at) kids.push(text('p', 'VMs, instances and other users\' containers take a signed reading, and this host has none yet, so this list may not be complete.', 'muted small'));
    const lv = lvs.find((x) => x.host === h.host);
    if (!mine.length) { kids.push(text('p', h.measured_at ? 'Nothing found.' : 'No containers found by the scan.', 'muted small')); if (lv) kids.push(infLibvirt(h.host, lv)); continue; }
    const panel = el('div', { class: 'stack' });
    kids.push(infTable(['Name', 'Kind', 'State', 'Ports', 'Stored on', 'Worth a look'], mine.map((w) => [
      w.runtime === 'libvirt' && w.name ? button(w.name, () => infVm(panel, h.host, w), 'btn ghost sm mono') : el('span', { class: 'mono' }, w.name || '?'),
      `${w.runtime} ${w.kind}${w.user ? ` (${w.user})` : ''}${w.panel ? ' · panel' : ''}`,
      w.state || '?',
      (w.ports || []).map((p) => `${p.host_ip}:${p.host_port}→${p.port}/${p.proto}`).join(', '),
      [...new Set((w.mounts || []).map((m) => m.on ? `${m.on.mount} (${m.on.filesystem})` : null).filter(Boolean))].join(', '),
      w.detail ? (w.findings || []).join('; ') : 'Not read in full'])), panel);
    if (lv) kids.push(infLibvirt(h.host, lv));
  }
  content.replaceChildren(...kids);
}

/* A libvirt VM: what the last reading says of it, its snapshots, and buttons that stage a plan step. Nothing runs from
   here: each button opens the step's form, the plan is checked and saved, and runs as every plan does (Changes tab). */
const INF_VM_STATE = { running: 'st-ok', 'shut off': 'muted', paused: 'st-warn', crashed: 'st-failed' };
function infVm(panel, host, w) {
  const edit = typeof openTask === 'function' && can('plans.edit');
  const stage = (label, type, params, cls = 'btn sm') => button(label, () => openTask(type, host, params), cls);
  const head = el('div', { class: 'row wrap' }, el('b', { class: 'mono' }, w.name), text('span', w.state || '?', INF_VM_STATE[w.state] || ''),
    text('span', `${w.vcpus || '?'} vCPUs · ${w.memory_mib != null ? fmtBytes(w.memory_mib * 2 ** 20) : '?'} · ${w.firmware || 'bios'}${w.tpm ? ' · TPM' : ''}${w.autostart ? ' · starts at boot' : ''}`, 'muted small'),
    text('span', w.agent === 'connected' ? 'guest agent answers: snapshots freeze its filesystems' : w.agent ? `guest agent ${w.agent}` : 'no guest agent channel', w.agent === 'connected' ? 'st-ok small' : 'muted small'),
    button('Close', () => panel.replaceChildren(), 'btn ghost sm'));
  const kids = [head];
  if (edit) {
    const acts = el('div', { class: 'row wrap', role: 'group', 'aria-label': `Plan a change to ${w.name}` });
    const lv = { runtime: 'libvirt', name: w.name };
    if (w.state !== 'running') acts.append(stage('Start', 'workload-action', { ...lv, action: 'start' }));
    else acts.append(stage('Shut down', 'workload-action', { ...lv, action: 'stop' }), stage('Restart', 'workload-action', { ...lv, action: 'restart' }),
      stage('Force off', 'workload-action', { ...lv, action: 'force-off' }, 'btn sm danger'));
    acts.append(stage('Snapshot…', 'vm-snapshot', { name: w.name, disk_only: true }), stage('Change…', 'vm-edit', { name: w.name }),
      button('Copy to another host…', () => infVmCopy(host, w), 'btn sm'));
    if (can('console.open')) acts.append(el('a', { class: 'btn sm', href: `/console#${encodeURIComponent(w.name)}`, target: '_blank', rel: 'noopener' }, 'Console'));
    acts.append(stage('Remove…', 'workload-remove', lv, 'btn ghost sm danger'));
    kids.push(acts, text('p', 'Each button opens the step of a change plan: it is checked against this reading, reports first, and runs when the plan is deployed.', 'muted small'));
  }
  kids.push(text('h4', 'Disks'), infTable(['Disk', 'Kind', 'Bus', 'Format', 'File or device', 'Stored on'], (w.disks || []).map((d) => {
    const m = (w.mounts || []).find((x) => x.dest === d.target);
    return [el('span', { class: 'mono' }, d.target || '?'), d.device + (d.readonly ? ', read-only' : ''), d.bus || '', d.format + (d.backing ? ', on a base image' : ''),
      el('span', { class: 'mono' }, d.source || ''), m && m.on ? `${m.on.mount} (${m.on.filesystem})` : ''];
  })));
  const snaps = w.snapshots || [];
  kids.push(text('h4', `Snapshots (${snaps.length})`));
  if (!snaps.length) kids.push(text('p', 'None.', 'muted small'));
  else kids.push(infTable(['Snapshot', 'Taken', 'Kind', 'Of a VM that was', ''], snaps.slice().reverse().map((x) => [
    el('span', { class: 'mono' }, x.name + (x.current ? ' (current)' : '')), x.created ? fmtTime(x.created) : '',
    x.location === 'external' ? 'disk-only' : 'internal, with memory', x.state === 'disk-snapshot' ? 'its disks only' : x.state || '',
    edit ? el('div', { class: 'row' }, stage('Revert…', 'vm-revert', { name: w.name, snapshot: x.name }, 'btn ghost sm'),
      stage('Delete…', 'vm-snapshot', { name: w.name, snapshot: x.name, action: 'delete', disk_only: x.location === 'external' }, 'btn ghost sm')) : ''])));
  panel.replaceChildren(el('div', { class: 'card stack', role: 'region', 'aria-label': `VM ${w.name}` }, ...kids));
  panel.scrollIntoView({ block: 'nearest' });
}

/* Networks and storage pools of a libvirt host, each with the steps that change or remove it, and a new one. */
function infLibvirt(host, lv) {
  const box = el('div', { class: 'stack' });
  const edit = typeof openTask === 'function' && can('plans.edit');
  const stage = (label, type, params, cls = 'btn ghost sm') => button(label, () => openTask(type, host, params), cls);
  const yes = (v) => (v == null ? '?' : v ? 'yes' : 'no');
  box.append(el('div', { class: 'row' }, text('h4', 'libvirt networks'), edit ? stage('New network…', 'libvirt-network', { mode: 'nat', autostart: true }, 'btn sm') : ''),
    infTable(['Network', 'Kind', 'Address', 'DHCP', 'Bridge', 'Up', 'At boot', ''], lv.networks.map((n) => [
      el('span', { class: 'mono' }, n.name), n.mode, n.address ? `${n.address}/${/^\d+$/.test(n.netmask || '') ? n.netmask : infBits(n.netmask)}` : '', n.dhcp || '', n.bridge || '', yes(n.active), yes(n.autostart),
      edit ? el('div', { class: 'row' }, stage('Change…', 'libvirt-network', { name: n.name, mode: n.mode, bridge: n.mode === 'bridge' ? n.bridge : '',
        address: n.address ? `${n.address}/${/^\d+$/.test(n.netmask || '') ? n.netmask : infBits(n.netmask)}` : '', dhcp: n.dhcp || '', autostart: !!n.autostart }),
      stage('Remove…', 'libvirt-network', { name: n.name, state: 'absent' })) : ''])));
  box.append(el('div', { class: 'row' }, text('h4', 'Storage pools'), edit ? stage('New pool…', 'libvirt-pool', { type: 'dir', autostart: true }, 'btn sm') : ''),
    infTable(['Pool', 'Kind', 'Folder or source', 'Free', 'Up', 'At boot', ''], lv.pools.map((p) => [
      el('span', { class: 'mono' }, p.name), p.type || '', el('span', { class: 'mono' }, p.path || p.source || ''),
      p.available != null ? `${fmtBytes(p.available)} of ${fmtBytes(p.capacity)}` : '', yes(p.active), yes(p.autostart),
      edit ? el('div', { class: 'row' }, stage('Change…', 'libvirt-pool', { name: p.name, type: p.type, path: p.type === 'dir' ? p.path : '', source: p.type !== 'dir' ? p.source || '' : '', autostart: !!p.autostart }),
        stage('Remove…', 'libvirt-pool', { name: p.name, state: 'absent' })) : ''])));
  return box;
}
function infBits(mask) { return String(mask || '').split('.').reduce((n, o) => n + ((Number(o) >>> 0).toString(2).match(/1/g) || []).length, 0) || ''; }

/* Copy a VM as it is to another libvirt host: two steps, a send of its disks here and the VM defined there from this reading. */
async function infVmCopy(host, w) {
  showTab('details');
  const { hosts } = await getJSON('/api/workloads/libvirt');
  const target = el('select', {}, ...hosts.map((h) => new Option(h.host === host ? `${h.host} (beside it, as a new VM)` : h.host, h.host)));
  const pool = el('select', {});
  const fillPools = () => { const h = hosts.find((x) => x.host === target.value); pool.replaceChildren(...((h && h.pools) || []).filter((p) => p.type === 'dir').map((p) => new Option(`${p.name} (${p.path})`, p.name))); };
  target.addEventListener('change', () => { fillPools(); if (target.value === host && asName.value === '') asName.value = `${w.name}-copy`; });
  const asName = el('input', { type: 'text', class: 'mono', placeholder: w.name, autocomplete: 'off', spellcheck: 'false' });
  const tick = (label, on) => { const i = el('input', { type: 'checkbox' }); i.checked = on; return [i, el('label', { class: 'check' }, i, label)]; };
  const [live, liveL] = tick('While it runs: from a disk-only snapshot, merged back after', w.state === 'running');
  const [start, startL] = tick('Start the copy', false), [macs, macsL] = tick('Keep its MAC addresses (run only one of the two)', false);
  const out = el('div', { class: 'stack' });
  const body = () => ({ source: host, name: w.name, target: target.value, as: asName.value.trim(), pool: pool.value, live: live.checked, start: start.checked, keep_macs: macs.checked });
  const show = (r) => {
    const items = r.check.tasks.flatMap((t, i) => t.items.map((x) => el('li', {}, text('b', `${i ? 'There' : 'Here'}, ${x.level}: `, x.level === 'crit' ? 'st-failed' : x.level === 'warn' ? 'st-warn' : 'muted'), x.text)));
    return [el('ol', {}, ...r.plan.tasks.map((t) => el('li', {}, taskTitle(t), text('span', ` (on ${t.host})`, 'muted')))), el('ul', { class: 'small' }, ...items)];
  };
  const preview = button('Preview', async () => {
    try { out.replaceChildren(...show(await (await postJSON('/api/vm/copy/preview', body())).json())); } catch (err) { out.replaceChildren(text('p', err.message, 'st-failed')); }
  }, 'btn sm');
  const save = button('Save the plan', async () => {
    try {
      const r = await (await postJSON('/api/vm/copy', body())).json();
      out.replaceChildren(text('p', `Saved change plan #${r.id}. Deploy it from Changes: each disk goes by a send of its own, which a script run by hand cannot make.`, 'st-ok'), ...show(r),
        typeof loadChanges === 'function' ? button('Open it in Changes', () => { showTab('changes'); loadChanges(r.id); }, 'btn sm') : '');
    } catch (err) { out.replaceChildren(text('p', err.message, 'st-failed')); }
  }, 'btn pri sm');
  fillPools();
  $('#summary').replaceChildren(el('div', { class: 'stack card stageform' },
    el('div', { class: 'row' }, el('b', {}, `Copy VM ${w.name} from ${host}`)),
    text('p', 'A plan of two steps: here each disk is sent and checked on both ends, there the VM is defined from what this reading says of it, with the same vCPUs, memory, firmware, disks and networks. Nothing runs until the plan is deployed.', 'muted small'),
    el('label', { class: 'field col' }, el('span', {}, 'To host'), target), el('label', { class: 'field col' }, el('span', {}, 'Into the pool'), pool),
    el('label', { class: 'field col' }, el('span', {}, 'Name of the copy (optional)'), asName),
    el('div', { class: 'row wrap' }, liveL, startL, macsL), el('div', { class: 'row end' }, preview, save), out));
  target.focus();
}

async function infExposure(content) {
  const qs = S.host ? `?host=${encodeURIComponent(S.host)}` : '';
  const { hosts } = await getJSON('/api/exposure' + qs);
  const out = document.createElement('div');
  const kids = [out];
  for (const h of hosts) {
    const head = document.createElement('div'); head.className = 'row';
    head.append(el('b', { class: 'mono' }, h.host), text('span', h.firewall_read ? `${(h.backends || []).join(', ') || 'no firewall'} · read ${infWhen(h.measured_at)}` : 'firewall rules not read', 'muted small'), infMeasure(h.host, out));
    kids.push(head);
    if (!h.read) { kids.push(text('p', 'No network reading yet: it comes with the next scan.', 'muted small')); continue; }
    kids.push(text('p', h.caveat, 'muted small'));
    kids.push(infTable(['Who can reach it', 'Port', 'Bound to', 'What', 'Because'], h.items.map((i) => [
      text('span', INF_LEVEL[i.level] || i.level, INF_CLASS[i.level] || ''),
      `${i.port}/${i.proto}`, i.addr,
      i.kind === 'published' ? `container ${i.container}${i.bypasses_frontend ? ' (not stopped by the host firewall front end)' : ''}` : (i.process || []).join(', '),
      [i.rule, ...(i.why || [])].filter(Boolean).join('; ')])));
  }
  content.replaceChildren(...kids);
}

async function infNetwork(content) {
  if (infNeedHost(content)) return;
  const { host, network } = await getJSON(`/api/network?host=${encodeURIComponent(S.host)}`);
  if (!network) { content.replaceChildren(text('p', `No network reading for ${host} yet: it comes with the next scan.`, 'muted')); return; }
  const kids = [text('p', `Read ${infWhen(network.read_at)}.`, 'muted small')];
  if (network.unreadable.length) kids.push(text('p', `Could not read: ${network.unreadable.join(', ')}. That does not mean there are none.`, 'st-warn'));
  kids.push(text('h4', 'Interfaces'), infTable(['Name', 'Kind', 'State', 'Addresses', 'MTU', 'Part of'], network.interfaces.map((i) => [
    el('span', { class: 'mono' }, i.name), i.kind + (i.vlan_id ? ` ${i.vlan_id}` : ''), i.state, i.addresses.map((a) => `${a.ip}/${a.prefix}`).join(', '), i.mtu, i.master || ''])));
  kids.push(text('h4', 'Routes'), infTable(['To', 'Via', 'Device'], network.routes.map((r) => [r.dst, r.via || '', r.dev || ''])));
  kids.push(text('h4', 'Seen nearby'), text('p', 'From the host\'s neighbour table. These may not be managed hosts.', 'muted small'),
    infTable(['Address', 'MAC', 'Device'], network.neighbours.map((n) => [n.ip, n.mac, n.dev])));
  kids.push(text('p', `DNS: ${network.dns.nameservers.join(', ') || 'none read'}`, 'small'));
  content.replaceChildren(...kids);
}

async function infFirewall(content) {
  if (infNeedHost(content)) return;
  const { host, firewall, measured_at: at, stale } = await getJSON(`/api/firewall?host=${encodeURIComponent(S.host)}`);
  const out = document.createElement('div');
  const head = document.createElement('div'); head.className = 'row';
  head.append(el('b', { class: 'mono' }, host), text('span', `read ${infWhen(at)}${stale ? ' (old)' : ''}`, 'muted small'), infMeasure(host, out));
  if (!firewall) { content.replaceChildren(head, out, text('p', 'Not read yet. Reading firewall rules takes deploy access and a signed run.', 'muted')); return; }
  const kids = [head, out];
  if (!firewall.readable) kids.push(text('p', `Not readable: ${firewall.notes.join('; ')}. Treat this as unknown, not as open or closed.`, 'st-warn'));
  kids.push(text('p', `Backends: ${firewall.backends.join(', ') || 'none'}. Default policies: ${Object.entries(firewall.policies).map(([k, v]) => `${k} ${v}`).join(', ') || 'none read'}.`, 'small'));
  kids.push(infTable(['Where', 'Action', 'Protocol', 'Ports', 'From', 'Note'], firewall.rules.map((r) => [
    `${r.table} ${r.chain}`, r.action || '', r.proto || '', (r.dports || []).map((p) => Array.isArray(p) ? p.join('-') : p).join(', '), r.saddr || '',
    [r.comment, ...(r.unmodelled || []).map((u) => `not understood: ${u}`)].filter(Boolean).join('; ')])));
  content.replaceChildren(...kids);
}
