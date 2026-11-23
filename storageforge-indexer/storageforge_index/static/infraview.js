'use strict';
/* Infrastructure tab: what runs on each host, its network, its firewall rules and who can reach what. Everything is read from
   the index and says how old it is. "Measure now" is the one action, and it only reads. DOM APIs only. Loaded after
   dockerview.js; uses the shared helpers. */

const INF = { view: 'workloads', wlRuntime: '', wlState: '', wlFind: '', vmTab: 'all', fwFind: '' };
const INF_VIEWS = [['workloads', 'Workloads'], ['containers', 'Containers'], ['exposure', 'Exposure'], ['network', 'Network'], ['firewall', 'Firewall'], ['sfnet', 'StorageForge network'], ['toolbox', 'Toolbox']];
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
    if (id === 'containers' && !can('services.view')) continue;
    if ((id === 'exposure' || id === 'firewall') && !can('security.view')) continue;
    if (id === 'network' && !can('map.view')) continue;
    const b = button(label, () => { INF.view = id; loadInfra(); }, INF.view === id ? 'on' : '');
    nav.append(b);
  }
  const content = document.createElement('div'); content.className = 'stack';
  content.append(text('p', 'Loading…', 'muted small'));
  box.replaceChildren(nav, content);
  try {
    await ({
      workloads: infWorkloads,
      containers: infContainers,
      exposure: infExposure,
      network: infNetwork,
      firewall: infFirewall,
      sfnet: sfnView,
      toolbox: infToolbox,
    })[INF.view](content);
  } catch (err) { content.replaceChildren(text('p', err.message, 'st-failed')); }
}

async function infContainers(content) {
  const box = el('div', { id: 'dockerbox', class: 'stack' });
  content.replaceChildren(
    text('p', 'Containers and compose stacks on each host, the folders they use, and stacks stored on disk that are not deployed. Stacks run by a manager in a container (Dockhand, Portainer, Komodo) are traced to their real folders.', 'muted small'),
    box,
  );
  await loadDocker();
}

async function infToolbox(content) {
  const msg = el('p', { id: 'toolboxmsg', class: 'muted', role: 'status', hidden: true });
  const box = el('div', { id: 'toolboxbox', class: 'stack' });
  content.replaceChildren(
    text('p', 'Tools from a signed catalog, installed on hosts as change plans and shown here at the level each supports. Every install, removal and action saves a change plan, deployed from Changes with its report first.', 'muted small'),
    msg,
    box,
  );
  await loadToolbox();
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
  const systemContainer = (w) => ['lxc', 'incus'].includes(w.runtime) || (w.runtime === 'proxmox' && w.kind === 'instance');
  const virtualMachine = (w) => !systemContainer(w) && (['libvirt', 'proxmox'].includes(w.runtime) || w.kind === 'vm');
  const vms = workloads.filter(virtualMachine);
  const cts = workloads.filter((w) => !vms.includes(w));
  const running = workloads.filter((w) => w.state === 'running');
  const vcpus = vms.reduce((a, w) => a + (Number(w.vcpus) || 0), 0);
  const ramMib = vms.reduce((a, w) => a + (Number(w.memory_mib) || 0), 0);
  const warnCount = workloads.filter((w) => (w.findings || []).length > 0).length;
  const kpis = el('div', { class: 'pve-kpis' },
    el('div', { class: 'pve-kpi accent' }, text('span', 'Nodes', 'pve-kpi-lbl'), el('b', {}, String(hosts.length)), text('small', `${workloads.length} total guests`)),
    el('div', { class: `pve-kpi ${running.length ? 'ok' : ''}` }, text('span', 'Running', 'pve-kpi-lbl'), el('b', {}, String(running.length)), text('small', `${workloads.length - running.length} stopped / other`)),
    el('div', { class: 'pve-kpi' }, text('span', 'VMs / Instances', 'pve-kpi-lbl'), el('b', {}, String(vms.length)), text('small', `${vcpus} vCPUs · ${ramMib ? fmtBytes(ramMib * 2 ** 20) : '0 B'}`)),
    el('div', { class: `pve-kpi ${warnCount ? 'warn' : ''}` }, text('span', 'Containers & Alerts', 'pve-kpi-lbl'), el('b', {}, String(cts.length)), text('small', `${warnCount} guest${warnCount === 1 ? '' : 's'} with findings`)));

  const listBox = el('div', { class: 'stack' });
  const rtSel = el('select', { 'aria-label': 'Filter guest runtime', onchange: () => { INF.wlRuntime = rtSel.value; drawList(); } },
    new Option('All runtimes', ''), new Option('VMs (libvirt / Proxmox)', 'vm'), new Option('System containers (LXC / Incus)', 'lxc'), new Option('App containers (Docker / Podman)', 'ctr'));
  rtSel.value = INF.wlRuntime;
  const stSel = el('select', { 'aria-label': 'Filter guest state', onchange: () => { INF.wlState = stSel.value; drawList(); } },
    new Option('All states', ''), new Option('Running', 'running'), new Option('Stopped / off', 'stopped'), new Option('With findings', 'findings'));
  stSel.value = INF.wlState;
  const find = el('input', { type: 'search', value: INF.wlFind, placeholder: 'Filter guests, ports or mounts…', 'aria-label': 'Filter guests', autocomplete: 'off',
    oninput: () => { INF.wlFind = find.value; drawList(); } });
  const targetHost = S.host || (hosts[0] && hosts[0].host) || '';
  const edit = typeof openTask === 'function' && can('plans.edit') && targetHost;
  const bar = el('div', { class: 'pve-toolbar' }, rtSel, stSel, find,
    edit ? button('+ New VM…', () => openTask('vm-create', targetHost, {}), 'btn sm pri') : null,
    edit && lvs.length ? button('+ New Network…', () => openTask('libvirt-network', targetHost, { mode: 'nat', autostart: true }), 'btn sm') : null,
    edit && lvs.length ? button('+ New Pool…', () => openTask('libvirt-pool', targetHost, { type: 'dir', autostart: true }), 'btn sm') : null);

  function matchesGuest(w) {
    if (INF.wlRuntime === 'vm' && !virtualMachine(w)) return false;
    if (INF.wlRuntime === 'lxc' && !systemContainer(w)) return false;
    if (INF.wlRuntime === 'ctr' && !['docker', 'podman', 'podman_rootless', 'compose', 'truenas-app'].includes(w.runtime)) return false;
    if (INF.wlState === 'running' && w.state !== 'running') return false;
    if (INF.wlState === 'stopped' && w.state === 'running') return false;
    if (INF.wlState === 'findings' && !(w.findings || []).length) return false;
    const q = INF.wlFind.trim().toLowerCase();
    if (!q) return true;
    const hay = [w.host, w.name, w.runtime, w.kind, w.state, w.api?.connection, w.api?.platform, w.api?.node, w.api?.environment, ...(w.findings || []),
      ...(w.ports || []).map((p) => `${p.host_ip}:${p.host_port}:${p.port}`),
      ...(w.mounts || []).map((m) => m.on?.mount || m.dest || '')].join(' ').toLowerCase();
    return hay.includes(q);
  }

  function drawList() {
    const kids = [];
    const scanned = new Set(hosts.map((h) => h.host));
    const apiOnly = workloads.filter((w) => w.source === 'api' && !scanned.has(w.host));
    const groups = hosts.map((h) => ({ host: h, rows: workloads.filter((w) => w.host === h.host) }));
    if (apiOnly.length) groups.push({ host: null, rows: apiOnly });
    for (const { host: h, rows: mine } of groups) {
      const shown = mine.filter(matchesGuest);
      const head = el('div', { class: 'row' }, el('b', { class: h ? 'mono' : '' }, h ? h.host : 'Connected platforms'));
      if (h) {
        head.append(text('span', `containers read ${infWhen(h.containers_read_at)} · VMs and instances read ${infWhen(h.measured_at)}${h.measure_stale ? ' (old)' : ''}`, 'muted small'), infMeasure(h.host, out));
      }
      kids.push(head);
      if (h && !h.measured_at) kids.push(text('p', "VMs, instances and other users' containers take a signed reading, and this host has none yet, so this list may not be complete.", 'muted small'));
      const lv = h ? lvs.find((x) => x.host === h.host) : null;
      if (!mine.length) { kids.push(text('p', h.measured_at ? 'Nothing found.' : 'No containers found by the scan.', 'muted small')); if (lv) kids.push(infLibvirt(h.host, lv)); continue; }
      if (!shown.length) { kids.push(text('p', `No guests match the current filters (${mine.length} hidden).`, 'muted small')); if (lv) kids.push(infLibvirt(h.host, lv)); continue; }
      const panel = el('div', { class: 'stack' });
      kids.push(infTable(['Name', 'Kind', 'State', 'Platform API', 'Ports', 'Stored on', 'Worth a look'], shown.map((w) => [
        w.runtime === 'libvirt' && w.name && w.source !== 'api'
          ? button(w.name, () => infVm(panel, w.host, w), 'btn ghost sm mono')
          : w.name ? button(w.name, () => infGuest(panel, w.host, w), 'btn ghost sm mono') : el('span', { class: 'mono' }, '?'),
        `${w.runtime} ${w.kind}${w.user ? ` (${w.user})` : ''}${w.panel ? ' · panel' : ''}`,
        text('span', w.state || '?', INF_VM_STATE[w.state] || ''),
        w.api?.seen === false ? 'Not seen' : w.api?.connection
          ? `${w.api.connection}${w.api.differs?.length ? ` · ${w.api.differs.length} differences` : ''}` : '',
        (w.ports || []).map((p) => `${p.host_ip}:${p.host_port}→${p.port}/${p.proto}`).join(', '),
        [...new Set((w.mounts || []).map((m) => m.on ? `${m.on.mount} (${m.on.filesystem})` : null).filter(Boolean))].join(', '),
        w.detail ? (w.findings || []).join('; ') : 'Not read in full'])), panel);
      if (lv) kids.push(infLibvirt(h.host, lv));
    }
    listBox.replaceChildren(...kids);
  }
  drawList();
  content.replaceChildren(out, kpis, bar, listBox);
}

function infWorkloadApi(w) {
  const api = w.api;
  if (!api) return null;
  if (api.seen === false) return text('p', api.why || 'The platform API did not list this workload.', 'muted small');
  const details = [api.connection, api.platform, api.node || w.host, api.remote, api.environment, api.stack].filter(Boolean);
  const state = api.status || api.state;
  if (state) details.push(`state ${state}`);
  const kids = [text('h4', 'Platform API'), text('p', details.join(' · '), 'small')];
  if (w.source === 'api') kids.push(text('p', 'Listed by the platform API only.', 'muted small'));
  if (api.differs?.length) {
    kids.push(infTable(['Field', 'Platform API', 'SSH reading'], api.differs.map((d) => [
      d.field, String(d.api ?? '—'), String(d.ssh ?? '—'),
    ])));
  }
  return el('div', { class: 'stack' }, ...kids);
}

/* Proxmox-style container / LXC guest summary & control card */
function infGuest(panel, host, w) {
  const edit = typeof openTask === 'function' && can('plans.edit') && host && w.source !== 'api' && ['docker', 'podman', 'incus'].includes(w.runtime);
  const stage = (label, action, cls = 'btn sm') => button(label, () => openTask('workload-action', host, { runtime: w.runtime, name: w.name, action }), cls);
  const head = el('div', { class: 'row wrap' }, el('b', { class: 'mono' }, w.name), text('span', w.state || '?', INF_VM_STATE[w.state] || ''),
    text('span', `${w.runtime} · ${w.kind}${w.user ? ` (${w.user})` : ''}`, 'muted small'),
    button('Close', () => panel.replaceChildren(), 'btn ghost sm'));
  const kids = [head, infWorkloadApi(w)];
  if (edit) {
    const acts = el('div', { class: 'row wrap', role: 'group', 'aria-label': `Plan a change to ${w.name}` });
    if (w.state !== 'running') acts.append(stage('Start', 'start'));
    else acts.append(stage('Stop', 'stop'), stage('Restart', 'restart'));
    acts.append(button('Remove…', () => openTask('workload-remove', host, { runtime: w.runtime, name: w.name }), 'btn ghost sm danger'));
    if (typeof hlLinkEl === 'function' && can('hostlogs.view')) acts.append(hlLinkEl(host, 'Logs', { q: w.name, small: true }));
    kids.push(acts);
  }
  if ((w.mounts || []).length) {
    kids.push(text('h4', 'Mounts'), infTable(['Source', 'Target', 'Backed by'], w.mounts.map((m) => [
      el('span', { class: 'mono' }, m.source || ''), el('span', { class: 'mono' }, m.dest || ''), m.on ? `${m.on.mount} (${m.on.filesystem})` : ''])));
  }
  if ((w.ports || []).length) {
    kids.push(text('h4', 'Published ports'), infTable(['Host', 'Port', 'Proto'], w.ports.map((p) => [p.host_ip || '0.0.0.0', String(p.host_port || p.port), p.proto || 'tcp'])));
  }
  if ((w.findings || []).length) kids.push(text('p', w.findings.join('; '), 'st-warn small'));
  panel.replaceChildren(el('div', { class: 'card stack pve-drawer', role: 'region', 'aria-label': `Guest ${w.name}` }, ...kids));
  panel.scrollIntoView({ block: 'nearest' });
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
  const vmKpis = el('div', { class: 'pve-kpis' },
    el('div', { class: `pve-kpi ${w.state === 'running' ? 'ok' : w.state === 'crashed' ? 'bad' : ''}` }, text('span', 'State', 'pve-kpi-lbl'), el('b', {}, w.state || '?'), text('small', w.autostart ? 'Autostart on' : 'Manual start')),
    el('div', { class: 'pve-kpi accent' }, text('span', 'Compute', 'pve-kpi-lbl'), el('b', {}, `${w.vcpus || '?'} vCPU`), text('small', w.memory_mib != null ? fmtBytes(w.memory_mib * 2 ** 20) : 'Memory ?')),
    el('div', { class: 'pve-kpi' }, text('span', 'Firmware & Agent', 'pve-kpi-lbl'), el('b', {}, (w.firmware || 'bios').toUpperCase()), text('small', `${w.tpm ? 'TPM · ' : ''}${w.agent === 'connected' ? 'QEMU agent OK' : 'Agent offline'}`)),
    el('div', { class: 'pve-kpi' }, text('span', 'Disks & Snapshots', 'pve-kpi-lbl'), el('b', {}, `${(w.disks || []).length} / ${(w.snapshots || []).length}`), text('small', 'disks / snapshots')));
  const kids = [head, vmKpis, infWorkloadApi(w)];
  if (edit) {
    const acts = el('div', { class: 'row wrap', role: 'group', 'aria-label': `Plan a change to ${w.name}` });
    const lv = { runtime: 'libvirt', name: w.name };
    if (w.state !== 'running') acts.append(stage('Start', 'workload-action', { ...lv, action: 'start' }));
    else acts.append(stage('Shut down', 'workload-action', { ...lv, action: 'stop' }), stage('Restart', 'workload-action', { ...lv, action: 'restart' }),
      stage('Force off', 'workload-action', { ...lv, action: 'force-off' }, 'btn sm danger'));
    acts.append(stage('Snapshot…', 'vm-snapshot', { name: w.name, disk_only: true }), stage('Change…', 'vm-edit', { name: w.name }),
      button('Copy to another host…', () => infVmCopy(host, w), 'btn sm'));
    if (can('console.open')) acts.append(el('a', { class: 'btn sm', href: `/console#${encodeURIComponent(w.name)}`, target: '_blank', rel: 'noopener' }, 'Console'));
    if (typeof hlLinkEl === 'function' && can('hostlogs.view')) acts.append(hlLinkEl(host, 'Logs', { q: w.name, small: true }));
    acts.append(stage('Remove…', 'workload-remove', lv, 'btn ghost sm danger'));
    kids.push(acts, text('p', 'Each button opens the step of a change plan: it is checked against this reading, reports first, and runs when the plan is deployed.', 'muted small'));
  }
  const secHw = el('div', { class: 'stack' }, text('h4', 'Disks'), infTable(['Disk', 'Kind', 'Bus', 'Format', 'File or device', 'Stored on'], (w.disks || []).map((d) => {
    const m = (w.mounts || []).find((x) => x.dest === d.target);
    return [el('span', { class: 'mono' }, d.target || '?'), d.device + (d.readonly ? ', read-only' : ''), d.bus || '', d.format + (d.backing ? ', on a base image' : ''),
      el('span', { class: 'mono' }, d.source || ''), m && m.on ? `${m.on.mount} (${m.on.filesystem})` : ''];
  })));
  const snaps = w.snapshots || [];
  const secSnap = el('div', { class: 'stack' }, text('h4', `Snapshots (${snaps.length})`),
    !snaps.length ? text('p', 'None.', 'muted small') : infTable(['Snapshot', 'Taken', 'Kind', 'Of a VM that was', ''], snaps.slice().reverse().map((x) => [
      el('span', { class: 'mono' }, x.name + (x.current ? ' (current)' : '')), x.created ? fmtTime(x.created) : '',
      x.location === 'external' ? 'disk-only' : 'internal, with memory', x.state === 'disk-snapshot' ? 'its disks only' : x.state || '',
      edit ? el('div', { class: 'row' }, stage('Revert…', 'vm-revert', { name: w.name, snapshot: x.name }, 'btn ghost sm'),
        stage('Delete…', 'vm-snapshot', { name: w.name, snapshot: x.name, action: 'delete', disk_only: x.location === 'external' }, 'btn ghost sm')) : ''])));
  const vmBar = el('div', { class: 'pve-toolbar' });
  const vmTabs = [['all', 'Summary (Hardware + Snapshots)'], ['hw', 'Hardware & Disks'], ['snaps', 'Snapshots']];
  const syncVm = () => {
    secHw.hidden = INF.vmTab === 'snaps';
    secSnap.hidden = INF.vmTab === 'hw';
    vmBar.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.vmtab === INF.vmTab)));
  };
  for (const [id, label] of vmTabs) {
    const b = button(label, () => { INF.vmTab = id; syncVm(); }, 'btn ghost sm');
    b.dataset.vmtab = id;
    vmBar.append(b);
  }
  syncVm();
  kids.push(vmBar, secHw, secSnap);
  panel.replaceChildren(el('div', { class: 'card stack pve-drawer', role: 'region', 'aria-label': `VM ${w.name}` }, ...kids));
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
    if ((h.tunnels || []).length) {          // public with no port open: no firewall reading shows these
      kids.push(text('p', 'Tunnels on this host. A tunnel dials out, so what it publishes is public with no port open here or on the router, and the firewall does not stop it.', 'muted small'));
      kids.push(infTable(['Who can reach it', 'Public at', 'Sent to', 'Through', 'Because'], h.tunnels.map((t) => [
        text('span', INF_LEVEL[t.level] || t.level, INF_CLASS[t.level] || ''), t.public || 'not known', t.local || '', t.label, [t.rule, ...(t.why || [])].filter(Boolean).join('; ')])));
    }
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
  const ifaces = network.interfaces || [];
  const nonLo = ifaces.filter((i) => i.kind !== 'loopback');
  const upCount = nonLo.filter((i) => String(i.state).toLowerCase() === 'up').length;
  const bridgesBonds = nonLo.filter((i) => ['bridge', 'bond', 'vlan', 'wireguard'].includes(i.kind)).length;
  const defRoute = (network.routes || []).find((r) => r.dst === 'default');
  const cfg = network.config;
  const mgrName = cfg ? ({ netplan: 'netplan', nm: 'NetworkManager', networkd: 'systemd-networkd', ifupdown: 'ifupdown', none: 'unmanaged' }[cfg.manager] || cfg.manager) : 'not read';
  const kpis = el('div', { class: 'pve-kpis' },
    el('div', { class: `pve-kpi ${upCount ? 'ok' : ''}` }, text('span', 'Links Up', 'pve-kpi-lbl'), el('b', {}, `${upCount} / ${nonLo.length}`), text('small', `${bridgesBonds} virtual / overlay`)),
    el('div', { class: 'pve-kpi accent' }, text('span', 'Default Gateway', 'pve-kpi-lbl'), el('b', {}, defRoute?.via || 'none'), text('small', defRoute?.dev ? `via ${defRoute.dev}` : 'no default route')),
    el('div', { class: 'pve-kpi' }, text('span', 'DNS & Config', 'pve-kpi-lbl'), el('b', {}, String((network.dns?.nameservers || []).length)), text('small', `${mgrName} · ${(network.neighbours || []).length} neighbours`)));
  const portCards = nonLo.length ? el('div', { class: 'pve-ports' }, ...nonLo.map((i) => {
    const up = String(i.state).toLowerCase() === 'up';
    const addrs = (i.addresses || []).filter((a) => a.scope !== 'link').map((a) => `${a.ip}/${a.prefix}`);
    return el('div', { class: `pve-port ${up ? 'up' : 'down'}` },
      el('div', { class: 'pve-port-hd' }, el('b', { class: 'mono small' }, i.name), text('span', i.state || '?', up ? 'st-ok small' : 'st-failed small')),
      text('span', `${i.kind || ''}${i.vlan_id ? ` vlan ${i.vlan_id}` : ''}${i.master ? ` · → ${i.master}` : ''}${i.mtu ? ` · mtu ${i.mtu}` : ''}`, 'pve-port-meta'),
      addrs.length ? text('span', addrs.join(', '), 'mono small') : text('span', 'no address', 'muted small'));
  })) : null;
  const kids = [el('div', { class: 'row wrap', style: 'justify-content:space-between' }, text('p', `Read ${infWhen(network.read_at)}.`, 'muted small'),
    can('devices.view') ? el('a', { class: 'btn ghost sm', href: '/manage#/compose' }, 'Open Network Manager →') : null), kpis];
  if (network.unreadable.length) kids.push(text('p', `Could not read: ${network.unreadable.join(', ')}. That does not mean there are none.`, 'st-warn'));
  if (portCards) kids.push(text('h4', 'Ports & Bridges'), portCards);
  kids.push(text('h4', 'Interfaces'), infTable(['Name', 'Kind', 'State', 'Addresses', 'MTU', 'Part of'], ifaces.map((i) => [
    el('span', { class: 'mono' }, i.name), i.kind + (i.vlan_id ? ` ${i.vlan_id}` : ''), i.state, i.addresses.map((a) => `${a.ip}/${a.prefix}`).join(', '), i.mtu, i.master || ''])));
  kids.push(text('h4', 'Routes'), infTable(['To', 'Via', 'Device'], network.routes.map((r) => [r.dst, r.via || '', r.dev || ''])));
  if (cfg) {
    const said = { netplan: 'netplan', nm: 'NetworkManager', networkd: 'systemd-networkd', ifupdown: 'ifupdown', none: 'nothing that keeps it' }[cfg.manager] || cfg.manager;
    const live = new Set(ifaces.map((i) => i.name));
    kids.push(text('h4', 'Set up in files'), text('p', `The network is kept by ${said}. What its files say, beside what the kernel has above.`, 'muted small'));
    if (cfg.unreadable.length) kids.push(text('p', `The scan user could not read: ${cfg.unreadable.join(', ')}. What they say is not shown.`, 'st-warn'));
    kids.push(infTable(['Name', 'Set up in', 'DHCP', 'Addresses', 'Routes', 'Now'], Object.entries(cfg.interfaces).filter(([n]) => n !== 'lo').map(([n, c]) => [
      el('span', { class: 'mono' }, n), c.source || '', ['4', '6'].filter((f) => c[`dhcp${f}`]).map((f) => `IPv${f}`).join(', '), (c.addresses || []).join(', '),
      (c.routes || []).map((r) => `${r.to || 'default'} via ${r.via || ''}`).join(', '), live.has(n) ? 'present' : 'not present'])));
  }
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
  const polText = Object.entries(firewall.policies).map(([k, v]) => `${k} ${v}`).join(', ') || 'none read';
  const tblBox = el('div', { class: 'stack' });
  const qIn = el('input', { type: 'search', value: INF.fwFind, placeholder: 'Filter rules by chain, action, port, IP…', 'aria-label': 'Filter firewall rules', autocomplete: 'off',
    oninput: () => { INF.fwFind = qIn.value; drawRules(); } });
  const bar = el('div', { class: 'pve-toolbar' }, qIn,
    can('devices.view') ? el('a', { class: 'btn ghost sm', href: '/manage#/compose' }, 'Edit in Network Manager →') : null);
  const kpis = el('div', { class: 'pve-kpis' },
    el('div', { class: `pve-kpi ${firewall.readable ? 'ok' : 'warn'}` }, text('span', 'Backends', 'pve-kpi-lbl'), el('b', {}, firewall.backends.join(', ') || 'none'), text('small', firewall.readable ? 'Readable' : 'Restricted read')),
    el('div', { class: 'pve-kpi' }, text('span', 'Default Policies', 'pve-kpi-lbl'), el('b', {}, String(Object.keys(firewall.policies).length)), text('small', polText)),
    el('div', { class: 'pve-kpi accent' }, text('span', 'Rules Modelled', 'pve-kpi-lbl'), el('b', {}, String((firewall.rules || []).length)), text('small', `${(firewall.rules || []).filter((r) => (r.unmodelled || []).length).length} partial`)));
  function drawRules() {
    const q = INF.fwFind.trim().toLowerCase();
    const filtered = (firewall.rules || []).filter((r) => {
      if (!q) return true;
      return `${r.table} ${r.chain} ${r.action} ${r.proto} ${(r.dports || []).join(',')} ${r.saddr || ''} ${r.comment || ''}`.toLowerCase().includes(q);
    });
    tblBox.replaceChildren(infTable(['Where', 'Action', 'Protocol', 'Ports', 'From', 'Note'], filtered.map((r) => [
      `${r.table} ${r.chain}`, r.action || '', r.proto || '', (r.dports || []).map((p) => Array.isArray(p) ? p.join('-') : p).join(', '), r.saddr || '',
      [r.comment, ...(r.unmodelled || []).map((u) => `not understood: ${u}`)].filter(Boolean).join('; ')])));
  }
  drawRules();
  kids.push(text('p', `Backends: ${firewall.backends.join(', ') || 'none'}. Default policies: ${polText}.`, 'small'), kpis, bar, tblBox);
  content.replaceChildren(...kids);
}
