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
  const { workloads, hosts } = await getJSON('/api/workloads' + qs);
  const out = document.createElement('div');
  const kids = [out];
  for (const h of hosts) {
    const mine = workloads.filter((w) => w.host === h.host);
    const head = document.createElement('div'); head.className = 'row';
    head.append(el('b', { class: 'mono' }, h.host), text('span', `containers read ${infWhen(h.containers_read_at)} · VMs and instances read ${infWhen(h.measured_at)}${h.measure_stale ? ' (old)' : ''}`, 'muted small'), infMeasure(h.host, out));
    kids.push(head);
    if (!h.measured_at) kids.push(text('p', 'VMs, instances and other users\' containers take a signed reading, and this host has none yet, so this list may not be complete.', 'muted small'));
    if (!mine.length) { kids.push(text('p', h.measured_at ? 'Nothing found.' : 'No containers found by the scan.', 'muted small')); continue; }
    kids.push(infTable(['Name', 'Kind', 'State', 'Ports', 'Stored on', 'Worth a look'], mine.map((w) => [
      el('span', { class: 'mono' }, w.name || '?'),
      `${w.runtime} ${w.kind}${w.user ? ` (${w.user})` : ''}${w.panel ? ' · panel' : ''}`,
      w.state || '?',
      (w.ports || []).map((p) => `${p.host_ip}:${p.host_port}→${p.port}/${p.proto}`).join(', '),
      [...new Set((w.mounts || []).map((m) => m.on ? `${m.on.mount} (${m.on.filesystem})` : null).filter(Boolean))].join(', '),
      w.detail ? (w.findings || []).join('; ') : 'Not read in full'])));
  }
  content.replaceChildren(...kids);
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
