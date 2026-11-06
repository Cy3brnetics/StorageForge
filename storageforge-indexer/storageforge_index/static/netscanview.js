'use strict';
/* Scan tab, beside the map: what the opt-in nmap scanner found. Off until someone turns it on and names a network. A machine StorageForge manages links back to its own pages, and what it
   doesn't manage is what's new on the network. Everything else in StorageForge reads what enrolled machines report: this is the only thing that sends packets. DOM APIs only. */

const NS = { scan: null, timer: 0 };

async function loadNetScan() {
  const fresh = latest('netscan');                  // UX-12: the scan picked last is the one shown, whichever answer comes back first
  const box = $('#netscanview');
  box.replaceChildren(text('p', 'Loading…', 'muted small'));
  try {
    const data = await getJSON('/api/netscan' + (NS.scan ? `?scan=${NS.scan}` : ''));
    if (!fresh()) return;
    renderNetScan(box, data);
  } catch (err) { if (fresh()) box.replaceChildren(text('p', err.message, 'st-failed')); }
}

function renderNetScan(box, data) {
  const cfg = data.settings, res = data.results;
  const out = document.createElement('div'); out.className = 'nscan';
  const head = document.createElement('div'); head.className = 'nscan-head';
  head.append(text('h2', 'Network scan'), text('span', cfg.enabled ? 'On' : 'Off', cfg.enabled ? 'nscan-chip on' : 'nscan-chip'));
  const msg = text('p', '', 'small muted');
  const manage = can('netscan.run');
  if (manage) {
    const ranges = document.createElement('input'); ranges.value = (cfg.ranges || []).join(' '); ranges.placeholder = '192.168.1.0/24'; ranges.setAttribute('aria-label', 'Networks to scan');
    const every = document.createElement('input'); every.type = 'number'; every.min = 0; every.max = 720; every.value = cfg.every_hours || 0; every.setAttribute('aria-label', 'Hours between scans');
    const fail = (err) => { msg.textContent = err.message; msg.className = 'small st-failed'; };
    const save = async (enabled) => { try { await postJSON('/api/netscan/settings', { enabled, ranges: ranges.value.split(/[\s,]+/).filter(Boolean), every_hours: Number(every.value) }); loadNetScan(); } catch (err) { fail(err); } };
    head.append(button(cfg.enabled ? 'Turn off' : 'Turn on', () => save(!cfg.enabled), cfg.enabled ? 'btn' : 'btn pri'));
    const ctl = document.createElement('div'); ctl.className = 'nscan-ctl';
    const lab = (t, i) => { const l = document.createElement('label'); l.append(text('span', t, 'muted small'), i); return l; };
    ctl.append(lab('Networks', ranges), lab('Every (hours, 0 is never)', every), button('Save', () => save(cfg.enabled), 'btn'));
    if (cfg.enabled) ctl.append(button('Scan now', async () => { try { const r = await (await postJSON('/api/netscan/run', {})).json(); NS.scan = r.scan_id; msg.textContent = `Scanning ${r.targets.join(', ')}…`; clearTimeout(NS.timer); NS.timer = setTimeout(pollNetScan, 3000); } catch (err) { fail(err); } }, 'btn pri'));
    out.append(head, ctl);
  } else out.append(head);
  out.append(text('p', 'A connect scan with nmap, only of the private networks named here. Nothing else in StorageForge sends a packet to find out what exists, and with this off nothing does.', 'small muted'));
  if (!cfg.nmap) out.append(text('p', 'nmap is not installed where StorageForge runs.', 'st-warn small'));
  out.append(msg);
  const scan = res.scan;
  if (data.scans?.length) {
    const pick = document.createElement('select'); pick.setAttribute('aria-label', 'Which scan');
    for (const s of data.scans) { const o = document.createElement('option'); o.value = s.id; o.textContent = `${fmtTime(s.started_at)} · ${s.target} · ${s.status}${s.hosts != null ? ` · ${s.hosts} found` : ''}`; o.selected = scan && s.id === scan.id; pick.append(o); }
    pick.addEventListener('change', () => { NS.scan = Number(pick.value); loadNetScan(); });
    out.append(pick);
  }
  if (scan?.status === 'failed') out.append(text('p', `This scan failed: ${scan.error}`, 'st-failed small'));
  if (!scan) { out.append(text('p', 'No scans yet.', 'muted')); box.replaceChildren(out); return; }
  // grouped by what was scanned (UX-29), in the order the ranges were named, with anything outside them last. The server says which range each
  // address is in; a /24 was assumed here before, which is wrong for a /16, a /23 or a /25. A range that found nothing says so.
  const groups = new Map((res.ranges || []).map((r) => [r, []]));
  for (const h of res.hosts) {
    const key = h.range || 'other';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(h);
  }
  for (const [net, hosts] of groups) {
    const sec = document.createElement('section'); sec.className = 'nscan-net';
    sec.append(text('h3', `${net === 'other' ? 'Outside the scanned ranges' : net} · ${hosts.length}`));
    if (!hosts.length) sec.append(text('p', 'Nothing answered.', 'muted small'));
    const grid = document.createElement('div'); grid.className = 'nscan-grid';
    for (const h of hosts) grid.append(netScanCard(h));
    sec.append(grid); out.append(sec);
  }
  if (res.gone?.length) out.append(text('p', `Gone since the scan before: ${res.gone.join(', ')}`, 'st-warn small'));
  box.replaceChildren(out);
}

function netScanCard(h) {
  const c = document.createElement('article'); c.className = 'nscan-card ' + (h.link.managed ? 'managed' : 'unknown');
  const title = document.createElement('div'); title.className = 'nscan-title';
  title.append(text('b', h.link.name || h.name || h.ip));
  if (h.link.kind === 'device') title.append(text('span', 'device', 'nscan-chip on'));
  else if (h.link.kind === 'host') title.append(text('span', 'host', 'nscan-chip on'));
  else title.append(text('span', 'not managed', 'nscan-chip warn'));
  if (h.new) title.append(text('span', 'new', 'nscan-chip warn'));
  c.append(title, text('div', [h.ip, h.mac, h.vendor].filter(Boolean).join(' · '), 'muted small'));
  const ports = document.createElement('div'); ports.className = 'nscan-ports';
  for (const p of h.ports) {
    const known = (h.new_ports || []).includes(p.port);
    ports.append(text('span', `${p.port}${p.service ? ` ${p.service}` : ''}`, 'nscan-port' + (known ? ' new' : '')));
  }
  c.append(ports);
  const links = document.createElement('div'); links.className = 'nscan-links';
  for (const l of h.link.links || []) {
    const a = document.createElement('a'); a.className = 'btn'; a.href = l.url; a.textContent = l.label;
    links.append(a);
  }
  c.append(links);
  return c;
}

async function pollNetScan() {
  try {
    const data = await getJSON('/api/netscan');
    const running = (data.scans || []).some((s) => s.status === 'running');
    if ($('#netscanview').hidden) return;
    if (running) { NS.timer = setTimeout(pollNetScan, 4000); return; }
    NS.scan = null; loadNetScan();
  } catch { /* the next look */ }
}
