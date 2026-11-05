'use strict';
/* Side-panel checks: Access (folders scans could not read, and read-only scan access set up after the fact) and
   Copies (duplicate folders by name and structure). Loaded after app.js and topology.js; uses their helpers. */

/* ── access ──────────────────────────────────────────────────────── */
const ACCESS = { hosts: [], open: null, script: {} };

async function loadAccess() {
  const box = $('#accessbox');
  try { ACCESS.hosts = (await getJSON('/api/access')).hosts; }
  catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); return; }
  renderAccess();
  if (T.mode === 'topo') renderTopoSoon();      // the unreadable-folder badges on host headers
}
function accessState(h) {
  if (h.access === 'capability') return ['st-ok', 'Read-only scan access is set up'];
  if (!h.scan_id) return ['muted', 'Not scanned yet'];
  if (h.denied_total || h.read_errors) return ['st-failed', `${h.denied_total || h.read_errors} folder${(h.denied_total || h.read_errors) === 1 ? '' : 's'} unreadable as ${h.scan_user || 'the scan user'}`];
  return ['st-ok', `Everything was readable as ${h.scan_user || 'the scan user'}`];
}
function renderAccess() {
  const box = $('#accessbox');
  if (!ACCESS.hosts.length) { box.replaceChildren(text('p', 'No scanned hosts yet.', 'muted')); return; }
  box.replaceChildren(...ACCESS.hosts.map((h) => {
    const [cls, msg] = accessState(h);
    const card = el('section', { class: 'card' }, el('div', { class: 'row' }, el('b', { class: 'mono' }, h.host), text('span', msg, cls)));
    if (!h.denied_total && h.read_errors && h.access !== 'capability') {
      card.append(text('p', 'This scan predates per-folder reporting; rescan to list the folders.', 'muted'));
    }
    if (h.denied.length) {
      const list = el('ol', { class: 'denied' }, ...h.denied.slice(0, 12).map((d) => el('li', { class: 'mono' }, d.path)));
      card.append(list);
      if (h.denied.length > 12) card.append(button(`Show all ${h.denied_total}`, () => {
        list.replaceChildren(...h.denied.map((d) => el('li', { class: 'mono' }, d.path)));
        if (h.denied_total > h.denied.length) list.append(el('li', { class: 'muted' }, `…and ${h.denied_total - h.denied.length} more`));
      }, 'btn ghost sm'));
    }
    const acts = el('div', { class: 'row' });
    if (h.access !== 'capability' && h.scan_id) acts.append(button('Set up read-only access…', () => { ACCESS.open = ACCESS.open === h.host ? null : h.host; renderAccess(); }, 'btn pri sm'));
    acts.append(button('Scan now', () => queueScan(h.host), 'btn ghost sm'));
    if (h.access === 'capability') acts.append(button('Remove access…', () => { ACCESS.open = ACCESS.open === h.host ? null : h.host; renderAccess(); }, 'btn ghost sm'));
    card.append(acts);
    if (ACCESS.open === h.host) card.append(grantForm(h, h.access === 'capability'));
    return card;
  }));
}
function grantForm(h, remove) {
  const msg = el('p', { class: 'muted', hidden: true });
  const warn = el('p', { class: 'st-warn', hidden: true });
  const viaScan = el('input', { type: 'radio', name: 'via', value: 'scan', checked: true });
  const viaAdmin = el('input', { type: 'radio', name: 'via', value: 'admin' });
  const admin = el('input', { type: 'text', placeholder: 'admin account, e.g. root or your login', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', disabled: true });
  const pw = el('input', { type: 'password', autocomplete: 'off', 'data-1p-ignore': true, 'data-lpignore': 'true', 'data-bwignore': 'true', required: true });
  const sync = () => { admin.disabled = !viaAdmin.checked; pw.previousSibling.textContent = viaAdmin.checked ? "That account's password (SSH login and sudo; used once, not stored)" : `${h.scan_user || 'Scan user'}'s sudo password (used once, not stored)`; };
  viaScan.addEventListener('change', sync); viaAdmin.addEventListener('change', sync);
  const pre = el('pre', { class: 'script', hidden: true });
  const form = el('form', { class: 'stack grant' },
    text('p', remove
      ? 'Removes the private find and sha256sum copies and the storageforge-scan group. Scans go back to the scan user\'s own permissions.'
      : `Gives ${h.scan_user || 'the scan user'} private copies of find and sha256sum that can list and checksum every file. They cannot write, change owners or run anything as root, and nobody else can use them.`, 'muted'),
    el('label', { class: 'check' }, viaScan, `Use ${h.scan_user || 'the scan user'}'s own sudo (connects with its vault key)`),
    el('label', { class: 'check' }, viaAdmin, 'Use an admin account with a password'),
    admin,
    el('label', { class: 'field col' }, el('span', {}, ''), pw),
    el('div', { class: 'row end' },
      button('Show the script', async () => {
        try {
          const key = h.host + (remove ? ':remove' : '');
          ACCESS.script[key] = ACCESS.script[key] || (await getJSON(`/api/access/script?host=${encodeURIComponent(h.host)}${remove ? '&remove=1' : ''}`)).script;
          pre.textContent = ACCESS.script[key]; pre.hidden = !pre.hidden;
        } catch (err) { msg.hidden = false; msg.textContent = err.message; msg.className = 'st-failed'; }
      }, 'btn ghost sm'),
      el('button', { type: 'submit', class: 'btn pri sm' }, remove ? 'Remove' : 'Run it now')),
    pre, msg, warn);
  sync();
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const body = { host: h.host, password: pw.value, admin_user: viaAdmin.checked ? admin.value.trim() : null, remove };
    pw.value = '';
    const btn = ev.submitter; btn.disabled = true;
    warn.hidden = true;
    msg.hidden = false; msg.className = 'muted'; msg.textContent = `Running on ${h.host} with sudo…`;
    try {
      const r = await (await postJSON('/api/access/grant', body)).json();
      msg.className = 'st-ok';
      msg.textContent = remove ? 'Removed.' : `Done via ${r.via}. Rescan ${h.host} to read the folders that were missing.`;
      warn.textContent = r.warning || ''; warn.hidden = !r.warning;
      if (!remove) form.append(el('div', { class: 'row end' }, button(`Scan ${h.host} now`, () => queueScan(h.host), 'btn pri sm')));
    } catch (err) { msg.className = 'st-failed'; msg.textContent = err.message; }
    finally { btn.disabled = false; }
  });
  return form;
}

/* ── copies ──────────────────────────────────────────────────────── */
function sparkline(points, total) {
  if (points.length < 2) return text('span', 'one scan so far', 'muted small');
  const t0 = points[0][0], span = (points[points.length - 1][0] - t0) || 1;
  const line = points.map(([t, u]) => `${(((t - t0) / span) * 118 + 1).toFixed(1)},${(29 - (u / total) * 28).toFixed(1)}`).join(' ');
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 120 30'); svg.setAttribute('width', '120'); svg.setAttribute('height', '30'); svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `Used space, ${Math.round((points[points.length - 1][1] / total) * 100)} percent now`);
  const p = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
  p.setAttribute('points', line); p.setAttribute('fill', 'none'); p.setAttribute('stroke', 'currentColor'); p.setAttribute('stroke-width', '1.5');
  svg.append(p);
  return svg;
}
async function loadTrends() {
  const box = $('#trendbox');
  try {
    const { mounts } = await getJSON(`/api/capacity${S.host ? `?host=${encodeURIComponent(S.host)}` : ''}`);
    if (!mounts.length) { box.replaceChildren(text('p', 'History starts with the next scan of each host.', 'muted')); return; }
    const order = [...mounts].sort((a, b) => (a.days_left ?? Infinity) - (b.days_left ?? Infinity));
    box.replaceChildren(el('ol', { class: 'copies' }, ...order.map((m) => el('li', { class: 'row' }, sparkline(m.points, m.total),
      el('span', { class: 'mono small' }, `${m.host}:${m.mount}`),
      text('span', `${fmtBytes(m.used)} of ${fmtBytes(m.total)}`, 'muted small'),
      m.days_left !== null ? text('span', `full in about ${m.days_left} days`, m.days_left <= 30 ? 'st-failed small' : 'st-running small') : ''))));
  } catch (err) { box.replaceChildren(text('p', err.message, 'muted')); }
}
async function loadChanged() {
  const box = $('#changedbox');
  if (!S.host) { box.replaceChildren(text('p', 'Pick a host at the top to see what its last scan found changed.', 'muted')); return; }
  try {
    const r = await getJSON(`/api/file-changes?host=${encodeURIComponent(S.host)}`);
    if (!r.scan) { box.replaceChildren(text('p', 'No finished scans of this host yet.', 'muted')); return; }
    box.replaceChildren(
      text('p', `Scan #${r.scan.scan_id}, ${fmtTime(r.scan.started_at)}: +${r.scan.added.toLocaleString()} ~${r.scan.modified.toLocaleString()} -${r.scan.deleted.toLocaleString()}${r.truncated ? ' (folders below cover the first 20,000)' : ''}`, 'small'),
      el('ol', { class: 'copies' }, ...r.folders.map((f) => el('li', { class: 'row' }, el('span', { class: 'mono small' }, f.folder),
        text('span', `+${f.added.toLocaleString()} ~${f.modified.toLocaleString()} -${f.deleted.toLocaleString()} · ${f.delta < 0 ? '-' : '+'}${fmtBytes(Math.abs(f.delta))}`, 'muted small')))));
  } catch (err) { box.replaceChildren(text('p', err.message, 'muted')); }
}
/* ── malware ─────────────────────────────────────────────────────── */
async function malwarePost(path, body, box) {
  try {
    const res = await postJSON(path, body);
    const r = await res.json().catch(() => ({}));
    if (res.ok) return r;
    box.append(text('p', r.error || 'That was refused', 'st-failed'));
    if (r.output) box.append(el('pre', { class: 'small' }, r.output));
  } catch (err) { box.append(text('p', err.message, 'st-failed')); }
  return null;
}
function malwareHost(h) {
  const run = h.last_run, box = el('div', { class: 'stack' });
  const when = (t) => fmtTime(t);
  box.append(text('strong', h.host));
  box.append(text('p', !h.installed ? 'ClamAV scan not deployed.' : !run ? 'Deployed. No result yet.'
    : `Last scan ${when(run.finished_at)}: ${run.scanned.toLocaleString()} files, ${run.found} found. ${run.version || ''}${[0, 1].includes(run.exit_code) ? '' : ` Exit code ${run.exit_code}: it may be incomplete.`}`,
  run && ![0, 1].includes(run.exit_code) ? 'st-failed small' : 'muted small'));
  if (can('deploy.apply')) {
    const schedule = el('select', { 'aria-label': 'Schedule' }, ...['daily', 'weekly', 'monthly'].map((s) => new Option(s, s)));
    schedule.value = h.config.schedule;
    const paths = el('input', { type: 'text', 'aria-label': 'Folders to scan, separated by spaces', value: h.config.paths.join(' '), title: 'Folders to scan, separated by spaces. Each stays on its own filesystem.' });
    const save = async () => malwarePost(`/api/clamav/hosts/${encodeURIComponent(h.host)}/config`, { schedule: schedule.value, paths: paths.value.split(/\s+/).filter(Boolean) }, box);
    const go = (mode, title, extra) => async () => { if (await save()) startDeploy('clamav', h.host, mode, title, extra); };
    box.append(el('div', { class: 'row' }, schedule, paths));
    const buttons = [button('Dry run', go('report', `ClamAV dry run on ${h.host}`, {}), 'btn sm ghost'), button(h.installed ? 'Update' : 'Deploy', go('apply', `Deploy ClamAV to ${h.host}`, {}), 'btn sm')];
    if (h.installed) buttons.push(button('Scan now', go('apply', `ClamAV scan on ${h.host}`, { run: true }), 'btn sm ghost'), button('Remove', async () => { if (await confirmDialog({ title: `Remove the ClamAV scan from ${h.host}?`, body: 'Quarantined files stay.', confirm: 'Remove', danger: true })) startDeploy('clamav', h.host, 'apply', `Remove ClamAV scan from ${h.host}`, { remove: true }); }, 'btn sm ghost'));
    if (h.installed && can('deploy.report')) buttons.push(button('Collect', async () => { if (await malwarePost(`/api/clamav/hosts/${encodeURIComponent(h.host)}/collect`, {}, box)) loadMalware(); }, 'btn sm ghost'));
    box.append(el('div', { class: 'row' }, ...buttons));
    if (!h.deploy_ready) box.append(text('p', 'Set up deploy access for this host first.', 'muted small'));
  }
  return box;
}
function malwareDetection(d, box) {
  const act = (verb, body) => async () => { if (await malwarePost(`/api/clamav/detections/${d.id}/${verb}`, body, box)) loadMalware(); };
  const acts = [];
  if (d.state === 'open' && can('security.manage')) {
    acts.push(button('Look at it', async () => { const r = await malwarePost('/api/security/malware/preview', { id: d.id }, box); if (r?.output) box.append(el('pre', { class: 'small sec-out' }, r.output)); }, 'btn sm ghost'));
  }
  if (can('deploy.destructive')) {
    if (d.state === 'open') {
      acts.push(button('Quarantine', async () => {
        const sys = d.system_path;
        if (!(await confirmDialog({ title: `Move ${d.path} on ${d.host} to quarantine?`, body: `${sys ? 'This is a system path: moving it can stop the host from booting.\n\n' : ''}A running process that has it open keeps running.`, confirm: 'Move to quarantine', danger: true }))) return;
        act('quarantine', { allow_system: sys })();
      }, 'btn sm'));
      acts.push(button(d.ignored ? 'Stop ignoring' : 'Not malware: ignore', act('ignore', { ignore: !d.ignored, reason: 'marked in the Malware panel' }), 'btn sm ghost'));
    } else if (d.state === 'quarantined') {
      acts.push(button('Restore', async () => { if (await confirmDialog({ title: `Move ${d.path} back to where it was on ${d.host}?`, body: 'It will be ignored from then on.', confirm: 'Restore' })) act('restore', {})(); }, 'btn sm ghost'));
    }
  }
  const cls = d.ignored ? 'muted' : d.state === 'open' ? 'st-failed' : 'muted';
  return el('div', { class: 'stack' }, text('strong', `${d.signature}${d.state === 'quarantined' ? ' (in quarantine)' : ''}${d.ignored ? ' (ignored)' : ''}`, cls),
    text('span', `${d.host}:${d.path}`, 'mono small'), el('div', { class: 'row' }, ...acts));
}
async function loadMalware() {
  const hostsBox = $('#malwarehosts'), box = $('#malwarebox');
  try {
    const { hosts, detections } = await getJSON(`/api/clamav${S.host ? `?host=${encodeURIComponent(S.host)}` : ''}`);
    hostsBox.replaceChildren(...hosts.map(malwareHost));
    box.replaceChildren(...(detections.length ? detections.map((d) => malwareDetection(d, box)) : [text('p', 'No detections reported.', 'muted')]));
  } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); }
}
async function loadDupes() {
  try {
    const { groups } = await getJSON(`/api/dupes${S.host ? `?host=${encodeURIComponent(S.host)}` : ''}`);
    $('#dupesection').hidden = !groups.length;
    $('#dupesbox').replaceChildren(...groups.map((g) => el('details', {}, el('summary', {}, `${g.copies} copies of ${fmtBytes(g.size)}, ${fmtBytes(g.reclaimable)} to reclaim`),
      el('ul', { class: 'copies small mono' }, ...g.files.map((f) => el('li', {}, f))))));
  } catch { $('#dupesection').hidden = true; }
}
async function loadCopies() {
  loadTrends(); loadChanged(); loadDupes();
  const box = $('#copiesbox');
  box.replaceChildren(text('p', 'Comparing folders…', 'muted'));
  const qs = new URLSearchParams({ min_files: $('#copyfiles').value, min_size: $('#copysize').value });
  if (S.host) qs.set('host', S.host);
  try {
    const r = await getJSON(`/api/folders/duplicates?${qs}`);
    const head = text('p', `${r.total_groups} folder${r.total_groups === 1 ? '' : 's'} with copies among ${r.folders_checked.toLocaleString()} checked` +
      (r.reclaimable_same_host ? ` · ${fmtBytes(r.reclaimable_same_host)} could be freed within hosts` : ''), 'muted');
    if (!r.groups.length) { box.replaceChildren(head); return; }
    box.replaceChildren(head, ...r.groups.map((g) => el('section', { class: 'card' },
      el('div', { class: 'row' }, el('b', {}, `${g.count}× · ${g.files.toLocaleString()} files · ${fmtBytes(g.bytes)}`),
        text('span', g.scope === 'same host' ? `same host · ${fmtBytes(g.reclaimable)} reclaimable` : 'across hosts (a backup?)',
             g.scope === 'same host' ? 'pill local-only' : 'pill unknown'),
        g.same_name ? null : text('span', 'renamed', 'pill unknown')),
      el('ol', { class: 'copies' }, ...g.copies.map((c) => el('li', {},
        button('', () => runSearch({ under: c.path, host: c.host }), 'copy')))),
    )));
    box.querySelectorAll('.copy').forEach((b, i) => {
      const c = r.groups.flatMap((g) => g.copies)[i];
      b.append(text('span', c.host, 'm'), text('span', c.path, 'p'));
      b.title = 'List the files in this folder';
    });
  } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); }
}
$('#copyform').addEventListener('submit', (ev) => { ev.preventDefault(); loadCopies(); });

/* ── cold data ───────────────────────────────────────────────────── */
async function loadCold() {
  const box = $('#coldbox');
  box.replaceChildren(text('p', 'Reading folder ages from the index…', 'muted'));
  const qs = new URLSearchParams({ years: $('#coldyears').value, min_size: $('#coldsize').value });
  if (S.host) qs.set('host', S.host);
  try {
    const r = await getJSON(`/api/folders/cold?${qs}`);
    box.replaceChildren(text('p', `${r.total} folder${r.total === 1 ? '' : 's'}, ${fmtBytes(r.bytes)} untouched since ${fmtDate(r.cutoff)}`, 'muted'),
      el('ol', { class: 'copies' }, ...r.folders.map((f) => el('li', { class: 'coldrow' },
        el('span', { class: 'p' }, f.path),
        el('span', { class: 'm' }, `${f.host} · ${fmtBytes(f.bytes)} · ${f.files.toLocaleString()} files · newest ${fmtDate(f.newest)}`),
        button('Move…', () => moveFrom(f.host, f.path), 'btn ghost sm')))));
  } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); }
}
$('#coldform').addEventListener('submit', (ev) => { ev.preventDefault(); loadCold(); });
