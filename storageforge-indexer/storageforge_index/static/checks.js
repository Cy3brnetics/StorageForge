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
  if (T.mode === 'topo') renderTopo();          // the unreadable-folder badges on host headers
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
    pre, msg);
  sync();
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const body = { host: h.host, password: pw.value, admin_user: viaAdmin.checked ? admin.value.trim() : null, remove };
    pw.value = '';
    const btn = ev.submitter; btn.disabled = true;
    msg.hidden = false; msg.className = 'muted'; msg.textContent = `Running on ${h.host} with sudo…`;
    try {
      const r = await (await postJSON('/api/access/grant', body)).json();
      msg.className = 'st-ok';
      msg.textContent = remove ? 'Removed.' : `Done via ${r.via}. Rescan ${h.host} to read the folders that were missing.`;
      if (!remove) form.append(el('div', { class: 'row end' }, button(`Scan ${h.host} now`, () => queueScan(h.host), 'btn pri sm')));
    } catch (err) { msg.className = 'st-failed'; msg.textContent = err.message; }
    finally { btn.disabled = false; }
  });
  return form;
}

/* ── copies ──────────────────────────────────────────────────────── */
async function loadCopies() {
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
    box.replaceChildren(text('p', `${r.total} folder${r.total === 1 ? '' : 's'}, ${fmtBytes(r.bytes)} untouched since ${new Date(r.cutoff * 1000).toISOString().slice(0, 10)}`, 'muted'),
      el('ol', { class: 'copies' }, ...r.folders.map((f) => el('li', { class: 'coldrow' },
        el('span', { class: 'p' }, f.path),
        el('span', { class: 'm' }, `${f.host} · ${fmtBytes(f.bytes)} · ${f.files.toLocaleString()} files · newest ${new Date(f.newest * 1000).toISOString().slice(0, 10)}`),
        button('Move…', () => moveFrom(f.host, f.path), 'btn ghost sm')))));
  } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); }
}
$('#coldform').addEventListener('submit', (ev) => { ev.preventDefault(); loadCold(); });
