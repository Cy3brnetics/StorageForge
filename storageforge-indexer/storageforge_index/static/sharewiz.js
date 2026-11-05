'use strict';
/* Share wizard: pick the folder on the server from the index, choose NFS or SMB and who may use it, pick where each
   client mounts it (seeing that client's own mounts), then check it all on the server and save it into the host's
   design. Deploying is the existing shares deploy (Deploy tab). Loaded after app.js, topology.js and fsbrowse.js. */

const SW = { dlg: null, timer: 0, req: 0 };
const SW_STEPS = ['Folder', 'Access', 'Clients', 'Review'];
const SM = { dlg: null, req: 0, checks: new Map(), pending: new Set(), error: '' };
// the share itself, not its place in a list: the topology's list is the scan merged with the design
const swWas = (e) => (e ? { protocol: e.protocol || e.proto, name: e.name, path: e.path } : null);

async function openShareWizard({ host = '', path = '', index = null, share = null } = {}) {
  let hostsList = [];
  try { hostsList = (await getJSON('/api/hosts')).indexed; } catch (err) { notify(err.message, 'error'); return false; }
  if (host && !hostsList.some((h) => h.hostname === host)) return false;      // a planned host: nothing to browse
  const e = share || {};
  const isSmb = /^(SMB|CIFS)/i.test(e.protocol || e.proto || '');
  Object.assign(SW, {
    step: share ? 1 : 0, hosts: hostsList, index, share, saved: null, check: null, here: null, anyway: false, checking: false, busy: false, touched: false,
    s: { host: host || (hostsList[0] || {}).hostname || '', path: e.path || path || '', proto: isSmb ? 'SMB' : 'NFS',
         version: isSmb ? 'SMB3' : (/^NFS/i.test(e.protocol || '') ? e.protocol : 'NFSv4.2'), name: e.name || '',
         rules: (e.rules && e.rules.length ? e.rules : e.clients && !isSmb ? [{ clients: e.clients, options: e.options || NFS_PRESETS['read-write'] }] : [])
           .map((r) => ({ ...r })),
         users: isSmb ? e.clients || '' : '', readonly: isSmb && /\bro\b/.test(e.options || ''),
         smb: isSmb ? e.smb : null, mounts: (e.mounts || []).map((m) => ({ ...m })) },
  });
  if (SW.dlg) SW.dlg.remove();
  SW.dlg = el('dialog', { class: 'swdlg', 'aria-label': 'Share wizard' });
  SW.dlg.addEventListener('cancel', (ev) => { ev.preventDefault(); swLeave(); });
  SW.dlg.addEventListener('input', () => { SW.touched = true; });          // typing counts before the field is left: entry() only reports on change
  document.body.append(SW.dlg);
  SW.dlg.showModal();
  swRender();
  swValidate();
  return true;
}
/* Escape in the wizard asks before it throws away a share that was edited and not saved (UX-41). Past the first step,
   with something changed: the folder pick alone costs nothing to redo. The Close button is a deliberate click and closes. */
function swLeave() {
  if (!SW.dlg) return;
  if (!(SW.step > 0 && SW.touched && !SW.saved)) { closeShareWizard(); return; }
  if (SW.dlg.querySelector('.swdiscard')) return;
  const keep = button('Keep editing', () => ask.remove(), 'btn sm');
  const ask = el('div', { class: 'swdiscard row', role: 'alertdialog', 'aria-label': 'Discard what you entered?' },
    text('span', 'Discard what you entered? The share is not saved.'), el('span', { class: 'grow' }), keep, button('Discard', closeShareWizard, 'btn danger sm'));
  SW.dlg.prepend(ask);
  keep.focus();
}
function closeShareWizard() { if (SW.dlg) { SW.dlg.close(); SW.dlg.remove(); SW.dlg = null; } if (SM.dlg) smRender(); }

function swExport() {
  const s = SW.s;
  const name = s.name || (s.path.split('/').pop() || 'share');
  return s.proto === 'NFS'
    ? { protocol: s.version, name, path: s.path, rules: s.rules.filter((r) => r.clients.trim()), mounts: s.mounts.filter((m) => m.host) }
    : { protocol: 'SMB3', name, path: s.path, clients: s.users, options: s.readonly ? 'ro' : '', mounts: s.mounts.filter((m) => m.host), ...(s.smb ? { smb: s.smb } : {}) };
}
function swChanged(ms = 350) { SW.touched = true; SW.saved = null; SW.checking = true; clearTimeout(SW.timer); SW.timer = setTimeout(swValidate, ms); swRenderChecks(); }
async function swValidate() {
  const s = SW.s;
  clearTimeout(SW.timer);
  if (!s.host || !s.path) { SW.check = null; SW.checking = false; swRenderChecks(); return; }
  const n = ++SW.req;
  SW.checking = true;
  try {
    const r = await (await postJSON('/api/shares/validate', { host: s.host, export: swExport(), index: SW.index, was: swWas(SW.share) })).json();
    if (n === SW.req) SW.check = r;
  } catch (err) { if (n === SW.req) SW.check = { error: err.message, items: [], crit: 1, warn: 0 }; }
  if (n !== SW.req) return;                       // a newer check is on its way and will draw
  SW.checking = false;
  swRenderChecks();
  if (SW.step === 2) swRenderStep(false);         // per-client results sit next to each client
}
async function swPick(p) {                        // choosing the folder is the whole step: go on to who may use it
  const s = SW.s;
  const auto = !s.name || s.name === (s.path.split('/').pop() || 'share');     // a name the last folder gave it follows the folder
  s.path = p;
  if (auto) s.name = p.split('/').pop() || 'share';
  try { SW.here = await getJSON(`/api/fs/browse?host=${encodeURIComponent(s.host)}&path=${encodeURIComponent(p)}`); }   // what is mounted inside it, for its rules
  catch { SW.here = null; }
  if (!SW.dlg) return;
  SW.step = 1;
  swRender();
  swChanged(0);
}

function swRender() {
  const s = SW.s;
  const nav = el('ol', { class: 'swsteps' }, ...SW_STEPS.map((t, i) => el('li', { class: i === SW.step ? 'cur' : i < SW.step ? 'done' : '' },
    el('button', { type: 'button', disabled: i > 0 && !s.path, onclick: () => { SW.step = i; swRender(); } }, text('b', String(i + 1)), t))));
  SW.dlg.replaceChildren(
    el('header', { class: 'row swhead' }, el('h2', {}, SW.index != null ? 'Edit share' : 'New share'),
      s.host ? Object.assign(text('span', s.path ? `${s.host}:${s.path}` : s.host, 'fsk mono'), { title: s.path ? `${s.host}:${s.path}` : s.host }) : null, nav, el('span', { class: 'grow' }),
      button('Close', closeShareWizard, 'btn ghost sm')),
    el('div', { class: 'swbody' }, el('section', { id: 'swmain', class: 'stack' }), el('aside', { id: 'swchecks', class: 'stack' })),
    !SW.step && !s.path ? null : el('footer', { class: 'row swfoot' },
      SW.step ? button('← Back', () => { SW.step--; swRender(); }, 'btn ghost') : null, el('span', { class: 'grow' }),
      SW.step < 3 && s.path ? el('button', { type: 'button', class: 'btn pri', onclick: () => { SW.step++; swRender(); } }, `Next: ${SW_STEPS[SW.step + 1]} →`) : null));
  swRenderStep(true);
  swRenderChecks();
}

function swRenderStep(full) {
  const main = $('#swmain');
  if (!main) return;
  const s = SW.s;
  if (SW.step === 0) {
    if (!full) return;
    const hostSel = el('select', { 'aria-label': 'Server', onchange: () => { s.host = hostSel.value; s.path = ''; swChanged(); swRender(); } },
      ...SW.hosts.map((h) => new Option(h.hostname, h.hostname)));
    hostSel.value = s.host;
    const chosen = el('div', { class: 'row swchosen' });
    const showChosen = () => chosen.replaceChildren(...[text('span', 'Share:', 'muted'),
      s.path ? text('b', s.path, 'mono') : text('span', 'browse to a folder, then "Share this folder"', 'muted')].filter(Boolean));
    const br = fsBrowser({ host: s.host, path: s.path || '/', pick: 'folder', pickLabel: 'Share this folder',
      onChange: (_p, d) => { SW.here = d; },
      onPick: swPick });
    showChosen();
    main.replaceChildren(el('div', { class: 'row' }, field('Server', hostSel), chosen),
      text('p', 'Browse the server\'s folders as the last scan saw them. Badges show disks (◉), network mounts (⇄), shares and planned mounts.', 'muted small'), br);
    return;
  }
  if (SW.step === 1) {
    if (!full) return;
    const proto = el('div', { class: 'seg', role: 'group', 'aria-label': 'Protocol' }, ...['NFS', 'SMB'].map((p) =>
      el('button', { type: 'button', 'aria-pressed': String(s.proto === p), onclick: () => { s.proto = p; s.version = p === 'SMB' ? 'SMB3' : 'NFSv4.2'; swChanged(); swRender(); } }, p)));
    const help = s.proto === 'NFS' ? 'For Linux and macOS clients. Access is by client address; files keep their numeric owners.'
      : 'For Windows, macOS and Linux. Access is by Samba user; clients mount with a password file.';
    const name = entry(s.name, (v) => { s.name = v; swChanged(); }, { placeholder: s.path.split('/').pop() || 'share', class: 'mono' });
    const kids = [el('div', { class: 'row' }, proto, text('span', help, 'muted small')),
      field(s.proto === 'SMB' ? 'Share name (clients see //server/name)' : 'Name (for you)', name)];
    if (s.proto === 'NFS') {
      const ver = choice(['NFSv4.2', 'NFSv3'], s.version, (v) => { s.version = v; swChanged(); });
      kids.push(field('Version', ver), swRulesEditor());
    } else {
      kids.push(field('Who may connect (Samba users or @groups; empty = any Samba account)',
        entry(s.users, (v) => { s.users = v; swChanged(); }, { placeholder: 'gabe @family', class: 'mono' })),
      check('Read-only', s.readonly, (v) => { s.readonly = v; swChanged(); }));
    }
    main.replaceChildren(...kids);
    return;
  }
  if (SW.step === 2) {
    if (full || !main.querySelector('.swclients')) main.replaceChildren(swClientsEditor());
    else swClientResults();
    return;
  }
  // review
  const ex = swExport();
  const crit = SW.check && !SW.checking ? SW.check.crit : 0;
  const docDirty = typeof T !== 'undefined' && T.docs.get(s.host) && T.docs.get(s.host).dirty;
  const sig = JSON.stringify([ex, crit, docDirty, SW.anyway, SW.saved, SW.busy, SW.index]);
  if (!full && main._sig === sig) return;         // the same page: a button rebuilt under the pointer loses its click
  main._sig = sig;
  const anyway = check('Save even with problems (the deploy check still blocks them)', SW.anyway, (v) => { SW.anyway = v; swRenderStep(true); });
  const what = [
    `${s.host} shares ${ex.path} over ${ex.protocol}${ex.protocol.startsWith('SMB') ? ` as //${s.host}/${ex.name}` : ''}`,
    ex.protocol.startsWith('NFS') ? (ex.rules.length ? `to ${ex.rules.map((r) => `${r.clients} (${r.options || 'rw'})`).join(', ')}` : 'to nobody yet: add a client rule')
      : (s.users ? `for ${s.users}${s.readonly ? ', read-only' : ''}` : `for any Samba account${s.readonly ? ', read-only' : ''}`),
    ...ex.mounts.map((m) => `${m.host} mounts it at ${m.path} (fstab: automount, nofail)`)];
  main.replaceChildren(
    el('ul', { class: 'swsummary' }, ...what.map((t) => text('li', t))),
    SW.saved ? el('div', { class: 'card' }, text('b', `Saved in ${SW.saved.host}'s design.`, 'st-ok'),
      text('p', 'Deploying installs the server side on the server and mounts it on each client. It starts with a read-only report.', 'muted small'),
      el('div', { class: 'row start' }, button('Deploy (report first)…', () => swDeploy(SW.saved.host), 'btn pri sm'),
        button('Download the script', () => swDownload(SW.saved.host), 'btn sm'), button('Close', closeShareWizard, 'btn ghost sm')))
      : el('div', { class: 'stack' },
        docDirty ? text('p', `The topology has unsaved edits on ${s.host}: save or discard them first.`, 'st-failed') : null,
        crit ? anyway : null,
        el('div', { class: 'row' }, el('button', { type: 'button', class: 'btn pri', disabled: !!docDirty || (crit && !SW.anyway) || !s.path || !!SW.busy, onclick: () => swSave(true) },
          'Save and deploy (report first)…'),
        el('button', { type: 'button', class: 'btn', disabled: !!docDirty || (crit && !SW.anyway) || !s.path || !!SW.busy, onclick: () => swSave() },
          SW.index != null ? 'Save changes only' : 'Save only'),
        SW.index != null ? button('Remove share', swRemove, 'btn ghost danger') : null)));
}

function swRulesEditor() {
  const s = SW.s;
  const box = el('div', { class: 'mounton' });
  const below = (SW.here && SW.here.here && SW.here.here.mounts_below || []).filter((m) => m.kind === 'local');
  const draw = () => {
    const rows = s.rules.map((r, j) => {
      const who = entry(r.clients, (v) => { r.clients = v; swChanged(); }, { placeholder: '10.42.0.0/24, a host, or @netgroup', class: 'mono' });
      const preset = el('select', { 'aria-label': 'Access', onchange: () => { if (preset.value) { r.options = NFS_PRESETS[preset.value]; opts.value = r.options; swChanged(); } } },
        ...Object.keys(NFS_PRESETS).map((k) => new Option(k, k)), new Option('custom', ''));
      preset.value = Object.keys(NFS_PRESETS).find((k) => NFS_PRESETS[k] === r.options) || '';
      const opts = entry(r.options, (v) => { r.options = v; preset.value = Object.keys(NFS_PRESETS).find((k) => NFS_PRESETS[k] === v) || ''; swChanged(); }, { placeholder: 'rw,sync,no_subtree_check', class: 'mono' });
      return el('div', { class: 'stack nfsrule' }, el('div', { class: 'row' }, who, preset, button('×', () => { s.rules.splice(j, 1); swChanged(); draw(); }, 'btn ghost sm')), opts);
    });
    const subnets = new Map();             // /24s the scanned hosts live in
    for (const h of SW.hosts) {
      const m = /^(\d+\.\d+\.\d+)\.\d+$/.exec(h.ip || '');
      if (m && h.hostname !== s.host) subnets.set(`${m[1]}.0/24`, (subnets.get(`${m[1]}.0/24`) || 0) + 1);
    }
    const have = new Set(s.rules.flatMap((r) => r.clients.split(/\s+/)));
    const add = (c) => { s.rules.push({ clients: c, options: NFS_PRESETS['read-write'] }); swChanged(); draw(); };
    const chips = [...[...subnets].map(([c, n]) => [c, `${c} (${n} host${n === 1 ? '' : 's'})`]),
      ...SW.hosts.filter((h) => h.hostname !== s.host).map((h) => [h.ip || h.hostname, h.hostname])].filter(([c]) => !have.has(c));
    const cross = below.length ? check(`Show the ${below.length} filesystem${below.length === 1 ? '' : 's'} mounted inside (crossmnt): ${below.map((m) => m.target).join(', ')}`,
      s.rules.length && s.rules.every((r) => /\bcrossmnt\b/.test(r.options)), (v) => {
        for (const r of s.rules) r.options = v ? (r.options || NFS_PRESETS['read-write']).replace(/(,crossmnt)?$/, ',crossmnt') : r.options.replace(/,?crossmnt/g, '');
        swChanged(); draw();
      }) : null;
    box.replaceChildren(text('span', 'Who may mount it: one rule per client or subnet', 'muted'), ...rows,
      el('div', { class: 'row wrap' }, button('+ Rule', () => add(''), 'btn ghost sm'),
        chips.length ? text('span', 'Add:', 'muted small') : null, ...chips.slice(0, 10).map(([c, l]) => button(l, () => add(c), 'chip'))), ...(cross ? [cross] : []));
  };
  draw();
  return box;
}

function swClientsEditor() {
  const s = SW.s;
  const box = el('div', { class: 'stack swclients' });
  const draw = () => {
    const def = '/mnt/' + ((s.name || s.path.split('/').pop() || 'share').replace(/[^A-Za-z0-9_.-]/g, '-'));
    const rows = s.mounts.map((m, j) => {
      const host = el('select', { 'aria-label': 'Client', onchange: () => { m.host = host.value; swChanged(); } }, new Option('client host…', ''),
        ...SW.hosts.filter((h) => h.hostname !== s.host).map((h) => new Option(h.hostname, h.hostname)));
      host.value = m.host || '';
      const path = entry(m.path, (v) => { m.path = v; swChanged(); }, { placeholder: def, class: 'mono' });
      const browse = button('Browse…', async () => {
        const p = await pickPath(m.host, m.path ? dirOf(m.path) : '/mnt', { pick: 'mount', title: `Mount point on ${m.host}` });
        if (p) { m.path = p; path.value = p; swChanged(); }
      }, 'btn ghost sm');
      return el('div', { class: 'card swclient', dataset: { host: m.host || '', path: m.path || '' } },
        el('div', { class: 'row' }, host, path, browse, button('×', () => { s.mounts.splice(j, 1); swChanged(); draw(); }, 'btn ghost sm')),
        el('ul', { class: 'mvcheck' }));
    });
    const unused = SW.hosts.filter((h) => h.hostname !== s.host && !s.mounts.some((m) => m.host === h.hostname));
    box.replaceChildren(
      text('p', 'Each client gets an fstab line (automount, nofail, so a missing server never blocks its boot) and the folder is created. Leave this empty to only share it.', 'muted small'),
      ...rows,
      el('div', { class: 'row wrap' }, button('+ Client', () => { s.mounts.push({ host: '', path: def }); swChanged(); draw(); }, 'btn ghost sm'),
        unused.length ? text('span', 'Add:', 'muted small') : null,
        ...unused.slice(0, 10).map((h) => button(h.hostname, () => { s.mounts.push({ host: h.hostname, path: def }); swChanged(); draw(); }, 'chip'))));
    swClientResults();
  };
  draw();
  return box;
}
function swClientResults() {
  for (const card of document.querySelectorAll('.swclient')) {
    const i = [...card.parentElement.querySelectorAll('.swclient')].indexOf(card);
    const m = SW.s.mounts[i];
    const ul = card.querySelector('.mvcheck');
    if (!m || !SW.check || !m.host) { ul.replaceChildren(); continue; }
    const key = `${m.host}:${(m.path || '').replace(/\/$/, '')}`;
    ul.replaceChildren(...SW.check.items.filter((x) => x.text.includes(key) || x.text.includes(`client ${m.host} `) || x.text.includes(`on ${m.host}`))
      .map((x) => text('li', x.text, `lv-${x.level}`)));
  }
}

function swRenderChecks() {
  const box = $('#swchecks');
  if (!box) return;
  const c = SW.check;
  if (!c) { box.replaceChildren(text('h3', 'Checks'), text('p', SW.checking ? 'Checking…' : 'Pick a folder to start.', 'muted small')); return; }
  const order = { crit: 0, warn: 1, ok: 2, note: 3 };
  const items = [...c.items].sort((a, b) => order[a.level] - order[b.level]);
  box.replaceChildren(...[el('div', { class: 'row' }, text('h3', 'Checks'),
    text('span', SW.checking ? 'checking…' : c.error ? 'error' : c.crit ? `${c.crit} to fix` : c.warn ? `${c.warn} warning${c.warn === 1 ? '' : 's'}` : 'all good', SW.checking ? 'muted' : c.crit || c.error ? 'st-failed' : c.warn ? 'st-running' : 'st-ok')),
  c.error ? text('p', c.error, 'st-failed') : null,
  el('ul', { class: 'mvcheck' }, ...items.map((x) => text('li', x.text, `lv-${x.level}`))),
  text('p', 'Checked against the last scan of each host. Nothing is changed until you deploy.', 'muted small')].filter(Boolean));
  if (SW.step === 3) swRenderStep(false);
}

function swDeploy(host) {
  closeSharesManager(); closeShareWizard();
  startDeploy('shares', host, 'report', `shares of ${host}`);
}
async function swSave(thenDeploy = false) {
  if (SW.busy) return;                            // two quick clicks would add the share, then refuse it as a duplicate
  const s = SW.s;
  SW.busy = true; swRenderStep(false);
  try {
    if (SW.checking) await swValidate();          // the last edit's check decides, not the one before it
    if (SW.check && SW.check.crit && !SW.anyway) return;
    const r = await (await postJSON('/api/shares', { host: s.host, export: swExport(), index: SW.index, was: swWas(SW.share) })).json();
    SW.saved = r; SW.index = r.index; SW.share = r.export;
    smReload(r.host);
    if (typeof loadGraph === 'function') loadGraph();
    if (curTab() === 'deploy' && !thenDeploy) loadDeploy();
    if (thenDeploy) swDeploy(r.host);
    else swRender();
  } catch (err) { notify(err.message, 'error'); }
  finally { SW.busy = false; if (SW.dlg) swRenderStep(false); }
}
async function swRemove() {
  const s = SW.s;
  if (!(await confirmDialog({ title: `Remove the share of ${s.path} from ${s.host}’s design?`, body: 'Hosts keep it until you deploy again.', confirm: 'Remove share', danger: true }))) return;
  try {
    await smDelete(s.host, SW.share);
    closeShareWizard();
    toast('Share removed from the design');
  } catch (err) { notify(err.message, 'error'); }
}
async function swDownload(host) {
  try {
    const res = await api(`/api/shares/script?host=${encodeURIComponent(host)}`);
    const a = document.createElement('a'); a.href = URL.createObjectURL(await res.blob());
    a.download = `shares-${host.split('.')[0].toLowerCase()}.sh`; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (err) { notify(err.message, 'error'); }
}

/* The shares manager: every share on the hosts in view, with who may use it, who mounts it and what the checks say.
   Designed shares open in the wizard; shares only the scan knows are read-only, since the host's own config holds them. */
function smDelete(host, e) {
  const q = new URLSearchParams({ host, ...swWas(e) });
  return api(`/api/shares?${q}`, { method: 'DELETE' }).then(() => { smReload(host); if (typeof loadGraph === 'function') loadGraph(); });
}
function smReload(host) {          // the saved design changed under the topology: fetch it again unless edits are open
  if (typeof T === 'undefined' || !T.docs.has(host) || T.docs.get(host).dirty) return;
  if (T.sel && T.sel.host === host && T.sel.key.startsWith('exp:')) T.sel = null;     // keys are list indexes
  if (T.mode === 'topo') loadDesigns();           // it refetches every doc without open edits
}
function smKey(e) {                // payloads.share_key
  const p = String(e.protocol || e.proto || '').toUpperCase();
  return /^(SMB|CIFS)/.test(p) ? `SMB|${String(e.name || '').toLowerCase()}` : p.startsWith('NFS') ? `NFS|${String(e.path || '').replace(/\/+$/, '') || '/'}` : `${p}|${e.path}|${e.name}`;
}
function openSharesManager(filter = '') {
  if (SM.dlg) return;
  SM.dlg = el('dialog', { class: 'swdlg smdlg', 'aria-label': 'Shares' });
  SM.dlg.addEventListener('cancel', (ev) => { ev.preventDefault(); closeSharesManager(); });
  SM.find = el('input', { type: 'search', placeholder: 'Filter by host, name, path or client…', 'aria-label': 'Filter shares', value: filter, oninput: smRender });
  SM.list = el('div', { class: 'smlist stack' });
  SM.dlg.append(el('header', { class: 'row swhead' }, el('h2', {}, 'Shares'), SM.find, el('span', { class: 'grow' }),
    button('+ New share', () => openShareWizard({}), 'btn pri sm'), button('Close', closeSharesManager, 'btn ghost sm')), SM.list);
  document.body.append(SM.dlg);
  SM.dlg.showModal();
  smLoad();
}
function closeSharesManager() { if (SM.dlg) { SM.dlg.close(); SM.dlg.remove(); SM.dlg = null; } }
async function smLoad() {          // the checks and what is not deployed yet; the list itself comes from the topology's docs
  if (!SM.dlg) return;
  smRender();
  const n = ++SM.req;
  const docs = [...T.docs.values()].filter((d) => d.bp && !d.dirty && d.savedAt && designedShares(d).length);
  const [checks, deployed] = await Promise.all([
    Promise.all(docs.map((d) => getJSON(`/api/shares/check?host=${encodeURIComponent(d.host)}`).then((c) => [d.host, c]).catch(() => null))),
    getJSON('/api/deploy').catch(() => null)]);
  if (n !== SM.req || !SM.dlg) return;
  SM.checks = new Map(checks.filter(Boolean));
  SM.pending = new Set(deployed ? deployed.drift.filter((x) => x.kind === 'pending').map((x) => x.ref) : []);
  smRender();
}
function smState(doc, e) {
  if (!e.designed && e.fromScan) return ['on the host only', 'unknown', 'Found by the scan in the host\'s own config. StorageForge did not deploy it and does not change it.'];
  if (e.fromScan) return ['deployed', 'protected', 'In the design and found on the host by the last scan.'];
  if (doc.sharesDeployed) return ['deployed', 'protected', 'Deployed from this design. The next scan of the host confirms it.'];
  return ['planned', 'local-only', 'In the design, not found on the host yet: deploy it, or scan again if it is already there.'];
}
function smMountedBy(doc, i, e) {
  const seen = [...(e.mounts || []).filter((m) => m.host).map((m) => `${m.host}:${m.path}`),
    ...[...T.docs.values()].flatMap((d) => (d.bp && d.bp.remotes || [])
      .filter((r) => { const f = shareSource(d, r); return f && f.host === doc.host && f.key === `exp:${i}`; }).map((r) => `${d.host}:${r.mount}`))];
  return [...new Set(seen)];
}
function smAccess(e) {
  if (e.rules && e.rules.length) return e.rules.map((r) => `${r.clients} (${r.options || 'default options'})`).join(', ');
  return [e.clients, e.options].filter(Boolean).join(' · ') || (/^(SMB|CIFS)/i.test(e.protocol || e.proto || '') ? 'any Samba account' : 'no clients');
}
function smShow(host, key) { closeSharesManager(); showTab('details'); selectBox(host, key); reveal(host, key); }
async function smEdit(doc, i, e) {
  const managed = /^(NFS|SMB|CIFS)/i.test(e.protocol || e.proto || '');
  if (managed && await openShareWizard({ host: doc.host, index: i, share: e })) return;
  smShow(doc.host, `exp:${i}`);                   // a planned host, or SFTP/S3: the topology's own form
}
async function smRemove(doc, i, e) {
  const [state] = smState(doc, e);
  const label = `${e.protocol || e.proto} ${e.name || e.path}`;
  if (!(await confirmDialog({ title: `Remove ${label} from ${doc.host}’s design?`, confirm: 'Remove share', danger: true,
    body: state === 'deployed' ? `It stays on the host and its clients until you deploy ${doc.host}’s shares again, which takes it down.` : '' }))) return;
  SM.error = '';
  if (doc.source !== 'scan') {                    // a planned host's design: an unsaved edit like any other
    doc.bp.exports.splice(i, 1);
    if (T.sel && T.sel.host === doc.host && T.sel.key.startsWith('exp:')) T.sel = null;
    touched(doc, 'exports');
    smRender();
    return;
  }
  try { await smDelete(doc.host, e); } catch (err) { SM.error = err.message; smRender(); }
}
function smRow(doc, i, e, chk) {
  const [state, cls, why] = smState(doc, e);
  const scanOnly = !e.designed && e.fromScan;
  const dirty = doc.dirty ? `Save or discard the edits on ${doc.host} first` : '';
  const items = chk ? chk.items.filter((x) => ['crit', 'warn'].includes(x.level) && chk.exports[x.export] && smKey(chk.exports[x.export]) === smKey(e)) : [];
  const by = smMountedBy(doc, i, e);
  const act = (label, fn, cls2) => { const b = button(label, fn, cls2); if (dirty) { b.disabled = true; b.title = dirty; } return b; };
  const pill = text('span', state, `pill ${cls}`); pill.title = why;
  return el('li', { class: 'card smrow' },
    el('div', { class: 'row' }, text('span', e.protocol || e.proto || '?', 'fsk'), text('b', e.name || e.path, 'mono'), pill, el('span', { class: 'grow' }),
      button('Show', () => smShow(doc.host, `exp:${i}`), 'btn ghost sm'),
      scanOnly ? null : act('Edit', () => smEdit(doc, i, e), 'btn sm'),
      scanOnly ? null : act('Remove', () => smRemove(doc, i, e), 'btn ghost sm danger')),
    el('dl', { class: 'smfacts' }, text('dt', 'Folder'), text('dd', e.path || '?', 'mono'), text('dt', 'Access'), text('dd', smAccess(e), 'mono'),
      text('dt', 'Mounted on'), text('dd', by.length ? by.join(', ') : 'no client', by.length ? 'mono' : 'muted')),
    scanOnly ? text('p', 'Change it in the host\'s own config; the next scan picks it up.', 'muted small') : null,
    items.length ? el('ul', { class: 'mvcheck' }, ...items.map((x) => text('li', x.text, `lv-${x.level}`))) : null);
}
function smRender() {
  if (!SM.dlg) return;
  const q = SM.find.value.trim().toLowerCase();
  const groups = [];
  for (const host of T.order) {
    const doc = T.docs.get(host);
    if (!doc || !doc.bp) continue;
    const rows = (doc.bp.exports || []).map((e, i) => [i, e]).filter(([i, e]) => !q
      || [host, e.protocol, e.proto, e.name, e.path, smAccess(e), ...smMountedBy(doc, i, e)].join(' ').toLowerCase().includes(q));
    if (!rows.length) continue;
    const chk = SM.checks.get(host);
    const designed = designedShares(doc).length;
    const blocked = (b) => { if (doc.dirty) { b.disabled = true; b.title = `Save or discard the edits on ${host} first`; } return b; };
    groups.push(el('section', { class: 'stack' },
      el('div', { class: 'row wrap' }, text('h3', host, 'mono'),
        doc.dirty ? text('span', 'unsaved edits', 'dirty') : null,
        SM.pending.has(host) ? text('span', 'design changed, not deployed', 'pill local-only') : null,
        chk && chk.crit ? text('span', `${chk.crit} to fix`, 'st-failed') : null,
        el('span', { class: 'grow' }),
        blocked(button('+ Share here', () => openShareWizard({ host }).then((ok) => { if (!ok) { closeSharesManager(); addExport(doc); } }), 'btn ghost sm')),
        designed ? blocked(button('Checks & script', () => { closeSharesManager(); deployShares(doc); }, 'btn ghost sm')) : null,
        designed && doc.source === 'scan' ? blocked(button('Deploy (report first)…', () => { closeSharesManager(); startDeploy('shares', host, 'report', `shares of ${host}`); }, 'btn sm')) : null),
      el('ul', { class: 'smshares' }, ...rows.map(([i, e]) => smRow(doc, i, e, chk)))));
  }
  const any = T.order.some((h) => ((T.docs.get(h) || {}).bp || {}).exports && T.docs.get(h).bp.exports.length);
  SM.list.replaceChildren(...[SM.error ? text('p', SM.error, 'st-failed') : null, ...groups,
    groups.length ? null : text('p', any ? 'No share matches the filter.' : 'No shares on the hosts in view yet. Add one with + New share.', 'muted')].filter(Boolean));
}
