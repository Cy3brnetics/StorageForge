'use strict';
/* Share wizard: pick the folder on the server from the index, choose NFS or SMB and who may use it, pick where each
   client mounts it (seeing that client's own mounts), then check it all on the server and save it into the host's
   design. Deploying is the existing shares deploy (Deploy tab). Loaded after app.js, topology.js and fsbrowse.js. */

const SW = { dlg: null, timer: 0, req: 0 };
const SW_STEPS = ['Folder', 'Access', 'Clients', 'Review'];

async function openShareWizard({ host = '', path = '', index = null, share = null } = {}) {
  let hostsList = [];
  try { hostsList = (await getJSON('/api/hosts')).indexed; } catch (err) { toast(err.message); return false; }
  if (host && !hostsList.some((h) => h.hostname === host)) return false;      // a planned host: nothing to browse
  const e = share || {};
  const isSmb = /^(SMB|CIFS)/i.test(e.protocol || e.proto || '');
  Object.assign(SW, {
    step: share ? 1 : 0, hosts: hostsList, index, share, saved: null, check: null, here: null, anyway: false,
    s: { host: host || (hostsList[0] || {}).hostname || '', path: e.path || path || '', proto: isSmb ? 'SMB' : 'NFS',
         version: isSmb ? 'SMB3' : (/^NFS/i.test(e.protocol || '') ? e.protocol : 'NFSv4.2'), name: e.name || '',
         rules: (e.rules && e.rules.length ? e.rules : e.clients && !isSmb ? [{ clients: e.clients, options: e.options || NFS_PRESETS['read-write'] }] : [])
           .map((r) => ({ ...r })),
         users: isSmb ? e.clients || '' : '', readonly: isSmb && /\bro\b/.test(e.options || ''),
         mounts: (e.mounts || []).map((m) => ({ host: m.host, path: m.path })) },
  });
  if (SW.dlg) SW.dlg.remove();
  SW.dlg = el('dialog', { class: 'swdlg', 'aria-label': 'Share wizard' });
  SW.dlg.addEventListener('cancel', (ev) => { ev.preventDefault(); closeShareWizard(); });
  document.body.append(SW.dlg);
  SW.dlg.showModal();
  swRender();
  swValidate();
  return true;
}
function closeShareWizard() { if (SW.dlg) { SW.dlg.close(); SW.dlg.remove(); SW.dlg = null; } }

function swExport() {
  const s = SW.s;
  const name = s.name || (s.path.split('/').pop() || 'share');
  return s.proto === 'NFS'
    ? { protocol: s.version, name, path: s.path, rules: s.rules.filter((r) => r.clients.trim()), mounts: s.mounts.filter((m) => m.host) }
    : { protocol: 'SMB3', name, path: s.path, clients: s.users, options: s.readonly ? 'ro' : '', mounts: s.mounts.filter((m) => m.host) };
}
function swChanged() { SW.saved = null; clearTimeout(SW.timer); SW.timer = setTimeout(swValidate, 350); }
async function swValidate() {
  const s = SW.s;
  if (!s.host || !s.path) { SW.check = null; swRenderChecks(); return; }
  const n = ++SW.req;
  try {
    const r = await (await postJSON('/api/shares/validate', { host: s.host, export: swExport(), index: SW.index })).json();
    if (n === SW.req) SW.check = r;
  } catch (err) { if (n === SW.req) SW.check = { error: err.message, items: [], crit: 1, warn: 0 }; }
  swRenderChecks();
  if (SW.step >= 2) swRenderStep(false);          // per-client results sit next to each client
}

function swRender() {
  const s = SW.s;
  const nav = el('ol', { class: 'swsteps' }, ...SW_STEPS.map((t, i) => el('li', { class: i === SW.step ? 'cur' : i < SW.step ? 'done' : '' },
    el('button', { type: 'button', disabled: i > 0 && !s.path, onclick: () => { SW.step = i; swRender(); } }, text('b', String(i + 1)), t))));
  SW.dlg.replaceChildren(
    el('header', { class: 'row swhead' }, el('h2', {}, SW.index != null ? 'Edit share' : 'New share'),
      s.host ? text('span', s.path ? `${s.host}:${s.path}` : s.host, 'fsk mono') : null, nav, el('span', { class: 'grow' }),
      button('Close', closeShareWizard, 'btn ghost sm')),
    el('div', { class: 'swbody' }, el('section', { id: 'swmain', class: 'stack' }), el('aside', { id: 'swchecks', class: 'stack' })),
    el('footer', { class: 'row swfoot' },
      SW.step ? button('← Back', () => { SW.step--; swRender(); }, 'btn ghost') : null, el('span', { class: 'grow' }),
      SW.step < 3 ? el('button', { type: 'button', class: 'btn pri', disabled: !s.path, onclick: () => { SW.step++; swRender(); } }, `Next: ${SW_STEPS[SW.step + 1]} →`) : null));
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
      onPick: (p) => { s.path = p; if (!s.name) s.name = p.split('/').pop() || 'share'; showChosen(); swChanged(); swRender(); } });
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
  const crit = SW.check ? SW.check.crit : 0;
  const docDirty = typeof T !== 'undefined' && T.docs.get(s.host) && T.docs.get(s.host).dirty;
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
      el('div', { class: 'row start' }, button('Deploy (report first)…', () => { closeShareWizard(); startDeploy('shares', SW.saved.host, 'report', `shares of ${SW.saved.host}`); }, 'btn pri sm'),
        button('Download the script', () => swDownload(SW.saved.host), 'btn sm'), button('Close', closeShareWizard, 'btn ghost sm')))
      : el('div', { class: 'stack' },
        docDirty ? text('p', `The topology has unsaved edits on ${s.host}: save or discard them first.`, 'st-failed') : null,
        crit ? anyway : null,
        el('div', { class: 'row' }, el('button', { type: 'button', class: 'btn pri', disabled: !!docDirty || (crit && !SW.anyway) || !s.path, onclick: swSave },
          SW.index != null ? 'Save changes' : 'Save share'),
        SW.index != null && !(SW.share && SW.share.fromScan) ? button('Remove share', swRemove, 'btn ghost danger') : null)));
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
  if (!c) { box.replaceChildren(text('h3', 'Checks'), text('p', 'Pick a folder to start.', 'muted small')); return; }
  const order = { crit: 0, warn: 1, ok: 2, note: 3 };
  const items = [...c.items].sort((a, b) => order[a.level] - order[b.level]);
  box.replaceChildren(...[el('div', { class: 'row' }, text('h3', 'Checks'),
    text('span', c.error ? 'error' : c.crit ? `${c.crit} to fix` : c.warn ? `${c.warn} warning${c.warn === 1 ? '' : 's'}` : 'all good', c.crit || c.error ? 'st-failed' : c.warn ? 'st-running' : 'st-ok')),
  c.error ? text('p', c.error, 'st-failed') : null,
  el('ul', { class: 'mvcheck' }, ...items.map((x) => text('li', x.text, `lv-${x.level}`))),
  text('p', 'Checked against the last scan of each host. Nothing is changed until you deploy.', 'muted small')].filter(Boolean));
  if (SW.step === 3) swRenderStep(true);
}

async function swSave() {
  const s = SW.s;
  try {
    const r = await (await postJSON('/api/shares', { host: s.host, export: swExport(), index: SW.index })).json();
    SW.saved = r; SW.index = r.index;
    if (typeof T !== 'undefined' && T.docs.has(r.host) && !T.docs.get(r.host).dirty) { T.docs.delete(r.host); if (T.mode === 'topo') loadDesigns(); }
    if (typeof loadGraph === 'function') loadGraph();
    swRender();
  } catch (err) { toast(err.message); }
}
async function swRemove() {
  const s = SW.s;
  if (!confirm(`Remove the share of ${s.path} from ${s.host}'s design? Hosts keep it until you deploy again.`)) return;
  try {
    await api(`/api/shares?host=${encodeURIComponent(s.host)}&index=${SW.index}`, { method: 'DELETE' });
    if (typeof T !== 'undefined' && T.docs.has(s.host) && !T.docs.get(s.host).dirty) { T.docs.delete(s.host); if (T.mode === 'topo') loadDesigns(); }
    closeShareWizard();
    toast('Share removed from the design');
  } catch (err) { toast(err.message); }
}
async function swDownload(host) {
  try {
    const res = await api(`/api/shares/script?host=${encodeURIComponent(host)}`);
    const a = document.createElement('a'); a.href = URL.createObjectURL(await res.blob());
    a.download = `shares-${host.split('.')[0].toLowerCase()}.sh`; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (err) { toast(err.message); }
}
