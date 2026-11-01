'use strict';
/* Moves tab: plan rsync steps (copy, move, mirror, rsnapshot) between folders on scanned hosts, check the plan
   against the index, and download the script that runs it. Loaded after app.js, topology.js and checks.js. */

const MV = { plans: [], plan: null, hosts: [], result: null, dirty: false };
const METHOD_HELP = {
  copy: 'Copy the folder. The source is left alone.',
  move: 'Copy, verify, then cut over: the source is renamed to *.migrated-<date> (never deleted) and, on the same host, linked to the new place.',
  mirror: 'Keep a copy in sync on a timer (systemd). Optionally remove files at the destination that are gone from the source.',
  rsnapshot: 'Rotating hard-linked snapshots of the source at the destination, on timers (needs rsnapshot there).',
  git: 'A bare archive of a git repository (git clone --mirror): every branch and tag, refreshed by --run and on a timer after --install.',
};
const SCHEDULE_PRESETS = { hourly: 'hourly', daily: 'daily (midnight)', '*-*-* 02:30:00': 'daily at 02:30', '*-*-* 00/4:00:00': 'every 4 hours',
  '*-*-* 00/6:00:00': 'every 6 hours', weekly: 'weekly (Monday 00:00)', 'Sun *-*-* 03:00:00': 'Sundays at 03:00', monthly: 'monthly (the 1st)' };
const KEEP_PRESETS = { 'Homelab: 7 days, 4 weeks, 6 months': { hourly: 0, daily: 7, weekly: 4, monthly: 6 },
  'Busy: 24 hours, 7 days, 4 weeks': { hourly: 24, daily: 7, weekly: 4, monthly: 0 },
  'Archive: 14 days, 8 weeks, 24 months': { hourly: 0, daily: 14, weekly: 8, monthly: 24 } };
const blankStep = (src = {}, dst = {}) => ({ method: 'copy', src: { host: src.host || '', path: src.path || '' },
  dst: { host: dst.host || '', path: dst.path || '' }, excludes: [], note: '',
  options: { remote_sudo: true, one_fs: true, link_back: true, checksum: false, delete: false, schedule: 'daily',
             keep: { hourly: 0, daily: 7, weekly: 4, monthly: 6 } } });

async function loadMoves(selectId) {
  const box = $('#movesbox');
  try {
    const [{ plans }, { indexed }] = await Promise.all([getJSON('/api/moves'), getJSON('/api/hosts')]);
    MV.plans = plans; MV.hosts = indexed.map((h) => h.hostname).sort();
    if (selectId) MV.plan = await getJSON(`/api/moves/${selectId}`);
  } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); return; }
  if (!MV.plan) MV.plan = { name: '', steps: [] };
  renderMoves();
}
function touch() { MV.dirty = true; MV.result = null; const b = $('#mvsave'); if (b) b.textContent = 'Save*'; }
function renderMoves() {
  const p = MV.plan;
  const planOption = (x) => new Option(`${x.name} (${x.steps})${x.deployed_at ? ` · deployed ${stamp(x.deployed_at)}` : ''}`, x.id);
  const live = MV.plans.filter((x) => x.deployed_at);
  const pick = el('select', { 'aria-label': 'Move plan', onchange: async () => {
    if (MV.dirty && !confirm('Discard unsaved changes to this plan?')) { pick.value = p.id || ''; return; }
    MV.dirty = false; MV.result = null; MV.plan = pick.value ? await getJSON(`/api/moves/${pick.value}`) : { name: '', steps: [] }; renderMoves();
  } }, new Option('New plan…', ''), ...MV.plans.filter((x) => !x.deployed_at).map(planOption),
    live.length ? el('optgroup', { label: 'Deployed as jobs' }, ...live.map(planOption)) : '');
  pick.value = p.id || '';
  const name = el('input', { type: 'text', placeholder: 'plan name, e.g. TR01 media to Archie', 'aria-label': 'Plan name',
    onchange: () => { p.name = name.value.trim(); touch(); } }); name.value = p.name || '';
  const steps = el('ol', { class: 'mvsteps' }, ...p.steps.map((s, i) => stepCard(s, i)));
  const res = MV.result;
  const total = res ? el('p', { class: res.crit ? 'st-failed' : res.warn ? 'st-running' : 'st-ok' },
    `${fmtBytes(res.bytes)} in all · about ${eta(res.eta_s)} · ${res.crit} critical · ${res.warn} warning${res.warn === 1 ? '' : 's'}`) : null;
  $('#movesbox').replaceChildren(
    el('div', { class: 'row' }, pick, name),
    p.deployed_at && !MV.dirty ? text('p', `Deployed as jobs on ${stamp(p.deployed_at)}. The Deploy tab shows how they are running; edit the plan and deploy it again to change them.`, 'st-ok small') : '',
    steps,
    el('div', { class: 'row' }, button('+ Add step', () => { p.steps.push(blankStep()); touch(); renderMoves(); }, 'btn sm')),
    total || '',
    el('div', { class: 'row end' },
      p.id ? button('Delete plan', delPlan, 'btn ghost sm danger') : '',
      p.id ? button('Duplicate', copyPlan, 'btn ghost sm') : '',
      p.id ? button('Export JSON', exportPlan, 'btn ghost sm') : '',
      button('Check', checkPlan, 'btn sm'),
      el('button', { id: 'mvsave', type: 'button', class: 'btn sm', onclick: savePlan }, MV.dirty ? 'Save*' : 'Save'),
      button('Download script', downloadScript, 'btn sm'),
      button('Deploy…', deployPlan, 'btn pri sm')),
    el('p', { id: 'mvmsg', class: 'muted', hidden: true }),
    el('details', { class: 'mvhelp' }, el('summary', {}, 'How the script runs'),
      el('p', { class: 'muted' }, 'Copy it to the machine you run storage-setup.sh from. ./plan.sh reports what is there (read-only); '
        + '--dry-run shows what rsync would send; sudo ./plan.sh --run copies, --verify compares, --cutover finishes move steps, '
        + '--install sets up mirror and rsnapshot timers. Each step runs on its destination host: add --host user@host to run it there over SSH. '
        + 'It never deletes, and it stops if a destination mount is not mounted.')));
}
const eta = (s) => s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min` : `${Math.max(1, Math.floor(s / 60))} min`;
function hostSelect(value, onchange) {
  const s = el('select', { onchange: () => onchange(s.value) }, new Option('host…', ''), ...MV.hosts.map((h) => new Option(h, h)));
  s.value = value || '';
  return s;
}
function endEditor(s, side, label) {
  const end = s[side];
  const path = el('input', { type: 'text', class: 'mono', placeholder: side === 'src' ? '/mnt/data01/media' : '/mnt/coldStorage/media',
    'aria-label': `${label} path`, onchange: () => { end.path = path.value.trim(); touch(); } });
  path.value = end.path || '';
  const browser = el('div', { class: 'browser', hidden: true });
  const browse = button('Browse', () => {
    if (!end.host) { alertMv('Pick the host first'); return; }
    browser.hidden = !browser.hidden;
    if (!browser.hidden) openBrowser(browser, end.host, end.path || '/', (p) => { end.path = p; path.value = p; touch(); browser.hidden = true; });
  }, 'btn ghost sm');
  return el('div', { class: 'mvend' }, el('span', { class: 'lbl' }, label),
    el('div', { class: 'row' }, hostSelect(end.host, (h) => { end.host = h; touch(); }), path, browse), browser);
}
function openBrowser(box, host, path, choose) {     // the shared index browser (fsbrowse.js), inline
  box.replaceChildren(fsBrowser({ host, path, onPick: choose }));
}
function stepCard(s, i) {
  const p = MV.plan, o = s.options;
  const method = el('select', { 'aria-label': 'Method', onchange: () => { s.method = method.value; touch(); renderMoves(); } },
    ...['copy', 'move', 'mirror', 'rsnapshot', 'git'].map((m) => new Option(m, m)));
  method.value = s.method;
  const opt = (key, label) => { const c = el('input', { type: 'checkbox', onchange: () => { o[key] = c.checked; touch(); } }); c.checked = !!o[key]; return el('label', { class: 'check' }, c, label); };
  const excl = el('textarea', { rows: 2, class: 'mono', placeholder: 'excludes, one per line: *.tmp  .Trash-*  cache/', 'aria-label': 'Excludes',
    onchange: () => { s.excludes = excl.value.split('\n').map((x) => x.trim()).filter(Boolean); touch(); } });
  excl.value = (s.excludes || []).join('\n');
  const opts = el('div', { class: 'opts' }, opt('remote_sudo', 'sudo rsync on the source host'), opt('one_fs', 'stay on one filesystem'), opt('checksum', 'compare by checksum'));
  if (s.method === 'move') opts.append(opt('link_back', 'leave a symlink at the old path (same host)'));
  if (s.method === 'mirror') opts.append(opt('delete', 'delete files gone from the source (--delete-after)'));
  if (s.method === 'mirror' || s.method === 'rsnapshot' || s.method === 'git') {
    const custom = el('input', { type: 'text', class: 'mono', placeholder: 'systemd time, e.g. Mon..Fri 22:00', 'aria-label': 'Custom schedule',
      onchange: () => { o.schedule = custom.value.trim() || 'daily'; touch(); } });
    const sch = el('select', { 'aria-label': 'Schedule', onchange: () => {
      custom.hidden = sch.value !== 'custom';
      if (sch.value !== 'custom') { o.schedule = sch.value; touch(); } else custom.focus();
    } }, ...Object.entries(SCHEDULE_PRESETS).map(([v, l]) => new Option(l, v)), new Option('custom…', 'custom'));
    const known = Object.prototype.hasOwnProperty.call(SCHEDULE_PRESETS, o.schedule || 'daily');
    sch.value = known ? o.schedule || 'daily' : 'custom';
    custom.value = known ? '' : o.schedule; custom.hidden = known;
    opts.append(el('div', { class: 'row wrap' }, el('label', { class: 'field' }, el('span', {}, s.method === 'rsnapshot' ? 'Snapshots' : 'Runs'), sch), custom));
    if (s.method === 'rsnapshot') {
      opts.append(el('div', { class: 'row keep' }, text('span', 'Keep', 'muted'), ...['hourly', 'daily', 'weekly', 'monthly'].map((k) => {
        const n = el('input', { type: 'number', min: 0, max: 999, 'aria-label': `${k} snapshots to keep`, onchange: () => { o.keep[k] = +n.value || 0; touch(); } });
        n.value = (o.keep || {})[k] || 0; return el('label', { class: 'field' }, el('span', {}, k), n);
      })), el('div', { class: 'row wrap' }, text('span', 'Presets:', 'muted small'), ...Object.entries(KEEP_PRESETS).map(([name, k]) =>
        button(name, () => { o.keep = { ...k }; touch(); renderMoves(); }, 'btn ghost sm'))));
    }
  }
  opts.append(jobOptions(s));
  const login = el('input', { type: 'text', placeholder: 'source login (default: its scan user), e.g. root@10.42.0.3', class: 'mono',
    'aria-label': 'Source SSH login', onchange: () => { o.src_login = login.value.trim() || null; touch(); } });
  login.value = o.src_login || '';
  const result = (MV.result && MV.result.steps[i]) || null;
  const done = !MV.dirty && p.progress && p.progress[i];
  const marks = done ? [done.copied && `copied ${done.copied}`, done.cutover && `cut over ${done.cutover}`].filter(Boolean) : [];
  const li = el('li', { class: 'card mvstep' },
    el('div', { class: 'row' }, el('b', {}, `Step ${i + 1}`), method,
      el('span', { class: 'row tools' },
        i ? button('↑', () => { [p.steps[i - 1], p.steps[i]] = [p.steps[i], p.steps[i - 1]]; touch(); renderMoves(); }, 'btn ghost sm') : '',
        i < p.steps.length - 1 ? button('↓', () => { [p.steps[i + 1], p.steps[i]] = [p.steps[i], p.steps[i + 1]]; touch(); renderMoves(); }, 'btn ghost sm') : '',
        button('Remove', () => { p.steps.splice(i, 1); touch(); renderMoves(); }, 'btn ghost sm danger'))),
    text('p', METHOD_HELP[s.method], 'muted small'),
    marks.length ? text('p', `${marks.join(' · ')} (at the last scan of ${s.dst.host})`, 'st-ok small') : '',
    endEditor(s, 'src', 'From'), endEditor(s, 'dst', 'To'),
    s.only?.length ? text('p', `Only these ${s.only.length} file${s.only.length === 1 ? '' : 's'} from that folder: ${s.only.slice(0, 8).join(', ')}${s.only.length > 8 ? ' and more' : ''}`, 'muted small') : null,
    el('details', {}, el('summary', {}, 'Options'), opts, excl, s.src.host && s.dst.host && s.src.host !== s.dst.host ? login : ''),
    result ? el('ul', { class: 'mvcheck' }, ...result.items.map((it) => el('li', { class: `lv-${it.level}` }, it.text))) : '');
  const redo = (fn) => () => { fn(); touch(); renderMoves(); };
  li._menu = () => [{ heading: `Step ${i + 1} · ${s.method}${s.src.path ? ' · ' + s.src.path : ''}` },
    { label: 'Move up', disabled: !i, run: redo(() => { [p.steps[i - 1], p.steps[i]] = [p.steps[i], p.steps[i - 1]]; }) },
    { label: 'Move down', disabled: i === p.steps.length - 1, run: redo(() => { [p.steps[i + 1], p.steps[i]] = [p.steps[i], p.steps[i + 1]]; }) },
    { label: 'Duplicate', run: redo(() => { p.steps.splice(i + 1, 0, structuredClone(s)); }) },
    { label: 'Swap source and destination', run: redo(() => { [s.src, s.dst] = [s.dst, s.src]; }) },
    s.src.host && s.src.path ? { label: 'Browse the source folder', run: () => browseFolders(s.src.host, s.src.path, mountFor(s.src.host, s.src.path)) } : null,
    '-', { label: 'Remove', danger: true, run: redo(() => { p.steps.splice(i, 1); }) }];
  return li;
}
/* what only deployed jobs use: run window, day/night bandwidth, pre/post commands, btrfs snapshot first, verify */
function jobOptions(s) {
  const o = s.options;
  const line = (key, label, placeholder, attrs = {}) => {
    const i = el('input', { type: 'text', class: 'mono', placeholder, 'aria-label': label, ...attrs,
      onchange: () => { o[key] = i.value.trim() || null; touch(); } });
    i.value = o[key] ?? ''; return el('label', { class: 'field' }, el('span', {}, label), i);
  };
  const cmds = (key, label, placeholder) => {
    const t = el('textarea', { rows: 2, class: 'mono', placeholder, 'aria-label': label,
      onchange: () => { o[key] = t.value.split('\n').map((x) => x.trim()).filter(Boolean); touch(); } });
    t.value = (o[key] || []).join('\n'); return el('label', { class: 'field col' }, el('span', {}, label), t);
  };
  const snap = el('input', { type: 'checkbox', onchange: () => { o.snapshot = snap.checked; touch(); } }); snap.checked = !!o.snapshot;
  const verify = el('select', { 'aria-label': 'Checksum verify', onchange: () => { o.verify = verify.value || null; touch(); } },
    new Option('on demand', ''), new Option('weekly', 'weekly'), new Option('monthly', 'monthly'));
  verify.value = o.verify || '';
  const check = (key, label) => {
    const c = el('input', { type: 'checkbox', onchange: () => { o[key] = c.checked; touch(); } }); c.checked = !!o[key];
    return el('label', { class: 'check' }, c, label);
  };
  const pick = (key, label, options) => {
    const c = el('select', { 'aria-label': label, onchange: () => { o[key] = c.value || null; touch(); } }, ...options.map(([v, t]) => new Option(t, v)));
    c.value = o[key] || ''; return el('label', { class: 'field' }, el('span', {}, label), c);
  };
  const routes = el('textarea', { rows: 3, class: 'mono', 'aria-label': 'Routes to the source', placeholder: 'lan 192.168.1.20\nmesh 100.64.0.20 tailscale0',
    onchange: () => {
      o.routes = routes.value.split('\n').map((x) => x.trim().split(/\s+/)).filter((w) => w[0]).map(([via, address, iface]) => ({ via, address, iface: iface || null }));
      touch();
    } });
  routes.value = (o.routes || []).map((r) => [r.via, r.address, r.iface].filter(Boolean).join(' ')).join('\n');
  const suggest = button('Suggest from Docker', async () => {
    if (!s.src.host || !s.src.path) return;
    try {
      const { usage } = await getJSON(`/api/docker/usage?host=${encodeURIComponent(s.src.host)}&path=${encodeURIComponent(s.src.path)}`);
      const stacks = [...new Set(usage.filter((u) => u.stack).map((u) => u.stack))];
      if (!stacks.length) { alertMv(`No compose stack on ${s.src.host} uses ${s.src.path}.`, 'muted'); return; }
      o.pre = stacks.map((x) => `docker compose -p ${x} stop`); o.post = stacks.map((x) => `docker compose -p ${x} start`);
      touch(); renderMoves();
    } catch (err) { alertMv(err.message); }
  }, 'btn ghost sm');
  return el('details', { class: 'jobopts' }, el('summary', {}, 'When deployed as a job'),
    text('p', 'Used when this step is deployed from the Deploy tab (the downloaded script ignores them).', 'muted small'),
    el('div', { class: 'row wrap' }, line('window', 'Only run between', '01:00-06:00', { size: 12 }),
      line('bwlimit', 'Bandwidth by day (KB/s)', 'unlimited', { size: 9, inputmode: 'numeric' }),
      line('bwlimit_night', 'by night (KB/s)', 'unlimited', { size: 9, inputmode: 'numeric' }),
      line('night', 'Night is', '22:00-07:00', { size: 12 })),
    cmds('pre', 'Before each run, on the source (one command per line, as root)', 'docker compose -p immich stop'),
    cmds('post', 'After it (also when the run fails)', 'docker compose -p immich start'),
    el('div', { class: 'row wrap' }, suggest,
      el('label', { class: 'check' }, snap, 'Copy from a btrfs snapshot of the source (stops the stack only for the snapshot)'),
      el('label', { class: 'field' }, el('span', {}, 'Checksum verify'), verify)),
    el('label', { class: 'field col' }, el('span', {}, 'Routes to the source, tried in order, each "lan|mesh address [interface]". A bandwidth limit applies on mesh only. Empty: the scanned address'), routes),
    el('div', { class: 'row wrap' }, pick('transport', 'Transfer with', [['', 'rsync'], ['btrfs', 'btrfs send'], ['zfs', 'zfs send']]),
      check('dedup', 'Make files already at the destination from local data'), check('dedup_hardlink', 'allow hard links for dedup'),
      pick('hash', 'Hash', [['', 'SHA-256'], ['blake3', 'BLAKE3']])),
    el('div', { class: 'row wrap' }, check('preflight', 'Check room to receive first (data and metadata)'),
      line('reserve_gb', 'Keep free (GiB)', '1', { size: 5, inputmode: 'numeric' }),
      pick('extent_dedup', 'duperemove the destination', [['', 'never'], ['weekly', 'weekly'], ['monthly', 'monthly']])));
}
function alertMv(msg, cls = 'st-failed') { const m = $('#mvmsg'); m.hidden = false; m.textContent = msg; m.className = cls; }
async function checkPlan() {
  try {
    MV.result = await (await postJSON('/api/moves/check', MV.plan)).json();
    renderMoves();
  } catch (err) { alertMv(err.message); }
}
async function savePlan() {
  const p = MV.plan;
  try {
    const r = p.id
      ? await (await api(`/api/moves/${p.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(p) })).json()
      : await (await postJSON('/api/moves', p)).json();
    MV.dirty = false;
    await loadMoves(r.id);
    alertMv('Saved.', 'st-ok');
    return r.id;
  } catch (err) { alertMv(err.message); return null; }
}
async function copyPlan() {
  if (MV.dirty && !confirm('The copy is made from the saved plan, without your unsaved changes. Continue?')) return;
  try {
    const copy = await (await api(`/api/moves/${MV.plan.id}/copy`, { method: 'POST' })).json();
    MV.dirty = false; MV.result = null;
    await loadMoves(copy.id);
  } catch (err) { alert(err.message); }
}
function exportPlan() {   // the same shape `storageforge-index moves import` reads
  const { name, steps } = MV.plan;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify({ name, steps }, null, 2)], { type: 'application/json' }));
  a.download = `${(name || 'move-plan').replace(/[^\w.-]+/g, '-')}.json`;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
async function downloadScript() {
  const id = MV.dirty || !MV.plan.id ? await savePlan() : MV.plan.id;
  if (!id) return;
  try {
    const res = await api(`/api/moves/${id}/script`);
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (res.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'move.sh';
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    alertMv(`Downloaded ${a.download}. Make it executable (chmod +x) and start with ./${a.download} for the read-only report.`, 'st-ok');
  } catch (err) { alertMv(err.message); }
}
async function deployPlan() {   // the Deploy tab runs the read-only report on every host first
  const id = MV.dirty || !MV.plan.id ? await savePlan() : MV.plan.id;
  if (id) startDeploy('jobs', id, 'report', `move plan "${MV.plan.name}"`);
}
async function delPlan() {
  if (!confirm(`Delete the plan "${MV.plan.name}"? Scripts you downloaded keep working.`)) return;
  try { await api(`/api/moves/${MV.plan.id}`, { method: 'DELETE' }); MV.plan = null; MV.dirty = false; loadMoves(); }
  catch (err) { alertMv(err.message); }
}
/* from the topology: start a step at a mount point */
function moveFrom(host, path) {
  if (!MV.plan) MV.plan = { name: '', steps: [] };
  MV.plan.steps.push(blankStep({ host, path })); MV.dirty = true; MV.result = null;
  showTab('moves');
}
