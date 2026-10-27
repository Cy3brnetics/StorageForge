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
  const pick = el('select', { 'aria-label': 'Move plan', onchange: async () => {
    if (MV.dirty && !confirm('Discard unsaved changes to this plan?')) { pick.value = p.id || ''; return; }
    MV.dirty = false; MV.result = null; MV.plan = pick.value ? await getJSON(`/api/moves/${pick.value}`) : { name: '', steps: [] }; renderMoves();
  } }, new Option('New plan…', ''), ...MV.plans.map((x) => new Option(`${x.name} (${x.steps})`, x.id)));
  pick.value = p.id || '';
  const name = el('input', { type: 'text', placeholder: 'plan name, e.g. TR01 media to Archie', 'aria-label': 'Plan name',
    onchange: () => { p.name = name.value.trim(); touch(); } }); name.value = p.name || '';
  const steps = el('ol', { class: 'mvsteps' }, ...p.steps.map((s, i) => stepCard(s, i)));
  const res = MV.result;
  const total = res ? el('p', { class: res.crit ? 'st-failed' : res.warn ? 'st-running' : 'st-ok' },
    `${fmtBytes(res.bytes)} in all · about ${eta(res.eta_s)} · ${res.crit} critical · ${res.warn} warning${res.warn === 1 ? '' : 's'}`) : null;
  $('#movesbox').replaceChildren(
    el('div', { class: 'row' }, pick, name),
    steps,
    el('div', { class: 'row' }, button('+ Add step', () => { p.steps.push(blankStep()); touch(); renderMoves(); }, 'btn sm')),
    total || '',
    el('div', { class: 'row end' },
      p.id ? button('Delete plan', delPlan, 'btn ghost sm danger') : '',
      button('Check', checkPlan, 'btn sm'),
      el('button', { id: 'mvsave', type: 'button', class: 'btn sm', onclick: savePlan }, MV.dirty ? 'Save*' : 'Save'),
      button('Download script', downloadScript, 'btn pri sm')),
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
async function openBrowser(box, host, path, choose) {
  box.replaceChildren(text('p', 'Reading the index…', 'muted'));
  try {
    const r = await getJSON(`/api/browse?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}`);
    const up = r.path === '/' ? null : r.path.replace(/\/[^/]*$/, '') || '/';
    box.replaceChildren(
      el('div', { class: 'row' }, el('b', { class: 'mono' }, r.path),
        r.size ? text('span', `${fmtBytes(r.size.bytes)} · ${r.size.files.toLocaleString()} files`, 'muted') : text('span', r.indexed ? '' : 'not indexed', 'muted'),
        button('Use this folder', () => choose(r.path), 'btn pri sm')),
      el('ul', { class: 'dirs' },
        up ? el('li', {}, button('', () => openBrowser(box, host, up, choose), 'dir')) : '',
        ...r.dirs.map((d) => el('li', {}, button('', () => openBrowser(box, host, (r.path === '/' ? '' : r.path) + '/' + d.name, choose), 'dir')))));
    const btns = box.querySelectorAll('.dir');
    let k = 0;
    if (up) { btns[k++].append(text('span', '..', 'n')); }
    r.dirs.forEach((d) => { btns[k++].append(text('span', d.name + (d.mount ? `  (${d.mount} mount)` : ''), 'n'), text('span', d.bytes ? fmtBytes(d.bytes) : '', 's')); });
  } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); }
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
    const sch = el('select', { onchange: () => { o.schedule = sch.value; touch(); } }, ...['hourly', 'daily', 'weekly', 'monthly'].map((x) => new Option(x, x)));
    sch.value = o.schedule || 'daily';
    if (s.method !== 'rsnapshot') opts.append(el('label', { class: 'field' }, el('span', {}, 'Runs'), sch));
    else opts.append(el('div', { class: 'row keep' }, text('span', 'Keep', 'muted'), ...['hourly', 'daily', 'weekly', 'monthly'].map((k) => {
      const n = el('input', { type: 'number', min: 0, max: 999, 'aria-label': `${k} snapshots to keep`, onchange: () => { o.keep[k] = +n.value || 0; touch(); } });
      n.value = (o.keep || {})[k] || 0; return el('label', { class: 'field' }, el('span', {}, k), n);
    })));
  }
  const login = el('input', { type: 'text', placeholder: 'source login (default: its scan user), e.g. root@10.42.0.3', class: 'mono',
    'aria-label': 'Source SSH login', onchange: () => { o.src_login = login.value.trim() || null; touch(); } });
  login.value = o.src_login || '';
  const result = (MV.result && MV.result.steps[i]) || null;
  return el('li', { class: 'card mvstep' },
    el('div', { class: 'row' }, el('b', {}, `Step ${i + 1}`), method,
      el('span', { class: 'row tools' },
        i ? button('↑', () => { [p.steps[i - 1], p.steps[i]] = [p.steps[i], p.steps[i - 1]]; touch(); renderMoves(); }, 'btn ghost sm') : '',
        i < p.steps.length - 1 ? button('↓', () => { [p.steps[i + 1], p.steps[i]] = [p.steps[i], p.steps[i + 1]]; touch(); renderMoves(); }, 'btn ghost sm') : '',
        button('Remove', () => { p.steps.splice(i, 1); touch(); renderMoves(); }, 'btn ghost sm danger'))),
    text('p', METHOD_HELP[s.method], 'muted small'),
    endEditor(s, 'src', 'From'), endEditor(s, 'dst', 'To'),
    el('details', {}, el('summary', {}, 'Options'), opts, excl, s.src.host && s.dst.host && s.src.host !== s.dst.host ? login : ''),
    result ? el('ul', { class: 'mvcheck' }, ...result.items.map((it) => el('li', { class: `lv-${it.level}` }, it.text))) : '');
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
