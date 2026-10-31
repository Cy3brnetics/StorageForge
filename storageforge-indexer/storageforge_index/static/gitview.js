'use strict';
/* Git tab: every repository the scans found, its state, and its copies on other machines. "Archive to…" starts a
   Moves step that keeps a bare mirror elsewhere. Loaded after moves.js; uses its helpers. */

const GITV = { data: null, filter: '', all: false, picked: new Set() };
const GIT_STATE = {
  uncommitted: ['local-only', 'Uncommitted changes in the working copy'],
  unpushed: ['local-only', 'Commits not pushed to its upstream'],
  behind: ['local-only', 'Another copy has newer commits'],
  'single copy': ['broken', 'No copy of this history on any scanned machine'],
  copied: ['unknown', 'Another scanned machine has this history'],
  archived: ['protected', 'A bare archive copy exists on another machine'],
  error: ['broken', 'git could not read it'],
};

async function loadGit() {
  const box = $('#gitbox');
  const qs = new URLSearchParams(); if (S.host) qs.set('host', S.host); if (GITV.all) qs.set('all', '1');
  try { [GITV.data, GITV.hosts] = await Promise.all([getJSON(`/api/git?${qs}`), getJSON('/api/hosts').then((h) => h.indexed.map((x) => x.hostname).sort())]); }
  catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); return; }
  renderGit();
}
const ago = (t) => {
  if (!t) return 'no commits';
  const d = (Date.now() / 1000 - t) / 86400;
  return d < 1 ? 'today' : d < 60 ? `${Math.round(d)} days ago` : d < 730 ? `${Math.round(d / 30)} months ago` : `${Math.round(d / 365)} years ago`;
};
function renderGit() {
  const { repos, summary } = GITV.data;
  if (!repos.length) {
    $('#gitbox').replaceChildren(text('p', 'No repositories yet. Scans find them from the next scan of each host (working copies and bare repositories).', 'muted'));
    return;
  }
  const chips = el('div', { class: 'row chips' }, button(`All ${repos.length}`, () => { GITV.filter = ''; renderGit(); }, `chip${GITV.filter ? '' : ' on'}`),
    ...Object.entries(summary).filter(([, n]) => n).map(([k, n]) => {
      const b = button(`${k} ${n}`, () => { GITV.filter = k; renderGit(); }, `chip${GITV.filter === k ? ' on' : ''}`);
      b.title = GIT_STATE[k][1]; return b;
    }));
  const shown = repos.filter((r) => !GITV.filter || r.state === GITV.filter);
  const all = el('input', { type: 'checkbox', onchange: () => { GITV.all = all.checked; loadGit(); } }); all.checked = GITV.all;
  const toggle = el('label', { class: 'check' }, all, GITV.all ? 'Showing caches and build checkouts' : `Show ${GITV.data.hidden} in caches and build trees`);
  const key = (r) => `${r.host}:${r.path}`;
  const target = el('select', { 'aria-label': 'Archive to host' }, new Option('host…', ''), ...(GITV.hosts || []).map((h) => new Option(h, h)));
  const singles = repos.filter((r) => r.state === 'single copy');
  const bulk = el('div', { class: 'row wrap' },
    singles.length ? button(`Select ${singles.length} single-copy`, () => { singles.forEach((r) => GITV.picked.add(key(r))); renderGit(); }, 'btn ghost sm') : '',
    GITV.picked.size ? button('Clear', () => { GITV.picked.clear(); renderGit(); }, 'btn ghost sm') : '',
    target, button(`Archive ${GITV.picked.size} selected`, () => archiveSelected(target.value), 'btn sm'));
  $('#gitbox').replaceChildren(chips, toggle, ignoreEditor(), bulk, el('ol', { class: 'gitlist' }, ...shown.map((r) => {
    const pick = el('input', { type: 'checkbox', 'aria-label': `Select ${r.name}`, onchange: () => {
      if (pick.checked) GITV.picked.add(key(r)); else GITV.picked.delete(key(r)); renderGit();
    } }); pick.checked = GITV.picked.has(key(r));
    const [cls, why] = GIT_STATE[r.state] || ['unknown', ''];
    const p = text('span', r.state, `pill ${cls}`); p.title = why;
    const meta = [r.bare ? 'bare' : r.branch || 'detached', `${r.refs ?? '?'} refs`, r.size_kb ? fmtBytes(r.size_kb * 1024) : null,
                  r.dirty ? `${r.dirty} changed` : null, r.ahead ? `${r.ahead} ahead` : null, r.behind ? `${r.behind} behind` : null].filter(Boolean).join(' · ');
    return el('li', { class: 'card' },
      el('div', { class: 'row' }, pick, el('b', {}, r.name), p),
      el('span', { class: 'mono small' }, `${r.host}:${r.path}`),
      el('span', { class: 'muted small' }, meta),
      r.head_subject ? el('span', { class: 'small' }, `${ago(r.head_time)}: ${r.head_subject}`) : el('span', { class: 'muted small' }, r.error || 'no commits'),
      r.remotes.length ? el('span', { class: 'muted small mono' }, r.remotes.map((x) => `${x.name} ${x.url}`).join('  ')) : '',
      r.copies.length ? el('ul', { class: 'copies small' }, ...r.copies.map((c) =>
        el('li', {}, `${c.same_head ? '=' : c.head_time > (r.head_time || 0) ? '↑ newer' : '↓ older'}  ${c.host}:${c.path}${c.bare ? ' (bare)' : ''}`))) : '',
      el('div', { class: 'row end' }, button('Archive to…', () => archiveRepo(r), 'btn ghost sm')));
  })));
}
function ignoreEditor() {
  const host = S.host || '';
  const list = el('textarea', { rows: 3, class: 'mono', 'aria-label': 'Paths to hide', placeholder: '/scratch/\n!/.cache/keep-this/' });
  list.value = ((GITV.data.ignore || {})[host || '*'] || []).join('\n');
  const save = button('Save', async () => {
    try {
      await api('/api/git/ignore', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host, paths: list.value.split('\n') }) });
      await loadGit();
    } catch (err) { alert(err.message); }
  }, 'btn sm');
  return el('details', {}, el('summary', {}, `Hide repositories ${host ? `on ${host}` : 'on every host'}`),
    text('p', 'One path fragment per line. A line starting with ! shows matching repositories even if they would be hidden.', 'muted small'), list, save);
}
function addArchiveStep(r, dstHost) {
  if (!MV.plan) MV.plan = { name: '', steps: [] };
  if (!MV.plan.name) MV.plan.name = 'Git archives';
  const s = blankStep({ host: r.host, path: r.path }, { host: dstHost, path: `/srv/git-archive/${r.name}.git` });
  s.method = 'git';
  MV.plan.steps.push(s); MV.dirty = true; MV.result = null;
}
function archiveRepo(r) {
  addArchiveStep(r, '');
  showTab('moves');
}
function archiveSelected(dstHost) {
  const repos = GITV.data.repos.filter((r) => GITV.picked.has(`${r.host}:${r.path}`) && r.host !== dstHost);
  if (!dstHost || !repos.length) { alert(dstHost ? 'Select repositories on other hosts first.' : 'Pick the host to archive to first.'); return; }
  repos.forEach((r) => addArchiveStep(r, dstHost));
  GITV.picked.clear();
  showTab('moves');
}
