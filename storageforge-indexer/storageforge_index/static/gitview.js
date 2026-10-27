'use strict';
/* Git tab: every repository the scans found, its state, and its copies on other machines. "Archive to…" starts a
   Moves step that keeps a bare mirror elsewhere. Loaded after moves.js; uses its helpers. */

const GITV = { data: null, filter: '', all: false };
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
  try { GITV.data = await getJSON(`/api/git?${qs}`); }
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
  $('#gitbox').replaceChildren(chips, toggle, el('ol', { class: 'gitlist' }, ...shown.map((r) => {
    const [cls, why] = GIT_STATE[r.state] || ['unknown', ''];
    const p = text('span', r.state, `pill ${cls}`); p.title = why;
    const meta = [r.bare ? 'bare' : r.branch || 'detached', `${r.refs ?? '?'} refs`, r.size_kb ? fmtBytes(r.size_kb * 1024) : null,
                  r.dirty ? `${r.dirty} changed` : null, r.ahead ? `${r.ahead} ahead` : null, r.behind ? `${r.behind} behind` : null].filter(Boolean).join(' · ');
    return el('li', { class: 'card' },
      el('div', { class: 'row' }, el('b', {}, r.name), p),
      el('span', { class: 'mono small' }, `${r.host}:${r.path}`),
      el('span', { class: 'muted small' }, meta),
      r.head_subject ? el('span', { class: 'small' }, `${ago(r.head_time)}: ${r.head_subject}`) : el('span', { class: 'muted small' }, r.error || 'no commits'),
      r.remotes.length ? el('span', { class: 'muted small mono' }, r.remotes.map((x) => `${x.name} ${x.url}`).join('  ')) : '',
      r.copies.length ? el('ul', { class: 'copies small' }, ...r.copies.map((c) =>
        el('li', {}, `${c.same_head ? '=' : c.head_time > (r.head_time || 0) ? '↑ newer' : '↓ older'}  ${c.host}:${c.path}${c.bare ? ' (bare)' : ''}`))) : '',
      el('div', { class: 'row end' }, button('Archive to…', () => archiveRepo(r), 'btn ghost sm')));
  })));
}
function archiveRepo(r) {
  if (!MV.plan) MV.plan = { name: '', steps: [] };
  if (!MV.plan.name) MV.plan.name = 'Git archives';
  const s = blankStep({ host: r.host, path: r.path }, { host: '', path: `/srv/git-archive/${r.name}.git` });
  s.method = 'git';
  MV.plan.steps.push(s); MV.dirty = true; MV.result = null;
  showTab('moves');
}
