'use strict';
/* Git tab and Git Inspector drawer: repository discovery, live status checks,
   remote sync (fetch, pull, push, sync), commit history and changelog generator. */

const GITV = { data: null, filter: '', textFilter: '', all: false, selectedRepo: null };
const GITD = { repo: null, tab: 'status', status: null, history: null, syncLog: '', loading: false, diffSha: null, diffOutput: '' };

const GIT_STATE = {
  uncommitted: ['local-only', 'Uncommitted changes in the working copy'],
  unpushed: ['local-only', 'Commits not pushed to its upstream'],
  behind: ['local-only', 'Another copy has newer commits'],
  'single copy': ['broken', 'No copy of this history on any scanned machine'],
  copied: ['unknown', 'Another scanned machine has this history'],
  archived: ['protected', 'A bare archive copy exists on another machine'],
  error: ['broken', 'git could not read it'],
};

const ago = (t) => {
  if (!t) return 'no commits';
  const d = (Date.now() / 1000 - t) / 86400;
  return d < 1 ? 'today' : d < 60 ? `${Math.round(d)} days ago` : d < 730 ? `${Math.round(d / 30)} months ago` : `${Math.round(d / 365)} years ago`;
};

async function loadGit() {
  const box = $('#gitbox');
  if (!box) return;
  const qs = new URLSearchParams();
  if (S.host) qs.set('host', S.host);
  if (GITV.all) qs.set('all', '1');
  try {
    GITV.data = await getJSON(`/api/git?${qs}`);
  } catch (err) {
    box.replaceChildren(text('p', err.message, 'st-failed'));
    return;
  }
  renderGit();
  updateDrawerRepoInfo();
}

/* ── Find / Survey repos on demand ───────────────────────────────── */
async function findRepos() {
  const msg = $('#git-scan-msg');
  const btn = $('#git-find-btn');
  if (btn) btn.disabled = true;
  if (msg) { msg.textContent = 'Searching hosts for repositories...'; msg.className = 'muted small'; }
  try {
    const res = await api('/api/git/survey', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: S.host || undefined }),
    });
    const data = await res.json();
    if (msg) {
      if (data.results) {
        const total = data.results.reduce((acc, r) => acc + (r.repos || 0), 0);
        msg.textContent = `Found ${total} repositories across ${data.results.length} host(s)`;
      } else {
        msg.textContent = `Found ${data.repos ?? 0} repositories on ${data.host || S.host || 'host'}`;
      }
      msg.className = 'st-ok small';
    }
    await loadGit();
  } catch (err) {
    if (msg) { msg.textContent = `Failed: ${err.message}`; msg.className = 'st-failed small'; }
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ── Render Git Tab ──────────────────────────────────────────────── */
function renderGit() {
  const box = $('#gitbox');
  if (!box) return;
  if (!GITV.data || !GITV.data.repos.length) {
    box.replaceChildren(text('p', 'No repositories yet. Click "Find repos" above or scan a host to discover working copies and bare repositories.', 'muted'));
    return;
  }
  const { repos, summary } = GITV.data;

  const chips = el('div', { class: 'row chips' },
    button(`All ${repos.length}`, () => { GITV.filter = ''; renderGit(); }, `chip${GITV.filter ? '' : ' on'}`),
    ...Object.entries(summary).filter(([, n]) => n).map(([k, n]) => {
      const b = button(`${k} ${n}`, () => { GITV.filter = k; renderGit(); }, `chip${GITV.filter === k ? ' on' : ''}`);
      b.title = GIT_STATE[k] ? GIT_STATE[k][1] : '';
      return b;
    })
  );

  let shown = repos.filter((r) => !GITV.filter || r.state === GITV.filter);
  if (GITV.textFilter) {
    const q = GITV.textFilter.toLowerCase();
    shown = shown.filter((r) => r.name.toLowerCase().includes(q) || r.path.toLowerCase().includes(q) || r.host.toLowerCase().includes(q));
  }

  const all = el('input', { type: 'checkbox', onchange: () => { GITV.all = all.checked; loadGit(); } });
  all.checked = GITV.all;
  const toggle = el('label', { class: 'check' }, all, GITV.all ? 'Showing caches and build checkouts' : `Show ${GITV.data.hidden} in caches and build trees`);

  const listItems = shown.map((r) => {
    const [cls, why] = GIT_STATE[r.state] || ['unknown', ''];
    const p = text('span', r.state, `pill ${cls}`); p.title = why;
    const meta = [
      r.bare ? 'bare' : r.branch || 'detached',
      `${r.refs ?? '?'} refs`,
      r.size_kb ? fmtBytes(r.size_kb * 1024) : null,
      r.dirty ? `${r.dirty} changed` : null,
      r.ahead ? `${r.ahead} ahead` : null,
      r.behind ? `${r.behind} behind` : null,
    ].filter(Boolean).join(' · ');

    const inspectBtn = button('▾ Inspect', () => openGitDrawer(r, 'status'), 'btn pri sm');
    inspectBtn.title = 'Open live status, commits, changelog and sync in bottom drawer';

    const checkBtn = button('Check status', async () => {
      checkBtn.disabled = true;
      checkBtn.textContent = 'Checking...';
      try {
        await checkRepoStatus(r.host, r.path);
        openGitDrawer(r, 'status');
      } finally {
        checkBtn.disabled = false;
        checkBtn.textContent = 'Check status';
      }
    }, 'btn ghost sm');

    const canSync = (r.remotes && r.remotes.length) || r.upstream;
    const syncBtn = canSync ? button('Sync', () => openGitDrawer(r, 'sync'), 'btn ghost sm') : null;

    return el('li', { class: 'card' },
      el('div', { class: 'row' }, el('b', {}, r.name), p),
      el('span', { class: 'mono small' }, `${r.host}:${r.path}`),
      el('span', { class: 'muted small' }, meta),
      r.head_subject ? el('span', { class: 'small' }, `${ago(r.head_time)}: ${r.head_subject}`) : el('span', { class: 'muted small' }, r.error || 'no commits'),
      r.remotes && r.remotes.length ? el('span', { class: 'muted small mono' }, r.remotes.map((x) => `${x.name} ${x.url}`).join('  ')) : '',
      r.copies && r.copies.length ? el('ul', { class: 'copies small' }, ...r.copies.map((c) =>
        el('li', {}, `${c.same_head ? '=' : c.head_time > (r.head_time || 0) ? '↑ newer' : '↓ older'}  ${c.host}:${c.path}${c.bare ? ' (bare)' : ''}`))) : '',
      el('div', { class: 'row end' },
        inspectBtn,
        checkBtn,
        syncBtn,
        button('Archive to…', () => archiveRepo(r), 'btn ghost sm')
      )
    );
  });

  box.replaceChildren(chips, toggle, el('ol', { class: 'gitlist' }, ...listItems));
}

function archiveRepo(r) {
  if (!MV.plan) MV.plan = { name: '', steps: [] };
  if (!MV.plan.name) MV.plan.name = 'Git archives';
  const s = blankStep({ host: r.host, path: r.path }, { host: '', path: `/srv/git-archive/${r.name}.git` });
  s.method = 'git';
  MV.plan.steps.push(s); MV.dirty = true; MV.result = null;
  showTab('moves');
}

/* ── Git Drawer / Inspector (bottom corner of detail panel) ──────── */
function openGitDrawer(repo, tab = 'status') {
  GITD.repo = repo;
  const drawer = $('#gitdrawer');
  if (!drawer) return;
  drawer.classList.remove('collapsed');

  updateDrawerRepoInfo();
  switchGitTab(tab);
}

function closeGitDrawer() {
  const drawer = $('#gitdrawer');
  if (drawer) drawer.classList.add('collapsed');
}

function toggleGitDrawer() {
  const drawer = $('#gitdrawer');
  if (!drawer) return;
  if (drawer.classList.contains('collapsed')) {
    if (!GITD.repo && GITV.data && GITV.data.repos.length) {
      GITD.repo = GITV.data.repos[0];
    }
    drawer.classList.remove('collapsed');
    updateDrawerRepoInfo();
    switchGitTab(GITD.tab || 'status');
  } else {
    drawer.classList.add('collapsed');
  }
}

function updateDrawerRepoInfo() {
  const r = GITD.repo;
  const title = $('#gitdrawer-title');
  const host = $('#gitdrawer-host');
  const path = $('#gitdrawer-path');
  const pillEl = $('#gitdrawer-pill');
  const quickSync = $('#gitdrawer-btn-sync');

  if (!r) {
    if (title) title.textContent = 'Git Inspector';
    if (host) host.textContent = '';
    if (path) path.textContent = 'Select a repository to inspect';
    if (pillEl) pillEl.hidden = true;
    if (quickSync) quickSync.hidden = true;
    return;
  }

  if (title) title.textContent = `${r.name || 'Repository'}`;
  if (host) host.textContent = r.host;
  if (path) { path.textContent = r.path; path.title = `${r.host}:${r.path}`; }

  if (pillEl) {
    pillEl.hidden = false;
    const [cls] = GIT_STATE[r.state] || ['unknown'];
    pillEl.className = `pill sm ${cls}`;
    pillEl.textContent = r.state || 'unknown';
  }

  if (quickSync) {
    const canSync = (r.remotes && r.remotes.length) || r.upstream;
    quickSync.hidden = !canSync;
  }
}

function switchGitTab(tabName) {
  GITD.tab = tabName;
  const nav = $('#gitdrawer-nav');
  if (nav) {
    nav.querySelectorAll('button').forEach((b) => {
      const on = b.dataset.gtab === tabName;
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', on);
    });
  }

  const content = $('#gitdrawer-content');
  if (!content) return;
  content.querySelectorAll('.gtab-pane').forEach((p) => {
    p.hidden = p.id !== `gtab-${tabName}`;
  });

  if (!GITD.repo) {
    content.querySelector(`#gtab-${tabName}`).replaceChildren(
      text('p', 'Select a repository from the Git tab or Details panel to inspect.', 'muted')
    );
    return;
  }

  if (tabName === 'status') renderDrawerStatus();
  else if (tabName === 'commits') renderDrawerCommits();
  else if (tabName === 'changelog') renderDrawerChangelog();
  else if (tabName === 'sync') renderDrawerSync();
}

/* ── Live Status Check ───────────────────────────────────────────── */
async function checkRepoStatus(host, path) {
  try {
    const res = await api('/api/git/status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, path }),
    });
    const status = await res.json();
    GITD.status = status;

    // Update in GITV.data if present
    if (GITV.data && GITV.data.repos) {
      const idx = GITV.data.repos.findIndex((r) => r.host === host && r.path === path);
      if (idx !== -1) {
        Object.assign(GITV.data.repos[idx], status);
        renderGit();
      }
    }
    if (GITD.repo && GITD.repo.host === host && GITD.repo.path === path) {
      Object.assign(GITD.repo, status);
      updateDrawerRepoInfo();
      if (GITD.tab === 'status') renderDrawerStatus();
    }
    return status;
  } catch (err) {
    if (GITD.tab === 'status') {
      const pane = $('#gtab-status');
      if (pane) pane.replaceChildren(text('p', `Status check failed: ${err.message}`, 'st-failed'));
    }
    throw err;
  }
}

function renderDrawerStatus() {
  const pane = $('#gtab-status');
  if (!pane || !GITD.repo) return;
  const r = GITD.status || GITD.repo;

  const cards = el('div', { class: 'git-status-grid' },
    el('div', { class: 'git-stat-card' },
      el('small', {}, 'Branch'),
      el('b', {}, r.bare ? 'bare mirror' : r.branch || 'detached HEAD')
    ),
    el('div', { class: 'git-stat-card' },
      el('small', {}, 'Working Tree'),
      el('b', { class: r.dirty ? 'st-failed' : 'st-ok' }, r.dirty ? `${r.dirty} uncommitted files` : 'Clean')
    ),
    el('div', { class: 'git-stat-card' },
      el('small', {}, 'Upstream Tracking'),
      el('b', {}, r.upstream ? `${r.upstream} (↑${r.ahead || 0} ↓${r.behind || 0})` : 'None')
    ),
    el('div', { class: 'git-stat-card' },
      el('small', {}, 'Latest Commit'),
      el('b', { class: 'mono small' }, r.head_commit ? r.head_commit.slice(0, 8) : 'None'),
      el('span', { class: 'small muted' }, r.head_subject || '')
    )
  );

  const actions = el('div', { class: 'row' },
    button('Check status now', async () => {
      pane.replaceChildren(text('p', 'Running git status check over SSH...', 'muted'));
      await checkRepoStatus(r.host, r.path);
    }, 'btn pri sm'),
    button('Fast Sync', () => { switchGitTab('sync'); }, 'btn ghost sm'),
    button('History & Commits', () => { switchGitTab('commits'); }, 'btn ghost sm'),
    button('Archive to…', () => archiveRepo(r), 'btn ghost sm')
  );

  const parts = [cards, actions];

  // Dirty files section
  if (r.dirty_files && r.dirty_files.length) {
    const list = el('ul', { class: 'git-dirty-list' }, ...r.dirty_files.map((f) =>
      el('li', { class: 'git-dirty-item' },
        el('span', { class: `git-file-code ${f.code.trim()}` }, f.code),
        el('span', { class: 'small mono' }, f.path)
      )
    ));
    parts.push(el('div', {}, el('h4', { class: 'small muted' }, `Modified & untracked files (${r.dirty_files.length})`), list));
  }

  // Remotes section
  if (r.remotes && r.remotes.length) {
    parts.push(el('div', {},
      el('h4', { class: 'small muted' }, 'Configured Remotes'),
      el('ul', { class: 'git-dirty-list' }, ...r.remotes.map((rm) =>
        el('li', { class: 'git-dirty-item' },
          el('b', {}, rm.name),
          el('span', { class: 'mono small muted' }, rm.url || rm.fetch_url || '')
        )
      ))
    ));
  }

  // Fleet copies section
  if (r.copies && r.copies.length) {
    parts.push(el('div', { class: 'git-copy-box stack' },
      el('h4', { class: 'small muted' }, `Fleet Copies (${r.copies.length})`),
      el('ul', { class: 'git-dirty-list' }, ...r.copies.map((c) =>
        el('li', { class: 'git-dirty-item' },
          el('span', { class: `pill sm ${c.same_head ? 'protected' : c.newer ? 'local-only' : 'unknown'}` },
            c.same_head ? 'In sync' : c.newer ? 'Newer' : 'Older'),
          el('span', { class: 'mono small' }, `${c.host}:${c.path}${c.bare ? ' (bare)' : ''}`)
        )
      ))
    ));
  }

  pane.replaceChildren(...parts);
}

/* ── Commits History View ────────────────────────────────────────── */
async function loadRepoHistory(host, path) {
  const pane = $('#gtab-commits');
  if (pane) pane.replaceChildren(text('p', 'Loading commit history and tags...', 'muted'));
  try {
    const res = await api(`/api/git/history?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}&max=50`);
    GITD.history = await res.json();
    if (GITD.tab === 'commits') renderDrawerCommits();
    if (GITD.tab === 'changelog') renderDrawerChangelog();
  } catch (err) {
    if (pane) pane.replaceChildren(text('p', `Failed to load history: ${err.message}`, 'st-failed'));
  }
}

async function showCommitDiff(sha, targetEl) {
  if (GITD.diffSha === sha) {
    GITD.diffSha = null;
    targetEl.replaceChildren();
    return;
  }
  GITD.diffSha = sha;
  targetEl.replaceChildren(text('p', 'Loading commit stat...', 'muted small'));
  try {
    const res = await api(`/api/git/commit?host=${encodeURIComponent(GITD.repo.host)}&path=${encodeURIComponent(GITD.repo.path)}&sha=${encodeURIComponent(sha)}`);
    const data = await res.json();
    targetEl.replaceChildren(el('pre', { class: 'git-commit-diff' }, data.output));
  } catch (err) {
    targetEl.replaceChildren(text('p', err.message, 'st-failed small'));
  }
}

function renderDrawerCommits() {
  const pane = $('#gtab-commits');
  if (!pane || !GITD.repo) return;
  if (!GITD.history) {
    loadRepoHistory(GITD.repo.host, GITD.repo.path);
    return;
  }
  const { commits, tags } = GITD.history;
  if (!commits || !commits.length) {
    pane.replaceChildren(text('p', 'No commits found in this repository.', 'muted'));
    return;
  }

  const headRow = el('div', { class: 'row' },
    el('b', {}, `Commits (${commits.length})`),
    tags && tags.length ? el('span', { class: 'muted small' }, `${tags.length} tag(s)`) : '',
    button('Refresh', () => loadRepoHistory(GITD.repo.host, GITD.repo.path), 'btn ghost xs')
  );

  const list = el('ol', { class: 'git-commit-list' }, ...commits.map((c) => {
    const diffBox = el('div', {});
    const item = el('li', { class: 'git-commit-item' },
      el('div', { class: 'git-commit-head' },
        el('span', { class: 'git-sha' }, c.short_hash || c.hash.slice(0, 7)),
        c.refs ? el('span', { class: 'pill sm unknown mono' }, c.refs) : '',
        el('span', { class: 'git-commit-meta' }, ago(c.time))
      ),
      el('div', { class: 'git-commit-subj' }, c.subject),
      el('div', { class: 'git-commit-meta' }, `${c.author} · ${c.email}`),
      diffBox
    );
    item.addEventListener('click', (ev) => {
      if (ev.target.tagName !== 'BUTTON' && ev.target.tagName !== 'A') {
        showCommitDiff(c.hash, diffBox);
      }
    });
    return item;
  }));

  pane.replaceChildren(headRow, list);
}

/* ── Changelog Generator View ────────────────────────────────────── */
function renderDrawerChangelog() {
  const pane = $('#gtab-changelog');
  if (!pane || !GITD.repo) return;
  if (!GITD.history) {
    loadRepoHistory(GITD.repo.host, GITD.repo.path);
    return;
  }
  const { changelog } = GITD.history;
  if (!changelog || !changelog.length) {
    pane.replaceChildren(text('p', 'No changelog entries could be extracted from commits.', 'muted'));
    return;
  }

  const copyBtn = button('Copy Markdown', () => {
    let md = `# Changelog - ${GITD.repo.name}\n\n`;
    for (const rel of changelog) {
      md += `## ${rel.version} ${rel.date ? '(' + new Date(rel.date * 1000).toISOString().slice(0, 10) + ')' : ''}\n\n`;
      for (const [catName, items] of Object.entries(rel.categories)) {
        if (!items || !items.length) continue;
        const heading = catName === 'features' ? 'Features' :
                        catName === 'fixes' ? 'Bug Fixes' :
                        catName === 'docs' ? 'Documentation' :
                        catName === 'perf' ? 'Performance' :
                        catName === 'maintenance' ? 'Maintenance' : 'Other';
        md += `### ${heading}\n`;
        for (const it of items) {
          md += `- ${it.subject} (${it.short_hash})\n`;
        }
        md += '\n';
      }
    }
    navigator.clipboard.writeText(md).then(() => {
      copyBtn.textContent = 'Copied!';
      setTimeout(() => { copyBtn.textContent = 'Copy Markdown'; }, 2000);
    });
  }, 'btn ghost xs');

  const topRow = el('div', { class: 'row' },
    el('b', {}, 'Version History & Changelog'),
    copyBtn
  );

  const entries = changelog.map((rel) => {
    const cats = [];
    const catLabels = {
      features: '✨ Features',
      fixes: '🐛 Bug Fixes',
      docs: '📝 Documentation',
      perf: '⚡ Performance',
      maintenance: '🔧 Maintenance & Refactor',
      other: '📌 Other Changes',
    };

    for (const [key, label] of Object.entries(catLabels)) {
      const items = rel.categories[key];
      if (items && items.length) {
        cats.push(el('div', { class: 'git-cl-cat' },
          el('h4', {}, `${label} (${items.length})`),
          el('ul', { class: 'git-cl-list' }, ...items.map((it) =>
            el('li', {},
              el('span', { class: 'mono small' }, `${it.short_hash} `),
              el('span', {}, it.subject)
            )
          ))
        ));
      }
    }

    return el('div', { class: 'git-cl-release' },
      el('div', { class: 'git-cl-header' },
        el('b', {}, rel.version),
        el('span', { class: 'muted small' }, rel.date ? new Date(rel.date * 1000).toISOString().slice(0, 10) : `${rel.count} commits`)
      ),
      ...cats
    );
  });

  pane.replaceChildren(topRow, ...entries);
}

/* ── Remote Sync View ────────────────────────────────────────────── */
async function syncRepo(host, path, action = 'sync') {
  const pane = $('#gtab-sync');
  const term = $('#git-sync-term');
  const btns = pane ? pane.querySelectorAll('button') : [];
  btns.forEach((b) => { b.disabled = true; });

  if (term) {
    term.textContent = `[${new Date().toLocaleTimeString()}] Executing git ${action} on ${host}:${path}...\n`;
  }

  try {
    const res = await api('/api/git/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, path, action }),
    });
    const result = await res.json();
    if (term) {
      term.textContent += (result.output || '') + '\n';
      if (result.ok) {
        term.textContent += `==> Sync completed successfully (exit code 0).\n`;
      } else {
        term.textContent += `==> Error: ${result.error || 'Failed'}\n`;
      }
    }
    if (result.status) {
      GITD.status = result.status;
      if (GITD.repo) Object.assign(GITD.repo, result.status);
      updateDrawerRepoInfo();
    }
  } catch (err) {
    if (term) {
      term.textContent += `\nError executing sync: ${err.message}\n`;
    }
  } finally {
    btns.forEach((b) => { b.disabled = false; });
  }
}

function renderDrawerSync() {
  const pane = $('#gtab-sync');
  if (!pane || !GITD.repo) return;
  const r = GITD.status || GITD.repo;

  const remotesList = r.remotes && r.remotes.length
    ? r.remotes.map((rm) => `${rm.name}: ${rm.url || rm.fetch_url || ''}`).join('\n')
    : 'No remotes configured.';

  const infoBox = el('div', { class: 'git-copy-box' },
    el('div', { class: 'row' }, el('b', {}, 'Sync Status:'), text('span', r.upstream ? `Tracking ${r.upstream}` : 'No upstream branch')),
    el('div', { class: 'mono small muted', style: 'margin-top:4px' }, remotesList)
  );

  const actions = el('div', { class: 'row' },
    button('Full Sync (Fetch + Pull)', () => syncRepo(r.host, r.path, 'sync'), 'btn pri sm'),
    button('Fetch All', () => syncRepo(r.host, r.path, 'fetch'), 'btn sm'),
    button('Fast-Forward Pull', () => syncRepo(r.host, r.path, 'pull'), 'btn sm'),
    button('Push Upstream', () => syncRepo(r.host, r.path, 'push'), 'btn ghost sm')
  );

  const term = el('pre', { id: 'git-sync-term', class: 'git-term' },
    `Ready to sync ${r.host}:${r.path}.\nSelect an action above to fetch, pull or synchronize commits with configured remotes.`
  );

  pane.replaceChildren(infoBox, actions, term);
}

/* ── Open Git for a specific path (from Details or Topology) ────── */
async function openGitForPath(host, path) {
  if (!GITV.data) await loadGit();
  const repos = (GITV.data && GITV.data.repos) || [];
  const p = path.replace(/\/$/, '');
  const r = repos.find((x) => x.host === host && (x.path === p || x.path.startsWith(p + '/')));
  if (r) {
    openGitDrawer(r, 'status');
  } else {
    // If no indexed repo found, open drawer with mock repo and check status on-demand
    openGitDrawer({ host, path: p, name: p.split('/').pop() || p, state: 'unknown' }, 'status');
    checkRepoStatus(host, p);
  }
}

/* ── Event Wiring ────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  const toggleBtn = $('#gitdrawer-toggle');
  if (toggleBtn) toggleBtn.addEventListener('click', toggleGitDrawer);

  const closeBtn = $('#gitdrawer-close');
  if (closeBtn) closeBtn.addEventListener('click', closeGitDrawer);

  const quickSyncBtn = $('#gitdrawer-btn-sync');
  if (quickSyncBtn) {
    quickSyncBtn.addEventListener('click', () => {
      if (GITD.repo) {
        openGitDrawer(GITD.repo, 'sync');
        syncRepo(GITD.repo.host, GITD.repo.path, 'sync');
      }
    });
  }

  const nav = $('#gitdrawer-nav');
  if (nav) {
    nav.addEventListener('click', (ev) => {
      const b = ev.target.closest('button[data-gtab]');
      if (b) switchGitTab(b.dataset.gtab);
    });
  }

  const findBtn = $('#git-find-btn');
  if (findBtn) findBtn.addEventListener('click', findRepos);

  const filterInput = $('#git-filter-text');
  if (filterInput) {
    filterInput.addEventListener('input', () => {
      GITV.textFilter = filterInput.value.trim();
      renderGit();
    });
  }
});
