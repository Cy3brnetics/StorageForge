'use strict';
/* Deploy tab: hosts set up for signed deploys, deployed rsync/rsnapshot jobs (state, runs, actions, snapshots), shares,
   drift, alerts and their channels. Every deploy runs the read-only report on each host first; Apply comes after.
   Loaded after dockerview.js; uses the shared helpers. */

const DP = { data: null, group: null, poll: 0, job: null, err: '', setup: null, settingsForm: null, openRuns: new Set(), cancelRequested: false };
const JOB_STATE = { ok: 'protected', failed: 'broken', stale: 'local-only', 'never-ran': 'unknown', paused: 'unknown' };
const RUN_LINE = /^\s{2}(ok|missing|conflict|->|other)\s/;

function when(ts) {
  if (!ts) return 'never';
  const s = Math.round(Date.now() / 1000 - ts), a = Math.abs(s);
  const t = a < 90 ? `${a} s` : a < 5400 ? `${Math.round(a / 60)} min` : a < 129600 ? `${Math.round(a / 3600)} h` : `${Math.round(a / 86400)} days`;
  return s >= 0 ? `${t} ago` : `in ${t}`;
}
const stamp = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '');

async function loadDeploy() {
  try {
    DP.data = await getJSON('/api/deploy');
    DP.err = '';
    // If no deploy panel is open, resume watching any active deploy from recent groups
    if (!DP.group && DP.data?.groups) {
      const active = DP.data.groups.find((g) => ['running', 'queued'].includes(g.state));
      if (active) {
        DP.group = { gid: active.group_id, kind: active.kind, ref: active.ref, mode: active.mode, title: active.title, extra: active.options, runs: [], done: false };
        pollGroup();
      }
    }
  } catch (err) { DP.err = err.message; }
  renderDeploy();
}

/* ── running a deploy: report first, then apply ─────────────────── */
async function startDeploy(kind, ref, mode, title, extra = {}) {
  showTab('deploy');
  DP.cancelRequested = false;
  try {
    const r = await (await postJSON('/api/deploy/start', { kind, ref, mode, ...extra })).json();
    DP.group = { gid: r.group, kind, ref, mode, title, extra, runs: [], done: false };
  } catch (err) {
    const body = err.body || {};
    DP.group = {
      kind, ref, mode, title, extra,
      error: err.message,
      stale: Boolean(body.stale),
      missingHosts: body.hosts || null,
      blockers: body.blockers || null,
      runs: [], done: true
    };
  }
  renderDeploy();
  if (DP.group?.gid) pollGroup();
}

async function cancelGroup(gid, force = false) {
  try {
    DP.cancelRequested = true;
    renderGroup();
    const r = await (await postJSON(`/api/deploy/groups/${gid}/cancel`, { force })).json();
    toast(force ? 'Deploy force stopped' : 'Cancel requested; stopping remaining hosts');
    pollGroup();
  } catch (err) { toast(err.message); }
}

async function retryGroup(gid) {
  toast('Retrying deploy…');
  try {
    const r = await (await postJSON(`/api/deploy/groups/${gid}/retry`, {})).json();
    DP.cancelRequested = false;
    DP.group = { gid: r.group, kind: r.kind, ref: r.ref, mode: r.mode, title: r.title, extra: r.extra, runs: [], done: false };
    renderDeploy();
    pollGroup();
  } catch (err) { toast(err.message); }
}

async function openGroup(gid, title, kind, ref, mode, extra = {}) {
  try {
    const data = await getJSON(`/api/deploy/groups/${gid}`);
    const g = data.group || {};
    DP.group = { gid, title: title || g.title, kind: kind || g.kind, ref: ref || g.ref, mode: mode || g.mode, extra: extra || g.options || {}, runs: data.runs || [], done: g.state !== 'running' };
    renderDeploy();
    if (!DP.group.done) pollGroup();
    $('#dpgroup')?.scrollIntoView({ block: 'start', behavior: 'smooth' });
  } catch (err) { toast(err.message); }
}

async function pollGroup() {
  clearTimeout(DP.poll);
  const g = DP.group;
  if (!g || !g.gid || g.done) return;
  try {
    const data = await getJSON(`/api/deploy/groups/${g.gid}`);
    g.runs = data.runs || [];
    const grp = data.group;
    if (grp) g.state = grp.state;
    g.done = g.runs.length > 0 && (
      ['ok', 'failed', 'incomplete', 'cancelled', 'interrupted'].includes(grp?.state) ||
      g.runs.every((r) => !['running', 'queued'].includes(r.status))
    );
  } catch (err) { g.error = err.message; g.done = true; }
  renderGroup();
  if (!g.done) DP.poll = setTimeout(pollGroup, 1000);
  else if (g.mode === 'apply') {
    loadDeploy();
    if (g.error) return;
    if (g.kind === 'changes') chApplied(g.ref);
    if (g.kind === 'jobs') loadMoves(!MV.dirty && MV.plan?.id === g.ref ? g.ref : undefined);
    setTimeout(followJobs, 1000);    // the group's rescans are queued as it ends; the graph and designs reload after them
  }
}

function outputBlock(out) {
  const pre = el('pre', { class: 'dpout' });
  for (const line of (out || '').split('\n')) {
    const m = line.match(RUN_LINE);
    pre.append(m ? text('span', line + '\n', `dl-${{ ok: 'ok', missing: 'miss', conflict: 'crit', '->': 'do', other: 'note' }[m[1]]}`) : line + '\n');
  }
  return pre;
}

function runCard(r, g) {
  const label = { ok: 'protected', failed: 'broken', refused: 'broken', incomplete: 'local-only', running: 'local-only', queued: 'unknown', skipped: 'unknown', cancelled: 'unknown' }[r.status] || 'unknown';
  const cardId = `dp-run-${r.run_id}`;
  const existing = document.getElementById(cardId);
  const wasOpen = existing ? existing.open : (DP.openRuns.has(r.run_id) || !g.done || r.status !== 'ok' || g.runs.length === 1);

  const summaryParts = [el('b', { class: 'mono' }, r.host), ` · ${r.kind}${r.mode === 'apply' ? '' : ' report'} · `, text('span', r.status, `pill ${label}`)];
  if (r.summary) {
    const sm = r.summary;
    const bits = [sm.ok ? `${sm.ok} ok` : '', sm.missing ? `${sm.missing} missing` : '', sm.conflict ? `${sm.conflict} conflict` : '', sm.did ? `${sm.did} did` : ''].filter(Boolean);
    if (bits.length) summaryParts.push(' · ', text('span', bits.join(', '), 'muted small'));
  }
  if (r.confirmed_at) {
    const confPill = r.host_exit === 0 ? text('span', 'confirmed by scan', 'pill protected small') : text('span', `scan: exit ${r.host_exit}`, 'pill broken small');
    confPill.title = `Host finished with exit ${r.host_exit} (confirmed ${stamp(r.confirmed_at)})`;
    summaryParts.push(' · ', confPill);
  }

  const details = el('details', { class: 'card', id: cardId, open: wasOpen });
  details.addEventListener('toggle', () => {
    if (details.open) DP.openRuns.add(r.run_id);
    else DP.openRuns.delete(r.run_id);
  });
  details.append(el('summary', {}, ...summaryParts));

  if (r.fetched_log?.output) {
    details.append(el('details', { class: 'card stack', open: true },
      el('summary', {}, text('b', 'Host log fetched by scan', 'muted small'), text('span', `fetched ${when(r.fetched_log.fetched_at)}`, 'muted small')),
      outputBlock(r.fetched_log.output)));
  }

  const preText = r.output || (r.status === 'queued' ? 'waiting for the hosts before it' : '');
  const outPre = outputBlock(preText);
  if (existing) {
    const oldPre = existing.querySelector('pre.dpout');
    if (oldPre) {
      const wasAtBottom = (oldPre.scrollHeight - oldPre.scrollTop <= oldPre.clientHeight + 40);
      oldPre.replaceWith(outPre);
      if (wasAtBottom) outPre.scrollTop = outPre.scrollHeight;
      else outPre.scrollTop = oldPre.scrollTop;
    } else {
      details.append(outPre);
    }
  } else {
    details.append(outPre);
  }
  return details;
}

function renderGroup() {
  const box = $('#dpgroup');
  const g = DP.group;
  if (!box) return;
  if (!g) { box.replaceChildren(); box.hidden = true; return; }
  box.hidden = false;
  const failed = g.runs.filter((r) => ['failed', 'refused'].includes(r.status));
  const unfinished = g.runs.filter((r) => r.status === 'incomplete');

  // Summary counts across runs
  let totOk = 0, totMiss = 0, totCrit = 0, totDid = 0;
  for (const r of g.runs) {
    if (r.summary) {
      totOk += r.summary.ok || 0;
      totMiss += r.summary.missing || 0;
      totCrit += r.summary.conflict || 0;
      totDid += r.summary.did || 0;
    }
  }
  const totals = [totOk ? `${totOk} ok` : '', totMiss ? `${totMiss} missing` : '', totCrit ? `${totCrit} conflict` : '', totDid ? `${totDid} did` : ''].filter(Boolean).join(' · ');

  const statusLabel = g.done ? (g.error ? (g.stale ? 'plan changed' : 'could not start') : failed.length ? `${failed.length} host(s) failed` : unfinished.length ? `${unfinished.length} host(s) not finished` : 'finished') : (DP.cancelRequested ? 'stopping…' : 'running…');
  const statusClass = g.done ? (g.error || failed.length ? 'st-failed' : unfinished.length ? 'st-running' : 'st-ok') : 'st-running';

  const tools = el('span', { class: 'row tools' });
  if (!g.done && g.gid) {
    if (!DP.cancelRequested) {
      tools.append(button('Cancel', () => cancelGroup(g.gid, false), 'btn ghost sm danger'));
    } else {
      tools.append(button('Force stop', () => cancelGroup(g.gid, true), 'btn sm danger'));
    }
  }
  if (g.done && g.gid && (failed.length || unfinished.length || ['failed', 'incomplete', 'cancelled', 'interrupted'].includes(g.state))) {
    tools.append(button('Retry failed hosts', () => retryGroup(g.gid), 'btn pri sm'));
  }
  tools.append(button('Close', () => { DP.group = null; renderGroup(); }, 'btn ghost sm'));

  const head = el('div', { class: 'row' },
    el('div', { class: 'row wrap' },
      el('b', {}, `${g.mode === 'apply' ? 'Applying' : 'Dry run (report)'}: ${g.title}`),
      text('span', statusLabel, statusClass),
      totals ? text('span', `(${totals})`, 'muted small') : ''),
    tools);

  const kids = [head];
  if (g.error) {
    kids.push(text('p', g.error, 'st-failed'));
    if (g.stale) {
      kids.push(el('div', { class: 'row wrap' },
        button('Run dry run again', () => startDeploy(g.kind, g.ref, 'report', g.title, g.extra), 'btn pri sm')));
    }
    const missing = g.missingHosts || (g.error.match(/on: (.+)$/) || [])[1]?.split(', ');
    if (missing?.length) {
      kids.push(el('div', { class: 'row wrap' }, ...missing.map((h) => button(`Set up ${h}…`, () => setupForm(h), 'btn sm'))));
    }
    if (g.blockers?.length) {
      kids.push(el('ul', { class: 'mvcheck' }, ...g.blockers.map((b) => el('li', { class: 'lv-crit' }, `${b.host}: ${b.text}`))));
    }
  }

  for (const r of g.runs) {
    kids.push(runCard(r, g));
  }

  if (g.done && !g.error && g.mode === 'apply') {
    if (g.runs.some((r) => (r.output || '').includes('destructive, skipped'))) {
      kids.push(text('p', 'Drive tasks were skipped, so this plan has not finished. Deploy it again with "include drive tasks" ticked.', 'st-failed small'));
    } else if (unfinished.length) {
      kids.push(text('p', 'The "missing" lines above were not done. Each says what it needs; do that, then deploy again.', 'st-running small'));
    }
    kids.push(text('p', 'These hosts are being rescanned, so the other tabs catch up once their scans end.', 'muted small'));
  }

  if (g.done && !g.error && g.mode === 'report') {
    // When applying from a dry run, pass the dry run's group ID as report_group so the backend checks for plan staleness
    const again = (extra = {}) => startDeploy(g.kind, g.ref, 'apply', g.title, { ...g.extra, ...extra, report_group: g.gid });
    const row = el('div', { class: 'row end wrap' });
    if (g.kind === 'changes') {
      const destr = el('input', { type: 'checkbox' });
      row.append(el('label', { class: 'check' }, destr, 'include drive tasks (partition, format, add device)'));
      row.append(button(failed.length ? 'Apply anyway' : 'Apply', () => again({ destructive: destr.checked }), failed.length ? 'btn danger' : 'btn pri'));
    } else if (g.kind === 'jobs') {
      if (!g.extra.remove) row.append(button('Apply, timers paused', () => again({ paused: true }), 'btn'));
      row.append(button(failed.length ? 'Apply anyway' : g.extra.remove ? 'Remove the jobs' : 'Apply', () => again(), failed.length || g.extra.remove ? 'btn danger' : 'btn pri'));
    } else {
      row.append(button(failed.length ? 'Apply anyway' : 'Apply', () => again(), failed.length ? 'btn danger' : 'btn pri'));
    }
    kids.push(text('p', failed.length ? 'The report found problems (conflict lines). Fix them and run the dry run again, or apply anyway.'
      : 'Nothing was changed. "missing" lines are what Apply would do.', failed.length ? 'st-failed small' : 'muted small'), row);
  }

  box.replaceChildren(...kids);
}

/* ── deploy access per host ─────────────────────────────────────── */
function setupForm(host, remove = false) {
  const pw = el('input', { type: 'password', autocomplete: 'off', placeholder: 'sudo password', 'aria-label': 'sudo password' });
  const admin = el('input', { type: 'text', autocomplete: 'off', placeholder: 'admin user (optional)', 'aria-label': 'Admin user' });
  const msg = el('p', { class: 'muted small', hidden: true });

  const title = remove ? `Remove deploy access from ${host}` : `Set up deploy access on ${host}`;
  const intro = remove
    ? 'Removes the storageforge-deploy user and its sudoers rule. Installed jobs keep running on their timers. Needs root once: password is never stored.'
    : 'Creates the storageforge-deploy user, whose SSH key can only start a runner that checks StorageForge\'s signature, and installs that runner. Needs root once: password is never stored. Leave admin user empty to use scan user\'s sudo.';

  const submitBtn = el('button', { type: 'submit', class: remove ? 'btn danger sm' : 'btn pri sm' }, remove ? 'Remove access' : 'Set up');
  const rowInputs = el('div', { class: 'row wrap' }, pw, admin, submitBtn);

  const formKids = [
    el('div', { class: 'row' }, el('b', {}, title), button('Cancel', () => { DP.setup = null; form.remove(); }, 'btn ghost sm')),
    text('p', intro, 'muted small'),
    rowInputs
  ];

  if (!remove) {
    formKids.push(
      el('div', { class: 'row wrap' }, text('span', 'Or run it yourself as root:', 'muted small'),
        button('Download the setup script', () => download('/api/deploy/setup-script', 'storageforge-deploy-setup.sh', {}), 'btn ghost sm'),
        button('I ran it: test', async () => {
          msg.hidden = false; msg.textContent = 'Testing a signed run…';
          try {
            const r = await (await postJSON('/api/deploy/adopt', { host })).json();
            msg.textContent = r.output;
            msg.className = r.state === 'ready' ? 'st-ok small' : 'st-failed small';
            loadDeploy();
          } catch (err) { msg.textContent = err.message; msg.className = 'st-failed small'; }
        }, 'btn ghost sm'))
    );
  }
  formKids.push(msg);

  const form = el('form', { class: 'card stack' }, ...formKids);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    msg.hidden = false; msg.className = 'muted small'; msg.textContent = remove ? 'Removing access…' : 'Setting up…';
    try {
      const r = await (await postJSON('/api/deploy/access', { host, password: pw.value, admin_user: admin.value.trim() || null, remove })).json();
      pw.value = '';
      msg.className = (r.state === 'ready' || r.state === 'removed') ? 'st-ok small' : 'st-failed small';
      msg.textContent = r.output || `Deploy access ${r.state}`;
      loadDeploy();
    } catch (err) { pw.value = ''; msg.className = 'st-failed small'; msg.textContent = err.message; }
  });

  DP.setup = form;
  showTab('deploy');
  $('#dpsetup')?.replaceChildren(form);
  pw.focus();
}

async function download(url, fallback, body) {   // body: POST it as JSON (for a download that changes something)
  try {
    const res = await (body ? postJSON(url, body) : api(url));
    const a = document.createElement('a'); a.href = URL.createObjectURL(await res.blob());
    a.download = (res.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || fallback;
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (err) { toast(err.message); }
}

function removeAccess(host) {
  setupForm(host, true);
}

/* ── jobs ───────────────────────────────────────────────────────── */
async function jobAction(j, verb) {
  if (verb === 'cutover' && !confirm(`Cut over ${j.name}? The source is renamed to *.migrated-<date> after a clean verify.`)) return;
  toast(`${verb}: ${j.id}…`);
  try {
    const r = await (await postJSON(`/api/deploy/jobs/${j.id}/${verb}`, {})).json();
    if (verb === 'snapshots') { DP.job = { job: j, snapshots: r.snapshots || [], output: r.status === 'ok' ? '' : r.output }; renderJobPanel(); return; }
    if (['dryrun', 'log', 'cutover'].includes(verb) || r.status !== 'ok') { DP.job = { job: j, title: verb, output: r.output }; renderJobPanel(); }
    toast(r.status === 'ok' ? `${verb}: done` : `${verb}: ${r.status}`);
    if (['pause', 'resume', 'run', 'verify'].includes(verb)) setTimeout(loadDeploy, verb === 'run' || verb === 'verify' ? 4000 : 300);
  } catch (err) { toast(err.message); }
}
async function jobHistory(j) {
  try { const r = await getJSON(`/api/deploy/jobs/${j.id}`); DP.job = { job: j, runs: r.runs }; renderJobPanel(); }
  catch (err) { toast(err.message); }
}
function jobMenu(j) {
  const a = (label, verb, extra = {}) => ({ label, run: () => jobAction(j, verb), ...extra });
  return [{ heading: j.name }, a('Run now', 'run'), a('Dry run (what it would copy)', 'dryrun'), j.method !== 'git' ? a('Verify checksums now', 'verify') : null,
    j.paused ? a('Resume timers', 'resume') : a('Pause timers', 'pause'), '-', { label: 'History', run: () => jobHistory(j) }, a('Journal log', 'log'),
    j.snapshots ? a('Snapshots…', 'snapshots') : null, j.method === 'move' ? a('Cut over (rename the source)', 'cutover', { danger: true }) : null,
    '-', { label: 'Open the plan in Moves', run: () => { showTab('moves'); loadMoves(j.plan_id); } },
    { label: 'Copy job id', run: () => copyText(j.id) }];
}
function jobRow(j) {
  const last = j.last, verify = j.verify;
  const li = el('li', { class: 'card dpjob' },
    el('div', { class: 'row' }, text('span', j.state, `pill ${JOB_STATE[j.state] || 'unknown'}`), el('b', {}, j.name),
      el('span', { class: 'row tools' }, button('Run now', () => jobAction(j, 'run'), 'btn ghost sm'),
        button('Dry run', () => jobAction(j, 'dryrun'), 'btn ghost sm'), button('⋯', (ev) => openMenu(jobMenu(j), ev.clientX, ev.clientY, li), 'btn ghost sm'))),
    text('span', [j.method, j.schedule ? `on "${j.schedule}"` : 'run on demand', j.window ? `window ${j.window}` : '',
      j.snapshot ? 'btrfs snapshot first' : '', j.pre.length ? `${j.pre.length} pre command(s)` : '', j.verify_schedule ? `verify ${j.verify_schedule}` : '',
      `runs on ${j.runner}`].filter(Boolean).join(' · '), 'muted small'),
    last ? text('span', `last run ${when(last.end || last.start)}: ${last.rc === 0 ? 'ok' : 'exit ' + last.rc}${last.bytes ? ' · ' + fmtBytes(last.bytes) : ''}${last.files ? ` · ${last.files.toLocaleString()} files` : ''} · ${last.message || ''}`,
      last.rc === 0 ? 'small' : 'st-failed small') : text('span', j.paused ? 'paused' : 'no run reported yet', 'muted small'),
    j.last_ok && j.last_ok !== last ? text('span', `last good run ${when(j.last_ok.end)}`, 'muted small') : '',
    verify ? text('span', `verify ${when(verify.end)}: ${verify.message}`, verify.rc === 0 ? 'muted small' : 'st-failed small') : '');
  li._menu = () => jobMenu(j);
  return li;
}
function renderJobPanel() {
  const box = $('#dpjobpanel');
  if (!box) return;
  const v = DP.job;
  if (!v) { box.replaceChildren(); box.hidden = true; return; }
  box.hidden = false;
  const kids = [el('div', { class: 'row' }, el('b', {}, v.job.name), button('Close', () => { DP.job = null; renderJobPanel(); }, 'btn ghost sm'))];
  if (v.output) kids.push(text('span', v.title || '', 'muted small'), outputBlock(v.output));
  if (v.runs) {
    kids.push(el('table', { class: 'dptable' }, el('tr', {}, ...['When', 'Kind', 'Result', 'Copied', 'Message'].map((h) => el('th', {}, h))),
      ...v.runs.map((r) => el('tr', {}, el('td', { title: stamp(r.start) }, when(r.end || r.start)), el('td', {}, r.kind + (r.level ? ` ${r.level}` : '')),
        el('td', { class: r.rc === 0 ? '' : 'st-failed' }, r.rc === 0 ? 'ok' : `exit ${r.rc}`),
        el('td', {}, r.bytes ? `${fmtBytes(r.bytes)} · ${r.files.toLocaleString()} files` : ''), el('td', { class: 'small' }, `${r.message || ''}${r.via === 'scan' ? ' (from a scan)' : ''}`)))));
    if (!v.runs.length) kids.push(text('p', 'No runs reported yet.', 'muted'));
  }
  if (v.snapshots) {
    if (!v.snapshots.length) kids.push(text('p', 'No snapshots yet: the first one is taken on the job\'s schedule (or Run now).', 'muted'));
    kids.push(el('ul', { class: 'dklist' }, ...v.snapshots.map((s) => el('li', {},
      button(`${s.name} · ${stamp(s.time)}`, () => browseSnapshot(v.job, s.name, ''), 'link')))));
  }
  if (v.browse) {
    const b = v.browse;
    const up = b.path ? b.path.split('/').slice(0, -1).join('/') : null;
    kids.push(el('div', { class: 'row' }, el('b', { class: 'mono' }, `${b.snapshot}:/${b.path}`),
      up !== null ? button('↑ Up', () => browseSnapshot(v.job, b.snapshot, up), 'btn ghost sm') : '',
      b.path ? button('Restore this folder', () => restoreFrom(v.job, b.snapshot, b.path), 'btn sm') : ''));
    if (b.error) kids.push(text('p', b.error, 'st-failed small'));
    kids.push(el('ul', { class: 'fbrowse' }, ...b.entries.map((e) => {
      const rel = (b.path ? b.path + '/' : '') + e.name;
      return el('li', {}, e.type === 'd' ? button(e.name + '/', () => browseSnapshot(v.job, b.snapshot, rel), 'n mono link') : el('span', { class: 'n mono' }, e.name),
        text('span', e.type === 'd' ? '' : fmtBytes(e.size), 's'), button('Restore', () => restoreFrom(v.job, b.snapshot, rel), 'btn ghost sm'));
    })));
  }
  box.replaceChildren(...kids);
  box.scrollIntoView({ block: 'nearest' });
}
async function browseSnapshot(j, snapshot, path) {
  try {
    const b = await (await postJSON(`/api/deploy/jobs/${j.id}/browse`, { snapshot, path })).json();
    DP.job = { ...DP.job, job: j, browse: b }; renderJobPanel();
  } catch (err) { toast(err.message); }
}
async function restoreFrom(j, snapshot, path) {
  if (!confirm(`Restore ${path} from ${snapshot} to ${j.source}?\n\nIt lands beside the original as ${path}.restored-<time>; nothing is overwritten.`)) return;
  try {   // it runs in the background; its runs show like a deploy's
    const r = await (await postJSON(`/api/deploy/jobs/${j.id}/restore`, { snapshot, path })).json();
    DP.group = { gid: r.group, kind: 'restore', ref: j.id, mode: 'apply', title: `restore ${path} from ${snapshot} into ${j.source}:${r.target}`,
                 extra: {}, runs: [], done: false };
    renderGroup(); pollGroup(); toast('Restore started');
  } catch (err) { toast(err.message); }
}

/* ── the tab ────────────────────────────────────────────────────── */
function renderDeploy() {
  const box = $('#deploybox');
  if (!box) return;
  if (DP.err) { box.replaceChildren(text('p', DP.err, 'st-failed')); return; }
  const d = DP.data;
  if (!d) { box.replaceChildren(text('p', 'Loading…', 'muted')); return; }
  const typing = DP.setup?.contains(document.activeElement) ? document.activeElement : null;
  const parts = [el('div', { id: 'dpgroup', class: 'stack', hidden: true }), el('div', { id: 'dpsetup' }, DP.setup || ''), el('div', { id: 'dpjobpanel', class: 'card stack', hidden: true })];
  if (d.alerts?.length) {
    parts.push(el('section', { class: 'stack' }, el('h3', {}, `Alerts (${d.alerts.length})`), el('ul', { class: 'mvcheck' },
      ...d.alerts.map((a) => el('li', { class: a.kind.includes('fail') ? 'lv-crit' : 'lv-warn' }, `${a.title}${a.message ? ': ' + a.message : ''} · since ${when(a.first_at)}`)))));
  }
  // hosts
  const ready = new Set(d.access.filter((a) => a.state === 'ready').map((a) => a.host));
  parts.push(el('section', { class: 'stack' }, el('h3', {}, 'Deploy access'),
    text('p', 'A host set up here runs scripts StorageForge signed, as root, and nothing else. Every deploy shows a read-only report before it changes anything.', 'muted small'),
    el('ul', { class: 'dklist' }, ...d.access.map((a) => {
      const li = el('li', {}, el('div', { class: 'row' }, el('b', { class: 'mono' }, a.host),
        text('span', { ready: 'ready', failed: 'setup failed', removed: 'removed', none: 'not set up' }[a.state] || a.state, `pill ${a.state === 'ready' ? 'protected' : a.state === 'failed' ? 'broken' : 'unknown'}`),
        el('span', { class: 'row tools' }, a.state === 'ready' ? button('Remove…', () => removeAccess(a.host), 'btn ghost sm') : button('Set up…', () => setupForm(a.host), 'btn sm'))),
        a.state === 'failed' && a.detail ? text('span', a.detail.split('\n').slice(-2).join(' '), 'st-failed small') : '');
      li._menu = () => [{ heading: a.host }, a.state === 'ready' ? { label: 'Remove deploy access…', run: () => removeAccess(a.host), danger: true } : { label: 'Set up deploy access…', run: () => setupForm(a.host) },
        { label: 'Deploy history', run: () => showHistory(a.host) }, { label: 'Copy hostname', run: () => copyText(a.host) }];
      return li;
    }))));
  // jobs by plan
  const byPlan = new Map();
  for (const j of d.jobs) { if (!byPlan.has(j.plan_id)) byPlan.set(j.plan_id, []); byPlan.get(j.plan_id).push(j); }
  const pending = new Map(d.drift.filter((x) => x.kind === 'pending').map((x) => [x.ref, x.text]));
  const planName = (id) => (d.plans.find((p) => p.id === id) || {}).name || `deleted plan ${id}`;
  const jobsBox = el('section', { class: 'stack' }, el('h3', {}, 'Jobs (rsync, rsnapshot, git)'));
  for (const p of d.plans) if (!byPlan.has(p.id)) byPlan.set(p.id, []);
  for (const [pid, js] of byPlan) {
    const name = planName(pid), title = `move plan "${name}"`;
    const pend = pending.get(`p${pid}`);
    jobsBox.append(el('div', { class: 'card stack' },
      el('div', { class: 'row wrap' }, el('b', {}, name), js.length ? text('span', `${js.length} job${js.length === 1 ? '' : 's'} deployed`, 'muted small') : text('span', 'not deployed', 'muted small'),
        pend ? text('span', pend, 'pill local-only') : '',
        el('span', { class: 'row tools' }, button('Dry run', () => startDeploy('jobs', pid, 'report', title), 'btn sm'),
          js.length ? button('Remove from hosts…', () => startDeploy('jobs', pid, 'report', `remove the jobs of "${name}"`, { remove: true }), 'btn ghost sm danger') : '')),
      js.length ? el('ol', { class: 'chtasks' }, ...js.map(jobRow)) : ''));
  }
  if (!byPlan.size) jobsBox.append(text('p', 'No move plans yet. Plan rsync, rsnapshot or git steps in the Moves tab, then deploy them here.', 'muted'));
  parts.push(jobsBox);
  // shares
  const shareHosts = [...new Set([...d.deployed.filter((x) => x.kind === 'shares').map((x) => x.ref),
    ...[...T.docs.values()].filter((doc) => doc.bp && designedShares(doc).length).map((doc) => doc.host)])].sort();
  parts.push(el('section', { class: 'stack' }, el('h3', {}, 'Shares (NFS, SMB)'),
    shareHosts.length ? el('ul', { class: 'dklist' }, ...shareHosts.map((h) => {
      const dep = d.deployed.find((x) => x.kind === 'shares' && x.host === h && x.ref === h);
      return el('li', {}, el('div', { class: 'row wrap' }, el('b', { class: 'mono' }, h),
        text('span', dep ? `deployed ${when(dep.at)} · clients: ${(dep.detail.clients || []).join(', ') || 'none'}` : 'not deployed', 'muted small'),
        pending.get(h) ? text('span', 'design changed', 'pill local-only') : '',
        el('span', { class: 'row tools' }, button('Check', () => { const doc = T.docs.get(h); if (doc) deployShares(doc); }, 'btn ghost sm'),
          button('Dry run', () => startDeploy('shares', h, 'report', `shares of ${h}`), 'btn sm'))));
    })) : text('p', 'No shares designed yet: add an export to a mount in the topology (+ Export this), save the design, then deploy it here.', 'muted small')));
  // drift
  const changed = d.drift.filter((x) => x.kind === 'changed');
  parts.push(el('section', { class: 'stack' }, el('h3', {}, 'Drift'),
    changed.length ? el('ul', { class: 'mvcheck' }, ...changed.map((x) => el('li', { class: 'lv-warn' }, `${x.host}: ${x.text}`)))
      : text('p', 'Nothing deployed was changed by hand, as of each host\'s last scan.', 'muted small')));

  // Recent deploys (groups from engine.py recent, with mode, state, hosts and click-to-view/retry)
  const groupsList = d.groups || [];
  parts.push(el('details', { class: 'card' }, el('summary', {}, `Recent deploys (${groupsList.length})`),
    groupsList.length ? el('ul', { class: 'dklist' }, ...groupsList.map((g) => {
      const statePill = text('span', g.state, `pill ${{ ok: 'protected', failed: 'broken', incomplete: 'local-only', running: 'local-only', cancelled: 'unknown', interrupted: 'broken' }[g.state] || 'unknown'}`);
      const hostPills = (g.hosts || []).map((h) => text('span', `${h.host}: ${h.status}`, `pill small ${{ ok: 'protected', failed: 'broken', incomplete: 'local-only', running: 'local-only', skipped: 'unknown' }[h.status] || 'unknown'}`));
      const item = el('li', {},
        el('div', { class: 'row wrap' },
          button(`${stamp(g.started_at)} · ${g.title || (g.kind + ' ' + (g.ref || ''))} · ${g.mode}`, () => openGroup(g.group_id, g.title, g.kind, g.ref, g.mode, g.options), 'link small bold'),
          statePill,
          el('span', { class: 'row wrap' }, ...hostPills)));
      return item;
    })) : text('p', 'No deploys yet.', 'muted small')));

  parts.push(settingsForm(d.settings));
  box.replaceChildren(...parts);
  typing?.focus();
  renderGroup(); renderJobPanel();
}

async function showHistory(host) {
  try {
    const { runs } = await getJSON(`/api/deploy/runs?host=${encodeURIComponent(host)}&limit=30`);
    DP.job = { job: { name: `deploy history of ${host}` }, title: '', output: runs.map((r) => `${stamp(r.started_at)}  ${r.kind} ${r.ref || ''}  ${r.mode}  ${r.status}${r.confirmed_at ? ' (confirmed: ' + (r.host_exit === 0 ? 'ok' : 'exit ' + r.host_exit) + ')' : ''}`).join('\n') || 'nothing yet' };
    renderJobPanel();
  } catch (err) { toast(err.message); }
}

function settingsForm(s) {
  if (DP.settingsForm) return DP.settingsForm;
  const f = (v, attrs) => { const i = el('input', { type: 'text', autocomplete: 'off', class: 'mono', ...attrs }); i.value = v || ''; return i; };
  const url = f(s.report_url, { placeholder: `e.g. https://10.42.0.100:8443 (how hosts reach StorageForge)` });
  const a = s.alerts;
  const nUrl = f(a.ntfy.url, { placeholder: 'https://ntfy.sh' }), nTopic = f(a.ntfy.topic, { placeholder: 'topic' }), nTok = f(a.ntfy.token, { placeholder: 'token (optional)', type: 'password' });
  const gUrl = f(a.gotify.url, { placeholder: 'https://gotify.example' }), gTok = f(a.gotify.token, { placeholder: 'app token', type: 'password' });
  const wUrl = f(a.webhook.url, { placeholder: 'https://… (JSON POST)' });
  const res = el('input', { type: 'checkbox' }); res.checked = a.notify_resolved !== false;
  const msg = el('p', { class: 'muted small', hidden: true });
  const body = () => ({ report_url: url.value.trim(), alerts: { ntfy: { url: nUrl.value.trim(), topic: nTopic.value.trim(), token: nTok.value },
    gotify: { url: gUrl.value.trim(), token: gTok.value }, webhook: { url: wUrl.value.trim() }, notify_resolved: res.checked } });
  const save = async () => {
    try { await api('/api/deploy/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body()) }); msg.hidden = false; msg.className = 'st-ok small'; msg.textContent = 'Saved.'; return true; }
    catch (err) { msg.hidden = false; msg.className = 'st-failed small'; msg.textContent = err.message; return false; }
  };
  const row = (label, ...inputs) => el('label', { class: 'field col' }, el('span', {}, label), el('div', { class: 'row' }, ...inputs));
  const form = el('details', { class: 'card stack' }, el('summary', {}, 'Reporting and alerts'),
    row('Report URL: jobs post each run here', url),
    !s.report_url && !/^(localhost|127\.)/.test(location.hostname) ? button(`Use ${location.origin}`, () => { url.value = location.origin; }, 'btn ghost sm') : '',
    text('p', 'Without it, runs still reach StorageForge with the next scan of each host. Alerts (failed or stale jobs, verify differences, drift) always show here; they can also be pushed:', 'muted small'),
    row('ntfy', nUrl, nTopic, nTok), row('Gotify', gUrl, gTok), row('Webhook', wUrl),
    el('label', { class: 'check' }, res, 'also notify when an alert resolves'),
    el('div', { class: 'row end' }, button('Send a test', async () => {
      if (!(await save())) return;
      try { const r = await (await postJSON('/api/deploy/settings/test', {})).json(); msg.textContent = r.sent.join(' · '); msg.className = 'muted small'; }
      catch (err) { msg.textContent = err.message; msg.className = 'st-failed small'; }
    }, 'btn sm'), button('Save', save, 'btn pri sm')), msg);
  DP.settingsForm = form;
  return form;
}
