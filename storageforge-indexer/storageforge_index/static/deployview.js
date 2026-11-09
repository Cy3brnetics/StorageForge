'use strict';
/* Deploy tab: hosts set up for signed deploys, deployed rsync/rsnapshot jobs (state, runs, actions, snapshots), shares,
   drift, alerts and their channels. Every deploy runs the read-only report on each host first; Apply comes after.
   Loaded after dockerview.js; uses the shared helpers. */

const DP = { data: null, group: null, poll: 0, job: null, err: '', setup: null, settingsForm: null, openRuns: new Set(), cancelRequested: false,
  groupBox: null, rest: null, dismissed: new Set(), starting: false, pollTick: 0 };
const JOB_STATE = { ok: 'protected', failed: 'broken', stale: 'local-only', 'never-ran': 'unknown', paused: 'unknown', unseen: 'unknown', missing: 'broken' };
const RUN_LINE = /^\s{2}(ok|missing|conflict|->|other)\s/;

const when = (ts) => fmtAgo(ts);
const stamp = (ts) => fmtTime(ts);

async function loadDeploy() {
  try {
    DP.data = await getJSON('/api/deploy');
    DP.err = '';
    getJSON('/api/deploy/snapjobs').then((r) => { DP.found = r.found; renderSnapFound(); }).catch(() => {});
    // If no deploy panel is open, resume watching any active deploy from recent groups
    if (!DP.group && DP.data?.groups) {
      const active = DP.data.groups.find((g) => ['running', 'queued'].includes(g.state) && !DP.dismissed.has(g.group_id));
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
  if (DP.starting) return;           // one click starts one deploy, however long the answer takes
  DP.starting = true;
  const before = DP.group;
  DP.cancelRequested = false;
  // on screen at once, in place of the button that was pressed; it also keeps loadDeploy from adopting this deploy as a stranger
  DP.group = { kind, ref, mode, title, extra, runs: [], done: false, starting: true };
  showTab('deploy');
  deployBoxes();
  renderGroup();
  DP.groupBox.closest('.tab').scrollTop = 0;   // the deploy shows at the top of a tab that may be scrolled to its button
  try {
    const r = await (await postJSON('/api/deploy/start', { kind, ref, mode, ...extra })).json();
    DP.group = { gid: r.group, kind, ref, mode, title, extra, runs: [], done: false };
  } catch (err) {
    if (/not confirmed/.test(err.message)) {   // the password or host key prompt was cancelled: nothing changed, so neither does the panel
      DP.group = before;
      notify(err.message, 'error');
    } else {
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
  } finally { DP.starting = false; }
  renderGroup();
  if (DP.group?.gid) pollGroup();
}

async function cancelGroup(gid, force = false) {
  try {
    DP.cancelRequested = true;
    renderGroup();
    const r = await (await postJSON(`/api/deploy/groups/${gid}/cancel`, { force })).json();
    toast(force ? 'Deploy force stopped' : 'Cancel requested; stopping remaining hosts');
    pollGroup();
  } catch (err) { notify(err.message, 'error'); }
}

async function retryGroup(gid) {
  toast('Retrying deploy…');
  try {
    const r = await (await postJSON(`/api/deploy/groups/${gid}/retry`, {})).json();
    DP.cancelRequested = false;
    DP.group = { gid: r.group, kind: r.kind, ref: r.ref, mode: r.mode, title: r.title, extra: r.extra, runs: [], done: false };
    renderGroup();
    pollGroup();
  } catch (err) { notify(err.message, 'error'); }
}

async function openGroup(gid, title, kind, ref, mode, extra = {}) {
  try {
    const data = await getJSON(`/api/deploy/groups/${gid}`);
    const g = data.group || {};
    DP.group = { gid, title: title || g.title, kind: kind || g.kind, ref: ref || g.ref, mode: mode || g.mode, extra: extra || g.options || {}, runs: data.runs || [], done: g.state !== 'running' };
    DP.dismissed.delete(gid);
    renderGroup();
    if (!DP.group.done) pollGroup();
    $('#dpgroup')?.scrollIntoView({ block: 'start', behavior: 'smooth' });
  } catch (err) { notify(err.message, 'error'); }
}

async function pollGroup() {
  clearTimeout(DP.poll);
  const g = DP.group;
  if (!g || !g.gid || g.done) return;
  const tick = ++DP.pollTick;                // a newer poll, or another deploy on screen, makes this answer old news
  const current = () => tick === DP.pollTick && g === DP.group;
  try {
    const data = await getJSON(`/api/deploy/groups/${g.gid}`);
    g.fails = 0;
    g.runs = data.runs || [];
    const grp = data.group;
    if (grp) g.state = grp.state;
    g.done = g.runs.length > 0 && (
      ['ok', 'failed', 'incomplete', 'cancelled', 'interrupted'].includes(grp?.state) ||
      g.runs.every((r) => !['running', 'queued'].includes(r.status))
    );
  } catch (err) {
    g.fails = (g.fails || 0) + 1;
    if (g.fails < 5) {                       // the deploy goes on without this page: one lost answer must not end the view of it
      if (current()) DP.poll = setTimeout(pollGroup, 2000);
      return;
    }
    g.error = err.message; g.done = true;
  }
  if (!current()) return;
  renderGroup();
  if (!g.done) DP.poll = setTimeout(pollGroup, 1000);
  else if (g.kind === 'updates' && g.mode === 'report') loadDeploy();     // the System updates list shows what the check found
  else if (g.mode === 'apply') {
    loadDeploy();
    if (g.error) return;
    if (g.kind === 'changes') chApplied(g.ref);
    if (g.kind === 'shares' && typeof loadDesigns === 'function') loadDesigns();     // it refreshes the shares manager too
    if (g.kind === 'jobs') loadMoves(!MV.dirty && MV.plan?.id === g.ref ? g.ref : undefined);
    setTimeout(followJobs, 1000);    // the group's rescans are queued as it ends; the graph and designs reload after them
  }
}

function fillOutput(pre, out) {
  pre.replaceChildren(...(out || '').replace(/\n$/, '').split('\n').map((line) => {
    const m = line.match(RUN_LINE);
    return m ? text('span', line + '\n', `dl-${{ ok: 'ok', missing: 'miss', conflict: 'crit', '->': 'do', other: 'note' }[m[1]]}`) : line + '\n';
  }));
}
function outputBlock(out) {
  const pre = el('pre', { class: 'dpout' });
  fillOutput(pre, out);
  return pre;
}
function redraw(node, sig, build) {          // only when something shown changed: a button rebuilt under the pointer loses its click
  if (node._sig === sig) return;
  node._sig = sig;
  node.replaceChildren(...build().filter(Boolean));
}

/* A run's card lives as long as the deploy is on screen and polls only update it, so what is open, scrolled or selected stays. */
function runCard(r, g, cards) {
  let c = cards.get(r.run_id);
  if (!c) {
    const node = el('details', { class: 'card', id: `dp-run-${r.run_id}`, open: DP.openRuns.has(r.run_id) || !g.done || r.status !== 'ok' || g.runs.length === 1 });
    node.addEventListener('toggle', () => {
      if (node.open) DP.openRuns.add(r.run_id);
      else DP.openRuns.delete(r.run_id);
    });
    c = { node, head: el('summary'), fetched: el('div'), out: outputBlock(''), text: null };
    node.append(c.head, c.fetched, c.out);
    cards.set(r.run_id, c);
  }
  const label = { ok: 'protected', failed: 'broken', refused: 'broken', incomplete: 'local-only', running: 'local-only', queued: 'unknown', skipped: 'unknown', cancelled: 'unknown' }[r.status] || 'unknown';
  redraw(c.head, JSON.stringify([r.host, r.kind, r.mode, r.status, r.summary, r.confirmed_at, r.host_exit]), () => {
    const parts = [el('b', { class: 'mono' }, r.host), ` · ${r.kind}${r.mode === 'apply' ? '' : ' report'} · `, text('span', r.status, `pill ${label}`)];
    if (r.summary) {
      const sm = r.summary;
      const bits = [sm.ok ? `${sm.ok} ok` : '', sm.missing ? `${sm.missing} missing` : '', sm.conflict ? `${sm.conflict} conflict` : '', sm.did ? `${sm.did} did` : ''].filter(Boolean);
      if (bits.length) parts.push(' · ', text('span', bits.join(', '), 'muted small'));
    }
    if (r.confirmed_at) {
      const confPill = r.host_exit === 0 ? text('span', 'confirmed by scan', 'pill protected small') : text('span', `scan: exit ${r.host_exit}`, 'pill broken small');
      confPill.title = `Host finished with exit ${r.host_exit} (confirmed ${stamp(r.confirmed_at)})`;
      parts.push(' · ', confPill);
    }
    return parts;
  });
  redraw(c.fetched, String(r.fetched_log?.fetched_at || ''), () => (r.fetched_log?.output ? [el('details', { class: 'card stack', open: true },
    el('summary', {}, text('b', 'Host log fetched by scan', 'muted small'), text('span', `fetched ${when(r.fetched_log.fetched_at)}`, 'muted small')),
    outputBlock(r.fetched_log.output))] : []));
  const shown = r.output || (r.status === 'queued' ? 'waiting for the hosts before it' : r.status === 'running' ? 'connecting…' : '');
  if (c.text !== shown) {
    const pre = c.out, follow = pre.scrollHeight - pre.scrollTop <= pre.clientHeight + 40;
    c.text = shown;
    fillOutput(pre, shown);
    if (follow) pre.scrollTop = pre.scrollHeight;
  }
  return c.node;
}

function renderGroup() {
  const box = DP.groupBox;
  const g = DP.group;
  if (!box) return;
  if (!g) { box.replaceChildren(); box.hidden = true; box._key = null; return; }
  box.hidden = false;
  const key = g.gid || g;
  if (box._key !== key) {
    box._key = key;
    box._parts = { head: el('div', { class: 'stack' }), runs: el('div', { class: 'stack' }), foot: el('div', { class: 'stack' }), cards: new Map() };
    box.replaceChildren(box._parts.head, box._parts.runs, box._parts.foot);
  }
  const { head, runs, foot, cards } = box._parts;
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

  const statusLabel = g.starting ? 'starting…' : g.done ? (g.error ? (g.stale ? 'plan changed' : g.gid ? 'lost contact' : 'could not start') : failed.length ? `${failed.length} host(s) failed` : unfinished.length ? `${unfinished.length} host(s) not finished` : 'finished') : (DP.cancelRequested ? 'stopping…' : 'running…');
  const statusClass = g.done ? (g.error || failed.length ? 'st-failed' : unfinished.length ? 'st-running' : 'st-ok') : 'st-running';
  const retry = g.done && g.gid && (failed.length || unfinished.length || ['failed', 'incomplete', 'cancelled', 'interrupted'].includes(g.state));

  redraw(head, JSON.stringify([statusLabel, totals, Boolean(retry), DP.cancelRequested, g.done, g.error, g.starting]), () => {
    const tools = el('span', { class: 'row tools' });
    if (!g.done && g.gid) {
      if (!DP.cancelRequested) {
        tools.append(button('Cancel', () => cancelGroup(g.gid, false), 'btn ghost sm danger'));
      } else {
        tools.append(button('Force stop', () => cancelGroup(g.gid, true), 'btn sm danger'));
      }
    }
    if (retry) tools.append(button('Retry failed hosts', () => retryGroup(g.gid), 'btn pri sm'));
    if (!g.starting) {
      tools.append(button('Close', () => {
        if (g.gid && !g.done) DP.dismissed.add(g.gid);     // closed while it runs: it stays closed when the tab reloads
        DP.group = null; renderGroup();
      }, 'btn ghost sm'));
    }
    const kids = [el('div', { class: 'row' },
      el('div', { class: 'row wrap' },
        el('b', {}, `${g.mode === 'apply' ? 'Applying' : 'Dry run (report)'}: ${g.title}`),
        text('span', statusLabel, statusClass),
        totals ? text('span', `(${totals})`, 'muted small') : ''),
      tools)];
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
    return kids;
  });

  const live = new Set(g.runs.map((r) => r.run_id));
  for (const [id, c] of cards) if (!live.has(id)) { c.node.remove(); cards.delete(id); }
  for (const r of g.runs) {
    const node = runCard(r, g, cards);
    if (!node.parentNode) runs.append(node);
  }

  const skipped = g.runs.some((r) => (r.output || '').includes('destructive, skipped'));
  foot.classList.toggle('dpactions', g.done && !g.error && g.mode === 'report');     // stays in view: the reports above it can be long
  // A failed run with no conflict line never got to report: ssh, the key or the runner failed, not the plan
  const broken = failed.filter((r) => !r.summary?.conflict);
  const noReport = g.runs.length > 0 && broken.length === g.runs.length;     // Apply would fail the same way on every host
  redraw(foot, JSON.stringify([g.done, Boolean(g.error), g.mode, failed.length, broken.map((r) => r.host), unfinished.length, skipped]), () => {
    const kids = [];
    if (g.done && !g.error && g.mode === 'apply') {
      if (skipped) {
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
      if (noReport) {
        // no Apply: nothing was checked, and it cannot reach these hosts either
      } else if (g.kind === 'changes') {
        const destr = el('input', { type: 'checkbox' });
        row.append(el('label', { class: 'check' }, destr, 'include drive tasks (partition, format, add device)'));
        row.append(button(failed.length ? 'Apply anyway' : 'Apply', () => again({ destructive: destr.checked }), failed.length ? 'btn danger' : 'btn pri'));
      } else if (g.kind === 'jobs') {
        if (!g.extra.remove) row.append(button('Apply, timers paused', () => again({ paused: true }), 'btn'));
        row.append(button(failed.length ? 'Apply anyway' : g.extra.remove ? 'Remove the jobs' : 'Apply', () => again(), failed.length || g.extra.remove ? 'btn danger' : 'btn pri'));
      } else {
        row.append(button(failed.length ? 'Apply anyway' : 'Apply', () => again(), failed.length ? 'btn danger' : 'btn pri'));
      }
      const conflicted = failed.length - broken.length;
      const why = [
        broken.length ? `${broken.map((r) => r.host).join(', ')} could not run the report, so nothing was checked there. Its output above says why; fix that, then Retry failed hosts.${noReport || conflicted ? '' : ' Apply anyway changes the other hosts and fails on these again.'}` : '',
        conflicted ? `The report found problems (conflict lines). Fix them and run the dry run again${noReport ? '' : ', or apply anyway'}.` : '',
      ].filter(Boolean).join(' ');
      kids.push(text('p', failed.length ? why : 'Nothing was changed. "missing" lines are what Apply would do.', failed.length ? 'st-failed small' : 'muted small'));
      if (row.childElementCount) kids.push(row);
    }
    return kids;
  });
}

/* ── deploy access per host ─────────────────────────────────────── */
function setupForm(host, remove = false) {
  const pw = el('input', { type: 'password', autocomplete: 'off', placeholder: 'sudo password', 'aria-label': 'sudo password' });
  const admin = el('input', { type: 'text', autocomplete: 'off', placeholder: 'admin user (optional)', 'aria-label': 'Admin user' });
  const msg = el('p', { class: 'muted small', hidden: true });
  const warn = el('p', { class: 'st-warn small', hidden: true });

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
  formKids.push(msg, warn);

  const form = el('form', { class: 'card stack' }, ...formKids);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    warn.hidden = true;
    msg.hidden = false; msg.className = 'muted small'; msg.textContent = remove ? 'Removing access…' : 'Setting up…';
    try {
      const r = await (await postJSON('/api/deploy/access', { host, password: pw.value, admin_user: admin.value.trim() || null, remove })).json();
      pw.value = '';
      msg.className = (r.state === 'ready' || r.state === 'removed') ? 'st-ok small' : 'st-failed small';
      msg.textContent = r.output || `Deploy access ${r.state}`;
      warn.textContent = r.warning || ''; warn.hidden = !r.warning;
      loadDeploy();
    } catch (err) { pw.value = ''; msg.className = 'st-failed small'; msg.textContent = err.message; }
  });

  DP.setup = form;
  showTab('deploy');
  $('#dpsetup')?.replaceChildren(form);
  pw.focus();
}

/* Hosts behind NAT that dial in through the tunnel. The install script holds the node's private key and comes only once. */
function remoteNodesCard() {
  const list = el('div', { class: 'stack' });
  const name = el('input', { type: 'text', class: 'mono', placeholder: 'node name, e.g. cabin-nas', 'aria-label': 'Node name' });
  const endpoint = el('input', { type: 'text', class: 'mono', placeholder: 'forge.example.com:2222', 'aria-label': 'Address nodes dial' });
  const refresh = async () => {
    try {
      const r = await getJSON('/api/remote/nodes');
      if (!endpoint.value) endpoint.value = r.endpoint;
      if (!r.tunnel) { list.replaceChildren(text('p', 'The tunnel is not running. Start the stack with docker-compose.remote.yml as well: see docs/remote-nodes.md.', 'muted small')); return; }
      list.replaceChildren(...r.nodes.map((n) => el('div', { class: 'row wrap' }, text('span', n.state, `pill ${n.state === 'ready' ? 'ok' : n.state === 'expired' ? 'failed' : 'unknown'}`), el('b', {}, n.name),
        text('span', [n.host, n.address, n.expires_at ? `key expires ${when(n.expires_at)}` : ''].filter(Boolean).join(' · '), 'muted small'),
        n.online && n.state !== 'ready' || n.state === 'connected' ? button('Adopt', async () => {
          try { const out = await (await postJSON(`/api/remote/nodes/${n.id}/adopt`, {})).json(); toast(out.state === 'scanning' ? 'Scanning it: press Adopt again when the scan is done' : `${n.name}: ${out.state}`); refresh(); } catch (err) { notify(err.message, 'error'); }
        }, 'btn sm') : '',
        button('Revoke…', async () => {
          if (!(await confirmDialog({ title: `Cut off ${n.name} now?`, body: 'It can only come back with a new install script.', confirm: 'Cut off', danger: true }))) return;
          try { await api(`/api/remote/nodes/${n.id}`, { method: 'DELETE' }); refresh(); } catch (err) { notify(err.message, 'error'); }
        }, 'btn ghost sm danger'))));
    } catch (err) { list.replaceChildren(text('p', err.message, 'st-failed small')); }
  };
  refresh();
  return el('details', { class: 'card stack' }, el('summary', {}, 'Remote nodes'),
    text('p', 'For hosts StorageForge cannot reach: they dial in through the tunnel. Only that port needs to be open to them.', 'muted small'),
    list, el('div', { class: 'row wrap' }, name, endpoint, button('Add node', async () => {
      try {
        const r = await (await postJSON('/api/remote/nodes', { name: name.value.trim(), endpoint: endpoint.value.trim() })).json();
        const a = el('a', { href: URL.createObjectURL(new Blob([r.script], { type: 'text/x-shellscript' })), download: `storageforge-remote-${r.name}.sh` });
        a.click(); URL.revokeObjectURL(a.href);
        toast(`Run the downloaded script as root on ${r.name} with --apply. Its key expires ${when(r.expires_at)}. It holds a private key: delete it afterwards.`);
        name.value = ''; refresh();
      } catch (err) { notify(err.message, 'error'); }
    }, 'btn sm')));
}
async function download(url, fallback, body) {   // body: POST it as JSON (for a download that changes something)
  try {
    const res = await (body ? postJSON(url, body) : api(url));
    const a = document.createElement('a'); a.href = URL.createObjectURL(await res.blob());
    a.download = (res.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || fallback;
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (err) { notify(err.message, 'error'); }
}

function removeAccess(host) {
  setupForm(host, true);
}

/* ── system updates ─────────────────────────────────────────────── */
function updatePill(u) {
  if (u.blocked) return text('span', 'cannot update', 'pill unknown');
  if (['running', 'queued'].includes(u.status)) return text('span', u.status, 'pill local-only');
  if (u.status && !['ok', 'incomplete'].includes(u.status)) return text('span', u.status, 'pill broken');
  if (u.pending === null) return text('span', u.status ? 'count unknown' : 'not checked', 'pill unknown');
  return u.pending ? text('span', `${u.pending} update${u.pending === 1 ? '' : 's'}`, 'pill local-only') : text('span', 'up to date', 'pill protected');
}
function updatesSection(d) {
  const rows = d.updates || [], able = rows.filter((u) => !u.blocked);
  const running = (d.groups || []).some((g) => g.kind === 'updates' && g.state === 'running');
  const updateAll = button(`Update all ${able.length} host${able.length === 1 ? '' : 's'}`, async () => {
    if (await confirmDialog({ title: `Install all system updates on ${able.length} host${able.length === 1 ? '' : 's'} now?`, body: 'Services whose packages change may restart. Nothing reboots.', confirm: 'Install updates' })) startDeploy('updates', 'all', 'apply', 'system updates on all hosts');
  }, 'btn pri sm');
  const check = button('Check for updates', () => startDeploy('updates', 'all', 'report', 'system updates on all hosts'), 'btn sm');
  updateAll.disabled = check.disabled = running || !able.length;
  return el('section', { class: 'stack' },
    el('div', { class: 'row wrap' }, el('h3', {}, 'System updates'), el('span', { class: 'row tools' }, check, updateAll)),
    text('p', 'Runs each host\'s own package manager, on every host at once. One host failing does not stop the others, local config files are kept, and nothing reboots: hosts that need it are marked here.', 'muted small'),
    rows.length ? el('ul', { class: 'dklist' }, ...rows.map((u) => el('li', {}, el('div', { class: 'row wrap' }, el('b', { class: 'mono' }, u.host), updatePill(u),
      u.reboot ? text('span', 'reboot waiting', 'pill local-only') : '',
      text('span', u.blocked || [u.manager, u.checked_at ? `checked ${when(u.checked_at)}` : '', u.updated_at ? `updated ${when(u.updated_at)}` : ''].filter(Boolean).join(' · '), 'muted small'),
      el('span', { class: 'row tools' }, u.group ? button('Output', () => openGroup(u.group), 'btn ghost sm') : '',
        u.blocked ? '' : button('Update', async () => {
          if (await confirmDialog({ title: `Install all system updates on ${u.host} now?`, body: 'Services whose packages change may restart. Nothing reboots.', confirm: 'Install updates' })) startDeploy('updates', u.host, 'apply', `system updates on ${u.host}`);
        }, 'btn ghost sm'))))))
      : text('p', 'No hosts are set up for deploys yet: set one up under Deploy access.', 'muted small'));
}

/* ── jobs ───────────────────────────────────────────────────────── */
async function jobAction(j, verb) {
  if (verb === 'cutover' && !(await confirmDialog({ title: `Cut over ${j.name}?`, body: 'The source is renamed to *.migrated-<date> after a clean verify.', confirm: 'Cut over', danger: true }))) return;
  toast(`${verb}: ${j.id}…`);
  try {
    const r = await (await postJSON(`/api/deploy/jobs/${j.id}/${verb}`, {})).json();
    if (verb === 'snapshots') { DP.job = { job: j, snapshots: r.snapshots || [], output: r.status === 'ok' ? '' : r.output }; renderJobPanel(); return; }
    if (['dryrun', 'log', 'cutover'].includes(verb) || r.status !== 'ok') { DP.job = { job: j, title: verb, output: r.output }; renderJobPanel(); }
    toast(r.status === 'ok' ? `${verb}: done` : `${verb}: ${r.status}`);
    if (['pause', 'resume', 'run', 'verify'].includes(verb)) setTimeout(loadDeploy, verb === 'run' || verb === 'verify' ? 4000 : 300);
  } catch (err) { notify(err.message, 'error'); }
}
async function jobHistory(j) {
  try { const r = await getJSON(`/api/deploy/jobs/${j.id}`); DP.job = { job: j, runs: r.runs }; renderJobPanel(); }
  catch (err) { notify(err.message, 'error'); }
}
function jobMenu(j) {
  const a = (label, verb, extra = {}) => ({ label, run: () => jobAction(j, verb), ...extra });
  if (j.imported) return snapJobMenu(j, a);
  return [{ heading: j.name }, a('Run now', 'run'), a('Dry run (what it would copy)', 'dryrun'), j.method !== 'git' ? a('Verify checksums now', 'verify') : null,
    j.paused ? a('Resume timers', 'resume') : a('Pause timers', 'pause'), '-', { label: 'History', run: () => jobHistory(j) }, a('Journal log', 'log'),
    j.snapshots ? a('Snapshots…', 'snapshots') : null, j.extent_dedup ? a('Run duperemove now', 'dedupe') : null, j.method === 'move' ? a('Cut over (rename the source)', 'cutover', { danger: true }) : null,
    '-', { label: 'Open the plan in Moves', run: () => { showTab('moves'); loadMoves(j.plan_id); } },
    { label: 'Copy job id', run: () => copyText(j.id) }];
}
function jobRow(j) {
  const last = j.last, verify = j.verify;
  const li = el('li', { class: 'card dpjob' },
    el('div', { class: 'row' }, text('span', j.state, `pill ${JOB_STATE[j.state] || 'unknown'}`), el('b', {}, j.name),
      el('span', { class: 'row tools' }, button('Run now', () => jobAction(j, 'run'), 'btn ghost sm'),
        button(j.method === 'snapper' ? 'Show config' : 'Dry run', () => jobAction(j, 'dryrun'), 'btn ghost sm'), button('⋯', (ev) => openMenu(jobMenu(j), ev.clientX, ev.clientY, li), 'btn ghost sm'))),
    text('span', [j.method, j.imported ? 'imported' : '', j.schedule ? `on "${j.schedule}"` : j.imported ? 'no schedule found' : 'run on demand',
      j.imported && j.levels ? Object.entries(j.levels).map(([k, v]) => `${k} ${v}`).join(', ') : '', j.fstype ? `on ${j.fstype}` : '', j.window ? `window ${j.window}` : '',
      j.snapshot ? 'btrfs snapshot first' : '', j.pre.length ? `${j.pre.length} pre command(s)` : '', j.verify_schedule ? `verify ${j.verify_schedule}` : '',
      j.transport && j.transport !== 'rsync' ? `${j.transport} stream` : '', j.routes && j.routes.length ? `routes ${j.routes.map((r) => r.via).join(' > ')}` : '',
      j.dedup ? 'dedup' : '', j.extent_dedup ? `duperemove ${j.extent_dedup}` : '',
      `runs on ${j.runner}`].filter(Boolean).join(' · '), 'muted small'),
    j.live && !['finished', 'failed'].includes(j.live.state) ? text('span', [j.live.state, j.live.percent != null ? `${j.live.percent}%` : '', j.live.speed,
      j.live.route ? `via ${j.live.route} ${j.live.node}` : '', j.live.dedup_ratio ? `dedup ${Math.round(j.live.dedup_ratio * 100)}%` : '',
      // a killed run never says it ended, and a stream says nothing while it sends: show how old this is, not that it is current
      Date.now() / 1000 - j.live.at > 300 ? `last heard ${when(j.live.at)}` : ''].filter(Boolean).join(' · '), Date.now() / 1000 - j.live.at > 300 ? 'muted small' : 'small') : '',
    last ? text('span', `last run ${when(last.end || last.start)}: ${last.rc === 0 ? 'ok' : 'exit ' + last.rc}${last.bytes ? ' · ' + fmtBytes(last.bytes) : ''}${last.files ? ` · ${last.files.toLocaleString()} files` : ''} · ${last.message || ''}`,
      last.rc === 0 ? 'small' : 'st-failed small') : text('span', j.paused ? 'paused' : 'no run reported yet', 'muted small'),
    j.last_ok && j.last_ok !== last ? text('span', `last good run ${when(j.last_ok.end)}`, 'muted small') : '',
    verify ? text('span', `verify ${when(verify.end)}: ${verify.message}`, verify.rc === 0 ? 'muted small' : 'st-failed small') : '',
    ...(j.fit || []).map(fitLine));
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
  } catch (err) { notify(err.message, 'error'); }
}
async function restoreFrom(j, snapshot, path) {
  if (!(await confirmDialog({ title: `Restore ${path} from ${snapshot}?`, body: `It goes to ${j.source}, beside the original as ${path}.restored-<time>. Nothing is overwritten.`, confirm: 'Restore' }))) return;
  try {   // it runs in the background; its runs show like a deploy's
    const r = await (await postJSON(`/api/deploy/jobs/${j.id}/restore`, { snapshot, path })).json();
    DP.group = { gid: r.group, kind: 'restore', ref: j.id, mode: 'apply', title: `restore ${path} from ${snapshot} into ${j.source}:${r.target}`,
                 extra: {}, runs: [], done: false };
    renderGroup(); pollGroup(); toast('Restore started');
  } catch (err) { notify(err.message, 'error'); }
}

/* ── rsnapshot and snapper jobs StorageForge did not deploy ─────── */
function fitLine(f) { return text('span', f.text, f.level === 'crit' ? 'st-failed small' : 'muted small'); }
function snapJobMenu(j, a) {
  return [{ heading: j.name }, a('Run now', 'run'), a(j.method === 'snapper' ? 'Show config and snapshots' : 'Dry run (what it would copy)', 'dryrun'),
    j.paused ? a('Resume its schedule', 'resume') : a('Pause its schedule', 'pause'), '-', { label: 'History', run: () => jobHistory(j) }, a('Log', 'log'), a('Snapshots…', 'snapshots'),
    { label: 'Retention…', run: () => editRetention(j) }, '-',
    { label: 'Forget (leaves the host as it is)', run: () => forgetJob(j), danger: true }, { label: 'Copy job id', run: () => copyText(j.id) }];
}
function snapMapsChanged() {       // the graphs and the Files map hold what they last loaded
  FM.data = null;
  loadGraph(); loadDesigns();
  if (fmActive()) fmLoad();
}
async function editRetention(j) {
  const now = Object.entries(j.levels || {}).map(([k, v]) => `${k}=${v}`).join(' ');
  const form = await formDialog({
    title: `How many of ${j.name}'s snapshots to keep?`,
    body: `A lower count deletes older snapshots at the next ${j.method === 'snapper' ? 'cleanup' : 'rotation'}.`,
    fields: [{ name: 'keep', label: 'Keep, per level', value: now, placeholder: 'daily=7 weekly=4', hint: 'A level, an equals sign and a count, with a space between levels.',
               validate: (v) => (/^\w+=\d+(\s+\w+=\d+)*$/.test(v) ? '' : 'Write it as level=count, like daily=7 weekly=4.') }],
  });
  if (form === null || form.keep === now) return;
  const keep = {};
  for (const w of form.keep.split(/\s+/)) { const [k, v] = w.split('='); keep[k] = Number(v); }
  try {
    const r = await (await postJSON(`/api/deploy/jobs/${j.id}/retention`, { keep })).json();
    DP.job = { job: j, title: 'retention', output: r.output }; renderJobPanel(); loadDeploy();
  } catch (err) { notify(err.message, 'error'); }
}
async function forgetJob(j) {
  if (!(await confirmDialog({ title: `Stop tracking ${j.name}?`, body: `It keeps running on ${j.runner}, and its snapshots stay.`, confirm: 'Stop tracking' }))) return;
  try { await postJSON(`/api/deploy/jobs/${j.id}/forget`, {}); toast('Forgotten'); loadDeploy(); snapMapsChanged(); } catch (err) { notify(err.message, 'error'); }
}
async function importFound(f) {
  try { await postJSON('/api/deploy/snapjobs/import', { host: f.host, tool: f.tool, config: f.config }); toast(`Imported ${f.name}`); loadDeploy(); snapMapsChanged(); }
  catch (err) { notify(err.message, 'error'); }
}
async function lookAsRoot(host) {
  toast(`Looking on ${host} as root…`);
  try { const r = await (await postJSON('/api/deploy/snapjobs/probe', { host })).json(); DP.found = r.found; renderSnapFound(); loadDeploy(); snapMapsChanged(); toast('Done'); }
  catch (err) { notify(err.message, 'error'); }
}
function foundRow(f, ready) {
  const levels = Object.entries(f.levels || {}).map(([k, v]) => (v === null ? k : `${k} ${v}`)).join(', ');
  const usable = !f.orphan && f.readable !== false && f.root;
  return el('li', {}, el('div', { class: 'row wrap' }, text('span', f.tool, 'pill unknown'), el('b', { class: 'mono' }, `${f.host}:${f.root || f.config}`),
    el('span', { class: 'row tools' },
      ready.has(f.host) && !usable ? button('Look as root', () => lookAsRoot(f.host), 'btn ghost sm') : '',
      usable ? button('Import', () => importFound(f), 'btn sm') : '')),
  text('span', [f.config, f.fstype ? `on ${f.fstype}` : '', levels, f.count ? `${f.count} snapshots, newest ${when(f.newest)}` : '',
    (f.schedule || []).map((e) => e.unit || e.file).join(', ')].filter(Boolean).join(' · '), 'muted small'),
  !usable && !f.orphan ? text('span', ready.has(f.host) ? 'The scan account cannot read it: look as root.' : 'The scan account cannot read it: set up deploy access to look as root.', 'muted small') : '',
  f.orphan && !ready.has(f.host) ? text('span', 'Set up deploy access to look for its config as root.', 'muted small') : '',
  ...(f.fit || []).map(fitLine));
}
function newSnapForm(d) {
  const host = el('select', {}, ...d.access.map((a) => new Option(a.host, a.host))), path = el('input', { type: 'text', class: 'mono', placeholder: '/home' });
  const out = el('div', { class: 'stack' });
  const check = async () => {
    try {
      const a = await getJSON(`/api/deploy/snapjobs/advice?host=${encodeURIComponent(host.value)}&path=${encodeURIComponent(path.value.trim())}`);
      const name = el('input', { type: 'text', class: 'mono', placeholder: 'config name, e.g. home' });
      out.replaceChildren(text('p', `${a.path} is on ${a.fstype || 'an unknown filesystem'} (${a.mount || '?'}). ${a.why}`, a.level === 'crit' ? 'st-failed small' : 'small'),
        a.tool === 'snapper' ? el('div', { class: 'row' }, name, button('Create snapper config', async () => {
          try { const r = await (await postJSON('/api/deploy/snapjobs/snapper', { host: a.host, path: a.path, name: name.value.trim() })).json();
            out.append(outputBlock(r.output)); loadDeploy(); snapMapsChanged(); } catch (err) { notify(err.message, 'error'); }
        }, 'btn sm')) : a.tool === 'rsnapshot' ? button('Plan an rsnapshot step in Moves', () => showTab('moves'), 'btn sm') : '');
    } catch (err) { out.replaceChildren(text('p', err.message, 'st-failed small')); }
  };
  return el('details', { class: 'card stack' }, el('summary', {}, 'New snapshot job'),
    text('p', 'Picks the tool for the folder\'s filesystem: snapper on btrfs, rsnapshot on ext4, xfs and others with hard links.', 'muted small'),
    el('div', { class: 'row wrap' }, host, path, button('Check', check, 'btn ghost sm')), out);
}
function renderSnapFound() {
  const box = $('#dpsnapfound');
  if (!box) return;
  const ready = new Set((DP.data?.access || []).filter((a) => a.state === 'ready').map((a) => a.host));
  const fresh = (DP.found || []).filter((f) => !f.job);
  box.replaceChildren(fresh.length ? el('ul', { class: 'dklist' }, ...fresh.map((f) => foundRow(f, ready)))
    : text('p', DP.found ? 'Nothing new found. Scans look at /etc, cron and systemd; Look as root also reads what only root can.' : 'Looking…', 'muted small'));
}

/* ── the tab ────────────────────────────────────────────────────── */
/* The running deploy has its own box, which stays put while the rest of the tab reloads around it. */
function deployBoxes() {
  if (!DP.rest) {
    DP.groupBox = el('div', { id: 'dpgroup', class: 'stack', hidden: true });
    DP.rest = el('div', { class: 'stack' });
    $('#deploybox').replaceChildren(DP.groupBox, DP.rest);
  }
  return DP.rest;
}
const foldKey = (d) => (d.querySelector(':scope > summary')?.textContent || '').replace(/\d+/g, '#');   // "Recent deploys (3)" stays itself at 4

function renderDeploy() {
  const box = deployBoxes();
  if (DP.err) { box.replaceChildren(text('p', DP.err, 'st-failed')); return; }
  const d = DP.data;
  if (!d) { box.replaceChildren(text('p', 'Loading…', 'muted')); return; }
  const scroller = box.closest('.tab'), top = scroller ? scroller.scrollTop : 0;
  const folds = new Map([...box.querySelectorAll('details')].map((x) => [foldKey(x), x.open]));
  const typing = DP.setup?.contains(document.activeElement) ? document.activeElement : null;
  const parts = [el('div', { id: 'dpsetup' }, DP.setup || ''), el('div', { id: 'dpjobpanel', class: 'card stack', hidden: true })];
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
  parts.push(updatesSection(d));
  // jobs by plan
  const byPlan = new Map();
  for (const j of d.jobs.filter((x) => !x.imported)) { if (!byPlan.has(j.plan_id)) byPlan.set(j.plan_id, []); byPlan.get(j.plan_id).push(j); }
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
  const imported = d.jobs.filter((x) => x.imported);
  parts.push(el('section', { class: 'stack' }, el('h3', {}, 'Existing snapshot jobs (rsnapshot, snapper)'),
    text('p', 'Importing tracks a job and lets you run, pause and restore from it here. Its config, cron lines and timers stay where they are.', 'muted small'),
    imported.length ? el('ol', { class: 'chtasks' }, ...imported.map(jobRow)) : '',
    el('div', { id: 'dpsnapfound' }),
    ready.size ? el('div', { class: 'row wrap' }, ...[...ready].map((h) => button(`Look on ${h} as root`, () => lookAsRoot(h), 'btn ghost sm'))) : '',
    DP.newSnap || (DP.newSnap = newSnapForm(d))));
  // shares
  const shareHosts = [...new Set([...d.deployed.filter((x) => x.kind === 'shares').map((x) => x.ref), ...(d.share_hosts || [])])].sort();
  parts.push(el('section', { class: 'stack' }, el('div', { class: 'row' }, el('h3', {}, 'Shares (NFS, SMB)'), el('span', { class: 'grow' }),
    button('+ New share', () => openShareWizard({}), 'btn ghost sm')),
    shareHosts.length ? el('ul', { class: 'dklist' }, ...shareHosts.map((h) => {
      const dep = d.deployed.find((x) => x.kind === 'shares' && x.host === h && x.ref === h);
      return el('li', {}, el('div', { class: 'row wrap' }, el('b', { class: 'mono' }, h),
        text('span', dep ? `deployed ${when(dep.at)} · clients: ${(dep.detail.clients || []).join(', ') || 'none'}` : 'not deployed', 'muted small'),
        pending.get(h) ? text('span', 'design changed', 'pill local-only') : '',
        el('span', { class: 'row tools' }, button('Check', () => deployShares(T.docs.get(h) || { host: h }), 'btn ghost sm'),
          button('Deploy (report first)…', () => startDeploy('shares', h, 'report', `shares of ${h}`), 'btn sm'))));
    })) : text('p', 'No shares designed yet. Add one with + New share, then deploy it here.', 'muted small')));
  // schedules deleted while installed (older versions allowed it): a timer still runs them as root
  const orphans = [...new Set(d.drift.filter((x) => x.deleted).map((x) => x.schedule))];
  if (orphans.length) {
    parts.push(el('section', { class: 'stack' }, el('h3', {}, 'Deleted schedules still on hosts'),
      el('ul', { class: 'dklist' }, ...orphans.map((sid) => el('li', {}, el('div', { class: 'row wrap' }, el('b', {}, `schedule #${sid}`),
        text('span', d.drift.filter((x) => x.schedule === sid).map((x) => x.host).join(', '), 'muted small'),
        el('span', { class: 'row tools' }, button('Uninstall', () => startDeploy('schedules', sid, 'apply', `uninstall deleted schedule #${sid}`, { remove: true }), 'btn ghost sm danger'))))))));
  }
  // drift
  const changed = d.drift.filter((x) => x.kind === 'changed');
  parts.push(el('section', { class: 'stack' }, el('h3', {}, 'Drift'),
    changed.length ? el('ul', { class: 'mvcheck' }, ...changed.map((x) => el('li', { class: 'lv-warn' }, `${x.host}: ${x.text}`)))
      : text('p', 'Nothing deployed was changed by hand, as of each host\'s last scan.', 'muted small')));

  parts.push(remoteNodesCard());
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
  for (const x of box.querySelectorAll('details')) if (folds.has(foldKey(x))) x.open = folds.get(foldKey(x));
  typing?.focus();
  renderGroup(); renderJobPanel(); renderSnapFound();
  if (scroller) scroller.scrollTop = top;
}

async function showHistory(host) {
  try {
    const { runs } = await getJSON(`/api/deploy/runs?host=${encodeURIComponent(host)}&limit=30`);
    DP.job = { job: { name: `deploy history of ${host}` }, title: '', output: runs.map((r) => `${stamp(r.started_at)}  ${r.kind} ${r.ref || ''}  ${r.mode}  ${r.status}${r.confirmed_at ? ' (confirmed: ' + (r.host_exit === 0 ? 'ok' : 'exit ' + r.host_exit) + ')' : ''}`).join('\n') || 'nothing yet' };
    renderJobPanel();
  } catch (err) { notify(err.message, 'error'); }
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
