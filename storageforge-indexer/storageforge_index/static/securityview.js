'use strict';
/* Security: what hosts report about themselves, and the levers that act on them.
   Two rules, both for the person reading this page in the middle of an incident: a value nobody measured says "not measured",
   never a reassuring default; and a button says what really happened, from what the run on the host reported.
   Under the strict CSP nothing here may be an inline handler: everything is built with el(), text() and button(). */

const SEC = { panel: 'overview' };
const SEC_PANELS = [['overview', 'Overview'], ['worm', 'Holds'], ['decoys', 'Decoys'], ['mac', 'Access control'], ['firewall', 'Firewall'],
                    ['behavior', 'Behaviour'], ['integrity', 'Integrity'], ['compliance', 'Compliance']];
const SEC_NEEDS_HOST = new Set(['decoys', 'mac', 'behavior', 'integrity', 'compliance']);

const secWhen = (t) => (t ? new Date(t * 1000).toLocaleString() : 'never');
const secAgo = (t) => {
  if (!t) return 'never';
  const s = Math.max(0, Date.now() / 1000 - t);
  return s < 90 ? 'just now' : s < 5400 ? `${Math.round(s / 60)} min ago` : s < 129600 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} days ago`;
};
const secSpan = (s) => (s === null || s === undefined ? '' : s < 5400 ? `${Math.round(s / 60)} min` : s < 129600 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} days`);
const secQ = (host) => (host ? `?host=${encodeURIComponent(host)}` : '');
const NOT_MEASURED = 'not measured';
const secVal = (v, suffix = '') => (v === null || v === undefined ? NOT_MEASURED : `${v}${suffix}`);
const secPill = (label, tone) => text('span', label, `sec-pill sec-${tone}`);
const secOkPill = (v, yes = 'yes', no = 'no') => (v === null || v === undefined ? secPill(NOT_MEASURED, 'unknown') : v ? secPill(yes, 'secure') : secPill(no, 'warning'));
const secCard = (title, ...kids) => el('section', { class: 'sec-card' }, text('h3', title), ...kids);
const secStat = (label, value, cls = '') => el('div', {}, text('small', label), text('b', String(value), cls));
/* The panel is a narrow rail, so a "table" is a stack of rows: the first cell heads each one, the rest are labelled lines. */
const secCell = (c) => (c instanceof Node ? c : text('span', c === null || c === undefined ? '' : String(c)));
const secEmpty = (c) => c === null || c === undefined || c === '' || (c instanceof Node && !c.textContent && !c.childElementCount);
const secTable = (heads, rows) => el('div', { class: 'sec-rows' }, ...rows.map((r) => el('div', { class: 'sec-row' },
  el('div', { class: 'sec-row-head' }, secCell(r[0])),
  ...r.slice(1).map((c, i) => (secEmpty(c) ? null : heads[i + 1] ? el('div', { class: 'sec-kv' }, text('span', heads[i + 1], 'sec-k'), el('div', { class: 'sec-v' }, secCell(c))) : el('div', { class: 'sec-v' }, secCell(c)))))));
const secField = (label, input) => el('label', { class: 'sec-field' }, text('span', label), input);

function secInput(placeholder, value = '') { const i = el('input', { type: 'text', placeholder }); i.value = value; return i; }
function secArea(placeholder, value = '') { const i = el('textarea', { rows: '3', placeholder }); i.value = value; return i; }
const secCan = (perm) => can(perm);

/* Posts, then shows the answer in place. api() throws on a refusal: the body explains why, and the run's output belongs beside it. */
async function secPost(path, body, out, method = 'POST', touched = false) {
  out.replaceChildren(text('p', 'Working…', 'muted small'));
  try {
    const opts = method === 'DELETE' ? { method } : null;
    const res = opts ? await api(path, opts) : await postJSON(path, body);
    return secShow(await res.json(), out);
  } catch (err) {
    if (err.body?.webauthn && !touched) {
      out.replaceChildren(text('p', 'Touch your security key.', 'st-warn'));
      try { await secTouchKey(); } catch (e) { out.replaceChildren(text('p', e.message, 'st-failed')); return null; }
      return secPost(path, body, out, method, true);
    }
    if (err.body) return secShow(err.body, out);
    out.replaceChildren(text('p', err.message, 'st-failed'));
    return null;
  }
}

function secShow(r, out) {
  const kids = [];
  if (r.error) kids.push(text('p', r.error, 'st-failed'));
  else if (r.message) kids.push(text('p', r.message, 'st-ok'));
  else if (r.mode === 'apply') kids.push(text('p', 'Done, and confirmed on the host.', 'st-ok'));
  else if (r.mode === 'report') kids.push(text('p', 'Dry run: nothing was changed.', 'muted'));
  if (r.steps?.length) kids.push(secTable(['Step', 'Outcome', 'Detail'], r.steps.map((s) => [s.step, secPill(s.status, s.status === 'ok' ? 'secure' : s.status === 'failed' ? 'critical' : 'unknown'), s.detail])));
  if (r.break_glass_key) {
    kids.push(text('p', 'Write this down now. It is not stored and will not be shown again:', 'st-failed'));
    kids.push(el('pre', { class: 'sec-key' }, r.break_glass_key));
  }
  if (r.script) kids.push(el('pre', { class: 'small sec-out' }, r.script));
  if (r.output) kids.push(el('pre', { class: 'small sec-out' }, r.output));
  out.replaceChildren(...kids);
  return r.error ? null : r;
}

/* The three things every action on a host can do. The UI never skips straight to a change without the dry run being one click away. */
function secActions(path, body, out, { apply = 'Apply', after, danger, need = 'security.manage' } = {}) {
  const go = (mode) => async () => {
    if (mode === 'apply' && danger && !confirm(danger)) return;
    const r = await secPost(path, { ...body(), mode }, out);
    if (r && mode === 'apply' && after) after(r);
  };
  if (!secCan(need)) return el('div', {});
  return el('div', { class: 'row wrap sec-acts' }, button('Show script', go('preview'), 'btn sm ghost'), button('Dry run', go('report'), 'btn sm'), button(apply, go('apply'), danger ? 'btn sm danger' : 'btn sm pri'));
}

async function loadSecurity() {
  const nav = $('#sec-subnav');
  if (!nav.childElementCount) {
    nav.append(...SEC_PANELS.map(([id, label]) => {
      const b = button(label, () => secOpen(id));
      b.dataset.sub = id;
      return b;
    }));
  }
  secOpen(window.SEC_LINK_PANEL || SEC.panel);
  window.SEC_LINK_PANEL = null;
}

function secOpen(panel) {
  SEC.panel = SEC_PANELS.some(([id]) => id === panel) ? panel : 'overview';
  document.querySelectorAll('#sec-subnav button').forEach((b) => b.setAttribute('aria-pressed', b.dataset.sub === SEC.panel));
  secRender();
}

async function secRender() {
  const box = $('#sec-content'), turn = (SEC.turn = (SEC.turn || 0) + 1);      // a slow panel must not land on top of the one clicked after it
  box.replaceChildren(text('p', 'Loading…', 'muted'));
  await secBanner();
  if (turn !== SEC.turn) return;
  if (SEC_NEEDS_HOST.has(SEC.panel) && !S.host) {
    box.replaceChildren(text('p', 'Pick a host at the top of the page: this panel is about one host at a time.', 'muted'));
    return;
  }
  try {
    const built = await ({ overview: secOverview, worm: secWorm, decoys: secDecoys, mac: secMac, firewall: secFirewall, behavior: secBehavior, integrity: secIntegrity, compliance: secCompliance, ...SEC_MORE })[SEC.panel]();
    if (turn === SEC.turn) box.replaceChildren(built);
  } catch (err) {
    if (turn === SEC.turn) box.replaceChildren(text('p', err.message, 'st-failed'));
  }
}

async function secBanner() {
  const b = $('#sec-banner');
  try {
    const p = await getJSON(`/api/security/posture${secQ(S.host)}`);
    SEC.posture = p;
    b.className = `sec-banner sec-${p.state}`;
    b.replaceChildren(text('b', { secure: 'Nothing wrong found', warning: 'Needs a look', critical: 'Incident', unknown: 'Not known' }[p.state]), text('span', p.banner));
  } catch (err) {
    b.className = 'sec-banner sec-unknown';
    b.replaceChildren(text('span', err.message, 'st-failed'));
  }
}

function secMeasureButton(host, out) {
  return button('Measure now', async () => { if (await secPost('/api/security/measure', { host }, out)) secRender(); }, 'btn sm');
}

/* ── overview ─────────────────────────────────────────────────────── */
async function secOverview() {
  const p = SEC.posture || await getJSON(`/api/security/posture${secQ(S.host)}`);
  const out = el('div', { class: 'stack' });
  const rows = p.hosts.map((h) => {
    const why = el('div', { class: 'small' });
    h.critical.forEach((c) => why.append(text('div', c, 'st-failed')));
    h.warnings.forEach((c) => why.append(text('div', c, 'st-warn')));
    h.gaps.forEach((c) => why.append(text('div', c, 'muted')));
    if (!why.childElementCount) why.append(text('div', 'nothing found', 'muted'));
    return [text('b', h.host), secPill(h.state, h.state), h.measured_at ? secAgo(h.measured_at) : NOT_MEASURED,
            h.sentinel ? (h.sentinel_active === null ? 'deployed' : h.sentinel_active ? `running${h.armed ? ', armed' : ''}` : 'not running') : 'none',
            `${h.decoys_armed} armed${h.decoys_tripped ? `, ${h.decoys_tripped} tripped` : ''}`, `${h.holds_verified} of ${h.holds_active} verified`, secVal(h.mac), why,
            secCan('security.manage') && h.deploy_ready ? secMeasureButton(h.host, out) : text('span', h.deploy_ready ? '' : 'set up deploy access first', 'muted small')];
  });
  const kids = [secCard('Hosts', p.hosts.length ? secTable(['Host', 'State', 'Measured', 'Sentinel', 'Decoys', 'Holds', 'Access control', 'What is known', ''], rows) : text('p', 'No hosts have been scanned yet.', 'muted'), out)];
  if (p.clock_suspect) {
    const c = p.clock_suspect;
    kids.unshift(secCard('This machine\'s clock looks wrong',
      text('p', `${c.agree} of ${c.measured} hosts differ from it by the same ${c.seconds} s, which unrelated clocks do not do. It looks ${c.direction}, so the hosts are probably fine. Timelocks have stopped, and past 10 minutes hosts refuse signed runs.`, 'st-failed'),
      text('p', 'Fix time sync on the machine StorageForge runs on, and in its container if it has its own clock. Then measure the hosts again and clear this.', 'muted small'),
      secCan('security.emergency') ? button('Fixed and measured: clear the hosts', async () => { if (await secPost('/api/security/worm/clock/clear', { controller: true }, out)) secRender(); }, 'btn sm') : ''));
  }
  if (p.controller_clock) {
    kids.unshift(secCard('This machine\'s clock moved', text('p', `${p.controller_clock.reason}. Cool-offs are timed on this clock, so none will run until someone has looked.`, 'st-failed'),
      button('It is right now: clear this', async () => { if (await secPost('/api/security/worm/clock/clear', { controller: true }, out)) secRender(); }, 'btn sm')));
  }
  kids.push(secCard('Alarms', p.events.length ? secTable(['When', 'Host', 'What', 'From', ''], p.events.map((e) => [secWhen(e.occurred_at), e.host, el('div', {}, secPill(e.severity, e.severity === 'crit' ? 'critical' : 'warning'), text('span', ` ${e.summary}`)), e.via,
    e.acknowledged_at ? text('span', `seen by ${e.acknowledged_by}`, 'muted small') : secCan('security.emergency') ? button('Seen', async () => { if (await secPost(`/api/security/events/${e.id}/ack`, {}, out)) secRender(); }, 'btn sm') : ''])) : text('p', 'None recorded. That only means something for hosts with a running sentinel.', 'muted')));
  if (S.host) kids.push(await secIncident(S.host));
  return el('div', { class: 'stack' }, ...kids);
}

async function secIncident(host) {
  const b = await getJSON(`/api/security/incident/blast-radius${secQ(host)}`);
  const out = el('div', { class: 'stack' });
  const path = secInput('/srv/shares/finance'), client = secInput('10.0.1.42'), pid = secInput('optional'), minutes = secInput('0', '0');
  const checks = ['triage', 'quarantine', 'snapshot', 'freeze'].map((a) => { const c = el('input', { type: 'checkbox' }); c.checked = true; c.value = a; return c; });
  const snap = secInput('tank/shares@sf-incident-…, or a btrfs path', b.newest_hold?.snapshot || ''), mnt = secInput('/mnt/sf-cleanroom', '/mnt/sf-cleanroom');
  return el('div', { class: 'stack' },
    secCard(`Damage on ${host}`,
      !b.incident_at ? text('p', 'No incident is recorded on this host.', 'muted') : el('div', { class: 'stack' },
        el('div', { class: 'stat-row' }, secStat('Incident', secWhen(b.incident_at)), secStat('Changed since', secVal(b.changed_since)), secStat('Unchanged', secVal(b.unchanged_files)), secStat('Named like ransomware', secVal(b.ransom_names), b.ransom_names ? 'st-failed' : ''),
          secStat('Extra extensions', secVal(b.appended_extensions)), secStat('Look encrypted', secVal(b.entropy_flagged)), secStat('Most data lost', b.rpo_seconds === null ? 'no hold from before' : secSpan(b.rpo_seconds))),
        text('p', b.scan_at ? `From the scan of ${secWhen(b.scan_at)}. A scan compares names, sizes and dates: "unchanged" means it saw no difference, not that the contents were checked.` : 'No scan since the incident, so there are no file counts. Freeze first, then scan.', 'muted small'))),
    secCan('security.emergency') ? secCard('Emergency brake',
      text('p', 'Runs on the host now, in this order, and reports each step: save what is only in memory, drop the client, snapshot and hold, make the filesystem read-only. A step that cannot run says so.', 'muted small'),
      el('div', { class: 'sec-form' }, secField('Path under attack', path), secField('Client address', client), secField('Process id', pid), secField('Drop for minutes (0: until lifted)', minutes)),
      el('div', { class: 'row wrap' }, ...checks.map((c) => el('label', { class: 'small' }, c, ` ${c.value}`))),
      secActions('/api/security/incident/brake', () => ({ host, path: path.value.trim(), client_ip: client.value.trim(), pid: pid.value.trim(), minutes: minutes.value.trim(), actions: checks.filter((c) => c.checked).map((c) => c.value) }), out,
        { apply: 'Pull the brake', danger: `Pull the emergency brake on ${host}? Shares on that path stop accepting writes.`, need: 'security.emergency', after: () => secRender() }), out) : el('div', {}),
    secCan('security.emergency') ? secCard('Clean room',
      text('p', 'Mounts a snapshot read-only with no programs or devices, shared with nobody, to look at before trusting it.', 'muted small'),
      el('div', { class: 'sec-form' }, secField('Snapshot', snap), secField('Mount at', mnt)),
      secActions('/api/security/incident/clean-room', () => ({ host, snapshot: snap.value.trim(), mount: mnt.value.trim() }), out, { apply: 'Mount it', need: 'security.emergency' }),
      el('div', { class: 'row wrap' }, button('Sweep it with ClamAV and YARA', async () => { const r = await secPost('/api/security/incident/clean-room/sweep', { host, mount: mnt.value.trim() }, out); if (r) out.prepend(text('p', r.clean ? `${r.message}, in ${r.files} files.` : r.hits.length ? `${r.hits.length} found in ${r.files} files: ${r.hits.slice(0, 5).map((h) => h.what).join('; ')}` : 'Neither ClamAV nor YARA is on this host, so nothing was checked.', r.clean ? 'st-ok' : 'st-failed')); }, 'btn sm'),
        button('Take it down', () => secPost('/api/security/incident/clean-room', { host, snapshot: snap.value.trim(), mount: mnt.value.trim(), mode: 'apply', remove: true }, out), 'btn sm ghost'))) : el('div', {}));
}

/* ── holds ────────────────────────────────────────────────────────── */
async function secWorm() {
  const d = await getJSON(`/api/security/worm/holds${secQ(S.host)}`);
  const out = el('div', { class: 'stack' }), emergency = secCan('security.emergency');
  const redo = (r) => { if (r) secRender(); };
  const rows = d.holds.map((h) => {
    const release = el('div', { class: 'row wrap' });
    if (emergency && h.status === 'locked') {
      release.append(button(h.expired ? 'Release' : 'Ask to release', async () => {
        const legal = h.legal_hold && confirm(`${h.snapshot} is a legal hold. Ask to release it anyway?`);
        if (h.legal_hold && !legal) return;
        redo(await secPost('/api/security/worm/release', { hold_id: h.id, release_legal: legal }, out));
      }, 'btn sm ghost'));
    }
    const state = h.missing_at ? secPill('gone from host', 'critical') : h.status === 'release_pending' ? secPill('release waiting', 'warning') : h.status === 'released' ? secPill('released', 'unknown') : h.verified_at ? secPill(`seen ${secAgo(h.verified_at)}`, 'secure') : secPill('not seen yet', 'unknown');
    return [h.host, h.snapshot, h.hold_tag, h.filesystem, secWhen(h.created_at), h.legal_hold ? 'legal: until released' : h.expired ? `passed ${secWhen(h.expires_at)}` : secWhen(h.expires_at), state, release];
  });
  const q = d.quorum, kids = [];
  if (d.clock) {
    const c = d.clock;
    kids.push(secCard(`Clock on ${S.host}`,
      el('div', { class: 'stat-row' }, secStat('Off the controller', c.measured_at ? `${c.offset_seconds || 0} s` : NOT_MEASURED), secStat('Time source', c.chrony ? `${c.chrony.source} (${c.chrony.offset_ms} ms)` : c.ntp_synced === null ? NOT_MEASURED : c.ntp_synced ? 'synchronized' : 'not synchronized'), secStat('NTS sources', secVal(c.nts_sources)), secStat('Measured', secAgo(c.measured_at))),
      c.frozen ? el('div', { class: 'stack' }, text('p', `Releases on this host are stopped: ${c.reason}`, 'st-failed'), emergency ? button('I have looked: clear it', async () => redo(await secPost('/api/security/worm/clock/clear', { host: S.host }, out)), 'btn sm') : '') : text('p', 'A jump of over a minute against uptime or this machine stops all releases on this host until someone clears it. Holds expire on this machine\'s clock, so moving the host\'s cannot expire one.', 'muted small')));
  }
  kids.push(secCard('Who can release a hold',
    el('div', { class: 'stat-row' }, secStat('Rule', q.label), secStat('Established admins', q.established_admins), secStat('Offline key', q.break_glass_armed ? 'made' : 'not made', q.break_glass_armed ? '' : 'st-warn')),
    text('p', 'An admin account counts only once it is older than the cool-off, so an attacker cannot make a second admin to approve themselves. Every pending release raises an alert through your channels.', 'muted small'),
    emergency ? el('div', { class: 'row wrap' }, button(q.break_glass_armed ? 'Replace the offline key' : 'Make the offline key', async () => redo(await secPost('/api/security/worm/break-glass/key', {}, out)), 'btn sm')) : ''));
  if (d.pending.length) {
    kids.push(secCard('Waiting', secTable(['What', 'Host', 'Asked by', 'Asked', 'Runs', ''], d.pending.map((t) => {
      const key = secInput('offline key'), acts = el('div', { class: 'row wrap' });
      if (emergency) {
        acts.append(button('Abort', async () => redo(await secPost('/api/security/worm/abort', { timelock_id: t.id }, out)), 'btn sm danger'));
        if (t.mode === 'dual_admin') acts.append(button('Approve', async () => redo(await secPost('/api/security/worm/quorum/approve', { timelock_id: t.id }, out)), 'btn sm'));
        if (t.action === 'worm_release') acts.append(key, button('Use the key', async () => redo(await secPost('/api/security/worm/break-glass', { timelock_id: t.id, break_glass_key: key.value.trim() }, out)), 'btn sm'));
      }
      return [t.action === 'worm_release' ? `release ${t.target_ref}` : 'replace the offline key', t.host, t.actor, secWhen(t.requested_at), t.mode === 'dual_admin' ? 'when a second admin approves' : `in ${secSpan(t.remaining_seconds)}`, acts];
    }))));
  }
  const snapshot = secInput('tank/shares@daily, or a btrfs path'), days = secInput('14', '14'), legal = el('input', { type: 'checkbox' }), create = el('input', { type: 'checkbox' });
  kids.push(secCard('Holds', el('div', { class: 'stat-row' }, secStat('Active', d.summary.active), secStat('Seen on host', d.summary.verified), secStat('Gone from host', d.summary.missing, d.summary.missing ? 'st-failed' : ''), secStat('Legal', d.summary.legal), secStat('Expiring in a day', d.summary.expiring_24h)),
    d.holds.length ? secTable(['Host', 'Snapshot', 'Tag', 'Kind', 'Made', 'Until', 'On the host', ''], rows) : text('p', 'No holds yet.', 'muted'),
    text('p', 'A ZFS hold stops zfs destroy, including by mistake or by a script, and btrfs read-only stops writes. Neither stops someone with root who releases it first: this page would then show it gone. Only a copy on another machine is out of their reach.', 'muted small')));
  if (S.host && emergency) {
    kids.push(secCard(`New hold on ${S.host}`, el('div', { class: 'sec-form' }, secField('Snapshot', snapshot), secField('Days', days)),
      el('div', { class: 'row wrap' }, el('label', { class: 'small' }, legal, ' legal hold: until released'), el('label', { class: 'small' }, create, ' take the ZFS snapshot if it is not there')),
      secActions('/api/security/worm/hold', () => ({ host: S.host, snapshot: snapshot.value.trim(), retention_days: days.value.trim(), legal_hold: legal.checked, create: create.checked }), out, { apply: 'Hold it', need: 'security.emergency', after: () => secRender() })));
  }
  kids.push(out);
  return el('div', { class: 'stack' }, ...kids);
}

/* ── decoys ───────────────────────────────────────────────────────── */
async function secDecoys() {
  const host = S.host, d = await getJSON(`/api/security/canaries${secQ(host)}`), c = d.config, out = el('div', { class: 'stack' });
  const folders = secArea('/srv/shares/finance', (c.folders.length ? c.folders : d.suggested).join('\n')), names = secArea('', c.names.join('\n'));
  const armed = el('input', { type: 'checkbox' }); armed.checked = c.armed;
  const minutes = secInput('60', String(c.minutes));
  const spread = el('select', { 'aria-label': 'Where decoys go' }, new Option('Only in these folders', 'root'), new Option('Their first level too', 'top'), new Option('Some folders further down', 'random'), new Option('Folders the last scan saw change', 'recent'));
  spread.value = c.spread || 'root';
  const checks = ['triage', 'quarantine', 'snapshot', 'freeze'].map((a) => { const i = el('input', { type: 'checkbox' }); i.checked = c.actions.includes(a); i.value = a; return i; });
  const save = async () => secPost('/api/security/sentinel', { host, spread: spread.value, folders: folders.value.split('\n').map((s) => s.trim()).filter(Boolean), names: names.value.split('\n').map((s) => s.trim()).filter(Boolean), armed: armed.checked, minutes: minutes.value.trim(), actions: checks.filter((i) => i.checked).map((i) => i.value) }, out);
  const go = (mode, title, extra = {}) => async () => { if (await save()) startDeploy('security', host, mode, title, extra); };
  const test = d.last_test;
  const kids = [secCard(`Sentinel on ${host}`,
    el('div', { class: 'stat-row' }, secStat('Deployed', d.installed ? (d.out_of_date ? 'yes, an older version' : 'yes') : 'no', d.out_of_date ? 'st-warn' : ''), secStat('Running', d.measured_at ? (d.sentinel?.active ? 'yes' : 'no') : NOT_MEASURED), secStat('Armed', d.measured_at ? (d.sentinel?.armed ? 'yes' : 'no') : NOT_MEASURED),
      secStat('Audit rules', d.auditd ? secVal(d.auditd.storageforge_rules) : NOT_MEASURED), secStat('Last test', test ? secAgo(test.occurred_at) : 'never')),
    text('p', d.report_url ? 'A trip reports here within seconds.' : 'No report URL is set (Settings), so a trip reaches this page only with the next scan or measurement. The brake on the host does not wait for it.', d.report_url ? 'muted small' : 'st-warn small'),
    text('p', 'Decoys catch what walks into them. They watch for changes, not reads, so backups and indexing do not trip them. Attribution comes from the audit log and smbd: over NFS the server cannot tell which client did it, so there is no address to drop.', 'muted small'),
    secCan('deploy.apply') ? el('div', { class: 'row wrap sec-acts' }, button('Dry run', go('report', `Security: dry run on ${host}`), 'btn sm'), button('Save and deploy', go('apply', `Security: deploy on ${host}`), 'btn sm pri'),
      d.installed ? button('Test it', async () => { const r = await secPost('/api/security/canaries/test', { host }, out); if (r) out.prepend(text('p', `The sentinel saw the write in ${r.latency_ms} ms.`, 'st-ok')); }, 'btn sm') : '',
      d.summary.tripped ? button('Re-arm tripped decoys', go('apply', `Security: re-arm on ${host}`, { rearm: true }), 'btn sm') : '',
      d.installed ? button('Remove', () => { if (confirm(`Remove the sentinel from ${host}? Unchanged decoys are deleted; changed ones stay.`)) startDeploy('security', host, 'apply', `Security: remove from ${host}`, { remove: true }); }, 'btn sm ghost') : '') : '', out),
  secCard('What the next deploy installs',
    el('div', { class: 'sec-form' }, secField('Folders, one a line', folders), secField('File names, one a line. {Dept} is the folder\'s name, {Year} this year', names), secField('Where in them', spread)),
    !c.folders.length && d.suggested.length ? text('p', 'Suggested from the shares in this host\'s design.', 'muted small') : '',
    secCan('security.emergency') ? el('div', { class: 'stack' },
      el('label', {}, armed, ' Armed: when a decoy changes, the host pulls the brake by itself'),
      el('div', { class: 'row wrap' }, ...checks.map((i) => el('label', { class: 'small' }, i, ` ${i.value}`)), secField('Drop for minutes (0: until lifted)', minutes)),
      text('p', 'Off by default. One changed file then cuts off a client and can make a share read-only: a user or a sync tool opening the wrong file will do it too. Add machines that must never be cut off under Firewall.', 'muted small')) : ''),
  d.audit_rules?.length ? secCard('Audit rules on the host', el('pre', { class: 'small sec-out' }, d.audit_rules.join('\n')), text('p', 'As auditctl lists them, at the last measurement.', 'muted small')) : '',
  secCard('Decoys', el('div', { class: 'stat-row' }, secStat('Armed', d.summary.armed), secStat('Tripped', d.summary.tripped, d.summary.tripped ? 'st-failed' : ''), secStat('Samba shares with previous versions', secVal(d.shadow_copy2_shares))),
    d.canaries.length ? secTable(['File', 'State', 'Written', 'Last seen intact', 'SHA-256'], d.canaries.map((k) => [k.path, secPill(k.status, k.status === 'armed' ? 'secure' : 'critical'), secWhen(k.deployed_at), k.status === 'tripped' ? `tripped ${secWhen(k.tripped_at)}` : secAgo(k.verified_at), text('code', k.sha256.slice(0, 16), 'small')])) : text('p', 'None deployed. A decoy appears here once a deploy has written it and read its hash back.', 'muted'))];
  return el('div', { class: 'stack' }, ...kids);
}

/* ── access control ───────────────────────────────────────────────── */
async function secMac() {
  const host = S.host, d = await getJSON(`/api/security/mac/status${secQ(host)}`), out = el('div', { class: 'stack' });
  if (!d.measured_at) return secCard('Access control', text('p', `${host} has not been measured, so nothing is known about it.`, 'muted'), secCan('security.manage') ? secMeasureButton(host, out) : '', out);
  const path = secInput('/srv/data'), type = el('select', {}, ...d.se_types.map((t) => new Option(t, t)));
  const fix = (name, value) => secActions('/api/security/mac/remediate', () => ({ host, boolean: name, value }), out, { apply: `Set ${value}`, after: () => secRender() });
  const relabel = secActions('/api/security/mac/remediate', () => ({ host, path: path.value.trim(), type: type.value }), out, { apply: 'Relabel', after: () => secRender() });
  return el('div', { class: 'stack' },
    secCard(`Access control on ${host}`, el('div', { class: 'stat-row' }, secStat('Framework', d.framework ? (d.framework === 'selinux' ? 'SELinux' : 'AppArmor') : 'none', d.framework ? '' : 'st-warn'), secStat('Mode', d.selinux_mode || (d.apparmor.enabled ? `${secVal(d.apparmor.enforce)} enforcing, ${secVal(d.apparmor.complain)} complaining` : 'off')), secStat('Measured', secAgo(d.measured_at)), secStat('Storage denials', d.avc.filter((a) => a.storage).length)),
      text('p', 'Turning SELinux on from here is not offered: it can stop services that have been relying on it being off. Look at the denials first.', 'muted small'), secCan('security.manage') ? secMeasureButton(host, out) : ''),
    d.booleans.length ? secCard('Storage booleans', secTable(['Boolean', 'Now', 'Should be', '', ''], d.booleans.map((b) => [b.name, b.value, secVal(b.expected), secOkPill(b.ok, 'as expected', 'too open'), b.ok ? '' : fix(b.name, b.expected)]))) : '',
    d.fcontext.length ? secCard('Mount labels', secTable(['Mount', 'Now', 'Policy says', ''], d.fcontext.map((f) => [f.path, f.live, secVal(f.expected), secOkPill(f.aligned, 'matches', 'drifted')]))) : '',
    secCard('Recent denials', d.avc.length ? secTable(['When', 'Program', 'Asked for', 'On', 'Its context', 'Target'], d.avc.slice(0, 50).map((a) => [secWhen(a.at), text('span', a.daemon, a.storage ? 'st-warn' : ''), a.action, a.path, a.scontext, a.tcontext])) : text('p', 'None in the last 10 minutes, as far as ausearch can say.', 'muted')),
    SEC_MORE.macExtra(host, d),
    d.selinux_mode ? secCard('Relabel a share', text('p', 'Registers the type with semanage, so it survives a relabel, then runs restorecon. This is the usual fix for a denial on a share.', 'muted small'), el('div', { class: 'sec-form' }, secField('Path', path), secField('Type', type)), relabel) : '',
    out);
}

/* ── firewall ─────────────────────────────────────────────────────── */
async function secFirewall() {
  const host = S.host, d = await getJSON(`/api/security/firewall/quarantine${secQ(host)}`), out = el('div', { class: 'stack' });
  const ip = secInput('10.0.1.42 or 10.0.1.0/24'), minutes = secInput('60', '60'), reason = secInput('why');
  const tier = el('select', { 'aria-label': 'Tier' }, new Option('These minutes', ''), new Option('Tier 1', '1'), new Option('Tier 2', '2'), new Option('Tier 3', '3'));
  const vips = secArea('one address or network a line', d.vips.join('\n'));
  const lift = (q) => async () => { if (await secPost(`/api/security/firewall/quarantine/${encodeURIComponent(q.ip_address)}?host=${encodeURIComponent(q.host)}&mode=apply`, null, out, 'DELETE')) secRender(); };
  return el('div', { class: 'stack' },
    secCard('Quarantine', d.quarantine.length ? secTable(['Host', 'Address', 'Why', 'Since', 'Ends', 'In the firewall', ''], d.quarantine.map((q) => [q.host, q.ip_address, q.reason, secWhen(q.added_at), q.expires_at ? `in ${secSpan(q.remaining_seconds)}` : 'until lifted', secOkPill(q.live, 'yes', 'no, it is gone'), secCan('security.manage') ? button('Lift', lift(q), 'btn sm ghost') : ''])) : text('p', 'Nobody is quarantined.', 'muted'),
      d.unknown_drops?.length ? text('p', `Dropped on the host with no record here: ${d.unknown_drops.join(', ')}`, 'st-warn') : '',
      host ? el('div', { class: 'stack' }, el('div', { class: 'sec-form' }, secField('Address', ip), secField('Minutes (0: until lifted)', minutes), secField('Or a tier', tier), secField('Why', reason)),
        secActions('/api/security/firewall/quarantine', () => ({ host, ip_address: ip.value.trim(), minutes: minutes.value.trim(), ...(tier.value ? { tier: tier.value } : {}), reason: reason.value.trim() }), out, { apply: 'Drop it', after: () => secRender() })) : text('p', 'Pick a host to add an address.', 'muted')),
    host ? secCard(`Firewall on ${host}`, el('div', { class: 'stat-row' }, secStat('Found', d.measured_at ? (d.firewalls.join(', ') || 'none') : NOT_MEASURED), secStat('Quarantine table', d.measured_at ? (d.fence_present ? 'present' : 'not yet') : NOT_MEASURED), secStat('Airgap', d.measured_at ? (d.airgap ? 'ENGAGED' : 'off') : NOT_MEASURED, d.airgap ? 'st-failed' : ''), secStat('StorageForge reaches it from', d.controller.join(', ') || 'unknown')),
      text('p', 'The quarantine is its own nftables table, ahead of firewalld or ufw, so it works beside either and neither can undo it.', 'muted small'),
      secCan('security.emergency') ? el('div', { class: 'stack' }, text('h4', 'Emergency airgap'), text('p', 'Cuts everything except StorageForge, open connections included. It undoes itself in 10 minutes unless StorageForge can still reach the host through it, so it cannot lock you out for good.', 'muted small'),
        d.airgap ? button('Lift the airgap', async () => { if (await secPost('/api/security/firewall/airgap', { host, enabled: false, mode: 'apply' }, out)) secRender(); }, 'btn sm')
          : secActions('/api/security/firewall/airgap', () => ({ host, enabled: true }), out, { apply: 'Airgap this host', danger: `Cut ${host} off from everything but StorageForge? Every client loses its shares.`, need: 'security.emergency', after: () => secRender() })) : '') : '',
    secCan('security.emergency') ? secCard('Never cut these off', text('p', 'Hypervisors, domain controllers, replication peers. Neither a person nor an armed sentinel can quarantine them. StorageForge itself is always exempt. Hosts get this list with their next deploy.', 'muted small'), vips, button('Save', async () => { if (await secPost('/api/security/firewall/vip', { vips: vips.value.split('\n').map((s) => s.trim()).filter(Boolean) }, out)) secRender(); }, 'btn sm')) : '',
    out);
}

/* ── behaviour ────────────────────────────────────────────────────── */
function secBars(series, threshold) {
  const max = Math.max(1, threshold || 0, ...series.map((s) => s.files_per_hour));
  return el('div', { class: 'sec-bars', role: 'img', 'aria-label': 'Files changed per hour, by scan' }, ...series.map((s) => {
    const b = el('i', { title: `${secWhen(s.at)}: ${s.files_per_hour} files an hour (${s.added} added, ${s.modified} changed, ${s.deleted} deleted)` });
    b.style.height = `${Math.max(2, (s.files_per_hour / max) * 100)}%`;
    if (threshold && s.files_per_hour > threshold) b.className = 'over';
    return b;
  }));
}

async function secBehavior() {
  const host = S.host, d = await getJSON(`/api/security/behavior${secQ(host)}`), v = d.velocity, e = d.entropy, out = el('div', { class: 'stack' });
  return el('div', { class: 'stack' },
    secCard('How fast files change', v.latest ? el('div', { class: 'stack' },
      el('div', { class: 'stat-row' }, secStat('Last scan', `${v.latest.files_per_hour} files an hour`, v.anomaly ? 'st-failed' : ''), secStat('Usual', v.baseline_median === null ? `needs ${6 - Math.min(5, v.scans - 1)} more scans` : `${v.baseline_median} an hour`), secStat('Alerts above', secVal(v.threshold)), secStat('Named like ransomware', v.ransom_names, v.ransom_names ? 'st-failed' : ''), secStat('Extra extensions', v.appended_extensions, v.appended_extensions >= 50 ? 'st-failed' : '')),
      secBars(v.series, v.threshold), v.ransom_samples.length ? secTable(['Named like ransomware'], v.ransom_samples.map((p) => [p])) : '',
      text('p', 'From the difference between scans, so it catches damage no decoy was in the path of, but only after the next scan. Oldest on the left.', 'muted small')) : text('p', 'It takes two scans of this host to compare.', 'muted')),
    secCard('Do changed files look encrypted?', e ? el('div', { class: 'stack' },
      el('div', { class: 'stat-row' }, secStat('Sampled', secAgo(e.measured_at)), secStat('Files read', `${e.read} of ${e.asked}`), secStat('Plain', e.buckets.low), secStat('Dense', e.buckets.mid + e.buckets.high), secStat('Random-looking', e.buckets.ciphertext_like), secStat('With no known header', e.flagged_count, e.flagged_count ? 'st-failed' : '')),
      e.flagged.length ? secTable(['File', 'Bits per byte', 'Size', 'First bytes'], e.flagged.slice(0, 50).map((f) => [f.path, f.entropy, f.size, text('code', f.head, 'small')])) : '') : text('p', 'No sample yet. Sampling reads the first 4 KiB of what the last scan saw change, on the host.', 'muted'),
      text('p', 'Compressed data looks just like ciphertext, so archives, images and video are skipped, and a known file header clears a file. What is left is a reason to look, not proof.', 'muted small'),
      secCan('security.manage') ? el('div', { class: 'row wrap sec-acts' }, button('Sample changed files', async () => { if (await secPost('/api/security/behavior/entropy', { host }, out)) secRender(); }, 'btn sm'), button('ClamAV on changed files', async () => { const r = await secPost('/api/security/behavior/diff-scan', { host }, out); if (r) out.prepend(text('p', `Scanned ${r.scanned} changed files in ${r.seconds} s: ${r.found} new detections. They are in the Malware panel.`, r.found ? 'st-failed' : 'st-ok')); }, 'btn sm')) : ''),
    secCard('Falco', text('p', d.measured_at ? (d.falco?.installed ? `Installed, ${d.falco.active ? 'running' : 'not running'}.` : 'Not installed.') : `${NOT_MEASURED}.`, 'muted'), button('Rules, alerts and YARA', () => secOpen('detect'), 'btn sm')),
    out);
}

/* ── integrity ────────────────────────────────────────────────────── */
async function secIntegrity() {
  const host = S.host, d = await getJSON(`/api/security/integrity${secQ(host)}`), out = el('div', { class: 'stack' });
  if (!d.measured_at) return secCard('Integrity', text('p', `${host} has not been measured, so nothing is known about it.`, 'muted'), secCan('security.manage') ? secMeasureButton(host, out) : '', out);
  const a = d.aide, l = d.lynis;
  const run = (tool, label) => secActions('/api/security/integrity/run', () => ({ host, tool }), out, { apply: label });
  return el('div', { class: 'stack' },
    secCard('AIDE', a ? el('div', { class: 'stack' },
      el('div', { class: 'stat-row' }, secStat('Baseline', a.baseline_at ? secWhen(a.baseline_at) : 'none', a.baseline_at ? '' : 'st-warn'), secStat('Last check', a.last_action === 'check' ? secWhen(a.last_at) : 'never'), secStat('Added', secVal(a.added)), secStat('Removed', secVal(a.removed)), secStat('Changed', secVal(a.changed), a.changed ? 'st-failed' : '')),
      a.entries.length ? el('pre', { class: 'small sec-out' }, a.entries.join('\n')) : '') : text('p', 'Not installed. Making a baseline installs it.', 'muted'),
      text('h4', 'Check files'), run('aide-check', 'Run a check'), text('h4', 'Make a new baseline'), text('p', 'After an upgrade you trust. Anything already changed becomes the new normal.', 'muted small'), run('aide-init', 'Make the baseline')),
    secCard('Lynis', l ? el('div', { class: 'stack' }, el('div', { class: 'stat-row' }, secStat('Hardening index', secVal(l.hardening_index)), secStat('Audited', secWhen(l.at)), secStat('Warnings', l.warnings.length), secStat('Suggestions', l.suggestions.length)),
      l.warnings.length ? secTable(['Warning', ''], l.warnings.map((w) => [w.id, w.text])) : '', l.suggestions.length ? secTable(['Suggestion', ''], l.suggestions.slice(0, 50).map((w) => [w.id, w.text])) : '') : text('p', 'No audit has run.', 'muted'), run('lynis', 'Run an audit')),
    text('p', 'These run in the background on the host. Measure again when they are done.', 'muted small'), secCan('security.manage') ? secMeasureButton(host, out) : '', out, await SEC_MORE.integrityExtra(host));
}

/* ── compliance ───────────────────────────────────────────────────── */
async function secCompliance() {
  const host = S.host, { standards, note, presets = [], custom = [] } = await getJSON('/api/security/compliance/standards'), out = el('div', { class: 'stack' });
  const pick = el('select', { 'aria-label': 'Standard' }, ...standards.map((s) => new Option(s.name, s.id)), ...presets.map((s) => new Option(`Role: ${s.name}`, s.id)), ...custom.map((s) => new Option(`Yours: ${s.name}`, s.id)));
  const body = el('div', { class: 'stack' });
  const show = async () => {
    const d = await getJSON(`/api/security/compliance/status/${encodeURIComponent(host)}?profile=${encodeURIComponent(pick.value)}`);
    pick.value = d.profile;
    body.replaceChildren(el('div', { class: 'stat-row' }, secStat('Checks passing', d.score === null ? NOT_MEASURED : `${d.passed} of ${d.checks.length}`), secStat('Failing', d.failed, d.failed ? 'st-warn' : ''), secStat('Cannot tell', d.unknown), secStat('Waived', d.waived || 0), secStat('Measured', d.measured_at ? secAgo(d.measured_at) : 'never')),
      d.drift?.length ? text('p', `Passed before and fails now: ${d.drift.join(', ')}`, 'st-warn') : '',
      secTable(['Check', 'Control', 'Result', 'Reading'], d.checks.map((c) => [c.label, c.control, secPill(c.result, c.result === 'pass' ? 'secure' : c.result === 'fail' ? 'warning' : 'unknown'), c.waiver ? `${c.detail}. Waived by ${c.waiver.approver}: ${c.waiver.reason}` : c.detail])));
  };
  pick.addEventListener('change', show);
  await show();
  return el('div', { class: 'stack' }, secCard(`Baseline on ${host}`, text('p', note, 'muted small'), secField('Standard', pick), body, secCan('security.manage') ? secMeasureButton(host, out) : ''),
    secCard('Set the baseline', text('p', 'Packages, kernel settings, umask, audit rules and the quarantine table. It leaves SELinux, decoys and holds to you, and the numbers above change only when a measurement sees the result.', 'muted small'),
      secActions('/api/security/compliance/init', () => ({ host, profile: pick.value }), out, { apply: 'Set the baseline', danger: `Change kernel settings, umask and audit rules on ${host}?`, after: () => secRender() })),
    SEC_MORE.complianceExtra(host, pick, standards), out);
}
