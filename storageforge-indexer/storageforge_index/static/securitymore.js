'use strict';
/* Security, continued: policy, identity, fencing, Falco and YARA, playbooks, dashboards, the timeline and hardware keys.
   The same two rules as securityview.js: what nobody measured says so, and a button says what really happened on the host. */

const SEC_MORE = {};
SEC_PANELS.push(['policy', 'Retention'], ['fencing', 'Fencing'], ['identity', 'Identity'], ['detect', 'Falco and YARA'], ['playbooks', 'Playbooks'], ['dash', 'Dashboard'], ['timeline', 'Timeline'], ['seckeys', 'Hardware keys']);
['fencing', 'identity', 'detect'].forEach((p) => SEC_NEEDS_HOST.add(p));

const secLines = (t) => t.value.split('\n').map((s) => s.trim()).filter(Boolean);
const secChanges = (r, out) => { if (r?.plan_id) out.prepend(el('div', { class: 'row wrap' }, text('p', `${r.tasks} step(s) staged in plan #${r.plan_id}.`, 'st-ok'), button('Open Changes', () => showTab('changes'), 'btn sm'))); };
const secSave = async (path, body, out, after) => { const r = await secPost(path, body, out); if (r && after) after(r); return r; };

/* ── retention ────────────────────────────────────────────────────── */
SEC_MORE.policy = async function secPolicy() {
  const host = S.host, d = await getJSON(`/api/security/worm/policies${secQ(host)}`), w = await getJSON(`/api/security/worm/holds${secQ(host)}`), out = el('div', { class: 'stack' });
  const pattern = secInput('tank/prod/* or /data/*'), days = secInput('30', '30'), legal = el('input', { type: 'checkbox' }), auto = el('input', { type: 'checkbox' });
  const scope = el('select', { 'aria-label': 'Which hosts' }, new Option('This host', host || '*'), new Option('Every host', '*'));
  const emergency = secCan('security.emergency');
  const kids = [secCard('Retention tiers',
    text('p', 'Each day, or when you ask, the newest snapshot of each dataset a policy names gets a hold. A hold is only added here, so this cannot lose anything. The snapshots come from the last measurement.', 'muted small'),
    d.policies.length ? secTable(['Pattern', 'Hosts', 'Keep', 'By itself', ''], d.policies.map((p) => [p.pattern, p.host === '*' ? 'every host' : p.host, p.legal ? 'until released' : `${p.days} days`, p.auto ? 'daily' : 'when asked', emergency ? button('Remove', async () => { if (await secPost(`/api/security/worm/policies/${p.id}`, null, out, 'DELETE')) secRender(); }, 'btn sm ghost') : ''])) : text('p', 'No policies.', 'muted'),
    emergency ? el('div', { class: 'stack' }, el('div', { class: 'sec-form' }, secField('Dataset or path', pattern), secField('Days', days), secField('Applies to', scope)),
      el('div', { class: 'row wrap' }, el('label', { class: 'small' }, legal, ' legal hold: until released'), el('label', { class: 'small' }, auto, ' apply each day')),
      button('Add policy', () => secSave('/api/security/worm/policies', { host: scope.value, pattern: pattern.value.trim(), days: days.value.trim(), legal: legal.checked, auto: auto.checked }, out, () => secRender()), 'btn sm pri')) : '',
    host && d.targets.length ? secTable(['Would hold', 'Dataset', 'Days'], d.targets.map((t) => [t.snapshot, t.dataset, t.legal ? 'until released' : t.days])) : host ? text('p', 'Every snapshot a policy names on this host already has a hold, or none has been read.', 'muted small') : '',
    host && emergency ? secActions('/api/security/worm/policies/apply', () => ({ host }), out, { apply: 'Apply now', need: 'security.emergency', after: () => secRender() }) : '')];
  if (host && emergency) {
    const target = secInput('tank/shares, or a btrfs folder of snapshots');
    kids.push(secCard('Legal freeze', text('p', 'Holds every snapshot under a dataset until released, so a scheduled prune cannot take any of them: ZFS refuses to destroy what is held. On btrfs read-only stops writes and does not stop a delete, so root can still remove them.', 'muted small'),
      secField('Dataset or folder', target), secActions('/api/security/worm/freeze', () => ({ host, target: target.value.trim() }), out, { apply: 'Freeze', need: 'security.emergency', danger: 'Hold every snapshot under this? Each one then needs its own release.', after: () => secRender() })));
    const snap = secInput('tank/shares@daily, or a btrfs path', w.holds[0]?.snapshot || ''), live = secInput('live folder, for btrfs');
    const pv = el('div', { class: 'stack' });
    kids.push(secCard('What would a rollback change?', text('p', 'Compares the snapshot with what is there now, on the host, and changes nothing. Then you can stage it.', 'muted small'),
      el('div', { class: 'sec-form' }, secField('Snapshot', snap), secField('Live folder', live)),
      el('div', { class: 'row wrap sec-acts' },
        button('Compare', async () => { const r = await secPost('/api/security/worm/preview', { host, snapshot: snap.value.trim(), live: live.value.trim() }, pv); if (r) pv.replaceChildren(el('div', { class: 'stat-row' }, ...Object.entries(r.counts).map(([k, v]) => secStat({ M: 'Changed', '+': 'Added since', '-': 'Gone since', R: 'Renamed' }[k] || k, v))), r.samples.length ? secTable(['Path', 'What'], r.samples.slice(0, 40).map((x) => [x.path, x.what])) : text('p', 'No differences.', 'st-ok')); }, 'btn sm'),
        button('Stage the rollback', async () => { const r = await secPost('/api/security/worm/preview/stage', { host, snapshot: snap.value.trim(), live: live.value.trim() }, pv); secChanges(r, pv); }, 'btn sm')), pv));
  }
  const from = secInput('days back', '90'), ev = el('div', { class: 'stack' });
  kids.push(secCard('Expiry', secHeatmap(w.holds), text('p', 'One square a day for the next 90 days. Darker means more holds expire that day.', 'muted small')));
  if (secCan('audit.verify') && secCan('audit.view')) kids.push(secCard('Evidence', text('p', 'A signed record of holds, alarms and what was done, to hand to an auditor. It is evidence and not a certificate: only an auditor can attest. It can be checked with ssh-keygen and the key in the file.', 'muted small'),
    secField('Days back', from), button('Download', async () => {
      try {
        const r = await (await postJSON('/api/security/evidence', { ...(host ? { host } : {}), from: Math.floor(Date.now() / 1000) - Number(from.value || 90) * 86400 })).json();
        const a = el('a', { href: URL.createObjectURL(new Blob([JSON.stringify(r, null, 1)], { type: 'application/json' })), download: `storageforge-evidence${host ? `-${host}` : ''}.json` }); a.click();
        ev.replaceChildren(text('p', r.verify, 'small mono'));
      } catch (err) { ev.replaceChildren(text('p', err.message, 'st-failed')); }
    }, 'btn sm'), ev));
  kids.push(out);
  return el('div', { class: 'stack' }, ...kids);
};

function secHeatmap(holds) {
  const days = new Map(), now = Date.now() / 1000;
  for (const h of holds) {
    if (!h.expires_at || h.legal_hold || h.status === 'released' || h.expires_at < now) continue;
    const d = Math.floor((h.expires_at - now) / 86400);
    if (d < 90) days.set(d, (days.get(d) || 0) + 1);
  }
  const grid = el('div', { class: 'sec-heat', role: 'img', 'aria-label': 'Holds expiring in the next 90 days' });
  for (let i = 0; i < 90; i++) {
    const n = days.get(i) || 0, c = el('i', { title: `${new Date((now + i * 86400) * 1000).toLocaleDateString()}: ${n} hold(s) expire` });
    c.className = n === 0 ? '' : n < 3 ? 'h1' : n < 10 ? 'h2' : 'h3';
    grid.append(c);
  }
  return grid;
}

/* ── who can reach each share ─────────────────────────────────────── */
SEC_MORE.fencing = async function secFencing() {
  const host = S.host, d = await getJSON(`/api/security/firewall/shares${secQ(host)}`), t = await getJSON('/api/security/firewall/tiers'), out = el('div', { class: 'stack' });
  const rows = d.shares.map((s) => {
    const cidrs = secInput('10.0.20.0/24', s.declared.filter((x) => /[0-9]/.test(x)).join(','));
    const iface = secInput('only on interface');
    return [text('b', `${s.name || s.path} (${s.protocol})`), s.path, s.declared.join(', ') || 'nobody declared',
      s.firewall ? el('div', {}, secPill(MP_LEVEL[s.firewall] || s.firewall, s.firewall === 'any' ? 'critical' : s.firewall === 'lan' ? 'warning' : 'secure'), text('div', s.rule || '', 'muted small'), s.fenced_to ? text('div', `Fenced to ${s.fenced_to.join(', ')}`, 'small') : '') : NOT_MEASURED,
      s.connected.length ? s.connected.map((c) => `${c.client} (${c.connections})`).join(', ') : d.measured_at ? 'nobody' : NOT_MEASURED,
      secCan('plans.edit') ? el('div', { class: 'row wrap' }, cidrs, iface, button('Stage a fence', async () => { const r = await secPost('/api/security/firewall/shares/stage', { host, name: s.name || 'share', service: s.protocol === 'SMB' ? 'smb' : 'nfs', clients: cidrs.value.trim(), iface: iface.value.trim() }, out); secChanges(r, out); }, 'btn sm')) : ''];
  });
  const inputs = {};
  for (const k of ['1', '2', '3']) inputs[k] = secInput('minutes', String(t.tiers[k].minutes));
  return el('div', { class: 'stack' },
    secCard(`Shares on ${host}`, text('p', d.caveat, 'muted small'), d.read ? '' : text('p', 'The firewall has not been read here, so what it allows is not known.', 'st-warn small'),
      rows.length ? secTable(['Share', 'Path', 'Declared clients', 'The firewall allows', 'Connected now', ''], rows) : text('p', 'No shares in this host\'s design.', 'muted')),
    secCard('How long a client stays dropped', text('p', 'A second offence inside 30 days goes up a tier. 0 means until someone lifts it.', 'muted small'),
      el('div', { class: 'sec-form' }, ...['1', '2', '3'].map((k) => secField(`Tier ${k}: ${t.tiers[k].label}`, inputs[k]))),
      secCan('security.manage') ? button('Save', () => secSave('/api/security/firewall/tiers', { tiers: Object.fromEntries(['1', '2', '3'].map((k) => [k, { minutes: inputs[k].value.trim(), label: t.tiers[k].label }])) }, out), 'btn sm') : ''), out);
};

/* ── identity ─────────────────────────────────────────────────────── */
SEC_MORE.identity = async function secIdentity() {
  const host = S.host, d = await getJSON(`/api/security/mac/identity-anomalies${secQ(host)}`), c = d.config, out = el('div', { class: 'stack' });
  const max = secInput('10', String(c.max_shares)), a = secInput('hour', c.off_from ?? ''), b = secInput('hour', c.off_to ?? '');
  return el('div', { class: 'stack' },
    secCard(`Who is connected on ${host}`, text('p', 'Off until you turn it on: it writes down who connected from where, on the host. Sampled each minute from smbstatus, so it sees what is connected at that moment and nothing that came and went between. It cannot see how much was read: that takes per-file auditing, which is not built.', 'muted small'),
      el('div', { class: 'stat-row' }, secStat('Sampling', c.enabled ? 'on' : 'off'), secStat('Read', d.sampled_at ? secAgo(d.sampled_at) : NOT_MEASURED)),
      el('div', { class: 'sec-form' }, secField('Alert above this many shares for one user', max), secField('Off hours from', a), secField('Off hours to', b)),
      secActions('/api/security/mac/identity/deploy', () => ({ host, enabled: true, max_shares: max.value.trim(), off_from: a.value.trim(), off_to: b.value.trim() }), out, { apply: 'Turn on', after: () => secRender() }),
      c.enabled && secCan('security.manage') ? button('Turn off, and delete what it recorded', () => secSave('/api/security/mac/identity/deploy', { host, enabled: false, mode: 'apply' }, out, () => secRender()), 'btn sm ghost') : '', out),
    secCard('Flagged', d.events.length ? secTable(['When', 'What', ''], d.events.map((e) => [secWhen(e.occurred_at), e.summary, ''])) : text('p', d.sampled_at ? 'Nothing flagged.' : 'Nothing to go on yet.', 'muted')),
    secCard('Connected at the last sample', d.sessions.length ? secTable(['User', 'From', 'Share'], d.sessions.map((s) => [s.user, s.client, s.share])) : text('p', 'Nobody, or not read.', 'muted')));
};

/* ── Falco and YARA ───────────────────────────────────────────────── */
SEC_MORE.detect = async function secDetect() {
  const host = S.host, d = await getJSON(`/api/security/behavior${secQ(host)}`), y = await getJSON('/api/security/behavior/yara/rules'), out = el('div', { class: 'stack' });
  const rules = el('textarea', { rows: '14', class: 'mono small', spellcheck: 'false' }); rules.value = d.falco_rules;
  const yname = secInput('Rule set name'), ybody = el('textarea', { rows: '10', class: 'mono small', spellcheck: 'false', placeholder: 'rule name { ... }' }); ybody.value = Object.values(y.example)[0] || '';
  const f = d.scan_filters, over = secInput('MB', String(f.skip_over_mb)), skip = secInput('.mkv .iso', f.skip_ext.join(' ')), deep = secInput('.exe .sh', f.deep_ext.join(' '));
  const ent = secArea('/srv/docs 7.2, one a line', d.thresholds.entropy.map((e) => `${e.prefix} ${e.threshold}`).join('\n'));
  const velo = d.thresholds.velocity[host] || {}, factor = secInput('3', String(velo.factor ?? 3)), floor = secInput('500', String(velo.floor ?? 500));
  return el('div', { class: 'stack' },
    secCard(`Falco on ${host}`, el('div', { class: 'stat-row' }, secStat('Installed', d.measured_at ? (d.falco?.installed ? 'yes' : 'no') : NOT_MEASURED), secStat('Running', d.measured_at ? (d.falco?.active ? 'yes' : 'no') : NOT_MEASURED), secStat('Alerts read', d.falco_events.length)),
      text('p', 'It comes from Falco\'s own repository, which the script adds, and needs a kernel with modern eBPF. Alerts reach here with each measurement. A rule sees one event at a time, so "many renames fast" is for the change rate between scans, not for Falco. $STORAGE_MOUNT_ONE, $STORAGE_MOUNTS, $CANARY_PATHS and $AUTHORIZED_BACKUP_SCRIPTS are filled in from the index.', 'muted small'),
      secField('Rules', rules), secActions('/api/security/behavior/falco', () => ({ host, rules: rules.value }), out, { apply: 'Install with these rules', after: () => secRender() }),
      d.falco_events.length ? secTable(['When', 'Rule', ''], d.falco_events.map((e) => [secWhen(e.occurred_at), e.summary, secPill(e.severity, e.severity === 'crit' ? 'critical' : 'warning')])) : ''),
    secCard('YARA', text('p', 'Rules are data here, and YARA on the host checks them first. They run on what the last scan saw change, and matches join the Malware panel, where they can be quarantined. Test runs one on the changed files and records nothing.', 'muted small'),
      y.rules.length ? secTable(['Rule set', 'Used', ''], y.rules.map((r) => [r.name, r.enabled ? 'yes' : 'no', secCan('security.manage') ? button('Remove', async () => { if (await secPost(`/api/security/behavior/yara/rules/${r.id}`, null, out, 'DELETE')) secRender(); }, 'btn sm ghost') : ''])) : text('p', 'None saved: the example below is used.', 'muted small'),
      secField('Name', yname), secField('Rule', ybody),
      secCan('security.manage') ? el('div', { class: 'row wrap sec-acts' }, button('Save', () => secSave('/api/security/behavior/yara/rules', { name: yname.value.trim(), body: ybody.value }, out, () => secRender()), 'btn sm'),
        button('Test on changed files', async () => { const r = await secPost('/api/security/behavior/yara', { host, dry: true, rules: ybody.value }, out); if (r) out.prepend(text('p', `Tested on ${r.scanned} changed files in ${r.seconds} s: ${r.hits} matches. ${(r.matches || []).join(', ')}`, r.hits ? 'st-warn' : 'st-ok')); }, 'btn sm'),
        button('Scan changed files', async () => { const r = await secPost('/api/security/behavior/yara', { host }, out); if (r) out.prepend(text('p', `Scanned ${r.scanned} files in ${r.seconds} s: ${r.found} new detections.`, r.found ? 'st-failed' : 'st-ok')); }, 'btn sm pri')) : ''),
    secCard('What a scan of changed files skips', el('div', { class: 'sec-form' }, secField('Skip files over, MB', over), secField('Skip these', skip), secField('Never skip these', deep)),
      secCan('security.manage') ? button('Save', () => secSave('/api/security/behavior/filters', { skip_over_mb: over.value.trim(), skip_ext: skip.value.split(/\s+/), deep_ext: deep.value.split(/\s+/) }, out), 'btn sm') : ''),
    secCard('Thresholds', text('p', 'Tune these against what a host has actually reported. For each folder, the entropy above which a changed file with no known header is flagged. For this host, how far above its own usual change rate raises an alert.', 'muted small'),
      secField('Folder and bits per byte, one a line', ent), el('div', { class: 'sec-form' }, secField('Times its usual rate', factor), secField('And at least, files an hour', floor)),
      secCan('security.manage') ? button('Save', () => secSave('/api/security/behavior/thresholds', { entropy: secLines(ent).map((l) => { const [prefix, threshold] = l.split(/\s+/); return { prefix, threshold }; }), velocity: { ...d.thresholds.velocity, [host]: { factor: factor.value.trim(), floor: floor.value.trim() } } }, out), 'btn sm') : ''), out);
};

/* ── playbooks ────────────────────────────────────────────────────── */
SEC_MORE.playbooks = async function secPlaybooks() {
  const d = await getJSON('/api/security/playbooks'), out = el('div', { class: 'stack' }), emergency = secCan('security.emergency');
  const name = secInput('Name'), trig = el('select', { 'aria-label': 'When' }, ...Object.entries(d.triggers).map(([k, v]) => new Option(v, k))), host = secInput('every host, or nas-*'), path = secInput('under this path');
  const mode = el('select', { 'aria-label': 'How' }, new Option('Say what it would do, and do nothing', 'dry_run'), new Option('Ask a person first', 'confirm'), new Option('Do it by itself', 'live'));
  const acts = Object.entries(d.actions).map(([k, v]) => { const c = el('input', { type: 'checkbox' }); c.value = k; return el('label', { class: 'small' }, c, ` ${v}`); });
  return el('div', { class: 'stack' },
    d.pending.length ? secCard('Waiting for you', secTable(['Playbook', 'Host', 'Why', 'It would', ''], d.pending.map((r) => [r.playbook, r.host, r.summary, (r.actions || []).join(', '), emergency ? el('div', { class: 'row wrap' }, button('Do it', () => secSave(`/api/security/playbooks/runs/${r.id}`, { confirm: true }, out, () => secRender()), 'btn sm danger'), button('Dismiss', () => secSave(`/api/security/playbooks/runs/${r.id}`, { confirm: false }, out, () => secRender()), 'btn sm ghost')) : '']))) : '',
    secCard('Playbooks', text('p', 'If this happens, do that. New ones say what they would do and do nothing: watch one for a while before letting it act. These run from StorageForge, so they need it up and the host reachable. An armed sentinel acts on the host by itself, with neither.', 'muted small'),
      d.playbooks.length ? secTable(['Name', 'When', 'Then', 'How', ''], d.playbooks.map((p) => [p.name, d.triggers[p.trigger], p.actions.map((a) => d.actions[a]).join(', '), p.dry_run ? 'only says' : p.conditions.confirm ? 'asks first' : 'by itself', emergency ? button('Remove', async () => { if (await secPost(`/api/security/playbooks/${p.id}`, null, out, 'DELETE')) secRender(); }, 'btn sm ghost') : ''])) : text('p', 'None.', 'muted'),
      emergency ? el('div', { class: 'stack' }, el('div', { class: 'sec-form' }, secField('Name', name), secField('When', trig), secField('On which hosts', host), secField('Under which path', path), secField('How', mode)), el('div', { class: 'row wrap' }, ...acts),
        button('Save', () => secSave('/api/security/playbooks', { name: name.value.trim(), trigger: trig.value, mode: mode.value === 'confirm' ? 'confirm' : mode.value, conditions: { host: host.value.trim(), path: path.value.trim() }, actions: acts.map((l) => l.firstChild).filter((c) => c.checked).map((c) => c.value) }, out, () => secRender()), 'btn sm pri')) : ''),
    await secRoutesCard(out),
    secCard('What they have done', d.runs.length ? secTable(['When', 'Playbook', 'Host', 'Outcome', 'Why'], d.runs.slice(0, 50).map((r) => [secWhen(r.at), r.playbook, r.host, secPill(r.outcome, r.outcome === 'failed' ? 'critical' : r.outcome === 'ran' ? 'secure' : 'unknown'), r.detail.summary])) : text('p', 'Nothing yet.', 'muted')), out);
};

async function secRoutesCard(out) {
  if (!secCan('settings.manage')) return '';
  const cfg = (await getJSON('/api/deploy/settings')).alerts || {};
  const routes = secArea('crit nas-* pagerduty,ntfy', (cfg.routes || []).map((r) => `${r.level} ${r.host} ${r.channels.join(',')}`).join('\n')), key = secInput('routing key', cfg.pagerduty?.routing_key || '');
  return secCard('Where alerts go', text('p', 'By severity and host. Level is crit, warn or any, and channels are ntfy, gotify, webhook and pagerduty. With no route matching, an alert goes to every channel: one too many is better than one nobody gets. SMS goes through a webhook to your provider.', 'muted small'),
    secField('Routes, one a line', routes), secField('PagerDuty routing key', key),
    button('Save', async () => { try { await api('/api/deploy/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ alerts: { pagerduty: { routing_key: key.value.trim() }, routes: secLines(routes).map((l) => { const [level, host, channels] = l.split(/\s+/); return { level, host, channels: (channels || '').split(',') }; }) } }) }); out.replaceChildren(text('p', 'Saved.', 'st-ok')); } catch (err) { out.replaceChildren(text('p', err.body?.error || err.message, 'st-failed')); } }, 'btn sm'));
}

/* ── dashboards ───────────────────────────────────────────────────── */
SEC_MORE.dash = async function secDash() {
  const [{ dashboards }, { tiles }] = await Promise.all([getJSON('/api/security/dash'), getJSON('/api/security/dash/tiles')]);
  const out = el('div', { class: 'stack' });
  let current = dashboards[0] || { name: 'My dashboard', layout: Object.keys(tiles).slice(0, 6).map((kind) => ({ kind, w: 1, h: 1 })) };
  const pick = el('select', { 'aria-label': 'Dashboard' }, ...dashboards.map((d) => new Option(d.name, String(d.id)))), add = el('select', { 'aria-label': 'Add a tile' }, ...Object.entries(tiles).map(([k, v]) => new Option(v, k))), name = secInput('Name', current.name);
  const grid = el('div', { class: 'sec-grid' });
  const draw = async () => {
    grid.replaceChildren(...current.layout.map((t, i) => {
      const body = el('div', { class: 'sec-tile-body small' }, text('p', 'Loading…', 'muted'));
      const tile = el('section', { class: 'sec-tile', draggable: 'true' }, el('div', { class: 'row' }, text('b', tiles[t.kind] || t.kind),
        button('↔', () => { t.w = t.w >= 2 ? 1 : 2; draw(); }, 'btn sm ghost'), button('✕', () => { current.layout.splice(i, 1); draw(); }, 'btn sm ghost')), body);
      tile.style.gridColumn = `span ${t.w}`;
      tile.addEventListener('dragstart', (ev) => ev.dataTransfer.setData('text/plain', String(i)));
      tile.addEventListener('dragover', (ev) => ev.preventDefault());
      tile.addEventListener('drop', (ev) => { ev.preventDefault(); const from = Number(ev.dataTransfer.getData('text/plain')); const [m] = current.layout.splice(from, 1); current.layout.splice(i, 0, m); draw(); });
      getJSON(`/api/security/dash/tile/${t.kind}${secQ(S.host)}`).then((v) => body.replaceChildren(...secTile(v))).catch((err) => body.replaceChildren(text('p', err.message, 'st-failed')));
      return tile;
    }));
  };
  pick.addEventListener('change', () => { current = dashboards.find((d) => String(d.id) === pick.value); name.value = current.name; draw(); });
  draw();
  return el('div', { class: 'stack' }, secCard('Dashboard', text('p', 'Yours alone. Drag a tile to move it. Every number was read from a host, and what nobody read says so.', 'muted small'),
    el('div', { class: 'row wrap' }, dashboards.length ? pick : '', add, button('Add', () => { current.layout.push({ kind: add.value, w: 1, h: 1 }); draw(); }, 'btn sm'), name, button('Save', () => secSave('/api/security/dash', { name: name.value.trim(), layout: current.layout }, out, () => secRender()), 'btn sm pri'))), grid, out);
};

function secTile(v) {
  if (v.none) return [text('p', v.none, 'muted')];
  if (v.text) return [secPill(v.state, v.state), text('p', v.text, 'small')];
  if (v.stats) return [el('div', { class: 'stat-row' }, ...v.stats.map((s) => secStat(s.label, s.value)))];
  return (v.rows || []).map((r) => el('div', { class: 'sec-kv' }, text('span', r.label, 'sec-k'), el('div', { class: 'sec-v' }, r.series ? secSpark(r.series) : '', text('span', r.value === null || r.value === undefined ? NOT_MEASURED : String(r.value)), r.host ? text('span', ` ${r.host}`, 'muted') : '')));
}

function secSpark(values) {
  const w = 80, h = 18, max = Math.max(1, ...values), step = values.length > 1 ? w / (values.length - 1) : 0;
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - (v / max) * h).toFixed(1)}`).join(' ');
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); s.setAttribute('width', w); s.setAttribute('height', h); s.setAttribute('class', 'sec-spark');
  const l = document.createElementNS('http://www.w3.org/2000/svg', 'polyline'); l.setAttribute('points', pts); s.append(l);
  return s;
}

/* ── the timeline ─────────────────────────────────────────────────── */
SEC_MORE.timeline = async function secTimeline() {
  const fields = { client: secInput('client address'), user: secInput('user'), dataset: secInput('dataset or path'), protocol: secInput('SMB or NFS') }, body = el('div', { class: 'stack' });
  const go = async () => {
    const q = new URLSearchParams(S.host ? { host: S.host } : {});
    for (const [k, i] of Object.entries(fields)) if (i.value.trim()) q.set(k, i.value.trim());
    const { rows } = await getJSON(`/api/security/timeline?${q}`);
    body.replaceChildren(rows.length ? secTable(['When', 'Host', 'What', 'Source'], rows.slice(0, 300).map((r) => [secWhen(r.at), r.host, el('div', {}, secPill(r.severity, r.severity === 'crit' ? 'critical' : r.severity === 'warn' ? 'warning' : 'unknown'), text('span', ` ${r.text}`)), r.source])) : text('p', 'Nothing matches.', 'muted'));
  };
  await go();
  return el('div', { class: 'stack' }, secCard('Timeline', text('p', 'Alarms, what people and playbooks did, and who was dropped, in one line.', 'muted small'), el('div', { class: 'sec-form' }, ...Object.entries(fields).map(([k, i]) => secField(k, i))), button('Filter', go, 'btn sm')), body);
};

/* ── hardware keys ────────────────────────────────────────────────── */
const secB64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const secUnb64u = (t) => Uint8Array.from(atob(t.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

async function secEnrollKey(name) {
  const begin = () => postJSON('/api/security/webauthn/register/begin', {});
  let res;
  try { res = await begin(); } catch (err) {      // an account with a key: adding another takes a touch on it first
    if (!err.body?.webauthn) throw err;
    await secTouchKey();
    res = await begin();
  }
  const o = await res.json();
  const cred = await navigator.credentials.create({ publicKey: { ...o, challenge: secUnb64u(o.challenge), user: { ...o.user, id: secUnb64u(o.user.id) }, excludeCredentials: o.excludeCredentials.map((c) => ({ ...c, id: secUnb64u(c.id) })) } });
  return (await postJSON('/api/security/webauthn/register/finish', { name, clientDataJSON: secB64u(cred.response.clientDataJSON), attestationObject: secB64u(cred.response.attestationObject) })).json();
}

async function secTouchKey() {
  const o = await (await postJSON('/api/security/webauthn/assert/begin', {})).json();
  const got = await navigator.credentials.get({ publicKey: { ...o, challenge: secUnb64u(o.challenge), allowCredentials: o.allowCredentials.map((c) => ({ ...c, id: secUnb64u(c.id) })) } });
  return (await postJSON('/api/security/webauthn/assert/finish', { id: secB64u(got.rawId), clientDataJSON: secB64u(got.response.clientDataJSON), authenticatorData: secB64u(got.response.authenticatorData), signature: secB64u(got.response.signature) })).json();
}

SEC_MORE.seckeys = async function secKeys() {
  const d = await getJSON('/api/security/webauthn'), out = el('div', { class: 'stack' }), name = secInput('Name', 'security key');
  const say = (fn, done) => async () => { try { await fn(); out.replaceChildren(text('p', done, 'st-ok')); secRender(); } catch (err) { out.replaceChildren(text('p', err.message, 'st-failed')); } };
  return el('div', { class: 'stack' }, secCard('Hardware keys', text('p', 'With a key enrolled, releasing a hold, the offline key and the airgap also ask for a touch on it. A browser only offers this over HTTPS or on localhost. If the key is lost, the offline key still works on the holds it covers, once a touch is off the account.', 'muted small'),
    d.keys.length ? secTable(['Key', 'Added', ''], d.keys.map((k) => [k.name, secWhen(k.created_at), button('Remove', async () => { if (await secPost(`/api/security/webauthn/${k.id}`, null, out, 'DELETE')) secRender(); }, 'btn sm ghost')])) : text('p', 'None enrolled.', 'muted'),
    el('div', { class: 'row wrap sec-acts' }, name, button('Enroll a key', say(() => secEnrollKey(name.value.trim()), 'Enrolled.'), 'btn sm pri'), d.keys.length ? button(d.stepped_up ? 'Touched: good for 5 minutes' : 'Touch it now', say(secTouchKey, 'Good for 5 minutes.'), 'btn sm') : ''), out));
};

/* ── what the other panels gain ───────────────────────────────────── */
SEC_MORE.complianceExtra = function secComplianceExtra(host, pick, standards) {
  const out = el('div', { class: 'stack' }), waivers = el('div', { class: 'stack' }), finding = secInput('a check, such as sysctl, or a Lynis id'), why = secInput('why this does not apply'), days = secInput('days', '90');
  const list = async () => { const { waivers: w } = await getJSON(`/api/security/waivers${secQ(host)}`); waivers.replaceChildren(w.length ? secTable(['Finding', 'Hosts', 'Why', 'By', 'Until', ''], w.map((x) => [x.finding, x.host === '*' ? 'every host' : x.host, x.reason, x.approver, x.expired ? 'expired' : secWhen(x.expires_at), secCan('security.manage') ? button('Remove', async () => { await secPost(`/api/security/waivers/${x.id}`, null, out, 'DELETE'); list(); }, 'btn sm ghost') : ''])) : text('p', 'No waivers.', 'muted small')); };
  list();
  const name = secInput('Name of the profile'), base = el('select', { 'aria-label': 'Based on' }, ...standards.map((s) => new Option(s.name, s.id))), target = secInput('Lynis target'), worm = secInput('Hold days');
  const pk = el('div', { class: 'stack' });
  return el('div', { class: 'stack' },
    secCard('Re-converge', text('p', 'Stages a plan for what can be fixed by a step, and lists what needs a person. Nothing changes until you apply it in Changes.', 'muted small'),
      el('div', { class: 'row wrap sec-acts' }, secCan('plans.edit') ? button('Stage a plan', async () => { const r = await secPost('/api/security/compliance/reconverge', { host, profile: pick.value }, out); secChanges(r, out); if (r?.by_hand?.length) out.append(secTable(['For a person'], r.by_hand.map((x) => [x]))); }, 'btn sm') : '',
        el('a', { class: 'btn sm', href: `/api/security/compliance/script?host=${encodeURIComponent(host)}&profile=${encodeURIComponent(pick.value)}` }, 'Download sf-init-compliance.sh')), out),
    secCard('Waivers', text('p', 'Says a failing check does not apply here, who said so, and until when. It still shows, and does not count against the host.', 'muted small'), waivers,
      secCan('security.manage') ? el('div', { class: 'stack' }, el('div', { class: 'sec-form' }, secField('Finding', finding), secField('Why', why), secField('Days', days)), button('Add', async () => { if (await secPost('/api/security/waivers', { host, finding: finding.value.trim(), reason: why.value.trim(), days: days.value.trim() }, out)) { list(); secRender(); } }, 'btn sm')) : ''),
    secCard('Your own profile', text('p', 'A standard with your numbers. The targets are StorageForge\'s suggestions either way: no standard sets them.', 'muted small'),
      el('div', { class: 'sec-form' }, secField('Name', name), secField('Based on', base), secField('Lynis target', target), secField('Hold days', worm)),
      secCan('security.manage') ? button('Save', () => secSave('/api/security/profiles', { name: name.value.trim(), base: base.value, overrides: { target_lynis: target.value.trim(), min_worm_days: worm.value.trim() } }, out, () => secRender()), 'btn sm') : ''),
    secCard('What is on this host', text('p', 'Present, installable from its package lists, or blocked: for a host with no mirror, make a bundle on an online host of the same distro, and pass it to the script with --offline-bundle.', 'muted small'), pk,
      secCan('security.manage') ? el('div', { class: 'row wrap sec-acts' }, button('Check', async () => { const r = await secPost('/api/security/packages/check', { host }, pk); if (r) pk.replaceChildren(secTable(['Tool', 'State'], Object.entries(r.tools).map(([k, v]) => [k, secPill(v, v === 'present' ? 'secure' : v === 'installable' ? 'warning' : 'critical')]))); }, 'btn sm'),
        button('Make a bundle here', async () => { const r = await secPost('/api/security/packages/bundle', { host, mode: 'apply' }, pk); if (r?.path) pk.prepend(text('p', `${r.packages} packages in ${r.path}. SHA-256 ${r.sha256}`, 'st-ok small')); }, 'btn sm')) : ''));
};

SEC_MORE.integrityExtra = async function secIntegrityExtra(host) {
  const out = el('div', { class: 'stack' }), { lynis } = await getJSON(`/api/security/trend${secQ(host)}`), { paths } = await getJSON('/api/security/integrity/aide/watch'), watch = secArea('/opt/backup/bin, one a line', paths.join('\n'));
  return el('div', { class: 'stack' },
    secCard('Stage the fixes', text('p', 'Turns the Lynis findings that map to a safe step into a plan: SSH settings, kernel settings, umask. The rest is listed for a person, not guessed at.', 'muted small'),
      lynis.length ? el('div', { class: 'row wrap' }, secSpark(lynis.map((x) => x.value)), text('span', `Hardening index ${lynis[lynis.length - 1].value}, over ${lynis.length} readings`, 'small')) : '',
      secCan('plans.edit') ? button('Stage them', async () => { const r = await secPost('/api/security/integrity/stage', { host }, out); secChanges(r, out); if (r?.by_hand?.length) out.append(secTable(['For a person', ''], r.by_hand.slice(0, 50).map((x) => [x.id, x.text]))); }, 'btn sm') : '', out),
    secCard('Extra paths for AIDE', text('p', 'In-house scripts and tools to watch, on the next baseline and check.', 'muted small'), watch, secCan('security.manage') ? button('Save', () => secSave('/api/security/integrity/aide/watch', { paths: secLines(watch) }, out), 'btn sm') : ''));
};

SEC_MORE.macExtra = function secMacExtra(host, d) {
  const out = el('div', { class: 'stack' }), noise = secArea('smbd /var/cache/*, one a line', (d.noise_rules || []).map((n) => `${n.daemon} ${n.path}`).join('\n')), map = secArea('/data/dept_* samba_share_t, one a line', (d.context_map || []).map((r) => `${r.pattern} ${r.type}`).join('\n'));
  const lateral = (d.avc || []).filter((a) => a.lateral);
  const profile = secInput('usr.sbin.smbd'), rules = el('textarea', { rows: '4', class: 'mono small', placeholder: '/srv/pool/dataset/** rwk,' }), mode = el('select', { 'aria-label': 'Mode' }, new Option('enforce', 'enforce'), new Option('complain', 'complain'));
  const stage = (task) => async () => { const r = await secPost('/api/map/stage', { plan: `Access control: ${host}`, tasks: [{ host, ...task() }] }, out); secChanges(r ? { ...r, tasks: 1 } : r, out); };
  return el('div', { class: 'stack' },
    lateral.length ? secCard('A daemon reached for something it should not', secTable(['When', 'Program', 'On'], lateral.map((a) => [secWhen(a.at), a.daemon, a.path])), text('p', 'These are never folded away as noise.', 'muted small')) : '',
    secCard('Booleans and labels as plan steps', d.booleans.filter((b) => b.ok === false).length ? secTable(['Boolean', 'Now', 'Should be', ''], d.booleans.filter((b) => b.ok === false).map((b) => [b.name, b.value, b.expected, secCan('plans.edit') ? button('Stage', stage(() => ({ type: 'selinux-boolean', params: { name: b.name, value: b.expected } })), 'btn sm') : ''])) : text('p', 'Nothing to stage.', 'muted small'), d.context_drift?.length ? secTable(['Mount', 'Is', 'Your rule says'], d.context_drift.map((x) => [x.path, x.live, x.want])) : '', secCan('plans.edit') && d.context_drift?.length ? button('Stage these labels', async () => { const r = await secPost('/api/security/mac/context/stage', { host }, out); secChanges(r, out); }, 'btn sm') : ''),
    secCard('Path to label rules', text('p', 'Your own rule for what a path should be labelled. Compared with what the last measurement read.', 'muted small'), map, secCan('security.manage') ? button('Save', () => secSave('/api/security/mac/context', { rules: secLines(map).map((l) => { const [pattern, type] = l.split(/\s+/); return { pattern, type }; }) }, out, () => secRender()), 'btn sm') : ''),
    secCard('Denials that are only noise', text('p', 'Folded out of the counts, not deleted. Program and path, each may have a *.', 'muted small'), noise, secCan('security.manage') ? button('Save', () => secSave('/api/security/mac/noise', { rules: secLines(noise).map((l) => { const [daemon, path] = l.split(/\s+/); return { daemon, path }; }) }, out, () => secRender()), 'btn sm') : ''),
    d.apparmor?.enabled ? secCard('AppArmor', text('p', 'Local rules go in /etc/apparmor.d/local, so a package update keeps them. Both become steps in a plan.', 'muted small'), secField('Profile', profile), rules,
      secCan('plans.edit') ? el('div', { class: 'row wrap sec-acts' }, button('Stage these rules', stage(() => ({ type: 'apparmor-local', params: { profile: profile.value.trim(), rules: rules.value } })), 'btn sm'), mode, button('Stage this mode', stage(() => ({ type: 'apparmor-mode', params: { profile: profile.value.trim(), mode: mode.value } })), 'btn sm')) : '') : '', out);
};

/* ── the line at the top of every page ────────────────────────────── */
// the chip is chrome.js's, so the planner, /manage and the search page show the same one; a click here opens the Security panel
const threatBanner = sfSecurityChip($('#threatbanner'), () => { showTab('security'); }, () => can('security.view'), 1500);
