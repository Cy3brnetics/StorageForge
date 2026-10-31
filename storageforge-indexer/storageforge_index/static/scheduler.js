'use strict';
/* Unified Scheduler panel: schedule any StorageForge operation (task, change, move, shares, scan, command)
   as client-side cron jobs with comprehensive server-side verification, direct SSH deploy, and run inspector. */

const SCH = {
  schedules: [],
  installed: {},
  runs: [],
  hosts: [],
  tasks: [],
  changes: [],
  moves: [],
  current: null,
  tokenMsg: '',
  err: '',
  openRunId: null,
};

const CRON_PRESETS = [
  { label: 'Every 15m', expr: '*/15 * * * *' },
  { label: 'Hourly', expr: '0 * * * *' },
  { label: 'Nightly 02:00', expr: '0 2 * * *' },
  { label: 'Weekly Sun 03:00', expr: '0 3 * * 0' },
  { label: 'Monthly 1st', expr: '0 4 1 * *' },
];

function blankSchedule(host = '') {
  return {
    schedule_id: null,
    name: '',
    host: host || S.host || SCH.hosts[0] || '',
    cron_expr: '0 2 * * *',
    task_type: 'task',
    task_ref: '',
    paused: false,
    config: {
      timezone: 'UTC',
      window: '',
      timeout_sec: 3600,
      concurrency_policy: 'skip',
      retry_count: 0,
      retry_delay_sec: 30,
      retry_backoff: 1.0,
      nice: 10,
      ionice_class: 'best-effort',
      ionice_priority: 7,
      user: 'root',
      env: {},
      jitter_sec: 0,
      verify_policy: 'comprehensive',
      verify_rules: {
        require_exit_zero: true,
        check_mounts: [],
        min_free_gib: {},
        paths_must_exist: [],
        paths_must_not_exist: [],
        output_must_match: '',
        output_must_not_match: '',
        auto_rescan: false,
      },
      notify_on: ['failure', 'verify_failure'],
    },
  };
}

async function loadScheduler(selectId = null) {
  const box = $('#schedulebox');
  if (!box) return;
  try {
    const [sRes, hRes, tRes, cRes, mRes] = await Promise.all([
      getJSON('/api/scheduler/schedules'),
      getJSON('/api/hosts').catch(() => ({ indexed: [] })),
      getJSON('/api/tasks').catch(() => ({ tasks: [] })),
      getJSON('/api/changes').catch(() => ({ plans: [] })),
      getJSON('/api/moves').catch(() => ({ plans: [] })),
    ]);
    SCH.schedules = sRes.schedules || [];
    SCH.installed = sRes.installed || {};
    SCH.hosts = (hRes.indexed || []).map((x) => x.hostname).sort();
    SCH.tasks = tRes.tasks || [];
    SCH.changes = cRes.plans || [];
    SCH.moves = mRes.plans || [];
    SCH.err = '';

    const targetId = selectId ?? SCH.current?.schedule_id;
    if (targetId) {
      const found = SCH.schedules.find((s) => s.schedule_id === targetId);
      if (found) SCH.current = JSON.parse(JSON.stringify(found));
    }
    if (!SCH.current) {
      SCH.current = SCH.schedules[0] ? JSON.parse(JSON.stringify(SCH.schedules[0])) : blankSchedule();
    }
    await loadScheduleRuns();
  } catch (err) {
    SCH.err = err.message;
  }
  renderScheduler();
}

async function loadScheduleRuns() {
  try {
    const sid = SCH.current?.schedule_id;
    const url = sid ? `/api/scheduler/schedules/${sid}/runs?limit=30` : '/api/scheduler/runs?limit=30';
    const r = await getJSON(url);
    SCH.runs = r.runs || [];
  } catch {
    SCH.runs = [];
  }
}

function fmtMinFree(map) {
  return Object.entries(map || {}).map(([p, g]) => `${p}:${g}`).join(', ');
}

function parseMinFree(str) {
  const out = {};
  for (const part of (str || '').split(',')) {
    const idx = part.lastIndexOf(':');
    if (idx <= 0) continue;
    const p = part.slice(0, idx).trim();
    const g = parseInt(part.slice(idx + 1).trim(), 10);
    if (p.startsWith('/') && g > 0) out[p] = g;
  }
  return out;
}

function fmtEnvLines(env) {
  return Object.entries(env || {}).map(([k, v]) => `${k}=${v}`).join('\n');
}

function parseEnvLines(str) {
  const out = {};
  for (const line of (str || '').split('\n')) {
    const idx = line.indexOf('=');
    if (idx <= 0) continue;
    const k = line.slice(0, idx).trim();
    const v = line.slice(idx + 1).trim();
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) out[k] = v;
  }
  return out;
}

function statusClass(st) {
  if (st === 'verified' || st === 'ok') return 'st-ok';
  if (st === 'verify_failed' || st === 'warn') return 'st-warn';
  if (st === 'failed' || st === 'crit') return 'st-failed';
  return 'muted';
}

function renderScheduler() {
  const box = $('#schedulebox');
  if (!box) return;
  box.replaceChildren();

  if (SCH.err) {
    box.append(text('p', SCH.err, 'st-failed'));
  }
  if (SCH.tokenMsg) {
    const notice = el('div', { class: 'card' },
      text('b', 'Client Auth Token (copy now; shown once):'),
      el('pre', { class: 'mono small', style: 'overflow-x:auto;margin:6px 0' }, SCH.tokenMsg),
      el('div', { class: 'row end' },
        button('Copy token', () => copyText(SCH.tokenMsg, 'Copied token'), 'btn sm'),
        button('Dismiss', () => { SCH.tokenMsg = ''; renderScheduler(); }, 'btn ghost sm')
      )
    );
    box.append(notice);
  }

  // Top bar: schedule selector + New button
  const sel = el('select', {
    'aria-label': 'Select schedule',
    onchange: async () => {
      const id = Number(sel.value);
      const found = SCH.schedules.find((x) => x.schedule_id === id);
      SCH.current = found ? JSON.parse(JSON.stringify(found)) : blankSchedule();
      SCH.tokenMsg = '';
      await loadScheduleRuns();
      renderScheduler();
    },
  });
  sel.append(new Option('+ New schedule…', '0'));
  for (const s of SCH.schedules) {
    const st = s.paused ? 'paused' : (s.last_status || 'idle');
    sel.append(new Option(`#${s.schedule_id} ${s.name} (${s.host} · ${s.cron_expr} · ${st})`, String(s.schedule_id)));
  }
  sel.value = SCH.current?.schedule_id ? String(SCH.current.schedule_id) : '0';

  box.append(
    el('div', { class: 'row wrap' },
      el('label', { class: 'field grow' }, text('span', 'Schedule'), sel),
      button('+ New', async () => {
        SCH.current = blankSchedule();
        SCH.tokenMsg = '';
        await loadScheduleRuns();
        renderScheduler();
      }, 'btn sm')
    )
  );

  // Schedule summary pills if existing
  const cur = SCH.current || blankSchedule();
  const cfg = cur.config || blankSchedule().config;
  const vr = cfg.verify_rules || {};

  if (cur.schedule_id) {
    const inst = SCH.installed[String(cur.schedule_id)] || [];
    const nextStr = cur.paused ? 'paused' : (cur.next_run_at ? `${when(cur.next_run_at)} (${stamp(cur.next_run_at)})` : '—');
    const lastStr = cur.last_run_at ? `${when(cur.last_run_at)} (${cur.last_status || '—'})` : 'never';
    box.append(
      el('div', { class: 'card stack' },
        el('div', { class: 'row wrap' },
          text('b', `${cur.name} (#${cur.schedule_id})`),
          text('span', cur.paused ? 'PAUSED' : (cur.last_status || 'IDLE').toUpperCase(), `pill sm ${statusClass(cur.last_status)}`),
          inst.length
            ? text('span', `Deployed on ${inst.map((i) => i.host).join(', ')}`, 'small st-ok')
            : text('span', 'Not deployed via SSH yet', 'small muted')
        ),
        text('span', `Next run: ${nextStr} · Last run: ${lastStr}`, 'small muted'),
        el('div', { class: 'row wrap' },
          button(cur.paused ? 'Resume' : 'Pause', async () => {
            try {
              const verb = cur.paused ? 'Resum' : 'Paus';
              const r = await (await postJSON(`/api/scheduler/schedules/${cur.schedule_id}/pause`, { paused: !cur.paused })).json();
              toast(r.host_pending ? `Saved, but ${r.host_pending.join(', ')} has no deploy access: its timer has not changed`
                : r.group ? `${verb}ing on ${r.hosts.join(', ')}…` : `Schedule ${verb.toLowerCase()}ed`);
              await loadScheduler(cur.schedule_id);
            } catch (e) { toast(e.message); }
          }, 'btn sm'),
          button('Run now (SSH)', async () => {
            startDeploy('schedules', cur.schedule_id, 'apply', `run schedule ${cur.name}`, { run: true });
          }, 'btn pri sm'),
          button('Verify now', async () => {
            try {
              const r = await (await postJSON(`/api/scheduler/schedules/${cur.schedule_id}/verify`, {})).json();
              toast(`Verification: ${r.status} — ${r.verify_result?.summary || ''}`);
              await loadScheduler(cur.schedule_id);
            } catch (e) { toast(e.message); }
          }, 'btn sm'),
          button('Deploy (SSH)', () => {
            startDeploy('schedules', cur.schedule_id, 'report', `schedule ${cur.name}`);
          }, 'btn sm'),
          inst.length ? button('Uninstall', () => {
            startDeploy('schedules', cur.schedule_id, 'apply', `uninstall schedule ${cur.name}`, { remove: true });
          }, 'btn ghost sm danger') : null,
          el('a', { class: 'btn ghost sm', href: `/api/scheduler/schedules/${cur.schedule_id}/install-script`, download: `install-schedule-${cur.schedule_id}.sh` }, 'Install .sh'),
          el('a', { class: 'btn ghost sm', href: `/api/scheduler/schedules/${cur.schedule_id}/script`, download: `task-${cur.schedule_id}.sh` }, 'Task .sh'),
          button('Rotate token', async () => {
            try {
              const r = await (await postJSON(`/api/scheduler/schedules/${cur.schedule_id}/token`, {})).json();
              SCH.tokenMsg = r.token;
              renderScheduler();
            } catch (e) { toast(e.message); }
          }, 'btn ghost sm'),
          button('Delete', async () => {
            if (!confirm(`Delete schedule "${cur.name}" (#${cur.schedule_id})?`)) return;
            try {
              await api(`/api/scheduler/schedules/${cur.schedule_id}`, { method: 'DELETE' });
              SCH.current = null;
              toast('Schedule deleted');
              await loadScheduler();
            } catch (e) { toast(e.message); }
          }, 'btn ghost sm danger')
        )
      )
    );
  }

  // Schedule Configuration Form
  const nameIn = el('input', { type: 'text', value: cur.name || '', placeholder: 'nightly-zfs-backup', required: true });
  const hostIn = el('input', { type: 'text', value: cur.host || '', placeholder: 'nas-01', list: 'sch-hosts-dl', required: true });
  const cronIn = el('input', { type: 'text', class: 'mono', value: cur.cron_expr || '0 2 * * *', placeholder: '0 2 * * *', required: true });
  const tzIn = el('input', { type: 'text', value: cfg.timezone || 'UTC', placeholder: 'UTC or America/New_York' });
  const winIn = el('input', { type: 'text', class: 'mono', value: cfg.window || '', placeholder: '01:00-06:00 (optional)' });

  const typeSel = el('select', {
    onchange: () => {
      cur.task_type = typeSel.value;
      if (cur.task_type === 'shares' && !cur.task_ref) cur.task_ref = hostIn.value.trim();
      renderRefPicker();
    },
  },
    new Option('Storage Task (blocks)', 'task'),
    new Option('Change Plan (folders/mounts/drives)', 'change'),
    new Option('Move Plan (rsync data move)', 'move'),
    new Option('Shares (NFS / SMB design)', 'shares'),
    new Option('Command (shell script/command)', 'command')
  );
  typeSel.value = cur.task_type || 'task';

  const refBox = el('div', { class: 'stack' });
  let getRefValue = () => cur.task_ref || '';

  function renderRefPicker() {
    refBox.replaceChildren();
    const t = typeSel.value;
    if (t === 'task' && SCH.tasks.length) {
      const s = el('select', {});
      s.append(new Option('— Select a Storage Task —', ''));
      for (const x of SCH.tasks) s.append(new Option(`${x.name} (${x.host || 'any host'})`, x.slug || String(x.id)));
      s.value = cur.task_ref || '';
      getRefValue = () => s.value.trim();
      refBox.append(el('label', { class: 'field col' }, text('span', 'Storage Task'), s));
    } else if (t === 'change' && SCH.changes.length) {
      const s = el('select', {});
      s.append(new Option('— Select a Change Plan —', ''));
      for (const x of SCH.changes) s.append(new Option(`#${x.id} ${x.name}`, String(x.id)));
      s.value = cur.task_ref || '';
      getRefValue = () => s.value.trim();
      refBox.append(el('label', { class: 'field col' }, text('span', 'Change Plan'), s));
    } else if (t === 'move' && SCH.moves.length) {
      const s = el('select', {});
      s.append(new Option('— Select a Move Plan —', ''));
      for (const x of SCH.moves) s.append(new Option(`#${x.id} ${x.name}`, String(x.id)));
      s.value = cur.task_ref || '';
      getRefValue = () => s.value.trim();
      refBox.append(el('label', { class: 'field col' }, text('span', 'Move Plan'), s));
    } else if (t === 'command') {
      const ta = el('textarea', { class: 'mono', rows: 3, placeholder: 'zpool scrub tank && btrfs scrub status /mnt/data' });
      ta.value = cur.task_ref || '';
      getRefValue = () => ta.value.trim();
      refBox.append(el('label', { class: 'field col' }, text('span', 'Shell Command (runs as bash -euo pipefail)'), ta));
    } else {
      const inp = el('input', {
        type: 'text',
        value: cur.task_ref || (t === 'scan' || t === 'shares' ? hostIn.value.trim() : ''),
        placeholder: t === 'scan' || t === 'shares' ? 'Host name (e.g. nas-01)' : 'Task name/slug or Plan ID',
      });
      getRefValue = () => inp.value.trim();
      refBox.append(el('label', { class: 'field col' }, text('span', t === 'shares' ? 'Server Host' : t === 'scan' ? 'Host to Scan' : 'Target Reference'), inp));
    }
  }
  renderRefPicker();

  // Execution & Resource controls
  const concSel = el('select', {},
    new Option('Skip if already running', 'skip'),
    new Option('Queue and wait for lock', 'queue'),
    new Option('Replace running instance', 'replace')
  );
  concSel.value = cfg.concurrency_policy || 'skip';

  const timeoutIn = el('input', { type: 'number', min: 0, max: 864000, value: cfg.timeout_sec ?? 3600 });
  const jitterIn = el('input', { type: 'number', min: 0, max: 300, value: cfg.jitter_sec ?? 0 });
  const retriesIn = el('input', { type: 'number', min: 0, max: 10, value: cfg.retry_count ?? 0 });
  const retryDelayIn = el('input', { type: 'number', min: 1, max: 3600, value: cfg.retry_delay_sec ?? 30 });
  const retryBackoffIn = el('input', { type: 'number', step: '0.5', min: 1, max: 10, value: cfg.retry_backoff ?? 1.0 });
  const niceIn = el('input', { type: 'number', min: -20, max: 19, value: cfg.nice ?? 10 });
  const ioniceSel = el('select', {},
    new Option('best-effort', 'best-effort'),
    new Option('idle', 'idle'),
    new Option('realtime', 'realtime')
  );
  ioniceSel.value = cfg.ionice_class || 'best-effort';
  const ionicePrioIn = el('input', { type: 'number', min: 0, max: 7, value: cfg.ionice_priority ?? 7 });
  const userIn = el('input', { type: 'text', value: cfg.user || 'root' });
  const envArea = el('textarea', { class: 'mono', rows: 2, placeholder: 'RESTIC_REPOSITORY=/srv/backup\nBORG_PASSPHRASE=...' });
  envArea.value = fmtEnvLines(cfg.env);

  // Verification controls
  const vPolicySel = el('select', {},
    new Option('Comprehensive (Report + StorageForge Index state)', 'comprehensive'),
    new Option('State only (StorageForge Index state)', 'state_only'),
    new Option('Report only (Exit code & output regex)', 'report_only'),
    new Option('None (Skip verification)', 'none')
  );
  vPolicySel.value = cfg.verify_policy || 'comprehensive';

  const reqZeroChk = el('input', { type: 'checkbox', checked: vr.require_exit_zero !== false });
  const rescanChk = el('input', { type: 'checkbox', checked: Boolean(vr.auto_rescan) });
  const mountsIn = el('input', { type: 'text', class: 'mono', value: (vr.check_mounts || []).join(', '), placeholder: '/mnt/nas, /srv/pool' });
  const minFreeIn = el('input', { type: 'text', class: 'mono', value: fmtMinFree(vr.min_free_gib), placeholder: '/mnt/nas:50, /srv/pool:100' });
  const existIn = el('input', { type: 'text', class: 'mono', value: (vr.paths_must_exist || []).join(', '), placeholder: '/mnt/nas/backups/latest' });
  const notExistIn = el('input', { type: 'text', class: 'mono', value: (vr.paths_must_not_exist || []).join(', '), placeholder: '/mnt/nas/tmp/lock' });
  const matchIn = el('input', { type: 'text', class: 'mono', value: vr.output_must_match || '', placeholder: 'completed successfully|0 errors' });
  const notMatchIn = el('input', { type: 'text', class: 'mono', value: vr.output_must_not_match || '', placeholder: 'FATAL|ERROR|corruption' });
  const notifyFailChk = el('input', { type: 'checkbox', checked: (cfg.notify_on || ['failure']).includes('failure') });
  const notifyVerChk = el('input', { type: 'checkbox', checked: (cfg.notify_on || ['verify_failure']).includes('verify_failure') });

  const form = el('form', {
    class: 'card stack',
    onsubmit: async (ev) => {
      ev.preventDefault();
      const notifyOn = [];
      if (notifyFailChk.checked) notifyOn.push('failure');
      if (notifyVerChk.checked) notifyOn.push('verify_failure');

      const payload = {
        name: nameIn.value.trim(),
        host: hostIn.value.trim(),
        cron_expr: cronIn.value.trim(),
        task_type: typeSel.value,
        task_ref: getRefValue(),
        paused: Boolean(cur.paused),
        config: {
          timezone: tzIn.value.trim() || 'UTC',
          window: winIn.value.trim(),
          timeout_sec: Number(timeoutIn.value) || 0,
          concurrency_policy: concSel.value,
          retry_count: Number(retriesIn.value) || 0,
          retry_delay_sec: Number(retryDelayIn.value) || 30,
          retry_backoff: Number(retryBackoffIn.value) || 1.0,
          nice: Number(niceIn.value),
          ionice_class: ioniceSel.value,
          ionice_priority: Number(ionicePrioIn.value),
          user: userIn.value.trim() || 'root',
          env: parseEnvLines(envArea.value),
          jitter_sec: Number(jitterIn.value) || 0,
          verify_policy: vPolicySel.value,
          verify_rules: {
            require_exit_zero: reqZeroChk.checked,
            check_mounts: mountsIn.value.split(',').map((s) => s.trim()).filter(Boolean),
            min_free_gib: parseMinFree(minFreeIn.value),
            paths_must_exist: existIn.value.split(',').map((s) => s.trim()).filter(Boolean),
            paths_must_not_exist: notExistIn.value.split(',').map((s) => s.trim()).filter(Boolean),
            output_must_match: matchIn.value.trim(),
            output_must_not_match: notMatchIn.value.trim(),
            auto_rescan: rescanChk.checked,
          },
          notify_on: notifyOn,
        },
      };

      try {
        if (cur.schedule_id) {
          const updated = await (await api(`/api/scheduler/schedules/${cur.schedule_id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          })).json();
          SCH.current = updated;
          toast(`Saved schedule "${updated.name}"`);
          await loadScheduler(updated.schedule_id);
        } else {
          const created = await (await postJSON('/api/scheduler/schedules', payload)).json();
          SCH.current = created.schedule;
          SCH.tokenMsg = created.token || '';
          toast(`Created schedule "${created.schedule.name}"`);
          await loadScheduler(created.schedule.schedule_id);
        }
      } catch (e) {
        toast(e.message);
      }
    },
  },
    text('h3', cur.schedule_id ? `Edit Schedule #${cur.schedule_id}` : 'Create New Schedule'),
    el('div', { class: 'row wrap' },
      el('label', { class: 'field col grow' }, text('span', 'Schedule Name'), nameIn),
      el('label', { class: 'field col grow' }, text('span', 'Target Host'), hostIn)
    ),
    el('div', { class: 'row wrap' },
      el('label', { class: 'field col grow' }, text('span', 'Cron Expression (min hour dom mon dow)'), cronIn),
      el('label', { class: 'field col' }, text('span', 'Timezone'), tzIn)
    ),
    el('div', { class: 'row wrap' },
      ...CRON_PRESETS.map((p) => button(p.label, () => { cronIn.value = p.expr; }, 'btn ghost sm'))
    ),
    el('label', { class: 'field col' }, text('span', 'Task Type'), typeSel),
    refBox,
    el('details', { open: true },
      el('summary', {}, text('b', 'Server Verification Rules')),
      el('div', { class: 'stack', style: 'margin-top:8px' },
        el('label', { class: 'field col' }, text('span', 'Verification Policy'), vPolicySel),
        el('label', { class: 'check' }, reqZeroChk, ' Require exit code 0'),
        el('label', { class: 'check' }, rescanChk, ' Queue automatic host scan after schedule reports completion'),
        el('label', { class: 'field col' }, text('span', 'Mounts that must be present (comma-separated)'), mountsIn),
        el('label', { class: 'field col' }, text('span', 'Minimum free space GiB (path:gib, comma-separated)'), minFreeIn),
        el('label', { class: 'field col' }, text('span', 'Paths that must exist in index (comma-separated)'), existIn),
        el('label', { class: 'field col' }, text('span', 'Paths that must NOT exist in index (comma-separated)'), notExistIn),
        el('div', { class: 'row wrap' },
          el('label', { class: 'field col grow' }, text('span', 'Output must match regex'), matchIn),
          el('label', { class: 'field col grow' }, text('span', 'Output must NOT match regex'), notMatchIn)
        ),
        el('div', { class: 'row wrap' },
          el('label', { class: 'check' }, notifyFailChk, ' Alert on execution failure'),
          el('label', { class: 'check' }, notifyVerChk, ' Alert on server verification failure')
        )
      )
    ),
    el('details', {},
      el('summary', {}, text('b', 'Execution, Concurrency, Retries & Priority')),
      el('div', { class: 'stack', style: 'margin-top:8px' },
        el('div', { class: 'row wrap' },
          el('label', { class: 'field col grow' }, text('span', 'Concurrency Policy'), concSel),
          el('label', { class: 'field col grow' }, text('span', 'Allowed Time Window'), winIn)
        ),
        el('div', { class: 'row wrap' },
          el('label', { class: 'field col grow' }, text('span', 'Timeout (sec, 0=none)'), timeoutIn),
          el('label', { class: 'field col grow' }, text('span', 'Random Jitter (sec)'), jitterIn),
          el('label', { class: 'field col grow' }, text('span', 'Run as User'), userIn)
        ),
        el('div', { class: 'row wrap' },
          el('label', { class: 'field col grow' }, text('span', 'Retries on failure'), retriesIn),
          el('label', { class: 'field col grow' }, text('span', 'Retry Delay (sec)'), retryDelayIn),
          el('label', { class: 'field col grow' }, text('span', 'Backoff Multiplier'), retryBackoffIn)
        ),
        el('div', { class: 'row wrap' },
          el('label', { class: 'field col grow' }, text('span', 'CPU Nice (-20..19)'), niceIn),
          el('label', { class: 'field col grow' }, text('span', 'I/O Class'), ioniceSel),
          el('label', { class: 'field col grow' }, text('span', 'I/O Priority (0..7)'), ionicePrioIn)
        ),
        el('label', { class: 'field col' }, text('span', 'Environment Variables (KEY=VALUE per line)'), envArea)
      )
    ),
    el('div', { class: 'row end' },
      button(cur.schedule_id ? 'Save Changes' : 'Create Schedule', null, 'btn pri')
    ),
    el('datalist', { id: 'sch-hosts-dl' }, ...SCH.hosts.map((h) => new Option(h, h)))
  );

  box.append(form);

  // Run History & Server Verification Inspector
  const runsHead = el('div', { class: 'row' },
    text('h3', cur.schedule_id ? `Run History & Verification (#${cur.schedule_id})` : 'Recent Schedule Runs'),
    button('Refresh', async () => { await loadScheduleRuns(); renderScheduler(); }, 'btn ghost sm')
  );
  box.append(runsHead);

  if (!SCH.runs.length) {
    box.append(text('p', 'No runs recorded yet. Deploy the schedule to the client or click "Run now".', 'muted'));
    return;
  }

  const runList = el('ol', { class: 'list' });
  for (const r of SCH.runs) {
    const vrSummary = r.verify_result?.summary || '';
    const checks = r.verify_result?.checks || [];
    const isOpen = SCH.openRunId === r.run_id;

    const li = el('li', { class: 'stack' },
      el('div', { class: 'row wrap' },
        text('b', `#${r.run_id} ${r.schedule_name || `Schedule #${r.schedule_id}`}`),
        text('span', r.status, statusClass(r.status)),
        text('span', `exit ${r.exit_code ?? '—'} · ${when(r.started_at)} on ${r.host}`, 'small muted'),
        button(isOpen ? 'Hide details' : 'Inspect', () => {
          SCH.openRunId = isOpen ? null : r.run_id;
          renderScheduler();
        }, 'btn ghost sm'),
        button('Re-verify', async () => {
          try {
            const rev = await (await postJSON(`/api/scheduler/schedules/${r.schedule_id}/verify`, { run_id: r.run_id })).json();
            toast(`Run #${r.run_id}: ${rev.status}`);
            await loadScheduleRuns();
            renderScheduler();
          } catch (e) { toast(e.message); }
        }, 'btn ghost sm')
      ),
      vrSummary ? text('span', `${vrSummary} (${r.report_source || 'report'})`, 'small muted') : null
    );

    if (isOpen) {
      const checkItems = checks.map((c) =>
        el('li', {},
          text('span', `[${(c.status || 'ok').toUpperCase()}] ${c.name}: `, statusClass(c.status)),
          text('span', c.message || '')
        )
      );
      li.append(
        el('div', { class: 'card stack', style: 'margin-top:4px' },
          text('b', 'Server Verification Checks'),
          checkItems.length ? el('ul', { class: 'list' }, ...checkItems) : text('span', 'No checks recorded', 'muted small'),
          r.output ? text('b', 'Execution Output') : null,
          r.output ? el('pre', { class: 'mono small', style: 'max-height:220px;overflow:auto' }, r.output) : null
        )
      );
    }
    runList.append(li);
  }
  box.append(runList);
}
