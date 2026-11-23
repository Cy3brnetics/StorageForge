'use strict';
/* The optional agent on the Keys page (docs/agent.md, routes_agent.py): which hosts run one, in which mode, and which signed plugins of
   the release each runs. A plugin that declares a privilege takes an admin; the files plugin is root on its host in effect, and this is
   where it is switched on, so that is said here first, in plain words, before it can be ticked. Loaded after kernel.js and app.js. */

function agentPluginRow(p, on) {
  const box = sfNode('input', { type: 'checkbox', value: p.name, 'aria-label': `Run the ${p.name} plugin` });
  if (on) box.checked = true;
  const warn = p.root_in_effect ? sfNode('p', { class: 'st-failed small' }, sfNode('b', {}, 'Root on this host in effect. '), p.note.replace(/^ROOT ON THIS HOST IN EFFECT\.\s*/, '')) : null;
  return sfNode('label', { class: 'stack' }, sfNode('span', { class: 'row' }, box, sfNode('b', {}, p.name),
    p.privileged ? sfNode('span', { class: 'muted small' }, ' · takes an admin') : null),
  warn || sfNode('span', { class: 'muted small' }, p.note));
}

function agentPluginsForm(host, plugins, running) {
  const rows = plugins.map((p) => agentPluginRow(p, running.includes(p.name)));
  const go = sfNode('button', { type: 'submit', class: 'btn pri sm' }, 'Run these plugins');
  const form = sfNode('form', { class: 'stack' }, ...rows, go);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const chosen = [...form.querySelectorAll('input[type=checkbox]')].filter((b) => b.checked).map((b) => b.value);
    const root = plugins.filter((p) => p.root_in_effect && chosen.includes(p.name) && !running.includes(p.name));
    if (root.length && !(await confirmDialog({ title: `Give the agent on ${host} root in effect?`, danger: true, confirm: 'Switch it on',
      body: `${root.map((p) => p.note).join('\n\n')}\n\nIt is written to the audit log with your name, and only an admin can do it.` }))) return;
    try {
      const got = await (await postJSON(`/api/agents/${encodeURIComponent(host)}/plugins`, { plugins: chosen }, { busy: go })).json();
      notify(got.warning ? `${host}: plugins set. ${got.warning}` : `${host}: plugins set (manifest ${got.counter}).`);
    } catch (err) { notify(err.message, 'error'); }
    loadAgents();
  });
  return form;
}

function agentLine(a) {
  const cls = a.state === 'running' ? 'st-ok' : a.state === 'wiped' || a.state === 'failed' ? 'st-failed' : 'muted';
  const mode = a.mode === 'monitoring' ? 'monitoring only: no change plans, deploys, Moves, sends, clone, holds or quarantine; the console turns SSH on for one session' : 'beside SSH';
  return sfNode('p', {}, sfNode('b', {}, a.host), ' · ', sfNode('span', { class: cls }, a.state), ` · ${mode}`,
    a.runtime ? ` · ${a.runtime}` : '', a.fingerprint ? sfNode('span', { class: 'muted small' }, ` · ${a.fingerprint}`) : null);
}

function agentMonitoringForm() {
  const host = sfNode('input', { required: true, maxlength: 100, autocomplete: 'off', spellcheck: false });
  const address = sfNode('input', { required: true, maxlength: 255, autocomplete: 'off', spellcheck: false });
  const port = sfNode('input', { type: 'number', min: 1, max: 65535, value: 22, required: true });
  const arch = sfNode('select', {}, new Option('x86-64', 'x86_64'), new Option('ARM64', 'aarch64'));
  const label = (name, field) => sfNode('label', { class: 'sf-field' }, sfNode('span', {}, name), field);
  const submit = sfNode('button', { type: 'submit', class: 'btn pri sm' }, 'Register host');
  const form = sfNode('form', { class: 'stack' },
    label('Host name', host), label('SSH address', address), label('SSH port', port), label('Architecture', arch), submit);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      const res = await postJSON('/api/agents/monitoring', {
        host: host.value.trim(), address: address.value.trim(), port: Number(port.value), arch: arch.value,
      }, { busy: submit });
      const registered = await res.json();
      await loadAgents();
      notify(`${registered.host} registered. Open its setup instructions to continue.`);
    } catch (err) { notify(err.message, 'error'); }
  });
  return sfNode('details', {}, sfNode('summary', {}, 'Register a monitoring-only Linux host'), form);
}

function agentMonitoringSetup(host) {
  const path = `/api/agents/${encodeURIComponent(host)}`;
  const panel = sfNode('div', { class: 'stack' });
  const load = button('Get setup instructions', async () => {
    try {
      const setup = await getJSON(`${path}/setup`);
      const scriptName = setup.platform === 'windows' ? 'storageforge-agent-setup.ps1' : 'storageforge-agent-setup.sh';
      const script = button('Download setup script', () => {
        const url = URL.createObjectURL(new Blob([setup.script], { type: 'text/plain' }));
        const a = sfNode('a', { href: url, download: scriptName });
        document.body.append(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
      }, 'btn ghost sm');
      const program = setup.platform === 'linux' ? button('Download storageforge-agentctl', () =>
        download(`/api/agents/program/${encodeURIComponent(setup.arch)}`, 'storageforge-agentctl'), 'btn ghost sm') : null;
      panel.replaceChildren(sfNode('p', {}, setup.how), sfNode('div', { class: 'row wrap' }, script, program));
    } catch (err) { panel.replaceChildren(sfNode('p', { class: 'st-failed' }, err.message)); }
  }, 'btn ghost sm');
  const kids = [sfNode('summary', {}, 'Set up monitoring'), load, panel];
  if (can('agent.privilege')) {
    const line = sfNode('textarea', { required: true, maxlength: 2000, rows: 2, spellcheck: false, autocomplete: 'off' });
    const confirmed = sfNode('input', { type: 'checkbox', required: true });
    const submit = sfNode('button', { type: 'submit', class: 'btn pri sm' }, 'Adopt host');
    const form = sfNode('form', { class: 'stack' },
      sfNode('label', { class: 'sf-field' }, sfNode('span', {}, 'Line beginning storageforge-agent-adopt'), line),
      sfNode('label', { class: 'check' }, confirmed, 'I compared the key in this line with the host’s own SSH public key.'),
      submit);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      try {
        const res = await postJSON(`${path}/adopt`, { line: line.value.trim() }, { busy: submit });
        const adopted = await res.json();
        await loadAgents();
        notify(`${adopted.host}: ${adopted.state}.`);
      } catch (err) { notify(err.message, 'error'); }
    });
    kids.push(form);
  }
  return sfNode('details', { class: 'stack' }, ...kids);
}

function agentRecords(host) {
  const panel = sfNode('div', { class: 'stack' });
  const refresh = button('Load recent records', async () => {
    try {
      const data = await getJSON(`/api/agents/${encodeURIComponent(host)}/records?limit=30`);
      const records = (data.records || []).map((record) => sfNode('details', {},
        sfNode('summary', {}, `${record.plugin} · ${record.kind} · `, timeEl(record.received_at)),
        sfNode('pre', {}, JSON.stringify(record.body, null, 2))));
      const actions = (data.actions || []).map((action) => sfNode('li', {},
        timeEl(action.at), ` · ${action.action} · ${action.outcome}`, action.detail ? ` · ${action.detail}` : ''));
      panel.replaceChildren(sfNode('p', { class: 'muted small' }, data.label),
        ...(records.length ? records : [sfNode('p', {}, 'No records received.')]),
        ...(actions.length ? [sfNode('h4', {}, 'Recent actions'), sfNode('ul', {}, ...actions)] : []));
    } catch (err) { panel.replaceChildren(sfNode('p', { class: 'st-failed' }, err.message)); }
  }, 'btn ghost sm');
  return sfNode('details', { class: 'stack' }, sfNode('summary', {}, 'Agent records'), refresh, panel);
}

async function loadAgents() {
  const box = document.getElementById('agentbox');
  if (!box) return;
  let d;
  try { d = await getJSON('/api/agents'); } catch (err) { box.replaceChildren(sfNode('p', { class: 'muted' }, err.message)); box.hidden = false; return; }
  const enrolled = (d.agents || []).filter((a) => a.state && a.state !== 'off');
  const kids = [sfNode('h3', {}, 'Agents'),
    sfNode('p', { class: 'muted small' }, 'The agent is an extra, switched on one host at a time: readings as they happen. Built, not lab-tested. See docs/agent.md.')];
  if (can('keys.manage')) kids.push(agentMonitoringForm());
  if (!enrolled.length) kids.push(sfNode('p', { class: 'muted' }, 'No host runs the agent.'));
  for (const a of enrolled) {
    kids.push(agentLine(a));
    if (can('hosts.view')) kids.push(agentRecords(a.host));
    if (a.mode === 'monitoring' && a.state !== 'running' && can('keys.manage')) kids.push(agentMonitoringSetup(a.host));
    if (a.state === 'running' && can('keys.manage') && (d.plugins || []).length) {
      const det = sfNode('details', {}, sfNode('summary', {}, 'Plugins'), agentPluginsForm(a.host, d.plugins, a.plugins || []));
      kids.push(det);
    }
  }
  if (!(d.plugins || []).length) kids.push(sfNode('p', { class: 'muted small' }, 'This server offers no signed plugins: the release key\'s holder signs them (agent/plugins.sh sign).'));
  box.replaceChildren(...kids);
  box.hidden = false;
}
