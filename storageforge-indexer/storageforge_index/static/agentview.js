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

async function loadAgents() {
  const box = document.getElementById('agentbox');
  if (!box) return;
  let d;
  try { d = await getJSON('/api/agents'); } catch (err) { box.replaceChildren(sfNode('p', { class: 'muted' }, err.message)); box.hidden = false; return; }
  const enrolled = (d.agents || []).filter((a) => a.state && a.state !== 'off');
  const kids = [sfNode('h3', {}, 'Agents'),
    sfNode('p', { class: 'muted small' }, 'The agent is an extra, switched on one host at a time: readings as they happen. Built, not lab-tested. See docs/agent.md.')];
  if (!enrolled.length) kids.push(sfNode('p', { class: 'muted' }, 'No host runs the agent.'));
  for (const a of enrolled) {
    kids.push(agentLine(a));
    if (a.state === 'running' && can('keys.manage') && (d.plugins || []).length) {
      const det = sfNode('details', {}, sfNode('summary', {}, 'Plugins'), agentPluginsForm(a.host, d.plugins, a.plugins || []));
      kids.push(det);
    }
  }
  if (!(d.plugins || []).length) kids.push(sfNode('p', { class: 'muted small' }, 'This server offers no signed plugins: the release key\'s holder signs them (agent/plugins.sh sign).'));
  box.replaceChildren(...kids);
  box.hidden = false;
}
