'use strict';
/* StorageForge's own encrypted network (roadmap section 2.1, sfnetwork.py), a view of the Infrastructure tab: make the network, its
   members with what the readings confirm, add and remove a member, rotate a key, the controller's own end, the findings, and the plan.
   Nothing here reaches a host: what changes one is the plan, which opens in Changes and is run there. Names and keys reach the page as
   text only. Loaded after infraview.js, whose table and button helpers it uses. */

const SFN_STATE = {
  ok: ['st-ok', 'Confirmed'], differs: ['st-warn', 'Differs from the plan'], pending: ['st-warn', 'Waiting for its key'], 'no interface': ['st-warn', 'No interface yet'],
  'not scanned': ['st-warn', 'No reading yet'], 'key refused': ['st-failed', 'Key refused'], revoked: ['muted', 'Removed'],
};
const SFN_STEP = {
  'make the key': 'the next plan makes a second key on the host', 'tell the peers': 'the next plan tells its peers the new key', switch: 'the next plan switches it to the new key',
  'key refused': 'the key the host made is one another member has: take the rotation back',
};
const SFN_LINK_NAME = 'StorageForge controller';

function sfnErr(err) { return (err.body && err.body.error) || err.message; }

/* What wants attention, worst first. Each line carries its sign in the class (✕, !), never colour alone. */
function sfnFindings(d) {
  const out = [];
  const add = (level, host, textOf) => out.push({ level, host, text: textOf });
  for (const m of d.members) {
    if (m.host.includes('(revoked')) continue;
    if (m.key_changed) add('crit', m.host, `${m.host} shows a key that is not the one on record. Nobody planned a rotation: either its interface was made again by hand, or this is another machine. Its peers keep the key on record, so it is not let in.`);
    if (m.state === 'key refused') add('crit', m.host, `${m.host} made a key another member already has. A key pair belongs to one host: remove this member and add it again.`);
    if (m.key_unasked) add('warn', m.host, `${m.host} has a second key waiting that nobody asked for. It is not taken, and the next plan removes it.`);
    if ((m.unknown || []).length) add('warn', m.host, `${m.host} has ${m.unknown.length} peer${m.unknown.length === 1 ? '' : 's'} nobody asked for. The next plan revokes ${m.unknown.length === 1 ? 'it' : 'them'}.`);
    if (m.state === 'revoked' && m.still_up) add('warn', m.host, `${m.host} was removed and its interface is still up. The next plan takes it down.`);
  }
  const c = d.controller || {};
  if (c.link && c.error) add('crit', SFN_LINK_NAME, `The controller's link reports: ${c.error}.`);
  if (c.link && c.configured && !c.running) add('warn', SFN_LINK_NAME, 'The controller\'s link is not running: nothing has been heard from it for a minute. With Docker, start the sfnet service.');
  if (c.pending) add('warn', SFN_LINK_NAME, 'The controller\'s own interface is not what it should be yet. Apply it to the controller below.');
  return out.sort((a, b) => (a.level === 'crit' ? 0 : 1) - (b.level === 'crit' ? 0 : 1));
}

function sfnAct(label, title, fn, cls = 'btn ghost sm') {
  const b = sfNode('button', { type: 'button', class: cls, title }, label);
  // an action that was cancelled answers false: the view is not drawn again, so focus stays on the button it came back to
  sfOnClick(b, async () => { try { if (await fn() === false) return; } catch (err) { notify(sfnErr(err), 'error'); } await loadInfra(); });
  return b;
}

function sfnMemberRow(d, m, may) {
  const [cls, word] = SFN_STATE[m.state] || ['st-warn', m.state];
  const state = sfNode('span', {}, sfNode('span', { class: cls }, word));
  if (m.key_changed) state.append(sfNode('br'), sfNode('span', { class: 'st-failed' }, 'A different key'));
  const peers = [];
  if ((m.confirmed || []).length) peers.push(sfNode('span', { class: 'st-ok' }, `${m.confirmed.length} confirmed by key`));
  if ((m.missing || []).length) peers.push(sfNode('span', { class: 'st-warn' }, `missing: ${m.missing.join(', ')}`));
  if (!peers.length) peers.push(sfNode('span', { class: 'muted' }, m.state === 'revoked' ? '' : 'none yet'));
  const rot = m.rotation ? sfNode('span', { class: 'st-warn' }, `Rotation: ${SFN_STEP[m.rotation.step] || m.rotation.step}`,
    (m.rotation.waiting || []).length ? ` (waiting for ${m.rotation.waiting.join(', ')})` : '') : null;
  const acts = [];
  if (may && m.state !== 'revoked') {
    if (m.rotation) {
      acts.push(sfnAct('Take the rotation back', `Stop the key rotation of ${m.host}, before it has switched`, () => postJSON('/api/sfnet/members/rotate', { host: m.host, cancel: true })));
    } else if (m.public_key && !m.key_changed) {
      acts.push(sfnAct('Rotate key', `Give ${m.host} a new key pair, through the next three plans`, async () => {
        const yes = await confirmDialog({ title: `Rotate the key of ${m.host}`, confirm: 'Rotate',
          body: 'Three plans follow, each after a new reading: the host makes a second key, its peers learn it, and then the host switches and the old key is deleted. Nothing is interrupted until the switch.' });
        if (!yes) return false;
        await postJSON('/api/sfnet/members/rotate', { host: m.host });
      }));
    }
    acts.push(sfnAct('Remove', `Take ${m.host} off the network`, async () => {
      const yes = await confirmDialog({ title: `Remove ${m.host} from the StorageForge network`, confirm: 'Remove', danger: true,
        body: 'The next plan takes its key off every other member and removes its interface and its key. Its address is not given to another host.' });
      if (!yes) return false;
        await postJSON('/api/sfnet/members/remove', { host: m.host });
    }));
  }
  const name = sfNode('span', { 'data-member': m.host }, m.host, m.is_controller && !m.link ? sfNode('span', { class: 'muted' }, ' (the controller runs here)') : null,
    m.hub ? sfNode('span', { class: 'muted' }, ' · hub') : null);
  return [name, m.address, state, m.public_key ? sfNode('code', { title: m.public_key }, `${m.public_key.slice(0, 12)}…`) : sfNode('span', { class: 'muted' }, 'not made yet'),
    sfNode('span', { class: 'stack' }, peers, rot), m.endpoint || sfNode('span', { class: 'muted' }, 'calls the others'), sfNode('span', { class: 'row wrap' }, acts)];
}

function sfnController(d, may) {
  const c = d.controller || {}, box = sfNode('section', { id: 'sfn-controller', class: 'stack', 'aria-labelledby': 'sfn-controller-h' }, sfNode('h3', { id: 'sfn-controller-h' }, 'The controller'));
  const say = (t, cls = 'muted') => box.append(sfNode('p', { class: cls }, t));
  if (c.member && !c.link) {
    say(`The controller runs on ${c.member} and uses that host's interface. Its connections to the other members go over the network where the readings confirm them.`);
    if (may) box.append(sfNode('div', { class: 'row wrap' }, sfnAct('It does not run there', 'The controller is on no member', () => postJSON('/api/sfnet/controller', { on: null }))));
    return box;
  }
  const mine = d.members.find((m) => m.link && m.state !== 'revoked');
  if (mine) {
    say(`The controller is a member at ${mine.address}, through its link, which keeps its private key where the server cannot read it. `
      + 'Its own SSH connections to a member go over the network where both confirm each other by key, and to the normal address otherwise.');
    say(c.running ? 'The link is running.' : 'The link is not running.', c.running ? 'st-ok' : 'st-warn');
  } else if (c.configured) {
    say('The controller is not on the network. As a member, its scans, deploys and consoles reach the other members over it.');
  } else {
    say('The controller is not on the network, and this server was not started with a link for it. With Docker, start the stack with docker-compose.sfnet.yml as well. '
      + 'Where StorageForge runs on a host it also scans, add that host as a member and say here that the controller runs on it.');
  }
  if (!may) return box;
  const row = sfNode('div', { class: 'row wrap' });
  if (c.pending) row.append(sfnAct('Apply to the controller', 'Hand the link what the controller\'s interface should be: its address, port and peers', () => postJSON('/api/sfnet/controller/apply', {}), 'btn sm'));
  if (!mine && c.configured) {
    row.append(sfnAct('Add the controller', 'The controller as a member, through its link', async () => {
      const f = await formDialog({ title: 'Add the controller to the network', confirm: 'Add',
        body: 'Leave the address empty and the controller calls the hosts, which needs no open port here.\n\nGive an address only where hosts must call the controller, and publish UDP port 51903 there.',
        fields: [{ name: 'endpoint', label: 'Where hosts call it (optional)', placeholder: 'an address or a name, without a port', maxlength: 255 }] });
      if (f) await postJSON('/api/sfnet/controller', f.endpoint ? { endpoint: f.endpoint } : {});
    }, 'btn sm'));
  }
  const hosts = d.members.filter((m) => !m.link && m.state !== 'revoked');
  if (!mine && hosts.length) {
    const pick = sfNode('select', { id: 'sfn-on', 'aria-label': 'The member the controller runs on' }, hosts.map((m) => sfNode('option', { value: m.host }, m.host)));
    row.append(pick, sfnAct('The controller runs on this member', 'StorageForge runs on that host, with no container, and uses its interface', () => postJSON('/api/sfnet/controller', { on: pick.value })));
  }
  if (row.childNodes.length) box.append(row);
  return box;
}

function sfnAdd(d, hosts) {
  const members = new Set(d.members.filter((m) => m.state !== 'revoked').map((m) => m.host));
  const free = hosts.filter((h) => !members.has(h));
  const box = sfNode('section', { id: 'sfn-add', class: 'stack', 'aria-labelledby': 'sfn-add-h' }, sfNode('h3', { id: 'sfn-add-h' }, 'Add a member'));
  if (!free.length) { box.append(sfNode('p', { class: 'muted' }, 'Every scanned host is a member.')); return box; }
  const host = sfNode('select', { id: 'sfn-host' }, free.map((h) => sfNode('option', { value: h }, h)));
  const where = sfNode('input', { id: 'sfn-endpoint', type: 'text', placeholder: 'the address scans use', maxlength: 255, autocomplete: 'off', spellcheck: false });
  const nat = sfNode('input', { id: 'sfn-nat', type: 'checkbox' });
  const hub = sfNode('input', { id: 'sfn-hub', type: 'checkbox' });
  box.append(sfNode('div', { class: 'row wrap' },
    sfNode('label', { for: 'sfn-host' }, 'Host ', host),
    sfNode('label', { for: 'sfn-endpoint' }, 'Where the others call it ', where),
    sfNode('label', { for: 'sfn-nat' }, nat, ' Nobody can call it: it calls the others'),
    d.network.topology === 'hub' ? sfNode('label', { for: 'sfn-hub' }, hub, ' A hub') : null,
    sfnAct('Add', 'The host gets an address for good. The next plan makes its interface and its key pair on the host', () => postJSON('/api/sfnet/members',
      { host: host.value, ...(where.value.trim() ? { endpoint: where.value.trim() } : {}), reachable: !nat.checked, hub: hub.checked }), 'btn sm')));
  return box;
}

async function sfnPlan(out) {
  try {
    const r = await (await postJSON('/api/sfnet/plan', {})).json();
    if (!r.plan_id) { out.replaceChildren(sfNode('span', { class: 'st-ok' }, 'Every member is as it should be: there is nothing to plan.')); return; }
    out.replaceChildren(sfNode('span', {}, `Saved "${r.name}" with ${r.tasks} step${r.tasks === 1 ? '' : 's'}. Run it from Changes, then take a new reading of each host: the reading is what confirms a key. `),
      typeof loadChanges === 'function' ? button('Open it in Changes', () => { showTab('changes'); loadChanges(r.plan_id); }, 'btn sm') : '');
  } catch (err) { out.replaceChildren(sfNode('span', { class: 'st-failed' }, sfnErr(err))); }
}

async function sfnView(content) {
  const [d, hosts] = await Promise.all([getJSON('/api/sfnet'), getJSON('/api/hosts').then((h) => h.indexed.map((x) => x.hostname).sort()).catch(() => [])]);
  const may = can('security.manage');
  const intro = sfNode('p', { class: 'muted' }, 'A WireGuard network of StorageForge\'s own between the hosts you choose, so that what passes between them and the controller is encrypted even on the LAN. '
    + 'It needs no outside service. Each host makes its own key pair, and the private key never leaves it.');
  if (!d.network) {
    const kids = [intro, sfNode('p', { id: 'sfn-none' }, 'There is no StorageForge network yet.')];
    if (may) {
      const topo = sfNode('select', { id: 'sfn-topology' }, sfNode('option', { value: 'mesh' }, 'Mesh: every member talks to every other'), sfNode('option', { value: 'hub' }, 'Hub: members meet at the hubs'));
      const range = sfNode('input', { id: 'sfn-range', type: 'text', placeholder: 'picked for you', maxlength: 18, autocomplete: 'off', spellcheck: false });
      kids.push(sfNode('div', { class: 'row wrap' }, sfNode('label', { for: 'sfn-topology' }, 'Shape ', topo), sfNode('label', { for: 'sfn-range' }, 'Range ', range),
        sfnAct('Make the network', 'Picks a range no scanned host uses, and never 100.64.0.0/10. No host is touched', () => postJSON('/api/sfnet',
          { topology: topo.value, ...(range.value.trim() ? { range: range.value.trim() } : {}) }), 'btn sm')));
    }
    content.replaceChildren(...kids);
    return;
  }
  const n = d.network, found = sfnFindings(d), live = d.members.filter((m) => !m.host.includes('(revoked'));
  const findings = sfNode('section', { id: 'sfn-findings', class: 'stack', 'aria-labelledby': 'sfn-findings-h' }, sfNode('h3', { id: 'sfn-findings-h' }, 'Findings'),
    found.length ? sfNode('ul', { class: 'list' }, found.map((f) => sfNode('li', { 'data-level': f.level }, sfNode('span', { class: f.level === 'crit' ? 'st-failed' : 'st-warn' }, f.text))))
      : sfNode('p', { class: 'st-ok' }, 'Nothing is wrong that the readings show.'));
  const planOut = sfNode('span', { id: 'sfn-plan-out', role: 'status' });
  const plan = can('plans.edit') ? sfNode('div', { class: 'row wrap' },
    button('Save the plan', () => sfnPlan(planOut), 'btn'), planOut) : null;
  content.replaceChildren(intro,
    sfNode('p', { id: 'sfn-summary' }, `Range ${n.range} · UDP port ${n.port} · ${n.topology === 'hub' ? 'hub and spokes' : 'mesh'} · interface ${d.interface} · `
      + `${live.filter((m) => m.state !== 'revoked').length} member${live.filter((m) => m.state !== 'revoked').length === 1 ? '' : 's'}`),
    findings,
    sfNode('section', { class: 'stack', 'aria-labelledby': 'sfn-members-h' }, sfNode('h3', { id: 'sfn-members-h' }, 'Members'),
      live.length ? infTable(['Member', 'Address', 'State', 'Public key', 'Peers', 'Called at', 'Actions'], live.map((m) => sfnMemberRow(d, m, may)))
        : sfNode('p', { class: 'muted' }, 'No member yet.'),
      sfNode('p', { class: 'muted small' }, 'A state comes from the last reading of each host. A peer is confirmed when the host holds its key with the address it should carry.')),
    plan, may ? sfnAdd(d, hosts) : null, sfnController(d, may));
}
