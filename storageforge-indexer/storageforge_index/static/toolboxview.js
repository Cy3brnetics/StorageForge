'use strict';
/* Toolbox (toolbox.py, tbadapters.py, routes_toolbox.py; docs/toolbox.md): the catalog, a card per host with the tools on it, and one tool
   at a time, the way a deep link names it (#/topo/toolbox?host=gw-01&tool=wireguard, or the older #host=gw-01&tab=toolbox&tool=wireguard).
   A tool is shown at its GUI level: a link to its own UI, status tiles, or a panel with actions. Installing, removing and every action
   save a change plan and run nothing: the plan is deployed from Changes, report first. A custom entry is signed on the operator's machine
   with the command shown; this page only sends the signature to be checked. A cancelled dialog changes nothing and redraws nothing. */

const TB = { tool: null, cat: null, inst: null, may: false };
const TB_HEALTH = { ok: '✓ running', down: '✕ down', warn: '! needs a look', missing: '✕ not found', staged: '… staged, not deployed yet', unavailable: '! status unavailable', unknown: '? unknown' };
const TB_TRUST = { 'release-signed': '✓ signed by the release key', packaged: 'packaged with this version, not release-signed yet', 'operator-signed': '✓ signed by an operator key',
  unsigned: '! not signed', refused: '✕ refused' };
const tbMsg = (msg, ok) => { const m = $('#toolboxmsg'); m.hidden = false; m.className = ok ? 'st-ok' : 'st-failed'; m.replaceChildren(msg); announce(String(msg)); };
const tbDo = async (fn) => { try { await fn(); } catch (err) { tbMsg(err.message, false); } };
const tbLevel = (s) => s === 'ok' ? 'st-ok' : s === 'crit' || s === 'down' || s === 'missing' ? 'st-failed' : 'st-warn';

function tbRouteParams() { return TB.tool ? { tool: TB.tool } : {}; }
function tbTakeLink(q) { TB.tool = q.get('tool') || null; }

function tbStaged(got, what) {
  const box = sfNode('span', {}, `${what}: saved as the change plan #${got.plan_id}. Nothing has run: check and deploy it from Changes. `,
    button('Open Changes', () => showTab('changes'), 'btn ghost sm'));
  tbMsg(box, true);
}

function tbTiles(st) {
  if (!st) return sfNode('p', { class: 'muted' }, 'No reading of this tool yet: the next infrastructure reading of the host shows it.');
  return sfNode('div', { class: 'stack' },
    sfNode('p', {}, sfNode('span', { class: tbLevel(st.health) }, TB_HEALTH[st.health] || st.health), ' · read ', timeEl(st.checked_at),
      st.version ? ` · version ${st.version}` : ''),
    sfNode('ul', { class: 'tbtiles' }, (st.tiles || []).map((t) => sfNode('li', { class: tbLevel(t.level) }, sfNode('b', {}, `${t.label}: `), t.value))),
    st.error ? sfNode('p', { class: 'st-warn' }, st.error) : null);
}

function tbLinks(links) {
  return (links || []).map((l) => sfNode('p', { class: 'tblink' },
    sfNode('a', { href: l.url, target: '_blank', rel: 'noopener noreferrer' }, l.label),
    l.tunnel ? sfNode('span', { class: 'muted' }, ' · it listens on the host itself: first run ', sfNode('code', {}, l.tunnel)) : null,
    l.sso ? sfNode('span', { class: 'muted' }, ` · ${l.sso}`) : null));
}

function tbPeers(st) {
  if (!st || !(st.peers || []).length) return null;
  return sfNode('table', { class: 'tbpeers' }, sfNode('caption', {}, 'Peers'),
    sfNode('thead', {}, sfNode('tr', {}, ['Interface', 'Public key', 'Addresses', 'Endpoint', 'Last handshake'].map((h) => sfNode('th', { scope: 'col' }, h)))),
    sfNode('tbody', {}, st.peers.map((p) => sfNode('tr', {}, sfNode('td', {}, p.iface), sfNode('td', {}, sfNode('code', {}, p.public_key)),
      sfNode('td', {}, (p.allowed_ips || []).join(', ') || 'none'), sfNode('td', {}, p.endpoint || 'it calls in'),
      sfNode('td', {}, p.handshake ? timeEl(p.handshake) : 'never')))));
}

async function tbAction(host, tool, a) {
  const fields = a.fields.map((f) => ({ name: f.name, label: f.label, required: !!f.required, placeholder: f.options ? f.options.join(', ') : '',
    value: f.options && f.options.length === 1 ? f.options[0] : '', validate: (v) => (f.required && !v ? `${f.label} is required`
      : f.options && v && !f.options.includes(v) ? `${f.label} is one of ${f.options.join(', ')}` : '') }));
  let values = {};
  if (fields.length) {
    values = await formDialog({ title: `${a.label} on ${host}`, body: 'This saves a change plan with the step it takes. Nothing changes on the host until the plan is deployed.', fields, confirm: 'Save the plan' });
    if (!values) return;                               // cancelled: nothing is sent and the page stays as it is
  } else if (!(await confirmDialog({ title: `${a.label} on ${host}?`, body: 'This saves a change plan. Nothing changes on the host until the plan is deployed.', confirm: 'Save the plan' }))) return;
  const got = await (await postJSON(`/api/toolbox/${encodeURIComponent(host)}/${encodeURIComponent(tool)}/actions/${encodeURIComponent(a.id)}`, { values })).json();
  tbStaged(got, a.label);
}

function tbHostCard(host, tools) {
  const card = sfNode('li', { class: 'card tbhost', 'data-host': host }, sfNode('h4', {}, host));
  if (!tools.length) card.append(sfNode('p', { class: 'muted' }, 'No tool from the catalog was found or staged here.'));
  for (const t of tools) {
    const entry = (TB.cat.entries || []).find((e) => e.id === t.tool) || { name: t.tool };
    const inst = (TB.inst.installs || []).find((i) => i.host === host && i.tool === t.tool);
    const st = (TB.inst.status || []).find((s) => s.host === host && s.tool === t.tool);
    const health = st ? st.health : inst ? (inst.status === 'staged' ? 'staged' : 'unknown') : 'unknown';
    card.append(sfNode('div', { class: 'tbrow', 'data-tool': t.tool },
      sfNode('b', {}, entry.name), ' ', sfNode('span', { class: tbLevel(health) }, TB_HEALTH[health] || health),
      inst ? sfNode('span', { class: 'muted' }, ` · ${inst.method}, ${inst.status}`) : sfNode('span', { class: 'muted' }, ' · found, not installed by StorageForge'),
      ' ', button('Open', () => tbOpen(t.tool, host), 'btn ghost sm')));
  }
  return card;
}

function tbOpen(tool, host) {
  TB.tool = tool;
  if (host && host !== S.host && [...$('#host').options].some((o) => o.value === host)) { const pick = $('#host'); pick.value = host; pick.dispatchEvent(new Event('change')); }
  routeSync();
  loadToolbox();
}

function tbField(label, input, hint) { return sfNode('label', { class: 'sf-field' }, sfNode('span', {}, label), input, hint ? sfNode('small', {}, hint) : null); }

function tbInstallForm(e, host) {
  const method = sfNode('select', { id: 'tbmethod' }, sfNode('option', { value: '' }, 'the safest this host can take'),
    e.methods.map((m) => sfNode('option', { value: m }, (e.method_labels || {})[m] || m)));
  const exposure = sfNode('select', { id: 'tbexposure' }, sfNode('option', { value: '' }, `as the entry says (${e.exposure.default})`),
    ['loopback', 'management', 'any'].map((x) => sfNode('option', { value: x }, x)));
  const bind = sfNode('input', { id: 'tbbind', autocomplete: 'off', spellcheck: false, placeholder: '10.0.10.5' });
  const allow = sfNode('input', { id: 'tballow', autocomplete: 'off', spellcheck: false, placeholder: '192.168.1.0/24' });
  const inputs = (e.inputs || []).map((i) => [i, sfNode('input', { id: `tbin-${i.name}`, value: i.default || '', autocomplete: 'off', spellcheck: false })]);
  const report = sfNode('div', { id: 'tbreport', class: 'stack', 'aria-live': 'polite' });
  const body = () => ({ host, tool: e.id, method: method.value || null, exposure: exposure.value || null, bind: bind.value.trim() || null, allow_from: allow.value.trim() || null,
    inputs: Object.fromEntries(inputs.map(([i, el]) => [i.name, el.value.trim()])) });
  const preview = button('Show the plan and its report', () => tbDo(async () => {
    const pv = await (await postJSON('/api/toolbox/preview', body())).json();
    report.replaceChildren(sfNode('p', {}, sfNode('b', {}, 'Method: '), pv.why),
      sfNode('ul', {}, pv.report.map((x) => sfNode('li', { class: tbLevel(x.level === 'note' ? 'warn' : x.level) }, x.text))),
      sfNode('p', { class: 'muted' }, `Steps: ${pv.tasks.map((t) => t.type).join(', ')}. Data it keeps: ${(pv.made.data || []).join(', ') || 'none'}.`));
  }), 'btn');
  const stage = button('Save as a change plan', () => tbDo(async () => {
    let accept = false;
    if (e.trust === 'unsigned') {
      accept = await confirmDialog({ title: `Accept the unsigned entry ${e.name} for ${host}?`, danger: true, confirm: 'Accept it for this host',
        body: 'Nobody signed this entry. Accepting it vouches for every command it leads to on this host, as root. Sign it with an operator key instead where you can.' });
      if (!accept) return;                             // cancelled: nothing is sent
    }
    const got = await (await postJSON('/api/toolbox/stage', { ...body(), accept_unsigned: accept })).json();
    tbStaged(got, `${e.name} on ${host}`);
    loadToolbox();
  }), 'btn pri');
  return sfNode('form', { class: 'stack', id: 'tbinstall', onsubmit: (ev) => ev.preventDefault() },
    sfNode('h4', {}, `Install on ${host}`),
    tbField('Method', method, 'Rootless container first, then the distribution package, then a binary checked by its SHA-256; a container of root or a compose stack last.'),
    tbField('Exposure', exposure, 'Loopback: only the host itself, reached through SSH or a reverse proxy. Management: one address of the host. Any: every network it is on.'),
    tbField('Address to bind to (management)', bind), tbField('Only these may reach it', allow, 'Addresses or ranges, comma separated: a firewall fence beside the install.'),
    inputs.map(([i, el]) => tbField(i.label, el)),
    sfNode('div', { class: 'row end' }, preview, stage), report);
}

async function tbToolView(id) {
  const box = sfNode('section', { id: 'tbtool', class: 'card stack', 'aria-labelledby': 'tbtooltitle' });
  let e;
  try { e = await getJSON(`/api/toolbox/catalog/${encodeURIComponent(id)}`); } catch (err) { box.append(sfNode('p', { class: 'st-failed' }, err.message)); return box; }
  box.append(sfNode('div', { class: 'row' }, sfNode('h3', { id: 'tbtooltitle' }, e.name), button('Back to the catalog', () => { TB.tool = null; routeSync(); loadToolbox(); }, 'btn ghost sm')),
    sfNode('p', {}, e.summary),
    sfNode('p', { class: 'muted' }, `${e.category} · entry revision ${e.revision}${e.app_version ? ` · ${e.app_version}` : ''} · `, sfNode('span', { class: tbLevel(e.trust === 'refused' ? 'crit' : e.trust === 'unsigned' ? 'warn' : 'ok') }, TB_TRUST[e.trust] || e.trust),
      ` · ${e.lab} · shown as ${e.gui_level}`),
    sfNode('p', { class: 'muted' }, e.trust_why),
    e.risks.length ? sfNode('ul', { class: 'tbrisks', 'aria-label': 'Risk labels' }, e.risks.map((r) => sfNode('li', { class: 'st-warn' }, sfNode('b', {}, `! ${r.title}: `), `${r.means}. ${r.mitigation}.`))) : null,
    e.notes ? sfNode('p', {}, e.notes) : null);
  const host = S.host;
  if (!host) { box.append(sfNode('p', { class: 'muted' }, 'Choose a host at the top to see this tool there, or to install it.')); return box; }
  try {
    const st = await getJSON(`/api/toolbox/installed/${encodeURIComponent(host)}/${encodeURIComponent(id)}/status`);
    box.append(sfNode('h4', {}, `On ${host}`), tbTiles(st.status), ...tbLinks(st.links));
    const peers = tbPeers(st.status);
    if (peers) box.append(peers);
    if (st.actions.length) box.append(sfNode('div', { class: 'row wrap', 'aria-label': 'Actions' }, st.actions.map((a) => button(a.label, () => tbDo(() => tbAction(host, id, a)), 'btn ghost sm'))));
    if (st.install && st.install.managed_by === 'storageforge' && !['removed', 'remove-staged'].includes(st.install.status)) {
      box.append(button(`Remove from ${host}, keeping its data`, () => tbDo(async () => {
        const data = (st.install.params.data || []);
        if (!(await confirmDialog({ title: `Remove ${e.name} from ${host}?`, confirm: 'Save the plan', body: 'This saves a change plan that stops it and takes away what its install made. Its data stays where it is.',
          items: data.length ? data.map((d) => `kept: ${d}`) : ['it kept no data folders'] }))) return;
        const got = await (await postJSON('/api/toolbox/stage', { host, tool: id, action: 'remove' })).json();
        tbStaged(got, `Removing ${e.name} from ${host}`);
        loadToolbox();
      }), 'btn ghost sm danger'));
    }
  } catch (err) { box.append(sfNode('p', { class: 'st-failed' }, err.message)); }
  if (e.trust !== 'refused') box.append(tbInstallForm(e, host));
  return box;
}

function tbCatalogList() {
  const cats = {};
  for (const e of TB.cat.entries) (cats[e.category || 'unreadable'] ||= []).push(e);
  return sfNode('section', { id: 'tbcatalog', 'aria-labelledby': 'tbcattitle' }, sfNode('h3', { id: 'tbcattitle' }, 'Catalog'),
    sfNode('p', { class: 'muted' }, `The official catalog: ${TB.cat.official.why}.`),
    Object.entries(cats).map(([c, es]) => sfNode('div', {}, sfNode('h4', {}, c),
      sfNode('ul', { class: 'list' }, es.map((e) => sfNode('li', { 'data-tool': e.id },
        sfNode('b', {}, e.name), sfNode('span', { class: 'm' }, ` · ${e.summary}`),
        sfNode('span', { class: `m ${tbLevel(e.trust === 'refused' ? 'crit' : e.trust === 'unsigned' ? 'warn' : 'ok')}` }, ` · ${TB_TRUST[e.trust] || e.trust}`),
        sfNode('span', { class: 'm' }, ` · ${e.lab} · ${e.gui_level}${e.risks.length ? ` · ${e.risks.map((r) => r.title).join(', ')}` : ''}`),
        ' ', button('Open', () => tbOpen(e.id), 'btn ghost sm')))))));
}

function tbEditor() {
  const area = sfNode('textarea', { id: 'tbyaml', rows: 16, spellcheck: false, 'aria-describedby': 'tbedhint',
    placeholder: 'format: 1\nid: my-tool\nrevision: 1\nname: My tool\ncategory: monitoring\nsummary: What it does.\ninstall:\n  methods:\n    - kind: container\n      image: docker.io/me/tool:1.0@sha256:…' });
  const sig = sfNode('textarea', { id: 'tbsig', rows: 6, spellcheck: false, placeholder: '-----BEGIN SSH SIGNATURE-----' });
  const host = sfNode('input', { id: 'tbdryhost', autocomplete: 'off', spellcheck: false, value: S.host || '', placeholder: 'host for the dry run' });
  const out = sfNode('div', { id: 'tbedout', class: 'stack', 'aria-live': 'polite' });
  const validate = button('Check it', () => tbDo(async () => {
    const v = await (await postJSON('/api/toolbox/catalog/validate', { yaml: area.value, signature: sig.value })).json();
    out.replaceChildren(v.ok ? sfNode('p', { class: 'st-ok' }, '✓ The entry passes the schema.') : sfNode('ul', {}, v.problems.map((p) => sfNode('li', { class: 'st-failed' }, `✕ ${p}`))),
      (v.risks || []).length ? sfNode('p', { class: 'st-warn' }, `Risk labels: ${v.risks.map((r) => r.title).join(', ')}.`) : null,
      v.sign ? sfNode('p', {}, 'Sign it on your own machine, where your key is: save the text exactly as checked (the button below), then run ', sfNode('code', {}, v.sign)) : null,
      v.ok ? button('Save the text as a file', () => { const a = sfNode('a', { href: URL.createObjectURL(new Blob([v.text], { type: 'text/yaml' })), download: `${(/^id:\s*(\S+)/m.exec(v.text) || [])[1] || 'entry'}.yaml` }); a.click(); URL.revokeObjectURL(a.href); }, 'btn ghost sm') : null,
      sfNode('p', { class: tbLevel(v.signature.state === 'operator-signed' ? 'ok' : v.signature.state === 'refused' ? 'crit' : 'warn') }, `Signature: ${v.signature.why}.`),
      sfNode('p', { class: 'muted' }, `SHA-256 of the text: ${v.sha256}`));
  }), 'btn');
  const dry = button('Dry run on the host', () => tbDo(async () => {
    const pv = await (await postJSON('/api/toolbox/preview', { yaml: area.value, host: host.value.trim() })).json();
    out.replaceChildren(sfNode('p', {}, sfNode('b', {}, 'Method: '), pv.why), sfNode('ul', {}, pv.report.map((x) => sfNode('li', { class: tbLevel(x.level === 'note' ? 'warn' : x.level) }, x.text))),
      sfNode('p', { class: 'muted' }, `Steps it would save: ${pv.tasks.map((t) => t.type).join(', ')}. Nothing was saved.`));
  }), 'btn');
  const save = button('Save the entry', () => tbDo(async () => {
    const got = await (await postJSON('/api/toolbox/catalog/custom', { yaml: area.value, signature: sig.value })).json();
    tbMsg(`${got.id} is saved: ${got.why}.`, got.state === 'operator-signed');
    loadToolbox();
  }), 'btn pri');
  return sfNode('details', { id: 'tbcustom' }, sfNode('summary', {}, 'Custom entries'),
    sfNode('p', { class: 'muted', id: 'tbedhint' }, 'An entry of your own, in the same YAML as the catalog. It is root on the host by another name, so saving or signing one takes the permission to run commands as root. The controller never holds your private key: you sign on your machine and paste the signature here.'),
    tbField('Entry', area), tbField('Signature (optional)', sig, 'What ssh-keygen -Y sign wrote into the .sig file.'), tbField('Host for the dry run', host),
    sfNode('div', { class: 'row end' }, validate, dry, TB.may ? save : null), out,
    (TB.cat.entries.filter((e) => e.source === 'custom')).length ? sfNode('ul', { class: 'list' }, TB.cat.entries.filter((e) => e.source === 'custom').map((e) => sfNode('li', {},
      sfNode('b', {}, e.id), sfNode('span', { class: 'm' }, ` · ${TB_TRUST[e.trust] || e.trust}`),
      TB.may ? button('Remove', () => tbDo(async () => {
        if (!(await confirmDialog({ title: `Remove the custom entry ${e.id}?`, danger: true, confirm: 'Remove', body: 'Tools installed from it stay on their hosts; plans that name it are refused until it is back.' }))) return;
        await api(`/api/toolbox/catalog/custom/${encodeURIComponent(e.id)}`, { method: 'DELETE' });
        tbMsg(`Removed ${e.id}.`, true);
        loadToolbox();
      }), 'btn ghost sm danger') : null))) : null);
}

async function tbSigners() {
  const box = sfNode('details', { id: 'tbsigners' }, sfNode('summary', {}, 'Operator keys'));
  if (!TB.may) return null;
  const got = await getJSON('/api/toolbox/signers');
  box.append(sfNode('p', { class: 'muted' }, `Public keys whose signature makes a custom entry signed, in the namespace ${got.namespace}. Only the public half is kept here.`),
    got.signers.length ? sfNode('ul', { class: 'list' }, got.signers.map((s) => sfNode('li', {}, sfNode('b', {}, s.name), sfNode('span', { class: 'm' }, ` · ${s.fingerprint} · added by ${s.added_by} `), timeEl(s.added_at),
      button('Remove', () => tbDo(async () => {
        if (!(await confirmDialog({ title: `Remove the key ${s.name}?`, danger: true, confirm: 'Remove', body: 'Entries it signed are refused until someone signs them again.' }))) return;
        await api(`/api/toolbox/signers/${encodeURIComponent(s.name)}`, { method: 'DELETE' });
        loadToolbox();
      }), 'btn ghost sm danger')))) : sfNode('p', { class: 'muted' }, 'No operator key yet.'),
    button('Add a key', () => tbDo(async () => {
      const v = await formDialog({ title: 'Add an operator key', body: 'The public key only: the line in your id_ed25519.pub. The private key stays on your machine.', confirm: 'Add it',
        fields: [{ name: 'name', label: 'Name', required: true, placeholder: 'alice' }, { name: 'public_key', label: 'Public key', required: true, placeholder: 'ssh-ed25519 AAAA…' }] });
      if (!v) return;                                  // cancelled
      await postJSON('/api/toolbox/signers', v);
      tbMsg(`Added the key ${v.name}.`, true);
      loadToolbox();
    }), 'btn ghost sm'));
  return box;
}

async function loadToolbox() {
  const fresh = latest('toolbox');
  const box = $('#toolboxbox');
  try {
    const [cat, inst] = await Promise.all([getJSON('/api/toolbox/catalog'), getJSON('/api/toolbox/installed')]);
    if (!fresh()) return;
    TB.cat = cat; TB.inst = inst; TB.may = cat.may_write;
    const hosts = {};
    for (const i of inst.installs) (hosts[i.host] ||= new Map()).set(i.tool, { tool: i.tool });
    for (const s of inst.status) (hosts[s.host] ||= new Map()).set(s.tool, { tool: s.tool });
    const shown = S.host ? [S.host] : Object.keys(hosts).sort();
    const parts = [];
    if (TB.tool) parts.push(await tbToolView(TB.tool));
    if (!fresh()) return;
    parts.push(sfNode('section', { id: 'tbhosts', 'aria-labelledby': 'tbhoststitle' }, sfNode('h3', { id: 'tbhoststitle' }, 'Hosts'),
      shown.length ? sfNode('ul', { class: 'tbcards' }, shown.map((h) => tbHostCard(h, [...(hosts[h] || new Map()).values()])))
        : sfNode('p', { class: 'muted' }, 'No tool from the catalog is installed or found on any host yet. Open one below to install it.')));
    parts.push(tbCatalogList(), tbEditor());
    const signers = await tbSigners();
    if (!fresh()) return;
    if (signers) parts.push(signers);
    const open = [...box.querySelectorAll('details[open]')].map((d) => d.id);
    box.replaceChildren(...parts);
    for (const id of open) { const d = box.querySelector(`#${id}`); if (d) d.open = true; }
  } catch (err) { if (fresh()) tbMsg(err.message, false); }
}

$('#host').addEventListener('change', () => { if (curTab() === 'toolbox' || (curTab() === 'infra' && typeof INF !== 'undefined' && INF.view === 'toolbox')) loadToolbox(); });      // the cards and the open tool follow the host picker
