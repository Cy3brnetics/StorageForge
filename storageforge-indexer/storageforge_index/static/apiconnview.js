'use strict';
/* Keys → Platform connections (apiconn.py): StorageForge reading a Proxmox VE, Backup Server or Datacenter Manager through its own API.
   The order is the guide first (the least the token needs, and the commands that make it), then the token, then the certificate: the
   token is sent nowhere until a person has accepted the certificate the platform presents. The token's secret is typed once and goes to
   the vault; no answer brings it back, so this page never holds it after the form is sent. */

const vapiMsg = (msg, ok) => { const m = $('#platformmsg'); m.hidden = false; m.className = ok ? 'st-ok' : 'st-failed'; m.replaceChildren(msg); };
const vapiDo = async (fn) => { try { await fn(); } catch (err) { vapiMsg(err.message, false); } };
const VAPI_STATE = { 'certificate-unaccepted': 'certificate not accepted yet: nothing has been sent', 'certificate-changed': 'the certificate changed: nothing is sent until you accept it',
  'not-read': 'not read yet', ok: 'read', failed: 'the last read failed' };

function vapiGuide(g) {
  const steps = sfNode('ol', { class: 'stack' }, g.steps.map((s) => sfNode('li', {}, sfNode('p', {}, s.say), sfNode('p', { class: 'muted' }, `Where: ${s.where}`),
    s.run.length ? sfNode('pre', {}, sfNode('code', {}, s.run.join('\n'))) : null)));
  return sfNode('div', { class: 'stack', id: 'platformguide' },
    sfNode('p', {}, sfNode('b', {}, 'The least it needs: '), g.least, '.'),
    sfNode('p', { class: 'muted' }, g.why_role, ' ', g.scope),
    g.reach ? sfNode('p', { class: 'st-warn' }, g.reach) : null,
    steps,
    g.actions.length ? sfNode('p', { class: 'muted' }, 'Read-only by default. Actions, each asked for only when you turn it on: ',
      g.actions.map((a) => `${a.action} (${a.privs.join(', ')} on ${a.on})`).join('; '), '.') : sfNode('p', { class: 'muted' }, g.no_actions || 'Read-only.'),
    sfNode('p', { class: 'muted' }, 'Never: ', g.never.join('; '), '.'),
    sfNode('p', { class: 'muted' }, `Written from the platform's documentation as published on ${g.fetched}. This platform is ${g.label}.`));
}

async function vapiAccept(c, offered) {
  const cert = offered || (await getJSON(`/api/keys/platforms/${c.conn_id}/certificate`)).certificate;
  const file = { pve: '/etc/pve/local/pve-ssl.pem', pbs: '/etc/proxmox-backup/proxy.pem', pdm: '/etc/proxmox-datacenter-manager/auth/api.pem' }[c.kind];
  const ok = await confirmDialog({ title: `Accept the certificate of ${c.name}?`, confirm: 'Accept it',
    body: `${c.base_url} presents the certificate below. Compare its fingerprint with the platform's own before you accept it: on the platform, run\n\nopenssl x509 -noout -fingerprint -sha256 -in ${file}\n\nThe token is sent only to a server that presents this certificate.`,
    items: [`SHA-256 ${cert.sha256}`, ...(cert.subject ? [`subject ${cert.subject}`, `issuer ${cert.issuer}${cert.self_signed ? ' (self-signed)' : ''}`] : []),
      ...(c.cert_sha256 ? [`accepted before: ${c.cert_sha256}`] : [])] });
  if (!ok) return false;                     // cancelled: nothing is sent and nothing on the page changes
  await postJSON(`/api/keys/platforms/${c.conn_id}/certificate`, { sha256: cert.sha256 });
  return true;
}

function vapiReadback(rb) {
  if (!rb) return null;
  const parts = [sfNode('span', { class: rb.verdict === 'exact' ? 'st-ok' : rb.verdict === 'over' ? 'st-failed' : 'st-warn' },
    { exact: 'The token can do exactly what the guide asks.', short: 'The token lacks something a feature needs.', over: 'The token can do more than StorageForge needs.' }[rb.verdict])];
  for (const s of rb.short || []) parts.push(sfNode('span', { class: 'm' }, ` ${s.what}: add ${s.add}.`));
  if ((rb.over || []).length) parts.push(sfNode('span', { class: 'm' }, ` More than needed: ${rb.over.map((o) => `${o.priv} on ${o.path}`).join(', ')}.`));
  for (const n of rb.notes || []) parts.push(sfNode('span', { class: 'm' }, ` ${n}.`));
  return sfNode('div', { class: 'readback' }, parts);
}

function vapiRow(c, manage) {
  const li = document.createElement('li');
  li.dataset.platform = c.name;
  li.append(text('span', c.name), text('span', ` ${c.title} at ${c.base_url}${c.host ? ` (host ${c.host})` : ''} · token ${c.token_id} · ${VAPI_STATE[c.state] || c.state}`, 'm'),
    ...(c.read_at ? [text('span', ' · read ', 'm'), timeEl(c.read_at)] : []),
    ...(c.read_error ? [text('span', ` · ${c.read_error}`, 'm')] : []),
    ...(c.actions.length ? [text('span', ` · actions on: ${c.actions.join(', ')}`, 'm')] : [text('span', ' · read-only', 'm')]));
  const rb = vapiReadback(c.readback);
  if (rb) li.append(rb);
  if (!manage) return li;
  if (c.state === 'certificate-unaccepted' || c.state === 'certificate-changed') li.append(button('Accept the certificate', () => vapiDo(async () => {
    if (await vapiAccept(c)) { vapiMsg(`The certificate of ${c.name} is accepted.`, true); loadPlatforms(); }
  }), 'btn ghost sm'));
  else li.append(button('Test', () => vapiDo(async () => {
    const got = await (await postJSON(`/api/keys/platforms/${c.conn_id}/read`, {})).json();
    const n = Object.values(got.counts).reduce((a, b) => a + b, 0);
    vapiMsg(`Read ${n} object${n === 1 ? '' : 's'} from ${c.name}.${got.skipped.length ? ` Not read: ${got.skipped.join('; ')}` : ''}`, got.readback.verdict === 'exact');
    loadPlatforms();
  }), 'btn ghost sm'));
  li.append(button('Remove', () => vapiDo(async () => {
    if (!(await confirmDialog({ title: `Remove ${c.name}?`, confirm: 'Remove', danger: true, typed: c.name,
      body: `Its token is deleted from the vault and what it read is forgotten. The token ${c.token_id} still works on the platform until you delete it there.` }))) return;
    const got = await (await api(`/api/keys/platforms/${c.conn_id}`, { method: 'DELETE' })).json();
    vapiMsg(`Removed ${c.name}. ${got.note}`, true);
    loadPlatforms();
  }), 'btn ghost sm danger'));
  return li;
}

function vapiForm(kinds) {
  const field = (label, input, hint) => sfNode('label', { class: 'sf-field' }, sfNode('span', {}, label), input, hint ? sfNode('small', {}, hint) : null);
  const kind = sfNode('select', { id: 'platkind' }, kinds.map((k) => sfNode('option', { value: k.kind }, k.title)));
  const scope = sfNode('input', { id: 'platscope', autocomplete: 'off', placeholder: '/' });
  const scopeHint = { pve: 'Paths: / for all, or /vms /storage /nodes to keep the rest hidden.', pbs: 'The datastores it should see, separated by spaces.', pdm: 'The remotes it should see, separated by spaces.' };
  const hint = sfNode('small', {});
  const setHint = () => { hint.textContent = scopeHint[kind.value]; scope.placeholder = { pve: '/', pbs: 'store1', pdm: 'pve-a pbs-b' }[kind.value]; };
  kind.addEventListener('change', setHint);
  setHint();
  const guideBox = sfNode('div', { class: 'stack', id: 'platguidebox' });
  const name = sfNode('input', { id: 'platname', required: true, maxlength: 40, pattern: '[a-z0-9][a-z0-9-]{0,39}', autocomplete: 'off', placeholder: 'pve-lab' });
  const url = sfNode('input', { id: 'platurl', required: true, autocomplete: 'off', placeholder: 'https://pve.example:8006' });
  const tokenId = sfNode('input', { id: 'plattokenid', required: true, autocomplete: 'off', spellcheck: false, placeholder: 'storageforge@pve!storageforge' });
  const secret = sfNode('input', { id: 'plattoken', required: true, type: 'password', autocomplete: 'off', spellcheck: false });
  const host = sfNode('input', { id: 'plathost', autocomplete: 'off', placeholder: 'found by its address when empty' });
  const tokenForm = sfNode('form', { class: 'stack', id: 'plattokenform', hidden: true },
    field('Name of this connection', name), field('Address', url, 'https only: plain HTTP is refused.'), field('Token ID', tokenId, 'user@realm!tokenname, as the platform shows it.'),
    field('Token secret', secret, 'Shown by the platform once. It goes into the vault and is never shown again.'), field('Scanned host it runs on', host),
    sfNode('div', { class: 'row end' }, sfNode('button', { class: 'btn pri', type: 'submit' }, 'Add, then check the certificate')));
  const show = sfNode('button', { class: 'btn', type: 'button' }, 'Show what the token needs');
  show.addEventListener('click', () => vapiDo(async () => {
    const q = scope.value.trim() ? `?scope=${encodeURIComponent(scope.value.trim())}` : '';
    const g = await getJSON(`/api/keys/platforms/guide/${kind.value}${q}`);
    guideBox.replaceChildren(vapiGuide(g));
    tokenId.placeholder = `storageforge@${kind.value}!storageforge`;
    tokenForm.hidden = false;
  }));
  tokenForm.addEventListener('submit', (ev) => { ev.preventDefault(); vapiDo(async () => {
    const body = { kind: kind.value, name: name.value.trim(), url: url.value.trim(), token_id: tokenId.value.trim(), token: secret.value, host: host.value.trim() || null };
    secret.value = '';
    const got = await (await postJSON('/api/keys/platforms', body)).json();
    body.token = null;
    const c = got.connection;
    vapiMsg(`${c.name} is added and its token is in the vault. Nothing has been sent to it yet.`, true);
    tokenForm.reset(); tokenForm.hidden = true; guideBox.replaceChildren();
    if (got.certificate && await vapiAccept(c, got.certificate)) {
      const read = await (await postJSON(`/api/keys/platforms/${c.conn_id}/read`, {})).json();
      vapiMsg(`${c.name}: certificate accepted and read. ${vapiReadback(read.readback).textContent}`, read.readback.verdict === 'exact');
    } else if (!got.certificate) vapiMsg(`${c.name} is added, but its certificate could not be fetched: ${got.certificate_error}`, false);
    loadPlatforms(false);
  }); });
  return sfNode('details', { id: 'platadd' }, sfNode('summary', {}, 'Add a platform connection'),
    sfNode('div', { class: 'stack' }, field('Platform', kind), sfNode('label', { class: 'sf-field' }, sfNode('span', {}, 'What it should see'), scope, hint),
      sfNode('div', { class: 'row end' }, show), guideBox, tokenForm));
}

async function loadPlatforms(withForm = true) {
  const box = $('#platformbox');
  if (!box) return;
  try {
    const d = await getJSON('/api/keys/platforms');
    const manage = can('keys.manage');
    const list = document.createElement('ol'); list.className = 'list'; list.id = 'platformlist';
    list.replaceChildren(...d.connections.map((c) => vapiRow(c, manage)));
    if (!d.connections.length) list.replaceChildren(text('li', 'No platform connections yet.', 'muted'));
    const form = !manage ? '' : (!withForm && $('#platadd')) || vapiForm(d.kinds);
    box.replaceChildren(list, form);
  } catch (err) { box.replaceChildren(text('p', err.message, 'muted')); }
}
