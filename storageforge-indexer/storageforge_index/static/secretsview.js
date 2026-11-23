'use strict';
/* Keys → Secrets for plan steps (secretstore.py): make a secret, see it once, list them by name, rotate and remove. The server never sends
   a value again after the answer that made or rotated it, so this page keeps none: the box that shows it is emptied when it is hidden or
   the list is loaded again. */

const vsecMsg = (msg, ok) => { const m = $('#secretmsg'); m.hidden = false; m.className = ok ? 'st-ok' : 'st-failed'; m.replaceChildren(msg); };
const vsecDo = async (fn) => { try { await fn(); } catch (err) { vsecMsg(err.message, false); } };

function vsecShowOnce(name, value, what) {
  const box = $('#secretonce');
  const code = text('code', value, 'pub');
  const hide = () => { box.replaceChildren(); box.hidden = true; };
  box.hidden = false;
  box.replaceChildren(
    text('p', `${what} ${name}. It is shown this once: copy it now. StorageForge will not show it again, here or anywhere.`),
    code,
    button('Copy', async (ev) => {
      try { await navigator.clipboard.writeText(value); ev.target.textContent = 'Copied'; }
      catch { getSelection().selectAllChildren(code); }
    }, 'btn ghost sm'),
    button('Hide it', hide, 'btn ghost sm'));
}

function vsecRow(s, manage, apply) {
  const li = document.createElement('li');
  const made = s.origin === 'generated' ? `${s.kind}, ${s.length} characters` : 'given by a person';
  const policy = s.policy ? [s.policy.steps.length ? `steps ${s.policy.steps.join(', ')}` : '', s.policy.hosts.length ? `hosts ${s.policy.hosts.join(', ')}` : '',
    s.policy.platforms.length ? `platforms ${s.policy.platforms.join(', ')}` : '', s.policy.sensitive ? 'step-up to release' : ''].filter(Boolean).join(' · ') : 'any named step or host';
  const went = s.delivered.length ? s.delivered.map((d) => d.host).join(', ') : 'not delivered yet';
  li.append(text('span', s.name), text('span', `${made} · made `, 'm'), timeEl(s.created_at),
    ...(s.value_rotated_at ? [text('span', ' · rotated ', 'm'), timeEl(s.value_rotated_at)] : []),
    text('span', ` · for ${policy} · on ${went}`, 'm'));
  if (manage && apply && s.origin === 'generated') li.append(button('Rotate', () => vsecDo(async () => {
    const plan = await getJSON(`/api/keys/secrets/${encodeURIComponent(s.name)}/rotate`);
    if (plan.blocked.length) { vsecMsg(`Not rotated: ${plan.blocked.join('; ')}`, false); return; }
    if (!(await confirmDialog({ title: `Rotate ${s.name}?`, confirm: 'Rotate',
      body: `A new value (${plan.note}) goes to each host below into a file beside the old one. Only when every host has it does the vault switch and each host move it over the old one; if one does not take it, nothing changes anywhere.\n\nA service that read the old value keeps using it until it reads the file again.`,
      items: plan.hosts.length ? plan.hosts.map((h) => `${h.host} (${h.how}${h.step ? `, step ${h.step}` : ''})`) : ['No host yet: only the vault changes.'] }))) return;
    const got = await (await postJSON(`/api/keys/secrets/${encodeURIComponent(s.name)}/rotate`, {})).json();     // a 409 throws, with why
    vsecMsg(got.why ? `Rotated. ${got.why}` : `Rotated on ${got.results.length} host${got.results.length === 1 ? '' : 's'}.`, !got.why);
    if (got.value) vsecShowOnce(s.name, got.value, 'The new value of');
    loadSecrets(false);
  }), 'btn ghost sm'));
  if (manage) li.append(button('Remove', () => vsecDo(async () => {
    if (!(await confirmDialog({ title: `Remove ${s.name}?`, confirm: 'Remove', danger: true, typed: s.name,
      body: 'It is deleted from the vault, and a plan step that names it can no longer get it. Copies on hosts are in memory and go at their next reboot.' }))) return;
    await api(`/api/keys/secrets/${encodeURIComponent(s.name)}`, { method: 'DELETE' });
    vsecMsg(`Removed ${s.name}.`, true);
    loadSecrets();
  }), 'btn ghost sm danger'));
  return li;
}

function vsecForm(kinds) {
  const name = sfNode('input', { id: 'secname', required: true, maxlength: 64, pattern: '[A-Za-z0-9][A-Za-z0-9._-]{0,63}', autocomplete: 'off', spellcheck: false, placeholder: 'grafana-admin' });
  const kind = sfNode('select', { id: 'seckind' }, kinds.map((k) => sfNode('option', { value: k.kind }, `${k.kind}: ${k.made_of}`)));
  const length = sfNode('input', { id: 'seclength', type: 'number', inputmode: 'numeric' });
  const setLength = () => { const k = kinds.find((x) => x.kind === kind.value); length.min = k.min; length.max = k.max; length.value = k.length; length.disabled = k.min === k.max; };
  kind.addEventListener('change', setLength);
  setLength();
  const steps = sfNode('input', { id: 'secsteps', placeholder: 'tailscale netbird', autocomplete: 'off' });
  const hosts = sfNode('input', { id: 'sechosts', placeholder: 'nas-01 web-02', autocomplete: 'off' });
  const platforms = sfNode('input', { id: 'secplatforms', placeholder: 'pve-main truenas-01', autocomplete: 'off' });
  const sensitive = sfNode('input', { id: 'secsensitive', type: 'checkbox' });
  const field = (label, input, hint) => sfNode('label', { class: 'sf-field' }, sfNode('span', {}, label), input, hint ? sfNode('small', {}, hint) : null);
  const form = sfNode('form', { class: 'stack' },
    field('Name', name), field('Kind', kind), field('Length', length),
    field('Only for these steps', steps, 'Step kinds, separated by spaces. Empty: any step.'),
    field('Only for these hosts', hosts, 'Empty: any host.'),
    field('Only for these platforms', platforms, 'Connected platform names, separated by spaces. Empty: any platform.'),
    sfNode('label', { class: 'check' }, sensitive, ' With the key enclave, each release takes a step-up'),
    sfNode('div', { class: 'row end' }, sfNode('button', { class: 'btn pri', type: 'submit' }, 'Make it')));
  form.addEventListener('submit', (ev) => { ev.preventDefault(); vsecDo(async () => {
    const r = await (await postJSON('/api/keys/secrets', { name: name.value.trim(), kind: kind.value, length: length.disabled ? null : Number(length.value),
      steps: steps.value, hosts: hosts.value, platforms: platforms.value, sensitive: sensitive.checked })).json();
    vsecShowOnce(r.secret.name, r.value, 'Made');
    vsecMsg(`${r.secret.name} is in the vault. A plan step that names it gets it on the host when the plan is applied.`, true);
    form.reset(); setLength();
    loadSecrets(false);
  }); });
  return sfNode('details', {}, sfNode('summary', {}, 'Make a secret'), form);
}

async function loadSecrets(clearShown = true) {
  const box = $('#secretbox');
  if (!box) return;
  if (clearShown) { const once = $('#secretonce'); once.replaceChildren(); once.hidden = true; }
  try {
    const d = await getJSON('/api/keys/secrets');
    const manage = can('keys.manage');
    const list = document.createElement('ol'); list.className = 'list';
    list.replaceChildren(...d.secrets.map((s) => vsecRow(s, manage, can('deploy.apply'))));
    if (!d.secrets.length) list.replaceChildren(text('li', 'No secrets yet.', 'muted'));
    box.replaceChildren(
      text('p', d.enclave ? 'Sealed inside the key enclave, which releases one only for a host and step its policy names, and writes each release into the audit log.'
        : 'Sealed in the vault. With the key enclave configured they are sealed inside it instead.', 'muted'),
      list, manage ? vsecForm(d.kinds) : '');
  } catch (err) { box.replaceChildren(text('p', err.message, 'muted')); }
}
