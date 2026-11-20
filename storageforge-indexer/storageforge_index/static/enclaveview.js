'use strict';
/* The key enclave on the Keys page (roadmap section 14, routes_enclave.py): whether the extra layer on the vault's keys is there, and
   where it is not, that it is not and why. A locked enclave is unlocked here by a person who types the vault secret: it goes to the
   server once and is checked inside the enclave. Loaded after kernel.js and app.js. */

function enclaveLine(d) {
  const cls = d.state === 'unlocked' ? 'st-ok' : d.state === 'off' ? 'muted' : d.state === 'locked' ? 'st-warn' : 'st-failed';
  return sfNode('p', {}, sfNode('b', { class: cls }, d.label), d.detail ? ` · ${d.detail}` : '');
}

function enclaveCounts(d) {
  if (!d.counts || d.state === 'off' || d.state === 'down') return null;
  const c = d.counts, l = d.limits || {};
  return sfNode('p', { class: 'muted small' }, `Since it started: ${c.signed || 0} signatures, ${c.released || 0} secrets released, ${c.refused || 0} requests refused by its limits, `
    + `${c.bad_requests || 0} of ${c.bad_limit || 5} malformed requests before it locks down. Its limits are its own: ${l.sign_per_key_per_minute || 600} signatures a minute per key, `
    + `${l.release_per_secret_per_minute || 60} releases a minute per secret, ${l.unlock_per_minute || 6} unlock attempts a minute.`);
}

function enclaveUnlockForm(d) {
  if (!can('keys.manage') || (d.state !== 'locked' && d.state !== 'lockdown')) return null;
  const secret = sfNode('input', { type: 'password', autocomplete: 'off', required: true, minlength: 32, 'aria-label': 'Vault secret', placeholder: 'the vault secret',
    'data-1p-ignore': '', 'data-lpignore': 'true', 'data-bwignore': 'true' });
  const go = sfNode('button', { type: 'submit', class: 'btn pri' }, 'Unlock');
  const form = sfNode('form', { class: 'row' }, secret, go);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const typed = secret.value;
    secret.value = '';
    try {
      const now = await (await postJSON('/api/enclave/unlock', { secret: typed }, { busy: go })).json();
      notify(now.state === 'unlocked' ? 'The key enclave is unlocked.' : now.label, now.state === 'unlocked' ? 'info' : 'error');
    } catch (err) { notify(err.message, 'error'); }
    loadEnclave();
  });
  return sfNode('div', { class: 'stack' },
    sfNode('p', { class: 'muted small' }, d.state === 'lockdown'
      ? 'Only a person unlocks it after a lock-down. The secret you type goes to the server once and is checked inside the enclave.'
      : 'Type the vault secret to unlock it. It goes to the server once and is checked inside the enclave; nothing here keeps it.'),
    form);
}

function enclaveLockButton(d) {
  if (!can('keys.manage') || d.state !== 'unlocked') return null;
  const b = sfNode('button', { type: 'button', class: 'btn ghost sm danger', title: 'It forgets every key. Scans, deploys, sends and the console stop until it is unlocked again' }, 'Lock the enclave');
  sfOnClick(b, async () => {
    if (!(await confirmDialog({ title: 'Lock the key enclave?', body: 'It forgets the vault\'s keys. Nothing that needs a key works until it is unlocked again, by the starter or by a person with the vault secret.',
      confirm: 'Lock it', danger: true }))) return;
    try { await postJSON('/api/enclave/lock', {}); } catch (err) { notify(err.message, 'error'); }
    loadEnclave();
  });
  return b;
}

async function loadEnclave() {
  const box = document.getElementById('enclavebox');
  if (!box) return;
  let d;
  try { d = await getJSON('/api/enclave'); } catch (err) { box.replaceChildren(sfNode('p', { class: 'muted' }, err.message)); box.hidden = false; return; }
  box.replaceChildren(sfNode('h3', {}, 'Key enclave'), enclaveLine(d), enclaveCounts(d), enclaveUnlockForm(d), enclaveLockButton(d));
  box.hidden = false;
}
