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

/* Step-up: whether the enclave checks people itself, and this account's own record with it. */
function enclaveStepUp(d) {
  if (d.state !== 'unlocked' || !d.stepup) return null;
  const su = d.stepup;
  const line = su.required
    ? `Step-up is on: making or changing a key takes a password or a security key that the enclave checks itself. ${su.people} account${su.people === 1 ? ' is' : 's are'} enrolled.`
    : 'Step-up is off: nobody has enrolled, so the enclave makes and changes keys on the web app\'s word.';
  const mine = su.enrolled
    ? `Your password is enrolled${su.security_keys ? `, with ${su.security_keys} security key${su.security_keys === 1 ? '' : 's'}` : ''}.${su.stale_keys ? ' Your security keys changed since: enroll again to give the enclave the ones you have now.' : ''}`
    : 'You are not enrolled.';
  const kids = [sfNode('p', { class: 'muted small' }, `${line} ${mine}`)];
  if (can('keys.manage')) {
    const b = sfNode('button', { type: 'button', class: 'btn ghost sm' }, su.enrolled ? 'Enroll again' : 'Enroll your password with the enclave');
    sfOnClick(b, async () => {
      const first = !su.required;
      const f = await formDialog({ title: 'Enroll with the key enclave', confirm: 'Enroll',
        body: 'The enclave keeps a hash of your account password, and the public keys of your security keys, sealed under the vault\'s key. From then on it checks you itself before it makes or changes a key.'
          + (first ? '' : '\n\nSomeone is enrolled already, so this takes a step-up of yours, or the vault secret if you have none yet.'),
        fields: [{ name: 'password', label: 'Your account password', type: 'password', required: true },
          ...(first || su.enrolled ? [] : [{ name: 'secret', label: 'The vault secret (only if you have no step-up yet)', type: 'password' }])] });
      if (!f) return;
      try { await postJSON('/api/enclave/stepup/enroll', { password: f.password, ...(f.secret ? { secret: f.secret } : {}) }); notify('Enrolled with the key enclave.'); }
      catch (err) { notify(err.message, 'error'); }
      loadEnclave();
    });
    kids.push(b);
  }
  return sfNode('div', { class: 'stack' }, kids);
}

/* The audit log's head, which the enclave keeps: where the log no longer ends there, a person who has looked at why takes it as it is. */
function enclaveChain(d) {
  const c = d.chain;
  if (!c || d.state !== 'unlocked' || (!c.behind && !c.unwritten)) return null;
  const kids = [sfNode('p', { class: c.behind || c.releases_unwritten ? 'st-failed' : 'st-warn' },
    c.behind ? 'The audit log no longer ends where the enclave last signed it: entries were removed or changed. No secret is released until someone has looked.'
      : `${c.unwritten} audit ${c.unwritten === 1 ? 'entry' : 'entries'} the enclave signed ${c.unwritten === 1 ? 'was' : 'were'} not written to the log`
        + (c.releases_unwritten ? `, ${c.releases_unwritten} of them the record of a released secret.` : '.'))];
  if (c.behind && can('keys.manage')) {
    const b = sfNode('button', { type: 'button', class: 'btn ghost sm danger', title: 'Audit → Verify chain shows what is there. Accepting is written to the log, with your name' }, 'Take the log as it is now');
    sfOnClick(b, async () => {
      if (!(await confirmDialog({ title: 'Take the audit log as it is now?', body: 'The enclave will sign on from the log\'s last entry. What was removed stays removed: do this after finding out what happened. It is written to the log with your name.', confirm: 'Take it as it is', danger: true }))) return;
      try { await postJSON('/api/enclave/chain/accept', {}); } catch (err) { notify(err.message, 'error'); }
      loadEnclave();
    });
    kids.push(b);
  }
  return sfNode('div', { class: 'stack' }, kids);
}

function enclaveUnlockForm(d) {
  if (!can('keys.manage') || (d.state !== 'locked' && d.state !== 'lockdown')) return null;
  const secret = sfNode('input', { type: 'password', autocomplete: 'off', required: true, minlength: 32, 'aria-label': 'Vault secret', placeholder: 'the vault secret',
    'data-1p-ignore': '', 'data-lpignore': 'true', 'data-bwignore': 'true' });
  const go = sfNode('button', { type: 'submit', class: 'btn pri' }, 'Unlock');
  // after a lock-down, an enclave with step-up on lifts it only for a person it checks: the account password goes with the secret
  const pw = d.state === 'lockdown' ? sfNode('input', { type: 'password', autocomplete: 'current-password', 'aria-label': 'Your account password', placeholder: 'your account password, if you enrolled' }) : null;
  const form = sfNode('form', { class: 'row' }, secret, pw, go);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const typed = secret.value, password = pw ? pw.value : '';
    secret.value = '';
    if (pw) pw.value = '';
    try {
      const now = await (await postJSON('/api/enclave/unlock', { secret: typed, ...(password ? { password } : {}) }, { busy: go })).json();
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

/* For the security view's overview (securityview.js): the same label, so that where the enclave is off or cannot run here the page
   that sums up what protects this installation says the extra layer is not there. Null for an account that may not see keys. */
async function enclaveSecurityCard() {
  let d;
  try { d = await getJSON('/api/enclave'); } catch { return null; }
  return sfNode('div', { class: 'stack', id: 'sec-enclave' }, enclaveLine(d),
    d.on ? null : sfNode('p', { class: 'muted small' }, 'With the enclave the vault\'s keys are held in a micro VM with no network device, and the web app only asks it for signatures. See Keys → Key enclave.'));
}

async function loadEnclave() {
  const box = document.getElementById('enclavebox');
  if (!box) return;
  let d;
  try { d = await getJSON('/api/enclave'); } catch (err) { box.replaceChildren(sfNode('p', { class: 'muted' }, err.message)); box.hidden = false; return; }
  box.replaceChildren(sfNode('h3', {}, 'Key enclave'), enclaveLine(d), enclaveCounts(d), enclaveChain(d), enclaveStepUp(d), enclaveUnlockForm(d), enclaveLockButton(d));
  box.hidden = false;
}
