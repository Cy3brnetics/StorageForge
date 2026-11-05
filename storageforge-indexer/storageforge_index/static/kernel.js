'use strict';
/* The kernel every page shares (UX-10, 11 and 23 of the UI audit of 2026-11-04): the one api() call, dialogs in place of confirm(), alert()
   and prompt(), a live region and toasts that say what happened, and a busy state. DOM APIs only and no third-party code, so it runs under
   the strict 'self' CSP. Loaded after session.js on the main page, the planner, /manage and /search. Only this file and session.js call
   fetch(): tests/test_ui_kernel.py fails when another script does. */

/* ── a tiny element builder, private to the kernel ───────────────── */
function sfNode(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'spellcheck') { e.spellcheck = !!v; continue; }          // false has to be set, not skipped
    if (v === false || v == null) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
    else if (k in e && k !== 'list' && k !== 'form') e[k] = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) e.append(kid);
  return e;
}
let sfSeq = 0;
let sfUserName = '';              // the pages set this when they know who is signed in: it only lets a password manager fill the right account

/* ── latest answer wins (UX-12) ──────────────────────────────────── */
/* `const fresh = latest('search')` when a request starts and `if (!fresh()) return` after each await, so a slow answer never lands on top
   of the one asked for after it, and never changes state the newer one has already set. */
const LATEST = {};
function latest(key) {
  const n = LATEST[key] = (LATEST[key] || 0) + 1;
  return () => LATEST[key] === n;
}

/* ── busy and announced ──────────────────────────────────────────── */
function busy(el, on = true) {
  if (!el) return;
  if (on) {
    el.setAttribute('aria-busy', 'true');
    if ('disabled' in el) { el.dataset.sfWasDisabled = el.disabled ? '1' : ''; el.disabled = true; }
  } else {
    el.removeAttribute('aria-busy');
    if ('disabled' in el) { el.disabled = el.dataset.sfWasDisabled === '1'; delete el.dataset.sfWasDisabled; }
  }
}
async function withBusy(el, work) {
  busy(el, true);
  try { return await work(); } finally { busy(el, false); }
}

let sfLive = null;
function announce(message) {      // for a screen reader: what just happened, without moving focus
  if (!sfLive) { sfLive = sfNode('div', { class: 'sf-live', role: 'status', 'aria-live': 'polite' }); document.body.append(sfLive); }
  sfLive.textContent = '';
  setTimeout(() => { sfLive.textContent = message; }, 50);        // clearing first makes the same message read again
}

function notify(message, kind = 'info') {        // a toast. An error stays until it is dismissed; anything else goes after a few seconds
  let box = document.getElementById('sf-toasts');
  if (!box) { box = sfNode('div', { id: 'sf-toasts', class: 'sf-toasts' }); document.body.append(box); }
  const t = sfNode('div', { class: `sf-toast ${kind}`, role: kind === 'error' ? 'alert' : 'status' }, sfNode('span', {}, String(message)));
  if (kind === 'error') t.append(sfNode('button', { type: 'button', class: 'sf-btn ghost', onclick: () => t.remove() }, 'Dismiss'));
  else setTimeout(() => t.remove(), 4200);
  box.append(t);
}

const toast = (message, kind) => notify(message, kind);          // the name the main page's scripts already use

/* ── dialogs ─────────────────────────────────────────────────────── */
function sfModal(content, labelledby) {          // a native modal <dialog>: focus stays inside, Escape closes it, and focus goes back to where it was
  const opener = document.activeElement;
  const dlg = sfNode('dialog', { class: 'sf-dialog', 'aria-labelledby': labelledby });
  dlg.append(content);
  document.body.append(dlg);
  dlg.addEventListener('close', () => { dlg.remove(); if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus(); });
  dlg.showModal();
  return dlg;
}

/* confirmDialog({ title, body, items, confirm, cancel, danger, typed }) → Promise<boolean>.
   `title` is the question and `body` says what will happen (paragraphs split on a blank line); `items` lists what is affected; `confirm` is a
   verb, not "OK". `danger` makes the button red and puts focus on Cancel. `typed` is a name the person must type before the button works,
   for what cannot be undone. Every string is shown as text, so a path or a host name from a machine cannot become markup. */
function confirmDialog({ title, body = '', items = [], confirm = 'OK', cancel = 'Cancel', danger = false, typed = '' }) {
  return new Promise((resolve) => {
    const id = `sf-dlg-${++sfSeq}`;
    let answer = false;
    const ok = sfNode('button', { type: 'submit', class: `sf-btn ${danger ? 'danger' : 'pri'}` }, confirm);
    const no = sfNode('button', { type: 'button', class: 'sf-btn ghost' }, cancel);
    const typedInput = typed ? sfNode('input', { type: 'text', autocomplete: 'off', spellcheck: false }) : null;
    const form = sfNode('form', { method: 'dialog' },
      sfNode('h2', { id }, title),
      String(body).split('\n\n').filter(Boolean).map((t) => sfNode('p', {}, t)),
      items.length ? sfNode('ul', {}, items.map((i) => sfNode('li', {}, i))) : null,
      typed ? sfNode('label', { class: 'sf-field' }, sfNode('span', {}, 'Type ', sfNode('b', {}, typed), ' to confirm'), typedInput) : null,
      sfNode('div', { class: 'sf-actions' }, no, ok));
    if (typed) {
      ok.disabled = true;
      typedInput.addEventListener('input', () => { ok.disabled = typedInput.value.trim() !== typed; });
    }
    const dlg = sfModal(form, id);
    form.addEventListener('submit', (ev) => { ev.preventDefault(); if (typed && typedInput.value.trim() !== typed) return; answer = true; dlg.close(); });
    no.addEventListener('click', () => dlg.close());
    dlg.addEventListener('close', () => resolve(answer));
    (typedInput || (danger ? no : ok)).focus();
  });
}

/* "A question? What follows it." → { title, body }: for the places that kept a native confirm()'s question and its consequence in one string. */
function sfQuestion(sentence) {
  const m = /^(.*?\?)\s+(.*)$/s.exec(String(sentence));
  return m ? { title: m[1], body: m[2] } : { title: String(sentence), body: '' };
}

/* noticeDialog({ title, body, close }) → Promise<void>: a message that has to be read before the page goes on, which is what alert() was
   for. Anything that can wait is a notify() toast instead. */
function noticeDialog({ title, body = '', close = 'OK' }) {
  return new Promise((resolve) => {
    const id = `sf-dlg-${++sfSeq}`;
    const ok = sfNode('button', { type: 'submit', class: 'sf-btn pri' }, close);
    const form = sfNode('form', { method: 'dialog' }, sfNode('h2', { id }, title),
      String(body).split('\n\n').filter(Boolean).map((t) => sfNode('p', {}, t)), sfNode('div', { class: 'sf-actions' }, ok));
    const dlg = sfModal(form, id);
    form.addEventListener('submit', (ev) => { ev.preventDefault(); dlg.close(); });
    dlg.addEventListener('close', () => resolve());
    ok.focus();
  });
}

/* formDialog({ title, body, fields, confirm, cancel }) → Promise<{name: value}|null>. A field is { name, label, value, placeholder, hint,
   type, required, maxlength, inputmode, validate(value) → a message to refuse it with, or '' }. */
function formDialog({ title, body = '', fields = [], confirm = 'Save', cancel = 'Cancel' }) {
  return new Promise((resolve) => {
    const id = `sf-dlg-${++sfSeq}`;
    let answer = null;
    const inputs = fields.map((f) => sfNode('input', { type: f.type || 'text', value: f.value ?? '', placeholder: f.placeholder, required: !!f.required,
                                                       maxlength: f.maxlength, inputmode: f.inputmode, autocomplete: 'off', spellcheck: false }));
    const err = sfNode('p', { class: 'sf-err', role: 'alert', hidden: true });
    const no = sfNode('button', { type: 'button', class: 'sf-btn ghost' }, cancel);
    const form = sfNode('form', { method: 'dialog' },
      sfNode('h2', { id }, title),
      String(body).split('\n\n').filter(Boolean).map((t) => sfNode('p', { class: 'muted' }, t)),
      fields.map((f, i) => sfNode('label', { class: 'sf-field' }, sfNode('span', {}, f.label), inputs[i], f.hint ? sfNode('small', {}, f.hint) : null)),
      err,
      sfNode('div', { class: 'sf-actions' }, no, sfNode('button', { type: 'submit', class: 'sf-btn pri' }, confirm)));
    const dlg = sfModal(form, id);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const values = {};
      for (const [i, f] of fields.entries()) {
        const v = inputs[i].value.trim();
        const bad = f.validate ? f.validate(v) : '';
        if (bad) { err.textContent = bad; err.hidden = false; inputs[i].focus(); return; }
        values[f.name] = v;
      }
      answer = values;
      dlg.close();
    });
    no.addEventListener('click', () => dlg.close());
    dlg.addEventListener('close', () => resolve(answer));
    if (inputs[0]) { inputs[0].focus(); inputs[0].select(); }
  });
}

/* ── password again before commands run on hosts ─────────────────── */
async function sfKnowUser() {     // who is signed in, so a password manager can offer the right password; asked only when a password is wanted
  if (sfUserName) return;
  try { const r = await fetch('/api/me', { credentials: 'same-origin' }); if (r.ok) sfUserName = (await r.json()).username || ''; } catch { /* the hint is optional */ }
}
let sfReauth = null;
function confirmPassword() {      // one dialog however many calls are waiting on it
  if (sfReauth) return sfReauth;
  sfReauth = sfKnowUser().then(() => new Promise((resolve, reject) => {
    const pw = sfNode('input', { id: 'reauthpw', type: 'password', autocomplete: 'current-password', required: true });
    const msg = sfNode('p', { id: 'reauthmsg', class: 'sf-err', role: 'alert', hidden: true });
    const cancel = sfNode('button', { id: 'reauthcancel', type: 'button', class: 'sf-btn ghost' }, 'Cancel');
    const form = sfNode('form', { id: 'reauthform', method: 'dialog' },
      sfNode('h2', { id: 'reauthtitle' }, 'Confirm your password'),
      sfNode('p', { class: 'muted' }, 'Running commands on your hosts (and changing how long sessions last) needs your password again. It stays confirmed for 5 minutes.'),
      sfUserName ? sfNode('input', { type: 'text', autocomplete: 'username', value: sfUserName, hidden: true }) : null,
      sfNode('label', { class: 'sf-field' }, sfNode('span', {}, 'Password'), pw), msg,
      sfNode('div', { class: 'sf-actions' }, cancel, sfNode('button', { type: 'submit', class: 'sf-btn pri' }, 'Confirm')));
    const dlg = sfModal(form, 'reauthtitle');
    let settled = false;
    const finish = (fn, arg) => { if (settled) return; settled = true; fn(arg); };
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const password = pw.value;
      pw.value = '';
      const res = await fetch('/api/reauth', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) });
      if (res.status === 401) { dlg.close(); finish(reject, new Error('Sign in required')); sfSignedOut(); return; }
      if (!res.ok) { msg.textContent = (await res.json().catch(() => ({}))).error || res.statusText; msg.hidden = false; pw.focus(); return; }
      finish(resolve); dlg.close();
    });
    cancel.addEventListener('click', () => dlg.close());
    dlg.addEventListener('close', () => finish(reject, new Error('Password not confirmed: nothing was run')));
    pw.focus();
  })).finally(() => { sfReauth = null; });
  return sfReauth;
}

/* ── a person checks a host's SSH key before a password goes to it ── */
function confirmHostKey(hk) {
  return new Promise((resolve, reject) => {
    const msg = sfNode('p', { class: 'sf-err', role: 'alert', hidden: true });
    const cancel = sfNode('button', { type: 'button', class: 'sf-btn ghost' }, 'Cancel');
    const host = hk.port && hk.port !== 22 ? `${hk.host} (port ${hk.port})` : hk.host;
    const form = sfNode('form', { method: 'dialog' },
      sfNode('h2', { id: 'hktitle' }, 'Check this host’s SSH key'),
      sfNode('p', { class: 'muted' }, 'A password is about to go to ', sfNode('b', {}, host), '. StorageForge has not talked to it before, or nobody has checked its key yet. Run this on that machine and compare:'),
      sfNode('pre', {}, 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'),
      sfNode('ul', { class: 'sf-keys' }, hk.keys.map((k) => sfNode('li', {}, sfNode('code', {}, k.fingerprint), k.type ? ` ${k.type}` : ''))),
      sfNode('p', { class: 'muted small' }, 'If the fingerprints differ, something else answered at that address: cancel, and nothing is sent.'),
      msg,
      sfNode('div', { class: 'sf-actions' }, cancel, sfNode('button', { type: 'submit', class: 'sf-btn pri' }, 'They match')));
    const dlg = sfModal(form, 'hktitle');
    let settled = false;
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      try {
        await api('/api/hostkey/confirm', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                            body: JSON.stringify({ host: hk.host, port: hk.port, fingerprint: hk.keys[0].fingerprint }) });
        settled = true; dlg.close(); resolve();
      } catch (err) { msg.textContent = err.message; msg.hidden = false; }
    });
    cancel.addEventListener('click', () => dlg.close());
    dlg.addEventListener('close', () => { if (!settled) { settled = true; reject(new Error('Host key not confirmed: no password was sent')); } });
  });
}

/* ── the one api() ───────────────────────────────────────────────── */
/* Returns the Response of a request that worked, and throws an Error (with .status and .body) for one that did not. It handles, in one
   place, what every page used to do for itself: a 401 empties the page and goes to /login; a 403 that asks for the password again opens
   the password dialog and retries once; a 409 that carries a host key shows it to the person and retries. `busy: element` shows the busy
   state on that element for as long as the call takes. */
function api(path, opts = {}) {
  const { busy: el, ...init } = opts;
  return el ? withBusy(el, () => sfFetch(path, init, false)) : sfFetch(path, init, false);
}
async function sfFetch(path, init, confirmed) {
  const res = await fetch(path, { credentials: 'same-origin', ...init });
  if (res.status === 401) {          // the session is gone: session.js empties the page and goes to /login
    const msg = (await res.json().catch(() => ({}))).error || '';
    sfSignedOut(/ended/.test(msg) ? 'ended' : ''); throw new Error('Sign in required');
  }
  if (res.status === 403 && !confirmed && (await res.clone().json().catch(() => ({}))).reauth) {
    await confirmPassword();                     // commands on hosts: type the password again, then retry once
    return sfFetch(path, init, true);
  }
  if (res.status === 409) {                      // a password would go to a host key nobody checked: show it first
    const hk = (await res.clone().json().catch(() => ({}))).hostkey;
    if (hk) { await confirmHostKey(hk); return sfFetch(path, init, confirmed); }
  }
  if (!res.ok) {
    let msg = res.statusText, body = null;
    try { body = await res.json(); msg = body.error || msg; } catch { /* not JSON */ }
    const err = new Error(msg);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return res;
}
const getJSON = async (path, opts) => (await api(path, opts)).json();
const postJSON = (path, body, opts = {}) => api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), ...opts });
