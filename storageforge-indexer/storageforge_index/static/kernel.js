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
/* A busy element says so (aria-busy, and a spinner on a button) and cannot be clicked again meanwhile. It is not `disabled`, because a
   disabled button cannot take focus back when a dialog it opened closes, and a keyboard user would lose their place. */
function busy(el, on = true) {
  if (!el) return;
  if (on) {
    el.setAttribute('aria-busy', 'true');
    if (el.tagName === 'BUTTON') el.setAttribute('aria-disabled', 'true');
  } else {
    el.removeAttribute('aria-busy');
    if (el.tagName === 'BUTTON') el.removeAttribute('aria-disabled');
  }
}
/* A click handler that shows its button busy while an async handler runs, and ignores a second click meanwhile (UX-11). */
function sfOnClick(button, handler) {
  button.addEventListener('click', (ev) => {
    if (button.getAttribute('aria-busy') === 'true') return;
    const r = handler(ev);
    if (r && typeof r.then === 'function') { busy(button, true); r.finally(() => busy(button, false)); }       // finally() passes a failure on, so it is still reported
  });
  return button;
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

/* ── a list that is cut says so (UX-13) ───────────────────────────── */
/* sfMoreList(items, render, { limit = 12, label, tag = 'div', className }) shows the first `limit` items and, when there are more, a real
   button "Show N more" that shows the rest in place and then reads "Show fewer". render(item, index) returns a Node. Items are only ever
   built with DOM calls, so a name that a host reports as `<b>x</b>` stays text. The button is never replaced, so focus stays on it, and
   aria-expanded and aria-controls say what it does. `label` names the things ("findings") for the screen reader's announcement. `tag` is the
   element that holds the items ('ul' or 'ol' when render() returns <li>) and `className` goes on it. The rest is built on the first
   expansion only. */
function sfMoreList(items, render, { limit = 12, label = '', tag = 'div', className = '' } = {}) {
  const all = Array.from(items || []);
  const cut = Math.max(0, limit | 0);
  const box = sfNode(tag, { class: className, id: `sf-more-${++sfSeq}` });
  box.append(...all.slice(0, cut).map((item, i) => render(item, i)));
  const wrap = sfNode('div', { class: 'sf-more' }, box);
  if (all.length <= cut) return wrap;
  const hidden = all.length - cut;
  const noun = label ? ` ${label}` : '';
  let rest = null, open = false;
  const button = sfNode('button', { type: 'button', class: 'sf-btn ghost sf-more-btn', 'aria-expanded': 'false', 'aria-controls': box.id }, `Show ${hidden} more`);
  button.addEventListener('click', () => {
    open = !open;
    if (open) {
      rest = rest || all.slice(cut).map((item, i) => render(item, cut + i));
      box.append(...rest);
    } else {
      for (const node of rest) node.remove();
      button.scrollIntoView?.({ block: 'nearest' });          // the list got shorter above the button: keep it in sight
    }
    button.setAttribute('aria-expanded', String(open));
    button.textContent = open ? 'Show fewer' : `Show ${hidden} more`;
    announce(open ? `Showing all ${all.length}${noun}` : `Showing the first ${cut} of ${all.length}${noun}`);
  });
  wrap.append(button);
  return wrap;
}

/* ── what a URL says (UX-08) ──────────────────────────────────────── */
/* A page's place is in its URL after the #: #/map/firewall?host=nas. sfParseHash() reads that form; the old forms (#host=nas&tab=changes,
   #overview@atlas) come back with `parts` empty and `legacy` true, for the page to read as it always did. sfPushHash() makes a step of
   its own in the history, so Back goes where the person was, and sfReplaceHash() tidies the URL without one. */
function sfParseHash(hash = location.hash) {
  const h = hash.replace(/^#/, '');
  if (!h.startsWith('/')) return { parts: [], q: new URLSearchParams(h.includes('=') ? h : ''), legacy: !!h, raw: h };
  const cut = h.indexOf('?');
  const path = cut < 0 ? h.slice(1) : h.slice(1, cut);
  const parts = path.split('/').filter(Boolean).map((p) => { try { return decodeURIComponent(p); } catch { return p; } });
  return { parts, q: new URLSearchParams(cut < 0 ? '' : h.slice(cut + 1)), legacy: false, raw: h };
}
function sfFormatHash(parts, params = {}) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== '' && v != null) q.set(k, v);
  const qs = q.toString();
  return '#/' + parts.map(encodeURIComponent).join('/') + (qs ? `?${qs}` : '');
}
const sfSameHash = (a, b) => new URL(a, location.href).hash === new URL(b, location.href).hash;
function sfPushHash(hash) { if (!sfSameHash(hash, location.hash)) history.pushState(null, '', location.pathname + location.search + hash); }
function sfReplaceHash(hash) { if (!sfSameHash(hash, location.hash)) history.replaceState(null, '', location.pathname + location.search + hash); }

/* ── work that is not saved: one rule for every editor (UX-15) ───── */
/* An editor says when it holds work nobody has saved: sfUnsaved({ id, label, dirty(), kept }). `kept: true` means it already keeps its own draft in
   this browser (Compose, the map's staged steps, a change plan, the planner), so leaving the page loses nothing and nothing is asked. For any
   other, the one beforeunload below asks before the page goes away, and if the session ends first sfLostWork() leaves a note for the sign-in
   page that names what was kept and what could not be. */
const SF_UNSAVED = [];
function sfUnsaved(spec) { SF_UNSAVED.push(spec); }
window.addEventListener('beforeunload', (ev) => { if (SF_UNSAVED.some((u) => !u.kept && u.dirty())) ev.preventDefault(); });
function sfLostWork() {          // session.js calls this just before it empties the page
  const dirty = SF_UNSAVED.filter((u) => u.dirty());
  if (!dirty.length) return;
  try { localStorage.setItem('sf.lostwork', JSON.stringify({ at: Date.now(), kept: dirty.filter((u) => u.kept).map((u) => u.label), lost: dirty.filter((u) => !u.kept).map((u) => u.label) })); } catch { /* storage blocked */ }
}
/* A draft kept in this browser belongs to the person who wrote it, so another account on the same browser never sees it. */
function sfStash(key, value, user) {
  try {
    if (value == null || value === '' || (Array.isArray(value) && !value.length)) localStorage.removeItem(key);
    else localStorage.setItem(key, JSON.stringify({ user: user || '', value }));
  } catch { /* storage blocked: the draft lasts until the page does */ }
}
function sfRecall(key, fallback, user) {
  try {
    const got = JSON.parse(localStorage.getItem(key) || 'null');
    return got && got.user === (user || '') ? got.value : fallback;
  } catch { return fallback; }
}

/* ── one way to show a time and a size (UX-16) ───────────────────── */
/* A time is shown in local time, because that is the clock a person is reading, with its UTC form on hover (title) for matching it against a
   host's own logs. Times come as seconds since the epoch. fmtTime() is the text, timeEl() the <time> element that carries the hover, fmtDate()
   the day, fmtClock() the time of day, and fmtAgo() "5 min ago" or "in 2 h". Sizes are binary units (KiB, MiB) from fmtBytes(). */
const sfPad = (n) => String(n).padStart(2, '0');
function fmtDate(ts) {
  if (ts == null || ts === '') return '';
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${sfPad(d.getMonth() + 1)}-${sfPad(d.getDate())}`;
}
function fmtClock(ts) {
  if (ts == null || ts === '') return '';
  const d = new Date(ts * 1000);
  return `${sfPad(d.getHours())}:${sfPad(d.getMinutes())}:${sfPad(d.getSeconds())}`;
}
function fmtTime(ts, { seconds = false } = {}) {
  if (ts == null || ts === '') return '';
  return `${fmtDate(ts)} ${fmtClock(ts).slice(0, seconds ? 8 : 5)}`;
}
function fmtUtc(ts) {
  if (ts == null || ts === '') return '';
  return `${new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19)} UTC`;
}
function timeEl(ts, opts) {
  const t = document.createElement('time');
  if (ts == null || ts === '') return t;
  t.dateTime = new Date(ts * 1000).toISOString();
  t.title = fmtUtc(ts);
  t.textContent = fmtTime(ts, opts);
  return t;
}
function fmtAgo(ts, { never = 'never' } = {}) {
  if (!ts) return never;
  const s = Math.round(Date.now() / 1000 - ts), a = Math.abs(s);
  const t = a < 90 ? `${a} s` : a < 5400 ? `${Math.round(a / 60)} min` : a < 129600 ? `${Math.round(a / 3600)} h` : a < 5184000 ? `${Math.round(a / 86400)} days`
    : a < 63072000 ? `${Math.round(a / 2592000)} months` : `${Math.round(a / 31536000)} years`;
  return s >= 0 ? `${t} ago` : `in ${t}`;
}
function fmtBytes(n) {
  if (n == null || n === '') return '—';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']; let v = Number(n), i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i < 2 ? 0 : 2)} ${u[i]}`;
}

/* ── one place for keyboard shortcuts (UX-40, UX-41, UX-20) ──────── */
/* Every global shortcut declares itself with sfShortcut(), and the one listener below applies the one rule for "someone is typing": a
   shortcut does not act inside a text field or under an open dialog, and not with Ctrl, Alt or Meta held, unless it says it may. Typing a
   path starts with a slash, so a shortcut that took `/` from anywhere took it from the path, and from a password in the confirm dialog.
   A shortcut declares what it is for, so the list of them (sfShortcuts()) can be shown to a person. A widget's own keys, on its own
   element, are not global shortcuts and stay where they are. tests/test_ui_kernel.py fails when a script registers a keydown on the
   document itself. */
const inField = (ev) => !!ev.target.closest?.('input, textarea, select, [contenteditable]');
const dialogOpen = () => !!document.querySelector('dialog[open]');
const typing = (ev) => inField(ev) || dialogOpen();
const plain = (ev) => !(ev.ctrlKey || ev.metaKey || ev.altKey || ev.isComposing);
const SF_SHORTCUTS = [];

/* { id, key, mods, label, where, fields, dialogs, when(ev), run(ev) }. mods: 'none' (no Ctrl, Alt or Meta; Shift may be held, as a slash
   needs it on some keyboards), 'shift' (Shift and nothing else), 'mod' (Ctrl or Meta, with Shift as it likes, no Alt) or 'any'.
   fields and dialogs let it act inside a text field or under an open dialog. run() may return false to say it found nothing to do,
   and the next shortcut for the key gets it; anything else is the key taken. */
function sfShortcut({ id, key, mods = 'none', label, where = 'Anywhere on the page', fields = false, dialogs = false, when = null, run }) {
  const spec = { id, key, mods, label, where, fields, dialogs, when, run };
  SF_SHORTCUTS.push(spec);
  return spec;
}
function sfShortcuts() { return SF_SHORTCUTS.map(({ id, key, mods, label, where }) => ({ id, key, mods, label, where })); }
function sfModsOk(mods, ev) {
  const mod = ev.ctrlKey || ev.metaKey;
  if (mods === 'any') return true;
  if (mods === 'shift') return ev.shiftKey && !mod && !ev.altKey;
  if (mods === 'mod') return mod && !ev.altKey;
  return !mod && !ev.altKey;
}
document.addEventListener('keydown', (ev) => {
  if (ev.isComposing || typeof ev.key !== 'string') return;
  const typingNow = inField(ev), dialogNow = dialogOpen();
  for (const sc of SF_SHORTCUTS) {
    if (ev.key.toLowerCase() !== sc.key.toLowerCase() || !sfModsOk(sc.mods, ev)) continue;
    if ((typingNow && !sc.fields) || (dialogNow && !sc.dialogs)) continue;
    if (sc.when && !sc.when(ev)) continue;
    if (sc.run(ev) !== false) return;
  }
});

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
let sfMePromise = null;
function sfMe() {                 // who is signed in and what they may do, asked once for the page
  if (!sfMePromise) sfMePromise = getJSON('/api/me').catch((err) => { sfMePromise = null; throw err; });
  return sfMePromise;
}
async function sfKnowUser() {     // so a password manager can offer the right password; asked only when a password is wanted
  if (sfUserName) return;
  try { sfUserName = (await sfMe()).username || ''; } catch { /* the hint is optional */ }
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
