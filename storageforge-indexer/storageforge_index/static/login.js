/* The sign-in page: the only page served without a session. On success it goes back to ?next= (a path on this
   site only), keeping the #fragment the planner and app links use. */
'use strict';
const q = new URLSearchParams(location.search);
const next = /^\/(?![/\\])\S*$/.test(q.get('next') || '') ? q.get('next') : '/';
const msg = document.getElementById('loginmsg');
function say(text) { msg.textContent = text; msg.hidden = !text; }
if (q.get('ended')) say('Your session ended. Sign in again.');
else if (q.get('out')) say('Signed out.');
// work the page held when the session ended: what is still in this browser, and what could not be kept (kernel.js, sfLostWork)
try {
  const lost = JSON.parse(localStorage.getItem('sf.lostwork') || 'null');
  localStorage.removeItem('sf.lostwork');
  if (lost && Date.now() - lost.at < 3600000) {
    const parts = [lost.kept.length ? `Kept in this browser until you sign in again: ${lost.kept.join(', ')}.` : '', lost.lost.length ? `Could not be kept: ${lost.lost.join(', ')}.` : ''];
    say([msg.textContent, ...parts].filter(Boolean).join(' '));
  }
} catch { /* nothing to say */ }

document.getElementById('loginform').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const pw = document.getElementById('password');
  // route_code: this browser will send the code of the moment on sensitive requests (routecode.py), and is given its route key for that
  const body = JSON.stringify({ username: document.getElementById('username').value.trim(), password: pw.value, route_code: true });
  pw.value = '';
  try {
    const res = await fetch('/api/login', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body });
    if (!res.ok) { say((await res.json().catch(() => ({}))).error || res.statusText); pw.focus(); return; }
    const got = await res.json().catch(() => ({}));
    try {
      if (got.route_key) localStorage.setItem('sf.route', JSON.stringify({ key: got.route_key, skew: got.now - Date.now() / 1000 }));
      else localStorage.removeItem('sf.route');
    } catch { /* storage blocked: the app asks for the key again, behind the password */ }
    location.replace(next + (next.includes('#') ? '' : location.hash));
  } catch (err) { say(err.message); }
});

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (t) => Uint8Array.from(atob(t.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const waBtn = document.getElementById('loginwebauthn');
if (waBtn && navigator.credentials) {
  waBtn.addEventListener('click', async () => {
    const username = document.getElementById('username').value.trim();
    if (!username) { say('Enter your username first.'); document.getElementById('username').focus(); return; }
    try {
      const br = await fetch('/api/login/webauthn/begin', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }) });
      if (!br.ok) { say((await br.json().catch(() => ({}))).error || br.statusText); return; }
      const opts = await br.json();
      const pub = { ...opts, challenge: unb64u(opts.challenge), allowCredentials: (opts.allowCredentials || []).map((c) => ({ ...c, id: unb64u(c.id) })) };
      const cred = await navigator.credentials.get({ publicKey: pub });
      const fr = await fetch('/api/login/webauthn/finish', {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: cred.id, rawId: b64u(cred.rawId), response: { clientDataJSON: b64u(cred.response.clientDataJSON), authenticatorData: b64u(cred.response.authenticatorData), signature: b64u(cred.response.signature) }, route_code: true }),
      });
      if (!fr.ok) { say((await fr.json().catch(() => ({}))).error || fr.statusText); return; }
      const got = await fr.json().catch(() => ({}));
      try { if (got.route_key) localStorage.setItem('sf.route', JSON.stringify({ key: got.route_key, skew: got.now - Date.now() / 1000 })); } catch {}
      location.replace(next + (next.includes('#') ? '' : location.hash));
    } catch (err) { say(err.message); }
  });
}
