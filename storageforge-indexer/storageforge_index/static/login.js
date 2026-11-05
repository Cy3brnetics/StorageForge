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
  const body = JSON.stringify({ username: document.getElementById('username').value.trim(), password: pw.value });
  pw.value = '';
  try {
    const res = await fetch('/api/login', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body });
    if (!res.ok) { say((await res.json().catch(() => ({}))).error || res.statusText); pw.focus(); return; }
    location.replace(next + (next.includes('#') ? '' : location.hash));
  } catch (err) { say(err.message); }
});
