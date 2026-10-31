/* The page an invite or password reset link opens. The token is in the #fragment, so it never reaches a proxy's logs
   or a Referer header. */
'use strict';
const token = location.hash.slice(1);
const $ = (id) => document.getElementById(id);
history.replaceState(null, '', '/enroll');

function bad(why) { $('enrollform').hidden = true; $('enrollbad').hidden = false; $('enrollbadwhy').textContent = why; }
async function post(path, body) {
  const res = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

(async () => {
  if (!token) { bad('It has no invite code. Ask an admin for a new link.'); return; }
  const { ok, data } = await post('/api/enroll/check', { token });
  if (!ok) { bad(`${data.error || 'The link could not be checked.'} Ask an admin for a new link.`); return; }
  const form = $('enrollform');
  form.hidden = false;
  if (data.reset_user) {
    $('enrolltitle').textContent = 'Set a new password';
    $('enrollwhat').textContent = `For the account ${data.reset_user}. Every session of that account ends.`;
    $('enrollnamefield').hidden = true;
  } else {
    $('enrollwhat').textContent = `You are invited with the role ${data.role}. This link works once.`;
    $('enrollname').required = true;
    $('enrollname').focus();
  }
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const msg = $('enrollmsg');
    const r = await post('/api/enroll', { token, username: $('enrollname').value.trim(), password: $('enrollpw').value });
    if (r.ok) { location.replace('/login'); return; }
    if (r.status === 403) { bad(`${r.data.error} Ask an admin for a new link.`); return; }
    msg.textContent = r.data.error || 'That did not work.'; msg.hidden = false;
  });
})().catch((err) => bad(err.message));
