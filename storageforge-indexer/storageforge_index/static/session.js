/* Signed-out guard, loaded first by the app and the planner. When the session is gone (any 401, its end time, coming
   back to the tab, or the back button after signing out) the page is emptied and replaced by /login, so nothing
   loaded earlier stays on screen. */
'use strict';
function sfSignedOut(how = '') {   // how: '' | 'ended' | 'out'
  if (sfSignedOut.gone) return;
  sfSignedOut.gone = true;
  if (typeof sfLostWork === 'function') sfLostWork();      // the kernel notes what was kept and what could not be, for the sign-in page
  document.body.replaceChildren();
  const q = new URLSearchParams({ next: location.pathname + location.search + location.hash });
  if (how) q.set(how, '1');
  location.replace('/login?' + q);
}
let sfTimer = 0;
function sfSessionEnds(at) {        // epoch seconds, from /api/me; checked again just after it passes
  clearTimeout(sfTimer);
  if (at) sfTimer = setTimeout(sfCheckSession, Math.min(Math.max(at * 1000 - Date.now() + 1500, 1000), 2 ** 31 - 1));
}
async function sfCheckSession() {
  try {
    const r = await fetch('/api/me', { credentials: 'same-origin', cache: 'no-store' });
    if (r.status === 401) { sfSignedOut(/ended/.test((await r.json().catch(() => ({}))).error || '') ? 'ended' : ''); return; }
    if (r.ok) sfSessionEnds((await r.json()).session_ends);
  } catch { /* offline: the next check tries again */ }
}
async function sfSignOut() {
  await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
  sfSignedOut('out');
}
setInterval(sfCheckSession, 60000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) sfCheckSession(); });
addEventListener('pageshow', (ev) => { if (ev.persisted) sfCheckSession(); });
sfCheckSession();
