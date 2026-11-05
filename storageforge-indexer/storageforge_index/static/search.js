/* The search-only page: accounts that may search files but not see hosts land here instead of the app. */
'use strict';
const $id = (id) => document.getElementById(id);
const size = (n) => (n == null ? '' : fmtBytes(n));        // the kernel's, like every page
async function call(path, opts) {         // the kernel's api(): a 401 ends the page, and an error carries the server's message
  return (await api(path, opts)).json().catch(() => ({}));
}
call('/api/search/hosts').then(({ hosts }) => $id('shost').append(...hosts.map((h) => new Option(h, h)))).catch(() => {});

$id('sform').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const q = new URLSearchParams({ q: $id('sq').value.trim(), limit: '200' });
  if ($id('shost').value) q.set('host', $id('shost').value);
  const msg = $id('smsg');
  msg.textContent = 'Searching…';
  try {
    const { results } = await call(`/api/search?${q}`);
    msg.textContent = results.length ? `${results.length} found${results.length === 200 ? ' (showing the first 200)' : ''}` : 'Nothing found.';
    $id('sresults').replaceChildren(...results.map((r) => {
      const li = document.createElement('li');
      const path = document.createElement('code'); path.textContent = r.path;
      const what = document.createElement('span'); what.className = 'muted small'; what.textContent = ` ${r.host} · ${size(r.size)}`;
      li.append(path, what);
      return li;
    }));
  } catch (err) { msg.textContent = err.message; }
});

$id('spwform').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    await call('/api/me/password', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: $id('spwold').value, new_password: $id('spwnew').value }) });
    sfSignedOut('');
  } catch (err) { $id('spwmsg').textContent = err.message; }
});
