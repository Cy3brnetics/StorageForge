/* The console page (/console#<host>): a terminal on a host or VM (console.py). SSH by LAN or Tailscale, or the VM's serial
   console through its libvirt host. Output comes by long polling, what is typed goes by POST, so no WebSocket is needed.
   A session belongs to this account alone, is in the audit log, and is recorded in full when recording is on. */
'use strict';

const CON = { host: decodeURIComponent(location.hash.slice(1)), info: null, term: null, fit: null, sid: null, next: 0, stop: false, out: Promise.resolve(), pend: '' };
const $c = (id) => document.getElementById(id);

function b64ToBytes(b64) {
  const s = atob(b64), out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function bytesToB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function status(text, kind = '') { const el = $c('cons-status'); el.textContent = text; el.dataset.kind = kind; }

async function load() {
  if (!CON.host) { status('Open a console from a host in StorageForge.', 'err'); $c('cons-connect').disabled = true; return; }
  $c('cons-title').textContent = `Console: ${CON.host}`;
  document.title = `${CON.host} · Console · StorageForge`;
  try {
    CON.info = await getJSON(`/api/console/hosts/${encodeURIComponent(CON.host)}`);
  } catch (e) { status(e.message, 'err'); $c('cons-connect').disabled = true; return; }
  const sel = $c('cons-route');
  const opts = CON.info.routes.map((r) => ({ value: `ssh:${r.route}`, label: `SSH over ${r.route === 'lan' ? 'LAN' : 'Tailscale'} (${r.address})` }));
  if (CON.info.serial) opts.push({ value: 'serial:', label: `Serial console${CON.info.serial.via === 'local' ? ' (on this machine)' : ` (through ${CON.info.serial.host})`}` });
  sel.replaceChildren(...opts.map((o) => sfNode('option', { value: o.value }, o.label)));
  if (!opts.length) { status(`${CON.host} has no address from its scans, and is no VM StorageForge knows.`, 'err'); $c('cons-connect').disabled = true; }
  $c('cons-route-help').textContent = 'SSH uses the key bound to this host for "console" in the vault, and only a host key a scan confirmed. '
    + 'The serial console works when the network or SSH of a VM does not. Your password is asked for each session.';
  $c('cons-rec').hidden = !CON.info.recording;
  if (CON.info.viewer) {
    const v = CON.info.viewer, code = sfNode('code', {}, v.command);
    const copy = sfNode('button', { type: 'button', class: 'sf-btn ghost sm' }, 'Copy');
    copy.addEventListener('click', () => navigator.clipboard.writeText(v.command).then(() => notify('Copied')).catch(() => notify('Select it and copy', 'err')));
    $c('cons-viewer').replaceChildren(sfNode('strong', {}, 'Graphical console: '), code, ' ', copy,
      sfNode('span', { class: 'cons-help' }, ` In virt-viewer or Remote Viewer: native speed, clipboard and resizing. ${v.note.charAt(0).toUpperCase() + v.note.slice(1)}.`));
    $c('cons-viewer').hidden = false;
  }
}

function makeTerm() {
  if (CON.term) CON.term.dispose();
  CON.term = new Terminal({ cursorBlink: true, scrollback: 5000, convertEol: false, fontSize: 14,
    fontFamily: 'ui-monospace, "Cascadia Mono", "DejaVu Sans Mono", Menlo, monospace', allowProposedApi: false });
  CON.fit = new FitAddon.FitAddon();
  CON.term.loadAddon(CON.fit);
  CON.term.open($c('cons-term'));
  CON.fit.fit();
  CON.term.onData((d) => send(new TextEncoder().encode(d)));
  CON.term.onBinary((d) => send(Uint8Array.from(d, (ch) => ch.charCodeAt(0) & 0xff)));
  CON.term.onResize(({ cols, rows }) => { if (CON.sid) postJSON(`/api/console/sessions/${CON.sid}/resize`, { cols, rows }).catch(() => {}); });
}

// what is typed goes in order, in batches a few milliseconds apart, so a fast typist is not a request per key
let batch = [], timer = null;
function send(bytes) {
  if (!CON.sid) return;
  batch.push(bytes);
  if (!timer) timer = setTimeout(flush, 8);
}
function flush() {
  timer = null;
  const parts = batch; batch = [];
  if (!parts.length || !CON.sid) return;
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0; for (const p of parts) { all.set(p, at); at += p.length; }
  const sid = CON.sid;
  CON.out = CON.out.then(() => postJSON(`/api/console/sessions/${sid}/input`, { data: bytesToB64(all) }))
    .catch((e) => status(`Not sent: ${e.message}`, 'err'));
}

async function poll() {
  while (!CON.stop && CON.sid) {
    let r;
    try {
      r = await getJSON(`/api/console/sessions/${CON.sid}/output?after=${CON.next}&wait=20`);
    } catch (e) {
      if (e.status === 404) { ended('This console has ended.'); return; }
      status(`Reconnecting: ${e.message}`, 'err');
      await new Promise((res) => setTimeout(res, 2000));
      continue;
    }
    if (r.gap) CON.term.write('\r\n\x1b[2m[some output was missed while this page was away]\x1b[0m\r\n');
    if (r.data) CON.term.write(b64ToBytes(r.data));
    CON.next = r.next;
    if (r.closed) { ended(`Ended: ${r.closed}.`); return; }
  }
}

function ended(text) {
  CON.sid = null;
  status(text);
  $c('cons-connect').hidden = false; $c('cons-close').hidden = true; $c('cons-route').disabled = false;
}

async function connect() {
  const [kind, route] = $c('cons-route').value.split(':');
  makeTerm();
  status('Connecting…');
  $c('cons-connect').disabled = true;
  try {
    const res = await postJSON('/api/console/sessions', { host: CON.host, kind, route: route || 'auto', cols: CON.term.cols, rows: CON.term.rows });
    const s = await res.json();
    CON.sid = s.id; CON.next = 0; CON.stop = false;
    status(`Connected${s.kind === 'ssh' ? ` over ${s.route === 'lan' ? 'LAN' : 'Tailscale'} to ${s.address}` : ': serial console'}.${s.recording ? ' Recording.' : ''}`, 'ok');
    $c('cons-connect').hidden = true; $c('cons-close').hidden = false; $c('cons-route').disabled = true;
    CON.term.focus();
    poll();
  } catch (e) {
    status(e.message, 'err');
  } finally {
    $c('cons-connect').disabled = false;
  }
}

async function disconnect() {
  const sid = CON.sid;
  if (!sid) return;
  CON.stop = true;
  await api(`/api/console/sessions/${sid}`, { method: 'DELETE' }).catch(() => {});
  ended('Disconnected.');
}

// who may change recording (settings.manage) or read recordings (console.recordings): the panel shows what each may do
async function adminPanel() {
  const me = await sfMe().catch(() => null);
  const perms = new Set(me?.permissions || []);
  const canSet = perms.has('settings.manage'), canRead = perms.has('console.recordings');
  if (!canSet && !canRead) return;
  const body = $c('cons-admin-body'), parts = [];
  if (canSet) {
    const s = await getJSON('/api/console/settings');
    const rec = sfNode('input', { type: 'checkbox', id: 'cons-rec-on' }); rec.checked = s.record;
    const keep = sfNode('input', { type: 'number', min: 1, max: 3650, id: 'cons-keep', value: s.keep_days, class: 'cons-num' });
    const msg = sfNode('span', { role: 'status' });
    const save = sfNode('button', { type: 'button', class: 'sf-btn sm' }, 'Save');
    save.addEventListener('click', async () => {
      try {
        await api('/api/console/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ record: rec.checked, keep_days: Number(keep.value) }) });
        msg.textContent = 'Saved. It applies to sessions opened from now on.';
      } catch (e) { msg.textContent = e.message; }
    });
    parts.push(sfNode('p', {}, sfNode('label', { for: 'cons-rec-on' }, rec, ' Record every console session in full: what is typed, passwords too, and what is shown')),
      sfNode('p', {}, sfNode('label', { for: 'cons-keep' }, 'Keep recordings for ', keep, ' days'), ' ', save, ' ', msg),
      sfNode('p', { class: 'cons-help' }, 'Opening and closing every session is in the audit log either way.'));
  }
  if (canRead) {
    const { recordings } = await getJSON('/api/console/recordings');
    const rows = recordings.map((r) => sfNode('tr', {},
      sfNode('td', {}, fmtTime(r.started)), sfNode('td', {}, r.host || ''), sfNode('td', {}, r.user || ''),
      sfNode('td', {}, r.kind || ''), sfNode('td', {}, fmtBytes(r.bytes)),
      sfNode('td', {}, sfNode('a', { href: `/api/console/recordings/${encodeURIComponent(r.name)}`, download: r.name }, 'Download'))));
    parts.push(recordings.length
      ? sfNode('table', { class: 'cons-recs' }, sfNode('thead', {}, sfNode('tr', {}, ...['Started', 'Host', 'By', 'Kind', 'Size', ''].map((h) => sfNode('th', {}, h)))), sfNode('tbody', {}, ...rows))
      : sfNode('p', { class: 'cons-help' }, 'No recordings.'),
      sfNode('p', { class: 'cons-help' }, 'Recordings are asciicast files: play one with asciinema play FILE.'));
  }
  body.replaceChildren(...parts);
  $c('cons-admin').hidden = false;
}

$c('cons-connect').addEventListener('click', connect);
$c('cons-close').addEventListener('click', disconnect);
// closing the tab closes the session: keepalive lets the request outlive the page
window.addEventListener('pagehide', () => { if (CON.sid) sfOnLeave(`/api/console/sessions/${CON.sid}`, 'DELETE'); });
new ResizeObserver(() => { if (CON.fit) CON.fit.fit(); }).observe($c('cons-term'));
load();
adminPanel().catch(() => {});
