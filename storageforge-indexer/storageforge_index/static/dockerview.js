'use strict';
/* Docker tab: compose stacks (running, stopped, stored on disk only), their containers and the host folders they use,
   unused volumes, and "which containers use this folder?". Loaded after gitview.js; uses the shared helpers. */

const DK = { hosts: [], usage: [] };
const DK_STATE = { running: 'protected', 'partly running': 'local-only', stopped: 'unknown', stored: 'unknown',
                   unreadable: 'broken', standalone: 'unknown' };

async function loadDocker() {
  const box = $('#dockerbox');
  const qs = S.host ? `?host=${encodeURIComponent(S.host)}` : '';
  try {
    const [{ hosts }, { usage }] = await Promise.all([getJSON('/api/docker' + qs), getJSON('/api/docker/usage' + qs)]);
    DK.hosts = hosts; DK.usage = usage;
  } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); return; }
  renderDocker();
}
function mountText(m, vols) {
  const v = m.name && vols[m.name];
  const from = m.type === 'volume' ? `volume ${m.name.length > 24 ? m.name.slice(0, 12) + '…' : m.name}${v && v.size ? ` (${fmtBytes(v.size)})` : ''}` : m.source;
  return `${from} → ${m.dest}${m.rw ? '' : ' (read-only)'}`;
}
function renderDocker() {
  const box = $('#dockerbox');
  if (!DK.hosts.length) { box.replaceChildren(text('p', 'No container engines or compose files yet: they are read from the next scan of each host.', 'muted')); return; }
  const who = whoUses();
  box.replaceChildren(who, ...DK.hosts.map((h) => {
    const vols = Object.fromEntries(h.volumes.map((v) => [v.name, v]));
    const unusedBytes = h.unused_volumes.reduce((a, v) => a + (v.size || 0), 0);
    const head = el('div', { class: 'row' }, el('b', { class: 'mono' }, h.host),
      text('span', h.engine ? `${h.engine} · ${h.running}/${h.containers} running` : 'no engine reachable', 'muted'));
    const stacks = h.stacks.map((s) => {
      const pill = text('span', s.state, `pill ${DK_STATE[s.state] || 'unknown'}`);
      const kids = [el('div', { class: 'row' }, el('b', {}, s.project || 'Standalone containers'), pill,
        s.manager !== 'compose' ? text('span', s.manager, 'chip') : '', s.socket ? text('span', 'docker socket', 'pill broken') : '')];
      if (s.socket) kids.push(text('span', 'A container here mounts the Docker socket: it can control every container on the host (root-equivalent).', 'muted small'));
      if (s.dir) kids.push(el('span', { class: 'mono small' }, s.dir));
      if (s.error) kids.push(text('span', s.error, 'st-failed small'));
      if (s.containers.length) {
        kids.push(el('ul', { class: 'dklist' }, ...s.containers.map((c) => el('li', {},
          el('span', {}, el('b', {}, c.name), text('span', ` ${c.state} · ${c.image || ''}`, 'muted')),
          ...c.mounts.filter((m) => m.source || m.name).map((m) => el('span', { class: 'mono small' }, mountText(m, vols)))))));
      } else if (s.services.length) {
        kids.push(text('span', 'Not deployed. Services in the compose file:', 'muted small'),
          el('ul', { class: 'dklist' }, ...s.services.map((sv) => el('li', {}, el('span', {}, el('b', {}, sv.name), text('span', ` ${sv.image || ''}`, 'muted')),
            ...sv.volumes.filter((v) => v.source).map((v) => el('span', { class: 'mono small' },
              `${v.source} → ${v.dest}${v.rw ? '' : ' (read-only)'}${v.unresolved ? ' (uses a variable)' : ''}`))))));
      }
      if (s.dir) kids.push(el('div', { class: 'row end' }, button('Move…', () => moveFrom(h.host, s.dir), 'btn ghost sm')));
      return el('details', { class: 'card dkstack', open: s.state === 'running' && DK.hosts.length === 1 && h.stacks.length < 6 },
        el('summary', {}, `${s.project || 'standalone'} · ${s.state}${s.containers.length ? ` · ${s.running}/${s.containers.length}` : ''}`), ...kids);
    });
    const unused = h.unused_volumes.length ? el('details', { class: 'card' },
      el('summary', {}, `${h.unused_volumes.length} unused volume${h.unused_volumes.length === 1 ? '' : 's'}${unusedBytes ? ` · ${fmtBytes(unusedBytes)}` : ''}`),
      text('p', 'No container uses these. Remove one with docker volume rm <name> on the host once you are sure (or docker volume prune).', 'muted small'),
      el('ul', { class: 'dklist' }, ...h.unused_volumes.sort((a, b) => (b.size || 0) - (a.size || 0)).map((v) =>
        el('li', {}, el('span', { class: 'mono small' }, `${v.name}${v.size ? ` · ${fmtBytes(v.size)}` : ''}${v.project ? ` · from ${v.project}` : ''}`))))) : '';
    return el('section', { class: 'stack dkhost' }, head, ...stacks, unused);
  }));
}
function whoUses() {
  const host = el('select', { 'aria-label': 'Host' }, ...DK.hosts.map((h) => new Option(h.host, h.host)));
  if (S.host) host.value = S.host;
  const path = el('input', { type: 'text', class: 'mono', placeholder: '/mnt/data01/media', 'aria-label': 'Folder' });
  const out = el('ul', { class: 'dklist' });
  const form = el('form', { class: 'stack card' }, el('b', {}, 'Which containers use a folder?'),
    el('div', { class: 'row' }, host, path, el('button', { type: 'submit', class: 'btn sm' }, 'Check')), out);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (!path.value.trim()) return;
    try {
      const { usage } = await getJSON(`/api/docker/usage?host=${encodeURIComponent(host.value)}&path=${encodeURIComponent(path.value.trim())}`);
      out.replaceChildren(...(usage.length ? usage.map((u) => el('li', {}, el('span', {}, el('b', {}, u.container), text('span', ` ${u.state}${u.stack ? ' · ' + u.stack : ''}`, 'muted')),
        el('span', { class: 'mono small' }, `${u.path} → ${u.dest}${u.rw ? '' : ' (read-only)'}`))) : [text('li', 'No container uses it.', 'muted')]));
    } catch (err) { out.replaceChildren(text('li', err.message, 'st-failed')); }
  });
  return form;
}
/* topology: containers whose folders sit on this mount point (the innermost mount holding each folder) */
function containersOn(host, target, mounts) {
  const under = (p, r) => r === '/' || p === r || p.startsWith(r + '/');
  return DK.usage.filter((u) => u.host === host && under(u.path, target)
    && !mounts.some((m) => m.length > target.length && under(m, target) && under(u.path, m)));
}
