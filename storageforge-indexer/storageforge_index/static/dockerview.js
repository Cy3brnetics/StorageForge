'use strict';
/* Docker tab: compose stacks (running, stopped, stored on disk only), their containers and the host folders they use,
   unused volumes, and "which containers use this folder?". Loaded after gitview.js; uses the shared helpers. */

const DK = { hosts: [], usage: [], state: '', find: '', tableView: false };
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
  const totalStacks = DK.hosts.reduce((a, h) => a + h.stacks.length, 0);
  const runStacks = DK.hosts.reduce((a, h) => a + h.stacks.filter((s) => s.state === 'running').length, 0);
  const totalCts = DK.hosts.reduce((a, h) => a + (h.containers || 0), 0);
  const runCts = DK.hosts.reduce((a, h) => a + (h.running || 0), 0);
  const totalUnused = DK.hosts.reduce((a, h) => a + h.unused_volumes.length, 0);
  const totalUnusedBytes = DK.hosts.reduce((a, h) => a + h.unused_volumes.reduce((b, v) => b + (v.size || 0), 0), 0);
  const kpis = el('div', { class: 'pve-kpis' },
    el('div', { class: 'pve-kpi accent' }, text('span', 'Engines', 'pve-kpi-lbl'), el('b', {}, String(DK.hosts.length)), text('small', `${DK.hosts.filter((h) => h.engine).length} reachable`)),
    el('div', { class: `pve-kpi ${runStacks ? 'ok' : ''}` }, text('span', 'Compose Stacks', 'pve-kpi-lbl'), el('b', {}, `${runStacks} / ${totalStacks}`), text('small', 'running / total')),
    el('div', { class: `pve-kpi ${runCts ? 'ok' : ''}` }, text('span', 'Containers', 'pve-kpi-lbl'), el('b', {}, `${runCts} / ${totalCts}`), text('small', 'active / total')),
    el('div', { class: `pve-kpi ${totalUnused ? 'warn' : ''}` }, text('span', 'Unused Volumes', 'pve-kpi-lbl'), el('b', {}, String(totalUnused)), text('small', totalUnusedBytes ? fmtBytes(totalUnusedBytes) : 'none stale')));

  const listBox = el('div', { class: 'stack' });
  const stSel = el('select', { 'aria-label': 'Filter container stacks', onchange: () => { DK.state = stSel.value; drawDockerList(); } },
    new Option('All states', ''), new Option('Running', 'running'), new Option('Stopped / stored', 'stopped'), new Option('Docker socket risk', 'socket'));
  stSel.value = DK.state;
  const qIn = el('input', { type: 'search', value: DK.find, placeholder: 'Filter stacks, containers, images or paths…', 'aria-label': 'Filter stacks', autocomplete: 'off',
    oninput: () => { DK.find = qIn.value; drawDockerList(); } });
  const modeCards = button('Stack Cards', () => { DK.tableView = false; drawDockerList(); }, 'btn ghost sm');
  const modeTbl = button('Container Table', () => { DK.tableView = true; drawDockerList(); }, 'btn ghost sm');
  const bar = el('div', { class: 'pve-toolbar' }, modeCards, modeTbl, stSel, qIn);

  function matchStack(h, s) {
    if (DK.state === 'running' && s.state !== 'running') return false;
    if (DK.state === 'stopped' && s.state === 'running') return false;
    if (DK.state === 'socket' && !s.socket) return false;
    const q = DK.find.trim().toLowerCase();
    if (!q) return true;
    return `${h.host} ${s.project || ''} ${s.dir || ''} ${s.state} ${s.containers.map((c) => `${c.name} ${c.image || ''}`).join(' ')} ${s.services.map((sv) => `${sv.name} ${sv.image || ''}`).join(' ')}`.toLowerCase().includes(q);
  }

  function drawDockerList() {
    modeCards.setAttribute('aria-pressed', String(!DK.tableView));
    modeTbl.setAttribute('aria-pressed', String(DK.tableView));
    const kids = [];
    if (DK.tableView) {
      const trows = [];
      for (const h of DK.hosts) {
        const vols = Object.fromEntries(h.volumes.map((v) => [v.name, v]));
        for (const s of h.stacks.filter((x) => matchStack(h, x))) {
          if (s.containers.length) {
            for (const c of s.containers) {
              trows.push([text('span', h.host, 'mono'), s.project || 'standalone', text('b', c.name, 'mono'),
                text('span', c.state, `pill ${DK_STATE[c.state] || 'unknown'}`), text('span', c.image || '', 'mono small'),
                c.mounts.filter((m) => m.source || m.name).map((m) => mountText(m, vols)).join('; '),
                s.dir ? button('Move…', () => moveFrom(h.host, s.dir), 'btn ghost sm') : '']);
            }
          } else {
            for (const sv of s.services) {
              trows.push([text('span', h.host, 'mono'), s.project || 'stored', text('b', sv.name, 'mono'),
                text('span', s.state, `pill ${DK_STATE[s.state] || 'unknown'}`), text('span', sv.image || '', 'mono small'),
                sv.volumes.filter((v) => v.source).map((v) => `${v.source} → ${v.dest}`).join('; '),
                s.dir ? button('Move…', () => moveFrom(h.host, s.dir), 'btn ghost sm') : '']);
            }
          }
        }
      }
      kids.push(trows.length ? infTable(['Host', 'Stack', 'Container', 'State', 'Image', 'Mounts', ''], trows)
        : text('p', 'No containers match the current filters.', 'muted small'));
    }
    kids.push(...DK.hosts.map((h) => {
      const vols = Object.fromEntries(h.volumes.map((v) => [v.name, v]));
      const unusedBytes = h.unused_volumes.reduce((a, v) => a + (v.size || 0), 0);
      const head = el('div', { class: 'row' }, el('b', { class: 'mono' }, h.host),
        text('span', h.engine ? `${h.engine} · ${h.running}/${h.containers} running` : 'no engine reachable', 'muted'));
      const stacks = h.stacks.filter((s) => matchStack(h, s)).map((s) => {
        const pill = text('span', s.state, `pill ${DK_STATE[s.state] || 'unknown'}`);
        const skids = [el('div', { class: 'row' }, el('b', {}, s.project || 'Standalone containers'), pill,
          s.manager !== 'compose' ? text('span', s.manager, 'chip') : '', s.socket ? text('span', 'docker socket', 'pill broken') : '')];
        if (s.socket) skids.push(text('span', 'A container here mounts the Docker socket: it can control every container on the host (root-equivalent).', 'muted small'));
        if (s.dir) skids.push(el('span', { class: 'mono small' }, s.dir));
        if (s.error) skids.push(text('span', s.error, 'st-failed small'));
        if (s.containers.length) {
          skids.push(el('ul', { class: 'dklist' }, ...s.containers.map((c) => el('li', {},
            el('span', {}, el('b', {}, c.name), text('span', ` ${c.state} · ${c.image || ''}`, 'muted')),
            ...c.mounts.filter((m) => m.source || m.name).map((m) => el('span', { class: 'mono small' }, mountText(m, vols)))))));
        } else if (s.services.length) {
          skids.push(text('span', 'Not deployed. Services in the compose file:', 'muted small'),
            el('ul', { class: 'dklist' }, ...s.services.map((sv) => el('li', {}, el('span', {}, el('b', {}, sv.name), text('span', ` ${sv.image || ''}`, 'muted')),
              ...sv.volumes.filter((v) => v.source).map((v) => el('span', { class: 'mono small' },
                `${v.source} → ${v.dest}${v.rw ? '' : ' (read-only)'}${v.unresolved ? ' (uses a variable)' : ''}`))))));
        }
        if (s.dir) skids.push(el('div', { class: 'row end' }, button('Move…', () => moveFrom(h.host, s.dir), 'btn ghost sm')));
        return el('details', { class: 'card dkstack', open: s.state === 'running' && DK.hosts.length === 1 && h.stacks.length < 6 },
          el('summary', {}, `${s.project || 'standalone'} · ${s.state}${s.containers.length ? ` · ${s.running}/${s.containers.length}` : ''}`), ...skids);
      });
      const unused = h.unused_volumes.length ? el('details', { class: 'card' },
        el('summary', {}, `${h.unused_volumes.length} unused volume${h.unused_volumes.length === 1 ? '' : 's'}${unusedBytes ? ` · ${fmtBytes(unusedBytes)}` : ''}`),
        text('p', 'No container uses these. Remove one with docker volume rm <name> on the host once you are sure (or docker volume prune).', 'muted small'),
        el('ul', { class: 'dklist' }, ...h.unused_volumes.sort((a, b) => (b.size || 0) - (a.size || 0)).map((v) =>
          el('li', {}, el('span', { class: 'mono small' }, `${v.name}${v.size ? ` · ${fmtBytes(v.size)}` : ''}${v.project ? ` · from ${v.project}` : ''}`))))) : '';
      return el('section', { class: 'stack dkhost' }, head, ...stacks, unused);
    }));
    listBox.replaceChildren(...kids);
  }
  drawDockerList();
  const who = whoUses();
  box.replaceChildren(kpis, bar, who, listBox);
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
