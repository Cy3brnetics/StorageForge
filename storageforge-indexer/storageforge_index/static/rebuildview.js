'use strict';
/* Rebuild tab: the saved configuration of each host, what changed between versions, and the reinstall script.
   Uses download() from deployview.js. */

const RB = { list: null, host: null, versions: [], version: null, detail: null };
const rbWhen = (t) => fmtTime(t);

async function loadRebuild() {
  const box = $('#rebuildbox');
  try { RB.list = await getJSON('/api/hostconfigs'); }
  catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); return; }
  if (RB.host) await pickRebuildHost(RB.host, RB.version); else renderRebuild();
}
async function pickRebuildHost(host, version) {
  RB.host = host;
  try {
    RB.versions = (await getJSON(`/api/hostconfigs?host=${encodeURIComponent(host)}`)).versions;
    RB.version = version || RB.versions[0]?.config_id || null;
    RB.detail = RB.version ? await getJSON(`/api/hostconfigs/${RB.version}`) : null;
  } catch (err) { $('#rebuildbox').replaceChildren(text('p', err.message, 'st-failed')); return; }
  renderRebuild();
}
function rbCounts(v) {
  return [`${v.mounts} mounts`, v.subvolumes ? `${v.subvolumes} subvolumes` : null, v.zfs_pools ? `${v.zfs_pools} ZFS pools` : null,
    `${v.shares} shares`, `${v.users} users`, `${v.links} symlinks`].filter(Boolean).join(' · ');
}
function renderRebuild() {
  const box = $('#rebuildbox');
  if (RB.host) { box.replaceChildren(...rbHostView()); return; }
  const { versions, not_captured: missing } = RB.list;
  if (!versions.length && !missing.length) { box.replaceChildren(text('p', 'No scanned hosts yet.', 'muted')); return; }
  const rows = versions.map((v) => {
    const open = button(v.host, () => pickRebuildHost(v.host), 'link');
    return el('li', { class: 'card' },
      el('div', { class: 'row' }, el('b', {}, open), v.complete ? '' : text('span', 'mount table only', 'pill local-only')),
      el('span', { class: 'muted small' }, rbWhen(v.captured_at)), el('span', { class: 'small' }, rbCounts(v)));
  });
  box.replaceChildren(
    el('div', { class: 'row end' }, versions.length ? button('Download all (.tar.gz)', () => download('/api/hostconfigs/bundle', 'hostconfigs.tar.gz'), 'btn sm') : ''),
    el('p', { class: 'muted small' }, `Up to ${RB.list.keep} versions are kept per host. Keep a download somewhere other than this machine.`),
    el('ol', { class: 'gitlist' }, ...rows),
    missing.length ? el('p', { class: 'muted small' }, `Nothing saved yet for ${missing.join(', ')}: scan them.`) : '');
}
const RB_KIND = { device: 'drive', network: 'network', derived: 'bind', zfs: 'ZFS', virtual: 'memory', rootfs: 'system disk', system: 'system disk' };
function rbHostView() {
  const d = RB.detail;
  const back = button('← All hosts', () => { RB.host = null; RB.version = null; RB.detail = null; loadRebuild(); }, 'btn ghost sm');
  if (!d) return [back, text('p', `Nothing saved for ${RB.host} yet. Scan it, and its configuration appears here.`, 'muted')];
  const pick = el('select', { 'aria-label': 'Version', onchange: () => pickRebuildHost(RB.host, Number(pick.value)) },
    ...RB.versions.map((v) => el('option', { value: String(v.config_id) }, rbWhen(v.captured_at))));
  pick.value = String(RB.version);
  const q = `?host=${encodeURIComponent(RB.host)}&id=${RB.version}`;
  const live = d.mounts.filter((m) => !['system', 'rootfs'].includes(m.kind));
  const out = [
    el('div', { class: 'row' }, back, el('b', {}, d.host)),
    el('div', { class: 'row' }, el('label', { class: 'field' }, text('span', 'Version'), pick),
      button('Reinstall script', () => download(`/api/hostconfigs/script${q}`, 'reinstall.sh'), 'btn pri sm'),
      button('Bundle (.tar.gz)', () => download(`/api/hostconfigs/bundle${q}`, 'hostconfig.tar.gz'), 'btn sm')),
    el('p', { class: 'muted small' }, 'After reinstalling: bash reinstall.sh reports what is missing, and sudo bash reinstall.sh --apply mounts it all. Passwords and keys are not saved, so the script tells you what to set.'),
    el('p', { class: 'small' }, rbCounts(d.summary)),
  ];
  if (!d.summary.complete) out.push(text('p', 'This version comes from a scan that did not read config files. Scan the host again to save its fstab and accounts.', 'st-warn'));
  if (d.unreadable.length) out.push(text('p', `The scan user could not read ${d.unreadable.join(', ')}, so these are not saved. Give it read access, or keep them yourself.`, 'st-warn'));
  out.push(text('h3', `Mounts (${live.length})`));
  out.push(el('ol', { class: 'gitlist' }, ...d.mounts.map((m) => el('li', { class: 'card' },
    el('div', { class: 'row' }, el('b', { class: 'mono small' }, m.target), text('span', RB_KIND[m.kind] || m.kind, 'pill unknown'),
      m.origin === 'live' ? text('span', 'not in fstab', 'pill local-only') : '', m.blocked ? text('span', 'needs credentials', 'pill broken') : ''),
    el('span', { class: 'muted small mono' }, `${m.spec}  ${m.fstype}  ${m.options}`)))));
  if (d.datasets.length) {
    out.push(text('h3', `ZFS datasets (${d.datasets.length})`));
    out.push(el('ul', { class: 'copies small mono' }, ...d.datasets.map((x) => el('li', {}, `${x.target}  ${x.name}`))));
  }
  if (d.exports.length) {
    out.push(text('h3', `Shares (${d.exports.length})`));
    out.push(el('ul', { class: 'copies small mono' }, ...d.exports.map((x) => el('li', {}, `${x.protocol}  ${x.path}  ${x.clients || ''}`))));
  }
  if (d.links.length) {
    out.push(text('h3', `Symlinks (${d.links.length})`));
    out.push(el('ul', { class: 'copies small mono' }, ...d.links.map((x) => el('li', {}, `${x.path} → ${x.target}`))));
  }
  const users = d.accounts.users || [];
  if (users.length) {
    out.push(text('h3', `Accounts (${users.length})`));
    out.push(el('ul', { class: 'copies small mono' }, ...users.map((u) => el('li', {}, `${u.name}  ${u.uid}:${u.gid}  ${u.home}`))));
  }
  out.push(text('h3', 'Config files'));
  out.push(d.files.length ? el('ul', { class: 'copies small mono' }, ...d.files.map((f) => el('li', {}, f))) : text('p', 'None saved.', 'muted'));
  out.push(text('h3', 'Changed in this version'));
  if (!d.previous) out.push(text('p', 'This is the first saved version.', 'muted'));
  else if (!d.changes.length) out.push(text('p', 'Nothing in the compared parts.', 'muted'));
  else for (const c of d.changes) {
    out.push(el('b', { class: 'small' }, c.name));
    out.push(text('pre', c.lines.join('\n') + (c.more ? `\n… ${c.more} more lines` : ''), 'small'));
  }
  return out;
}
