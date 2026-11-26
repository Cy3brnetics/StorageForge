'use strict';
/* Standalone Administration & Vault window (/admin): manages Keys, Enclave/Agent/SSH CA,
   Secrets & Platforms, Accounts & Roles, and Audit Log & Backups cleanly in focused sections. */

const AD_SECS = {
  keys: ['Keys & Host Bindings', 'Generate keys inside the encrypted vault, install public keys onto hosts, and bind allowed actions.'],
  enclave: ['Enclave, Agent & SSH CA', 'Vault step-up verification, StorageForge host agents, and short-lived SSH certificates.'],
  secrets: ['Secrets & Platforms', 'Plan-step vault secrets and Proxmox VE / PBS / PDM platform API connections.'],
  users: ['User Management', 'Manage user accounts, one-time invite links, password resets and role permissions.'],
  audit: ['Audit Log & Backups', 'Tamper-evident audit chain verification and StorageForge essentials backups.'],
  maintenance: ['Controller maintenance', 'Configuration, upgrades and service operations.'],
  account: ['My Password', 'Change the password for your signed-in account.'],
};

const AD = { sec: 'keys', booted: false };

function adAllowed(sec) {
  if (sec === 'keys' || sec === 'enclave' || sec === 'secrets') return can('keys.view');
  if (sec === 'users') return can('users.manage') || can('roles.manage');
  if (sec === 'audit') return can('audit.view') || can('audit.verify') || can('backups.view');
  return true;
}

function adOpen(sec, push = true) {
  if (!AD_SECS[sec] || !adAllowed(sec)) {
    sec = Object.keys(AD_SECS).find(adAllowed) || 'account';
  }
  AD.sec = sec;
  document.querySelectorAll('#adnav button').forEach((b) => {
    const on = b.dataset.sec === sec;
    if (on) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });
  for (const id of Object.keys(AD_SECS)) {
    const elSec = $(`#ad-sec-${id}`);
    if (elSec) elSec.hidden = id !== sec;
  }
  const [title, sub] = AD_SECS[sec];
  $('#adtitle').textContent = title;
  $('#adsub').textContent = sub;
  if (push && AD.booted) sfPushHash(sfFormatHash([sec]));
  if (sec === 'keys' || sec === 'enclave' || sec === 'secrets') loadKeys();
  if (sec === 'users') loadUsers();
  if (sec === 'audit') loadAudit();
  if (sec === 'maintenance' && typeof loadMaintenance === 'function') loadMaintenance();
}

document.querySelectorAll('#adnav button').forEach((b) => b.addEventListener('click', () => adOpen(b.dataset.sec)));

sfPaletteSource(() => {
  if (!ME) return [];
  return Object.entries(AD_SECS).filter(([id]) => adAllowed(id)).map(([id, [title]]) => ({
    label: `Admin: ${title}`,
    hint: 'Admin section',
    run: () => adOpen(id),
  }));
});

(async function boot() {
  try {
    const me = await sfMe();
    setMe(me);
    if (me.site) document.title = `${me.site} · Admin & Vault · StorageForge`;
    document.querySelectorAll('#adnav button').forEach((b) => { b.hidden = !adAllowed(b.dataset.sec); });
    const p = sfParseHash();
    const initial = location.pathname === '/admin/users' ? 'users' : (p.parts[0] || p.q.get('tab') || 'keys');
    adOpen(initial, false);
    if (typeof loadAdminSummary === 'function') loadAdminSummary();
    AD.booted = true;
    sfReplaceHash(sfFormatHash([AD.sec]));
    window.addEventListener('hashchange', () => {
      const next = sfParseHash().parts[0] || 'keys';
      if (next !== AD.sec) adOpen(next, false);
    });
    document.addEventListener('sf:scan', () => {
      if (!AD.booted || document.querySelector('dialog[open]')) return;
      if (typeof loadAdminSummary === 'function') loadAdminSummary();
      if (AD.sec === 'audit') loadAudit();
    });
  } catch (err) {
    if (!/Sign in/.test(err.message)) notify(err.message, 'error');
  } finally {
    document.documentElement.dataset.routeReady = '1';
  }
})();
