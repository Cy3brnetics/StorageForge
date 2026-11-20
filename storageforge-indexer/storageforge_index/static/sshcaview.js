'use strict';
/* Keys → SSH certificates: the certificate authority, which hosts StorageForge logs in to with a certificate, what was issued, and
   revoking. Nothing here reaches a host: a button that changes one stages a change plan, and Changes runs it. */

const caMsg = (msg, ok, plan) => {
  const m = $('#sshcamsg'); m.hidden = false; m.className = ok ? 'st-ok' : 'st-failed';
  m.replaceChildren(msg, ...(plan ? [' ', button('Open Changes', () => showTab('changes'), 'btn ghost sm')] : []));
};
const caDo = async (fn) => { try { await fn(); } catch (err) { caMsg(err.message, false); } };
const caStage = (body, what) => caDo(async () => {
  const r = await (await postJSON('/api/keys/ssh-ca/plan', body)).json();
  if (!r.plan_id) { caMsg('No host is given certificates yet, so there is nowhere to send it.', false); return; }
  caMsg(`${what}: ${r.tasks} step${r.tasks === 1 ? '' : 's'} staged in plan #${r.plan_id}. Nothing has run yet.`, true, true);
});

function caHostRow(h, manage) {
  const li = document.createElement('li');
  const cert = h.host_certificate;
  li.append(text('span', h.host), text('span', cert ? `host certificate until ${fmtDate(cert.expires_at)}${cert.renew ? ', ends soon' : ''}` : 'no host certificate', 'm'));
  const toggle = (what, label) => {
    const b = button(`${label}: ${h[what] ? 'on' : 'off'}`, () => caDo(async () => {
      await api(`/api/keys/ssh-ca/hosts/${encodeURIComponent(h.host)}`, jsonOpts('PUT', { console: h.console, scan: h.scan, [what]: !h[what] }));
      loadSshCa();
    }), 'btn ghost sm');
    b.setAttribute('aria-pressed', String(h[what]));
    b.disabled = !manage;
    return b;
  };
  li.append(toggle('console', 'Console'), toggle('scan', 'Scans'));
  if (manage) li.append(button(cert ? 'New host certificate' : 'Issue host certificate', () => caDo(async () => {
    const r = await (await postJSON(`/api/keys/ssh-ca/hosts/${encodeURIComponent(h.host)}/certificate`, {})).json();
    caMsg(`Host certificate for ${r.principals.join(', ')} issued. The trust step installs it on ${r.host}.`, true);
    loadSshCa();
  }), 'btn ghost sm'));
  if (can('plans.edit')) li.append(button('Stage trust', () => caStage({ kind: 'trust', hosts: [h.host], host_cert: !!cert }, `Trust the CA on ${h.host}`), 'btn ghost sm'));
  return li;
}

function caCertRow(c, manage) {
  const li = document.createElement('li');
  const state = c.revoked_at ? `revoked by ${c.revoked_by}` : c.ended ? 'ended' : 'valid';
  li.append(text('span', `${c.kind === 'host' ? 'host' : c.purpose} · ${c.host} · ${c.principals.join(', ')}`),
    text('span', `serial ${c.serial} · issued by ${c.issued_by} `, 'm'), timeEl(c.issued_at), text('span', ' · ends ', 'm'), timeEl(c.expires_at),
    text('span', state, c.revoked_at ? 'st-failed' : c.ended ? 'muted' : 'st-ok'));
  if (manage && !c.revoked_at && !c.ended) li.append(button('Revoke', () => caDo(async () => {
    if (!(await confirmDialog({ title: `Revoke certificate ${c.serial}?`, confirm: 'Revoke', danger: true,
      body: `It stops logging in to ${c.host} once the revocation list has been installed there: stage the list afterwards. It cannot be taken back.` }))) return;
    const r = await (await postJSON(`/api/keys/ssh-ca/certificates/${c.serial}/revoke`, {})).json();
    caMsg(`Revoked. The revocation list is now version ${r.krl_version}: stage it for the hosts.`, true);
    loadSshCa();
  }), 'btn ghost sm danger'));
  return li;
}

async function loadSshCa() {
  const box = $('#sshcabox');
  if (!box) return;
  try {
    const d = await getJSON('/api/keys/ssh-ca');
    const manage = can('keys.manage');
    if (!d.ca) {
      box.replaceChildren(text('p', 'There is no SSH CA yet.', 'muted'), manage ? button('Make the SSH CA', () => caDo(async () => {
        const r = await (await postJSON('/api/keys/ssh-ca', {})).json();
        caMsg(`The SSH CA was made in the vault (${r.fingerprint}).`, true);
        loadKeys();
      }), 'btn sm') : '');
      return;
    }
    const pub = text('code', d.ca.public_key, 'pub');
    const hosts = document.createElement('ol'); hosts.className = 'list';
    hosts.replaceChildren(...d.hosts.map((h) => caHostRow(h, manage)));
    if (!d.hosts.length) hosts.replaceChildren(text('li', 'No hosts yet.', 'muted'));
    const certs = d.certificates.length
      ? sfMoreList(d.certificates, (c) => caCertRow(c, manage), { limit: 8, label: 'certificates', tag: 'ol', className: 'list' })
      : text('p', 'No certificates issued yet.', 'muted');
    const krl = document.createElement('p'); krl.className = 'muted';
    krl.append(`Revocation list version ${d.krl_version}, naming ${d.revoked} certificate${d.revoked === 1 ? '' : 's'}. `);
    if (can('plans.edit')) krl.append(button('Stage the list for the hosts', () => caStage({ kind: 'krl' }, 'Revocation list'), 'btn ghost sm'));
    box.replaceChildren(
      text('p', `CA key ${d.ca.key} · ${d.ca.fingerprint}`, 'm'), pub,
      button('Copy public key', async (ev) => {
        try { await navigator.clipboard.writeText(d.ca.public_key); ev.target.textContent = 'Copied'; }
        catch { getSelection().selectAllChildren(pub); }
      }, 'btn ghost sm'),
      text('h4', 'Hosts'),
      text('p', `Console and Scans: StorageForge logs in with a certificate made for that one login (${Math.round(d.seconds.console / 60)} minutes for a console, ${Math.round(d.seconds.scan / 60)} for a scan). The host has to trust the CA first: Stage trust writes the plan step. A host that does not trust it yet is still reached with the key, as before.`, 'muted'),
      hosts, text('h4', 'Certificates'), certs, krl);
  } catch (err) { box.replaceChildren(text('p', err.message, 'muted')); }
}
