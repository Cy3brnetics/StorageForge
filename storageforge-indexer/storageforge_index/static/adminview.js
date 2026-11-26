'use strict';
/* Keys, bindings, audit log, backups, accounts, invites and roles for the /admin window.
   Extracted cleanly from app.js so all administration workflows live in one dedicated workspace. */

function keyMsg(msg, ok) {
  const m = $('#instmsg');
  if (!m) return;
  m.hidden = false;
  m.textContent = msg;
  m.className = ok ? 'st-ok' : 'st-failed';
}

const AD_STATE = { keys: [], bindings: [], users: null, roles: null, entries: [], backups: null };

function renderAdminKpis() {
  const box = $('#ad-kpis');
  if (!box) return;
  const tile = (val, lbl, sub, sec, cls = '') => {
    const b = el('button', { type: 'button', class: `pve-kpi ${cls}`, onclick: () => typeof adOpen === 'function' && adOpen(sec) },
      text('span', lbl, 'pve-kpi-lbl'), el('b', {}, val), text('small', sub));
    return b;
  };
  const items = [];
  if (can('keys.view')) {
    items.push(tile(String(AD_STATE.keys.length), 'Vault Keys', `${AD_STATE.bindings.length} host bindings`, 'keys', 'accent'));
  }
  if (can('users.manage') || can('roles.manage')) {
    const uCount = AD_STATE.users == null ? '—' : String(AD_STATE.users);
    const rCount = AD_STATE.roles == null ? '—' : `${AD_STATE.roles} roles`;
    items.push(tile(uCount, 'Users & Roles', rCount, 'users'));
  }
  if (can('audit.view')) {
    const bad = AD_STATE.entries.filter((a) => a.outcome !== 'ok').length;
    items.push(tile(String(AD_STATE.entries.length), 'Audit Events', bad ? `${bad} failed / denied` : 'recent events ok', 'audit', bad ? 'warn' : 'ok'));
  }
  if (can('backups.view') && AD_STATE.backups) {
    const b = AD_STATE.backups;
    const lbl = b.external ? 'PG' : String((b.backups || []).length);
    const sub = b.external ? 'external pg_dump' : (b.backups?.[0] ? `last ${fmtAgo(b.backups[0].created)}` : 'none yet');
    items.push(tile(lbl, 'Essentials Backups', sub, 'audit', b.backups?.[0] || b.external ? 'ok' : 'warn'));
  }
  box.hidden = !items.length;
  box.replaceChildren(...items);
}

async function loadAdminSummary() {
  const jobs = [];
  if (can('keys.view')) jobs.push(getJSON('/api/keys').then((r) => { AD_STATE.keys = r.keys || []; AD_STATE.bindings = r.bindings || []; }).catch(() => {}));
  if (can('users.manage')) jobs.push(getJSON('/api/users').then((r) => { AD_STATE.users = (r.users || []).length; }).catch(() => {}));
  if (can('roles.manage')) jobs.push(getJSON('/api/roles').then((r) => { AD_STATE.roles = (r.roles || []).length; }).catch(() => {}));
  if (can('audit.view')) jobs.push(getJSON('/api/audit?limit=100').then((r) => { AD_STATE.entries = r.entries || []; }).catch(() => {}));
  if (can('backups.view')) jobs.push(getJSON('/api/backups').then((r) => { AD_STATE.backups = r; }).catch(() => {}));
  await Promise.all(jobs);
  renderAdminKpis();
}

function renderBindingsList() {
  const bindingsEl = $('#bindings');
  if (!bindingsEl) return;
  const actFilter = $('#ad-bindact')?.value || '';
  const q = ($('#ad-bindfind')?.value || '').trim().toLowerCase();
  const filtered = AD_STATE.bindings.filter((b) => {
    const acts = b.actions.split(',');
    if (actFilter && !acts.includes(actFilter)) return false;
    return !q || `${b.user}@${b.pattern}:${b.port} ${b.key} ${b.kind} ${b.actions}`.toLowerCase().includes(q);
  });
  bindingsEl.replaceChildren(...filtered.map((b) => {
    const li = document.createElement('li');
    const acts = b.actions.split(',');
    li.append(text('span', `${b.user}@${b.pattern}:${b.port} → ${b.key}`), text('span', `${b.kind} · ${b.actions}`, 'm'));
    if (b.kind === 'host') li.append(button('Scan now', () => queueScan(b.pattern), 'btn ghost sm'));
    if (!acts.includes('deploy')) {
      const toggle = (act, label) => {
        const on = acts.includes(act);
        const next = on ? acts.filter((a) => a !== act && !(act === 'scan' && a === 'checksum')) : [...acts, act, ...(act === 'checksum' && !acts.includes('scan') ? ['scan'] : [])];
        const btn = button(`${label}: ${on ? 'on' : 'off'}`, () => setBindingActions(b, next), 'btn ghost sm');
        btn.setAttribute('aria-pressed', String(on));
        if (!next.length) { btn.disabled = true; btn.title = 'A binding allows something: Unbind it instead'; }
        if (act === 'console' && !can('console.open')) { btn.disabled = true; btn.title = 'Your account cannot open consoles'; }
        return btn;
      };
      li.append(toggle('checksum', 'Checksums'), toggle('console', 'Console'));
    }
    li.append(button('Unbind', () => removeVaultItem(`/api/bindings/${b.binding_id}`, `Stop using ${b.key} for ${b.user}@${b.pattern}?`), 'btn ghost sm danger'));
    return li;
  }));
  if (!filtered.length) bindingsEl.replaceChildren(text('li', AD_STATE.bindings.length ? 'No bindings match the filter.' : 'No bindings yet.', 'muted'));
}

function renderAuditList() {
  const auditEl = $('#audit');
  if (!auditEl) return;
  const out = $('#ad-auditout')?.value || '';
  const q = ($('#ad-auditfind')?.value || '').trim().toLowerCase();
  const filtered = AD_STATE.entries.filter((a) => {
    if (out && a.outcome !== out) return false;
    return !q || `${a.action} ${a.outcome} ${a.actor} ${a.host || ''} ${a.key || ''} ${JSON.stringify(a.detail || {})}`.toLowerCase().includes(q);
  });
  auditEl.replaceChildren(...filtered.map((a) => {
    const li = document.createElement('li');
    li.append(
      text('span', `${a.action} · ${a.outcome}${a.host ? ' · ' + a.host : ''}`, `st-${a.outcome}`),
      Object.assign(text('span', `${fmtTime(a.ts, { seconds: true })} · ${a.actor}${a.key ? ' · ' + a.key : ''}`, 'm'), { title: fmtUtc(a.ts) }),
      ...(Object.keys(a.detail).length ? [text('span', JSON.stringify(a.detail), 'm')] : []),
    );
    return li;
  }));
  if (!filtered.length) auditEl.replaceChildren(text('li', AD_STATE.entries.length ? 'No audit entries match the filter.' : 'No audit entries yet.', 'muted'));
}

async function loadKeys(select) {
  if (typeof loadEnclave === 'function') loadEnclave();
  if (typeof loadAgents === 'function') loadAgents();
  const keysEl = $('#keys');
  if (!keysEl) return;
  try {
    const { keys, bindings } = await getJSON('/api/keys');
    AD_STATE.keys = keys || [];
    AD_STATE.bindings = bindings || [];
    renderAdminKpis();
    const sel = $('#instkey');
    if (sel) {
      const keep = select || sel.value;
      sel.replaceChildren(...keys.map((k) => new Option(`${k.name} · ${k.type}`, k.name)));
      if (keep) sel.value = keep;
    }
    keysEl.replaceChildren(...keys.map((k) => {
      const li = document.createElement('li');
      const pub = text('code', k.public_key, 'pub');
      li.append(
        text('span', `${k.name} · ${k.type} · ${k.origin} · ${k.bindings} binding${k.bindings === 1 ? '' : 's'}`),
        text('span', k.fingerprint, 'm'),
        pub,
        button('Copy public key', async (ev) => {
          try { await navigator.clipboard.writeText(k.public_key); ev.target.textContent = 'Copied'; }
          catch { getSelection().selectAllChildren(pub); }
        }, 'btn ghost sm'),
        k.bindings ? '' : button('Remove', () => removeVaultItem(`/api/keys/${encodeURIComponent(k.name)}`, `Remove key ${k.name}? It cannot be recovered.`), 'btn ghost sm danger'),
      );
      return li;
    }));
    if (!keys.length) keysEl.replaceChildren(text('li', 'No keys yet. Generate one above.', 'muted'));
    const bk = $('#bindkey');
    if (bk) {
      const bkeep = bk.value;
      bk.replaceChildren(...keys.map((k) => new Option(`${k.name} · ${k.type}`, k.name)));
      if (bkeep) bk.value = bkeep;
    }
    if ($('#bindconsole')) {
      $('#bindconsole').disabled = !can('console.open');
      $('#bindconsole').title = can('console.open') ? '' : 'Your account cannot open consoles, so it cannot allow one';
    }
    if ($('#instconsole') && $('#bindconsole')) {
      $('#instconsole').disabled = $('#bindconsole').disabled;
      $('#instconsole').title = $('#bindconsole').title;
    }
    renderBindingsList();
  } catch (err) {
    keysEl.replaceChildren(text('li', err.message, 'muted'));
  }
  if (typeof loadSshCa === 'function') loadSshCa();
  if (typeof loadSecrets === 'function') loadSecrets();
  if (typeof loadPlatforms === 'function') loadPlatforms();
}

async function setBindingActions(b, actions) {
  if (actions.includes('console') && !b.actions.split(',').includes('console')
      && !(await confirmDialog({
        title: `Allow the web console as ${b.user}@${b.pattern}?`,
        confirm: 'Allow the console',
        body: `Anyone who may open consoles gets a terminal as ${b.user} there, able to do whatever ${b.user} can. Every session is in the audit log.`,
      }))) return;
  try { await api(`/api/bindings/${b.binding_id}`, jsonOpts('PUT', { actions })); loadKeys(); }
  catch (err) { keyMsg(err.message, false); }
}

async function removeVaultItem(path, question) {
  if (!(await confirmDialog({ title: question, confirm: 'Remove', danger: true }))) return;
  try { await api(path, { method: 'DELETE' }); loadKeys(); }
  catch (err) { keyMsg(err.message, false); }
}

const untilText = (t) => fmtTime(t);
function showLink(what, token) {
  $('#linkwhat').textContent = what;
  $('#linkurl').value = `${location.origin}/enroll#${token}`;
  $('#linkbox').hidden = false;
  $('#linkurl').select();
}

let CATALOG = [];
async function loadUsers() {
  const usersCard = $('#userscard'), rolesCard = $('#rolescard');
  if (!usersCard || !rolesCard) return;
  usersCard.hidden = !can('users.manage');
  rolesCard.hidden = !can('roles.manage');
  if (usersCard.hidden && rolesCard.hidden) return;
  try {
    const { roles, catalog } = await getJSON('/api/roles');
    CATALOG = catalog;
    AD_STATE.roles = roles.length;
    const mine = roles.filter((r) => r.permissions.every((p) => ME.permissions.includes(p)));
    if (can('roles.manage')) renderRoles(roles, mine);
    if (!can('users.manage')) { renderAdminKpis(); return; }
    for (const sel of [$('#newuserrole'), $('#inviterole')]) {
      const was = sel.value;
      sel.replaceChildren(...mine.map((r) => new Option(r.name, r.name)));
      sel.value = was && mine.some((r) => r.name === was) ? was : 'viewer';
    }
    const [{ users }, { invites, now }] = await Promise.all([getJSON('/api/users'), getJSON('/api/invites')]);
    AD_STATE.users = users.length;
    renderAdminKpis();
    const change = async (u, body) => {
      try { await api(`/api/users/${encodeURIComponent(u)}`, jsonOpts('PUT', body)); }
      catch (err) { $('#usermsg').textContent = err.message; }
      loadUsers();
    };
    $('#userlist').replaceChildren(...users.map((u) => {
      const role = el('select', { 'aria-label': `Role of ${u.username}`, onchange: () => change(u.username, { role: role.value }) },
        ...roles.map((r) => new Option(r.name, r.name)));
      role.value = u.role;
      return el('li', {}, text('span', `${u.username}${u.disabled_at ? ' · disabled' : ''}`),
        el('div', { class: 'row wrap' },
          role,
          button(u.disabled_at ? 'Enable' : 'Disable', () => change(u.username, { disabled: !u.disabled_at }), 'btn ghost sm'),
          button('Password reset link', async () => {
            try { showLink(`New password for ${u.username}, good for one day:`, (await (await postJSON(`/api/users/${encodeURIComponent(u.username)}/reset-link`, {})).json()).token); }
            catch (err) { $('#usermsg').textContent = err.message; }
          }, 'btn ghost sm'),
          button('Remove', async () => {
            if (!(await confirmDialog({ title: `Remove account ${u.username}?`, confirm: 'Remove account', danger: true }))) return;
            try { await api(`/api/users/${encodeURIComponent(u.username)}`, { method: 'DELETE' }); }
            catch (err) { $('#usermsg').textContent = err.message; }
            loadUsers();
          }, 'btn ghost sm danger')));
    }));
    $('#invitelist').replaceChildren(...invites.map((i) => {
      const open = !i.used_at && !i.revoked_at && i.expires_at > now;
      const state = i.used_at ? `used by ${i.used_by}` : i.revoked_at ? 'revoked' : open ? `open until ${untilText(i.expires_at)}` : 'expired';
      const what = i.reset_user ? `Password reset for ${i.reset_user}` : `${i.role}${i.note ? ` · ${i.note}` : ''}`;
      return el('li', {}, text('span', what), text('span', `${state} · made by ${i.created_by}`, 'm'),
        ...(open ? [button('Revoke', async () => {
          try { await api(`/api/invites/${i.invite_id}`, { method: 'DELETE' }); }
          catch (err) { $('#invitemsg').textContent = err.message; }
          loadUsers();
        }, 'btn ghost sm danger')] : []));
    }));
  } catch (err) {
    $('#usermsg').textContent = err.message;
  }
}

let editingRole = null;
function checkRoleRisk() {
  const on = (p) => !!document.querySelector(`#roleperms input[value="${p}"]:checked`);
  $('#rolerisk').hidden = !(on('plans.edit') && (on('deploy.apply') || on('deploy.destructive')));
}
function openRoleForm(role) {
  editingRole = role ? role.name : null;
  $('#roleform').hidden = false;
  $('#rolename').value = role ? role.name : '';
  $('#rolename').disabled = !!role;
  $('#roledesc').value = role ? role.description : '';
  $('#rolemsg').textContent = '';
  $('#roleperms').replaceChildren(...CATALOG.map((g) => el('fieldset', { class: 'permgroup' }, text('legend', g.group),
    ...g.permissions.map((p) => {
      const box = el('input', { type: 'checkbox', value: p.name, onchange: checkRoleRisk });
      box.checked = !!role && role.permissions.includes(p.name);
      box.disabled = !can(p.name);
      return el('label', { class: 'perm', title: p.name }, box, text('span', p.text), ...(p.high_risk ? [text('span', 'high risk', 'st-warn small')] : []));
    }))));
  checkRoleRisk();
}
function renderRoles(roles, mine) {
  $('#rolelist').replaceChildren(...roles.map((r) => el('li', {},
    text('span', `${r.name}${r.builtin ? ' · built-in' : ''} · ${r.users} account${r.users === 1 ? '' : 's'}`),
    text('span', r.description || `${r.permissions.length} permissions`, 'm'),
    ...(r.builtin || !mine.includes(r) ? [] : [
      el('div', { class: 'row wrap' },
        button('Edit', () => openRoleForm(r), 'btn ghost sm'),
        button('Remove', async () => {
          if (!(await confirmDialog({ title: `Remove role ${r.name}?`, confirm: 'Remove role', danger: true }))) return;
          try { await api(`/api/roles/${encodeURIComponent(r.name)}`, { method: 'DELETE' }); $('#rolemsg').textContent = ''; }
          catch (err) { notify(err.message, 'error'); }
          loadUsers();
        }, 'btn ghost sm danger'))]))));
}

async function loadBackups() {
  const box = $('#backupsbox');
  if (!box) return;
  try {
    const b = await getJSON('/api/backups');
    AD_STATE.backups = b;
    renderAdminKpis();
    if (b.external) {
      box.replaceChildren(text('p', 'This database is PostgreSQL: StorageForge makes no backups of it. Use pg_dump, and keep the vault secret safe.', 'st-running'));
      return;
    }
    const newest = b.backups[0];
    const hours = newest ? (Date.now() / 1000 - newest.created) / 3600 : null;
    const host = el('input', { type: 'text', placeholder: 'host', 'aria-label': 'Copy backups to host' }); host.value = b.target?.host || '';
    const path = el('input', { type: 'text', class: 'mono', placeholder: '/srv/storageforge-backups', 'aria-label': 'Folder on that host' }); path.value = b.target?.path || '';
    const msg = text('span', '', 'muted');
    const when_ = (x) => fmtTime(x);
    box.replaceChildren(
      text('p', newest ? `Newest: ${newest.kind}, ${fmtBytes(newest.bytes)}, ${hours < 48 ? `${Math.round(hours)} h` : `${Math.round(hours / 24)} days`} ago. Runs nightly at ${b.hour}:00, keeps ${b.keep}.` : 'No backups yet.', newest && hours < 48 ? 'st-ok' : 'st-failed'),
      b.nightly ? text('p', `Last nightly: ${b.nightly.outcome}, ${when_(b.nightly.at)}`, `small st-${b.nightly.outcome}`) : '',
      b.copy ? text('p', `Last copy off this machine: ${b.copy.outcome}, ${when_(b.copy.at)}${b.copy.detail.error ? `: ${b.copy.detail.error}` : ''}`, `small st-${b.copy.outcome}`)
        : text('p', 'These backups sit on the same volume as the database. Add a host below so that losing the volume does not lose them too.', 'small st-running'),
      el('div', { class: 'row wrap' }, host, path,
        button('Save', async () => {
          try { await api('/api/backups/target', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ host: host.value.trim(), path: path.value.trim() }) }); msg.textContent = 'Saved. It uses the key bound to that host for deploys.'; }
          catch (err) { msg.textContent = err.message; }
        }, 'btn ghost sm'),
        button('Back up now', async () => {
          try { await postJSON('/api/backups', { kind: 'essentials' }); loadBackups(); }
          catch (err) { msg.textContent = err.message; }
        }, 'btn sm'), msg));
  } catch (err) {
    box.replaceChildren(text('p', err.message, 'muted'));
  }
}

async function loadAudit() {
  loadUsers();
  if (can('backups.view')) loadBackups();
  if ($('#verify')) $('#verify').hidden = !can('audit.verify');
  if ($('#backupshead')) $('#backupshead').hidden = $('#backupsbox').hidden = !can('backups.view');
  const auditEl = $('#audit');
  if (!auditEl) return;
  auditEl.hidden = !can('audit.view');
  if (!can('audit.view')) return;
  try {
    const { entries } = await getJSON('/api/audit?limit=100');
    AD_STATE.entries = entries || [];
    renderAdminKpis();
    renderAuditList();
  } catch (err) {
    auditEl.replaceChildren(text('li', err.message, 'muted'));
  }
}

function bindAdminForms() {
  $('#ad-bindact')?.addEventListener('change', renderBindingsList);
  $('#ad-bindfind')?.addEventListener('input', renderBindingsList);
  $('#ad-auditout')?.addEventListener('change', renderAuditList);
  $('#ad-auditfind')?.addEventListener('input', renderAuditList);
  $('#bindform')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const actions = [['scan', '#bindscan'], ['checksum', '#bindsum'], ['console', '#bindconsole']].filter(([, id]) => $(id).checked).map(([a]) => a);
    const body = { key: $('#bindkey').value, host: $('#bindhost').value.trim(), port: Number($('#bindport').value), user: $('#binduser').value.trim(), actions };
    try {
      const r = await (await postJSON('/api/bindings', body)).json();
      keyMsg(`Bound ${body.key} to ${body.user}@${body.host} for ${r.actions.replaceAll(',', ', ')} (binding #${r.binding_id}).`, true);
      $('#bindhost').value = '';
      loadKeys();
    } catch (err) { keyMsg(err.message, false); }
  });
  $('#genform')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const name = $('#genname').value.trim();
    try {
      await (await postJSON('/api/keys', { name, type: $('#gentype').value })).json();
      $('#genname').value = '';
      keyMsg(`Generated key "${name}". Now install it on a host.`, true);
      loadKeys(name);
    } catch (err) { keyMsg(err.message, false); }
  });
  $('#installform')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const body = {
      key: $('#instkey').value, host: $('#insthost').value.trim(), port: Number($('#instport').value),
      user: $('#instuser').value.trim(), password: $('#instpw').value,
      bind: $('#instbind').checked, checksum: $('#instsum').checked, console: $('#instconsole').checked,
    };
    $('#instpw').value = '';
    const btn = ev.submitter; btn.disabled = true;
    keyMsg(`Running ssh-copy-id for ${body.user}@${body.host}…`, true);
    try {
      const r = await (await postJSON('/api/keys/install', body)).json();
      keyMsg(`Installed "${body.key}" on ${body.user}@${body.host}`
             + (r.keys_added === 0 ? ' (it was already there)' : ', and key login works')
             + (r.binding_id ? ` and bound it for ${(r.actions || 'scan').replaceAll(',', ', ')} (binding #${r.binding_id}).` : '.'), true);
      loadKeys();
    } catch (err) { keyMsg(err.message, false); }
    finally { btn.disabled = false; }
  });
  $('#linkcopy')?.addEventListener('click', async () => {
    $('#linkurl').select();
    try { await navigator.clipboard.writeText($('#linkurl').value); toast('Link copied'); } catch { toast('Copy it from the box'); }
  });
  $('#rolenew')?.addEventListener('click', () => openRoleForm(null));
  $('#rolecancel')?.addEventListener('click', () => { $('#roleform').hidden = true; });
  $('#roleform')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const body = {
      name: $('#rolename').value.trim(), description: $('#roledesc').value.trim(),
      permissions: [...document.querySelectorAll('#roleperms input:checked')].map((b) => b.value),
    };
    try {
      if (editingRole) await api(`/api/roles/${encodeURIComponent(editingRole)}`, jsonOpts('PUT', body));
      else await api('/api/roles', jsonOpts('POST', body));
      $('#roleform').hidden = true;
      loadUsers();
    } catch (err) { $('#rolemsg').textContent = err.message; }
  });
  $('#inviteform')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const role = $('#inviterole').value;
      const r = await (await postJSON('/api/invites', { role, hours: Number($('#invitehours').value), note: $('#invitenote').value.trim() })).json();
      showLink(`Invite with the role ${role}:`, r.token);
      $('#invitenote').value = ''; $('#invitemsg').textContent = '';
    } catch (err) { $('#invitemsg').textContent = err.message; }
    loadUsers();
  });
  $('#pwform')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await postJSON('/api/me/password', { password: $('#pwold').value, new_password: $('#pwnew').value });
      sfSignedOut('');
    } catch (err) { $('#pwmsg').textContent = err.message; }
  });
  $('#userform')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await postJSON('/api/users', { username: $('#newuser').value.trim(), password: $('#newuserpw').value, role: $('#newuserrole').value });
      ev.target.reset(); $('#usermsg').textContent = '';
    } catch (err) { $('#usermsg').textContent = err.message; }
    loadUsers();
  });
  $('#verify')?.addEventListener('click', async () => {
    $('#verified').textContent = 'Checking…';
    try {
      const v = await getJSON('/api/audit/verify');
      const weak = v.unkeyed_after_keyed ? ` · ${v.unkeyed_after_keyed} later entries were written with the vault locked (no key): `
        + `whoever can write the database could have rewritten them, from #${v.first_unkeyed_after_keyed}` : '';
      const head = v.head && v.head.enclave ? ` · Key enclave: ${v.head.why}` : '';
      $('#verified').textContent = (v.valid ? `Chain intact · ${v.entries_checked} entries` : v.first_bad_id ? `Chain broken at entry #${v.first_bad_id}` : 'Every entry there is checks out, and the log was cut or changed') + weak + head;
      $('#verified').className = !v.valid ? 'st-failed' : weak ? 'st-warn' : 'st-ok';
    } catch (err) { $('#verified').textContent = err.message; }
  });
}

async function loadMaintenance() {
  const sec = $('#ad-sec-maintenance');
  if (!sec) return;
  sec.replaceChildren(text('p', 'Loading controller status…', 'muted'));
  const cards = [];
  const v = await getJSON('/api/version').catch(() => null);
  if (v) {
    cards.push(el('div', { class: 'card stack' },
      text('h3', 'Controller release & health'),
      el('div', { class: 'row wrap' },
        text('b', `StorageForge ${v.version}`),
        v.update_available ? text('span', `Release ${v.latest} is available`, 'st-warn') : text('span', v.checking ? 'Up to date' : 'Release check not configured (STORAGEFORGE_UPDATE_URL)', 'muted small')),
      v.source ? text('p', `Source: ${v.source}${v.checked_at ? ` · checked ${fmtTime(v.checked_at)}` : ''}${v.error ? ` · ${v.error}` : ''}`, 'muted small') : '',
      el('div', { class: 'row wrap' },
        can('backups.view') ? button('Open Backups & Audit', () => adOpen('audit'), 'btn sm') : '')));
  }
  if (can('keys.view')) {
    const sig = await getJSON('/api/scans/signing').catch(() => null);
    if (sig) {
      const msg = text('span', '', 'muted small');
      const modeSel = el('select', { 'aria-label': 'Signed scan requirement' },
        new Option('Accept unsigned scans (default)', 'off'),
        new Option('Require signed scans on all hosts', 'on'));      // the server's switch is on or off (scansign.parse_switch)
      modeSel.value = sig.require ? 'on' : 'off';
      const saveMode = can('settings.manage') ? button('Save policy', async () => {
        try {
          await api('/api/scans/signing', jsonOpts('PUT', { require: modeSel.value === 'on' }));
          toast('Scan signing policy saved');
          loadMaintenance();
        } catch (err) { msg.textContent = err.message; msg.className = 'st-failed small'; }
      }, 'btn sm pri') : '';
      const pinnedRows = (sig.pinned || []).map((p) => el('li', { class: 'row wrap' },
        text('code', p.address), text('span', `${p.fingerprint} · pinned ${fmtTime(p.pinned_at)} (${p.how})`, 'muted small'),
        can('keys.manage') ? button('Forget', async () => {
          if (!(await confirmDialog({ title: `Forget scan signer for ${p.address}?`, body: 'The next scan will need to pin a signer again.', confirm: 'Forget', danger: true }))) return;
          try { await api(`/api/scans/signing/${encodeURIComponent(p.address)}`, { method: 'DELETE' }); loadMaintenance(); }
          catch (err) { notify(err.message, 'error'); }
        }, 'btn ghost sm') : ''));
      cards.push(el('div', { class: 'card stack' },
        text('h3', 'Scan payload signing'),
        text('p', 'Verify scan payloads signed on target hosts before ingesting them into the index.', 'muted small'),
        el('div', { class: 'row wrap' }, modeSel, saveMode, msg),
        pinnedRows.length ? el('ul', { class: 'list' }, ...pinnedRows) : text('p', 'No host scan signers pinned yet.', 'muted small')));
    }
  }
  if (can('logs.view') || can('audit.view')) {
    const qIn = el('input', { type: 'text', placeholder: 'Filter host or text…', 'aria-label': 'Filter operational log' });
    const list = el('ul', { class: 'list' });
    const outBox = el('pre', { class: 'small', hidden: true });
    const refreshLogs = async () => {
      try {
        const q = qIn.value.trim();
        const d = await getJSON(`/api/log?limit=40${q ? `&q=${encodeURIComponent(q)}` : ''}`);
        const entries = d.entries || [];
        list.replaceChildren(...(entries.length ? entries.map((e) => el('li', { class: 'row wrap' },
          text('span', `${fmtTime(e.ts)} · ${e.source}`, 'muted small'),
          text('b', `${e.host || 'controller'} · ${e.action}`),
          text('span', e.summary || e.outcome, e.outcome === 'failed' || e.outcome === 'denied' ? 'st-failed small' : 'small'),
          e.has_output ? button('Output', async () => {
            const r = await getJSON(`/api/log/output?id=${encodeURIComponent(e.id)}`);
            outBox.textContent = r.output || '(empty)';
            outBox.hidden = false;
          }, 'btn ghost sm') : '')) : [text('li', 'No matching operational log entries.', 'muted small')]));
      } catch (err) { list.replaceChildren(text('li', err.message, 'st-failed small')); }
    };
    cards.push(el('div', { class: 'card stack' },
      text('h3', 'Operational logbook & export'),
      text('p', 'Combined timeline of audit events, deployments, scans, scheduled runs and task runs on this controller.', 'muted small'),
      el('div', { class: 'row wrap' }, qIn, button('Filter', refreshLogs, 'btn sm'),
        ...['csv', 'json', 'text'].map((fmt) => button(`Export ${fmt.toUpperCase()}`, () => download(`/api/log/export?format=${fmt}`, `storageforge-log.${fmt === 'text' ? 'txt' : fmt}`), 'btn ghost sm'))),
      outBox, list));
    refreshLogs();
  }
  sec.replaceChildren(...(cards.length ? cards : [el('div', { class: 'card' }, text('p', 'No controller maintenance actions are available for your role.', 'muted'))]));
}

bindAdminForms();
