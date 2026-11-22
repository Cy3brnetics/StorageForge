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

async function loadKeys(select) {
  if (typeof loadEnclave === 'function') loadEnclave();
  if (typeof loadAgents === 'function') loadAgents();
  const keysEl = $('#keys');
  if (!keysEl) return;
  try {
    const { keys, bindings } = await getJSON('/api/keys');
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
    const bindingsEl = $('#bindings');
    if (bindingsEl) {
      bindingsEl.replaceChildren(...bindings.map((b) => {
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
      if (!bindings.length) bindingsEl.replaceChildren(text('li', 'No bindings yet.', 'muted'));
    }
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
    const mine = roles.filter((r) => r.permissions.every((p) => ME.permissions.includes(p)));
    if (can('roles.manage')) renderRoles(roles, mine);
    if (!can('users.manage')) return;
    for (const sel of [$('#newuserrole'), $('#inviterole')]) {
      const was = sel.value;
      sel.replaceChildren(...mine.map((r) => new Option(r.name, r.name)));
      sel.value = was && mine.some((r) => r.name === was) ? was : 'viewer';
    }
    const [{ users }, { invites, now }] = await Promise.all([getJSON('/api/users'), getJSON('/api/invites')]);
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
    auditEl.replaceChildren(...entries.map((a) => {
      const li = document.createElement('li');
      li.append(
        text('span', `${a.action} · ${a.outcome}${a.host ? ' · ' + a.host : ''}`, `st-${a.outcome}`),
        Object.assign(text('span', `${fmtTime(a.ts, { seconds: true })} · ${a.actor}${a.key ? ' · ' + a.key : ''}`, 'm'), { title: fmtUtc(a.ts) }),
        ...(Object.keys(a.detail).length ? [text('span', JSON.stringify(a.detail), 'm')] : []),
      );
      return li;
    }));
  } catch (err) {
    auditEl.replaceChildren(text('li', err.message, 'muted'));
  }
}

function bindAdminForms() {
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

bindAdminForms();
