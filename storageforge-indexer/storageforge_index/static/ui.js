'use strict';
/* Shared DOM and permission helpers for standalone StorageForge windows (/security, /logs, /admin).
   Loaded right after chrome.js; pairs with kernel.js so there are no duplicate fetch wrappers or formatters. */

const $ = (s) => document.querySelector(s);

function el(tag, attrs = {}, ...kids) {
  return sfNode(tag, attrs, ...kids);
}

function text(tag, s, cls) {
  const e = document.createElement(tag);
  e.textContent = s;
  if (cls) e.className = cls;
  return e;
}

function button(label, fn, cls = 'btn') {
  const b = text('button', label, cls);
  b.type = 'button';
  return sfOnClick(b, fn);
}

const jsonOpts = (method, body) => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

const S = { host: '' };
const MP_LEVEL = { any: 'Any address', lan: 'Private networks', vpn: 'VPN only', blocked: 'Blocked', loopback: 'This machine only', unknown: 'Unknown' };
let ME = null;
function setMe(me) {
  ME = me;
  sfUserName = me?.username || '';
}
const can = (perm) => !!ME && (ME.permissions || []).includes(perm);

function copyText(s, what = 'Copied') {
  const done = () => toast(`${what}: ${s}`);
  const ta = Object.assign(document.createElement('textarea'), { value: s, readOnly: true });
  ta.style.cssText = 'position:fixed;opacity:0';
  document.body.append(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch { /* fall through */ }
  ta.remove();
  if (ok) done();
  else if (navigator.clipboard && isSecureContext) navigator.clipboard.writeText(s).then(done, () => toast('Could not copy'));
  else toast('Could not copy');
}

async function download(url, fallback, body) {
  try {
    const res = await (body ? postJSON(url, body) : api(url));
    const a = document.createElement('a');
    a.href = URL.createObjectURL(await res.blob());
    a.download = (res.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || fallback;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (err) {
    notify(err.message, 'error');
  }
}

function showTab(name, params = {}) {
  const targets = {
    security: '/security',
    malware: '/security#/malware',
    hostlogs: '/logs',
    keys: '/admin#/keys',
    audit: '/admin#/audit',
  };
  if (targets[name]) {
    location.href = targets[name];
    return;
  }
  const q = { ...(S.host ? { host: S.host } : {}), ...params };
  location.href = `/${sfFormatHash(['topo', name], q)}`;
}

async function queueScan(host) {
  try {
    const r = await (await postJSON('/api/scan', { host })).json();
    toast(`Scan queued for ${host} (job #${r.job_id}). Open Scans on the main page to follow it.`);
  } catch (err) {
    notify(err.message, 'error');
  }
}

async function startDeploy(kind, ref, mode, title, extra = {}) {
  try {
    const r = await (await postJSON('/api/deploy/start', { kind, ref, mode, ...extra })).json();
    const msg = `${title} started (deploy group #${r.group}). Opening Deployments…`;
    toast(msg);
    location.href = `/#/topo/deploy?host=${encodeURIComponent(S.host || '')}`;
  } catch (err) {
    if (!/not confirmed/.test(err.message)) notify(err.message, 'error');
  }
}

async function populateHostSelect(sel) {
  if (!sel) return;
  try {
    const { indexed, graph } = await getJSON('/api/hosts');
    const names = [...new Set([...(graph || []), ...(indexed || []).map((h) => h.hostname)])].sort();
    sel.replaceChildren(new Option('All hosts', ''), ...names.map((n) => new Option(n, n)));
    if (S.host && names.includes(S.host)) sel.value = S.host;
  } catch { /* host list is optional for accounts without hosts */ }
}

function needHost(box, what, redraw, preferred) {
  const sel = $('#host');
  const hosts = sel ? [...sel.options].map((o) => o.value).filter(Boolean) : [];
  if (!hosts.length) {
    box.replaceChildren(text('p', 'No host has been scanned yet.', 'muted'));
    return;
  }
  const start = hosts.includes(preferred) ? preferred : hosts[0];
  const pick = el('select', { 'aria-label': 'Host' }, hosts.map((h) => el('option', { value: h, selected: h === start }, h)));
  box.replaceChildren(
    text('p', `${what} is about one host at a time.`, 'muted'),
    el('div', { class: 'row' }, pick, button('Open', () => {
      if (sel) {
        sel.value = pick.value;
        sel.dispatchEvent(new Event('change'));
      } else {
        S.host = pick.value;
        redraw();
      }
    }, 'btn pri sm')),
  );
}
