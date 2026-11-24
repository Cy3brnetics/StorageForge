'use strict';
/* The notification center (roadmap section 12, notifications.py): every open alert in one list, critical first, one row per host and kind.
   Each can be acknowledged; what can be ignored can be snoozed or muted, and what cannot says so in place of the buttons. Text from hosts
   reaches the page through textContent only. Loaded after kernel.js and chrome.js. */

const NT = { host: '', kind: '', level: '', offset: 0, q: '', data: null };
const NT_LEVEL = { crit: 'Critical', warn: 'Warning', info: 'Information' };
const NT_EVENT = { opened: 'opened', escalated: 'became critical', resolved: 'resolved', acknowledged: 'acknowledged', unacknowledged: 'no longer acknowledged', snoozed: 'snoozed', unsnoozed: 'snooze ended' };
const NT_WHY = 'Cannot be snoozed or muted: it leaves when it is resolved.';

const ntNotifChip = sfNotificationChip(document.getElementById('notifchip'), () => { showTab('notifications'); }, () => can('deploy.view'), 1800);

/* fn returns false when the person cancelled its dialog: nothing changed, so the list is not drawn again under them. */
function ntAct(label, title, fn) {
  const b = sfNode('button', { type: 'button', class: 'btn ghost sm', title }, label);
  sfOnClick(b, async () => {
    try { if (await fn() === false) return; } catch (e) { notify(e.message, 'error'); }
    await loadNotifications(); ntNotifChip();
  });
  return b;
}

function ntItem(x) {
  const may = can('notifications.manage'), key = encodeURIComponent(x.key).replace(/%2F/g, '/').replace(/%3A/g, ':');
  const acts = [];
  if (may) {
    acts.push(x.acked ? ntAct('Not on it', 'Take the acknowledgement back', () => api(`/api/notifications/ack/${key}`, { method: 'DELETE' }))
      : ntAct('Acknowledge', 'Say you are on it. It stays in the list until it is resolved', async () => {
        const f = await formDialog({ title: 'Acknowledge', body: x.title, fields: [{ name: 'note', label: 'A note for whoever looks next', maxlength: 500 }], confirm: 'Acknowledge' });
        if (!f) return false;
        await postJSON(`/api/notifications/ack/${key}`, { note: f.note });
      }));
    if (x.ignorable && !x.quiet) {
      const hours = sfNode('select', { 'aria-label': `Snooze ${x.title} for` }, [['1', '1 hour'], ['8', '8 hours'], ['24', '1 day'], ['168', '7 days'], ['720', '30 days']].map(([v, t]) => sfNode('option', { value: v }, t)));
      acts.push(hours, ntAct('Snooze', 'Hide it and do not push it for this long. A snooze ends if it becomes critical', () => postJSON(`/api/notifications/snooze/${key}`, { hours: Number(hours.value) })));
      acts.push(ntAct('Mute…', 'Mute this kind on this host', async () => {
        const f = await formDialog({ title: `Mute ${x.kind} on ${x.host || 'every host'}`, body: 'New notifications of this kind are listed apart and not pushed. A critical one is never muted.',
          fields: [{ name: 'note', label: 'Why', maxlength: 500 }, { name: 'days', label: 'For how many days (empty: until removed)', inputmode: 'numeric' }], confirm: 'Mute' });
        if (!f) return false;
        await postJSON('/api/notifications/mutes', { host: x.host || '*', kind: x.kind, note: f.note, ...(f.days ? { days: Number(f.days) } : {}) });
      }));
    }
    if (x.snoozed_until) acts.push(ntAct('End snooze', 'Show it again now', () => api(`/api/notifications/snooze/${key}`, { method: 'DELETE' })));
  }
  // A fix is a change plan made ready: it opens in Changes, where its report is read and its deploy takes the password. Its way back is another.
  const open = (plan) => { showTab('changes'); loadChanges(plan); };
  const fix = [];
  if (x.fix && can('plans.edit')) {
    if (x.fix.plan) {
      const see = sfNode('button', { type: 'button', class: 'btn ghost sm', title: 'Open the plan in Changes: report it, then deploy it with your password' }, `Open the prepared fix (plan ${x.fix.plan})`);
      see.addEventListener('click', () => open(x.fix.plan));
      const back = sfNode('button', { type: 'button', class: 'btn ghost sm', title: x.fix.undo }, 'Prepare the way back');
      sfOnClick(back, async () => { try { const r = await (await postJSON(`/api/notifications/undo/${x.fix.plan}`, {})).json(); open(r.plan); } catch (e) { notify(e.message, 'error'); } });
      fix.push(see, back);
    } else {
      const make = sfNode('button', { type: 'button', class: 'btn sm', title: 'Saves a change plan and opens it in Changes. Nothing runs until you deploy it there, with your password' }, `Prepare a fix: ${x.fix.label}`);
      sfOnClick(make, async () => { try { const r = await (await postJSON(`/api/notifications/fix/${key}`, {})).json(); open(r.plan); } catch (e) { notify(e.message, 'error'); } });
      fix.push(make);
    }
  }
  // the host's lines from an hour before it opened (hostlogsview.js)
  const logs = x.host && can('hostlogs.view') && typeof hlLinkEl === 'function' ? hlLinkEl(x.host, `${x.host}'s logs`, { from: x.first_at - 3600, small: true }) : null;
  if (logs) acts.push(logs);
  const cls = x.level === 'crit' ? 'st-failed' : x.level === 'warn' ? 'st-warn' : '';
  return sfNode('li', { 'data-key': x.key },
    sfNode('span', cls ? { class: cls } : {}, x.title),
    x.message ? sfNode('span', { class: 'm' }, x.message) : null,
    sfNode('span', { class: 'm' }, `${NT_LEVEL[x.level]} · open since `, timeEl(x.first_at), x.acked ? ` · ${x.acked.by} is on it${x.acked.note ? `: ${x.acked.note}` : ''}` : '',
      x.snoozed_until ? ' · snoozed until ' : '', x.snoozed_until ? timeEl(x.snoozed_until) : null, x.muted ? ' · muted' : ''),
    !x.ignorable ? sfNode('span', { class: 'm' }, NT_WHY) : null,
    x.fix ? sfNode('span', { class: 'm' }, `A fix can be prepared: ${x.fix.label}. Its way back: ${x.fix.undo}.`) : null,
    fix.length ? sfNode('span', { class: 'row wrap' }, fix) : null,
    acts.length ? sfNode('span', { class: 'row wrap' }, acts) : null);
}

function ntGroups(groups) {
  return groups.map((g) => sfNode('section', { class: `nt-group nt-l-${g.level}` },
    sfNode('h3', {}, `${NT_LEVEL[g.level]}: ${g.kind}${g.host ? ` on ${g.host}` : ''}`, g.count > 1 ? sfNode('span', { class: 'cnt' }, ` × ${g.count}`) : null),
    sfMoreList(g.items, ntItem, { limit: 3, label: 'of this kind', tag: 'ul', className: 'list' })));
}

async function loadNotifications() {
  const q = new URLSearchParams();
  for (const k of ['host', 'kind', 'level']) if (NT[k]) q.set(k, NT[k]);
  let d;
  try { d = await getJSON(`/api/notifications?${q}`); } catch (e) { document.getElementById('nt-groups').replaceChildren(sfNode('p', { class: 'st-failed' }, e.message)); return; }
  NT.data = d;
  const fill = (id, values, first) => {
    const sel = document.getElementById(id), keep = sel.value;
    sel.replaceChildren(sfNode('option', { value: '' }, first), ...values.map((v) => sfNode('option', { value: v }, v)));
    sel.value = values.includes(keep) ? keep : '';
  };
  fill('nt-host', d.hosts, 'All hosts'); fill('nt-kind', d.kinds, 'Every kind');
  const c = d.counts;
  document.getElementById('nt-count').textContent = d.total ? `${d.total} open: ${c.crit} critical, ${c.warn} warning${c.warn === 1 ? '' : 's'}, ${c.info} for information.` : 'Nothing open wants attention.';
  document.getElementById('nt-groups').replaceChildren(...ntGroups(d.groups));
  const quiet = d.quiet.reduce((n, g) => n + g.count, 0);
  document.getElementById('nt-quiet-box').hidden = !quiet && !d.mutes.length;
  document.getElementById('nt-quiet-sum').textContent = `Snoozed and muted (${quiet})`;
  document.getElementById('nt-quiet').replaceChildren(...ntGroups(d.quiet));
  document.getElementById('nt-mutes').replaceChildren(d.mutes.length ? sfNode('h3', {}, 'Mutes') : '', sfNode('ul', { class: 'list' }, d.mutes.map((m) => sfNode('li', {},
    sfNode('span', {}, `${m.kind} on ${m.host === '*' ? 'every host' : m.host}`),
    sfNode('span', { class: 'm' }, `by ${m.by}`, m.note ? `: ${m.note}` : '', m.until ? ' · until ' : ' · until removed', m.until ? timeEl(m.until) : null),
    can('notifications.manage') ? ntAct('Remove', 'End this mute', () => api(`/api/notifications/mutes/${m.id}`, { method: 'DELETE' })) : null))));
  if (document.getElementById('nt-history-box').open) ntHistory(false);
}

async function ntHistory(more) {
  NT.offset = more ? NT.offset + 50 : 0;
  const q = new URLSearchParams({ limit: '50', offset: String(NT.offset) });
  if (NT.q) q.set('q', NT.q);
  if (NT.host) q.set('host', NT.host);
  const list = document.getElementById('nt-history');
  try {
    const d = await getJSON(`/api/notifications/history?${q}`);
    const rows = d.events.map((e) => sfNode('li', {}, sfNode('span', {}, e.title),
      sfNode('span', { class: 'm' }, timeEl(e.at), ` · ${NT_EVENT[e.event] || e.event}${e.actor ? ` by ${e.actor}` : ''}${e.note ? `: ${e.note}` : ''} · ${NT_LEVEL[e.level] || e.level}${e.host ? ` · ${e.host}` : ''}`)));
    if (more) list.append(...rows); else list.replaceChildren(...(rows.length ? rows : [sfNode('li', { class: 'muted' }, 'Nothing in the history matches.')]));
    document.getElementById('nt-older').hidden = !d.more;
  } catch (e) { list.replaceChildren(sfNode('li', { class: 'st-failed' }, e.message)); }
}

for (const k of ['host', 'kind', 'level']) document.getElementById(`nt-${k}`).addEventListener('change', (ev) => { NT[k] = ev.target.value; loadNotifications(); });
document.getElementById('nt-history-box').addEventListener('toggle', (ev) => { if (ev.target.open) ntHistory(false); });
document.getElementById('nt-older').addEventListener('click', () => ntHistory(true));
let ntTyping = 0;
document.getElementById('nt-hq').addEventListener('input', (ev) => { NT.q = ev.target.value.trim(); clearTimeout(ntTyping); ntTyping = setTimeout(() => ntHistory(false), 250); });
document.addEventListener('sf:notifications', () => {
  if (!document.getElementById('tab-notifications')?.hidden && !document.querySelector('dialog[open]')) loadNotifications();
});
