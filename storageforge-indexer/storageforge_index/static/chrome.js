'use strict';
/* The parts of the top bar that every page shares (UX-09 and UX-03 of the UI audit of 2026-11-04): the security chip, the links into the
   other pages, and the person signed in with Sign out. The main page keeps its own header for what only it has (the views, the host filter,
   the search box) and takes the chip from here; the planner, /manage and the search page mount the lot into the slot their layout leaves
   (an element with data-sf-chrome and data-here). It also holds the Preferences dialog, and tells the command palette (Ctrl+K, in kernel.js)
   which pages this person may go to. DOM APIs only, so a name a machine reports can never become markup. Loaded after kernel.js. */

const SF_CHIP = { secure: 'Security: nothing wrong found', warning: 'Security: needs a look', critical: 'Security: incident', unknown: 'Security: not known' };
const sfSecDraws = [];
const sfNotifDraws = [];
let sfLastScanMark = null;
let sfLastNotifMark = null;
let sfFastPollUntil = 0;
let sfWatchTimer = 0;

function sfNoteScanMark(mark) {
  if (mark) sfLastScanMark = mark;
}

function sfNoteNotifMark(mark) {
  if (mark) sfLastNotifMark = mark;
}

function sfScanQueued() {
  sfFastPollUntil = Date.now() + 90000;
  sfScheduleWatch(2000);
}

/* Fills `chip` (a button) with where the security posture stands, always as "Security: …" with the reason under it, and keeps it fresh.
   `open()` is what a click does. `allowed()` says whether this person may see security at all: they see no chip if not.
   Returns the function that draws it again. */
function sfSecurityChip(chip, open, allowed = () => true, delay = 0) {
  const draw = async () => {
    if (!allowed()) { chip.hidden = true; return; }
    try {
      const p = await getJSON('/api/security/posture');
      chip.hidden = false;
      chip.className = `threat sec-${p.state}`;
      chip.replaceChildren(sfNode('b', {}, SF_CHIP[p.state] || SF_CHIP.unknown), sfNode('span', { class: 'threat-detail' }, p.banner));
      chip.title = p.banner;                 // the detail is cut to two lines on the chip; hovering still gives all of it
    } catch { chip.hidden = true; }
  };
  chip.addEventListener('click', open);
  sfSecDraws.push(draw);
  setInterval(() => { if (!document.hidden) draw(); }, 60000);
  setTimeout(draw, delay);
  return draw;
}

/* The count of open notifications, on every page (roadmap section 12): critical ones first and in words, so the number never stands alone.
   A click opens the center. Nothing is shown to someone who may not see alerts, or when nothing is open. */
function sfNotificationChip(chip, open, allowed = () => true, delay = 0) {
  let prevMark = null;
  const draw = async () => {
    if (!allowed()) { chip.hidden = true; return; }
    try {
      const { counts, total, mark } = await getJSON('/api/notifications/summary');
      chip.hidden = !total;
      const level = counts.crit ? 'crit' : counts.warn ? 'warn' : 'info';
      chip.className = `threat nt-${level}`;
      const head = counts.crit ? `${counts.crit} critical notification${counts.crit === 1 ? '' : 's'}` : `${total} notification${total === 1 ? '' : 's'}`;
      const rest = [counts.crit && counts.warn ? `${counts.warn} warning${counts.warn === 1 ? '' : 's'}` : '', counts.crit && counts.info ? `${counts.info} for information` : '',
                    !counts.crit && counts.warn ? `${counts.warn} warning${counts.warn === 1 ? '' : 's'}, none critical` : '', !counts.crit && !counts.warn ? 'for information' : ''].filter(Boolean).join(', ');
      chip.replaceChildren(sfNode('b', {}, head), sfNode('span', { class: 'threat-detail' }, rest));
      chip.title = `${head}${rest ? `: ${rest}` : ''}. Open the notification center`;
      const cnt = document.getElementById('ncrit'); if (cnt) cnt.textContent = counts.crit ? String(counts.crit) : '';
      if (mark) {
        const changed = prevMark !== null && prevMark !== mark;
        prevMark = mark;
        if (changed) document.dispatchEvent(new CustomEvent('sf:notifications', { detail: { counts, total, mark } }));
      }
    } catch { chip.hidden = true; }
  };
  chip.addEventListener('click', open);
  sfNotifDraws.push(draw);
  setInterval(() => { if (!document.hidden) draw(); }, 60000);
  setTimeout(draw, delay);
  return draw;
}

async function sfWatchTick() {
  sfWatchTimer = 0;
  const nextDelay = Date.now() < sfFastPollUntil ? 2000 : 8000;
  if (!document.hidden && sfPerms && sfPerms.has('hosts.view')) {
    try {
      const d = await getJSON('/api/hosts');
      const sm = d.scan_mark || null, nm = d.notif_mark || null;
      const scanChanged = sm && sfLastScanMark !== null && sm !== sfLastScanMark;
      const notifChanged = nm && sfLastNotifMark !== null && nm !== sfLastNotifMark;
      if (sm) sfLastScanMark = sm;
      if (nm) sfLastNotifMark = nm;
      if (scanChanged) {
        sfSecDraws.forEach((fn) => fn());
        sfNotifDraws.forEach((fn) => fn());
        document.dispatchEvent(new CustomEvent('sf:scan', { detail: d }));
      } else if (notifChanged) {
        sfNotifDraws.forEach((fn) => fn());
      }
    } catch { /* transient network error: try on the next tick */ }
  }
  sfScheduleWatch(nextDelay);
}

function sfScheduleWatch(ms) {
  clearTimeout(sfWatchTimer);
  sfWatchTimer = setTimeout(sfWatchTick, ms);
}

sfScheduleWatch(5000);
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) sfScheduleWatch(200);
});

// [key, href, label, the permission it needs]
const SF_PAGES = [
  ['main', '/', 'Topology and map', 'hosts.view'],
  ['planner', '/planner', 'Storage planner', 'hosts.view'],
  ['manage', '/manage', 'Network management', 'devices.view'],
  ['security', '/security', 'Security center', 'security.view'],
  ['logs', '/logs', 'Host logs', 'hostlogs.view'],
  ['admin', '/admin', 'Admin & vault', 'hosts.view'],
];

// the steps of a plan live in the main page's rail: one way in from here, under one name each
const SF_PLAN = [['changes', '/#/topo/changes', 'Changes', 'plans.view'], ['moves', '/#/topo/moves', 'Moves', 'plans.view'], ['schedule', '/#/topo/schedule', 'Schedule', 'plans.view']];

/* Links to Host Logs (/logs), shared across Topology, Details, Notifications and /manage. */
function hlUrlTime(secs) {
  if (secs == null) return '';
  const iso = new Date(secs * 1000).toISOString();
  return `${iso.slice(0, 16)}Z`;
}
function hlLink(host, { q = '', unit = '', from = null } = {}) {
  return `/logs${sfFormatHash([], { lhost: host, unit, q, ...(from != null ? { range: 'custom', from: hlUrlTime(from) } : {}) })}`;
}
function hlLinkEl(host, label = 'Logs', opts = {}) {
  const what = opts.q ? ` that mention ${opts.q}` : opts.unit ? ` from ${opts.unit}` : '';
  return sfNode('a', { class: opts.small ? 'btn ghost sm' : 'btn', href: hlLink(host, opts), title: `The lines of ${host}'s journal${what}` }, label);
}
function hlDeviceWord(kind, name) {
  const v = String(name || '').trim();
  if (!v) return '';
  if (kind === 'mount' && !v.startsWith('/dev/')) return v;
  return v.replace(/^\/dev\/(mapper\/)?/, '').slice(0, 200);
}
function hlDeviceLinkEl(host, kind, name) {
  if (!host || typeof can !== 'function' || !can('hostlogs.view')) return null;
  const q = hlDeviceWord(kind, name);
  return q ? hlLinkEl(host, 'Logs', { q, small: true }) : null;
}

/* The chrome of a page that has none of its own. A slot says which parts it wants in data-sf-chrome ("site pages chip user", the default),
   so a page can put the chip at the top where it is seen and the rest further down. */
async function sfMountChrome(slot) {
  let me;
  try { me = await sfMe(); } catch { return; }              // a 401 has already sent the page to /login
  const perms = new Set(me.permissions || []);
  const here = slot.dataset.here;
  const want = new Set((slot.dataset.sfChrome || 'site pages chip user').split(/\s+/));
  const links = [...SF_PAGES, ...SF_PLAN].filter(([, , , need]) => perms.has(need));          // the pages, then the way into the plan's steps on the main page
  if (!perms.has('hosts.view')) links.push(['search', '/search', 'File search', null]);      // the one page an account with no hosts can use
  const chip = sfNode('button', { type: 'button', class: 'threat sec-unknown', hidden: true });
  const bell = sfNode('button', { type: 'button', class: 'threat nt-none', hidden: true });
  const parts = [
    want.has('site') && me.site ? sfNode('span', { class: 'sf-site' }, me.site) : null,
    want.has('pages') ? sfNode('nav', { 'aria-label': 'Pages' }, links.map(([key, href, label]) => sfNode('a', { class: 'sf-btn ghost', href, 'aria-current': key === here ? 'page' : null }, label))) : null,
    want.has('chip') ? chip : null,
    want.has('chip') ? bell : null,
    want.has('user') ? sfNode('div', { class: 'sf-user' }, sfNode('span', {}, me.username),
      sfNode('button', { type: 'button', class: 'sf-btn ghost', onclick: sfPreferences }, 'Preferences'), sfNode('button', { type: 'button', class: 'sf-btn ghost', onclick: sfSignOut }, 'Sign out')) : null,
  ].filter(Boolean);                                         // replaceChildren(null) would write the word "null"
  slot.className = 'sf-chrome';
  slot.replaceChildren(...parts);
  if (want.has('chip')) sfSecurityChip(chip, () => { location.href = '/security'; }, () => perms.has('security.view'));
  if (want.has('chip')) sfNotificationChip(bell, () => { location.href = '/#/topo/notifications'; }, () => perms.has('deploy.view'));
}
document.querySelectorAll('[data-sf-chrome]').forEach(sfMountChrome);

/* ── Preferences: how this browser shows the page ──────────────────── */
/* Theme, density and reduced motion, kept in this browser for the account (kernel.js: sfPrefsRead, sfPrefsApply, sfPrefsSave), and applied as
   they are chosen. Nothing here goes to the server. Opened from the user menu, the main page's header and the command palette. */
const SF_PREF_FIELDS = [
  ['theme', 'Theme', [['system', 'Follow the system'], ['light', 'Light'], ['dark', 'Dark']]],
  ['density', 'Density', [['comfortable', 'Comfortable'], ['compact', 'Compact: tighter rows and buttons']]],
  ['motion', 'Motion', [['system', 'Follow the system'], ['reduce', 'Reduce motion']]],
];
async function sfPreferences() {
  if (document.querySelector('dialog.sf-prefs')) return;
  let user = '';
  try { user = (await sfMe()).username || ''; } catch { return; }
  const prefs = sfPrefsRead(user);
  const id = `sf-dlg-${++sfSeq}`;
  const radios = new Map();
  const change = (name, value) => { prefs[name] = value; sfPrefsApply(prefs); sfPrefsSave(prefs, user); };
  const groups = SF_PREF_FIELDS.map(([name, legend, options]) => sfNode('fieldset', {}, sfNode('legend', {}, legend), options.map(([value, label]) => {
    const input = sfNode('input', { type: 'radio', name: `pref-${name}`, value, checked: prefs[name] === value });
    input.addEventListener('change', () => change(name, value));
    radios.set(`${name}:${value}`, input);
    return sfNode('label', {}, input, sfNode('span', {}, label));
  })));
  const reset = sfNode('button', { type: 'button', class: 'sf-btn ghost' }, 'Reset');
  reset.addEventListener('click', () => {
    for (const [name, choices] of Object.entries(SF_PREF_CHOICES)) { change(name, choices[0]); radios.get(`${name}:${choices[0]}`).checked = true; }
    announce('Preferences reset');
  });
  const form = sfNode('form', { method: 'dialog' }, sfNode('h2', { id }, 'Preferences'),
    sfNode('p', { class: 'muted small' }, `Kept in this browser for ${user}, not on the server. A change applies at once.`),
    groups, sfNode('div', { class: 'sf-actions' }, reset, sfNode('button', { type: 'submit', class: 'sf-btn pri' }, 'Done')));
  const dlg = sfModal(form, id);
  dlg.classList.add('sf-prefs');
  radios.values().next().value.focus();
}
document.getElementById('prefs')?.addEventListener('click', sfPreferences);          // the main page's header has its own button

/* ── what the command palette offers besides the shortcuts ─────────── */
let sfPerms = null;
sfMe().then((me) => { sfPerms = new Set(me.permissions || []); }).catch(() => { /* a 401 has already sent the page to /login */ });
const SF_SEARCH_PAGE = ['search', '/search', 'File search', 'search.files'];
sfPaletteSource(() => {
  if (!sfPerms) return [];
  const mainHasPanels = !!document.querySelector('.tabs button[data-tab]');            // there the panels are offered by the page itself
  return [...SF_PAGES, SF_SEARCH_PAGE, ...(mainHasPanels ? [] : SF_PLAN)]
    .filter(([, href, , need]) => sfPerms.has(need) && href !== location.pathname)
    .map(([, href, label]) => ({ label: `Go to ${label}`, hint: 'Page', run: () => { location.href = href; } }));
});
sfPaletteSource(() => [{ label: 'Preferences', hint: 'Theme, density, motion', run: sfPreferences }, { label: 'Sign out', hint: 'Session', run: sfSignOut }]);

/* ── first run: what to do on an empty install ─────────────────────── */
/* sfFirstRun(card, { user, steps: [{ label, detail, href, done }] }) fills a card that has an <ol>, a heading and a Dismiss button. Each step is a
   real link (into a panel, by the router's hash), and says "Done" or "To do" in words. The card goes away for good when the person dismisses it
   (remembered per account in this browser) and when every step is done. Returns whether it is showing. */
const sfFirstRunKey = (user) => `sf.firstrun.${user}`;
function sfFirstRun(card, { user = '', steps }) {
  const list = card.querySelector('ol'), dismiss = card.querySelector('button');
  if (sfRecall(sfFirstRunKey(user), false, user) || !steps.length || steps.every((s) => s.done)) { card.hidden = true; return false; }
  list.replaceChildren(...steps.map((s) => sfNode('li', { class: s.done ? 'done' : '' },
    sfNode('span', { class: 'frstate' }, s.done ? '✓ Done' : 'To do'),
    sfNode('a', { href: s.href }, s.label), sfNode('span', { class: 'muted small' }, s.detail))));
  dismiss.onclick = () => {
    sfStash(sfFirstRunKey(user), true, user);
    card.hidden = true;
    announce('Checklist dismissed');
    card.parentElement?.focus?.();
  };
  card.hidden = false;
  return true;
}
