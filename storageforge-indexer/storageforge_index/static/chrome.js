'use strict';
/* The parts of the top bar that every page shares (UX-09 and UX-03 of the UI audit of 2026-11-04): the security chip, the links into the
   other pages, and the person signed in with Sign out. The main page keeps its own header for what only it has (the views, the host filter,
   the search box) and takes the chip from here; the planner, /manage and the search page mount the lot into the slot their layout leaves
   (an element with data-sf-chrome and data-here). DOM APIs only, so a name a machine reports can never become markup. Loaded after kernel.js. */

const SF_CHIP = { secure: 'Security: nothing wrong found', warning: 'Security: needs a look', critical: 'Security: incident', unknown: 'Security: not known' };

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
  setInterval(draw, 60000);
  setTimeout(draw, delay);
  return draw;
}

// [key, href, label, the permission it needs]
const SF_PAGES = [['main', '/', 'Topology and map', 'hosts.view'], ['planner', '/planner', 'Storage planner', 'hosts.view'],
                  ['manage', '/manage', 'Network management', 'devices.view']];

// the steps of a plan live in the main page's rail: one way in from here, under one name each
const SF_PLAN = [['changes', '/#/topo/changes', 'Changes', 'plans.view'], ['moves', '/#/topo/moves', 'Moves', 'plans.view'], ['schedule', '/#/topo/schedule', 'Schedule', 'plans.view']];

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
  const parts = [
    want.has('site') && me.site ? sfNode('span', { class: 'sf-site' }, me.site) : null,
    want.has('pages') ? sfNode('nav', { 'aria-label': 'Pages' }, links.map(([key, href, label]) => sfNode('a', { class: 'sf-btn ghost', href, 'aria-current': key === here ? 'page' : null }, label))) : null,
    want.has('chip') ? chip : null,
    want.has('user') ? sfNode('div', { class: 'sf-user' }, sfNode('span', {}, me.username), sfNode('button', { type: 'button', class: 'sf-btn ghost', onclick: sfSignOut }, 'Sign out')) : null,
  ].filter(Boolean);                                         // replaceChildren(null) would write the word "null"
  slot.className = 'sf-chrome';
  slot.replaceChildren(...parts);
  if (want.has('chip')) sfSecurityChip(chip, () => { location.href = '/#tab=security'; }, () => perms.has('security.view'));
}
document.querySelectorAll('[data-sf-chrome]').forEach(sfMountChrome);
