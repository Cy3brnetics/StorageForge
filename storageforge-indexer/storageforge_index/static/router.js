'use strict';
/* The main page's place is in its URL (UX-08 of the UI audit of 2026-11-04): #/<view>/<panel>?host=…, so Back and Forward go where the
   person was, a copied URL lands where it was copied, and a link inside the page, which only changes the hash, works without a reload.
   The old forms (#host=nas&tab=changes&view=map&layers=…) are still read, and tidied into the new one. Loaded before app.js so that
   setMode(), showTab() and the host picker can tell it when something changed; it uses the rest only when something is asked of it. */
const ROUTE = { ready: false, applying: false };
const ROUTE_VIEWS = ['topo', 'graph', 'tasks', 'map', 'scan'];
const routeTab = () => document.querySelector('.tabs button.on')?.dataset.tab || 'details';
const routeHasTab = (name) => !!name && !!document.querySelector(`.tabs button[data-tab="${CSS.escape(name)}"]`);

function routeState() {
  const tab = routeTab();
  const params = { host: S.host };
  if (T.mode === 'map' && typeof mapRouteParams === 'function') Object.assign(params, mapRouteParams());
  if (tab === 'security' && typeof SEC !== 'undefined' && SEC.panel && SEC.panel !== 'overview') params.sec = SEC.panel;
  if (tab === 'hostlogs' && typeof hlRouteParams === 'function') Object.assign(params, hlRouteParams());      // the Logs range and filters (hostlogsview.js)
  return { parts: [T.mode, tab], params };
}

/* Called by whatever changed the view, the panel, the host or the map: the URL follows, as a step of its own in the history. */
function routeSync(replace = false) {
  if (!ROUTE.ready || ROUTE.applying) return;
  const s = routeState();
  (replace ? sfReplaceHash : sfPushHash)(sfFormatHash(s.parts, s.params));
}

/* What a hash asks for, in either form. An old link that names no host leaves the host as it is. */
function routeRead(parsed = sfParseHash()) {
  const q = parsed.q;
  if (!parsed.legacy && parsed.parts.length) {
    const [view, panel] = parsed.parts;
    return { view: ROUTE_VIEWS.includes(view) ? view : null, panel: panel || null, host: q.get('host') || '', sec: q.get('sec'), q };      // no host in a URL of this form is all of them
  }
  return { view: ROUTE_VIEWS.includes(q.get('view')) ? q.get('view') : null, panel: q.get('tab'), host: q.get('host'), sec: q.get('panel'), q };
}

function routeApply(r) {
  const was = ROUTE.applying;
  ROUTE.applying = true;                          // what this does to the page is not a new step in the history
  try {
    const pick = $('#host');
    if (r.host != null && r.host !== S.host && [...pick.options].some((o) => o.value === r.host)) {
      pick.value = r.host;
      pick.dispatchEvent(new Event('change'));   // the same handlers as choosing it
    }
    if (r.view === 'map' && typeof mapTakeLink === 'function') mapTakeLink(r.q);
    if (r.view && r.view !== T.mode) setMode(r.view);
    if (r.sec) window.SEC_LINK_PANEL = r.sec;
    if (r.panel === 'hostlogs' && typeof hlTakeLink === 'function') hlTakeLink(r.q);
    if (routeHasTab(r.panel)) showTab(r.panel);
  } finally { ROUTE.applying = was; }
}

/* At start: the host and the view now, and the panel (returned) once the data is in. */
function routeTake() {
  const r = routeRead();
  if (!r.view && !r.panel && !r.host) return null;
  routeApply({ ...r, panel: null });
  if (r.sec) window.SEC_LINK_PANEL = r.sec;
  if (r.panel === 'hostlogs' && typeof hlTakeLink === 'function') hlTakeLink(r.q);
  return routeHasTab(r.panel) ? r.panel : null;
}

function routeStart() {                           // once the page has what it needs: the URL is made canonical, and from here it is followed
  ROUTE.ready = true;
  routeSync(true);
}

addEventListener('hashchange', () => {            // Back and Forward, a typed URL, a link inside the page
  if (!ROUTE.ready) return;
  routeApply(routeRead());
  routeSync(true);
});
