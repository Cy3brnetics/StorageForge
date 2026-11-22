'use strict';
/* The main page's place is in its URL (UX-08 of the UI audit of 2026-11-04): #/<view>/<panel>?host=…, so Back and Forward go where the
   person was, a copied URL lands where it was copied, and a link inside the page, which only changes the hash, works without a reload.
   The old forms (#host=nas&tab=changes&view=map&layers=…) are still read, and tidied into the new one. Loaded before app.js so that
   setMode(), showTab() and the host picker can tell it when something changed; it uses the rest only when something is asked of it. */
const ROUTE = { ready: false, applying: false };
const ROUTE_VIEWS = ['topo', 'graph', 'tasks', 'map', 'scan'];
const routeTab = () => document.querySelector('.tabs button.on')?.dataset.tab || 'details';
const routeHasTab = (name) => !!name && !!document.querySelector(`.tabs button[data-tab="${CSS.escape(name)}"]`);

/* Standalone windows and combined workspace panels mapped from legacy tab names. */
function routeWindowRedirect(r) {
  if (!r || !r.panel) return false;
  const hostQ = r.host ? { host: r.host } : {};
  if (r.panel === 'security') {
    const sub = r.sec || 'overview';
    location.replace(`/security${sfFormatHash([sub], hostQ)}`);
    return true;
  }
  if (r.panel === 'malware') {
    location.replace(`/security${sfFormatHash(['malware'], hostQ)}`);
    return true;
  }
  if (r.panel === 'hostlogs') {
    const p = {};
    for (const k of ['lhost', 'range', 'from', 'to', 'level', 'unit', 'q']) {
      const v = r.q?.get(k);
      if (v) p[k] = v;
    }
    if (!p.lhost && r.host) p.lhost = r.host;
    location.replace(`/logs${sfFormatHash([], p)}`);
    return true;
  }
  if (r.panel === 'keys' || r.panel === 'audit') {
    location.replace(`/admin${sfFormatHash([r.panel])}`);
    return true;
  }
  return false;
}

function routeResolvePanel(r) {
  const sub = r.q?.get('sub');
  if (r.panel === 'schedule' || (r.panel === 'deploy' && sub === 'schedule')) {
    window.DEPLOY_LINK_SUB = 'schedule';
    return 'deploy';
  }
  if (r.panel === 'deploy' && sub === 'deploy') window.DEPLOY_LINK_SUB = 'deploy';
  if (r.panel === 'access' || (r.panel === 'jobs' && sub === 'access')) {
    window.SCANS_LINK_SUB = 'access';
    return 'jobs';
  }
  if (r.panel === 'jobs' && sub === 'jobs') window.SCANS_LINK_SUB = 'jobs';
  if (r.panel === 'docker') {
    if (typeof INF !== 'undefined') INF.view = 'containers';
    return 'infra';
  }
  if (r.panel === 'toolbox') {
    if (typeof INF !== 'undefined') INF.view = 'toolbox';
    if (typeof tbTakeLink === 'function' && r.q) tbTakeLink(r.q);
    return 'infra';
  }
  if (r.panel === 'infra' && sub && typeof INF !== 'undefined') {
    INF.view = sub;
    if (sub === 'toolbox' && typeof tbTakeLink === 'function' && r.q) tbTakeLink(r.q);
  }
  if (r.panel === 'rebuild' && sub) window.REBUILD_LINK_SUB = sub;
  return r.panel;
}

function routeState() {
  const tab = routeTab();
  const params = { host: S.host };
  if (T.mode === 'map' && typeof mapRouteParams === 'function') Object.assign(params, mapRouteParams());
  if (tab === 'deploy' && typeof DEPLOY_SUB !== 'undefined' && DEPLOY_SUB !== 'deploy') params.sub = DEPLOY_SUB;
  if (tab === 'jobs' && typeof SCANS_SUB !== 'undefined' && SCANS_SUB !== 'jobs') params.sub = SCANS_SUB;
  if (tab === 'rebuild' && typeof REBUILD_SUB !== 'undefined' && REBUILD_SUB !== 'configs') params.sub = REBUILD_SUB;
  if (tab === 'infra' && typeof INF !== 'undefined' && INF.view !== 'workloads') params.sub = INF.view;
  if (tab === 'infra' && typeof INF !== 'undefined' && INF.view === 'toolbox' && typeof tbRouteParams === 'function') Object.assign(params, tbRouteParams());
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
  if (routeWindowRedirect(r)) return;
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
    const resolved = routeResolvePanel(r);
    if (routeHasTab(resolved)) showTab(resolved);
  } finally { ROUTE.applying = was; }
}

/* At start: the host and the view now, and the panel (returned) once the data is in. */
function routeTake() {
  ROUTE.seen = location.hash;                     // what start-up read: a change after this and before routeStart() is not lost
  const r = routeRead();
  if (routeWindowRedirect(r)) return null;
  if (!r.view && !r.panel && !r.host) return null;
  routeApply({ ...r, panel: null });
  const resolved = routeResolvePanel(r);
  return routeHasTab(resolved) ? resolved : null;
}

function routeStart() {                           // once the page has what it needs: the URL is made canonical, and from here it is followed
  ROUTE.ready = true;
  document.documentElement.dataset.routeReady = '1';          // from here a choice is a step in the history; a test, or anything that drives the page, can wait for this
  if (ROUTE.seen !== undefined && location.hash !== ROUTE.seen) routeApply(routeRead());     // a link or typed address during start-up: hashchange was not followed yet
  routeSync(true);
}

addEventListener('hashchange', () => {            // Back and Forward, a typed URL, a link inside the page
  if (!ROUTE.ready) return;
  routeApply(routeRead());
  routeSync(true);
});
