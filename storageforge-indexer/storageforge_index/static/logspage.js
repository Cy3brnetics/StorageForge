'use strict';
/* Standalone Host Logs & Monitoring window (/logs): binds URL hash parameters to hostlogsview.js. */

let hlBooted = false;

function routeSync(replace = false) {
  if (!hlBooted) return;
  const h = sfFormatHash([], hlRouteParams());
  if (replace) sfReplaceHash(h);
  else sfPushHash(h);
}

(async function boot() {
  try {
    const me = await getJSON('/api/me');
    setMe(me);
    if (me.site) document.title = `${me.site} · Host Logs · StorageForge`;
    if (!can('hostlogs.view')) {
      $('#logs-root').replaceChildren(text('p', 'Your account cannot view host logs.', 'st-failed'));
      return;
    }
    const p = sfParseHash();
    hlTakeLink(p.q);
    await loadHostLogs();
    hlBooted = true;
    routeSync(true);
    window.addEventListener('hashchange', () => {
      hlTakeLink(sfParseHash().q);
      loadHostLogs();
    });
  } catch (err) {
    if (!/Sign in/.test(err.message)) {
      $('#logs-root').replaceChildren(text('p', err.message, 'st-failed'));
    }
  } finally {
    document.documentElement.dataset.routeReady = '1';
  }
})();
