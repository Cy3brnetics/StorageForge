'use strict';
/* Standalone Security & Threat Center window (/security): connects securityview.js, securitymore.js and malwareview.js
   with URL routing (#/<panel>?host=...), host filtering and the Ctrl+K palette. */

let secBooted = false;

function routeSync(replace = false) {
  if (!secBooted) return;
  const h = sfFormatHash([SEC.panel], { host: S.host });
  if (replace) sfReplaceHash(h);
  else sfPushHash(h);
}

function secApplyHash() {
  const p = sfParseHash();
  const q = p.q;
  const sub = p.parts[0] || q.get('sec') || 'overview';
  if (q.has('host')) {
    S.host = q.get('host') || '';
    const sel = $('#host');
    if (sel) sel.value = S.host;
  }
  if (SEC_PANELS.some(([id]) => id === sub)) SEC.panel = sub;
}

$('#host')?.addEventListener('change', () => {
  S.host = $('#host').value;
  routeSync();
  secRender();
});

sfPaletteSource(() => {
  if (!ME || (!can('security.view') && !can('files.browse'))) return [];
  return SEC_PANELS.map(([id, name]) => ({
    label: `Security: ${name}`,
    hint: 'Security panel',
    run: () => secOpen(id),
  }));
});

(async function boot() {
  try {
    const [me] = await Promise.all([sfMe(), populateHostSelect($('#host'))]);
    setMe(me);
    if (me.site) document.title = `${me.site} · Security Center · StorageForge`;
    secApplyHash();
    const sel = $('#host');
    if (sel && S.host) sel.value = S.host;
    if (!can('security.view') && !can('files.browse')) {
      $('#sec-banner').replaceChildren(text('p', 'Your account cannot view security posture.', 'st-failed'));
    } else if (!can('security.view') && can('files.browse')) {
      SEC.panel = 'malware';
      await loadSecurity();
    } else {
      await loadSecurity();
    }
    secBooted = true;
    routeSync(true);
    window.addEventListener('hashchange', () => {
      secApplyHash();
      secRender();
      document.querySelectorAll('#sec-subnav button').forEach((b) => b.setAttribute('aria-pressed', b.dataset.sub === SEC.panel));
    });
    document.addEventListener('sf:scan', async () => {
      if (!secBooted || document.querySelector('dialog[open]')) return;
      await populateHostSelect($('#host'));
      await loadSecurity();
    });
  } catch (err) {
    if (!/Sign in/.test(err.message)) {
      $('#sec-content').replaceChildren(text('p', err.message, 'st-failed'));
    }
  } finally {
    document.documentElement.dataset.routeReady = '1';
  }
})();
