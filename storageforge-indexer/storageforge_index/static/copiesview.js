'use strict';
/* Copies on other hosts (copies.py): the list at the top of Cleanup, Duplicates, and the Keep in sync dialog the file map opens too.
   A folder with a copy on another host is a possible backup. Keep in sync saves a Moves plan with one mirror step and opens it in
   Moves: nothing is copied until that plan is deployed there, with the password. A pair with a deployed sync is listed as kept in
   sync, with the state and last run of its job. Loaded after checks.js; uses the helpers of app.js and topology.js and the kernel's
   dialog. DOM APIs only. */

const CP = { data: null, seq: 0 };
const cpAt = (p) => `${p.host}:${p.path}`;
// not "Keep in sync…" alone: the file map has that for sending a picked folder to a folder you choose
const cpSyncLabel = (copies) => (copies === 2 ? 'Keep these two in sync…' : 'Keep two of these in sync…');
const CP_PILL = { ok: 'pill protected', failed: 'pill broken', stale: 'pill broken', missing: 'pill broken', 'never-ran': 'pill unknown', paused: 'pill unknown' };

/* ── the dialog: which side is the source ────────────────────────── */
/* places: the folders of one set of copies, [{host, path}, …]. Answers the prepared plan ({plan, name, existing}), or null. */
async function copiesKeepInSync(places) {
  const qs = new URLSearchParams();
  for (const p of places) { qs.append('host', p.host); qs.append('path', p.path); }
  let info;
  try { info = await getJSON(`/api/copies/sides?${qs}`); } catch (err) { notify(err.message, 'error'); return null; }
  const sides = info.sides;
  const choice = await new Promise((resolve) => {
    const id = `cp-sync-${++CP.seq}`;
    let answer = null;
    const says = (s) => `${cpAt(s)} · ${s.indexed ? `${s.files.toLocaleString()} files, ${fmtBytes(s.bytes)}, last change ${s.changed_at ? fmtTime(s.changed_at) : 'not known'}` : 'not in the index'}`;
    const src = sfNode('select', { class: 'cp-src', 'aria-label': 'Source: the side that is copied from' }, sides.map((s, i) => sfNode('option', { value: String(i) }, says(s))));
    const dst = sfNode('select', { class: 'cp-dst', 'aria-label': 'Destination: the side that is written to' });
    const fill = () => {                     // the destination is one of the other sides
      const was = dst.value;
      dst.replaceChildren(...sides.map((s, i) => (String(i) === src.value ? null : sfNode('option', { value: String(i) }, cpAt(s)))).filter(Boolean));
      if ([...dst.options].some((o) => o.value === was)) dst.value = was;
    };
    src.value = String(info.source);
    fill();
    src.addEventListener('change', fill);
    const del = sfNode('input', { type: 'checkbox', class: 'cp-delete' });
    const runs = sfNode('select', { class: 'cp-runs', 'aria-label': 'How often it runs' }, [['hourly', 'every hour'], ['daily', 'every day'], ['weekly', 'every week']].map(([v, t]) => sfNode('option', { value: v }, t)));
    runs.value = 'daily';
    const no = sfNode('button', { type: 'button', class: 'sf-btn ghost' }, 'Cancel');
    const form = sfNode('form', { method: 'dialog', class: 'cp-sync' },
      sfNode('h2', { id }, 'Keep these two in sync'),
      sfNode('p', { class: 'muted' }, 'One way, from the source to the destination, on a timer. A file that differs at the destination is replaced by the one from the source. Nothing else there is removed unless you tick the box below.'),
      sfNode('label', { class: 'sf-field' }, sfNode('span', {}, `Source. The side that changed last is offered: ${cpAt(sides[info.source])}`), src),
      sfNode('label', { class: 'sf-field' }, sfNode('span', {}, 'Destination'), dst),
      sfNode('label', { class: 'sf-field' }, sfNode('span', {}, 'Runs'), runs),
      sfNode('label', { class: 'check' }, del, 'Also delete at the destination what is gone from the source'),
      sfNode('p', { class: 'muted small' }, 'This saves a plan in Moves with one mirror step. Nothing is copied until you check it there and deploy it, with your password.'),
      sfNode('div', { class: 'sf-actions' }, no, sfNode('button', { type: 'submit', class: 'sf-btn pri' }, 'Prepare the sync')));
    const dlg = sfModal(form, id);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const from = sides[Number(src.value)], to = sides[Number(dst.value)];
      answer = { src: { host: from.host, path: from.path }, dst: { host: to.host, path: to.path }, delete: del.checked, schedule: runs.value };
      dlg.close();
    });
    no.addEventListener('click', () => dlg.close());
    dlg.addEventListener('close', () => resolve(answer));
    src.focus();
  });
  if (!choice) return null;
  let got;
  try { got = await (await postJSON('/api/copies/sync', choice)).json(); } catch (err) { notify(err.message, 'error'); return null; }
  copiesOpenPlan(got);
  return got;
}
function copiesOpenPlan(got) {             // the plan is read and deployed in Moves, like any other
  const what = `${got.existing ? 'Already prepared' : 'Prepared'} as the Moves plan "${got.name}". `;
  if (typeof MV !== 'undefined' && MV.dirty) {
    notify(`${what}Moves holds changes that are not saved: save or discard them, then pick this plan there to check and deploy it.`, 'error');
  } else {
    toast(`${what}Check it and deploy it there: nothing syncs until then.`);
    showTab('moves');
    loadMoves(got.plan);
  }
  loadPairs();
}

/* "These are not a backup of each other": the set is set aside and no longer suggested or counted in the notification, until Suggest again. */
async function copiesDismiss(places, on) {
  try { await postJSON('/api/copies/dismiss', { copies: places.map(({ host, path }) => ({ host, path })), dismissed: on }); }
  catch (err) { notify(err.message, 'error'); return false; }
  toast(on ? 'Set aside. It is not suggested again, and stays listed under "Not a backup of each other".' : 'It is suggested again.');
  await loadPairs();
  return true;
}

/* ── the list in Cleanup ─────────────────────────────────────────── */
async function loadPairs() {
  const box = $('#pairsbox');
  if (!box) return;
  if (!CP.data) box.replaceChildren(text('p', 'Comparing folders…', 'muted'));
  try { CP.data = await getJSON('/api/copies'); } catch (err) { box.replaceChildren(text('p', err.message, 'st-failed')); return; }
  renderPairs();
  if (CP.data.stale) setTimeout(() => { if (box.isConnected && CP.data?.stale) loadPairs(); }, STALE_AGAIN_MS);
}
function cpPlaces(places) {               // the two-part button the folder copies below use: host, then path, as text
  const ol = el('ol', { class: 'copies' });
  for (const c of places) {
    const b = Object.assign(button('', () => runSearch({ under: c.path, host: c.host }), 'copy'), { title: 'List the files in this folder' });
    b.append(text('span', c.host, 'm'), text('span', c.path, 'p'));
    ol.append(el('li', {}, b));
  }
  return ol;
}
function cpKept(k) {
  const last = k.last ? `last run ${fmtTime(k.last.end || k.last.start)}` : 'no run yet';
  const good = k.last_ok && k.last && k.last_ok.run !== k.last.run ? ` · last good run ${fmtTime(k.last_ok.end || k.last_ok.start)}` : '';
  return el('section', { class: 'card kept', 'data-state': k.state },
    el('div', { class: 'row wrap' }, el('b', {}, `${cpAt(k.src)} → ${cpAt(k.dst)}`),
      text('span', `kept in sync · ${k.state_text}`, CP_PILL[k.state] || 'pill unknown')),
    text('p', `${last}${good} · runs ${k.schedule || 'when started'} · one way${k.delete ? ', and deletes at the destination what is gone from the source' : ', nothing deleted at the destination'}`, 'muted small'),
    el('div', { class: 'row' }, button('Open in Deploy', () => showTab('deploy'), 'btn ghost sm'),
      k.plan ? button('Open its plan', () => { showTab('moves'); loadMoves(k.plan); }, 'btn ghost sm') : null));
}
function cpSuggested(s) {
  const acts = [];
  if (s.prepared) {
    acts.push(text('span', `Prepared as the Moves plan "${s.prepared.name}", not deployed yet`, 'muted small'),
      button('Open the plan', () => { showTab('moves'); loadMoves(s.prepared.plan); }, 'btn sm'));
  } else if (can('plans.edit')) {
    acts.push(Object.assign(button(cpSyncLabel(s.copies.length), () => copiesKeepInSync(s.copies.map(({ host, path }) => ({ host, path }))), 'btn sm pri'),
      { title: 'Prepares a plan in Moves that copies one side to the other on a timer. Nothing syncs until you deploy it there' }));
  }
  if (can('plans.edit')) {
    acts.push(Object.assign(button('Not a backup of each other', () => copiesDismiss(s.copies, true), 'btn ghost sm'),
      { title: 'Stops suggesting this set and counting it in the notification. The folders stay listed as copies on other hosts' }));
  }
  return el('section', { class: 'card suggested' },
    el('div', { class: 'row wrap' }, el('b', {}, `${s.files.toLocaleString()} files · ${fmtBytes(s.bytes)}`), copyElsewherePill(),
      s.same_name ? null : text('span', 'renamed', 'pill unknown')),
    cpPlaces(s.copies), el('div', { class: 'row wrap cpacts' }, ...acts));
}
function cpAside(s) {
  return el('section', { class: 'card aside' },
    el('div', { class: 'row wrap' }, el('b', {}, `${s.files.toLocaleString()} files · ${fmtBytes(s.bytes)}`)),
    cpPlaces(s.copies),
    can('plans.edit') ? el('div', { class: 'row' }, button('Suggest again', () => copiesDismiss(s.copies, false), 'btn ghost sm')) : null);
}
function renderPairs() {
  const d = CP.data, box = $('#pairsbox');
  if (!d || !box) return;
  const here = (places) => !S.host || places.some((p) => p.host === S.host);
  const kept = d.kept.filter((k) => here([k.src, k.dst])), suggested = d.suggested.filter((s) => here(s.copies)), aside = d.dismissed.filter((s) => here(s.copies));
  const out = [staleNote(d)].filter(Boolean);
  if (kept.length) out.push(text('h4', `Kept in sync (${kept.length})`), ...kept.map(cpKept));
  out.push(text('h4', `Not kept in sync (${suggested.length})`));
  if (suggested.length) out.push(text('p', 'Largest first. Keep a pair in sync, or say that it is not a backup of each other and it is not suggested again.', 'muted small'),
    sfMoreList(suggested, cpSuggested, { limit: 8, label: 'pairs', className: 'stack' }));
  else out.push(text('p', kept.length || aside.length ? 'Nothing is left to answer: every folder with a copy on another host is kept in sync or set aside.' : 'No folder has a copy on another host at this size.', 'muted'));
  if (aside.length) {
    out.push(el('details', { class: 'cpaside', open: CP.asideOpen || null, ontoggle: (ev) => { CP.asideOpen = ev.target.open; } },
      el('summary', {}, `Not a backup of each other (${aside.length})`),
      text('p', 'You said these are not a backup of each other. They are not suggested and not counted in the notification.', 'muted small'),
      ...aside.map(cpAside)));
  }
  box.replaceChildren(...out);
}
$('#host').addEventListener('change', renderPairs);
