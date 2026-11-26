'use strict';
/* The Workloads page's two ways to make a change: the create wizard (WL.onNew) and the review of one step from the panel (WL.onAction).
   Both end the same way: the step is checked with POST /api/changes/check, the items are shown, and Save as a plan stores a plan of that one
   step (POST /api/changes), where report and apply happen in Changes as ever. Nothing here changes a host. The fields come from the step's
   spec (GET /api/changes/types) through stepFields, the same code the Changes forms use. Loaded after workloads.js, stepfields.js. */

// the kinds that create something, by the runtime that holds what they make
const WW_KINDS = { docker: ['container', 'stack'], podman: ['container', 'stack'], libvirt: ['vm-create', 'vm-iso', 'vm'], incus: ['incus'], lxc: ['lxc'], proxmox: ['pve-vm', 'pve-ct'] };
const WW_WHERE = ['storage', 'pool', 'template', 'iso'];
const WW_WHERE_OF = { 'pve-vm': ['source', 'iso', 'image'] };      // what a VM is made from belongs with where its disk goes
const WW_GROUPS = [
  ['Resources', ['cores', 'vcpus', 'memory_mb', 'ram_mb', 'disk_gb', 'disk']],
  ['Network', ['bridge', 'network', 'ip', 'gateway', 'publish']],
  ['Access', ['user', 'ssh_key', 'key', 'password_secret']],
];
const WW = { types: null, dlg: null };
const wwTypes = async () => { if (!WW.types) WW.types = (await getJSON('/api/changes/types')).types; return WW.types; };
/* a plan name that is not taken by the same step done earlier: the title, then the time, within the 80 characters plans allow */
function wwName(title, n = 1) {
  const d = new Date(), p = (x) => String(x).padStart(2, '0');
  const tail = `, ${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}${n > 1 ? ` (${n})` : ''}`;
  return `workloads: ${title}`.slice(0, 80 - tail.length) + tail;
}
const wwPlanHref = (id) => `/${sfFormatHash(['topo', 'changes'], { plan: id })}`;

/* The create steps a host can take. A Proxmox VE node gets the Proxmox ones, and containers and stacks when it runs Docker or Podman, but not the generic
   VM, LXC and Incus steps (they refuse a node); no other host gets the Proxmox ones. A runtime is offered when the scan found it, and Docker and Podman
   always elsewhere (the step installs nothing: runtime-install does that). */
function wwKinds(types, host, runtime) {
  const have = (host && host.runtimes) || [];
  let rts = host && host.proxmox ? ['proxmox', ...['docker', 'podman'].filter((r) => have.includes(r))] : ['docker', 'podman', ...((host && host.runtimes) || []).filter((r) => !['docker', 'podman', 'proxmox'].includes(r))];
  if (runtime) rts = rts.filter((r) => r === runtime);
  const out = [];
  for (const r of rts) {
    for (const kind of WW_KINDS[r] || []) {
      if (!types[kind]) continue;
      const found = r === 'docker' || r === 'podman' ? ((host && host.runtimes) || []).includes(r) : true;
      out.push({ kind, runtime: r, spec: types[kind], note: found ? '' : `${r} was not found on this host by its last scan; this step installs nothing` });
    }
  }
  return out;
}

/* What a Proxmox node holds, as the select options of the fields that name it; a field with nothing to pick from stays free text */
function wwChoices(entry, host) {
  const node = entry.runtime === 'proxmox' && host && host.proxmox_node;
  if (!node) return {};
  const need = entry.kind === 'pve-ct' ? 'rootdir' : 'images';
  const out = {
    storage: (node.storages || []).filter((s) => !(s.content || []).length || s.content.includes(need)).map((s) => ({ value: s.name, label: `${s.name} (${s.type}${s.active ? '' : ', not active'})` })),
    iso: (node.isos || []).map((i) => ({ value: i.volid, label: i.volid })),
    template: (node.templates || []).map((i) => ({ value: i.volid, label: i.volid })),
  };
  if (out.template.length || entry.kind === 'pve-ct') out.template.free = 'Another template…';       // pveam downloads a named template that is not on the node yet
  for (const k of Object.keys(out)) if (!out[k].length) delete out[k];
  return out;
}

/* a step's fields as pages: where, then the groups of WW_GROUPS, then everything else as Settings */
function wwPages(spec, nodes, kind = '') {
  const items = spec.fields.map((f, i) => ({ f, node: nodes[i] })).filter((x) => x.f.name !== 'runtime');
  const used = new Set();
  const take = (pred) => items.filter((x) => !used.has(x) && pred(x) && used.add(x));
  const pages = [['Where', take((x) => (['name', 'hostname'].includes(x.f.name) && x.f.required) || WW_WHERE.includes(x.f.name) || (WW_WHERE_OF[kind] || []).includes(x.f.name) || x.f.kind === 'path')]];
  for (const [title, names] of WW_GROUPS) pages.push([title, take((x) => names.includes(x.f.name))]);
  pages.push(['Settings', take(() => true)]);
  return pages.filter(([, xs]) => xs.length).map(([title, xs]) => ({ title, items: xs }));
}

/* a Proxmox VM has the ISO field when it installs from an ISO and the image field when it comes from a cloud image, never both */
function wwVmSource(spec, sf) {
  const node = (name) => sf.nodes[spec.fields.findIndex((f) => f.name === name)];
  const show = () => { node('iso').hidden = sf.controls.source.value !== 'iso'; node('image').hidden = sf.controls.source.value !== 'image'; };
  sf.controls.source.addEventListener('change', show);
  show();
}
const wwSection = (xs, kind = '') => {         // required first, optional under More; what a VM is made from is not optional to look at
  const open = (x) => x.f.required || (WW_WHERE_OF[kind] || []).includes(x.f.name);
  const req = xs.filter(open), opt = xs.filter((x) => !open(x));
  return [...req.map((x) => x.node), opt.length ? el('details', {}, el('summary', {}, req.length ? 'More' : 'Optional'), ...opt.map((x) => x.node)) : null];
};

/* ── the review: check, show, save ────────────────────────────────── */
function wwReview(box, step, spec, { title = '', done = () => {}, back = null } = {}) {
  const S = { seq: 0, check: null, error: '', idle: false, saved: null, busy: false, touched: false, focusNext: true, tries: 1, title: title || spec.label || step.type };
  // fields the panel did not fill (Edit…, Snapshots…, a snapshot name) are asked here, above the check
  const extra = (spec.fields || []).filter((f) => !(f.name in step.params) && f.kind !== 'confirm');
  const form = extra.length ? stepFields({ ...spec, fields: spec.fields }, step.params, { type: step.type, host: step.host }) : null;
  const formNodes = form ? form.nodes.filter((_, i) => extra.includes(spec.fields[i])) : [];
  const confirmField = (spec.fields || []).find((f) => f.kind === 'confirm');
  const want = confirmField ? String(step.params[spec.confirm_of || ''] || '') : '';
  const confirmInput = confirmField ? el('input', { type: 'text', class: 'mono', autocomplete: 'off', spellcheck: false, 'aria-label': confirmField.label, placeholder: want }) : null;
  const nameInput = el('input', { type: 'text', maxLength: 80, 'aria-label': 'Plan name', value: wwName(title || spec.label || step.type) });
  nameInput.addEventListener('input', () => {
    S.touched = true;
    if (S.error) { S.error = ''; if (S.check) draw(); else run(); }          // a failed save must not keep Save off once the name is edited
  });
  // a step the panel gave nothing to (engine settings) is not checked while every field is empty: that check can only say "set at least one"
  const hold = extra.length > 0 && !Object.values(step.params).some((v) => typeof v === 'string' && v.trim());
  const confirmed = () => !confirmInput || (want ? confirmInput.value.trim() === want : !!confirmInput.value.trim());
  const body = () => ({ name: nameInput.value.trim(), tasks: [{ ...step, params: { ...step.params, ...(form ? Object.fromEntries(extra.map((f) => [f.name, form.read()[f.name]])) : {}), ...(confirmInput ? { confirm: confirmInput.value.trim() } : {}) } }] });
  async function run() {
    const n = ++S.seq;
    S.check = null; S.error = ''; S.idle = false;
    if (!confirmed()) { draw(); return; }
    if (hold && !Object.values(body().tasks[0].params).some((v) => typeof v === 'string' && v.trim())) { S.idle = true; draw(); return; }
    draw();
    try {
      const r = await (await postJSON('/api/changes/check', { ...body(), name: 'check' })).json();
      if (n !== S.seq) return;
      S.check = r;
      const t = r.tasks && r.tasks[0];
      if (t && t.title && !S.touched) { S.title = t.title; nameInput.value = wwName(t.title); }
    } catch (err) { if (n !== S.seq) return; S.error = err.message; }
    draw();
  }
  async function save() {
    S.busy = true; draw();
    try {
      let plan;
      try { plan = await (await postJSON('/api/changes', body())).json(); }
      catch (err) {          // the name is taken: once more with a number, since the person did not choose this name
        if (S.touched || S.tries > 1 || !/already exists/.test(err.message)) throw err;
        S.tries = 2; nameInput.value = wwName(S.title, 2);
        plan = await (await postJSON('/api/changes', body())).json();
      }
      S.saved = plan.id; WW.last = plan.id;
    } catch (err) { S.error = err.message; }
    S.busy = false; draw();
  }
  // the inputs are mounted once and never replaced, so typing keeps its focus; draw() only fills the results region and the Save button
  const results = el('div', { class: 'stack' });
  const saveBtn = el('button', { type: 'button', class: 'btn pri sm wlsave', disabled: true, onclick: save }, 'Save as a plan');
  const mounted = [
    el('div', { class: 'row' }, el('b', {}, spec.label || step.type), text('span', `${spec.group || ''} · ${step.host}`, 'muted small')),
    spec.help ? text('p', spec.help, 'muted small') : null,
    ...formNodes,
    spec.destructive ? text('p', 'This step is destructive. Its script only does this with --apply --destructive.', 'st-failed small') : null,
    confirmInput ? el('label', { class: 'field col' }, el('span', {}, confirmField.label + (want ? ` (${want})` : '')), confirmInput) : null,
    results,
    el('label', { class: 'field col' }, el('span', {}, 'Plan name'), nameInput),
    text('p', 'Checked against the last scan of each host. Saving makes a change plan; nothing is changed until you apply it from Changes.', 'muted small'),
    el('div', { class: 'row end' }, back ? button('Back', back, 'btn ghost sm') : null, button('Cancel', () => done(null), 'btn ghost sm'), saveBtn)];
  const canSave = () => !!S.check && !S.check.crit && !S.error && !S.busy && !!nameInput.value.trim();
  function draw() {
    if (S.saved) {
      box.replaceChildren(text('p', `Saved as plan ${S.saved}.`, 'st-ok'),
        text('p', 'Nothing has changed on the host yet. Open the plan in Changes to read its report and apply it.', 'muted small'),
        el('div', { class: 'row end' }, el('a', { class: 'btn pri sm wlopen', href: wwPlanHref(S.saved) }, `Open plan ${S.saved} in Changes`), button('Close', () => done(S.saved), 'btn sm')));
      box.querySelector('.wlopen').focus();
      return;
    }
    const items = S.check && S.check.tasks[0] ? S.check.tasks[0].items : [];
    const order = { crit: 0, warn: 1, ok: 2, note: 3 };
    const sorted = [...items].sort((a, b) => order[a.level] - order[b.level]);
    const crit = S.check ? S.check.crit : 0, warn = S.check ? S.check.warn : 0;
    const waiting = !S.check && !S.error && !S.idle && confirmed();
    results.replaceChildren(
      el('div', { class: 'row' }, text('h3', 'Checks'),
        text('span', waiting ? 'checking…' : S.idle ? 'waiting for a value' : !confirmed() ? 'waiting for the confirmation' : S.error ? 'error' : crit ? `${crit} to fix` : warn ? `${warn} warning${warn === 1 ? '' : 's'}` : 'all good',
          waiting || S.idle || !confirmed() ? 'muted small' : crit || S.error ? 'st-failed small' : warn ? 'st-running small' : 'st-ok small')),
      S.error ? text('p', S.error, 'st-failed') : null,
      S.idle ? text('p', 'Fill in at least one setting above to see what the check says about it.', 'muted small') : null,
      sorted.length ? el('ul', { class: 'mvcheck wl-check' }, ...sorted.map((x) => text('li', x.text, `lv-${x.level}`))) : null);
    saveBtn.disabled = !canSave();
    if (!box.firstChild) {
      box.replaceChildren(...mounted.filter(Boolean));
      if (S.focusNext) { S.focusNext = false; (box.querySelector('input, select') || box.querySelector('button')).focus(); }
    }
  }
  if (form) {
    const again = () => { clearTimeout(S.timer); S.timer = setTimeout(run, 300); };
    formNodes.forEach((n) => { n.addEventListener('input', again); n.addEventListener('change', again); });
  }
  if (confirmInput) confirmInput.addEventListener('input', () => { clearTimeout(S.timer); S.timer = setTimeout(run, 250); });
  nameInput.addEventListener('input', () => { saveBtn.disabled = !canSave(); });
  run();
}

function wwDialog(label) {
  if (WW.dlg) WW.dlg.remove();
  const box = el('div', { class: 'stack wlwiz-body' });
  const dlg = el('dialog', { class: 'sf-dialog wlwiz', 'aria-label': label }, box);
  dlg.addEventListener('close', () => { dlg.remove(); if (WW.dlg === dlg) WW.dlg = null; });
  document.body.append(dlg);
  dlg.showModal();
  WW.dlg = dlg;
  return { box, close: () => dlg.close() };
}

/* reviewStep(step): check one step from the panel and offer to save it as a plan; resolves to the plan's id, or null when closed unsaved */
async function reviewStep(step) {
  let types;
  try { types = await wwTypes(); } catch (err) { notify(err.message, 'error'); return null; }
  const spec = types[step.type];
  if (!spec) { notify(`This version does not know the step ${step.type}.`, 'error'); return null; }
  return new Promise((resolve) => {
    const { box, close } = wwDialog(spec.label);
    WW.dlg.addEventListener('close', () => resolve(WW.last || null), { once: true });
    WW.last = null;
    wwReview(box, step, spec, { done: (id) => { WW.last = id; close(); } });
  });
}

/* ── the wizard ───────────────────────────────────────────────────── */
async function wizOpen({ host = '', runtime = '' } = {}) {
  let types;
  try { types = await wwTypes(); } catch (err) { notify(err.message, 'error'); return null; }
  const hosts = (WL.listing && WL.listing.hosts) || [];
  const hostObj = (n) => hosts.find((h) => h.name === n);
  const W = { host, runtime, entry: null, page: 0, sf: null, pages: [], built: '', msg: '' };
  const { box, close } = wwDialog('Create a workload');
  WW.last = null;
  const finish = (id) => { WW.last = id; close(); };

  function build() {         // the fields of the chosen step on the chosen host; kept while neither changes
    const key = `${W.host}|${W.entry.runtime}|${W.entry.kind}`;
    if (W.built === key) return;
    const prior = W.sf ? W.sf.read() : {};
    W.sf = stepFields(W.entry.spec, { ...prior, ...(W.entry.spec.fields.some((f) => f.name === 'runtime') ? { runtime: W.entry.runtime } : {}) },
      { type: W.entry.kind, host: W.host, choices: wwChoices(W.entry, hostObj(W.host)) });
    W.pages = wwPages(W.entry.spec, W.sf.nodes, W.entry.kind);
    if (W.entry.kind === 'pve-vm') wwVmSource(W.entry.spec, W.sf);
    W.built = key;
  }
  const missing = (xs) => { const v = W.sf.read(); return xs.filter((x) => x.f.required && typeof v[x.f.name] !== 'boolean' && !String(v[x.f.name] || '').trim()).map((x) => x.f.label); };
  const steps = () => ['What', ...(W.entry ? W.pages.map((p) => p.title) : []), 'Review'];
  const stepObj = () => {
    const params = W.sf.read();
    if (W.entry.kind === 'pve-vm') { if (params.source !== 'iso') params.iso = ''; if (params.source !== 'image') params.image = ''; }      // the one that is hidden is not sent
    return { type: W.entry.kind, host: W.host, params };
  };

  function nav(next, hasBack) {
    return el('div', { class: 'row end' }, hasBack ? button('Back', () => { W.page--; W.msg = ''; draw(); }, 'btn ghost sm') : null, button('Cancel', () => finish(null), 'btn ghost sm'), next);
  }
  function draw() {
    const names = steps();
    const head = el('ol', { class: 'wlwiz-steps' }, ...names.map((n, i) => el('li', { 'aria-current': i === W.page ? 'step' : null, class: i === W.page ? 'on' : '' }, n)));
    if (W.page === 0) {
      const kinds = wwKinds(types, hostObj(W.host), W.runtime);
      const hostSel = host ? null : el('label', { class: 'field col' }, el('span', {}, 'Host'),
        el('select', { onchange: (ev) => { W.host = ev.target.value; W.entry = null; draw(); } }, new Option('(choose)', ''), ...hosts.map((h) => new Option(h.name, h.name))));
      if (hostSel) hostSel.querySelector('select').value = W.host;
      const list = !W.host ? text('p', 'Pick a host first.', 'muted small') : !kinds.length ? text('p', 'This host has nothing that can run here yet: no runtime was found by its last scan.', 'muted small') :
        el('div', { class: 'stack', role: 'radiogroup', 'aria-label': 'What to create' }, ...kinds.map((k, i) => {
          const r = el('input', { type: 'radio', name: 'wwkind', checked: !!W.entry && W.entry.kind === k.kind && W.entry.runtime === k.runtime, onchange: () => { W.entry = k; W.msg = ''; } });
          return el('label', { class: 'check wlwiz-kind', 'data-kind': k.kind }, r, el('span', {}, el('b', {}, k.spec.label), ` · ${k.runtime}`, k.spec.help ? el('small', { class: 'muted' }, ` ${k.spec.help}`) : null, k.note ? el('small', { class: 'muted' }, ` ${k.note}`) : null));
        }));
      box.replaceChildren(el('h2', {}, 'Create a workload'), head, hostSel, W.host ? text('p', `On ${W.host}`, 'muted small') : null, list,
        W.msg ? text('p', W.msg, 'st-failed small') : null,
        nav(button('Next', () => {
          if (!W.entry) { W.msg = 'Choose what to create.'; draw(); return; }
          build(); W.page = 1; W.msg = ''; draw();
        }, 'btn pri sm'), false));
      box.querySelector('input, select')?.focus();
      return;
    }
    const last = W.page === names.length - 1;
    if (last) {
      const rv = el('div', { class: 'stack' });
      box.replaceChildren(el('h2', {}, 'Review'), head, rv);
      wwReview(rv, stepObj(), W.entry.spec, { done: finish, back: () => { W.page--; draw(); } });
      return;
    }
    const pg = W.pages[W.page - 1];
    box.replaceChildren(el('h2', {}, pg.title), head, W.page === 1 ? text('p', `${W.entry.spec.label} on ${W.host}`, 'muted small') : null, el('div', { class: 'stack' }, ...wwSection(pg.items, W.entry.kind)),
      W.msg ? text('p', W.msg, 'st-failed small') : null,
      nav(button('Next', () => {
        const gap = missing(pg.items);
        if (gap.length) { W.msg = `Fill in: ${gap.join(', ')}.`; draw(); return; }
        W.page++; W.msg = ''; draw();
      }, 'btn pri sm'), true));
    box.querySelector('input, select')?.focus();
  }
  if (host && runtime) {          // opened from a runtime: its only kind is the one to pick when there is just one
    const only = wwKinds(types, hostObj(host), runtime);
    if (only.length === 1) W.entry = only[0];
  }
  draw();
  return new Promise((resolve) => WW.dlg.addEventListener('close', () => resolve(WW.last || null), { once: true }));
}

WL.onNew = (where) => { wizOpen(where); };
WL.onAction = (step) => { reviewStep(step); };
