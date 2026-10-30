---
id: GM-07
status: open
severity: high
effort: S
area: "[[Plans, Planner and UI]]"
tags: [finding, security, xss, planner, ui, gemini-audit]
found: 2026-10-29
---
# GM-07 Planner innerHTML sinks lack escaping on tier, kind, and device identifiers

## Location
- `storageforge_index/static/planner.js:14-23, 586-593, 628, 636-637, 645-646, 742, 766, 788-797, 802-803, 983-989, 1142, 1160-1162`
- `storageforge_index/blueprint.py:26-54`

## Mechanics & Root Cause
### 1. Incomplete Field Sanitization in `tidy(s)` (`planner.js:14-23`)
```javascript
const scrub=x=>typeof x==='string'?x.replace(/[\x00-\x1f\x7f<>"'`]/g,''):Array.isArray(x)?x.map(scrub):x&&typeof x==='object'?Object.fromEntries(Object.entries(x).map(([k,v])=>[k,scrub(v)])):x;
const ident=s=>String(s??'').replace(/[^A-Za-z0-9._@+:-]/g,'');
const tidy=s=>{(s.disks||[]).forEach(d=>{d.dev=ident(d.dev);d.table=ident(d.table||'gpt');(d.parts||[]).forEach(p=>{p.id=ident(p.id);p.fs=ident(p.fs);if(p.member)p.member=ident(p.member);if(p.role)p.role=ident(p.role);(p.subvols||[]).forEach(sv=>{sv.name=ident(sv.name)})})});
  (s.pools||[]).forEach(p=>{p.name=ident(p.name);p.type=ident(p.type);p.level=ident(p.level);if(p.fs)p.fs=ident(p.fs);if(p.vg)p.vg=ident(p.vg);if(p.lv)p.lv=ident(p.lv);(p.datasets||[]).forEach(ds=>{ds.name=ident(ds.name)})});
  (s.remotes||[]).forEach(r=>{r.id=ident(r.id)});(s.exports||[]).forEach(e=>{e.id=ident(e.id)});return s};
```
While `scrub(x)` strips `<> "'` `` ` `` when loading from `localStorage` (`line 114`) or `fromBlueprint` (`line 956`), `tidy(s)` does **not** restrict `d.tier`, `p.tier`, `l.kind`, `r.proto`, `r.status`, `ds.recordsize`, `ds.compression`, `ds.sync`, or `p.encryption` with `ident()` or an enum whitelist. Furthermore, runtime mutations in `planner.js:1132-1163` (`view.addEventListener('change', ...)` and `view.addEventListener('submit', ...)`) modify `S` and call `commit()` -> `render()` directly without running `scrub()` or `tidy()`.

### 2. Unescaped Interpolations in `innerHTML` Sinks (`planner.js`)
Multiple rendering functions interpolate state properties directly into HTML attributes and element bodies without `esc()`:
- `d.tier` and `p.tier` (`planner.js:636, 637, 645, 742, 788, 793`):
  ```javascript
  return `<article class="disk ${d.tier} ${sel?'sel':''}" ...>
    <div class="dh"><span class="dev">/dev/${esc(d.dev)}</span><span class="chip t-${d.tier}">${esc(d.bus)}</span>...
  ```
- `l.kind` (`planner.js:766, 803`):
  ```javascript
  return `<tr data-node="link:${esc(l.id)}"><td><span class="kind ${l.kind}">${l.kind}</span></td>...`
  ```
- `d.dev`, `x.id`, `p.name`, `p.type`, `p.level` in Overview & Devices (`planner.js:589, 590, 628, 646`):
  ```javascript
  // line 590
  return it('pool:'+p.name,`${p.name} · ${p.type} ${p.level}`,...)
  // line 628
  segs=`<button type="button" ... data-node="disk:${d.dev}" ...>`
  ```
  Notice `ident()` allows `+`, `:`, `@`, `.`, `-`, `_`, while `d.tier` and `l.kind` allow any string not containing `<> "'` `` ` `` (including whitespace, which breaks out of unquoted attributes or injects extra CSS classes/attributes).

### 3. Missing `reauth: true` Handling in `planner.js:apiJSON` (`planner.js:983-989`)
Unlike `app.js`, `apiJSON()` in `planner.js:983-989` handles `r.status === 401` by redirecting to `/login`, but does **not** check for `r.status === 403 && d.reauth` (`SF.reauth()`), so any `@password_confirmed` action added to planner endpoints fails without prompting for password confirmation.

## Impact
Crafted `tier` or `kind` values in imported blueprints inject arbitrary classes/attributes into the Planner DOM, and direct state edits bypass `tidy(s)`/`scrub(s)` before rendering into `innerHTML`.

## Remediation
1. Enforce enum whitelists in `tidy(s)` for `d.tier` (`['fast','mass','remote']`), `p.tier` (`['fast','mass','remote']`), and `l.kind` (`['symlink','bind','hardlink']`).
2. Wrap all `innerHTML` interpolations (`d.tier`, `p.tier`, `l.kind`, `p.name`, `p.type`, `p.level`, `d.dev`, `x.id`) in `esc(...)`.
3. Add `if (r.status === 403 && d && d.reauth && window.SF) ...` handling to `apiJSON()` in `planner.js:983-989`.

## Done when
- [ ] `tidy(s)` validates `tier` and `kind` against allowed enums and all `innerHTML` interpolations in `planner.js` use `esc()`.
