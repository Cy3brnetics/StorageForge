---
id: GM-05
status: open
severity: high
effort: S
area: "[[API, Auth and Security]]"
tags: [finding, security, deploy, vault, gemini-audit]
found: 2026-10-29
---
# GM-05 Deploy adopt lacks hostname validation and binds arbitrary vault patterns

## Location
- `storageforge_index/server.py:1023-1027` (`api_deploy_adopt()`)
- `storageforge_index/deploy.py:550-563` (`adopt()`)

## Mechanics & Root Cause
`POST /api/deploy/adopt` (`server.py:1023-1027`) passes `str(json_body().get('host', '')).strip()` directly to `deploy.adopt()` without calling `keyinstall.validate()` or `scriptkit.host_name()`:
```python
# server.py:1023-1027
@web.post('/api/deploy/adopt')
@login_required
@password_confirmed
def api_deploy_adopt():
    return jsonify(deploy.adopt(db, conn(), str(json_body().get('host', '')).strip(), actor()))
```
In `deploy.adopt()` (`deploy.py:550-563`):
```python
def adopt(db, conn, host: str, actor: str | None = None) -> dict:
    """After the setup script was run by hand: bind the deploy key to the host and prove a signed run works."""
    actor = actor or actor_name()
    name, addr = canonical(conn, host), connect_address(conn, host)
    port = conn.scalar('SELECT ssh_port FROM hosts WHERE hostname = :h', {'h': name}) or 22
    with Vault(db, conn).unlock() as v:
        ensure_keys(v)
        if not [b for b in v.bindings() if b['key'] == DEPLOY_KEY and b['pattern'] == addr]:
            v.bind(DEPLOY_KEY, addr, DEPLOY_USER, port, actions='deploy', priority=50)
    probe = run(db, name, 'echo "signed runs work on $(uname -n): $(id -un), $(ssh -V 2>&1)"', kind='setup', ref='probe',
                mode='apply', actor=actor, require_ready=False)
    state = 'ready' if probe['status'] == 'ok' else 'failed'
    set_access(conn, name, state, probe['output'], actor)
    return {'host': name, 'state': state, 'output': probe['output']}
```
1. If `host` is not already in `hosts`, `canonical()` and `connect_address()` return `host` verbatim.
2. `v.bind(DEPLOY_KEY, addr, ...)` (`deploy.py:558`) accepts glob patterns (`*`, `*.lan`), CIDR ranges (`0.0.0.0/0`, `10.0.0.0/8`), empty strings, or strings starting with `-`.
3. Even when `probe = run(db, name, ...)` on line 559 subsequently fails (`state = 'failed'`), `v.bind()` has **already committed the binding** to `key_bindings` in the database and never removes it on probe failure!

## Impact
An operator or attacker can permanently bind `storageforge-deploy` (the root-capable deploy SSH key) to wildcard patterns like `*` or `0.0.0.0/0` at priority `50`, or leave behind broken/dangling deploy bindings whenever `adopt` fails its probe.

## Remediation
1. Validate `host` with `keyinstall.validate(host, DEPLOY_USER, 22)` (which enforces `HOST.fullmatch(host)` and rejects `*`, `?`, `/`, or leading `-`) at the start of `deploy.adopt()`.
2. If `probe['status'] != 'ok'` and the binding was newly created by `adopt()`, unbind it so failed adoptions do not leave active deploy bindings in the vault.

## Done when
- [ ] `deploy.adopt()` validates `host` with `keyinstall.validate()` and removes newly created bindings if the probe fails.
