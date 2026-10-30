---
id: GM-20
status: open
severity: medium
effort: S
area: "[[API, Auth and Security]]"
tags: [finding, logic, access, deploy, ssh, gemini-audit]
found: 2026-10-29
---
# GM-20 Deploy enroll and sudo_run fail without existing scan key binding or on non-default SSH ports

## Location
- `storageforge_index/access.py:119-156` (`sudo_run()`)
- `storageforge_index/deploy.py:284-314` (`enroll()`)
- `storageforge_index/server.py:752, 1017` (`api_access_grant()`, `api_deploy_access()`)

## Mechanics & Root Cause
1. **`access.sudo_run()` Unconditionally Requires a `'scan'` Key Binding (`access.py:124-143`)**:
   ```python
   host = connect_address(conn, host)
   with Vault(db, conn).unlock() as v:
       b = v.resolve(host, 'scan')
       from .hostkeys import require_confirmed
       require_confirmed(conn, host, b.port)          # a password goes only to a host key a person confirmed
       script = make_script(b.user)
       sudo = 'sudo -S -p "" sh -c ' + shlex.quote(script)
       if not admin_user or admin_user == b.user:
           # the scan user's own sudo rights, connecting with its vault key
           with ephemeral_agent(v.decrypt_key(b.key_id), ttl=120) as sock:
               t = Transport(host=host, user=b.user, port=b.port, agent_sock=sock, known_hosts=str(known_hosts_path()),
                             isolated=True, strict=True)
               ...
   # an admin account: password login (askpass answers ssh once), then sudo with the same password on stdin
   validate(host, admin_user, b.port)
   ```
   Even when `deploy.enroll()` (`deploy.py:294`) calls `sudo_run(..., lambda _u: ..., password, admin_user)` with an explicit `admin_user` and `password` (which uses password SSH login at lines 146–153 and ignores `_u`!), line 126 **unconditionally executes `b = v.resolve(host, 'scan')`**. If a host does not have a `'scan'` key bound in the vault (e.g. enrolling a deploy target host before scanning it, or removing deploy access after unbinding its scan key), `sudo_run()` immediately raises `NoBinding`.
2. **`deploy.enroll()` Ignores the Vault Binding's SSH Port When Binding `DEPLOY_KEY` (`deploy.py:299-308`)**:
   ```python
   port = conn.scalar('SELECT ssh_port FROM hosts WHERE hostname = :h', {'h': name}) or 22
   mine = [b for b in v.bindings() if b['key'] == DEPLOY_KEY and b['pattern'] == addr]
   ...
   if not mine:
       v.bind(DEPLOY_KEY, addr, DEPLOY_USER, port, actions='deploy', priority=50)
   ```
   If the host has a `'scan'` binding on a non-default SSH port (e.g. `2222`) so `sudo_run()` succeeded on `b.port` (`2222`), but the host has not completed a scan yet (so it has no row in `hosts`), `SELECT ssh_port FROM hosts WHERE hostname = :h` returns `None`. `deploy.enroll()` then binds `storageforge-deploy` to port **`22`**, causing the subsequent `probe` on line 310 to fail immediately.
3. **Password Left on Subshell `stdin` When `sudo` Is `NOPASSWD` or `root` (`access.py:130, 137, 152`)**:
   - `sudo = 'sudo -S -p "" sh -c ' + shlex.quote(script)` runs with `input=password + '\n'` on `stdin`. If the user is `root` or has `NOPASSWD: ALL` in sudoers, `sudo -S` does not read `stdin`, leaving the cleartext password unread on the pipe where any child command reading `stdin` inside `script` can consume it.

## Impact
`POST /api/deploy/access` fails with `NoBinding` on any host without a `'scan'` binding, fails on non-22 SSH ports if the host is unscanned, and leaves the admin password in `stdin` buffer when `sudo` does not prompt.

## Remediation
1. In `access.sudo_run()`, wrap `v.resolve(host, 'scan')` in `try ... except NoBinding` when `admin_user` is provided, falling back to `hosts.ssh_port` or `port=22` and `scan_user = admin_user`.
2. In `deploy.enroll()`, fall back to the `'scan'` binding's port (`r.get('port')`) when `hosts.ssh_port` is null.
3. Prefix the remote script in `sudo_run()` with `exec </dev/null\n` so child commands never inherit the `sudo -S` password pipe.

## Done when
- [ ] `deploy.enroll` and `access.sudo_run` succeed with `admin_user` + `password` even without a prior `'scan'` binding and preserve non-22 SSH ports.
