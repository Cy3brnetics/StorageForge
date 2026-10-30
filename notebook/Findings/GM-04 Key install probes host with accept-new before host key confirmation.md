---
id: GM-04
status: open
severity: high
effort: S
area: "[[API, Auth and Security]]"
tags: [finding, security, ssh, hostkeys, gemini-audit]
found: 2026-10-29
---
# GM-04 Key install probes host with accept-new before host key confirmation

## Location
- `storageforge_index/server.py:685-690` (`api_key_install()`)
- `storageforge_index/keyinstall.py:45-61` (`key_login_works()`)
- `storageforge_index/remote.py:113, 124` (`Transport`)
- `storageforge_index/hostkeys.py:68-102` (`require_confirmed()`, `confirm()`)
- `storageforge_index/db.py:204-212` (`rekey_host()`)
- `storageforge_index/static/app.js:808-825` (`withHostKeyConfirm()`)

## Mechanics & Root Cause
In `POST /api/keys/install` (`server.py:685-690`), the server checks whether key login already works **before** checking whether the host's SSH key has been confirmed by the operator:
```python
# server.py:685-690
if keyinstall.key_login_works(db, conn(), name, host, user, port):
    res = {'host': host, 'user': user, 'port': port, 'already_installed': True}
else:
    hostkeys.require_confirmed(conn(), host, port)
    res = keyinstall.install_public_key(pub, host, user, port, password)
    res['already_installed'] = False
```
Inside `keyinstall.key_login_works()` (`keyinstall.py:45-61`), `Transport` is constructed with the default `strict=False`:
```python
with ephemeral_agent(buf, ttl=30) as sock:
    t = Transport(host=host, user=user, port=port, agent_sock=sock, known_hosts=str(known_hosts_path()),
                  isolated=True)
    try:
        p = subprocess.run(t.argv('echo storageforge-ok'), stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=15, env=child_env())
```
Because `strict=False` (`remote.py:113, 124`), `t.argv(...)` passes `-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=<known_hosts>` to `ssh`.

This creates a multi-step security and logic failure:
1. **Premature `known_hosts` Pollution**: During the SSH handshake in `key_login_works()` (which happens *before* user authentication), `ssh` with `accept-new` **automatically writes the unconfirmed remote server's host key into StorageForge's shared `known_hosts` file**.
2. **Corrupted Confirmation Prompt & Scanner Trust**: Even when pubkey auth fails (`key_login_works` returns `False`), `known_hosts` now contains the unconfirmed key. When `hostkeys.require_confirmed(conn(), host, port)` runs on line 688, `pinned = known_host_keys(host, port, str(known_hosts_path()))` is now non-empty (`hostkeys.py:75`), so it takes the `if pinned:` branch (`line 79`):
   ```python
   if pinned:   # pinned by a scan (trust on first use): show that key, it is the one the password would go to
       raise HostKeyNeeded(host, port, [{'type': '', 'fingerprint': fp} for fp in pinned], True)
   ```
   This loses the key algorithm `type` (`''`) and falsely reports `pinned=True` (telling the operator the key was already pinned by an earlier scan). Meanwhile, background scans will now trust that polluted `known_hosts` entry!
3. **Complete Bypass of `require_confirmed`**: If an attacker-controlled or MITM SSH server accepts public-key authentication during `key_login_works()`, `key_login_works()` returns `True`, **completely skipping `hostkeys.require_confirmed()`** and binding the vault key to the unconfirmed host (`server.py:691-695`).
4. **Related Host Key Flaws**:
   - `hostkeys.require_confirmed()` (`hostkeys.py:76`) checks `if pinned and set(pinned) & _confirmed(conn, host, port): return`. If `known_hosts` holds multiple keys for a host (e.g. a confirmed RSA key and an unconfirmed Ed25519 key), `set(pinned) & _confirmed` is truthy even though OpenSSH will negotiate the unconfirmed Ed25519 key.
   - `app.js:823` hardcodes `fingerprint: hk.keys[0].fingerprint`, only ever confirming the first key in the list.
   - `db.rekey_host()` (`db.py:204-212`) clears `hosts.host_keys` and `ssh_host`, but never deletes old rows from `host_key_confirmations`.

## Impact
An unconfirmed or MITM SSH host key is automatically written into `known_hosts` before the user is ever prompted to confirm it (`SF-24` regression), and can bypass confirmation entirely if public-key auth is accepted.

## Remediation
1. In `server.py:685`, call `hostkeys.require_confirmed(conn(), host, port)` **before** `keyinstall.key_login_works()`.
2. In `keyinstall.key_login_works()`, pass `strict=True` (`StrictHostKeyChecking=yes`) so a login probe can never mutate `known_hosts`.
3. In `db.rekey_host()`, delete matching rows from `host_key_confirmations`.

## Done when
- [ ] `require_confirmed` runs before `key_login_works` in `api_key_install`.
- [ ] `key_login_works` uses `strict=True` (`StrictHostKeyChecking=yes`).
- [ ] `rekey_host` purges `host_key_confirmations` for the host.
