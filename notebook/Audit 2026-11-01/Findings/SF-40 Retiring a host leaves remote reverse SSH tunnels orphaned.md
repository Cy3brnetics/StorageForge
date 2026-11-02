---
id: SF-40
status: done
severity: medium
effort: S
area: Remote nodes
verified: proven
tags: [finding, audit-2026-11-01]
found: 2026-11-01
---
# SF-40 Retiring a host leaves remote reverse SSH tunnels orphaned

**Medium** · effort S · Remote nodes · Proven · part of [[Audit 2026-11-01]]

## What exists
When an operator retires a host via `retire.retire(host_id)` (or `DELETE /api/hosts/<name>`), the retire logic removes host blueprints, pool bindings, alerts, and the host record itself. However, it does not check or revoke any `remote_nodes` associated with that host.

## Evidence
- `storageforge_index/retire.py:53-85`:
  `retire(host_id, ...)` executes:
  ```python
  DELETE FROM blueprint_hosts WHERE host_id = ?
  DELETE FROM pool_hosts WHERE host_id = ?
  DELETE FROM alerts WHERE host_id = ?
  DELETE FROM hosts WHERE id = ?
  ```
  It never queries or modifies `remote_nodes`.
- `storageforge_index/remotes.py:175-186`:
  `revoke(conn, node_id)` marks `revoked_at` and calls `sync(conn)`.
- When an adopted remote node's host is retired, `remote_nodes.revoked_at` remains `NULL`. Because `remotes.sync(conn)` is never called on host retirement, the remote node's public key remains in `/run/sf-tunnel-keys/authorized_keys`.
- In `remotes.overview(conn)`, the node remains listed with state `'ready'` or `'connected'`, but `host: None`. The reverse SSH tunnel from the remote machine continues to dial in, bind its loopback port on 127.42.x.y:22, and remain connected indefinitely.

## Why it matters
Retiring a host is intended to completely sever StorageForge's management of a decommissioned or untrusted machine. Leaving the reverse SSH tunnel active and authorized allows a retired or decommissioned node to maintain persistent network connectivity into the StorageForge host's tunnel loopback network, consuming tunnel ports and posing an unauthorized persistent access risk.

## Suggested approach
In `retire.retire()`, query `remote_nodes` for any record where `host_id == host['id']` (or `hostname == host['name']`). For each matching remote node, invoke `remotes.revoke(conn, node_id)`. Then call `remotes.sync(conn)` to prune the public key from `authorized_keys`.

## Done when
- [ ] Retiring a host with an adopted remote node marks the remote node as revoked.
- [ ] Retiring a remote host removes its key from `/run/sf-tunnel-keys/authorized_keys`.
- [ ] A unit test verifies that `retire(host_id)` revokes the associated remote node.

## Outcome
**Severity after checking: Medium.** Confirmed. Fixed 2026-11-01 in `b222e78`. `retire()` revokes the node and calls `remotes.sync(drop_sessions=True)` after the commit. Gemini's evidence names the wrong signature and tables, and its "persistent access" impact is overstated: a tunnel key can only listen on its own address, and the host's bindings were already deleted. The real effect is a retired machine that stays connected and holds its address. Test: `test_retiring_its_host_cuts_the_tunnel`.
