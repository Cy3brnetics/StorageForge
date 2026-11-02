---
id: SF-41
status: done
severity: medium
effort: S
area: Remote nodes
verified: proven
tags: [finding, audit-2026-11-01]
found: 2026-11-01
---
# SF-41 Remote nodes overview rewrites authorized_keys on GET and blocks on offline nodes

**Medium** · effort S · Remote nodes · Proven · part of [[Audit 2026-11-01]]

## What exists
`GET /api/remote/nodes` delegates to `remotes.overview(conn)`. In `remotes.overview()`, every call invokes `sync(conn)`, which writes `/run/sf-tunnel-keys/authorized_keys.new` and replaces `authorized_keys` atomically on the filesystem on every GET request. Additionally, for every active node, `overview()` sequentially invokes `online(addr)`, which attempts a TCP socket connect with a 2.0-second timeout per node.

## Evidence
- `storageforge_index/server.py:2708-2713`:
  ```python
  @app.get('/api/remote/nodes')
  @require_permission('hosts.view')
  def api_remote_nodes_list():
      with get_db() as conn:
          return jsonify({'nodes': remotes.overview(conn)})
  ```
- `storageforge_index/remotes.py:192-207`:
  ```python
  def overview(conn: Any) -> list[dict[str, Any]]:
      sync(conn)
      out = []
      for r in list_nodes(conn):
          ...
          if r.get('revoked_at'):
              st = 'revoked'
          elif online(addr):
              st = 'connected'
          elif r.get('adopted_at'):
              st = 'ready'
          else:
              st = 'pending'
  ```
- `storageforge_index/remotes.py:228-235`:
  `online(addr)` creates a `socket.socket()`, sets `sock.settimeout(2.0)`, and calls `sock.connect((addr, 22))`.
- Proof: Tracing the execution path confirms that an unprivileged read-only dashboard request (`GET /api/remote/nodes` with `hosts.view`) performs disk file replacement. When 4 remote nodes are offline or unresponsive, the request blocks the HTTP worker thread for 8.0 seconds.

## Why it matters
1. HTTP GET requests must be read-only and idempotent. Mutating `/run/sf-tunnel-keys/authorized_keys` on GET causes unnecessary disk write thrashing, file lock contention, and failure if the filesystem is mounted read-only.
2. Waitress runs with 8 worker threads by default (`server.py:3501`). Sequential 2-second timeouts per offline node mean that a small number of concurrent users opening the Remote Nodes UI will block all 8 worker threads, causing a denial of service across the entire web application.

## Suggested approach
Remove `sync(conn)` from `overview()`. Keys should only be written during node mutation operations (`add_node` and `revoke`). Perform liveness checks either through a non-blocking background thread or with an immediate non-blocking socket check with a very low aggregate timeout (or check established SSH socket state directly from the tunnel listener).

## Done when
- [ ] `GET /api/remote/nodes` does not call `sync(conn)` or write to `authorized_keys`.
- [ ] Offline remote nodes do not sequentially block HTTP worker threads.
- [ ] A unit test verifies that `overview()` does not invoke `sync()`.

## Outcome
**Severity after checking: Low (was Medium).** Partly confirmed. Fixed 2026-11-01 in `b222e78`. **Gemini's fix was rejected:** `sync` stays in `overview()`, because it is what repairs the keys after a restore or a lost volume (`test_the_database_decides_what_the_tunnel_reads`), and nothing else does. It now writes only on a change, under a temp name unique to the thread, so two page loads can't collide. **The 8-second claim is wrong for offline nodes:** the tunnel shares this network, so no forward means an instant refusal (`test_a_node_nobody_is_behind_answers_at_once`). Only a hung forward uses the timeout, and probes now run together, at most about 4 seconds for 16 nodes per batch.
