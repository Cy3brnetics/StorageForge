---
id: PF-30
status: done
severity: low
effort: S
area: Remote nodes
verified: read
tags: [finding, audit-2026-11-01]
found: 2026-11-01
---
# PF-30 Remote node IP address calculation wraps and allows broadcast addresses

**Low** · effort S · Remote nodes · Read · part of [[Audit 2026-11-01]]

## What exists
In `remotes.py:address(node_id)`, the loopback IP address assigned to each reverse SSH tunnel is computed from `node_id` using bit shifts:
`f'{NET}{(node_id >> 8) & 255}.{node_id & 255}'` where `NET = '127.42.'`.

## Evidence
- `storageforge_index/remotes.py:34-37`:
  ```python
  NET = '127.42.'

  def address(node_id: int) -> str:
      return f'{NET}{(node_id >> 8) & 255}.{node_id & 255}'
  ```
- If `node_id == 0`, the address is `127.42.0.0` (network address).
- If `node_id == 255`, the address is `127.42.0.255` (broadcast address).
- If `node_id == 256`, the address is `127.42.1.0`.
- If `node_id >= 65536`, `(node_id >> 8) & 255` wraps around modulo 256, generating IP collisions with previously assigned node IDs (for example, `node_id = 65537` yields `127.42.0.1`, colliding with `node_id = 1`).

## Why it matters
Using `.0` and `.255` addresses on loopback interfaces can cause socket bind or connect failures depending on host kernel routing and sysctl flags. Unchecked wrap-around above 65535 causes silent IP collisions, routing SSH tunnel traffic to the wrong remote host.

## Suggested approach
Validate `1 <= node_id <= 65000` (or raise `ValueError` on exhaustion), and avoid assigning `.0` and `.255` host octets when mapping integer IDs to the `127.42.0.0/16` block.

## Done when
- [ ] `remotes.address(node_id)` rejects invalid node IDs or out-of-range IDs.
- [ ] Generated IP addresses avoid `.0` and `.255` suffixes.
- [ ] Unit tests verify address assignment boundaries.

## Outcome
**Severity after checking: Low.** Mostly wrong. The code uses `127.77.`, not `127.42.`, and port 10022, not 22. All of 127/8 is local on Linux: `127.77.0.255` and `127.77.1.0` were bound and connected to here, so `.0` and `.255` are ordinary addresses and are still used. ID 0 never occurs. Only the wrap above 65535 is real, and `add()` now refuses it. Fixed 2026-11-01 in `b222e78`. Test: `test_addresses_run_out_rather_than_wrap`.
