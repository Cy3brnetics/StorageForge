---
id: EQ-06
status: done
severity: low
effort: S
area: Remote nodes / Test coverage
verified: read
tags: [finding, audit-2026-11-01]
found: 2026-11-01
---
# EQ-06 Missing test for retiring remote node hosts

**Low** · effort S · Remote nodes / Test coverage · Read · part of [[Audit 2026-11-01]]

## What exists
`tests/test_remote_nodes.py` tests enrolling, listing, adopting, and explicitly revoking remote nodes. `tests/test_retire.py` tests retiring hosts with various blueprints and storage disks. However, there is no test verifying what happens when a host that was adopted from a remote node is retired via `retire.retire()` or `DELETE /api/hosts/<name>`.

## Evidence
- `storageforge-indexer/tests/test_remote_nodes.py`:
  Covers `add_node`, `sync`, `adopt`, `revoke`, and token generation. It does not invoke `retire.retire()`.
- `storageforge-indexer/tests/test_retire.py`:
  Seeds hosts directly in the database and calls `retire()`. It never sets up a `remote_nodes` record.
- Because no integration test links the remote node lifecycle with the host retirement lifecycle, the orphaned tunnel defect in [[SF-40 Retiring a host leaves remote reverse SSH tunnels orphaned|SF-40]] was not caught by the test suite.

## Why it matters
Host lifecycle and remote node lifecycle intersect directly at host adoption and retirement. Gaps in test coverage between interconnected subsystems allow lifecycle state divergence to go undetected.

## Suggested approach
Add an integration test in `tests/test_remote_nodes.py` or `tests/test_retire.py` that adopts a remote node into a host, calls `retire.retire()`, and asserts that the remote node is revoked and keys are synced.

## Done when
- [ ] A test exists verifying that retiring an adopted host revokes its remote node record and updates authorized keys.

## Outcome
**Severity after checking: Low.** Confirmed, though the retire tests are in `test_tasks.py` and `test_scheduler.py`, and `test_retire.py` does not exist. Fixed 2026-11-01 in `b222e78` with `test_retiring_its_host_cuts_the_tunnel` and `test_retiring_any_other_host_leaves_the_nodes_alone`.
