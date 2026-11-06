---
id: SF-61
status: open
severity: medium
effort: S
area: Network devices
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-61 A RouterOS change goes ahead when planting its rollback failed

**Medium** · S · Network devices · Proven against a stand-in session, not on a real router · part of [[Audit 2026-11-05]]

## What exists
Every change to a device first plants a way back on the device, and the docs and the route's own header promise that `/api/devices/changes/<id>/apply` changes a device "only with a rollback timer already planted on it". The OpenWrt, pfSense and Cisco planters check the device's answer (`'planted' not in got`, `cisco.ERROR.search`) and raise `DeviceError` so nothing is applied. The RouterOS planter does not look at any answer: it saves a backup, removes an old scheduler and adds the scheduler that loads the backup, and returns the three outputs, which `apply()` throws away.

## Evidence
`netdevice.py:384-388` (`RouterOsApply.plant`) returns `out` with no check; `netdevice.py:564` calls `applier.plant(run, rollback)` and ignores the result, then calls `applier.apply` on the next line. `RouterOsApply.apply` (`netdevice.py:390-397`) does match failure words in the output of each change line, so the author knew RouterOS reports a refused command as text; `DirectTransport.run` only raises for an ssh exit status of 255 (`remote.py:191`).

Ran `/tmp/sfaudit/a/probe_api.py` (`test_d_routeros_plant_unchecked`): a throwaway database, a RouterOS device, a reported change, and `netdevice.session` replaced by a stand-in whose `run` answers `failure: not enough disk space` to `/system/backup/save` and `/system/scheduler/add` and nothing to the rest. `apply(..., hold=True)` returned `{'ok': True, 'status': 'unconfirmed', 'message': 'Confirm it before the timer runs out, or the device goes back.'}` and the stand-in saw all four commands, including the change itself (`/ip firewall filter add ...`). With a real RouterOS the text a failed `backup/save` or `scheduler/add` gives, and its exit status, were not tried: the lab was not run in this audit.

## Why it matters
When the backup cannot be saved (disk full, a read-only account) or the scheduler cannot be added, the change is applied with no timer on the device, and the report to the person says there is one. If that change cuts StorageForge off, nothing brings the router back: the state becomes `lost`. This is the one protection the device-change feature promises. It needs the plant to fail while the change itself succeeds, which is unusual, so Medium and not High.

## Suggested approach
Have `RouterOsApply.plant` check each answer with the same failure words `apply` uses, and read the scheduler back (`/system/scheduler/print count-only where name=sf-<id>`) before it returns, raising `DeviceError` if it is not there. A test feeds a stand-in `run` the failure text and asserts that `apply` sends no change line.

## Done when
- [ ] A failed `backup/save` or `scheduler/add` stops `apply()` before the first change line, with status back at `reported` and an error saying the rollback could not be planted
- [ ] The scheduler is read back before the change goes on
- [ ] A test in `test_routers.py` holds both
- [ ] The commit is written here
