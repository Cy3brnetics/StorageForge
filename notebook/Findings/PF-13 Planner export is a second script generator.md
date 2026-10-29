---
id: PF-13
status: done
fixed: 2026-10-29
severity: high
effort: M
area: "[[Plans and the planner]]"
tags: [finding, design, safety]
found: 2026-10-29
---
# PF-13 Planner export is a second script generator

## What exists
Two ways to turn intent into commands on a host:

| | Changes (`changes.py`) | Planner Export (`planner.js:503-595`) |
| :-- | :-- | :-- |
| Runs | server side | in the browser |
| Pre-checks against the index | yes, per task (`/api/changes/check`) | none |
| Report-first | yes: default run only reports | `DRY_RUN=1` default |
| Destructive steps | need `--destructive` too | `wipefs --all` and `parted mklabel` run with just `DRY_RUN=0` |
| Ansible | yes | yes, separately written |
| Deployable, logged, audited | yes | no: copy or download only |
| Escaping of scanned names | checked (`blueprint.check_text`) | SF-17, still open |

## Why it matters
The planner's script is the only path in the app that can wipe a disk without the safeguards the rest of the app insists on, and its logic has to be kept equal to `changes.py` by hand. Every fix to one (quoting, mdadm flags, fstab handling) has to be made twice.

## Suggested approach
1. Add "Create change plan from this design" to the planner's Export view: diff the design against the latest scan and emit Changes tasks (`partition`, `mkfs`, `btrfs-*`, `mount`, `fstab`, `link`...). The task types already exist (`/api/changes/types`).
2. Keep the fstab, systemd units, JSON and YAML exports (they are descriptions, not actions).
3. Replace the Bash and Ansible tabs with a link to the generated plan, or keep them for one release as "legacy preview" with a banner.
4. That closes SF-17 for the script half by construction.

## Done when
- [x] The planner has no code that emits `wipefs`, `mkfs`, `zpool create` or `mdadm --create`
- [x] A design change can be deployed through Changes and appears in the audit log

## What was done (2026-10-29)
- `storageforge_index/fromdesign.py`: compares a design with `blueprint.from_index()` and returns change-plan tasks plus `manual` (no task type for it) and `left` (on the host, not in the design). Only additions and edits; nothing that erases data the scan saw is ever staged. Drive tasks keep an empty `confirm`, so `changes.normalize` refuses them until the device is typed in the Changes tab.
- `POST /api/planner/changes` (409 when the host hasn't been scanned).
- Planner Export: new **Change plan** tab with **Stage in Changes**; Bash and Ansible tabs, `genBash`, `genAnsible`, `mkfsCmd` and `sh()` removed.
- Changes tab flags unconfirmed drive tasks.
- Tests: `ChangePlanTests.test_design_*` and the API case in `test_api`. Checked by hand in the browser: stage, refused check, confirm, passing check.

## Follow-up
The planner can no longer emit pool creation at all. See [[PF-17 Changes has no pool tasks]].
