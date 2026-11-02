# Feature audit, 2026-11-01

Written while building the [feature guide](features/README.md). It compared the code with these docs and ran the product against the [KVM lab](kvm-lab.md), at the code of commit `b7364bd`.

## How it was checked

- **Routes:** each route in `server.py` and `routes_*.py` was looked up in the [API reference](api-reference.md).
- **CLI:** each `add_parser` name in `cli.py` was looked up in the [CLI reference](cli-reference.md). All were present.
- **Web UI:** all 14 panels, three views and eight planner views were opened in headless Chromium, with no page errors or failed requests from the product itself.
- **On real hosts:** the lab's demo ran scans on seven VMs, deploy access on five, an NFS and an SMB share, an rsnapshot job, a btrfs send and an alert delivered to ntfy. It passed.

The [catalogue](features/README.md#catalogue) marks which features were used, only shown, or left to the test tiers. No test tier was run for this audit. Remote nodes, sites and reset, cutover, restore and PostgreSQL weren't exercised.

## Fixed in the docs

| Where | It said | The code does |
| :--- | :--- | :--- |
| `security.md` | There are no roles, and every account can do everything | Four built-in roles, custom roles and a permission on most routes |
| `operations.md` | There is no way to remove a host | **Retire…**, `hosts remove` and `DELETE /api/hosts/<name>` |
| `plans-and-scripts.md` | Storage tasks have no CLI | `tasks list`, `check`, `script` and `import` |
| `scanning-and-search.md` | Task checks don't warn about running containers | They do (`tasks.py`) |
| `kvm-lab.md`, lab README | Full test runs tiers 0-5 | `cmd_test_all` runs 0 to 7 |
| `api-reference.md` | 20 routes and pages missing | Added: invites, roles, enroll, file map, ignore list, activity log, Git survey, snapshot jobs, deploy check, planner offsite, search hosts |
| `web-ui.md` | No file map, no Git Inspector, Audit is only the log | All described now |

## Still open in the product

These need a decision or a code change, so nothing was changed.

| # | Finding | Detail |
| :--- | :--- | :--- |
| 1 | **Activity log has no screen** | `/api/log`, its export and `storageforge-index log` work, but no page calls them. A UI for it, or a note that it is API and CLI only, would close this. |
| 2 | **Schedule panel offers something it refuses** | Its intro lists "Host scans", and `TASK_TYPES` still holds `scan`, but the form has no such option and `scheduler.py` rejects it. The text should go. |
| 3 | **Audit entries go unkeyed if the server starts before `vault init`** | The server loads the audit key at startup, so entries have no HMAC until it restarts, though deploys unlock the vault and work normally. Only **Verify chain** shows it. Seen on this audit's own rig, whose first `vault init` failed and was rerun after the server started. Docker and the documented order aren't affected. A warning at that moment, or loading the key later, would close it. |
| 4 | **"Has not been scrubbed in 35 days" on a new pool** | A pool made the same day raises this with "no scrub on record". The lab's demo therefore leaves four open alerts, while the lab README says one. The wording overstates what is known: the pool isn't 35 days old. |
| 5 | **Reports can't get back from the lab to the libvirt host** | Only matters for a server run off `sf-ctl`, as here. VMs couldn't reach `10.77.0.1`, so jobs couldn't report until reverse SSH tunnels were added. The job itself ran. |
| 6 | **The tab named Audit holds accounts, roles and backups** | Those are hard to find under that name. A rename or separate tab would help. |

## Not covered by any automatic check

The lab tests use the API, not the pages ([what the lab can't test](kvm-lab.md#what-the-lab-cant-test)). So this audit's look through the web UI was a single manual pass, and the screens have no regression tests.
