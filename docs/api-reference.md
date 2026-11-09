# API reference

The web UI is built on this API; anything it does can be scripted.

## Conventions

- **Session.** Every `/api/*` route except `/api/login`, `/api/jobs/report` and `/api/jobs/state` needs a signed-in session cookie. Sign in with `POST /api/login`.
- **Bodies** are JSON objects sent with `Content-Type: application/json`; anything else is refused with 400. Bodies are capped at 4 KiB, except a design (2 MiB).
- **Re-authentication.** Routes marked 🔑 need the account password typed within the last 5 minutes. Without it they answer `403 {"error", "reauth": true}`; call `POST /api/reauth` and retry.
- **Errors** are `{"error": "…"}` with a status:

  | Status | Meaning |
  | :--- | :--- |
  | 400 | invalid input (the message says which field) |
  | 401 | not signed in, or the session ended |
  | 403 | password confirmation needed (`reauth: true`), or a token for another job |
  | 404 | no such plan, task, job or host |
  | 409 | a precondition: hosts without deploy access, a plan with deployed jobs, an installed task, or a host key to confirm (`hostkey: {…}`) |
  | 429 | rate limited (`Retry-After` is set) |
  | 502 | the host could not be reached or refused (key install, access, deploy access) |

```bash
curl -c jar -H 'Content-Type: application/json' -d '{"username":"admin","password":"…"}' https://sf.lan:8443/api/login
curl -b jar 'https://sf.lan:8443/api/search?q=*.cr2&limit=20'
```

## Pages

| Method | Path | |
| :--- | :--- | :--- |
| GET | `/login` | sign-in page; the only page served without a session |
| GET | `/` | main page; without a session, a redirect to `/login?next=/` |
| GET | `/planner` | planner; likewise |
| GET | `/search` | the plain search page; without a session, a redirect to sign in |
| GET | `/enroll#<token>` | the page an invite or reset link opens; no session needed |
| POST | `/api/me/password` | `{"password", "new_password"}`: change your own password; your sessions end |
| GET, POST | `/api/users` | accounts (admin, password confirmed); POST `{"username", "password", "role"}` |
| PUT, DELETE | `/api/users/<name>` | `{"role", "disabled"}`; the last enabled admin can't be removed, disabled or demoted |
| GET, POST | `/api/invites` | single-use sign-up links (`users.manage`); POST `{"role", "hours"?, "note"?}` returns the token once |
| DELETE | `/api/invites/<id>` | revoke an open link |
| GET, POST | `/api/roles` | built-in and custom roles and the permission catalogue; POST `{"name", "description", "permissions"}` adds a custom role |
| PUT, DELETE | `/api/roles/<name>` | change or remove a custom role; built-in roles stay as they are |
| POST | `/api/enroll/check` | `{"token"}`: what the link gives; no session needed |
| POST | `/api/enroll` | `{"token", "username", "password"}`: use the link to make the account or set its new password; no session needed |
| GET | `/healthz` | `{"status"}`; also version, database, vault, worker and user count from inside the container or when signed in |

## Session

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| POST | `/api/login` | `{"username", "password"}` | start a session; rate limited (see [Security](security.md#sign-in-limits)) |
| POST | `/api/logout` | | end it, server-side too |
| POST | `/api/reauth` | `{"password"}` | confirm the password for 5 minutes; returns `until` |
| GET | `/api/me` | | user, session length, when it ends |
| PUT 🔑 | `/api/me` | `{"session_minutes"}` | 30–480 |

## Index, graph and search

| Method | Path | |
| :--- | :--- | :--- |
| GET | `/api/hosts` | indexed hosts and hosts in the graph |
| GET | `/api/graph[?host=]` | nodes and edges |
| GET | `/api/canvas[?host=]` | Obsidian `.canvas` download |
| GET | `/api/search?q=&host=&size_gt=&type=f\|d\|l&under=&limit=` | needs `q`, `size_gt` or `under`; `limit` ≤ 500 |
| GET | `/api/browse?host=&path=` | subfolders with indexed sizes (move pickers) |
| GET | `/api/fs/browse?host=&path=` | folders and files with mounts, shares and planned mounts |
| GET | `/api/folders/duplicates?host=&min_files=&min_size=` | duplicate folders |
| GET | `/api/folders/cold?host=&years=&min_size=` | folders whose newest file is older than the cutoff |
| GET | `/api/git?host=` | repositories, copies and archive state |
| POST | `/api/git/status` | `{"host", "path"}`: live status of a repository a scan found |
| POST | `/api/git/history` | `{"host", "path", "max"?}`: commits and tags, at most 200 |
| POST | `/api/git/commit` | `{"host", "path", "sha"}`: one commit's details |
| POST | `/api/git/sync` | `{"host", "path", "action"}`: fetch, pull, push or sync as a signed run, as the repository's owner (password confirmed, needs deploy access) |
| GET, PUT | `/api/git/ignore` | path fragments hidden from the Git tab: PUT `{"host", "paths"}`, no host means every host, `!x` shows `x` |
| GET | `/api/docker?host=` | containers, stacks, volumes |
| GET | `/api/docker/usage?host=&path=` | containers using a folder (or all usage for a host) |
| GET | `/api/jobs` | the last 50 scan jobs |
| GET | `/api/scans/signing` | signed scan payloads: whether they are required, each host's last scan (signed, partly signed or unsigned, by which keys, and why not), and the pinned scan signing keys |
| PUT | `/api/scans/signing` | `{"require": true}` refuses payloads a host did not sign; `keys.manage`, audited |
| DELETE | `/api/scans/signing/<address>` | forget the scan signing key pinned for an address, after a rebuild; `keys.manage`, audited |
| DELETE | `/api/hosts/<name>[?keep_design=1]` | retire a host (password confirmed); 409 while anything is deployed there |
| DELETE | `/api/keys/<name>`, `/api/bindings/<id>` | remove a key with no bindings, or a binding (password confirmed) |
| PUT | `/api/backups/target` | `{"host", "path"}`: copy each backup to that host; empty stops copying |
| GET | `/api/capacity?host=` | each mount's usage over 30 days and when it fills up at that rate |
| GET | `/api/file-changes?host=&scan=&limit=` | what a scan found changed, grouped by folder |
| GET | `/api/dupes?host=&min_size=&limit=` | identical files from checksum scans |
| GET, PUT | `/api/hosts/<name>/schedule` | the host's own scan interval and quiet hours: `{"interval": "1d", "quiet_hours": "22-6"}`; empty uses the global interval, no quiet hours |
| POST | `/api/scan` | `{"host"}`: queue a vault-backed scan (202, `{"job_id"}`); duplicates collapse |
| POST | `/api/scan/all` | `{}`: queue a scan of every host bound by name for scanning (202, `{"jobs": {host: job_id}}`); duplicates collapse |

### Also in the index

| Method | Path | |
| :--- | :--- | :--- |
| GET | `/api/search/hosts` | host names, for filtering a search |
| GET | `/api/filemap?host=&min_size=&folders=&system=` | the Graph view's file map: folders holding copies and the lines between them |
| GET, PUT | `/api/files/ignore` | paths and fragments left out of the file map and of broken-link flags |
| POST | `/api/git/survey` | `{"host"}`: ask a host for its repositories over SSH |
| GET | `/api/log?host=&sources=&outcomes=&q=&since=&until=&limit=&offset=` | what has been done: audit log, deploys, scans and task runs in one list |
| GET | `/api/log/output?id=` | the full output of one deploy run or fetched log |
| GET | `/api/log/export?format=csv\|json\|text&output=1` | the same list as a file |
| GET | `/api/hostlogs?host=&unit=&level=&q=&since=&until=&limit=&offset=` | hosts' journal lines as scans collected them, newest first; `level=warning` means warning or worse; takes `hostlogs.view` |
| GET | `/api/hostlogs/status?host=` | how the last pickup from each host went, and what to do if it couldn't read the journal |
| GET | `/api/hostlogs/counts?host=&since=&until=` | stored lines by level and by UTC hour (ISO strings) for the Logs view; `since` after `until` is refused; at most 792 hours, newest kept (`truncated` says so); takes `hostlogs.view` |
| GET | `/api/hostlogs/units?host=` | the unit names stored with a line count each, most lines first, at most 200; takes `hostlogs.view` |
| GET | `/api/hostlogs/export?format=csv\|json\|text` | the same lines as a file, up to 20,000; audited |

## Keys, access and audit

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| GET | `/api/keys` | | keys (public halves) and bindings |
| POST | `/api/keys` | `{"name", "type": "ed25519"\|"rsa"}` | generate a key in the vault |
| POST 🔑 | `/api/keys/install` | `{"key", "host", "port", "user", "password", "bind", "checksum"}` | `ssh-copy-id`, verify key login, optionally bind; 10/min |
| POST | `/api/hostkey/confirm` | `{"host", "port", "fingerprint"}` | confirm a host key before a password goes there *(in progress)* |
| GET | `/api/access?host=` | | how scans read each host, and unreadable folders |
| GET | `/api/access/script?host=\|user=&remove=1` | | the read-only access setup or removal script |
| POST 🔑 | `/api/access/grant` | `{"host", "password", "admin_user"?, "remove"?}` | run that script once with sudo; 10/min |
| GET | `/api/audit[?limit=]` | | newest entries (≤ 1000) |
| GET | `/api/audit/verify` | | `{"valid", "entries_checked", "first_bad_id"}` |

## Designs and planner

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| GET | `/api/planner/hosts` | | scanned hosts and saved designs; whether the example shows |
| GET | `/api/planner/design?host=&source=saved\|scan` | | the saved design, or one built from the latest scan plus saved intent; `shares_deployed` says this design's shares are the ones last deployed |
| PUT | `/api/planner/design` | a `storageforge/v1` `StorageBlueprint` | save and rebuild the host's graph |
| POST | `/api/planner/changes` | a `storageforge/v1` `StorageBlueprint` (saved or not) | `{host, name, tasks, manual, left, destructive}`: the change-plan tasks that bring the scanned host to the design, what needs doing by hand, and what the design leaves alone. Stages nothing; 409 when the host has not been scanned |
| PUT | `/api/planner/example` | `{"show"}` | show or hide the example host for everyone |
| GET | `/api/planner/activity?host=` | | staged changes, moves, shares, jobs, drift and unreadable folders on a host |

### Also for designs

| Method | Path | |
| :--- | :--- | :--- |
| PUT | `/api/planner/offsite` | `{"host", "offsite"}`: mark whether a host counts as offsite |

## Plans

Each plan type has the same shape: list, create, one, check, script.

| Method | Path | |
| :--- | :--- | :--- |
| GET, POST | `/api/changes` | list; create from `{"name", "tasks": [{"type", "host", "params"}]}` |
| GET, PUT, DELETE | `/api/changes/<id>` | |
| GET | `/api/changes/types` | task types and their fields |
| POST | `/api/changes/check` | check a plan, saved or not |
| GET | `/api/changes/<id>/script`, `/api/changes/<id>/ansible` | downloads |
| GET, POST | `/api/moves` | list; create from `{"name", "steps": [{"method", "src": {"host", "path"}, "dst": {…}, "options"}]}` |
| GET, PUT, DELETE | `/api/moves/<id>` | DELETE answers 409 while jobs are deployed |
| POST | `/api/moves/check` | |
| GET | `/api/moves/<id>/script` | download |
| GET | `/api/shares/check?host=` | the host's designed shares, checked |
| GET | `/api/shares/script?host=` | download |
| POST | `/api/shares/validate` | `{"host", "export", "index"?}`: check one share before saving |
| POST | `/api/shares` | `{"host", "export", "index"?}`: add, or replace share `index` |
| DELETE | `/api/shares?host=&index=` | remove a designed share |
| GET, POST | `/api/tasks` | list (with block types, templates, schedules, where installed); create from `{"name", "host", "schedule", "blocks", "on_fail"}` |
| GET, PUT, DELETE | `/api/tasks/<id>` | DELETE answers 409 while installed |
| POST | `/api/tasks/check`, `/api/tasks/script` | for a task body, saved or not |

## Deployments

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| GET | `/api/deploy` | | access per host, jobs, deployed, alerts, drift, settings, recent runs, `share_hosts` (scanned hosts with designed shares) |
| POST | `/api/deploy/setup-script` | `{"remove"?}` | download; makes the deploy keys on first use |
| POST 🔑 | `/api/deploy/access` | `{"host", "password", "admin_user"?, "remove"?}` | set deploy access up (or remove it) with sudo once; 10/min |
| POST 🔑 | `/api/deploy/adopt` | `{"host"}` | after running the setup by hand: bind and test |
| POST 🔑 | `/api/deploy/start` | `{"kind": "jobs"\|"shares"\|"changes"\|"tasks"\|"schedules", "ref", "mode": "report"\|"apply", …}` | see [Deployments](deployments.md#running-a-deploy); returns `{"group", "hosts"}` |
| GET | `/api/deploy/groups/<id>` | | the runs of one deploy, with output (poll while running) |
| GET | `/api/deploy/runs[?host=&limit=]`, `/api/deploy/runs/<id>` | | history, or one run's output |
| GET | `/api/deploy/jobs/<id>` | | a deployed job and its runs |
| POST | `/api/deploy/jobs/<id>/<verb>` | | `dryrun`, `log`, `snapshots`; 🔑 for `run`, `verify`, `pause`, `resume`, `cutover` |
| POST | `/api/deploy/jobs/<id>/browse` | `{"snapshot", "path"}` | list a folder in an rsnapshot snapshot |
| POST 🔑 | `/api/deploy/jobs/<id>/restore` | `{"snapshot", "path"}` | copy it back as `<path>.restored-<time>` |
| GET, PUT | `/api/deploy/settings` | `{"report_url", "alerts": {…}}` | |
| POST | `/api/deploy/settings/test` | | send a test alert; 10/min |
| POST | `/api/jobs/report` | a run result; `Authorization: Bearer <job token>` | no session; 120/min |
| GET, POST | `/api/remote/nodes` | POST `{"name", "endpoint"}` | nodes that dial in; POST returns its install script once |
| POST | `/api/remote/nodes/<id>/adopt` | | scan a connected node and test a signed run; call again while it says `scanning` |
| DELETE | `/api/remote/nodes/<id>` | | revoke a node: cuts its tunnel |
| POST | `/api/jobs/state` | a state event; `Authorization: Bearer <job token>` | no session; 120/min |

### Also for deploys

| Method | Path | |
| :--- | :--- | :--- |
| POST | `/api/deploy/check` | 🔑 `{"host"}`: what the host can run, by a signed probe, or from its last scan if not set up |
| GET | `/api/deploy/snapjobs` | rsnapshot and snapper jobs found on hosts, imported or not |
| GET | `/api/deploy/snapjobs/advice` | which snapshot tool suits a folder's filesystem |
| POST | `/api/deploy/snapjobs/probe` | 🔑 `{"host"}`: look again as root (signed, read-only) |
| POST | `/api/deploy/snapjobs/import` | 🔑 `{"host", "tool", "config"}`: track a job found on a host |
| POST | `/api/deploy/snapjobs/snapper` | 🔑 create a snapper config on a btrfs subvolume |

## Security

See [Ransomware defense](ransomware-defense.md). Reads need `security.view`. 🔑 runs on a host or changes state, and asks for a fresh password. Where it says *mode*, `preview` returns the script, `report` dry-runs it (the default) and `apply` does it; the answer has `ok`, `status` and `output`, and is 409 with `error` if the run failed. Nothing is recorded unless the host confirmed it.

| Method | Path | Body or query | Needs |
| :--- | :--- | :--- | :--- |
| GET | `/api/security/posture` | `?host=` | what is known about each host, and every reason it is not fine |
| GET | `/api/security/events` | `?host=&all=1` | alarms; `all` includes routine events |
| POST 🔑 | `/api/security/events/<id>/ack` | | `security.emergency` |
| POST 🔑 | `/api/security/measure` | `{"host"}` | `security.manage` |
| POST | `/api/security/report` | `{"lines": [...]}`, `Authorization: Bearer <sentinel token>`, no session | a sentinel's token; it speaks only for its own host |
| GET | `/api/security/worm/holds` | `?host=` | holds, quorum, what is waiting, the clock |
| POST 🔑 | `/api/security/worm/hold` | `{"host", "snapshot", "retention_days"\|"legal_hold", "hold_tag"?, "create"?, "mode"}` | `security.emergency` |
| POST 🔑 | `/api/security/worm/release` | `{"hold_id", "release_legal"?}` | `security.emergency` |
| POST 🔑 | `/api/security/worm/quorum/approve` | `{"timelock_id"}` | `security.emergency`, a different established admin |
| POST 🔑 | `/api/security/worm/abort` | `{"timelock_id"}` | `security.emergency` |
| POST 🔑 | `/api/security/worm/break-glass` | `{"timelock_id", "break_glass_key"}` | `security.emergency` |
| POST 🔑 | `/api/security/worm/break-glass/key` | | `security.emergency`; the first key at once, a replacement after a timelock |
| POST 🔑 | `/api/security/worm/cool-off` | `{"hours": 12\|24\|48\|72}` | `security.emergency`; it cannot be shortened |
| POST 🔑 | `/api/security/worm/clock/clear` | `{"host"}` or `{"controller": true}` | `security.emergency` |
| GET | `/api/security/canaries` | `?host=` | decoys and, for a host, its sentinel |
| POST 🔑 | `/api/security/sentinel` | `{"host", "folders", "names"?, "armed"?, "actions"?, "minutes"?}` | `security.sentinel`; takes effect at the next deploy (`/api/deploy/start`, kind `security`, with `remove` or `rearm`) Deploying it (`/api/deploy/start`, mode `apply`) takes this and `deploy.apply` |
| POST 🔑 | `/api/security/canaries/test` | `{"host"}` | `security.manage`; returns `latency_ms` |
| GET | `/api/security/mac/status` | `?host=` | access control as measured |
| POST 🔑 | `/api/security/mac/remediate` | `{"host", "boolean", "value", "mode"}` or `{"host", "path", "type", "mode"}` | `security.manage` |
| GET | `/api/security/firewall/quarantine` | `?host=` | |
| POST 🔑 | `/api/security/firewall/quarantine` | `{"host", "ip_address", "minutes"?, "reason"?, "mode"}` | `security.manage` |
| DELETE 🔑 | `/api/security/firewall/quarantine/<ip>` | `?host=&mode=` | `security.manage` |
| POST 🔑 | `/api/security/firewall/vip` | `{"vips": [...]}` | `security.emergency` |
| POST 🔑 | `/api/security/firewall/airgap` | `{"host", "enabled"?, "mode"}` | `security.emergency` |
| GET | `/api/security/behavior` | `?host=` | change rate, ransom names, entropy |
| POST 🔑 | `/api/security/behavior/entropy` | `{"host"}` | `security.manage` |
| POST 🔑 | `/api/security/behavior/diff-scan` | `{"host"}` | `security.manage` |
| GET | `/api/security/integrity` | `?host=` | AIDE and Lynis as last read |
| POST 🔑 | `/api/security/integrity/run` | `{"host", "tool": "aide-init"\|"aide-check"\|"lynis", "mode"}` | `security.manage` |
| GET | `/api/security/compliance/standards` | | |
| GET | `/api/security/compliance/status/<host>` | `?profile=` | readings against a standard; `score` is null until measured |
| POST 🔑 | `/api/security/compliance/init` | `{"host", "profile", "mode"}` | `security.manage` |
| GET | `/api/security/incident/blast-radius` | `?host=&at=` | no file counts without a scan since the incident |
| POST 🔑 | `/api/security/incident/brake` | `{"host", "path"?, "client_ip"?, "pid"?, "minutes"?, "actions"?, "mode"}` | `security.emergency`; returns the outcome of each step |
| POST 🔑 | `/api/security/incident/clean-room` | `{"host", "snapshot", "mount"?, "remove"?, "mode"}` | `security.emergency` |


### Policy, detection and response

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| GET, POST 🔑 | `/api/security/waivers` | `{"host", "finding", "reason", "days"}` | `security.manage`; a host may be `*` |
| GET, POST 🔑 | `/api/security/profiles` | `{"name", "base", "overrides": {"target_lynis", "min_worm_days", "add", "drop"}}` | use as `custom:<name>` |
| POST | `/api/security/compliance/reconverge` | `{"host", "profile"}` | stages a plan: `plans.edit` |
| GET | `/api/security/compliance/script` | `?host=&profile=` | `sf-init-compliance.sh`: `plans.scripts` |
| POST | `/api/security/integrity/stage` | `{"host"}` | Lynis findings as a plan |
| GET, POST 🔑 | `/api/security/worm/policies` | `{"host", "pattern", "days", "legal", "auto"}` | saving and removing: `security.emergency` |
| POST 🔑 | `/api/security/worm/policies/apply` | `{"host", "mode"}` | `security.manage`; mode `apply` also takes `security.emergency` |
| POST 🔑 | `/api/security/worm/freeze` | `{"host", "target", "mode"}` | `security.emergency` |
| POST 🔑 | `/api/security/worm/preview` | `{"host", "snapshot", "live"}` | what a rollback would change. Only reads |
| POST | `/api/security/worm/preview/stage` | same | |
| POST | `/api/security/evidence` | `{"host"?, "from"?, "to"?}` | signed record: `audit.view` and `audit.verify`, 10 a minute |
| GET | `/api/security/mac/identity-anomalies` | `?host=` | sessions and flags |
| POST 🔑 | `/api/security/mac/identity/deploy` | `{"host", "enabled", "max_shares", "off_from", "off_to", "mode"}` | |
| GET | `/api/security/firewall/shares` | `?host=` | declared clients, what the firewall allows, who is connected |
| POST | `/api/security/firewall/shares/stage` | `{"host", "name", "service", "clients", "iface"}` | stages a fence |
| GET, POST 🔑 | `/api/security/firewall/tiers` | `{"tiers"}` | |
| POST 🔑 | `/api/security/behavior/falco` | `{"host", "rules", "enabled", "mode"}` | |
| POST 🔑 | `/api/security/behavior/yara` | `{"host", "dry", "rules"}` | |
| GET, POST 🔑 | `/api/security/behavior/yara/rules` | `{"name", "body", "enabled"}` | |
| POST 🔑 | `/api/security/behavior/thresholds`, `/filters` | | |
| GET, POST 🔑 | `/api/security/playbooks` | `{"name", "trigger", "conditions", "actions", "mode"}` | mode: `dry_run`, `confirm`, `live` |
| POST 🔑 | `/api/security/playbooks/runs/<id>` | `{"confirm"}` | |
| POST 🔑 | `/api/security/packages/check`, `/bundle` | `{"host"}` | |
| POST 🔑 | `/api/security/incident/clean-room/sweep` | `{"host", "mount"}` | |
| GET | `/api/security/dash/tile/<kind>`, `/api/security/timeline`, `/api/security/badges` | | |
| POST | `/api/security/webauthn/assert/begin`, `/finish` | | a touch, good for 5 minutes |
| POST 🔑 | `/api/security/webauthn/register/begin`, `/finish` | | enroll a key: an account that has one touches it first. Removing a key takes the same |

## Map

See [Infrastructure map](infrastructure-map.md). Reads need `map.view`; exposure, reach and firewall detail also need `security.view`.

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| GET | `/api/map` | `?layers=&host=&at=&redact=1` | nodes and edges; `at` goes back in time |
| GET | `/api/map/node/<id>`, `/api/map/edge` | `?src=&dst=&rel=` | evidence and history |
| GET | `/api/map/snapshots` | `?host=` | the timeline |
| GET | `/api/map/exposure` | `?scope=lan\|vpn\|any&host=` | |
| GET | `/api/map/reach` | `?from=&to=&port=&proto=` | |
| GET | `/api/map/coverage` | `?host=` | workloads no hold or decoy reaches |
| POST | `/api/map/whatif` | `{"tasks", "flows"}` | reads only |
| POST | `/api/map/stage` | `{"plan", "tasks"}` | `plans.edit` |
| POST 🔑 | `/api/map/placeholders/<id>/promote` | | `keys.manage` |
| GET | `/api/map/export` | `?format=&layers=&redact=1` | audited |
| GET, POST, DELETE | `/api/map/views`, `/api/map/annotations` | | `map.edit`. A view is seen by its owner, or by everyone with `"shared": true`, and changed only by its owner |
| GET, POST 🔑, DELETE 🔑 | `/api/map/manual` | `{"kind", "label", "url", "links"}` | `map.edit` |
| GET, POST, DELETE | `/api/map/designs` | `{"name", "doc"}` | `plans.edit` |
| GET | `/api/map/designs/<id>/compare`, `/export` | `?target=bash\|ansible\|terraform\|puppet` | |
| POST | `/api/map/designs/<id>/stage` | | what is missing, as a plan |
| GET | `/api/workloads`, `/api/network`, `/api/firewall`, `/api/exposure` | `?host=` | |
| GET | `/api/workloads/libvirt` | `?host=` | each libvirt host's networks and storage pools, from its last reading. A libvirt VM in `/api/workloads` carries its disks, snapshots and guest agent state |
| POST 🔑 | `/api/infra/measure` | `{"host"}` | `security.manage` |

## Scheduler

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| GET | `/api/scheduler/schedules[?host=&task_type=&paused=]` | | list configured schedules |
| POST | `/api/scheduler/schedules` | `{"name", "host", "cron_expr", "task_type", "task_ref", "config"?}` | create schedule; returns schedule and initial auth token |
| GET, PUT, DELETE | `/api/scheduler/schedules/<id>` | `PUT`: updated fields | inspect, edit, or remove schedule |
| POST | `/api/scheduler/schedules/<id>/pause` | `{"paused": true\|false}` | pause or resume schedule |
| POST | `/api/scheduler/schedules/<id>/token` | | rotate/generate new execution bearer token |
| POST | `/api/scheduler/schedules/<id>/run` | | run schedule immediately over SSH deploy access (password confirmed) |
| POST | `/api/scheduler/report` | run report, up to 512 KiB (`Authorization: Bearer <token>`) | a host reports a run; a repeated nonce is ignored |
| POST | `/api/scheduler/schedules/<id>/verify` | `{"run_id"?}` | re-verify schedule or specific run against the StorageForge index |
| GET | `/api/scheduler/schedules/<id>/script` | | download compiled shell script for the task (a command schedule also takes `plans.edit`) |
| GET | `/api/scheduler/schedules/<id>/install-script` | | download full installer script (config, script, cron entry; a command schedule also takes `plans.edit`) |
| GET | `/api/scheduler/schedules/<id>/cron` | | output `/etc/cron.d/` entry string |
| GET | `/api/scheduler/schedules/<id>/runs[?limit=]` | | execution history and server verification reports for schedule |
| GET | `/api/scheduler/runs[?host=&limit=]` | | global schedule runs history |
| POST | `/api/scheduler/report` | execution report; `Authorization: Bearer <token>` | client execution reporting; triggers server verification (120/min) |

## Host configurations

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| GET | `/api/hostconfigs?host=` | | the newest version of each host, or every version of one |
| GET | `/api/hostconfigs/<id>` | | one version, and what changed since the one before |
| GET | `/api/hostconfigs/script?host=&id=` | | the reinstall script |
| GET | `/api/hostconfigs/bundle?host=&id=` | | a `.tar.gz` of scripts, records and config files; every host without `host=` |
| POST | `/api/clone/preview` | `{source, target, files, map, mode, packages, accounts, shares, snapshots, services}` | the plans that would copy one host onto another, the data at risk, and what isn't copied. Saves nothing |
| POST | `/api/clone` | as above, and `accept: [risk ids]` | saves them. 409 with `open` until every critical and warning risk is in `accept`, and the audit log records the accepted ones |
| GET | `/api/vm/images` | | the cloud images a `vm-create` step can start from |
| POST | `/api/vm/copy/preview`, `/api/vm/copy` | `{source, name, target, as?, pool?, network?, live?, start?, keep_macs?}` | the plan that copies a VM as it is to another libvirt host ([VMs on libvirt](vms.md#copying-a-vm-to-another-libvirt-host)): its two steps and their check, or saved as a change plan (201, `id`) |
| GET | `/api/vm/specs` | | VM specs, built in and your own, and the fields a spec may set |
| PUT, DELETE | `/api/vm/specs/<name>` | `{field: value, "note"}` | save or remove one of your specs. The built-in ones can't be changed |
| GET | `/api/hostconfigs/packages?host=[&against=]` | | the packages a host was given on purpose, its Flatpak and Snap apps and package sources; with `against=`, what each host has that the other lacks |
| GET | `/api/hostconfigs/packages/script?host=` | | a script that installs them on the machine it runs on, with the same package manager; reports unless `--apply` |

## Console

See [Console](console.md). Each needs `console.open`, except where it says.

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| GET | `/api/console/hosts/<host>` | | its routes (LAN, Tailscale), its serial console, the virt-viewer command, whether sessions are recorded, your open sessions |
| POST 🔑 | `/api/console/sessions` | `{host, kind: ssh\|serial, route: auto\|lan\|tailscale, cols, rows}` | opens a session; 409 with why when it can't |
| GET | `/api/console/sessions/<id>/output` | `?after=N&wait=S` | output after N, base64; waits up to S seconds (at most 25) for some. `closed` once it ended |
| POST | `/api/console/sessions/<id>/input` | `{data}` | base64, at most 64 KiB at once |
| POST | `/api/console/sessions/<id>/resize` | `{cols, rows}` | |
| DELETE | `/api/console/sessions/<id>` | | closes it. Another account's session is 404, admins' included |
| GET, PUT 🔑 | `/api/console/settings` | `{record, keep_days}` | changing it needs `settings.manage` |
| GET | `/api/console/recordings`, `/api/console/recordings/<name>` | | `console.recordings`: the list, and one as an asciicast download |

## Backups

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| GET | `/api/backups` | | backups on disk, schedule and retention |
| POST | `/api/backups` | `{"kind": "essentials"\|"full"}` | make one now; 6 per hour |
