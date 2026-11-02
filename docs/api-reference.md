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
| GET | `/api/planner/design?host=&source=saved\|scan` | | the saved design, or one built from the latest scan plus saved intent |
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
| GET | `/api/deploy` | | access per host, jobs, deployed, alerts, drift, settings, recent runs |
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
| GET | `/api/scheduler/schedules/<id>/script` | | download compiled shell script for the task |
| GET | `/api/scheduler/schedules/<id>/install-script` | | download full installer script (config, script, cron entry) |
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

## Backups

| Method | Path | Body | |
| :--- | :--- | :--- | :--- |
| GET | `/api/backups` | | backups on disk, schedule and retention |
| POST | `/api/backups` | `{"kind": "essentials"\|"full"}` | make one now; 6 per hour |
