# Deployments: shares, rsync and rsnapshot jobs from the web UI

Design for 2026-10-27. Decisions from the questions:

| Question | Answer |
| :--- | :--- |
| Who runs deployments | The web UI, over SSH: read-only report first, apply after confirming. Scripts stay downloadable. |
| Root on the hosts | A `storageforge-deploy` user whose sudo runs one root-owned runner, which only runs scripts StorageForge signed. |
| Job reporting | Both: every run posts its result to StorageForge, and scans read the run log as a fallback. |
| What is tracked | Run history, stale-backup alerts, drift from the plan, snapshot browse and restore. |
| Alerts | Web UI, ntfy or Gotify, webhook. |
| NFS | Edit and remove deployed shares, rules per client, a UID/GID check across server and clients. |
| Job extras | Pre/post commands, btrfs snapshot first, exact schedules and run windows, weekly checksum verify. |
| Layout | Moves, Changes and shares stay where they are; a new **Deploy** tab lists what is deployed and its state. |

## 1. Deploy access

The setup runs once per host, either with a sudo password typed into the web UI (never stored, as with read-only scan access) or by running the downloaded script as root. It creates:

- **The `storageforge-deploy` user.** A system account with no password and a root-owned `~/.ssh/authorized_keys` that the user cannot edit. The deploy key's line carries `restrict,command="sudo -n /usr/local/sbin/storageforge-run"`, so whatever command SSH asks for, only the runner starts.
- **`/etc/sudoers.d/storageforge-deploy`**, which allows only two commands:
  - `/usr/local/sbin/storageforge-run`;
  - `/usr/local/sbin/storageforge-job --serve *` (section 3).

  It is checked with `visudo -cf` before it is installed.
- **`/usr/local/sbin/storageforge-run`.** A root-owned Bash program that reads one request from stdin:
  ```
  STORAGEFORGE-RUN 1
  <payload bytes>
  <signature bytes>
  <payload><signature>[data for the script's stdin]
  ```
  The payload is a header followed by a blank line and the script. The header holds `host:`, `issued:` (epoch), `nonce:` and `args:`. The runner refuses the request unless all of these hold:
  - the signature verifies (`ssh-keygen -Y verify`, namespace `storageforge-deploy`);
  - `host` is this machine's short hostname;
  - `issued` is within the last 10 minutes;
  - the nonce has not been seen before;
  - `args` matches a strict character set.

  It then runs the script as root, logs a line to `/var/log/storageforge/run.log` and passes the exit code through.
- **`/etc/storageforge/allowed_signers`**, holding StorageForge's signing public key.

**Keys in the vault:**
- **`storageforge-signing`** (ed25519): signs payloads and is never bound to a host.
- **`storageforge-deploy`** (ed25519): the SSH login, bound per host with the new action `deploy`.

Stealing the deploy key alone gets nothing: without a fresh signature, the runner runs nothing.

Signatures use OpenSSH's SSHSIG format, written in Python with `cryptography`. Hosts need OpenSSH 8.1 or later for `ssh-keygen -Y`; Rocky 9, Debian 11+ and Raspberry Pi OS 11+ all have it.

## 2. Deploy runs

Each deploy run sends one signed script to one host. A run is recorded in `deploy_runs` with:
- host, kind (`shares`, `jobs`, `changes`, `job-action`, `setup`) and ref;
- mode (`report` or `apply`), actor, start, end, exit code;
- output, truncated to 256 KiB.

A background thread streams the output into the row, and the UI polls it. Every run is also in the audit log.

**One deploy** covers every host it touches, in a fixed order:
- **Shares:** the server first, then each client. That includes clients the last deployment had and the design has since dropped, so their mounts are removed.
- **Jobs:** source hosts first, so their serve config and keys exist, then the hosts that run the jobs.
- **Changes:** each host in the plan.

The report runs first on every host. Apply is offered only when no host reported a conflict, or when the user overrides that.

## 3. Jobs (rsync and rsnapshot)

Every step of a Moves plan, deployed, becomes a job with a stable id `<plan-slug>-<step-id>`. Jobs run on the destination host and pull from the source.

**Host side, on the destination (the runner):**
- `/usr/local/sbin/storageforge-job`, a static Bash program installed and updated by deploys.
- `/etc/storageforge/jobs/<id>.conf` (0644): shell assignments written by Python with `shlex.quote`.
- `/etc/storageforge/jobs/<id>.key` (0600): the job's SSH key for the source.
- `/etc/storageforge/jobs/<id>.token` (0600): the report token.
- `sf-job-<id>.service`, plus `.timer` for scheduled methods (mirror, rsnapshot, git). There is also an optional `sf-job-<id>-verify.timer` for the weekly checksum verify.
- `/var/lib/storageforge/jobs/<id>/runs.jsonl` (0644), one line per run.

**Host side, on the source (serve):**
- `/etc/storageforge/serve/<id>.conf`: the allowed root path, pre/post commands and the snapshot mode.
- A line in `storageforge-deploy`'s authorized_keys: `restrict,command="sudo -n /usr/local/sbin/storageforge-job --serve <id> \"$SSH_ORIGINAL_COMMAND\""`. It is a managed block, rewritten from the serve configs on each deploy.
- `--serve` accepts only these requests:
  - `pre`, `post`, `snap`, `unsnap`;
  - `rsync --server --sender …`, with every path inside the allowed root or its snapshot;
  - `git-upload-pack '<path>'`, likewise restricted to the allowed root.

  It refuses `--remove-source-files`. That makes it a small rrsync.
- This replaces today's manual steps: the root key on the destination, the scan user's sudoers line for rsync, and agent forwarding. Same-host jobs skip SSH entirely.

**One run (`storageforge-job run <id> [level]`):**
1. Window check: when a window is set, a run outside it exits as "skipped (outside window)". `RuntimeMaxSec` stops a run at the end of its window, and `--partial` lets the next run resume.
2. Bandwidth: `BW_DAY` or `BW_NIGHT`, chosen by the start time.
3. `pre` on the source: stop a compose stack, dump a database, or any command.
4. `snap` on the source when the source is btrfs: a read-only snapshot of the subvolume that holds the path, at `<subvol>/.storageforge-snap/<id>`. Then `post` runs straight away, so a stopped stack is only down for the snapshot itself.
5. The transfer, by method:
   - **copy, move, mirror:** rsync;
   - **rsnapshot:** `rsnapshot -c conf <level>`; only the lowest level transfers, higher levels rotate;
   - **git:** `git remote update`.
6. `unsnap` on the source, and `post` if the snapshot step did not already run it. A trap makes sure post runs even when the transfer fails.
7. The result goes to `runs.jsonl` and is posted to `<report_url>/api/jobs/report` with the job token. The post is best effort: curl, then wget, then python3.

Other modes:
- `verify <id>` (also on a weekly timer when enabled): `rsync -n -i -c`, reporting the number of differing files and the first ones.
- `cutover <id>`: move steps, as today.
- `snapshots <id>`, `ls <id> <snap> <path>`, `pack <id> <snap> <path>`: snapshot browse and restore.
- `status`: JSON for all jobs (last runs, timer state).

**Schedules** are systemd `OnCalendar` expressions. There are presets (hourly, daily 02:30, every 4 hours, weekly Sunday 03:00, monthly), and custom expressions are checked against a strict character set. Retention presets show an estimate of the space they need, from the index.

## 4. Reporting, history, stale alerts

- **Reports:** `POST /api/jobs/report` takes a `Bearer <job token>`; the database keeps only the token's SHA-256. The body has job, run uuid, kind, level, start, end, exit code, bytes, files and a message. It is rate limited and needs no session.
- **Scan fallback:** scans read the last 50 lines of each `runs.jsonl`, plus the timer state, in a new `@@jobs` inventory section. They are de-duplicated by run uuid.
- **History:** stored in `job_runs`.
- **Stale:** a job is stale when its last good run is older than twice its schedule period plus an hour. The period is worked out from the OnCalendar expression.
- **3-2-1:** the graph adds a `REPLICATES_TO` edge for each mirror or rsnapshot job, coloured by the job's freshness, so the mount health dots follow the real jobs.

## 5. Alerts

- `settings` holds the channels: an ntfy URL, topic and optional token; a Gotify URL and token; a webhook URL. Each has a test button.
- `alerts` has one row per open problem, keyed `kind:ref`, with first and last seen and when it was notified. A notification goes out when a problem opens and when it resolves.
- **Kinds:** job failed, job stale, verify found differences, drift, deploy failed.
- A thread re-evaluates them every 5 minutes.

## 6. Drift

There are two kinds:
- **Pending:** the plan or design changed since it was last deployed. The hash of the generated deploy is stored in `deployed`.
- **Changed on the host:** apply runs record what they wrote:
  - `/var/lib/storageforge/managed/<kind>.sha256`, for files readable by the scan user;
  - `<kind>.lines`, for StorageForge's own fstab lines;
  - the timer units they own.

  Scans run `sha256sum -c`, check the lines, and run `systemctl is-enabled` on the timers. Anything that fails is drift.

## 7. NFS

- **Rules per client:** an export gets `rules: [{clients, options}]` and becomes `path client1(opts1) client2(opts2)`. The presets are read-only, read-write, read-write without root squash, and all users as one owner (`all_squash,anonuid,anongid`). Options are checked against the list of known export options. The old single `clients`/`options` still works as one rule.
- **Edit and remove:** the exports file is already rewritten whole. On clients, each fstab line StorageForge adds is preceded by a marker: `# storageforge share <server>:<path>`. A deploy removes the server's marked lines that are no longer wanted, unmounts them first, and stops their automount units. Clients from the last deployment are included even after the design drops them.
- **ID check:** scans collect users and groups with UID/GID ≥ 1000 (`@@ids`). For each read-write export, the owners of its files (from the index) are compared with the same names on each client. A mismatch, such as `gabe is 1000 on tr01 and 1001 on cachyos`, is a warning in the share check.

## 8. Snapshot browse and restore

Snapshot browse and restore are for rsnapshot jobs.
- **Browse:** pick a snapshot by level and date, then browse its folders.
- **Restore:** a file or folder goes back to the source host as `<original>.restored-<date>` and never overwrites anything.
  - **Same host:** `cp -a`.
  - **Other host:** a tar stream piped through StorageForge, from a signed `pack` run on the backup host into a signed `unpack` run on the source. The tar arrives on the runner's stdin, after the signed request.
  - The size is shown before starting.

## 9. Data model (migration 010)

| Table | Holds |
| :--- | :--- |
| `deploy_access` | Hosts set up for deploy (state, OpenSSH version, when, by whom). |
| `deploy_runs` | Section 2. |
| `deployed` | Per host and kind: deploy hash, when and by whom, and the clients or jobs included. |
| `jobs` | Id, plan, step, runner host, source host, method, schedule, token hash, paused, last deploy. |
| `job_runs` | Run uuid, job, kind, level, start, end, exit code, bytes, files, message, source. |
| `alerts` | Section 5. |
| `settings` | Key/value JSON. |

## 10. Security notes

- Nothing in a signed payload is stored. That includes job private keys and tokens, which travel only inside the SSH session.
- The signing key is the trust anchor. Rotating it means re-running the setup, which rewrites `allowed_signers`. The setup's removal script undoes everything.
- **Pre/post commands** are root commands written in the UI. Only signed-in users can write them, every deploy that installs them is audited, and the UI shows them in the report before apply.
- **The serve hook** only reads below its job's root, and only runs the hooks configured for that job.
