---
id: PF-02
status: done
severity: high
effort: M
area: "[[Data protection]]"
tags: [finding, partial]
found: 2026-10-29
---
# PF-02 Protection matrix ignores deployed jobs

## What exists
- The planner and report show a 3-2-1 matrix per dataset: sync, snapshots, backup target, last backup, offsite (`planner.js:980 vProtection`, `analysis.py`, report section 4).
- Since the 10-27 audit StorageForge **deploys** the protection itself: move steps with method `mirror`/`rsnapshot`, and storage tasks such as the "btrfs snapshots", "ZFS snapshots" and rsync templates (`tasks.py:123-138`). Deployed jobs report every run to `/api/jobs/report`, so `job_runs` knows each job's source, target and last good run.

## What is missing
The two halves never meet. `blueprint.py:79-86` creates every protection row as `sync: None`, `backup.target: None`, `last: None`, and only a saved design (typed by hand) fills them. No code in `jobs.py`, `tasks.py` or `alerts.py` reads or writes `protection`. A dataset that StorageForge mirrors nightly still shows red in the matrix until someone types the same fact in.

## Suggested approach
1. Add `protection_from_jobs(conn, host)` that maps each deployed job to the dataset containing its source path (`analysis.containing_mount` already does the lookup) and returns `{sync|snap|backup: {tool, target, last, offsite?}}`, using `last_ok.end` for `last`.
2. Overlay it in `payloads.overlay` after the saved design, marked `source: 'deployed'` so the planner shows it read-only with a link to the job in the Deploy tab.
3. Offsite: true when the runner/target host is not the source host and is tagged offsite (a host flag in the design is enough to start).
4. Then [[PF-01 Alerts only cover deploys|PF-01]] gets "backup past its age" alerts for free.

## Done when
- [ ] Deploying an rsnapshot move fills the backup column, with its last run time
- [ ] A hand-entered row still wins where no job covers the dataset

Related: [[PF-03 Backup and snapshot detection]]

## Progress 2026-10-30
`protection.py` fills the matrix from deployed jobs and scheduled tasks. Typed values stay where nothing covers a dataset and come back if the job goes. Hosts are marked offsite from the Protection view.
