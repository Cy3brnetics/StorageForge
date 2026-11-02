---
id: PF-28
status: done
severity: medium
effort: S
area: Jobs / Scheduler
verified: read
tags: [finding, audit-2026-11-01]
found: 2026-11-01
---
# PF-28 Job reports over 4 KiB are refused with 413 Payload Too Large

**Medium** · effort S · Jobs / Scheduler · Read · part of [[Audit 2026-11-01]]

## What exists
`POST /api/jobs/report` and `POST /api/jobs/state` accept job execution reports from host scan runners and sync jobs. However, `server.py` enforces a default `MAX_BODY = 4096` bytes. While `body_limit()` expands the limit for `/api/scheduler/report` (addressed in [[PF-18 Schedule reports over 4 KiB are refused|PF-18]]), it omits `/api/jobs/report` and `/api/jobs/state`.

## Evidence
- `storageforge_index/server.py:561-569`:
  ```python
  @app.before_request
  def body_limit():
      if request.path == '/api/scheduler/report':
          request.max_content_length = 512 * 1024
      elif request.path.startswith('/api/planner/'):
          request.max_content_length = 1024 * 1024
      else:
          request.max_content_length = MAX_BODY  # 4096 bytes
  ```
- `storageforge_index/server.py:2460` (`api_jobs_report`): receives JSON containing job logs and stdout/stderr from snapshot and sync jobs.
- When an rsnapshot, snapper, or btrfs sync job executes and produces standard tool logs (rsync transfer statistics, file lists, or snapshot tree diffs) exceeding 4 KiB, Flask rejects the request before it enters the view handler with HTTP 413 Payload Too Large.

## Why it matters
Snapshot and sync jobs regularly produce more than 4 KiB of diagnostic output when multiple files or volumes change. The host runner's report is rejected, meaning StorageForge fails to record job status, duration, and output, leaving the job displayed as stuck, timed out, or unreported in the jobs dashboard.

## Suggested approach
Add `/api/jobs/report` and `/api/jobs/state` to `body_limit()` with a 512 KiB limit, matching the scheduler report handler:
```python
if request.path in ('/api/scheduler/report', '/api/jobs/report', '/api/jobs/state'):
    request.max_content_length = 512 * 1024
```

## Done when
- [ ] `POST /api/jobs/report` and `POST /api/jobs/state` accept payloads up to 512 KiB.
- [ ] A unit test verifies that a job report exceeding 4 KiB is accepted and stored.

## Outcome
**Severity after checking: Low (was Medium).** Mostly wrong. Reports carry no logs or stdout: `report()` sends a one-line summary with the message cut at 2000 characters, and `body_limit` is not the code quoted. A refused report is not lost either, since the next scan reads `runs.jsonl`. It can still exceed 4 KiB with a long non-ASCII or heavily escaped message. Fixed 2026-11-01 in `b222e78` with 16 KiB on `/api/jobs/report`, not 512 KiB, because this route takes bytes before the token is checked. `/api/jobs/state` stays at 4 KiB: its fields are short. Test: `test_a_full_length_run_message_is_not_refused`.
