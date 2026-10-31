---
tags: [audit-rules, checklist]
---
# Feature and design checklist

The question for each feature: was it built the right way, and did anything get missed?

## Should it exist in this form?
- [ ] Does something already do this? If two paths do one job, which should go?
- [ ] Does it reuse the older path's protections, or reimplement them? List what the older one checks, then compare
- [ ] Does it add a dependency on target hosts (Python, cron)? Do all supported distros have it? Does preflight check?

## Does it do what it says?
- [ ] Every setting in the form changes behaviour. Search for the name in the runtime code
- [ ] Every status word means what it says. What actually proves "verified"?
- [ ] Every button's message is true on the host, not just in the database
- [ ] The docs describe what the code does

## The whole life cycle
Walk each one. Most gaps are here.
- [ ] Create, edit, deploy, run
- [ ] Edit after deploy: does drift notice? Does it notice a change in what it depends on?
- [ ] Pause and resume, on the host
- [ ] Delete while deployed: refused, or cleaned up? Can it still be uninstalled afterwards?
- [ ] Host retired, renamed or rekeyed
- [ ] Server restored from backup
- [ ] Upgrade from an older version on the host
- [ ] A dependency deleted (the plan a schedule runs)

## When things go wrong
- [ ] Output larger than expected, in every step it passes through
- [ ] The server is down when a host reports: is it retried, and what is lost?
- [ ] Bad input saved today that breaks a run next week: validate on save
- [ ] Store first, then process, so a crash in processing can't lose the record
- [ ] `except Exception: pass`: what does it hide?
- [ ] Does anything alert when this silently stops?

## Wired into the rest
- [ ] Backup lists, on both databases, and pruning for new tables
- [ ] Alerts, logbook, audit, report, CLI and API docs
- [ ] Both database dialects: types differ (`scans.started_at` is an integer on SQLite and `TIMESTAMPTZ` on PostgreSQL)

## Tests
- [ ] Do tests hit the failure cases, or only the sunny path with small data?
- [ ] Does a test bless behaviour that should not exist?
- [ ] Is it in the lab, on real distros? Commands needing root can't be proven by a unit test
- [ ] Can a whole class be caught by walking a list (URL map, generators, tables), rather than one test per case?
