---
id: PF-14
status: in-progress
severity: low
effort: M
area: "[[Reports and exports]]"
tags: [finding, carried-over]
found: 2026-10-29
---
# PF-14 Reports and canvas predate newer features

U6 from the 10-27 audit, still open.

## What exists
`report.py` sections: 1 summary and topology, 2 disks, 3 links and mounts, 4 3-2-1 matrix, 5 economics, appendices A (index) and B (method). `canvas.py` (141 lines) draws hosts, disks, mounts and links.

## What is missing
Nothing on git repositories, NFS/SMB shares, Docker stacks and the folders they use, move plans, storage tasks, deployed jobs with their last runs, drift, open alerts, or unreadable folders. The report is the one artifact that leaves the app, and it describes the app as it was a week ago.

## Suggested approach
Add sections 6 to 9 built from the same functions the API uses (`gitrepos`, `shares.check`, `docker`, `jobs.overview`, `alerts.list_alerts`). In the canvas, add share edges (dashed, remote colour, matching U5) and a group per Docker stack.

## Done when
- [ ] `report` mentions every deployed job with its last run and every open alert

## Progress 2026-10-30
`reportextra.py` adds sections 6 to 11. Not done: share edges and stack groups in the canvas.
