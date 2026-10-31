---
tags: [audit-rules]
---
# Note format

Each audit is one folder in the vault:

```
Audit YYYY-MM-DD/
  Audit YYYY-MM-DD.md     the first page
  Findings/               one note per finding
```

## The first page holds, in this order
1. A short version: is it safe to ship, and where the problems cluster
2. A count by severity
3. The few things to read first
4. Findings tables with severity, effort and whether proven
5. A fix order, with each step making the next easier
6. A verdict per feature: is it well built, should it change
7. What was done well
8. Scope and method: baseline, head, what was read in full, in part and not at all, what was run, what was not

## A finding
Start from `Templates/Audit finding`. Keep to one problem. Headings:
- **What exists:** what the code does, in plain words
- **Evidence:** file and line, then what the proof showed
- **Why it matters:** who can do what, and what follows
- **Suggested approach:** a recommendation, not a menu
- **Done when:** checkable, ideally a test

Name files `<id> <short title>.md`. Link liberally with `[[...]]`. In a table, escape the pipe: `[[note\|short]]`.

## Writing
State what is true, and how you know it. Write for someone who wasn't there and may fix it months from now. Skip words like *critical flaw* outside the severity field: the facts should carry it.
