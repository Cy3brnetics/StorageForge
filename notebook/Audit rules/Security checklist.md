---
tags: [audit-rules, checklist]
---
# Security checklist

## For every route
- [ ] Who may reach it with no session? `@login_required`, or a stated reason
- [ ] Which permission covers it in `permissions._RULES`, and does the rule's first match really mean that route? Rules match in order, and a broad earlier pattern can win
- [ ] Is the permission's text honest about what this route can lead to? Should it be marked high risk?
- [ ] Runs on a host or changes access: does it need a fresh password (`@password_confirmed`)?
- [ ] Runs a command: is it POST, never GET? Does GET change nothing at all, including tokens and database rows?
- [ ] Writes an audit row? Does an audit failure stop the action, or get swallowed?
- [ ] Does a broader read route return the same data a narrower route refuses? Compare `/api/x` with `/api/x/settings`
- [ ] Is body size right? The 4 KiB default also breaks legitimate large bodies, so test both directions
- [ ] Is it expensive (Argon2 unlock, whole-table read, SSH)? Rate limit and cap it
- [ ] Do numeric inputs have limits on both sides? Negative values often mean "no limit"
- [ ] Does it trust the `Host` header or another request value when building something that outlives the request?

## For everything that runs on a host
- [ ] Do values reach Bash as data? Is it in `test_no_generator_lets_a_value_run_as_code`?
- [ ] Can a value end a heredoc? Delimiters should be unguessable, or values encoded
- [ ] With no flags, does it only report?
- [ ] Which key and binding does it use? A `scan` binding must never change anything
- [ ] Does it go through the signed runner, so it gets the nonce, run record and audit?
- [ ] Does it run with no person involved? Text from the host must never shape what gets signed
- [ ] Are files it leaves readable only by who should read them? Do logs grow without limit?
- [ ] Does it run a tool that reads config from a place an unprivileged user controls? `git` in a repository is the known example
- [ ] Environment variables from users: are `LD_*`, `BASH_ENV`, `PATH` and `GIT_*` refused?
- [ ] Temp files and locks in world-writable places: `O_NOFOLLOW`, private folders?

## For everything that runs on the server
- [ ] Does user input ever become a process here? It should not. The server holds the vault
- [ ] Does a child process inherit the server's environment?
- [ ] Is "localhost" treated as a special host anywhere?

## For credentials and tokens
- [ ] Only a hash stored? Shown once? Never in logs, run output or audit detail?
- [ ] Sent only over TLS? Refuse rather than fall back to `http://`
- [ ] Can an old token be replayed? What ends it? When is it rotated, and does rotation break a working client?
- [ ] Does a link stay valid after what it grants has changed?

## For permissions and roles
- [ ] Can a route let someone do more than the permission says (destructive, root, another account)?
- [ ] Is the same action reachable another way, with a weaker check? Schedules against deploys was the 2026-10-31 example
- [ ] Do custom roles and built-in roles both behave?
- [ ] Can anyone grant more than they hold?

## For the browser
- [ ] DOM APIs only for host data, with no `innerHTML`
- [ ] CSP unchanged
- [ ] CSV and exports safe from spreadsheet formulas
- [ ] Tree and card maps: do file names, paths, dataset tags, or snapshot labels pass into DOM attributes or markup safely?
- [ ] Folder picker and navigation: can path traversal (`../`) escape the index root or leak parent folder contents?

## For remote nodes and reverse SSH tunnels
- [ ] Does the tunnel server configuration strictly constrain incoming connections?
- [ ] Does `authorized_keys` enforce forced commands (`command=...`), `no-pty`, `no-agent-forwarding`, `no-X11-forwarding`?
- [ ] Are port forwards restricted to loopback (`permitopen="127.0.0.1:..."`) so external networks cannot be pivoted through?
- [ ] Can a remote host forge another host's identity or hijack its assigned reverse tunnel port?
- [ ] Are tunnel authorized_keys and config files written atomically with strict `0600` permissions?
- [ ] Does terminating or removing a remote node revoke its key and close active tunnel connections immediately?

## For multi-tenant sites and key vaults
- [ ] Does every site-scoped route enforce site ownership and prevent cross-site object references?
- [ ] Can an operator in site A view, read, or execute plans against hosts in site B?
- [ ] Key vaults: do generate-only vaults strictly prohibit reading or exporting private keys once created?
- [ ] Does site deletion or reset clean up keys, credentials, and state cleanly without leaving orphaned tokens?
- [ ] Reset links: are reset tokens single-use, bounded by time, invalidated after password reset, and do they terminate all active sessions?
- [ ] Role escalation via reset/invite: can an admin in a restricted site generate an invite or reset link with permissions exceeding their own role?

## For sync engine, snapshot jobs and external tool configs
- [ ] Do snapshot jobs (rsnapshot, snapper) validate configuration files and parameters before running?
- [ ] Can malicious or malformed options in job specs lead to arbitrary command execution on target hosts?
- [ ] Does the sync engine acquire volume locks before running, and are locks reliably released on errors or timeouts?
- [ ] Do sync scripts go through `storageforge-run` with signed nonces and execution tracking?
- [ ] Are remote rsync/ssh transfer commands properly escaped and restricted?

## For dependencies and containers
- [ ] Scanner results triaged by reachability, each critical with a written decision
- [ ] The scan is of the image the Dockerfile builds today: compare the versions in the report with the image
- [ ] Lock files updated, with images pinned by digest
