---
id: SF-55
status: open
severity: low
effort: S
area: Network devices
verified: read
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-55 A device rollback script runs from a guessable temporary folder

**Low** · S · Network devices · Read · part of [[Audit 2026-11-05]]

## What exists
Applying a change to an OpenWrt or pfSense device plants a rollback: `OpenWrtApply` and `PfApply` copy the configuration into `/tmp/sf-<change id>` on the device and write `back.sh` there, which a background shell runs as root when the timer ends unless the change is confirmed. The folder name is the change's number, which a person with a shell on the device can guess.

## Evidence
`netdevice.py:407-415` and `:441-452`: `self.dir = f'/tmp/sf-{cid}'`, then `mkdir -p {self.dir}`, `cp` into it, and `cat > {self.dir}/back.sh`. `mkdir -p` succeeds on a folder that already exists and is someone else's, so whoever made it first owns what is in it. Read, not run: it needs a second, unprivileged account on a device, which the lab devices do not have, and the lab was not run in this audit.

## Why it matters
On a device that has another local account, that account can create `/tmp/sf-42` first, then replace `back.sh` before the timer ends, and root runs its content. OpenWrt and most routers have no such account, and the account would need to know the next change number, so it is Low.

## Suggested approach
Make the folder with `mktemp -d` (random, mode 0700), keep its name in the change record so a confirm or a later rollback finds it, and fail when it cannot be made. The device scripts are strings in `netdevice.py`, so the check is a test that runs them under a stand-in shell.

## Done when
- [ ] The rollback folder is made fresh and private, and an existing one of that name is not used
- [ ] A test runs the plant script with a pre-made folder of the same name and sees it refused or ignored
- [ ] The commit is written here
