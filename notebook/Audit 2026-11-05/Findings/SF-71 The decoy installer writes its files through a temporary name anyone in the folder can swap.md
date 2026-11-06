---
id: SF-71
status: open
severity: medium
effort: S
area: Ransomware defense
verified: proven
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-71 The decoy installer writes its files through a temporary name anyone in the folder can swap

**Medium** · S · Ransomware defense · Proven · part of [[Audit 2026-11-05]]

## What exists
The sentinel deploy writes decoy files into the shares a person names. For each one, the root script makes a temporary file next to the final name, fills it, sets owner and mode, and renames it. Share folders are exactly the folders that other accounts can write to.

## Evidence
`secscripts.py:669-681` (`INSTALL_BODY`): `tmp=$(mktemp "$dir/.sf.XXXXXX")`, then `printf ... >"$tmp"`, `head -c ... >>"$tmp"`, `chown --reference="$dir" "$tmp"`, `chmod 0666 "$tmp"` (when the folder is world-writable, else 0664), then `mv -f -- "$tmp" "$p"`. Every one of these follows a symlink. The check `[[ -L $p ]]` guards the final name only, not the temporary one.

I ran the real loop (extracted from `INSTALL_BODY`) over 150 decoy names in a mode 0777 folder under `/tmp/sfaudit/b/race`, with a second process watching the folder with `inotifywait` and replacing each `.sf.*` file by a symlink to a mode 0600 file of mine as soon as it appeared (`/tmp/sfaudit/b/p4.py`). All 150 swaps won. The target went from mode 0600, 18 bytes, to mode 0666 and 21,212 bytes: the script appended random bytes to it and made it writable by everyone. In this probe both sides were my own account, so what is proven is that the script follows the link and in which order; the privilege step is that on a real host the script is root and the swapper is another local account.

## Why it matters
Any local account (or an NFS client, which can create symlinks) that can write to a decoy folder can turn a deploy of the sentinel, a re-arm, or a deploy of an unchanged list after a change into: append of random bytes to, and `chmod 0666` of, any root file it names (for `/etc/passwd` or a sudoers file, that is a path to root). The window is the seconds a deploy takes, and the attacker needs to know it runs, so it is Medium rather than High.

## Suggested approach
Do not make the file in the shared folder under a guessable-by-watching name that is then edited by path. Build the decoy in a root-private temporary folder (`mktemp -d` under `$STATE`, mode 0700), set owner and mode there, then put it in place with a single operation that does not follow a link at the destination (`install -T` or `ln`+`rename` on the same filesystem, with `mv -T`), after checking the destination is not a link. Test it as `RollbackFolder` in `test_routers.py` does for SF-55: run the loop under a stand-in shell with a pre-made link of the temporary name.

## Done when
- [ ] No step of the decoy write follows a link made by another account in the share folder
- [ ] A test swaps the temporary file for a link during the loop and sees the target unchanged
- [ ] The decoy still has the folder's owner and mode, so a user who can change files there can trip it
