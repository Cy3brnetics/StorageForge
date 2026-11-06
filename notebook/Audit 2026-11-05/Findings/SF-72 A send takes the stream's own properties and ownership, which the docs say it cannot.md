---
id: SF-72
status: open
severity: medium
effort: M
area: Send and receive steps
verified: read
tags: [finding, audit-2026-11-05]
found: 2026-11-05
---
# SF-72 A send takes the stream's own properties and ownership, which the docs say it cannot

**Medium** · M · Send and receive steps · Read · part of [[Audit 2026-11-05]]

## What exists
The receiving side of a send (SF-48) runs as root behind a forced command, and `docs/security.md` says of the key: "It can't read the receiver ... or run anything at all", and that the chroot and `-x mountpoint` "confine what a stream can name". The point of the whole design is that a taken-over sender, which holds the send key, can do little to the receiver.

## Evidence
`scriptkit.py:197` runs `btrfs receive -C "$ROOT"` and `:199` runs `zfs receive -u -x mountpoint -- "$ROOT"`. Nothing else about the stream is limited:
- btrfs: files in the received subvolume keep the owner, group, mode and setuid bits the stream carries. The receive-time check only counts names (`recv_state`, `extra`). The restore path in `jobscript.py` strips setuid, device nodes and pipes ("removed setuid/setgid from N restored file(s)"), which shows the risk is known there, but the receive does not.
- ZFS: only the property `mountpoint` is excluded. A stream made with `zfs send -p` or `-R` carries the others (`sharenfs`, `sharesmb`, `setuid`, `devices`, `exec`, `canmount`, quotas). `-u` only stops the mount now; the dataset mounts at the next boot or `zfs mount -a`, under the inherited mountpoint, with those properties.

Read, not run: there is no ZFS or btrfs on this machine and the lab (tier 16) has not run. The ZFS property behaviour is OpenZFS's documented one for `zfs receive` without `-x`/`-o`; it should be confirmed in the lab.

## Why it matters
A taken-over sender can hand the receiving host a root-owned setuid shell inside a backup folder (any local account on the receiver that can reach the folder then has root), or a dataset that is exported over NFS or SMB with the stream's settings. The receiver is typically a backup NAS, and ransomware reaching the backups through a sender is the case this feature is built against. Rated Medium: it needs a taken-over sender and either a local account or an exposed share on the receiver.

## Suggested approach
For ZFS, receive with `-o` overrides that are safe by construction (`-o canmount=noauto -o setuid=off -o devices=off -o exec=off`, and `-x sharenfs -x sharesmb`), or refuse streams that carry properties. For btrfs, mount the receive folder `nosuid,nodev` (check it in the receiving script and report a conflict when it is not), or move the received subvolume under a parent that is not traversable by others (mode 0700 on `$ROOT`, which the receiving script sets). State in `docs/security.md` which of these the key can still do. Lab tier 16 should send a stream with a setuid file and `sharenfs` set.

## Done when
- [ ] A received dataset cannot export itself, mount with setuid or devices, or auto-mount
- [ ] A received btrfs folder cannot give a local account a setuid root file
- [ ] The docs list what a stolen send key can still put on the receiver
- [ ] Lab tier 16 includes a hostile stream and passes

## Progress
2026-11-06, in `3de010a`: the ZFS receive adds `-x sharenfs -x sharesmb -o setuid=off -o devices=off -o canmount=noauto`, so a stream cannot bring an export or a setuid file with it; `docs/security.md` advises `nosuid,nodev` or a 0700 parent for a btrfs receive folder. **Still open**, because it needs a lab run (tier 16) with a hostile stream: on ZFS, a `zfs send -p` or `-R` stream carrying `sharenfs`, `sharesmb`, a setuid file, a device node and `canmount=on`; confirm `-x` and `-o` work together including an incremental receive, that no export appears, `setuid` and `devices` read `off`, and the dataset does not mount at boot. On btrfs, a subvolume with a root-owned setuid file: confirm it arrives intact and whether `nosuid` or a 0700 parent stops a local account using it. `canmount=noauto` means a received dataset no longer mounts at boot.
