---
id: GM-23
status: open
severity: medium
effort: S
area: "[[Scanner, Database and Analytics]]"
tags: [finding, logic, scanner, inventory, capacity, search, gemini-audit]
found: 2026-10-29
---
# GM-23 Inventory section parser collisions, missing mountinfo superblock options, and capacity edge cases

## Location
- `storageforge_index/remote.py:321-330, 362-380` (`parse_sections()`, `parse_mountinfo()`)
- `storageforge_index/capacity.py:71-90, 131-145` (`pool_capacity()`, `_btrfs_alloc()`)
- `storageforge_index/search.py:72-88, 195-214` (`glob_to_regex()`, `run_dupes()`)

## Mechanics & Root Cause
### 1. `remote.py:parse_sections()` Has No Section Whitelist and Drops Unterminated Final Section (`remote.py:321-330`)
```python
def parse_sections(text: str) -> dict[str, str]:
    out, cur, buf = {}, None, []
    for line in text.splitlines():
        if line.startswith('@@'):
            if cur:
                out[cur] = '\n'.join(buf)
            cur, buf = line[2:].strip(), []
        else:
            buf.append(line)
    return out
```
- Unlike `docker.py:_sections()` (which checks `tag in ('engine', 'ps', 'inspect', 'volumes', 'df', 'compose', 'file')`), `remote.py:parse_sections()` treats **any** line starting with `@@` inside `/etc/fstab` (within `managed`), `/etc/exports`, `/etc/samba/smb.conf`, or `runs.jsonl` as a new section header, corrupting the inventory parse.
- If the SSH output is truncated before `@@end`, the final section in `buf` is dropped because `if cur: out[cur] = '\n'.join(buf)` is not flushed after the loop.

### 2. `remote.py:parse_mountinfo()` Drops Superblock Mount Options (`b[2]`) (`remote.py:362-380`)
In `/proc/self/mountinfo` (`a[0..5] - b[0..2]`), `a[5]` holds only VFS-level mount options (`rw,relatime`), while filesystem-specific superblock options (`subvol=/@`, `compress=zstd:3`, NFS `vers=4.2`) sit in `b[2]`. `parse_mountinfo()` only reads `options=a[5]` and discards `b[2]`, so on any host where `findmnt -J` is unavailable and `mountinfo` is used as the fallback, Btrfs subvolume and mount-option checks lose all superblock options.

### 3. `capacity.py` Negative Usable Capacity & Missing Btrfs `raid5`/`raid6` (`capacity.py:71-90, 131-145`)
- In `pool_capacity()`, `btrfs` `level` (`line 141`) only maps `{'raid1': 2, 'raid1c3': 3, 'raid1c4': 4, 'raid10': 2}.get(level, 1)`. For `btrfs` `raid5` or `raid6`, `copies` defaults to `1` (`data = raw`, `parity = 0`, `tolerance = 0`).
- When drive count `n` is smaller than required for the RAID level (e.g. 1 drive in `mdadm raid5` or `btrfs raid1`, or 2 drives in `btrfs raid10`), `data` is `0`, and subtracting `meta = data * 0.01 + 512 * MiB` (`line 143-145`) yields **negative `usable` capacity** (`-536870912.0` bytes / `-512 MiB`).

### 4. `search.py:run_dupes()` Ignores `host` Filter in Inner Member Query (`search.py:195-214`)
```python
    for h, n, size, reclaim in groups:
        members = conn.all("""SELECT h.hostname, d.path, f.filename FROM file_records f JOIN directories d ON d.dir_id = f.dir_id
                              JOIN mounts m ON m.mount_id = f.mount_id JOIN hosts h ON h.host_id = m.host_id
                              WHERE f.checksum_hash = :c ORDER BY h.hostname, d.path""", {'c': h})
```
When `GET /api/duplicates?host=nas-01` or `storageforge-index dupes --host nas-01` is called, the outer query (`line 204`) filters by `{host_sql}`, but the inner query (`line 209-211`) selects all files with `WHERE f.checksum_hash = :c` across **every host**, returning cross-host paths in `files` while computing `copies` and `reclaimable` only for `nas-01`.

## Impact
Corrupted inventory sections if config files or logs contain `@@`; missing Btrfs subvolume/compression options on `mountinfo` fallback hosts; negative or wrong usable capacity on Btrfs RAID5/6 or under-populated pools; inconsistent host filtering in `run_dupes`.

## Remediation
1. Whitelist valid section names in `remote.py:parse_sections()` and flush `cur` after the loop.
2. Merge `a[5]` and `b[2]` options in `remote.py:parse_mountinfo()`.
3. Handle `raid5`/`raid6` for `btrfs` and clamp `usable = max(0.0, ...)` in `capacity.py`.
4. Include `{host_sql}` in the inner `members` query in `search.py:run_dupes()`.

## Done when
- [ ] `parse_sections`, `parse_mountinfo`, `pool_capacity`, and `run_dupes` handle all four cases accurately.
