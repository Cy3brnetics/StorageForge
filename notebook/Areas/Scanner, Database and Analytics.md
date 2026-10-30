---
tags: [area, gemini-audit]
---
# Scanner, Database and Analytics

Agentless SSH scanner (`scanner.py`, `remote.py`, `stream.py`), SQLite and PostgreSQL database layer (`db.py`, `migrations/*`, `backup.py`), duplicate and cold folder analytics (`folders.py`, `search.py`), and RAID/pool capacity math (`capacity.py`, `payloads.py`).

## Findings
- [[GM-13 PostgreSQL runtime crashes across folders, backups, alerts, shares, and timestamps]] (High)
- [[GM-14 Scanner skips child Btrfs subvolumes by marking them alias while also pruning them]] (High)
- [[GM-23 Inventory section parser collisions, missing mountinfo superblock options, and capacity edge cases]] (Medium)
- [[GM-25 Thread-safety races in folder_cache, backup.create, Vault._UNLOCKED, and SQLite nested tx]] (Low)

Back to [[Home]]
