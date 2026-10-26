# Example inputs: host "atlas"

These files describe the example homelab host from the StorageForge dashboard. They are sample data, not a real machine.

| File | Produced by |
| :--- | :--- |
| `blueprint.json` | StorageForge dashboard → Export → Blueprint JSON |
| `fstab` | StorageForge dashboard → Export → /etc/fstab |
| `df-h.txt` | `df -h` (example values) |
| `zpool-status.txt` | `zpool status` (example values, one drive with checksum errors) |

Regenerate the report:

```bash
storageforge-index report --blueprint examples/atlas/blueprint.json --fstab examples/atlas/fstab \
  --df examples/atlas/df-h.txt --zpool-status examples/atlas/zpool-status.txt \
  --as-of 2026-10-26 --kwh-price 0.30 --currency '€' -o reports/atlas-architecture-report.md
```
