"""A host's identity as the rest of StorageForge compares it: its short name, and the pattern a typed host name or
address must match. No imports from the package, so db.py and everything above it can use it."""
from __future__ import annotations

import re

# A host as plans name it: hostname, IPv4, [IPv6] or IPv6%zone. Never a line break or space; callers also refuse a
# leading '-'.
HOST_RE = re.compile(r'[A-Za-z0-9_.:\[\]%-]{1,253}')


def short(name: str) -> str:
    """The first label, lowercase, without characters other than a-z, 0-9, '_' and '-'; 'unknown' when nothing is left.
    The same rule as host_slug in the generated scripts (storage-setup.sh, change runs, reinstall)."""
    return re.sub(r'[^a-z0-9_-]', '', (name or '').split('.')[0].lower()) or 'unknown'
