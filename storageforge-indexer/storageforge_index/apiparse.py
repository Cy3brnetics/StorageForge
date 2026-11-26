"""Reading the JSON answers of platform APIs: the shared loaders and bounded readers of untrusted values.

Every reader in the api*.py modules turns a platform's answer into StorageForge's own fields.
The answer is untrusted text, so these never raise on it: a value of the wrong type or out of
range reads as None, and a document that is not JSON reads as absent.
"""
from __future__ import annotations

import json
import re


def _load(text):
    """The JSON document in text, or None when it is not JSON (including one nested too deep)."""
    try:
        return json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None


def _list(text) -> tuple[list, bool]:
    """The document as a list of dicts, and whether it was not a list at all."""
    doc = _load(text)
    if not isinstance(doc, list):
        return [], True
    return [x for x in doc if isinstance(x, dict)], False


def _data(text):
    """The 'data' of an answer enveloped as {"data": ...} (Proxmox), or None when the text is not one."""
    doc = _load(text)
    return doc.get('data') if isinstance(doc, dict) else None


def _items(text) -> tuple[list, bool]:
    """The 'data' of an enveloped answer as a list of dicts, and whether it was not a list at all."""
    data = _data(text)
    if not isinstance(data, list):
        return [], True
    return [x for x in data if isinstance(x, dict)], False


def _s(v, n: int = 200):
    return v[:n] if isinstance(v, str) else None


def _i(v):
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)) and v == v and abs(v) < 1e19:
        return int(v)
    if isinstance(v, str) and v.isdigit() and len(v) < 19:
        return int(v)
    return None


def _f(v):
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) < 1e19 else None


def _b(v):
    if isinstance(v, bool):
        return v
    if v in (0, 1, '0', '1'):
        return str(v) == '1'
    return None


def _when(v):
    """A date as epoch seconds: {"$date": ms} as the TrueNAS JSON encoder writes datetimes, an ISO string, or epoch seconds."""
    if isinstance(v, dict) and _i(v.get('$date')) is not None:
        return _i(v['$date']) // 1000
    if isinstance(v, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?', v.strip()):
        from datetime import datetime, timezone
        try:
            d = datetime.fromisoformat(v.strip().replace('Z', '+00:00'))
        except ValueError:
            return None
        return int((d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp())
    n = _i(v)
    return n if n is not None and n < 1 << 40 else None
