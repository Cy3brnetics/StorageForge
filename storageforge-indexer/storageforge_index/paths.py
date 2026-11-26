"""Is this path under that folder, and which mount holds it.

Pure functions with no imports, so the SSH side, the agent side and the planners can all use them.
"""
from __future__ import annotations


def is_under(path: str, root: str) -> bool:
    """Whether path is root or inside it. A relative path is under nothing, not even '/'."""
    if root == '/':
        return path.startswith('/')
    return path == root or path.startswith(root.rstrip('/') + '/')


def deepest(items, path: str, key=lambda x: x):
    """The item whose folder, key(item), is the deepest one holding path, or None. The first of equals wins."""
    return max((i for i in items if is_under(path, key(i))), key=lambda i: len(key(i)), default=None)
