"""Stderr for daemon threads. A daemon thread caught writing to stderr as the interpreter finalizes holds the stream's lock,
and Python aborts the process (exit 134) when it needs that lock to flush. So writes take this gate, and exit closes it for good."""
from __future__ import annotations

import atexit
import sys
import threading
import traceback

_gate = threading.Lock()


def say(text: str):
    with _gate:
        print(text, file=sys.stderr, flush=True)


def trace():
    """The current exception's traceback, as traceback.print_exc()."""
    with _gate:
        traceback.print_exc()
        sys.stderr.flush()


def _close():
    _gate.acquire(timeout=5)     # a write stuck on a full pipe must not hold up exit


atexit.register(_close)
