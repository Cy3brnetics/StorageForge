"""What the web app takes from what agents reported, a few seconds after the receiver stored it, on a background thread of its own and
never on a web request's (roadmap sections 11.3 and 3 phase 2; the receiver, a process of its own, stored it: agentreceiver.py).

    run(db, wake)      the loop: every TICK_SECS, take_once(db), and wake the notification center when something changed
    take_once(db)      agents' last words (agentguard.take_reports, which acts only on the agent that sent one)

The receiver's database role writes only its own three tables; moving what agents said into the rest of StorageForge happens here,
on the web app's side, so that role stays as narrow as it is.
"""
from __future__ import annotations

import time

from . import agentguard, errlog
from .db import Database

TICK_SECS = 5


def take_once(db: Database) -> dict:
    return {'wiped': agentguard.take_reports(db)}


def run(db: Database, wake=None, tick: float = TICK_SECS):
    time.sleep(tick)
    while True:
        try:
            done = take_once(db)
            if wake and any(done.values()):
                wake()
        except Exception:
            errlog.trace()
        time.sleep(tick)
