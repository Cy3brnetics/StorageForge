"""Waiting for a page to say it is ready, and saying why when it doesn't.

Seen twice under load (GitHub CI's secrets page test, a local heavy run's key enclave test): a page that never set
data-route-ready, with nothing in the server's log. The server in these tests runs in the test's own process, so on a timeout
every thread's stack is printed with the script errors the page raised: the next one shows what the page was waiting for."""
from __future__ import annotations

import sys
import threading
import traceback


def threads_now() -> str:
    names = {t.ident: t.name for t in threading.enumerate()}
    out = []
    for ident, frame in sys._current_frames().items():
        if ident == threading.get_ident():
            continue
        out.append(f'--- thread {names.get(ident, ident)}\n' + ''.join(traceback.format_stack(frame)[-12:]))
    return '\n'.join(out)


def ready(case, page, errors, what: str = 'the page') -> None:
    """page.wait_for_selector('html[data-route-ready]'), failing `case` with the page's script errors and the server's threads."""
    try:
        page.wait_for_selector('html[data-route-ready]', state='attached')
    except Exception as exc:
        case.fail(f'{what} never said it was ready ({type(exc).__name__}); script errors: {errors}\n\nthreads of this process:\n{threads_now()}')
