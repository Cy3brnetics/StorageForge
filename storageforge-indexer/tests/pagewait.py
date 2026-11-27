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


def install() -> None:
    """Every Playwright timeout in this process says what this process's threads were doing when it was raised. tests/run.py
    calls it in each worker, so whichever browser test stalls next, its report names what the in-process server was blocked on."""
    try:
        from playwright._impl import _errors
    except ImportError:
        return
    cls = _errors.TimeoutError
    if getattr(cls, '_sf_threads', False):
        return
    plain = cls.__init__

    def init(self, *args, **kwargs):
        plain(self, *args, **kwargs)
        try:
            self._sf_threads_text = threads_now()
        except Exception:
            self._sf_threads_text = ''

    def text(self):
        return Exception.__str__(self) + ('\n\nthreads of this process when it timed out:\n' + self._sf_threads_text if getattr(self, '_sf_threads_text', '') else '')
    cls.__init__, cls.__str__, cls._sf_threads = init, text, True
