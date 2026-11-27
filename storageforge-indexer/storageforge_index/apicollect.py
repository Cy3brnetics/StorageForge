"""What one read of a platform found, collected the same way by every reader (apipve, apipbs, apipdm, apixo, apitruenas, apidockhand,
apiportainer, apikomodo, apipangolin): the objects, and one line for each part that could not be read.

A call that fails with an ApiError becomes a skipped line, and the read goes on. A certificate that changed or a pin that was lost is
never one of those: it is raised, and it fails the whole read (apiread.read records it and keeps the last good reading). A list that
holds more than a read takes is cut in one way too: Cap counts across lists, asks for no more once it is full, and says so once.
"""
from __future__ import annotations

LINE = 200                   # the longest skipped line kept


class Reading:
    def __init__(self, objs: list | None = None):
        self.objs = list(objs or [])
        self.skipped: list[str] = []

    def skip(self, line: str):
        self.skipped.append(line[:LINE])

    def call(self, label: str, fn, quiet: bool = False):
        """fn(), or None when it failed with an ApiError: written down as 'label: why', or dropped when quiet. A changed certificate or a
        lost pin is raised."""
        from .apiconn import ApiError, CertificateChanged, NotPinned
        try:
            return fn()
        except (CertificateChanged, NotPinned):
            raise
        except ApiError as exc:
            if not quiet:
                self.skip(f'{label}: {exc}')
            return None

    def cut(self, most: int, what: str):
        """Says that a list held more than `most` and the rest was not read."""
        self.skip(f'more than {most} {what}: the rest was not read')

    def cap(self, most: int, what: str) -> Cap:
        return Cap(self, most, what)

    def result(self) -> tuple[list, list]:
        """(objects, skipped), each skipped line once."""
        return self.objs, list(dict.fromkeys(self.skipped))


class Cap:
    """At most `most` items over any number of lists. take() keeps what still fits; full() is asked before the next list is fetched, so
    once nothing more fits nothing more is asked for. Either one says, once, that the rest was not read."""
    def __init__(self, reading: Reading, most: int, what: str):
        self.reading, self.most, self.what, self.left = reading, most, what, most

    def full(self) -> bool:
        if self.left <= 0:
            self.reading.cut(self.most, self.what)
            return True
        return False

    def take(self, items: list) -> list:
        if len(items) > self.left:
            self.reading.cut(self.most, self.what)
        kept = list(items[:max(self.left, 0)])
        self.left -= len(kept)
        return kept
