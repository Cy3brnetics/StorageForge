"""What the random tests (test_props_*.py) share: Hypothesis, set up for the two ways they run.

    light   SF_PROPS unset: a small number of examples, the same ones every run (derandomize), so a red light run is a real change and not luck.
    deep    SF_PROPS=deep (tests/run.py deep): many examples from a fresh seed, and the failures Hypothesis finds are kept in .hypothesis/ and tried first next time.

A random test says what must hold for every input of a kind (a parser never throws anything but its own error, what the compiler accepts it can
emit and read back, a quoted value stays one word to the shell), where a controlled test pins one input to one answer. When one fails,
Hypothesis prints the smallest input it found: add that input to the module's controlled tests, so it is pinned for good.

Without Hypothesis (pip install hypothesis) the random tests skip, and the rest of the suite runs as before.
"""
import os
import unittest

try:
    from hypothesis import HealthCheck, assume, example, given, settings
    from hypothesis import strategies as st
    HAVE = True
except ImportError:          # the tests skip; these stand-ins only let the modules import
    HAVE = False

    class _Anything:
        def __getattr__(self, _):
            return self

        def __call__(self, *a, **k):
            return self

        def __or__(self, _):
            return self

    st = _Anything()

    def given(*_a, **_k):
        def wrap(fn):
            def skipped(self, *a, **k):
                raise unittest.SkipTest('needs hypothesis (pip install hypothesis; CI has it)')
            skipped.__name__, skipped.__doc__ = fn.__name__, fn.__doc__
            return skipped
        return wrap

    def example(*_a, **_k):
        return lambda fn: fn

    def settings(*_a, **_k):
        return lambda fn: fn

    def assume(_):
        return True

    HealthCheck = None

DEEP = os.environ.get('SF_PROPS') == 'deep'

if HAVE:
    _quiet = [HealthCheck.too_slow, HealthCheck.filter_too_much, HealthCheck.data_too_large]
    settings.register_profile('light', max_examples=60, derandomize=True, deadline=None, database=None, suppress_health_check=_quiet, print_blob=True)
    settings.register_profile('deep', max_examples=int(os.environ.get('SF_PROPS_EXAMPLES', 2000)), deadline=None, suppress_health_check=_quiet, print_blob=True)
    settings.load_profile('deep' if DEEP else 'light')


def scaled(light: int, deep: int) -> int:
    """Examples for a test that is slower than most (it runs bash, say): a few in light, more in deep."""
    return deep if DEEP else light


__all__ = ['HAVE', 'DEEP', 'assume', 'example', 'given', 'settings', 'st', 'scaled']
