#!/usr/bin/env python3
"""Run the unit suite by block (tests/blocks.py says which class is in which), on one core or many.

    python tests/run.py                   light, the minute to run after any change
    python tests/run.py light medium      both
    python tests/run.py heavy -j 8        the slow block, eight classes at a time
    python tests/run.py all -j 8          light, medium and heavy: what CI runs
    python tests/run.py deep              the random tests again, with many examples and a fresh seed
    python tests/run.py --list heavy      the classes in a block, and nothing run

`python -m unittest discover -s tests` still runs everything in one process, as before.

-j N runs N worker processes, each taking the next class off a queue: a class keeps its setUpClass and its order. Every test makes its own temporary
folder, database and ports, so classes don't meet. Timing-bound tests are written with margins for a loaded CI runner, but if one fails under -j
and passes alone, that is a finding: say so rather than raising the margin.

A light test that takes more than LIGHT_BUDGET seconds, or a medium one more than MEDIUM_BUDGET, is listed at the end: move its class in blocks.py.
"""
import argparse
import collections
import io
import os
import sys
import time
import traceback
import unittest
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import get_context
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
# tools the `test` extra installs (shellcheck) sit beside this interpreter, and a venv that was not activated is not on PATH
os.environ['PATH'] = os.path.dirname(os.path.abspath(sys.executable)) + os.pathsep + os.environ.get('PATH', '')
import blocks  # noqa: E402

LIGHT_BUDGET, MEDIUM_BUDGET = 1.5, 6.0


def discover() -> dict[str, list[str]]:
    """{'module.Class': [test ids]}, in discovery order. A module that fails to import comes back as a test of its own, so it fails loudly."""
    found = collections.OrderedDict()

    def walk(s):
        for t in s:
            if isinstance(t, unittest.TestSuite):
                walk(t)
            else:
                found.setdefault('.'.join(t.id().split('.')[:2]), []).append(t.id())
    walk(unittest.defaultTestLoader.discover(str(HERE), top_level_dir=str(HERE)))
    return found


class Timed(unittest.TextTestResult):
    def startTest(self, test):
        self._started = time.perf_counter()
        super().startTest(test)

    def stopTest(self, test):
        self.times[test.id()] = time.perf_counter() - self._started
        blocking()                  # a failed test's captured output is written here: it must not be lost to EAGAIN
        super().stopTest(test)


def blocking() -> None:
    """stdout and stderr back to blocking. Playwright's driver is a Node process that shares them, and Node makes a pipe
    non-blocking for every process holding it: a large write then fails with BlockingIOError once the pipe is full. On GitHub CI
    that lost a failed test's report and skipped its class's teardown, so the next browser class in the worker found Playwright's
    loop still running."""
    for fd in (1, 2):
        try:
            os.set_blocking(fd, True)
        except OSError:
            pass


def run_class(name: str, ids: list[str]) -> dict:
    """Runs one class in this process. Returns plain data, so it crosses back from a worker."""
    os.chdir(HERE.parent)
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    blocking()
    stream = io.StringIO()
    started = time.perf_counter()
    try:
        suite = unittest.defaultTestLoader.loadTestsFromNames(ids)
        runner = unittest.TextTestRunner(stream=stream, verbosity=0, buffer=True, resultclass=Timed)
        Timed.times = {}
        result = runner.run(suite)
    except Exception:
        return {'name': name, 'ran': 0, 'failures': [(name, traceback.format_exc())], 'skipped': [], 'times': {}, 'seconds': time.perf_counter() - started}
    return {
        'name': name,
        'ran': result.testsRun,
        'failures': [(t.id(), text) for t, text in result.failures + result.errors + [(t, 'unexpected success') for t in result.unexpectedSuccesses]],
        'skipped': [(t.id(), why) for t, why in result.skipped],
        'times': dict(Timed.times),
        'seconds': time.perf_counter() - started,
    }


def chosen(classes: dict, wanted: set[str]) -> dict:
    if 'deep' in wanted:
        return {c: ids for c, ids in classes.items() if blocks.is_random(c)}
    if 'all' in wanted:
        wanted = set(blocks.BLOCKS)
    return {c: ids for c, ids in classes.items() if blocks.block_of(c) in wanted}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('blocks', nargs='*', default=['light'], choices=[*blocks.BLOCKS, 'all', 'deep'])
    ap.add_argument('-j', '--jobs', type=int, default=1, help='worker processes (default 1)')
    ap.add_argument('-k', dest='pattern', help='only classes whose name holds this text')
    ap.add_argument('--list', action='store_true', help='list the classes and run nothing')
    ap.add_argument('--examples', type=int, help='with deep: examples per random test (default 2000)')
    a = ap.parse_args(argv)
    wanted = set(a.blocks)
    if 'deep' in wanted:
        os.environ['SF_PROPS'] = 'deep'
        if a.examples:
            os.environ['SF_PROPS_EXAMPLES'] = str(a.examples)
    os.chdir(HERE.parent)
    todo = chosen(discover(), wanted)
    if a.pattern:
        todo = {c: ids for c, ids in todo.items() if a.pattern in c}
    if a.list:
        for c, ids in todo.items():
            print(f'{blocks.block_of(c):6}  {len(ids):4}  {c}')
        print(f'{sum(map(len, todo.values()))} tests in {len(todo)} classes')
        return 0
    if not todo:
        print('nothing to run')
        return 1

    label = ' '.join(sorted(wanted))
    print(f'{label}: {sum(map(len, todo.values()))} tests in {len(todo)} classes, {a.jobs} at a time', flush=True)
    started = time.perf_counter()
    results = []
    if a.jobs <= 1:
        for c, ids in todo.items():
            results.append(run_class(c, ids))
            print('F' if results[-1]['failures'] else '.', end='', flush=True)
    else:
        # the longest classes first, by test count, so one big class doesn't start last and hold the run open
        order = sorted(todo.items(), key=lambda kv: (blocks.block_of(kv[0]) != 'heavy', -len(kv[1])))
        with ProcessPoolExecutor(max_workers=a.jobs, mp_context=get_context('spawn')) as pool:
            futures = [pool.submit(run_class, c, ids) for c, ids in order]
            for f in as_completed(futures):
                results.append(f.result())
                print('F' if results[-1]['failures'] else '.', end='', flush=True)
    wall = time.perf_counter() - started
    print()

    failures = [f for r in results for f in r['failures']]
    skipped = [s for r in results for s in r['skipped']]
    times = {t: s for r in results for t, s in r['times'].items()}
    for test, text in failures:
        print('=' * 100 + f'\nFAIL: {test}\n' + '-' * 100 + f'\n{text}')

    over = [(t, s) for t, s in times.items()
            if (blocks.block_of(t) == 'light' and s > LIGHT_BUDGET) or (blocks.block_of(t) == 'medium' and s > MEDIUM_BUDGET)]
    if over and a.jobs <= 1:          # under -j the machine is shared, and a time says little
        print(f'\nOver its block\'s budget (light {LIGHT_BUDGET}s, medium {MEDIUM_BUDGET}s): move the class in tests/blocks.py, or make it faster')
        for t, s in sorted(over, key=lambda x: -x[1]):
            print(f'  {s:6.1f}s  {blocks.block_of(t):6}  {t}')
    print('\nSlowest:')
    for t, s in sorted(times.items(), key=lambda x: -x[1])[:8]:
        print(f'  {s:6.1f}s  {t}')
    if skipped:
        print(f'\nSkipped {len(skipped)}:')
        for why, n in collections.Counter(w for _, w in skipped).most_common():
            print(f'  {n:4}  {why}')
    ran = sum(r['ran'] for r in results)
    print(f'\n{label}: ran {ran} in {wall:.1f}s, {len(failures)} failed, {len(skipped)} skipped')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
