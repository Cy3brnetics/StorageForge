"""A daemon thread writing to stderr must not abort the process as it exits (Fatal Python error, exit 134)."""
import subprocess
import sys
import unittest

WRITERS = """
import threading, time
from storageforge_index import errlog
def write():
    while True:
        try:
            raise ValueError('x' * 2000)
        except ValueError:
            errlog.trace()
for _ in range(8):
    threading.Thread(target=write, daemon=True).start()
time.sleep(0.05)
"""


class ExitWhileWriting(unittest.TestCase):
    def test_threads_writing_at_exit_do_not_abort(self):
        for _ in range(20):
            p = subprocess.run([sys.executable, '-c', WRITERS], capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr[-500:])
            self.assertNotIn('Fatal Python error', p.stderr)
