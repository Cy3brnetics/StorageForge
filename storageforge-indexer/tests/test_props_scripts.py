"""Random tests of the scripts StorageForge writes for hosts, with hostile values. test_sends.HostileValues pins one canary through the send
scripts; these build the value from every piece of shell syntax that ends a word, a quote, a heredoc or a line, so the case nobody wrote down is
tried too. A value either reaches the script as data or is refused with a ValueError, and whatever is refused here is refused for a reason a
person could act on.

The canary is a command, sfcanary, that leaves a file when it runs. The scripts are checked as text (no sfcanary outside quotes and heredocs),
with bash -n, and some are run against the stand-in btrfs, zfs, ssh and sudo of test_sends.TwoHosts."""
import itertools
import re
import shutil
import subprocess
import unittest

from props import HAVE, given, settings, st, scaled
from storageforge_index import changes, jobs, moves, receiving, scriptkit, tasks
from test_sends import PIN, TwoHosts

# each of these ends something in some shell context; together they make values no single example covers
PIECES = ['$(sfcanary)', '`sfcanary`', ';sfcanary;', '|sfcanary', '&&sfcanary', '||sfcanary', '&sfcanary&', '\nsfcanary\n', '$(', ')', '`', '"', "'", '\\', '${IFS}',
          '$IFS', '${x:-$(sfcanary)}', '*', '?', '[', ']', '{', '}', '~', '#', '!', ' ', '\t', '--', '-', 'EOF', 'SF_00AA11BB22CC', '%s', '=', '>', '<', '<<',
          '\u202e', '\u2028', '\x85', '\r', '\x1b[2J', 'é', 'a', 'b', '1', '/', '.', '..']
hostile = st.lists(st.sampled_from(PIECES), min_size=1, max_size=8).map(''.join)
counter = itertools.count(1)
BASH = shutil.which('bash')


def runnable(script: str) -> list[str]:
    """Lines where bash would run sfcanary: unquoted (where it may be only an argument, but an unquoted value is split into words and is a
    defect either way), or as $( or ` inside double quotes or an unquoted heredoc. Quoting is followed as bash
    follows it ('...' is literal, "..." takes \" and expansions, $'...' takes \', # starts a comment at a word's start, <<'TAG' is literal to
    TAG, <<TAG expands), so shlex.quote's '...'"'"'...' reads as the one word it is. The run in test_it_stays_data_when_the_send_scripts_run is
    the last word; this is the quick check over every script."""
    found, i, n = set(), 0, len(script)
    line_of = lambda k: script.count('\n', 0, k)          # noqa: E731
    pending = []                                           # heredocs opened on this line: (tag, expands)
    state = 'code'
    while i < n:
        c = script[i]
        if state == 'code':
            if c == '\n':
                i += 1
                for tag, expands in pending:
                    close = re.compile(rf'^\t*{re.escape(tag)}$', re.M).search(script, i)
                    body_end = close.start() if close else n
                    body = script[i:body_end]
                    if expands and re.search(r'\$\(sfcanary|`sfcanary', body):
                        found.add(line_of(i))
                    i = close.end() if close else n
                pending = []
                continue
            if c == '#' and (i == 0 or script[i - 1] in ' \t\n;&|('):
                i = script.find('\n', i)
                i = n if i < 0 else i
                continue
            if script.startswith('<<', i) and not script.startswith('<<<', i):
                m = re.match(r"<<-?\s*(?:'([^']+)'|\"([^\"]+)\"|\\?([A-Za-z_][A-Za-z0-9_]*))", script[i:])
                if m:
                    pending.append((m[1] or m[2] or m[3], m[3] is not None and not script[i:i + m.end()].count('\\')))
                    i += m.end()
                    continue
            if script.startswith("$'", i):
                state, i = 'ansi', i + 2
                continue
            if c == "'":
                state, i = 'single', i + 1
                continue
            if c == '"':
                state, i = 'double', i + 1
                continue
            if c == '\\':
                i += 2
                continue
            if script.startswith('sfcanary', i):
                found.add(line_of(i))
            i += 1
        elif state == 'single':
            if c == "'":
                state = 'code'
            i += 1
        elif state == 'ansi':
            if c == '\\':
                i += 2
                continue
            if c == "'":
                state = 'code'
            i += 1
        else:                                              # double
            if c == '\\':
                i += 2
                continue
            if c == '"':
                state = 'code'
            elif script.startswith('$(sfcanary', i) or script.startswith('`sfcanary', i):
                found.add(line_of(i))
            i += 1
    lines = script.split('\n')
    return [lines[k] for k in sorted(found)]


class TheCheckItself(unittest.TestCase):
    def test_it_finds_what_runs_and_passes_what_does_not(self):
        runs = ['X=$(sfcanary)', 'echo "$(sfcanary)"', 'a;sfcanary;b', 'cat <<EOF\n$(sfcanary)\nEOF\n', 'echo `sfcanary`', "echo 'a'sfcanary"]
        data = ["echo '$(sfcanary)'", "echo '/srv/$(sfcanary)'\"'\"''", 'echo "a;sfcanary;b"', "cat <<'EOF'\n$(sfcanary)\nEOF\n", '# $(sfcanary)',
                "echo $'\\'$(sfcanary)'", 'echo "\\$(sfcanary)"']
        for text in runs:
            with self.subTest(runs=text):
                self.assertTrue(runnable(text))
        for text in data:
            with self.subTest(data=text):
                self.assertEqual(runnable(text), [])


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class CommentsStayComments(unittest.TestCase):
    @given(st.text(max_size=60) | hostile)
    def test_text_put_after_a_hash_stays_on_its_line(self, text):
        out = scriptkit.one_line(text)
        self.assertEqual(len(out.splitlines()) if out else 1, 1, repr(out))              # str.splitlines knows every line break there is
        self.assertFalse(re.search('[\x00-\x08\x0a-\x1f\x7f]', out), repr(out))    # what a terminal acts on when the script is read with cat

    @given(st.lists(st.text(max_size=30) | hostile, max_size=5))
    def test_a_header_of_comments_runs_nothing(self, lines):
        header = '\n'.join('# ' + line for line in scriptkit.comments(lines, '').split('\n'))
        self.assertEqual(runnable(header), [])
        r = subprocess.run([BASH, '-c', header + '\necho done'], capture_output=True, text=True, timeout=10, env={'PATH': '/nonexistent'})
        self.assertEqual((r.returncode, r.stdout), (0, 'done\n'), r.stderr)


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class HostileValuesAnywhere(TwoHosts):
    def setUp(self):
        super().setUp()
        (self.bin / 'sfcanary').write_text(f'#!/bin/bash\ntouch {self.t}/RAN\n')
        (self.bin / 'sfcanary').chmod(0o755)

    def grants(self, root, tool='btrfs'):
        hs = moves.hosts(self.conn)
        return [receiving.send(self.conn, hs, hs['nas'], 'nas', 'pc', tool, root, f't{next(counter)}', 'd', 2)]

    def scripts(self, value):
        """Every script of a send, a task and a plan, with the value where a path goes. None when the value is refused."""
        path = '/srv/' + value
        try:
            s = self.grants(path)
            keys = jobs.new_secrets(s)
            return {'receive report': receiving.receive_script('rt9-', value, 'pc', s, None),
                    'receive apply': receiving.receive_script('rt9-', value, 'pc', s, keys, 123),
                    'send report': receiving.send_script('rt9-', value, 'nas', s, None, {}),
                    'send apply': receiving.send_script('rt9-', value, 'nas', s, keys, {s[0]['id']: PIN}),
                    'task': tasks.script(self.conn, tasks.normalize({'name': 't', 'host': 'nas', 'blocks': [{'type': 'btrfs_send', 'params': {'into': path, 'prefix': 'd', 'dst_host': 'pc', 'dst': path, 'keep': 1}}]})),
                    'plan': changes.script(self.conn, {'name': 'p', 'tasks': [{'type': 'btrfs-send', 'host': 'nas', 'params': {'source': path, 'parent': path, 'dest_host': 'pc', 'dest': path}}]})}
        except ValueError as exc:
            self.assertTrue(str(exc), 'refused with no reason')
            return None

    @settings(max_examples=scaled(30, 400))
    @given(hostile)
    def test_a_hostile_value_is_data_in_every_script_or_refused(self, value):
        out = self.scripts(value)
        if out is None:
            return
        self.assertEqual({k: runnable(v) for k, v in out.items() if runnable(v)}, {}, repr(value))
        for name, script in out.items():
            r = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
            self.assertEqual(r.returncode, 0, f'{name} with {value!r}: {r.stderr}')

    @settings(max_examples=scaled(4, 60))
    @given(hostile)
    def test_it_stays_data_when_the_send_scripts_run(self, value):
        path = '/srv/' + value
        try:
            s = self.grants(path)
        except ValueError:
            return
        keys = jobs.new_secrets(s)
        for host, script in (('pc', receiving.receive_script('rt9-', value, 'pc', s, keys)), ('nas', receiving.send_script('rt9-', value, 'nas', s, keys, {s[0]['id']: PIN}))):
            r = self.run_script(host, script, ['--apply'])
            self.assertFalse((self.t / 'RAN').exists(), f'{value!r} ran on {host}: {r.stdout[-500:]}{r.stderr[-500:]}')


if __name__ == '__main__':
    unittest.main()
