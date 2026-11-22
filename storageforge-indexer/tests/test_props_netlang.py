"""Random tests of the network language (rostranspiler.py). Its values become shell lines, XML and device commands, so what parse() accepts has to be
safe to write into any of them, and what it refuses has to be refused with a DslError and nothing else. test_routers.Language pins single inputs;
these draw statements from the schema itself, so a new path or attribute is covered the day it is added."""
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from props import HAVE, given, scaled, settings, st
from storageforge_index import rostranspiler as r

# what a value must never hold once parse() has accepted it: each is a word break, a quote or a command to some target's shell
UNSAFE = re.compile(r'[\x00-\x1f\x7f$`;&|<>\\\'"(){}\[\]]')

ipv4 = st.ip_addresses(v=4).map(str)
ipv6 = st.ip_addresses(v=6).map(str)
ip = ipv4 | ipv6


def _network(addr_prefix):
    addr, prefix = addr_prefix
    return str(ipaddress.ip_network(f'{addr}/{prefix}', strict=False))


net4 = st.tuples(ipv4, st.integers(0, 32)).map(_network)
net6 = st.tuples(ipv6, st.integers(0, 128)).map(_network)
network = net4 | net6
name = st.from_regex(r'\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,20}\Z')
port = st.integers(1, 65535)
port_part = port.map(str) | st.tuples(port, port).map(lambda p: f'{min(p)}-{max(p)}')
ports = st.lists(port_part, min_size=1, max_size=4).map(','.join)
vlan = st.integers(1, 4094)
comment = st.text(st.characters(codec='utf-8', exclude_characters='"\'`$\\<>;&|[]{}\x7f\x85', exclude_categories=('Cc', 'Cs', 'Zl', 'Zp', 'Cf')), max_size=40)
wgkey = st.binary(min_size=32, max_size=32).map(lambda b: __import__('base64').b64encode(b).decode())
mac = st.lists(st.integers(0, 255), min_size=6, max_size=6).map(lambda b: ':'.join(f'{x:02x}' for x in b))


def maybe_not(s):
    return st.tuples(st.booleans(), s).map(lambda t: ('!' if t[0] else '') + t[1])


def _options_of(check):
    """The choices an _oneof() check takes, read from its closure."""
    if check.__code__ is r._oneof('x').__code__:
        return check.__closure__[0].cell_contents
    return None


STRATEGIES = {
    r._name: maybe_not(name),
    r._names: st.lists(name, min_size=1, max_size=3).map(','.join),
    r._cidr: maybe_not(network | st.tuples(ipv4, ipv4).map('-'.join)),
    r._cidrs: st.lists(network, min_size=1, max_size=3).map(','.join),
    r._prefix: network,
    r._entry: network | st.tuples(ipv4, ipv4).map('-'.join),
    r._ip_ok: ip,
    r._ips: st.lists(ip, min_size=1, max_size=3).map(','.join),
    r._iface_addr: st.tuples(ipv4, st.integers(0, 32)).map(lambda t: f'{t[0]}/{t[1]}') | st.tuples(ipv6, st.integers(0, 128)).map(lambda t: f'{t[0]}/{t[1]}'),
    r._ports: maybe_not(ports),
    r._int: st.integers(0, 999_999_999).map(str),
    r._yesno: st.sampled_from(['yes', 'no', 'true', 'false']),
    r._comment: comment,
    r._mac: mac,
    r._proto: st.sampled_from(sorted(r.PROTOS)) | st.integers(0, 255).map(str),
    r._state: st.sets(st.sampled_from(sorted(r.STATES)), min_size=1).map(lambda s: ','.join(sorted(s))),
    r._vlans: st.lists(vlan.map(str) | st.tuples(vlan, vlan).map(lambda v: f'{min(v)}-{max(v)}'), min_size=1, max_size=3).map(','.join),
    r._range: st.lists(ipv4 | st.tuples(ipv4, ipv4).map('-'.join), min_size=1, max_size=3).map(','.join),
    r._endpoint: st.tuples(ipv4 | name.filter(lambda n: re.fullmatch(r'[A-Za-z0-9.:-]+', n)), port).map(lambda t: f'{t[0]}:{t[1]}'),
    r._wgkey: wgkey,
    r._pos: st.integers(0, 50).map(str) | st.from_regex(r'\A(?:\*[0-9a-f]{1,4}|[A-Za-z0-9][A-Za-z0-9._:-]{0,15})\Z'),
}


def value_for(check):
    options = _options_of(check)
    if options:
        return st.sampled_from(options)
    return STRATEGIES[check]


@st.composite
def statement(draw, paths=None):
    """One statement the schema allows, as the attributes a person would write."""
    path = draw(st.sampled_from(paths or sorted(r.SCHEMA)))
    verb, schema, required = r.SCHEMA[path]
    optional = sorted(set(schema) - set(required))
    keys = list(required) + draw(st.lists(st.sampled_from(optional), unique=True, max_size=4)) if optional else list(required)
    attrs = {k: draw(value_for(schema[k])) for k in keys}
    if path == r.FILTER and attrs.get('action') == 'jump':
        attrs.setdefault('jump-target', draw(name))
    if path == r.NAT and attrs.get('action') == 'dst-nat':
        attrs.setdefault('to-addresses', draw(ip))
    return r.Stmt(path, verb, attrs)


def as_text(stmts):
    return ''.join(s.text(redact=False) + '\n' for s in stmts)


programs = st.lists(statement(), min_size=1, max_size=8)
firewall_programs = st.lists(statement([r.FILTER, r.NAT, r.ALIST]), min_size=1, max_size=8)


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class WhatItAccepts(unittest.TestCase):
    @given(programs)
    def test_a_statement_the_schema_allows_reads_back_as_written(self, stmts):
        back = r.parse(as_text(stmts))
        self.assertEqual([(s.path, s.verb, s.attrs) for s in back], [(s.path, s.verb, s.attrs) for s in stmts])

    @given(programs)
    def test_routeros_output_is_the_same_program(self, stmts):
        once = r.parse(as_text(stmts))
        again = r.parse(r.emit(once, 'routeros')['text'])
        self.assertEqual([s.attrs for s in again], [s.attrs for s in once])

    @given(programs)
    def test_no_accepted_value_holds_a_character_a_shell_reads(self, stmts):
        for s in r.parse(as_text(stmts)):
            for k, v in s.attrs.items():
                if k in ('comment', 'log-prefix'):
                    self.assertFalse(re.search(r'[\x00-\x1f\x7f$`;&|<>\\\'"\[\]{}]', v), (k, v))
                else:
                    self.assertFalse(UNSAFE.search(v) or re.search(r'\s', v), (k, v))

    @given(programs, st.sampled_from(r.TARGETS))
    def test_every_target_takes_every_statement_or_says_why_not(self, stmts, target):
        out = r.emit(r.parse(as_text(stmts)), target)
        self.assertEqual(set(out) >= {'target', 'text', 'files', 'unsupported', 'notes'}, True)
        for u in out['unsupported']:
            self.assertTrue(u['why'], u)
        for k, v in r.emit(r.parse(as_text(stmts)), target).items():
            self.assertEqual(out[k], v, f'{target} gave a different {k} for the same input')

    @given(st.lists(statement([('interface', 'wireguard')]), min_size=1, max_size=3), st.sampled_from(r.TARGETS))
    def test_a_private_key_shows_only_where_the_target_needs_it(self, stmts, target):
        stmts = r.parse(as_text(stmts))
        for s in stmts:
            self.assertNotIn(s.get('private-key') or '\0', s.text())
        out = r.emit(stmts, target)
        for u in out['unsupported']:
            for s in stmts:
                if s.get('private-key'):
                    self.assertNotIn(s['private-key'], u['statement'])

    @given(firewall_programs)
    def test_what_is_read_back_from_a_model_is_the_language_again(self, stmts):
        """from_model() renders any firewall reading in the language. What it renders from rules the language wrote has to parse."""
        stmts = r.parse(as_text(stmts))
        model = r.to_model_rules(stmts)
        text = r.from_model(None, {'rules': model['rules'], 'nat': model['nat']})
        r.parse('\n'.join(line for line in text.splitlines() if '# also:' not in line))


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class WhatItRefuses(unittest.TestCase):
    @given(st.text(max_size=300))
    def test_any_text_is_read_or_refused_with_a_dsl_error(self, text):
        try:
            r.parse(text)
        except r.DslError:
            pass

    @given(st.sampled_from(sorted(r.SCHEMA)), st.dictionaries(st.from_regex(r'\A[a-z][a-z-]{0,15}\Z'), st.text(max_size=30), max_size=5))
    def test_any_attributes_on_a_real_path_are_read_or_refused(self, path, attrs):
        verb = r.SCHEMA[path][0]
        line = f'/{" ".join(path)} {verb} ' + ' '.join(f'{k}="{v}"' if ' ' in v else f'{k}={v}' for k, v in attrs.items())
        try:
            stmts = r.parse(line)
        except r.DslError:
            return
        for s in stmts:
            for k, v in s.attrs.items():
                if k not in ('comment', 'log-prefix'):
                    self.assertFalse(UNSAFE.search(v), (k, v))

    @given(statement([r.FILTER]), st.sampled_from(['src-address', 'dst-address', 'in-interface', 'dst-port', 'chain', 'comment']),
           st.sampled_from(['$(id)', '`id`', 'a;id', 'a|id', 'a&&id', "a'b", 'a"b', 'a\\', '{a}', '[a]', 'a\u202eb', 'a\u200bb', 'a\nb', 'a>b']))
    def test_a_hostile_value_in_any_attribute_is_refused(self, stmt, key, bad):
        text = stmt.text(redact=False).replace('\n', ' ')
        line = text + f' {key}="{bad}"' if '"' not in bad else text + f' {key}={bad}'
        with self.assertRaises(r.DslError):
            r.parse(line)


BASH = shutil.which('bash')
SHELL_TARGETS = ('firewalld', 'ufw', 'openwrt', 'networkmanager')
STUBS = '\n'.join(f'{cmd}() {{ printf "%s\\0" {cmd} "$@" >> "$ARGV"; printf "%s\\0" --- >> "$ARGV"; echo cfg0; }}' for cmd in ('firewall-cmd', 'ufw', 'uci', 'nmcli'))


@unittest.skipUnless(HAVE and shutil.which('bash'), 'needs hypothesis and bash')
class ShellTargets(unittest.TestCase):
    """The four targets that are shell: run with each command replaced by one that writes down its arguments, and nothing else on PATH."""

    def run_script(self, text):
        with tempfile.TemporaryDirectory() as d:
            argv = os.path.join(d, 'argv')
            open(argv, 'w').close()
            script = os.path.join(d, 's.sh')
            with open(script, 'w') as f:
                f.write('set -u\n' + STUBS + '\ngrep() { return 0; }\nsed() { :; }\n' + text)
            p = subprocess.run([BASH, script], capture_output=True, text=True, timeout=20, env={'ARGV': argv, 'PATH': '/nonexistent'})
            calls = Path(argv).read_text(encoding='utf-8', errors='replace').split('\0---\0')
            return p, [c.split('\0') for c in calls if c]

    @settings(max_examples=scaled(15, 300))
    @given(firewall_programs, st.sampled_from(SHELL_TARGETS))
    def test_the_script_parses_and_runs_only_its_own_commands(self, stmts, target):
        out = r.emit(r.parse(as_text(stmts)), target)
        p, _ = self.run_script(out['text'])
        self.assertNotIn('command not found', p.stderr, out['text'])
        self.assertNotIn('syntax error', p.stderr, out['text'])

    @settings(max_examples=scaled(15, 300))
    @given(statement([r.FILTER]), comment.filter(lambda c: c.strip()))
    def test_a_comment_arrives_as_one_argument(self, stmt, text):
        stmt.attrs.update({'chain': 'input', 'action': 'accept', 'protocol': 'tcp', 'dst-port': '22', 'comment': text})
        for k in ('src-port', 'jump-target', 'connection-state', 'src-address-list', 'dst-address-list', 'log-prefix', 'place-before'):
            stmt.attrs.pop(k, None)
        stmts = r.parse(as_text([stmt]))
        out = r.emit(stmts, 'ufw')
        p, calls = self.run_script(out['text'])
        self.assertEqual(p.returncode, 0, p.stderr)
        args = [c for c in calls if c and c[0] == 'ufw']
        if args:
            self.assertIn(text, args[0], out['text'])


if __name__ == '__main__':
    unittest.main()
