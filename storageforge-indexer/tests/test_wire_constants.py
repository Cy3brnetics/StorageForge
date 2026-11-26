"""Protocol constants written once in Python and once in Rust, read from both sources and compared (roadmap 0.7.0, BE-26).

Each side keeps its own constant: the controller's Python and the agent, wire and enclave crates are built and shipped apart. This test
reads each Rust `const` from its source file with a regular expression, works out its value (a string or byte string literal, an
integer with `<<`, an array of strings) and compares it with the Python one. It needs no cargo, so it runs in the light block. A Rust
constant that was renamed, moved or given a form this reader does not know fails the test: it is never skipped.

Some lists look alike and are not pairs: hostlogs.FIELDS and agent/src/journal.rs FIELDS differ on purpose (the agent also reads
_TRANSPORT), so they are not compared here."""
import ast
import re
import unittest
from pathlib import Path
from unittest import mock

from storageforge_index import agentreceiver, agenttunnel, enclave, enclave_vm, remote, sfagent

ROOT = Path(__file__).resolve().parents[1]

# (Python module, Python name, Rust file under storageforge-indexer, Rust const name, compare as a set)
PAIRS = [
    # the frame every Rust and Python reader shares
    (agenttunnel, 'MAX_FRAME', 'wire/src/lib.rs', 'MAX_FRAME', False),
    (enclave, 'MAX_FRAME', 'wire/src/lib.rs', 'MAX_FRAME', False),
    # the agent's tunnel
    (agenttunnel, 'PROTOCOL_NAME', 'wire/src/noise.rs', 'PROTOCOL_NAME', False),
    (agenttunnel, 'TAG', 'wire/src/noise.rs', 'TAG', False),
    (agenttunnel, 'MAX_HANDSHAKE_PAYLOAD', 'wire/src/noise.rs', 'MAX_HANDSHAKE_PAYLOAD', False),
    (agenttunnel, 'PROLOGUE', 'agent/src/tunnel.rs', 'PROLOGUE', False),
    (agenttunnel, 'CHUNK', 'agent/src/tunnel.rs', 'CHUNK', False),
    # the agent's batches
    (agentreceiver, 'MAX_BATCH', 'agent/src/tunnel.rs', 'MAX_BATCH', False),
    (agentreceiver, 'MAX_RECORDS', 'agent/src/tunnel.rs', 'MAX_RECORDS', False),
    (agenttunnel, 'NS_BATCH', 'agent/src/sig.rs', 'NS_BATCH', False),
    # storageforge-agentctl
    (sfagent, 'OPS', 'agent/src/request.rs', 'OPS', False),
    (sfagent, 'REFUSED', 'agent/src/request.rs', 'REFUSED', False),
    (sfagent, 'NS_REQUEST', 'agent/src/sig.rs', 'NS_AGENTCTL', False),
    (sfagent, 'NS_MANIFEST', 'agent/src/sig.rs', 'NS_MANIFEST', False),
    (sfagent, 'AGENT_USER', 'agent/src/host.rs', 'AGENT_USER', False),
    (sfagent, 'ROOT_GROUPS', 'agent/src/host.rs', 'ROOT_GROUPS', True),   # a set on both sides; the Rust array is sorted
    # the enclave
    (enclave, 'NOISE_NAME', 'enclave/src/main.rs', 'NOISE_NAME', False),
    (enclave, 'NOISE_PROLOGUE', 'enclave/src/main.rs', 'NOISE_PROLOGUE', False),
    (enclave_vm, 'PORT', 'enclave/src/main.rs', 'VSOCK_PORT', False),
]

_INT = re.compile(r'\d[\d_]*')


def _value(expr: str, where: str):
    """The value of a Rust constant expression of the forms the pairs use; anything else is an error, never a guess."""
    expr = expr.strip()
    if re.fullmatch(r'b"(?:[^"\\]|\\.)*"', expr):
        return ast.literal_eval(expr)
    if re.fullmatch(r'"(?:[^"\\]|\\.)*"', expr):
        return ast.literal_eval(expr)
    if expr.startswith('[') and expr.endswith(']'):
        items = [i.strip() for i in expr[1:-1].split(',') if i.strip()]
        return tuple(_value(i, where) for i in items)
    m = re.fullmatch(r'(\d[\d_]*)(?:\s*<<\s*(\d[\d_]*))?', expr)
    if m:
        n = int(m[1].replace('_', ''))
        return n << int(m[2].replace('_', '')) if m[2] else n
    raise AssertionError(f'{where}: the value {expr!r} is not a form this test reads; teach _value it')


def rust_const(path: str, name: str):
    """The value of `const NAME: TYPE = VALUE;` (pub or not) at the top level of a Rust file. Missing or twice is an error."""
    src = (ROOT / path).read_text()
    found = re.findall(rf'^(?:pub(?:\([^)]*\))?\s+)?const\s+{re.escape(name)}\s*:[^=]+=\s*(.+?);\s*(?://.*)?$', src, re.M)
    where = f'{path} const {name}'
    if len(found) != 1:
        raise AssertionError(f'{where}: found {len(found)} times, not once; was it renamed or moved? Update PAIRS in this test')
    return _value(found[0], where)


class RustReader(unittest.TestCase):
    def test_it_reads_the_forms_the_pairs_use(self):
        self.assertEqual(_value('b"ab\\x00"', 'x'), b'ab\0')
        self.assertEqual(_value('"x"', 'x'), 'x')
        self.assertEqual(_value('512 << 10', 'x'), 512 << 10)
        self.assertEqual(_value('4_096', 'x'), 4096)
        self.assertEqual(_value('["a", "b"]', 'x'), ('a', 'b'))

    def test_a_form_it_does_not_know_fails_rather_than_skips(self):
        with self.assertRaises(AssertionError):
            _value('MAX_FRAME + TAG', 'x')

    def test_a_missing_constant_fails_rather_than_skips(self):
        with self.assertRaises(AssertionError):
            rust_const('wire/src/lib.rs', 'NO_SUCH_CONSTANT')


class SameOnBothSides(unittest.TestCase):
    def test_each_python_constant_equals_its_rust_one(self):
        for module, py, path, rs, as_set in PAIRS:
            with self.subTest(f'{module.__name__.rsplit(".", 1)[-1]}.{py} = {path} {rs}'):
                ours, theirs = getattr(module, py), rust_const(path, rs)
                if isinstance(ours, list):
                    ours = tuple(ours)
                if as_set:
                    ours, theirs = sorted(ours), sorted(theirs)
                self.assertEqual(ours, theirs)

    def test_an_agentctl_request_starts_with_the_magic_line_the_agent_reads(self):
        magic = rust_const('agent/src/request.rs', 'MAGIC')
        with mock.patch.object(sfagent.deploy, 'sshsig', return_value='sig'):
            out = sfagent.request(object(), 'status', '0' * 32, now=1, nonce='a' * 32)
        self.assertTrue(out.startswith(magic.encode() + b'\n'), out[:40])

    def test_the_agent_scan_writes_only_sections_the_ssh_scan_parser_knows(self):
        script = (ROOT / 'agent/scan/inventory.scan').read_text()
        names = re.findall(r'^section\s+(\w+)\s*$', script, re.M)
        self.assertTrue(names, 'agent/scan/inventory.scan names no section')
        self.assertEqual(sorted(set(names) - remote.SECTIONS), [], 'remote.py INVENTORY_SCRIPT does not write these sections')


if __name__ == '__main__':
    unittest.main()
