"""SSH wire strings and key fingerprints, in one place.

Standard library only, on purpose: the pure format modules (sshca) and the agent receiver's side of the package may import it without
pulling in the vault, the database or ssh. Signature checking is not here: agenttunnel.verify_batch keeps its own strict refusals and
scansign.signer_key its own lax reading, because each is a boundary of its own.
"""
from __future__ import annotations

import base64
import hashlib
import struct


def put(b: bytes) -> bytes:
    """A length-prefixed SSH string (RFC 4251 section 5)."""
    return struct.pack('>I', len(b)) + b


def fingerprint_of_blob(blob: bytes) -> str:
    """OpenSSH's SHA256:... fingerprint of a public key blob, as ssh-keygen -l shows it. Fingerprints are stored and compared as text,
    so this form must not change by one character."""
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def fingerprint_of_line(public_line: str) -> str:
    """The fingerprint of an OpenSSH public key line ('type base64 [comment]'). Worked out here, never taken from a host. Decodes leniently
    and raises (IndexError, binascii.Error) on a line that is not one: callers use the result as a string."""
    return fingerprint_of_blob(base64.b64decode(public_line.split()[1]))
