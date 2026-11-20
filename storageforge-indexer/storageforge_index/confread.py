"""A configuration file without its credentials (roadmap section 2, rule 3): what Nebula, Teleport, Boundary and Pomerium keep in the
same file as their routes, and what must never leave the host.

`tunnels.SECRET_LINE` drops a line. That is enough for a tunnel's token, which sits on one line, and not for these files: a key can
be written under its name as a block (`key: |` and the PEM below it), a header that carries a password is a line under
`set_request_headers:`, and a list of secrets is one item to a line. So the scrubber here drops a line that names a credential and
with it everything that belongs to it: the lines indented deeper, the list items at its own depth, a quoted value that runs on, and
any PEM block wherever it stands.

The same rule is written twice: `SCRUB_AWK` runs on the host, before anything is sent, and `scrub()` runs on the server on what
arrives, so a file read by an older collector is cut by the newer rule. A test runs both on the same files and wants the same text.
"""
from __future__ import annotations

import re

from . import tunnels

# Wider than a tunnel's: these files name keys, cookies, headers, connection strings and accounts, and write passwords into URLs
# (`postgresql://user:password@host`). Written as an extended regular expression awk takes, matched against the line in lower case,
# with no quote and no backslash in it so that it can stand in a script.
SECRET_LINE = tunnels.SECRET_LINE[:-1] + '|key|psk|cookie|header|authoriz|bearer|connection|account|license|seed|recovery|://[^/ ]*:[^/ @]*@)'
_SECRET = re.compile(SECRET_LINE)

# One line of awk. `skip` is the depth of the credential line whose block is being dropped, `dash` whether that line was a list
# item, `quote` an open double-quoted value, `pem` a PEM block.
SCRUB_AWK = ('BEGIN { skip = -1 } { n = match($0, /[^ \\t]/); if (!n) next; '
             'if (pem) { if ($0 ~ /-----END/) pem = 0; next } '
             'if (quote) { if ($0 ~ /"/) quote = 0; next } '
             'if (skip >= 0 && (n > skip || (n == skip && !dash && substr($0, n, 1) == "-"))) next; skip = -1; '
             'if ($0 ~ /-----BEGIN/) { pem = ($0 !~ /-----END/); next } '
             'if (tolower($0) ~ re) { skip = n; dash = (substr($0, n, 1) == "-"); t = $0; quote = (gsub(/"/, "", t) % 2); next } print }')


def scrub(text: str) -> str:
    """What `SCRUB_AWK` leaves, line for line."""
    out, skip, dash, quote, pem = [], -1, False, False, False
    for line in text.splitlines():
        m = re.search(r'[^ \t]', line)
        if not m:
            continue
        n = m.start() + 1
        if pem:
            pem = '-----END' not in line
            continue
        if quote:
            quote = '"' not in line
            continue
        if skip >= 0 and (n > skip or (n == skip and not dash and line[n - 1] == '-')):
            continue
        skip = -1
        if '-----BEGIN' in line:
            pem = '-----END' not in line
            continue
        if _SECRET.search(line.lower()):
            skip, dash, quote = n, line[n - 1] == '-', line.count('"') % 2 == 1
            continue
        out.append(line)
    return '\n'.join(out)
