"""Minimal pure-Python ISO/IEC 18004 QR Code SVG generator (Byte mode, EC Level L, versions 1..10).

Used by the WireGuard Toolbox peer manager to render scannable peer configuration QR codes as inline SVG without external dependencies.
"""
from __future__ import annotations

# Version capacities (total data codewords for EC Level L) and EC codewords per block (1 block for V1..V5, 2 blocks for V6..V9, 4 for V10)
_VERSIONS = {
    1: (19, 7, 1),
    2: (34, 10, 1),
    3: (55, 15, 1),
    4: (80, 20, 1),
    5: (108, 26, 1),
    6: (136, 18, 2),
    7: (156, 20, 2),
    8: (194, 24, 2),
    9: (232, 30, 2),
    10: (274, 18, 4),
}

_ALIGN = {
    1: (), 2: (6, 18), 3: (6, 22), 4: (6, 26), 5: (6, 30),
    6: (6, 34), 7: (6, 22, 38), 8: (6, 24, 42), 9: (6, 26, 46), 10: (6, 28, 50),
}

# GF(256) with primitive polynomial 0x11d
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    return 0 if (a == 0 or b == 0) else _EXP[_LOG[a] + _LOG[b]]


def _rs_gen(degree: int) -> list[int]:
    g = [1]
    for i in range(degree):
        nxt = [0] * (len(g) + 1)
        root = _EXP[i]
        for j, v in enumerate(g):
            nxt[j] ^= v
            nxt[j + 1] ^= _gf_mul(v, root)
        g = nxt
    return g


def _rs_rem(data: list[int], degree: int) -> list[int]:
    gen = _rs_gen(degree)
    rem = [0] * degree
    for b in data:
        factor = b ^ rem[0]
        rem = rem[1:] + [0]
        if factor:
            for i in range(degree):
                rem[i] ^= _gf_mul(gen[i + 1], factor)
    return rem


def _encode_codewords(payload: bytes) -> tuple[int, list[int]]:
    n = len(payload)
    ver = next((v for v, (cap, _, _) in _VERSIONS.items() if n + (2 if v < 10 else 3) <= cap), None)
    if ver is None:
        payload = payload[:270]
        n = len(payload)
        ver = 10
    cap, ec_len, blocks = _VERSIONS[ver]
    bits: list[int] = [0, 1, 0, 0]  # Byte mode (0100)
    cc_bits = 8 if ver < 10 else 16
    for i in range(cc_bits - 1, -1, -1):
        bits.append((n >> i) & 1)
    for b in payload:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    for _ in range(min(4, cap * 8 - len(bits))):
        bits.append(0)
    while len(bits) % 8:
        bits.append(0)
    data = [sum(bits[i + j] << (7 - j) for j in range(8)) for i in range(0, len(bits), 8)]
    pads = (0xEC, 0x11)
    idx = 0
    while len(data) < cap:
        data.append(pads[idx % 2])
        idx += 1
    block_size = cap // blocks
    extra = cap % blocks
    d_blocks, ec_blocks, pos = [], [], 0
    for b in range(blocks):
        sz = block_size + (1 if b >= blocks - extra else 0)
        chunk = data[pos:pos + sz]
        pos += sz
        d_blocks.append(chunk)
        ec_blocks.append(_rs_rem(chunk, ec_len))
    out = []
    max_d = max(len(b) for b in d_blocks)
    for i in range(max_d):
        for b in d_blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ec_len):
        for b in ec_blocks:
            out.append(b[i])
    return ver, out


def _format_bits(mask: int) -> int:
    # EC Level L is 01, format polynomial 0x537, mask 0x5412
    data = (1 << 3) | mask
    rem = data << 10
    for i in range(4, -1, -1):
        if rem & (1 << (i + 10)):
            rem ^= 0x537 << i
    return ((data << 10) | rem) ^ 0x5412


def _version_bits(ver: int) -> int:
    rem = ver << 12
    for i in range(5, -1, -1):
        if rem & (1 << (i + 12)):
            rem ^= 0x1F25 << i
    return (ver << 12) | rem


def _build_matrix(ver: int, codewords: list[int], mask: int = 0) -> list[list[int]]:
    size = 17 + 4 * ver
    grid: list[list[int | None]] = [[None] * size for _ in range(size)]
    reserved = [[False] * size for _ in range(size)]

    def set_mod(r: int, c: int, val: int, res: bool = True):
        if 0 <= r < size and 0 <= c < size:
            grid[r][c] = int(bool(val))
            if res:
                reserved[r][c] = True

    def finder(r0: int, c0: int):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                if 0 <= dr <= 6 and 0 <= dc <= 6:
                    v = dr in (0, 6) or dc in (0, 6) or (2 <= dr <= 4 and 2 <= dc <= 4)
                    set_mod(r0 + dr, c0 + dc, int(v))
                else:
                    set_mod(r0 + dr, c0 + dc, 0)

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)

    for i in range(8, size - 8):
        set_mod(6, i, (i + 1) % 2)
        set_mod(i, 6, (i + 1) % 2)

    pts = _ALIGN[ver]
    for r in pts:
        for c in pts:
            if (r < 9 and c < 9) or (r < 9 and c > size - 10) or (r > size - 10 and c < 9):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    set_mod(r + dr, c + dc, int(max(abs(dr), abs(dc)) != 1))

    set_mod(size - 8, 8, 1)
    for i in range(9):
        if i != 6:
            reserved[8][i] = True
            reserved[i][8] = True
    for i in range(8):
        reserved[8][size - 1 - i] = True
        reserved[size - 1 - i][8] = True
    if ver >= 7:
        vbits = _version_bits(ver)
        for i in range(18):
            bit = (vbits >> i) & 1
            r, c = i // 3, size - 11 + (i % 3)
            set_mod(r, c, bit)
            set_mod(c, r, bit)

    bits = [(b >> i) & 1 for b in codewords for i in range(7, -1, -1)]
    bi = 0
    up = True
    col = size - 1
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if up else range(size)
        for r in rows:
            for dc in (0, -1):
                c = col + dc
                if not reserved[r][c]:
                    bit = bits[bi] if bi < len(bits) else 0
                    bi += 1
                    m = ((r + c) % 2 == 0) if mask == 0 else (r % 2 == 0) if mask == 1 else (c % 3 == 0)
                    grid[r][c] = bit ^ int(m)
        up = not up
        col -= 2

    fbits = _format_bits(mask)
    for i in range(6):
        set_mod(8, i, (fbits >> (14 - i)) & 1)
    set_mod(8, 7, (fbits >> 8) & 1)
    set_mod(8, 8, (fbits >> 7) & 1)
    set_mod(7, 8, (fbits >> 6) & 1)
    for i in range(6):
        set_mod(5 - i, 8, (fbits >> (5 - i)) & 1)
    for i in range(7):
        set_mod(size - 1 - i, 8, (fbits >> (14 - i)) & 1)
    for i in range(8):
        set_mod(8, size - 8 + i, (fbits >> (7 - i)) & 1)

    return [[int(cell or 0) for cell in row] for row in grid]


def svg(text: str, border: int = 2) -> str:
    """Renders text as a self-contained QR Code SVG string."""
    ver, codewords = _encode_codewords((text or '').encode('utf-8'))
    matrix = _build_matrix(ver, codewords, mask=0)
    size = len(matrix)
    dim = size + 2 * border
    rects = []
    for r, row in enumerate(matrix):
        c = 0
        while c < size:
            if row[c]:
                start = c
                while c < size and row[c]:
                    c += 1
                rects.append(f'<rect x="{start + border}" y="{r + border}" width="{c - start}" height="1"/>')
            else:
                c += 1
    body = ''.join(rects)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" width="160" height="160" '
            f'shape-rendering="crispEdges" role="img" aria-label="WireGuard peer QR code">'
            f'<rect width="{dim}" height="{dim}" fill="#ffffff"/><g fill="#000000">{body}</g></svg>')
