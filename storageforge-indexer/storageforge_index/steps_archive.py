"""Plan steps for maximum lossless file and folder archiving and safe archive extraction.

Supports ultra-ratio lossless compression profiles:
  - zstd-ultra: tar + zstd --ultra -22 --long=27 -T0 (.tar.zst) for high deduplicating compression and fast restore
  - xz-extreme: tar + xz -9 -e -T0 (.tar.xz) for maximum LZMA2 dictionary compression
  - 7z-ultra:   7z -t7z -m0=lzma2 -mx=9 -mfb=273 -md=64m -ms=on (.7z) solid LZMA2 archive
  - zstd-high:  tar + zstd -19 -T0 (.tar.zst) for high lossless compression with low memory overhead

When compress_host is set to another host, raw tar streams under idle CPU/IO priority over SSH to that remote
compression host, which runs the heavy lossless compression and full round-trip decompression check in a zero-disk
FIFO stream and sends verified archive bytes back, sparing weak or busy storage hosts from CPU and RAM load.
"""
from __future__ import annotations

import posixpath
import shlex

from . import changes
from .changes import F
from .db import Conn
from .fsmap import SYSTEM_DIRS
from .moves import find_host, hosts, mount_of
from .scriptkit import package_check

CODECS = ['zstd-ultra', 'xz-extreme', '7z-ultra', 'zstd-high']
CODEC_EXT = {
    'zstd-ultra': '.tar.zst',
    'zstd-high': '.tar.zst',
    'xz-extreme': '.tar.xz',
    '7z-ultra': '.7z',
}
CODEC_TOOL = {
    'zstd-ultra': 'zstd',
    'zstd-high': 'zstd',
    'xz-extreme': 'xz',
    '7z-ultra': '7z',
}
ARCHIVE_SUFFIXES = ('.tar.zst', '.tzst', '.tar.xz', '.txz', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.7z')
OS_PROTECTED = set(SYSTEM_DIRS) | {'/', '/boot/efi', '/boot/firmware', '/efi'}


def archive_ext(codec: str) -> str:
    return CODEC_EXT.get(codec or 'zstd-ultra', '.tar.zst')


def default_archive_path(src: str, codec: str = 'zstd-ultra') -> str:
    clean = posixpath.normpath(src or '/archive')
    if clean == '/':
        return '/root-archive' + archive_ext(codec)
    return clean + archive_ext(codec)


def _resolve_worker(conn: Conn, task: dict) -> tuple[dict | None, str, int]:
    raw = str((task.get('params') or {}).get('compress_host') or '').strip()
    if not raw:
        return None, '', 22
    hs = hosts(conn)
    th = find_host(hs, task.get('host') or '')
    wh = find_host(hs, raw)
    if wh and th and wh['id'] == th['id']:
        return None, '', 22
    if wh:
        return wh, f'{wh["ssh_user"] or "root"}@{wh["ssh_host"]}', int(wh['ssh_port'] or 22)
    if raw.lower() == str(task.get('host') or '').strip().lower():
        return None, '', 22
    return None, f'root@{raw}', 22


def _args_archive(conn: Conn, task: dict) -> list[str]:
    _, login, port = _resolve_worker(conn, task)
    return [login, str(port) if login else '']


# Uses need, act, try, later, ok, conflict, info, human and t_trash from changes.py. Avoid apostrophes in bash text.
BASH = r"""
# ── lossless ultra-compression archive and safe extraction ─────────────
sf_idle() {
  if command -v ionice >/dev/null 2>&1 && ionice -c3 true 2>/dev/null; then
    ionice -c3 nice -n 19 "$@"
  elif command -v nice >/dev/null 2>&1; then
    nice -n 19 "$@"
  else
    "$@"
  fi
}

sf_tar_create_flags() {
  TAR_CREATE_FLAGS=(--numeric-owner --sparse)
  if tar --version 2>/dev/null | grep -qi "gnu tar"; then
    TAR_CREATE_FLAGS+=(--acls --xattrs)
  fi
}

sf_zstd_compress() { # codec -> compresses stdin to stdout
  local codec=$1
  if [[ $codec == zstd-ultra ]]; then
    sf_idle zstd -q -T0 --ultra -22 --long=27 -c
  else
    sf_idle zstd -q -T0 -19 -c
  fi
}

sf_zstd_decompress() { # file -> decompresses to stdout
  sf_idle zstd -dc --long=31 -- "$1"
}

sf_7z_bin() {
  local c
  for c in 7z 7zz 7za; do
    command -v "$c" >/dev/null 2>&1 && { printf "%s" "$c"; return 0; }
  done
  return 1
}

sf_remote_compress_cmd() { # codec -> self-contained bash snippet: stdin raw tar -> stdout verified archive
  local codec=$1 comp ver
  if [[ $codec == xz-extreme ]]; then
    comp="xz -9 -e -T0 -c"
    ver="xz -dc <\"\$d/v\" | tar -tf - >/dev/null"
  elif [[ $codec == zstd-high ]]; then
    comp="zstd -q -T0 -19 -c"
    ver="( zstd -dc --long=31 <\"\$d/v\" ) | tar -tf - >/dev/null"
  else
    comp="( zstd -q -T0 --ultra -22 --long=27 -c )"
    ver="( zstd -dc --long=31 <\"\$d/v\" ) | tar -tf - >/dev/null"
  fi
  printf "%s" "set -o pipefail; d=\$(mktemp -d) || exit 2; mkfifo \"\$d/v\" || { rm -rf \"\$d\"; exit 2; }; ( $ver ) & vp=\$!; nice -n 19 sh -c \"$comp\" | tee \"\$d/v\"; rc=\$?; wait \"\$vp\" || rc=9; rm -rf \"\$d\"; exit \"\$rc\""
}

sf_verify_archive_file() { # file [codec]
  local f=$1 codec=${2:-} seven
  case "$codec:$f" in
    7z-ultra:*|*:*.7z)
      seven=$(sf_7z_bin) || { conflict "7z is not installed to verify $f"; return 1; }
      sf_idle "$seven" t -bd -- "$f" >/dev/null || return 1 ;;
    xz-extreme:*|*:*.tar.xz|*:*.txz)
      ( set -o pipefail; sf_idle xz -dc -- "$f" | tar -tf - >/dev/null ) || return 1 ;;
    zstd-*:*|*:*.tar.zst|*:*.tzst)
      ( set -o pipefail; sf_zstd_decompress "$f" | tar -tf - >/dev/null ) || return 1 ;;
    *:*.tar.gz|*:*.tgz)
      ( set -o pipefail; sf_idle gzip -dc -- "$f" | tar -tf - >/dev/null ) || return 1 ;;
    *:*.tar.bz2|*:*.tbz2)
      ( set -o pipefail; sf_idle bzip2 -dc -- "$f" | tar -tf - >/dev/null ) || return 1 ;;
    *)
      conflict "unsupported archive extension on $f"; return 1 ;;
  esac
}

sf_check_tar_members() { # reads tar -tf lines on stdin -> 0 if every path is relative and stays inside dest
  awk "
    /^\// || /(^|\/)\.\.(\/|$)/ { bad = 1; exit 1 }
    END { exit bad ? 1 : 0 }
  "
}

t_archive() { local src=$1 dst=$2 codec=${3:-zstd-ultra} verify=${4:-1} trash=${5:-} comp_host_raw=${6:-} comp_login=${7:-} comp_port=${8:-22}
  src=$(realpath -m -s -- "$src" 2>/dev/null) || { conflict "cannot work out the path $1"; return 0; }    # //proc is /proc
  case $src in
    /|/proc|/sys|/dev|/run) conflict "refusing to archive virtual or root filesystem $src"; return 0 ;;
  esac
  if [[ -f $dst && ! -L $dst ]]; then
    if [[ $trash == 1 && ( -e $src || -L $src ) ]]; then
      conflict "$dst already exists; verify that it contains the current source before moving $src to trash"
      return 0
    fi
    ok "$dst already exists"
    return 0
  fi
  [[ -e $dst || -L $dst ]] && { conflict "$dst already exists and is not a regular file"; return 0; }
  [[ -e $src ]] || { later "$src must exist"; return 0; }
  [[ -L $src ]] && { conflict "$src is a symbolic link: archive its target instead"; return 0; }
  mountpoint -q -- "$src" && { conflict "$src is a mount point: archive a folder inside it or unmount first"; return 0; }
  local abs_src abs_dst_parent abs_dst parent base part before_bytes after_bytes saved sum seven tool rc=0
  abs_src=$(realpath -m -- "$src")
  abs_dst=$(realpath -m -- "$dst") || { conflict "cannot resolve $dst"; return 0; }
  if [[ $abs_dst == "$abs_src" || $abs_dst == "${abs_src%/}"/* ]]; then
    conflict "archive destination $dst cannot be the source itself or inside $src"
    return 0
  fi
  if [[ -n $comp_login ]]; then
    [[ $codec == 7z-ultra ]] && { conflict "7z-ultra writes a seekable solid archive and cannot stream to remote compressor $comp_login; use zstd-ultra, xz-extreme or zstd-high"; return 0; }
    need tar tar || return 0
    tool=zstd; [[ $codec == xz-extreme ]] && tool=xz
    if ! ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -p "${comp_port:-22}" "$comp_login" "command -v tar >/dev/null && command -v $tool >/dev/null" 2>/dev/null; then
      conflict "cannot reach remote compression host $comp_login over SSH or $tool/tar is not installed there"
      return 0
    fi
    act "stream $src -> $comp_login ($codec, CPU offloaded) -> $dst" || return 0
  else
    case $codec in
      zstd-ultra|zstd-high) need tar tar || return 0; need zstd zstd || return 0 ;;
      xz-extreme) need tar tar || return 0; need xz xz-utils || return 0 ;;
      7z-ultra)
        if ! seven=$(sf_7z_bin); then
          need 7z p7zip-full || return 0
          seven=7z
        fi ;;
      *) conflict "unknown compression profile: $codec"; return 0 ;;
    esac
    act "compress $src -> $dst ($codec, lossless)" || return 0
  fi
  try mkdir -p -- "$(dirname -- "$dst")" || return 0
  before_bytes=$(du -sxb -- "$src" 2>/dev/null | awk "{print \$1}" || stat -c %s -- "$src" 2>/dev/null || echo 0)
  parent=$(dirname -- "$abs_src")
  base=$(basename -- "$abs_src")
  part="$dst.sf-part.$$"
  rm -f -- "$part" "$part.sha"
  sf_tar_create_flags
  if [[ -n $comp_login ]]; then
    ( set -o pipefail
      sf_idle tar -C "$parent" "${TAR_CREATE_FLAGS[@]}" -cf - -- "$base" \
        | ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -p "${comp_port:-22}" "$comp_login" "$(sf_remote_compress_cmd "$codec")" \
        | tee "$part" | sha256sum | awk "{print \$1}" >"$part.sha" ) || rc=$?
    sum=$(cat "$part.sha" 2>/dev/null || true)
    rm -f -- "$part.sha"
  else
    case $codec in
      zstd-ultra|zstd-high)
        ( set -o pipefail; sf_idle tar -C "$parent" "${TAR_CREATE_FLAGS[@]}" -cf - -- "$base" | sf_zstd_compress "$codec" >"$part" ) || rc=$? ;;
      xz-extreme)
        ( set -o pipefail; sf_idle tar -C "$parent" "${TAR_CREATE_FLAGS[@]}" -cf - -- "$base" | sf_idle xz -9 -e -T0 -c >"$part" ) || rc=$? ;;
      7z-ultra)
        seven=$(sf_7z_bin)
        ( cd "$parent" && sf_idle "$seven" a -t7z -m0=lzma2 -mx=9 -mfb=273 -md=64m -ms=on -mmt=on -bd -- "$abs_dst.sf-part.$$" "$base" >/dev/null ) || rc=$? ;;
    esac
  fi
  if ((rc != 0)) || [[ ! -s $part ]]; then
    rm -f -- "$part"
    conflict "compression of $src into $dst failed (exit $rc)"
    return 0
  fi
  if [[ -z $comp_login && $verify == 1 ]]; then
    if ! sf_verify_archive_file "$part" "$codec"; then
      rm -f -- "$part"
      conflict "archive $dst failed lossless round-trip verification; removed partial file"
      return 0
    fi
  fi
  [[ -n ${sum:-} ]] || sum=$(sha256sum <"$part" | awk "{print \$1}")
  if [[ -z $sum ]] || ! ln -T -- "$part" "$dst"; then
    rm -f -- "$part"
    conflict "could not finalize $dst"
    return 0
  fi
  rm -f -- "$part"
  printf "%s  %s\n" "$sum" "$(basename -- "$dst")" >"$dst.sha256"
  chmod 0644 -- "$dst.sha256" 2>/dev/null || true
  after_bytes=$(stat -c %s -- "$dst" 2>/dev/null || echo 0)
  saved=$(( before_bytes > after_bytes ? before_bytes - after_bytes : 0 ))
  ok "archived $src -> $dst ($(human "$before_bytes") -> $(human "$after_bytes"), saved $(human "$saved"))"
  if [[ $trash == 1 ]]; then
    t_trash "$src"
  fi
}

t_archive_extract() { local archive=$1 dest=$2 verify_sum=${3:-1} dmode downer
  if [[ -f "$dest/.sf-extracted" ]] && [[ $(cat "$dest/.sf-extracted" 2>/dev/null || true) == "$archive" ]]; then
    ok "$archive already extracted into $dest"
    return 0
  fi
  [[ -f $archive && ! -L $archive ]] || { later "$archive must exist as a regular file"; return 0; }
  [[ -L $dest ]] && { conflict "$dest is a symbolic link"; return 0; }
  case $archive in
    *.tar.zst|*.tzst) need tar tar || return 0; need zstd zstd || return 0 ;;
    *.tar.xz|*.txz) need tar tar || return 0; need xz xz-utils || return 0 ;;
    *.tar.gz|*.tgz) need tar tar || return 0; need gzip gzip || return 0 ;;
    *.tar.bz2|*.tbz2) need tar tar || return 0; need bzip2 bzip2 || return 0 ;;
    *.7z) sf_7z_bin >/dev/null || { need 7z p7zip-full || return 0; } ;;
    *) conflict "unsupported archive format: $archive (expected .tar.zst, .tar.xz, .tar.gz, .tar.bz2 or .7z)"; return 0 ;;
  esac
  if [[ $verify_sum == 1 && -f "$archive.sha256" ]]; then
    local want got
    want=$(awk "{print \$1; exit}" "$archive.sha256")
    got=$(sha256sum <"$archive" | awk "{print \$1}")
    if [[ -n $want && $want != "$got" ]]; then
      conflict "checksum mismatch for $archive (expected $want, got $got)"
      return 0
    fi
  fi
  act "extract $archive -> $dest" || return 0
  local stage rc=0 seven
  try mkdir -p -- "$(dirname -- "$dest")" || return 0
  stage="$dest.sf-extract.$$"
  rm -rf -- "$stage"
  try mkdir -m 0700 -- "$stage" || return 0
  case $archive in
    *.tar.zst|*.tzst)
      if ! ( set -o pipefail; sf_zstd_decompress "$archive" | tar -tf - | sf_check_tar_members ); then
        rm -rf -- "$stage"; conflict "$archive contains unsafe member paths (leading / or ..)"; return 0
      fi
      ( set -o pipefail; sf_zstd_decompress "$archive" | tar -C "$stage" --no-same-permissions -xpf - ) || rc=$? ;;
    *.tar.xz|*.txz)
      if ! ( set -o pipefail; sf_idle xz -dc -- "$archive" | tar -tf - | sf_check_tar_members ); then
        rm -rf -- "$stage"; conflict "$archive contains unsafe member paths (leading / or ..)"; return 0
      fi
      ( set -o pipefail; sf_idle xz -dc -- "$archive" | tar -C "$stage" --no-same-permissions -xpf - ) || rc=$? ;;
    *.tar.gz|*.tgz)
      if ! ( set -o pipefail; sf_idle gzip -dc -- "$archive" | tar -tf - | sf_check_tar_members ); then
        rm -rf -- "$stage"; conflict "$archive contains unsafe member paths (leading / or ..)"; return 0
      fi
      ( set -o pipefail; sf_idle gzip -dc -- "$archive" | tar -C "$stage" --no-same-permissions -xpf - ) || rc=$? ;;
    *.tar.bz2|*.tbz2)
      if ! ( set -o pipefail; sf_idle bzip2 -dc -- "$archive" | tar -tf - | sf_check_tar_members ); then
        rm -rf -- "$stage"; conflict "$archive contains unsafe member paths (leading / or ..)"; return 0
      fi
      ( set -o pipefail; sf_idle bzip2 -dc -- "$archive" | tar -C "$stage" --no-same-permissions -xpf - ) || rc=$? ;;
    *.7z)
      seven=$(sf_7z_bin)
      if ! sf_idle "$seven" l -slt -- "$archive" | sed -n "s/^Path = //p" | tail -n +2 | sf_check_tar_members; then
        rm -rf -- "$stage"; conflict "$archive contains unsafe member paths (leading / or ..)"; return 0
      fi
      sf_idle "$seven" x -bd -y "-o$stage" -- "$archive" >/dev/null || rc=$? ;;
  esac
  find "$stage" -xdev \( -type b -o -type c -o -type p -o -type s \) -delete 2>/dev/null || true
  find "$stage" -xdev -type f -perm /6000 -exec chmod ug-s {} + 2>/dev/null || true
  if ((rc != 0)); then
    rm -rf -- "$stage"
    conflict "extraction of $archive failed (exit $rc)"
    return 0
  fi
  chmod 0755 -- "$stage"
  if [[ ! -e $dest ]]; then
    try mv -T -- "$stage" "$dest" || { rm -rf -- "$stage"; return 0; }
  else
    try mkdir -p -- "$dest" || { rm -rf -- "$stage"; return 0; }
    # cp -a of "stage/." also copies the attributes of the staging folder onto dest, so its owner and mode are put back after
    dmode=$(stat -c %a -- "$dest") && downer=$(stat -c %u:%g -- "$dest") || { rm -rf -- "$stage"; conflict "could not read the owner of $dest"; return 0; }
    cp -a -- "$stage/." "$dest/" || { rm -rf -- "$stage"; conflict "could not move extracted files into $dest"; return 0; }
    chown -- "$downer" "$dest" 2>/dev/null || true; chmod -- "$dmode" "$dest" 2>/dev/null || true
    rm -rf -- "$stage"
  fi
  printf "%s\n" "$archive" >"$dest/.sf-extracted"
  ok "extracted $archive into $dest"
}
"""


def _check_archive(conn: Conn, c: changes.Host, h: dict, p: dict, say):
    src = '/' + posixpath.normpath(p['path']).lstrip('/')
    dst = '/' + posixpath.normpath(p['dest']).lstrip('/')
    codec = p.get('codec') or 'zstd-ultra'
    comp_raw = str(p.get('compress_host') or '').strip()
    if src in OS_PROTECTED:
        say('crit', f'refusing to archive operating system or virtual directory {src}')
        return
    if src in c.mounted and src not in c.unmounted:
        say('crit', f'{src} is a mount point: pick a folder inside it or unmount it first')
        return
    if dst == src or dst.startswith(src.rstrip('/') + '/'):
        say('crit', f'archive destination {dst} cannot be the same as {src} or inside it')
        return
    st = c.state(src)
    if st == 'missing':
        say('crit', f'{src} does not exist (or was removed in an earlier step)')
    elif st == 'link':
        say('crit', f'{src} is a symbolic link: archive the real folder or file instead')
    elif st == 'unknown':
        say('warn', f'{src} is not in the index; the script checks it on {h["name"]}')
    dst_st = c.state(dst)
    if dst_st not in ('missing', 'unknown'):
        say('crit', f'{dst} already exists as a {dst_st}')
    tool = CODEC_TOOL.get(codec, 'zstd')
    wh = find_host(hosts(conn), comp_raw) if comp_raw else None
    remote_worker = bool(comp_raw and (not wh or wh['id'] != h['id']) and comp_raw.lower() != h['name'].lower())
    if remote_worker:
        if codec == '7z-ultra':
            say('crit', '7z-ultra writes a seekable solid archive and cannot stream over SSH; pick zstd-ultra, xz-extreme or zstd-high for remote CPU-offloaded compression')
            return
        if not wh:
            say('warn', f'remote compression host {comp_raw} has not been scanned; the script connects to root@{comp_raw} over SSH')
        else:
            say(*package_check(conn, wh, tool))
            say('note', f'CPU-offloaded compression: {h["name"]} streams raw tar under idle IO/CPU priority to {wh["name"]} ({codec} + round-trip check in RAM), sparing {h["name"]} CPU (or use Moves -> Archive -> Deploy for automatic restricted per-job SSH keys)')
    else:
        say(*package_check(conn, h, tool))
    want_ext = archive_ext(codec)
    if not dst.endswith(want_ext):
        say('warn', f'{codec} writes a {want_ext} archive; consider naming the destination *{want_ext}')
    sz = c.size(src) if st == 'dir' else None
    dm = mount_of(h, dst)
    if sz and sz['entries']:
        say('ok', f'{sz["files"]:,} file(s), {changes._fmt(sz["bytes"])} source size; compressed losslessly with {codec}')
        if dm and dm.get('total'):
            free = (dm['total'] or 0) - (dm['used'] or 0)
            if free < sz['bytes'] * 0.25:
                say('warn', f'destination mount {dm["target"]} has {changes._fmt(free)} free for {changes._fmt(sz["bytes"])} of uncompressed input')
    else:
        say('ok', f'compresses {src} -> {dst} with {codec}' + (' and verifies lossless decompression' if p.get('verify') else ''))
    if p.get('trash_source'):
        say('note', 'moves original to .storageforge-trash only after the archive and its decompression check pass')
        c.gone.add(src)
    c.made.add(dst)


def _check_extract(conn: Conn, c: changes.Host, h: dict, p: dict, say):
    arc = '/' + posixpath.normpath(p['archive']).lstrip('/')
    dst = '/' + posixpath.normpath(p['dest']).lstrip('/')
    if dst in OS_PROTECTED:
        say('crit', f'refusing to extract directly over system directory {dst}')
        return
    if arc == dst or arc.startswith(dst.rstrip('/') + '/'):
        say('warn', f'{arc} is inside {dst}')
    if not any(arc.lower().endswith(s) for s in ARCHIVE_SUFFIXES):
        say('crit', f'{arc} does not have a supported archive extension ({", ".join(ARCHIVE_SUFFIXES)})')
        return
    st = c.state(arc)
    if st == 'missing':
        say('crit', f'{arc} does not exist (or is created only outside this plan)')
    elif st == 'dir':
        say('crit', f'{arc} is a folder, not an archive file')
    elif st == 'unknown':
        say('note', f'{arc} is not in the index; the script verifies it on {h["name"]}')
    if arc.lower().endswith(('.tar.zst', '.tzst')):
        say(*package_check(conn, h, 'zstd'))
    elif arc.lower().endswith(('.tar.xz', '.txz')):
        say(*package_check(conn, h, 'xz'))
    elif arc.lower().endswith('.7z'):
        say(*package_check(conn, h, '7z'))
    say('ok', f'extracts {arc} into {dst} after path-safety and checksum checks')
    c.made.add(dst)


def _ansible_archive(t: dict, conn: Conn | None = None) -> dict:
    p = t['params']
    q = shlex.quote
    src, dst, codec = q(p['path']), q(p['dest']), p.get('codec') or 'zstd-ultra'
    _, comp_login, comp_port = _resolve_worker(conn, t) if conn is not None else (None, '', 22)
    parent_expr = f'parent=$(dirname -- "$(realpath -m -- {src})"); base=$(basename -- "$(realpath -m -- {src})")'
    if comp_login and codec != '7z-ultra':
        remote_comp = 'xz -9 -e -T0 -c' if codec == 'xz-extreme' else ('zstd -q -T0 -19 -c' if codec == 'zstd-high' else '( zstd -q -T0 --ultra -22 --long=27 -c )')
        pack_cmd = f'nice -n 19 tar -C "$parent" --numeric-owner --sparse -cf - -- "$base" | ssh -o BatchMode=yes -p {int(comp_port)} {q(comp_login)} {q(remote_comp)} >"$part"'
        ver_cmd = ''
    elif codec == 'xz-extreme':
        pack_cmd = 'nice -n 19 tar -C "$parent" --numeric-owner --sparse -cf - -- "$base" | nice -n 19 xz -9 -e -T0 -c >"$part"'
        ver_cmd = 'xz -dc -- "$part" | tar -tf - >/dev/null'
    elif codec == '7z-ultra':
        pack_cmd = 'seven=$(command -v 7z || command -v 7zz || command -v 7za); ( cd "$parent" && nice -n 19 "$seven" a -t7z -m0=lzma2 -mx=9 -mfb=273 -md=64m -ms=on -mmt=on -bd -- "$part" "$base" >/dev/null )'
        ver_cmd = 'seven=$(command -v 7z || command -v 7zz || command -v 7za); "$seven" t -bd -- "$part" >/dev/null'
    elif codec == 'zstd-high':
        pack_cmd = 'nice -n 19 tar -C "$parent" --numeric-owner --sparse -cf - -- "$base" | nice -n 19 zstd -q -T0 -19 -c >"$part"'
        ver_cmd = '( zstd -dc --long=31 -- "$part" ) | tar -tf - >/dev/null'
    else:
        pack_cmd = 'nice -n 19 tar -C "$parent" --numeric-owner --sparse -cf - -- "$base" | ( nice -n 19 zstd -q -T0 --ultra -22 --long=27 -c ) >"$part"'
        ver_cmd = '( zstd -dc --long=31 -- "$part" ) | tar -tf - >/dev/null'
    verify_line = f'{ver_cmd}\n' if (p.get('verify', True) and ver_cmd) else ''
    return {
        'name': changes.title(t),
        'ansible.builtin.shell': {
            'executable': '/bin/bash',
            'cmd': (
                f'set -euo pipefail\n'
                f'[ -f {dst} ] && {{ echo unchanged; exit 0; }}\n'
                f'mkdir -p -- "$(dirname -- {dst})"\n'
                f'part="$(realpath -m -- {dst}).sf-part.$$"\n'
                f'trap \'rm -f -- "$part"\' EXIT\n'
                f'{parent_expr}\n'
                f'{pack_cmd}\n'
                f'{verify_line}'
                f'sha256sum <"$part" | awk \'{{print $1}}\' >{dst}.sha256\n'
                f'mv -n -- "$part" {dst}\n'
            ),
        },
        'register': 'sf_out',
        'changed_when': "'unchanged' not in sf_out.stdout",
    }


def _ansible_extract(t: dict) -> dict:
    p = t['params']
    q = shlex.quote
    arc, dst = q(p['archive']), q(p['dest'])
    return {
        'name': changes.title(t),
        'ansible.builtin.shell': {
            'executable': '/bin/bash',
            'cmd': (
                f'set -euo pipefail\n'
                f'[ -f {dst}/.sf-extracted ] && [ "$(cat {dst}/.sf-extracted)" = {arc} ] && {{ echo unchanged; exit 0; }}\n'
                f'mkdir -p -- {dst}\n'
                f'case {arc} in\n'
                f'  *.tar.zst|*.tzst) ( zstd -dc --long=31 -- {arc} ) | tar -C {dst} --no-same-permissions -xpf - ;;\n'
                f'  *.tar.xz|*.txz) xz -dc -- {arc} | tar -C {dst} --no-same-permissions -xpf - ;;\n'
                f'  *.tar.gz|*.tgz) gzip -dc -- {arc} | tar -C {dst} --no-same-permissions -xpf - ;;\n'
                f'  *.tar.bz2|*.tbz2) bzip2 -dc -- {arc} | tar -C {dst} --no-same-permissions -xpf - ;;\n'
                f'  *.7z) seven=$(command -v 7z || command -v 7zz || command -v 7za); "$seven" x -bd -y -o{dst} -- {arc} >/dev/null ;;\n'
                f'  *) echo "unsupported archive" >&2; exit 1 ;;\n'
                f'esac\n'
                f'printf "%s\\n" {arc} >{dst}/.sf-extracted\n'
            ),
        },
        'register': 'sf_out',
        'changed_when': "'unchanged' not in sf_out.stdout",
    }


changes.register(
    'archive',
    {
        'group': 'Files and folders',
        'label': 'Compress into lossless archive',
        'fields': [
            F('path', 'path', 'Source file or folder', required=True),
            F('dest', 'path', 'Archive file to write', required=True, placeholder='/mnt/cold/media.tar.zst'),
            F('codec', 'choice', 'Lossless compression profile', options=CODECS, required=True, default='zstd-ultra'),
            F('verify', 'bool', 'Verify lossless round-trip decompression and write .sha256', default=True),
            F('trash_source', 'bool', 'Move original to .storageforge-trash after archive verifies', default=False),
            F('compress_host', 'host', 'Remote compression host (optional — spares this host CPU)', added=True,
              placeholder='this host, or a fast host such as tr01 to offload compression CPU'),
        ],
        'help': 'Packs a file or folder with maximum lossless compression (zstd --ultra -22 --long, xz -9e, or solid 7z LZMA2) under idle CPU/IO priority, verifies full decompression before finishing, and writes a .sha256 checksum. Set a remote compression host to stream tar over SSH so weak or busy machines spend zero CPU on compression.',
    },
    ('path', 'dest', 'codec', 'verify', 'trash_source', 'compress_host'),
    lambda p: f'Compress {p["path"]} → {p["dest"]} ({p.get("codec") or "zstd-ultra"}{", via " + p["compress_host"] if p.get("compress_host") else ""})',
    _check_archive,
    _ansible_archive,
    args_of=_args_archive,
)

changes.register(
    'archive-extract',
    {
        'group': 'Files and folders',
        'label': 'Extract archive',
        'fields': [
            F('archive', 'path', 'Archive file', required=True, placeholder='/mnt/cold/media.tar.zst'),
            F('dest', 'path', 'Extract into folder', required=True, placeholder='/mnt/data/restored'),
            F('verify_checksum', 'bool', 'Verify .sha256 sidecar first when present', default=True),
        ],
        'help': 'Verifies the archive .sha256 checksum if present, checks all member paths against path traversal, and extracts losslessly.',
    },
    ('archive', 'dest', 'verify_checksum'),
    lambda p: f'Extract {p["archive"]} → {p["dest"]}',
    _check_extract,
    _ansible_extract,
)

changes.EXTRA_BASH.append(BASH)
