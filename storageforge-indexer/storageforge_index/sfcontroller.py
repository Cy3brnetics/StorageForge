"""The controller's own end of the StorageForge network (roadmap section 2.1): a WireGuard interface where the controller runs.

The controller runs without root and, in Docker, with every capability dropped, so it cannot make a network interface and must not
hold a private key. Two parts do it between them:

    the link      a small root program (LINK below) with CAP_NET_ADMIN and nothing else. It makes `sf0` and its key pair, keeps
                  the private key in a folder only it can read, and applies what the controller asks for
    the controller  writes what it wants (address, port, peers by public key) and reads what the link reports (public keys,
                  addresses, handshakes)

They share two folders and nothing else. The controller writes the `want` folder and the link only reads it; the link writes the
`state` folder and the controller only reads it. Neither file holds a secret. The link checks every line of the want file before it
acts on it, because the program that writes it is the one a break-in would start from: a line that is not an address, a port or a
WireGuard public key stops the pass, and nothing in the file can name a file, a command or an interface other than `sf0`.

In Docker the link is the `sfnet` service of docker-compose.sfnet.yml, which shares the controller's network namespace. A
controller that runs on a host needs no link when that host is scanned: the host joins like any other and the controller is said
to run on it (sfnetwork.controller_on). Otherwise the link runs there as a systemd unit (docs/infrastructure-map.md). The private key is made where the link runs and is never in the database, in a
want or state file, in a log or on a command line.

    configured()        whether this controller was started with the two folders
    reading()           what the link last reported, as a scan's WireGuard reading; None when it is not running
    want(...)           the text of the want file
    write(text)         put it in place
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

from . import inframeasure, sfnet

NAME = 'StorageForge controller'          # the member's name: no scanned host can have a space in its own
STALE = 60                                # seconds without a report: the link is not running
MAX_STATE = 1 << 20
WANT_ENV, STATE_ENV = 'STORAGEFORGE_SFNET_WANT', 'STORAGEFORGE_SFNET_STATE'
ALLOWED = re.compile(r'\d{1,3}(\.\d{1,3}){3}/\d{1,2}(,\d{1,3}(\.\d{1,3}){3}/\d{1,2})*')
ENDPOINT = re.compile(r'([A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?|\[[0-9A-Fa-f:]{2,39}\]):\d{1,5}')


def _dir(env: str) -> Path | None:
    value = os.environ.get(env, '').strip()
    return Path(value) if value else None


def configured() -> bool:
    return bool(_dir(WANT_ENV) and _dir(STATE_ENV))


def _file(env: str, kind: str) -> Path | None:
    folder = _dir(env)
    return folder / f'{sfnet.INTERFACE}.{kind}' if folder else None


def report() -> dict:
    """{'running', 'error', 'age', 'interfaces'}: what the link last said. Nothing here is trusted beyond what a host's own reading
    is: it is parsed by the same reader, which keeps public keys and drops every other line."""
    path = _file(STATE_ENV, 'state')
    out = {'configured': configured(), 'running': False, 'error': None, 'age': None, 'interfaces': None}
    if path is None:
        return out
    try:
        if path.stat().st_size > MAX_STATE:
            return {**out, 'error': 'the link wrote more than it ever should'}
        lines = path.read_text(errors='replace').splitlines()
    except OSError:
        return out
    stamp = next((line.split('\t')[1] for line in lines if line.startswith('t\t') and line.split('\t')[1].isdigit()), None)
    if stamp is None:
        return out
    out['age'] = max(0, int(time.time()) - int(stamp))
    out['running'] = out['age'] <= STALE
    out['error'] = next((line.split('\t', 1)[1][:200] for line in lines if line.startswith('x\t')), None)
    if out['running']:
        out['interfaces'] = inframeasure.parse_wireguard(lines)
    return out


def reading() -> list | None:
    """The controller's WireGuard interfaces as the link sees them, in the shape of a host's reading. None: no link is running."""
    return report()['interfaces']


def want(network: dict, member: dict | None, peers: list[dict], rotation: tuple[str, str | None] | None = None) -> str:
    """The want file: the interface, each peer, and the half of a rotation that is due. A member that is revoked or gone asks for
    the interface to be removed. Every value is checked here as well as by the link."""
    lines = ['v\t1']
    if member is None or member['state'] == 'revoked':
        return '\n'.join(lines + [f'x\t{sfnet.INTERFACE}']) + '\n'
    prefix = network['range'].split('/')[1]
    lines.append(f'i\t{sfnet.INTERFACE}\t{member["address"]}/{prefix}\t{int(network["port"])}')
    for p in peers:
        allowed, endpoint, keepalive = ','.join(p['allowed']), p.get('endpoint') or '', str(p.get('keepalive') or '')
        if not sfnet.WGKEY.fullmatch(p['public_key']) or (allowed and not ALLOWED.fullmatch(allowed)) or (endpoint and not ENDPOINT.fullmatch(endpoint)) or (keepalive and not keepalive.isdigit()):
            raise sfnet.NetworkError(f'a peer of the controller is not one the link would take: {p.get("host")}')
        lines.append('\t'.join(('p', p['public_key'], allowed or '-', endpoint or '-', keepalive or '-')))
    if rotation:
        phase, key = rotation
        if phase not in ('prepare', 'switch', 'cancel') or (phase == 'switch' and not sfnet.WGKEY.fullmatch(key or '')):
            raise sfnet.NetworkError('a rotation is prepare, switch with a key, or cancel')
        lines.append(f'r\t{phase}\t{key if phase == "switch" else "-"}')
    return '\n'.join(lines) + '\n'


def wanted() -> str | None:
    path = _file(WANT_ENV, 'want')
    try:
        return path.read_text() if path else None
    except OSError:
        return None


def write(text: str):
    path = _file(WANT_ENV, 'want')
    if path is None:
        raise sfnet.NetworkError('this controller was not started with a link for the StorageForge network: see docs/infrastructure-map.md')
    tmp = path.with_suffix('.tmp')
    try:
        tmp.write_text(text)
        os.chmod(tmp, 0o644)             # the link reads it as another user; nothing in it is secret
        os.replace(tmp, path)
    except OSError as exc:
        raise sfnet.NetworkError(f'could not write what the controller wants: {exc.strerror}') from None


# The link. Bash, run as root with CAP_NET_ADMIN: `storageforge-sfnet-link run` loops, `once` does one pass. It uses wg and ip and
# nothing else. Every message it writes is a fixed sentence: no line of the want file is ever echoed, since that file could be made
# to point at anything.
LINK = r'''#!/usr/bin/env bash
# Written by StorageForge: the end of the StorageForge network that the controller has (sfcontroller.py).
# Run as root, with CAP_NET_ADMIN and nothing else. The private key is made here and stays in $SF_WG_DIR.
set -u
umask 077
IFACE=sf0
KEYS=${SF_WG_DIR:-/etc/wireguard}; WANT_DIR=${SF_WG_WANT:-/run/storageforge-sfnet/want}; STATE_DIR=${SF_WG_STATE:-/run/storageforge-sfnet/state}
EVERY=${SF_WG_EVERY:-5}
KEY=$KEYS/$IFACE.key; NEXT=$KEYS/$IFACE.key.next; MARK=$KEYS/$IFACE.storageforge
WANT=$WANT_DIR/$IFACE.want; STATE=$STATE_DIR/$IFACE.state
TAB=$(printf "\t")
RE_KEY="^[A-Za-z0-9+/]{43}=\$"
RE_ADDR="^[0-9]{1,3}(\\.[0-9]{1,3}){3}/[0-9]{1,2}\$"
RE_ALLOWED="^[0-9]{1,3}(\\.[0-9]{1,3}){3}/[0-9]{1,2}(,[0-9]{1,3}(\\.[0-9]{1,3}){3}/[0-9]{1,2})*\$"
RE_ENDPOINT="^([A-Za-z0-9]([A-Za-z0-9.-]{0,252}[A-Za-z0-9])?|\\[[0-9A-Fa-f:]{2,39}\\]):[0-9]{1,5}\$"
RE_NUM="^[0-9]{1,5}\$"

up() { wg show "$IFACE" public-key >/dev/null 2>&1; }

# What the controller may read: public keys, addresses and times, in the lines a host scan prints. $1: what went wrong, if anything.
state() { local tmp=$STATE.tmp ours=0
  [[ -e $MARK ]] && ours=1
  { printf "t\t%s\n" "$(date +%s)"
    [[ -n ${1:-} ]] && printf "x\t%s\n" "$1"
    if ((ours)) && up; then
      printf "i\t%s\t%s\t%s\n" "$IFACE" "$(wg show "$IFACE" public-key)" "$(wg show "$IFACE" listen-port)"
      wg show "$IFACE" endpoints | while IFS=$TAB read -r k v; do printf "e\t%s\t%s\t%s\n" "$IFACE" "$k" "$v"; done
      wg show "$IFACE" allowed-ips | while IFS=$TAB read -r k v; do printf "a\t%s\t%s\t%s\n" "$IFACE" "$k" "${v// /,}"; done
      wg show "$IFACE" latest-handshakes | while IFS=$TAB read -r k v; do printf "h\t%s\t%s\t%s\n" "$IFACE" "$k" "$v"; done
      [[ -s $NEXT ]] && printf "n\t%s\t%s\n" "$IFACE" "$(wg pubkey <"$NEXT")"
    fi
  } >"$tmp" 2>/dev/null
  chmod 0644 "$tmp"; mv -f "$tmp" "$STATE"
}

stop() { state "$1"; return 1; }

once() { local kind a b c d n=0 address="" port="" remove=0 phase="" newkey="" have now allowed endpoint keepalive key
  local -A peers=()
  install -d -m 0755 "$STATE_DIR" 2>/dev/null
  command -v wg >/dev/null && command -v ip >/dev/null || { stop "this has no wg or no ip command"; return 1; }
  [[ -f $WANT && ! -L $WANT ]] || { state; return 0; }
  (( $(stat -c %s "$WANT") <= 1048576 )) || { stop "the want file is larger than it ever should be"; return 1; }
  while IFS=$TAB read -r kind a b c d || [[ -n $kind ]]; do
    ((++n <= 5000)) || { stop "the want file has more lines than it ever should"; return 1; }
    case $kind in
      "") ;;
      v) [[ $a == 1 ]] || { stop "the want file is of a version this link does not know"; return 1; } ;;
      i) [[ $a == "$IFACE" && $b =~ $RE_ADDR && $c =~ $RE_NUM ]] && ((c >= 1 && c <= 65535)) || { stop "the interface line is not an address and a port"; return 1; }
         address=$b; port=$c ;;
      p) [[ $a =~ $RE_KEY ]] && [[ $b == - || $b =~ $RE_ALLOWED ]] && [[ $c == - || $c =~ $RE_ENDPOINT ]] && [[ $d == - || $d =~ $RE_NUM ]] || { stop "a peer line is not a key, addresses, a place to call and a keepalive"; return 1; }
         peers[$a]="$b $c $d" ;;
      r) [[ $a == prepare || $a == cancel ]] || [[ $a == switch && $b =~ $RE_KEY ]] || { stop "the rotation line is not prepare, switch with a key, or cancel"; return 1; }
         phase=$a; newkey=$b ;;
      x) [[ $a == "$IFACE" ]] || { stop "only $IFACE can be removed"; return 1; }
         remove=1 ;;
      *) stop "the want file has a line this link does not know"; return 1 ;;
    esac
  done <"$WANT"
  if ((remove)); then
    if [[ -e $MARK ]]; then ip link del "$IFACE" 2>/dev/null; rm -f "$KEY" "$NEXT" "$MARK"; fi
    state; return 0
  fi
  [[ -n $address ]] || { state; return 0; }
  if [[ ! -e $MARK ]] && { up || [[ -e $KEYS/$IFACE.conf ]]; }; then stop "$IFACE is here and StorageForge did not make it: it is left as it is"; return 1; fi
  if ! up && ip link show dev "$IFACE" >/dev/null 2>&1; then stop "$IFACE is here and is not a WireGuard interface: it is left as it is"; return 1; fi
  install -d -m 0700 "$KEYS" || { stop "the key folder cannot be made"; return 1; }
  if [[ ! -s $KEY ]]; then wg genkey >"$KEY" || { rm -f "$KEY"; stop "could not make a key"; return 1; }; fi
  : >"$MARK"
  up || ip link add "$IFACE" type wireguard 2>/dev/null || { stop "could not make $IFACE: the WireGuard module has to be loaded where this runs, and this needs NET_ADMIN"; return 1; }
  [[ $(wg show "$IFACE" public-key) == "$(wg pubkey <"$KEY")" ]] || wg set "$IFACE" private-key "$KEY" || { stop "could not give $IFACE its key"; return 1; }
  [[ $(wg show "$IFACE" listen-port) == "$port" ]] || wg set "$IFACE" listen-port "$port" || { stop "could not listen on that port"; return 1; }
  now=$(ip -o -4 addr show dev "$IFACE" | while read -r _ _ _ v _; do printf "%s" "$v"; break; done)
  if [[ $now != "$address" ]]; then ip addr flush dev "$IFACE"; ip addr add "$address" dev "$IFACE" || { stop "could not give $IFACE its address"; return 1; }; fi
  ip link set "$IFACE" up || { stop "could not bring $IFACE up"; return 1; }
  case $phase in
    prepare) if [[ ! -s $NEXT ]]; then wg genkey >"$NEXT" || rm -f "$NEXT"; fi ;;
    # only to the key the peers were given: any other next key stays where it is, unused
    switch) if [[ -s $NEXT && $(wg pubkey <"$NEXT") == "$newkey" ]]; then wg set "$IFACE" private-key "$NEXT" && mv -f "$NEXT" "$KEY"; fi ;;
    cancel) rm -f "$NEXT" ;;
  esac
  for have in $(wg show "$IFACE" peers); do
    [[ -n ${peers[$have]+x} ]] || wg set "$IFACE" peer "$have" remove
  done
  for key in "${!peers[@]}"; do
    read -r allowed endpoint keepalive <<<"${peers[$key]}"
    [[ $allowed == - ]] && allowed=""
    have=$(wg show "$IFACE" peers | grep -cxF "$key" || true)
    now=$(wg show "$IFACE" allowed-ips | while IFS=$TAB read -r k v; do [[ $k == "$key" ]] && printf "%s" "${v// /,}"; done)
    [[ $now == "(none)" ]] && now=""
    # a peer that is there with the right addresses is left as it is: its endpoint moves as it roams
    ((have)) && [[ $now == "$allowed" ]] && continue
    local -a more=(allowed-ips "$allowed")
    [[ $endpoint != - ]] && more+=(endpoint "$endpoint")
    [[ $keepalive != - && $keepalive != 0 ]] && more+=(persistent-keepalive "$keepalive")
    wg set "$IFACE" peer "$key" "${more[@]}" || { stop "a peer could not be set"; return 1; }
  done
  state
}

# In Docker this shares the network of the server container. When that container restarts alone, its network is made again and
# this is left in the old one, where only lo and the interface made here remain: stop, so that Docker starts this again in the new one.
alone() { local n; n=$(ip -o link show 2>/dev/null | grep -cvE "^[0-9]+: (lo|$IFACE)[:@]" || true); ((n == 0)); }

case ${1:-run} in
  once) once ;;
  run) trap "exit 0" TERM INT
       while :; do
         if alone; then echo "storageforge-sfnet-link: the network this was started in is gone: stopping, to be started again in the one the server has now" >&2; exit 1; fi
         once; sleep "$EVERY" & wait $!
       done ;;
  *) echo "usage: storageforge-sfnet-link run|once" >&2; exit 2 ;;
esac
'''
