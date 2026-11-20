"""Plan steps that join a host to a private network and take it out again (roadmap section 2): netbird, zerotier, nebula and
openziti. None is lab-tested: lab tier 22 is written and has not run.

Each tool was read for how it takes its secret before a step was written (2026-11-20, from each project's own documentation and
source), because a command line is readable by every account on the host:

    netbird     `netbird up --setup-key-file FILE`. The client reads the file and hands the key to its daemon over a local socket.
                A netbird without that option is refused: it could only take the key as an argument or in its environment
    zerotier    no secret at all. A network is joined by its id, and the controller decides afterwards whether the node is let in
    nebula      no secret travels. The host makes its own key pair, the CA key signs in the vault, and what comes back is a
                certificate, which is public (overlaykeys.py and nebulaca.py)
    openziti    `ziti-edge-tunnel enroll --jwt FILE`. The token is read from the file, works once, and is removed afterwards
    netmaker    NO STEP. `netclient join -t TOKEN` is the only way in: no file, no stdin, no environment variable (its own
                container script builds `-t $TOKEN` too). The token registers a machine on the network, so it stays out of here
                until netclient can read it from a file

A secret reaches the host as for the tailscale step: the vault holds it (`vault secret-add NAME`), `vault send-secret` writes it
to /run/storageforge/secrets/NAME over ssh's stdin (memory, mode 600), and the step names the file to the program. It is in no
plan, script, playbook or log, and the file is removed once the host has joined: the host then holds a key of its own.

No step here installs its program: each has a package source of its own to add, and that is the operator's choice. No step
changes what the network's controller knows beyond what the program itself does when it joins or leaves, and each step says so.
"""
from __future__ import annotations

import re
import shlex

from . import changes, steps_tunnels
from .changes import F

NAME = re.compile(r'[A-Za-z0-9_.-]{1,64}')
HOSTNAME = re.compile(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?')
URL = re.compile(r'https?://[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?')
ZT_NETWORK = re.compile(r'[0-9a-f]{16}')
SECRET_DIR = '/run/storageforge/secrets'
NETBIRD_ARGS = ('secret', 'management_url', 'hostname', 'state')
ZEROTIER_ARGS = ('network', 'state')

# No apostrophes: the script text is checked for values that could end a quoted word.
# tun_systemd, tun_secret_missing, tun_unit_start and tun_unit_stop are in steps_tunnels.BASH, which every plan script carries.
BASH = r"""
# ── private networks: join and leave ────────────────────────────────
ov_service() { # $1 the unit: start it when systemd runs this host and it is not running. Says what it would do in a report
  tun_systemd || return 0
  systemctl is-active --quiet "$1" && return 0
  act "systemctl enable --now $1" || return 1
  systemctl enable --now "$1" >/dev/null 2>&1 || { conflict "could not start $1: journalctl -u $1 says why"; return 1; }
}

# NetBird. Its JSON status is one line: {"management":{"url":"...","connected":true,...},...}
# A program is never piped into grep -q here: grep leaves at the first match, and under pipefail a program still writing then fails the pipe
ov_says() { local out; out=$("${@:2}" 2>&1) || true; grep -qE -- "$1" <<<"$out"; }      # $1 a pattern, the rest a command: does its output have it
nb_management() { local s; s=$(netbird status --json 2>/dev/null) || true; s=${s//[[:space:]]/}; [[ $s =~ \"management\":\{[^}]*\} ]] && echo "${BASH_REMATCH[0]}"; return 0; }
nb_connected() { [[ $(nb_management) == *"\"connected\":true"* ]]; }
nb_url() { nb_management | sed -n "s/.*\"url\":\"\([^\"]*\)\".*/\1/p"; }
nb_host() { sed -E "s#^[a-z]+://##; s#[:/].*##" <<<"$1"; }
nb_unregistered() { ov_says "^Daemon status: (NeedsLogin|LoginFailed|SessionExpired)" netbird status; }
nb_ip() { local s; s=$(netbird status --ipv4 2>/dev/null) || true; echo "${s%%$'\n'*}"; }
t_netbird() { local secret=$1 url=$2 name=$3 state=${4:-present} f out ip at args=()
  f=${SF_SECRET_DIR:-/run/storageforge/secrets}/$secret
  if [[ $state == absent ]]; then
    command -v netbird >/dev/null || { ok "NetBird is not installed"; return 0; }
    netbird status >/dev/null 2>&1 || { ok "the NetBird service does not run here: this host is on no NetBird network"; return 0; }
    if nb_unregistered; then ok "not registered with a NetBird management server"; return 0; fi
    if ov_says "^ +deregister" netbird --help; then
      act "netbird deregister: leave the network and remove this peer at the management server (the package stays)" || return 0
      if ! out=$(netbird deregister 2>&1); then conflict "netbird deregister failed: $(tail -n 2 <<<"$out" | tr "\n" " ")"; return 0; fi
      ok "left the NetBird network, and this peer is removed at the management server"
    else
      nb_connected || { ok "not connected to a NetBird network. This netbird has no deregister, so the peer stays listed at the management server until it is removed there"; return 0; }
      act "netbird down (this netbird has no deregister: the peer stays listed at the management server until it is removed there)" || return 0
      try netbird down >/dev/null && ok "disconnected from the NetBird network"
    fi
    return 0
  fi
  command -v netbird >/dev/null || { conflict "netbird is not installed: install it from the package source NetBird gives (pkgs.netbird.io), which this step does not add"; return 0; }
  if ! ov_says "--setup-key-file" netbird up --help; then
    conflict "this netbird ($(netbird version 2>/dev/null || true)) cannot read its setup key from a file (--setup-key-file): with it the key would be on a command line, so nothing is done. Update netbird"
    return 0
  fi
  if ! netbird status >/dev/null 2>&1; then
    ov_service netbird || return 0
    if ((APPLY)) && ! netbird status >/dev/null 2>&1; then conflict "the NetBird service does not answer: netbird service install, then netbird service start"; return 0; fi
  fi
  if nb_connected; then
    at=$(nb_url)
    if [[ -n $url && -n $at && $(nb_host "$at") != "$(nb_host "$url")" ]]; then
      conflict "on a NetBird network already, managed at $at and not at $url: a step with state absent leaves it first"; return 0
    fi
    ok "on a NetBird network already, as $(nb_ip), managed at ${at:-a server it does not name}"
    [[ -e $f ]] && rm -f -- "$f" && info "removed the setup key file it no longer needs"
    return 0
  fi
  if [[ ! -r $f ]]; then
    if nb_unregistered || ! netbird status >/dev/null 2>&1; then tun_secret_missing "$f" "$secret" "setup key"; return 0; fi
    # registered before and only disconnected: it has a key of its own and needs no setup key
    act "netbird up (registered already, and only disconnected)" || return 0
  else
    args=("--setup-key-file=$f")
    [[ -n $url ]] && args+=("--management-url=$url")
    [[ -n $name ]] && args+=("--hostname=$name")
    act "netbird up ${args[*]}" || return 0
  fi
  if ! out=$(netbird up "${args[@]}" 2>&1); then conflict "netbird up failed: $(tail -n 2 <<<"$out" | tr "\n" " ")"; return 0; fi
  nb_connected || { conflict "netbird up returned, and the management server is not connected: netbird status says why. The setup key file is kept at $f"; return 0; }
  rm -f -- "$f"
  ip=$(nb_ip)
  ok "joined the NetBird network as ${ip:-an address not known yet}; the setup key file is removed, as the peer keeps a key of its own"
}

# ZeroTier. zerotier-cli get NETWORK status prints OK, ACCESS_DENIED, REQUESTING_CONFIGURATION, NOT_FOUND, or nothing when not joined
zt_up() { ov_says "^200 info " zerotier-cli info; }
zt_node() { local s; s=$(zerotier-cli info 2>/dev/null) || true; [[ $s =~ ^200\ info\ ([0-9a-f]+) ]] && echo "${BASH_REMATCH[1]}"; return 0; }
zt_status() { local s; s=$(zerotier-cli get "$1" status 2>/dev/null) || true; s=${s%%$'\n'*}; [[ $s =~ ^[A-Z_]+$ ]] && echo "$s"; return 0; }
zt_ip() { local s; s=$(zerotier-cli get "$1" ip4 2>/dev/null) || true; echo "${s%%$'\n'*}"; }
zt_say() { local net=$1 st=$2 node; node=$(zt_node)
  case $st in
    OK) ok "on ZeroTier network $net as $(zt_ip "$net"), node $node" ;;
    ACCESS_DENIED) info "joined ZeroTier network $net, and its controller has not authorised node $node: that is done at the controller, not by this step"
                   ok "asked to join $net as node $node" ;;
    NOT_FOUND) conflict "ZeroTier network $net is not found: no controller answers for that id" ;;
    *) info "joined ZeroTier network $net as node $node, and the controller has not answered yet (${st:-no status}): a private network waits for the node to be authorised there"
       ok "asked to join $net as node $node" ;;
  esac
}
t_zerotier() { local net=$1 state=${2:-present} st out i
  if [[ $state == absent ]]; then
    command -v zerotier-cli >/dev/null || { ok "ZeroTier is not installed"; return 0; }
    zt_up || { ok "the ZeroTier service does not run here: this host is on no ZeroTier network"; return 0; }
    [[ -n $(zt_status "$net") ]] || { ok "not on ZeroTier network $net"; return 0; }
    act "zerotier-cli leave $net (the package stays, and the node stays listed at the controller until it is removed there)" || return 0
    if ! out=$(zerotier-cli leave "$net" 2>&1); then conflict "zerotier-cli leave failed: $(tail -n 1 <<<"$out")"; return 0; fi
    ok "left ZeroTier network $net. Its controller still lists node $(zt_node) as a member: remove it there to forget it"
    return 0
  fi
  command -v zerotier-cli >/dev/null || { conflict "zerotier-cli is not installed: install ZeroTier from the package source it gives (install.zerotier.com), which this step does not add"; return 0; }
  if ! zt_up; then
    ov_service zerotier-one || return 0
    if ((APPLY)); then
      for i in 1 2 3 4 5; do zt_up && break; sleep "${SF_OVERLAY_WAIT:-1}"; done
      zt_up || { conflict "the ZeroTier service does not answer: zerotier-cli info says why"; return 0; }
    fi
  fi
  st=$(zt_status "$net")
  if [[ -n $st ]]; then zt_say "$net" "$st"; return 0; fi
  act "zerotier-cli join $net (the controller of a private network must then authorise this node: this step does not)" || return 0
  if ! out=$(zerotier-cli join "$net" 2>&1); then conflict "zerotier-cli join failed: $(tail -n 1 <<<"$out")"; return 0; fi
  for i in 1 2 3 4 5 6; do st=$(zt_status "$net"); [[ $st == OK || $st == ACCESS_DENIED || $st == NOT_FOUND ]] && break; sleep "${SF_OVERLAY_WAIT:-1}"; done
  zt_say "$net" "$st"
}
"""


def _secret_ok(p, say) -> bool:
    if not NAME.fullmatch(p['secret']):
        say('crit', f'{p["secret"]} is not a secret name: letters, digits, . _ and -')
        return False
    return True


def _secret_note(h, p, say, what: str, after: str):
    say('note', f'the {what} is read on {h["name"]} from {SECRET_DIR}/{p["secret"]}: before running, storageforge-index vault send-secret {p["secret"]} --host {h["name"]}. '
                f'It is named to the program as a file and is on no command line. {after}')


def _check_netbird(conn, c, h, p, say):
    if not _secret_ok(p, say):
        return
    if p['management_url'] and not URL.fullmatch(p['management_url']):
        say('crit', 'the management server is its address, such as https://netbird.example.com')
    if p['hostname'] and not HOSTNAME.fullmatch(p['hostname']):
        say('crit', f'{p["hostname"]} is not a NetBird peer name: lower-case letters, digits and -')
    if p['state'] == 'absent':
        say('note', 'netbird deregister: the host leaves the network and its peer is removed at the management server. NetBird stays installed. '
                    'A netbird too old to deregister is disconnected, and its peer stays listed until it is removed there')
        return
    _secret_note(h, p, say, 'setup key', 'It is removed once the peer has joined')
    say('note', 'needs netbird installed already, new enough to take --setup-key-file. An older one is refused, because it could only take the key as an argument. Not lab-tested'
                + ('' if p['management_url'] else '. No management server is named: netbird uses the one it knows, which is NetBird\'s own service unless it was told another'))


def _check_zerotier(conn, c, h, p, say):
    if not ZT_NETWORK.fullmatch(p['network']):
        say('crit', 'a ZeroTier network id is 16 digits and letters a to f, such as 8056c2e21c000001')
        return
    if p['state'] == 'absent':
        say('note', f'zerotier-cli leave {p["network"]}. The node stays listed at the controller until it is removed there, and ZeroTier stays installed')
        return
    say('note', f'zerotier-cli join {p["network"]}. No secret is involved: the id names the network, and a private network lets the node in only once its '
                'controller has authorised it. This step does not authorise it and says which node id to authorise')
    say('note', 'needs ZeroTier installed already. Not lab-tested')


HEAD = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { echo "info: $*"; }\n'
        'act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; durable() { sync; }\n')


def _ansible(fn: str, args: tuple, args_of=None):
    def render(t, conn=None):
        q = shlex.quote
        p = t['params']
        words = [('1' if p[a] else '') if isinstance(p.get(a), bool) else str(p.get(a) or '') for a in args]
        words += args_of(conn, t) if args_of and conn is not None else []
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': HEAD + steps_tunnels.BASH + BASH + f'\n{fn} ' + ' '.join(q(w) for w in words) + '\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


STATE = F('state', 'choice', 'Join or leave', options=['present', 'absent'], default='present')
changes.register('netbird', {'group': 'Network', 'label': 'Join a NetBird network (not lab-tested)', 'fields': [
    F('secret', 'name', 'Setup key (a vault secret)', required=True, placeholder='netbird-key'),
    F('management_url', 'text', 'Management server', placeholder='https://netbird.example.com'),
    F('hostname', 'text', 'Peer name on the network'), STATE],
    'help': 'Joins with a setup key the vault holds. The key reaches the host with vault send-secret, netbird reads it from a file in memory '
            '(--setup-key-file), and it is removed once the peer has joined. NetBird has to be installed already. Leaving removes the peer at the management server.'},
    NETBIRD_ARGS, lambda p: 'Leave the NetBird network' if p['state'] == 'absent' else 'Join the NetBird network' + (f' at {p["management_url"]}' if p.get('management_url') else ''),
    _check_netbird, _ansible('t_netbird', NETBIRD_ARGS))
changes.register('zerotier', {'group': 'Network', 'label': 'Join a ZeroTier network (not lab-tested)', 'fields': [
    F('network', 'text', 'Network id', required=True, placeholder='8056c2e21c000001'), STATE],
    'help': 'Joins or leaves a ZeroTier network by its id. No secret is involved. A private network lets the node in only once its controller has '
            'authorised it: this step says which node id to authorise, and does not do it. ZeroTier has to be installed already.'},
    ZEROTIER_ARGS, lambda p: f'{"Leave" if p["state"] == "absent" else "Join"} ZeroTier network {p.get("network") or ""}'.rstrip(),
    _check_zerotier, _ansible('t_zerotier', ZEROTIER_ARGS))
changes.EXTRA_BASH.append(BASH)
