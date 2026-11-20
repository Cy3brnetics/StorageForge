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

import base64
import re
import shlex
import time

from . import changes, nebulaca, overlaykeys, steps_tunnels
from .changes import F

NAME = re.compile(r'[A-Za-z0-9_.-]{1,64}')
HOSTNAME = re.compile(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?')
URL = re.compile(r'https?://[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?')
ZT_NETWORK = re.compile(r'[0-9a-f]{16}')
SECRET_DIR = '/run/storageforge/secrets'
NETBIRD_ARGS = ('secret', 'management_url', 'hostname', 'state')
ZEROTIER_ARGS = ('network', 'state')
NEBULA_ARGS = ('ca', 'lighthouse', 'lighthouses', 'port', 'inbound', 'state')
ZITI_ARGS = ('secret', 'identity', 'state')
IDENTITY = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}')

# No apostrophes: the script text is checked for values that could end a quoted word.
# tun_systemd, tun_secret_missing, tun_unit_start and tun_unit_stop are in steps_tunnels.BASH, which every plan script carries.
BASH = r"""
# ── private networks: join and leave ────────────────────────────────
ov_scrubbed() { # $1 a secret file, $2 what a program said: the same with the secret taken out, should the program have repeated it. No process is started
  local s=; [[ -r $1 ]] && s=$(<"$1"); s=${s//[[:space:]]/}
  if [[ -n $s ]]; then printf "%s" "${2//"$s"/(the secret)}"; else printf "%s" "$2"; fi
}
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
  if ! out=$(netbird up "${args[@]}" 2>&1); then conflict "netbird up failed: $(ov_scrubbed "$f" "$out" | tail -n 2 | tr "\n" " ")"; return 0; fi
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

# Nebula. The certificate authority is in the vault, and what reaches this host is public: the CA certificate and the configuration,
# both made when the script was written. The host key was made here by vault nebula-issue and is never read
nebula_ours() { local first=; [[ -e $1 ]] || return 0; IFS= read -r first <"$1" || true; [[ $first == "# Written by StorageForge"* ]]; }
nebula_same() { [[ -e $2 ]] && [[ $(printf %s "$1" | base64 -d 2>/dev/null) == "$(cat "$2")" ]]; }        # $1 base64, $2 a file
t_nebula() { local ca=$1 lh=$2 state=${6:-present} cab64=${7:-} confb64=${8:-} d unit=storageforge-nebula.service bin out new swapped=
  # words 3 to 5 (the lighthouses, the port, the inbound rules) are in the configuration already, which is word 8
  d=${SF_NEBULA_DIR:-/etc/nebula}
  local conf=$d/config.yml
  if [[ $state == absent ]]; then
    if [[ ! -e ${SF_UNIT_DIR:-/etc/systemd/system}/$unit && ! -e $conf && ! -e $d/host.crt ]]; then ok "no Nebula started by StorageForge is here"; return 0; fi
    nebula_ours "$conf" || { conflict "$conf was not written by StorageForge: a Nebula somebody set up by hand is left alone"; return 0; }
    act "stop $unit and remove it, $conf, the certificates and the host key in $d (nebula stays installed). The certificate stays good elsewhere until it ends: storageforge-index vault nebula-revoke $ca NAME revokes it" || return 0
    tun_unit_stop "$unit"
    rm -f "$conf" "$conf.sf-before" "$d/host.crt" "$d/host.crt.sf-before" "$d/host.key" "$d/host.pub" "$d/ca.crt" "$d/ca.crt.sf-before"
    ok "Nebula no longer runs from here, and its key is gone: a certificate issued for it opens nothing now. Revoke it at the CA all the same"
    return 0
  fi
  bin=$(command -v nebula) || { conflict "nebula is not installed: install it from the distribution or from its releases (github.com/slackhq/nebula), which this step does not do"; return 0; }
  command -v nebula-cert >/dev/null || { conflict "nebula-cert is not installed: it comes with nebula, and checks the certificate here"; return 0; }
  tun_systemd || { conflict "this step runs Nebula as a systemd unit, and systemd does not run this host"; return 0; }
  [[ -n $cab64 && -n $confb64 ]] || { conflict "when this script was written there was no Nebula CA named $ca, or its configuration could not be made: the check of the plan says which"; return 0; }
  nebula_ours "$conf" || { conflict "$conf was not written by StorageForge: a Nebula somebody set up by hand is left alone"; return 0; }
  if systemctl is-active --quiet nebula.service; then conflict "nebula.service runs a Nebula here that StorageForge did not start: it is left alone, and two would fight over the interface"; return 0; fi
  if [[ ! -s $d/host.key || ! -s $d/host.crt ]]; then
    if ((APPLY)); then conflict "no host certificate in $d: storageforge-index vault nebula-issue $ca --host $(uname -n) --address ADDRESS/PREFIX, then run this again"
    else missing "it needs a host certificate in $d: storageforge-index vault nebula-issue $ca --host $(uname -n) --address ADDRESS/PREFIX"; fi
    return 0
  fi
  if ! out=$(nebula-cert verify -ca <(printf %s "$cab64" | base64 -d) -crt "$d/host.crt" 2>&1); then
    conflict "the certificate in $d/host.crt is not a running one of CA $ca ($(tail -n 1 <<<"$out")): storageforge-index vault nebula-issue $ca --host $(uname -n) --address ADDRESS/PREFIX issues another"; return 0
  fi
  if nebula_same "$cab64" "$d/ca.crt" && nebula_same "$confb64" "$conf" && systemctl is-active --quiet "$unit"; then
    ok "Nebula runs as $unit from $conf${lh:+, as a lighthouse}, with a certificate CA $ca issued"; return 0
  fi
  act "write $conf and the certificate of CA $ca, have nebula -test read them, and run Nebula as $unit${lh:+, as a lighthouse}" || return 0
  new=$d/.sf-new-config.yml
  if ! nebula_same "$cab64" "$d/ca.crt"; then
    [[ -e $d/ca.crt ]] && cp -p "$d/ca.crt" "$d/ca.crt.sf-before" && swapped=1
    printf %s "$cab64" | base64 -d >"$d/ca.crt.new" && chmod 0644 "$d/ca.crt.new" && mv -f "$d/ca.crt.new" "$d/ca.crt" || { conflict "could not write $d/ca.crt"; return 0; }
  fi
  ( umask 077; printf %s "$confb64" | base64 -d >"$new" ) || { rm -f "$new"; conflict "could not write beside $conf"; return 0; }
  if ! out=$("$bin" -test -config "$new" 2>&1); then
    rm -f "$new"; [[ -n $swapped ]] && mv -f "$d/ca.crt.sf-before" "$d/ca.crt"
    conflict "nebula -test refuses the new configuration ($(tail -n 1 <<<"$out")): what was in place is left as it was"; return 0
  fi
  [[ -e $conf ]] && cp -p "$conf" "$conf.sf-before"
  mv -f "$new" "$conf"; durable "$conf" "$d/ca.crt"
  if ! tun_unit_start "$unit" "[Unit]
Description=Nebula, started by StorageForge with a certificate its CA issued
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$bin -config $conf
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target" 1; then
    conflict "Nebula did not stay running: journalctl -u $unit says why"; return 0
  fi
  ok "Nebula runs as $unit from $conf${lh:+, as a lighthouse: others must reach its UDP port, which this step does not open in a firewall}"
}

# OpenZiti. An identity is enrolled once, from a token that works once (a JWT): ziti-edge-tunnel reads the token from a file and
# writes the identity, with the private key it made, to a file the tunneller loads
t_openziti() { local secret=$1 name=$2 state=${3:-present} f d id unit=ziti-edge-tunnel.service bin out
  f=${SF_SECRET_DIR:-/run/storageforge/secrets}/$secret; d=${SF_ZITI_DIR:-/opt/openziti/etc/identities}; id=$d/$name.json
  if [[ $state == absent ]]; then
    [[ -e $id ]] || { ok "no OpenZiti identity named $name is here"; return 0; }
    act "remove $id, which holds the identity and its key, and restart $unit (the tunneller stays installed, and the identity stays defined at the controller until it is deleted there)" || return 0
    rm -f -- "$id"
    if tun_systemd && systemctl is-active --quiet "$unit"; then systemctl restart "$unit" >/dev/null 2>&1 || info "$unit did not restart: journalctl -u $unit says why"; fi
    ok "the identity $name and its key are gone from this host. Delete it at the controller too: until then the controller still knows it"
    return 0
  fi
  bin=$(command -v ziti-edge-tunnel) || { conflict "ziti-edge-tunnel is not installed: install it from the package source OpenZiti gives (get.openziti.io), which this step does not add"; return 0; }
  if [[ -s $id ]]; then
    ok "enrolled already as $name: $id"
    [[ -e $f ]] && rm -f -- "$f" && info "removed the enrollment token file: a token works once"
    if systemctl cat "$unit" >/dev/null 2>&1; then ov_service "$unit" || true; fi
    return 0
  fi
  [[ -r $f ]] || { tun_secret_missing "$f" "$secret" "enrollment token"; return 0; }
  if (($(grep -c "" "$f") != 1)) || ! grep -qxE "[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" "$f"; then
    conflict "the file at $f does not hold an enrollment token: one line of three parts with dots between (a JWT)"; return 0
  fi
  act "ziti-edge-tunnel enroll --jwt $f --identity $id (the token works once), and have $unit load the identity" || return 0
  mkdir -p "$d" || { conflict "could not make $d"; return 0; }
  if ! out=$( umask 077; "$bin" enroll --jwt "$f" --identity "$id" 2>&1 ); then
    rm -f -- "$id"
    conflict "the enrollment failed: $(ov_scrubbed "$f" "$out" | tail -n 2 | tr "\n" " "). A token works once and for a limited time: make another at the controller, and send it again"; return 0
  fi
  [[ -s $id ]] || { rm -f -- "$id"; conflict "ziti-edge-tunnel enroll returned and wrote no identity"; return 0; }
  # the packaged service runs as the user ziti: its group reads the identity, and nobody else does
  if getent group ziti >/dev/null 2>&1 && chgrp ziti "$id" 2>/dev/null; then chmod 0640 "$id"; else chmod 0600 "$id"; fi
  rm -f -- "$f"
  if tun_systemd && systemctl cat "$unit" >/dev/null 2>&1; then
    systemctl enable "$unit" >/dev/null 2>&1 || true
    systemctl restart "$unit" >/dev/null 2>&1 || { conflict "enrolled as $name, and $unit did not restart to load it: journalctl -u $unit says why"; return 0; }
    ok "enrolled as $name, and $unit loads $id. The token file is removed: it works once"
  else
    ok "enrolled as $name: $id. No $unit is here to load it: ziti-edge-tunnel run --identity-dir $d does. The token file is removed: it works once"
  fi
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


def _check_openziti(conn, c, h, p, say):
    if not _secret_ok(p, say):
        return
    if not IDENTITY.fullmatch(p['identity']):
        say('crit', 'an identity name is letters, digits, . _ and -: it names the file the identity is kept in')
        return
    if p['state'] == 'absent':
        say('note', f'removes the identity file {p["identity"]}.json, with its key, and restarts the tunneller. The identity stays defined at the controller until it is deleted there')
        return
    _secret_note(h, p, say, 'enrollment token (the JWT the controller gave for this identity)', 'It works once, and is removed once the identity is enrolled')
    say('note', 'the identity file the enrollment writes holds a private key made on this host: it is readable by root and the group ziti only, and it never leaves the host')
    say('note', 'needs ziti-edge-tunnel installed already. Its service gives names in 100.64.0.0/10 by default, the range Tailscale and NetBird use: '
                'on a host that is on one of them, set ZITI_DNS_IP_RANGE for the service first. Not lab-tested')


# ── Nebula ──
def _nebula_issued(record: dict, host: str, now: float | None = None) -> dict | None:
    """The newest running certificate this CA issued for the host, by the name vault nebula-issue was given or the certificate's own."""
    at = now if now is not None else time.time()
    short = host.split('.')[0].lower()
    mine = [i for i in record.get('issued', []) if not i.get('revoked') and i['not_after'] > at
            and ((i.get('host') or '').lower() in (host.lower(), short) or i['name'].lower() in (host.lower(), short))]
    return max(mine, key=lambda i: i['at']) if mine else None


def _nebula_config(conn, host: str, p: dict) -> str:
    """config.yml for this host from the step's fields. A lighthouse that is in the list every host is given does not name itself."""
    record = overlaykeys.cas(conn).get(p['ca']) or {}
    own = _nebula_issued(record, host)
    known = nebulaca.lighthouses(p['lighthouses'])
    if own:
        known.pop(own['address'].split('/')[0], None)
    return nebulaca.config(lighthouse=bool(p['lighthouse']), lighthouses_text=', '.join(f'{k}={v}' for k, v in known.items()), port=int(p['port']) if p['port'] else None,
                           inbound_text=p['inbound'] or 'icmp', blocklist=overlaykeys.blocklist(conn, p['ca']))


def _nebula_args(conn, t) -> list[str]:
    """The CA certificate and the configuration, in base64: both public, both made now. Empty when they cannot be made, and the
    step then stops and says so."""
    p = t['params']
    record = overlaykeys.cas(conn).get(p['ca']) if overlaykeys.CA_NAME.fullmatch(p['ca']) else None
    if p['state'] == 'absent' or not record:
        return ['', '']
    try:
        text = _nebula_config(conn, t['host'], p)
    except (nebulaca.CertificateError, ValueError):
        return ['', '']
    return [base64.b64encode(record['certificate'].encode()).decode(), base64.b64encode(text.encode()).decode()]


def _check_nebula(conn, c, h, p, say):
    if not overlaykeys.CA_NAME.fullmatch(p['ca']):
        say('crit', 'a CA name is letters, digits, _ and -, up to 32')
        return
    if p['state'] == 'absent':
        say('note', f'stops the Nebula StorageForge started here and removes its configuration, certificates and host key. Nebula stays installed. '
                    f'The certificate is not revoked by this: storageforge-index vault nebula-revoke {p["ca"]} NAME')
        return
    record = overlaykeys.cas(conn).get(p['ca'])
    if not record:
        say('crit', f'there is no Nebula CA named {p["ca"]}: storageforge-index vault nebula-ca {p["ca"]} makes it, with its key in the vault')
        return
    now = time.time()
    if record['not_after'] <= now:
        say('crit', f'the certificate of CA {p["ca"]} ended {time.strftime("%Y-%m-%d", time.gmtime(record["not_after"]))}: no host accepts what it issued')
    elif record['not_after'] - now < 30 * 86400:
        say('warn', f'the certificate of CA {p["ca"]} ends {time.strftime("%Y-%m-%d", time.gmtime(record["not_after"]))}, and every host certificate with it')
    try:
        _nebula_config(conn, h['name'], p)
    except (nebulaca.CertificateError, ValueError) as exc:
        say('crit', str(exc))
    issued = _nebula_issued(record, h['name'], now)
    if issued:
        say('note', f'{h["name"]} has a certificate from CA {p["ca"]} as {issued["name"]} at {issued["address"]}, until {time.strftime("%Y-%m-%d", time.gmtime(issued["not_after"]))}')
    else:
        say('warn', f'no running certificate from CA {p["ca"]} is on record for {h["name"]}: storageforge-index vault nebula-issue {p["ca"]} --host {h["name"]} --address ADDRESS/PREFIX. '
                    'The host makes its own key for it, which never leaves the host. Without a certificate the step stops and says so')
    blocked = overlaykeys.blocklist(conn, p['ca'], now)
    say('note', 'no secret travels: the CA certificate and the configuration are public, and are written into the script when it is made'
                + (f', with the {len(blocked)} revoked certificate(s) this host must refuse' if blocked else '') + '. nebula -test reads the result before Nebula is restarted')
    if p['lighthouse']:
        say('note', f'a lighthouse listens on UDP port {p["port"] or nebulaca.PORT}, which the other hosts must reach: this step opens no firewall')
    say('note', 'needs nebula and nebula-cert installed already. A Nebula that was set up by hand here is left alone. Not lab-tested')


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
changes.register('nebula', {'group': 'Network', 'label': 'Join a Nebula network (not lab-tested)', 'fields': [
    F('ca', 'name', 'Certificate authority (made with vault nebula-ca)', required=True, placeholder='home'),
    F('lighthouse', 'bool', 'This host is a lighthouse'),
    F('lighthouses', 'text', 'Lighthouses: Nebula address = where it is reached', placeholder='10.9.0.1=lh.example.org:4242'),
    F('port', 'number', 'UDP port (4242 for a lighthouse, any free one otherwise)'),
    F('inbound', 'text', 'Allowed in over Nebula (icmp if empty)', placeholder='icmp, tcp/22, tcp/443@web'), STATE],
    'help': 'Writes the Nebula configuration and the CA certificate, checks them with nebula -test and runs Nebula as a unit of its own. The host certificate comes first, '
            'from vault nebula-issue: the host makes its own key, and the CA key signs in the vault. No secret travels. Nebula has to be installed already.'},
    NEBULA_ARGS, lambda p: 'Leave the Nebula network' if p['state'] == 'absent' else f'Join the Nebula network of CA {p.get("ca") or ""}'.rstrip() + (' as a lighthouse' if p.get('lighthouse') else ''),
    _check_nebula, _ansible('t_nebula', NEBULA_ARGS, _nebula_args), args_of=_nebula_args)
changes.register('openziti', {'group': 'Network', 'label': 'Enroll an OpenZiti identity (not lab-tested)', 'fields': [
    F('secret', 'name', 'Enrollment token (a vault secret holding the JWT)', required=True, placeholder='ziti-web-1'),
    F('identity', 'name', 'Identity name', required=True, placeholder='web-1'), STATE],
    'help': 'Enrolls this host as an OpenZiti identity from a one-time token the vault holds. The token reaches the host with vault send-secret and '
            'ziti-edge-tunnel reads it from a file (enroll --jwt FILE), so it is on no command line. The tunneller has to be installed already.'},
    ZITI_ARGS, lambda p: f'{"Remove" if p["state"] == "absent" else "Enroll"} the OpenZiti identity {p.get("identity") or ""}'.rstrip(),
    _check_openziti, _ansible('t_openziti', ZITI_ARGS))
changes.EXTRA_BASH.append(BASH)
