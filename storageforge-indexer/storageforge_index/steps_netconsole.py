"""The netconsole plan step: a host's kernel sends its messages over UDP to the controller's netconsole receiver (netconsole.py, roadmap
section 3, phase 5), so a panic or a hard hang is seen when nothing in user space is left to say it.

What it writes, and nothing else:

    /etc/modprobe.d/storageforge-netconsole.conf     options netconsole netconsole=+<sport>@<src>/<dev>,<port>@<target>/<next hop MAC>
    /etc/modules-load.d/storageforge-netconsole.conf netconsole, so it starts at boot
    /sys/kernel/config/netconsole/storageforge       the same target now, when netconsole was loaded already and configfs has it

The interface, the host's own address on it and the MAC address of the next hop are worked out on the host from `ip route get` to the
target, since netconsole sends from the driver and does no routing or address lookup of its own. `+` asks for the extended format,
which carries each message's level. When netconsole is not loaded yet it is loaded with these settings, and the way back unloads it.

The way back is the same step with "absent": the configfs target is turned off and removed, both files are deleted, and netconsole is
unloaded if this step loaded it. Nothing else on the host changes: the console log level is said, never set.

Nothing here is secret. What reaches the controller is plain UDP, unsigned (docs/security.md).
"""
from __future__ import annotations

import ipaddress
import re
import shlex

from . import changes, netconsole
from .changes import F

changes.CHECKS.setdefault('ipv4', re.compile(r'(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}'))
ARGS = ('target', 'port', 'source_port', 'interface', 'state')

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
# ── netconsole: kernel messages over UDP to the controller (netconsole.py) ──
nc_field() { awk -v k="$1" '{ for (i = 1; i < NF; i++) if ($i == k) { print $(i + 1); exit } }'; }
# Whether the configfs target StorageForge makes is there, on and with these settings: the one way to read what is running.
nc_target_matches() {
  [[ -d $cfs && $(cat "$cfs/enabled" 2>/dev/null || true) == 1 && $(cat "$cfs/dev_name" 2>/dev/null || true) == "$dev" \
     && $(cat "$cfs/remote_ip" 2>/dev/null || true) == "$target" && $(cat "$cfs/remote_port" 2>/dev/null || true) == "$port" \
     && $(cat "$cfs/local_port" 2>/dev/null || true) == "$sport" && $(cat "$cfs/local_ip" 2>/dev/null || true) == "$src" \
     && $(cat "$cfs/remote_mac" 2>/dev/null || true) == "$mac" ]]
}
t_netconsole() { local target=$1 port=${2:-6666} sport=${3:-6665} dev=${4:-} state=${5:-present}
  local root=${NC_ROOT:-} cfs bk boot mp ml want route src via hop mac before level f did=
  cfs=$root/sys/kernel/config/netconsole/storageforge; bk=$root/etc/storageforge/netconsole
  boot=$root/run/storageforge/netconsole-loaded     # in /run, so a reboot clears it: the module is then not ours any more
  mp=$root/etc/modprobe.d/storageforge-netconsole.conf; ml=$root/etc/modules-load.d/storageforge-netconsole.conf
  if [[ $state == absent ]]; then
    if [[ -d $cfs ]]; then
      act "turn off and remove the netconsole target StorageForge made" || return 0
      echo 0 >"$cfs/enabled" 2>/dev/null || true; rmdir "$cfs" 2>/dev/null || true; did=1
    fi
    for f in "$mp" "$ml"; do
      if [[ -e $f ]]; then act "remove $f" || return 0; rm -f "$f"; did=1; fi
    done
    if [[ -e $bk/loaded ]]; then
      act "unload netconsole, which this step loaded" || return 0
      modprobe -r netconsole 2>/dev/null || info "netconsole stays loaded until the next reboot"; rm -f "$bk/loaded"; did=1
    fi
    if [[ -n $did ]]; then ok "netconsole from StorageForge is off: kernel messages are no longer sent to the controller"
    else ok "netconsole is not set up by StorageForge here"; fi
    return 0
  fi
  modinfo netconsole >/dev/null 2>&1 || [[ -d $root/sys/module/netconsole ]] || { conflict "this kernel has no netconsole module"; return 0; }
  route=$(ip -4 route get "$target" 2>/dev/null | head -n 1 || true)
  [[ -n $route ]] || { conflict "there is no route from here to $target"; return 0; }
  [[ -n $dev ]] || dev=$(nc_field dev <<<"$route")
  src=$(nc_field src <<<"$route"); via=$(nc_field via <<<"$route"); hop=${via:-$target}
  [[ -n $dev && -n $src ]] || { conflict "could not tell which interface and address reach $target"; return 0; }
  mac=$(ip neigh show "$hop" dev "$dev" 2>/dev/null | nc_field lladdr || true)
  if [[ -z $mac ]]; then
    ping -c 1 -W 1 "$hop" >/dev/null 2>&1 || true
    mac=$(ip neigh show "$hop" dev "$dev" 2>/dev/null | nc_field lladdr || true)
  fi
  [[ $mac =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || { conflict "could not find the MAC address of $hop on $dev, which netconsole has to send to"; return 0; }
  want="options netconsole netconsole=+$sport@$src/$dev,$port@$target/$mac"
  before=$(cat "$mp" 2>/dev/null || true)
  if [[ $before == "$want" && $(cat "$ml" 2>/dev/null || true) == netconsole ]]; then
    ok "netconsole starts at boot, sending to $target port $port"
  else
    act "netconsole at boot: to $target port $port from $src port $sport on $dev, next hop $mac" || return 0
    mkdir -p "${mp%/*}" "${ml%/*}"; printf "%s\n" "$want" >"$mp"; printf "netconsole\n" >"$ml"; durable "$mp" "$ml"
  fi
  if [[ ! -d $root/sys/module/netconsole ]]; then
    act "load netconsole now" || return 0
    modprobe netconsole 2>/dev/null || { conflict "modprobe netconsole failed: the settings start at the next reboot"; return 0; }
    mkdir -p "$bk" "${boot%/*}"; : >"$bk/loaded"; : >"$boot"
    ok "netconsole is loaded and sending to $target port $port"
  elif nc_target_matches || [[ $before == "$want" && -e $boot ]]; then
    ok "netconsole is loaded with these settings"
  else
    [[ -d $root/sys/kernel/config/netconsole ]] || mount -t configfs none "$root/sys/kernel/config" 2>/dev/null || true
    if [[ -d $root/sys/kernel/config/netconsole ]]; then
      act "send through netconsole now, with a target of its own in configfs" || return 0
      [[ -d $cfs ]] && { echo 0 >"$cfs/enabled" 2>/dev/null || true; }
      mkdir -p "$cfs" || { conflict "could not make a netconsole target in configfs"; return 0; }
      printf "%s" "$dev" >"$cfs/dev_name"; printf "%s" "$sport" >"$cfs/local_port"; printf "%s" "$port" >"$cfs/remote_port"
      printf "%s" "$src" >"$cfs/local_ip"; printf "%s" "$target" >"$cfs/remote_ip"; printf "%s" "$mac" >"$cfs/remote_mac"
      echo 1 >"$cfs/extended" 2>/dev/null || info "this kernel sends the plain format: lines come without their level"
      echo 1 >"$cfs/enabled" 2>/dev/null || { conflict "the kernel refused the netconsole target"; return 0; }
      [[ -n $before ]] && info "the settings netconsole was loaded with before go on sending until the next reboot"
      ok "netconsole is sending to $target port $port"
    else
      conflict "netconsole is loaded already, with other settings, and this kernel has no configfs for it: the new settings start at the next reboot"
      return 0
    fi
  fi
  level=$(cut -f1 "$root/proc/sys/kernel/printk" 2>/dev/null || true)
  [[ -n $level ]] && info "the console log level here is $level: netconsole sends what is more urgent than that, and panics and oopses always"
  if ((APPLY)); then printf "<3>storageforge: netconsole check from %s\n" "$(hostname 2>/dev/null || echo this host)" >"$root/dev/kmsg" 2>/dev/null || true; fi
  return 0
}
"""


def _port(v, what: str, say) -> bool:
    if not str(v).isdigit() or not 0 < int(v) < 65536:
        say('crit', f'{what} is a port, from 1 to 65535')
        return False
    return True


def _check(conn, c, h, p, say):
    try:
        target = ipaddress.ip_address(p['target'])
    except ValueError:
        say('crit', 'the target is the IPv4 address the controller is reached at from this host')
        return
    if target.is_loopback or target.is_unspecified or target.is_multicast:
        say('crit', f'{target} cannot be where netconsole sends: give the controller\'s address as this host reaches it')
    ok = _port(p['port'] or netconsole.DEFAULT_PORT, 'The controller port', say) & _port(p['source_port'] or netconsole.DEFAULT_SOURCE_PORT, 'The source port', say)
    if p['state'] == 'absent':
        say('note', 'removes the netconsole target and the two files StorageForge wrote, and unloads netconsole if this step loaded it')
        return
    if not ok:
        return
    sport = int(p['source_port'] or netconsole.DEFAULT_SOURCE_PORT)
    src = next((s for s in netconsole.sources(conn) if s['host'].lower() == h['name'].lower()), None)
    if not src:
        say('warn', f'the controller takes netconsole packets only from a known address and port: add {h["name"]} under Logs, Netconsole, with port {sport}, or what it sends is dropped')
    elif src['port'] != sport:
        say('warn', f'the controller expects {h["name"]} to send from port {src["port"]}, and this sends from {sport}')
    elif not src['enabled']:
        say('warn', f'{h["name"]} is turned off under Logs, Netconsole: what it sends is dropped')
    if not netconsole.listen_address():
        say('warn', 'the controller does not listen for netconsole now: set STORAGEFORGE_NETCONSOLE_LISTEN, such as 0.0.0.0:6666, and restart it')
    say('note', 'the interface, the address and the next hop are worked out on the host from its route to the target. It starts at boot, and now')
    say('note', 'netconsole is plain UDP with no signature: a line that comes this way says something sent it from this host\'s address, not that the host did')


def _title(p) -> str:
    if p['state'] == 'absent':
        return 'Stop sending kernel messages over netconsole'
    return f'Send kernel messages to {p["target"]} port {p["port"] or netconsole.DEFAULT_PORT} over netconsole'


def _ansible(t, conn=None):
    q = shlex.quote
    p = t['params']
    head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
            'act() { echo "changed: $*"; }; durable() { sync; }\n')
    words = [p['target'], p['port'] or str(netconsole.DEFAULT_PORT), p['source_port'] or str(netconsole.DEFAULT_SOURCE_PORT), p['interface'] or '', p['state'] or 'present']
    return changes.shell_task(t, head + BASH + '\nt_netconsole ' + ' '.join(q(w) for w in words) + '\n')


changes.register('netconsole', {'group': 'Monitoring', 'label': 'Send kernel messages to the controller (netconsole)', 'fields': [
    F('target', 'ipv4', 'Controller address, as this host reaches it', required=True, placeholder='10.42.0.10'),
    F('port', 'number', 'Controller port', placeholder=str(netconsole.DEFAULT_PORT)),
    F('source_port', 'number', 'Port to send from', placeholder=str(netconsole.DEFAULT_SOURCE_PORT)),
    F('interface', 'name', 'Interface (empty: the one the route takes)', placeholder='eth0'),
    F('state', 'choice', 'Send or stop', options=['present', 'absent'], default='present')],
    'help': 'Sets netconsole up to start at boot and now, so panics and hangs reach the controller when the host cannot say anything else. '
            'Plain UDP, unsigned: add the host under Logs, Netconsole so the controller takes what it sends. Stopping removes all of it.'},
    ARGS, _title, _check, _ansible)
changes.EXTRA_BASH.append(BASH)
