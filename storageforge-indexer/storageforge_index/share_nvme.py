"""NVMe over TCP shares: the kernel's nvmet target on the server, nvme-cli on the one client.

NVMe/TCP exports a block device, not a folder. The server backs it with a sparse file NAME.img in the share's folder, attached to a loop
device (or with a block device the share names instead) and exports it as namespace 1 of the subsystem
nqn.2026-11.org.storageforge:<server>.<name> through configfs. Only the client's host NQN, nqn.2026-11.org.storageforge:host:<client>,
may connect (attr_allow_any_host is 0). configfs is empty after a reboot, so a script StorageForge writes
(/etc/storageforge/nvmet/NAME.sh) rebuilds the configuration, and a oneshot unit storageforge-nvmet-NAME.service runs it at boot.

Client: a unit named like every other share unit connects at boot (nvme connect -t tcp), finds the namespace by its subsystem NQN, makes
a filesystem only when the disk is blank and the mount asks for one, and mounts it by UUID. Stopping the unit unmounts and disconnects.

A block device with an ordinary filesystem must be mounted by one host at a time, so the share allows exactly one client mount.
"""
from __future__ import annotations

import re

from . import netshares
from .moves import host_slug
from .netshares import Driver, Field

NAME = re.compile(r'[a-z0-9][a-z0-9._-]{0,40}')
DEVICE = re.compile(r'/dev/[A-Za-z0-9][A-Za-z0-9._/-]{0,100}')
PREFIX = 'nqn.2026-11.org.storageforge'


def nqn(server: str, name: str) -> str:
    return f'{PREFIX}:{host_slug(server)}.{name}'


BASH = r"""
nvme_nqn() { echo "nqn.2026-11.org.storageforge:$SERVER.$1"; }   # SHARE NAME -> its subsystem NQN
# The two functions below are copied into the boot script of each share (declare -f), so they use no helper of this script and no glob
# (set -f is in force here). NVMET, NQN, DEV, FILE, PORT, ADDR, FAM and HOSTS are variables of the caller.
nvmet_up() {
  local dev=$DEV s p ns h l want
  modprobe nvmet; modprobe nvmet-tcp
  mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
  if [[ -n $FILE ]]; then
    [[ -f $FILE ]] || { echo "$FILE is missing" >&2; return 1; }
    dev=$(losetup -j "$FILE" -O NAME -n | head -n 1)
    [[ -n $dev ]] || dev=$(losetup -f --show "$FILE")
  fi
  [[ -b $dev ]] || { echo "$dev is not a block device" >&2; return 1; }
  s=$NVMET/subsystems/$NQN; ns=$s/namespaces/1; p=$NVMET/ports/$PORT
  [[ -d $s ]] || mkdir "$s"
  echo 0 >"$s/attr_allow_any_host"
  [[ -d $ns ]] || mkdir "$ns"
  if [[ $(cat "$ns/device_path") != "$dev" || $(cat "$ns/enable") != 1 ]]; then
    echo 0 >"$ns/enable" 2>/dev/null || true
    echo "$dev" >"$ns/device_path"
    echo 1 >"$ns/enable"
  fi
  for h in ${HOSTS[@]+"${HOSTS[@]}"}; do
    [[ -d $NVMET/hosts/$h ]] || mkdir "$NVMET/hosts/$h"
    [[ -L $s/allowed_hosts/$h ]] || ln -s "$NVMET/hosts/$h" "$s/allowed_hosts/$h"
  done
  want=" ${HOSTS[*]-} "
  while IFS= read -r l; do
    [[ $want == *" $l "* ]] || rm -f -- "$s/allowed_hosts/$l"
  done < <(find "$s/allowed_hosts" -mindepth 1 -maxdepth 1 -printf "%f\n")
  if [[ ! -d $p ]]; then
    mkdir "$p"
    echo "$ADDR" >"$p/addr_traddr"; echo tcp >"$p/addr_trtype"; echo "$PORT" >"$p/addr_trsvcid"; echo "$FAM" >"$p/addr_adrfam"
  fi
  [[ -L $p/subsystems/$NQN ]] || ln -s "$s" "$p/subsystems/$NQN"
}
nvmet_teardown() { # NQN -> the subsystem, its namespaces, its allowed hosts and its links on the ports gone; a port left with none goes too
  local s=$NVMET/subsystems/$1 l n
  while IFS= read -r l; do
    rm -f -- "$l"; rmdir "${l%/subsystems/*}" 2>/dev/null || true
  done < <(find "$NVMET/ports" -mindepth 3 -maxdepth 3 -type l -name "$1" 2>/dev/null)
  [[ -d $s ]] || return 0
  while IFS= read -r l; do rm -f -- "$s/allowed_hosts/$l"; done < <(find "$s/allowed_hosts" -mindepth 1 -maxdepth 1 -printf "%f\n")
  while IFS= read -r n; do
    echo 0 >"$s/namespaces/$n/enable" 2>/dev/null || true
    rmdir "$s/namespaces/$n"
  done < <(find "$s/namespaces" -mindepth 1 -maxdepth 1 -type d -printf "%f\n")
  rmdir "$s"
}
nvmet_main() { # the end of every boot script: what it does with its first word
  cat <<"EOF"
case ${1:-} in
  up) nvmet_up ;;
  down)
    nvmet_teardown "$NQN" || true
    if [[ -n $FILE ]]; then
      d=$(losetup -j "$FILE" -O NAME -n | head -n 1)
      [[ -z $d ]] || losetup -d "$d" || true
    fi ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
EOF
}
nvmet_ours() { # the StorageForge subsystems of this server that are in configfs now
  find "$NVMET/subsystems" -mindepth 1 -maxdepth 1 -name "nqn.2026-11.org.storageforge:$SERVER.*" -printf "%f\n" 2>/dev/null | sort || true
}
server_nvme() {
  local NVMET=${SF_NVMET_ROOT:-/sys/kernel/config/nvmet} dir=${SF_NVMET_DIR:-/etc/storageforge/nvmet}
  local modconf=${SF_NVMET_MODLOAD:-/etc/modules-load.d/storageforge-nvmet.conf}
  local i j idx=() keep=() scripts=" " want=" " name n file dev size port param unit script body ubody hosts hl h changed addr fam clients f
  mapfile -t idx < <(indices_of NVME)
  for i in ${idx[@]+"${idx[@]}"}; do
    n=$(nvme_nqn "${E_NAME[$i]}"); want+="$n "; keep+=("storageforge-nvmet-${E_NAME[$i]}.service"); scripts+="${E_NAME[$i]}.sh "
  done
  if ((!${#idx[@]})) && ! compgen -G "/etc/systemd/system/storageforge-nvmet-*" >/dev/null && [[ ! -d $dir && ! -e $modconf ]] && [[ -z $(nvmet_ours) ]]; then
    return 0
  fi
  section "NVMe over TCP server (kernel nvmet)"
  if ((${#idx[@]})); then
    if command -v modinfo >/dev/null && ! { modinfo nvmet-tcp >/dev/null 2>&1 || [[ -d /sys/module/nvmet_tcp ]]; }; then
      conflict "this kernel has no nvmet-tcp module: NVMe over TCP needs Linux 5.0 or later built with NVME_TARGET_TCP"; return 0
    fi
    MANAGED_FILES+=("$modconf")
    own_file "$modconf" "nvmet"$'\n'"nvmet-tcp" || true
    if ((APPLY)); then
      modprobe nvmet && modprobe nvmet-tcp || { conflict "could not load the nvmet and nvmet-tcp modules"; return 0; }
      mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config || { conflict "could not mount configfs"; return 0; }
    elif [[ ! -d $NVMET ]]; then missing "the nvmet and nvmet-tcp modules are not loaded"; fi
    addr=$SERVER_ADDR; fam=ipv4
    if [[ $addr == *:* ]]; then fam=ipv6
    elif [[ ! $addr =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then info "$addr is a name, not an address: the port listens on 0.0.0.0, and the firewall rule limits who may reach it"; addr=0.0.0.0; fi
  fi
  for i in ${idx[@]+"${idx[@]}"}; do
    name=${E_NAME[$i]}; n=$(nvme_nqn "$name"); param=${E_PARAM[$i]}; file=; unit=storageforge-nvmet-$name.service; script=$dir/$name.sh
    dev=$(par device "$param"); size=$(par size_gb "$param"); port=$(par port "$param"); port=${port:-4420}
    if [[ -n $dev ]]; then
      if [[ ! -b $dev ]]; then conflict "$dev is not a block device on $(uname -n)"; continue; fi
      if command -v lsblk >/dev/null && [[ -n $(lsblk -nro MOUNTPOINT "$dev" 2>/dev/null | tr -d "[:space:]") ]]; then
        conflict "$dev (or a partition of it) is mounted here: a disk in use cannot also be exported"; continue
      fi
      ok "backing device $dev"
    else
      file=${E_PATH[$i]}/$name.img
      share_dir "${E_PATH[$i]}"
      if [[ -f $file ]]; then
        ok "$file ($(stat -c %s "$file") bytes)"
        [[ $(stat -c %s "$file") -ge $((size * 1073741824)) ]] || info "$file is smaller than the ${size} GB the design asks for: StorageForge never resizes a disk that clients may hold data on"
      elif ((APPLY)); then
        truncate -s "${size}G" "$file" && doing "created $file (${size} GB, sparse: it takes space as it is written)" || { conflict "could not create $file"; continue; }
      else missing "$file (a sparse ${size} GB file)"; fi
    fi
    hosts=(); hl=
    for j in "${!C_PROTO[@]}"; do
      [[ ${C_PROTO[$j]} == NVME && ${C_NAME[$j]} == "$name" ]] || continue
      h="nqn.2026-11.org.storageforge:host:${C_HOST[$j]}"; hosts+=("$h"); hl+=$(printf "%q " "$h")
    done
    body=$(printf "NVMET=%q\nNQN=%q\nDEV=%q\nFILE=%q\nPORT=%q\nADDR=%q\nFAM=%q\nHOSTS=(%s)\n" "$NVMET" "$n" "$dev" "$file" "$port" "$addr" "$fam" "$hl")
    body="#!/bin/bash"$'\n'"# Written by StorageForge: puts the NVMe over TCP subsystem $n back in configfs, which a reboot empties. Run by $unit."$'\n'"set -eu"$'\n'"$body"$'\n'"$(declare -f nvmet_up nvmet_teardown)"$'\n'"$(nvmet_main)"
    ubody="# Written by StorageForge: the NVMe over TCP share $name of $SERVER.
[Unit]
Description=StorageForge NVMe over TCP share $name: export $n
Wants=network-online.target
After=network-online.target${file:+
RequiresMountsFor=${E_PATH[$i]}}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash \"$script\" up
ExecStop=/bin/bash \"$script\" down

[Install]
WantedBy=multi-user.target"
    MANAGED_FILES+=("$script")
    changed=0
    own_file "$script" "$body" && changed=1
    unit_file "$unit" "$ubody" && changed=1
    if ((APPLY)); then
      if systemctl is-active -q "$unit"; then
        ((changed)) && { systemctl restart "$unit" || conflict "could not restart $unit: journalctl -u $unit"; }
      else systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "$unit did not start: journalctl -u $unit"; fi
    fi
    if [[ -d $NVMET/subsystems/$n/allowed_hosts && -L $NVMET/ports/$port/subsystems/$n ]]; then ok "$n is exported on port $port"
    elif ((!APPLY)); then missing "$n is not exported yet"
    else conflict "$n is not in configfs after $unit started: journalctl -u $unit"; fi
    clients=$(printf "%s " "${E_CLIENTS[$i]}")
    open_port "NVMe over TCP $name" "$port/tcp" "$clients"
  done
  # What StorageForge made for shares the design no longer has: units (their stop takes the export down), anything still in
  # configfs under this server NQN prefix, and the scripts. Subsystems of anyone else are never looked at.
  drop_units storageforge-nvmet- ${keep[@]+"${keep[@]}"}
  while IFS= read -r n; do
    [[ -n $n && $want != *" $n "* ]] || continue
    if ((APPLY)); then nvmet_teardown "$n" && doing "removed the subsystem $n" || conflict "could not remove the subsystem $n"
    else missing "would remove the subsystem $n"; fi
  done < <(nvmet_ours)
  while IFS= read -r f; do
    [[ -n $f && $scripts != *" $f "* ]] || continue
    if ((APPLY)); then rm -f -- "$dir/$f"; doing "removed $dir/$f"; else missing "would remove $dir/$f"; fi
  done < <(find "$dir" -maxdepth 1 -name "*.sh" -printf "%f\n" 2>/dev/null | sort)
  if ((!${#idx[@]})) && [[ -e $modconf ]]; then
    if ((APPLY)); then backup "$modconf"; rm -f -- "$modconf"; doing "removed $modconf"; else missing "would remove $modconf"; fi
  fi
  return 0
}
nvme_client_sh() { # the part of a client script that does not depend on the mount
  cat <<"EOF"
dev_of() { # the namespace of the subsystem NQN
  local s d
  for s in /sys/class/nvme-subsystem/nvme-subsys*; do
    [[ -r $s/subsysnqn && $(cat "$s/subsysnqn") == "$NQN" ]] || continue
    for d in "$s"/nvme*n*; do [[ -e $d ]] && { echo "/dev/${d##*/}"; return 0; }; done
  done
  return 1
}
start() {
  local dev= uuid n rc
  modprobe nvme-tcp 2>/dev/null
  if ! dev_of >/dev/null; then nvme connect -t tcp -a "$ADDR" -s "$PORT" -n "$NQN" || return 1; fi
  for n in $(seq 1 30); do dev=$(dev_of) && break; sleep 1; done
  [[ -b $dev ]] || { echo "no namespace for $NQN after connecting" >&2; return 1; }
  udevadm settle 2>/dev/null || true
  rc=0; blkid -p "$dev" >/dev/null 2>&1 || rc=$?
  if ((rc == 2)); then       # blkid sees nothing at all on it: only then is it blank
    if [[ $FORMAT != none ]]; then "mkfs.$FORMAT" "$dev" || return 1; udevadm settle 2>/dev/null || true; fi
  elif ((rc != 0)); then echo "blkid could not read $dev (status $rc): not formatting it" >&2; return 1; fi
  uuid=$(blkid -p -o value -s UUID "$dev" 2>/dev/null) || uuid=
  [[ -n $uuid ]] || { echo "$dev holds no filesystem: choose a format for the mount, or make one by hand" >&2; return 1; }
  mkdir -p "$TARGET"
  mountpoint -q "$TARGET" || mount ${OPTS:+-o "$OPTS"} "UUID=$uuid" "$TARGET"
}
stop() {
  if mountpoint -q "$TARGET"; then umount "$TARGET" || return 1; fi
  nvme disconnect -n "$NQN" >/dev/null 2>&1 || true
  return 0
}
case ${1:-} in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
EOF
}
nvme_script() { echo "${SF_NVME_DIR:-/etc/storageforge/nvme}/$SERVER/$(share_unit "$1" | tr -c "A-Za-z0-9_.\n-" _).sh"; }   # TARGET -> its client script
client_nvme() {
  local i=$1 t=${C_TARGET[$1]} n port fmt unit script hostnqn cur body ubody changed=0 etc=${SF_NVME_ETC:-/etc/nvme}
  n=$(nvme_nqn "${C_NAME[$i]}"); port=$(par port "${C_PARAM[$i]}"); fmt=$(par format "${C_PARAM[$i]}")
  unit=$(share_unit "$t").service; script=$(nvme_script "$t"); hostnqn=nqn.2026-11.org.storageforge:host:$ME
  section "mount ${C_SOURCE[$i]} at $t (NVMe over TCP)"
  need_cmd nvme "NVMe tools" nvme-cli nvme-cli nvme-cli nvme-cli || return 0
  if command -v modinfo >/dev/null && ! { modinfo nvme-tcp >/dev/null 2>&1 || [[ -d /sys/module/nvme_tcp ]]; }; then
    conflict "this kernel has no nvme-tcp module: NVMe over TCP needs Linux 5.0 or later built with NVME_TCP"; return 0
  fi
  # The server lets in only this name, so a hostnqn another tool made is never overwritten: that is for the operator to decide.
  cur=$(head -n 1 "$etc/hostnqn" 2>/dev/null || true)
  if [[ $cur == "$hostnqn" ]]; then ok "$etc/hostnqn is $hostnqn"
  elif [[ -z $cur || $cur == nqn.2026-11.org.storageforge:host:* ]]; then
    if ((APPLY)); then mkdir -p "$etc" && printf "%s\n" "$hostnqn" >"$etc/hostnqn" && durable "$etc/hostnqn" && doing "wrote $etc/hostnqn ($hostnqn)"
    else missing "$etc/hostnqn ($hostnqn)"; fi
  else conflict "$etc/hostnqn holds $cur, which StorageForge did not write, and $SERVER only lets $hostnqn in: remove that file (or replace its line) and deploy again"; return 0; fi
  own_file "${SF_NVME_MODLOAD:-/etc/modules-load.d/storageforge-nvme-tcp.conf}" "nvme-tcp" || true
  if [[ $fmt != none && -n $fmt ]] && ! command -v "mkfs.$fmt" >/dev/null; then
    if ((APPLY)); then conflict "mkfs.$fmt is not installed: install $([[ $fmt == xfs ]] && echo xfsprogs || echo e2fsprogs)"; return 0
    else missing "mkfs.$fmt (install $([[ $fmt == xfs ]] && echo xfsprogs || echo e2fsprogs))"; fi
  fi
  body=$(printf "NQN=%q\nADDR=%q\nPORT=%q\nFORMAT=%q\nTARGET=%q\nOPTS=%q\n" "$n" "$SERVER_ADDR" "${port:-4420}" "${fmt:-none}" "$t" "${C_OPTS[$i]}")
  body="#!/bin/bash"$'\n'"# Written by StorageForge: connects $n from $SERVER_ADDR and mounts it at $t. Run by $unit."$'\n'"set -u"$'\n'"$body"$'\n'"$(nvme_client_sh)"
  ubody="# Written by StorageForge: the NVMe over TCP share ${C_NAME[$i]} of $SERVER at $t.
[Unit]
Description=StorageForge NVMe over TCP share ${C_NAME[$i]} of $SERVER at $t
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=90
ExecStart=/bin/bash \"$script\" start
ExecStop=/bin/bash \"$script\" stop
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target"
  own_file "$script" "$body" && changed=1
  unit_file "$unit" "$ubody" && changed=1
  if ((APPLY)); then
    if systemctl is-active -q "$unit"; then
      ((changed)) && { systemctl restart "$unit" 2>/dev/null || true; }
    else systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "$unit did not start: journalctl -u $unit"; fi
  fi
  if timeout -k 2 10 mountpoint -q "$t"; then ok "mounted"
  elif ((APPLY)); then conflict "$t is not mounted: journalctl -u $unit"
  else missing "not mounted"; fi
}
cleanup_nvme() { # subsystems of this server that no mount here uses are disconnected, and the scripts of dropped mounts removed
  local i want=" " keep=" " s n f sys=${SF_NVME_SYS:-/sys/class/nvme-subsystem} dir=${SF_NVME_DIR:-/etc/storageforge/nvme}/$SERVER
  for i in "${!C_HOST[@]}"; do
    [[ ${C_HOST[$i]} == "$ME" && ${C_PROTO[$i]} == NVME ]] || continue
    want+="$(nvme_nqn "${C_NAME[$i]}") "; keep+="$(basename "$(nvme_script "${C_TARGET[$i]}")") "
  done
  [[ -d $sys || -d $dir ]] || return 0
  section "NVMe over TCP subsystems of $SERVER no mount uses"
  local found=0
  while IFS= read -r s; do
    n=$(cat "$s/subsysnqn" 2>/dev/null || true)
    [[ $n == "nqn.2026-11.org.storageforge:$SERVER."* && $want != *" $n "* ]] || continue
    found=1
    if ((!APPLY)); then missing "would disconnect $n"
    elif nvme disconnect -n "$n" >/dev/null 2>&1; then doing "disconnected $n"
    else conflict "could not disconnect $n (is it mounted?)"; fi
  done < <(find "$sys" -mindepth 1 -maxdepth 1 -name "nvme-subsys*" 2>/dev/null | sort)
  while IFS= read -r f; do
    [[ -n $f && $keep != *" $f "* ]] || continue
    found=1
    if ((APPLY)); then rm -f -- "$dir/$f"; doing "removed $dir/$f"; else missing "would remove $dir/$f"; fi
  done < <(find "$dir" -maxdepth 1 -name "*.sh" -printf "%f\n" 2>/dev/null | sort)
  ((found)) || ok "nothing to remove"
  return 0
}
"""


class Nvme(Driver):
    def normalize(self, s: dict) -> dict:
        out = netshares.clean(self.fields, s)
        if out.get('device') and not DEVICE.fullmatch(out['device']):
            raise ValueError('the block device is a path under /dev, such as /dev/sdb or /dev/vg0/lv-nvme')
        if out.get('device') and '..' in out['device']:
            raise ValueError('the block device is a path under /dev, such as /dev/sdb or /dev/vg0/lv-nvme')
        if out.get('device') and out.get('size_gb'):
            raise ValueError('give either a size (a file in the share folder) or a block device, not both')
        return out

    def check(self, conn, hs, srv, e, say):
        st = e.get('settings') or {}
        if not NAME.fullmatch(e['name'] or ''):
            say('crit', 'an NVMe over TCP share needs a name of lowercase letters, digits, . _ - (it is part of the subsystem name)')
        if not st.get('size_gb') and not st.get('device'):
            say('crit', 'set the size of the disk in GB (a file in the share folder) or a block device on the server to export')
        elif st.get('size_gb') and re.search(r'\s', e['path'] or ''):
            say('crit', f'{e["path"]} has a space in it: the disk file lives there, so use a folder without spaces')
        n = len(e.get('mounts') or [])
        if n > 1:
            say('crit', 'a block device is shared with one client at a time: two hosts mounting an ordinary filesystem on it corrupt it. '
                        'Keep one client mount, or use NFS or SMB to share files')
        elif n == 0:
            say('crit', 'name the one client that connects: only its NVMe host name is let in')
        if st.get('device'):
            say('note', f'{st["device"]} on {srv["name"]} is exported whole: whatever is on it is what the client sees, and it must not be mounted on the server')
        elif st.get('size_gb'):
            say('note', f'the disk is a sparse {st["size_gb"]} GB file, {e["path"]}/{e["name"]}.img, which takes space as the client writes')
        say('note', 'the kernel target (nvmet-tcp) needs Linux 5.0 or later on the server, and nvme-tcp on the client; '
                    'the deploy loads the modules and keeps them loaded at boot')
        say('warn', 'NVMe over TCP has no password or encryption here: the only check is the client host NQN, which anyone who knows it can claim. '
                    'Keep it on a trusted network or VLAN')
        if not (e.get('clients') or '').strip():
            say('note', 'no client addresses: the firewall port is opened to any source')

    def check_mount(self, conn, srv, e, mt, ch, say):
        st = mt.get('settings') or {}
        who = f'{ch["name"]}:{mt["path"]}'
        say('note', f'{who} connects as {PREFIX}:host:{host_slug(ch["name"])}, set in /etc/nvme/hostnqn')
        if (st.get('format') or 'none') == 'none':
            say('note', f'{who}: no format chosen, so the disk must already hold a filesystem; choose ext4 or xfs to make one on a blank disk')
        else:
            say('note', f'{who}: a {st["format"]} filesystem is made only if the disk shows no signature at all')

    def server_params(self, e, srv, hs):
        st = e.get('settings') or {}
        return {'size_gb': st.get('size_gb') or '', 'device': st.get('device') or '', 'port': st.get('port') or 4420}

    def client_params(self, e, mt, srv, hs):
        return {'port': (e.get('settings') or {}).get('port') or 4420, 'format': (mt.get('settings') or {}).get('format') or 'none'}

    def client_source(self, e, address):
        return f'nvme-tcp://{address}/{e["name"]}'


netshares.register(Nvme(
    key='NVME', label='NVMe over TCP',
    help='The kernel NVMe target exports a disk (a file in the share folder, or a block device) to one client, which mounts it as a local disk. One client only; no password.',
    clients_label='Client addresses', clients_help='Addresses or subnets the firewall port is opened to. The one client that connects is the mount below.',
    fields=[Field('size_gb', 'int', 'Disk size (GB)', 'The disk is a sparse file NAME.img in the share folder. Leave empty to export a block device instead.',
                  options=(1, 1048576), placeholder='100'),
            Field('device', 'path', 'Block device instead', 'A disk or logical volume on the server that nothing mounts, such as /dev/vg0/nvme.', placeholder='/dev/vg0/nvme'),
            Field('port', 'int', 'TCP port', 'NVMe over TCP is 4420.', default=4420, options=(1, 65535))],
    mount_fields=[Field('format', 'choice', 'Make a filesystem', 'Only when the disk is blank. none expects a filesystem already on it.',
                        options=('none', 'ext4', 'xfs'), default='none')],
    needs_client='NVMe tools', bash=BASH))
