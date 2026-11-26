"""NBD shares: a disk image on the server, exported by nbd-server, and attached as a block device on one client.

Server: a sparse backing file NAME.img in the share's folder (made only when missing; a bigger size grows it, a smaller one is refused).
StorageForge's export lives in its own file, /etc/nbd-server/conf.d/storageforge-NAME.conf, with an authfile
(/etc/nbd-server/storageforge-NAME.allow) that lets only the addresses of the client mounts in. The main config gets one line,
`includedir = /etc/nbd-server/conf.d`, after a backup, when it lacks it. TLS is optional: certificate, key and CA paths on the server.
nbd-server has no accounts and no passwords: the address allow-list is the only thing that decides who connects, which the check says.

Client: nbd-client attaches the export to a /dev/nbdN that StorageForge picks once and records, a unit
(storageforge-share-SERVER.<target>.service) runs a small helper of StorageForge to connect, format when the disk holds nothing,
mount by UUID, and on stop unmount and disconnect. A block device with an ordinary filesystem must have one writer, so a share
with more than one client mount is refused by the check.
"""
from __future__ import annotations

import ipaddress
import re

from . import netshares
from .netshares import Driver, Field

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,40}')
PATH = re.compile(r'/[A-Za-z0-9_./@+=,:-]{1,300}')
MAX_GB = 1048576

BASH = r"""
NBD_DIR=${SF_NBD_DIR:-/etc/nbd-server}
NBD_CONF=$NBD_DIR/config
NBD_CONFD=$NBD_DIR/conf.d
NBD_CDIR=${SF_NBD_CLIENT_DIR:-/etc/storageforge/nbd}
NBD_STATE=${SF_NBD_STATE:-/var/lib/storageforge/nbd}
NBD_MODLOAD=${SF_NBD_MODLOAD:-/etc/modules-load.d/storageforge-nbd.conf}
NBD_RESTART=0
NBD_CLAIMED=""
nbd_include() { # the main config includes conf.d, where StorageForge keeps its exports
  local line done=0 tmp
  if [[ ! -e $NBD_CONF ]]; then
    own_file "$NBD_CONF" "# Written by StorageForge: nbd-server had no config. Its exports are in $NBD_CONFD.
[generic]
    includedir = $NBD_CONFD" && NBD_RESTART=1
    return 0
  fi
  if grep -qsE "^[[:space:]]*includedir[[:space:]]*=[[:space:]]*$NBD_CONFD/?[[:space:]]*$" "$NBD_CONF"; then ok "$NBD_CONF includes $NBD_CONFD"; return 0; fi
  if grep -qsE "^[[:space:]]*includedir" "$NBD_CONF"; then
    conflict "$NBD_CONF includes another folder than $NBD_CONFD: add includedir = $NBD_CONFD there, or move the include"; return 1
  fi
  if ((!APPLY)); then missing "includedir = $NBD_CONFD in $NBD_CONF (added once, after a backup)"; return 0; fi
  backup "$NBD_CONF"; tmp=$NBD_CONF.storageforge-new
  if grep -qiE "^[[:space:]]*\[generic\][[:space:]]*$" "$NBD_CONF"; then
    while IFS= read -r line || [[ -n $line ]]; do
      printf "%s\n" "$line"
      if ((!done)) && [[ $line =~ ^[[:space:]]*\[[Gg][Ee][Nn][Ee][Rr][Ii][Cc]\][[:space:]]*$ ]]; then printf "    includedir = %s\n" "$NBD_CONFD"; done=1; fi
    done <"$NBD_CONF" >"$tmp"
  else
    { printf "[generic]\n    includedir = %s\n\n" "$NBD_CONFD"; cat "$NBD_CONF"; } >"$tmp"
  fi
  if durable "$tmp" && mv -f -- "$tmp" "$NBD_CONF"; then durable "$NBD_CONF"; doing "added includedir = $NBD_CONFD to $NBD_CONF (backup: $NBD_CONF.storageforge-$STAMP)"; NBD_RESTART=1
  else rm -f -- "$tmp"; conflict "could not add includedir to $NBD_CONF"; return 1; fi
}
nbd_prune() { # KEEP-FILE-NAMES... -> StorageForge exports and allow-lists no share of the design owns any more
  local f keep=" $* "
  while IFS= read -r f; do
    [[ -n $f && $keep != *" ${f##*/} "* ]] || continue
    if ((APPLY)); then backup "$f"; rm -f -- "$f"; doing "removed $f"; NBD_RESTART=1; else missing "would remove $f"; fi
  done < <({ find "$NBD_CONFD" -maxdepth 1 -type f -name "storageforge-*.conf" 2>/dev/null; find "$NBD_DIR" -maxdepth 1 -type f -name "storageforge-*.allow" 2>/dev/null; } | sort)
  return 0
}
nbd_image() { # PATH SIZE_GB -> the backing file: made sparse when missing, grown when smaller, never shrunk
  local img=$1 gb=$2 want have user group
  want=$((gb * 1024 * 1024 * 1024))
  if [[ -e $img ]]; then
    have=$(stat -c %s -- "$img")
    if ((have == want)); then ok "$img is $gb GB"
    elif ((have > want)); then conflict "$img is $((have / 1024 / 1024 / 1024)) GB and the design says $gb GB: StorageForge never shrinks a disk image (that would cut off data); set the size back, or shrink it yourself"
    elif ((APPLY)); then truncate -s "$want" -- "$img" && doing "grew $img to $gb GB; the filesystem on it grows when the client runs resize2fs or xfs_growfs" || conflict "could not grow $img"
    else missing "$img would grow from $((have / 1024 / 1024 / 1024)) GB to $gb GB"; fi
  elif ((APPLY)); then truncate -s "$want" -- "$img" && doing "created $img, $gb GB, sparse" || { conflict "could not create $img"; return 0; }
  else missing "$img (would be created: $gb GB, sparse)"; fi
  if ((APPLY)) && [[ -e $img ]]; then
    user=$(grep -E "^[[:space:]]*user[[:space:]]*=" "$NBD_CONF" 2>/dev/null | head -n 1 | cut -d= -f2 | tr -d " \t" || true)
    group=$(grep -E "^[[:space:]]*group[[:space:]]*=" "$NBD_CONF" 2>/dev/null | head -n 1 | cut -d= -f2 | tr -d " \t" || true)
    if [[ -n $user ]] && id -u "$user" >/dev/null 2>&1; then
      chown "$user:${group:-$user}" -- "$img" 2>/dev/null || chown "$user" -- "$img" || true; chmod 0660 -- "$img"
    else chmod 0600 -- "$img"; fi
  fi
  return 0
}
server_nbd() {
  local i idx=() keep=() name img size allow cert key ca body unit active=0 conf allowf extra
  mapfile -t idx < <(indices_of NBD)
  if ((!${#idx[@]})); then
    compgen -G "$NBD_CONFD/storageforge-*" >/dev/null || compgen -G "$NBD_DIR/storageforge-*" >/dev/null || return 0
    section "NBD server"; nbd_prune
    if ((NBD_RESTART && APPLY)); then unit=$(unit_of nbd-server nbd) || true; systemctl is-active -q "$unit" && { systemctl restart "$unit" && doing "restarted $unit" || conflict "could not restart $unit"; }; fi
    return 0
  fi
  section "NBD server (nbd-server)"
  need_cmd nbd-server "NBD server" nbd-server nbd nbd nbd || return 0
  nbd_include || true
  ((APPLY)) && mkdir -p -- "$NBD_CONFD"
  for i in "${idx[@]}"; do
    name=${E_NAME[$i]}; size=$(par size_gb "${E_PARAM[$i]}"); allow=$(par allow "${E_PARAM[$i]}")
    cert=$(par tls_cert "${E_PARAM[$i]}"); key=$(par tls_key "${E_PARAM[$i]}"); ca=$(par tls_ca "${E_PARAM[$i]}")
    if [[ ! $name =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ || ! $size =~ ^[0-9]+$ ]]; then conflict "NBD share $name: needs a name of letters, digits, _ - and a size in GB"; continue; fi
    if [[ -z $allow ]]; then conflict "NBD share $name: no client address to allow in: nbd-server has no logins, so without addresses anyone could connect"; continue; fi
    img=${E_PATH[$i]}/$name.img; conf=$NBD_CONFD/storageforge-$name.conf; allowf=$NBD_DIR/storageforge-$name.allow
    keep+=("storageforge-$name.conf" "storageforge-$name.allow")
    if [[ -n $cert ]]; then
      if [[ ! -r $cert || ! -r $key ]] || [[ -n $ca && ! -r $ca ]]; then
        conflict "NBD share $name: the TLS files ($cert, $key${ca:+, $ca}) are not all on this host: put them there, StorageForge does not make certificates"; continue
      fi
    fi
    [[ -d ${E_PATH[$i]} ]] && ok "${E_PATH[$i]} exists" || { if ((APPLY)); then doing "mkdir -p ${E_PATH[$i]}"; mkdir -p -- "${E_PATH[$i]}"; else missing "${E_PATH[$i]}"; fi; }
    nbd_image "$img" "$size"
    extra=""
    [[ -n $cert ]] && extra="
certfile = $cert
keyfile = $key
force_tls = true"
    [[ -n $ca ]] && extra+="
cacertfile = $ca"
    body="# StorageForge NBD export $name. Written by shares-$SERVER.sh; edit the design, not this file.
[$name]
exportname = $img
authfile = $allowf
readonly = false
multifile = false$extra"
    own_file "$allowf" "# StorageForge: the addresses that may connect to the NBD export $name
$(tr " " "\n" <<<"$allow")" && NBD_RESTART=1
    own_file "$conf" "$body" && NBD_RESTART=1
    MANAGED_FILES+=("$conf" "$allowf")
    open_port "NBD $name" 10809/tcp "$allow"
  done
  nbd_prune ${keep[@]+"${keep[@]}"}
  unit=$(unit_of nbd-server nbd) || true
  systemctl is-active -q "$unit" 2>/dev/null && active=1
  service_on nbd-server nbd
  if ((APPLY && NBD_RESTART && active)); then systemctl restart "$unit" && doing "restarted $unit: its config changed" || conflict "could not restart $unit"; fi
}
nbd_run() { # start | stop: what the client unit does. Written into the helper beside its settings (DEV SERVER NAME TARGET FORMAT MNTOPTS ARGS)
  local fs rc uuid n src
  case ${1:-} in
    start)
      modprobe nbd 2>/dev/null || true
      mkdir -p -- "$TARGET"
      if ! nbd-client -c "$DEV" >/dev/null 2>&1; then
        nbd-client "$SERVER" -N "$NAME" "$DEV" -persist ${ARGS[@]+"${ARGS[@]}"} || return 1
      fi
      for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        [[ $(blockdev --getsize64 "$DEV" 2>/dev/null || echo 0) -gt 0 ]] && break
        sleep 1
      done
      udevadm settle 2>/dev/null || true
      rc=0; fs=$(blkid -p -o value -s TYPE "$DEV" 2>/dev/null) || rc=$?
      if ((rc == 2)); then
        case $FORMAT in
          ext4) mkfs.ext4 -q "$DEV" || return 1 ;;
          xfs) mkfs.xfs -q "$DEV" || return 1 ;;
          *) echo "$DEV holds no filesystem and the format setting is none" >&2; return 1 ;;
        esac
        udevadm settle 2>/dev/null || true
      elif ((rc != 0)); then echo "blkid could not read $DEV (status $rc): not formatting it" >&2; return 1; fi
      uuid=$(blkid -p -o value -s UUID "$DEV" 2>/dev/null) || uuid=""
      src=$DEV; [[ -n $uuid ]] && src=UUID=$uuid
      mountpoint -q "$TARGET" || mount -o "$MNTOPTS" "$src" "$TARGET" ;;
    stop)
      if mountpoint -q "$TARGET"; then umount "$TARGET" || return 1; fi
      nbd-client -d "$DEV" || true ;;
    *) echo "usage: start | stop" >&2; return 2 ;;
  esac
}
nbd_pick_dev() { # UNIT -> the /dev/nbdN this mount uses: the one recorded for it, else the first one nobody uses
  local f=$NBD_STATE/$1.dev n d
  if [[ -s $f ]]; then read -r d <"$f" || true; [[ $d =~ ^/dev/nbd[0-9]+$ ]] && { echo "$d"; return 0; }; fi
  for ((n = 0; n < 64; n++)); do
    d=/dev/nbd$n
    [[ " $NBD_CLAIMED " == *" $d "* ]] && continue
    grep -rqsxF -- "$d" "$NBD_STATE" && continue
    if [[ -d /sys/module/nbd ]]; then
      [[ -d /sys/block/nbd$n ]] || continue
      [[ -e /sys/block/nbd$n/pid ]] && continue
      [[ $(cat "/sys/block/nbd$n/size" 2>/dev/null || echo 0) -gt 0 ]] && continue
    fi
    echo "$d"; return 0
  done
  return 1
}
client_nbd() {
  local i=$1 t=${C_TARGET[$1]} p=${C_PARAM[$1]} name fmt unit key dev helper body ca cert key opts args=() auto=${C_AUTO[$1]} changed=0 f
  name=$(par name "$p"); fmt=$(par format "$p"); ca=$(par tls_ca "$p"); cert=$(par tls_cert "$p"); key=$(par tls_key "$p")
  unit=$(share_unit "$t").service; key=${unit%.service}; key=${key//\\/_}; helper=$NBD_CDIR/$key.sh   # systemd-escape makes backslashes: not in a file name a unit runs
  section "mount ${C_SOURCE[$i]} at $t (NBD)"
  need_cmd nbd-client "NBD client" nbd-client nbd nbd nbd || return 0
  if [[ ! $name =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ || ! $fmt =~ ^(none|ext4|xfs)$ ]]; then conflict "the NBD settings of $t are not usable (export name, format)"; return 0; fi
  if [[ -d /sys/module/nbd ]]; then ok "kernel module nbd is loaded"
  elif ((APPLY)); then modprobe nbd && doing "loaded the nbd module" || { conflict "could not load the nbd kernel module: this kernel may not have it"; return 0; }
  else missing "the nbd kernel module is not loaded (would modprobe nbd)"; fi
  own_file "$NBD_MODLOAD" "# Written by StorageForge: the NBD shares need the nbd module at boot.
nbd" || true
  dev=$(nbd_pick_dev "$key") || { conflict "no free /dev/nbdN for $t (the nbd module makes 16 by default: modprobe nbd nbds_max=32)"; return 0; }
  NBD_CLAIMED+=" $dev"
  if [[ -n $cert || -n $ca ]]; then args+=(-x); fi
  [[ -n $ca ]] && args+=(-C "$ca")
  [[ -n $cert ]] && args+=(-F "$cert" -K "$key")
  opts=${C_OPTS[$i]:-defaults}
  body="#!/bin/bash
# Written by StorageForge: attaches the NBD export $name of $SERVER at $dev and mounts it at $t.
DEV=$(printf %q "$dev")
SERVER=$(printf %q "$SERVER_ADDR")
NAME=$(printf %q "$name")
TARGET=$(printf %q "$t")
FORMAT=$(printf %q "$fmt")
MNTOPTS=$(printf %q "$opts")
ARGS=($(printf "%q " ${args[@]+"${args[@]}"}))
$(declare -f nbd_run)
nbd_run \"\$@\""
  if own_file "$helper" "$body"; then changed=1; ((APPLY)) && chmod 0755 -- "$helper"; fi
  body="# Written by StorageForge: the NBD share $name of $SERVER, attached at $dev and mounted at $t.
[Unit]
Description=StorageForge NBD share $name of $SERVER at $t
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=120
ExecStart=$helper start
ExecStop=$helper stop
Restart=on-failure
RestartSec=30
$(if [[ $auto == 1 ]]; then printf "\n[Install]\nWantedBy=multi-user.target"; fi)"
  unit_file "$unit" "$body" && changed=1
  if ((APPLY)); then
    mkdir -p -- "$NBD_STATE"; printf "%s\n" "$dev" >"$NBD_STATE/$key.dev"
    if ((changed)) && systemctl is-active -q "$unit"; then systemctl restart "$unit" 2>/dev/null || true; fi
    systemctl is-active -q "$unit" || { if [[ $auto == 1 ]]; then systemctl enable --now "$unit"; else systemctl start "$unit"; fi >/dev/null 2>&1 || conflict "$unit did not start: journalctl -u $unit"; }
  fi
  if timeout -k 2 10 mountpoint -q "$t"; then ok "mounted from $dev"
  elif ((APPLY)); then sleep 2; timeout -k 2 10 mountpoint -q "$t" && ok "mounted from $dev" || conflict "$t is not mounted: journalctl -u $unit"
  else missing "not mounted (would use $dev)"; fi
}
cleanup_nbd() { # helpers and device records of mounts the design dropped (their units are gone by now)
  local f u
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    u=${f##*/}; u=${u%.sh}
    grep -rlsF --include="storageforge-share-*.service" -- "$f " /etc/systemd/system >/dev/null && continue
    if ((APPLY)); then rm -f -- "$f" "$NBD_STATE/$u.dev"; doing "removed $f"; else missing "would remove $f"; fi
  done < <(find "$NBD_CDIR" -maxdepth 1 -type f -name "storageforge-share-$SERVER.*.sh" 2>/dev/null | sort)
  return 0
}
"""


def _address(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
    except ValueError:
        return False
    return True


class Nbd(Driver):
    def normalize(self, s: dict) -> dict:
        out = netshares.clean(self.fields, s)
        for k in ('tls_cert', 'tls_key', 'tls_ca'):
            if out.get(k) and not PATH.fullmatch(out[k]):
                raise ValueError(f'{k} is an absolute path of letters, digits and ._-/@+=,:')
        if bool(out.get('tls_cert')) != bool(out.get('tls_key')):
            raise ValueError('TLS needs both a certificate and its key')
        if out.get('tls_ca') and not out.get('tls_cert'):
            raise ValueError('a CA file only goes with a certificate and key')
        return out

    def normalize_mount(self, s: dict) -> dict:
        out = netshares.clean(self.mount_fields, s)
        for k in ('tls_cert', 'tls_key', 'tls_ca'):
            if out.get(k) and not PATH.fullmatch(out[k]):
                raise ValueError(f'{k} is an absolute path of letters, digits and ._-/@+=,:')
        if bool(out.get('tls_cert')) != bool(out.get('tls_key')):
            raise ValueError('a client certificate needs its key too')
        return out

    @staticmethod
    def allowed(e: dict) -> list:
        """The addresses the export lets in: what check() worked out from the mounts' hosts, else just the ones typed in."""
        if '_nbd_allow' in e:
            return list(e['_nbd_allow'])
        return [x for x in (e.get('clients') or '').split() if _address(x)]

    def check(self, conn, hs, srv, e, say):
        from .moves import find_host
        st = e.get('settings') or {}
        if not NAME.fullmatch(e['name'] or ''):
            say('crit', 'an NBD share needs a name of letters, digits, _ - (it is the export clients ask for)')
        if not PATH.fullmatch(e['path'] or ''):
            say('crit', f'{e["path"]!r}: the folder with the disk image needs a path of letters, digits and ._-/@+=,: (no spaces)')
        if not st.get('size_gb'):
            say('crit', 'an NBD share needs the size of its disk image in GB')
        allow = []
        for mt in e['mounts']:
            ch = find_host(hs, mt['host'])
            addr = (ch or {}).get('ssh_host') or ''
            if not _address(addr):
                say('crit', f'{mt["host"]} is reached as {addr or "no address"}, not an IP address: nbd-server can only allow addresses in, '
                            'so list its IP under who may connect')
            elif addr not in allow:
                allow.append(addr)
        for tok in (e.get('clients') or '').split():
            if not _address(tok):
                say('crit', f'{tok} is not an IP address or subnet: nbd-server allows addresses only')
            elif tok not in allow:
                allow.append(tok)
        e['_nbd_allow'] = allow
        if not allow:
            say('crit', 'an NBD share needs the address of the client that uses it: nbd-server has no logins, so without one anyone could connect')
        if len(e['mounts']) > 1:
            say('crit', f'{len(e["mounts"])} clients mount this disk: a block device with an ordinary filesystem has one writer, and a second '
                        'client corrupts it. Keep one mount, or use NFS or SMB to share files')
        say('note', f'{e["path"]}/{e["name"]}.img, {st.get("size_gb", "?")} GB sparse, is exported as "{e["name"]}" on port 10809: '
                    'a bigger size grows it, a smaller one is refused')
        say('note', 'nbd-server has no user authentication: only the address allow-list ('
                    + (', '.join(allow) or 'empty') + ') decides who connects, and addresses can be spoofed on a shared network')
        if st.get('tls_cert'):
            say('ok', 'TLS is on and required (force_tls)' + ('; clients must show a certificate the CA signed' if st.get('tls_ca') else ''))
        else:
            say('warn', 'no TLS: the disk travels in the clear. Set a certificate and key to encrypt it, or keep it on a trusted network')

    def check_mount(self, conn, srv, e, mt, ch, say):
        st = mt.get('settings') or {}
        es = e.get('settings') or {}
        where = f'{ch["name"]}:{mt["path"]}'
        if es.get('tls_cert') and not st.get('tls_ca'):
            say('warn', f'{where}: no CA file set, so it cannot check the server certificate')
        if es.get('tls_ca') and not (st.get('tls_cert') and st.get('tls_key')):
            say('crit', f'{where}: the server wants a client certificate (it has a CA file): set the client certificate and key paths')
        if not es.get('tls_cert') and any(st.get(k) for k in ('tls_ca', 'tls_cert')):
            say('note', f'{where}: has TLS files but the share has no TLS; the client will ask for TLS and the server will refuse')
        if (st.get('format') or 'ext4') == 'none':
            say('note', f'{where}: format is none: the disk must already hold a filesystem, or the mount fails')
        else:
            say('note', f'{where}: formatted {st.get("format") or "ext4"} only when the disk holds nothing at all')

    def server_params(self, e, srv, hs):
        st = e.get('settings') or {}
        return {'size_gb': st.get('size_gb') or '', 'allow': ' '.join(self.allowed(e)),
                'tls_cert': st.get('tls_cert') or '', 'tls_key': st.get('tls_key') or '', 'tls_ca': st.get('tls_ca') or ''}

    def client_params(self, e, mt, srv, hs):
        st = mt.get('settings') or {}
        es = e.get('settings') or {}
        shared = bool(es.get('tls_cert'))
        return {'name': e['name'], 'format': st.get('format') or 'ext4',
                'tls_ca': st.get('tls_ca') or '' if shared else '', 'tls_cert': st.get('tls_cert') or '' if shared else '',
                'tls_key': st.get('tls_key') or '' if shared else ''}

    def client_source(self, e, address):
        return f'nbd://{address}/{e["name"]}'


netshares.register(Nbd(
    key='NBD', label='NBD',
    help='A disk image on the server, exported with nbd-server and attached as a block device on one client, which formats and mounts it. '
         'Only one client may use it; there are no logins, only an address allow-list.',
    clients_label='Extra client addresses', clients_help='IP addresses or subnets nbd-server lets in, space separated. The mounts addresses are added for you.',
    fields=[Field('size_gb', 'int', 'Disk size (GB)', 'Size of NAME.img in the shared folder, made sparse. It can grow later, never shrink.',
                  options=(1, MAX_GB), required=True, placeholder='100'),
            Field('tls_cert', 'path', 'TLS certificate (on the server)', 'With the key, turns TLS on and makes it required.'),
            Field('tls_key', 'path', 'TLS key (on the server)'),
            Field('tls_ca', 'path', 'TLS CA file (on the server)', 'When set, clients must show a certificate this CA signed.')],
    mount_fields=[Field('format', 'choice', 'Format when empty', 'Made only when the disk holds no filesystem and no signature at all.',
                        options=('ext4', 'xfs', 'none'), default='ext4'),
                  Field('tls_ca', 'path', 'TLS CA file (on the client)', 'Checks the server certificate.'),
                  Field('tls_cert', 'path', 'TLS certificate (on the client)', 'Only when the server has a CA file.'),
                  Field('tls_key', 'path', 'TLS key (on the client)')],
    needs_server='NBD server', needs_client='NBD client', bash=BASH))
