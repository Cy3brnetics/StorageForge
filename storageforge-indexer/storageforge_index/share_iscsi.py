"""iSCSI shares: the Linux LIO target on the server (targetcli) and open-iscsi on the client.

Server: the share's folder holds a sparse image, NAME.img, that LIO serves as a fileio backstore: one target
(iqn.2026-11.org.storageforge:<server>.<name>), one LUN, a portal on 0.0.0.0:3260, and an ACL for each client's initiator name only.
Those names are not learnt: a client's is iqn.2026-11.org.storageforge:<client>, so the server knows them before the client has run
anything. CHAP is on, with one user name and a secret from the vault. The configuration is saved with targetcli saveconfig and the
target service is enabled, so it comes back after a reboot. Only targets with StorageForge's IQN prefix for this server are ever
deleted; the image files are never deleted.

Client: the initiator name is set (only when the file still has a distribution default), the target is discovered, the node record
gets CHAP and automatic startup, and the session is logged in. A blank disk is formatted only when the mount says to; the filesystem
is mounted by UUID from a unit that never holds up boot.

A block device with an ordinary filesystem cannot be mounted by two hosts at once without being corrupted, so a share has one client.
"""
from __future__ import annotations

import re

from . import netshares
from .moves import find_host, host_slug
from .netshares import Driver, Field

IQN_BASE = 'iqn.2026-11.org.storageforge'
NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,39}')       # part of an IQN and of a backstore name, so lower case and no dots
CHAP_USER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._@-]{0,31}')
ADDRESS = re.compile(r'[0-9a-fA-F.:]+(/[0-9]+)?')

BASH = r"""
ISCSI_PREFIX=iqn.2026-11.org.storageforge
ISCSI_NODES=${SF_ISCSI_NODES:-/var/lib/iscsi/nodes}
ISCSI_BYPATH=${SF_ISCSI_BYPATH:-/dev/disk/by-path}
ISCSI_NAMEFILE=${SF_ISCSI_NAMEFILE:-/etc/iscsi/initiatorname.iscsi}
ISCSI_CHANGED=0
iscsi_slug() { echo "${1//_/-}"; }
iscsi_pw() { sed -n 's/^password[[:space:]]*=[[:space:]]*//p' "$1" | sed -n 1p; }   # a secret file -> its password: capture it, never print it
iscsi_pw_ok() { [[ $1 =~ ^[A-Za-z0-9._@+-]{12,16}$ ]]; }   # LIO takes 12 to 16 characters
tc() { # targetcli arguments (never a secret) -> quiet on success, a conflict with its first line on failure
  local out; out=$(targetcli "$@" 2>&1) || { conflict "targetcli $*: $(sed -n 1p <<<"$out")"; return 1; }
  ISCSI_CHANGED=1
}
tc_get() { targetcli "$@" 2>/dev/null || true; }
iscsi_addrs() { # words -> the addresses and subnets in them, a host name by its first IPv4 address
  local t a out=()
  for t in $1; do
    if [[ $t =~ ^[0-9a-fA-F.:]+(/[0-9]+)?$ ]]; then out+=("$t")
    else a=$(getent ahostsv4 "$t" 2>/dev/null | awk 'NR == 1 { print $1 }') || true; [[ -z $a ]] || out+=("$a"); fi
  done
  echo "${out[*]-}"
}
iscsi_set_auth() { # ACL-PATH USER PASSWORD -> CHAP on that ACL. The password goes in on targetcli's stdin only: on a command line
  # any local account could read it from the process list, so a targetcli that does not take commands from a pipe gets no CHAP here.
  local path=$1 u=$2 pw=$3 got
  { printf 'cd %s\nset auth userid=%s password=' "$path" "$u"; printf '%s\n' "$pw"; } | targetcli >/dev/null 2>&1 || true
  got=$(tc_get "$path" get auth userid | sed -n 's/^userid=//p')
  if [[ $got != "$u" ]]; then
    conflict "could not set CHAP on $path through targetcli's stdin: set it by hand (targetcli $path set auth userid=$u password=…)"; return 1
  fi
  ISCSI_CHANGED=1
}
iscsi_share() { # share index -> image, backstore, target, LUN, portal, attributes and ACLs of one share
  local i=$1 p=${E_PARAM[$1]} iqn bs size u sf pf pw img want have tpg ini grown=0 cu cpw acls x kv wanted
  iqn=$(par iqn "$p"); bs=$(par backstore "$p"); size=$(par size_gb "$p"); u=$(par chap_user "$p"); sf=$(par chap_secret "$p")
  wanted=$(par initiators "$p"); img=${E_PATH[$i]}/${E_NAME[$i]}.img; tpg=/iscsi/$iqn/tpg1
  [[ $size =~ ^[0-9]+$ ]] || { conflict "${E_NAME[$i]}: the size is not a number of GiB"; return 0; }
  want=$((size * 1073741824))
  if [[ -d ${E_PATH[$i]} ]]; then ok "${E_PATH[$i]} exists"; elif act "mkdir -p ${E_PATH[$i]}"; then mkdir -p -- "${E_PATH[$i]}"; fi
  if [[ -e $img ]]; then
    have=$(stat -c %s "$img")
    if ((have == want)); then ok "$img is $size GiB"
    elif ((have < want)); then
      if act "grow $img from $((have >> 30)) to $size GiB"; then truncate -s "$want" "$img" && grown=1 || conflict "could not grow $img"; fi
    else conflict "$img is $((have >> 30)) GiB, more than the $size GiB the share says: shrinking it would cut the disk, so it is left alone"; fi
  elif act "create the sparse image $img ($size GiB)"; then
    truncate -s "$want" "$img" || conflict "could not create $img"
  fi
  pf=$(secret "$sf"); pw=
  if [[ -n $pf ]]; then
    pw=$(iscsi_pw "$pf")
    iscsi_pw_ok "$pw" || { conflict "the vault secret $sf needs a line password = ... of 12 to 16 letters, digits or . _ @ + - (LIO requires 12 to 16)"; return 0; }
  elif ((APPLY)); then conflict "the vault secret $sf (the CHAP secret) is not on this host: deploy from StorageForge, which brings it"; return 0; fi
  if grep -qE "o- $bs( |\$)" <<<"$(tc_get /backstores/fileio ls 1)"; then
    ok "backstore $bs"
    ((grown)) && info "the target reads the image size when it starts: restart $(unit_of target rtslib-fb-targetctl) to show the new size, then rescan on the client"
  elif act "create fileio backstore $bs on $img (write-through)"; then
    tc /backstores/fileio create "name=$bs" "file_or_dev=$img" write_back=false || return 0
  fi
  if grep -qE "o- ${iqn//./\\.}( |\$)" <<<"$(tc_get /iscsi ls 1)"; then ok "target $iqn"
  elif act "create target $iqn"; then tc /iscsi create "$iqn" || return 0
  else missing "its LUN, portal, CHAP and ACLs for ${wanted:-no initiator}"; return 0; fi
  if grep -qE "o- lun0 .*fileio/$bs " <<<"$(tc_get "$tpg" ls)"; then ok "lun0 is $bs"
  elif grep -qE "o- lun0 " <<<"$(tc_get "$tpg/luns" ls)"; then conflict "lun0 of $iqn is not $bs: a target of StorageForge has one LUN, so remove the target by hand"
  elif act "add lun0 ($bs) to $iqn"; then tc "$tpg/luns" create "/backstores/fileio/$bs" || true; fi
  if grep -qE "o- 0\.0\.0\.0:3260 " <<<"$(tc_get "$tpg/portals" ls)"; then ok "portal 0.0.0.0:3260"
  elif act "portal 0.0.0.0:3260 for $iqn"; then tc "$tpg/portals" create 0.0.0.0 3260 || true; fi
  for kv in authentication=1 generate_node_acls=0 demo_mode_write_protect=0 cache_dynamic_acls=0; do
    if [[ $(tc_get "$tpg" get attribute "${kv%=*}") == "$kv" ]]; then continue; fi
    if act "set $kv on $tpg"; then tc "$tpg" set attribute "$kv" || true; fi
  done
  acls=$(tc_get "$tpg/acls" ls | grep -oE 'o- iqn\.[^ ]+' | cut -c4-) || true
  for ini in $wanted; do
    if grep -qxF -- "$ini" <<<"$acls"; then ok "ACL $ini"
    elif act "allow initiator $ini on $iqn"; then tc "$tpg/acls" create "$ini" || continue
    else continue; fi
    cu=$(tc_get "$tpg/acls/$ini" get auth userid | sed -n 's/^userid=//p')
    cpw=$(tc_get "$tpg/acls/$ini" get auth password | sed -n 's/^password=//p')
    # a targetcli that does not show the password gives nothing to compare: then only the user name decides
    if [[ $cu == "$u" && ( -z $pw || -z $cpw || $cpw == "$pw" ) ]]; then ok "CHAP of $ini ($u)"
    elif [[ -z $pw ]] && ! ((APPLY)); then missing "CHAP user $u on the ACL of $ini"
    elif act "set CHAP ($u) on the ACL of $ini"; then iscsi_set_auth "$tpg/acls/$ini" "$u" "$pw" || true; fi
  done
  for x in $acls; do
    [[ " $wanted " == *" $x "* ]] && continue
    if act "remove the ACL of $x from $iqn (no mount of this share uses it)"; then tc "$tpg/acls" delete "$x" || true; fi
  done
  x=$(iscsi_addrs "$(par addrs "$p") ${E_CLIENTS[$i]}")
  if [[ -n $x ]]; then open_port iSCSI 3260/tcp "$x"; else info "no client address known: port 3260 is not opened"; fi
}
iscsi_prune() { # KEEP-IQNS KEEP-BACKSTORES -> StorageForge targets of this server and their backstores that no share has any more
  local t b pre=$ISCSI_PREFIX:$(iscsi_slug "$SERVER"). bpre=sf-$(iscsi_slug "$SERVER")- first=1
  command -v targetcli >/dev/null || return 0
  while IFS= read -r t; do
    [[ $t == "$pre"* && $1 != *" $t "* ]] || continue
    ((first)) && { section "iSCSI targets of $SERVER the design no longer has"; first=0; }
    if act "delete target $t (its image file stays)"; then tc /iscsi delete "$t" || true; fi
  done < <(tc_get /iscsi ls 1 | grep -oE 'o- iqn\.[^ ]+' | cut -c4-)
  while IFS= read -r b; do
    [[ $b == "$bpre"* && $2 != *" $b "* ]] || continue
    ((first)) && { section "iSCSI targets of $SERVER the design no longer has"; first=0; }
    if act "delete backstore $b (its image file stays)"; then tc /backstores/fileio delete "$b" || true; fi
  done < <(tc_get /backstores/fileio ls 1 | grep -oE 'o- sf-[^ ]+' | cut -c4-)
  return 0
}
server_iscsi() {
  local i idx=() keep=" " keepbs=" " unit
  mapfile -t idx < <(indices_of ISCSI)
  if ((!${#idx[@]})); then
    iscsi_prune " " " "
    if ((ISCSI_CHANGED)); then doing "targetcli saveconfig"; targetcli saveconfig >/dev/null 2>&1 || conflict "targetcli saveconfig failed"; fi
    return 0
  fi
  section "iSCSI target (LIO, targetcli)"
  need_cmd targetcli "iSCSI target" targetcli-fb targetcli targetcli-fb targetcli-fb || return 0
  command -v targetcli >/dev/null || return 0      # a report on a host without it has said what it would install
  for i in "${idx[@]}"; do
    iscsi_share "$i" || true
    keep+="$(par iqn "${E_PARAM[$i]}") "; keepbs+="$(par backstore "${E_PARAM[$i]}") "
  done
  iscsi_prune "$keep" "$keepbs"
  if ((ISCSI_CHANGED)); then doing "targetcli saveconfig"; targetcli saveconfig >/dev/null 2>&1 || conflict "targetcli saveconfig failed"; fi
  # enabled, not started: the running target already is what was just saved, and starting the unit would restore over it
  unit=$(unit_of target rtslib-fb-targetctl) || true
  if systemctl is-enabled -q "$unit" 2>/dev/null; then ok "$unit enabled (the saved config comes back at boot)"
  elif act "systemctl enable $unit"; then reload_systemd; systemctl enable "$unit" >/dev/null 2>&1 || conflict "could not enable $unit: the target would be gone after a reboot"; fi
}
iscsi_initiator() { # IQN -> the initiator name file says it, replacing only a distribution default
  local f=$ISCSI_NAMEFILE cur dflt='^iqn\.(1993-08\.org\.debian:01|1994-05\.com\.redhat|1996-04\.de\.suse:01|2005-03\.org\.open-iscsi):[0-9a-f]+$'
  cur=$(sed -n 's/^InitiatorName=[[:space:]]*//p' "$f" 2>/dev/null | sed -n 1p) || true
  if [[ $cur == "$1" ]]; then ok "initiator name $1"; return 0; fi
  if [[ -n $cur && $cur != "$ISCSI_PREFIX:"* && ! $cur =~ $dflt ]]; then
    conflict "$f names $cur, which is not a distribution default or StorageForge's: the server only lets $1 in. Put InitiatorName=$1 in it, or remove the file, then deploy again"
    return 1
  fi
  if own_file "$f" "## Written by StorageForge: the name the iSCSI server has an ACL for.
InitiatorName=$1" && ((APPLY)); then
    if iscsiadm -m session >/dev/null 2>&1; then info "sessions are open: iscsid reads the new name when it restarts"
    elif systemctl is-active -q iscsid 2>/dev/null; then systemctl restart iscsid 2>/dev/null || true; fi
  fi
  return 0
}
iscsi_record() { # IQN PORTAL-ADDRESS PORT -> the node record file, if there is one
  find "$ISCSI_NODES/$1" -type f -path "*/$2,$3,*" 2>/dev/null | sed -n 1p
}
iscsi_rec_new() { # RECORD USER SECRETFILE -> the record with CHAP and automatic startup, on stdout. The password goes from the file
  # into the output without being on any command line.
  awk -v user="$2" '
    FNR == NR { if ($0 ~ /^password[ \t]*=/) { sub(/^password[ \t]*=[ \t]*/, ""); pw = $0 } next }
    /^node\.startup[ ]*=/ || /^node\.session\.auth\.(authmethod|username|password)[ ]*=/ { next }
    { print }
    END { print "node.startup = automatic"; print "node.session.auth.authmethod = CHAP"
          print "node.session.auth.username = " user; print "node.session.auth.password = " pw }' "$3" "$1"
}
iscsi_disk() { # IQN TRIES -> the block device of its LUN 0, waiting up to TRIES seconds for udev
  local n d
  for ((n = 0; n < $2; n++)); do
    d=$(compgen -G "$ISCSI_BYPATH/*iscsi-$1-lun-0" | sed -n 1p) || true
    if [[ -n $d ]]; then readlink -f "$d"; return 0; fi
    sleep 1
  done
  d=$(compgen -G "$ISCSI_BYPATH/*iscsi-$1-lun-0" | sed -n 1p) || true
  [[ -z $d ]] || readlink -f "$d"
  return 0
}
client_iscsi() {
  local i=$1 t=${C_TARGET[$1]} p=${C_PARAM[$1]} iqn ini u sf fmt port portal pf pw rec cur new dev fs uuid rc out unit opts body changed=0
  iqn=$(par iqn "$p"); ini=$(par initiator "$p"); u=$(par chap_user "$p"); sf=$(par chap_secret "$p"); fmt=$(par format "$p"); port=$(par port "$p")
  portal=$SERVER_ADDR:$port; [[ $SERVER_ADDR == *:* ]] && portal=[$SERVER_ADDR]:$port
  unit=$(share_unit "$t").service
  section "mount ${C_SOURCE[$i]} at $t (iSCSI)"
  need_cmd iscsiadm "iSCSI initiator" open-iscsi iscsi-initiator-utils open-iscsi open-iscsi || return 0
  command -v iscsiadm >/dev/null || return 0
  iscsi_initiator "$ini" || return 0
  service_on iscsid
  pf=$(secret "$sf"); pw=
  if [[ -n $pf ]]; then
    pw=$(iscsi_pw "$pf")
    iscsi_pw_ok "$pw" || { conflict "the vault secret $sf needs a line password = ... of 12 to 16 letters, digits or . _ @ + - (LIO requires 12 to 16)"; return 0; }
  elif ((APPLY)); then conflict "the vault secret $sf (the CHAP secret) is not on this host: deploy from StorageForge, which brings it"; return 0; fi
  rec=$(iscsi_record "$iqn" "$SERVER_ADDR" "$port")
  if [[ -z $rec ]]; then
    if act "discover $portal and add the node record of $iqn"; then
      out=$(iscsiadm -m discovery -t sendtargets -p "$portal" -o nonpersistent 2>&1) || { conflict "discovery on $portal failed: $(sed -n 1p <<<"$out")"; return 0; }
      awk -v t="$iqn" '$2 == t { f = 1 } END { exit !f }' <<<"$out" \
        || { conflict "$portal does not offer $iqn: deploy the server side first, and check that this initiator ($ini) is in its ACL"; return 0; }
      iscsiadm -m node -o new -T "$iqn" -p "$portal" >/dev/null 2>&1 || { conflict "could not add the node record of $iqn"; return 0; }
      rec=$(iscsi_record "$iqn" "$SERVER_ADDR" "$port")
    fi
  fi
  if [[ -n $rec ]]; then
    if [[ -n $pw ]]; then
      new=$(iscsi_rec_new "$rec" "$u" "$pf")
      if [[ $new == "$(cat "$rec")" ]]; then ok "node record: CHAP ($u) and automatic startup"
      elif act "set CHAP ($u) and automatic startup in the node record"; then printf '%s\n' "$new" >"$rec" || conflict "could not write the node record"; fi
    elif [[ $(sed -n 's/^node.session.auth.username = //p' "$rec") == "$u" && $(sed -n 's/^node.startup = //p' "$rec") == automatic ]]; then ok "node record: CHAP user $u and automatic startup"
    else missing "CHAP user $u and automatic startup in the node record"; fi
  elif ((APPLY)); then
    # No record yet: iscsiadm makes an empty one (no password on its command line, where the process list would show it), and the
    # password goes into that file from the secret file, as above
    iscsiadm -m node -o new -T "$iqn" -p "$portal" >/dev/null 2>&1 || true
    rec=$(iscsi_record "$iqn" "$SERVER_ADDR" "$port")
    [[ -n $rec && -n $pw ]] || { conflict "could not make the node record of $iqn to put CHAP in"; return 0; }
    new=$(iscsi_rec_new "$rec" "$u" "$pf") && printf '%s\n' "$new" >"$rec" && doing "set CHAP ($u) and automatic startup in the node record" \
      || { conflict "could not write the node record of $iqn"; return 0; }
  fi
  out=$(iscsiadm -m session 2>/dev/null || true)
  if grep -qF " $iqn (" <<<"$out"; then ok "logged in to $iqn"
  elif act "log in to $iqn at $portal"; then
    out=$(iscsiadm -m node -T "$iqn" -p "$portal" --login 2>&1) || { conflict "login to $iqn failed (CHAP secret or ACL wrong?): $(tail -n 1 <<<"$out")"; return 0; }
  fi
  dev=$(iscsi_disk "$iqn" $((APPLY ? 20 : 0)))
  if [[ -z $dev ]]; then
    if ((APPLY)); then conflict "the disk of $iqn did not appear under $ISCSI_BYPATH: journalctl -u iscsid"
    else missing "not logged in yet: would find the disk of $iqn and mount it at $t"; fi
    return 0
  fi
  out=$(blkid -p "$dev" 2>/dev/null) && rc=0 || rc=$?
  if ((rc == 2)); then       # blkid sees nothing at all on it
    if [[ $fmt == none || -z $fmt ]]; then conflict "$dev has no filesystem and the mount says not to format it: make one by hand, or set format to ext4 or xfs"; return 0
    elif ! command -v "mkfs.$fmt" >/dev/null; then conflict "mkfs.$fmt is not installed, so $dev cannot be formatted"; return 0
    elif act "format the blank disk $dev as $fmt"; then
      "mkfs.$fmt" -q "$dev" >/dev/null 2>&1 || { conflict "mkfs.$fmt failed on $dev"; return 0; }
      udevadm settle 2>/dev/null || true
    else return 0; fi
  elif ((rc != 0)); then conflict "could not look at $dev with blkid"; return 0; fi
  fs=$(blkid -p -s TYPE -o value "$dev" 2>/dev/null) || true
  uuid=$(blkid -p -s UUID -o value "$dev" 2>/dev/null) || true
  if [[ ! $fs =~ ^[a-z0-9]+$ || ! $uuid =~ ^[A-Za-z0-9-]+$ ]]; then
    conflict "$dev holds something that is not a filesystem with a UUID (a partition table?): StorageForge mounts only a filesystem on the whole disk"; return 0
  fi
  opts=defaults,_netdev,nofail; [[ -z ${C_OPTS[$i]} ]] || opts+=,${C_OPTS[$i]}
  body="# Written by StorageForge: the iSCSI share ${C_NAME[$i]} of $SERVER at $t.
# Nothing requires this unit, so a server that is down fails it alone and never holds up boot.
[Unit]
Description=StorageForge iSCSI share ${C_NAME[$i]} of $SERVER at ${t//%/%%}
Wants=network-online.target
After=network-online.target iscsid.service remote-fs-pre.target
Before=remote-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=150
Restart=on-failure
RestartSec=30
ExecStartPre=-$(command -v iscsiadm) -m node -T $iqn -p $portal --login
ExecStartPre=$(command -v timeout) 60 /bin/sh -c 'until [ -b /dev/disk/by-uuid/$uuid ]; do sleep 1; done'
ExecStartPre=/usr/bin/mkdir -p \"${t//%/%%}\"
ExecStart=/usr/bin/mount -t $fs -o $opts UUID=$uuid \"${t//%/%%}\"
ExecStop=/usr/bin/umount \"${t//%/%%}\"

[Install]
WantedBy=remote-fs.target"
  unit_file "$unit" "$body" && changed=1
  if ((APPLY)); then
    if ((changed)) && systemctl is-active -q "$unit"; then systemctl restart "$unit" 2>/dev/null || true; fi
    systemctl is-active -q "$unit" || systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "$unit did not start: journalctl -u $unit"
  fi
  if timeout -k 2 10 mountpoint -q "$t"; then ok "mounted"; elif ((APPLY)); then sleep 2; timeout -k 2 10 mountpoint -q "$t" && ok "mounted" || conflict "$t is not mounted: journalctl -u $unit"; else missing "not mounted"; fi
}
cleanup_iscsi() { # log out of StorageForge targets of this server that no mount here uses any more (the units are already gone)
  command -v iscsiadm >/dev/null || return 0
  local i t keep=" " first=1 pre=$ISCSI_PREFIX:$(iscsi_slug "$SERVER"). out
  for i in "${!C_HOST[@]}"; do
    [[ ${C_HOST[$i]} == "$ME" && ${C_PROTO[$i]} == ISCSI ]] && keep+="$(par iqn "${C_PARAM[$i]}") "
  done
  while IFS= read -r t; do
    [[ $t == "$pre"* && $keep != *" $t "* ]] || continue
    ((first)) && { section "iSCSI targets of $SERVER no longer mounted here"; first=0; }
    if act "log out of $t and forget it"; then
      iscsiadm -m node -T "$t" --logout >/dev/null 2>&1 || true
      out=$(iscsiadm -m node -T "$t" -o delete 2>&1) || conflict "could not forget $t (still in use?): $(sed -n 1p <<<"$out")"
    fi
  done < <(iscsiadm -m node 2>/dev/null | awk '{ print $2 }' | sort -u)
  return 0
}
"""


class Iscsi(Driver):
    def normalize(self, s: dict) -> dict:
        out = netshares.clean(self.fields, s)
        if out.get('chap_user') and not CHAP_USER.fullmatch(out['chap_user']):
            raise ValueError('the CHAP user is letters, digits and . _ @ - (up to 32)')
        return out

    @staticmethod
    def server_slug(srv: dict) -> str:
        return host_slug(srv['name']).replace('_', '-')

    @classmethod
    def iqn(cls, srv: dict, e: dict) -> str:
        return f'{IQN_BASE}:{cls.server_slug(srv)}.{e["name"]}'

    @staticmethod
    def initiator(host: str) -> str:
        return f'{IQN_BASE}:{host_slug(host).replace("_", "-")}'

    @staticmethod
    def backstore(srv: dict, e: dict) -> str:
        return f'sf-{Iscsi.server_slug(srv)}-{e["name"]}'

    def check(self, conn, hs, srv, e, say):
        st = e.get('settings') or {}
        if not NAME.fullmatch(e['name'] or ''):
            say('crit', 'an iSCSI share needs a name of lower-case letters, digits and - (it is part of the target name)')
        else:
            say('note', f'target {self.iqn(srv, e)}, one LUN, portal 0.0.0.0:3260; the disk is {e["path"].rstrip("/")}/{e["name"]}.img')
        size = st.get('size_gb')
        if not isinstance(size, int) or not 1 <= size <= 65536:
            say('crit', 'an iSCSI share needs a size in GiB, from 1 to 65536')
        else:
            say('note', f'the image is sparse: it takes space as the disk fills, up to {size} GiB. It can be made larger later, never smaller')
        if not st.get('chap_secret'):
            say('crit', 'name the vault secret with the CHAP password (a line password = ..., 12 to 16 characters): without CHAP anyone who reaches port 3260 can read the disk')
        if not CHAP_USER.fullmatch(st.get('chap_user') or 'storageforge'):
            say('crit', 'the CHAP user is letters, digits and . _ @ - (up to 32)')
        mounts = e.get('mounts') or []
        if len(mounts) > 1:
            say('crit', f'{len(mounts)} clients mount this disk: a disk with an ordinary filesystem is corrupted when two hosts use it at once. '
                        'Keep one client, or share a filesystem (NFS, SMB) instead')
        elif not mounts:
            say('warn', 'no client mount: the target lets no initiator in until one is added')
        say('warn', 'the disk is one file on the share\'s filesystem: a snapshot of that filesystem holds it as it was at that instant, '
                    'which the client sees as a crash (crash-consistent only)')

    def check_mount(self, conn, srv, e, mt, ch, say):
        if host_slug(mt['host']) != host_slug(ch['name']):
            say('crit', f'{mt["host"]} is another name for {ch["name"]}: name the client by its host name, because the initiator name '
                        f'({self.initiator(mt["host"])}) is made from it')
        st = mt.get('settings') or {}
        if (st.get('format') or 'none') == 'none':
            say('note', f'{ch["name"]}:{mt["path"]}: a blank disk is not formatted (format is none): the disk needs a filesystem already')
        else:
            say('note', f'{ch["name"]}:{mt["path"]}: a blank disk is formatted as {st["format"]}; a disk with anything on it is never touched')

    def server_params(self, e, srv, hs):
        st = e.get('settings') or {}
        mounts = e.get('mounts') or []
        addrs = [ch['ssh_host'] for ch in (find_host(hs, m['host']) for m in mounts) if ch]
        return {'iqn': self.iqn(srv, e), 'backstore': self.backstore(srv, e), 'size_gb': st.get('size_gb') or 0,
                'chap_user': st.get('chap_user') or 'storageforge', 'chap_secret': st.get('chap_secret') or '',
                'initiators': ' '.join(self.initiator(m['host']) for m in mounts), 'addrs': ' '.join(addrs)}

    def client_params(self, e, mt, srv, hs):
        st, ms = e.get('settings') or {}, mt.get('settings') or {}
        return {'iqn': self.iqn(srv, e), 'initiator': self.initiator(mt['host']), 'chap_user': st.get('chap_user') or 'storageforge',
                'chap_secret': st.get('chap_secret') or '', 'format': ms.get('format') or 'none', 'port': 3260}

    def client_source(self, e, address):
        return f'iscsi://{address}:3260/{e["name"]}'

    def server_secrets(self, e):
        s = (e.get('settings') or {}).get('chap_secret')
        return [s] if s else []

    def client_secrets(self, e, mt):
        return self.server_secrets(e)


netshares.register(Iscsi(
    key='ISCSI', label='iSCSI',
    help='A block disk from the server: an image file in the share folder served by the Linux LIO target with CHAP, mounted by one client with open-iscsi.',
    clients_label='Extra addresses allowed to reach port 3260',
    clients_help='Optional. The client mount below is let in by its initiator name and its address; add others here, space separated.',
    fields=[Field('size_gb', 'int', 'Size (GiB)', 'The disk image is sparse and can be made larger later, never smaller.', options=(1, 65536), required=True, placeholder='100'),
            Field('chap_user', 'text', 'CHAP user', 'Letters, digits and . _ @ -.', default='storageforge'),
            Field('chap_secret', 'secret', 'Vault secret with the CHAP password', 'A secret with a line password = ..., 12 to 16 characters (LIO requires that).', placeholder='nas-iscsi-chap')],
    mount_fields=[Field('format', 'choice', 'Format a blank disk as', 'Only a disk with nothing on it is formatted; none leaves that to you.',
                        options=('none', 'ext4', 'xfs'), default='none')],
    needs_server='iSCSI target', needs_client='iSCSI initiator', bash=BASH))
