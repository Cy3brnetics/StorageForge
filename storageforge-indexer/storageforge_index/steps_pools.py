"""Plan steps for pools that already exist, and for LUKS: a vdev added to a ZFS pool, a disk replaced or attached there; a
disk added to an md array, replaced in it, or the array grown; a device formatted as LUKS, opened, closed, or given a new
key slot (docs/change-plans.md).

Every step that writes to a device is destructive, so the script runs it only with --apply --destructive and the device
typed again, and the device must be free (dev_guard). Nothing here forces anything: zpool add refuses a vdev whose
replication does not match the pool unless it is forced, and the step looks at the pool first and says so in plain words,
so a mirror is never turned into a stripe by a stray disk. A reshape, a resilver or a rebuild runs in the background: the
step starts it, says how far it is, and a rerun reports it until it is done.

A LUKS key is a vault secret (`vault secret-add`), written to the host by `vault send-secret` into
/run/storageforge/secrets/<name> (memory, mode 600). cryptsetup reads it on stdin or from a file in that same memory, never
from a command line, and the file is removed once the step has used it: the vault keeps the key.
"""
from __future__ import annotations

import json
import re
import shlex

from . import changes
from .changes import CONFIRM, CONFIRM_ALL, DEVICES, F

SECRET_DIR = '/run/storageforge/secrets'
SECRET = re.compile(r'[A-Za-z0-9_.-]{1,64}')
MAPPER = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}')
MD_NAME = re.compile(r'[A-Za-z0-9_-]{1,32}')
LEAF = re.compile(r'/dev/[A-Za-z0-9/_.:+-]+|[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}')      # a device path, a name zpool status prints, or a guid
ZFS_LEVELS = ['mirror', 'raidz1', 'raidz2', 'raidz3', 'stripe']
ZFS_MIN = {'stripe': 1, 'mirror': 2, 'raidz1': 2, 'raidz2': 3, 'raidz3': 4}
ROLES = ['data', 'log', 'cache', 'spare']
MD_GROWS = ('raid1', 'raid4', 'raid5', 'raid6', 'raid10')
CRYPTTAB = ['', 'noauto', 'ask']
WIPE = F('wipe', 'bool', 'It has a filesystem: overwrite it')

# Uses need, dev_guard, devs_guard, act, try, later and the report helpers of the change script. No apostrophes: the
# script text is checked for values that could end a quoted word.
BASH = r"""
# ── pools that exist, and LUKS ──────────────────────────────────────
# the data vdevs of a ZFS pool, one line each: mirror:2, raidz2:6, stripe:1 for a single disk. A replacing or spare vdev
# under a mirror is not counted as a member.
zp_shape() { zpool status -P -- "$1" 2>/dev/null | awk -v p="$1" '$1 == "config:" {c = 1; next} !c || NF == 0 || $1 == "NAME" {next} $1 == "errors:" {exit} {match($0, /^[ \t]*/); ind = RLENGTH} $1 == p && !base {base = ind; sec = "data"; next} ind == base {sec = $1; next} sec != "data" {next} ind == base + 2 {if (t != "") print t ":" n; t = $1; n = 0; if (t ~ /^(mirror|raidz[0-9]?|draid)/) {sub(/-[0-9]+$/, "", t); if (t == "raidz") t = "raidz1"} else {print "stripe:1"; t = ""}; next} t != "" && ind == base + 4 {n++} END {if (t != "") print t ":" n}'; }
# every leaf of the pool with the top-level vdev it is in: "mirror-0 /dev/sdb1", "disk /dev/sdc1", "log /dev/nvme0n1p1"
zp_leaves() { zpool status -P -- "$1" 2>/dev/null | awk -v p="$1" '$1 == "config:" {c = 1; next} !c || NF == 0 || $1 == "NAME" {next} $1 == "errors:" {exit} {match($0, /^[ \t]*/); ind = RLENGTH} $1 == p && !base {base = ind; sec = "data"; next} ind == base {sec = $1; next} sec != "data" {print sec, $1; next} ind == base + 2 {t = $1; if (t !~ /^(mirror|raidz|draid|replacing|spare)/) {print "disk", $1; t = ""}; next} t != "" {print t, $1}'; }
# zp_find POOL NAME: the top-level vdev NAME is in (a path, a short name such as sdb, or a guid), or nothing
zp_find() { local pool=$1 want=$2 r top leaf
  r=$want; [[ $want == /* ]] || [[ $want =~ ^[0-9]+$ ]] || r=/dev/$want
  [[ -e $r ]] && r=$(readlink -f -- "$r")
  while read -r top leaf; do
    [[ -n $leaf ]] || continue
    [[ $leaf == "$want" ]] && { echo "$top"; return 0; }
    [[ -e $leaf ]] && leaf=$(readlink -f -- "$leaf")
    # zpool puts a whole disk it was given in a partition of its own: /dev/sdb is in the pool as /dev/sdb1
    if [[ $leaf == "$r" || $leaf =~ ^${r}p?[0-9]+$ ]]; then echo "$top"; return 0; fi
  done < <(zp_leaves "$pool"; zpool status -g -- "$pool" 2>/dev/null | awk -v p="$pool" '$1 == "config:" {c = 1; next} c && $1 ~ /^[0-9]+$/ {print "guid", $1}')
  return 1
}
zp_said() { case $1 in mirror:*) echo "a ${1#*:}-way mirror" ;; stripe:1) echo "a single disk" ;; *) echo "a ${1%%:*} of ${1#*:} disks" ;; esac; }
zp_scan() { zpool status -- "$1" 2>/dev/null | sed -n "s/^ *scan: //p" | head -n 1; }
zp_wipe() { local d; [[ $1 == 1 ]] || return 0; shift; for d in "$@"; do try wipefs -aq -- "$d" || return 1; done; }

t_zfs_add() { local pool=$1 level=$2 devs=$3 role=${4:-data} wipe=$5 arr d in=0 out=0 want shape s vdev=() opts=() ashift
  need zpool zfsutils-linux || return 0
  zpool list -H -o name -- "$pool" >/dev/null 2>&1 || { later "pool $pool must exist"; return 0; }
  read -ra arr <<<"$devs"
  for d in "${arr[@]}"; do if zp_find "$pool" "$d" >/dev/null; then in=$((in + 1)); else out=$((out + 1)); fi; done
  if ((in && !out)); then ok "$devs already in pool $pool"; return 0; fi
  ((in)) && { conflict "some of $devs are in pool $pool and some are not: add the rest in a step of their own"; return 0; }
  if [[ $role == data ]]; then
    shape=$(zp_shape "$pool" | sort -u)
    [[ -n $shape ]] || { conflict "could not read the layout of pool $pool (zpool status)"; return 0; }
    [[ $shape == draid* ]] && { conflict "pool $pool is draid: add to it by hand"; return 0; }
    want="$level:${#arr[@]}"; [[ $level == stripe ]] && want=stripe:1
    while read -r s; do
      [[ $s == "$want" ]] && continue
      # zpool add refuses this unless forced, and forcing it would leave the pool only as safe as its weakest vdev
      conflict "pool $pool is made of $(zp_said "$s") and the new vdev would be $(zp_said "$want"): zpool add refuses a mismatched layout unless forced, and this step never forces it"
      return 0
    done <<<"$shape"
    [[ $level == stripe ]] || vdev=("$level")
  else
    [[ $role == log || $level == stripe ]] || { conflict "a $role vdev is a list of disks, with no mirror or raidz"; return 0; }
    [[ $role == log && $level == mirror ]] && vdev=(mirror)
    vdev=("$role" ${vdev[@]+"${vdev[@]}"})
  fi
  devs_guard "$wipe" "${arr[@]}" || return 0
  ashift=$(zpool get -H -o value ashift -- "$pool" 2>/dev/null || true)
  [[ $ashift =~ ^[0-9]+$ && $ashift != 0 ]] && opts=(-o "ashift=$ashift")       # the same sector size as the pool, or it can never be removed again
  act "zpool add $pool ${vdev[*]} $devs" || return 0
  zp_wipe "$wipe" "${arr[@]}" || return 0
  try zpool add ${opts[@]+"${opts[@]}"} -- "$pool" ${vdev[@]+"${vdev[@]}"} "${arr[@]}" || return 0
  ok "added to $pool: $(zpool list -H -o size,health -- "$pool" 2>/dev/null | tr "\t" " ")"
  [[ $role == data ]] && info "existing data stays where it is: new writes spread over every vdev"
}

t_zfs_replace() { local pool=$1 old=$2 new=$3 wipe=$4 top
  need zpool zfsutils-linux || return 0
  zpool list -H -o name -- "$pool" >/dev/null 2>&1 || { later "pool $pool must exist"; return 0; }
  if zp_find "$pool" "$new" >/dev/null; then
    if zp_find "$pool" "$old" >/dev/null; then ok "replacing $old with $new: $(zp_scan "$pool")"; else ok "$new has taken the place of $old: $(zp_scan "$pool")"; fi
    return 0
  fi
  top=$(zp_find "$pool" "$old") || { conflict "$old is not in pool $pool"; return 0; }
  [[ $top == cache || $top == spares ]] && { conflict "$old is a $top device: remove it and add the new one instead"; return 0; }
  devs_guard "$wipe" "$new" || return 0
  act "zpool replace $pool $old $new" || return 0
  zp_wipe "$wipe" "$new" || return 0
  try zpool replace -- "$pool" "$old" "$new" || return 0
  ok "resilvering onto $new: $(zp_scan "$pool")"
  info "it runs in the background and the pool stays in use; $old leaves the pool when it is done"
}

t_zfs_attach() { local pool=$1 have=$2 new=$3 wipe=$4 top
  need zpool zfsutils-linux || return 0
  zpool list -H -o name -- "$pool" >/dev/null 2>&1 || { later "pool $pool must exist"; return 0; }
  if top=$(zp_find "$pool" "$new"); then ok "$new is in pool $pool ($top): $(zp_scan "$pool")"; return 0; fi
  top=$(zp_find "$pool" "$have") || { conflict "$have is not in pool $pool"; return 0; }
  case $top in
    disk|mirror-*|logs) ;;
    *) conflict "$have is in $top: attach makes a mirror of a single disk or widens a mirror, and nothing else"; return 0 ;;
  esac
  devs_guard "$wipe" "$new" || return 0
  act "zpool attach $pool $have $new ($([[ $top == disk ]] && echo "a single disk becomes a mirror" || echo "$top gets one more side"))" || return 0
  zp_wipe "$wipe" "$new" || return 0
  try zpool attach -- "$pool" "$have" "$new" || return 0
  ok "resilvering onto $new: $(zp_scan "$pool")"
}

# ── md ──────────────────────────────────────────────────────────────
md_path() { if [[ -e /dev/md/$1 ]]; then echo "/dev/md/$1"; elif [[ $1 =~ ^md[0-9]+$ && -e /dev/$1 ]]; then echo "/dev/$1"; else echo "/dev/md/$1"; fi; }
# md_role DETAIL DEVICE: active sync, spare, spare rebuilding, faulty ... as mdadm --detail lists it, or nothing
md_role() { local r=$2; [[ -e $r ]] && r=$(readlink -f -- "$r"); awk -v d="$r" '$NF == d && $1 ~ /^[0-9-]+$/ {s = ""; for (i = 5; i < NF; i++) s = s (s == "" ? "" : " ") $i; print s; exit}' <<<"$1"; }
md_field() { sed -n "s/^ *$2 : //p" <<<"$1" | head -n 1; }
md_progress() { local d; d=$(mdadm --detail "$1" 2>/dev/null); sed -n "s/^ *\(Reshape\|Rebuild\|Resync\) Status : /\1 /p" <<<"$d" | head -n 1; }

t_md_add() { local name=$1 dev=$2 wipe=$3 a detail role state
  need mdadm mdadm || return 0
  a=$(md_path "$name")
  detail=$(mdadm --detail "$a" 2>/dev/null) || { later "array $name must exist"; return 0; }
  role=$(md_role "$detail" "$dev")
  if [[ -n $role && $role != *faulty* ]]; then ok "$dev is in $name ($role)"; return 0; fi
  [[ -n $role ]] && { conflict "$dev is in $name and has failed: take it out (mdadm $a --remove $dev) before adding it again"; return 0; }
  devs_guard "$wipe" "$dev" || return 0
  state=$(md_field "$detail" State)
  act "mdadm $a --add $dev ($([[ $state == *degraded* ]] && echo "the array is degraded: it rebuilds onto it" || echo "as a spare"))" || return 0
  zp_wipe "$wipe" "$dev" || return 0
  try mdadm "$a" --add "$dev" || return 0
  ok "added: $(md_role "$(mdadm --detail "$a" 2>/dev/null)" "$dev")$(p=$(md_progress "$a"); [[ -n $p ]] && echo ", $p")"
}

t_md_replace() { local name=$1 old=$2 new=$3 wipe=$4 a detail ro rn
  need mdadm mdadm || return 0
  a=$(md_path "$name")
  detail=$(mdadm --detail "$a" 2>/dev/null) || { later "array $name must exist"; return 0; }
  ro=$(md_role "$detail" "$old"); rn=$(md_role "$detail" "$new")
  if [[ $rn == *rebuilding* || $ro == *want-replacement* ]]; then ok "copying onto $new: $(md_progress "$a")"; return 0; fi
  if [[ $rn == active* ]]; then
    if [[ $ro == *faulty* ]]; then
      act "mdadm $a --remove $old (replaced by $new)" && try mdadm "$a" --remove "$old" && ok "$old is out of $name"
    else ok "$new has taken the place of $old"; fi
    return 0
  fi
  [[ $ro == active* ]] || { conflict "$old is not a working member of $name ($([[ -n $ro ]] && echo "$ro" || echo "not in it")): add the new disk with md-add, and the array rebuilds onto it"; return 0; }
  if [[ -z $rn ]]; then devs_guard "$wipe" "$new" || return 0; fi
  act "mdadm $a --add $new, then --replace $old --with $new (the array stays redundant while it copies)" || return 0
  if [[ -z $rn ]]; then zp_wipe "$wipe" "$new" || return 0; try mdadm "$a" --add "$new" || return 0; fi
  try mdadm "$a" --replace "$old" --with "$new" || return 0
  ok "copying onto $new: $(md_progress "$a")"
  info "run the plan again when it is done to take $old out of the array"
}

t_md_grow() { local name=$1 devs=$2 size=$3 wipe=$4 a detail level state raid d r arr=() add=() count=0 p used min s
  need mdadm mdadm || return 0
  a=$(md_path "$name")
  detail=$(mdadm --detail "$a" 2>/dev/null) || { later "array $name must exist"; return 0; }
  p=$(md_progress "$a")
  if [[ $p == Reshape* ]]; then ok "a reshape is running: $p"; return 0; fi
  level=$(md_field "$detail" "Raid Level"); state=$(md_field "$detail" State); raid=$(md_field "$detail" "Raid Devices")
  read -ra arr <<<"$devs"
  for d in ${arr[@]+"${arr[@]}"}; do
    r=$(md_role "$detail" "$d")
    case $r in active*) ;; spare) count=$((count + 1)) ;; '') add+=("$d"); count=$((count + 1)) ;; *) conflict "$d is in $name as $r"; return 0 ;; esac
  done
  if ((count)); then
    case $level in raid1|raid4|raid5|raid6|raid10) ;; *) conflict "$name is $level: this step grows raid1, raid4, raid5, raid6 and raid10"; return 0 ;; esac
    [[ $state == *degraded* || $state == *recovering* || $state == *resyncing* ]] && { conflict "$name is $state: let it finish before growing it"; return 0; }
    ((${#add[@]})) && { devs_guard "$wipe" "${add[@]}" || return 0; }
    act "mdadm $a --grow --raid-devices=$((raid + count))${add[*]:+, after adding ${add[*]}}" || return 0
    if ((${#add[@]})); then zp_wipe "$wipe" "${add[@]}" || return 0; for d in "${add[@]}"; do try mdadm "$a" --add "$d" || return 0; done; fi
    try mdadm --grow "$a" --raid-devices="$((raid + count))" || return 0
    ok "growing to $((raid + count)) devices: $(md_progress "$a")"
    info "it runs in the background and the array stays usable; grow the filesystem on it once it is done"
    md_conf_refresh "$a"
    [[ $size == max ]] && info "the size grows on a run after the reshape is done"
    return 0
  fi
  ((${#arr[@]})) && ok "$devs are in $name: $raid devices"
  [[ $size == max ]] || return 0
  # each member a percent and 128 MiB larger than what the array uses of it: there is room to grow into
  used=$(md_field "$detail" "Used Dev Size" | awk "{print \$1}"); min=
  while read -r d; do s=$(lsblk -bndo SIZE -- "$d" 2>/dev/null) || continue; [[ -z $min || $s -lt $min ]] && min=$s; done < <(awk "\$NF ~ /^\\/dev\\// && /active/ {print \$NF}" <<<"$detail")
  if [[ -z $used || -z $min ]]; then conflict "could not read the sizes of $name and its devices"; return 0; fi
  if (( min / 1024 - used <= used / 100 + 131072 )); then ok "$name uses all of its devices"; return 0; fi
  act "mdadm $a --grow --size=max (each device has $(( (min / 1024 - used) / 1024 )) MiB more to give)" || return 0
  try mdadm --grow "$a" --size=max || return 0
  ok "grown: $(mdadm --detail "$a" | sed -n "s/^ *Array Size : //p")"
  info "grow the filesystem on it next (resize2fs, xfs_growfs or btrfs filesystem resize)"
}
md_conf_refresh() { # an ARRAY line that counts the devices goes stale when the count changes
  local conf=/etc/mdadm.conf uuid line; [[ -d /etc/mdadm ]] && conf=/etc/mdadm/mdadm.conf
  uuid=$(mdadm --detail --export "$1" 2>/dev/null | sed -n "s/^MD_UUID=//p")
  [[ -n $uuid ]] && grep -qs -- "UUID=$uuid.*num-devices=\|num-devices=.*UUID=$uuid" "$conf" || return 0
  line=$(mdadm --detail --brief "$1") || return 0
  cp -a "$conf" "$conf.storageforge-$STAMP"
  grep -v -- "$uuid" "$conf.storageforge-$STAMP" >"$conf"; printf "%s\n" "$line" >>"$conf"
  ok "$conf: the line for this array is brought up to date"
}

# ── LUKS ────────────────────────────────────────────────────────────
# luks_key SECRET: sets LUKS_KEY to the file vault send-secret wrote, after checking it is there and in memory
luks_key() { LUKS_KEY=/run/storageforge/secrets/$1
  if [[ ! -r $LUKS_KEY ]]; then
    if ((APPLY)); then conflict "no key at $LUKS_KEY: storageforge-index vault send-secret $1 --host $(uname -n), then run this again"
    else missing "it needs the key at $LUKS_KEY: storageforge-index vault send-secret $1 --host $(uname -n)"; fi
    return 1
  fi
  case $(stat -f -c %T "$LUKS_KEY" 2>/dev/null) in tmpfs|ramfs) ;; *) conflict "$LUKS_KEY is not in memory (tmpfs): a key is not kept on a disk"; return 1 ;; esac
}
# the key as it was typed, without the newline vault send-secret ends it with; printf is built in, so it is on no command line
luks_feed() { local k; k=$(<"$1"); printf "%s" "$k"; }
luks_drop() { rm -f -- "$@" && info "removed the key file: the vault keeps the key"; }
luks_crypttab() { # name device how: noauto (listed, opened by hand or a later step) or ask (asked for at boot, and boot goes on without it)
  local name=$1 dev=$2 how=$3 uuid opts line have
  [[ -n $how ]] || return 0
  uuid=$(cryptsetup luksUUID "$dev" 2>/dev/null) || { conflict "could not read the LUKS UUID of $dev"; return 1; }
  opts=luks,noauto; [[ $how == ask ]] && opts=luks,nofail
  line="$name UUID=$uuid none $opts"
  have=$(awk -v n="$name" "\$1 == n" /etc/crypttab 2>/dev/null)
  if [[ $have == "$line" ]]; then ok "/etc/crypttab lists $name"; return 0; fi
  [[ -n $have ]] && { conflict "/etc/crypttab has another line for $name: $have"; return 1; }
  act "add to /etc/crypttab: $line" || return 0
  [[ -e /etc/crypttab ]] && cp -a /etc/crypttab "/etc/crypttab.storageforge-$STAMP"
  printf "%s\n" "$line" >>/etc/crypttab; chmod 0600 /etc/crypttab; durable /etc/crypttab
  ok "/etc/crypttab: $line"
}
luks_open_now() { # device name keyfile
  if ! luks_feed "$3" | cryptsetup open --key-file=- "$1" "$2"; then conflict "cryptsetup open $1 $2 failed: the key of the vault secret does not open it"; return 1; fi
  ok "open at /dev/mapper/$2"
}

t_luks_format() { local dev=$1 name=$2 secret=$3 wipe=$4 open=$5 tab=$6
  need cryptsetup cryptsetup || return 0
  if cryptsetup isLuks "$dev" 2>/dev/null; then
    ok "$dev is LUKS already ($(cryptsetup luksUUID "$dev" 2>/dev/null))"
    if [[ -n $open && ! -e /dev/mapper/$name ]]; then
      luks_key "$secret" || return 0
      act "cryptsetup open $dev $name (the key through stdin)" || return 0
      luks_open_now "$dev" "$name" "$LUKS_KEY" || return 0
      luks_drop "$LUKS_KEY"
    elif [[ -n $open ]]; then ok "open at /dev/mapper/$name"; fi
    luks_crypttab "$name" "$dev" "$tab"
    return 0
  fi
  devs_guard "$wipe" "$dev" || return 0
  luks_key "$secret" || return 0
  act "cryptsetup luksFormat --type luks2 $dev, with the key of vault secret $secret through stdin${open:+, then open it as $name}" || return 0
  zp_wipe "$wipe" "$dev" || return 0
  if ! luks_feed "$LUKS_KEY" | cryptsetup luksFormat --type luks2 --batch-mode --key-file=- "$dev"; then conflict "cryptsetup luksFormat $dev failed"; return 0; fi
  ok "$dev is LUKS2 ($(cryptsetup luksUUID "$dev" 2>/dev/null))"
  if [[ -n $open ]]; then luks_open_now "$dev" "$name" "$LUKS_KEY" || return 0; fi
  luks_drop "$LUKS_KEY"
  luks_crypttab "$name" "$dev" "$tab"
}

t_luks_open() { local dev=$1 name=$2 secret=$3 tab=$4
  need cryptsetup cryptsetup || return 0
  if [[ -e /dev/mapper/$name ]]; then ok "open at /dev/mapper/$name"; luks_crypttab "$name" "$dev" "$tab"; return 0; fi
  cryptsetup isLuks "$dev" 2>/dev/null || { later "$dev must be a LUKS device"; return 0; }
  luks_key "$secret" || return 0
  act "cryptsetup open $dev $name (the key through stdin)" || return 0
  luks_open_now "$dev" "$name" "$LUKS_KEY" || return 0
  luks_drop "$LUKS_KEY"
  luks_crypttab "$name" "$dev" "$tab"
}

t_luks_close() { local name=$1 used holders
  need cryptsetup cryptsetup || return 0
  [[ -e /dev/mapper/$name ]] || { ok "$name is not open"; return 0; }
  used=$(lsblk -nro MOUNTPOINT "/dev/mapper/$name" 2>/dev/null | grep . | paste -sd" " -) || true
  [[ -z $used ]] || { conflict "/dev/mapper/$name is in use: mounted at $used. Unmount it first"; return 0; }
  holders=$(ls "/sys/class/block/$(basename "$(readlink -f "/dev/mapper/$name")")/holders" 2>/dev/null | paste -sd" " -) || true
  [[ -z $holders ]] || { conflict "/dev/mapper/$name holds $holders (LVM or another mapping): close those first"; return 0; }
  act "cryptsetup close $name" || return 0
  try cryptsetup close "$name" && ok "closed"
}

t_luks_add_key() { local dev=$1 secret=$2 new=$3 have tmp
  need cryptsetup cryptsetup || return 0
  cryptsetup isLuks "$dev" 2>/dev/null || { later "$dev must be a LUKS device"; return 0; }
  luks_key "$new" || return 0; local nk=$LUKS_KEY
  if luks_feed "$nk" | cryptsetup open --test-passphrase --key-file=- "$dev" 2>/dev/null; then
    ok "the key of $new opens $dev already"; ((APPLY)) && luks_drop "$nk"; return 0
  fi
  luks_key "$secret" || return 0; have=$LUKS_KEY
  luks_feed "$have" | cryptsetup open --test-passphrase --key-file=- "$dev" 2>/dev/null || { conflict "the key of $secret does not open $dev"; return 0; }
  act "cryptsetup luksAddKey $dev: a slot for the key of $new, unlocked with the key of $secret (both from files in memory)" || return 0
  tmp=$(mktemp -p /run/storageforge/secrets .sf-luks-XXXXXX) || { conflict "could not make a file in /run/storageforge/secrets"; return 0; }
  luks_feed "$nk" >"$tmp"
  if ! luks_feed "$have" | cryptsetup luksAddKey --key-file=- "$dev" "$tmp"; then rm -f -- "$tmp"; conflict "cryptsetup luksAddKey $dev failed"; return 0; fi
  rm -f -- "$tmp"
  ok "a key slot for $new on $dev"
  luks_drop "$nk" "$have"
}
"""


# ── checks against the index ────────────────────────────────────────
def zpool_statuses(c) -> list[dict]:
    """The pools zpool status printed at the last scan, with their vdevs."""
    from .payloads import parse_zpool_status
    inv = c.conn.scalar('SELECT inventory_json FROM hosts WHERE host_id = :h', {'h': c.h['id']})
    inv = (inv if isinstance(inv, dict) else json.loads(inv or '{}')) or {}
    return parse_zpool_status(inv['zpool_status']) if inv.get('zpool_status') else []


def vdev_shape(v: dict) -> str:
    """mirror:2, raidz2:6, stripe:1, as the script prints it."""
    kind = v['type'] if v['type'] != 'raidz' else 'raidz1'
    return 'stripe:1' if kind == 'disk' else f'{kind}:{len(v["members"])}'


def said(shape: str) -> str:
    kind, _, n = shape.partition(':')
    return f'a {n}-way mirror' if kind == 'mirror' else 'a single disk' if shape == 'stripe:1' else f'a {kind} of {n} disks'


def _leaf(name: str) -> str:
    return name.removeprefix('/dev/').removeprefix('disk/by-id/')


def _pool_status(c, h, pool, say):
    if pool not in c.zpools():
        say('crit' if c.zpools() else 'note', f'there is no pool {pool} on {h["name"]}' if c.zpools() else f'no ZFS pool in the last scan of {h["name"]}; the script checks')
        return None
    st = next((s for s in zpool_statuses(c) if s['name'] == pool), None)
    if not st and pool not in c.new_zpools:
        say('note', f'zpool status of {pool} was not read at the last scan: the script reads its layout before it adds anything')
    return st


def _in_pool(st: dict | None, dev: str) -> str | None:
    if not st:
        return None
    name = _leaf(dev)
    for v in st['vdevs']:
        for m in v['members']:
            if _leaf(m) == name or re.fullmatch(re.escape(name) + r'p?\d+', _leaf(m)):
                return 'disk' if v['type'] == 'disk' else v['type']
    for sec in ('log', 'cache', 'spares', 'special'):
        if any(_leaf(m) == name for m in st.get(sec) or []):
            return sec
    return None


def _device_size(c, dev):
    info = c.device(dev)
    if not info:
        return None
    return (info.get('part') or info.get('disk') or {}).get('size') if info['kind'] == 'part' else info['disk'].get('size')


def _check_zfs_add(conn, c, h, p, say):
    st = _pool_status(c, h, p['pool'], say)
    devs = p['devices'].split()
    role, level = p['role'] or 'data', p['level']
    if role == 'data' and len(devs) < ZFS_MIN[level]:
        say('crit', f'{level} needs at least {ZFS_MIN[level]} devices')
    if role == 'data' and level == 'stripe' and len(devs) > 1:
        say('warn', f'{len(devs)} single-disk vdevs: losing any one of them loses the pool')
    if role in ('cache', 'spare') and level != 'stripe':
        say('crit', f'a {role} vdev is a list of disks: choose stripe')
    if role == 'log' and level not in ('stripe', 'mirror'):
        say('crit', 'a log vdev is one disk or a mirror')
    if st and all(_in_pool(st, d) for d in devs):
        say('ok', f'{p["devices"]} already in pool {p["pool"]}: nothing to do')
        return
    if st and role == 'data':
        shapes = sorted({vdev_shape(v) for v in st['vdevs']})
        want = 'stripe:1' if level == 'stripe' else f'{level}:{len(devs)}'
        if any(s.startswith('draid') for s in shapes):
            say('crit', f'pool {p["pool"]} is draid: add to it by hand')
        elif shapes and any(s != want for s in shapes):
            say('crit', f'pool {p["pool"]} is made of {", ".join(said(s) for s in shapes)} and the new vdev would be {said(want)}: '
                        'zpool add refuses a mismatched layout unless forced, and this step never forces it')
        elif shapes:
            say('ok', f'the new vdev matches the pool: {said(want)}, like the {len(st["vdevs"])} there')
        say('note', 'a data vdev cannot be taken out of a pool that has a raidz vdev, so check the devices: the pool keeps them')
    changes._check_devices(c, h, devs, p['wipe'], say)
    if any(re.fullmatch(r'/dev/(sd[a-z]+|vd[a-z]+)\d*', d) for d in devs):
        say('warn', 'sdX names can change at boot: /dev/disk/by-id/... names are safer for a pool')


def _check_zfs_replace(conn, c, h, p, say):
    st = _pool_status(c, h, p['pool'], say)
    if not LEAF.fullmatch(p['old']) or p['old'].startswith('-'):
        say('crit', f'{p["old"]} is not a device, a name zpool status prints, or a guid')
        return
    if _leaf(p['old']) == _leaf(p['device']):
        say('crit', 'the old and the new device are the same: to bring a disk back after it was swapped in place, run zpool replace POOL DEVICE by hand')
        return
    if st and _in_pool(st, p['device']):
        say('ok', f'{p["device"]} is in pool {p["pool"]} already')
        return
    if st and not _in_pool(st, p['old']) and not p['old'].isdigit():
        say('crit', f'{p["old"]} is not in pool {p["pool"]} at the last scan')
    elif st and _in_pool(st, p['old']) in ('cache', 'spares'):
        say('crit', f'{p["old"]} is a {_in_pool(st, p["old"])} device: remove it and add the new one instead')
    old, new = _device_size(c, p['old']) if p['old'].startswith('/dev/') else None, _device_size(c, p['device'])
    if old and new and new < old:
        say('crit', f'{p["device"]} is smaller than {p["old"]}: zpool replace needs a device at least as large')
    changes._check_devices(c, h, [p['device']], p['wipe'], say)
    say('note', 'resilvers in the background while the pool stays in use; the old device leaves the pool when it is done')


def _check_zfs_attach(conn, c, h, p, say):
    st = _pool_status(c, h, p['pool'], say)
    if not LEAF.fullmatch(p['existing']) or p['existing'].startswith('-'):
        say('crit', f'{p["existing"]} is not a device or a name zpool status prints')
        return
    if st and _in_pool(st, p['device']):
        say('ok', f'{p["device"]} is in pool {p["pool"]} already')
        return
    where = _in_pool(st, p['existing'])
    if st and not where:
        say('crit', f'{p["existing"]} is not in pool {p["pool"]} at the last scan')
    elif where and where not in ('disk', 'mirror', 'log'):
        say('crit', f'{p["existing"]} is in a {where} vdev: attach makes a mirror of a single disk or widens a mirror, and nothing else')
    elif where == 'disk':
        say('ok', f'{p["existing"]} becomes a 2-way mirror with {p["device"]}')
    elif where == 'mirror':
        say('ok', f'the mirror {p["existing"]} is in gets one more side')
    old, new = _device_size(c, p['existing']) if p['existing'].startswith('/dev/') else None, _device_size(c, p['device'])
    if old and new and new < old:
        say('crit', f'{p["device"]} is smaller than {p["existing"]}: a mirror side must be at least as large')
    changes._check_devices(c, h, [p['device']], p['wipe'], say)


def _md_pool(c, name):
    return next((x for x in c.node['pools'] if x['type'] == 'mdadm' and x['name'] in (name, f'md/{name}')), None)


def _check_md_name(c, h, name, say):
    if not MD_NAME.fullmatch(name):
        say('crit', f'{name} is not an array name: letters, digits, - and _, up to 32')
        return None, False
    pool = _md_pool(c, name)
    if not pool:
        say('note', f'no array {name} in the last scan of {h["name"]} (lsblk names arrays md127 and so on): the script looks for /dev/md/{name}')
    return pool, True


def _member(pool, dev) -> bool:
    return bool(pool) and dev.removeprefix('/dev/') in pool['members']


def _check_md_add(conn, c, h, p, say):
    pool, good = _check_md_name(c, h, p['name'], say)
    if not good:
        return
    if _member(pool, p['device']):
        say('ok', f'{p["device"]} is in {p["name"]} already')
        return
    changes._check_devices(c, h, [p['device']], p['wipe'], say)
    if pool and pool['level'] in ('raid0', 'linear'):
        say('crit', f'{p["name"]} is {pool["level"]}: a disk added to it is not used. Grow it instead')
    say('note', 'a working array takes it as a spare; a degraded one rebuilds onto it at once')


def _check_md_replace(conn, c, h, p, say):
    pool, good = _check_md_name(c, h, p['name'], say)
    if not good:
        return
    if p['old'] == p['device']:
        say('crit', 'the old and the new device are the same')
        return
    if _member(pool, p['device']) and not _member(pool, p['old']):
        say('ok', f'{p["device"]} has taken the place of {p["old"]}')
        return
    if pool and not _member(pool, p['old']):
        say('crit', f'{p["old"]} is not in {p["name"]} at the last scan')
    if pool and pool['level'] in ('raid0', 'linear'):
        say('crit', f'{p["name"]} is {pool["level"]}: mdadm replaces a disk only in an array with redundancy')
    old, new = _device_size(c, p['old']), _device_size(c, p['device'])
    if old and new and new < old:
        say('crit', f'{p["device"]} is smaller than {p["old"]}')
    changes._check_devices(c, h, [p['device']], p['wipe'], say)
    say('note', 'copies onto the new disk while the array stays redundant; a rerun takes the old one out once it is done')


def _check_md_grow(conn, c, h, p, say):
    pool, good = _check_md_name(c, h, p['name'], say)
    if not good:
        return
    devs = p['devices'].split()
    if not devs and p['size'] != 'max':
        say('crit', 'name the devices to grow onto, or grow to the full size of the devices it has')
        return
    if pool and devs and pool['level'] not in MD_GROWS:
        say('crit', f'{p["name"]} is {pool["level"]}: this step grows {", ".join(MD_GROWS)}')
    if pool and devs and all(_member(pool, d) for d in devs):
        say('ok', f'{p["devices"]} are in {p["name"]} already')
    elif devs:
        changes._check_devices(c, h, [d for d in devs if not _member(pool, d)], p['wipe'], say)
        if pool:
            say('ok', f'{p["name"]} grows from {len(pool["members"])} to {len(pool["members"]) + len([d for d in devs if not _member(pool, d)])} devices')
        say('note', 'the reshape runs in the background and can take hours; the array stays usable. Grow the filesystem on it after')
        if pool and pool['level'] in ('raid5', 'raid6'):
            say('warn', 'a power cut during a reshape is survived with metadata 1.x, and still the riskiest time for the array: have a backup')
    if p['size'] == 'max':
        say('note', 'the size grows once no reshape is running, to the smallest device in the array')


def _check_luks_names(p, say, *, secret='secret'):
    good = True
    if 'name' in p and not MAPPER.fullmatch(p['name']):
        say('crit', f'{p["name"]} is not a mapping name: letters, digits, . _ and -')
        good = False
    for key in (secret, 'new_secret'):
        if p.get(key) and not SECRET.fullmatch(p[key]):
            say('crit', f'{p[key]} is not a secret name: letters, digits, . _ and -')
            good = False
    return good


def _send_note(h, *names):
    sends = ' and '.join(f'storageforge-index vault send-secret {n} --host {h["name"]}' for n in names)
    return f'the key is read on {h["name"]} from {SECRET_DIR}, in memory, and goes to cryptsetup on stdin: before running, {sends}. The file is removed once it is used'


def _check_luks_format(conn, c, h, p, say):
    if not _check_luks_names(p, say):
        return
    info = c.device(p['device'])
    if info and (info.get('fs') == 'crypto_LUKS' or info.get('part', {}).get('encrypted')):
        say('ok', f'{p["device"]} is LUKS already: it is not formatted again')
    else:
        changes._check_devices(c, h, [p['device']], p['wipe'], say)
    if p['crypttab'] == 'ask':
        say('note', 'at boot the passphrase is asked for on the console, and the boot goes on without it if nobody types it (nofail)')
    say('note', _send_note(h, p['secret']))


def _check_luks_open(conn, c, h, p, say):
    if not _check_luks_names(p, say):
        return
    info = c.device(p['device'])
    if info and info.get('part', {}).get('crypt') == p['name']:
        say('ok', f'{p["device"]} is open as {p["name"]} already')
        return
    if not info and not p['device'].startswith(('/dev/disk/', '/dev/mapper/')):
        say('note', f'{p["device"]} was not seen by the last scan of {h["name"]}: the script looks')
    elif info and info.get('fs') not in (None, 'crypto_LUKS') and not info.get('part', {}).get('encrypted'):
        say('crit', f'{p["device"]} holds {info["fs"]}, not LUKS')
    say('note', _send_note(h, p['secret']))


def _check_luks_close(conn, c, h, p, say):
    if not _check_luks_names(p, say):
        return
    used = sorted(t for t, m in c.mounted.items() if (m.get('source') or '').split('[')[0] in (f'/dev/mapper/{p["name"]}', f'mapper/{p["name"]}'))
    if used:
        say('crit', f'/dev/mapper/{p["name"]} is mounted at {", ".join(used)}: unmount it first')
    say('note', 'the device stays LUKS and its data stays; only the open mapping goes')


def _check_luks_add_key(conn, c, h, p, say):
    if not _check_luks_names(p, say):
        return
    if p['secret'] == p['new_secret']:
        say('crit', 'the new key is the key it has')
        return
    say('note', 'cryptsetup checks the key it has opens the device before it adds the new one: the new key goes in a free slot and the old keys stay')
    say('note', _send_note(h, p['secret'], p['new_secret']))


# ── Ansible: the same function the script runs, gated as the drive tasks are ──
def _ansible(fn: str, args: tuple, destructive: bool):
    def render(t):
        q = shlex.quote
        p = t['params']
        call = ' '.join(q(str(p.get(a) if not isinstance(p.get(a), bool) else ('1' if p[a] else ''))) for a in args)
        helpers = ''.join(re.search(rf'^{name}\(\) \{{.*?^\}}$', changes.CHANGE_BODY_3, re.M | re.S)[0] + '\n' for name in ('devs_guard', 'dev_guard'))
        head = ('set -u; APPLY=1; STAMP=$(date +%Y%m%d-%H%M%S); ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }\n'
                'info() { echo "$*"; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }; durable() { sync; }\n'
                'need() { command -v "$1" >/dev/null || conflict "$1 is not installed (package ${2:-$1})"; }\n')
        task = {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + helpers + BASH + f'\n{fn} {call}\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
        if destructive:
            task.update({'tags': ['destructive'], 'when': 'storageforge_destructive | default(false) | bool'})
        return task
    return render


def _reg(kind, spec, args, title_of, check_of):
    changes.register(kind, spec, args, title_of, check_of, _ansible('t_' + kind.replace('-', '_'), args, bool(spec.get('destructive'))))


_reg('zfs-add', {'group': 'ZFS', 'label': 'Add a vdev to a pool', 'destructive': True, 'fields': [
    F('pool', 'name', 'Pool', required=True), F('level', 'choice', 'Layout of the new vdev', options=ZFS_LEVELS, required=True), DEVICES,
    F('role', 'choice', 'As (data if empty)', options=[''] + ROLES[1:]), WIPE, CONFIRM_ALL],
    'help': 'The new vdev must have the layout the pool has: a mirror pool takes another mirror of as many disks. zpool add refuses '
            'anything else unless forced, and this step never forces it. A data vdev cannot be taken out of a pool with raidz in it.'},
    ('pool', 'level', 'devices', 'role', 'wipe'), lambda p: f'Add {p["level"]} {p["devices"]} to ZFS pool {p["pool"]}' + (f' as {p["role"]}' if p['role'] else ''),
    _check_zfs_add)

_reg('zfs-replace', {'group': 'ZFS', 'label': 'Replace a disk in a pool', 'destructive': True, 'fields': [
    F('pool', 'name', 'Pool', required=True), F('old', 'word', 'Disk to replace (as zpool status names it, or its guid)', required=True, placeholder='/dev/sdb or 1234567890'),
    F('device', 'device', 'New disk', required=True), WIPE, CONFIRM],
    'help': 'Resilvers onto the new disk while the pool stays in use; the old one leaves the pool when it is done.'},
    ('pool', 'old', 'device', 'wipe'), lambda p: f'Replace {p["old"]} with {p["device"]} in ZFS pool {p["pool"]}', _check_zfs_replace)

_reg('zfs-attach', {'group': 'ZFS', 'label': 'Attach a disk (make or widen a mirror)', 'destructive': True, 'fields': [
    F('pool', 'name', 'Pool', required=True), F('existing', 'word', 'Disk in the pool to mirror', required=True, placeholder='/dev/sdb'),
    F('device', 'device', 'New disk', required=True), WIPE, CONFIRM],
    'help': 'A single disk becomes a 2-way mirror, or a mirror gets one more side. A raidz is not widened here.'},
    ('pool', 'existing', 'device', 'wipe'), lambda p: f'Attach {p["device"]} to {p["existing"]} in ZFS pool {p["pool"]}', _check_zfs_attach)

_reg('md-add', {'group': 'mdadm', 'label': 'Add a disk to an array', 'destructive': True, 'fields': [
    F('name', 'name', 'Array (/dev/md/<name>, or md0)', required=True, placeholder='data'), F('device', 'device', 'New disk', required=True), WIPE, CONFIRM],
    'help': 'A working array takes it as a spare; a degraded one rebuilds onto it at once.'},
    ('name', 'device', 'wipe'), lambda p: f'Add {p["device"]} to mdadm array {p["name"]}', _check_md_add)

_reg('md-replace', {'group': 'mdadm', 'label': 'Replace a disk in an array', 'destructive': True, 'fields': [
    F('name', 'name', 'Array (/dev/md/<name>, or md0)', required=True, placeholder='data'), F('old', 'device', 'Disk to replace', required=True),
    F('device', 'device', 'New disk', required=True), WIPE, CONFIRM],
    'help': 'Copies onto the new disk while the array stays redundant (mdadm --replace). Run the plan again once it is done to take the old disk out.'},
    ('name', 'old', 'device', 'wipe'), lambda p: f'Replace {p["old"]} with {p["device"]} in mdadm array {p["name"]}', _check_md_replace)

_reg('md-grow', {'group': 'mdadm', 'label': 'Grow an array', 'destructive': True, 'confirm_of': 'name', 'fields': [
    F('name', 'name', 'Array (/dev/md/<name>, or md0)', required=True, placeholder='data'),
    F('devices', 'devices', 'Devices to grow onto', placeholder='/dev/sdd'), F('size', 'choice', 'Then use all of each device', options=['', 'max']), WIPE,
    F('confirm', 'confirm', 'Type the devices again (or the array name, to only grow the size)', required=True)],
    'help': 'Adds the devices and reshapes the array onto them, which runs in the background for hours while the array stays usable. '
            'After larger disks replaced the old ones, max grows the array into them. Grow the filesystem on it afterwards.'},
    ('name', 'devices', 'size', 'wipe'), lambda p: f'Grow mdadm array {p["name"]}' + (f' onto {p["devices"]}' if p['devices'] else '') + (' to the full size of its devices' if p['size'] else ''),
    _check_md_grow)

_reg('luks-format', {'group': 'LUKS', 'label': 'Encrypt a device (LUKS)', 'destructive': True, 'fields': [
    F('device', 'device', 'Device', required=True), F('name', 'name', 'Open it as /dev/mapper/', required=True, placeholder='data-crypt'),
    F('secret', 'name', 'Key (a vault secret)', required=True, placeholder='data-luks-key'), WIPE, F('open', 'bool', 'Open it after', default=True),
    F('crypttab', 'choice', 'List it in /etc/crypttab', options=CRYPTTAB), CONFIRM],
    'help': 'LUKS2, with a key the vault holds. The key reaches the host with vault send-secret and goes to cryptsetup on stdin, '
            'never on a command line; the file is removed once it is used.'},
    ('device', 'name', 'secret', 'wipe', 'open', 'crypttab'), lambda p: f'Encrypt {p["device"]} with LUKS' + (f' and open it as {p["name"]}' if p['open'] else ''),
    _check_luks_format)

_reg('luks-open', {'group': 'LUKS', 'label': 'Open a LUKS device', 'fields': [
    F('device', 'device', 'Device', required=True), F('name', 'name', 'As /dev/mapper/', required=True, placeholder='data-crypt'),
    F('secret', 'name', 'Key (a vault secret)', required=True, placeholder='data-luks-key'), F('crypttab', 'choice', 'List it in /etc/crypttab', options=CRYPTTAB)],
    'help': 'The key reaches the host with vault send-secret and goes to cryptsetup on stdin; the file is removed once it is used.'},
    ('device', 'name', 'secret', 'crypttab'), lambda p: f'Open {p["device"]} as {p["name"]}', _check_luks_open)

_reg('luks-close', {'group': 'LUKS', 'label': 'Close a LUKS device', 'fields': [F('name', 'name', 'Mapping (/dev/mapper/<name>)', required=True)],
     'help': 'Only when nothing is mounted from it. The data and the encryption stay.'},
     ('name',), lambda p: f'Close {p["name"]}', _check_luks_close)

_reg('luks-add-key', {'group': 'LUKS', 'label': 'Add a key to a LUKS device', 'fields': [
    F('device', 'device', 'Device', required=True), F('secret', 'name', 'A key it has (a vault secret)', required=True),
    F('new_secret', 'name', 'The new key (a vault secret)', required=True)],
    'help': 'Both keys reach the host with vault send-secret and stay in memory; the new one goes in a free key slot and the old keys stay.'},
    ('device', 'secret', 'new_secret'), lambda p: f'Add the key {p["new_secret"]} to {p["device"]}', _check_luks_add_key)

changes.EXTRA_BASH.append(BASH)
