"""rclone on a host: a remote from the vault, with rclone crypt on top if asked, mounted by a systemd unit.

One library for every place StorageForge uses rclone: the rclone-mount plan step here (a cloud drive or any rclone backend mounted on a
host), and the rclone share protocol (share_rclone.py), which serves a remote to other hosts.

The remote's sensitive settings never sit in a plan, a script or a log. They are a vault secret holding rclone config lines
(`key = value`, as `rclone config show` prints them: a Drive token and client, S3 keys, a WebDAV password), which comes on the signed
runner's stdin in an apply (secretstore.py) and is written, with the plain settings the step names, into a file only root can read:
/etc/storageforge/rclone/NAME.conf. Crypt's two passwords are a second vault secret (`password = …`, and `password2 = …` for the salt),
obscured on the host with `rclone obscure -`, which reads them from a pipe, so they are on no command line.

Losing the crypt secret loses the data behind it: rclone cannot decrypt without it, and neither can anyone else. The vault's backups
keep it; keep a copy offline too.

rclone obscure gives a new answer every run, so the file is rewritten only when what went into it changed: a hash of the inputs is kept
beside it (NAME.inputs, 0600), and a remount follows only then. The mount is a unit, storageforge-rclone-<escaped target>.service, that
waits for the network, restarts when rclone fails, and is left out at boot rather than holding it up when the remote cannot be reached.

Google Drive: rclone's shared client ID is being retired during 2026, so a Drive remote takes your own client (a Desktop-app OAuth
client in Google Cloud, with the Drive API on). Run `rclone authorize "drive" "CLIENT_ID" "CLIENT_SECRET"` on a machine with a browser,
then keep client_id, client_secret and the token it prints in one vault secret (docs/network-filesystems.md).
"""
from __future__ import annotations

import re
import shlex

from . import changes
from .changes import F

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,40}')
BACKEND = re.compile(r'[a-z][a-z0-9]{1,30}')
OPTION = re.compile(r'[a-z][a-z0-9_]{0,60}=[A-Za-z0-9_.:/@+-]{0,300}')
REMOTE_PATH = re.compile(r'[A-Za-z0-9_.:/@+ -]{0,300}')
# The backends offered first: the common ones. Any other rclone backend name works too (rclone help backends lists them).
BACKENDS = ('drive', 'onedrive', 'dropbox', 'box', 'pcloud', 'mega', 'protondrive', 'koofr', 'jottacloud', 'seafile', 's3', 'b2',
            'gcs', 'azureblob', 'azurefiles', 'swift', 'storj', 'sftp', 'webdav', 'ftp', 'smb', 'http', 'hidrive', 'yandex', 'zoho')
CACHE_MODES = ('writes', 'off', 'minimal', 'full')
FILENAME_ENC = ('standard', 'obfuscate', 'off')
ARGS = ('name', 'backend', 'remote_path', 'options', 'secret', 'crypt', 'crypt_secret', 'filename_encryption', 'target', 'owner', 'cache', 'state')

# Shared by the plan step and share_rclone.py. No apostrophes: a change plan's script is checked for words that could end a quote.
LIB = r"""
rc_bin() { command -v rclone 2>/dev/null || { [[ -x /usr/bin/rclone ]] && echo /usr/bin/rclone; }; }
rc_install() { # rclone and FUSE, from the package manager of this host
  local m pkgs="rclone fuse3"
  if [[ -n $(rc_bin) ]] && { command -v fusermount3 >/dev/null || command -v fusermount >/dev/null; }; then ok "rclone $(rclone version 2>/dev/null | head -n 1 | cut -d" " -f2) and FUSE installed"; return 0; fi
  for m in apt-get dnf yum zypper pacman; do command -v $m >/dev/null && break; m=; done
  [[ -n $m ]] || { conflict "rclone is not installed and this host has no package manager I know (apt, dnf, yum, zypper, pacman)"; return 1; }
  [[ $m == zypper ]] && pkgs="rclone fuse3"
  act "install $pkgs with $m" || return 1
  case $m in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y -q $pkgs >/dev/null 2>&1 || { apt-get update -q >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -q $pkgs >/dev/null 2>&1; } ;;
    dnf|yum) $m install -y -q $pkgs >/dev/null 2>&1 ;;
    zypper) zypper -n -q install $pkgs >/dev/null 2>&1 ;;
    pacman) pacman -S --noconfirm --needed $pkgs >/dev/null 2>&1 ;;
  esac
  [[ -n $(rc_bin) ]] || { conflict "could not install rclone with $m"; return 1; }
  ok "installed rclone $(rclone version 2>/dev/null | head -n 1 | cut -d" " -f2)"
}
rc_secret() { local d=/run/storageforge/secrets; ((EUID != 0)) && d=${SF_SECRET_DIR:-$d}; echo "$d/$1"; }
# NAME BACKEND OPTIONS SECRET CRYPT CRYPT_SECRET FNENC REMOTE_PATH -> /etc/storageforge/rclone/NAME.conf, rewritten when its inputs
# changed. 0: written now, 1: as it was, 2: could not (said why).
rc_config() {
  local name=$1 backend=$2 opts=$3 secret=$4 crypt=$5 csecret=$6 fnenc=${7:-standard} rpath=$8
  local dir=${SF_RCLONE_DIR:-/etc/storageforge/rclone} conf src csrc sum kv p p2 tmp
  conf=$dir/$name.conf
  src=$(rc_secret "$secret"); csrc=
  [[ -z $secret || -s $src ]] || { conflict "the vault secret $secret is not on this host: apply this from StorageForge, which brings it"; return 2; }
  if [[ -n $crypt ]]; then
    [[ -n $csecret ]] || { conflict "rclone crypt needs a vault secret with its passwords"; return 2; }
    csrc=$(rc_secret "$csecret")
    [[ -s $csrc ]] || { conflict "the vault secret $csecret is not on this host: apply this from StorageForge, which brings it"; return 2; }
    grep -qE "^password *= *[^ ]" "$csrc" || { conflict "the vault secret $csecret has no password = line"; return 2; }
  fi
  sum=$( { printf "%s\n" "$name" "$backend" "$opts" "$crypt" "$fnenc" "$rpath"; [[ -z $secret ]] || cat -- "$src"; [[ -z $csrc ]] || cat -- "$csrc"; } | sha256sum | cut -d" " -f1)
  if [[ -s $conf && $(cat "$conf.inputs" 2>/dev/null) == "$sum" ]]; then ok "$conf"; return 1; fi
  act "write the rclone config $conf (root only)" || return 1
  (umask 077; mkdir -p "$dir") && chmod 700 "$dir"
  tmp=$(mktemp "$dir/.$name.XXXXXX") || { conflict "could not write in $dir"; return 2; }
  {
    printf "[%s]\ntype = %s\n" "$name" "$backend"
    for kv in ${opts//,/ }; do printf "%s = %s\n" "${kv%%=*}" "${kv#*=}"; done
    [[ -z $secret ]] || grep -vE "^\s*(\[|type *=)" "$src" || true
    if [[ -n $csrc ]]; then
      p=$(sed -n "s/^password *= *//p" "$csrc" | head -n 1); p2=$(sed -n "s/^password2 *= *//p" "$csrc" | head -n 1)
      printf "\n[%s-crypt]\ntype = crypt\nremote = %s:%s\nfilename_encryption = %s\ndirectory_name_encryption = %s\n" "$name" "$name" "$rpath" "$fnenc" "$([[ $fnenc == off ]] && echo false || echo true)"
      printf "password = %s\n" "$(printf "%s" "$p" | rclone obscure -)"
      [[ -z $p2 ]] || printf "password2 = %s\n" "$(printf "%s" "$p2" | rclone obscure -)"
      p= p2=
    fi
  } >"$tmp" || { rm -f -- "$tmp"; conflict "could not write $conf"; return 2; }
  if durable "$tmp" && mv -f -- "$tmp" "$conf" && (umask 077; printf "%s\n" "$sum" >"$conf.inputs"); then ok "wrote $conf"; return 0; fi
  rm -f -- "$tmp"; conflict "could not write $conf"; return 2
}
# UNIT REMOTE TARGET CONF OWNER CACHE DESCRIPTION [CHANGED] -> the mount unit, enabled and running; restarted when the config CHANGED
rc_mount_unit() {
  local unit=$1 remote=$2 target=$3 conf=$4 owner=${5:-root} cache=${6:-writes} what=$7 changed=${8:-0} f=${SF_UNIT_DIR:-/etc/systemd/system}/$1 body uid gid bin
  bin=$(rc_bin); bin=${bin:-/usr/bin/rclone}
  uid=$(id -u "$owner" 2>/dev/null) || { conflict "there is no account $owner here"; return 0; }
  gid=$(id -g "$owner")
  body="# Written by StorageForge: $what. Edit the plan, not this file.
[Unit]
Description=StorageForge rclone mount: $what
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
ExecStartPre=/usr/bin/mkdir -p \"$target\"
ExecStart=$bin mount \"$remote\" \"$target\" --config \"$conf\" --cache-dir /var/cache/storageforge/rclone --vfs-cache-mode $cache --allow-other --uid $uid --gid $gid --umask 002 --dir-cache-time 5m --log-level NOTICE
ExecStop=/bin/sh -c \"fusermount3 -uz \\\"$target\\\" 2>/dev/null || fusermount -uz \\\"$target\\\"\"
Restart=on-failure
RestartSec=15
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target"
  if [[ -e $f && $(cat "$f") == "$body" ]]; then ok "$unit"
  else
    act "write $unit" || return 0
    printf "%s\n" "$body" >"$f.sf-new" && durable "$f.sf-new" && mv -f -- "$f.sf-new" "$f" || { rm -f -- "$f.sf-new"; conflict "could not write $f"; return 0; }
    reload_systemd; changed=1
  fi
  if systemctl is-enabled -q "$unit" 2>/dev/null && systemctl is-active -q "$unit"; then
    if ((changed)); then act "restart $unit for the new settings" && { systemctl restart "$unit" 2>&1 || conflict "$unit did not start again: $(systemctl status "$unit" --no-pager -n 3 2>&1 | tail -n 3 | tr "\n" " ")"; }; else ok "$unit running"; fi
  else
    act "start $unit" || return 0
    systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "$unit did not start: $(journalctl -u "$unit" -n 3 --no-pager 2>&1 | tail -n 3 | tr "\n" " ")"
  fi
  if timeout -k 2 10 mountpoint -q "$target"; then ok "$target is mounted"; elif ((APPLY)); then conflict "$target is not mounted: journalctl -u $unit"; fi
  return 0
}
rc_drop_unit() { # UNIT -> stopped, disabled and removed
  local f=${SF_UNIT_DIR:-/etc/systemd/system}/$1
  [[ -e $f ]] || { ok "no $1"; return 0; }
  act "stop and remove $1" || return 0
  systemctl disable --now "$1" >/dev/null 2>&1 || true
  rm -f -- "$f"; reload_systemd; ok "removed $1"
}
"""

BASH = LIB + r"""
t_rclone_mount() { local name=$1 backend=$2 rpath=$3 opts=$4 secret=$5 crypt=$6 csecret=$7 fnenc=${8:-standard} target=$9 owner=${10:-root} cache=${11:-writes} state=${12:-present}
  local unit conf=${SF_RCLONE_DIR:-/etc/storageforge/rclone}/$1.conf remote rc
  unit=storageforge-rclone-$(systemd-escape -p "$target").service
  if [[ $state == absent ]]; then
    rc_drop_unit "$unit"
    if [[ -e $conf ]]; then act "remove $conf" && rm -f -- "$conf" "$conf.inputs"; fi
    return 0
  fi
  if ((!APPLY)); then
    command -v rclone >/dev/null && ok "rclone installed" || missing "would install rclone and FUSE"
    [[ -e ${SF_UNIT_DIR:-/etc/systemd/system}/$unit ]] && info "$unit is there: an apply checks its settings and the config against the vault secrets" || missing "would mount $name ($backend) at $target"
    timeout -k 2 10 mountpoint -q "$target" && ok "$target is mounted"
    return 0
  fi
  rc_install || return 0
  rc=0; rc_config "$name" "$backend" "$opts" "$secret" "$crypt" "$csecret" "$fnenc" "$rpath" || rc=$?   # set -e: 1 and 2 are answers
  ((rc == 2)) && return 0
  if [[ -n $crypt ]]; then remote="$name-crypt:"; else remote="$name:$rpath"; fi
  rc_mount_unit "$unit" "$remote" "$target" "$conf" "$owner" "$cache" "$name ($backend$([[ -n $crypt ]] && echo ", encrypted")) at $target" "$([[ $rc == 0 ]] && echo 1 || echo 0)"
}
"""


def _check(conn, c, h, p, say):
    if not NAME.fullmatch(p.get('name') or ''):
        say('crit', 'the remote name is letters, digits, dash and underscore, such as gdrive')
    if not BACKEND.fullmatch(p.get('backend') or ''):
        say('crit', 'the backend is an rclone backend name, such as drive, s3 or webdav')
    opts = [o for o in (p.get('options') or '').split(',') if o]
    bad = [o for o in opts if not OPTION.fullmatch(o)]
    if bad:
        say('crit', f'options are key=value, comma separated: {", ".join(bad)}')
    if any(o.split('=')[0] in ('token', 'client_secret', 'password', 'pass', 'secret_access_key', 'key', 'account_key', 'sas_url',
                               'service_account_credentials') for o in opts):
        say('crit', 'a password, key or token goes in the vault secret, not in the options: options are in the plan for anyone to read')
    if not REMOTE_PATH.fullmatch(p.get('remote_path') or ''):
        say('crit', 'the path in the remote is a folder or bucket path')
    target = p.get('target') or ''
    if any(ch in target for ch in '"\\%\n'):
        say('crit', 'the mount point cannot hold " \\ or %')
    if p.get('state') == 'absent':
        say('note', f'stops the rclone mount at {target} and removes its unit and config; nothing in the remote is touched')
        return
    if not p.get('secret') and p.get('backend') not in ('http', 'local', 'alias', 'union', 'combine'):
        say('warn', f'no vault secret: {p.get("backend")} usually needs a token, keys or a password (keep its rclone config lines in one secret)')
    if p.get('backend') == 'drive':
        say('note', 'Google Drive takes your own OAuth client: rclone\'s shared one is being retired during 2026. The secret holds client_id, '
                    'client_secret and the token `rclone authorize "drive" "CLIENT_ID" "CLIENT_SECRET"` printed (docs/network-filesystems.md)')
        if 'scope=' not in (p.get('options') or ''):
            say('note', 'no scope set: rclone uses drive (full access); drive.file limits it to what rclone made')
    if p.get('crypt'):
        if not p.get('crypt_secret'):
            say('crit', 'encryption needs a second vault secret with its passwords: password = …, and password2 = … for the salt')
        say('warn', 'the files are encrypted with the crypt secret: without it nobody can read them again, StorageForge included. '
                    'Keep a copy of that secret offline, beside the vault backups')
        if p.get('filename_encryption') == 'off':
            say('note', 'file and folder names stay readable in the remote: only contents are encrypted')
    if (p.get('cache') or 'writes') == 'off':
        say('note', 'no VFS cache: many programs that write files (office documents, databases) fail on a mount without it')
    say('note', f'the secrets reach {h["name"]} on the runner stdin when this plan is applied from StorageForge, into a root-only '
                f'/etc/storageforge/rclone/{p.get("name")}.conf. A policy on a secret that names steps must name rclone-mount')


def _title(p) -> str:
    if p.get('state') == 'absent':
        return f'Remove the rclone mount at {p.get("target")}'
    return f'Mount {p.get("backend")} remote {p.get("name")} at {p.get("target")}' + (' (encrypted)' if p.get('crypt') else '')


def _ansible(t, conn=None):
    q = shlex.quote
    p = t['params']
    head = changes.ansible_head('act() { echo "changed: $*"; }; durable() { sync; }; reload_systemd() { systemctl daemon-reload; }\n')
    words = changes.words_of(p, ARGS)
    return changes.shell_task(t, head + BASH + '\nt_rclone_mount ' + ' '.join(q(w) for w in words) + '\n')


changes.register('rclone-mount', {'group': 'Mounts', 'label': 'Mount an rclone remote (cloud drive, S3, WebDAV …)', 'fields': [
    F('name', 'name', 'Remote name', required=True, placeholder='gdrive'),
    F('backend', 'choice', 'Backend', options=list(BACKENDS), default='drive'),
    F('remote_path', 'text', 'Folder or bucket in the remote', placeholder='Backups/nas  ·  my-bucket/data'),
    F('options', 'options', 'Settings that are not secret (key=value, comma separated)', placeholder='scope=drive.file,team_drive=…'),
    F('secret', 'name', 'Vault secret with its rclone config lines (token, keys, password)', placeholder='gdrive-rclone'),
    F('crypt', 'bool', 'Encrypt with rclone crypt'),
    F('crypt_secret', 'secret', 'Vault secret with the crypt passwords (password = …, password2 = …)', placeholder='gdrive-crypt'),
    F('filename_encryption', 'choice', 'Encrypt file names', options=list(FILENAME_ENC), default='standard'),
    F('target', 'path', 'Mount point', required=True, placeholder='/mnt/gdrive'),
    F('owner', 'user', 'Files appear owned by', placeholder='root'),
    F('cache', 'choice', 'VFS cache', options=list(CACHE_MODES), default='writes'),
    F('state', 'choice', 'Mount or remove', options=['present', 'absent'], default='present')],
    'help': 'Any rclone backend mounted on the host by a systemd unit, with rclone crypt on top if asked. Tokens, keys and passwords stay in '
            'the vault and reach the host only when the plan is applied, into a config file only root can read.'},
    ARGS, _title, _check, _ansible)
changes.EXTRA_BASH.append(BASH)
