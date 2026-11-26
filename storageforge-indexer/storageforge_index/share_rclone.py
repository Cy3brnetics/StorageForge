"""rclone serve shares: an rclone remote (an encrypted Google Drive, say) served from the server to the LAN, so only the server holds the
cloud credentials.

Server: the remote's rclone config lines (a vault secret, with crypt on top if asked) are written by rclone.py's library into
/etc/storageforge/rclone/sf-serve-NAME.conf, and a unit, storageforge-rclone-serve-NAME.service, runs `rclone serve webdav|sftp|s3|http`
on it. The share's folder is rclone's VFS cache directory for the served remote, so it has to be on a local disk. The password
clients log in with comes from a second vault secret and is written to a root-only file the unit reads (--htpasswd for webdav and http,
an EnvironmentFile for sftp and s3): never on a command line.

Client: the same protocol mounted with rclone (rc_config for the remote, rc_mount_unit for the unit named like every share unit), from a
vault secret that holds the remote's login lines (user and obscured pass, or the S3 keys).
"""
from __future__ import annotations

import re

from . import netshares, rclone
from .netshares import Driver, Field

SERVE_AS = ('webdav', 'sftp', 's3', 'http')
BACKEND_OF = {'webdav': 'webdav', 'sftp': 'sftp', 's3': 's3', 'http': 'http'}
NAME = rclone.NAME
SAFE_PATH = re.compile(r'/[A-Za-z0-9_./+@: -]*')
ADDRESS = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,200}')
SECRET_KEYS = ('token', 'client_secret', 'password', 'pass', 'secret_access_key', 'key', 'account_key', 'sas_url',
               'service_account_credentials')

BASH = rclone.LIB + r"""
RCLONE_DIR=${SF_RCLONE_DIR:-/etc/storageforge/rclone}
RCS_CHANGED=0
rcs_client_name() { # share index -> the rclone remote name of one client mount: server, share and mount point keep two mounts apart
  echo "sf-share-$(printf "%s" "$SERVER" | sha256sum | cut -c1-8)-${C_NAME[$1]}-$(printf "%s" "${C_TARGET[$1]}" | sha256sum | cut -c1-8)"
}
rcs_drop_files() { # KEEP... -> sf-serve-* files of shares that are no longer in the design
  local f base nm keep=" $* "
  for f in "$RCLONE_DIR"/sf-serve-*; do
    [[ -e $f ]] || continue
    base=${f##*/}; nm=${base%%.*}
    [[ $keep != *" $nm "* ]] || continue
    if ((APPLY)); then rm -f -- "$f"; doing "removed $f"; else missing "would remove $f"; fi
  done
  return 0
}
rcs_access() { # SERVE_AS SECRET NAME -> the file with the client login the unit reads, root only. RCS_CHANGED=1 when rewritten, 2 when it cannot be made
  local as=$1 sname=$2 n=$3 src dest body line u p tmp re_u="^[A-Za-z0-9._@-]{1,64}$" re_p="^[A-Za-z0-9/+=._@-]{1,200}$" re_h="^[A-Za-z0-9._@-]{1,64}:[^[:space:]]{3,200}$"
  case $as in webdav|http) dest=$RCLONE_DIR/sf-serve-$n.htpasswd ;; *) dest=$RCLONE_DIR/sf-serve-$n.env ;; esac
  MANAGED_FILES+=("$dest")
  [[ -n $sname ]] || { conflict "the share needs a vault secret with the login clients use"; return 2; }
  src=$(secret "$sname")
  if [[ -z $src ]]; then
    if ((APPLY)); then conflict "the vault secret $sname is not on this host: apply this from StorageForge, which brings it"; return 2; fi
    if [[ -s $dest ]]; then info "$dest is there: an apply checks it against the vault secret $sname"; else missing "$dest (from the vault secret $sname)"; fi
    return 0
  fi
  case $as in
    webdav|http)
      body=$(grep -E "$re_h" "$src" || true)
      [[ -n $body && $(grep -c . "$src" || true) == "$(wc -l <<<"$body")" ]] || { conflict "the vault secret $sname must hold htpasswd lines only (user:hash, made with htpasswd -B)"; return 2; } ;;
    *)
      line=$(head -n 1 "$src"); u=${line%%:*}; p=${line#*:}
      [[ $line == *:* && $u =~ $re_u && $p =~ $re_p ]] || { conflict "the vault secret $sname must be one line, user:password (letters, digits and . _ @ - / + =)"; return 2; }
      if [[ $as == sftp ]]; then body=$(printf "RCLONE_USER=\"%s\"\nRCLONE_PASS=\"%s\"" "$u" "$p"); else body=$(printf "RCLONE_AUTH_KEY=\"%s,%s\"" "$u" "$p"); fi
      u= p= line= ;;
  esac
  if [[ -e $dest && $(cat "$dest") == "$body" ]]; then ok "$dest"; return 0; fi
  act "write $dest (root only)" || return 0
  (umask 077; mkdir -p "$RCLONE_DIR") && chmod 700 "$RCLONE_DIR"
  if tmp=$(mktemp "$RCLONE_DIR/.$n.XXXXXX") && printf "%s\n" "$body" >"$tmp" && chmod 600 "$tmp" && durable "$tmp" && mv -f -- "$tmp" "$dest"; then
    RCS_CHANGED=1; ok "wrote $dest"; return 0
  fi
  rm -f -- "${tmp:-}"; conflict "could not write $dest"; return 2
}
server_rclone() {
  local i idx=() keep=() n rn conf unit dest bin remote args body changed rc re_p="^/[A-Za-z0-9_./+@: -]*$" re_n="^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$"
  local backend rpath opts secret crypt csecret as port asecret ro cache envline
  mapfile -t idx < <(indices_of RCLONE)
  if ((!${#idx[@]})); then
    if compgen -G "/etc/systemd/system/storageforge-rclone-serve-*" >/dev/null || compgen -G "$RCLONE_DIR/sf-serve-*" >/dev/null; then
      section "rclone serve"; drop_units storageforge-rclone-serve-; rcs_drop_files
    fi
    return 0
  fi
  for i in "${idx[@]}"; do keep+=("sf-serve-${E_NAME[$i]}"); done
  for i in "${idx[@]}"; do
    n=${E_NAME[$i]}; rn=sf-serve-$n; conf=$RCLONE_DIR/$rn.conf; unit=storageforge-rclone-serve-$n.service; RCS_CHANGED=0
    backend=$(par backend "${E_PARAM[$i]}"); rpath=$(par remote_path "${E_PARAM[$i]}"); opts=$(par options "${E_PARAM[$i]}")
    secret=$(par secret "${E_PARAM[$i]}"); crypt=$(par crypt "${E_PARAM[$i]}"); csecret=$(par crypt_secret "${E_PARAM[$i]}")
    as=$(par serve_as "${E_PARAM[$i]}"); port=$(par port "${E_PARAM[$i]}"); asecret=$(par access_secret "${E_PARAM[$i]}")
    ro=$(par readonly "${E_PARAM[$i]}"); cache=$(par cache "${E_PARAM[$i]}")
    [[ $crypt == 1 ]] || crypt=
    section "rclone serve $as of the $backend remote for $n"
    if ! [[ $n =~ $re_n && ${E_PATH[$i]} =~ $re_p && $as =~ ^(webdav|sftp|s3|http)$ && $port =~ ^[0-9]{1,5}$ && $cache =~ ^[a-z]{1,10}$ && $backend =~ ^[a-z][a-z0-9]{1,30}$ ]]; then
      conflict "the settings of $n are not ones a script can use: check the share in StorageForge"; continue
    fi
    if ! rc_install && ((APPLY)); then continue; fi
    if [[ -d ${E_PATH[$i]} ]]; then ok "cache folder ${E_PATH[$i]} exists"
    elif ((APPLY)); then doing "mkdir -p ${E_PATH[$i]}"; mkdir -p -- "${E_PATH[$i]}"; else missing "cache folder ${E_PATH[$i]}"; fi
    MANAGED_FILES+=("$conf" "$conf.inputs")
    if ((APPLY)); then
      rc=0; rc_config "$rn" "$backend" "$opts" "$secret" "$crypt" "$csecret" standard "$rpath" || rc=$?
      ((rc == 2)) && continue
      [[ $rc == 0 ]] && RCS_CHANGED=1
    elif [[ -s $conf ]]; then ok "$conf (an apply checks it against the vault secrets)"; else missing "$conf: the rclone config of the remote, from the vault"; fi
    rc=0; rcs_access "$as" "$asecret" "$n" || rc=$?
    ((rc == 2)) && continue
    dest=
    case $as in webdav|http) dest=$RCLONE_DIR/$rn.htpasswd ;; *) dest=$RCLONE_DIR/$rn.env ;; esac
    if [[ -n $crypt ]]; then remote="$rn-crypt:"; else remote="$rn:$rpath"; fi
    bin=$(rc_bin); bin=${bin:-/usr/bin/rclone}
    args="--config \"$conf\" --cache-dir \"${E_PATH[$i]}\" --vfs-cache-mode ${cache:-writes} --addr :$port --log-level NOTICE"
    [[ $ro == 1 && $as != http ]] && args+=" --read-only"
    envline=
    case $as in webdav|http) args+=" --htpasswd \"$dest\"" ;; *) envline="EnvironmentFile=$dest" ;; esac
    body="# Written by StorageForge: serves the rclone remote of the share $n. Edit the design, not this file.
[Unit]
Description=StorageForge rclone serve $as: $n
Wants=network-online.target
After=network-online.target
RequiresMountsFor=${E_PATH[$i]}

[Service]
Type=simple"
    [[ -z $envline ]] || body+=$'\n'"$envline"
    body+=$'\n'"ExecStart=$bin serve $as \"$remote\" $args"$'\n'"Restart=on-failure"$'\n'"RestartSec=15"$'\n\n'"[Install]"$'\n'"WantedBy=multi-user.target"
    changed=$RCS_CHANGED; unit_file "$unit" "$body" && changed=1
    if ((APPLY)); then
      if ((changed)) && systemctl is-active -q "$unit"; then systemctl restart "$unit" 2>/dev/null || true; fi
      systemctl is-active -q "$unit" || systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "$unit did not start: journalctl -u $unit"
    fi
    if systemctl is-active -q "$unit" 2>/dev/null; then ok "$unit running"; elif ((!APPLY)); then missing "$unit is not running yet"; fi
    open_port "rclone serve $n" "$port/tcp" "${E_CLIENTS[$i]}"
  done
  drop_units storageforge-rclone-serve- "${keep[@]/#sf-serve-/storageforge-rclone-serve-}"
  rcs_drop_files "${keep[@]}"
}
client_rclone() {
  local i=$1 t=${C_TARGET[$1]} as port secret cache unit rn conf backend opts rc=0 changed=0 re_n="^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$"
  as=$(par serve_as "${C_PARAM[$i]}"); port=$(par port "${C_PARAM[$i]}"); secret=$(par secret "${C_PARAM[$i]}"); cache=$(par cache "${C_PARAM[$i]}")
  unit=$(share_unit "$t").service; rn=$(rcs_client_name "$i"); conf=$RCLONE_DIR/$rn.conf
  section "mount ${C_SOURCE[$i]} at $t (rclone, $as)"
  if ! [[ ${C_NAME[$i]} =~ $re_n && $as =~ ^(webdav|sftp|s3|http)$ && $port =~ ^[0-9]{1,5}$ && $cache =~ ^[a-z]{1,10}$ && $SERVER_ADDR =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$ ]]; then
    conflict "the settings of this mount are not ones a script can use: check the share in StorageForge"; return 0
  fi
  case $as in
    webdav) backend=webdav; opts="url=http://$SERVER_ADDR:$port,vendor=other" ;;
    http) backend=http; opts="url=http://$SERVER_ADDR:$port" ;;
    sftp) backend=sftp; opts="host=$SERVER_ADDR,port=$port" ;;
    s3) backend=s3; opts="provider=Other,endpoint=http://$SERVER_ADDR:$port,env_auth=false" ;;
  esac
  if ((!APPLY)); then
    command -v rclone >/dev/null && ok "rclone installed" || missing "would install rclone and FUSE"
    if [[ -e ${SF_UNIT_DIR:-/etc/systemd/system}/$unit ]]; then info "$unit is there: an apply checks its settings and the config against the vault secret $secret"; else missing "would mount $as://$SERVER_ADDR:$port at $t"; fi
    if timeout -k 2 10 mountpoint -q "$t"; then ok "mounted"; fi
    return 0
  fi
  rc_install || return 0
  rc_config "$rn" "$backend" "$opts" "$secret" "" "" standard "" || rc=$?   # set -e: 1 and 2 are answers
  ((rc == 2)) && return 0
  [[ $rc == 0 ]] && changed=1
  rc_mount_unit "$unit" "$rn:" "$t" "$conf" root "${cache:-writes}" "${C_NAME[$i]} of $SERVER ($as) at $t" "$changed"
}
cleanup_rclone() { # the remote configs of mounts of this server that the design no longer has (their units go with driver_units_cleanup)
  local i f base nm keep=" " pre
  pre=sf-share-$(printf "%s" "$SERVER" | sha256sum | cut -c1-8)-
  compgen -G "$RCLONE_DIR/$pre*" >/dev/null || return 0
  for i in "${!C_HOST[@]}"; do [[ ${C_HOST[$i]} == "$ME" && ${C_PROTO[$i]} == RCLONE ]] && keep+="$(rcs_client_name "$i") "; done
  section "rclone configs of $SERVER no longer in the design"
  for f in "$RCLONE_DIR/$pre"*; do
    base=${f##*/}; nm=${base%%.*}
    [[ $keep != *" $nm "* ]] || continue
    if ((APPLY)); then rm -f -- "$f"; doing "removed $f"; else missing "would remove $f"; fi
  done
  return 0
}
"""


class RcloneServe(Driver):
    def normalize(self, s: dict) -> dict:
        out = netshares.clean(self.fields, s)
        if out.get('remote_path') and not rclone.REMOTE_PATH.fullmatch(out['remote_path']):
            raise ValueError('the path in the remote is a folder or bucket path (letters, digits, and . _ : / @ + - space)')
        if out.get('options'):
            opts = [o.strip() for o in out['options'].split(',') if o.strip()]
            bad = [o for o in opts if not rclone.OPTION.fullmatch(o)]
            if bad:
                raise ValueError(f'options are key=value, comma separated: {", ".join(bad)}')
            if any(o.split('=')[0] in SECRET_KEYS for o in opts):
                raise ValueError('a password, key or token goes in the vault secret, not in the options: options are in the design for anyone to read')
            out['options'] = ','.join(opts)
        return out

    @staticmethod
    def st(e: dict) -> dict:
        s = e.get('settings') or {}
        return {'backend': s.get('backend') or 'drive', 'serve_as': s.get('serve_as') or 'webdav', 'port': int(s.get('port') or 8089),
                'cache': s.get('cache') or 'writes', 'crypt': bool(s.get('crypt')), 'readonly': bool(s.get('readonly')), **{
                    k: s.get(k) or '' for k in ('remote_path', 'options', 'secret', 'crypt_secret', 'access_secret')}}

    def check(self, conn, hs, srv, e, say):
        s = self.st(e)
        if not NAME.fullmatch(e['name'] or ''):
            say('crit', 'an rclone share needs a name of letters, digits, dash and underscore (it names the remote and its unit)')
        if not SAFE_PATH.fullmatch(e['path'] or ''):
            say('crit', f'{e["path"]}: the cache folder may hold letters, digits, and . _ + @ : - space only')
        try:
            from .fsmap import path_info
            m = path_info(conn, srv, e['path'])['mount']
        except Exception:
            m = None
        if m and m['kind'] != 'local':
            say('crit', f'{e["path"]} is the cache of the served remote and has to be on a local disk, not a {m["kind"]} mount or {m["fstype"]}')
        elif m:
            say('note', f'{e["path"]} holds rclone VFS cache files of the remote, not the remote itself: it grows with what clients read and write')
        if not s['secret'] and s['backend'] != 'http':
            say('warn', f'no vault secret: {s["backend"]} usually needs a token, keys or a password (keep its rclone config lines in one secret)')
        if s['backend'] == 'drive':
            say('note', "Google Drive takes your own OAuth client: rclone's shared one is being retired during 2026 (docs/network-filesystems.md)")
        if s['crypt']:
            if not s['crypt_secret']:
                say('crit', 'encryption needs a vault secret with its passwords: password = …, and password2 = … for the salt')
            say('warn', 'without the crypt secret nobody can read the files again, StorageForge included: keep a copy offline, beside the vault backups')
            say('note', 'clients get the files decrypted, and the cache folder holds them decrypted too')
        if not s['access_secret']:
            say('crit', 'name the vault secret with the login clients use' + (' (htpasswd lines)' if s['serve_as'] in ('webdav', 'http') else ' (user:password)'))
        if s['serve_as'] == 'http':
            say('note', 'rclone serve http is read only: clients can browse and download, not change anything')
        elif s['readonly']:
            say('note', 'read only: clients can list and download, not change anything')
        if s['serve_as'] in ('webdav', 'http', 's3'):
            say('warn', f'{s["serve_as"]} is plain HTTP here: the password crosses the network in the clear (basic auth). Keep it on a trusted LAN or put a TLS proxy or Tailscale in front')
        else:
            say('note', 'sftp is encrypted, but the client does not pin the server host key (rclone only checks one when a known hosts file is set)')
        if not (e.get('clients') or '').strip():
            say('warn', 'no clients named: the port is opened to anyone who can reach this host')
        try:
            from .shares import design_exports
            same = [o for o in design_exports(conn, srv['name']) if o is not e and o.get('proto') == 'RCLONE' and o.get('name') != e['name']
                    and self.st(o)['port'] == s['port']]
        except Exception:
            same = []
        if same:
            say('crit', f'port {s["port"]} is also used by the rclone share {same[0]["name"]}: give each its own port')
        say('note', f'rclone serve {s["serve_as"]} on port {s["port"]}; the remote credentials stay on {srv["name"]} and never reach clients')

    def check_mount(self, conn, srv, e, mt, ch, say):
        s = self.st(e)
        st = mt.get('settings') or {}
        if not st.get('secret'):
            say('crit', f'{ch["name"]}:{mt["path"]}: name the vault secret with the login for {s["serve_as"]} '
                        + ('(user = …, pass = … from `rclone obscure`)' if s['serve_as'] != 's3' else '(access_key_id = …, secret_access_key = …)'))
        if not SAFE_PATH.fullmatch(mt['path'] or ''):
            say('crit', f'{ch["name"]}:{mt["path"]}: the mount point may hold letters, digits, and . _ + @ : - space only')
        if not ADDRESS.fullmatch(srv.get('ssh_host') or ''):
            say('crit', f'{srv["name"]} is reached at {srv.get("ssh_host")!r}: rclone clients need a host name or IPv4 address')
        if s['serve_as'] == 'http':
            say('note', f'{ch["name"]}:{mt["path"]} is read only')

    def server_params(self, e, srv, hs):
        s = self.st(e)
        return {'backend': s['backend'], 'remote_path': s['remote_path'], 'options': s['options'], 'secret': s['secret'], 'crypt': s['crypt'],
                'crypt_secret': s['crypt_secret'], 'serve_as': s['serve_as'], 'port': s['port'], 'access_secret': s['access_secret'],
                'readonly': s['readonly'], 'cache': s['cache']}

    def client_params(self, e, mt, srv, hs):
        s = self.st(e)
        return {'serve_as': s['serve_as'], 'port': s['port'], 'secret': (mt.get('settings') or {}).get('secret') or '',
                'cache': (mt.get('settings') or {}).get('cache') or 'writes'}

    def client_source(self, e, address):
        s = self.st(e)
        return f'{s["serve_as"]}://{address}:{s["port"]}'

    def server_secrets(self, e):
        s = self.st(e)
        return list(dict.fromkeys(x for x in (s['secret'], s['crypt_secret'] if s['crypt'] else '', s['access_secret']) if x))

    def client_secrets(self, e, mt):
        k = (mt.get('settings') or {}).get('secret')
        return [k] if k else []


netshares.register(RcloneServe(
    key='RCLONE', label='rclone serve',
    help='Serves an rclone remote (an encrypted Google Drive, S3, …) from the server over WebDAV, SFTP, S3 or HTTP, so only the server holds the cloud credentials. The share folder is its cache.',
    clients_label='Who may connect', clients_help='Addresses or subnets allowed to reach the port, such as 10.42.0.0/24.',
    fields=[Field('backend', 'choice', 'Remote backend', 'The rclone backend of the remote to serve.', options=rclone.BACKENDS, default='drive'),
            Field('remote_path', 'text', 'Folder or bucket in the remote', placeholder='Backups/nas  ·  my-bucket/data'),
            Field('options', 'text', 'Settings that are not secret (key=value, comma separated)', placeholder='scope=drive.file,team_drive=…'),
            Field('secret', 'secret', 'Vault secret with the remote rclone config lines (token, keys, password)', placeholder='gdrive-rclone'),
            Field('crypt', 'bool', 'Remote is encrypted with rclone crypt', 'Clients get the files decrypted.', default=False),
            Field('crypt_secret', 'secret', 'Vault secret with the crypt passwords', 'password = …, and password2 = … for the salt.', placeholder='gdrive-crypt'),
            Field('serve_as', 'choice', 'Serve as', 'webdav, sftp and s3 can be written to; http is read only.', options=SERVE_AS, default='webdav'),
            Field('port', 'int', 'Port', default=8089, options=(1, 65535)),
            Field('access_secret', 'secret', 'Vault secret with the login clients use',
                  'webdav and http: htpasswd lines (htpasswd -B). sftp and s3: one line, user:password (s3: access key:secret key).', required=True, placeholder='gdrive-serve-login'),
            Field('readonly', 'bool', 'Read only', 'Clients can list and download, not change anything.', default=False),
            Field('cache', 'choice', 'VFS cache', 'How much rclone keeps in the share folder.', options=rclone.CACHE_MODES, default='writes')],
    mount_fields=[Field('secret', 'secret', 'Vault secret with the login for the share', 'rclone config lines: user = … and pass = … (from rclone obscure), or access_key_id and secret_access_key for s3.',
                        required=True, placeholder='nas-rclone-login'),
                  Field('cache', 'choice', 'VFS cache', options=rclone.CACHE_MODES, default='writes')],
    needs_server='rclone', needs_client='rclone', bash=BASH))
