"""WebDAV shares: `rclone serve webdav` on the server, an rclone mount of a webdav remote on the clients.

Server: one unit per share, storageforge-webdav-NAME.service, serves the shared folder on the share's port (8088 unless set) to the
users in a vault secret. That secret is an htpasswd file (`user:bcrypt-hash` lines, from `htpasswd -nB user`); an apply copies it to
/etc/storageforge/webdav/NAME.htpasswd, readable by root only, and rclone is pointed at that file, so no password is ever on a command
line. A certificate and key (paths on the server) turn on TLS; without them passwords cross the network in the clear, which the check says.

Client: rclone's webdav backend (vendor other) mounted by a unit named for the mount (rclone.LIB's rc_mount_unit). The login is a vault
secret of rclone config lines (`user = alice`, `pass = the plain password`): the password is obscured on the host by `rclone obscure -`
reading it from a pipe and written into a root-only config. An optional rclone crypt layer encrypts file contents and names before they
leave the client, so the server only ever holds ciphertext.

This is a plain file share. For a full web app with sharing links, a browser interface and sync clients, use Nextcloud from the Toolbox.
"""
from __future__ import annotations

import re

from . import netshares
from .netshares import Driver, Field
from .rclone import LIB

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,40}')
CERT_PATH = re.compile(r'/[A-Za-z0-9_./@+-]{1,300}')
ADDRESS = re.compile(r'[0-9.:]+(/[0-9]+)?')    # what the firewall helper (cidrs in shares.py) keeps of a clients list
DEFAULT_PORT = 8088

BASH = LIB + r"""
WEBDAV_DIR=${SF_WEBDAV_DIR:-/etc/storageforge/webdav}
WEBDAV_NAME_RE="^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}\$"
WEBDAV_USER_RE="^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\$"
webdav_prune() { # NAME... -> htpasswd files of shares the design no longer has (find, not a glob: the script runs with globbing off)
  local f n keep=" $* "
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    n=$(basename "$f" .htpasswd)
    if [[ $keep == *" $n "* ]]; then continue; fi
    if ((APPLY)); then rm -f -- "$f"; doing "removed $f"; else missing "would remove $f"; fi
  done < <(find "$WEBDAV_DIR" -maxdepth 1 -name "*.htpasswd" 2>/dev/null | sort)
  return 0
}
server_webdav() {
  local i idx=() keep=() ports=" " name path port ro cert key sec unit htp src body bin extra chg units=()
  mapfile -t idx < <(indices_of WEBDAV)
  if ((!${#idx[@]})); then
    if compgen -G "/etc/systemd/system/storageforge-webdav-*" >/dev/null || [[ -n $(find "$WEBDAV_DIR" -maxdepth 1 -name "*.htpasswd" 2>/dev/null) ]]; then
      section "WebDAV server"; drop_units storageforge-webdav-; webdav_prune
    fi
    return 0
  fi
  section "WebDAV server (rclone serve webdav)"
  rc_install || true
  bin=$(rc_bin); bin=${bin:-/usr/bin/rclone}
  for i in "${idx[@]}"; do
    name=${E_NAME[$i]}; path=${E_PATH[$i]}; unit=storageforge-webdav-$name.service; htp=$WEBDAV_DIR/$name.htpasswd; chg=0
    if ! [[ $name =~ $WEBDAV_NAME_RE ]]; then conflict "$name is not a name for a WebDAV share (letters, digits, . _ -)"; continue; fi
    keep+=("$name"); units+=("storageforge-webdav-$name.service"); MANAGED_FILES+=("$htp")
    port=$(par port "${E_PARAM[$i]}"); ro=$(par readonly "${E_PARAM[$i]}"); cert=$(par tls_cert "${E_PARAM[$i]}"); key=$(par tls_key "${E_PARAM[$i]}")
    sec=$(par users_secret "${E_PARAM[$i]}")
    if [[ $ports == *" $port "* ]]; then conflict "port $port is already used by another WebDAV share on this host: give $name its own"; continue; fi
    ports+="$port "
    share_dir "$path"
    if [[ -n $cert ]]; then
      if [[ -r $cert && -r $key ]]; then ok "TLS certificate $cert"
      elif ((APPLY)); then conflict "the TLS certificate $cert or its key $key cannot be read on this host"; continue
      else missing "the TLS certificate $cert and its key $key must be readable on this host"; fi
    fi
    if ((APPLY)); then
      src=$(secret "$sec")
      if [[ -z $src ]]; then conflict "the vault secret $sec (the users of $name) is not on this host: deploy from StorageForge, which brings it"; continue; fi
      if ! grep -qE "^[^:#[:space:]]+:[^[:space:]]+\$" "$src"; then conflict "the vault secret $sec has no user:hash line: it is an htpasswd file (htpasswd -nB user)"; continue; fi
      if [[ -e $htp ]] && cmp -s -- "$src" "$htp"; then ok "$htp"
      else
        (umask 077; mkdir -p "$WEBDAV_DIR") && chmod 700 "$WEBDAV_DIR" && install -m 600 -- "$src" "$htp" && doing "wrote $htp (root only)" && chg=1 \
          || { conflict "could not write $htp"; continue; }
      fi
    elif [[ -e $htp ]]; then ok "$htp"; else missing "would write $htp from the vault secret $sec (root only)"; fi
    extra=
    if [[ $ro == 1 ]]; then extra+=" --read-only"; fi
    if [[ -n $cert ]]; then extra+=" --cert \"$cert\" --key \"$key\""; fi
    body="# Written by StorageForge: serves $path over WebDAV. Edit the design, not this file.
[Unit]
Description=StorageForge WebDAV share $name: $path
Wants=network-online.target
After=network-online.target
RequiresMountsFor=$path

[Service]
Type=simple
ExecStart=$bin serve webdav \"$path\" --addr :$port --htpasswd \"$htp\"$extra --log-level NOTICE
Restart=on-failure
RestartSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target"
    unit_file "$unit" "$body" && chg=1
    if ((APPLY)); then
      if ((chg)) && systemctl is-active -q "$unit"; then systemctl restart "$unit" || conflict "$unit did not start again: journalctl -u $unit"; fi
      systemctl is-active -q "$unit" || systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "$unit did not start: journalctl -u $unit"
    fi
    if systemctl is-active -q "$unit" 2>/dev/null; then ok "$unit running"; elif ((!APPLY)); then missing "$unit is not running yet"; fi
    open_port "WebDAV $name" "$port/tcp" "${E_CLIENTS[$i]}"
  done
  drop_units storageforge-webdav- ${units[@]+"${units[@]}"}
  webdav_prune ${keep[@]+"${keep[@]}"}
}
webdav_cfg() { echo "sfwd-$SERVER-$(printf "%s" "$SERVER|${C_TARGET[$1]}" | sha256sum | cut -c1-10)"; }   # unique for this server and mount
webdav_pass() { # CONF PASSWORD -> the remote section of CONF gets its pass line, the password obscured by rclone reading it from a pipe
  local conf=$1 pw=$2 tmp ob line
  ob=$(printf "%s" "$pw" | "$(rc_bin)" obscure -) && [[ -n $ob ]] || return 1
  tmp=$(mktemp "$(dirname "$conf")/.pass.XXXXXX") || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    printf "%s\n" "$line"
    if [[ $line == "type = webdav" ]]; then printf "pass = %s\n" "$ob"; fi
  done <"$conf" >"$tmp" && durable "$tmp" && mv -f -- "$tmp" "$conf" || { rm -f -- "$tmp"; return 1; }
}
client_webdav() {
  local i=$1 t=${C_TARGET[$1]} p=${C_PARAM[$1]} unit cfg conf url addr=$SERVER_ADDR lsec csec crypt src user pw sum remote rc=0 chg=0
  local dir=${SF_RCLONE_DIR:-/etc/storageforge/rclone}
  unit=$(share_unit "$t").service; cfg=$(webdav_cfg "$i"); conf=$dir/$cfg.conf
  section "mount ${C_SOURCE[$i]} at $t (rclone, WebDAV)"
  if ((!APPLY)); then
    if [[ -n $(rc_bin) ]]; then ok "rclone installed"; else missing "would install rclone and FUSE"; fi
    if [[ -e ${SF_UNIT_DIR:-/etc/systemd/system}/$unit ]]; then info "$unit is there: an apply checks its settings and the config against the vault secrets"
    else missing "would mount ${C_SOURCE[$i]} at $t"; fi
    if timeout -k 2 10 mountpoint -q "$t"; then ok "$t is mounted"; fi
    return 0
  fi
  rc_install || return 0
  lsec=$(par login_secret "$p"); csec=$(par crypt_secret "$p"); crypt=; [[ $(par crypt "$p") == 1 ]] && crypt=1
  src=$(secret "$lsec")
  [[ -n $src ]] || { conflict "the vault secret $lsec (the WebDAV login) is not on this host: deploy from StorageForge, which brings it"; return 0; }
  user=$(sed -n "s/^user *= *//p" "$src" | head -n 1); pw=$(sed -n "s/^pass *= *//p" "$src" | head -n 1)
  if ! [[ $user =~ $WEBDAV_USER_RE ]]; then conflict "the vault secret $lsec needs a user = line with a plain user name (letters, digits, . _ @ -)"; return 0; fi
  [[ -n $pw ]] || { conflict "the vault secret $lsec has no pass = line"; return 0; }
  if [[ $addr == *:* && $addr != \[* ]]; then addr="[$addr]"; fi
  url=$(par scheme "$p")://$addr:$(par port "$p")/
  sum=$(sha256sum <"$src" | cut -c1-16)    # moves the inputs of rc_config when the secret changes, which obscure cannot (it differs every run)
  rc_config "$cfg" webdav "url=$url,vendor=other,user=$user,sf_secret=$sum" "" "$crypt" "$csec" standard "" || rc=$?
  ((rc == 2)) && return 0
  if ! grep -q "^pass = " "$conf" 2>/dev/null; then
    webdav_pass "$conf" "$pw" || { conflict "could not put the password into $conf"; return 0; }
    rc=0
  fi
  pw=
  if [[ -n $crypt ]]; then remote="$cfg-crypt:"; else remote="$cfg:"; fi
  if ((rc == 0)); then chg=1; fi
  rc_mount_unit "$unit" "$remote" "$t" "$conf" root writes "WebDAV share ${C_NAME[$i]} of $SERVER at $t$([[ -n $crypt ]] && echo ", encrypted")" "$chg"
}
cleanup_webdav() { # the rclone configs of mounts of this server that the design no longer has (their units went with driver_units_cleanup)
  local i f n keep=" "
  for i in "${!C_HOST[@]}"; do
    if [[ ${C_HOST[$i]} == "$ME" && ${C_PROTO[$i]} == WEBDAV ]]; then keep+="$(webdav_cfg "$i") "; fi
  done
  while IFS= read -r f; do
    [[ -n $f ]] || continue
    n=$(basename "$f" .conf)
    if [[ $keep == *" $n "* ]]; then continue; fi
    if ((APPLY)); then rm -f -- "$f" "$f.inputs"; doing "removed $f"; else missing "would remove $f"; fi
  done < <(find "${SF_RCLONE_DIR:-/etc/storageforge/rclone}" -maxdepth 1 -name "sfwd-$SERVER-??????????.conf" 2>/dev/null | sort)
  return 0
}
"""


class WebDav(Driver):
    def normalize(self, s: dict) -> dict:
        out = netshares.clean(self.fields, s)
        for k in ('tls_cert', 'tls_key'):
            if out.get(k) and not CERT_PATH.fullmatch(out[k]):
                raise ValueError('a certificate or key path uses letters, digits and . _ / @ + - only')
        return out

    @staticmethod
    def tls(e: dict) -> bool:
        st = e.get('settings') or {}
        return bool(st.get('tls_cert') and st.get('tls_key'))

    @staticmethod
    def port(e: dict) -> int:
        return int((e.get('settings') or {}).get('port') or DEFAULT_PORT)

    def check(self, conn, hs, srv, e, say):
        st = e.get('settings') or {}
        if not NAME.fullmatch(e['name'] or ''):
            say('crit', 'a WebDAV share needs a name of letters, digits, . _ - (it names the service)')
        if re.search(r'[%"\\$\n]', e['path'] or ''):
            say('crit', 'the shared folder cannot hold % " \\ or $: the service unit cannot carry them')
        if not 1024 <= self.port(e) <= 65535:
            say('crit', 'the port is between 1024 and 65535')
        if not st.get('users_secret'):
            say('crit', 'name the vault secret with the users (an htpasswd file: user:bcrypt-hash lines)')
        if bool(st.get('tls_cert')) != bool(st.get('tls_key')):
            say('crit', 'TLS needs both a certificate path and a key path on the server')
        if not self.tls(e):
            say('warn', 'plain HTTP: user names and passwords cross the network in the clear. Give it a certificate and key, '
                        'or keep it on a network you trust')
        else:
            say('note', 'TLS: clients must trust the certificate, or rclone refuses to connect')
        clients = (e.get('clients') or '').split()
        if not clients:
            say('warn', 'no clients listed: the firewall port is opened to any address, and only the passwords stand in the way')
        elif [c for c in clients if not ADDRESS.fullmatch(c)]:
            say('warn', 'the firewall rule takes addresses and subnets only (10.0.0.5, 10.0.0.0/24): a host name here is left out, '
                        'and if no address is left the port opens to any address')
        say('note', f'rclone serves {e["path"]} on port {self.port(e)} as {"read only" if st.get("readonly") else "read and write"}. '
                    'For a full web app with sharing links and sync clients, use Nextcloud from the Toolbox')

    def check_mount(self, conn, srv, e, mt, ch, say):
        st = mt.get('settings') or {}
        where = f'{ch["name"]}:{mt["path"]}'
        if not st.get('login_secret'):
            say('crit', f'{where}: name the vault secret with its login (rclone config lines: user = … and pass = …)')
        if st.get('crypt') and not st.get('crypt_secret'):
            say('crit', f'{where}: encryption needs a vault secret with its passwords (password = …, and password2 = … for the salt)')
        if st.get('crypt'):
            say('warn', f'{where}: the files are encrypted with the crypt secret: without it nobody can read them again. Keep a copy offline')

    def server_params(self, e, srv, hs):
        st = e.get('settings') or {}
        return {'port': self.port(e), 'readonly': bool(st.get('readonly')), 'users_secret': st.get('users_secret') or '',
                'tls_cert': st.get('tls_cert') or '', 'tls_key': st.get('tls_key') or ''}

    def client_params(self, e, mt, srv, hs):
        st = mt.get('settings') or {}
        return {'scheme': 'https' if self.tls(e) else 'http', 'port': self.port(e), 'login_secret': st.get('login_secret') or '',
                'crypt': bool(st.get('crypt')), 'crypt_secret': st.get('crypt_secret') or ''}

    def client_source(self, e, address):
        return f'{"https" if self.tls(e) else "http"}://{address}:{self.port(e)}/'

    def server_secrets(self, e):
        s = (e.get('settings') or {}).get('users_secret')
        return [s] if s else []

    def client_secrets(self, e, mt):
        st = mt.get('settings') or {}
        return [s for s in (st.get('login_secret'), st.get('crypt_secret') if st.get('crypt') else None) if s]


netshares.register(WebDav(
    key='WEBDAV', label='WebDAV',
    help='rclone serves the folder over WebDAV with users from a vault htpasswd file; clients mount it with rclone, optionally encrypted. '
         'A plain file share: Nextcloud in the Toolbox is the full web app.',
    clients_label='Addresses that may connect', clients_help='IP addresses or subnets, space separated: the firewall port is opened to them.',
    fields=[Field('users_secret', 'secret', 'Vault secret with the users', 'An htpasswd file: user:bcrypt-hash lines (htpasswd -nB alice).',
                  required=True, placeholder='nas-webdav-users'),
            Field('port', 'int', 'Port', 'The TCP port the server listens on.', options=(1024, 65535), default=DEFAULT_PORT),
            Field('readonly', 'bool', 'Read only', 'Clients can list and download, not change anything.', default=False),
            Field('tls_cert', 'path', 'TLS certificate (path on the server)', 'With the key, turns on HTTPS. Without them passwords travel in the clear.',
                  placeholder='/etc/ssl/certs/nas.pem'),
            Field('tls_key', 'path', 'TLS key (path on the server)', 'The private key of that certificate.', placeholder='/etc/ssl/private/nas.key')],
    mount_fields=[Field('login_secret', 'secret', 'Vault secret with its login', 'rclone config lines: user = alice, pass = the plain password (obscured on the host).',
                        required=True, placeholder='pc-webdav-login'),
                  Field('crypt', 'bool', 'Encrypt with rclone crypt', 'Contents and names are encrypted before they leave the client.', default=False),
                  Field('crypt_secret', 'secret', 'Vault secret with the crypt passwords', 'password = …, and password2 = … for the salt. Lose it and the data is gone.',
                        placeholder='pc-webdav-crypt')],
    needs_server='rclone', needs_client='rclone', bash=BASH))
