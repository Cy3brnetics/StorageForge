"""S3 shares: `rclone serve s3` on the server, an rclone mount of the bucket on each client.

Server: the share's folder is served as one bucket, named after the share, by a unit of StorageForge
(storageforge-s3-NAME.service) on the share's port. A small rclone config (a `combine` remote) maps the bucket name to the folder; the
access keys come from a vault secret (`access_key_id = ...` and `secret_access_key = ...` lines) and reach rclone through a root-only
EnvironmentFile (RCLONE_AUTH_KEY), so they are on no command line and in no unit. Without keys rclone would serve the bucket to anyone,
so the unit is not started when the secret is missing. TLS is optional and uses the certificate and key files the share names; without it
the keys and the data cross the network in the clear.

Client: rclone mount of an s3 remote (provider Other, path style) over the client's own copy of the keys from the vault, with rclone crypt
on top if asked, so the data is encrypted on the client before the server sees it. rclone.py's library writes the config and the unit.
For heavier use, MinIO or Garage from the Toolbox are real object stores; this is a simple way to share a folder over S3.
"""
from __future__ import annotations

import re

from . import netshares
from .netshares import Driver, Field
from .rclone import LIB

BUCKET = re.compile(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]')
FILE = re.compile(r'/[A-Za-z0-9_.+@:/-]{1,300}')       # a path in a unit: no space and no % or quote that systemd would read
DEFAULT_PORT = 9000

BASH = LIB + r"""
S3_DIR=${SF_S3_DIR:-/etc/storageforge/s3}
s3_secret_keys() { # SECRET FILE -> the access key id and the secret key in it, comma separated, only if both are plain
  local id key
  id=$(sed -n "s/^access_key_id *= *//p" "$1" | head -n 1 | tr -d " \r"); key=$(sed -n "s/^secret_access_key *= *//p" "$1" | head -n 1 | tr -d " \r")
  [[ $id =~ ^[A-Za-z0-9._-]+$ && $key =~ ^[A-Za-z0-9/+=._-]+$ ]] || return 1
  printf "%s,%s" "$id" "$key"
}
s3_slug() { printf "%s" "$1" | tr -c "A-Za-z0-9" "-" | sed "s/--*/-/g; s/^-//; s/-$//"; }
server_s3() {
  local tlsargs i idx=() ports=() keep=() keepf=() name port tls cert key unit conf envf src keys body changed started f dup
  mapfile -t idx < <(indices_of S3)
  if ((!${#idx[@]})); then
    if compgen -G "/etc/systemd/system/storageforge-s3-*" >/dev/null || compgen -G "$S3_DIR/*" >/dev/null; then
      section "S3 server"; drop_units storageforge-s3-
      for f in "$S3_DIR"/*.conf "$S3_DIR"/*.env; do
        [[ -e $f ]] || continue
        if ((APPLY)); then rm -f -- "$f"; doing "removed $f"; else missing "would remove $f"; fi
      done
    fi
    return 0
  fi
  section "S3 server (rclone serve s3)"
  rc_install || return 0
  for i in "${idx[@]}"; do
    name=${E_NAME[$i]}; port=$(par port "${E_PARAM[$i]}"); tls=$(par tls "${E_PARAM[$i]}")
    cert=$(par cert_file "${E_PARAM[$i]}"); key=$(par key_file "${E_PARAM[$i]}"); src=$(par secret "${E_PARAM[$i]}")
    unit=storageforge-s3-$name.service; conf=$S3_DIR/$name.conf; envf=$S3_DIR/$name.env
    keep+=("$unit"); keepf+=("$conf" "$envf"); changed=0
    for dup in ${ports[@]+"${ports[@]}"}; do [[ $dup == "$port" ]] && conflict "two S3 shares on $SERVER use port $port: give each its own"; done
    ports+=("$port")
    if [[ ${E_PATH[$i]} == *[\"\\]* || ${E_PATH[$i]} != /* ]]; then conflict "the folder of $name cannot hold a quote or backslash"; continue; fi
    if [[ -d ${E_PATH[$i]} ]]; then ok "${E_PATH[$i]} exists"
    elif ((APPLY)); then doing "mkdir -p ${E_PATH[$i]}"; mkdir -p -- "${E_PATH[$i]}"
    else missing "${E_PATH[$i]}"; fi
    body="[sf-s3]
type = combine
upstreams = \"$name=${E_PATH[$i]}\""
    if [[ -e $conf && $(cat "$conf") == "$body" ]]; then ok "$conf"
    elif ((APPLY)); then (umask 077; mkdir -p "$S3_DIR"; printf "%s\n" "$body" >"$conf") && doing "wrote $conf" && changed=1
    else missing "$conf"; fi
    if ((APPLY)); then
      keys=; [[ -n $(secret "$src") ]] && keys=$(s3_secret_keys "$(secret "$src")" || true)
      if [[ -z $keys ]]; then
        conflict "the vault secret $src is not on this host, or lacks plain access_key_id and secret_access_key lines: $unit is not started without keys (rclone would serve $name to anyone)"
        continue
      fi
      if [[ -e $envf && $(cat "$envf") == "RCLONE_AUTH_KEY=$keys" ]]; then ok "$envf"
      else (umask 077; mkdir -p "$S3_DIR"; printf "RCLONE_AUTH_KEY=%s\n" "$keys" >"$envf.new" && mv -f -- "$envf.new" "$envf") && doing "wrote the access keys to $envf (root only)" && changed=1
      fi
      keys=
    elif [[ -e $envf ]]; then ok "$envf (the keys are checked in an apply, against the vault secret $src)"
    else missing "$envf (the access keys from the vault secret $src)"; fi
    tlsargs=
    if [[ $tls == 1 ]]; then
      tlsargs=" --cert $cert --key $key"
      [[ -n $cert && -n $key ]] || { conflict "TLS for $name needs a certificate file and a key file"; continue; }
      [[ -r $cert && -r $key ]] && ok "TLS certificate $cert" || { ((APPLY)) && conflict "$cert or $key is not readable: $unit would not start" || missing "the TLS files $cert and $key are not both there"; }
    else info "$name is served over plain HTTP: the access keys and the data cross the network in the clear"; fi
    body="# Written by StorageForge: the S3 share $name ($(uname -n)). Edit the design, not this file.
[Unit]
Description=StorageForge S3 share $name (rclone serve s3)
After=network-online.target local-fs.target
Wants=network-online.target
RequiresMountsFor=${E_PATH[$i]}

[Service]
Type=simple
EnvironmentFile=$envf
ExecStart=$(rc_bin) serve s3 sf-s3: --config $conf --addr :$port --log-level NOTICE$tlsargs
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target"
    unit_file "$unit" "$body" && changed=1
    if ((APPLY)); then
      if systemctl is-active -q "$unit"; then
        ((changed)) && { systemctl restart "$unit" || conflict "$unit did not start again: journalctl -u $unit"; }
      else systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "$unit did not start: journalctl -u $unit"; fi
    else systemctl is-active -q "$unit" 2>/dev/null && ok "$unit running" || missing "$unit is not running"; fi
    open_port "S3 $name" "$port/tcp" "${E_CLIENTS[$i]}"
  done
  drop_units storageforge-s3- "${keep[@]}"
  for f in "$S3_DIR"/*.conf "$S3_DIR"/*.env; do
    [[ -e $f && " ${keepf[*]} " != *" $f "* ]] || continue
    if ((APPLY)); then rm -f -- "$f"; doing "removed $f"; else missing "would remove $f"; fi
  done
  MANAGED_FILES+=("${keepf[@]}")
  return 0
}
client_s3() {
  local i=$1 t=${C_TARGET[$1]} name rc=0 unit remote conf secret csecret crypt opts
  secret=$(par secret "${C_PARAM[$i]}"); csecret=$(par crypt_secret "${C_PARAM[$i]}"); crypt=$(par crypt "${C_PARAM[$i]}")
  [[ $crypt == 1 ]] || { crypt=; csecret=; }
  unit=$(share_unit "$t").service
  name=sf-$SERVER-$(s3_slug "$t")-$(printf "%s" "$t" | cksum | cut -d" " -f1)
  conf=${SF_RCLONE_DIR:-/etc/storageforge/rclone}/$name.conf
  opts="provider=Other,endpoint=$(par endpoint "${C_PARAM[$i]}"),force_path_style=true"
  section "mount ${C_SOURCE[$i]} at $t (rclone, S3)"
  if ((!APPLY)); then
    [[ -n $(rc_bin) ]] && ok "rclone installed" || missing "would install rclone and FUSE"
    [[ -e ${SF_UNIT_DIR:-/etc/systemd/system}/$unit ]] && info "$unit is there: an apply checks its settings and the config against the vault secrets" || missing "would mount ${C_SOURCE[$i]} at $t"
    timeout -k 2 10 mountpoint -q "$t" && ok "$t is mounted"
    return 0
  fi
  rc_install || return 0
  rc_config "$name" s3 "$opts" "$secret" "$crypt" "$csecret" standard "${C_NAME[$i]}" || rc=$?   # set -e: 1 and 2 are answers
  ((rc == 2)) && return 0
  if [[ -n $crypt ]]; then remote="$name-crypt:"; else remote="$name:${C_NAME[$i]}"; fi
  rc_mount_unit "$unit" "$remote" "$t" "$conf" root writes "S3 share ${C_NAME[$i]} of $SERVER at $t$([[ -n $crypt ]] && echo ", encrypted")" "$([[ $rc == 0 ]] && echo 1 || echo 0)"
}
cleanup_s3() { return 0; }    # its client units go with driver_units_cleanup; the rclone configs are small and hold the keys the next mount reuses
"""


class S3(Driver):
    def normalize(self, s: dict) -> dict:
        out = netshares.clean(self.fields, s)
        for k in ('cert_file', 'key_file'):
            if out.get(k) and not FILE.fullmatch(out[k]):
                raise ValueError('the certificate and key files are absolute paths of letters, digits and . _ + @ : / -')
        return out

    def normalize_mount(self, s: dict) -> dict:
        return netshares.clean(self.mount_fields, s)

    @staticmethod
    def port(e: dict) -> int:
        return int((e.get('settings') or {}).get('port') or DEFAULT_PORT)

    def check(self, conn, hs, srv, e, say):
        st = e.get('settings') or {}
        if not BUCKET.fullmatch(e['name'] or ''):
            say('crit', 'an S3 share is a bucket named after the share: 3 to 63 lowercase letters, digits and hyphens, not starting or ending with a hyphen')
        if not 1024 <= self.port(e) <= 65535:
            say('crit', 'the port is between 1024 and 65535')
        if not st.get('secret'):
            say('crit', 'name the vault secret with the access keys: access_key_id = … and secret_access_key = … lines. Without keys the bucket would be open to anyone')
        if st.get('tls'):
            if not (st.get('cert_file') and st.get('key_file')):
                say('crit', 'TLS needs the paths of a certificate file and a key file on the server')
            else:
                say('note', f'served over HTTPS with {st["cert_file"]}; clients must trust that certificate (a self-signed one has to be installed on each client)')
        else:
            say('warn', 'plain HTTP: the access keys and the data cross the network in the clear. Use it only on a trusted network, or set TLS')
        say('note', 'rclone serves one folder as a simple S3 bucket. For heavier use (many users, versioning, erasure coding) MinIO or Garage from the Toolbox are made for it')

    def check_mount(self, conn, srv, e, mt, ch, say):
        st = mt.get('settings') or {}
        if not st.get('secret'):
            say('crit', f'{ch["name"]}:{mt["path"]}: name the vault secret with its copy of the access keys')
        if st.get('crypt') and not st.get('crypt_secret'):
            say('crit', f'{ch["name"]}:{mt["path"]}: encryption needs a vault secret with its passwords (password = …, and password2 = … for the salt)')
        if st.get('crypt'):
            say('warn', f'{ch["name"]}:{mt["path"]}: files are encrypted on the client with the crypt secret: without it nobody can read them again. Keep a copy offline. '
                        'Every client of this share needs the same secret, and the bucket then holds only encrypted names and contents')
        elif (e.get('settings') or {}).get('tls') is not True:
            say('note', f'{ch["name"]}:{mt["path"]}: no TLS and no encryption: the data is readable on the network')

    def server_params(self, e, srv):
        st = e.get('settings') or {}
        return {'port': self.port(e), 'tls': bool(st.get('tls')), 'cert_file': st.get('cert_file') or '', 'key_file': st.get('key_file') or '',
                'secret': st.get('secret') or ''}

    def client_params(self, e, mt, srv):
        st, ms = e.get('settings') or {}, mt.get('settings') or {}
        addr = srv['ssh_host']
        host = f'[{addr}]' if ':' in addr else addr
        return {'endpoint': f'{"https" if st.get("tls") else "http"}://{host}:{self.port(e)}', 'secret': ms.get('secret') or '',
                'crypt': bool(ms.get('crypt')), 'crypt_secret': ms.get('crypt_secret') or ''}

    def client_source(self, e, address):
        return f's3://{address}:{self.port(e)}/{e["name"]}'

    def server_secrets(self, e):
        k = (e.get('settings') or {}).get('secret')
        return [k] if k else []

    def client_secrets(self, e, mt):
        ms = mt.get('settings') or {}
        return [k for k in (ms.get('secret'), ms.get('crypt_secret') if ms.get('crypt') else None) if k]


netshares.register(S3(
    key='S3', label='S3',
    help='rclone serves the folder as an S3 bucket named after the share; clients mount it with rclone, with optional client-side encryption. Keys come from the vault.',
    clients_label='Clients that may connect', clients_help='Addresses or subnets that may reach the S3 port, space separated.',
    fields=[Field('port', 'int', 'Port', 'The TCP port the S3 endpoint listens on.', options=(1024, 65535), default=DEFAULT_PORT),
            Field('secret', 'secret', 'Vault secret with the access keys', 'Lines access_key_id = … and secret_access_key = …', required=True, placeholder='nas-s3-keys'),
            Field('tls', 'bool', 'Serve over HTTPS', 'Needs the certificate and key files below. Without it the keys cross the network in the clear.', default=False),
            Field('cert_file', 'path', 'TLS certificate file on the server', 'Such as the self-signed StorageForge certificate.', placeholder='/etc/storageforge/tls/cert.pem'),
            Field('key_file', 'path', 'TLS key file on the server', '', placeholder='/etc/storageforge/tls/key.pem')],
    mount_fields=[Field('secret', 'secret', 'Vault secret with its copy of the access keys', 'Lines access_key_id = … and secret_access_key = …', required=True, placeholder='pc-s3-keys'),
                  Field('crypt', 'bool', 'Encrypt on the client (rclone crypt)', 'Data is encrypted before it reaches the server. Lose the secret and the data is gone.', default=False),
                  Field('crypt_secret', 'secret', 'Vault secret with the crypt passwords', 'password = …, and password2 = … for the salt.', placeholder='pc-s3-crypt')],
    needs_server='rclone', needs_client='rclone', bash=BASH))
