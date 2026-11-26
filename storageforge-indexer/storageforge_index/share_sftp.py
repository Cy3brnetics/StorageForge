"""SFTP shares: OpenSSH's own internal-sftp on the server, chrooted to the share, and sshfs on the clients.

Server: sshd already runs on every host StorageForge reaches, so nothing is installed. Each share gets a chroot that sshd accepts
(root-owned and not writable by anyone else, which a data folder is not): /srv/storageforge-sftp/NAME, with the shared folder bound into
it at /srv/storageforge-sftp/NAME/NAME by a unit of StorageForge. A drop-in, /etc/ssh/sshd_config.d/50-storageforge-sftp.conf, puts the
accounts the share names in that chroot with internal-sftp only: no shell, no forwarding, no tunnels. sshd -t checks it before sshd is
reloaded; a config sshd rejects is taken back. Each client mount's public key goes into its account's authorized_keys with `restrict`.

Client: sshfs as a unit (storageforge-share-SERVER.<target>.service), with the mount's private key from the vault in a root-only file
and the server's host keys pinned from StorageForge's own scan, so a man in the middle is refused rather than learnt.
"""
from __future__ import annotations

import re

from . import netshares
from .netshares import Driver, Field

ACCOUNT = re.compile(r'[a-z_][a-z0-9_.-]{0,31}')
PUBKEY = re.compile(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]{40,2000}( [^\x00-\x1f\x7f]{0,200})?')
UMASK = re.compile(r'0?[0-7]{3}')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,40}')

BASH = r"""
SFTP_ROOT=${SF_SFTP_ROOT:-/srv/storageforge-sftp}
SFTP_CONF=${SF_SFTP_CONF:-/etc/ssh/sshd_config.d/50-storageforge-sftp.conf}
sftp_bind_unit() { echo "storageforge-sftp-bind-$(systemd-escape -p "$1").service"; }   # the chroot path -> its bind unit
server_sftp() {
  local i idx=() body="# StorageForge SFTP shares for $(uname -n). Written by shares-$SERVER.sh; edit the design, not this file." keep=() chroot inner unit u users ro um changed=0
  mapfile -t idx < <(indices_of SFTP)
  if ((!${#idx[@]})); then
    if [[ -e $SFTP_CONF ]] || compgen -G "/etc/systemd/system/storageforge-sftp-bind-*" >/dev/null; then
      section "SFTP server"; drop_units storageforge-sftp-bind-
      if [[ -e $SFTP_CONF ]] && ((APPLY)); then backup "$SFTP_CONF"; rm -f -- "$SFTP_CONF"; doing "removed $SFTP_CONF"; sshd_reload; elif [[ -e $SFTP_CONF ]]; then missing "would remove $SFTP_CONF"; fi
    fi
    return 0
  fi
  section "SFTP server (OpenSSH internal-sftp)"
  if ! grep -qsE "^\s*Include\s+/etc/ssh/sshd_config.d/\*\.conf" /etc/ssh/sshd_config; then
    conflict "/etc/ssh/sshd_config does not include /etc/ssh/sshd_config.d/*.conf: add that line at its top, then deploy again"; return 0
  fi
  for i in "${idx[@]}"; do
    changed=0; chroot=$SFTP_ROOT/${E_NAME[$i]}; inner=$chroot/${E_NAME[$i]}; unit=$(sftp_bind_unit "$inner"); keep+=("$unit")
    users=$(par users "${E_PARAM[$i]}"); ro=$(par readonly "${E_PARAM[$i]}"); um=$(par umask "${E_PARAM[$i]}")
    [[ -d ${E_PATH[$i]} ]] && ok "${E_PATH[$i]} exists" || { if ((APPLY)); then doing "mkdir -p ${E_PATH[$i]}"; mkdir -p -- "${E_PATH[$i]}"; else missing "${E_PATH[$i]}"; fi; }
    if [[ -d $chroot ]] && [[ $(stat -c "%U %a" "$chroot") == "root 755" ]]; then ok "chroot $chroot"
    elif ((APPLY)); then mkdir -p -- "$inner" && chown root:root "$SFTP_ROOT" "$chroot" && chmod 755 "$SFTP_ROOT" "$chroot" && doing "chroot $chroot (root, 755)"
    else missing "chroot $chroot (root-owned, 755: sshd refuses any other)"; fi
    unit_file "$unit" "# Written by StorageForge: binds ${E_PATH[$i]} into the SFTP chroot of ${E_NAME[$i]}.
[Unit]
Description=StorageForge SFTP share ${E_NAME[$i]}: bind ${E_PATH[$i]}
RequiresMountsFor=${E_PATH[$i]}
Before=ssh.service sshd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/mkdir -p \"$inner\"
ExecStart=/usr/bin/mount --bind \"${E_PATH[$i]}\" \"$inner\"
ExecStop=/usr/bin/umount -l \"$inner\"

[Install]
WantedBy=multi-user.target" && changed=1
    if ((APPLY)); then
      if ((changed)) && systemctl is-active -q "$unit"; then systemctl restart "$unit" || conflict "could not bind ${E_PATH[$i]} into $inner"; fi
      systemctl is-active -q "$unit" || systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "could not bind ${E_PATH[$i]} into $inner: journalctl -u $unit"
    fi
    if timeout -k 2 10 mountpoint -q "$inner"; then ok "${E_PATH[$i]} is bound into $inner"; elif ((!APPLY)); then missing "${E_PATH[$i]} is not bound into $inner yet"; fi
    body+=$'\n\n'"Match User ${users// /,}"$'\n'"    ChrootDirectory $chroot"$'\n'"    ForceCommand internal-sftp -d /${E_NAME[$i]}${ro:+ -R}${um:+ -u $um}"
    body+=$'\n'"    AllowTcpForwarding no"$'\n'"    AllowAgentForwarding no"$'\n'"    X11Forwarding no"$'\n'"    PermitTunnel no"$'\n'"    PermitTTY no"
    for u in $users; do
      id -u "$u" >/dev/null 2>&1 && ok "account $u" || missing "account $u: make it first (useradd -M -s /usr/sbin/nologin $u), StorageForge does not make accounts"
    done
    sftp_keys "$i"
  done
  MANAGED_FILES+=("$SFTP_CONF")
  if own_file "$SFTP_CONF" "$body"; then
    if sshd -t 2>/tmp/sf-sshd-t.$$; then sshd_reload; rm -f /tmp/sf-sshd-t.$$
    else conflict "sshd -t rejects the SFTP config, so it was taken back: $(head -n 2 /tmp/sf-sshd-t.$$ | tr "\n" " ")"; rm -f /tmp/sf-sshd-t.$$
      if [[ -e $SFTP_CONF.storageforge-$STAMP ]]; then cp -a -- "$SFTP_CONF.storageforge-$STAMP" "$SFTP_CONF"; else rm -f -- "$SFTP_CONF"; fi; fi
  fi
  drop_units storageforge-sftp-bind- "${keep[@]}"
}
sshd_reload() { systemctl reload "$(unit_of sshd ssh)" 2>/dev/null && doing "reloaded sshd" || conflict "could not reload sshd"; }
sftp_keys() { # share index -> each client mount public key in its account authorized_keys, restricted
  local i=$1 j k u f home line
  for j in "${!C_PROTO[@]}"; do [[ ${C_PROTO[$j]} == SFTP && ${C_NAME[$j]} == "${E_NAME[$i]}" ]] || continue
    u=$(par user "${C_PARAM[$j]}"); k=$(par public_key "${C_PARAM[$j]}"); [[ -n $u && -n $k ]] || continue
    home=$(getent passwd "$u" | cut -d: -f6); [[ -n $home ]] || continue
    f=$home/.ssh/authorized_keys; line="restrict $k"
    if grep -qxF -- "$line" "$f" 2>/dev/null; then ok "$u has the key of ${C_HOST[$j]}"
    elif ((APPLY)); then install -d -m 700 -o "$u" -g "$(id -g "$u")" "$home/.ssh" && printf "%s\n" "$line" >>"$f" && chown "$u:$(id -g "$u")" "$f" && chmod 600 "$f" && doing "added the key of ${C_HOST[$j]} for $u"
    else missing "the key of ${C_HOST[$j]} in $f"; fi
  done
}
client_sftp() {
  local i=$1 t=${C_TARGET[$1]} u key kh unit dir=/etc/storageforge/sftp opts body
  u=$(par user "${C_PARAM[$i]}"); key=$(par key_secret "${C_PARAM[$i]}"); unit=$(share_unit "$t").service
  section "mount ${C_SOURCE[$i]} at $t (sshfs)"
  need_cmd sshfs "sshfs" sshfs fuse-sshfs sshfs sshfs || return 0
  if ((APPLY)); then
    local src; src=$(secret "$key")
    [[ -n $src ]] || { conflict "the vault secret $key (the private key for $u) is not on this host: deploy from StorageForge, which brings it"; return 0; }
    (umask 077; mkdir -p "$dir") && install -m 600 -- "$src" "$dir/$SERVER-$u.key"
    (umask 022; par known_hosts "${C_PARAM[$i]}" | tr "|" "\n" >"$dir/$SERVER.known_hosts")
  fi
  opts="allow_other,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,IdentityFile=$dir/$SERVER-$u.key,UserKnownHostsFile=$dir/$SERVER.known_hosts,StrictHostKeyChecking=yes,Port=$(par port "${C_PARAM[$i]}")"
  [[ -z ${C_OPTS[$i]} ]] || opts+=,${C_OPTS[$i]}
  body="# Written by StorageForge: the SFTP share ${C_NAME[$i]} of $SERVER at $t.
[Unit]
Description=StorageForge SFTP share ${C_NAME[$i]} of $SERVER at $t
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/bin/mkdir -p \"$t\"
ExecStart=/usr/bin/sshfs -f -o $opts $u@$SERVER_ADDR:/${C_NAME[$i]} \"$t\"
ExecStop=/bin/sh -c \"fusermount3 -uz \\\"$t\\\" 2>/dev/null || fusermount -uz \\\"$t\\\"\"
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target"
  local changed=0; unit_file "$unit" "$body" && changed=1
  if ((APPLY)); then
    if ((changed)) && systemctl is-active -q "$unit"; then systemctl restart "$unit" 2>/dev/null || true; fi
    systemctl is-active -q "$unit" || systemctl enable --now "$unit" >/dev/null 2>&1 || conflict "$unit did not start: journalctl -u $unit"
  fi
  if timeout -k 2 10 mountpoint -q "$t"; then ok "mounted"; elif ((APPLY)); then sleep 2; timeout -k 2 10 mountpoint -q "$t" && ok "mounted" || conflict "$t is not mounted: journalctl -u $unit"; else missing "not mounted"; fi
}
cleanup_sftp() { return 0; }    # its client units go with driver_units_cleanup; the key and known_hosts files are the next mount's
"""


class Sftp(Driver):
    def normalize(self, s: dict) -> dict:
        out = netshares.clean(self.fields, s)
        if out.get('umask') and not UMASK.fullmatch(out['umask']):
            raise ValueError('the umask is three octal digits, such as 002')
        return out

    def normalize_mount(self, s: dict) -> dict:
        out = netshares.clean(self.mount_fields, s)
        if out.get('user') and not ACCOUNT.fullmatch(out['user']):
            raise ValueError(f'{out["user"]!r} is not an account name')
        if out.get('public_key') and not PUBKEY.fullmatch(out['public_key']):
            raise ValueError('the public key is one OpenSSH public key line (ssh-ed25519 AAAA… comment)')
        return out

    @staticmethod
    def users(e: dict) -> list:
        return [u for u in (e.get('clients') or '').split() if u]

    def check(self, conn, hs, srv, e, say):
        if not NAME.fullmatch(e['name'] or ''):
            say('crit', 'an SFTP share needs a name of letters, digits, . _ - (it is the folder clients see)')
        users = self.users(e)
        bad = [u for u in users if not ACCOUNT.fullmatch(u)]
        if bad:
            say('crit', f'{", ".join(bad)} is not an account name: who may connect is a list of accounts on {srv["name"]}')
        if not users:
            say('crit', f'an SFTP share needs the accounts on {srv["name"]} that may use it')
        if 'root' in users:
            say('crit', 'root cannot be chrooted to a share: name the accounts that use it')
        say('note', f'{", ".join(users) or "the accounts"} are chrooted to {e["name"]} with internal-sftp only: no shell, no forwarding. '
                    'StorageForge does not make the accounts; each needs one on the server')
        st = e.get('settings') or {}
        if st.get('readonly'):
            say('note', 'read only: clients can list and download, not change anything')

    def check_mount(self, conn, srv, e, mt, ch, say):
        st = mt.get('settings') or {}
        if not st.get('user'):
            say('crit', f'{ch["name"]}:{mt["path"]}: name the account on {srv["name"]} it logs in as')
        elif st['user'] not in self.users(e):
            say('crit', f'{ch["name"]}:{mt["path"]}: {st["user"]} is not one of the accounts this share lets in')
        if not st.get('key_secret'):
            say('crit', f'{ch["name"]}:{mt["path"]}: name the vault secret with the private key it logs in with')
        if not st.get('public_key'):
            say('warn', f'{ch["name"]}:{mt["path"]}: no public key: its account on {srv["name"]} must already accept the key')
        if not srv.get('host_keys'):
            say('warn', f'StorageForge has no host key pinned for {srv["name"]}: rescan it, or the mount refuses to connect')

    def server_params(self, e, srv, hs):
        st = e.get('settings') or {}
        return {'users': ' '.join(self.users(e)), 'readonly': bool(st.get('readonly')), 'umask': st.get('umask') or ''}

    def client_params(self, e, mt, srv, hs):
        st = mt.get('settings') or {}
        keys = srv.get('host_keys') or []
        addr, port = srv['ssh_host'], int(srv.get('ssh_port') or 22)
        host = addr if port == 22 else f'[{addr}]:{port}'
        return {'user': st.get('user') or '', 'key_secret': st.get('key_secret') or '', 'public_key': st.get('public_key') or '',
                'port': port, 'known_hosts': '|'.join(f'{host} {k}' for k in keys if re.fullmatch(r'[a-z0-9@.-]+ [A-Za-z0-9+/=]+', k))}

    def client_source(self, e, address):
        return f'sftp://{address}/{e["name"]}'

    def client_secrets(self, e, mt):
        k = (mt.get('settings') or {}).get('key_secret')
        return [k] if k else []


netshares.register(Sftp(
    key='SFTP', label='SFTP',
    help='OpenSSH on the server, nothing to install: named accounts are chrooted to the share, and clients mount it with sshfs over a key from the vault.',
    clients_label='Accounts on the server that may connect', clients_help='Account names, space separated. Each needs an account on the server.',
    fields=[Field('readonly', 'bool', 'Read only', 'Clients can list and download, not change anything.', default=False),
            Field('umask', 'text', 'Umask for new files', 'Such as 002, so a group can share files.', placeholder='002')],
    mount_fields=[Field('user', 'text', 'Logs in as', 'One of the accounts the share lets in.', required=True, placeholder='backup'),
                  Field('key_secret', 'secret', 'Vault secret with its private key', 'An OpenSSH private key, kept in the vault.', required=True, placeholder='nas-sftp-key'),
                  Field('public_key', 'text', 'Its public key', 'Added to the account on the server, restricted to SFTP.', placeholder='ssh-ed25519 AAAA… backup@client')],
    needs_client='sshfs', bash=BASH))
