"""The ssh-ca-trust and ssh-ca-krl plan steps: make a host's sshd trust the StorageForge SSH CA, and give it the list of revoked
certificates (roadmap section 2, "SSH CA"; the CA is sshcerts.py).

What ssh-ca-trust writes, and nothing else:

    /etc/ssh/storageforge_user_ca.pub            the CA's public key
    /etc/ssh/storageforge_principals/<user>      who may log in as <user> with a certificate: `<user>@<this host>`, and what was added
    /etc/ssh/storageforge_revoked_keys           the revocation list, and its version beside it
    /etc/ssh/sshd_config.d/50-storageforge-ca.conf   TrustedUserCAKeys, AuthorizedPrincipalsFile, RevokedKeys, and HostCertificate if asked

It never locks anyone out. AuthorizedKeysFile and PubkeyAuthentication are not touched, and the step checks that sshd answers the
same for both afterwards. A user with no principals file cannot log in with a certificate and can with a key, as before. sshd -t
reads the result before sshd is reloaded, and a rejected or overruled change is put back from a copy taken first. A host that
already trusts another CA, or has a revocation list or principals of its own, is left alone and said so: sshd takes one of each.

The one file here that can lock people out is the revocation list: sshd refuses every key when it cannot read it. So a list is
checked with ssh-keygen on the host before it is moved into place, in one rename, and an older list never replaces a newer one.

Nothing here is secret: a CA's public key, names, and serial numbers.
"""
from __future__ import annotations

import base64
import re
import shlex

from . import changes, sshcerts
from .changes import F
from .steps_infra import ROLLBACK

USERS = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}(,[A-Za-z_][A-Za-z0-9_.-]{0,31}){0,31}')
PRINCIPALS = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,254}(,[A-Za-z0-9_][A-Za-z0-9_.@-]{0,254}){0,31}')
ARGS = ('users', 'principals', 'host_cert', 'state', 'rollback')

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
# ── the SSH CA: trust, and the revocation list ──────────────────────
# sshd -T prints its keywords in lower case in older OpenSSH and as the manual writes them in newer ones (10.6 does): both are read
ca_sshd_get() { { sshd -T 2>/dev/null || true; } | awk -v k="$1" 'tolower($1) == k { sub(/^[^ ]+ +/, ""); print; exit }'; }
ca_sshd_all() { { sshd -T 2>/dev/null || true; } | awk -v k="$1" 'tolower($1) == k { print $2 }'; }
ca_reload_line() { echo "systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd reload >/dev/null 2>&1 || service ssh reload >/dev/null 2>&1"; }
ca_reload() { sh -c "$(ca_reload_line)"; }
ca_krl_have() { local v; v=$(cat "$1.version" 2>/dev/null || true); if [[ $v =~ ^[0-9]+$ && -s $1 ]]; then echo "$v"; else echo -1; fi; }
ca_krl_put() { # the list from base64 into $1, checked first, in one rename. sshd refuses every key when it cannot read this file
  local to=$1 b64=$2 version=$3 cafile=$4 tmp
  command -v ssh-keygen >/dev/null || { conflict "ssh-keygen is not here to check the revocation list with: it is not installed unchecked"; return 1; }
  tmp=$(mktemp "$to.XXXXXX") || { conflict "could not write beside $to"; return 1; }
  if ! printf %s "$b64" | base64 -d >"$tmp" 2>/dev/null || [[ ! -s $tmp ]] || ! ssh-keygen -Q -f "$tmp" "$cafile" >/dev/null 2>&1; then
    rm -f "$tmp"; conflict "the revocation list does not read as one on this host: the one in place is left as it is"; return 1
  fi
  chmod 0644 "$tmp"; mv -f "$tmp" "$to"; printf "%s\n" "$version" >"$to.version"; chmod 0644 "$to.version"
  durable "$to" "$to.version"
}
ca_backup() { # a copy of what is there, and one script that puts it back: for a rejected change now, and for the rollback timer later
  local bk=$1 conf=$2 cafile=$3 pdir=$4 krlfile=$5 hc=${6:-} x
  mkdir -p "$bk" || { conflict "could not write $bk"; return 1; }
  chmod 0700 "$bk"; find "${bk%/*}" -maxdepth 1 -name "before-*" -mtime +7 -exec rm -rf {} + 2>/dev/null || true
  for x in "$conf conf" "$cafile ca" "$pdir p" "$krlfile krl" "$krlfile.version krlv" "${hc:+$hc hostcert}"; do
    [[ -n $x && -e ${x% *} ]] && cp -a "${x% *}" "$bk/${x#* }"
  done
  { printf "#!/bin/sh\n# Written by StorageForge (the ssh-ca-trust step): puts sshd back as the copy in this folder has it.\n"
    printf "rm -f %s; if [ -e %s/conf ]; then cp -a %s/conf %s; fi\n" "$conf" "$bk" "$bk" "$conf"
    printf "rm -rf %s; if [ -d %s/p ]; then cp -a %s/p %s; fi\n" "$pdir" "$bk" "$bk" "$pdir"
    printf "if [ -e %s/ca ]; then cp -a %s/ca %s; fi\n" "$bk" "$bk" "$cafile"
    printf "if [ -e %s/krl ]; then cp -a %s/krl %s.back && mv -f %s.back %s; cp -a %s/krlv %s.version; fi\n" "$bk" "$bk" "$krlfile" "$krlfile" "$krlfile" "$bk" "$krlfile"
    [[ -n $hc ]] && printf "if [ -e %s/hostcert ]; then cp -a %s/hostcert %s; else rm -f %s; fi\n" "$bk" "$bk" "$hc" "$hc"
    # a list sshd was told of and cannot read refuses every key: one that was not there before goes only once sshd has let go of it
    printf "if %s; then\n" "$(ca_reload_line)"
    printf "  [ -e %s/krl ] || rm -f %s %s.version\n  [ -e %s/ca ] || rm -f %s\nfi\n" "$bk" "$krlfile" "$krlfile" "$bk" "$cafile"; } >"$bk/restore.sh"
}

t_ssh_ca_trust() { local users=$1 extra=$2 wantcert=$3 state=${4:-present} roll=${5:-} ca=${6:-} hostp=${7:-} krl=${8:-} krlv=${9:-0} cert=${10:-}
  local d=${SF_SSH_DIR:-/etc/ssh} bk=${SF_SSHCA_STATE:-/var/lib/storageforge/ssh-ca}/before-$STAMP
  local conf=$d/sshd_config.d/50-storageforge-ca.conf cafile=$d/storageforge_user_ca.pub pdir=$d/storageforge_principals krlfile=$d/storageforge_revoked_keys main=$d/sshd_config
  local w u p x have keys pubkey hk= certfp err said same=1
  command -v sshd >/dev/null || { conflict "sshd is not installed on this host"; return 0; }
  if [[ $state == absent ]]; then
    if [[ ! -e $conf && ! -e $cafile && ! -d $pdir ]]; then ok "this host does not trust the StorageForge CA"; return 0; fi
    act "stop trusting the StorageForge CA: remove $conf, the CA key, the principals and the revocation list. authorized_keys is not touched" || return 0
    ca_backup "$bk" "$conf" "$cafile" "$pdir" "$krlfile" || return 0
    if [[ -n $roll ]]; then fw_tool; fw_arm "$roll" "sh $bk/restore.sh"; fi
    rm -f "$conf"
    err=$(mktemp)
    if ! sshd -t 2>"$err"; then
      said=$(cat "$err"); rm -f "$err"; sh "$bk/restore.sh"
      conflict "sshd -t rejected its configuration without $conf, so it was put back: $said"; return 0
    fi
    rm -f "$err"
    # the list stays until sshd has let go of it: sshd refuses every key while a list it was told of is missing
    ca_reload || { conflict "sshd did not reload: it trusts the CA until it is restarted, and the revocation list is left in place for it"; return 0; }
    rm -rf "$cafile" "$pdir" "$krlfile" "$krlfile.version"
    [[ -n $roll ]] || rm -rf "$bk"
    ok "certificates of the StorageForge CA no longer log in here. Keys in authorized_keys work as before"
    return 0
  fi
  [[ -n $ca ]] || { conflict "there is no SSH CA yet: make it under Keys, and this plan picks it up"; return 0; }
  [[ -n $hostp ]] || { conflict "this host has no name in the index to make its principals from"; return 0; }
  for u in ${users//,/ }; do id "$u" >/dev/null 2>&1 || { conflict "there is no account $u on this host"; return 0; }; done
  grep -qiE "^[[:space:]]*Include[[:space:]].*sshd_config\.d" "$main" 2>/dev/null || { conflict "$main does not include sshd_config.d: add the CA there by hand (TrustedUserCAKeys)"; return 0; }
  keys=$(ca_sshd_get authorizedkeysfile); pubkey=$(ca_sshd_get pubkeyauthentication)
  if [[ -z $pubkey ]]; then
    if ((APPLY)); then conflict "sshd -T gives nothing here, so its configuration cannot be read: nothing is changed"; else missing "sshd -T needs root to read the configuration: run the report with sudo"; fi
    return 0
  fi
  [[ $pubkey == yes ]] || { conflict "PubkeyAuthentication is off on this host, and a certificate is a public key: nothing is changed"; return 0; }
  for x in "trustedusercakeys $cafile" "authorizedprincipalsfile $pdir/%u" "revokedkeys $krlfile"; do
    have=$(ca_sshd_get "${x%% *}")
    if [[ -n $have && $have != none && $have != "${x#* }" ]]; then
      conflict "sshd already has ${x%% *} $have, and takes only one: StorageForge does not replace it. Nothing is changed"; return 0
    fi
  done
  if [[ -n $wantcert ]]; then
    [[ -n $cert ]] || { conflict "no host certificate is on record for this host: issue one under Keys first"; return 0; }
    command -v ssh-keygen >/dev/null || { conflict "ssh-keygen is not here to check the host certificate with"; return 0; }
  fi
  # what should be there, built aside and compared: a second run changes nothing and reloads nothing
  w=$(mktemp -d) || { conflict "could not make a temporary folder"; return 0; }
  printf "%s\n" "$ca" >"$w/ca"; mkdir "$w/p"
  for u in ${users//,/ }; do { printf "%s@%s\n" "$u" "$hostp"; for p in ${extra//,/ }; do printf "%s\n" "$p"; done; } >"$w/p/$u"; done
  { printf "# Written by StorageForge (the ssh-ca-trust step). Certificates of its CA log in as the users in %s.\n" "$pdir"
    printf "# AuthorizedKeysFile is not set here: keys work as they did.\n"
    printf "TrustedUserCAKeys %s\nAuthorizedPrincipalsFile %s/%%u\nRevokedKeys %s\n" "$cafile" "$pdir" "$krlfile"; } >"$w/conf"
  if [[ -n $wantcert ]]; then
    printf "%s\n" "$cert" >"$w/hostcert"
    certfp=$(ssh-keygen -l -f "$w/hostcert" 2>/dev/null | awk "{print \$2}") || true
    for x in $(ca_sshd_all hostkey); do
      [[ $x =~ ^[A-Za-z0-9_./-]+$ && -r $x.pub && -n $certfp && $(ssh-keygen -l -f "$x.pub" 2>/dev/null | awk "{print \$2}") == "$certfp" ]] && hk=$x
    done
    [[ -n $hk ]] || { rm -rf "$w"; conflict "the host certificate on record is for a host key this sshd does not use: issue it again after a scan"; return 0; }
    printf "HostCertificate %s-cert.pub\n" "$hk" >>"$w/conf"
    cmp -s "$w/hostcert" "$hk-cert.pub" || same=
  fi
  have=$(ca_krl_have "$krlfile")
  cmp -s "$w/ca" "$cafile" || { same=; have=-1; }      # another CA than the one in place: its list goes in with it, whatever version is there
  cmp -s "$w/conf" "$conf" && diff -rq "$w/p" "$pdir" >/dev/null 2>&1 || same=
  ((have >= krlv)) || same=
  if [[ -n $same ]]; then
    rm -rf "$w"; ok "trusts the StorageForge CA for $users, with revocation list version $have"; return 0
  fi
  act "trust the StorageForge CA for $users: a certificate for USER@$hostp${extra:+ or $extra} logs in as USER. Keys in authorized_keys go on working" || { rm -rf "$w"; return 0; }
  ca_backup "$bk" "$conf" "$cafile" "$pdir" "$krlfile" "${hk:+$hk-cert.pub}" || { rm -rf "$w"; return 0; }
  if [[ -n $roll ]]; then fw_tool; fw_arm "$roll" "sh $bk/restore.sh"; fi
  install -m 0644 "$w/ca" "$cafile"
  rm -rf "$pdir.new"; cp -r "$w/p" "$pdir.new"; chmod 0755 "$pdir.new"; chmod 0644 "$pdir.new"/*; rm -rf "$pdir"; mv "$pdir.new" "$pdir"
  # the list is in place and read before the line that names it: sshd refuses every key when it cannot read the file RevokedKeys names
  if ((have < krlv)) && ! ca_krl_put "$krlfile" "$krl" "$krlv" "$cafile"; then sh "$bk/restore.sh"; rm -rf "$w"; return 0; fi
  [[ -n $hk ]] && install -m 0644 "$w/hostcert" "$hk-cert.pub"
  mkdir -p "${conf%/*}"; install -m 0644 "$w/conf" "$conf"
  rm -rf "$w"
  command -v restorecon >/dev/null && restorecon -R "$cafile" "$pdir" "$krlfile" "$conf" 2>/dev/null || true
  err=$(mktemp)
  if ! sshd -t 2>"$err"; then
    said=$(cat "$err"); rm -f "$err"; sh "$bk/restore.sh"
    conflict "sshd -t rejected it, so everything was put back: $said"; return 0
  fi
  rm -f "$err"
  # another line of sshd_config can win over this file, and none of this may change how keys log in
  for x in "trustedusercakeys $cafile" "authorizedprincipalsfile $pdir/%u" "revokedkeys $krlfile" "authorizedkeysfile $keys" "pubkeyauthentication $pubkey"; do
    have=$(ca_sshd_get "${x%% *}")
    if [[ $have != "${x#* }" ]]; then
      sh "$bk/restore.sh"
      conflict "with $conf in place sshd answers ${x%% *} $have and not ${x#* }: everything was put back"; return 0
    fi
  done
  durable "$cafile" "$pdir" "$conf"
  if ! ca_reload; then sh "$bk/restore.sh"; conflict "sshd did not reload, so everything was put back"; return 0; fi
  [[ -n $roll ]] || rm -rf "$bk"
  ok "trusts the StorageForge CA for $users${hk:+, and presents its host certificate}. Keys in authorized_keys work as before"
}

t_ssh_ca_krl() { local ca=${1:-} krl=${2:-} krlv=${3:-0} d=${SF_SSH_DIR:-/etc/ssh} conf cafile krlfile have
  conf=$d/sshd_config.d/50-storageforge-ca.conf; cafile=$d/storageforge_user_ca.pub; krlfile=$d/storageforge_revoked_keys
  [[ -n $ca ]] || { conflict "there is no SSH CA yet, so there is nothing to revoke"; return 0; }
  if [[ ! -e $conf || ! -e $cafile ]]; then conflict "this host does not trust the StorageForge CA: the ssh-ca-trust step comes first, and brings the list with it"; return 0; fi
  [[ $(cat "$cafile" 2>/dev/null) == "$ca" ]] || { conflict "this host trusts another StorageForge CA than the one this list is for: run ssh-ca-trust here again"; return 0; }
  have=$(ca_krl_have "$krlfile")
  if ((have == krlv)); then ok "has revocation list version $krlv"; return 0; fi
  if ((have > krlv)); then ok "has revocation list version $have, newer than this plan was written with ($krlv): left as it is"; return 0; fi
  act "install revocation list version $krlv (it has $( ((have < 0)) && echo none || echo "version $have"))" || return 0
  ca_krl_put "$krlfile" "$krl" "$krlv" "$cafile" || return 0
  ok "revocation list version $krlv: sshd reads it at every login, so the certificates it names are refused from now on"
}
"""


def _host_name(conn, t) -> str:
    h = changes.find_host(changes.hosts(conn), t['host'])
    return h['name'] if h else t['host']


def _krl_args(conn) -> list[str]:
    made = sshcerts.krl(conn)
    return [sshcerts.ca_public(conn) or '', base64.b64encode(made[0]).decode() if made else '', str(made[1]) if made else '0']


def _trust_args(conn, t):
    """The CA, this host's name for its principals, the revocation list and its version, and the host certificate if asked for:
    all public, all worked out when the script is written, so a plan saved last week still installs today's list."""
    ca, krl, version = _krl_args(conn)
    name = _host_name(conn, t)
    cert = sshcerts.host_certificate(conn, name) if t['params'].get('host_cert') else None
    return [ca, name if sshcerts.HOST_NAME.fullmatch(name) else '', krl, version, (cert or {}).get('certificate') or '']


def _check_trust(conn, c, h, p, say):
    if not USERS.fullmatch(p['users']):
        say('crit', 'users are account names separated by commas, such as root,backup')
        return
    if p['principals'] and not PRINCIPALS.fullmatch(p['principals']):
        say('crit', 'principals are names separated by commas: letters, digits, . _ @ and -')
    if p['state'] == 'absent':
        got = sshcerts.host_setting(conn, h['name'])
        if got['console'] or got['scan']:
            say('warn', f'StorageForge logs in to {h["name"]} with certificates ({", ".join(k for k in sshcerts.PURPOSES if got[k])}): after this only its key in authorized_keys gets in')
        say('note', 'removes the CA, the principals and the revocation list. authorized_keys is not touched')
        return
    if not sshcerts.ca_public(conn):
        say('crit', 'there is no SSH CA yet: make it under Keys')
    if not sshcerts.HOST_NAME.fullmatch(h['name']):
        say('crit', f'{h["name"]} cannot be part of a principal')
    if p['host_cert'] and not sshcerts.host_certificate(conn, h['name']):
        say('crit', f'no host certificate is on record for {h["name"]}: issue one under Keys first')
    users = p['users'].split(',')
    shown = ', '.join(f'{u}@{h["name"]}' for u in users[:4])
    say('note', f'a certificate for {shown}{" …" if len(users) > 4 else ""}'
                + (f' or {p["principals"]}' if p['principals'] else '') + ' logs in as that user. Keys in authorized_keys go on working')
    if p['principals']:
        say('warn', f'{p["principals"]} is accepted for every user listed here, on every host that lists it: a certificate with it is not tied to this host')
    say('note', 'sshd -t reads the result before sshd is reloaded. A rejected change, or one another line of sshd_config overrules, is put back')
    if 'root' in users and (h.get('ssh_user') or '') != 'root':
        say('note', 'root is listed: a certificate for root logs in as root where PermitRootLogin allows keys')


def _check_krl(conn, c, h, p, say):
    if not sshcerts.ca_public(conn):
        say('crit', 'there is no SSH CA yet, so there is nothing to revoke')
        return
    say('note', f'installs the list as it stands when the plan runs (now version {sshcerts.krl_version(conn)}, {len(sshcerts.revoked_serials(conn))} certificate(s)). '
                'It is checked on the host before it replaces the one there, and an older list never replaces a newer one')


HEAD = ('APPLY=1; STAMP=$(date +%Y%m%d-%H%M%S); ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }\n'
        'act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; durable() { sync; }; fw_arm() { :; }; fw_tool() { :; }\n')


def _ansible(fn: str, args_of):
    def render(t, conn):
        q = shlex.quote
        p = t['params']
        own = [('1' if p[a] else '') if isinstance(p.get(a), bool) else str(p.get(a) or '') for a in changes.ARGS[t['type']]]
        extra = args_of(conn, t) if conn is not None else []
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': HEAD + BASH + f'\n{fn} ' + ' '.join(q(a) for a in own + extra) + '\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


changes.register('ssh-ca-trust', {'group': 'Hardening', 'label': 'Trust the SSH CA', 'fields': [
    F('users', 'options', 'Users a certificate may log in as', required=True, placeholder='root,backup'),
    F('principals', 'options', 'More principals to accept (optional)', placeholder='storage-admins'),
    F('host_cert', 'bool', 'Install this host\'s certificate too (issued under Keys)'),
    F('state', 'choice', 'Trust or stop trusting', options=['present', 'absent'], default='present'), ROLLBACK],
    'help': 'Sets TrustedUserCAKeys, the principals for each user and the revocation list, in a file of its own under sshd_config.d. '
            'authorized_keys is left as it is, sshd -t checks the result, and a rejected change is put back.'},
    ARGS, lambda p: 'Stop trusting the SSH CA' if p['state'] == 'absent' else f'Trust the SSH CA for {p["users"]}', _check_trust,
    _ansible('t_ssh_ca_trust', _trust_args), args_of=_trust_args)
changes.register('ssh-ca-krl', {'group': 'Hardening', 'label': 'Revoked SSH certificates', 'fields': [],
                                'help': 'Gives a host that trusts the SSH CA the current list of revoked certificates (RevokedKeys).'},
                 (), lambda p: 'Install the list of revoked SSH certificates', _check_krl, _ansible('t_ssh_ca_krl', lambda conn, t: _krl_args(conn)),
                 args_of=lambda conn, t: _krl_args(conn))
changes.EXTRA_BASH.append(BASH)
