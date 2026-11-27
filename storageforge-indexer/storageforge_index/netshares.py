"""Share protocols beyond NFS and SMB, each a driver that shares.py deploys the way it deploys those two.

A driver is one module (share_sftp.py, share_s3.py, ...) that registers itself here. shares.py keeps everything a share has in common:
the design it lives in, the wizard, the folder checks, the one generated script per server that is run on the server and on each
client (a report by default, --apply to make it so), the deploy, drift records and cleanup. A driver adds what is its own:

    key, label, help      the protocol as the design and the wizard name it ('SFTP'), and one line for the wizard
    fields                share-level settings, shown in the wizard and kept in the design under export['settings']
    mount_fields          settings of one client mount, kept under mount['settings']
    normalize(settings)   the share's settings checked and cleaned: ValueError for what cannot be saved
    normalize_mount(s)    the same for one mount's settings
    check(conn, hs, srv, e, say)   what the share check says about this share (say(level, text), level ok|note|warn|crit)
    check_mount(conn, srv, e, mt, ch, say)   what it says about one client mount, after the checks every mount gets
    server_params(e, srv, hs) / client_params(e, mt, srv, hs)   plain key=value strings the script reads (never a secret);
                          hs is the fleet (shares.hosts), for a driver that needs another host's address
    client_source(e, address)   what a client mounts, for the report and the mount's record ('sftp://nas/srv/x')
    server_secrets(e) / client_secrets(e, mt)   vault secret names that side needs: they come on the runner's stdin in an apply
    peer_hosts(e)         other servers the share needs (GlusterFS bricks): each runs peer_<k> I (I indexes E_*) before the server
    needs_server / needs_client   names in scriptkit.NEEDS, for "would install X" in the check
    bash                  defines server_<k> (called once on the server, whether or not the design has shares of it: with none it
                          takes its own config away), client_<k> I (one client mount, I indexes C_*), and cleanup_<k> (on a client,
                          after the units of mounts the design dropped are gone: anything else to undo, such as an iSCSI logout; often
                          just `return 0`). <k> is the key in lower case. A client unit named share_unit TARGET (.service) is
                          stopped and removed for you when its mount leaves the design.

Script conventions (shares.py SHARES_BODY_3 has the helpers; BASH below adds par, secret, share_unit, unit_file, drop_units, act,
open_port LABEL PORT/PROTO CLIENTS, indices_of KEY): E_PROTO/E_NAME/E_PATH/E_CLIENTS/E_OPTS and E_PARAM per share,
C_HOST/C_TARGET/C_PROTO/C_SOURCE/C_NAME and C_PARAM per client mount. par KEY "$blob" reads one value from a *_PARAM blob, and
secret NAME prints the path of a vault secret the run brought (empty when it did not). own_file, service_on, open_fw, need_cmd,
backup, durable, ok/doing/missing/conflict/info/skip/section are the same as NFS and SMB use. A driver writes only files and units
named for StorageForge, records what it wrote in MANAGED_FILES, and names a client unit so cleanup can find it:
    storageforge-share-<server>.<systemd-escaped target>.service, from share_unit TARGET (a host slug holds no dot, so one server's
    prefix never matches another's)
Values reach the script as single-quoted words (shlex.quote); a driver checks each against a pattern before that, as shares.py does.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .secretstore import NAME as SECRET_NAME

PARAM_KEY = re.compile(r'[a-z][a-z0-9_]{0,40}')
PARAM_VALUE = re.compile(r'[^\x00-\x1f\x7f]{0,2000}')


@dataclass
class Field:
    """One setting in the wizard. kind: text | choice | bool | int | secret (a vault secret's name) | path | hosts."""
    name: str
    kind: str
    label: str
    help: str = ''
    options: tuple = ()
    default: object = ''
    required: bool = False
    placeholder: str = ''

    def public(self) -> dict:
        return {'name': self.name, 'kind': self.kind, 'label': self.label, 'help': self.help, 'options': list(self.options),
                'default': self.default, 'required': self.required, 'placeholder': self.placeholder}


@dataclass
class Driver:
    key: str
    label: str
    help: str
    fields: list = field(default_factory=list)
    mount_fields: list = field(default_factory=list)
    needs_server: str = ''
    needs_client: str = ''
    clients_label: str = 'Who may connect'
    clients_help: str = ''
    bash: str = ''

    # the behaviour a driver overrides; these defaults keep a driver with no settings working
    def normalize(self, s: dict) -> dict:
        return clean(self.fields, s)

    def normalize_mount(self, s: dict) -> dict:
        return clean(self.mount_fields, s)

    def check(self, conn, hs, srv, e, say) -> None:
        return None

    def check_mount(self, conn, srv, e, mt, ch, say) -> None:
        return None

    def server_params(self, e: dict, srv: dict, hs: list) -> dict:
        return {}

    def client_params(self, e: dict, mt: dict, srv: dict, hs: list) -> dict:
        return {}

    def client_source(self, e: dict, address: str) -> str:
        return f'{self.key.lower()}://{address}{e["path"]}'

    def server_secrets(self, e: dict) -> list:
        return []

    def client_secrets(self, e: dict, mt: dict) -> list:
        return []

    def peer_hosts(self, e: dict) -> list:
        """Other servers this share needs (a GlusterFS replica's bricks): each runs peer_<k> I before the server runs server_<k>."""
        return []

    def public(self) -> dict:
        return {'key': self.key, 'label': self.label, 'help': self.help, 'fields': [f.public() for f in self.fields],
                'mount_fields': [f.public() for f in self.mount_fields], 'clients_label': self.clients_label, 'clients_help': self.clients_help}


DRIVERS: dict[str, Driver] = {}


def register(d: Driver) -> Driver:
    if not re.fullmatch(r'[A-Z][A-Z0-9]{1,15}', d.key) or d.key in ('NFS', 'SMB'):
        raise ValueError(f'not a share protocol key: {d.key}')
    fn = d.key.lower()
    for side in (f'server_{fn}()', f'client_{fn}()', f'cleanup_{fn}()'):
        if side not in d.bash:
            raise ValueError(f'the {d.key} driver has no {side} in its bash')
    DRIVERS[d.key] = d
    return d


def driver(proto: str) -> Driver | None:
    return DRIVERS.get(str(proto or '').upper())


def keys() -> list[str]:
    return sorted(DRIVERS)


def clean(fields: list, s: dict) -> dict:
    """Settings checked against their fields: unknown names dropped, choices and numbers held to what is offered, text to one line,
    secret names to what the vault names. Settings left at nothing are left out, so a share's hash moves only when one is set."""
    s = s or {}
    out = {}
    for f in fields:
        v = s.get(f.name, f.default)
        if f.kind == 'bool':
            if bool(v) != bool(f.default):
                out[f.name] = bool(v)
            continue
        if v in (None, ''):
            if f.required:
                raise ValueError(f'{f.label} is needed')
            continue
        if f.kind == 'int':
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise ValueError(f'{f.label} must be a whole number') from None
            lo, hi = (f.options or (0, 10 ** 9))[:2]
            if not lo <= v <= hi:
                raise ValueError(f'{f.label} must be between {lo} and {hi}')
        elif f.kind == 'choice':
            if v not in f.options:
                raise ValueError(f'{f.label} is one of {", ".join(map(str, f.options))}')
        elif f.kind == 'secret':
            v = str(v).strip()
            if not SECRET_NAME.fullmatch(v):
                raise ValueError(f'{f.label}: {v!r} is not the name of a vault secret')
        elif f.kind == 'path':
            v = str(v).strip()
            if not v.startswith('/') or '\n' in v or '"' in v or any(p in ('.', '..') for p in v.split('/')):
                raise ValueError(f'{f.label} must be an absolute path')
        else:
            v = ' '.join(str(v).split()) if f.kind == 'hosts' else str(v).strip()
            if not PARAM_VALUE.fullmatch(v) or '\n' in v:
                raise ValueError(f'{f.label} must be one line')
        if v != f.default:
            out[f.name] = v
    return out


def params_blob(params: dict) -> str:
    """key=value lines for a *_PARAM entry. A key is a word, a value one line: shlex.quote takes care of the rest."""
    lines = []
    for k, v in params.items():
        v = '' if v is None else ('1' if v is True else '0' if v is False else str(v))
        if not PARAM_KEY.fullmatch(k) or not PARAM_VALUE.fullmatch(v) or '\n' in v:
            raise ValueError(f'share parameter {k!r} is not a word with a one-line value')
        lines.append(f'{k}={v}')
    return '\n'.join(lines)


# The helpers every driver's bash may use, after shares.py's own. No apostrophes: the script is checked for words that could end a quote.
BASH = r"""
par() { awk -v k="$1" 'BEGIN { FS = "=" } $1 == k { sub(/^[^=]*=/, ""); print; exit }' <<<"$2"; }   # KEY BLOB -> its value
secret() { local d=/run/storageforge/secrets; ((EUID != 0)) && d=${SF_SECRET_DIR:-$d}; [[ -s $d/$1 ]] && echo "$d/$1"; return 0; }
share_unit() { echo "storageforge-share-$SERVER.$(systemd-escape -p "$1")"; }   # TARGET -> the name a client unit for it gets. The dot: a host slug has none, so nas. never matches nas-2.
MANAGED_FILES=()
act() { if ((APPLY)); then doing "$*"; return 0; fi; missing "would: $*"; return 1; }   # the rclone library (rclone.LIB) speaks this
open_port() { # LABEL PORT/PROTO CLIENTS -> the port open to those clients (addresses and subnets; none: any) in firewalld or ufw
  local label=$1 port=${2%/*} proto=${2#*/}
  [[ $proto == "$2" ]] && proto=tcp
  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    if firewall-cmd -q --query-port="$port/$proto" 2>/dev/null; then ok "firewalld allows $port/$proto ($label)"
    elif ((APPLY)); then doing "firewalld: allow $port/$proto ($label)"; firewall-cmd -q --permanent --add-port="$port/$proto" && firewall-cmd -q --reload
    else missing "firewalld does not allow $port/$proto ($label)"; fi
  elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep "^Status: active" >/dev/null; then
    ufw_allow "$label" "$port" "$proto" "$3"   # shares.py
  else info "no active firewalld or ufw: nothing to open for $label"; fi
}
share_dir() { [[ -d $1 ]] && ok "$1 exists" || { if ((APPLY)); then doing "mkdir -p $1"; mkdir -p -- "$1"; else missing "$1"; fi; }; }   # PATH -> the folder a share serves, made when it is not there
indices_of() { local i; for i in "${!E_PROTO[@]}"; do [[ ${E_PROTO[$i]} == "$1" ]] && echo "$i"; done; return 0; }
unit_file() { # NAME CONTENT -> a unit of StorageForge: written whole when it differs, systemd told; 0 if it changed
  local f=/etc/systemd/system/$1
  own_file "$f" "$2" || return 1
  ((APPLY)) && reload_systemd
  return 0
}
drop_units() { # PREFIX KEEP... -> stop, disable and remove units named PREFIX* that are not in KEEP (cleanup of a client)
  local prefix=$1 u keep removed=0; shift; keep=" $* "
  while IFS= read -r u; do
    [[ -n $u && $keep != *" $u "* ]] || continue
    removed=1
    if ((!APPLY)); then missing "would stop and remove $u"; continue; fi
    systemctl disable --now "$u" >/dev/null 2>&1 || true
    rm -f -- "/etc/systemd/system/$u"; doing "stopped and removed $u"
  done < <(find /etc/systemd/system -maxdepth 1 -name "$prefix*" -printf "%f\n" 2>/dev/null | sort)
  ((removed)) && ((APPLY)) && reload_systemd
  ((removed)) || ok "nothing to remove"
  return 0
}
driver_units_cleanup() { # on a client: units for mounts of this server that the design no longer has, whatever protocol made them
  local i keep=()
  compgen -G "/etc/systemd/system/storageforge-share-$SERVER.*" >/dev/null || return 0
  for i in "${!C_HOST[@]}"; do
    [[ ${C_HOST[$i]} == "$ME" && ${C_PROTO[$i]} != NFS && ${C_PROTO[$i]} != SMB ]] || continue
    keep+=("$(share_unit "${C_TARGET[$i]}").service" "$(share_unit "${C_TARGET[$i]}").mount")
  done
  section "mounts of $SERVER no longer in the design (units)"
  drop_units "storageforge-share-$SERVER." ${keep[@]+"${keep[@]}"}
}
"""


def load_all() -> None:
    """Import the driver modules, each of which registers itself. A driver whose module is missing is simply not offered."""
    import importlib
    for mod in ('share_sftp', 'share_s3', 'share_webdav', 'share_rclone', 'share_iscsi', 'share_nvme', 'share_virtiofs', 'share_nbd',
                'share_gluster'):
        try:
            importlib.import_module(f'{__package__}.{mod}')
        except ModuleNotFoundError as exc:
            if exc.name != f'{__package__}.{mod}':
                raise
