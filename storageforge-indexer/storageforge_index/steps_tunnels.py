"""The cloudflare-tunnel and pangolin-site plan steps: run a tunnel with its token or secret from the vault (roadmap section 2,
"Cloudflare Tunnel" and "Pangolin"). Neither is lab-tested against the real service: Cloudflare needs an account, and the lab has
no Pangolin server yet.

A tunnel makes a service public (exposure.py says so in the security view), and the token that starts it is all anyone needs to
run that tunnel from another machine. What both programs' own instructions do with it is put it on a command line:
`cloudflared service install <token>` writes it into the unit's ExecStart, and Newt's example unit has `--secret <secret>`. A
command line is readable by every account on the host. So here:

    the vault           holds the token (`vault secret-add NAME`), and it is in no plan, script, playbook or log
    vault send-secret   writes it to /run/storageforge/secrets/NAME on the host, over ssh's stdin
    the step            moves it into a file only root reads and starts the program with the file's name, never its content

    cloudflared         `tunnel run --token-file FILE` (in cloudflared since April 2025). An older cloudflared is refused: it could
                        only take the token as an argument or in its environment
    newt                its JSON configuration file, named by CONFIG_FILE: {"id", "secret", "endpoint"}. The site id and the
                        endpoint are not secret and are in the plan; the secret is spliced in on the host from the file

Unlike a Tailscale auth key, the token is needed at every start, so it stays on the host, in a file of mode 600 owned by root.
That is where the program's own credentials would be too. Neither step installs the program: each has a package source of its own
to add, and that is the operator's choice to make. Each step makes a unit of its own (`storageforge-cloudflared`,
`storageforge-newt`) and leaves a unit the program's installer made alone, saying so when that one has the token on its command line.
"""
from __future__ import annotations

import re
import shlex

from . import changes
from .changes import F
from .scriptkit import RELOAD_SYSTEMD
from .secretstore import NAME, SECRET_DIR, secret_ok

SITE_ID = re.compile(r'[A-Za-z0-9_-]{4,64}')
ENDPOINT = re.compile(r'https://[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?')
CF_ARGS = ('secret', 'state')
NEWT_ARGS = ('secret', 'site_id', 'endpoint', 'state')

# No apostrophes: the script text is checked for values that could end a quoted word.
BASH = r"""
# ── tunnels started from a token the vault holds ────────────────────
tun_systemd() { command -v systemctl >/dev/null && [[ -d ${SF_SYSTEMD_RUN:-/run/systemd/system} ]]; }
# Where the secret of a plan is: the folder sf_secrets_in and vault send-secret write. Root reads that one whatever SF_SECRET_DIR says, as they do
tun_secret_file() { local d=/run/storageforge/secrets; ((EUID != 0)) && d=${SF_SECRET_DIR:-$d}; echo "$d/$1"; }
tun_secret_missing() { # $1 the file, $2 the secret name, $3 what it is
  if ((APPLY)); then conflict "no $3 at $1: storageforge-index vault send-secret $2 --host $(uname -n), then run this again"
  else missing "it needs the $3 at $1: storageforge-index vault send-secret $2 --host $(uname -n)"; fi
}
tun_secret_take() { # the one line of $1 into $2, mode 600, without it passing through any command line
  local from=$1 to=$2
  mkdir -p "${to%/*}" && chmod 0700 "${to%/*}" || return 1
  (($(grep -c "" "$from") == 1)) || return 2                 # one line, and all of it: two lines are not joined into something that looks like a token
  ( umask 077; tr -d "\r\n" <"$from" >"$to.new" ) || { rm -f "$to.new"; return 1; }
  if ! grep -qxE "[A-Za-z0-9_=+/.-]{8,4096}" "$to.new"; then rm -f "$to.new"; return 2; fi
  chmod 0600 "$to.new"; mv -f "$to.new" "$to"
}
tun_unit_stop() { local unit=$1
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
  rm -f "${SF_UNIT_DIR:-/etc/systemd/system}/$unit"; reload_systemd || true      # stopped and removed all the same: reload_systemd has said what it left undone
}
tun_unit_start() { # $1 unit name, $2 its text, $3 restart when it already runs. 2: reload_systemd refused the reload and has said why
  local unit=$1 file=${SF_UNIT_DIR:-/etc/systemd/system}/$1 i p=${PROBLEMS:-0}
  if [[ ! -e $file || $(cat "$file") != "$2" ]]; then printf "%s\n" "$2" >"$file.new" && chmod 0644 "$file.new" && mv -f "$file.new" "$file" || return 1; fi
  reload_systemd || { ((${PROBLEMS:-0} > p)) && return 2; return 1; }      # 1 when the reload itself failed, which reload_systemd does not report
  systemctl enable "$unit" >/dev/null 2>&1 || true
  if [[ -n ${3:-} ]]; then systemctl restart "$unit" >/dev/null 2>&1 || return 1; else systemctl start "$unit" >/dev/null 2>&1 || return 1; fi
  for i in 1 2 3 4 5 6; do sleep "${SF_TUNNEL_WAIT:-1}"; systemctl is-active --quiet "$unit" || return 1; done      # one that starts and falls over is not running
}

t_cloudflare_tunnel() { local secret=$1 state=${2:-present} f tok bin unit=storageforge-cloudflared.service changed=
  f=$(tun_secret_file "$secret"); tok=${SF_CLOUDFLARED_DIR:-/etc/cloudflared}/storageforge-token
  if [[ $state == absent ]]; then
    if [[ ! -e ${SF_UNIT_DIR:-/etc/systemd/system}/$unit && ! -e $tok ]]; then ok "no Cloudflare Tunnel started by StorageForge is here"; return 0; fi
    act "stop $unit and remove it and its token file (cloudflared stays installed, and the tunnel stays defined at Cloudflare)" || return 0
    rm -f "$tok"; tun_unit_stop "$unit"      # the token first: where conflict exits (Ansible), a reload refused in tun_unit_stop would leave it
    ok "the tunnel no longer runs from here: what it published is no longer public through this host"
    return 0
  fi
  bin=$(command -v cloudflared) || { conflict "cloudflared is not installed: install it from the package source Cloudflare gives (pkg.cloudflare.com), which this step does not add"; return 0; }
  tun_systemd || { conflict "this step runs cloudflared as a systemd unit, and systemd does not run this host"; return 0; }
  if ! "$bin" tunnel run --help 2>&1 | grep -q -- "--token-file"; then
    conflict "this cloudflared ($("$bin" --version 2>/dev/null | head -n 1)) cannot read its token from a file (--token-file, since April 2025): with it the token would be on a command line, so nothing is done. Update cloudflared"
    return 0
  fi
  if systemctl cat cloudflared.service 2>/dev/null | grep -qE -- "--token[ =]"; then
    info "cloudflared.service, made by cloudflared service install, has the token on its command line, where every account on this host can read it: once this unit runs, remove that one with cloudflared service uninstall"
  fi
  if [[ ! -r $f ]]; then
    if [[ -s $tok ]] && systemctl is-active --quiet "$unit"; then ok "the tunnel runs as $unit, with its token read from $tok"; return 0; fi
    [[ -s $tok ]] || { tun_secret_missing "$f" "$secret" "tunnel token"; return 0; }
  fi
  act "keep the tunnel token in $tok, which only root reads, and run cloudflared from it as $unit. What the tunnel publishes becomes public" || return 0
  if [[ -r $f ]]; then
    tun_secret_take "$f" "$tok" || { conflict "the file at $f does not hold a tunnel token: one line of letters and digits"; return 0; }
    changed=1
  fi
  tun_unit_start "$unit" "[Unit]
Description=Cloudflare Tunnel, started by StorageForge with its token read from a file
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$bin --no-autoupdate tunnel run --token-file $tok
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target" "$changed" || {
    (($? == 2)) || conflict "cloudflared did not stay running: journalctl -u $unit says why (a token Cloudflare does not know is the usual reason)"; return 0
  }
  rm -f -- "$f"
  ok "the tunnel runs as $unit. Its token is in $tok and on no command line; the copy in $f is removed"
}

t_pangolin_site() { local secret=$1 id=$2 endpoint=$3 state=${4:-present} f conf bin unit=storageforge-newt.service changed= rc
  f=$(tun_secret_file "$secret"); conf=${SF_NEWT_DIR:-/etc/newt}/storageforge.json
  if [[ $state == absent ]]; then
    if [[ ! -e ${SF_UNIT_DIR:-/etc/systemd/system}/$unit && ! -e $conf ]]; then ok "no Pangolin site started by StorageForge is here"; return 0; fi
    act "stop $unit and remove it and its configuration (Newt stays installed, and the site stays defined at the Pangolin server)" || return 0
    rm -f "$conf"; tun_unit_stop "$unit"      # the secret first, as with the tunnel token
    ok "Newt no longer runs from here: what the site published is no longer reached through this host"
    return 0
  fi
  bin=$(command -v newt) || { conflict "newt is not installed: install it as the Pangolin server shows for a new site, which this step does not do"; return 0; }
  tun_systemd || { conflict "this step runs Newt as a systemd unit, and systemd does not run this host"; return 0; }
  if systemctl cat newt.service 2>/dev/null | grep -qE -- "--secret[ =]"; then
    info "newt.service has the site secret on its command line, where every account on this host can read it: once this unit runs, stop and remove that one"
  fi
  if [[ ! -r $f ]]; then
    if [[ -s $conf ]] && grep -qF "\"$id\"" "$conf" && grep -qF "\"$endpoint\"" "$conf" && systemctl is-active --quiet "$unit"; then
      ok "Newt runs as $unit for site $id at $endpoint, with its secret read from $conf"; return 0
    fi
    tun_secret_missing "$f" "$secret" "site secret"; return 0
  fi
  act "write site $id of $endpoint and its secret to $conf, which only root reads, and run Newt from it as $unit. What the site publishes at the Pangolin server reaches this host" || return 0
  rc=0; tun_secret_take "$f" "$conf.secret" || rc=$?
  if ((rc)); then rm -f "$conf.secret"; conflict "the file at $f does not hold a site secret: one line of letters and digits"; return 0; fi
  # the secret goes from one file into the other through cat: it is an argument of nothing
  ( umask 077; { printf "{\"id\":\"%s\",\"secret\":\"" "$id"; cat "$conf.secret"; printf "\",\"endpoint\":\"%s\"}\n" "$endpoint"; } >"$conf.new" ) || { rm -f "$conf.new" "$conf.secret"; conflict "could not write $conf"; return 0; }
  rm -f "$conf.secret"; chmod 0600 "$conf.new"; mv -f "$conf.new" "$conf"; changed=1
  tun_unit_start "$unit" "[Unit]
Description=Pangolin site (Newt), started by StorageForge with its secret read from a file
After=network-online.target
Wants=network-online.target

[Service]
Environment=CONFIG_FILE=$conf
ExecStart=$bin
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target" "$changed" || {
    (($? == 2)) || conflict "Newt did not stay running: journalctl -u $unit says why (a wrong secret, an endpoint it cannot reach, or a Newt too old to read CONFIG_FILE)"; return 0
  }
  rm -f -- "$f"
  ok "Newt runs as $unit for site $id. Its secret is in $conf and on no command line; the copy in $f is removed"
}
"""


def _secret_notes(h, p, say, what: str):
    say('note', f'the {what} is read on {h["name"]} from {SECRET_DIR}/{p["secret"]}: before running, storageforge-index vault send-secret {p["secret"]} --host {h["name"]}. '
                'It is moved into a file only root reads and is on no command line')
    say('warn', 'a tunnel makes what it publishes public, with no port open on this host or the router: the firewall does not stop it. Not lab-tested against the real service')


def _check_cloudflared(conn, c, h, p, say):
    if not secret_ok(p, say):
        return
    if p['state'] == 'absent':
        say('note', 'stops the tunnel StorageForge started here and removes its token file. The tunnel stays defined at Cloudflare, and cloudflared stays installed')
        return
    _secret_notes(h, p, say, 'tunnel token')
    say('note', 'needs cloudflared installed already, new enough to take --token-file (April 2025). An older one is refused, because it could only take the token as an argument')


def _check_newt(conn, c, h, p, say):
    if not secret_ok(p, say):
        return
    if p['state'] == 'absent':
        say('note', 'stops the Newt StorageForge started here and removes its configuration. The site stays defined at the Pangolin server')
        return
    if not SITE_ID.fullmatch(p['site_id']):
        say('crit', 'the site id is the one the Pangolin server shows for the site: letters and digits')
    if not ENDPOINT.fullmatch(p['endpoint']):
        say('crit', 'the endpoint is the address of the Pangolin server, such as https://pangolin.example.com')
    _secret_notes(h, p, say, 'site secret')
    say('note', 'needs newt installed already. The site id and the endpoint are not secret and are in this plan; the secret is not')


HEAD = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { echo "info: $*"; }\n'
        'act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }\n' + RELOAD_SYSTEMD)


def _ansible(fn: str, args: tuple):
    def render(t):
        q = shlex.quote
        call = ' '.join(q(w) for w in changes.words_of(t['params'], args))
        return changes.shell_task(t, HEAD + BASH + f'\n{fn} {call}\n')
    return render


STATE = F('state', 'choice', 'Run or remove', options=['present', 'absent'], default='present')
changes.register('cloudflare-tunnel', {'group': 'Network', 'label': 'Run a Cloudflare Tunnel (not lab-tested)', 'fields': [
    F('secret', 'name', 'Tunnel token (a vault secret)', required=True, placeholder='cloudflare-tunnel'), STATE],
    'help': 'Runs cloudflared with a tunnel token the vault holds. The token reaches the host with vault send-secret and is read from a file only root '
            'reads (--token-file), so it is on no command line. cloudflared has to be installed already. What the tunnel publishes becomes public.'},
    CF_ARGS, lambda p: 'Stop the Cloudflare Tunnel' if p['state'] == 'absent' else 'Run a Cloudflare Tunnel from a token in the vault', _check_cloudflared,
    _ansible('t_cloudflare_tunnel', CF_ARGS))
changes.register('pangolin-site', {'group': 'Network', 'label': 'Join a Pangolin server as a site (Newt, not lab-tested)', 'fields': [
    F('secret', 'name', 'Site secret (a vault secret)', required=True, placeholder='pangolin-site'),
    F('site_id', 'text', 'Site id', placeholder='2ix2t8xk22ubpfy'), F('endpoint', 'text', 'Pangolin server', placeholder='https://pangolin.example.com'), STATE],
    'help': 'Runs Newt with a site secret the vault holds. The secret reaches the host with vault send-secret and is written to a configuration file only '
            'root reads, so it is on no command line. Newt has to be installed already. What the site publishes at the Pangolin server reaches this host.'},
    NEWT_ARGS, lambda p: 'Leave the Pangolin server' if p['state'] == 'absent' else f'Join {p.get("endpoint") or "a Pangolin server"} as site {p.get("site_id") or ""}'.rstrip(), _check_newt,
    _ansible('t_pangolin_site', NEWT_ARGS))
changes.EXTRA_BASH.append(BASH)
