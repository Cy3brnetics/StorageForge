"""Shared pieces of the Bash scripts StorageForge writes (moves, share deployment): output in storage-setup.sh's
style (ok / missing / conflict / ->), and --host, which copies the script to another machine and runs it there
with sudo, forwarding your SSH agent."""

HELPERS = r"""if [[ -t 1 ]]; then G=$'\e[32m' Y=$'\e[33m' R=$'\e[31m' B=$'\e[34m' H=$'\e[1m' N0=$'\e[0m'; else G= Y= R= B= H= N0=; fi
section()  { printf '\n%s== %s ==%s\n' "$H" "$*" "$N0"; }
ok()       { printf '  %-9s %s\n' "${G}ok${N0}" "$*"; }
missing()  { printf '  %-9s %s\n' "${Y}missing${N0}" "$*"; }
conflict() { printf '  %-9s %s\n' "${R}conflict${N0}" "$*"; PROBLEMS=$((PROBLEMS + 1)); }
info()     { printf '  %-9s %s\n' "" "$*"; }
doing()    { printf '  %-9s %s\n' "${Y}->${N0}" "$*"; }
skip()     { printf '  %-9s %s\n' "${B}other${N0}" "$*"; }
PROBLEMS=0
host_slug() { local n=${1%%.*}; n=$(tr 'A-Z' 'a-z' <<<"$n" | tr -cd 'a-z0-9_-'); echo "${n:-unknown}"; }
human() { numfmt --to=iec-i --suffix=B "${1:-0}" 2>/dev/null || echo "$1 B"; }
"""

# Needs ARGS (the original arguments) and HOST set by the caller's option parsing.
REMOTE = r"""# ── remote: copy this script over, run it there with sudo, clean up (like storage-setup.sh --host) ──
if [[ -n $HOST ]]; then
  CTL=$(mktemp -d); trap 'ssh -o ControlPath="$CTL/s" -O exit "$HOST" 2>/dev/null; rm -rf "$CTL"' EXIT
  SSHO=(-o ControlMaster=auto -o ControlPath="$CTL/s" -o ControlPersist=60 -o ConnectTimeout=10)
  REST=(); skipnext=0
  for a in "${ARGS[@]}"; do if ((skipnext)); then skipnext=0; continue; fi; if [[ $a == --host ]]; then skipnext=1; continue; fi; REST+=("$a"); done
  tmp=$(ssh "${SSHO[@]}" "$HOST" 'mktemp -d /tmp/sf-move.XXXXXX')
  scp -q -o ControlPath="$CTL/s" "$0" "$HOST:$tmp/move.sh"
  # -A forwards your SSH agent, so a step on that host can pull from a third one with your key
  ssh "${SSHO[@]}" -A -t "$HOST" "cd $tmp && if [ \$(id -u) = 0 ]; then bash ./move.sh ${REST[*]:-}; else sudo --preserve-env=SSH_AUTH_SOCK bash ./move.sh ${REST[*]:-}; fi; rc=\$?; rm -rf $tmp; exit \$rc"
  exit $?
fi
"""
