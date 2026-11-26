"""The steps the 0.5.13 Toolbox adapters stage (roadmap section 4.2; tbadapters_b.py, docs/toolbox.md): each action of a panel StorageForge
builds for a tool is one of these, saved as a plan and deployed with its report first, like any step.

caddy-route    a route in Caddy to a tool on the same host, always to its loopback port, in /etc/caddy/conf.d/storageforge-<site>.caddy.
               The Caddyfile gets one import line for that folder if it has none; the whole configuration is checked with caddy validate
               before Caddy is reloaded, and what was there before is put back when the check fails.
ips-decision   a ban or its lifting, in CrowdSec (cscli decisions) or in one fail2ban jail (fail2ban-client). The Quarantine view offers
               it where a ban and StorageForge's own quarantine would disagree (tbfeeds.py).
trivy-scan     the images of the containers running on the host, or the images named, scanned for known vulnerabilities by Trivy or Grype.
               The program on the host is used when it is installed; otherwise the Trivy image of the catalog entry, pinned by digest, runs
               once per image (asking the Trivy server of the entry for its database when one answers on loopback). One line per finding
               goes into /var/lib/storageforge-tools/scans, which the next reading of the host reads back (tbadapters_b.py).

No apostrophes in the Bash below: the script text is checked for values that could end a quoted word.
"""
from __future__ import annotations

import ipaddress
import re
import shlex

from . import changes, toolbox
from .changes import F

SCANS = f'{toolbox.TOOLS_HOME}/scans'
SITE = re.compile(r'(?=.)(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*)?(:\d{1,5})?')
IMAGE_REF = re.compile(r'[a-z0-9][a-z0-9._-]*(:[0-9]{1,5})?(/[a-z0-9][a-z0-9._-]*)*(:[A-Za-z0-9._-]{1,128})?(@sha256:[0-9a-f]{64})?')
DURATION = re.compile(r'\d{1,4}[smhd]')
# One line a finding: v, id, package, installed, fixed, severity. Go templates, so the scanner writes what the host reads back.
TRIVY_TEMPLATE = ('{{- range . }}{{- range .Vulnerabilities }}v\t{{ .VulnerabilityID }}\t{{ .PkgName }}\t{{ .InstalledVersion }}\t{{ .FixedVersion }}\t{{ .Severity }}\n'
                  '{{ end }}{{ end }}')
GRYPE_TEMPLATE = ('{{- range .Matches }}v\t{{ .Vulnerability.ID }}\t{{ .Artifact.Name }}\t{{ .Artifact.Version }}\t'
                  '{{ range $i, $v := .Vulnerability.Fix.Versions }}{{ if $i }},{{ end }}{{ $v }}{{ end }}\t{{ .Vulnerability.Severity }}\n{{ end }}')

BASH = r"""
# ── Toolbox panel actions (steps_toolbox_b.py) ─
t_caddy_route() { local site=$1 port=$2 state=${3:-present} dir=/etc/caddy/conf.d main=/etc/caddy/Caddyfile file body keep= keepmain=
  command -v caddy >/dev/null || { later "caddy is not installed: install it from the Toolbox first"; return 0; }
  [[ -f $main ]] || { conflict "$main is not there: this step adds routes to the Caddy of the distribution package"; return 0; }
  file=$dir/storageforge-${site//[^A-Za-z0-9.-]/_}.caddy
  if [[ $state == absent ]]; then
    [[ -e $file ]] || { ok "there is no route for $site"; return 0; }
    act "remove the route for $site ($file) and reload Caddy" || return 0
    keep=$(mktemp) && cp -p -- "$file" "$keep"
    rm -f -- "$file"
  else
    body=$(printf "# Written by StorageForge: %s reaches a tool on this host by its loopback port\n%s {\n\treverse_proxy 127.0.0.1:%s\n}" "$site" "$site" "$port")
    if [[ -f $file && $(cat "$file") == "$body" ]] && grep -qE "^[[:space:]]*import[[:space:]]+(/etc/caddy/)?conf\.d/" "$main"; then ok "$site goes to 127.0.0.1:$port"; return 0; fi
    act "route $site to 127.0.0.1:$port in $file, check the whole configuration, and reload Caddy" || return 0
    mkdir -p -- "$dir"
    [[ -e $file ]] && { keep=$(mktemp) && cp -p -- "$file" "$keep"; }
    printf "%s\n" "$body" >"$file"
  fi
  if ! grep -qE "^[[:space:]]*import[[:space:]]+(/etc/caddy/)?conf\.d/" "$main"; then
    keepmain=$(mktemp) && cp -p -- "$main" "$keepmain"
    printf "\n# StorageForge routes, one file each\nimport /etc/caddy/conf.d/*.caddy\n" >>"$main"
    info "added an import of /etc/caddy/conf.d/*.caddy to $main"
  fi
  if ! out=$(caddy validate --adapter caddyfile --config "$main" 2>&1); then
    if [[ -n $keep ]]; then cp -p -- "$keep" "$file"; elif [[ $state != absent ]]; then rm -f -- "$file"; fi
    [[ -z $keepmain ]] || cp -p -- "$keepmain" "$main"
    rm -f -- "$keep" "$keepmain"
    conflict "caddy validate refused the configuration, so it was put back as it was: $(tail -n 2 <<<"$out" | tr "\n" " ")"; return 0
  fi
  rm -f -- "$keep" "$keepmain"
  durable "$main"
  if systemctl is-active --quiet caddy 2>/dev/null; then try systemctl reload caddy || return 0; fi
  if [[ $state == absent ]]; then ok "Caddy no longer routes $site"; else ok "Caddy routes $site to 127.0.0.1:$port"; fi
}
t_ips_decision() { local tool=$1 ip=$2 state=$3 jail=$4 duration=${5:-4h} reason=${6:-from StorageForge} have=0 scope=--ip
  [[ $ip == */* ]] && scope=--range
  case $tool in
    crowdsec)
      command -v cscli >/dev/null || { later "cscli is not installed"; return 0; }
      cscli decisions list "$scope" "$ip" -o raw 2>/dev/null | grep -q ",ban," && have=1
      if [[ $state == banned ]]; then
        ((have)) && { ok "CrowdSec bans $ip"; return 0; }
        act "ban $ip in CrowdSec for $duration ($reason)" && try cscli decisions add "$scope" "$ip" --duration "$duration" --type ban --reason "$reason" >/dev/null && ok "CrowdSec bans $ip"
      else
        ((have)) || { ok "CrowdSec has no ban on $ip"; return 0; }
        act "lift the CrowdSec ban on $ip" && try cscli decisions delete "$scope" "$ip" >/dev/null && ok "CrowdSec no longer bans $ip"
      fi ;;
    fail2ban)
      command -v fail2ban-client >/dev/null || { later "fail2ban is not installed"; return 0; }
      fail2ban-client status "$jail" >/dev/null 2>&1 || { conflict "fail2ban has no jail $jail"; return 0; }
      fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | tr " \t" "\n\n" | grep -qxF -- "$ip" && have=1
      if [[ $state == banned ]]; then
        ((have)) && { ok "the $jail jail bans $ip"; return 0; }
        act "ban $ip in the fail2ban jail $jail" && try fail2ban-client set "$jail" banip "$ip" >/dev/null && ok "the $jail jail bans $ip"
      else
        ((have)) || { ok "the $jail jail does not ban $ip"; return 0; }
        act "lift the ban on $ip in the fail2ban jail $jail" && try fail2ban-client set "$jail" unbanip "$ip" >/dev/null && ok "the $jail jail no longer bans $ip"
      fi ;;
    *) conflict "$tool is not crowdsec or fail2ban" ;;
  esac
  return 0
}
tb_scan_refs() { # the images of the running containers of Docker and root Podman, one a line, each a plain reference
  local e
  for e in docker podman; do command -v $e >/dev/null && $e ps --format "{{.Image}}" 2>/dev/null; done | grep -E "^[a-z0-9][a-z0-9._/:@-]{0,300}$" | sort -u | head -n 100
}
t_trivy_scan() { local target=$1 images=$2 scanner=${3:-trivy} verdict=$4 why=$5 image=$6 tpl=$7 dir=@SCANS@ refs ref key tmp rt= server= n=0 bad=0 rc f
  if [[ $verdict != ok ]]; then conflict "$why"; return 0; fi
  if [[ $target == running ]]; then refs=$(tb_scan_refs); else refs=$images; fi
  [[ -n $refs ]] || { ok "there is no image to scan"; return 0; }
  if ! command -v "$scanner" >/dev/null; then
    [[ $scanner == trivy && -n $image ]] || { conflict "$scanner is not installed on this host: install it from the Toolbox first"; return 0; }
    for rt in podman docker ""; do [[ -n $rt ]] && command -v $rt >/dev/null && break; done
    [[ -n $rt ]] || { conflict "neither trivy nor a container runtime to run its image is installed here"; return 0; }
    [[ $(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://127.0.0.1:4954/healthz 2>/dev/null) == 200 ]] && server=http://127.0.0.1:4954
    info "$why: the image $image${server:+, with the database of the Trivy server at $server}"
  else info "$why: $scanner $("$scanner" --version 2>/dev/null | head -n 1)"; fi
  if ((!APPLY)); then
    while IFS= read -r ref; do [[ -n $ref ]] && missing "would scan $ref with $scanner"; done <<<"$refs"
    return 0
  fi
  install -d -m 0750 -- "$dir"
  while IFS= read -r ref; do
    [[ -n $ref ]] || continue
    doing "scan $ref with $scanner"
    key=$(printf "%s" "$ref" | sha256sum | cut -c1-24)
    tmp=$(mktemp) || { conflict "could not make a temporary file"; return 0; }
    if [[ $scanner == grype ]]; then
      printf "%s" "$tpl" >"$tmp.tpl"
      grype -q -o template -t "$tmp.tpl" "registry:$ref" >"$tmp" 2>/dev/null; rc=$?; rm -f -- "$tmp.tpl"
    elif command -v trivy >/dev/null; then
      trivy image --quiet --image-src remote --scanners vuln --format template --template "$tpl" "$ref" >"$tmp" 2>/dev/null; rc=$?
    else
      "$rt" run --rm --network host -v sf-trivy-cache:/root/.cache/trivy "$image" image --quiet --image-src remote --scanners vuln ${server:+--server "$server"} \
        --format template --template "$tpl" "$ref" >"$tmp" 2>/dev/null; rc=$?
    fi
    if ((rc == 0)); then
      { printf "i\t%s\t%s\t%s\n" "$ref" "$(date +%s)" "$scanner"; grep -E "^v	" "$tmp" | head -n 5000; } >"$dir/$scanner-$key.tsv"
      n=$((n + 1)); ok "$ref: $(grep -c "^v	" "$tmp") findings"
    else bad=$((bad + 1)); info "could not scan $ref: an image only on this host, or a registry that wants a sign-in, cannot be scanned this way"; fi
    rm -f -- "$tmp"
  done <<<"$refs"
  # a report of an image that no longer runs would keep the CVE alert and the Fixable tile up for good
  if [[ $target == running ]]; then
    for f in "$dir/$scanner"-*.tsv; do
      [[ -f $f ]] || continue
      ref=$(head -n 1 "$f" | cut -f 2)
      printf "%s\n" "$refs" | grep -qxF -- "$ref" || rm -f -- "$f"
    done
  fi
  ((bad == 0)) || [[ $n -gt 0 ]] || { conflict "no image could be scanned"; return 0; }
  ok "$n image(s) scanned; the next reading of this host brings the findings in"
}
""".replace('@SCANS@', SCANS)


def _check_route(conn, c, h, p, say):
    if not SITE.fullmatch(p.get('site') or '') or len(p.get('site') or '') > 253:
        say('crit', 'the site is a host name, optionally with :port, such as grafana.lab.example or grafana.lab.example:8443')
    try:
        port = int(p.get('port') or 0)
    except ValueError:
        port = 0
    if not 0 < port < 65536:
        say('crit', 'the port is the loopback port of the tool on this host')
    say('note', 'Caddy reaches the tool on 127.0.0.1 only; the whole configuration is checked with caddy validate before Caddy is reloaded')


def _check_decision(conn, c, h, p, say):
    try:
        net = ipaddress.ip_network(str(p.get('ip') or ''), strict=False)
    except ValueError:
        say('crit', 'the address is one IP address or a network')
        return
    if p.get('tool') == 'fail2ban' and not p.get('jail'):
        say('crit', 'a fail2ban ban is in one jail: name it')
    if p.get('tool') == 'crowdsec' and p.get('duration') and not DURATION.fullmatch(p['duration']):
        say('crit', 'the duration is a number and s, m, h or d, such as 4h')
    if p.get('state') == 'banned':
        from . import security
        try:
            security.clean_target(conn, h['name'], str(net))
        except ValueError as exc:
            say('crit', str(exc))
            return
        say('warn', f'{net} cannot reach {h["name"]} while the ban holds')
    else:
        say('note', f'{p.get("tool")} lets {net} in again; a ban in another tool or in the StorageForge quarantine still holds')


def _scanner_words(conn, t) -> list[str]:
    """verdict, why, the pinned Trivy image of the catalog (when its entry is trusted), and the template the scanner writes with."""
    p = t['params']
    tpl = GRYPE_TEMPLATE if p.get('scanner') == 'grype' else TRIVY_TEMPLATE
    row = toolbox.find(conn, 'trivy')
    image, why = '', 'Trivy from the Toolbox'
    if row and row.get('entry') and row['trust'] in toolbox.TRUSTED:
        image = next((m['image'] for m in row['entry']['methods'] if m['kind'] in ('container', 'quadlet')), '')
        why = f'Trivy entry revision {row["entry"]["revision"]}, {row["trust_why"]}'
    for ref in (p.get('images') or '').split():
        if not IMAGE_REF.fullmatch(ref):
            return ['refused', f'{ref[:80]} is not an image reference', '', tpl]
    return ['ok', why, image, tpl]


def _check_scan(conn, c, h, p, say):
    refs = (p.get('images') or '').split()
    if p.get('target') == 'listed' and not refs:
        say('crit', 'name the images to scan, one a line')
    for ref in refs:
        if not IMAGE_REF.fullmatch(ref):
            say('crit', f'{ref[:80]} is not an image reference')
    say('note', 'each image is fetched from its registry to be scanned; one only on this host, or behind a sign-in, is not scanned this way')
    say('note', f'the findings go to {SCANS} on the host and come back with its next reading; nothing is changed in the images')


def _ansible(fn: str, args: tuple, extra=None):
    def render(t, conn=None):
        q = shlex.quote
        p = t['params']
        words = [str(p.get(a) or '') for a in args] + ((extra(conn, t) if conn is not None else ['refused', 'written without the index', '', '']) if extra else [])
        head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { :; }; doing() { :; }\n'
                'act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; later() { conflict "$*"; }; durable() { sync; }\n')
        return {'name': changes.title(t), 'ansible.builtin.shell': {'cmd': head + BASH + f'\n{fn} ' + ' '.join(q(w) for w in words) + '\n', 'executable': '/bin/bash'},
                'register': 'sf_out', 'changed_when': "'changed' in sf_out.stdout"}
    return render


ROUTE_ARGS = ('site', 'port', 'state')
DECISION_ARGS = ('tool', 'ip', 'state', 'jail', 'duration', 'reason')
SCAN_ARGS = ('target', 'images', 'scanner')

changes.register('caddy-route', {'group': 'Toolbox', 'label': 'Caddy route to a tool on this host', 'fields': [
    F('site', 'name', 'Site', required=True, placeholder='grafana.lab.example'), F('port', 'number', 'Loopback port of the tool', required=True, placeholder='3000'),
    F('state', 'choice', 'Add or remove', options=['present', 'absent'], default='present')],
    'help': 'One file in /etc/caddy/conf.d per route, always to 127.0.0.1. The whole configuration is checked before Caddy is reloaded, and put back if the check fails.'},
    ROUTE_ARGS, lambda p: f'Caddy: {p["site"]} {"removed" if p.get("state") == "absent" else "to 127.0.0.1:" + str(p.get("port"))}', _check_route,
    _ansible('t_caddy_route', ROUTE_ARGS))

changes.register('ips-decision', {'group': 'Toolbox', 'label': 'Ban or lift a ban (CrowdSec, fail2ban)', 'fields': [
    F('tool', 'choice', 'In', options=['crowdsec', 'fail2ban'], required=True), F('ip', 'cidr', 'Address or network', required=True, placeholder='203.0.113.7'),
    F('state', 'choice', 'Ban or lift', options=['banned', 'lifted'], required=True), F('jail', 'name', 'fail2ban jail', placeholder='sshd'),
    F('duration', 'word', 'CrowdSec ban for', placeholder='4h'), F('reason', 'text', 'Reason', placeholder='from StorageForge')],
    'help': 'A decision of CrowdSec or a ban in one fail2ban jail. The StorageForge quarantine is apart from both: lifting one leaves the others.'},
    DECISION_ARGS, lambda p: f'{p["tool"]}: {"ban" if p.get("state") == "banned" else "lift the ban on"} {p["ip"]}', _check_decision,
    _ansible('t_ips_decision', DECISION_ARGS))

changes.register('trivy-scan', {'group': 'Toolbox', 'label': 'Scan images for known vulnerabilities', 'fields': [
    F('target', 'choice', 'Images', options=['running', 'listed'], default='running'), F('images', 'lines', 'Images to scan, one a line', placeholder='docker.io/library/nginx:1.27'),
    F('scanner', 'choice', 'Scanner', options=['trivy', 'grype'], default='trivy')],
    'help': 'The images of the running containers, or the ones named, fetched from their registry and scanned. The findings come back with the next reading of the host.'},
    SCAN_ARGS, lambda p: f'Scan {"the running images" if p.get("target") != "listed" else "the images named"} with {p.get("scanner") or "trivy"}', _check_scan,
    _ansible('t_trivy_scan', SCAN_ARGS, _scanner_words), args_of=_scanner_words)
changes.EXTRA_BASH.append(BASH)
