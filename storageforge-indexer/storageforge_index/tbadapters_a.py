"""Toolbox adapters for the panels, VPN and overlay servers, zero trust and identity entries of 0.5.13 (roadmap section 4.2;
docs/toolbox.md). tbadapters.py holds the framework; this module adds what these entries need, and every part only reads.

Most of these tools have a web UI of their own, so their adapter says whether the container runs, which version, and what the
loopback health check answered (ContainerTool). A few say more, from a probe written here and never taken from an entry:

    headscale     how many nodes it knows and how many are online: the counts only, from `headscale nodes list -o json-line`
                  run in its container. The node list also carries machine keys and the prefix of the pre-auth key a node used,
                  so the list itself never leaves the host
    zerotier      the controller node's address, version and whether it is online (`zerotier-cli info`), nothing about networks
    strongswan    the IKE and child SAs by name and state (`swanctl --list-sas`, the lines that name an SA, never keys or SPIs
                  beyond what that line has), with the units and version
    nebula        the unit the nebula step runs (storageforge-nebula.service) and the version
    cloudflared   the unit the cloudflare-tunnel step runs and the version
    ssh-ca        whether sshd trusts the StorageForge SSH CA: the CA key's fingerprint and how many users have principals

A probe runs in a tool's container as that tool's own account for a rootless install (runuser and podman exec), with root's Podman
for a Quadlet install, or with docker for a compose stack, whichever finds a container named sf-<tool>.
"""
from __future__ import annotations

import re

from .tbadapters import Adapter, _containers, _tile

SECTIONS = ('tb_access',)
UNITS = ('strongswan.service', 'strongswan-starter.service', 'storageforge-nebula.service', 'storageforge-cloudflared.service')
BODY = r"""
# the Toolbox adapters of tbadapters_a.py: unit states, version lines and counts only
sec tb_access
tbx() { local t=$1 u=sf-$1
  shift
  if id -u "$u" >/dev/null 2>&1 && has runuser && has podman; then
    (cd / && runuser -u "$u" -- env XDG_RUNTIME_DIR="/run/user/$(id -u "$u")" podman exec "sf-$t" "$@" 2>/dev/null) && return 0
  fi
  if has podman && podman container exists "sf-$t" 2>/dev/null; then podman exec "sf-$t" "$@" 2>/dev/null && return 0; fi
  has docker && docker inspect "sf-$t" >/dev/null 2>&1 && docker exec "sf-$t" "$@" 2>/dev/null
}
if has systemctl; then
  for u in @UNITS@; do
    systemctl cat "$u" >/dev/null 2>&1 && printf "u\t%s\t%s\t%s\n" "$u" "$(systemctl is-active "$u" 2>/dev/null)" "$(systemctl is-enabled "$u" 2>/dev/null)"
  done
fi
has nebula && printf "v\tnebula\t%s\n" "$(nebula -version 2>/dev/null | sed -n "s/^Version: *//p" | head -n 1)"
has swanctl && printf "v\tstrongswan\t%s\n" "$(swanctl --version 2>/dev/null | head -n 1)"
has cloudflared && printf "v\tcloudflared\t%s\n" "$(cloudflared --version 2>/dev/null | head -n 1)"
if has swanctl; then
  swanctl --list-sas 2>/dev/null | grep -E "^[^ ]+: #[0-9]+, |^  [^ ]+: #[0-9]+, " | head -n 200 | while IFS= read -r l; do printf "s\t%s\n" "$l"; done
fi
if hs=$(tbx headscale headscale nodes list -o json-line); then
  printf "hs\t%s\t%s\n" "$(grep -o "\"online\":true" <<<"$hs" | wc -l)" "$(grep -o "\"machine_key\"" <<<"$hs" | wc -l)"
fi
hs=
if zt=$(tbx zerotier zerotier-cli info); then printf "zt\t%s\n" "$(head -n 1 <<<"$zt")"; fi
if [[ -r /etc/ssh/storageforge_user_ca.pub ]]; then
  printf "ca\t%s\t%s\n" "$(ssh-keygen -lf /etc/ssh/storageforge_user_ca.pub 2>/dev/null | cut -d " " -f 2)" "$(ls /etc/ssh/storageforge_principals 2>/dev/null | wc -l)"
fi
""".replace('@UNITS@', ' '.join(UNITS))

SA = re.compile(r'( *)([A-Za-z0-9._-]{1,64}): #(\d+), (?:reqid \d+, )?([A-Z_]{3,20})(?:, .*)?')


def read_access(lines: list[str]) -> dict:
    """What the tb_access section printed: units, versions, strongSwan SAs, Headscale and ZeroTier counts, the SSH CA trust. A line that
    is not one of these, or a value outside its shape, is left out."""
    out: dict = {'units': {}, 'versions': {}, 'ike': [], 'child': []}
    for line in lines:
        f = line.split('\t')
        if f[0] == 'u' and len(f) == 4 and f[1] in UNITS:
            out['units'][f[1]] = {'active': f[2][:20], 'enabled': f[3][:20]}
        elif f[0] == 'v' and len(f) == 3 and f[1] in ('nebula', 'strongswan', 'cloudflared'):
            m = re.search(r'\d+\.\d+(\.\d+)?', f[2])
            if m:
                out['versions'][f[1]] = m[0]
        elif f[0] == 's' and len(f) == 2:
            m = SA.fullmatch(f[1])
            if m:
                (out['child'] if m[1] else out['ike']).append({'name': m[2], 'id': int(m[3]), 'state': m[4]})
        elif f[0] == 'hs' and len(f) == 3 and f[1].strip().isdigit() and f[2].strip().isdigit():
            out['headscale'] = {'online': int(f[1]), 'nodes': int(f[2])}
        elif f[0] == 'zt' and len(f) == 2:
            m = re.fullmatch(r'200 info ([0-9a-f]{10}) (\d+\.\d+\.\d+) (ONLINE|OFFLINE|TUNNELED)', f[1].strip())
            if m:
                out['zerotier'] = {'address': m[1], 'version': m[2], 'state': m[3]}
        elif f[0] == 'ca' and len(f) == 3 and re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', f[1]) and f[2].strip().isdigit():
            out['sshca'] = {'fingerprint': f[1], 'users': int(f[2])}
    return out


def sections_of(sections: dict) -> dict:
    return {'access_a': read_access(sections.get('tb_access', []))}


def _access(reading: dict) -> dict:
    return ((reading.get('toolbox') or {}).get('access_a')) or {}


# ── the adapters ────────────────────────────────────────────────────
class ContainerTool(Adapter):
    """A tool in a container: the one named sf-<tool> or labelled with its id, else one from its image. With sidecars, how many run."""

    def __init__(self, name: str, image: str, level: str = 'status'):
        self.name, self.image, self.level = name, image, level

    def _all(self, ctx):
        return _containers(ctx, self.name, self.image)

    def detect(self, reading, ctx):
        cs = self._all(ctx)
        if not cs:
            return None
        main = next((c for c in cs if c.get('name') == f'sf-{self.name}'), None) or next((c for c in cs if not (c.get('labels') or {}).get('storageforge.part')), cs[0])
        parts = [c for c in cs if (c.get('labels') or {}).get('storageforge.part')]
        tag = (main.get('image') or '').split('@')[0].rsplit('/', 1)[-1].rsplit(':', 1)
        return {'running': main.get('state') == 'running', 'how': main.get('how') or 'container', 'container': main.get('name'),
                'managed': (main.get('labels') or {}).get('storageforge.tool') == self.name, 'version': tag[1] if len(tag) == 2 else None,
                'parts': len(parts), 'parts_running': sum(1 for c in parts if c.get('state') == 'running')}

    def extra(self, reading: dict, found: dict) -> tuple[list[dict], bool]:
        return [], True

    def status(self, reading, ctx, found):
        code = (ctx.get('health') or {}).get(self.name)
        tiles = [_tile('Container', f'{found["container"]}, {"running" if found["running"] else "stopped"}', 'ok' if found['running'] else 'crit'),
                 _tile('Version', found.get('version') or 'unknown')]
        if found.get('parts'):
            tiles.append(_tile('Beside it', f'{found["parts_running"]} of {found["parts"]} running', 'ok' if found['parts_running'] == found['parts'] else 'crit'))
        if code is not None:
            tiles.append(_tile('Health check', f'HTTP {code}' if code else 'no answer', 'ok' if code == 200 else 'crit'))
        more, good = self.extra(reading, found)
        tiles += more
        healthy = found['running'] and code in (None, 200) and found.get('parts_running', 0) == found.get('parts', 0) and good
        return {'health': 'ok' if healthy else 'down', 'version': found.get('version'), 'tiles': tiles}

    def metrics(self, reading, ctx):
        return {'containers': len(self._all(ctx))}


class Headscale(ContainerTool):
    def extra(self, reading, found):
        hs = _access(reading).get('headscale')
        if not hs:
            return [_tile('Nodes', 'not read: the reading could not ask headscale', 'warn')], True
        return [_tile('Nodes', f'{hs["online"]} of {hs["nodes"]} online')], True

    def metrics(self, reading, ctx):
        return dict(_access(reading).get('headscale') or {}, containers=len(self._all(ctx)))


class ZeroTier(ContainerTool):
    def extra(self, reading, found):
        zt = _access(reading).get('zerotier')
        if not zt:
            return [_tile('Controller', 'not read: zerotier-cli did not answer', 'warn')], True
        return [_tile('Controller', f'node {zt["address"]}, {zt["state"].lower()}', 'ok' if zt['state'] == 'ONLINE' else 'warn')], zt['state'] != 'OFFLINE'


class UnitTool(Adapter):
    """A tool from the distribution's packages, run by a systemd unit: the first of its units that exists, and its version line."""

    def __init__(self, name: str, units: tuple, version: str, level: str = 'status'):
        self.name, self.units, self.version, self.level = name, units, version, level

    def detect(self, reading, ctx):
        acc = _access(reading)
        unit = next((u for u in self.units if u in acc.get('units', {})), None)
        if not unit and self.version not in acc.get('versions', {}):
            return None
        st = acc['units'].get(unit) or {}
        return {'running': st.get('active') == 'active', 'how': 'package', 'unit': unit, 'enabled': st.get('enabled'), 'version': acc['versions'].get(self.version)}

    def status(self, reading, ctx, found):
        tiles = [_tile(found['unit'] or 'Unit', (f'{"running" if found["running"] else "not running"}, {found.get("enabled") or "unknown"} at boot')
                       if found['unit'] else 'installed, and no unit runs it yet', 'ok' if found['running'] else 'warn' if not found['unit'] else 'crit'),
                 _tile('Version', found.get('version') or 'unknown')]
        return {'health': 'ok' if found['running'] else 'down', 'version': found.get('version'), 'tiles': tiles}


class StrongSwan(UnitTool):
    def status(self, reading, ctx, found):
        st = super().status(reading, ctx, found)
        acc = _access(reading)
        ike, child = acc.get('ike') or [], acc.get('child') or []
        up = sum(1 for s in ike if s['state'] == 'ESTABLISHED')
        st['tiles'].append(_tile('IKE SAs', f'{up} of {len(ike)} established' if ike else 'none', 'ok'))
        st['tiles'].append(_tile('Tunnels', f'{sum(1 for s in child if s["state"] == "INSTALLED")} installed' if child else 'none', 'ok'))
        return st

    def metrics(self, reading, ctx):
        acc = _access(reading)
        return {'ike': len(acc.get('ike') or []), 'established': sum(1 for s in acc.get('ike') or [] if s['state'] == 'ESTABLISHED'),
                'child': sum(1 for s in acc.get('child') or [] if s['state'] == 'INSTALLED')}


class SshCa(Adapter):
    """The SSH CA is a feature of StorageForge itself (Keys, SSH CA). Its entry installs nothing new: it runs the ssh-ca-trust step, and
    this says whether sshd trusts the CA."""
    name = 'ssh-ca'

    def detect(self, reading, ctx):
        ca = _access(reading).get('sshca')
        return {'running': True, 'how': 'sshd', **ca} if ca else None

    def status(self, reading, ctx, found):
        return {'health': 'ok', 'version': None, 'tiles': [_tile('Trusts', f'the StorageForge SSH CA, {found["fingerprint"]}'),
                                                          _tile('Users with principals', str(found['users']))]}


ADAPTERS = {a.name: a for a in (
    ContainerTool('dockge', 'louislam/dockge'), ContainerTool('headscale-ui', 'gurucomputing/headscale-ui', 'link'),
    Headscale('headscale', 'headscale/headscale'), ZeroTier('zerotier', 'zerotier/zerotier'),
    ContainerTool('openziti', 'openziti/ziti-controller'), ContainerTool('authentik', 'goauthentik/server'), ContainerTool('keycloak', 'keycloak/keycloak'),
    ContainerTool('authelia', 'authelia/authelia'), ContainerTool('lldap', 'lldap/lldap'),
    UnitTool('nebula-lighthouse', ('storageforge-nebula.service',), 'nebula'), UnitTool('cloudflared', ('storageforge-cloudflared.service',), 'cloudflared'),
    StrongSwan('strongswan', ('strongswan.service', 'strongswan-starter.service'), 'strongswan'), SshCa())}
