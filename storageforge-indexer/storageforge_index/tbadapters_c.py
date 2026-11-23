"""Adapters of the Toolbox entries for backup and recovery, secrets, provisioning, storage-facing apps and offline (roadmap section 4.2;
docs/toolbox.md). Read-only, as every adapter is (tbadapters.py): they read one more section of the infrastructure reading, tb_c,
written here and never taken from an entry, which prints version lines, unit states, the last line of each restore test, and the seal
status OpenBao gives anyone without a token (initialized, sealed, the threshold and the number of shares). None of it is a secret.

Three kinds, so an entry needs no code of its own:
  CliTool        a program run by hand or by a timer (restic, Borg, sops, age, Ansible, Puppet, OpenTofu, Packer, the Proxmox Backup
                 client): installed or not, its version. restic and Borg add the restore tests: the last verified restore of each, and an
                 action that stages a restore-test step (steps_restoretest.py), with its schedule
  UnitTool       a service of the distribution (Samba, the NFS server, apt-cacher-ng): its unit, running and enabled
  ContainerTool  a container the Toolbox installed, found by its label or its name (sf-<tool>) in what the scan and the reading saw,
                 with its loopback health check; OpenBao adds its seal status and the unseal quorum
"""
from __future__ import annotations

import json
import re

from . import tbadapters
from .tbadapters import Adapter, _containers, _tile

SECTION = 'tb_c'
# what the tb_c section prints: version lines, unit states, restore test results and the unauthenticated seal status. Never a secret.
BODY = r"""
# the Toolbox adapters of backup, secrets, provisioning, storage and offline (tbadapters_c.py): versions, unit states, results
sec tb_c
has restic && printf 'v\trestic\t%s\n' "$(restic version 2>/dev/null | head -n 1 | cut -c1-80)"
has borg && printf 'v\tborg\t%s\n' "$(borg --version 2>/dev/null | head -n 1 | cut -c1-80)"
has sops && printf 'v\tsops\t%s\n' "$(sops --disable-version-check --version 2>/dev/null | head -n 1 | cut -c1-80)"
has age && printf 'v\tage\t%s\n' "$(age --version 2>/dev/null | head -n 1 | cut -c1-80)"
has ansible && printf 'v\tansible\t%s\n' "$(ansible --version 2>/dev/null | head -n 1 | cut -c1-80)"
has puppet && printf 'v\tpuppet\t%s\n' "$(puppet --version 2>/dev/null | head -n 1 | cut -c1-80)"
has tofu && printf 'v\topentofu\t%s\n' "$(tofu version 2>/dev/null | head -n 1 | cut -c1-80)"
has packer && printf 'v\tpacker\t%s\n' "$(CHECKPOINT_DISABLE=1 packer version 2>/dev/null | head -n 1 | cut -c1-80)"
has proxmox-backup-client && printf 'v\tproxmox-backup-client\t%s\n' "$(proxmox-backup-client version 2>/dev/null | head -n 1 | cut -c1-80)"
has kopia && printf 'v\tkopia\t%s\n' "$(kopia --version 2>/dev/null | head -n 1 | cut -c1-80)"
has smbd && printf 'v\tsamba\t%s\n' "$(smbd --version 2>/dev/null | head -n 1 | cut -c1-80)"
if has systemctl; then
  for u in smbd smb nfs-server apt-cacher-ng proxmox-backup-proxy proxmox-backup; do
    systemctl cat "$u.service" >/dev/null 2>&1 && printf 'u\t%s\t%s\t%s\n' "$u" "$(systemctl is-active "$u.service" 2>/dev/null)" "$(systemctl is-enabled "$u.service" 2>/dev/null)"
  done
fi
for f in /var/lib/storageforge-tools/restore-tests/*.last; do [[ -f $f ]] && printf 'r\t%s\n' "$(head -n 1 "$f" | cut -c1-500)"; done
if has curl && has ss && ss -Hltn 2>/dev/null | grep -q '127.0.0.1:8200 '; then
  printf 's\t%s\n' "$(curl -s --max-time 3 http://127.0.0.1:8200/v1/sys/seal-status 2>/dev/null | head -c 600 | tr -d '\n\t')"
fi
"""
VERSION = re.compile(r'[A-Za-z0-9 ._:()+\[\]/,-]{0,80}')
UNIT_STATE = re.compile(r'[a-z-]{1,20}')
SEAL_KEYS = ('initialized', 'sealed', 't', 'n', 'progress', 'version', 'type', 'storage_type')


def read_c(lines: list[str]) -> dict:
    """What the reading keeps of tb_c: {versions: {tool: line}, units: {unit: {active, enabled}}, restore_tests: [...], seal: {...}}."""
    out: dict = {'versions': {}, 'units': {}, 'restore_tests': [], 'seal': None}
    for line in lines:
        f = line.split('\t')
        if f[0] == 'v' and len(f) == 3 and re.fullmatch(r'[a-z-]{2,40}', f[1]) and VERSION.fullmatch(f[2]):
            out['versions'][f[1]] = f[2].strip()
        elif f[0] == 'u' and len(f) == 4 and re.fullmatch(r'[a-z-]{2,40}', f[1]):
            out['units'][f[1]] = {'active': f[2] if UNIT_STATE.fullmatch(f[2]) else 'unknown', 'enabled': f[3] if UNIT_STATE.fullmatch(f[3]) else 'unknown'}
        elif f[0] == 'r' and len(f) == 9 and f[1].isdigit() and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', f[2]):
            out['restore_tests'].append({'at': int(f[1]), 'name': f[2], 'tool': f[3][:20], 'verdict': 'ok' if f[4] == 'ok' else 'failed',
                                         'compared': int(f[5]) if f[5].isdigit() else 0, 'differ': int(f[6]) if f[6].isdigit() else 0,
                                         'absent': int(f[7]) if f[7].isdigit() else 0, 'message': f[8][:300]})
        elif f[0] == 's' and len(f) == 2:
            try:
                got = json.loads(f[1])
            except ValueError:
                continue
            if isinstance(got, dict):
                out['seal'] = {k: got[k] for k in SEAL_KEYS if k in got and isinstance(got[k], (bool, int, str)) and len(str(got[k])) < 40}
    return out


class CliTool(Adapter):
    """A program, not a service: there when its version line is in the reading."""
    level = 'status'

    def __init__(self, name: str, key: str | None = None):
        self.name, self.key = name, key or name

    def detect(self, reading, ctx):
        v = ((reading.get('toolbox') or {}).get('c') or {}).get('versions', {}).get(self.key)
        if v is None:
            return None
        return {'running': True, 'how': 'program', 'version': v or None}

    def status(self, reading, ctx, found):
        return {'health': 'ok', 'version': found.get('version'), 'tiles': [_tile('Installed', found.get('version') or 'yes, the version line was empty')]}


class BackupTool(CliTool):
    """restic and Borg: the restore tests of this tool on this host, the last verified restore, and the action that stages one."""
    level = 'full'

    def _tests(self, reading):
        return [t for t in ((reading.get('toolbox') or {}).get('c') or {}).get('restore_tests', []) if t['tool'] == self.name]

    def status(self, reading, ctx, found):
        tiles = [_tile('Installed', found.get('version') or 'yes')]
        tests = self._tests(reading)
        for t in sorted(tests, key=lambda t: -t['at']):
            tiles.append(_tile(f'Restore test {t["name"]}', ('verified: ' if t['verdict'] == 'ok' else 'FAILED: ') + t['message'], 'ok' if t['verdict'] == 'ok' else 'crit'))
        if not tests:
            tiles.append(_tile('Restore tests', 'none yet: a backup nobody restored is not known to work. Add one below', 'warn'))
        health = 'down' if any(t['verdict'] != 'ok' for t in tests) else 'ok' if tests else 'warn'
        return {'health': health, 'version': found.get('version'), 'tiles': tiles,
                'restore_tests': [{k: t[k] for k in ('name', 'at', 'verdict', 'compared', 'differ', 'absent', 'message')} for t in tests]}

    def actions(self, reading, ctx):
        return [{'id': 'restore-test', 'label': 'Test a restore, with hashes compared', 'fields': [
            {'name': 'name', 'kind': 'label', 'label': 'Name of the test', 'required': True},
            {'name': 'repo', 'kind': 'options', 'label': 'Repository', 'required': True},
            {'name': 'secret', 'kind': 'name', 'label': 'Repository key (a vault secret)', 'required': True},
            {'name': 'source', 'kind': 'path', 'label': 'Folder that was backed up', 'required': True},
            {'name': 'scratch', 'kind': 'path', 'label': 'Scratch folder, a dataset of its own', 'required': True},
            {'name': 'sample', 'kind': 'number', 'label': 'Files to compare, at most (200)'},
            {'name': 'schedule', 'kind': 'choice', 'label': 'Run it again', 'options': ['none', 'daily', 'weekly']}]}]

    def tasks(self, action, values, host, reading):
        if action != 'restore-test':
            raise ValueError(f'{self.name} has no action {action}')
        v = {k: str(values.get(k) or '').strip() for k in ('name', 'repo', 'secret', 'source', 'scratch', 'sample', 'schedule')}
        return [{'host': host, 'type': 'restore-test', 'params': {'name': v['name'], 'tool': self.name, 'repo': v['repo'], 'secret': v['secret'],
                 'source': v['source'], 'scratch': v['scratch'], 'sample': v['sample'] or '200', 'schedule': v['schedule'] or 'none'},
                 'note': f'{self.name} restore test, from the Toolbox'}]

    def metrics(self, reading, ctx):
        tests = self._tests(reading)
        return {'restore_tests': len(tests), 'failing': sum(1 for t in tests if t['verdict'] != 'ok')}


class UnitTool(Adapter):
    """A distribution service: its unit, running and enabled at boot. The first of its units the reading has is the one shown."""
    level = 'status'

    def __init__(self, name: str, units: tuple[str, ...], version_key: str | None = None):
        self.name, self.units, self.version_key = name, units, version_key

    def detect(self, reading, ctx):
        c = (reading.get('toolbox') or {}).get('c') or {}
        unit = next((u for u in self.units if u in c.get('units', {})), None)
        if not unit:
            return None
        st = c['units'][unit]
        return {'running': st['active'] == 'active', 'how': 'package', 'unit': unit, 'enabled': st['enabled'],
                'version': c.get('versions', {}).get(self.version_key) if self.version_key else None}

    def status(self, reading, ctx, found):
        tiles = [_tile(f'{found["unit"]}.service', f'{"running" if found["running"] else "not running"}, {found["enabled"]} at boot', 'ok' if found['running'] else 'crit')]
        if found.get('version'):
            tiles.append(_tile('Version', found['version']))
        return {'health': 'ok' if found['running'] else 'down', 'version': found.get('version'), 'tiles': tiles}


class ContainerTool(Adapter):
    """A container the Toolbox installed (label storageforge.tool, or the name sf-<tool>), or one of the same image found on the host."""
    level = 'status'

    def __init__(self, name: str, image_part: str):
        self.name, self.image_part = name, image_part

    def detect(self, reading, ctx):
        cs = _containers(ctx, self.name, self.image_part)
        if not cs:
            return None
        c = cs[0]
        tag = (c.get('image') or '').split('@')[0].rsplit(':', 1)
        return {'running': c.get('state') == 'running', 'how': c.get('how') or 'container', 'container': c.get('name'),
                'managed': (c.get('labels') or {}).get('storageforge.tool') == self.name, 'version': tag[1] if len(tag) == 2 and '/' not in tag[1] else None}

    def status(self, reading, ctx, found):
        code = ctx.get('health', {}).get(self.name)
        tiles = [_tile('Container', f'{found["container"]}, {"running" if found["running"] else "stopped"}', 'ok' if found['running'] else 'crit'),
                 _tile('Version', found.get('version') or 'unknown')]
        if not found.get('managed'):
            tiles.append(_tile('Installed by', 'not StorageForge: found on the host', 'warn'))
        if code is not None:
            tiles.append(_tile('Health check', f'HTTP {code}' if code else 'no answer', 'ok' if code == 200 else 'crit'))
        return {'health': 'ok' if found['running'] and code in (None, 200) else 'down', 'version': found.get('version'), 'tiles': tiles}

    def metrics(self, reading, ctx):
        return {'containers': len(_containers(ctx, self.name, self.image_part))}


class OpenBao(ContainerTool):
    """OpenBao: the container, and the seal status anyone may read (/v1/sys/seal-status): initialized, sealed, and the quorum, t of n
    unseal shares. Unsealing and initializing are done by the holders of the shares, never here: no key passes through StorageForge."""
    level = 'status'

    def status(self, reading, ctx, found):
        st = super().status(reading, ctx, found)
        seal = ((reading.get('toolbox') or {}).get('c') or {}).get('seal')
        if not seal:
            st['tiles'].append(_tile('Seal', 'not read: the reading found nothing listening on 127.0.0.1:8200', 'warn'))
            return st
        if not seal.get('initialized'):
            st['tiles'].append(_tile('Initialized', 'no: run bao operator init with -key-shares, -key-threshold and -pgp-keys, one key per holder', 'warn'))
            st['health'] = 'warn'
        else:
            quorum = f'{seal.get("t")} of {seal.get("n")} unseal shares'
            if seal.get('sealed'):
                st['tiles'].append(_tile('Sealed', f'yes: {quorum} are needed, {seal.get("progress") or 0} given so far', 'crit'))
                st['health'] = 'down'
            else:
                st['tiles'].append(_tile('Sealed', f'no, unsealed ({quorum})'))
        if seal.get('version'):
            st['version'] = str(seal['version'])
        st['seal'] = seal
        return st


ADAPTERS = [
    BackupTool('restic'), BackupTool('borg'), CliTool('kopia'), CliTool('proxmox-backup-client'),
    UnitTool('proxmox-backup-server', ('proxmox-backup-proxy', 'proxmox-backup')),
    CliTool('sops'), CliTool('age'), CliTool('ansible'), CliTool('puppet'), CliTool('opentofu'), CliTool('packer'),
    UnitTool('samba', ('smbd', 'smb'), 'samba'), UnitTool('nfs-server', ('nfs-server',)), UnitTool('apt-cacher-ng', ('apt-cacher-ng',)),
    OpenBao('openbao', 'openbao/openbao'), ContainerTool('vaultwarden', 'vaultwarden/server'), ContainerTool('netbootxyz', 'netbootxyz/netbootxyz'),
    ContainerTool('forgejo', 'forgejo/forgejo'), ContainerTool('renovate', 'renovate/renovate'), ContainerTool('technitium', 'technitium/dns-server'),
    ContainerTool('zot', 'project-zot/zot'), ContainerTool('minio', 'minio/minio'),
    ContainerTool('garage', 'dxflrs/garage'), ContainerTool('nextcloud', 'library/nextcloud'), ContainerTool('syncthing', 'syncthing/syncthing'),
    ContainerTool('jellyfin', 'jellyfin/jellyfin'),
]
tbadapters.ADAPTERS.update({a.name: a for a in ADAPTERS})
tbadapters.BODY += BODY
tbadapters.SECTIONS += (SECTION,)
tbadapters.READERS['c'] = lambda sections: read_c(sections.get(SECTION, []))
