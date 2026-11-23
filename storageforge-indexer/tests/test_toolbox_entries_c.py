"""The Toolbox entries of 0.5.13 part C (docs/toolbox.md): backup and recovery, secrets, provisioning and platform, storage-facing apps
and offline. Each packaged entry passes the schema with the install method it says, its image pinned by digest or its binary by the
publisher's SHA-256, its secrets declared and reaching the container as files; what the engine added for them (a container's command,
small files it reads, secrets by _FILE paths) is checked here and run through Bash; and each adapter reads what the infrastructure
reading of a host says, read-only, with its actions staged as plan steps."""
import base64
import shutil
import subprocess
import unittest

try:
    import test_toolbox as tt
    import test_toolbox_steps as tts
except ImportError:      # run as tests.test_x from the project folder
    from tests import test_toolbox as tt, test_toolbox_steps as tts
from storageforge_index import changes, tbadapters, toolbox

Base = tt.Base


def steps_without_their_tests():
    """The harness of test_toolbox_steps (stand-in podman, systemctl and package managers), without running its tests again here."""
    cls = type('StepsHarness', (tts.Steps,), {n: None for n in dir(tts.Steps) if n.startswith('test_')})
    return cls


Steps = steps_without_their_tests()

GROUP_C = {
    'backup': {'restic', 'borg', 'kopia', 'proxmox-backup-client', 'proxmox-backup-server'},
    'secrets': {'openbao', 'sops', 'age', 'vaultwarden'},
    'provisioning': {'packer', 'netbootxyz', 'forgejo', 'renovate', 'technitium', 'ansible', 'puppet', 'opentofu'},
    'storage': {'samba', 'nfs-server', 'minio', 'garage', 'nextcloud', 'syncthing', 'jellyfin'},
    'offline': {'zot', 'apt-cacher-ng'},
}
ENTRY = """format: 1
id: argtool
revision: 1
name: Argtool
category: storage
summary: A container with a command, a file and a secret.
install:
  methods:
    - kind: container
      image: docker.io/example/argtool:1.0@sha256:2222222222222222222222222222222222222222222222222222222222222222
      ports: ["3900:3900/tcp"]
      args: [server, --config, /etc/argtool.toml]
      env: {ARGTOOL_ADMIN_TOKEN_FILE: /run/secrets/argtool/admin_token}
      files:
        argtool.toml:
          path: /etc/argtool.toml
          text: |
            data_dir = "/var/lib/argtool"
            admin_token_file = "/run/secrets/argtool/admin_token"
requires:
  ports: [3900/tcp]
secrets:
  - {name: admin_token, kind: token}
"""


def entries_of(category: str) -> dict:
    out = {}
    for f in toolbox.CATALOG_DIR.glob('*.yaml'):
        e, problems = toolbox.load_entry(f.read_text())
        if e and e['category'] == category and e['id'] in GROUP_C.get(category, ()):
            out[e['id']] = (e, problems)
    return out


class EngineAdditions(Base):
    def test_a_command_files_and_secret_paths(self):
        e, problems = toolbox.load_entry(ENTRY)
        self.assertEqual(problems, [])
        m = e['methods'][0]
        self.assertEqual(m['args'], ['server', '--config', '/etc/argtool.toml'])
        r = toolbox.resolve(e, m, {}, '', '')
        text = toolbox.quadlet_text(e, m, r, True)
        self.assertIn('Exec=server --config /etc/argtool.toml', text)
        self.assertIn(f'Volume={toolbox.DATA_ROOT}/argtool/files/argtool.toml:/etc/argtool.toml:ro,Z', text)
        self.assertIn('Environment=ARGTOOL_ADMIN_TOKEN_FILE=/run/secrets/argtool/admin_token', text)
        self.assertIn(f'Volume={toolbox.DATA_ROOT}/argtool/secrets:/run/secrets/argtool:ro,Z', text)
        compose = toolbox.compose_text(e, m, r)
        self.assertIn('command:\n    - server', compose)
        folder, files = toolbox.file_words(e, m)
        self.assertEqual(folder, f'{toolbox.DATA_ROOT}/argtool/files')
        name, b64 = files.split('=', 1)
        self.assertEqual(name, 'argtool.toml')
        self.assertIn('data_dir', base64.b64decode(b64).decode())

    def test_what_the_additions_refuse(self):
        def problems(old, new):
            text = ENTRY.replace(old, new)
            self.assertNotEqual(text, ENTRY, old)
            return ' '.join(toolbox.load_entry(text)[1])
        self.assertIn('one word', problems('args: [server,', 'args: ["server; rm -rf /",'))
        self.assertIn('one word', problems('args: [server,', 'args: ["%h",'))
        self.assertIn('not one of the secrets the entry declares', problems('/run/secrets/argtool/admin_token}', '/run/secrets/argtool/other}'))
        self.assertIn('looks like a secret', problems('ARGTOOL_ADMIN_TOKEN_FILE: /run/secrets/argtool/admin_token', 'ARGTOOL_ADMIN_TOKEN: abc'))
        self.assertIn('looks like it holds a secret', problems('data_dir = "/var/lib/argtool"', 'rpc_secret = "0123456789abcdef0123456789abcdef"'))
        self.assertIn('absolute path in the container', problems('path: /etc/argtool.toml', 'path: ../etc/argtool.toml'))


class EngineFilesRun(Steps):
    def setUp(self):
        super().setUp()
        if shutil.which('base64'):
            (self.real / 'base64').symlink_to(shutil.which('base64'))

    def test_the_files_are_written_once_and_a_change_restarts_the_unit(self):
        toolbox.save_custom(self.conn, ENTRY, None, 'test')
        toolbox.stage(self.conn, 'box', 'argtool', 'root', accept_unsigned=True)
        out = self.install(False, 'argtool')
        self.assertIn('would: write', out)
        conf = self.root / 'srv/toolbox/argtool/files/argtool.toml'
        self.assertFalse(conf.exists(), 'a report writes nothing')
        out = self.install(True, 'argtool')
        self.assertIn('data_dir = "/var/lib/argtool"', conf.read_text())
        self.assertIn('ok: argtool.service is running', out)
        (self.fake / 'log').unlink()
        out = self.install(True, 'argtool')
        self.assertIn('is the file this entry gives', out)
        self.assertNotIn('restart', self.log())
        conf.write_text('changed by hand\n')
        out = self.install(True, 'argtool')
        self.assertIn('data_dir', conf.read_text())
        self.assertIn('restart argtool.service', self.log(), 'a file put back restarts the container that reads it')


class Entries(Base):
    def test_every_entry_of_part_c_passes_and_is_pinned(self):
        for category, ids in GROUP_C.items():
            got = entries_of(category)
            self.assertEqual(set(got), ids, category)
            for tid, (e, problems) in got.items():
                self.assertEqual(problems, [], tid)
                self.assertTrue(e['gui']['adapter'] or e['gui']['api'] or e['gui']['level'] == 'link', f'{tid} has an adapter or a link')
                for m in e['methods']:
                    if m['kind'] in ('container', 'quadlet', 'compose'):
                        self.assertRegex(m['image'], r'@sha256:[0-9a-f]{64}$', tid)
                    if m['kind'] == 'binary':
                        for f in m['files'].values():
                            self.assertRegex(f['sha256'], r'^[0-9a-f]{64}$')
                    for k, v in (m.get('env') or {}).items():
                        self.assertNotRegex(k, r'(?i)pass|secret|token' if not k.endswith('_FILE') else r'^$', tid)

    def test_the_manifest_lists_every_packaged_entry(self):
        import json
        texts = {f.stem: f.read_text() for f in toolbox.CATALOG_DIR.glob('*.yaml')}
        man = json.loads((toolbox.CATALOG_DIR / 'catalog.json').read_text())
        self.assertEqual(man['entries'], {k: toolbox.sha256(v) for k, v in texts.items()},
                         'an entry changed: python -m storageforge_index.toolbox manifest SERIAL writes the manifest again')

    def test_each_adapter_named_exists(self):
        for category in GROUP_C:
            for tid, (e, _) in entries_of(category).items():
                if e['gui']['adapter']:
                    self.assertIn(e['gui']['adapter'], tbadapters.ADAPTERS, tid)


def reading_with(lines: list[str], containers=()) -> tuple[dict, dict]:
    """A reading whose tb_c section printed these lines, read the way inframeasure.parse reads it, and the adapter context."""
    from storageforge_index import tbadapters_c
    return {'toolbox': {'c': tbadapters_c.read_c(lines)}}, {'containers': list(containers), 'health': {}, 'now': 0}


class Secrets(Base):
    def test_openbao_runs_its_server_from_the_file_it_is_given(self):
        e = toolbox.find(self.conn, 'openbao')['entry']
        m = e['methods'][0]
        self.assertEqual(m['kind'], 'container')
        text = toolbox.quadlet_text(e, m, toolbox.resolve(e, m, {}, '', ''), True)
        self.assertIn('Exec=server', text)
        self.assertIn('PublishPort=127.0.0.1:8200:8200/tcp', text)
        self.assertIn('storage "file"', m['files']['storageforge.hcl']['text'])
        self.assertNotIn('IPC_LOCK', text)

    def test_openbao_shows_its_seal_and_quorum_and_never_a_key(self):
        a = tbadapters.ADAPTERS['openbao']
        c = {'name': 'sf-openbao', 'image': 'quay.io/openbao/openbao:2.7.3@sha256:' + 'b' * 64, 'state': 'running', 'labels': {'storageforge.tool': 'openbao'}}
        reading, ctx = reading_with(['s\t{"type":"shamir","initialized":true,"sealed":true,"t":3,"n":5,"progress":1,"nonce":"x","version":"2.7.3","root_token":"never"}'], [c])
        found = a.detect(reading, ctx)
        st = a.status(reading, ctx, found)
        self.assertEqual(st['health'], 'down')
        self.assertIn('3 of 5 unseal shares are needed, 1 given so far', ' '.join(t['value'] for t in st['tiles']))
        self.assertNotIn('root_token', st['seal'], 'only the keys of the seal status are kept')
        reading, ctx = reading_with(['s\t{"initialized":false,"sealed":true,"t":0,"n":0}'], [c])
        st = a.status(reading, ctx, a.detect(reading, ctx))
        self.assertIn('-pgp-keys', ' '.join(t['value'] for t in st['tiles']))
        reading, ctx = reading_with(['s\tnot json'], [c])
        self.assertIn('not read', ' '.join(t['value'] for t in a.status(reading, ctx, a.detect(reading, ctx))['tiles']))

    def test_sops_is_the_publishers_binary_and_age_a_package(self):
        e = toolbox.find(self.conn, 'sops')['entry']
        m = e['methods'][0]
        self.assertEqual((m['kind'], m['name']), ('binary', 'sops'))
        self.assertEqual(m['files']['x86_64']['sha256'], 'e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b')
        self.assertIn('runs-as-root', [r['label'] for r in toolbox.risks(e)])
        pv = toolbox.preview(self.conn, 'nas', 'age')
        self.assertEqual(pv['method'], 'package')
        reading, ctx = reading_with(['v\tsops\tsops 3.13.3', 'v\tage\tv1.2.1'])
        self.assertEqual(tbadapters.ADAPTERS['sops'].detect(reading, ctx)['version'], 'sops 3.13.3')
        self.assertIsNone(tbadapters.ADAPTERS['ansible'].detect(reading, ctx))

    def test_vaultwarden_keeps_its_admin_page_off(self):
        e = toolbox.find(self.conn, 'vaultwarden')['entry']
        self.assertFalse(any('ADMIN' in k for m in e['methods'] for k in (m.get('env') or {})))
        self.assertEqual(e['health']['url'], 'http://127.0.0.1:8222/alive')
        self.assertIn('holds-credentials', [r['label'] for r in toolbox.risks(e)])


class Provisioning(Base):
    def setUp(self):
        super().setUp()
        self.host('fed', 'dnf', ['podman'])
        self.host('arch', 'pacman', [])

    def test_runners_install_where_the_distribution_has_them(self):
        self.assertEqual(toolbox.preview(self.conn, 'nas', 'ansible')['method'], 'package')
        self.assertEqual(toolbox.preview(self.conn, 'fed', 'opentofu')['method'], 'package')
        with self.assertRaises(toolbox.CatalogError) as no:
            toolbox.preview(self.conn, 'nas', 'opentofu')
        self.assertIn('no method of OpenTofu fits this host', str(no.exception))
        self.assertEqual(toolbox.preview(self.conn, 'arch', 'packer')['method'], 'package')
        words = toolbox.install_words(self.conn, next(t for t in toolbox.preview(self.conn, 'nas', 'puppet')['tasks'] if t['type'] == 'tool-install'))
        self.assertEqual(words[2], 'puppet-agent', 'Debian names it puppet-agent')
        self.assertEqual(words[6], '', 'no unit is switched on: puppet apply needs no server')

    def test_netbootxyz_runs_under_root_podman_bound_to_the_management_address(self):
        with self.assertRaises(toolbox.CatalogError) as no:
            toolbox.preview(self.conn, 'fed', 'netbootxyz')
        self.assertIn('give it', str(no.exception))
        pv = toolbox.preview(self.conn, 'fed', 'netbootxyz', bind='10.0.0.5')
        self.assertEqual(pv['method'], 'quadlet')
        self.assertIn('10.0.0.5:69:69/udp', pv['made']['ports'])
        self.assertIn('runs-as-root', [r['label'] for r in pv['risks']])

    def test_technitium_takes_its_password_from_a_file_in_the_host_network(self):
        pv = toolbox.preview(self.conn, 'fed', 'technitium')
        sec = next(t for t in pv['tasks'] if t['type'] == 'secret-file')
        self.assertEqual(sec['params']['secret'], 'tool-technitium-admin_password')
        self.assertEqual(sec['params']['path'], f'{toolbox.DATA_ROOT}/technitium/secrets/admin_password')
        labels = [r['label'] for r in pv['risks']]
        self.assertIn('host-network', labels)
        self.assertIn('internet-listener', labels)
        text = toolbox.install_words(self.conn, next(t for t in pv['tasks'] if t['type'] == 'tool-install'))[2]
        self.assertIn('Network=host', text)
        self.assertIn('Environment=DNS_SERVER_ADMIN_PASSWORD_FILE=/run/secrets/technitium/admin_password', text)
        self.assertNotIn('PASSWORD=', text.replace('PASSWORD_FILE=', ''))

    def test_forgejo_is_rootless_with_git_over_ssh_on_2222(self):
        pv = toolbox.preview(self.conn, 'fed', 'forgejo')
        self.assertEqual(pv['method'], 'container')
        self.assertEqual(pv['made']['ports'], ['127.0.0.1:3000:3000/tcp', '127.0.0.1:2222:22/tcp'])


class Storage(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'apt', ['podman'])

    def lines(self, pv, level=None):
        return ' | '.join(x['text'] for x in pv['report'] if level is None or x['level'] == level)

    def test_samba_is_fenced_to_its_clients_in_the_same_plan(self):
        pv = toolbox.preview(self.conn, 'box', 'samba')
        self.assertIn('fence: anyone on the networks box is on can reach its SMB ports', self.lines(pv, 'warn'))
        self.assertNotIn('fw-fence', [t['type'] for t in pv['tasks']])
        self.assertIn('decoys: no share to place decoys in yet: design the shares first', self.lines(pv))
        pv = toolbox.preview(self.conn, 'box', 'samba', allow_from='10.0.20.0/24')
        fence = next(t for t in pv['tasks'] if t['type'] == 'fw-fence')
        self.assertEqual((fence['params']['service'], fence['params']['clients']), ('smb', '10.0.20.0/24'))
        self.assertEqual([t['type'] for t in pv['tasks']], ['tool-install', 'fw-fence'], 'the fence comes after the install')
        plan = changes.normalize({'name': 'samba', 'tasks': pv['tasks']})
        self.assertEqual([i for x in changes.check(self.conn, plan)['tasks'] for i in x['items'] if i['level'] == 'crit'], [])
        text = changes.script(self.conn, plan)
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, capture_output=True, text=True).returncode, 0)

    def test_the_decoys_of_a_media_library_are_wired_in_when_staged(self):
        from storageforge_index import security
        pv = toolbox.preview(self.conn, 'box', 'jellyfin')
        media = f'{toolbox.DATA_ROOT}/jellyfin/media'
        self.assertIn(f'decoys: {media} will be added to the decoy folders of box', self.lines(pv))
        self.assertIn('the sentinel of box is not armed', self.lines(pv))
        self.assertEqual(security.sentinel_config(self.conn, 'box')['folders'], [], 'a preview saves nothing')
        got = toolbox.stage(self.conn, 'box', 'jellyfin', 'test')
        self.assertEqual(got['decoy_folders_added'], [media])
        self.assertEqual(security.sentinel_config(self.conn, 'box')['folders'], [media])
        self.conn.execute("INSERT INTO security_canaries (host, path, sha256, size, deployed_at, status, verified_at) VALUES ('box', :p, 'x', 1, 1, 'armed', 1)",
                          {'p': media + '/Passwords_Media.xlsx'})
        self.assertIn(f'decoys: 1 armed under {media}', self.lines(toolbox.preview(self.conn, 'box', 'jellyfin')))
        self.assertEqual(toolbox.stage(self.conn, 'box', 'jellyfin', 'test')['decoy_folders_added'], [], 'added once')

    def test_garage_asks_for_a_retention_hold_and_keeps_its_secrets_in_files(self):
        pv = toolbox.preview(self.conn, 'box', 'garage')
        self.assertIn(f'WORM: no retention hold reaches {toolbox.DATA_ROOT}/garage/data', self.lines(pv, 'warn'))
        self.assertIn('placement: the index does not know what', self.lines(pv))
        secrets = sorted(t['params']['secret'] for t in pv['tasks'] if t['type'] == 'secret-file')
        self.assertEqual(secrets, ['tool-garage-admin_token', 'tool-garage-metrics_token', 'tool-garage-rpc_secret'])
        self.assertTrue(all(t['params']['owner'] == 'sf-garage' and t['params']['mode'] == '0600' for t in pv['tasks'] if t['type'] == 'secret-file'))

    def test_syncthing_has_no_decoys_since_they_would_travel(self):
        e = toolbox.find(self.conn, 'syncthing')['entry']
        self.assertEqual(e['storage']['canaries'], 'none')
        self.assertNotIn('decoys:', self.lines(toolbox.preview(self.conn, 'box', 'syncthing')))

    def test_a_storage_block_that_is_wrong(self):
        text = toolbox.CATALOG_DIR.joinpath('jellyfin.yaml').read_text().replace('canaries: data', 'canaries: everywhere')
        self.assertIn('storage.canaries is one of', ' '.join(toolbox.load_entry(text)[1]))
        text = toolbox.CATALOG_DIR.joinpath('jellyfin.yaml').read_text().replace('volumes: [media]', 'volumes: [elsewhere]')
        self.assertIn('storage.volumes are names from requires.volumes', ' '.join(toolbox.load_entry(text)[1]))

    def test_units_and_containers_are_read(self):
        reading, ctx = reading_with(['u\tsmbd\tactive\tenabled', 'v\tsamba\tVersion 4.22.4', 'u\tnfs-server\tinactive\tdisabled'],
                                    [{'name': 'sf-jellyfin', 'image': 'docker.io/jellyfin/jellyfin:10.11.11@sha256:' + 'a' * 64, 'state': 'running', 'labels': {'storageforge.tool': 'jellyfin'}}])
        s = tbadapters.ADAPTERS['samba']
        st = s.status(reading, ctx, s.detect(reading, ctx))
        self.assertEqual((st['health'], st['version']), ('ok', 'Version 4.22.4'))
        n = tbadapters.ADAPTERS['nfs-server']
        self.assertEqual(n.status(reading, ctx, n.detect(reading, ctx))['health'], 'down')
        j = tbadapters.ADAPTERS['jellyfin']
        found = j.detect(reading, ctx)
        self.assertEqual((found['version'], found['managed']), ('10.11.11', True))
        self.assertIsNone(tbadapters.ADAPTERS['garage'].detect(reading, ctx))


if __name__ == '__main__':
    unittest.main()
