"""The Toolbox catalog engine (toolbox.py, steps_toolbox.py): the entry schema, signatures made and checked by the real ssh-keygen (the
release key over the official catalog's manifest, an operator key over a custom entry, which the controller only verifies), updates of
the official catalog, the override layer and that it survives an update, the method chosen and why, risk labels, staging an install as a
change plan, and the check at script time that refuses a step whose entry, override or signature is not what was staged."""
import json
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, security, toolbox

CUSTOM = """format: 1
id: whoami
revision: 1
name: Whoami
category: monitoring
summary: A container that answers with what it was asked.
install:
  methods:
    - kind: container
      image: docker.io/traefik/whoami:v1.10.3@sha256:1111111111111111111111111111111111111111111111111111111111111111
      ports: ["8099:80/tcp"]
requires:
  ports: [8099/tcp]
exposure:
  default: loopback
gui:
  native:
    url_template: "http://{host}:{port}/"
    port: 8099
"""


def keypair(d: Path, name: str) -> tuple[Path, str]:
    key = d / name
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', name, '-f', str(key)], check=True)
    return key, ' '.join(key.with_suffix('.pub').read_text().split()[:2])


def sign(key: Path, data: str, d: Path) -> str:
    f = d / 'tosign'
    f.write_text(data)
    subprocess.run(['ssh-keygen', '-Y', 'sign', '-q', '-f', str(key), '-n', toolbox.NAMESPACE, str(f)], check=True)
    out = (d / 'tosign.sig').read_text()
    (d / 'tosign.sig').unlink()
    return out


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = dbfactory.make(self, self.tmp / 'index.db')
        self.conn = self.db.connect()
        self.addCleanup(self.conn.close)
        self.db.migrate(self.conn)
        # a copy of the packaged catalog, so a test can sign it, change it or put a release key beside it
        self.cat = self.tmp / 'catalog'
        shutil.copytree(toolbox.CATALOG_DIR, self.cat)
        for p in (mock.patch.object(toolbox, 'CATALOG_DIR', self.cat), mock.patch.object(toolbox, 'RELEASE_SIGNERS', self.cat / 'release_signers')):
            p.start()
            self.addCleanup(p.stop)
        toolbox._verify_cached.cache_clear()
        self.host('nas', 'apt', [])

    def host(self, name, pm, tools, platform=None):
        pk = f'pm {pm}\nhave bash' + (f'\nplatform {platform}' if platform else '')
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES (:h, :h, 'scan', :i)", {'h': name, 'i': json.dumps({'packages': pk})})
        security._save_measurement(self.conn, name, 'infra', int(time.time()), 'measure', {'tools': tools})

    def release_key(self):
        key, pub = keypair(self.tmp, 'release')
        (self.cat / 'release_signers').write_text(f'# the release key\nstorageforge namespaces="{toolbox.NAMESPACE}" {pub}\n')
        toolbox._verify_cached.cache_clear()
        return key


class Schema(Base):
    def test_the_packaged_entries_pass_and_the_manifest_lists_them(self):
        texts = {f.stem: f.read_text() for f in toolbox.CATALOG_DIR.glob('*.yaml')}
        self.assertLessEqual({'wireguard', 'cockpit', 'uptime-kuma'}, set(texts))
        for tid, text in texts.items():
            e, problems = toolbox.load_entry(text)
            self.assertEqual(problems, [], tid)
            self.assertEqual(e['id'], tid)
        man = json.loads((toolbox.CATALOG_DIR / 'catalog.json').read_text())
        self.assertEqual(man['entries'], {k: toolbox.sha256(v) for k, v in texts.items()},
                         'an entry changed: python -m storageforge_index.toolbox manifest SERIAL writes the manifest again')

    def test_what_an_entry_may_not_say(self):
        def problems(old, new):
            text = CUSTOM.replace(old, new)
            self.assertNotEqual(text, CUSTOM, old)
            return ' '.join(toolbox.load_entry(text)[1])
        self.assertIn('pinned by digest', problems('@sha256:1111111111111111111111111111111111111111111111111111111111111111', ''))
        self.assertIn('privileged containers are refused', problems('      ports:', '      privileged: true\n      ports:'))
        self.assertIn('looks like a secret', problems('      ports:', '      env: {ADMIN_PASSWORD: x}\n      ports:'))
        self.assertIn('the address it binds to comes from the exposure', problems('"8099:80/tcp"', '"0.0.0.0:8099:80/tcp"'))
        self.assertIn('is not a field of an entry', problems('requires:', 'run: rm -rf /\nrequires:'))
        self.assertIn('not something an entry may ask for', problems('      ports:', '      socket: /var/run/docker.sock\n      ports:'))
        self.assertIn('capability SYS_ADMIN', problems('      ports:', '      caps_add: [SYS_ADMIN]\n      ports:'))
        pkg = 'format: 1\nid: tool\nrevision: 1\nname: T\ncategory: monitoring\nsummary: s\ninstall:\n  methods:\n    - kind: package\n      packages: {apt: [tool]}\n'
        self.assertEqual(toolbox.load_entry(pkg + '      units: [tool.service]\n')[1], [])
        self.assertIn('not named after tool', ' '.join(toolbox.load_entry(pkg + '      units: [debug-shell.service]\n')[1]))
        binary = 'format: 1\nid: tool\nrevision: 1\nname: T\ncategory: monitoring\nsummary: s\ninstall:\n  methods:\n    - kind: binary\n      name: sudo\n      files: {x86_64: {url: "https://x.example/a", sha256: %s}}\n' % ('a' * 64)
        self.assertIn('cannot stand in for another', ' '.join(toolbox.load_entry(binary)[1]))
        self.assertIn('no adapter nope', problems('gui:\n', 'gui:\n  panel: {level: status, adapter: nope}\n'))
        self.assertIn('type is one of', problems('requires:', 'steps:\n  - {type: command, params: {cmd: id}}\nrequires:'))
        self.assertIn('names an input', problems('requires:', 'steps:\n  - {type: wg-interface, params: {iface: "{nope}"}}\nrequires:'))
        self.assertIn('health.url', problems('gui:\n', 'health: {url: "http://10.0.0.1/"}\ngui:\n'))
        self.assertIn('env X is NAME', problems('      ports:', '      env: {X: "%h"}\n      ports:'))
        self.assertEqual(toolbox.load_entry('just: [a list')[1][0][:8], 'not YAML')

    def test_risk_labels_follow_the_method_and_the_exposure(self):
        e = toolbox.load_entry((self.cat / 'uptime-kuma.yaml').read_text())[0]
        self.assertEqual([r['label'] for r in toolbox.risks(e, 'container')], ['holds-credentials'])
        self.assertIn('runs-as-root', [r['label'] for r in toolbox.risks(e, 'quadlet')])
        self.assertIn('internet-listener', [r['label'] for r in toolbox.risks(e, 'container', 'any')])
        self.assertTrue(all(r['mitigation'] for r in toolbox.risks(e, 'quadlet', 'any')))


class Signatures(Base):
    def test_packaged_without_a_release_key_is_labelled_so(self):
        off = toolbox.official(self.conn)
        self.assertEqual(off['state'], 'packaged')
        trust = {r['id']: r['trust'] for r in toolbox.catalog(self.conn)}
        self.assertLessEqual({'cockpit', 'uptime-kuma', 'wireguard'}, set(trust))
        self.assertEqual(set(trust.values()), {'packaged'})
        self.assertTrue(all(r['lab'] == 'not lab-tested' for r in toolbox.catalog(self.conn)))

    def test_a_changed_file_in_the_package_is_refused(self):
        p = self.cat / 'cockpit.yaml'
        p.write_text(p.read_text().replace('port: 9090}', 'port: 9091}'))
        row = toolbox.find(self.conn, 'cockpit')
        self.assertEqual(row['trust'], 'refused')
        self.assertIn('changed after the catalog was made', row['trust_why'])
        with self.assertRaises(toolbox.CatalogError):
            toolbox.preview(self.conn, 'nas', 'cockpit')

    def test_the_release_key_signs_the_manifest(self):
        key = self.release_key()
        self.assertEqual(toolbox.official(self.conn)['state'], 'refused', 'with a release key in the package, an unsigned catalog is not offered')
        self.assertEqual(toolbox.catalog(self.conn), [])
        (self.cat / 'catalog.json.sig').write_text(sign(key, (self.cat / 'catalog.json').read_text(), self.tmp))
        toolbox._verify_cached.cache_clear()
        self.assertEqual({r['trust'] for r in toolbox.catalog(self.conn)}, {'release-signed'})
        other, _ = keypair(self.tmp, 'other')
        (self.cat / 'catalog.json.sig').write_text(sign(other, (self.cat / 'catalog.json').read_text(), self.tmp))
        toolbox._verify_cached.cache_clear()
        self.assertEqual(toolbox.official(self.conn)['state'], 'refused', 'another key over the same manifest')

    def update(self, key, serial, change=''):
        texts = {f.stem: f.read_text() for f in self.cat.glob('*.yaml')}
        texts['cockpit'] = texts['cockpit'].replace('revision: 1', 'revision: 2') + change
        man = toolbox.manifest_of(texts, serial)
        return man, sign(key, man, self.tmp), texts

    def test_a_catalog_update_needs_the_release_key_and_a_higher_serial(self):
        key, _ = keypair(self.tmp, 'unknown')
        man, sig, texts = self.update(key, 2)
        with self.assertRaisesRegex(toolbox.CatalogError, 'no release key is in this version'):
            toolbox.take_update(self.conn, man, sig, texts, 'test')
        key = self.release_key()
        (self.cat / 'catalog.json.sig').write_text(sign(key, (self.cat / 'catalog.json').read_text(), self.tmp))
        man, sig, texts = self.update(key, 2)
        bad = dict(texts, cockpit=texts['cockpit'].replace('cockpit.socket]', 'evil.socket]'))
        with self.assertRaisesRegex(toolbox.CatalogError, 'not the file'):
            toolbox.take_update(self.conn, man, sig, bad, 'test')
        got = toolbox.take_update(self.conn, man, sig, texts, 'test')
        self.assertEqual(got['serial'], 2)
        self.assertEqual(toolbox.find(self.conn, 'cockpit')['revision'], 2)
        with self.assertRaisesRegex(toolbox.CatalogError, 'older catalog is not taken back'):
            toolbox.take_update(self.conn, *self.update(key, 2), 'test')
        # a row changed in the database is no longer the signed update: that entry is refused, and is not offered in any form
        self.conn.execute("UPDATE toolbox_catalog SET spec_yaml = replace(spec_yaml, 'cockpit.socket]', 'evil.socket]') WHERE id = 'cockpit'")
        toolbox._verify_cached.cache_clear()
        self.assertEqual(toolbox.find(self.conn, 'cockpit')['trust'], 'refused')
        self.assertEqual(toolbox.find(self.conn, 'wireguard')['trust'], 'release-signed')
        # and a manifest changed in the database is not the one the release key signed: the packaged catalog is offered again
        self.conn.execute("UPDATE toolbox_catalog SET manifest_json = replace(manifest_json, '\"serial\":2', '\"serial\":9')")
        toolbox._verify_cached.cache_clear()
        self.assertEqual(toolbox.official(self.conn)['origin'], 'package')
        self.assertEqual(toolbox.find(self.conn, 'cockpit')['revision'], 1)

    def test_an_operator_key_signs_a_custom_entry_and_the_controller_only_verifies(self):
        key, pub = keypair(self.tmp, 'alice')
        with self.assertRaisesRegex(toolbox.CatalogError, 'public key as one line'):
            toolbox.add_signer(self.conn, 'alice', key.read_text(), 'test')
        toolbox.add_signer(self.conn, 'alice', pub, 'test')
        self.assertNotIn('PRIVATE', json.dumps(toolbox.signers(self.conn)))
        stranger, _ = keypair(self.tmp, 'mallory')
        with self.assertRaisesRegex(toolbox.CatalogError, 'not one of the operator keys'):
            toolbox.save_custom(self.conn, CUSTOM, sign(stranger, CUSTOM, self.tmp), 'test')
        got = toolbox.save_custom(self.conn, CUSTOM, sign(key, CUSTOM, self.tmp), 'test')
        self.assertEqual(got['state'], 'operator-signed')
        self.assertEqual(toolbox.find(self.conn, 'whoami')['signed_by'], 'alice')
        self.conn.execute("UPDATE toolbox_catalog SET spec_yaml = replace(spec_yaml, '8099:80', '8099:22') WHERE id = 'whoami'")
        self.assertEqual(toolbox.find(self.conn, 'whoami')['trust'], 'refused')
        self.assertIn('ssh-keygen -Y sign', toolbox.validate(self.conn, CUSTOM)['sign'])

    def test_a_signature_added_later_is_verified_before_it_is_kept(self):
        key, pub = keypair(self.tmp, 'alice')
        toolbox.add_signer(self.conn, 'alice', pub, 'test')
        self.assertEqual(toolbox.save_custom(self.conn, CUSTOM, None, 'test')['state'], 'unsigned')
        with self.assertRaises(toolbox.CatalogError):
            toolbox.sign_custom(self.conn, 'whoami', sign(key, CUSTOM + '# more\n', self.tmp))
        self.assertEqual(toolbox.sign_custom(self.conn, 'whoami', sign(key, CUSTOM, self.tmp))['state'], 'operator-signed')

    def test_a_custom_entry_cannot_take_an_official_name(self):
        with self.assertRaisesRegex(toolbox.CatalogError, 'official entry'):
            toolbox.save_custom(self.conn, CUSTOM.replace('id: whoami', 'id: cockpit'), None, 'test')


class Staging(Base):
    def setUp(self):
        super().setUp()
        self.host('box', 'dnf', ['podman'])

    def test_the_safest_method_the_host_can_take(self):
        self.assertEqual(toolbox.preview(self.conn, 'box', 'uptime-kuma')['method'], 'container')
        pv = toolbox.preview(self.conn, 'nas', 'uptime-kuma')
        self.assertEqual(pv['method'], 'container')
        self.assertTrue(pv['runtime_first'])
        self.assertEqual(pv['tasks'][0]['type'], 'runtime-install', 'no runtime here: Podman first, and the report says so')
        self.assertIn('Podman is installed first', ' '.join(x['text'] for x in pv['report']))
        self.assertEqual(toolbox.preview(self.conn, 'box', 'uptime-kuma', method='quadlet')['method'], 'quadlet')
        self.assertEqual(toolbox.preview(self.conn, 'nas', 'cockpit')['method'], 'package')
        with self.assertRaisesRegex(toolbox.CatalogError, 'no binary method'):
            toolbox.preview(self.conn, 'nas', 'cockpit', method='binary')
        self.host('tn', 'apt', [], platform='truenas')
        with self.assertRaisesRegex(toolbox.CatalogError, 'TrueNAS'):
            toolbox.preview(self.conn, 'tn', 'cockpit')

    def test_loopback_by_default_and_the_report_says_how_to_reach_it(self):
        pv = toolbox.preview(self.conn, 'box', 'uptime-kuma')
        self.assertEqual(pv['made']['ports'], ['127.0.0.1:3001:3001/tcp'])
        self.assertIn('ssh -L 3001:127.0.0.1:3001 box', ' '.join(x['text'] for x in pv['report']))
        pv = toolbox.preview(self.conn, 'box', 'uptime-kuma', exposure='management', bind='10.0.0.5')
        self.assertEqual(pv['made']['ports'], ['10.0.0.5:3001:3001/tcp'])
        with self.assertRaisesRegex(toolbox.CatalogError, 'one address'):
            toolbox.preview(self.conn, 'box', 'uptime-kuma', exposure='management')

    def test_staged_install_is_a_plan_whose_script_takes_its_values_from_the_entry(self):
        got = toolbox.stage(self.conn, 'box', 'uptime-kuma', 'test')
        plan = changes.get_plan(self.conn, got['plan_id'])
        self.assertEqual([t['type'] for t in plan['tasks']], ['tool-install'])
        self.assertEqual(toolbox.install_of(self.conn, 'box', 'uptime-kuma')['status'], 'staged')
        text = changes.script(self.conn, plan)
        self.assertIn('t_tool_install() {', text)
        self.assertIn('Image=docker.io/louislam/uptime-kuma:2.0.2@sha256:4c364ef96aaddac7ec4c85f5e5f31c3394d35f631381ccbbf93f18fd26ac7cba', text)
        self.assertIn('PublishPort=127.0.0.1:3001:3001/tcp', text)
        self.assertIn('Volume=/srv/toolbox/uptime-kuma/data:/app/data:Z', text)
        self.assertIn('sf-uptime-kuma', text)
        self.assertEqual(changes.check(self.conn, plan)['crit'], 0)
        self.assertIn('t_tool_install uptime-kuma', changes.ansible(self.conn, plan))

    def test_a_plan_edited_to_point_elsewhere_is_refused_on_the_host(self):
        got = toolbox.stage(self.conn, 'box', 'uptime-kuma', 'test')
        plan = changes.get_plan(self.conn, got['plan_id'])
        plan['tasks'][0]['params']['sha'] = 'a' * 64
        text = changes.script(self.conn, plan)
        self.assertIn('changed after this step was staged', text)
        self.assertNotIn('Image=', text)
        self.assertEqual(changes.check(self.conn, plan)['crit'], 1)
        plan['tasks'][0]['params'].update(sha=got['sha256'], tool='cockpit')
        self.assertIn('changed after this step was staged', changes.script(self.conn, plan))

    def test_an_entry_changed_after_staging_is_refused(self):
        got = toolbox.stage(self.conn, 'box', 'uptime-kuma', 'test')
        p = self.cat / 'uptime-kuma.yaml'
        p.write_text(p.read_text().replace('2.0.2@', '2.0.3@'))
        text = changes.script(self.conn, changes.get_plan(self.conn, got['plan_id']))
        self.assertNotIn('Image=', text)
        self.assertIn('changed after the catalog was made', text)

    def test_overrides_change_the_install_and_survive_an_update(self):
        toolbox.set_override(self.conn, 'box', 'uptime-kuma', 'ports: {3001: 3901}\nvolumes: {data: /tank/kuma}\n', 'test')
        got = toolbox.stage(self.conn, 'box', 'uptime-kuma', 'test')
        text = changes.script(self.conn, changes.get_plan(self.conn, got['plan_id']))
        self.assertIn('PublishPort=127.0.0.1:3901:3001/tcp', text)
        self.assertIn('Volume=/tank/kuma:/app/data:Z', text)
        self.assertIn('overridden on box: ports', ' '.join(x['text'] for x in got['report']))
        with self.assertRaises(toolbox.CatalogError):
            toolbox.set_override(self.conn, 'box', 'uptime-kuma', 'volumes: {data: /etc}\n', 'test')
        for bad in ('/etc/ssh', '/var/lib/docker', '/home/alice', '/', '/root/x'):
            with self.assertRaises(toolbox.CatalogError, msg=bad):
                toolbox.set_override(self.conn, 'box', 'uptime-kuma', f'volumes: {{data: {bad}}}\n', 'test')
        self.assertTrue(toolbox.data_folder_ok('/home/alice/kuma') and toolbox.data_folder_ok('/srv/kuma') and toolbox.data_folder_ok('/tank/apps/kuma'))
        with self.assertRaises(toolbox.CatalogError):
            toolbox.set_override(self.conn, 'box', 'uptime-kuma', 'image: docker.io/x/y:1\n', 'test')
        toolbox.set_override(self.conn, 'box', 'uptime-kuma', 'ports: {3001: 3902}\n', 'test')
        self.assertIn('override of uptime-kuma on box changed', changes.script(self.conn, changes.get_plan(self.conn, got['plan_id'])))
        # an update of the official catalog leaves the override as it was
        key = self.release_key()
        (self.cat / 'catalog.json.sig').write_text(sign(key, (self.cat / 'catalog.json').read_text(), self.tmp))
        texts = {f.stem: f.read_text() for f in self.cat.glob('*.yaml')}
        texts['uptime-kuma'] = texts['uptime-kuma'].replace('revision: 1', 'revision: 2')
        man = toolbox.manifest_of(texts, 5)
        toolbox.take_update(self.conn, man, sign(key, man, self.tmp), texts, 'test')
        self.assertEqual(toolbox.override_row(self.conn, 'box', 'uptime-kuma')['text'], 'ports: {3001: 3902}\n')
        pv = toolbox.preview(self.conn, 'box', 'uptime-kuma')
        self.assertEqual(pv['made']['ports'], ['127.0.0.1:3902:3001/tcp'])
        self.assertEqual([u['state'] for u in toolbox.updates(self.conn)], ['update'])

    def test_an_unsigned_custom_entry_needs_someone_to_accept_it_for_the_host(self):
        toolbox.save_custom(self.conn, CUSTOM, None, 'test')
        with self.assertRaisesRegex(toolbox.CatalogError, 'not signed'):
            toolbox.stage(self.conn, 'box', 'whoami', 'test')
        got = toolbox.stage(self.conn, 'box', 'whoami', 'root', accept_unsigned=True)
        plan = changes.get_plan(self.conn, got['plan_id'])
        self.assertIn('Image=docker.io/traefik/whoami', changes.script(self.conn, plan))
        self.assertEqual(toolbox.install_of(self.conn, 'box', 'whoami')['unsigned_by'], 'root')
        other = {'name': 'p2', 'tasks': [dict(plan['tasks'][0], host='nas')]}
        self.assertIn('nobody accepted it for nas', changes.script(self.conn, other))

    def test_wireguard_brings_its_interface_step(self):
        pv = toolbox.preview(self.conn, 'nas', 'wireguard', inputs={'iface': 'wg1', 'address': '10.9.0.1/24', 'port': '51900'})
        self.assertEqual([t['type'] for t in pv['tasks']], ['tool-install', 'wg-interface'])
        self.assertEqual(pv['tasks'][1]['params'], {'iface': 'wg1', 'address': '10.9.0.1/24', 'port': '51900', 'state': 'present'})
        with self.assertRaisesRegex(toolbox.CatalogError, 'not a valid port'):
            toolbox.preview(self.conn, 'nas', 'wireguard', inputs={'port': '51900; reboot'})
        self.assertIn('internet-listener', [r['label'] for r in pv['risks']])

    def test_removal_keeps_the_data_and_moving_it_is_destructive(self):
        toolbox.stage(self.conn, 'box', 'uptime-kuma', 'test')
        got = toolbox.stage_remove(self.conn, 'box', 'uptime-kuma', 'test')
        self.assertEqual(got['kept'], ['/srv/toolbox/uptime-kuma/data'])
        plan = changes.get_plan(self.conn, got['plan_id'])
        self.assertEqual([t['type'] for t in plan['tasks']], ['tool-remove'])
        self.assertIn("its data stays: /srv/toolbox/uptime-kuma/data", ' '.join(i['text'] for t in changes.check(self.conn, plan)['tasks'] for i in t['items']))
        got = toolbox.stage_remove(self.conn, 'box', 'uptime-kuma', 'test', with_data=True)
        plan = changes.get_plan(self.conn, got['plan_id'])
        self.assertEqual(plan['tasks'][1]['type'], 'tool-data-remove')
        self.assertTrue(changes.TYPES['tool-data-remove']['destructive'])
        with self.assertRaisesRegex(ValueError, 'again in the confirm field'):
            changes.normalize({'name': 'x', 'tasks': [{'host': 'box', 'type': 'tool-data-remove', 'params': {'tool': 'uptime-kuma', 'confirm': 'nope'}}]})
        text = changes.script(self.conn, plan)
        self.assertIn("tool-data-remove 'Move the data of uptime-kuma to the trash' uptime-kuma uptime-kuma ok", text)


if __name__ == '__main__':
    unittest.main()
