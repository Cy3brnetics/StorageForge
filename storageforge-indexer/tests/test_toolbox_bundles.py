"""Toolbox bundles, role profiles, per-host exclusions and custom dashboard tool tiles (roadmap 0.5.13)."""
import time

try:
    from test_toolbox import Base
except ImportError:
    from tests.test_toolbox import Base
from storageforge_index import secplus, secretstore, security, server, tbadapters, tbbundles, toolbox, users

PW = 'a long enough password'


class BundlesAndProfiles(Base):
    def setUp(self):
        super().setUp()
        self.host('edge', 'apt', ['podman', 'wg'])
        security._save_measurement(self.conn, 'edge', 'infra', int(time.time()), 'measure',
                                   {'tools': ['podman', 'wg'], 'listeners': [],
                                    'access': {'wireguard': [{'name': 'wg0', 'public_key': 'A' * 43 + '=', 'listen_port': 51820, 'peers': []}]}})
        users.create(self.conn, 'admin', PW, 'admin')
        users.create(self.conn, 'op', PW, 'operator')
        users.create(self.conn, 'view', PW, 'viewer')
        self.web = server.create_app(server.App(self.db), 's' * 48)

    def client(self, who='admin'):
        c = self.web.test_client()
        self.assertEqual(c.post('/api/login', json={'username': who, 'password': PW}).status_code, 200)
        return c

    def test_builtin_bundles_and_dependency_ordering(self):
        bundles = tbbundles.list_bundles(self.conn)
        ids = {b['id'] for b in bundles}
        self.assertLessEqual({'private-access', 'hardened-homelab', 'container-host', 'hypervisor',
                              'observability', 'zero-trust-gateway', 'backup-recovery'}, ids)
        ordered = tbbundles.order_entries(self.conn, ['uptime-kuma', 'caddy', 'authelia', 'wireguard', 'step-ca'])
        self.assertEqual(ordered, ['step-ca', 'authelia', 'wireguard', 'caddy', 'uptime-kuma'])

    def test_bundle_preview_deduplicates_runtime_detects_port_conflicts_and_stages_one_plan(self):
        # Traefik + nginx-proxy-manager both bind 8443/tcp (rootless) -> port collision detected; Caddy (package 443) + Traefik (quadlet 443) too
        pv = tbbundles.preview_bundle(self.conn, 'edge', entries=['traefik', 'nginx-proxy-manager'], name='Two proxies')
        self.assertTrue(pv['conflicts'], 'expected 8443 collision between traefik and nginx-proxy-manager')
        self.assertTrue(any('crit' == r['level'] and '8443' in r['text'] for r in pv['report']))
        with self.assertRaises(toolbox.CatalogError):
            tbbundles.stage_bundle(self.conn, 'edge', None, 'admin', entries=['traefik', 'nginx-proxy-manager'])

        # Bare host without podman -> single consolidated runtime-install step across multi-container bundle
        self.host('bare', 'apt', [])
        ch = tbbundles.preview_bundle(self.conn, 'bare', entries=['caddy', 'trivy', 'uptime-kuma'], name='Multi-container')
        rt_steps = [t for t in ch['tasks'] if t['type'] == 'runtime-install']
        self.assertEqual(len(rt_steps), 1, 'runtime-install should be consolidated once for the whole bundle')
        self.assertEqual(ch['tasks'][0]['type'], 'runtime-install')
        self.assertEqual(ch['order'], ['caddy', 'trivy', 'uptime-kuma'])
        self.assertEqual([t['params']['tool'] for t in ch['rollback_tasks']], ['uptime-kuma', 'trivy', 'caddy'])

        # Stage observability bundle into a single plan
        staged = tbbundles.stage_bundle(self.conn, 'edge', 'observability', 'admin')
        self.assertEqual([i['tool'] for i in staged['installs']], ['chrony', 'cockpit', 'uptime-kuma'])
        self.assertEqual(len({toolbox.install_of(self.conn, 'edge', t)['plan_id'] for t in ('chrony', 'cockpit', 'uptime-kuma')}), 1)

        # Whole-bundle removal stages reverse-order tool-remove steps keeping data
        rem = tbbundles.stage_bundle_remove(self.conn, 'edge', 'observability', 'admin')
        self.assertEqual([t['params']['tool'] for t in rem['tasks']], ['uptime-kuma', 'cockpit', 'chrony'])

    def test_user_bundle_crud_and_role_profiles_with_host_exclusions(self):
        custom = tbbundles.save_bundle(self.conn, {'id': 'my-stack', 'name': 'My Stack', 'summary': 'Custom set', 'entries': ['uptime-kuma', 'chrony']}, 'admin')
        self.assertTrue(custom['user_defined'])
        self.assertEqual(custom['entries'], ['chrony', 'uptime-kuma'])
        with self.assertRaises(toolbox.CatalogError):
            tbbundles.save_bundle(self.conn, {'id': 'observability', 'name': 'Dup', 'entries': ['chrony']}, 'admin')
        with self.assertRaises(toolbox.CatalogError):
            tbbundles.delete_bundle(self.conn, 'observability')

        # Role profiles forbid not-a-default entries (zerotier)
        with self.assertRaises(toolbox.CatalogError):
            tbbundles.set_role_profile(self.conn, 'edge', ['wireguard', 'zerotier'], {}, 'admin')

        hp = tbbundles.set_host_role(self.conn, 'edge', 'nas', ['samba'], 'admin')
        self.assertEqual(hp['role'], 'nas')
        self.assertNotIn('samba', hp['tools'])
        self.assertIn('nfs-server', hp['tools'])
        self.assertTrue(tbbundles.delete_bundle(self.conn, 'my-stack'))

    def test_custom_dashboard_tool_tiles_and_routes(self):
        # Populate toolbox_status via tbadapters.refresh for WireGuard
        tbadapters.refresh(self.conn, 'edge', {'tools': ['podman', 'wg'], 'listeners': [],
                                               'access': {'wireguard': [{'name': 'wg0', 'public_key': 'A' * 43 + '=', 'listen_port': 51820, 'peers': []}]}})
        kinds = secplus.tile_kinds(self.conn)
        self.assertIn('toolbox', kinds)
        self.assertIn('tool:wireguard', kinds)
        summary = secplus.tile(self.conn, 'toolbox', 'edge')
        self.assertIn('stats', summary)
        wg_tile = secplus.tile(self.conn, 'tool:wireguard', 'edge')
        self.assertIn('rows', wg_tile)

        c = self.client('admin')
        # Save custom Security Dashboard containing both built-in and Toolbox tool tiles
        r = c.post('/api/security/dash', json={'name': 'Ops Grid', 'layout': [{'kind': 'toolbox', 'w': 2, 'h': 1}, {'kind': 'tool:wireguard', 'w': 1, 'h': 1}]})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertIn('tool:wireguard', c.get('/api/security/dash/tiles').get_json()['tiles'])
        self.assertIn('toolbox', c.get('/api/toolbox/dash/tiles').get_json()['tiles'])

        # Viewer cannot mutate bundles/profiles; operator can
        v = self.client('view')
        self.assertEqual(v.post('/api/toolbox/bundles', json={'id': 'b1', 'name': 'B1', 'entries': ['chrony']}).status_code, 403)
        self.assertEqual(v.put('/api/toolbox/profiles/host/edge', json={'role': 'nas', 'excluded': ['samba']}).status_code, 403)

        op = self.client('op')
        self.assertEqual(op.post('/api/toolbox/bundles', json={'id': 'b1', 'name': 'B1', 'entries': ['chrony', 'uptime-kuma']}).status_code, 201)
        self.assertEqual(op.put('/api/toolbox/profiles/host/edge', json={'role': 'hypervisor', 'excluded': ['cockpit']}).status_code, 200)
        prof = op.get('/api/toolbox/profiles').get_json()
        edge = next(h for h in prof['hosts'] if h['host'] == 'edge')
        self.assertEqual(edge['excluded'], ['cockpit'])
        self.assertEqual(op.delete('/api/toolbox/bundles/b1').status_code, 200)
