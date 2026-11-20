"""Access proxies (roadmap section 2): what OpenZiti, Teleport, Boundary and Pomerium on a host say they give access to.

None of the four is installed on the machine these tests run on, so each sample is what the tool's own source or documentation
prints, and says which. What must hold: each target is named with where it is reached, a route anyone may use without a sign-in
is marked public, no credential and no person is in anything that comes back, and no reader raises."""
import json
import subprocess
import unittest

from storageforge_index import accessproxies, confread, inframeasure

# `ziti-edge-tunnel tunnel_status` of ziti-edge-tunnel 1.x (github.com/openziti/ziti-tunnel-sdk-c: the reply is printed by
# programs/ziti-edge-tunnel/ziti-edge-tunnel.c as pretty JSON, and its fields are the tunnel_status, tunnel_identity and
# tunnel_service models of include/model/dtos.h). One identity that may dial two services and is where a third comes out.
ZITI = json.dumps({'Success': True, 'Code': 0, 'Data': {
    'Active': True, 'Duration': 86400000, 'StartTime': '2026-11-19T10:00:00.000000Z', 'LogLevel': 'info', 'TunIpv4': '100.64.0.1', 'TunPrefixLength': 10, 'TunName': 'ziti0', 'AddDns': False,
    'ApiPageSize': 250, 'ConfigDir': '/var/lib/ziti',
    'IpInfo': {'Ip': '100.64.0.1', 'Subnet': '255.192.0.0', 'MTU': 65535, 'DNS': '100.64.0.2'},
    'ServiceVersion': {'Version': 'v1.7.12', 'Revision': 'abc1234', 'BuildDate': 'Mon Oct  5 2026'},
    'Identities': [
        {'Name': 'nas-01', 'Identifier': '/opt/openziti/etc/identities/nas-01.json', 'FingerPrint': 'c1b2a3', 'Active': True, 'Loaded': True, 'IdFileStatus': True, 'NeedsExtAuth': False,
         'MfaEnabled': False, 'MfaNeeded': False, 'ControllerVersion': 'v1.6.9', 'Config': {'ztAPI': 'https://ctrl.ziti.lab:1280', 'ztAPIs': ['https://ctrl.ziti.lab:1280'], 'ConfigTypes': None},
         'Metrics': {'Up': 1200, 'Down': 3400}, 'Tags': None,
         'Services': [
             {'Id': '5Qy1', 'Name': 'git', 'Protocols': ['tcp'], 'Addresses': [{'IsHost': True, 'HostName': 'git.ziti', 'IP': '', 'Prefix': 0}, {'IsHost': False, 'HostName': '', 'IP': '100.64.0.10', 'Prefix': 32}],
              'Ports': [{'Low': 22, 'High': 22}, {'Low': 443, 'High': 443}], 'OwnsIntercept': True, 'PostureChecks': None, 'IsAccessible': True, 'Timeout': -1, 'TimeoutRemaining': -1,
              'Permissions': {'Bind': False, 'Dial': True}},
             {'Id': '7Hx2', 'Name': 'lab-net', 'Protocols': ['tcp', 'udp'], 'Addresses': [{'IsHost': False, 'HostName': '', 'IP': '10.77.0.0', 'Prefix': 16}],
              'Ports': [{'Low': 1, 'High': 65535}], 'OwnsIntercept': True, 'Permissions': {'Bind': False, 'Dial': True}},
             {'Id': '9Kz3', 'Name': 'nas-ssh', 'Protocols': None, 'Addresses': None, 'Ports': None, 'OwnsIntercept': False, 'Permissions': {'Bind': True, 'Dial': False}}]},
        {'Name': 'backup', 'Identifier': '/opt/openziti/etc/identities/backup.json', 'Active': False, 'Loaded': True, 'NeedsExtAuth': True, 'Config': {'ztAPI': 'https://ctrl.ziti.lab:1280'}, 'Services': None}]}}, indent=1)

# `tctl status --format=json` (Teleport 17 and 18, tool/tctl/common/status_command.go: statusOutput with `cluster` and
# `authorities`), `tctl get nodes --format=json` (a list of node resources; the spec's fields are ServerSpecV2 of
# api/proto/teleport/legacy/types/types.proto: addr, hostname, cmd_labels, use_tunnel, version) and `tsh status --format=json`
# (tool/tsh/common/tsh.go, serializeProfiles: `active` and `profiles`, each a profileInfo).
TCTL_STATUS = json.dumps({'cluster': {'name': 'teleport.lab', 'version': '18.2.1', 'ca_pins': ['sha256:aa11']},
                          'authorities': [{'cluster_name': 'teleport.lab', 'type': 'host', 'rotation': {'state': 'standby'}, 'keys': [{'protocol': 'SSH', 'status': 'active', 'algorithm': 'Ed25519', 'storage': 'software'}]},
                                          {'cluster_name': 'teleport.lab', 'type': 'user', 'rotation': {'state': 'standby'}, 'keys': []}]}, indent=2)
# the text of an older tctl, which has no --format (docs: goteleport.com/docs/reference/cli/tctl/#tctl-status)
TCTL_STATUS_TEXT = """Cluster: teleport.lab
Version: 16.4.8
host CA rotation: standby
CA pins: sha256:aa11
"""
TCTL_NODES = json.dumps([
    {'kind': 'node', 'version': 'v2', 'metadata': {'name': '0f5a7a6c-0b77-4c5e-9d4b-1c3a55aa0001', 'labels': {'env': 'prod', 'hostname': 'a-label-not-a-name', 'owner': 'gabe@example.com'}, 'expires': '2026-11-20T18:00:00Z', 'revision': 'r1'},
     'spec': {'addr': '10.42.0.9:3022', 'hostname': 'db1', 'cmd_labels': {'kernel': {'period': '1h0m0s', 'command': ['uname', '-r'], 'result': '6.12.0'}}, 'rotation': {'current_id': '', 'started': '0001-01-01T00:00:00Z'},
              'version': '18.2.1'}},
    {'kind': 'node', 'version': 'v2', 'metadata': {'name': '0f5a7a6c-0b77-4c5e-9d4b-1c3a55aa0002', 'labels': {}}, 'spec': {'addr': '', 'hostname': 'laptop', 'use_tunnel': True, 'version': '18.2.1'}},
    {'kind': 'node', 'sub_kind': 'openssh', 'version': 'v2', 'metadata': {'name': '0f5a7a6c-0b77-4c5e-9d4b-1c3a55aa0003'}, 'spec': {'addr': '[fd00::7]:22', 'hostname': 'old-box', 'version': ''}}], indent=4)
TSH_STATUS = json.dumps({'active': {'profile_url': 'https://teleport.lab:443', 'username': 'gabe@example.com', 'cluster': 'teleport.lab', 'roles': ['access', 'editor'], 'traits': {'logins': ['root', 'gabe']},
                                    'logins': ['root', 'gabe'], 'kubernetes_enabled': False, 'valid_until': '2026-11-21T02:00:00Z', 'extensions': ['permit-pty']}, 'profiles': []}, indent=2)
# /etc/teleport.yaml as `teleport configure` writes it (goteleport.com/docs/reference/deployment/config), with a join token and a key pair
TELEPORT_CONF = """version: v3
teleport:
  nodename: tp-01
  data_dir: /var/lib/teleport
  auth_token: SECRETSECRETSECRET
  join_params:
    token_name: SECRETSECRET
    method: token
  ca_pin: sha256:aa11
  proxy_server: teleport.lab:443
  log:
    output: stderr
    severity: INFO
auth_service:
  enabled: "yes"
  listen_addr: 0.0.0.0:3025
  cluster_name: teleport.lab
  tokens:
    - proxy,node:SECRETSECRET
ssh_service:
  enabled: "yes"
  labels:
    env: prod
  commands:
    - name: hostname
      command: [hostname]
      period: 1m0s
proxy_service:
  enabled: "yes"
  web_listen_addr: 0.0.0.0:443
  public_addr: teleport.lab:443
  https_keypairs:
    - key_file: /etc/teleport/SECRET.key
      cert_file: /etc/teleport/tls.crt
  acme: {}
app_service:
  enabled: "no"
"""

# `boundary targets list -recursive -scope-id global -format json` (Boundary 0.19: the CLI prints the API's answer with its status
# code; a target's fields are api/targets/target.gen.go of github.com/hashicorp/boundary), and a controller and a worker
# configuration as developer.hashicorp.com/boundary/docs/configuration writes them, with the database address and the KMS keys.
BOUNDARY_TARGETS = json.dumps({'status_code': 200, 'items': [
    {'id': 'ttcp_1234567890', 'scope_id': 'p_1234567890', 'scope': {'id': 'p_1234567890', 'type': 'project', 'name': 'lab', 'parent_scope_id': 'o_1234567890'}, 'name': 'nas ssh', 'description': 'for gabe@example.com',
     'created_time': '2026-10-01T10:00:00Z', 'updated_time': '2026-10-01T10:00:00Z', 'version': 2, 'type': 'tcp', 'session_max_seconds': 28800, 'session_connection_limit': -1,
     'attributes': {'default_port': 22}, 'authorized_actions': ['read', 'authorize-session'], 'address': '10.42.0.5'},
    {'id': 'tssh_0987654321', 'scope_id': 'p_1234567890', 'scope': {'id': 'p_1234567890', 'type': 'project', 'name': 'lab'}, 'name': 'databases', 'type': 'ssh', 'host_source_ids': ['hsst_1111111111', 'hsst_2222222222'],
     'injected_application_credential_source_ids': ['clvlt_SECRET'], 'attributes': {'default_port': 22, 'default_client_port': 2222}},
    {'id': 'ttcp_5555555555', 'scope': {'name': 'lab'}, 'type': 'tcp', 'address': 'pg.lab.example.net', 'attributes': {'default_port': 5432}}]})
BOUNDARY_CONTROLLER = """disable_mlock = true

controller {
  name = "controller-1"
  description = "the lab controller"
  database {
    url = "postgresql://boundary:SECRETSECRET@db.lab:5432/boundary"
  }
  public_cluster_addr = "10.42.0.20:9201"
}

listener "tcp" {
  address = "0.0.0.0:9200"
  purpose = "api"
  tls_cert_file = "/etc/boundary.d/tls/cert.pem"
  tls_key_file  = "/etc/boundary.d/tls/SECRET.pem"
}

kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key = "SECRETSECRETSECRETSECRETSECRETSECRETSECRETg="
  key_id = "global_root"
}
"""
BOUNDARY_WORKER = """worker {
  name = "worker-1"
  public_addr = "worker.lab.example.net:9202"
  initial_upstreams = ["10.42.0.20:9201", "10.42.0.21:9201"]
  controller_generated_activation_token = "neslat_SECRETSECRET"
  auth_storage_path = "/var/lib/boundary/worker"
  tags {
    type = ["lab", "ssh"]
  }
}

listener "tcp" {
  address = "0.0.0.0:9202"
  purpose = "proxy"
}
"""

# /etc/pomerium/config.yaml: the settings and the route fields of pomerium.com/docs/reference (routes: from, to, policy in PPL,
# allow_public_unauthenticated_access, allow_any_authenticated_user, allowed_domains, set_request_headers, tls_skip_verify, prefix,
# redirect, response) and the policy language of pomerium.com/docs/internals/ppl.
POMERIUM = """authenticate_service_url: https://authenticate.example.com
address: :443
idp_provider: google
idp_client_id: 1234.apps.googleusercontent.com
idp_client_secret: SECRETSECRET
cookie_secret: SECRETSECRETSECRETSECRETSECRETSECRETSECRETg=
shared_secret: SECRETSECRETSECRETSECRETSECRETSECRETSECRETh=
signing_key: |
  LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tSECRET
  SECRETSECRETSECRET
certificates:
  - cert: /etc/pomerium/tls.crt
    key: /etc/pomerium/SECRET.key
routes:
  - from: https://grafana.example.com
    to: http://10.42.0.5:3000
    pass_identity_headers: true
    policy:
      - allow:
          or:
            - domain:
                is: example.com
            - email:
                is: gabe@example.com
      - deny:
          or:
            - email:
                is: mallory@example.com
  - from: https://status.example.com
    to: http://localhost:8080
    allow_public_unauthenticated_access: true
  - from: https://wiki.example.com
    prefix: /docs
    to:
      - https://wiki-1.lab:8443
      - https://wiki-2.lab:8443
    tls_skip_verify: true
    allow_any_authenticated_user: true
  - from: https://db.example.com
    to: https://admin:SECRET@10.42.0.7:8443
    allowed_domains:
      - example.com
      - example.org
    set_request_headers:
      Authorization: Basic SECRETSECRET
      X-Api-Key: SECRET
  - from: tcp+https://ssh.example.com:22
    to: tcp://nas-01:22
    policy:
      - allow:
          and:
            - authenticated_user: true
            - claim/groups: admins
  - from: https://open.example.com
    to: http://10.42.0.8
    policy:
      - allow:
          or:
            - accept: true
  - from: https://old.example.com
    redirect:
      host_redirect: new.example.com
  - from: https://nobody.example.com
    to: http://10.42.0.9
"""


def as_collected(section: str, text: str, args: str = '') -> str:
    """What the collector's own filter leaves of what a tool printed: the part of its line after the tool, run for real."""
    line = next(x for x in inframeasure.BODY.splitlines() if x.startswith(f'sec {section};'))
    out = ''
    for part in line.split(' try ')[1:]:
        if args and not part.startswith(args):
            continue
        ran = subprocess.run(['bash', '-c', 'capped() { head -c "$1"; }\n' + part[part.index(' | ') + 3:].rstrip('; }')], input=text, capture_output=True, text=True)
        out += ran.stdout
    return out


def pomerium_as_collected(text: str) -> str:
    line = next(x for x in inframeasure.BODY.splitlines() if x.startswith('sec pomerium_conf;'))
    scrubbed = subprocess.run(['awk', '-v', f're={confread.SECRET_LINE}', confread.SCRUB_AWK], input=text, capture_output=True, text=True, check=True).stdout
    return subprocess.run(['bash', '-c', line[line.index('sed -E'):]], input=scrubbed, capture_output=True, text=True, check=True).stdout


class OpenZiti(unittest.TestCase):
    def test_identities_and_the_services_each_may_dial_or_host(self):
        got = accessproxies.openziti(ZITI)
        self.assertEqual((got['tool'], got['roles'], got['server'], got['interface']), ('openziti', ['tunneler'], 'https://ctrl.ziti.lab:1280', 'ziti0'))
        self.assertEqual(got['identities'], [{'name': 'nas-01', 'active': True, 'loaded': True, 'controller': 'https://ctrl.ziti.lab:1280', 'needs_login': False, 'services': 3},
                                             {'name': 'backup', 'active': False, 'loaded': True, 'controller': 'https://ctrl.ziti.lab:1280', 'needs_login': True, 'services': 0}])
        git, net, ssh = got['targets']
        self.assertEqual((git['name'], git['address'], git['port'], git['kind'], git['addresses'], git['ports'], git['protocols'], git['hosted_here']),
                         ('git', 'git.ziti', '22', 'dial', ['git.ziti', '100.64.0.10'], ['22', '443'], ['tcp'], False))
        self.assertEqual((net['address'], net['ports'], net['protocols']), ('10.77.0.0', ['1-65535'], ['tcp', 'udp']))
        self.assertEqual((ssh['name'], ssh['kind'], ssh['hosted_here'], ssh['address'], ssh['identity']), ('nas-ssh', 'bind', True, None, 'nas-01'), 'this host is where that service comes out')
        self.assertEqual(accessproxies.sentence(got), 'OpenZiti (tunneler): 3 service(s)')
        self.assertNotIn('/opt/openziti', json.dumps(got), 'where the identity file is kept is not')

    def test_the_status_without_its_envelope_and_a_tunneler_with_no_identity(self):
        bare = accessproxies.openziti(json.dumps(json.loads(ZITI)['Data']))
        self.assertEqual(len(bare['targets']), 3)
        none = accessproxies.openziti('{"Success": true, "Code": 0, "Data": {"Active": true, "TunIpv4": "100.64.0.1", "TunName": "ziti0", "Identities": null}}')
        self.assertEqual((none['identities'], none['targets'], accessproxies.sentence(none)), ([], [], 'OpenZiti (tunneler): 0 service(s)'))
        self.assertEqual(accessproxies.openziti('{"Success": false, "Code": 1, "Error": "no such command"}')['error'], 'not the JSON this tool prints')


class Teleport(unittest.TestCase):
    def collected(self, status=TCTL_STATUS):
        nodes = as_collected('tp_nodes', TCTL_NODES)
        said = as_collected('tp_status', status, 'tctl status --format=json') if status.lstrip().startswith('{') else as_collected('tp_status', status, 'tctl status |')
        return said, nodes, confread.scrub(TELEPORT_CONF), as_collected('tp_login', TSH_STATUS)

    def test_what_leaves_the_host_is_the_few_fields_that_are_read(self):
        said, nodes, conf, login = self.collected()
        self.assertEqual(said.splitlines(), ['"name": "teleport.lab"', '"version": "18.2.1"'])
        self.assertEqual(login.splitlines(), ['"profile_url": "https://teleport.lab:443"', '"cluster": "teleport.lab"', '"valid_until": "2026-11-21T02:00:00Z"'])
        for text in (said, nodes, login):
            for word in ('gabe', 'uname', 'owner', 'logins', 'root', 'sha256', 'env'):
                self.assertNotIn(word, text, 'a label, a command and a user stay on the host')
        self.assertNotIn('SECRET', conf, 'and so do the join token and the name of the key file')
        self.assertEqual(conf.splitlines(), subprocess.run(['awk', '-v', f're={confread.SECRET_LINE}', confread.SCRUB_AWK], input=TELEPORT_CONF, capture_output=True, text=True).stdout.splitlines())
        self.assertIn('"hostname": "db1"', nodes)

    def test_the_cluster_its_nodes_and_what_this_host_is_to_it(self):
        for texts in (self.collected(), (TCTL_STATUS, TCTL_NODES, TELEPORT_CONF, TSH_STATUS)):
            got = accessproxies.teleport(*texts)
            self.assertEqual((got['tool'], got['roles'], got['cluster'], got['version'], got['server'], got['public'], got['name']),
                             ('teleport', ['auth', 'proxy', 'node'], 'teleport.lab', '18.2.1', 'teleport.lab:443', 'teleport.lab:443', 'tp-01'))
            self.assertEqual([(t['name'], t['address'], t['port'], t['kind'], t['access']) for t in got['targets']],
                             [('db1', '10.42.0.9', '3022', 'ssh', None), ('laptop', None, None, 'ssh', 'reached through the proxy'), ('old-box', 'fd00::7', '22', 'ssh', None)],
                             'a label called hostname is not the name of the node')
            self.assertEqual(got['login'], {'cluster': 'teleport.lab', 'proxy': 'https://teleport.lab:443', 'valid_until': '2026-11-21T02:00:00Z'})
            self.assertEqual(accessproxies.sentence(got), 'Teleport (auth and proxy and node) of teleport.lab: 3 node(s)')
            for word in ('gabe', 'SECRET', 'uname', 'sha256'):
                self.assertNotIn(word, json.dumps(got))

    def test_an_older_tctl_that_prints_text(self):
        said, nodes, conf, login = self.collected(TCTL_STATUS_TEXT)
        self.assertEqual(said.splitlines(), ['Cluster: teleport.lab', 'Version: 16.4.8'])
        got = accessproxies.teleport(said, nodes, conf, '')
        self.assertEqual((got['cluster'], got['version'], got['login']), ('teleport.lab', '16.4.8', None))

    def test_a_node_that_only_joins_and_a_laptop_that_is_only_signed_in(self):
        node = accessproxies.teleport('', '', 'version: v3\nteleport:\n  nodename: n1\n  auth_servers: [tp.lab:3025]\nssh_service:\n  enabled: yes\nauth_service:\n  enabled: no\nproxy_service:\n  enabled: no\n')
        self.assertEqual((node['roles'], node['server'], node['cluster'], node['targets']), (['node'], 'tp.lab:3025', None, []))
        laptop = accessproxies.teleport(login=as_collected('tp_login', TSH_STATUS))
        self.assertEqual((laptop['roles'], laptop['cluster'], laptop['login']['proxy']), ([], 'teleport.lab', 'https://teleport.lab:443'))
        self.assertEqual(accessproxies.teleport()['error'], 'nothing read')
        self.assertEqual(accessproxies.teleport('ERROR: access denied', 'ERROR: access denied')['error'], 'not what Teleport prints')


class Boundary(unittest.TestCase):
    def test_targets_where_a_token_was_at_hand(self):
        got = accessproxies.boundary(BOUNDARY_TARGETS, confread.scrub(BOUNDARY_CONTROLLER))
        self.assertEqual((got['roles'], got['name'], got['public'], got['targets_read']), (['controller'], 'controller-1', '10.42.0.20:9201', True))
        self.assertEqual([(t['name'], t['address'], t['port'], t['kind'], t['access'], t['scope']) for t in got['targets']],
                         [('nas ssh', '10.42.0.5', '22', 'tcp', None, 'lab'), ('databases', None, '22', 'ssh', '2 host source(s)', 'lab'), ('ttcp_5555555555', 'pg.lab.example.net', '5432', 'tcp', None, 'lab')])
        self.assertEqual(accessproxies.sentence(got), 'Boundary (controller): 3 target(s)')
        self.assertNotIn('SECRET', json.dumps(got))
        self.assertNotIn('gabe', json.dumps(got), 'a description is not kept')

    def test_a_description_and_the_credentials_a_target_is_given_stay_on_the_host(self):
        sent = as_collected('boundary_targets', BOUNDARY_TARGETS)
        self.assertNotIn('gabe', sent)
        self.assertNotIn('clvlt', sent)
        self.assertEqual(json.loads(sent)['items'][0]['description'], '', 'and what is sent is still the JSON it was')
        self.assertEqual(accessproxies.boundary(sent)['targets'], accessproxies.boundary(BOUNDARY_TARGETS)['targets'])
        odd = '{"items": [{"name": "a", "description": "said \\"x\\" to bob@example.com, twice", "address": "10.0.0.1"}]}'
        self.assertEqual(json.loads(as_collected('boundary_targets', odd)), {'items': [{'name': 'a', 'description': '', 'address': '10.0.0.1'}]}, 'a quote inside a description does not end it')

    def test_a_worker_and_a_controller_with_no_token_say_what_they_are(self):
        worker = accessproxies.boundary('', confread.scrub(BOUNDARY_WORKER))
        self.assertEqual((worker['roles'], worker['name'], worker['server'], worker['public'], worker['targets'], worker['targets_read']),
                         (['worker'], 'worker-1', '10.42.0.20:9201', 'worker.lab.example.net:9202', [], False))
        self.assertEqual(accessproxies.sentence(worker), 'Boundary (worker): its targets are kept at the controller and need a token to list')
        both = accessproxies.boundary('', BOUNDARY_CONTROLLER + BOUNDARY_WORKER)
        self.assertEqual(both['roles'], ['controller', 'worker'])
        self.assertNotIn('SECRET', json.dumps(both), 'the reader cuts again what the host should have cut')
        refused = accessproxies.boundary('Error from controller when performing list on targets\n\nError information:\n  Kind: Unauthenticated\n', confread.scrub(BOUNDARY_CONTROLLER))
        self.assertEqual((refused['roles'], refused['targets_read']), (['controller'], False), 'no token: the configuration is still read')
        self.assertEqual(accessproxies.boundary('Error from controller', '')['error'], 'not the JSON this tool prints')
        self.assertEqual(accessproxies.boundary('{"status_code": 200}')['targets'], [], 'a controller with no targets yet')

    def test_the_configuration_leaves_the_host_without_its_keys_and_database(self):
        for text in (BOUNDARY_CONTROLLER, BOUNDARY_WORKER):
            sent = subprocess.run(['awk', '-v', f're={confread.SECRET_LINE}', confread.SCRUB_AWK], input=text, capture_output=True, text=True, check=True).stdout
            self.assertNotIn('SECRET', sent)
            self.assertNotIn('postgresql', sent)
        self.assertIn('public_cluster_addr = "10.42.0.20:9201"', sent := confread.scrub(BOUNDARY_CONTROLLER))
        self.assertIn('name = "controller-1"', sent)


class Pomerium(unittest.TestCase):
    def check(self, got):
        self.assertEqual((got['tool'], got['roles'], got['server']), ('pomerium', ['proxy'], 'https://authenticate.example.com'))
        by = {t['name']: t for t in got['targets']}
        self.assertEqual(sorted(by), ['https://db.example.com', 'https://grafana.example.com', 'https://nobody.example.com', 'https://old.example.com', 'https://open.example.com',
                                      'https://status.example.com', 'https://wiki.example.com/docs', 'tcp+https://ssh.example.com:22'])
        g = by['https://grafana.example.com']
        self.assertEqual((g['address'], g['port'], g['kind'], g['access'], g['public'], g['upstream']), ('10.42.0.5', '3000', 'https', 'by policy: domain, email', False, 'http://10.42.0.5:3000'))
        s = by['https://status.example.com']
        self.assertEqual((s['address'], s['port'], s['access'], s['public']), ('localhost', '8080', 'public: anyone, without signing in', True))
        w = by['https://wiki.example.com/docs']
        self.assertEqual((w['address'], w['port'], w['access'], w['unverified']), ('wiki-1.lab', '8443', 'anyone who can sign in', True))
        self.assertEqual((by['tcp+https://ssh.example.com:22']['address'], by['tcp+https://ssh.example.com:22']['kind'], by['tcp+https://ssh.example.com:22']['access']),
                         ('nas-01', 'tcp+https', 'by policy: authenticated_user, claim'))
        self.assertEqual((by['https://open.example.com']['public'], by['https://open.example.com']['access']), (True, 'public: anyone, without signing in'), 'a policy that accepts everyone is public too')
        self.assertEqual((by['https://old.example.com']['kind'], by['https://old.example.com']['address']), ('redirect', None))
        self.assertEqual(by['https://nobody.example.com']['access'], 'no policy: nobody is let in')
        said = json.dumps(got)
        for word in ('SECRET', 'gabe', 'mallory', 'admin:', 'admins', 'googleusercontent'):
            self.assertNotIn(word, said, 'no secret, and a policy is told by what it asks for, not by who')
        self.assertEqual(accessproxies.sentence(got), 'Pomerium (proxy): 8 route(s). Public without a sign-in: https://status.example.com, https://open.example.com')
        return by

    def test_as_the_file_is_written(self):
        by = self.check(accessproxies.pomerium(POMERIUM))
        self.assertEqual((by['https://db.example.com']['access'], by['https://db.example.com']['address']), ('by policy: 2 domain(s)', None),
                         'the line with a password in it is dropped whole, and with it where that route goes')

    def test_as_the_collector_sends_it(self):
        sent = pomerium_as_collected(POMERIUM)
        for word in ('SECRET', 'gabe', 'mallory', 'admin:', 'Authorization', 'idp_client_secret', 'LS0t'):
            self.assertNotIn(word, sent)
        self.assertIn('is: someone', sent, 'an address in a policy is replaced on the host')
        self.assertIn('allow_public_unauthenticated_access: true', sent)
        self.check(accessproxies.pomerium(sent))

    def test_the_older_policy_list_and_a_file_with_no_routes(self):
        old = accessproxies.pomerium('authenticate_service_url: https://a.example.com\npolicy:\n  - from: https://x.example.com\n    to: http://10.0.0.1:80\n    allowed_users: [a@example.com, b@example.com]\n')
        self.assertEqual([(t['name'], t['access']) for t in old['targets']], [('https://x.example.com', 'by policy: 2 user(s)')])
        self.assertEqual(accessproxies.pomerium('address: :443\nidp_provider: google\n')['targets'], [])
        self.assertEqual(accessproxies.pomerium('ingress: []\n')['error'], 'not a Pomerium configuration')
        denied = accessproxies.pomerium('routes:\n  - from: https://x.example.com\n    to: http://10.0.0.1\n    policy:\n      - allow:\n          or:\n            - accept: true\n      - deny:\n          or:\n            - domain: {is: evil.example}\n')
        self.assertFalse(denied['targets'][0]['public'], 'accepting everyone and then denying some is not open to all')


class AnyText(unittest.TestCase):
    JUNK = ['', None, 7, 'x', '{', '[]', '{}', '[1]', '{"Data": 5}', '{"Data": {"Identities": [1, {"Services": [1, {"Addresses": [1, {"IsHost": true}], "Ports": [1, {"Low": "x"}, {"Low": 1}], "Permissions": 4}], "Config": 3}]}}',
            '{"items": [1, {"attributes": 5, "scope": 6, "host_source_ids": 7}, {"name": 5, "address": ["x"]}]}', '"kind": "node" "hostname": "' + 'h' * 900 + '" "addr": ":::::" "use_tunnel": true',
            'routes: 5', 'routes: [1, {from: 5}, {from: "https://a", to: 7, policy: 5}, {from: "https://b", to: [], policy: [1, {allow: 5}, {allow: {or: [1, {x: 1}]}}]}]', 'a: &a [*a]',
            'routes:\n  - from: https://user:pw@a.example.com\n    to: [[1]]\n    redirect: 5\n    prefix: 9', 'teleport: 5\nauth_service: 7', 'teleport:\n  auth_servers: []\nproxy_service:\n  enabled: yes\n  public_addr: []',
            'controller {\n  name = "' + 'n' * 900 + '"\n', 'worker {\n initial_upstreams = [\n', '[' * 5000, 'x' * (accessproxies.MAX_INPUT + 1), '{"Data": {"Identities": ' + '[' * 3000 + '}}',
            json.dumps({'items': [{'name': f't{i}', 'address': '10.0.0.1'} for i in range(2500)]}), 'routes:\n' + ''.join(f'  - from: https://r{i}.example.com\n    to: http://10.0.0.1\n' for i in range(2500))]

    def test_nothing_a_host_could_send_makes_a_reader_raise(self):
        for text in self.JUNK:
            for tool, reader in accessproxies.READERS.items():
                for got in ((reader(text),) if tool in ('openziti', 'pomerium') else (reader(text, text), reader('', text), reader(text, text, text, text) if tool == 'teleport' else reader(text))):
                    self.assertEqual(got['tool'], tool)
                    json.dumps(got)
                    self.assertIsInstance(accessproxies.sentence(got), str)
                    self.assertLessEqual(len(got.get('targets') or []), accessproxies.MAX_TARGETS)
                    for t in got.get('targets') or []:
                        self.assertLessEqual(len(t['name'] or ''), accessproxies.MAX_TEXT + 300)

    def test_a_reader_that_fails_leaves_an_error_and_the_others_are_still_read(self):
        from unittest import mock
        s = {'ziti_status': ZITI.splitlines(), 'pomerium_conf': POMERIUM.splitlines(), 'boundary_conf': BOUNDARY_WORKER.splitlines()}
        with mock.patch.dict(accessproxies.READERS, {'openziti': lambda *a: 1 / 0}):
            got = inframeasure.parse_proxies(s)
        self.assertEqual([(p['tool'], p.get('error')) for p in got], [('openziti', 'could not be read'), ('boundary', None), ('pomerium', None)])
        self.assertEqual(inframeasure.parse_proxies({}), [], 'a host with none of them has none')
        self.assertEqual(inframeasure.parse_access({}, [])['proxies'], [])


if __name__ == '__main__':
    unittest.main()
