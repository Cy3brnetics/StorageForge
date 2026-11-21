"""Random tests of every parser that reads what a host or device printed. That text comes from a machine StorageForge does not control: an old
release, a broken tool, a host that is lying. A parser either reads it, keeping what it can and marking what it can't, or refuses it with a
ValueError that says why. Anything else (an AttributeError, a KeyError, an XML ParseError) ends a scan with a message nobody can act on, and
twice it lost good readings with it: one odd section threw away a host's whole network reading, and a findmnt that printed null failed the scan
before the /proc/self/mountinfo fallback could run.

Two kinds of input: readings built from each parser's own section names and words, and the real fixtures under tests/fixtures with lines
dropped, repeated, swapped, cut short or spliced with junk."""
import json
import unittest
from pathlib import Path

from props import HAVE, given, settings, st, scaled
from storageforge_index import (apidockhand, apikomodo, apipangolin, apipbs, apipdm, apiportainer, apipve, apireadback, apitruenas, apixo, authkeys, cisco, clamav, firewall, gitrepos, health, hostconfig, hostlogs, inframeasure, netconfig, netconsole, netfacts, netscan, openwrt, payloads,
                                pfsense, pkglist, preflight, pstore, remote, routeros, secplus, security, snapfind, steps_services, updates)

FIX = Path(__file__).parent / 'fixtures'

# words the formats use, so random lines get past the first check of a parser and into the parts that read fields
WORDS = ['', ' ', '\t', ':', '=', '|', ',', '/', '-', '0', '1', '65535', '-1', '99999999999999999999', 'nan', 'inf', 'yes', 'no', 'true', 'null', '{', '}', '[', ']',
         '"', "'", '\\', '\x00', '\u202e', '²', 'é', 'tcp', 'udp', 'LISTEN', '0.0.0.0', '::', '10.0.0.1/24', '10.0.0.1', 'eth0', 'lo', '*', 'default', 'via',
         'dev', 'src', 'proto', 'inet', 'inet6', 'state', 'UP', 'name', 'type', 'id', 'MESSAGE', '__REALTIME_TIMESTAMP', 'PRIORITY', '_SYSTEMD_UNIT', 'Package',
         'Version', '@@', '<', '>', '/>', '<?xml version="1.0"?>', 'interface', 'access-list', 'permit', 'deny', 'any', 'host', 'eq', 'ip', 'nameserver', 'search']
KEYS = ['ifname', 'addr_info', 'local', 'prefixlen', 'family', 'dst', 'gateway', 'dev', 'name', 'type', '.id', 'address', 'interface', 'chain', 'action', 'disabled',
        'mtu', 'operstate', 'link_type', 'master', 'protocol', 'dst-port', 'src-address', 'filesystems', 'target', 'children', 'release', 'version', 'vlans', 'linkinfo']

word = st.sampled_from(WORDS)
line = st.lists(word | st.text(max_size=8), max_size=10).map(' '.join)
json_value = st.recursive(st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=8),
                          lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.sampled_from(KEYS) | st.text(max_size=5), inner, max_size=5),
                          max_leaves=12).map(json.dumps)
body = st.lists(line | json_value, max_size=8).map('\n'.join)
free_text = body | st.text(max_size=300)


def reading(sections):
    """Text in the @@section form the scan scripts print, from these section names."""
    return st.lists(st.tuples(st.sampled_from(list(sections)), body), max_size=8).map(lambda xs: ''.join(f'@@{name}\n{text}\n' for name, text in xs))


@st.composite
def mutated(draw, text: str):
    """A real reading, damaged the way output gets damaged."""
    lines = text.splitlines()
    for _ in range(draw(st.integers(1, 6))):
        if not lines:
            break
        i = draw(st.integers(0, len(lines) - 1))
        op = draw(st.sampled_from(['drop', 'repeat', 'swap', 'junk', 'insert', 'cut', 'blank']))
        if op == 'drop':
            del lines[i]
        elif op == 'repeat':
            lines.insert(i, lines[i])
        elif op == 'swap':
            j = draw(st.integers(0, len(lines) - 1))
            lines[i], lines[j] = lines[j], lines[i]
        elif op == 'junk':
            words = lines[i].split(' ')
            words[draw(st.integers(0, len(words) - 1))] = draw(word | json_value)
            lines[i] = ' '.join(words)
        elif op == 'insert':
            lines.insert(i, draw(line | json_value))
        elif op == 'cut':
            lines = lines[:i] + [lines[i][:draw(st.integers(0, len(lines[i])))]]
        else:
            lines[i] = ''
    return '\n'.join(lines)


# parser: what it may do with text it can't read. 'reads' never raises; 'refuses' may raise ValueError and nothing else.
READS = {
    'hostlogs.parse': hostlogs.parse, 'pstore.parse': pstore.parse, 'netconsole.parse_packet': lambda t: netconsole.parse_packet(t.encode('utf-8', 'surrogatepass')), 'updates.parse': updates.parse, 'health.parse_report': health.parse_report, 'health.parse_snapshots': health.parse_snapshots,
    'snapfind.parse': snapfind.parse, 'steps_services.parse': steps_services.parse, 'netfacts.parse_listeners': netfacts.parse_listeners,
    'netconfig.parse_netplan': netconfig.parse_netplan, 'netconfig.parse_networkd': netconfig.parse_networkd, 'netconfig.parse_nm': netconfig.parse_nm, 'netconfig.parse_ifupdown': netconfig.parse_ifupdown,
    'cisco.parse_running': cisco.parse_running, 'cisco.parse_acls': cisco.parse_acls, 'cisco.parse_brief': cisco.parse_brief, 'cisco.parse_routes': cisco.parse_routes,
    'cisco.parse_arp': cisco.parse_arp, 'cisco.parse_cdp': cisco.parse_cdp, 'cisco.parse_lldp': cisco.parse_lldp, 'cisco.parse_vlans': cisco.parse_vlans,
    'cisco.parse_counters': cisco.parse_counters, 'routeros.parse_terse': routeros.parse_terse, 'routeros.parse_table': routeros.parse_table,
    'firewall.parse_nft': firewall.parse_nft, 'firewall.parse_iptables': firewall.parse_iptables, 'firewall.parse_ufw': firewall.parse_ufw,
    'firewall.parse_firewalld': firewall.parse_firewalld, 'payloads.parse_fstab': payloads.parse_fstab, 'payloads.parse_df': payloads.parse_df,
    'payloads.parse_zpool_status': payloads.parse_zpool_status, 'payloads.parse_nfs_exports': payloads.parse_nfs_exports, 'payloads.parse_smb_conf': payloads.parse_smb_conf,
    'remote.parse_findmnt': remote.parse_findmnt, 'remote.parse_mountinfo': remote.parse_mountinfo, 'security.parse_event_line': security.parse_event_line,
    'security.parse_entropy': security.parse_entropy, 'authkeys.parse': authkeys.parse, 'clamav.parse_report': clamav.parse_report,
    'hostconfig.parse_configs': hostconfig.parse_configs, 'hostconfig.parse_accounts': hostconfig.parse_accounts, 'hostconfig.parse_fstab_lines': hostconfig.parse_fstab_lines,
    'gitrepos.parse_survey': gitrepos.parse_survey, 'preflight.parse_probe': preflight.parse_probe, 'pkglist.parse': pkglist.parse,
    'openwrt.parse_uci': openwrt.parse_uci, 'openwrt.parse_leases': openwrt.parse_leases, 'openwrt.parse_arp': openwrt.parse_arp, 'openwrt.parse_netstat': openwrt.parse_netstat,
    'pfsense.parse_netstat': pfsense.parse_netstat, 'pfsense.parse_arp': pfsense.parse_arp, 'pfsense.parse_sockstat': pfsense.parse_sockstat,
    'cisco.parse_ace': lambda t: [cisco.parse_ace(x, 'acl', n) for n, x in enumerate(t.splitlines())],
    # these take the lines of one section
    'secplus.parse_sessions': lambda t: secplus.parse_sessions(t.splitlines()), 'secplus.parse_falco': lambda t: secplus.parse_falco(t.splitlines()),
    'inframeasure.parse_listeners': lambda t: inframeasure.parse_listeners(t.splitlines()), 'inframeasure.parse_storage_clients': lambda t: inframeasure.parse_storage_clients(t.splitlines()),
    'inframeasure.parse_wireguard': lambda t: inframeasure.parse_wireguard(t.splitlines()), 'inframeasure.parse_tailscale': lambda t: inframeasure.parse_tailscale(t.splitlines()),
    'inframeasure.parse_overlays': lambda t: inframeasure.parse_overlays({k: t.splitlines() for k in ('tailscale_json', 'netbird_json', 'headscale_json', 'openvpn_status', 'zt_info', 'zt_networks', 'zt_peers',
                                                                                                    'openvpn_pki', 'nebula_conf', 'nebula_cert', 'netmaker_json', 'swan_sas', 'swan_conns')}),
    'inframeasure.parse_proxies': lambda t: inframeasure.parse_proxies({k: t.splitlines() for k in ('ziti_status', 'tp_status', 'tp_nodes', 'tp_conf', 'tp_login', 'boundary_targets', 'boundary_conf', 'pomerium_conf')}),
    'inframeasure.parse_tunnels': lambda t: inframeasure.parse_tunnels({k: t.splitlines() for k in ('cloudflared', 'frp', 'ngrok', 'tunnel_procs', 'tunnel_cmdline')}),
    'inframeasure.parse_proxy_routes': lambda t: inframeasure.parse_proxy_routes(t.splitlines(), t.splitlines()[::-1]),
    'apireadback.parse_permissions': apireadback.parse_permissions, 'apireadback.parse_token_info': apireadback.parse_token_info,
    'apipve.parse_version': apipve.parse_version, 'apipve.parse_resources': apipve.parse_resources, 'apipve.parse_backup_jobs': apipve.parse_backup_jobs,
    'apipve.parse_backups': apipve.parse_backups,
    'apipbs.parse_version': apipbs.parse_version, 'apipbs.parse_usage': apipbs.parse_usage, 'apipbs.parse_config': apipbs.parse_config,
    'apipbs.parse_groups': apipbs.parse_groups, 'apipbs.parse_snapshots': apipbs.parse_snapshots, 'apipbs.parse_jobs': apipbs.parse_jobs,
    'apipdm.parse_version': apipdm.parse_version, 'apipdm.parse_remotes': apipdm.parse_remotes, 'apipdm.parse_resources': apipdm.parse_resources,
    **{f'apitruenas.{n}': getattr(apitruenas, n) for n in dir(apitruenas) if n.startswith('parse_')},     # each takes the JSON text of one call's result
    **{f'apixo.{n}': getattr(apixo, n) for n in dir(apixo) if n.startswith('parse_')},
    **{f'apidockhand.{n}': getattr(apidockhand, n) for n in dir(apidockhand) if n.startswith('parse_')},
    **{f'apiportainer.{n}': getattr(apiportainer, n) for n in dir(apiportainer) if n.startswith('parse_')},
    **{f'apikomodo.{n}': getattr(apikomodo, n) for n in dir(apikomodo) if n.startswith('parse_')},
    **{f'apipangolin.{n}': getattr(apipangolin, n) for n in dir(apipangolin) if n.startswith('parse_')},
}
SECTIONED_READS = {'netfacts.parse': (netfacts.parse, netfacts.SECTIONS), 'inframeasure.parse': (inframeasure.parse, inframeasure.SECTIONS),
                   'remote.parse_sections': (remote.parse_sections, remote.SECTIONS), 'security.parse_measure': (security.parse_measure, getattr(security, 'SECTIONS', ('end',)))}
REFUSES = {'netscan.parse_xml': netscan.parse_xml, 'pfsense.load_xml': pfsense.load_xml}
SECTIONED_REFUSES = {'openwrt.parse': (openwrt.parse, openwrt.ALL_SECTIONS), 'pfsense.parse': (pfsense.parse, pfsense.SECTIONS)}


def holds(test, name, fn, text, may_refuse):
    try:
        fn(text)
    except ValueError as exc:
        if not may_refuse:
            test.fail(f'{name} threw ValueError({exc}) where it should read what it can: {text[:300]!r}')
        test.assertTrue(str(exc), f'{name} refused with no reason')
    except Exception as exc:
        test.fail(f'{name} threw {type(exc).__name__}({exc}): it should read what it can{" or refuse with a ValueError" if may_refuse else ""}. Input: {text[:300]!r}')


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class AnyText(unittest.TestCase):
    @settings(max_examples=scaled(25, 1000))
    @given(st.sampled_from(sorted(READS)), free_text)
    def test_a_parser_reads_any_text_without_throwing(self, name, text):
        holds(self, name, READS[name], text, False)

    @settings(max_examples=scaled(25, 1000))
    @given(st.sampled_from(sorted(REFUSES)), free_text)
    def test_an_xml_reader_reads_or_refuses_with_a_reason(self, name, text):
        holds(self, name, REFUSES[name], text, True)

    @settings(max_examples=scaled(40, 2000))
    @given(st.data())
    def test_a_reading_in_sections_is_read_or_refused_with_a_reason(self, data):
        name = data.draw(st.sampled_from(sorted(SECTIONED_READS) + sorted(SECTIONED_REFUSES)))
        fn, sections = SECTIONED_READS.get(name) or SECTIONED_REFUSES[name]
        holds(self, name, fn, data.draw(reading(sections)), name in SECTIONED_REFUSES)


ROS_FILES = {'address': 'ip_address', 'interface': 'interface', 'route': 'ip_route', 'filter': 'ip_firewall_filter', 'nat': 'ip_firewall_nat', 'neighbor': 'ip_neighbor',
             'bridge_port': 'interface_bridge_port', 'bridge_vlan': 'interface_bridge_vlan', 'vlan': 'interface_vlan', 'bonding': 'interface_bonding',
             'lease': 'ip_dhcp-server_lease', 'arp': 'ip_arp', 'address_list': 'ip_firewall_address-list', 'service': 'ip_service', 'iface_list': 'interface_list_member',
             'address6': 'ipv6_address', 'route6': 'ipv6_route'}
CISCO = {k: (FIX / 'cisco' / f'{k}.txt').read_text() for k in ('running', 'brief', 'route', 'acl')}
OPENWRT = (FIX / 'openwrt' / 'reading.txt').read_text()
PFSENSE_XML = (FIX / 'pfsense' / 'config.xml').read_text()


@unittest.skipUnless(HAVE, 'needs hypothesis (pip install hypothesis; CI has it)')
class DamagedFixtures(unittest.TestCase):
    """The same real readings test_routers checks field by field, damaged. What comes back still has the shape the map and the what-if read."""

    @settings(max_examples=scaled(30, 800))
    @given(st.sampled_from(sorted(ROS_FILES)), st.data())
    def test_a_damaged_routeros_table_still_gives_a_network_and_a_firewall(self, key, data):
        tables = {k: routeros.parse_table((FIX / 'routeros' / f'{v}.json').read_text()) for k, v in ROS_FILES.items()}
        tables[key] = routeros.parse_table(data.draw(mutated((FIX / 'routeros' / f'{ROS_FILES[key]}.json').read_text())))
        net, fw = routeros.network(tables), routeros.firewall(tables)
        self.assertIsInstance(net['interfaces'], list)
        self.assertIsInstance(fw['rules'], list)

    @settings(max_examples=scaled(30, 800))
    @given(st.sampled_from(sorted(CISCO)), st.data())
    def test_a_damaged_cisco_reading_still_gives_a_model(self, key, data):
        texts = dict(CISCO, **{key: data.draw(mutated(CISCO[key]))})
        m = cisco.model(texts)
        self.assertIsInstance(m, dict)

    @settings(max_examples=scaled(30, 800))
    @given(mutated(OPENWRT))
    def test_a_damaged_openwrt_reading_is_read_or_refused_with_a_reason(self, text):
        holds(self, 'openwrt.parse', openwrt.parse, text, True)

    @settings(max_examples=scaled(30, 800))
    @given(mutated(PFSENSE_XML))
    def test_a_damaged_pfsense_config_is_read_or_refused_with_a_reason(self, xml):
        holds(self, 'pfsense.parse', pfsense.parse, f'@@config\n{xml}\n@@version\n2.7.2\n@@end\n', True)


class FoundByTheseTests(unittest.TestCase):
    """What the random tests found, pinned as plain inputs. These run with or without Hypothesis."""

    def test_one_odd_network_section_is_unreadable_and_the_rest_is_kept(self):
        good = '[{"ifname": "eth0", "operstate": "UP", "mtu": 1500}]'
        got = netfacts.parse(f'@@link\n{good}\n@@addr\n[false]\n@@route\n[1, 2]\n@@neigh\n[]\n@@listen\n@@end\n')
        self.assertEqual([i['name'] for i in got['interfaces']], ['eth0'])
        self.assertIn('addresses', got['unreadable'])
        self.assertIn('routes', got['unreadable'])
        self.assertNotIn('neighbours', got['unreadable'])

    def test_a_findmnt_that_is_not_an_object_gives_way_to_mountinfo(self):
        for text in ('null', '[]', '{"filesystems": 3}', '{"filesystems": [null, {"target": "/", "fstype": "ext4"}]}'):
            with self.subTest(text):
                self.assertIsInstance(remote.parse_findmnt(text), list)
        self.assertEqual([m.target for m in remote.parse_findmnt('{"filesystems": [null, {"target": "/", "fstype": "ext4"}]}')], ['/'])

    def test_a_size_df_printed_that_cannot_be_read_is_unknown_and_the_other_rows_stay(self):
        rows = payloads.parse_df('Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 10G 2G ?? 20% /\n/dev/sdb1 \u00b2 1G 1G 50% /srv\n')
        self.assertEqual([(r['target'], r['avail']) for r in rows], [('/', None), ('/srv', 1 << 30)])
        self.assertIsNone(rows[1]['total'])

    def test_a_routeros_count_that_is_not_a_number_reads_as_zero(self):
        self.assertEqual(routeros.counters([{'name': 'ether1', 'rx-byte': '{"', 'tx-byte': '7'}, None, 'x'])[0]['rx_bytes'], 0)
        self.assertEqual(routeros.counters([{'name': 'ether1', 'tx-byte': '7'}])[0]['tx_bytes'], 7)

    def test_xml_that_does_not_parse_is_refused_with_a_value_error(self):
        for fn in (pfsense.load_xml, netscan.parse_xml):
            with self.subTest(fn.__module__), self.assertRaisesRegex(ValueError, 'does not parse'):
                fn('<a><b></a>')

    def test_a_damaged_ubus_dump_loses_that_entry_and_keeps_the_rest(self):
        text = OPENWRT.replace('"route": [', '"route": [null, {"target": "x", "mask": "y"}, ', 1)
        if text == OPENWRT:
            self.skipTest('the fixture has no ubus route list to damage')
        self.assertIsInstance(openwrt.parse(text)['net']['routes'], list)


class TheTablesAreComplete(unittest.TestCase):
    def test_every_parse_function_that_reads_host_output_is_in_a_table_or_named_as_a_validator(self):
        """A new parser gets a contract the day it is written. Validators of what an operator typed raise by design and are listed apart."""
        import re
        root = Path(__file__).resolve().parents[1] / 'storageforge_index'
        # what an operator typed, refused with an error by design; the network language has test_props_netlang; parse_access takes a dict, not text
        validators = {'capacity.parse_size', 'remotes.parse_endpoint', 'scheduler.parse_cron', 'cli.parse_age', 'scansign.parse_switch', 'rostranspiler.parse',
                      'inframeasure.parse_access'}
        known = set(READS) | set(SECTIONED_READS) | set(REFUSES) | set(SECTIONED_REFUSES) | validators
        found = {f'{p.stem}.{m}' for p in root.glob('*.py') for m in re.findall(r'^def (parse\w*)\(', p.read_text(), re.M)}
        self.assertEqual(sorted(found - known), [], 'give each a contract in test_props_parsers.py (READS, REFUSES, ...) or list it as a validator')


if __name__ == '__main__':
    unittest.main()
