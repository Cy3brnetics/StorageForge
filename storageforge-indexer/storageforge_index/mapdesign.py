"""Design mode: an intended topology, compared with what scans really found, and exported to what the operator's pipeline runs.

A design is a plain document:

    {'hosts': [{'name': 'nas-01', 'networks': [{'kind': 'bridge', 'name': 'br0', 'ports': 'eth1', 'address': '10.0.5.1/24'},
                                               {'kind': 'vlan', 'parent': 'eth0', 'vlan_id': 20}],
                'workloads': [{'kind': 'container', 'runtime': 'podman', 'name': 'web', 'image': 'nginx:1.27', 'publish': '127.0.0.1:8080:80'},
                              {'kind': 'vm', 'name': 'db', 'disk': '/tank/vm/db.qcow2', 'vcpus': 2, 'ram_mb': 4096}],
                'firewall': [{'action': 'allow', 'proto': 'tcp', 'port': '445', 'source': '10.0.20.0/24'}]}]}

The compare reads the index only. Exports go one way: nothing is ever imported from a script or a .tf file. The Bash and Ansible
come from the change plan the design becomes, so they run the same checked steps as a plan staged by hand. Terraform and Puppet
are for the operator's own pipeline; StorageForge never runs them, and their files hold no secrets because a design has none.
"""
from __future__ import annotations

import json
import re
import time

from . import changes, inframeasure, netfacts, workloads
from .db import Conn, loads

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}')
LIMIT = 200_000


def normalize(doc: dict) -> dict:
    """A design as the checks want it, through the same field checks every plan goes through, so a bad value is refused here."""
    hosts = []
    for h in (doc or {}).get('hosts') or []:
        name = str(h.get('name') or '').strip()
        if not name or not changes.CHECKS['host'].fullmatch(name):
            raise ValueError('every host in a design needs a name')
        hosts.append({'name': name, 'planned': bool(h.get('planned')), 'networks': [_net(n) for n in h.get('networks') or []], 'workloads': [_workload(w) for w in h.get('workloads') or []], 'firewall': [_rule(r) for r in h.get('firewall') or []]})
    plan = {'hosts': hosts, 'notes': str((doc or {}).get('notes') or '')[:2000]}
    changes.normalize({'name': 'design', 'tasks': tasks_of(plan)})
    return plan


def _net(n: dict) -> dict:
    kind = n.get('kind')
    if kind == 'bridge':
        return {'kind': 'bridge', 'name': str(n.get('name') or ''), 'ports': str(n.get('ports') or ''), 'address': str(n.get('address') or '')}
    if kind == 'vlan':
        return {'kind': 'vlan', 'parent': str(n.get('parent') or ''), 'vlan_id': str(n.get('vlan_id') or ''), 'address': str(n.get('address') or '')}
    raise ValueError(f'a network is a bridge or a vlan, not {kind!r}')


def _workload(w: dict) -> dict:
    kind = w.get('kind')
    if kind == 'container':
        return {'kind': 'container', 'runtime': str(w.get('runtime') or 'docker'), 'name': str(w.get('name') or ''), 'image': str(w.get('image') or ''), 'publish': str(w.get('publish') or ''), 'binds': str(w.get('binds') or ''), 'restart': str(w.get('restart') or ''), 'network': str(w.get('network') or '')}
    if kind == 'vm':
        return {'kind': 'vm', 'name': str(w.get('name') or ''), 'disk': str(w.get('disk') or ''), 'vcpus': str(w.get('vcpus') or ''), 'ram_mb': str(w.get('ram_mb') or ''), 'network': str(w.get('network') or ''), 'os_variant': str(w.get('os_variant') or ''), 'bridge': str(w.get('bridge') or '')}
    raise ValueError(f'a workload is a container or a vm, not {kind!r}')


def _rule(r: dict) -> dict:
    return {'action': str(r.get('action') or 'allow'), 'proto': str(r.get('proto') or 'tcp'), 'port': str(r.get('port') or ''), 'source': str(r.get('source') or ''), 'iface': str(r.get('iface') or ''), 'hook': str(r.get('hook') or 'input'), 'state': 'present', 'rollback': str(r.get('rollback') or '')}


def tasks_of(doc: dict) -> list[dict]:
    """In the order they can work: networks, then rules, then what uses them."""
    out = []
    for h in doc['hosts']:
        for n in h['networks']:
            out.append({'type': 'net-bridge' if n['kind'] == 'bridge' else 'net-vlan', 'host': h['name'], 'params': {k: v for k, v in n.items() if k != 'kind'}})
        for r in h['firewall']:
            out.append({'type': 'fw-rule', 'host': h['name'], 'params': r})
        for w in h['workloads']:
            out.append({'type': w['kind'], 'host': h['name'], 'params': {k: v for k, v in w.items() if k != 'kind'}})
    return out


def _actual(conn: Conn, name: str) -> dict:
    known = conn.scalar('SELECT hostname FROM hosts WHERE lower(hostname) = lower(:h) OR lower(ssh_host) = lower(:h)', {'h': name})
    if not known:
        return {'scanned': False, 'interfaces': {}, 'workloads': {}, 'rules': None}
    net, infra = netfacts.reading(conn, known), inframeasure.reading(conn, known)
    rows = workloads.listing(conn, known)['workloads']
    fw = (infra or {}).get('firewall')
    return {'scanned': True, 'name': known, 'interfaces': {i['name']: i for i in (net or {}).get('interfaces') or []}, 'net_read': bool(net), 'workloads': {w['name']: w for w in rows}, 'rules': fw.get('rules') if fw and fw.get('readable') else None}


def _rule_there(rules: list, r: dict) -> bool:
    from .firewall import _ports, port_matches
    ports = _ports(r['port'].replace('-', ':')) or []
    want = 'accept' if r['action'] == 'allow' else 'drop'
    for x in rules:
        action = x.get('action')
        if action == 'return' and x.get('chain') == 'DOCKER-USER':
            action = 'accept'
        if action != want or (x.get('proto') and r['proto'] not in str(x['proto']).split(',')):
            continue
        have = x.get('orig_dports') or x.get('dports') or []
        if not all(isinstance(p, int) and port_matches(have, p) for p in ports):
            continue
        if (x.get('saddr') or '') == r['source']:
            return True
    return False


def compare(conn: Conn, doc: dict) -> dict:
    """What is missing, what differs and what is there that the design does not name. Unread stays unread, never counted as missing."""
    missing, different, extra, unknown, there = [], [], [], [], []
    for h in doc['hosts']:
        a = _actual(conn, h['name'])
        name = h['name']
        if not a['scanned']:
            missing.append({'host': name, 'kind': 'host', 'what': name, 'why': 'not scanned'})
            for n in h['networks']:
                missing.append({'host': name, 'kind': n['kind'], 'what': n.get('name') or f'{n.get("parent")}.{n.get("vlan_id")}'})
            for w in h['workloads']:
                missing.append({'host': name, 'kind': w['kind'], 'what': w['name']})
            for r in h['firewall']:
                missing.append({'host': name, 'kind': 'rule', 'what': _rule_text(r)})
            continue
        for n in h['networks']:
            label = n['name'] if n['kind'] == 'bridge' else f'{n["parent"]}.{n["vlan_id"]}'
            if not a['net_read']:
                unknown.append({'host': name, 'kind': n['kind'], 'what': label, 'why': 'the network has not been read'})
            elif label not in a['interfaces']:
                missing.append({'host': name, 'kind': n['kind'], 'what': label})
            else:
                want = n.get('address')
                have = [f'{x["ip"]}/{x["prefix"]}' for x in a['interfaces'][label].get('addresses') or []]
                if want and want not in have:
                    different.append({'host': name, 'kind': n['kind'], 'what': label, 'want': want, 'have': ', '.join(have) or 'no address'})
                else:
                    there.append({'host': name, 'kind': n['kind'], 'what': label})
        named = set()
        for w in h['workloads']:
            named.add(w['name'])
            got = a['workloads'].get(w['name'])
            if not got:
                missing.append({'host': name, 'kind': w['kind'], 'what': w['name']})
            elif w['kind'] == 'container' and w['image'] and got.get('image') != w['image']:
                different.append({'host': name, 'kind': 'container', 'what': w['name'], 'want': w['image'], 'have': got.get('image')})
            elif got.get('state') not in ('running', 'shut off') and got.get('state'):
                different.append({'host': name, 'kind': w['kind'], 'what': w['name'], 'want': 'running', 'have': got.get('state')})
            else:
                there.append({'host': name, 'kind': w['kind'], 'what': w['name']})
        if h['workloads']:
            for wname, got in a['workloads'].items():
                if wname not in named:
                    extra.append({'host': name, 'kind': got['kind'], 'what': wname})
        for r in h['firewall']:
            if a['rules'] is None:
                unknown.append({'host': name, 'kind': 'rule', 'what': _rule_text(r), 'why': 'the firewall has not been read'})
            elif _rule_there(a['rules'], r):
                there.append({'host': name, 'kind': 'rule', 'what': _rule_text(r)})
            else:
                missing.append({'host': name, 'kind': 'rule', 'what': _rule_text(r)})
    return {'missing': missing, 'different': different, 'extra': extra, 'unknown': unknown, 'there': there, 'compared_at': int(time.time())}


def _rule_text(r: dict) -> str:
    return f'{r["action"]} {r["proto"]}/{r["port"]}' + (f' from {r["source"]}' if r.get('source') else '')


def missing_tasks(conn: Conn, doc: dict) -> list[dict]:
    """The change plan that closes the gap: only what the compare says is missing."""
    gap = compare(conn, doc)['missing']
    want = {(g['host'], g['kind'], g['what']) for g in gap}
    out = []
    for t in tasks_of(doc):
        p = t['params']
        what = {'net-bridge': lambda: ('bridge', p['name']), 'net-vlan': lambda: ('vlan', f'{p["parent"]}.{p["vlan_id"]}'), 'fw-rule': lambda: ('rule', _rule_text(p)),
                'container': lambda: ('container', p['name']), 'vm': lambda: ('vm', p['name'])}[t['type']]()
        if (t['host'], *what) in want:
            out.append(t)
    return out


# ── exports ─────────────────────────────────────────────────────────
def _hcl(value: str) -> str:
    """A string in HCL. ${ and %{ would be interpolated, so they are escaped too."""
    return json.dumps(str(value)).replace('${', '$${').replace('%{', '%%{')


def _slug(text: str) -> str:
    out = re.sub(r'[^A-Za-z0-9_]', '_', str(text))
    return ('r_' + out) if not out or out[0].isdigit() else out


def _ports_tf(publish: str) -> list[tuple[str, int, int, str]]:
    out = []
    for part in filter(None, (publish or '').split(',')):
        spec, _, proto = part.partition('/')
        f = spec.rsplit(':', 2)
        if len(f) == 3:
            out.append((f[0].strip('[]'), int(f[1]), int(f[2]), proto or 'tcp'))
        elif len(f) == 2:
            out.append(('0.0.0.0', int(f[0]), int(f[1]), proto or 'tcp'))
    return out


def terraform(doc: dict) -> str:
    """Neutral HCL, for Terraform or OpenTofu. Containers through kreuzwerker/docker, VMs through dmacvicar/libvirt. Podman has no
    provider we have verified, and firewall rules and networks have no good one, so they are named in comments and left out."""
    lines = ['# Written by StorageForge from a design. It goes one way: nothing reads this file back.', 'terraform {', '  required_providers {', '    docker  = { source = "kreuzwerker/docker" }', '    libvirt = { source = "dmacvicar/libvirt" }', '  }', '}', '']
    left_out = []
    for h in doc['hosts']:
        host = _slug(h['name'])
        containers = [w for w in h['workloads'] if w['kind'] == 'container' and w['runtime'] == 'docker']
        vms = [w for w in h['workloads'] if w['kind'] == 'vm']
        if containers:
            lines += [f'provider "docker" {{', f'  alias = {_hcl(host)}', f'  host  = {_hcl("ssh://" + h["name"])}', '}', '']
        if vms:
            lines += [f'provider "libvirt" {{', f'  alias = {_hcl(host)}', f'  uri   = {_hcl("qemu+ssh://" + h["name"] + "/system")}', '}', '']
        for w in containers:
            r = _slug(f'{host}_{w["name"]}')
            lines += [f'resource "docker_container" "{r}" {{', f'  provider = docker.{host}', f'  name     = {_hcl(w["name"])}', f'  image    = {_hcl(w["image"])}', f'  restart  = {_hcl(w["restart"] or "unless-stopped")}']
            for ip, ext, port, proto in _ports_tf(w['publish']):
                lines += ['  ports {', f'    internal = {port}', f'    external = {ext}', f'    ip       = {_hcl(ip)}', f'    protocol = {_hcl(proto)}', '  }']
            for bind in filter(None, w['binds'].split(',')):
                src, dst, *mode = bind.split(':')
                lines += ['  volumes {', f'    host_path      = {_hcl(src)}', f'    container_path = {_hcl(dst)}', *([f'    read_only      = true'] if mode and 'ro' in mode[0] else []), '  }']
            lines += ['}', '']
        for w in vms:
            r = _slug(f'{host}_{w["name"]}')
            lines += [f'resource "libvirt_domain" "{r}" {{', f'  provider = libvirt.{host}', f'  name     = {_hcl(w["name"])}', f'  memory   = {int(w["ram_mb"] or 2048)}', f'  vcpu     = {int(w["vcpus"] or 2)}', '  disk {', f'    file = {_hcl(w["disk"])}', '  }', '  network_interface {']
            lines += [f'    bridge = {_hcl(w["bridge"])}'] if w['bridge'] else [f'    network_name = {_hcl(w["network"] or "default")}']
            lines += ['  }', '  graphics {', '    type        = "spice"', '    listen_type = "address"', '    listen_address = "127.0.0.1"', '  }', '}', '']
        left_out += [f'{h["name"]}: podman container {w["name"]}' for w in h['workloads'] if w['kind'] == 'container' and w['runtime'] != 'docker']
        left_out += [f'{h["name"]}: {n["kind"]} {n.get("name") or n.get("parent")}' for n in h['networks']]
        left_out += [f'{h["name"]}: firewall rule {_rule_text(r)}' for r in h['firewall']]
    if left_out:
        lines += ['# Not here, because no provider we have tested does it well. The Bash or Ansible export has them:'] + [f'#   {_comment(x)}' for x in left_out] + ['']
    return '\n'.join(lines)


def _comment(text: str) -> str:
    return re.sub(r'[\r\n]+', ' ', str(text))


def _pp(value: str) -> str:
    return "'" + str(value).replace('\\', '\\\\').replace("'", "\\'") + "'"


def puppet(doc: dict) -> str:
    """Manifests using puppetlabs-docker, puppetlabs-firewall and exec for the rest. One node block for each host."""
    lines = ['# Written by StorageForge from a design. It goes one way: nothing reads this file back.', '# Needs the puppetlabs-docker and puppetlabs-firewall modules.', '']
    for h in doc['hosts']:
        lines.append(f'node {_pp(h["name"])} {{')
        for n in h['networks']:
            if n['kind'] == 'bridge':
                lines += [f'  exec {{ {_pp("sf-bridge-" + n["name"])}:', f"    command => ['/usr/sbin/ip', 'link', 'add', {_pp(n['name'])}, 'type', 'bridge'],", f"    unless  => ['/usr/sbin/ip', 'link', 'show', {_pp(n['name'])}],", '  }']
            else:
                label = f'{n["parent"]}.{n["vlan_id"]}'
                lines += [f'  exec {{ {_pp("sf-vlan-" + label)}:', f"    command => ['/usr/sbin/ip', 'link', 'add', 'link', {_pp(n['parent'])}, 'name', {_pp(label)}, 'type', 'vlan', 'id', {_pp(n['vlan_id'])}],", f"    unless  => ['/usr/sbin/ip', 'link', 'show', {_pp(label)}],", '  }']
        for i, r in enumerate(h['firewall']):
            lines += [f'  firewall {{ {_pp(f"{100 + i} storageforge {_rule_text(r)}")}:', f'    dport  => {_pp(r["port"].replace(":", "-"))},', f'    proto  => {_pp(r["proto"])},', f'    action => {_pp("accept" if r["action"] == "allow" else "drop")},',
                      *([f'    source => {_pp(r["source"])},'] if r['source'] else []), '  }']
        for w in h['workloads']:
            if w['kind'] == 'container':
                ports = [f'{ip}:{ext}:{port}/{proto}' for ip, ext, port, proto in _ports_tf(w['publish'])]
                lines += [f'  docker::run {{ {_pp(w["name"])}:', f'    image   => {_pp(w["image"])},', *([f'    ports   => [{", ".join(_pp(x) for x in ports)}],'] if ports else []),
                          *([f'    volumes => [{", ".join(_pp(x) for x in w["binds"].split(",") if x)}],'] if w['binds'] else []), '  }']
            else:
                net = f'bridge={w["bridge"]}' if w['bridge'] else f'network={w["network"] or "default"}'
                lines += [f'  exec {{ {_pp("sf-vm-" + w["name"])}:', "    command => ['/usr/bin/virt-install', '--import', '--name', " + _pp(w['name']) + ", '--disk', " + _pp(w['disk']) + ", '--vcpus', " + _pp(w['vcpus'] or '2') + ", '--memory', " + _pp(w['ram_mb'] or '2048') + ", '--network', " + _pp(net) + ", '--osinfo', " + _pp(w['os_variant'] or 'generic') + ", '--graphics', 'spice,listen=127.0.0.1', '--noautoconsole'],", f'    creates => {_pp("/etc/libvirt/qemu/" + w["name"] + ".xml")},', '  }']
        lines += ['}', '']
    return '\n'.join(lines)


# ── storing them ────────────────────────────────────────────────────
def list_designs(conn: Conn) -> list[dict]:
    return [{'id': i, 'name': n, 'owner': o, 'updated_at': u, 'hosts': len((loads(g) or {}).get('hosts') or [])} for i, n, o, g, u in conn.all('SELECT id, name, owner, graph_json, updated_at FROM map_designs ORDER BY name')]


def get_design(conn: Conn, design_id: int) -> dict:
    rows = conn.all('SELECT id, name, owner, graph_json, updated_at FROM map_designs WHERE id = :i', {'i': design_id})
    if not rows:
        raise LookupError(f'no design #{design_id}')
    r = rows[0]
    return {'id': r[0], 'name': r[1], 'owner': r[2], 'doc': loads(r[3]) or {'hosts': []}, 'updated_at': r[4]}


def save_design(conn: Conn, body: dict, actor: str) -> dict:
    name = str(body.get('name') or '').strip()
    if not NAME.fullmatch(name):
        raise ValueError('a design needs a plain name')
    doc = normalize(body.get('doc') or {})
    text = json.dumps(doc)
    if len(text) > LIMIT:
        raise ValueError('that design is too large to save')
    conn.execute("""INSERT INTO map_designs (name, owner, graph_json, updated_at) VALUES (:n, :o, :g, :t)
                    ON CONFLICT (name) DO UPDATE SET graph_json = excluded.graph_json, owner = excluded.owner, updated_at = excluded.updated_at""",
                 {'n': name, 'o': actor, 'g': text, 't': int(time.time())})
    return {'ok': True, 'id': conn.scalar('SELECT id FROM map_designs WHERE name = :n', {'n': name}), 'name': name}


def delete_design(conn: Conn, design_id: int):
    conn.execute('DELETE FROM map_designs WHERE id = :i', {'i': design_id})


