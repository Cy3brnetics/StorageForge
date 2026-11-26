"""Workload exports (roadmap section 6; infrastructure-platform-roadmap.md 7.5): a change plan's workload steps as Terraform or OpenTofu
(main.tf) and as a Puppet manifest, for the operator's own pipeline. Read straight from the plan, never from the Bash or from each other.

Terraform and OpenTofu take the same HCL: the providers are kreuzwerker/docker for containers and stacks, lxc/incus for Incus instances and
dmacvicar/libvirt for VMs. Puppet uses puppetlabs-docker (docker::run, docker_compose) where it has a type, and exec with an unless guard
where there is none (Incus, LXC, libvirt), so a second run changes nothing.

What has no counterpart is said in a comment where it would be, never dropped silently: a firewall rule (allow_from) goes through
storageforge-fwrules, which neither tool drives. No export holds a secret: the steps that are exported carry none (a compose file with a
secret written into it is refused by its check), and a VM's login key is a public key.

Apply inside StorageForge always goes through the signed runner; these files are for running elsewhere.
"""
from __future__ import annotations

import datetime as dt
import json
import re

from . import changes
from .steps_workloads import compose_model, incus_ports, labels_of, parse_publish

KINDS = ('container', 'stack', 'incus', 'lxc', 'vm-create', 'vm-iso', 'vm')
TARGETS = ('terraform', 'opentofu', 'puppet')


REF = '@@ref '         # a value that is a reference to another resource, written bare. No value a step takes holds a space after @@ref


def _refs(text: str) -> str:
    return re.sub(r'"@@ref ([A-Za-z0-9_.]+)"', r'\1', text)


def _id(name: str) -> str:
    """A resource name HCL and Puppet both take."""
    s = re.sub(r'[^A-Za-z0-9_]', '_', name or 'x')
    return s if re.match(r'[A-Za-z_]', s) else f'w_{s}'


def _publish(text: str | None) -> list[dict]:
    """The container step's '127.0.0.1:8080:80/tcp,8443:443' as {ip, external, internal, protocol}."""
    return [{'ip': r['bind'], 'external': int(r['published']), 'internal': int(r['target']), 'protocol': r['proto']} for r in parse_publish(text)[0] if r['published']]


def _binds(text: str | None) -> list[dict]:
    out = []
    for part in filter(None, (text or '').split(',')):
        f = part.split(':')
        if len(f) >= 2:
            out.append({'host_path': f[0], 'container_path': f[1], 'read_only': 'ro' in (f[2] if len(f) > 2 else '').split(',')})
    return out


# ── one model of what each step makes, both renderers read it ───────
def model(plan: dict) -> list[dict]:
    """[{'kind', 'host', 'name', ...}] for the workload steps of a plan; other steps are listed as skipped."""
    out = []
    for t in changes.normalize(plan)['tasks']:
        p, k = t['params'], t['type']
        if k not in KINDS:
            out.append({'kind': 'skipped', 'step': k, 'host': t['host'], 'title': changes.title(t)})
            continue
        base = {'kind': k, 'host': t['host'], 'name': p.get('name') or ''}
        if k == 'container':
            out.append({**base, 'runtime': p['runtime'], 'image': p['image'], 'ports': _publish(p['publish']), 'volumes': _binds(p['binds']),
                        'restart': p['restart'] or 'unless-stopped', 'network': p['network'], 'labels': {'storageforge.managed': 'true'}})
        elif k == 'stack':
            m = compose_model(p['compose'])
            labels, _ = labels_of(p['labels'])
            services = []
            for sname, s in m['services'].items():
                services.append({'name': f'{p["name"]}-{sname}', 'service': sname, 'image': s['image'] or '',
                                 'ports': [{'ip': x['bind'], 'external': int(x['published']), 'internal': int(x['target'] or x['published']), 'protocol': x['proto']}
                                           for x in s['ports'] if x['published'].isdigit() and (x['target'] or x['published']).isdigit()],
                                 'volumes': [{'host_path': b['source'], 'container_path': b['target'], 'read_only': 'ro' in b['options'].split(',')} for b in s['binds']]})
            out.append({**base, 'runtime': p['runtime'], 'dir': p['dir'] or f'/srv/stacks/{p["name"]}', 'compose': p['compose'], 'services': services,
                        'labels': {'storageforge.managed': 'true', 'storageforge.stack': p['name'], **labels}, 'allow_from': p['allow_from']})
        elif k == 'incus':
            ports, _ = incus_ports(p['publish'])
            labels, _ = labels_of(p['labels'])
            config = {**({'limits.cpu': p['cpus']} if p['cpus'] else {}), **({'limits.memory': f'{p["memory_mb"]}MiB'} if p['memory_mb'] else {}),
                      **({'security.nesting': 'true'} if p['nesting'] else {}), **({'boot.autostart': 'true'} if p['autostart'] else {}),
                      'user.storageforge.managed': 'true', **{f'user.{a}': b for a, b in labels.items()}}
            out.append({**base, 'image': p['image'] or 'images:debian/13', 'type': 'virtual-machine' if p['type'] == 'vm' else 'container',
                        'profiles': [x for x in (p['profiles'] or 'default').split(',') if x], 'pool': p['pool'], 'network': p['network'], 'config': config,
                        'proxies': [{'name': f'sf-port-{x["proto"]}-{x["published"]}', 'listen': f'{x["proto"]}:{x["bind"]}:{x["published"]}',
                                     'connect': f'{x["proto"]}:127.0.0.1:{x["target"]}'} for x in ports], 'allow_from': p['allow_from']})
        elif k == 'lxc':
            out.append({**base, 'distro': p['distro'], 'release': p['release'], 'arch': p['arch'] or 'amd64', 'network': p['network'], 'bridge': p['bridge'],
                        'autostart': bool(p['autostart'])})
        else:
            from . import steps_vm, steps_vmiso
            vm = {**base, 'vcpus': int(p.get('vcpus') or 2), 'memory_mb': int(p.get('ram_mb') or (4096 if k == 'vm-iso' else 2048)),
                  'network': p.get('network') or 'default', 'bridge': p.get('bridge') or '', 'pool': p.get('pool') or 'default'}
            if k == 'vm-create':
                img = steps_vm.IMAGES.get(p['image'])
                vm.update(source=p['image_url'] if p['image'] == 'custom' else (img[1] if img else ''), disk_gb=int(p['disk_gb'] or 20),
                          user=p['user'] or 'admin', ssh_key=p['ssh_key'], firmware=p['firmware'] or 'bios')
            elif k == 'vm-iso':
                iso = steps_vmiso.ISOS.get(p['iso'])
                vm.update(iso=p['iso_url'] if p['iso'] == 'custom' else '', iso_list=iso[1] if iso else '', disk_gb=int(p['disk_gb'] or 32), firmware=p['firmware'] or 'bios')
            else:
                vm.update(disk=p['disk'], disk_gb=0, firmware='bios')
            out.append(vm)
    return out


# ── HCL ─────────────────────────────────────────────────────────────
def _hstr(s) -> str:
    return json.dumps(str(s)).replace('${', '$${').replace('%{', '%%{')


def _hval(v, ind: str) -> str:
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return '[' + ', '.join(_hval(x, ind) for x in v) + ']'
    if isinstance(v, dict):
        inner = ind + '  '
        return '{\n' + ''.join(f'{inner}{_hstr(k)} = {_hval(x, inner)}\n' for k, x in v.items()) + ind + '}'
    return _hstr(v)


def _block(head: str, body: list, ind: str = '') -> str:
    """body: [('attr', name, value) | ('block', head, body) | ('comment', text)]."""
    out = [f'{ind}{head} {{']
    inner = ind + '  '
    for item in body:
        if item[0] == 'attr':
            out.append(f'{inner}{item[1]} = {_hval(item[2], inner)}')
        elif item[0] == 'comment':
            out.append(f'{inner}# {item[1]}')
        else:
            out.append(_block(item[1], item[2], inner))
    out.append(f'{ind}}}')
    return '\n'.join(out)


def _docker_container(rid: str, name: str, image: str, ports, volumes, labels: dict, restart: str = 'unless-stopped', network: str = '') -> list[str]:
    body = [('attr', 'name', name), ('attr', 'image', f'{REF}docker_image.{rid}.image_id'), ('attr', 'restart', restart)]
    for p in ports:
        body.append(('block', 'ports', [('attr', 'internal', p['internal']), ('attr', 'external', p['external']), ('attr', 'ip', p['ip']), ('attr', 'protocol', p['protocol'])]))
    for v in volumes:
        body.append(('block', 'volumes', [('attr', 'host_path', v['host_path']), ('attr', 'container_path', v['container_path']), ('attr', 'read_only', v['read_only'])]))
    for k, v in labels.items():
        body.append(('block', 'labels', [('attr', 'label', k), ('attr', 'value', v)]))
    if network:
        body.append(('block', 'networks_advanced', [('attr', 'name', network)]))
    return [_block(f'resource "docker_image" "{rid}"', [('attr', 'name', image), ('attr', 'keep_locally', True)]), _block(f'resource "docker_container" "{rid}"', body)]


def terraform(plan: dict, target: str = 'terraform') -> str:
    items = model(plan)
    used = {i['kind'] for i in items}
    providers = []
    if used & {'container', 'stack'}:
        providers.append(('docker', 'kreuzwerker/docker', '~> 3.0'))
    if 'incus' in used:
        providers.append(('incus', 'lxc/incus', '~> 0.3'))
    if used & {'vm-create', 'vm-iso', 'vm'}:
        providers.append(('libvirt', 'dmacvicar/libvirt', '~> 0.8'))
    tool = 'OpenTofu' if target == 'opentofu' else 'Terraform'
    cmd = 'tofu' if target == 'opentofu' else 'terraform'
    out = [f'# {tool} for the workloads of StorageForge change plan "{changes.one_line(plan["name"])}", generated {dt.datetime.now():%Y-%m-%d %H:%M}.\n'
           f'#   {cmd} init && {cmd} plan        # read it first; StorageForge itself applies through its signed runner, not this\n'
           '# One provider block per kind: each points at the host its steps are on (docker over ssh://, an incus remote, qemu+ssh:// for libvirt).']
    if providers:
        out.append(_block('terraform', [('block', 'required_providers', [('attr', n, {'source': s, 'version': v}) for n, s, v in providers])]))
        of = {'docker': {'container', 'stack'}, 'incus': {'incus'}, 'libvirt': {'vm-create', 'vm-iso', 'vm'}}
        for n, _, _ in providers:
            hosts = sorted({i['host'] for i in items if i['kind'] in of[n]})
            conf = {'docker': [('attr', 'host', f'ssh://root@{hosts[0]}')], 'libvirt': [('attr', 'uri', f'qemu+ssh://root@{hosts[0]}/system')],
                    'incus': [('comment', f'the default remote must be {hosts[0]} (incus remote add, then incus remote switch)')]}[n]
            if len(hosts) > 1:
                conf.append(('comment', f'its steps are on {", ".join(hosts)}: add an aliased provider for each host after the first, and a provider line to its resources'))
            out.append(_block(f'provider "{n}"', conf))
    for i in items:
        if i['kind'] == 'skipped':
            out.append(f'# step {i["step"]} on {i["host"]} ({i["title"]}) has no counterpart here, and is left out')
            continue
        rid = _id(f'{i["host"]}_{i["name"]}')
        if i['kind'] == 'container':
            out += _docker_container(rid, i['name'], i['image'], i['ports'], i['volumes'], i['labels'], i['restart'], i['network'])
        elif i['kind'] == 'stack':
            out.append(f'# stack {i["name"]}: each compose service as a container. The compose file itself is what StorageForge deploys, in {i["dir"]}')
            if i['allow_from']:
                out.append(f'# only {i["allow_from"]} may reach what it publishes: that rule is written by storageforge-fwrules, not here')
            for s in i['services']:
                out += _docker_container(_id(f'{rid}_{s["service"]}'), s['name'], s['image'], s['ports'], s['volumes'], {**i['labels'], 'com.docker.compose.service': s['service']})
        elif i['kind'] == 'incus':
            body = [('attr', 'name', i['name']), ('attr', 'image', i['image']), ('attr', 'type', i['type']), ('attr', 'profiles', i['profiles']), ('attr', 'config', i['config'])]
            if i['pool']:
                body.append(('block', 'device', [('attr', 'name', 'root'), ('attr', 'type', 'disk'), ('attr', 'properties', {'path': '/', 'pool': i['pool']})]))
            if i['network']:
                body.append(('block', 'device', [('attr', 'name', 'eth0'), ('attr', 'type', 'nic'), ('attr', 'properties', {'network': i['network']})]))
            for x in i['proxies']:
                body.append(('block', 'device', [('attr', 'name', x['name']), ('attr', 'type', 'proxy'), ('attr', 'properties', {'listen': x['listen'], 'connect': x['connect']})]))
            if i['allow_from']:
                body.append(('comment', f'only {i["allow_from"]} may reach its proxy ports: a fence storageforge-fwrules writes, not this'))
            out.append(_block(f'resource "incus_instance" "{rid}"', body))
        elif i['kind'] == 'lxc':
            out.append(f'# LXC container {i["name"]} on {i["host"]}: plain LXC has no provider. Use the Bash export, or Incus')
        else:
            out += _libvirt(rid, i)
    return _refs('\n\n'.join(out)) + '\n'


def _libvirt(rid: str, i: dict) -> list[str]:
    out = []
    disks = []
    if i['kind'] == 'vm-create':
        out.append(_block(f'resource "libvirt_volume" "{rid}_base"', [('attr', 'name', f'{i["name"]}-base.qcow2'), ('attr', 'pool', i['pool']), ('attr', 'source', i['source'])]))
        out.append(_block(f'resource "libvirt_volume" "{rid}_root"', [('attr', 'name', f'{i["name"]}-root.qcow2'), ('attr', 'pool', i['pool']),
                                                                        ('attr', 'base_volume_id', f'{REF}libvirt_volume.{rid}_base.id'), ('attr', 'size', i['disk_gb'] * 2**30)]))
        user = '#cloud-config\n' + json.dumps({'hostname': i['name'], 'ssh_pwauth': False, 'users': [{'name': i['user'], 'ssh_authorized_keys': [i['ssh_key']], 'sudo': 'ALL=(ALL) NOPASSWD:ALL'}]})
        out.append(_block(f'resource "libvirt_cloudinit_disk" "{rid}_seed"', [('attr', 'name', f'{i["name"]}-seed.iso'), ('attr', 'pool', i['pool']), ('attr', 'user_data', user)]))
        disks.append([('attr', 'volume_id', f'{REF}libvirt_volume.{rid}_root.id')])
    elif i['kind'] == 'vm-iso':
        out.append(_block(f'resource "libvirt_volume" "{rid}_root"', [('attr', 'name', f'{i["name"]}-root.qcow2'), ('attr', 'pool', i['pool']), ('attr', 'size', i['disk_gb'] * 2**30)]))
        disks.append([('attr', 'volume_id', f'{REF}libvirt_volume.{rid}_root.id')])
        if i['iso']:
            disks.append([('attr', 'url', i['iso'])])
        else:
            out.append(f'# the ISO is the newest of its release in {i["iso_list"]}: give its URL to the second disk of {i["name"]}')
    else:
        disks.append([('attr', 'file', i['disk'])])
    body = [('attr', 'name', i['name']), ('attr', 'memory', i['memory_mb']), ('attr', 'vcpu', i['vcpus'])]
    if i['kind'] == 'vm-create':
        body.append(('attr', 'cloudinit', f'{REF}libvirt_cloudinit_disk.{rid}_seed.id'))
    if i.get('firmware', '').startswith('uefi'):
        body.append(('attr', 'firmware', '/usr/share/OVMF/OVMF_CODE.fd'))
        body.append(('comment', 'the firmware path differs between distributions: check it on the host'))
    for d in disks:
        body.append(('block', 'disk', d))
    body.append(('block', 'network_interface', [('attr', 'bridge', i['bridge'])] if i['bridge'] else [('attr', 'network_name', i['network'])]))
    body.append(('block', 'graphics', [('attr', 'type', 'spice'), ('attr', 'listen_type', 'address'), ('attr', 'listen_address', '127.0.0.1')]))
    body.append(('block', 'console', [('attr', 'type', 'pty'), ('attr', 'target_port', '0'), ('attr', 'target_type', 'serial')]))
    out.append(_block(f'resource "libvirt_domain" "{rid}"', body))
    return out


# ── Puppet ──────────────────────────────────────────────────────────
def _pq(s) -> str:
    return "'" + str(s).replace('\\', '\\\\').replace("'", "\\'") + "'"


def _pval(v) -> str:
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return '[' + ', '.join(_pval(x) for x in v) + ']'
    return _pq(v)


def _resource(rtype: str, title: str, attrs: dict) -> str:
    width = max((len(k) for k in attrs), default=0)
    lines = [f'{rtype} {{ {_pq(title)}:'] + [f'  {k.ljust(width)} => {_pval(v)},' for k, v in attrs.items()] + ['}']
    return '\n'.join(lines)


def puppet(plan: dict) -> str:
    items = model(plan)
    out = [f'# Puppet manifest for the workloads of StorageForge change plan "{changes.one_line(plan["name"])}", generated {dt.datetime.now():%Y-%m-%d %H:%M}.\n'
           '# Needs the puppetlabs-docker module for containers and stacks. Incus, LXC and libvirt use exec with an unless guard: a second run changes nothing.\n'
           '#   puppet apply --noop this.pp        # read it first; StorageForge itself applies through its signed runner, not this']
    hosts = sorted({i['host'] for i in items if i['kind'] != 'skipped'})
    for host in hosts:
        body = []
        for i in [x for x in items if x.get('host') == host]:
            if i['kind'] == 'skipped':
                body.append(f'# step {i["step"]} ({i["title"]}) has no counterpart here, and is left out')
            elif i['kind'] == 'container':
                body.append(_resource('docker::run', i['name'], {'image': i['image'], 'ports': [f'{p["ip"]}:{p["external"]}:{p["internal"]}/{p["protocol"]}' for p in i['ports']],
                                                                 'volumes': [f'{v["host_path"]}:{v["container_path"]}{":ro" if v["read_only"] else ""}' for v in i['volumes']],
                                                                 'labels': [f'{k}={v}' for k, v in i['labels'].items()], 'restart': i['restart'],
                                                                 **({'net': i['network']} if i['network'] else {})}))
            elif i['kind'] == 'stack':
                labels = '{"services": {' + ', '.join(f'"{s["service"]}": {{"labels": {json.dumps(i["labels"])}}}' for s in i['services']) + '}}\n'
                body.append(_resource('file', i['dir'], {'ensure': 'directory', 'mode': '0750'}))
                body.append(_resource('file', f'{i["dir"]}/compose.yaml', {'ensure': 'file', 'content': i['compose'] + '\n'}))
                body.append(_resource('file', f'{i["dir"]}/storageforge.yaml', {'ensure': 'file', 'content': labels}))
                body.append(_resource('docker_compose', i['name'], {'ensure': 'present', 'compose_files': [f'{i["dir"]}/compose.yaml', f'{i["dir"]}/storageforge.yaml']}))
                if i['allow_from']:
                    body.append(f'# only {i["allow_from"]} may reach what stack {i["name"]} publishes: that rule is written by storageforge-fwrules, not here')
            elif i['kind'] == 'incus':
                args = ' '.join([f'-p {p}' for p in i['profiles']] + ([f'-s {i["pool"]}'] if i['pool'] else []) + ([f'-n {i["network"]}'] if i['network'] else [])
                                + (['--vm'] if i['type'] == 'virtual-machine' else []) + [f'-c {k}={v}' for k, v in i['config'].items()])
                body.append(_resource('exec', f'incus {i["name"]}', {'command': f'incus launch {i["image"]} {i["name"]} {args}', 'unless': f'incus info {i["name"]}',
                                                                     'path': ['/usr/bin', '/usr/sbin', '/bin', '/sbin']}))
                for x in i['proxies']:
                    body.append(_resource('exec', f'incus {i["name"]} {x["name"]}', {'command': f'incus config device add {i["name"]} {x["name"]} proxy listen={x["listen"]} connect={x["connect"]}',
                                                                                     'unless': f'incus config device get {i["name"]} {x["name"]} listen',
                                                                                     'path': ['/usr/bin', '/usr/sbin', '/bin', '/sbin']}))
            elif i['kind'] == 'lxc':
                body.append(_resource('exec', f'lxc {i["name"]}', {'command': f'lxc-create -n {i["name"]} -t download -- --dist {i["distro"]} --release {i["release"]} --arch {i["arch"]}',
                                                                   'unless': f'lxc-info -n {i["name"]}', 'path': ['/usr/bin', '/usr/sbin', '/bin', '/sbin']}))
            else:
                net = f'bridge={i["bridge"]}' if i['bridge'] else f'network={i["network"]}'
                disk = (f'--disk path={i["disk"]},bus=virtio --import' if i['kind'] == 'vm'
                        else f'--disk pool={i["pool"]},size={i["disk_gb"]},format=qcow2,bus=virtio' + (f' --cdrom {i["iso"]}' if i['kind'] == 'vm-iso' and i.get('iso') else ''))
                body.append(_resource('exec', f'vm {i["name"]}', {
                    'command': f'virt-install --connect qemu:///system --name {i["name"]} --vcpus {i["vcpus"]} --memory {i["memory_mb"]} {disk} --network {net},model=virtio '
                               '--graphics spice,listen=127.0.0.1 --noautoconsole', 'unless': f'virsh -c qemu:///system dominfo {i["name"]}',
                    'path': ['/usr/bin', '/usr/sbin', '/bin', '/sbin'], 'timeout': 1800}))
                if i['kind'] == 'vm-create':
                    body.append(f'# VM {i["name"]} starts from a cloud image with a cloud-init seed: the Bash export does that part, and this exec only names the disk')
        out.append(f'node {_pq(host)} {{\n' + '\n'.join(body) + '\n}')      # not indented: a file's content is a string, and must stay as it is
    return '\n\n'.join(out) + '\n'


def render(plan: dict, target: str) -> tuple[str, str]:
    """(file name, text)."""
    if target not in TARGETS:
        raise ValueError(f'the target is one of {", ".join(TARGETS)}')
    from .moves import slug
    if target == 'puppet':
        return f'workloads-{slug(plan["name"])}.pp', puppet(plan)
    return f'workloads-{slug(plan["name"])}.tf', terraform(plan, target)
