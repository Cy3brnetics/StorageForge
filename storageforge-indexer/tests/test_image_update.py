"""The image-update step (steps_workloads.py): its check, and the update itself with the real Docker and compose. Pulling needs a
registry, so the pull alone is played by a wrapper around the real docker that tags another local image under the name the stack runs,
as a registry with a newer image would: the recreate, the healthcheck and the rollback are Docker's own."""
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import changes, steps_workloads as wl
from test_workload_steps import HARNESS


class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)
        self.addCleanup(self.conn.close)
        self.conn.execute("INSERT INTO hosts (hostname, ssh_host, ssh_user, inventory_json) VALUES ('nas', 'nas', 'scan', '{}')")

    def items(self, **p):
        plan = {'name': 'u', 'tasks': [{'type': 'image-update', 'host': 'nas', 'params': p}]}
        return [(it['level'], it['text']) for it in changes.check(self.conn, changes.normalize(plan))['tasks'][0]['items']]

    def test_one_of_stack_or_unit_and_what_the_scan_saw(self):
        self.assertEqual(self.items(runtime='docker')[0][0], 'crit')
        self.assertEqual(self.items(runtime='docker', stack='wiki', unit='wiki.service')[0][0], 'crit')
        self.assertIn('crit', [l for l, _ in self.items(runtime='docker', unit='wiki.service')])     # Docker needs the container named
        self.assertIn('crit', [l for l, _ in self.items(runtime='podman', stack='wiki', wait='5')])
        import json
        hid = self.conn.scalar("SELECT host_id FROM hosts WHERE hostname = 'nas'")
        cs = [{'id': 'a', 'name': 'wiki-web-1', 'image': 'nginx:1.27', 'state': 'running', 'labels': {'com.docker.compose.project': 'wiki', 'com.docker.compose.service': 'web',
               'com.docker.compose.project.working_dir': '/srv/stacks/wiki'}, 'mounts': [], 'detail': True, 'health': None},
              {'id': 'b', 'name': 'wiki-db-1', 'image': 'postgres:16', 'state': 'running', 'labels': {'com.docker.compose.project': 'wiki', 'com.docker.compose.service': 'db',
               'com.docker.compose.project.working_dir': '/srv/stacks/wiki'}, 'mounts': [], 'detail': True, 'health': 'healthy'}]
        self.conn.execute("INSERT INTO docker_hosts (host_id, engine, access, root_dir, containers_json, volumes_json, compose_json, scan_id, updated_at) "
                          "VALUES (:h, 'docker', 'direct', '/var/lib/docker', :c, '[]', '[]', NULL, 1)", {'h': hid, 'c': json.dumps(cs)})
        got = self.items(runtime='docker', stack='wiki')
        self.assertTrue(any('wiki-web-1 has no healthcheck' in t for _, t in got), got)
        self.assertIn(('ok', 'wiki-db-1 has a healthcheck (healthy at the last scan)'), got)
        self.assertTrue(any(l == 'warn' and 'no service cache' in t for l, t in self.items(runtime='docker', stack='wiki', service='cache')))
        self.assertTrue(any(l == 'warn' and 'no stack other' in t for l, t in self.items(runtime='docker', stack='other')))


def ready() -> bool:
    if not shutil.which('docker') or subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode:
        return False
    return all(subprocess.run(['docker', 'image', 'inspect', i], capture_output=True).returncode == 0 for i in ('busybox:latest', 'alpine:3'))


@unittest.skipUnless(ready(), 'needs a Docker engine with the compose plugin, busybox:latest and alpine:3')
class RealDockerUpdate(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        tag = f'{os.getpid()}{int(time.time()) % 100000}'
        self.name, self.ref = f'sfupd{tag}', f'localhost/sfupd{tag}/app:1'
        self.dir = self.d / 'stack'
        self.dir.mkdir()
        self.bin = self.d / 'bin'
        self.bin.mkdir()
        real = shutil.which('docker')
        # the registry: "compose pull" tags $NEW under the name the stack runs; everything else is the real docker
        (self.bin / 'docker').write_text(f'#!/bin/bash\nif [[ $1 == compose && " $* " == *" pull "* ]]; then exec {real} tag "$NEW" "$REF"; fi\nexec {real} "$@"\n')
        (self.bin / 'docker').chmod(0o755)
        subprocess.run(['docker', 'tag', 'busybox:latest', self.ref], check=True, capture_output=True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        subprocess.run(['docker', 'compose', '-p', self.name, 'down', '-t', '1'], capture_output=True, cwd=self.dir)
        tags = subprocess.run(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'], capture_output=True, text=True).stdout.split()
        mine = [t for t in tags if t == self.ref or (t.startswith('localhost/storageforge-rollback:') and self.name in t)]
        if mine:
            subprocess.run(['docker', 'rmi', *mine], capture_output=True)

    def up(self, health: str):
        (self.dir / 'compose.yaml').write_text(f'''services:
  app:
    image: {self.ref}
    command: ["sleep", "300"]
    stop_grace_period: 1s
    healthcheck: {{test: ["CMD-SHELL", "{health}"], interval: 1s, timeout: 2s, retries: 2, start_period: 1s}}
''')
        subprocess.run(['docker', 'compose', '-p', self.name, 'up', '-d', '--wait', '--wait-timeout', '60'], check=True, capture_output=True, cwd=self.dir)

    def update(self, apply=True, new='alpine:3'):
        words = ['docker', self.name, '', '', '', '40']
        script = HARNESS + f'APPLY={int(apply)}\nFAKE={self.d}\nWL_TICK=1\n' + wl.BASH + '\nt_image_update ' + ' '.join(shlex.quote(w) for w in words) + '\nexit $((PROBLEMS > 0))\n'
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=240,
                              env={**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'LOG': str(self.d / 'log'), 'NEW': new, 'REF': self.ref})

    def image_of_app(self) -> str:
        cid = subprocess.run(['docker', 'ps', '-q', '--filter', f'label=com.docker.compose.project={self.name}'], capture_output=True, text=True).stdout.split()[0]
        return subprocess.run(['docker', 'inspect', '-f', '{{.Image}}', cid], capture_output=True, text=True).stdout.strip()

    def image_id(self, ref):
        return subprocess.run(['docker', 'image', 'inspect', '-f', '{{.Id}}', ref], capture_output=True, text=True).stdout.strip()

    def test_a_failed_healthcheck_puts_the_image_before_back(self):
        self.up('test ! -e /etc/alpine-release')         # healthy on busybox, unhealthy on alpine: the "new" image is broken
        before = self.image_of_app()
        report = self.update(apply=False)
        self.assertEqual(report.returncode, 0, report.stdout + report.stderr)
        self.assertIn(f'would: pull {self.ref}', report.stdout)
        self.assertEqual(self.image_id(self.ref), before)           # the report pulled nothing
        out = self.update()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('rolled back:', out.stdout)
        self.assertIn('is unhealthy on the new image', out.stdout)
        self.assertIn('runs the images it had before again, and is healthy', out.stdout)
        self.assertEqual(self.image_of_app(), before)
        self.assertEqual(self.image_id(self.ref), before)           # the name points at the old image again

    def test_a_healthy_update_stays_and_keeps_the_image_before(self):
        self.up('test -e /bin/sh')
        before = self.image_of_app()
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('and it is healthy. The images before are kept as localhost/storageforge-rollback:', out.stdout)
        self.assertEqual(self.image_of_app(), self.image_id('alpine:3'))
        kept = out.stdout.split('kept as ')[1].split()[0]
        self.assertEqual(self.image_id(kept), before)
        again = self.update()                                     # the "registry" has nothing newer now
        self.assertIn('are current: nothing changed', again.stdout)


if __name__ == '__main__':
    unittest.main()
