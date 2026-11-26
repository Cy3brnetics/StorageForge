"""The docker-daemon step: checked against the index, run as a report and through the Ansible export with stubbed docker, dockerd, systemctl and rsync."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

try:
    from test_tasks import Fleet
except ImportError:      # run as tests.test_x from the project folder
    from tests.test_tasks import Fleet
from storageforge_index import changes, steps_dockerd
from storageforge_index.runtimes import docker

SETTINGS = {'storage_driver': 'overlay2', 'log_driver': 'json-file', 'cgroup_driver': 'systemd', 'live_restore': False, 'registry_mirrors': []}


def container(name, restart='always', state='running'):
    return json.dumps({'id': name * 3, 'name': '/' + name, 'image': 'img', 'state': state, 'started': '', 'labels': {}, 'mounts': [], 'restart': restart})


def probe(engine='docker', root='/var/lib/docker', settings=None, containers=()):
    return '\n'.join([f'@@engine\t{engine}\tdirect', '@@root', root, '@@settings', json.dumps({**SETTINGS, **(settings or {})}), '@@daemonjson', '{}',
                      '@@containers', *containers, '@@end']) + '\n'


def plan(host='nas', **over):
    return {'name': 'dd', 'tasks': [{'type': 'docker-daemon', 'host': host, 'params': {'log_max_size': '10m', **over}}]}


class Loader(yaml.SafeLoader):
    """A playbook marks its commands !unsafe."""


Loader.add_constructor('!unsafe', lambda loader, node: loader.construct_scalar(node))


class Index(Fleet):
    def scan(self, host='nas', **kw):
        hid = self.conn.scalar('SELECT host_id FROM hosts WHERE hostname = :h', {'h': host})
        with mock.patch.object(docker, '_stream', return_value=probe(**kw)), mock.patch.object(docker, 'compose_candidates', return_value=[]):
            docker.survey(self.db, self.conn, None, hid, 1)

    def items(self, host='nas', **over):
        p = changes.normalize(plan(host, **over))
        return [(i['level'], i['text']) for i in changes.check(self.conn, p)['tasks'][0]['items']]


class Normalize(unittest.TestCase):
    def test_every_setting_empty_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'at least one'):
            changes.normalize({'name': 'dd', 'tasks': [{'type': 'docker-daemon', 'host': 'nas', 'params': {}}]})

    def test_a_bad_size_is_refused(self):
        for bad in ('10', '10mb', 'm', '-5m', '10 m'):
            with self.assertRaises(ValueError, msg=bad):
                changes.normalize(plan(log_max_size=bad))
        self.assertEqual(changes.normalize(plan(log_max_size='100k'))['tasks'][0]['params']['log_max_size'], '100k')

    def test_the_number_of_log_files_must_be_a_number(self):
        with self.assertRaises(ValueError):
            changes.normalize(plan(log_max_file='x'))

    def test_mirrors_are_https_urls_without_a_login(self):
        changes.normalize(plan(registry_mirrors='https://a.example https://b.example:5000/x'))
        for bad in ('http://a.example', 'https://u:p@a.example', 'a.example', 'https://a.example; rm -rf /'):
            with self.assertRaises(ValueError, msg=bad):
                changes.normalize(plan(registry_mirrors=bad))

    def test_choices_are_held_to_their_options(self):
        for key, bad in (('log_driver', 'gelf'), ('live_restore', 'maybe'), ('storage_driver', 'aufs')):
            with self.assertRaises(ValueError, msg=key):
                changes.normalize(plan(**{key: bad}))

    def test_the_step_is_in_the_workloads_group_and_moves_data_by_default(self):
        self.assertEqual(changes.TYPES['docker-daemon']['group'], 'Workloads')
        self.assertTrue(changes.normalize(plan(data_root='/srv/docker'))['tasks'][0]['params']['move_data'])


class Check(Index):
    def test_a_podman_host_is_a_crit(self):
        self.scan(engine='podman', root='/var/lib/containers/storage')
        self.assertTrue(any(lv == 'crit' and 'Podman' in t for lv, t in self.items()))

    def test_a_host_never_read_is_a_note(self):
        items = self.items()
        self.assertTrue(any(lv == 'note' and 'not read' in t for lv, t in items))
        self.assertFalse(any(lv == 'crit' for lv, _ in items))

    def test_a_target_inside_the_current_root_or_the_reverse_is_a_crit(self):
        self.scan()
        self.assertTrue(any(lv == 'crit' and 'inside' in t for lv, t in self.items(data_root='/var/lib/docker/new')))
        self.assertTrue(any(lv == 'crit' and 'inside' in t for lv, t in self.items(data_root='/var/lib')))
        self.assertTrue(any(lv == 'crit' for lv, t in self.items(data_root='/')))

    def test_a_target_on_the_system_disk_is_a_warn(self):
        self.scan()
        self.assertTrue(any(lv == 'warn' and 'system disk' in t for lv, t in self.items(data_root='/srv/docker')))
        self.assertFalse(any('system disk' in t for lv, t in self.items(data_root='/mnt/backup/docker')))

    def test_a_target_on_a_network_filesystem_is_a_warn(self):
        self.scan('pc')
        self.assertTrue(any(lv == 'warn' and 'network' in t for lv, t in self.items('pc', data_root='/mnt/media/docker')))

    def test_running_containers_without_live_restore_are_counted(self):
        self.scan(containers=[container('web'), container('db', 'no'), container('old', state='exited')])
        warn = [t for lv, t in self.items() if lv == 'warn' and 'live-restore is off' in t]
        self.assertEqual(len(warn), 1)
        self.assertIn('2 running containers', warn[0])
        self.assertIn('1 of them has no restart policy', warn[0])

    def test_live_restore_on_the_engine_removes_the_warning(self):
        self.scan(containers=[container('web')], settings={'live_restore': True})
        self.assertFalse(any('restart policy' in t for _, t in self.items()))

    def test_the_current_root_needs_no_move(self):
        self.scan()
        items = self.items(data_root='/var/lib/docker/')
        self.assertTrue(any(lv == 'note' and 'no move needed' in t for lv, t in items))
        self.assertFalse(any(lv == 'crit' for lv, _ in items))

    def test_a_new_root_without_the_move_says_it_starts_empty(self):
        self.scan()
        self.assertTrue(any(lv == 'warn' and 'empty' in t for lv, t in self.items(data_root='/mnt/backup/docker', move_data=False)))

    def test_another_storage_driver_hides_the_images_it_cannot_read(self):
        self.scan()
        self.assertTrue(any(lv == 'warn' and 'storage driver' in t for lv, t in self.items(storage_driver='btrfs')))
        self.assertFalse(any('storage driver' in t for lv, t in self.items(storage_driver='overlay2')))

    def test_the_number_of_log_files_is_one_to_a_hundred(self):
        self.scan()
        for bad in ('0', '101'):
            self.assertTrue(any(lv == 'crit' and '1 to 100' in t for lv, t in self.items(log_max_file=bad)), bad)
        self.assertFalse(any(lv == 'crit' for lv, _ in self.items(log_max_file='100')))

    def test_the_none_log_driver_takes_no_log_options(self):
        self.scan()
        self.assertTrue(any(lv == 'crit' and 'none' in t for lv, t in self.items(log_driver='none')))

    def test_docker_under_snap_is_not_edited(self):
        self.scan(root='/var/snap/docker/common/var-lib-docker')
        self.assertTrue(any(lv == 'crit' and 'snap' in t for lv, t in self.items()))


@unittest.skipIf(os.geteuid() == 0, 'the stubs steer the script to a temporary /etc/docker only for a user that is not root')
class Script(Index):
    OLD_DAEMON = {'hosts': ['fd://'], 'log-driver': 'json-file', 'tlsverify': False}

    def setUp(self):
        super().setUp()
        self.work = Path(tempfile.mkdtemp(dir=self.tmp))
        self.etc, self.stubs, self.log = self.work / 'etc', self.work / 'stubs', self.work / 'argv.log'
        self.old, self.new = self.work / 'old-root', self.work / 'new-root'
        for d in (self.etc, self.stubs, self.old):
            d.mkdir()
        (self.old / 'data').write_text('x' * 4096)
        (self.etc / 'daemon.json').write_text(json.dumps(self.OLD_DAEMON, indent=2) + '\n')
        (self.work / 'running.txt').write_text('web always\ntmp no\n')
        log, etc, work = self.log, self.etc, self.work
        self.stub('docker', f'''#!{sys.executable}
import json, os, sys
a = sys.argv[1:]
open("{log}", "a").write("docker " + " ".join(a) + "\\n")
if os.path.exists("{work}/down"):
    sys.exit(1)
try:
    cfg = json.load(open("{etc}/daemon.json"))
except Exception:
    cfg = {{}}
fmt = a[a.index("--format") + 1] if "--format" in a else ""
running = [l.split() for l in open("{work}/running.txt")]
if os.path.exists("{work}/restarted"):
    running = [r for r in running if r[1] != "no"]
if a[:1] == ["--version"]:
    print(open("{work}/version.txt").read().strip() if os.path.exists("{work}/version.txt") else "Docker version 27.0.1, build x")
elif a[:1] == ["info"]:
    print({{"{{{{.DockerRootDir}}}}": cfg.get("data-root", "{self.old}"), "{{{{.LoggingDriver}}}}": cfg.get("log-driver", "json-file"),
           "{{{{.Driver}}}}": cfg.get("storage-driver", "overlay2"), "{{{{.LiveRestoreEnabled}}}}": str(cfg.get("live-restore", False)).lower(),
           "{{{{.OperatingSystem}}}}": "Ubuntu 26.04"}}.get(fmt, ""))
elif a[:1] == ["ps"]:
    print("\\n".join(r[0] for r in running))
elif a[:1] == ["inspect"]:
    print(dict((r[0], r[1]) for r in running).get(a[-1], ""))
''')
        self.stub('dockerd', f'''#!/bin/sh
case "$1" in --help) [ -e "{work}/novalidate" ] || echo "      --validate    Validate daemon configuration and exit" ;;
  *) echo "dockerd $* | daemon.json then: $(tr -d ' \\n' < {etc}/daemon.json)" >> {log}; [ -e "{work}/invalid" ] && {{ echo "bad config" >&2; exit 1; }}; exit 0 ;;
esac
''')
        self.stub('systemctl', f'''#!/bin/sh
echo "systemctl $* | daemon.json then: $(tr -d ' \\n' < {etc}/daemon.json)" >> {log}
case "$1" in stop) touch {work}/down ;; start|restart) rm -f {work}/down; touch {work}/restarted ;; esac
''')
        self.stub('rsync', f'''#!/bin/sh
echo "rsync $* | daemon.json then: $(tr -d ' \\n' < {etc}/daemon.json)" >> {log}
[ -e "{work}/rsync-fails" ] && exit 23
exit 0
''')
        self.stub('uname', '#!/bin/sh\necho nas\n')

    def stub(self, name, text):
        (self.stubs / name).write_text(text)
        (self.stubs / name).chmod(0o755)

    def env(self, path=None):
        return {**os.environ, 'PATH': path or f'{self.stubs}:{os.environ["PATH"]}', 'SF_DOCKER_ETC': str(self.etc)}

    def daemon(self):
        return json.loads((self.etc / 'daemon.json').read_text())

    def logged(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def calls(self, prefix):
        return [i for i, line in enumerate(self.logged()) if line.startswith(prefix)]

    def report(self, **over):
        text = changes.script(self.conn, changes.normalize(plan(**over)))
        self.assertEqual(subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True).returncode, 0)
        r = subprocess.run(['bash', '-s', '--', '--report'], input=text, env=self.env(), capture_output=True, text=True, timeout=120)
        return r.stdout + r.stderr

    def export(self, path=None, **over):
        doc = yaml.load(changes.ansible(self.conn, changes.normalize(plan(**over))), Loader)
        cmd = next(t['ansible.builtin.shell']['cmd'] for play in doc for t in play['tasks'] if 'ansible.builtin.shell' in t and 't_docker_daemon' in t['ansible.builtin.shell']['cmd'])
        self.assertEqual(subprocess.run(['bash', '-n'], input=cmd, text=True, capture_output=True).returncode, 0)
        return subprocess.run(['bash', '-c', cmd], env=self.env(path), capture_output=True, text=True, timeout=60)

    def backups(self):
        return sorted(self.etc.glob('daemon.json.storageforge-*'))

    def tools_only(self, *names):
        """A PATH of the basic tools the script needs and the named ones, with no python3 or jq unless named."""
        d = Path(tempfile.mkdtemp(dir=self.work))
        for t in ('bash', 'dirname', 'mktemp', 'rm', 'cp', 'cat', 'diff', 'mkdir', 'date', 'id', 'readlink', 'grep', 'find', 'du', 'cut', 'df', 'tail', 'tr', 'sleep',
                  'mv', 'touch', 'install', 'head', 'wc', 'sed', 'env', 'sort', 'cmp', *names):
            src = shutil.which(t)
            if src:
                (d / t).symlink_to(src)
        for t in ('docker', 'dockerd', 'systemctl', 'rsync', 'uname'):
            (d / t).symlink_to(self.stubs / t)
        return str(d)

    # ── report ──
    def test_the_script_is_valid_bash_and_holds_no_apostrophe(self):
        self.assertNotIn("'", steps_dockerd.BASH)

    def test_the_report_shows_the_merged_file_and_changes_nothing(self):
        before = (self.etc / 'daemon.json').read_text()
        out = self.report(log_max_size='10m', log_max_file='3')
        self.assertRegex(out, r'\+\s+"max-size": "10m"')
        self.assertRegex(out, r'missing.*would')
        self.assertEqual((self.etc / 'daemon.json').read_text(), before)
        self.assertEqual(self.backups(), [])
        self.assertEqual([x for x in self.logged() if x.startswith(('systemctl', 'rsync'))], [])
        self.assertNotIn('command not found', out)

    def test_the_report_counts_the_running_containers_and_says_who_stays_stopped(self):
        out = self.report(data_root=str(self.new))
        self.assertIn('2 containers are running', out)
        self.assertRegex(out, r'1 of them has no restart policy.*stays? stopped')
        self.assertEqual(self.calls('systemctl'), [])

    def test_a_docker_that_cannot_validate_is_said_and_goes_on(self):
        (self.work / 'novalidate').write_text('')
        out = self.report()
        self.assertIn('this Docker cannot validate a config; checked as JSON only', out)
        self.assertEqual(self.calls('dockerd --validate'), [])

    # ── apply, through the Ansible export ──
    def test_an_apply_merges_keeps_other_keys_backs_up_validates_first_and_restarts(self):
        old = (self.etc / 'daemon.json').read_text()
        r = self.export(log_max_size='10m', log_max_file='3', live_restore='on', registry_mirrors='https://m.example', storage_driver='overlay2', log_driver='local')
        self.assertEqual(r.returncode, 0, r.stderr)
        d = self.daemon()
        self.assertEqual(d['hosts'], ['fd://'])
        self.assertIs(d['tlsverify'], False)
        self.assertEqual((d['log-driver'], d['log-opts'], d['live-restore'], d['registry-mirrors'], d['storage-driver']),
                         ('local', {'max-size': '10m', 'max-file': '3'}, True, ['https://m.example'], 'overlay2'))
        self.assertEqual([b.read_text() for b in self.backups()], [old])
        validate, restart = self.calls('dockerd --validate'), self.calls('systemctl restart docker')
        self.assertEqual((len(validate), len(restart)), (1, 1))
        self.assertLess(validate[0], restart[0])
        self.assertIn('"log-driver":"json-file"', self.logged()[validate[0]])      # validated before the file was written
        self.assertIn('--config-file', self.logged()[validate[0]])
        self.assertEqual(self.calls('rsync'), [])
        self.assertEqual(self.calls('systemctl stop'), [])
        self.assertNotIn('command not found', r.stderr)

    def test_the_log_options_already_there_are_kept(self):
        (self.etc / 'daemon.json').write_text(json.dumps({'log-opts': {'labels': 'a', 'max-size': '1m'}}))
        r = self.export(log_max_file='5')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.daemon()['log-opts'], {'labels': 'a', 'max-size': '10m', 'max-file': '5'})

    def test_a_missing_file_is_made_without_a_backup(self):
        (self.etc / 'daemon.json').unlink()
        r = self.export()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.daemon(), {'log-opts': {'max-size': '10m'}})
        self.assertEqual(self.backups(), [])

    def test_invalid_json_on_disk_is_a_conflict_naming_the_file_and_changes_nothing(self):
        (self.etc / 'daemon.json').write_text('{"hosts": [')
        r = self.export()
        self.assertNotEqual(r.returncode, 0)
        self.assertRegex(r.stderr, r'conflict.*daemon\.json.*not valid JSON')
        self.assertEqual((self.etc / 'daemon.json').read_text(), '{"hosts": [')
        self.assertEqual((self.backups(), self.calls('systemctl'), self.calls('dockerd --validate')), ([], [], []))

    def test_a_config_dockerd_rejects_is_not_written(self):
        (self.work / 'invalid').write_text('')
        before = (self.etc / 'daemon.json').read_text()
        r = self.export()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('bad config', r.stderr)
        self.assertEqual((self.etc / 'daemon.json').read_text(), before)
        self.assertEqual(self.calls('systemctl'), [])

    def test_an_apply_that_changes_nothing_restarts_nothing(self):
        (self.etc / 'daemon.json').write_text(json.dumps({'log-opts': {'max-size': '10m'}}))
        r = self.export()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.calls('systemctl'), [])
        self.assertEqual(self.backups(), [])

    def test_a_move_stops_docker_copies_writes_then_starts(self):
        old = (self.etc / 'daemon.json').read_text()
        r = self.export(data_root=str(self.new), log_max_size='')
        self.assertEqual(r.returncode, 0, r.stderr)
        stop, rsync, start = self.calls('systemctl stop docker.socket docker'), self.calls('rsync'), self.calls('systemctl start docker')
        self.assertEqual((len(stop), len(rsync), len(start)), (1, 1, 1))
        self.assertLess(stop[0], rsync[0])
        self.assertLess(rsync[0], start[0])
        line = self.logged()[rsync[0]]
        self.assertRegex(line, r'rsync -aHAX --numeric-ids .*' + str(self.old) + '/ ' + str(self.new) + '/')
        self.assertNotIn('data-root', line)                       # the file was still the old one while the data was copied
        self.assertIn(f'"data-root":"{self.new}"', self.logged()[start[0]])      # and new when docker started
        self.assertEqual(self.daemon()['data-root'], str(self.new))
        self.assertEqual(self.daemon()['hosts'], ['fd://'])
        self.assertEqual([b.read_text() for b in self.backups()], [old])
        self.assertEqual(self.calls('systemctl restart'), [])
        self.assertTrue(self.old.exists())                         # the old folder is kept
        self.assertIn('rm -rf ' + str(self.old), r.stdout)
        self.assertNotIn('command not found', r.stderr)

    def test_a_failing_rsync_leaves_the_file_and_starts_docker_on_the_old_root(self):
        (self.work / 'rsync-fails').write_text('')
        before = (self.etc / 'daemon.json').read_text()
        r = self.export(data_root=str(self.new))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('rsync', r.stderr)
        self.assertEqual((self.etc / 'daemon.json').read_text(), before)
        self.assertEqual(self.backups(), [])
        self.assertEqual(len(self.calls('systemctl start docker')), 1)
        self.assertLess(self.calls('rsync')[0], self.calls('systemctl start docker')[0])
        self.assertFalse((self.work / 'down').exists())

    def test_the_current_root_is_no_stop_no_rsync_no_restart(self):
        r = self.export(data_root=str(self.old) + '/', log_max_size='')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.calls('systemctl'), self.calls('rsync')), ([], []))
        self.assertEqual(self.daemon(), self.OLD_DAEMON)

    def test_a_target_that_is_not_empty_stops_before_docker_does(self):
        self.new.mkdir()
        (self.new / 'x').write_text('x')
        r = self.export(data_root=str(self.new))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('not empty', r.stderr)
        self.assertEqual((self.calls('systemctl'), self.calls('rsync')), ([], []))

    def test_an_empty_target_is_used(self):
        self.new.mkdir()
        r = self.export(data_root=str(self.new))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(self.calls('rsync')), 1)

    def test_no_room_stops_before_docker_does(self):
        self.stub('du', '#!/bin/sh\nprintf "999999999999\\t%s\\n" "$4"\n')
        self.stub('df', '#!/bin/sh\nprintf "Avail\\n1000\\n"\n')
        r = self.export(data_root=str(self.new))
        self.assertNotEqual(r.returncode, 0)
        self.assertRegex(r.stderr, r'room')
        self.assertEqual(self.calls('systemctl'), [])

    def test_a_move_without_the_data_only_changes_the_file(self):
        r = self.export(data_root=str(self.new), move_data='')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.calls('rsync'), self.calls('systemctl stop')), ([], []))
        self.assertEqual(len(self.calls('systemctl restart docker')), 1)
        self.assertEqual(self.daemon()['data-root'], str(self.new))

    def test_containers_that_are_not_back_are_named(self):
        r = self.export(data_root=str(self.new))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r'tmp.*no restart policy')

    def test_podman_behind_the_docker_name_is_a_conflict(self):
        (self.work / 'version.txt').write_text('podman version 5.0.0')
        r = self.export()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('Podman', r.stderr)
        self.assertEqual(self.calls('systemctl'), [])

    def test_jq_edits_the_file_when_there_is_no_python3(self):
        if not shutil.which('jq'):
            self.skipTest('jq is not installed here')
        r = self.export(path=self.tools_only('jq'), log_max_size='10m', log_max_file='3', live_restore='off', registry_mirrors='https://a.example https://b.example')
        self.assertEqual(r.returncode, 0, r.stderr)
        d = self.daemon()
        self.assertEqual((d['hosts'], d['log-opts'], d['live-restore'], d['registry-mirrors']),
                         (['fd://'], {'max-size': '10m', 'max-file': '3'}, False, ['https://a.example', 'https://b.example']))

    def test_jq_refuses_a_file_that_is_not_an_object(self):
        if not shutil.which('jq'):
            self.skipTest('jq is not installed here')
        (self.etc / 'daemon.json').write_text('[1]')
        r = self.export(path=self.tools_only('jq'))
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual((self.etc / 'daemon.json').read_text(), '[1]')

    def test_neither_python3_nor_jq_is_a_conflict(self):
        before = (self.etc / 'daemon.json').read_text()
        r = self.export(path=self.tools_only())
        self.assertNotEqual(r.returncode, 0)
        self.assertRegex(r.stderr, r'python3 nor jq')
        self.assertEqual((self.etc / 'daemon.json').read_text(), before)

    def test_values_reach_python_as_words_never_as_source(self):
        evil = f'{self.work}/$(touch {self.work}/pwned)"x'
        r = self.export(data_root=evil, move_data='')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.daemon()['data-root'], evil)
        self.assertFalse((self.work / 'pwned').exists())
        body = steps_dockerd.BASH.split('<<"PY"')[1].split('\nPY\n')[0]
        self.assertNotIn('$', body)


if __name__ == '__main__':
    unittest.main()
