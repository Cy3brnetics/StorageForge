"""Lists kept by hand in two places stay in step: container entrypoint vs CLI subcommands, backup tables vs schema.
Run with: python3 -m unittest discover -s tests -v"""
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

try:
    import dbfactory
except ImportError:      # run as tests.test_x from the project folder
    from tests import dbfactory
from storageforge_index import backup, cli
from storageforge_index.db import Database

ENTRYPOINT = Path(__file__).resolve().parents[1] / 'docker' / 'entrypoint.sh'
FIREWALL = ENTRYPOINT.with_name('egress-firewall.sh')


class Consistency(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = dbfactory.make(self, Path(self.tmp) / 'index.db')
        self.conn = self.db.connect()
        self.db.migrate(self.conn)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp)

    def test_entrypoint_knows_every_subcommand(self):
        # the first case arm before ") ;;" lists the names the entrypoint prepares the environment for
        arm = re.search(r'case "\$\{1:-serve\}" in\n(.*?)\) ;;', ENTRYPOINT.read_text(), re.S).group(1)
        known = {n.strip() for n in arm.replace('\\\n', '').split('|')} - {'-*'}
        sub = next(a for a in cli.build_parser()._actions if a.dest == 'cmd')
        self.assertEqual(set(sub.choices) - known, set(), 'add these to docker/entrypoint.sh')
        self.assertEqual(known - set(sub.choices), set(), 'not storageforge-index subcommands')

    @unittest.skipUnless(shutil.which('sh'), 'needs sh')
    @unittest.skipIf(os.geteuid() == 0, 'the entrypoint refuses root')
    def test_entrypoint_restore_and_global_options(self):
        """GM-16: restore ran migrate and vault init on the database it replaces; --db before the subcommand skipped
        the session secret check and migrated the default database instead."""
        import subprocess
        tmp = Path(self.tmp)
        (tmp / 'bin').mkdir()
        (tmp / 'bin' / 'storageforge-index').write_text(f'#!/bin/sh\necho "$*" >>{tmp}/calls\n')
        (tmp / 'bin' / 'storageforge-index').chmod(0o755)
        for d in ('data', 'run'):
            (tmp / d).mkdir()

        def start(*args, session=True):
            (tmp / 'calls').unlink(missing_ok=True)
            env = {'PATH': f'{tmp}/bin:/usr/bin:/bin', 'STORAGEFORGE_DATA_DIR': f'{tmp}/data',
                   'STORAGEFORGE_RUNTIME_DIR': f'{tmp}/run', 'STORAGEFORGE_ALLOW_DISK_RUNTIME': '1',
                   'STORAGEFORGE_IMPORT_DIR': f'{tmp}/none', 'STORAGEFORGE_VAULT_SECRET': 'v' * 40}
            if session:
                env['STORAGEFORGE_SESSION_SECRET'] = 's' * 40
            p = subprocess.run(['sh', str(ENTRYPOINT), *args], env=env, capture_output=True, text=True, timeout=30)
            calls = (tmp / 'calls').read_text().splitlines() if (tmp / 'calls').exists() else []
            return p.returncode, calls, p.stderr
        self.assertEqual(start('restore', '/app/backups/x.db', '--yes')[1], ['restore /app/backups/x.db --yes'])
        rc, calls, err = start('--db', '/srv/other.db', 'serve', session=False)
        self.assertNotEqual(rc, 0)
        self.assertIn('SESSION_SECRET', err)
        self.assertEqual(start('--db', '/srv/other.db', 'serve')[1],
                         ['--db /srv/other.db migrate', '--db /srv/other.db vault init', '--db /srv/other.db serve'])
        self.assertEqual(start()[1], ['migrate', 'vault init', 'serve'])
        (tmp / 'none').mkdir(mode=0o300)          # GM-15: a keys/ the container cannot list was skipped silently
        try:
            rc, calls, err = start()
        finally:
            (tmp / 'none').chmod(0o700)
        self.assertIn('no keys imported', err)
        self.assertEqual(calls, ['migrate', 'vault init', 'serve'])

    @unittest.skipUnless(shutil.which('sh') and shutil.which('openssl'), 'needs sh and openssl')
    def test_init_secrets_lets_the_container_group_list_keys(self):
        """GM-15: keys/ was left 0700 (umask 077), so uid 10001 could not list it even through the group."""
        import stat
        import subprocess
        tmp = Path(self.tmp) / 'stack'
        (tmp / 'docker').mkdir(parents=True)
        shutil.copy(ENTRYPOINT.with_name('init-secrets.sh'), tmp / 'docker')
        (tmp / 'keys').mkdir(mode=0o700)                                   # as an earlier run left it
        p = subprocess.run(['sh', str(tmp / 'docker' / 'init-secrets.sh')], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(stat.S_IMODE((tmp / 'keys').stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((tmp / 'secrets').stat().st_mode), 0o700)

    @unittest.skipIf(dbfactory.PG, 'backups are of SQLite databases (PostgreSQL: pg_dump)')
    def test_every_table_is_backed_up_or_rebuildable(self):
        tables = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'file_fts_%'")}
        both = set(backup.ESSENTIAL) & set(backup.REBUILDABLE)
        self.assertEqual(both, set(), 'in both lists')
        self.assertEqual(tables - set(backup.ESSENTIAL) - set(backup.REBUILDABLE), set(),
                         'new table: add it to backup.ESSENTIAL or backup.REBUILDABLE')
        self.assertEqual((set(backup.ESSENTIAL) | set(backup.REBUILDABLE)) - tables, set(), 'no such table')

    @unittest.skipIf(dbfactory.PG, 'backups are of SQLite databases (PostgreSQL: pg_dump)')
    def test_essentials_carry_plans_settings_and_deploy_state(self):
        now = int(time.time())
        for sql in ("INSERT INTO change_plans (name, body_json, created_at, updated_at) VALUES ('c', '{}', :t, :t)",
                    "INSERT INTO storage_tasks (name, body_json, created_at, updated_at) VALUES ('t', '{}', :t, :t)",
                    "INSERT INTO settings (key, value_json, updated_at) VALUES ('report_url', '\"https://sf\"', :t)",
                    "INSERT INTO deploy_access (host, state, updated_at) VALUES ('nas', 'ready', :t)",
                    "INSERT INTO deployed (host, kind, ref, deploy_hash, deployed_at) VALUES ('nas', 'jobs', '1', 'h', :t)",
                    "INSERT INTO jobs (job_id, name, method, runner_host, source_host, token_hash) "
                    "VALUES ('p1-s1', 'j', 'mirror', 'nas', 'nas', 'sha')",
                    "INSERT INTO host_key_confirmations (address, port, fingerprint, confirmed_by, confirmed_at) "
                    "VALUES ('nas', 22, 'SHA256:x', 'admin', :t)",
                    "INSERT INTO job_runs (run_uuid, job_id, kind, started_at, via, received_at) "
                    "VALUES ('r1', 'p1-s1', 'run', :t, 'report', :t)"):
            self.conn.execute(sql, {'t': now})
        dest = Path(self.tmp) / 'bk'
        dest.mkdir()
        out = backup.create(self.db, 'essentials', dest)['path']
        bk = sqlite3.connect(out)
        try:
            for t in ('change_plans', 'storage_tasks', 'settings', 'deploy_access', 'deployed', 'jobs',
                      'host_key_confirmations'):
                self.assertEqual(bk.execute(f'SELECT count(*) FROM {t}').fetchone()[0], 1, t)
            self.assertEqual(bk.execute('SELECT token_hash FROM jobs').fetchone()[0], 'sha')   # reports still verify
            self.assertEqual(bk.execute('SELECT count(*) FROM job_runs').fetchone()[0], 0)      # history stays behind
        finally:
            bk.close()


if __name__ == '__main__':
    unittest.main()


# A stand-in for iptables: keeps the filter table's chains in a JSON file and, after every change, notes each bridge
# that was filtered (in DOCKER-USER and INPUT, through a chain ending in REJECT) and no longer is.
FAKE_IPTABLES = r"""import json, os, sys
path = os.environ['FAKE_IPT_STATE']
st = json.load(open(path))
ch, args = st['chains'], sys.argv[1:]
if args[:1] == ['-n']:
    args = args[1:]
op, rest = args[0], args[1:]
def filtered():
    out = set()
    for br in st['bridges']:
        ok = []
        for base, rule in (('DOCKER-USER', f'-i {br} ! -o {br} -j '), ('INPUT', f'-i {br} -j ')):
            tgt = [r[len(rule):] for r in ch[base] if r.startswith(rule)]
            ok.append(any(ch.get(t) and ch[t][-1] == '-j REJECT' for t in tgt))
        if all(ok):
            out.add(br)
    return out
before = filtered()
rc = 0
if op == '-L':
    rc = 0 if rest[0] in ch else 1
elif op == '-S':
    print('\n'.join(f'-A {c} {r}' for c, rs in ch.items() for r in rs))
elif op == '-N':
    rc = 1 if rest[0] in ch else (ch.__setitem__(rest[0], []) or 0)
elif op == '-F':
    rc = 1 if rest[0] not in ch else (ch.__setitem__(rest[0], []) or 0)
elif op == '-X':
    used = any(r.endswith(' -j ' + rest[0]) for rs in ch.values() for r in rs)
    rc = 1 if rest[0] not in ch or used or ch[rest[0]] else (ch.pop(rest[0]) and 0)
else:
    c, rule = rest[0], ' '.join(rest[1:])
    words = rest[1:]
    target = words[words.index('-j') + 1] if '-j' in words else ''
    if c not in ch or (target not in ('RETURN', 'REJECT', '') and target not in ch):
        rc = 1
    elif op == '-A':
        ch[c].append(rule)
    elif op == '-I':
        ch[c].insert(0, rule)
    elif op == '-C':
        rc = 0 if rule in ch[c] else 1
    elif op == '-D':
        rc = 0 if rule in ch[c] and (ch[c].remove(rule) or True) else 1
st['opened'] = sorted(set(st['opened']) | (before - filtered()))
json.dump(st, open(path, 'w'))
sys.exit(rc)
"""


@unittest.skipUnless(shutil.which('sh'), 'needs sh')
class EgressFirewall(unittest.TestCase):
    """GM-18: a second bridge flushed the shared chain and left the first one open; a bad port tore the rules down
    before failing; traffic to the Docker host itself (INPUT) was never filtered."""

    def setUp(self):
        import json
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / 'bin').mkdir()
        for name, text in (('iptables', f'#!{sys.executable}\n' + FAKE_IPTABLES), ('id', '#!/bin/sh\necho 0\n')):
            (self.tmp / 'bin' / name).write_text(text)
            (self.tmp / 'bin' / name).chmod(0o755)
        self.state = self.tmp / 'state.json'
        self.state.write_text(json.dumps({'chains': {'DOCKER-USER': [], 'INPUT': []}, 'bridges': ['sf0', 'sfdemo0'],
                                          'opened': []}))

    def fw(self, *args, bridge='sf0', ports='22 443'):
        import json
        import subprocess
        env = {'PATH': f'{self.tmp}/bin:/usr/bin:/bin', 'FAKE_IPT_STATE': str(self.state),
               'STORAGEFORGE_BRIDGE': bridge, 'STORAGEFORGE_EGRESS_PORTS': ports}
        p = subprocess.run(['sh', str(FIREWALL), *args], env=env, capture_output=True, text=True, timeout=60)
        return p.returncode, json.loads(self.state.read_text())

    def chains(self, st):
        return {c: rs for c, rs in st['chains'].items() if c not in ('DOCKER-USER', 'INPUT')}

    def test_each_bridge_keeps_its_rules_and_never_opens(self):
        self.assertEqual(self.fw()[0], 0)
        rc, st = self.fw(bridge='sfdemo0')
        self.assertEqual(rc, 0)
        self.assertEqual(set(self.chains(st)), {'SF-EGRESS-sf0', 'SF-EGRESS-sfdemo0'})
        self.assertIn('-i sf0 -j SF-EGRESS-sf0', st['chains']['INPUT'])               # the Docker host itself
        rc, st = self.fw(ports='22 2222')                                               # re-run with new ports
        self.assertEqual(rc, 0)
        self.assertEqual(set(self.chains(st)), {'SF-EGRESS-sf0-b', 'SF-EGRESS-sfdemo0'})
        self.assertIn('-p tcp --dport 2222 -j RETURN', st['chains']['SF-EGRESS-sf0-b'])
        before = st
        rc, st = self.fw(ports='22 70000')                                              # refused before any change
        self.assertEqual((rc, st), (2, before))
        rc, st = self.fw('--remove')
        self.assertEqual(set(self.chains(st)), {'SF-EGRESS-sfdemo0'})
        self.assertFalse([r for rs in st['chains'].values() for r in rs if '-i sf0' in r])
        self.assertEqual(st['opened'], ['sf0'])                                         # only by --remove

    def test_moves_off_the_shared_legacy_chain(self):
        import json
        st = json.loads(self.state.read_text())
        st['chains']['SF-EGRESS'] = ['-j REJECT']
        for br in ('sf0', 'sfdemo0'):
            st['chains']['DOCKER-USER'].append(f'-i {br} ! -o {br} -j SF-EGRESS')
            st['chains']['INPUT'].append(f'-i {br} -j SF-EGRESS')    # as if the host had been covered too
        self.state.write_text(json.dumps(st))
        rc, st = self.fw()
        self.assertEqual(rc, 0)
        self.assertEqual(set(self.chains(st)), {'SF-EGRESS', 'SF-EGRESS-sf0'})        # sfdemo0 still uses it
        rc, st = self.fw(bridge='sfdemo0')
        self.assertEqual(set(self.chains(st)), {'SF-EGRESS-sf0', 'SF-EGRESS-sfdemo0'})  # the last user moved off
        self.assertEqual(st['opened'], [])
