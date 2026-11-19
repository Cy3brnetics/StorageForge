"""Test databases: SQLite in the test's temporary folder, or, when STORAGEFORGE_TEST_PG is a PostgreSQL server URL
(postgresql://user:password@127.0.0.1:5432/postgres, say a throwaway container), a fresh database per test that is
dropped afterwards. The same tests then cover both dialects.

On PostgreSQL a test's database is a copy of a template that already has every migration in it, so `db.migrate(conn)` in a
test finds nothing left to do. Running the 45 migrations into a new database for each of two thousand tests was most of what
made the PostgreSQL run take half an hour. The template is made once per set of migration files (its name holds their hash),
by whichever worker gets there first; the others wait on a lock and find it made. A test of the migrations themselves asks
for an empty database with `empty=True`.

Set STORAGEFORGE_TEST_PG_TEMPLATE=0 to migrate every database from nothing, as before.
"""
import hashlib
import os
import time
import uuid
from pathlib import Path

from storageforge_index.db import MIGRATIONS, Database

PG = os.environ.get('STORAGEFORGE_TEST_PG', '')
LOCK = 5_021_579          # the advisory lock that keeps two workers from making the template at once
_template = None


def _migrations_hash() -> str:
    h = hashlib.sha256()
    for f in sorted((Path(MIGRATIONS) / 'postgres').glob('*.sql')):
        h.update(f.name.encode() + b'\0' + f.read_bytes() + b'\0')
    return h.hexdigest()[:16]


def template() -> str:
    """The name of the migrated template database on the test server, made if it is not there."""
    global _template
    if _template:
        return _template
    import psycopg
    name = 'sf_tmpl_' + _migrations_hash()
    with psycopg.connect(PG, autocommit=True) as c:
        c.execute('SELECT pg_advisory_lock(%s)', (LOCK,))
        try:
            if not c.execute('SELECT 1 FROM pg_database WHERE datname = %s AND datistemplate', (name,)).fetchone():
                # one that was left half made by a run that was stopped, and the templates of migrations that have since changed
                for (old,) in c.execute("SELECT datname FROM pg_database WHERE datname LIKE 'sf\\_tmpl\\_%'").fetchall():
                    c.execute(f'ALTER DATABASE {old} IS_TEMPLATE false')
                    c.execute(f'DROP DATABASE IF EXISTS {old} WITH (FORCE)')
                c.execute(f'CREATE DATABASE {name}')
                db = Database(PG.rsplit('/', 1)[0] + '/' + name)
                conn = db.connect()
                try:
                    db.migrate(conn)
                finally:
                    conn.close()
                c.execute(f'ALTER DATABASE {name} IS_TEMPLATE true')          # marked last: a template without the mark is not finished
        finally:
            c.execute('SELECT pg_advisory_unlock(%s)', (LOCK,))
    _template = name
    return name


def make(case, sqlite_path, empty: bool = False) -> Database:
    if not PG:
        return Database(str(sqlite_path))
    import psycopg
    name = 'sf_test_' + uuid.uuid4().hex[:12]
    source = '' if empty or os.environ.get('STORAGEFORGE_TEST_PG_TEMPLATE') == '0' else f' TEMPLATE {template()}'
    with psycopg.connect(PG, autocommit=True) as c:
        for attempt in range(50):
            try:
                c.execute(f'CREATE DATABASE {name}{source}')
                # a test's database is dropped in a moment: no commit in it has to wait for the disk. This loses nothing but
                # the last commits if the server stops, and it is this database's setting alone
                c.execute(f'ALTER DATABASE {name} SET synchronous_commit = off')
                break
            except psycopg.errors.ObjectInUse:          # PostgreSQL copies a template for one session at a time
                if attempt == 49:
                    raise
                time.sleep(0.05)

    def drop():
        with psycopg.connect(PG, autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS {name} WITH (FORCE)')
    case.addCleanup(drop)
    return Database(PG.rsplit('/', 1)[0] + '/' + name)
