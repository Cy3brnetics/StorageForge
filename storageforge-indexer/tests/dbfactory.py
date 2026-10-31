"""Test databases: SQLite in the test's temporary folder, or, when STORAGEFORGE_TEST_PG is a PostgreSQL server URL
(postgresql://user:password@127.0.0.1:5432/postgres, say a throwaway container), a fresh database per test that is
dropped afterwards. The same tests then cover both dialects."""
import os
import uuid

from storageforge_index.db import Database

PG = os.environ.get('STORAGEFORGE_TEST_PG', '')


def make(case, sqlite_path) -> Database:
    if not PG:
        return Database(str(sqlite_path))
    import psycopg
    name = 'sf_test_' + uuid.uuid4().hex[:12]
    with psycopg.connect(PG, autocommit=True) as c:
        c.execute(f'CREATE DATABASE {name}')

    def drop():
        with psycopg.connect(PG, autocommit=True) as c:
            c.execute(f'DROP DATABASE IF EXISTS {name} WITH (FORCE)')
    case.addCleanup(drop)
    return Database(PG.rsplit('/', 1)[0] + '/' + name)
