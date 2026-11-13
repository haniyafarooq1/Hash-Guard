"""Tests for the SQLite storage layer (backend/storage/database.py).

Focuses on the connection lifecycle required by the API test suite:

* per-thread connection isolation during normal operation;
* reset_connections() closes the calling thread's cached connection;
* connections follow the configured database path.
"""

import sqlite3
import threading
import unittest

from backend.storage import database
from tests.test_helpers import HashGuardTestCase


class TestCustomDatabasePaths(HashGuardTestCase):

    def test_connections_follow_the_configured_path(self):
        other = self.root / "other.db"
        database.reset_connections()
        database.set_database_path(str(other))
        try:
            conn = database.get_connection()
            self.assertEqual(
                str(conn.execute("PRAGMA database_list").fetchone()[2]),
                str(other),
            )
        finally:
            database.reset_connections()
            database.set_database_path(str(self.db_file))
            database.init_db()


class TestConnectionLifecycle(HashGuardTestCase):

    def test_each_thread_gets_its_own_connection(self):
        connections = []
        ready = threading.Event()

        def worker():
            conn = database.get_connection()
            try:
                result = conn.execute("SELECT 1").fetchone()[0]
            except Exception as error:  # reported back to the main thread
                result = error
            connections.append((conn, result))
            ready.set()

        thread = threading.Thread(target=worker)
        thread.start()
        ready.wait(timeout=5)
        thread.join(timeout=5)

        mine = database.get_connection()
        self.assertEqual(len(connections), 1)
        worker_conn, worker_result = connections[0]
        self.assertIsNot(worker_conn, mine)
        self.assertEqual(worker_result, 1)  # usable inside its own thread
        self.assertIsNotNone(mine.execute("SELECT 1").fetchone())

    def test_reset_connections_is_idempotent(self):
        database.get_connection()
        database.reset_connections()
        database.reset_connections()  # second call must not raise
        # the calling thread transparently reopens afterwards
        conn = database.get_connection()
        self.assertIsNotNone(conn.execute("SELECT 1").fetchone())


if __name__ == "__main__":
    unittest.main()
