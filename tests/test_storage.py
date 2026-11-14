"""Tests for the SQLite storage layer (backend/storage/database.py).

Focuses on the connection lifecycle required by the API test suite:

* per-thread connection isolation during normal operation;
* parent directories of custom database paths are created automatically;
* reset_connections() closes the connections created by OTHER threads
  (FastAPI TestClient serves requests in worker threads; on Windows an
  open handle in one of those threads used to keep the temporary
  database file undeletable - WinError 32 - during test teardown);
* a worker thread whose cached connection was closed by a reset
  transparently reopens on its next use.
"""

import queue
import sqlite3
import threading
import unittest
from pathlib import Path

from backend.storage import database
from tests.test_helpers import HashGuardTestCase


class TestCustomDatabasePaths(HashGuardTestCase):

    def test_parent_directories_of_custom_paths_are_created(self):
        nested = self.root / "a" / "b" / "c" / "hashguard.db"
        database.reset_connections()
        database.set_database_path(str(nested))
        try:
            database.init_db()
            self.assertTrue(nested.parent.is_dir())
            self.assertTrue(nested.exists())
        finally:
            database.reset_connections()
            database.set_database_path(str(self.db_file))
            database.init_db()

    def test_connections_follow_the_configured_path(self):
        nested = self.root / "nested" / "other.db"
        database.reset_connections()
        database.set_database_path(str(nested))
        try:
            conn = database.get_connection()
            self.assertEqual(
                str(conn.execute("PRAGMA database_list").fetchone()[2]),
                str(nested),
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
            connections.append(database.get_connection())
            ready.set()

        thread = threading.Thread(target=worker)
        thread.start()
        ready.wait(timeout=5)
        thread.join(timeout=5)

        mine = database.get_connection()
        self.assertEqual(len(connections), 1)
        self.assertIsNot(connections[0], mine)
        # both are open and usable concurrently
        self.assertIsNotNone(connections[0].execute("SELECT 1").fetchone())
        self.assertIsNotNone(mine.execute("SELECT 1").fetchone())

    def test_reset_connections_closes_other_threads_connections(self):
        """The WinError 32 scenario: connections created inside worker
        threads must be closed by a reset on the main thread."""
        connections = []
        ready = threading.Event()

        def worker():
            connections.append(database.get_connection())
            ready.set()

        threads = []
        for _ in range(3):
            ready.clear()
            thread = threading.Thread(target=worker)
            thread.start()
            ready.wait(timeout=5)
            thread.join(timeout=5)
            threads.append(thread)

        self.assertEqual(len(connections), 3)
        # all three worker connections are open before the reset
        for conn in connections:
            self.assertIsNotNone(conn.execute("SELECT 1").fetchone())

        # the reset (test teardown situation) closes ALL of them
        database.reset_connections()

        for conn in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")
        self.assertEqual(len(database._registry), 0)

    def test_worker_thread_reopens_after_its_connection_was_reset(self):
        """A pooled worker thread with a stale cached connection must
        transparently reopen instead of failing."""
        requests = queue.Queue()
        replies = queue.Queue()

        def worker():
            first = database.get_connection()
            replies.put(first)
            requests.get(timeout=10)          # wait for the main-thread reset
            second = database.get_connection()
            replies.put(second)
            # prove the reopened connection actually works
            replies.put(second.execute("SELECT 1").fetchone()[0])

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            first = replies.get(timeout=10)
            database.reset_connections()       # closes the worker's connection
            requests.put("go")
            second = replies.get(timeout=10)
            value = replies.get(timeout=10)

            self.assertIsNot(first, second)
            self.assertEqual(value, 1)
            # the stale connection is really closed, the new one is live
            with self.assertRaises(sqlite3.ProgrammingError):
                first.execute("SELECT 1")
            self.assertIsNotNone(second.execute("SELECT 1").fetchone())
        finally:
            requests.put("go")
            thread.join(timeout=10)
            database.reset_connections()

    def test_reset_connections_is_idempotent(self):
        database.get_connection()
        database.reset_connections()
        database.reset_connections()  # second call must not raise
        self.assertEqual(len(database._registry), 0)


if __name__ == "__main__":
    unittest.main()
