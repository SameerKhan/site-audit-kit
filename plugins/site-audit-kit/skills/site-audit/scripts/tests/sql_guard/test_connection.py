"""GuardedConnection against a fake DB-API connection. No driver, no database."""
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import testcfg  # noqa: E402
testcfg.use_config()

import sql_guard  # noqa: E402
from sql_guard import GuardedConnection, GuardRejected, GuardSetupError  # noqa: E402

SECRET_ROW = "SECRET-ROW-VALUE-do-not-log"


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = None
        self._rows = []
        self.closed = False

    def execute(self, sql, params=None, *a, **k):
        if params is not None:
            raise AssertionError("the guard must never pass params to the driver")
        self.conn.executed.append(sql)
        result = self.conn.responder(sql)
        if isinstance(result, Exception):
            raise result
        self.description, self._rows = result

    def fetchall(self):
        return list(self._rows)

    def close(self):
        self.closed = True


class FakeConnection:
    """Answers the setup probes like a server; everything else returns one secret row."""

    def __init__(self, *, read_only_var="transaction_read_only", read_only_value=1,
                 database="audit_site", grants=None, user="audit_reader@127.0.0.1"):
        self.executed = []
        self.read_only_var = read_only_var
        self.read_only_value = read_only_value
        self.database = database
        self.user = user
        self.grants = grants if grants is not None else [
            ("GRANT USAGE ON *.* TO `audit_reader`@`127.0.0.1`",),
            ("GRANT SELECT ON `audit_site`.`wp_posts` TO `audit_reader`@`127.0.0.1`",),
        ]
        self.cursors = []

    def cursor(self):
        c = FakeCursor(self)
        self.cursors.append(c)
        return c

    def responder(self, sql):
        if sql == "SET SESSION TRANSACTION READ ONLY":
            return None, []
        if sql.startswith("SELECT @@SESSION."):
            var = sql.split(".", 1)[1]
            if var != self.read_only_var:
                return Exception(f"Unknown system variable '{var}'")
            return [(var,)], [(self.read_only_value,)]
        if sql == "SELECT DATABASE()":
            return [("DATABASE()",)], [(self.database,)]
        if sql == "SELECT CURRENT_USER()":
            return [("CURRENT_USER()",)], [(self.user,)]
        if sql == "SHOW GRANTS FOR CURRENT_USER()":
            return [("Grants",)], list(self.grants)
        return [("c",)], [(SECRET_ROW,)]


class GuardedConnectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "db-statements.log")

    def tearDown(self):
        self.tmp.cleanup()

    def records(self):
        with open(self.log, encoding="ascii") as fh:
            return [json.loads(line) for line in fh]

    def test_set_read_only_runs_first_and_is_verified(self):
        conn = FakeConnection()
        with GuardedConnection(conn, "site_ro", self.log):
            pass
        self.assertEqual(conn.executed[0], "SET SESSION TRANSACTION READ ONLY")
        self.assertEqual(conn.executed[1], "SELECT @@SESSION.transaction_read_only")
        self.assertIn("SELECT DATABASE()", conn.executed)
        self.assertTrue(all(c.closed for c in conn.cursors))

    def test_mariadb_tx_read_only_fallback(self):
        conn = FakeConnection(read_only_var="tx_read_only")
        with GuardedConnection(conn, "site", self.log):
            pass
        self.assertIn("SELECT @@SESSION.tx_read_only", conn.executed)

    def test_not_read_only_refuses_to_start(self):
        conn = FakeConnection(read_only_value=0)
        with self.assertRaises(GuardSetupError):
            GuardedConnection(conn, "site", self.log)
        conn = FakeConnection(read_only_var="something_else")
        with self.assertRaises(GuardSetupError):
            GuardedConnection(conn, "site", self.log)

    def test_readonly_default_database_must_match(self):
        conn = FakeConnection(database="wordpress")
        with self.assertRaises(GuardSetupError):
            GuardedConnection(conn, "site_ro", self.log)
        conn = FakeConnection(database="audit_site")
        with self.assertRaises(GuardSetupError):
            GuardedConnection(conn, "blog_ro", self.log)
        GuardedConnection(FakeConnection(database="audit_blog"), "blog_ro", self.log).close()

    def test_allowed_statement_runs_and_returns_rows(self):
        conn = FakeConnection()
        with GuardedConnection(conn, "site", self.log) as g:
            rows = g.execute("SELECT option_value FROM wp_options WHERE option_name='siteurl'")
            self.assertEqual(rows, [(SECRET_ROW,)])
            self.assertEqual(g.description, [("c",)])
        self.assertIn("SELECT option_value FROM wp_options WHERE option_name='siteurl'",
                      conn.executed)

    def test_rejected_statement_never_reaches_the_driver(self):
        bad = [
            "SELECT * FROM wp_users",
            "SELECT 1; DROP TABLE wp_posts",
            "SELECT /*! SLEEP(5) */ 1",
            "SELECT * FROM wp_terms INTO OUTFILE '/tmp/x'",
            "SET SESSION TRANSACTION READ WRITE",
            "SELECT option_value FROM wp_options",
            "UPDATE wp_posts SET post_title = post_title WHERE 1 = 0",
        ]
        conn = FakeConnection()
        with GuardedConnection(conn, "site", self.log) as g:
            before = list(conn.executed)
            for sql in bad:
                with self.subTest(sql=sql):
                    with self.assertRaises(GuardRejected) as cm:
                        g.execute(sql)
                    self.assertIsNotNone(cm.exception.verdict)
                    self.assertFalse(cm.exception.verdict.allowed)
            self.assertEqual(conn.executed, before)

    def test_params_are_refused(self):
        conn = FakeConnection()
        with GuardedConnection(conn, "site", self.log) as g:
            before = list(conn.executed)
            with self.assertRaises(GuardRejected):
                g.execute("SELECT option_value FROM wp_options WHERE option_name = %s",
                          ("siteurl",))
            self.assertEqual(conn.executed, before)

    def test_log_mode_600_has_statements_not_rows(self):
        conn = FakeConnection()
        with GuardedConnection(conn, "site", self.log) as g:
            g.execute("SELECT name FROM wp_terms")
            with self.assertRaises(GuardRejected):
                g.execute("SELECT * FROM wp_users")
        mode = stat.S_IMODE(os.stat(self.log).st_mode)
        self.assertEqual(mode, 0o600)
        with open(self.log, encoding="ascii") as fh:
            text = fh.read()
        self.assertNotIn(SECRET_ROW, text)
        recs = self.records()
        self.assertEqual(recs[0]["verdict"], "internal")
        self.assertEqual(recs[0]["sql"], "SET SESSION TRANSACTION READ ONLY")
        verdicts = [(r["verdict"], r["sql"]) for r in recs]
        self.assertIn(("allowed", "SELECT name FROM wp_terms"), verdicts)
        self.assertIn(("done", "SELECT name FROM wp_terms"), verdicts)
        self.assertIn(("rejected", "SELECT * FROM wp_users"), verdicts)
        done = [r for r in recs if r["verdict"] == "done"][0]
        self.assertEqual(done["rows"], 1)
        rejected = [r for r in recs if r["verdict"] == "rejected"][0]
        self.assertTrue(rejected["reasons"])

    def test_existing_log_is_tightened_and_appended(self):
        with open(self.log, "w") as fh:
            fh.write('{"verdict": "old"}\n')
        os.chmod(self.log, 0o644)
        GuardedConnection(FakeConnection(), "site", self.log).close()
        self.assertEqual(stat.S_IMODE(os.stat(self.log).st_mode), 0o600)
        self.assertEqual(self.records()[0]["verdict"], "old")

    def test_symlinked_log_is_refused(self):
        target = os.path.join(self.tmp.name, "target")
        open(target, "w").close()
        link = os.path.join(self.tmp.name, "link.log")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            GuardedConnection(FakeConnection(), "site", link)

    def test_identity_classifies_grants(self):
        conn = FakeConnection()
        with GuardedConnection(conn, "site_ro", self.log) as g:
            ident = g.identity()
        self.assertTrue(ident["select_only"], ident["reasons"])
        self.assertEqual(ident["current_user"], "audit_reader@127.0.0.1")
        self.assertIn("SHOW GRANTS FOR CURRENT_USER()", conn.executed)

    def test_identity_admin_is_not_select_only(self):
        conn = FakeConnection(grants=[("GRANT ALL PRIVILEGES ON *.* TO `wordpress`@`localhost` "
                                       "WITH GRANT OPTION",)], user="wordpress@localhost")
        with GuardedConnection(conn, "site", self.log) as g:
            ident = g.identity()
        self.assertFalse(ident["select_only"])

    def test_identity_readonly_rejects_grant_on_wordpress_db(self):
        conn = FakeConnection(grants=[
            ("GRANT USAGE ON *.* TO `audit_reader`@`127.0.0.1`",),
            ("GRANT SELECT ON `wordpress`.`wp_posts` TO `audit_reader`@`127.0.0.1`",)])
        with GuardedConnection(conn, "site_ro", self.log) as g:
            self.assertFalse(g.identity()["select_only"])

    def test_reassert_reruns_setup(self):
        conn = FakeConnection()
        with GuardedConnection(conn, "site", self.log) as g:
            g.reassert()
        self.assertEqual(conn.executed.count("SET SESSION TRANSACTION READ ONLY"), 2)

    def test_driver_error_is_logged_and_raised(self):
        conn = FakeConnection()
        with GuardedConnection(conn, "site", self.log) as g:
            conn.responder = lambda sql: RuntimeError("boom")
            with self.assertRaises(RuntimeError):
                g.execute("SELECT name FROM wp_terms")
        self.assertIn("error", [r["verdict"] for r in self.records()])

    def test_closed_wrapper_refuses(self):
        g = GuardedConnection(FakeConnection(), "site", self.log)
        g.close()
        with self.assertRaises(GuardSetupError):
            g.execute("SELECT name FROM wp_terms")

    def test_module_does_not_import_a_driver(self):
        with open(sql_guard.__file__, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("import mysql", src)
        self.assertNotIn("import pymysql", src)
        self.assertNotIn("import MySQLdb", src)


if __name__ == "__main__":
    unittest.main()
