"""Regression tests: prefix + extra_tables splits, install value types, identity gate.

No database, no network: installs come from throwaway configs, connections are fakes.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
sys.path.insert(0, HERE)
import testcfg  # noqa: E402
testcfg.use_config()
import sql_guard  # noqa: E402
from sql_guard import (GuardedConnection, GuardSetupError, InstallPolicy,  # noqa: E402
                       check_statement)
from test_connection import FakeConnection  # noqa: E402

USERS_Q = "SELECT user_login, user_pass FROM wp_users"
POSTS_Q = "SELECT post_password, post_content FROM wp_posts"


def build(**inst):
    """sql_guard's own policy build for one install 'x' with these settings (defaults filled
    in by audit_config.install_settings, bypassing the loader so sql_guard is tested alone)."""
    import audit_config
    cfg = {"db": {"installs": {"x": inst}, "public_post_types": ["post", "page"]}}
    return sql_guard._policy_from_settings("x", audit_config.install_settings(cfg, "x"))


class ExtraTableSplits(unittest.TestCase):
    """Finding 1: prefix + extra table must never resolve to a protected core table."""

    SPLITS = [
        ("wp", "_users"), ("w", "p_users"), ("wp", "_usermeta"), ("wp", "_comments"),
        ("wp", "_commentmeta"), ("wp_po", "sts"), ("wp_p", "osts"), ("wp_", "2_posts"),
        ("wp_post", "meta"), ("wp_opt", "ions"), ("wp_", "2_users"), ("WP", "_Users"),
        ("Wp", "_COMMENTS"), ("wp", "_options"), ("wp", "_postmeta"), ("wp_us", "ers"),
        ("wp_user", "meta"), ("wp_comment", "meta"), ("x", "users"), ("wp_", "blog_users"),
    ]

    def test_config_split_variants_are_refused(self):
        for prefix, extra in self.SPLITS:
            with self.subTest(prefix=prefix, extra=extra):
                with self.assertRaises(ValueError) as cm:
                    build(prefix=prefix, extra_tables=["terms", extra])
                self.assertIn("extra", str(cm.exception))

    def test_split_cannot_read_users_or_unfiltered_posts(self):
        for prefix, extra, q in (("wp", "_users", USERS_Q),
                                 ("w", "p_users", "SELECT u.user_pass FROM wp_users AS u"),
                                 ("wp", "_usermeta", "SELECT meta_value FROM wp_usermeta"),
                                 ("wp_po", "sts", POSTS_Q),
                                 ("wp", "_users", "SELECT user_pass FROM `wp_users`"),
                                 ("wp", "_users", "SELECT user_pass FROM WP_USERS")):
            with self.subTest(prefix=prefix, extra=extra, q=q):
                cfg = testcfg.merged(db={"installs": {"x": {"prefix": prefix,
                                                            "extra_tables": [extra]}}})
                testcfg.use_config(cfg)
                sql_guard._INSTALL_CACHE.clear()
                v = check_statement(q, "x")
                self.assertFalse(v, v)
        testcfg.use_config()
        sql_guard._INSTALL_CACHE.clear()

    def test_hand_built_policy_is_checked_too(self):
        for prefix, extra, q in (("wp", "_users", USERS_Q), ("wp_po", "sts", POSTS_Q)):
            pol = InstallPolicy(name="h", prefix=prefix, extra_tables=frozenset({extra}))
            v = check_statement(q, pol)
            self.assertFalse(v)
            self.assertIn("extra table", " ".join(v.reasons))

    def test_cli_prefix_with_config_extra_table_is_refused(self):
        cfg = testcfg.merged(db={"installs": {"x": {"extra_tables": ["meta", "terms"]}}})
        # Under the default prefix wp_ the full name is wp_meta: allowed (not a core table).
        testcfg.use_config(cfg)
        sql_guard._INSTALL_CACHE.clear()
        meta_q = "SELECT meta_value FROM wp_usermeta"
        try:
            self.assertTrue(check_statement("SELECT a FROM wp_meta", "x"))
            v = check_statement(meta_q, "x", prefix="wp_user")
            self.assertFalse(v)
            self.assertIn("extra table", " ".join(v.reasons))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = sql_guard._main(["--install", "x", "--prefix", "wp_user", meta_q])
            self.assertEqual(rc, 1)
            self.assertFalse(json.loads(buf.getvalue())["allowed"])
            cfg2 = testcfg.merged(db={"installs": {"x": {"extra_tables": ["sts"]}}})
            testcfg.use_config(cfg2)
            sql_guard._INSTALL_CACHE.clear()
            self.assertFalse(check_statement(POSTS_Q, "x", prefix="wp_po"))
            # GuardedConnection with a prefix override goes through the same check.
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    GuardedConnection(FakeConnection(), "x", os.path.join(d, "l"),
                                      prefix="wp_po")
        finally:
            testcfg.use_config()
            sql_guard._INSTALL_CACHE.clear()

    def test_quoted_or_odd_extra_tables_refused(self):
        for extra in ("`_users`", "`users`", "wp users", "users;", "", "x.users", "users​"):
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    build(extra_tables=[extra])

    def test_legitimate_extras_still_work(self):
        pol = build(extra_tables=["terms", "rank_math_redirections", "redirection_items"])
        self.assertTrue(check_statement("SELECT url FROM wp_redirection_items", pol))
        self.assertTrue(check_statement("SELECT name FROM WP_TERMS", pol))
        self.assertFalse(check_statement(USERS_Q, pol))


class InstallValueTypes(unittest.TestCase):
    """Finding 2: install values are type checked, never coerced."""

    def test_views_and_attended_only_must_be_booleans(self):
        for key in ("views", "attended_only"):
            for bad in ([], "false", "true", 0, 1, None, {}, 0.0):
                with self.subTest(key=key, bad=bad):
                    inst = {key: bad}
                    if key == "views":
                        inst["schema"] = "audit_views"
                    with self.assertRaises(ValueError) as cm:
                        build(**inst)
                    self.assertIn(key, str(cm.exception))
        self.assertTrue(build(views=True, schema="audit_views").views)
        self.assertFalse(build(views=False).views)

    def test_falsey_views_cannot_skip_views_checks(self):
        # The original exploit: "views": [] silently became views=False.
        with self.assertRaises(ValueError):
            build(views=[], schema="audit_views")

    def test_lists_must_be_lists_of_strings(self):
        for key in ("option_names", "meta_keys", "meta_prefixes", "template_post_types",
                    "extra_tables", "public_post_types", "residue_hosts"):
            for bad in ("siteurl", ["ok", 1], [None], [""], {"a": 1}, 5, True, [["x"]]):
                with self.subTest(key=key, bad=bad):
                    with self.assertRaises(ValueError):
                        build(**{key: bad})

    def test_prefix_shape(self):
        for bad in ("", "wp_; DROP", "wp-", "wp.", "a" * 33, 5, None, ["wp_"], "wp_\n",
                    "wé_"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    build(prefix=bad)
        self.assertEqual(build(prefix="a" * 32).prefix, "a" * 32)
        self.assertEqual(build(prefix="wp_2_").prefix, "wp_2_")

    def test_cli_prefix_shape(self):
        for bad in ("", "a" * 33, "wp_;", "wp_ "):
            with self.subTest(bad=bad):
                self.assertFalse(check_statement("SELECT name FROM wp_terms", "site", prefix=bad))

    def test_schema_is_plain_identifier(self):
        for bad in ("audit-views", "a.b", "a b", "`a`", "", "a" * 65, 5, ["a"], "a$b"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    build(views=True, schema=bad)

    def test_columns_values_are_lists_of_strings(self):
        for bad in ("ID", ["ID", 5], [None], {"ID": 1}, 7):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    build(columns={"posts": bad})
        for bad in ([], "x", 1):
            with self.subTest(columns=bad):
                with self.assertRaises(ValueError):
                    build(columns=bad)

    def test_hand_built_policy_types(self):
        for kw in ({"views": "false"}, {"attended_only": 0}, {"prefix": "wp; x"},
                   {"option_names": "siteurl"}, {"schema": "a-b"}):
            with self.subTest(kw=kw):
                v = check_statement("SELECT name FROM wp_terms", InstallPolicy(name="h", **kw))
                self.assertFalse(v)


class IdentityGate(unittest.TestCase):
    """Finding 3: GuardedConnection establishes identity before any user statement."""

    ADMIN = [("GRANT ALL PRIVILEGES ON *.* TO `wordpress`@`localhost` WITH GRANT OPTION",)]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "sql.log")

    def tearDown(self):
        self.tmp.cleanup()

    def records(self):
        with open(self.log, encoding="ascii") as fh:
            return [json.loads(line) for line in fh]

    def test_identity_runs_after_read_only_setup(self):
        conn = FakeConnection()
        with GuardedConnection(conn, "site", self.log) as g:
            self.assertTrue(g.identity_result["select_only"])
        ex = conn.executed
        self.assertEqual(ex[0], "SET SESSION TRANSACTION READ ONLY")
        self.assertLess(ex.index("SELECT @@SESSION.transaction_read_only"),
                        ex.index("SELECT CURRENT_USER()"))
        self.assertLess(ex.index("SELECT CURRENT_USER()"),
                        ex.index("SHOW GRANTS FOR CURRENT_USER()"))

    def test_admin_identity_refused_and_nothing_runs(self):
        conn = FakeConnection(grants=self.ADMIN, user="wordpress@localhost")
        with self.assertRaises(GuardSetupError) as cm:
            GuardedConnection(conn, "site", self.log)
        self.assertIn("not SELECT-only", str(cm.exception))
        self.assertNotIn("SELECT name FROM wp_terms", conn.executed)
        self.assertEqual(conn.executed[-1], "SHOW GRANTS FOR CURRENT_USER()")

    def test_missing_or_broken_grants_refused(self):
        for grants in ([], [("garbage line",)], [(None,)]):
            with self.subTest(grants=grants):
                with self.assertRaises(GuardSetupError):
                    GuardedConnection(FakeConnection(grants=grants), "site", self.log)

    def test_show_grants_error_refused(self):
        conn = FakeConnection()
        base = conn.responder
        conn.responder = lambda sql: (RuntimeError("denied") if sql.startswith("SHOW GRANTS")
                                      else base(sql))
        with self.assertRaises(GuardSetupError):
            GuardedConnection(conn, "site", self.log)

    def test_views_install_grants_must_name_its_schema(self):
        conn = FakeConnection(grants=[
            ("GRANT USAGE ON *.* TO `audit_reader`@`127.0.0.1`",),
            ("GRANT SELECT ON `wordpress`.* TO `audit_reader`@`127.0.0.1`",)])
        with self.assertRaises(GuardSetupError):
            GuardedConnection(conn, "site_ro", self.log)

    def test_attended_continues_with_loud_warning(self):
        conn = FakeConnection(grants=self.ADMIN, user="wordpress@localhost")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with GuardedConnection(conn, "site", self.log, attended=True) as g:
                self.assertEqual(g.execute("SELECT name FROM wp_terms"),
                                 [("SECRET-ROW-VALUE-do-not-log",)])
        self.assertIn("WARNING", err.getvalue())
        self.assertIn("NOT SELECT-only", err.getvalue())
        self.assertIn("identity_override", [r["verdict"] for r in self.records()])

    def test_attended_must_be_a_real_boolean(self):
        conn = FakeConnection(grants=self.ADMIN)
        for bad in (1, "yes", "true", [1]):
            with self.subTest(bad=bad):
                with self.assertRaises(GuardSetupError):
                    GuardedConnection(conn, "site", self.log, attended=bad)

    def test_reassert_rechecks_identity(self):
        conn = FakeConnection()
        g = GuardedConnection(conn, "site", self.log)
        self.addCleanup(g.close)
        conn.grants = self.ADMIN  # e.g. a reconnect landed on another user
        with self.assertRaises(GuardSetupError):
            g.reassert()
        with self.assertRaises(GuardSetupError):
            g.execute("SELECT name FROM wp_terms")
        self.assertNotIn("SELECT name FROM wp_terms", conn.executed)

    def test_select_only_identity_runs_statements(self):
        conn = FakeConnection()
        with GuardedConnection(conn, "site", self.log) as g:
            g.execute("SELECT name FROM wp_terms")
        self.assertIn("SELECT name FROM wp_terms", conn.executed)


if __name__ == "__main__":
    unittest.main()


class AttendedOnlyEnforced(unittest.TestCase):
    """An install marked attended_only refuses a connection unless attended=True is passed."""

    def test_attended_only_install_needs_attended_true(self):
        pol = InstallPolicy("ops", attended_only=True)
        log = os.path.join(tempfile.mkdtemp(), "sql.log")
        with self.assertRaises(GuardSetupError):
            GuardedConnection(FakeConnection(), pol, log)
