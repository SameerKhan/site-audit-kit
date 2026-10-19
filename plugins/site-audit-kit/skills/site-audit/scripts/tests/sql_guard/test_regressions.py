"""Regression tests for sql_guard: views installs, residue mode, grant classification and
grant-line redaction. No database.

Set SQL_GUARD_UNDER_TEST to another copy of sql_guard.py's directory to run these against it.
"""
import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(__file__)
sys.path.insert(0, os.environ.get("SQL_GUARD_UNDER_TEST")
                or os.path.abspath(os.path.join(_HERE, "..", "..")))
sys.path.insert(1, _HERE)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import testcfg  # noqa: E402
testcfg.use_config()

import sql_guard  # noqa: E402
from sql_guard import (GuardedConnection, GuardRejected, GuardSetupError, check_statement,  # noqa: E402
                       classify_grants)
from test_connection import FakeConnection  # noqa: E402

PUB = "p.post_status = 'publish' AND p.post_type IN ('page','post')"
HASH = "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"


def _ok(sql, install, **kw):
    return check_statement(sql, install, **kw).allowed


class ViewsDefenceInDepth(unittest.TestCase):
    """Read-only views installs skipped every column and row check."""

    REJECT = [
        "SELECT post_password FROM wp_posts",
        "SELECT post_password FROM wp_posts WHERE post_type = 'page'",
        "SELECT p.post_password FROM wp_posts p WHERE p.post_type = 'page'",
        "SELECT post_author, post_excerpt FROM wp_posts WHERE post_type = 'page'",
        "SELECT guid FROM wp_posts WHERE post_type = 'page'",
        "SELECT * FROM wp_posts",
        "SELECT * FROM wp_posts WHERE post_type = 'page'",
        "SELECT p.* FROM wp_posts p WHERE p.post_type = 'page'",
        "SELECT * FROM wp_options",
        "SELECT option_value FROM wp_options",
        "SELECT option_value FROM wp_options WHERE option_name = 'admin_email'",
        "SELECT option_value FROM wp_options WHERE option_name LIKE 'rank%'",
        "SELECT option_value FROM wp_options WHERE option_name = 'siteurl' OR 1 = 1",
        "SELECT name FROM wp_terms UNION SELECT option_value FROM wp_options "
        "WHERE option_name = 'admin_email'",
        "SELECT name FROM wp_terms WHERE (SELECT COUNT(*) FROM wp_options) > 0",
        "SELECT * FROM wp_users",
        "SELECT user_pass FROM wp_users",
        "SELECT * FROM wp_usermeta",
        "SELECT * FROM wp_comments",
        "SELECT * FROM wp_wpforms_entries",
        "SELECT post_content FROM wp_posts",
        "SELECT post_content FROM wp_posts WHERE post_type = 'revision'",
        "SELECT post_content FROM wp_posts WHERE post_status = 'draft' AND post_type = 'page'",
        "SELECT meta_value FROM wp_postmeta WHERE meta_key = '_elementor_data'",
        "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID "
        "WHERE " + PUB + " AND m.meta_key = '_edit_lock'",
        "SELECT COUNT(*) FROM wp_posts",
    ]
    ALLOW = [
        "SELECT ID, post_title, post_name FROM wp_posts WHERE post_type = 'page' "
        "AND post_status = 'publish'",
        "SELECT post_content FROM wp_posts WHERE post_status = 'publish' AND post_type = 'post'",
        "SELECT option_value FROM wp_options WHERE option_name = 'siteurl'",
        "SELECT option_name, option_value FROM wp_options WHERE option_name IN "
        "('siteurl','home','permalink_structure','blog_public','rank-math-options-titles')",
        "SELECT p.ID, m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID "
        "WHERE " + PUB + " AND m.meta_key = '_elementor_data'",
        "SELECT * FROM wp_terms",
        "SELECT * FROM wp_rank_math_redirections",
        "SELECT COUNT(*) FROM audit_site.wp_posts WHERE post_type <> 'revision'",
    ]

    def test_views_reject_what_section_2_forbids(self):
        for install in ("site_ro", "blog_ro"):
            for sql in self.REJECT:
                with self.subTest(install=install, sql=sql):
                    v = check_statement(sql, install)
                    self.assertFalse(v.allowed, "views install must still refuse this")
                    self.assertTrue(v.reasons)

    def test_views_allow_filtered_queries(self):
        for sql in self.ALLOW:
            with self.subTest(sql=sql):
                v = check_statement(sql, "site_ro")
                self.assertTrue(v.allowed, v.reasons)

    def test_post_password_reason_names_column(self):
        v = check_statement("SELECT post_password FROM wp_posts WHERE post_type='page'",
                            "site_ro")
        self.assertIn("post_password", " ".join(v.reasons))


HOST_COUNT = ("SELECT COUNT(*) FROM wp_posts WHERE post_type = 'revision' "
              "AND post_content LIKE '%spam-one.example%'")
META_COUNT = ("SELECT COUNT(*) FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID "
              "WHERE p.post_type = 'revision' AND m.meta_key = '_elementor_data' "
              "AND m.meta_value LIKE '%spam-three.example%'")


class ResidueIsCountOnly(unittest.TestCase):
    """Residue mode opened all revision content."""

    ALLOW = [
        HOST_COUNT,
        META_COUNT,
        "SELECT COUNT(*) AS n FROM wp_posts p WHERE p.post_type = 'revision' AND "
        "(p.post_content LIKE '%spam-one.example%' OR p.post_content LIKE '%spam-two.example%' "
        "OR p.post_content LIKE '%spam-three.example%')",
        "SELECT COUNT(DISTINCT p.post_parent) FROM wp_posts p WHERE p.post_type = 'revision' "
        "AND p.post_content LIKE '%spam-three.example%'",
        "SELECT COUNT(*), COUNT(DISTINCT m.post_id) FROM wp_posts p INNER JOIN wp_postmeta m "
        "ON m.post_id = p.ID WHERE p.post_type = 'revision' AND m.meta_key = '_elementor_data' "
        "AND (m.meta_value LIKE '%spam-one.example%' OR m.meta_value LIKE '%spam-three.example%')",
        "SELECT COUNT(*) FROM wp_posts p, wp_postmeta m WHERE m.post_id = p.ID AND "
        "p.post_type = 'revision' AND m.meta_key = '_elementor_data' AND "
        "m.meta_value LIKE '%spam-two.example%'",
    ]
    REJECT = [
        # two reproductions
        "SELECT post_content FROM wp_posts WHERE post_type='revision'",
        "SELECT q.post_content FROM wp_posts p JOIN wp_posts q ON 1 WHERE "
        "p.post_type='revision' AND q.post_type='revision'",
        # raw values, even with the host filter
        "SELECT post_content FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%'",
        "SELECT ID, post_title FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%'",
        "SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID "
        "WHERE p.post_type='revision' AND m.meta_key='_elementor_data' "
        "AND m.meta_value LIKE '%spam-three.example%'",
        "SELECT GROUP_CONCAT(post_content) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%'",
        "SELECT MAX(post_content) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%'",
        "SELECT COUNT(post_content) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%'",
        "SELECT COUNT(DISTINCT post_content) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%'",
        "SELECT COUNT(DISTINCT post_password) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%'",
        "SELECT LENGTH(post_content) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%'",
        "SELECT * FROM wp_posts WHERE post_type='revision' AND post_content LIKE '%spam-one.example%'",
        # count used as an oracle on other text
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' AND post_content LIKE '%password%'",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' AND SUBSTRING(post_content, 1, 1) = 'a'",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' AND ID = 5",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND (post_content LIKE '%spam-one.example%' OR post_content LIKE 'a%')",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND (post_content LIKE '%spam-one.example%' AND post_content LIKE '%x%')",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' OR 1=1",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' XOR 1",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' AND CASE WHEN "
        "post_content LIKE '%spam-one.example%' THEN 1 ELSE 0 END",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' AND ID BETWEEN 1 AND 9",
        # other hosts, other patterns
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%evil.example%'",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' AND post_content LIKE '%'",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%a%'",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one_example%'",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' ESCAPE '!'",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' COLLATE utf8mb4_bin",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_title LIKE '%spam-one.example%'",
        # missing pieces
        "SELECT COUNT(*) FROM wp_posts WHERE post_content LIKE '%spam-one.example%'",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision'",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type IN ('revision','page') "
        "AND post_content LIKE '%spam-one.example%'",
        "SELECT COUNT(*) FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID "
        "WHERE p.post_type='revision' AND m.meta_value LIKE '%spam-three.example%'",
        "SELECT COUNT(*) FROM wp_posts p JOIN wp_postmeta m ON 1 "
        "WHERE p.post_type='revision' AND m.meta_key='_elementor_data' "
        "AND m.meta_value LIKE '%spam-three.example%'",
        "SELECT COUNT(*) FROM wp_posts p LEFT JOIN wp_postmeta m ON m.post_id = p.ID "
        "AND m.meta_key='_elementor_data' WHERE p.post_type='revision' "
        "AND m.meta_value LIKE '%spam-three.example%'",
        # shapes
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' GROUP BY post_content",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' GROUP BY post_parent",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' HAVING COUNT(*) > 1",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' ORDER BY 1",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' LIMIT 1",
        HOST_COUNT + " UNION SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-three.example%'",
        "SELECT (SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-three.example%')",
        "SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%' AND ID IN (SELECT ID FROM wp_posts)",
        "SELECT COUNT(*) FROM (SELECT post_content FROM wp_posts WHERE post_type='revision') t",
        "WITH r AS (SELECT post_content FROM wp_posts WHERE post_type='revision') "
        "SELECT COUNT(*) FROM r",
        "EXPLAIN " + HOST_COUNT,
        "SELECT DISTINCT COUNT(*) FROM wp_posts WHERE post_type='revision' "
        "AND post_content LIKE '%spam-one.example%'",
        "SELECT COUNT(*) FROM wp_posts p JOIN wp_terms t ON 1 WHERE p.post_type='revision' "
        "AND p.post_content LIKE '%spam-one.example%'",
        "SELECT COUNT(*) FROM wp_posts p JOIN wp_posts q ON q.ID = p.ID WHERE "
        "p.post_type='revision' AND p.post_content LIKE '%spam-one.example%'",
        "SELECT COUNT(*) FROM wp_users",
        "SELECT * FROM wp_users",
        # ordinary queries are not accepted under the residue flag
        "SELECT name FROM wp_terms",
        "SELECT ID FROM wp_posts WHERE post_type = 'page'",
    ]

    def test_allowed_counts(self):
        for sql in self.ALLOW:
            with self.subTest(sql=sql):
                v = check_statement(sql, "docs", residue=True)
                self.assertTrue(v.allowed, v.reasons)

    def test_everything_else_rejected(self):
        for sql in self.REJECT:
            with self.subTest(sql=sql):
                v = check_statement(sql, "docs", residue=True)
                self.assertFalse(v.allowed, "residue mode must refuse this")
                self.assertTrue(v.reasons)

    def test_counts_need_the_flag_and_residue_hosts(self):
        for sql in self.ALLOW:
            with self.subTest(sql=sql):
                self.assertFalse(_ok(sql, "docs"))
                self.assertFalse(_ok(sql, "site", residue=True))
                self.assertFalse(_ok(sql, "site_ro", residue=True))

    def test_hosts_are_the_configured_ones(self):
        self.assertEqual(set(sql_guard.load_installs()["docs"].residue_hosts),
                         {"spam-one.example", "spam-two.example", "spam-three.example"})
        self.assertEqual(sql_guard.load_installs()["site"].residue_hosts, ())


class IdentityFailsClosed(unittest.TestCase):
    """No CURRENT_USER row still reported select_only=True."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "sql.log")

    def tearDown(self):
        self.tmp.cleanup()

    def _conn(self, user_rows):
        conn = FakeConnection()
        base = conn.responder

        def responder(sql):
            if sql == "SELECT CURRENT_USER()":
                return [("CURRENT_USER()",)], user_rows
            return base(sql)
        conn.responder = responder
        return conn

    def test_no_row(self):
        with self.assertRaises(GuardSetupError):
            GuardedConnection(self._conn([]), "site_ro", self.log)
        with GuardedConnection(self._conn([]), "site_ro", self.log, attended=True) as g:
            ident = g.identity()
        self.assertFalse(ident["select_only"])
        self.assertIsNone(ident["current_user"])
        self.assertIn("identity not established", " ".join(ident["reasons"]))

    def test_null_empty_or_odd_rows(self):
        for rows in ([(None,)], [("",)], [("   ",)], [()], [(42,)],
                     [("a@b",), ("c@d",)], [(b"\xff",)]):
            with self.subTest(rows=rows):
                with self.assertRaises(GuardSetupError):
                    GuardedConnection(self._conn(rows), "site_ro", self.log)
                with GuardedConnection(self._conn(rows), "site_ro", self.log,
                                       attended=True) as g:
                    self.assertFalse(g.identity()["select_only"])

    def test_bytes_user_is_decoded(self):
        with GuardedConnection(self._conn([(b"audit_reader@127.0.0.1",)]), "site_ro",
                               self.log) as g:
            ident = g.identity()
        self.assertTrue(ident["select_only"], ident["reasons"])
        self.assertEqual(ident["current_user"], "audit_reader@127.0.0.1")


LEAKY_GRANTS = [
    f"GRANT ALL ON *.* TO `u`@`h` IDENTIFIED BY PASSWORD '{HASH}'",
    f"GRANT ALL PRIVILEGES ON *.* TO 'u'@'h' IDENTIFIED BY PASSWORD '{HASH}' WITH GRANT OPTION",
    f"GRANT USAGE ON *.* TO `u`@`h` IDENTIFIED BY '{HASH}' EXTRA",
    f"GRANT FILE ON *.* TO `u`@`h` IDENTIFIED WITH mysql_native_password AS '{HASH}'",
    f"GRANT SUPER ON *.* TO `u`@`h` IDENTIFIED VIA ed25519 USING PASSWORD('{HASH}')",
    f"GRANT SUPER ON *.* TO `u`@`h` IDENTIFIED VIA unix_socket OR mysql_native_password "
    f"USING '{HASH}'",
    f"GRANT USAGE ON *.* TO `u`@`h` IDENTIFIED BY PASSWORD {HASH}",          # unparseable
    f"GRANT USAGE ON *.* TO `u`@`h` identified by password '{HASH}' trailing",  # lowercase
    f"GRANT USAGE ON *.* TO `u`@`h` REQUIRE NONE '{HASH}'",                   # quoted tail
    f"GRANT SELECT ('{HASH}' x) ON d.t TO `u`@`h`",                          # bad col list
    f"GRANT SELECT '{HASH}' ON d.t TO `u`@`h`",                              # odd token
    f"GRANT SELECT ON `d`.`t` TO `u`@`h` PASSWORD '{HASH}'",
    f"GRANT DELETE ON `audit_site`.* TO `u`@`h` IDENTIFIED BY PASSWORD '{HASH}'"
    + " X" * 100,
]


class GrantTextIsRedacted(unittest.TestCase):
    """Rejected grant lines put password hashes in reasons/logs."""

    def test_reasons_never_hold_the_hash(self):
        for line in LEAKY_GRANTS:
            with self.subTest(line=line):
                ok, reasons = classify_grants([line])
                self.assertFalse(ok)
                text = " ".join(reasons)
                self.assertNotIn(HASH, text)
                self.assertNotIn(HASH[1:12], text)
                self.assertIn("line 1", text)

    def test_reasons_still_say_why(self):
        ok, reasons = classify_grants([LEAKY_GRANTS[0]])
        self.assertIn("ALL PRIVILEGES", reasons[0])
        self.assertIn("<redacted>", reasons[0])

    def test_redact_helper(self):
        self.assertEqual(sql_guard.redact_grant("GRANT USAGE ON *.* TO `u`@`h`"),
                         "GRANT USAGE ON *.* TO `u`@`h`")
        self.assertNotIn("abc", sql_guard.redact_grant("x IDENTIFIED BY 'abc'"))
        self.assertNotIn("abc", sql_guard.redact_grant("x Password('abc')"))

    def test_select_only_summary_has_no_hash(self):
        ok, notes = classify_grants([f"GRANT USAGE ON *.* TO `u`@`h` IDENTIFIED BY PASSWORD "
                                     f"'{HASH}'"])
        self.assertTrue(ok)
        self.assertNotIn(HASH, " ".join(notes))

    def test_identity_log_has_no_hash(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        log = os.path.join(tmp.name, "sql.log")
        conn = FakeConnection(grants=[(line,) for line in LEAKY_GRANTS])
        with GuardedConnection(conn, "site", log, attended=True) as g:
            ident = g.identity()
        self.assertFalse(ident["select_only"])
        self.assertNotIn(HASH, json.dumps(ident))
        with open(log, encoding="ascii") as fh:
            self.assertNotIn(HASH, fh.read())

    def test_cli_output_has_no_hash(self):
        import contextlib
        import io
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "g.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(LEAKY_GRANTS) + "\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sql_guard._main(["--grants", path])
        self.assertEqual(rc, 1)
        self.assertNotIn(HASH, buf.getvalue())


class EmptyParamsRefused(unittest.TestCase):
    """params=() / {} slipped past the refusal."""

    def test_any_params_object_refused(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        log = os.path.join(tmp.name, "sql.log")
        conn = FakeConnection()
        with GuardedConnection(conn, "site", log) as g:
            for params in ((), {}, [], (1,), {"a": 1}, "", 0, False):
                with self.subTest(params=params):
                    before = len(conn.executed)
                    with self.assertRaises(GuardRejected):
                        g.execute("SELECT name FROM wp_terms", params)
                    self.assertEqual(len(conn.executed), before, "nothing reaches the driver")
            g.execute("SELECT name FROM wp_terms")  # None (the default) still works


class FalseRejects(unittest.TestCase):
    """Natural LIKE prefixes and the NOT EXISTS 'missing SEO
    description' query."""

    MISSING_DESC = ("SELECT COUNT(*) FROM wp_posts p WHERE p.post_status='publish' AND "
                    "p.post_type='post' AND NOT EXISTS (SELECT 1 FROM wp_postmeta m WHERE "
                    "m.post_id=p.ID AND m.meta_key='rank_math_description')")

    def test_unescaped_underscore_prefix_still_rejected_with_a_hint(self):
        for pat in ("rank_math_%", "_yoast_wpseo_%"):
            sql = ("SELECT p.ID, m.meta_value FROM wp_posts p JOIN wp_postmeta m ON "
                   f"m.post_id = p.ID WHERE {PUB} AND m.meta_key LIKE '{pat}'")
            with self.subTest(pat=pat):
                v = check_statement(sql, "site")
                self.assertFalse(v.allowed)
                self.assertIn("one-character wildcard", " ".join(v.reasons))
                esc = sql.replace(pat, pat.replace("_", "\\_"))
                self.assertTrue(_ok(esc, "site"), check_statement(esc, "site").reasons)

    def test_not_exists_missing_description_allowed(self):
        for install in ("site", "blog", "site_ro"):
            with self.subTest(install=install):
                v = check_statement(self.MISSING_DESC, install)
                self.assertTrue(v.allowed, v.reasons)
        exists = self.MISSING_DESC.replace("NOT EXISTS", "EXISTS")
        self.assertTrue(_ok(exists, "site"))
        listing = self.MISSING_DESC.replace("COUNT(*)", "p.ID, p.post_title")
        self.assertTrue(_ok(listing, "site"))

    def test_correlated_exists_cannot_widen(self):
        bad = [
            # outer not filtered to published / public
            self.MISSING_DESC.replace("p.post_status='publish' AND ", ""),
            self.MISSING_DESC.replace("p.post_type='post'", "p.post_type='revision'"),
            self.MISSING_DESC.replace("p.post_type='post'", "p.post_type<>'revision'"),
            # EXISTS not a top-level AND conjunct
            self.MISSING_DESC.replace("AND NOT EXISTS", "OR NOT EXISTS"),
            "SELECT COUNT(*) FROM wp_posts p WHERE p.post_status='publish' AND "
            "p.post_type='post' AND (1 = 0 OR NOT EXISTS (SELECT 1 FROM wp_postmeta m WHERE "
            "m.post_id=p.ID AND m.meta_key='rank_math_description'))",
            # subquery returns values
            "SELECT p.ID, (SELECT m.meta_value FROM wp_postmeta m WHERE m.post_id=p.ID AND "
            "m.meta_key='rank_math_description') FROM wp_posts p WHERE " + PUB,
            self.MISSING_DESC.replace("SELECT 1 FROM wp_postmeta", "SELECT m.meta_value FROM "
                                      "wp_postmeta"),
            # IN-subquery does not count
            "SELECT COUNT(*) FROM wp_posts p WHERE " + PUB + " AND p.ID IN (SELECT m.post_id "
            "FROM wp_postmeta m WHERE m.meta_key='rank_math_description')",
            # bad meta key, or no key at all
            self.MISSING_DESC.replace("rank_math_description", "_edit_lock"),
            self.MISSING_DESC.replace(" AND m.meta_key='rank_math_description'", ""),
            # correlation on the wrong column / not to the outer posts row
            self.MISSING_DESC.replace("m.post_id=p.ID", "m.meta_id=p.ID"),
            self.MISSING_DESC.replace("m.post_id=p.ID", "m.post_id=p.post_parent"),
            self.MISSING_DESC.replace("m.post_id=p.ID", "m.post_id=m.meta_id"),
            # nested deeper: grandparent correlation
            "SELECT COUNT(*) FROM wp_posts p WHERE " + PUB + " AND EXISTS (SELECT 1 FROM "
            "wp_terms t WHERE EXISTS (SELECT 1 FROM wp_postmeta m WHERE m.post_id=p.ID AND "
            "m.meta_key='rank_math_description'))",
            # a second subquery level inside the EXISTS
            "SELECT COUNT(*) FROM wp_posts p WHERE " + PUB + " AND EXISTS (SELECT 1 FROM "
            "wp_postmeta m WHERE m.post_id=p.ID AND m.meta_key='rank_math_description' AND "
            "m.meta_id IN (SELECT m2.meta_id FROM wp_postmeta m2))",
            # inner alias shadows the outer one
            "SELECT COUNT(*) FROM wp_posts p WHERE " + PUB + " AND NOT EXISTS (SELECT 1 FROM "
            "wp_postmeta m, wp_posts p WHERE m.post_id=p.ID AND "
            "m.meta_key='rank_math_description')",
            # EXISTS in the select list
            "SELECT EXISTS (SELECT 1 FROM wp_postmeta m WHERE m.post_id=p.ID AND "
            "m.meta_key='rank_math_description') FROM wp_posts p WHERE " + PUB,
        ]
        for sql in bad:
            with self.subTest(sql=sql):
                self.assertFalse(_ok(sql, "site"))
                self.assertFalse(_ok(sql, "site_ro"))


class BacktickCommentMarkers(unittest.TestCase):
    """`#` inside a backtick identifier was accepted."""

    def test_rejected(self):
        for ident in ("`#`", "`a#b`", "`--`", "`a--b`", "`/*`", "`*/`", "`/*!50000 x*/`"):
            sql = f"SELECT 1 FROM wp_terms {ident}"
            with self.subTest(sql=sql):
                v = check_statement(sql, "site")
                self.assertFalse(v.allowed)
                self.assertIn("backtick", " ".join(v.reasons))

    def test_plain_backticks_still_fine(self):
        self.assertTrue(_ok("SELECT `name` FROM `wp_terms` `t-1`", "site"))
        self.assertTrue(_ok("SELECT name FROM wp_terms WHERE name = '# -- /* */'", "site"))


class EscapedGrantDatabaseNames(unittest.TestCase):
    """SHOW GRANTS prints `audit\\_site` for db-level grants."""

    def _cls(self, line, allowed=("audit_site",)):
        return classify_grants(["GRANT USAGE ON *.* TO `audit_reader`@`%`", line],
                               allowed_databases=list(allowed))

    def test_escaped_db_level_name_equals_plain_name(self):
        ok, reasons = self._cls("GRANT SELECT ON `audit\\_site`.* TO `audit_reader`@`%`")
        self.assertTrue(ok, reasons)
        ok, reasons = self._cls("GRANT SELECT ON 'audit\\_site'.* TO 'audit_reader'@'%'")
        self.assertTrue(ok, reasons)

    def test_never_a_wildcard_match(self):
        bad = [
            "GRANT SELECT ON `audit\\_%`.* TO `x`@`%`",        # % wildcard
            "GRANT SELECT ON `audit%`.* TO `x`@`%`",
            "GRANT SELECT ON `%`.* TO `x`@`%`",
            "GRANT SELECT ON `audit_site`.* TO `x`@`%`",       # unescaped: a pattern
            "GRANT SELECT ON `audit\\_site2`.* TO `x`@`%`",
            "GRANT SELECT ON `audit\\_blog`.* TO `x`@`%`",
            "GRANT SELECT ON `audit\\x\\_site`.* TO `x`@`%`",     # unknown escape
            # table level: names are literal, so a backslash names another database
            "GRANT SELECT ON `audit\\_site`.`wp_posts` TO `x`@`%`",
        ]
        for line in bad:
            with self.subTest(line=line):
                ok, reasons = self._cls(line)
                self.assertFalse(ok)
                self.assertIn("outside the allowed schemas", " ".join(reasons))

    def test_table_level_plain_names_unchanged(self):
        ok, reasons = self._cls("GRANT SELECT ON `audit_site`.`wp_posts` TO `x`@`%`")
        self.assertTrue(ok, reasons)

    def test_without_allowed_databases_classification_unchanged(self):
        self.assertTrue(classify_grants(["GRANT SELECT ON `audit\\_site`.* TO `x`@`%`"])[0])


if __name__ == "__main__":
    unittest.main()
