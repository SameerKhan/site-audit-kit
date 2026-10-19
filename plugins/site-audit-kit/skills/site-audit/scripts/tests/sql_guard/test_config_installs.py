"""Installs come from the config: defaults, narrowing and refusals. No database."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))
import testcfg  # noqa: E402
testcfg.use_config()
import audit_config  # noqa: E402
import sql_guard  # noqa: E402
from sql_guard import check_statement  # noqa: E402


def installs(**inst):
    return sql_guard.load_installs(testcfg.load(testcfg.merged(db={"installs": inst})))


class WordPressDefaults(unittest.TestCase):
    def setUp(self):
        self.pol = installs(plain={})["plain"]

    def test_core_options_only(self):
        self.assertTrue(check_statement(
            "SELECT option_value FROM wp_options WHERE option_name = 'siteurl'", self.pol))
        self.assertFalse(check_statement(
            "SELECT option_value FROM wp_options WHERE option_name = 'rank-math-options-titles'",
            self.pol))

    def test_seo_meta_prefixes_but_no_builder_keys(self):
        pub = "p.post_status = 'publish' AND p.post_type IN ('page','post')"
        ok = ("SELECT m.meta_value FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID "
              "WHERE " + pub + " AND m.meta_key LIKE 'rank\\_math\\_%'")
        self.assertTrue(check_statement(ok, self.pol), check_statement(ok, self.pol).reasons)
        self.assertFalse(check_statement(ok.replace("LIKE 'rank\\_math\\_%'", "= '_elementor_data'"),
                                         self.pol))

    def test_plugin_tables_off_and_residue_off(self):
        self.assertFalse(check_statement("SELECT * FROM wp_rank_math_redirections", self.pol))
        self.assertTrue(check_statement("SELECT name FROM wp_terms", self.pol))
        q = ("SELECT COUNT(*) FROM wp_posts WHERE post_type='revision' "
             "AND post_content LIKE '%spam-one.example%'")
        self.assertFalse(check_statement(q, self.pol, residue=True))


class Narrowing(unittest.TestCase):
    def test_column_allowlist_narrows(self):
        pol = installs(n={"columns": {"posts": ["id", "post_type", "post_title"]}})["n"]
        self.assertTrue(check_statement("SELECT ID, post_title FROM wp_posts WHERE post_type = 'page'", pol))
        self.assertFalse(check_statement("SELECT post_name FROM wp_posts WHERE post_type = 'page'", pol))

    def test_extra_tables_and_template_types(self):
        pol = installs(n={"extra_tables": ["terms", "redirection_items"]})["n"]
        self.assertTrue(check_statement("SELECT url FROM wp_redirection_items", pol))
        self.assertFalse(check_statement("SELECT name FROM wp_term_taxonomy", pol))


class Refusals(unittest.TestCase):
    def test_forbidden_tables_cannot_be_configured(self):
        for t in ("users", "usermeta", "comments", "commentmeta", "posts", "options"):
            with self.subTest(table=t), self.assertRaises(ValueError):
                installs(bad={"extra_tables": ["terms", t]})

    def test_password_column_never_allowed(self):
        with self.assertRaises(ValueError):
            installs(bad={"columns": {"posts": ["id", "post_password"]}})
        with self.assertRaises(ValueError):
            installs(bad={"columns": {"posts": ["id", "not_a_column"]}})

    def test_residue_hosts_without_wildcards(self):
        for h in ("spam_one.example", "%", "a%b.example", "UPPER.example"):
            with self.subTest(host=h), self.assertRaises(ValueError):
                installs(bad={"residue_hosts": [h]})

    def test_views_needs_schema(self):
        with self.assertRaises(ValueError):
            installs(bad={"views": True})

    def test_unknown_install_key_refused(self):
        with self.assertRaises(audit_config.ConfigError):
            installs(bad={"tables": ["users"]})

    def test_unknown_install_name_refused(self):
        v = check_statement("SELECT 1", "no-such-install")
        self.assertFalse(v)
        self.assertIn("unknown install", v.reasons[0])

    def test_no_config_means_no_installs(self):
        saved = os.environ.get("SITE_AUDIT_CONFIG")
        os.environ["SITE_AUDIT_CONFIG"] = os.path.join(HERE, "does-not-exist.json")
        try:
            v = check_statement("SELECT 1", "site")
            self.assertFalse(v)
            self.assertIn("config", v.reasons[0])
        finally:
            os.environ["SITE_AUDIT_CONFIG"] = saved


class CliPublicTypesOnlyNarrow(unittest.TestCase):
    """sql_guard's --public-types may only narrow the install's configured public types."""

    SQL = ("SELECT p.ID, p.post_content FROM wp_posts p WHERE p.post_status = 'publish' "
           "AND p.post_type IN ({})")

    def cli(self, *args):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sql_guard._main(list(args))
        return rc, buf.getvalue()

    def test_widening_is_not_possible(self):
        # the configured list is post, page: asking for glossary too does not add it
        sql = self.SQL.format("'glossary'")
        self.assertEqual(self.cli("--install", "site", sql)[0], 1)
        self.assertEqual(self.cli("--install", "site", "--public-types", "post,page,glossary", sql)[0], 1)
        rc, out = self.cli("--install", "site", "--public-types", "glossary", sql)
        self.assertEqual(rc, 2)
        self.assertIn("shares no type", out)

    def test_narrowing_works(self):
        sql_page = self.SQL.format("'page'")
        self.assertEqual(self.cli("--install", "site", sql_page)[0], 0)
        self.assertEqual(self.cli("--install", "site", "--public-types", "post", sql_page)[0], 1)
        self.assertEqual(self.cli("--install", "site", "--public-types", "post,page", sql_page)[0], 0)


if __name__ == "__main__":
    unittest.main()
