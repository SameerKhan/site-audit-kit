"""SHOW GRANTS classification samples (MariaDB 10.4 and MySQL 8 forms). No database."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import testcfg  # noqa: E402
testcfg.use_config()

from sql_guard import classify_grants  # noqa: E402

RO_VIEWS = ["wp_posts", "wp_postmeta", "wp_options", "wp_terms", "wp_term_taxonomy",
            "wp_term_relationships", "wp_rank_math_redirections",
            "wp_rank_math_redirections_cache", "wp_rank_math_404_logs"]

# A read-only user on MariaDB 10.4: USAGE line with the two limits, then one SELECT line per view.
MARIADB_RO = [
    "GRANT USAGE ON *.* TO `audit_reader`@`127.0.0.1` IDENTIFIED BY PASSWORD "
    "'*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19' WITH MAX_QUERIES_PER_HOUR 20000 "
    "MAX_USER_CONNECTIONS 2",
] + [f"GRANT SELECT ON `audit_site`.`{v}` TO `audit_reader`@`127.0.0.1`" for v in RO_VIEWS]

# A read-only user on MySQL 8.0: limits live in SHOW CREATE USER, not SHOW GRANTS.
MYSQL8_RO = ["GRANT USAGE ON *.* TO `audit_reader`@`10.0.1.25`"] + [
    f"GRANT SELECT ON `audit_blog`.`{v}` TO `audit_reader`@`10.0.1.25`" for v in RO_VIEWS]

# The minimal "two-line" picture of a read-only identity (USAGE + SELECT).
RO_TWO_LINE = [
    "GRANT USAGE ON *.* TO `audit_reader`@`127.0.0.1` WITH MAX_QUERIES_PER_HOUR 20000 "
    "MAX_USER_CONNECTIONS 2",
    "GRANT SELECT ON `audit_site`.`wp_posts` TO `audit_reader`@`127.0.0.1`",
]

SELECT_ONLY = [
    ("mariadb read-only full", MARIADB_RO),
    ("mysql8 read-only full", MYSQL8_RO),
    ("read-only two line", RO_TWO_LINE),
    ("usage only", ["GRANT USAGE ON *.* TO `x`@`%`"]),
    ("old mariadb single quotes", [
        "GRANT USAGE ON *.* TO 'audit_reader'@'127.0.0.1' IDENTIFIED BY PASSWORD '*ABC'",
        "GRANT SELECT ON `audit_site`.`wp_posts` TO 'audit_reader'@'127.0.0.1'"]),
    ("double-quoted names", ['GRANT SELECT ON "db"."t" TO "u"@"h"']),
    ("unquoted names", ["GRANT SELECT ON db.t TO u@localhost"]),
    ("unquoted host pattern", ["GRANT USAGE ON *.* TO u@10.0.1.%"]),
    ("db level", ["GRANT SELECT ON `audit_blog`.* TO `x`@`%`"]),
    ("global select", ["GRANT SELECT ON *.* TO `reader`@`%`"]),
    ("on TABLE keyword", ["GRANT SELECT ON TABLE `db`.`t` TO `x`@`h`"]),
    ("mysql8 column level", ["GRANT SELECT (`ID`, `post_type`) ON `db`.`wp_posts` TO `x`@`h`"]),
    ("mariadb column level", ["GRANT SELECT (ID, post_title) ON `db`.`wp_posts` TO 'x'@'h'"]),
    ("select and usage together", ["GRANT SELECT, USAGE ON `db`.* TO `x`@`h`"]),
    ("mariadb via plugin", ["GRANT USAGE ON *.* TO `x`@`localhost` IDENTIFIED VIA unix_socket "
                            "OR mysql_native_password USING '*ABC'"]),
    ("mariadb via password()", ["GRANT USAGE ON *.* TO `x`@`localhost` IDENTIFIED VIA ed25519 "
                                "USING PASSWORD('secret')"]),
    ("require ssl", ["GRANT USAGE ON *.* TO `x`@`%` REQUIRE SSL"]),
    ("require issuer", ["GRANT USAGE ON *.* TO `x`@`%` REQUIRE ISSUER '/C=X' AND SUBJECT '/CN=y'"]),
    ("all limits", ["GRANT USAGE ON *.* TO `x`@`%` WITH MAX_QUERIES_PER_HOUR 1 "
                    "MAX_UPDATES_PER_HOUR 2 MAX_CONNECTIONS_PER_HOUR 3 MAX_USER_CONNECTIONS 4 "
                    "MAX_STATEMENT_TIME 1.5"]),
    ("trailing semicolon", ["GRANT USAGE ON *.* TO `x`@`%`;"]),
    ("tuple rows", [("GRANT USAGE ON *.* TO `x`@`%`",),
                    ("GRANT SELECT ON `d`.`t` TO `x`@`%`",)]),
    ("bytes rows", [(b"GRANT USAGE ON *.* TO `x`@`%`",)]),
    ("lower case", ["grant select on `d`.`t` to `x`@`%`"]),
]

NOT_SELECT_ONLY = [
    ("site admin", ["GRANT ALL PRIVILEGES ON *.* TO `wordpress`@`localhost` "
                               "IDENTIFIED BY PASSWORD '*X' WITH GRANT OPTION"], "ALL"),
    ("blog admin", ["GRANT USAGE ON *.* TO `wordpress`@`%`",
                            "GRANT ALL PRIVILEGES ON `wordpress`.* TO `wordpress`@`%`"], "ALL"),
    ("bare ALL", ["GRANT ALL ON `db`.* TO `x`@`%`"], "ALL"),
    ("file", ["GRANT FILE ON *.* TO `x`@`%`"], "FILE"),
    ("select plus file", ["GRANT SELECT, FILE ON *.* TO `x`@`%`"], "FILE"),
    ("proxy", ["GRANT PROXY ON ''@'%' TO 'x'@'%' WITH GRANT OPTION"], "PROXY"),
    ("proxy on user", ["GRANT PROXY ON `root`@`localhost` TO `x`@`%`"], "PROXY"),
    ("mysql8 role grant", ["GRANT USAGE ON *.* TO `x`@`%`", "GRANT `reader`@`%` TO `x`@`%`"],
     "role"),
    ("mysql8 two roles", ["GRANT `r1`@`%`,`r2`@`%` TO `x`@`%`"], "role"),
    ("mariadb role grant", ["GRANT `audit_role` TO `x`@`localhost`"], "role"),
    ("mariadb default role", ["GRANT USAGE ON *.* TO `x`@`localhost`",
                              "SET DEFAULT ROLE `audit_role` FOR `x`@`localhost`"], "role"),
    ("role with admin option", ["GRANT `r`@`%` TO `x`@`%` WITH ADMIN OPTION"], "role"),
    ("select with grant option", ["GRANT SELECT ON `db`.* TO `x`@`h` WITH GRANT OPTION"],
     "GRANT OPTION"),
    ("usage with grant option", ["GRANT USAGE ON *.* TO `x`@`h` WITH GRANT OPTION"],
     "GRANT OPTION"),
    ("grant option privilege", ["GRANT GRANT OPTION ON `db`.* TO `x`@`h`"], "GRANT OPTION"),
    ("insert column", ["GRANT SELECT (ID), INSERT (ID) ON `db`.`t` TO `x`@`h`"], "INSERT"),
    ("update column", ["GRANT UPDATE (post_title) ON `db`.`wp_posts` TO `x`@`h`"], "UPDATE"),
    ("dynamic privileges", ["GRANT BACKUP_ADMIN,SYSTEM_VARIABLES_ADMIN ON *.* TO `x`@`%`"],
     "dynamic"),
    ("mysql8 root dynamic", ["GRANT APPLICATION_PASSWORD_ADMIN,AUDIT_ADMIN,BINLOG_ADMIN ON *.* "
                             "TO `root`@`localhost` WITH GRANT OPTION"], "dynamic"),
    ("show view", ["GRANT SELECT, SHOW VIEW ON `db`.* TO `x`@`h`"], "SHOW VIEW"),
    ("process", ["GRANT PROCESS ON *.* TO `x`@`h`"], "PROCESS"),
    ("lock tables", ["GRANT SELECT, LOCK TABLES ON `db`.* TO `x`@`h`"], "LOCK TABLES"),
    ("create temporary", ["GRANT CREATE TEMPORARY TABLES ON `db`.* TO `x`@`h`"], "CREATE"),
    ("execute routine", ["GRANT EXECUTE ON PROCEDURE `db`.`p` TO `x`@`h`"], "EXECUTE"),
    ("select on function", ["GRANT SELECT ON FUNCTION `db`.`f` TO `x`@`h`"], "FUNCTION"),
    ("super", ["GRANT SUPER ON *.* TO `x`@`h`"], "SUPER"),
    ("mariadb binlog admin", ["GRANT BINLOG ADMIN ON *.* TO `x`@`h`"], "BINLOG"),
    ("unknown privilege word", ["GRANT FROBNICATE ON *.* TO `x`@`h`"], "unknown"),
    ("partial revoke", ["GRANT SELECT ON *.* TO `x`@`%`", "REVOKE SELECT ON `mysql`.* FROM `x`@`%`"],
     "REVOKE"),
    ("one bad among good", MARIADB_RO + ["GRANT DELETE ON `audit_site`.`wp_posts` TO "
                                         "`audit_reader`@`127.0.0.1`"], "DELETE"),
    ("unparseable: no object", ["GRANT SELECT ON TO `x`@`h`"], "unparseable"),
    ("unparseable: extra tail", ["GRANT SELECT ON *.* TO `x`@`%` EXTRA"], "unparseable"),
    ("unparseable: limit without number", ["GRANT USAGE ON *.* TO `x`@`%` WITH "
                                           "MAX_USER_CONNECTIONS"], "unparseable"),
    ("unparseable: garbage", ["Grants for x@%"], "unparseable"),
    ("unparseable: odd char", ["GRANT SELECT ON *.* TO `x`@`%` §"], "unparseable"),
    ("unparseable: two grantees", ["GRANT SELECT ON *.* TO `x`@`%`, `y`@`%`"], "unparseable"),
    ("empty string", [""], "unparseable"),
    ("empty list", [], "no grant lines"),
    ("none", None, "no grant lines"),
    ("wrong type", [42], "not a string"),
    ("two-column row", [("GRANT USAGE ON *.* TO `x`@`%`", "extra")], "one column"),
    ("bad utf8", [(b"\xff\xfe",)], "UTF-8"),
]


class GrantClassificationTests(unittest.TestCase):
    def test_select_only(self):
        for name, lines in SELECT_ONLY:
            with self.subTest(name=name):
                ok, reasons = classify_grants(lines)
                self.assertTrue(ok, reasons)
                self.assertTrue(reasons, "a summary line per grant is expected")

    def test_not_select_only(self):
        for name, lines, needle in NOT_SELECT_ONLY:
            with self.subTest(name=name):
                ok, reasons = classify_grants(lines)
                self.assertFalse(ok)
                self.assertTrue(reasons)
                self.assertIn(needle.lower(), " ".join(reasons).lower())

    def test_readonly_schema_restriction(self):
        ok, _ = classify_grants(MARIADB_RO, allowed_databases=["audit_site"])
        self.assertTrue(ok)
        ok, reasons = classify_grants(MARIADB_RO, allowed_databases=["audit_blog"])
        self.assertFalse(ok)
        self.assertIn("outside the allowed schemas", " ".join(reasons))
        # A grant naming the WordPress database itself fails the read-only check even though it is SELECT.
        lines = RO_TWO_LINE + ["GRANT SELECT ON `wordpress`.`wp_posts` TO "
                               "`audit_reader`@`127.0.0.1`"]
        self.assertTrue(classify_grants(lines)[0])
        self.assertFalse(classify_grants(lines, allowed_databases=["audit_site"])[0])
        # Global SELECT is SELECT-only, but never shaped like a read-only views user.
        self.assertFalse(classify_grants(["GRANT SELECT ON *.* TO `x`@`%`"],
                                         allowed_databases=["audit_site"])[0])
        # USAGE on *.* is fine under the read-only restriction.
        self.assertTrue(classify_grants(["GRANT USAGE ON *.* TO `x`@`%`"],
                                        allowed_databases=["audit_site"])[0])

    def test_every_failing_line_is_reported(self):
        ok, reasons = classify_grants(["GRANT FILE ON *.* TO `x`@`%`",
                                       "GRANT USAGE ON *.* TO `x`@`%`",
                                       "nonsense"])
        self.assertFalse(ok)
        self.assertEqual(len(reasons), 2)
        self.assertIn("line 1", reasons[0])
        self.assertIn("line 3", reasons[1])


if __name__ == "__main__":
    unittest.main()
