"""sf_supervise hardening: no secret-bearing URLs, reused --out limits, test-only script overrides."""
import json, os, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import testcfg  # noqa: E402
testcfg.use_config()
import sf_supervise as s  # noqa: E402


class ScriptOverridesTestOnly(unittest.TestCase):
    """SF_SFCALL and SF_REDACT_SCRIPT are honoured only under SF_SUPERVISE_TESTING=1."""

    def test_overrides_ignored_without_test_switch(self):
        env = {"SF_SFCALL": "/tmp/evil-sfcall", "SF_REDACT_SCRIPT": "/tmp/always-ok.py"}
        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop("SF_SUPERVISE_TESTING", None)
            self.assertEqual(s.sfcall_path(), s.BUNDLED_SFCALL)
            self.assertEqual(s.redact_path(), s.BUNDLED_REDACT)
            os.environ["SF_SUPERVISE_TESTING"] = "0"
            self.assertEqual(s.redact_path(), s.BUNDLED_REDACT)

    def test_overrides_honoured_with_test_switch_only_inside_tests(self):
        inside = os.path.join(s.TESTS_DIR, "_tmp", "x-redact.py")
        env = {"SF_SFCALL": s.BUNDLED_SFCALL, "SF_REDACT_SCRIPT": inside,
               "SF_SUPERVISE_TESTING": "1"}
        with mock.patch.dict(os.environ, env, clear=False):
            self.assertEqual(s.sfcall_path(), s.BUNDLED_SFCALL)
            self.assertEqual(s.redact_path(), inside)
        env["SF_REDACT_SCRIPT"] = "/tmp/always-ok.py"
        with mock.patch.dict(os.environ, env, clear=False):
            with self.assertRaises(SystemExit):
                s.redact_path()

    def test_bundled_scripts_sit_next_to_the_supervisor(self):
        here = os.path.dirname(os.path.abspath(s.__file__))
        self.assertEqual(s.BUNDLED_SFCALL, os.path.join(here, "sfcall.sh"))
        self.assertEqual(s.BUNDLED_REDACT, os.path.join(here, "redact_exports.py"))

    def test_sfcall_runs_with_supervised_env(self):
        seen = {}

        def fake_run(argv, **kw):
            seen.update(kw.get("env") or {})
            raise OSError("stop")
        with mock.patch.object(s.subprocess, "run", fake_run):
            with self.assertRaises(s.McpError):
                s.Mcp().raw("sf_crawl_progress")
        self.assertEqual(seen.get("SITE_AUDIT_SUPERVISED"), "1")
        self.assertNotEqual(os.environ.get("SITE_AUDIT_SUPERVISED"), "1")


class QueryRule(unittest.TestCase):
    def test_only_cache_bypass_query_allowed(self):
        self.assertIsNone(s.site_url_error("https://www.example.com/?nocache=1"))
        self.assertIsNone(s.site_url_error("https://www.example.com/blog/"))
        for u in ("https://www.example.com/?token=TOPSECRET",
                  "https://www.example.com/?nocache=1&token=x",
                  "https://www.example.com/#token=x",
                  "https://help.example.com/?q=1"):
            self.assertIsNotNone(s.site_url_error(u), u)

    def test_no_cache_bust_query_means_no_query(self):
        cfg = testcfg.load(testcfg.merged(cache_bust_query=None))
        self.assertIsNotNone(s.site_url_error("https://www.example.com/?nocache=1", cfg=cfg))
        self.assertIsNone(s.site_url_error("https://www.example.com/", cfg=cfg))

    def test_unconfigured_kit_allows_no_host(self):
        import audit_config
        cfg = audit_config.DEFAULTS
        self.assertIn("no crawl.hosts", s.site_url_error("https://www.example.com/", cfg=cfg))


class ReusedOut(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.out = os.path.join(self.home, "site-audit", "sf", "run-x")
        os.makedirs(self.out)
        with open(os.path.join(self.out, "supervise.json"), "w") as f:
            json.dump({"name": "x"}, f)
        self.p = mock.patch.dict(os.environ, {"HOME": self.home})
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def test_own_files_ok(self):
        open(os.path.join(self.out, "progress.log"), "w").close()
        self.assertIsNone(s.out_error(self.out, "x"))

    def test_unrelated_file_refused(self):
        open(os.path.join(self.out, "notes.txt"), "w").close()
        self.assertIn("did not write", s.out_error(self.out, "x"))


if __name__ == "__main__":
    unittest.main()
