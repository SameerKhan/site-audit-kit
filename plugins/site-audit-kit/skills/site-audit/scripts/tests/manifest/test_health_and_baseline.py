"""Regression tests for run_manifest.py: health URL query values
never reach manifest.json, manifest-summary.txt or stdout (stored as a list of {url, status}
entries); curl is not a required tool; a notes_run_regex without a usable group 1 and a
non-string method_table_heading never crash the build. Offline: every fetch is stubbed."""
import copy
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)
import run_manifest as rm  # noqa: E402
from test_run_manifest import ALIASES, REVIEWED, FakeEnv, md  # noqa: E402
from test_phase1_rows import FINDINGS, NOTE, PROMPT  # noqa: E402
import testcfg  # noqa: E402

SECRET = "TOPSECRET42"
STATUS = [f"https://www.example.com/status?token={SECRET}",
          f"https://www.example.com/status?token={SECRET}x"]   # same redacted form
HTMLU = [f"https://www.example.com/?sig={SECRET}&nocache=1"]


class HealthUrlsRedacted(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.home, "site-audit"), mode=0o700)
        self.repo = tempfile.mkdtemp()
        md(self.repo, "site-audit-2030-03-08.md", REVIEWED)
        self.toolkit = tempfile.mkdtemp()
        p = os.path.join(self.toolkit, "db_config.py")
        with open(p, "w") as f:
            f.write('DATABASES = {"site": {}, "blog": {}}\n')
        os.chmod(p, 0o600)
        self.cfg = testcfg.load(testcfg.merged(db={"config_file": p, "readonly_aliases": ALIASES}))
        # set after loading: the loader may refuse query strings in health URLs, and this test
        # is about what the manifest does with whatever URLs it is handed
        self.cfg["health"] = {**self.cfg["health"], "status_urls": STATUS, "html_urls": HTMLU}
        self.run_dir = os.path.join(self.home, "site-audit", "run-test0002")

    def tearDown(self):
        for d in (self.home, self.repo, self.toolkit):
            shutil.rmtree(d)

    def run_main(self, *extra):
        env = FakeEnv(self.home, http={STATUS[1]: (503, "text/plain", b"down")})
        out = io.StringIO()
        rc = rm.main(["--run-dir", self.run_dir, "--mode", "unattended",
                      "--baseline-dir", self.repo, *extra],
                     env=env, out=out, cfg=self.cfg, sfcall="/x/sfcall.sh")
        return rc, out.getvalue(), env

    def test_no_query_value_in_any_output(self):
        for extra in ((), ("--json",)):
            rc, out, env = self.run_main(*extra)
            self.assertNotIn(SECRET, out)
            # the real URLs were still fetched
            self.assertIn(["GET", STATUS[0]], env.calls)
            for name in ("manifest.json", "manifest-summary.txt"):
                with open(os.path.join(self.run_dir, name)) as f:
                    self.assertNotIn(SECRET, f.read(), name)

    def test_live_is_a_list_of_url_status_entries(self):
        self.run_main()
        with open(os.path.join(self.run_dir, "manifest.json")) as f:
            live = json.load(f)["live"]
        self.assertIsInstance(live["status"], list)
        self.assertIsInstance(live["html"], list)
        self.assertEqual([e["url"] for e in live["status"]],
                         ["https://www.example.com/status?token=X"] * 2)
        # two URLs that redact to the same string stay two entries
        self.assertEqual([e["status"] for e in live["status"]], [200, 503])
        self.assertEqual(live["html"][0]["url"], "https://www.example.com/?sig=X&nocache=X")
        self.assertTrue(live["html"][0]["html"])
        self.assertTrue(live["sf_crawls_held"])


class SfcallUsesTheManifestConfig(unittest.TestCase):
    """--config A: every sfcall.sh child gets SITE_AUDIT_CONFIG=A, whatever the parent had."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.home, "site-audit"), mode=0o700)
        self.repo = tempfile.mkdtemp()
        md(self.repo, "site-audit-2030-03-08.md", REVIEWED)
        self.toolkit = tempfile.mkdtemp()
        p = os.path.join(self.toolkit, "db_config.py")
        with open(p, "w") as f:
            f.write('DATABASES = {"site": {}, "blog": {}}\n')
        os.chmod(p, 0o600)
        self.cfg_path = testcfg.write_config(testcfg.merged(db={"config_file": p, "readonly_aliases": ALIASES}),
                                             directory=self.toolkit)
        self.seen = os.path.join(self.toolkit, "seen.txt")
        self.sfcall = os.path.join(self.toolkit, "sfcall.sh")
        with open(self.sfcall, "w") as f:
            f.write('#!/bin/sh\nprintf "%s\\n" "${SITE_AUDIT_CONFIG-unset}" >> "$SEEN_FILE"\nexit 3\n')
        os.chmod(self.sfcall, 0o700)
        self.run_dir = os.path.join(self.home, "site-audit", "run-test0003")

    def tearDown(self):
        for d in (self.home, self.repo, self.toolkit):
            shutil.rmtree(d)

    def test_child_gets_the_loaded_config_path(self):
        sfcall, seen = self.sfcall, self.seen

        class E(FakeEnv):
            def run(self, argv, timeout=60):
                if argv[0] == sfcall:
                    old = os.environ.get("SEEN_FILE")
                    os.environ["SEEN_FILE"] = seen
                    try:
                        return rm.Env.run(self, argv, timeout)
                    finally:
                        if old is None:
                            os.environ.pop("SEEN_FILE", None)
                        else:
                            os.environ["SEEN_FILE"] = old
                return FakeEnv.run(self, argv, timeout)

        parent = os.environ.get("SITE_AUDIT_CONFIG")
        self.assertNotEqual(parent, self.cfg_path)
        out = io.StringIO()
        rm.main(["--run-dir", self.run_dir, "--mode", "unattended", "--baseline-dir", self.repo,
                 "--config", self.cfg_path], env=E(self.home), out=out, sfcall=sfcall)
        with open(seen) as f:
            lines = f.read().split()
        self.assertTrue(lines, out.getvalue())
        self.assertEqual(set(lines), {os.path.abspath(self.cfg_path)})
        self.assertEqual(os.environ.get("SITE_AUDIT_CONFIG"), parent)  # the parent is untouched


class CurlNotRequired(unittest.TestCase):
    def test_curl_dropped(self):
        self.assertNotIn("curl", rm.REQUIRED_TOOLS)
        self.assertEqual(set(rm.REQUIRED_TOOLS), {"perl", "python3"})


class BaselineConfigRobustness(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        with open(os.path.join(self.d, "site-audit-2030-01-01.md"), "w") as f:
            f.write(FINDINGS)
        with open(os.path.join(self.d, "screaming-frog-run1-2030-01-03.md"), "w") as f:
            f.write(NOTE)
        self.b = {"kind": "previous-audit", "file": "site-audit-2030-01-01.md",
                  "date": "2030-01-01", "path": os.path.join(self.d, "site-audit-2030-01-01.md"),
                  "baseline_dir": self.d,
                  "screaming_frog_notes": ["screaming-frog-run1-2030-01-03.md"]}

    def tearDown(self):
        shutil.rmtree(self.d)

    def bc(self, **over):
        b = copy.deepcopy(rm.bconf())
        b.update(over)
        return b

    def ids(self, bc):
        return [x["id"] for x in rm.phase1_parse(self.b, PROMPT, bc)[0]]

    def test_run_regex_without_group_means_no_run_number(self):
        self.assertIn("screaming-frog-run1-2030-01-03-1", self.ids(self.bc(notes_run_regex="^screaming-")))

    def test_run_regex_with_unmatched_optional_group(self):
        ids = self.ids(self.bc(notes_run_regex=r"^screaming-frog-(x\d+)?"))
        self.assertIn("screaming-frog-run1-2030-01-03-1", ids)

    def test_run_regex_not_a_string_or_invalid(self):
        for bad in (42, None, "(unclosed"):
            with self.subTest(bad=bad):
                self.assertIn("screaming-frog-run1-2030-01-03-1",
                              self.ids(self.bc(notes_run_regex=bad)))

    def test_good_run_regex_still_used(self):
        self.assertIn("R1-1", self.ids(self.bc()))

    def test_method_table_heading_not_a_string(self):
        for bad in (42, None, "", ["x"]):
            with self.subTest(bad=bad):
                ids = self.ids(self.bc(method_table_heading=bad))
                self.assertIn("F14", ids)


if __name__ == "__main__":
    unittest.main()
