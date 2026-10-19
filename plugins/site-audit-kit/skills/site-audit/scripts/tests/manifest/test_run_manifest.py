"""Tests for run_manifest.py. Offline by default; set SITE_AUDIT_MANIFEST_LIVE=1 to also run one
live build against your real configuration (it writes into a temp run dir under the configured
run_root, then deletes it). Run: python3 -m unittest discover -s skills/site-audit/scripts/tests/manifest"""
import datetime as dt
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, SCRIPTS)
sys.path.insert(0, os.path.dirname(HERE))
import testcfg  # noqa: E402
testcfg.use_config()
import run_manifest as rm  # noqa: E402

CFG = testcfg.load()
BC = CFG["baseline"]
WWW = "https://www.example.com"
ALIASES = ["site_ro", "blog_ro"]

CRAWLS_JSON = json.dumps({"jsonrpc": "2.0", "id": "x", "result": {"content": [{"type": "text", "text": json.dumps([
    {"instanceDirName": "id-new", "crawlName": "crawl-new", "time": "Mar 13, 2030", "urlsCrawled": 10,
     "percentageComplete": 100.0},
    {"instanceDirName": "id-old", "crawlName": "crawl-old", "time": "Mar 9, 2030", "urlsCrawled": 5,
     "percentageComplete": 100.0}])}]}})

GEMINI_OUT = "Fetching available models...\nexample-gemini-pro\tExample Gemini Pro\nexample-gemini-flash\tx\n"
HTML = b"<!DOCTYPE html><html><head></head></html>"


class FakeEnv(rm.Env):
    def __init__(self, home, gemini_out=GEMINI_OUT, codex_rc=0, sf_rc=0, http=None, tools=None):
        self.home = home
        self.calls = []
        self.timeouts = {}
        self.fetch_log = None
        self.gemini_out, self.codex_rc, self.sf_rc = gemini_out, codex_rc, sf_rc
        self.http = http or {}
        self.tools = tools if tools is not None else {
            t: f"/usr/bin/{t}" for t in ("perl", "curl", "python3", "gcloud", "codex", "gemini", "dig")}

    def now(self):
        return dt.datetime(2030, 3, 19, 12, 0, tzinfo=dt.timezone.utc)

    def run(self, argv, timeout=60):
        self.calls.append(list(argv))
        self.timeouts[os.path.basename(argv[0])] = timeout
        if argv[0].endswith("codex"):
            assert argv[1:] == ["--version"], argv
            return self.codex_rc, "codex-cli 9.9.9\n" if self.codex_rc == 0 else ""
        if argv[0].endswith("sfcall.sh"):
            if argv[1] == "--list":
                return self.sf_rc, "{}"
            if argv[1] == "sf_list_crawls":
                return 0, CRAWLS_JSON + "\n"
            raise AssertionError(f"forbidden Screaming Frog tool: {argv[1]}")
        if argv[0] == "ps":
            assert argv[1:] == ["-ax", "-o", "args="], argv
            return 0, ("/sbin/launchd\n/usr/bin/java -Xmx2g -jar other.jar\n"
                       "/opt/screamingfrogseospider/jre/bin/java -Xmx8g -jar x\n")
        if argv[0].endswith("gemini"):
            return (0, self.gemini_out) if self.gemini_out is not None else (127, "")
        raise AssertionError(f"unexpected command {argv}")

    def which(self, name):
        return self.tools.get(os.path.basename(name))

    def http_get(self, url, timeout=15):
        self.calls.append(["GET", url])
        if url in self.http:
            r = self.http[url]
            return r if len(r) == 4 else (*r, None)
        if "/.well-known/" in url:
            return 200, "text/plain", b"ok", None
        return 200, "text/html; charset=UTF-8", HTML, None


def md(d, name, body="# Audit\n"):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(body)
    return p


REVIEWED = "# Audit\n\n## Findings\n\n### F1. Example finding\n\n## Review record: independent review\n| a | b |\n"


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self.m = os.path.join(self.repo, "baseline")
        os.makedirs(self.m)

    def tearDown(self):
        shutil.rmtree(self.repo)

    def test_picks_newest_completed_and_companions(self):
        md(self.m, "site-audit-2030-03-08.md", REVIEWED)
        for k in ("runbook", "decisions", "baseline-delta"):
            md(self.m, f"site-audit-2030-03-08-{k}.md", REVIEWED)
        md(self.m, "site-audit-prompt.md", REVIEWED)
        md(self.m, "site-audit-readonly-user.md", REVIEWED)
        md(self.m, "site-audit-2030-03-09-runbook.md", REVIEWED)
        b = rm.select_baseline(self.m, "2030-03-19", BC)
        self.assertEqual(b["file"], "site-audit-2030-03-08.md")
        self.assertEqual(b["kind"], "previous-audit")
        self.assertEqual(b["companions"], {"runbook": "site-audit-2030-03-08-runbook.md",
                                           "decisions": "site-audit-2030-03-08-decisions.md",
                                           "baseline-delta": "site-audit-2030-03-08-baseline-delta.md"})
        self.assertEqual(b["considered"], ["site-audit-2030-03-08.md"])

    def test_collision_suffix_is_newer(self):
        md(self.m, "site-audit-2030-03-08.md", REVIEWED)
        md(self.m, "site-audit-2030-03-12.md", REVIEWED)
        md(self.m, "site-audit-2030-03-12-2.md", REVIEWED)
        md(self.m, "site-audit-2030-03-12-2-runbook.md")
        md(self.m, "site-audit-2030-03-12-runbook.md")
        b = rm.select_baseline(self.m, "2030-03-19", BC)
        self.assertEqual(b["file"], "site-audit-2030-03-12-2.md")
        self.assertEqual(b["collision_suffix"], 2)
        self.assertEqual(b["companions"], {"runbook": "site-audit-2030-03-12-2-runbook.md"})

    def test_suffix_three_beats_two_and_ten_beats_three(self):
        for n in ("", "-2", "-3", "-10"):
            md(self.m, f"site-audit-2030-03-12{n}.md", REVIEWED)
        self.assertEqual(rm.select_baseline(self.m, "2030-03-19", BC)["file"], "site-audit-2030-03-12-10.md")

    def test_incomplete_skipped(self):
        md(self.m, "site-audit-2030-03-08.md", REVIEWED)
        md(self.m, "site-audit-2030-03-15.md", "# Findings\nreview record mentioned in prose only\n")
        b = rm.select_baseline(self.m, "2030-03-19", BC)
        self.assertEqual(b["file"], "site-audit-2030-03-08.md")
        self.assertEqual(b["skipped_incomplete"], ["site-audit-2030-03-15.md"])

    def test_screaming_frog_notes_later_only(self):
        md(self.m, "site-audit-2030-03-08.md", REVIEWED)
        md(self.m, "screaming-frog-run0-2030-03-09.md")
        md(self.m, "screaming-frog-run1-2030-03-10.md")
        md(self.m, "screaming-frog-run1-2030-03-01.md")
        md(self.m, "screaming-frog-audit-plan-2030-03.md")
        b = rm.select_baseline(self.m, "2030-03-19", BC)
        self.assertEqual(b["screaming_frog_notes"],
                         ["screaming-frog-run0-2030-03-09.md", "screaming-frog-run1-2030-03-10.md"])

    def test_fallback(self):
        md(self.m, "site-audit-2030-03-15.md", "# no record\n")
        md(self.m, "fallback-findings.md")
        md(self.m, "fallback-notes.md")
        b = rm.select_baseline(self.m, "2030-03-19", BC)
        self.assertEqual((b["kind"], b["file"], b["date"]), ("fallback", "fallback-findings.md", "2030-01-01"))
        self.assertTrue(b["also_read"])
        # without a configured fallback there is no baseline at all
        self.assertIsNone(rm.select_baseline(self.m, "2030-03-19")["kind"])

    def test_nothing_at_all_fails_closed(self):
        self.assertIsNone(rm.select_baseline(self.m, "2030-03-19", BC)["kind"])


class ReadonlyDbTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.marker = os.path.join(self.d, "SIDE_EFFECT_RAN")

    def tearDown(self):
        shutil.rmtree(self.d)

    def cfg(self, body):
        side = f"open({self.marker!r}, 'w').write('x')\nimport os\nos.system('touch {self.marker}')\n"
        with open(os.path.join(self.d, "db_config.py"), "w") as f:
            f.write(side + body)

    def test_defined_without_execution(self):
        self.cfg('DATABASES = {"site": {"password": "hunter2"}, "site_ro": {}, "blog_ro": {}}\n')
        r = rm.detect_readonly_db(os.path.join(self.d, "db_config.py"), ALIASES)
        self.assertTrue(r["parsed"])
        self.assertEqual(r["aliases"], {"site_ro": True, "blog_ro": True})
        self.assertFalse(os.path.exists(self.marker), "db_config.py must never be executed")
        self.assertNotIn("hunter2", json.dumps(r))

    def test_mentions_do_not_count(self):
        self.cfg('"""site_ro and blog_ro are planned"""\n# site_ro\n'
                 'DATABASES = {"site": {}, "blog": {"note": "blog_ro"}}\nprint("site_ro")\n')
        r = rm.detect_readonly_db(os.path.join(self.d, "db_config.py"), ALIASES)
        self.assertEqual(r["aliases"], {"site_ro": False, "blog_ro": False})
        self.assertFalse(os.path.exists(self.marker))

    def test_subscript_and_update(self):
        self.cfg('DATABASES = {}\nDATABASES["site_ro"] = {}\nDATABASES.update({"blog_ro": {}})\n')
        self.assertEqual(rm.detect_readonly_db(os.path.join(self.d, "db_config.py"), ALIASES)["aliases"], {"site_ro": True, "blog_ro": True})

    def test_one_missing(self):
        self.cfg('DATABASES = dict(site_ro={})\n')
        self.assertEqual(rm.detect_readonly_db(os.path.join(self.d, "db_config.py"), ALIASES)["aliases"], {"site_ro": True, "blog_ro": False})

    def test_syntax_error_and_absent(self):
        self.assertFalse(rm.detect_readonly_db(os.path.join(self.d, "db_config.py"), ALIASES)["present"])
        self.cfg("DATABASES = {\n")
        r = rm.detect_readonly_db(os.path.join(self.d, "db_config.py"), ALIASES)
        self.assertTrue(r["present"])
        self.assertFalse(r["parsed"])


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.home, "site-audit"), mode=0o700)
        self.repo = tempfile.mkdtemp()
        md(self.repo, "site-audit-2030-03-08.md", REVIEWED)
        self.toolkit = tempfile.mkdtemp()
        with open(os.path.join(self.toolkit, "db_config.py"), "w") as f:
            f.write('DATABASES = {"site": {}, "blog": {}}\n')
        os.chmod(os.path.join(self.toolkit, "db_config.py"), 0o600)
        self.cfg = testcfg.load(testcfg.merged(db={"config_file": os.path.join(self.toolkit, "db_config.py"),
                                                  "readonly_aliases": ALIASES}))
        self.run_dir = os.path.join(self.home, "site-audit", "run-test0001")

    def tearDown(self):
        for d in (self.home, self.repo, self.toolkit):
            shutil.rmtree(d)

    def build(self, mode="unattended", env=None, run_dir=None):
        env = env or FakeEnv(self.home)
        return rm.build(run_dir or self.run_dir, mode, self.repo, env=env, cfg=self.cfg,
                        sfcall="/x/sfcall.sh"), env

    def status(self, man, item):
        return next(i for i in man.items if i["item"] == item)["status"]

    def test_unattended_without_readonly_db_is_ok(self):
        man, env = self.build()
        self.assertEqual(man.failed_required, [], man.items)
        self.assertEqual(self.status(man, "readonly_db"), "not_measured")
        self.assertEqual(man.data["readonly_db"]["db_steps"], "NOT MEASURED (read-only DB user not configured)")
        p = os.path.join(self.run_dir, "manifest.json")
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.run_dir).st_mode), 0o700)
        with open(p) as f:
            data = json.load(f)
        self.assertEqual(data["result"], "OK")
        self.assertEqual(data["baseline"]["file"], "site-audit-2030-03-08.md")
        self.assertEqual(data["screaming_frog"]["stored_crawls"][0]["name"], "crawl-new")
        self.assertEqual(data["screaming_frog"]["jvm_xmx"], "8g")
        self.assertEqual(data["models"]["gemini"], "example-gemini-pro")
        self.assertEqual(data["models"]["codex"], "example-codex-model")
        self.assertEqual(data["bounder"], "bound.sh")
        self.assertFalse(data["live"]["sf_crawls_held"])
        sf_tools = [c[1] for c in env.calls if c[0].endswith("sfcall.sh")]
        self.assertEqual(sf_tools, ["--list", "sf_list_crawls"])
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.run_dir, "manifest-summary.txt")).st_mode), 0o600)

    def test_attended_without_readonly_db_warns(self):
        man, _ = self.build(mode="attended")
        self.assertEqual(man.failed_required, [])
        self.assertEqual(self.status(man, "readonly_db"), "warn")

    def test_missing_gemini_model_fails(self):
        env = FakeEnv(self.home, gemini_out="example-gemini-medium\tx\nexample-gemini-low\tx\n")
        man, _ = self.build(env=env)
        self.assertEqual([f["item"] for f in man.failed_required], ["model_gemini"])
        self.assertIsNone(man.data["models"]["gemini"], "no silent substitution")
        self.assertEqual(rm.main(["--run-dir", self.run_dir, "--mode", "unattended", "--baseline-dir", self.repo],
                                 env=env, out=io.StringIO(),
                                 cfg=self.cfg, sfcall="/x/sfcall.sh"), 2)

    def test_codex_unusable_and_gemini_missing_fail(self):
        env = FakeEnv(self.home, gemini_out=None, codex_rc=1)
        man, _ = self.build(env=env)
        self.assertEqual(sorted(f["item"] for f in man.failed_required), ["model_codex", "model_gemini"])

    def test_invalid_mode(self):
        man, _ = self.build(mode="sometimes")
        self.assertIn("mode", [f["item"] for f in man.failed_required])

    def test_run_dir_outside_root_fails(self):
        outside = tempfile.mkdtemp()
        try:
            man, _ = self.build(run_dir=os.path.join(outside, "run-x"))
            self.assertIn("run_dir", [f["item"] for f in man.failed_required])
            self.assertFalse(os.path.exists(os.path.join(outside, "run-x")))
        finally:
            shutil.rmtree(outside)

    def test_run_dir_bad_mode_fails(self):
        os.makedirs(self.run_dir)
        os.chmod(self.run_dir, 0o755)
        man, _ = self.build()
        self.assertIn("run_dir", [f["item"] for f in man.failed_required])

    def test_live_failures_hold_crawls_but_do_not_fail(self):
        http = {WWW + "/robots.txt": (429, "text/plain", b"slow down"),
                WWW + "/blog/?nocache=1": (200, "application/json", b"{}")}
        man, _ = self.build(env=FakeEnv(self.home, http=http, sf_rc=3))
        self.assertEqual(man.failed_required, [])
        self.assertTrue(man.data["live"]["sf_crawls_held"])
        self.assertEqual([e["note"] for e in man.data["live"]["status"]
                          if e["url"] == WWW + "/robots.txt"], ["rate limited (429)"])
        self.assertEqual(self.status(man, "sf_server"), "warn")
        self.assertEqual(self.status(man, "normal_html"), "warn")

    def test_missing_required_tool_fails(self):
        env = FakeEnv(self.home, tools={"curl": "/usr/bin/curl", "python3": "/usr/bin/python3"})
        man, _ = self.build(env=env)
        self.assertIn("tools_required", [f["item"] for f in man.failed_required])

    def test_db_config_world_readable_flagged(self):
        os.chmod(os.path.join(self.toolkit, "db_config.py"), 0o644)
        man, _ = self.build()
        self.assertEqual(self.status(man, "db_config_perms"), "warn")
        self.assertEqual(man.failed_required, [])

    def test_no_ticket_tracker_or_owner_data(self):
        man, _ = self.build()
        items = {i["item"] for i in man.items}
        self.assertFalse([i for i in items if "owner" in i or "ticket" in i], items)
        self.assertFalse([n for n in dir(rm) if "owner" in n.lower() or "ticket" in n.lower()])
        self.assertNotIn("owners", json.dumps(man.data))

    def test_first_run_without_baseline_is_recorded_not_failed(self):
        empty = tempfile.mkdtemp()
        try:
            man = rm.build(self.run_dir, "unattended", empty, env=FakeEnv(self.home), cfg=self.cfg,
                           sfcall="/x/sfcall.sh", first_run=True)
            self.assertEqual(man.failed_required, [], man.items)
            self.assertEqual(self.status(man, "baseline"), "first_run")
            man2 = rm.build(self.run_dir, "unattended", empty, env=FakeEnv(self.home), cfg=self.cfg,
                            sfcall="/x/sfcall.sh")
            self.assertIn("baseline", [f["item"] for f in man2.failed_required])
        finally:
            shutil.rmtree(empty)

    def test_unconfigured_models_are_advisory(self):
        cfg = testcfg.load(testcfg.merged(models={"gemini": {"model": "", "binary": "", "list_args": []},
                                                  "codex": {"model": "", "binary": "codex"}}))
        env = FakeEnv(self.home, gemini_out=None, codex_rc=1)
        man = rm.build(self.run_dir, "unattended", self.repo, env=env, cfg=cfg, sfcall="/x/sfcall.sh")
        self.assertEqual(man.failed_required, [], man.items)
        self.assertEqual(self.status(man, "model_gemini"), "not_configured")
        self.assertEqual(self.status(man, "model_codex"), "not_configured")
        self.assertFalse([c for c in env.calls if c[0].endswith(("gemini", "codex"))])


@unittest.skipUnless(os.environ.get("SITE_AUDIT_MANIFEST_LIVE") == "1",
                     "set SITE_AUDIT_MANIFEST_LIVE=1 to run live (uses your real config and network)")
class LiveTest(unittest.TestCase):
    def test_live_build(self):
        import audit_config
        cfg = audit_config.load_config(os.environ.get("SITE_AUDIT_LIVE_CONFIG"))
        root = audit_config.run_root(cfg)
        os.makedirs(root, mode=0o700, exist_ok=True)
        d = tempfile.mkdtemp(prefix="run-", dir=root)
        try:
            man = rm.build(d, "unattended", cfg=cfg)
            self.assertTrue(os.path.isfile(os.path.join(d, "manifest.json")))
            print("\n" + rm.summary_text(man))
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
