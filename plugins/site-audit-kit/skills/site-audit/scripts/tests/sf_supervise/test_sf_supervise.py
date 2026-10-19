"""Tests for scripts/sf_supervise.py against a fake MCP server (never the real Screaming Frog).

Run: python3 -m unittest discover -s skills/site-audit/scripts/tests/sf_supervise -v

Health URLs are http://www.example.com:<port>/... and reach a local fixture only because
SF_SUPERVISE_TESTING=1 makes the supervisor build its SafeFetcher with a resolver that answers
127.0.0.1 (and safe_fetch's loopback test hook). No test talks to the internet.
"""
import importlib.util
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import fake_mcp  # noqa: E402
import testcfg  # noqa: E402

CONFIG = testcfg.use_config()

SCRIPTS = os.path.abspath(os.path.join(HERE, "..", ".."))
SUPERVISE = os.path.join(SCRIPTS, "sf_supervise.py")
REAL_REDACT = os.path.join(SCRIPTS, "redact_exports.py")
NEEDED = {"sf_crawl_progress", "sf_crawl", "sf_pause_crawl", "sf_list_crawls", "sf_load_crawl",
          "sf_export_seo_element_urls"}
URL = "https://www.example.com/"

# argv[1:] logged; FAKE_REDACT_MODE: ok | fail-fix | fail-check | slow
FAKE_REDACT = """#!/usr/bin/env python3
import json, os, sys, time
with open(os.environ["FAKE_REDACT_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
mode = os.environ.get("FAKE_REDACT_MODE", "ok")
if mode == "slow":
    time.sleep(1.5)
if mode == "fail-fix" and "--check" not in sys.argv:
    sys.exit(2)
if mode == "fail-check" and "--check" in sys.argv:
    sys.exit(1)
"""


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def load_module():
    spec = importlib.util.spec_from_file_location("sf_supervise_under_test", SUPERVISE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# Script overrides are honoured only for files inside the kit's tests folder, so the
# fixtures live in a git-ignored folder there.
TEST_TMP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_tmp")
os.makedirs(TEST_TMP, mode=0o700, exist_ok=True)

class Base(unittest.TestCase):
    scenario_kw = {}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sfsup-", dir=TEST_TMP)
        self.home = os.path.join(self.tmp, "home")
        self.base = os.path.join(self.tmp, "sfbase")
        os.makedirs(self.home)
        os.makedirs(self.base)
        self.config = os.path.join(self.tmp, "sc-test.seospiderconfig")
        with open(self.config, "w") as f:
            f.write("fake config")
        self.sc = fake_mcp.Scenario(self.base, **self.scenario_kw)
        self.srv = fake_mcp.serve(fake_mcp.make_handler(self.sc))
        self.srv_alive = True
        self.health = fake_mcp.Health()
        self.hsrv = fake_mcp.serve(fake_mcp.make_health_handler(self.health))
        hp = self.hsrv.server_address[1]
        self.health_urls = [f"http://www.example.com:{hp}/home", f"http://www.example.com:{hp}/blog"]
        self.sfroot = os.path.join(self.home, "site-audit", "sf")
        self.out = os.path.join(self.sfroot, "run-t1")
        self.redact_log = os.path.join(self.tmp, "redact.log")
        self.fake_redact = os.path.join(self.tmp, "fake_redact.py")
        with open(self.fake_redact, "w") as f:
            f.write(FAKE_REDACT)

    def kill_server(self):
        if self.srv_alive:
            self.srv.shutdown()
            self.srv.server_close()
            self.srv_alive = False

    def tearDown(self):
        self.kill_server()
        self.hsrv.shutdown()
        self.hsrv.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)
        # every test: only the tools the supervisor needs were ever requested
        called = set(self.sc.tools()) | {l[1] for l in self.sc.log if l[0] == "rejected-session"}
        self.assertFalse(called - NEEDED - {None}, f"tools outside the allowlist: {called - NEEDED}")

    def env(self, redact="fake", redact_mode="ok", testing=True, **extra):
        e = dict(os.environ)
        e["HOME"] = self.home
        e["SITE_AUDIT_CONFIG"] = CONFIG
        e["SF_MCP_URL"] = f"http://127.0.0.1:{self.srv.server_address[1]}/mcp"
        e["SF_TIMEOUT"] = "10"
        e["FAKE_REDACT_LOG"] = self.redact_log
        e["FAKE_REDACT_MODE"] = redact_mode
        e.pop("SF_SUPERVISE_TESTING", None)
        e.pop("SITE_AUDIT_SUPERVISED", None)
        if testing:
            e["SF_SUPERVISE_TESTING"] = "1"
        if redact == "fake":
            e["SF_REDACT_SCRIPT"] = self.fake_redact
        elif redact == "missing":
            e["SF_REDACT_SCRIPT"] = os.path.join(self.tmp, "does-not-exist.py")
        else:
            e["SF_REDACT_SCRIPT"] = redact
        e.update(extra)
        return e

    def argv(self, *extra, config=None, health=True, limit="1", url=URL, out=None, base=None):
        a = [sys.executable, SUPERVISE, "--name", "t1", "--url", url,
             "--config", config or self.config, "--poll", "0.05", "--limit-hours", limit,
             "--out", out or self.out, "--sf-base", base or self.base, "--busy-base", "0.05",
             "--start-grace", "3", "--pause-verify-seconds", "2", "--idle-timeout", "10",
             "--health-timeout", "3"]
        if health:
            for u in self.health_urls:
                a += ["--health", u]
        return a + list(extra)

    def run_sup(self, *extra, redact="fake", redact_mode="ok", timeout=60, env_extra=None, testing=True,
                umask=None, **kw):
        pre = (lambda: os.umask(umask)) if umask is not None else None
        return subprocess.run(self.argv(*extra, **kw), env=self.env(redact, redact_mode, testing, **(env_extra or {})),
                              capture_output=True, text=True, timeout=timeout, preexec_fn=pre)

    def popen(self, *extra, redact="fake", redact_mode="ok", **kw):
        return subprocess.Popen(self.argv(*extra, **kw), env=self.env(redact, redact_mode), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)

    def state(self):
        with open(os.path.join(self.out, "supervise.json")) as f:
            return json.load(f)

    def progress_lines(self):
        p = os.path.join(self.out, "progress.log")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(l) for l in f if l.strip()]

    def redact_calls(self):
        if not os.path.exists(self.redact_log):
            return []
        with open(self.redact_log) as f:
            return [json.loads(l) for l in f]

    def wait_active(self, p, n=2):
        deadline = time.time() + 15
        while time.time() < deadline:
            if sum(1 for l in self.progress_lines() if l["state"] == "SpiderActiveState") >= n:
                return
            time.sleep(0.02)
        p.kill()
        self.fail("crawl never became active")


class HappyPath(Base):
    scenario_kw = {"active_polls": 3, "busy_after_load": 2, "expire_every": 4}

    def test_happy_path_with_export(self):
        r = self.run_sup("--export")
        self.assertEqual(r.returncode, 0, r.stderr)
        tools = self.sc.tools()
        crawl = [l for l in self.sc.log if l[0] == "tools/call" and l[1] == "sf_crawl"]
        self.assertEqual(len(crawl), 1)
        self.assertEqual(crawl[0][2], {"crawl_url": URL, "config_path": self.config,
                                       "crawl_name": "t1", "project_name": "site-audit"})
        # order: progress + list (preflight) before crawl; list -> load -> export at the end
        self.assertEqual(tools[0], "sf_crawl_progress")
        self.assertLess(tools.index("sf_list_crawls"), tools.index("sf_crawl"))
        self.assertLess(tools.index("sf_crawl"), tools.index("sf_load_crawl"))
        self.assertLess(tools.index("sf_load_crawl"), tools.index("sf_export_seo_element_urls"))
        self.assertNotIn("sf_pause_crawl", tools)
        load = [l for l in self.sc.log if l[1] == "sf_load_crawl" and l[0] == "tools/call"][0]
        self.assertEqual(load[2], {"crawl_id": self.sc.my_db})
        exports = [l for l in self.sc.log if l[0] == "tools/call" and l[1] == "sf_export_seo_element_urls"]
        self.assertEqual(len(exports), 3)
        self.assertEqual(exports[-1][2]["file_path"], "run-t1/internal_all.ndjson")
        self.assertIn("spider busy", r.stderr)
        self.assertGreater(self.sc.inits, 1)
        local = os.path.join(self.out, "internal_all.ndjson")
        sfcopy = os.path.join(self.base, "run-t1", "internal_all.ndjson")
        self.assertTrue(os.path.isfile(local))
        self.assertEqual(mode(local), 0o600)
        self.assertEqual(mode(sfcopy), 0o600)
        self.assertEqual(mode(self.out), 0o700)
        self.assertEqual(mode(os.path.join(self.base, "run-t1")), 0o700)
        self.assertEqual(mode(os.path.join(self.out, "supervise.json")), 0o600)
        self.assertEqual(mode(os.path.join(self.out, "progress.log")), 0o600)
        st = self.state()
        self.assertEqual(st["status"], "exported")
        self.assertTrue(st["owned"])
        self.assertEqual(st["database_id"], self.sc.my_db)
        self.assertEqual(st["crawl_id"], self.sc.my_db)
        self.assertEqual(st["redact"], "ok")
        lines = self.progress_lines()
        self.assertTrue(lines)
        for k in ("time", "state", "done", "waiting", "api", "analysis", "health"):
            self.assertIn(k, lines[0])
        self.assertTrue(any(l["state"] == "SpiderActiveState" for l in lines))
        self.assertTrue(any(str(l["state"]).startswith("CrawlAnalysis") for l in lines))
        self.assertEqual(lines[-1]["state"], "SpiderCrawlIdleState")
        self.assertTrue(all(len(l["health"]) == 2 and all(h["ok"] for h in l["health"]) for l in lines))
        # redactor: --fix-perms on both copies, then --check on both copies
        calls = self.redact_calls()
        self.assertEqual(len(calls), 2, calls)
        self.assertIn("--fix-perms", calls[0])
        self.assertIn("--check", calls[1])
        for c in calls:
            self.assertIn(os.path.join(self.base, "run-t1"), c)
            self.assertIn(self.out, c)

    def test_without_export_only_loads(self):
        r = self.run_sup()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("sf_load_crawl", self.sc.tools())
        self.assertNotIn("sf_export_seo_element_urls", self.sc.tools())
        self.assertEqual(self.state()["status"], "done")

    def test_redact_missing_exits_7(self):
        r = self.run_sup("--export", redact="missing")
        self.assertEqual(r.returncode, 7, r.stderr)
        self.assertIn("NOT redacted", r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "export-unredacted")
        self.assertEqual(st["redact"], "missing")
        self.assertEqual(mode(os.path.join(self.base, "run-t1", "internal_all.ndjson")), 0o600)

    def test_redact_fix_failure_exits_7(self):
        r = self.run_sup("--export", redact_mode="fail-fix")
        self.assertEqual(r.returncode, 7, r.stderr)
        self.assertEqual(self.state()["status"], "export-unredacted")

    def test_redact_check_failure_exits_7(self):
        r = self.run_sup("--export", redact_mode="fail-check")
        self.assertEqual(r.returncode, 7, r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "export-unredacted")
        self.assertTrue(st["redact"].startswith("check-failed"), st["redact"])

    @unittest.skipUnless(os.path.isfile(REAL_REDACT), "redact_exports.py not present")
    def test_real_redact_script_redacts_both_copies(self):
        r = self.run_sup("--export", redact=REAL_REDACT)
        self.assertEqual(r.returncode, 0, r.stderr)
        for p in (os.path.join(self.out, "internal_all.ndjson"),
                  os.path.join(self.base, "run-t1", "internal_all.ndjson")):
            with open(p) as f:
                text = f.read()
            self.assertNotIn("SECRETVALUE123", text, p)
            self.assertIn("token=REDACTED", text, p)
            self.assertEqual(mode(p), 0o600)

    def test_copies_are_private_even_with_umask_0(self):
        r = self.run_sup("--export", umask=0)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(mode(os.path.join(self.out, "internal_all.ndjson")), 0o600)
        self.assertEqual(mode(os.path.join(self.base, "run-t1", "internal_all.ndjson")), 0o600)
        self.assertEqual([n for n in os.listdir(self.out) if n.startswith(".tmp")], [])


class HealthFailure(Base):
    scenario_kw = {"active_polls": None}

    def test_health_failure_pauses_and_exits_5(self):
        self.health.status["/blog"] = 503
        r = self.run_sup()
        self.assertEqual(r.returncode, 5, r.stderr)
        self.assertIn("sf_pause_crawl", self.sc.tools())
        self.assertEqual(self.sc.phase, "paused")
        st = self.state()
        self.assertEqual(st["status"], "paused-health")
        self.assertTrue(st["paused"])
        self.assertIn("503", st["reason"])
        self.assertEqual(self.progress_lines()[-1]["health_fail_rounds"], 2)
        self.assertNotIn("sf_export_seo_element_urls", self.sc.tools())

    def test_single_failed_round_does_not_pause(self):
        self.health.status["/home"] = 500
        p = self.popen(limit="0.0006")
        deadline = time.time() + 10
        while time.time() < deadline and not self.progress_lines():
            time.sleep(0.01)
        self.health.status["/home"] = 200
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 6, err)  # hard limit, not health
        self.assertTrue(any(not l["health_ok"] for l in self.progress_lines()))


class HardLimit(Base):
    scenario_kw = {"active_polls": None}

    def test_hard_limit_pauses_and_exits_6(self):
        r = self.run_sup(limit="0.0005")  # 1.8 s
        self.assertEqual(r.returncode, 6, r.stderr)
        self.assertIn("sf_pause_crawl", self.sc.tools())
        self.assertEqual(self.sc.phase, "paused")
        st = self.state()
        self.assertEqual(st["status"], "partial")
        self.assertTrue(st["partial"])
        self.assertTrue(st["paused"])


class PauseNeverLands(Base):
    scenario_kw = {"active_polls": None, "pause_never": True}

    def test_hard_limit_with_unverified_pause_exits_8(self):
        r = self.run_sup(limit="0.0005")
        self.assertEqual(r.returncode, 8, r.stderr)
        self.assertIn("sf_pause_crawl", self.sc.tools())
        self.assertNotIn("crawl paused", r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "pause-not-verified")
        self.assertFalse(st["paused"])

    def test_health_failure_with_unverified_pause_exits_8(self):
        self.health.status["/blog"] = 503
        r = self.run_sup()
        self.assertEqual(r.returncode, 8, r.stderr)
        self.assertNotIn("crawl paused", r.stderr)
        self.assertEqual(self.state()["status"], "pause-not-verified")

    def test_signal_with_unverified_pause_exits_8(self):
        p = self.popen()
        self.wait_active(p)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 8, err)
        self.assertNotIn("crawl paused", err)
        self.assertFalse(self.state()["paused_on_signal"])


class Signals(Base):
    scenario_kw = {"active_polls": None, "pause_delay": 3}

    def test_sigterm_pauses_and_exits_143(self):
        p = self.popen()
        self.wait_active(p)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 143, err)
        self.assertIn("sf_pause_crawl", self.sc.tools())
        self.assertEqual(self.sc.phase, "paused")
        after = self.sc.tools()[self.sc.tools().index("sf_pause_crawl"):]
        self.assertGreaterEqual(after.count("sf_crawl_progress"), 2)
        st = self.state()
        self.assertEqual(st["status"], "interrupted")
        self.assertEqual(st["signal"], "SIGTERM")
        self.assertTrue(st["paused_on_signal"])
        self.assertTrue(any(e["event"] == "paused" for e in st["events"]))

    def test_sigint_exits_130(self):
        p = self.popen()
        self.wait_active(p)
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 130, err)
        self.assertEqual(self.sc.phase, "paused")


class SignalSameNameForeignCrawl(Base):
    """Ours is recorded, then a DIFFERENT crawl with the SAME name is running: never pause it."""
    scenario_kw = {"active_polls": None, "foreign_after": 2, "foreign_name": "t1"}

    def test_sigterm_does_not_pause_a_same_name_crawl_that_is_not_ours(self):
        p = self.popen()
        deadline = time.time() + 15
        while time.time() < deadline and not any(l.get("database_id") == "foreign-crawl-db"
                                                 for l in self.progress_lines()):
            time.sleep(0.02)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 8, err)
        self.assertNotIn("sf_pause_crawl", self.sc.tools())
        st = self.state()
        self.assertEqual(st["database_id"], self.sc.my_db)
        self.assertFalse(st["paused_on_signal"])
        self.assertTrue(any(e["event"] == "pause_skipped" for e in st["events"]))


class OwnershipForeignAtStart(Base):
    """Another crawl (other name) is the one running right after our sf_crawl returns."""
    scenario_kw = {"active_polls": None, "foreign_after": 0}

    def test_unproven_ownership_exits_1_and_never_pauses(self):
        r = self.run_sup()
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertNotIn("sf_pause_crawl", self.sc.tools())
        st = self.state()
        self.assertFalse(st["owned"])
        self.assertNotIn("database_id", st)
        self.assertEqual(st["status"], "ownership-unproven")


class OwnershipPreexistingSameName(Base):
    """The running crawl has our name but its id was already listed before we started."""
    scenario_kw = {"active_polls": None, "foreign_after": 0, "foreign_name": "t1", "foreign_preexisting": True}

    def test_same_name_id_from_before_start_is_not_ours(self):
        r = self.run_sup()
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertNotIn("sf_pause_crawl", self.sc.tools())
        st = self.state()
        self.assertFalse(st["owned"])
        self.assertIn("foreign-crawl-db", st["prestart_crawl_ids"])

    def test_signal_before_ownership_is_proven_never_pauses(self):
        p = self.popen()
        deadline = time.time() + 10
        while time.time() < deadline and "sf_crawl" not in self.sc.tools():
            time.sleep(0.005)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=30)
        self.assertIn(p.returncode, (1, 8), err)
        self.assertNotIn("sf_pause_crawl", self.sc.tools())


class ExportRecordedIdMissing(Base):
    """Our id is gone from sf_list_crawls; an older crawl with the same name is still listed."""
    scenario_kw = {"active_polls": 2, "hide_mine_after_finish": True, "same_name_old": True}

    def test_no_fallback_to_a_same_name_crawl(self):
        r = self.run_sup("--export")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertNotIn("sf_load_crawl", self.sc.tools())
        self.assertNotIn("sf_export_seo_element_urls", self.sc.tools())


class DeadServer(Base):
    scenario_kw = {"active_polls": None}

    def test_dead_server_exits_3_promptly(self):
        p = self.popen()
        self.wait_active(p)
        self.kill_server()
        t0 = time.time()
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 3, err)
        self.assertLess(time.time() - t0, 20)
        self.assertNotIn("crawl paused", err)
        self.assertEqual(self.state()["status"], "mcp-unreachable")

    def test_signal_with_dead_server_exits_8(self):
        p = self.popen()
        self.wait_active(p)
        self.kill_server()
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 8, err)
        self.assertNotIn("crawl paused", err)


class SignalDuringExport(Base):
    scenario_kw = {"active_polls": 2, "export_delay": 1.5}

    def _term_during_export(self, redact="fake"):
        p = self.popen("--export", redact=redact)
        self.assertTrue(self.sc.export_started.wait(20), "export never started")
        time.sleep(0.2)
        p.send_signal(signal.SIGTERM)
        return p, p.communicate(timeout=60)

    def test_sigterm_during_export_locks_down_and_redacts(self):
        p, (out, err) = self._term_during_export()
        self.assertEqual(p.returncode, 143, err)
        sfcopy = os.path.join(self.base, "run-t1", "internal_all.ndjson")
        self.assertEqual(mode(sfcopy), 0o600)
        calls = self.redact_calls()
        self.assertTrue(any("--check" in c for c in calls), calls)
        self.assertEqual(self.state()["redact"], "ok")

    def test_sigterm_during_export_with_redactor_missing_exits_7(self):
        p, (out, err) = self._term_during_export(redact="missing")
        self.assertEqual(p.returncode, 7, err)
        self.assertEqual(mode(os.path.join(self.base, "run-t1", "internal_all.ndjson")), 0o600)
        self.assertEqual(self.state()["status"], "export-unredacted")


class SignalDuringRedaction(Base):
    scenario_kw = {"active_polls": 2}

    def test_sigterm_during_redaction_is_not_lost(self):
        p = self.popen("--export", redact_mode="slow")
        deadline = time.time() + 20
        while time.time() < deadline and not self.redact_calls():
            time.sleep(0.02)
        self.assertTrue(self.redact_calls(), "redactor never ran")
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 143, err)
        self.assertEqual(self.state()["status"], "interrupted")


class SignalAfterLoadNoExport(Base):
    scenario_kw = {"active_polls": 2, "after_load_active": 60}

    def test_signal_on_the_no_export_path_is_not_lost(self):
        # SIGTERM lands while the supervisor waits for idle after sf_load_crawl (fake shows active)
        p = self.popen()
        deadline = time.time() + 20
        while time.time() < deadline and "sf_load_crawl" not in self.sc.tools():
            time.sleep(0.002)
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 143, err)
        self.assertNotIn("sf_pause_crawl", self.sc.tools())  # the crawl was finished: nothing to pause


class Preflight(Base):
    scenario_kw = {"initial": "active"}

    def test_refuses_when_a_crawl_is_running(self):
        r = self.run_sup("--export")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("not idle", r.stderr)
        self.assertEqual(self.sc.tools(), ["sf_crawl_progress"])
        self.assertEqual(self.sc.phase, "active")


class PreflightPaused(Base):
    scenario_kw = {"initial": "paused"}

    def test_refuses_when_a_crawl_is_paused(self):
        r = self.run_sup()
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(self.sc.tools(), ["sf_crawl_progress"])


class Arguments(Base):
    def assertRefused(self, r, text=None):
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        if text:
            self.assertIn(text, r.stderr)
        self.assertEqual(self.sc.log, [])

    def test_refuses_relative_config_path(self):
        self.assertRefused(self.run_sup(config="sc-test.seospiderconfig"), "ABSOLUTE")

    def test_refuses_missing_config(self):
        self.assertRefused(self.run_sup(config=os.path.join(self.tmp, "nope.seospiderconfig")))

    def test_dry_run_prints_plan_and_calls_nothing(self):
        r = self.run_sup("--dry-run", "--export")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("sf_crawl", r.stdout)
        self.assertIn("run-t1/internal_all.ndjson", r.stdout)
        self.assertIn("tools allowed", r.stdout)
        self.assertEqual(self.sc.log, [])
        self.assertFalse(os.path.exists(self.out))

    def test_non_finite_numbers_refused(self):
        for flag, val in (("--limit-hours", "nan"), ("--limit-hours", "inf"), ("--limit-hours", "5"),
                          ("--poll", "nan"), ("--poll", "inf"), ("--poll", "-1"),
                          ("--health-timeout", "nan"), ("--health-timeout", "inf"),
                          ("--health-slow", "nan"), ("--pause-verify-seconds", "inf"),
                          ("--idle-timeout", "nan"), ("--start-grace", "inf"), ("--busy-budget", "nan")):
            with self.subTest(flag=flag, val=val):
                self.assertRefused(self.run_sup(flag, val, "--dry-run"))
        for v in ("nan", "inf", "0", "x"):
            with self.subTest(SF_TIMEOUT=v):
                self.assertRefused(self.run_sup("--dry-run", env_extra={"SF_TIMEOUT": v}))

    def test_crawl_destinations(self):
        bad = ["http://169.254.169.254/", "https://example.test/", "https://www.example.com@evil.com/",
               "https://evil.com/?x=www.example.com", "https://www.example.com:8443/",
               "http://www.example.com/", "http://www.example.com/blogx", "ftp://www.example.com/",
               "https://WWW.example.com.evil.com/", "https://example.com/", "https://blog.example.com/",
               "https://www.example.com\\@evil.com/", "https://www.example.com/ x", "//www.example.com/",
               "http://help.example.com/blog/", "https://legacy.example.org/"]
        for u in bad:
            with self.subTest(url=u):
                self.assertRefused(self.run_sup("--dry-run", url=u))
        good = ["https://www.example.com/", "https://www.example.com/blog/", "https://help.example.com/",
                "http://www.example.com/blog/", "http://www.example.com/blog", "https://www.example.com"]
        for u in good:
            with self.subTest(url=u):
                r = self.run_sup("--dry-run", url=u)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_health_destinations(self):
        for u in ("https://evil.com/", "http://127.0.0.1/", "https://169.254.169.254/latest/",
                  "https://www.example.com@evil.com/", "file:///etc/passwd"):
            with self.subTest(health=u):
                r = subprocess.run(self.argv("--dry-run", health=False) + ["--health", u],
                                   env=self.env(testing=False), capture_output=True, text=True, timeout=30)
                self.assertRefused(r)
        # without the test switch a port or plain http on / is refused too
        r = subprocess.run(self.argv("--dry-run"), env=self.env(testing=False), capture_output=True, text=True,
                           timeout=30)
        self.assertRefused(r)

    def test_out_must_be_under_the_sf_root(self):
        self.assertRefused(self.run_sup("--dry-run", out=os.path.join(self.tmp, "elsewhere")))
        self.assertRefused(self.run_sup("--dry-run", out=self.sfroot))
        self.assertRefused(self.run_sup("--dry-run", out=os.path.join(self.sfroot, "..", "x")))

    def test_out_symlink_component_refused(self):
        target = os.path.join(self.tmp, "target")
        os.makedirs(target)
        os.makedirs(self.sfroot)
        os.symlink(target, os.path.join(self.sfroot, "link"))
        self.assertRefused(self.run_sup("--dry-run", out=os.path.join(self.sfroot, "link", "run")))
        self.assertRefused(self.run_sup("--dry-run", out=os.path.join(self.sfroot, "link")))
        self.assertEqual(os.listdir(target), [])

    def test_existing_out_with_unrelated_content_refused(self):
        os.makedirs(self.out)
        keep = os.path.join(self.out, "notes.sh")
        with open(keep, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(keep, 0o755)
        r = self.run_sup()
        self.assertRefused(r)
        self.assertEqual(mode(keep), 0o755)

    def test_existing_out_of_another_run_refused(self):
        os.makedirs(self.out)
        with open(os.path.join(self.out, "supervise.json"), "w") as f:
            json.dump({"name": "other-run"}, f)
        self.assertRefused(self.run_sup())

    def test_sf_base_must_be_the_real_base_without_test_switch(self):
        real = os.path.join(self.tmp, "real-base")
        os.makedirs(real)
        cfg = testcfg.write_config(testcfg.merged(screaming_frog={"base_dir": real}))
        r = subprocess.run(self.argv("--dry-run", health=False),
                           env=self.env(testing=False, SITE_AUDIT_CONFIG=cfg),
                           capture_output=True, text=True, timeout=30)
        self.assertRefused(r, "--sf-base")
        # an unset base_dir is refused too
        r = subprocess.run(self.argv("--dry-run", health=False), env=self.env(testing=False),
                           capture_output=True, text=True, timeout=30)
        self.assertRefused(r, "base_dir")
        # the configured base itself is accepted
        r = subprocess.run(self.argv("--dry-run", base=real), env=self.env(testing=True, SITE_AUDIT_CONFIG=cfg),
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_unconfigured_kit_refuses_every_crawl(self):
        missing = os.path.join(self.tmp, "no-such-config.json")
        r = subprocess.run(self.argv("--dry-run"), env=self.env(SITE_AUDIT_CONFIG=missing),
                           capture_output=True, text=True, timeout=30)
        self.assertRefused(r, "config")
        empty_home = os.path.join(self.tmp, "fresh-home")
        os.makedirs(empty_home)
        env = self.env(HOME=empty_home)
        env.pop("SITE_AUDIT_CONFIG")
        r = subprocess.run(self.argv("--dry-run"), env=env, capture_output=True, text=True, timeout=30)
        self.assertRefused(r, "no crawl.hosts")

    def test_sf_export_dir_symlink_refused_before_any_crawl(self):
        target = os.path.join(self.tmp, "target")
        os.makedirs(target)
        os.symlink(target, os.path.join(self.base, "run-t1"))
        r = self.run_sup("--export")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertNotIn("sf_crawl", self.sc.tools())
        self.assertEqual(os.listdir(target), [])

    def test_tool_allowlist(self):
        m = load_module()
        self.assertEqual(set(m.ALLOWED_TOOLS), NEEDED)
        # the allowlist is inside the kit's default sfcall.sh allowlist
        sys.path.insert(0, SCRIPTS)
        import audit_config
        listed = set(audit_config.DEFAULTS["screaming_frog"]["allowed_tools"])
        supervised = set(audit_config.SF_SUPERVISED_TOOLS)
        self.assertTrue(NEEDED <= listed | supervised, NEEDED - listed - supervised)
        # the default list is read-only: no state-changing tool is in it
        self.assertFalse([t for t in listed if audit_config.sf_supervised_only(t)], listed)
        for risky in ("sf_clear_crawl", "sf_run_node_js_script", "sf_npm_install", "sf_write_text_file",
                      "sf_open_url_in_browser", "sf_read_text_file"):
            self.assertNotIn(risky, listed)
        os.environ["SF_MCP_URL"] = "http://127.0.0.1:%d/mcp" % self.srv.server_address[1]
        mcp = m.Mcp()
        for t in ("sf_clear_crawl", "sf_run_node_js_script", "sf_npm_install", "sf_write_text_file",
                  "sf_open_url_in_browser", "sf_read_text_file", "sf_resume_crawl", "sf_generate_report",
                  "sf_url_content", "sf_crawl ", "SF_CRAWL", "anything"):
            with self.subTest(tool=t):
                with self.assertRaises(RuntimeError):
                    mcp.raw(t)
        self.assertEqual(self.sc.log, [])


class SfcallAllowlist(Base):
    """sfcall.sh refuses tools outside screaming_frog.allowed_tools before any request."""

    def sfcall(self, *args, **env_extra):
        return subprocess.run([os.path.join(SCRIPTS, "sfcall.sh"), *args], env=self.env(**env_extra),
                              capture_output=True, text=True, timeout=60)

    def test_disallowed_tools_never_reach_the_server(self):
        for tool in ("sf_clear_crawl", "sf_run_node_js_script", "sf_write_text_file", "sf_url_content",
                     "sf_open_url_in_browser", "anything"):
            with self.subTest(tool=tool):
                r = self.sfcall(tool, "{}")
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("allowed_tools", r.stderr)
        self.assertEqual(self.sc.log, [])

    def test_allowed_tool_and_list_work(self):
        r = self.sfcall("sf_crawl_progress")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.sfcall("--list").returncode, 0)
        sid_dir = os.path.join(self.home, "site-audit", "sf")
        self.assertEqual(mode(sid_dir), 0o700)

    STATE_CHANGING = ("sf_crawl", "sf_resume_crawl", "sf_load_crawl", "sf_pause_crawl",
                      "sf_export_seo_element_urls", "sf_export_crawl", "sf_generate_bulk_export",
                      "sf_generate_report")

    def test_state_changing_tools_refused_without_supervised_env(self):
        # even a config that lists them does not let a direct call through
        cfg = testcfg.write_config(testcfg.merged(screaming_frog={
            "base_dir": self.base, "allowed_tools": list(self.STATE_CHANGING) + ["sf_crawl_progress"]}))
        for tool in self.STATE_CHANGING:
            for c in (None, cfg):
                with self.subTest(tool=tool, config=c):
                    extra = {"SITE_AUDIT_CONFIG": c} if c else {}
                    r = self.sfcall(tool, '{"crawl_url": "https://www.example.com/"}', **extra)
                    self.assertEqual(r.returncode, 2, r.stderr)
                    self.assertIn("sf_supervise.py", r.stderr)
        r = self.sfcall("sf_crawl", "{}", SITE_AUDIT_SUPERVISED="0")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(self.sc.log, [])

    def test_state_changing_tool_reaches_server_only_when_supervised(self):
        self.sfcall("sf_pause_crawl", "{}", SITE_AUDIT_SUPERVISED="1")
        self.assertIn("sf_pause_crawl", self.sc.tools())

    def test_config_error_is_exit_2(self):
        r = self.sfcall("sf_crawl_progress", SITE_AUDIT_CONFIG=os.path.join(self.tmp, "missing.json"))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(self.sc.log, [])


class NeverStarts(Base):
    scenario_kw = {"never_starts": True}

    def test_crawl_that_never_becomes_active_fails(self):
        r = self.run_sup()
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(self.state()["status"], "failed")
        self.assertNotIn("sf_load_crawl", self.sc.tools())


# ---------------------------------------------------------------- unit level

class StubResult:
    def __init__(self, status=200, error=None, elapsed_ms=5):
        self.status, self.error, self.elapsed_ms = status, error, elapsed_ms

    @property
    def ok(self):
        return self.error is None and self.status is not None


class HealthUnit(unittest.TestCase):
    def setUp(self):
        self.m = load_module()

    def test_one_in_flight_request_per_url(self):
        release = threading.Event()
        calls = []

        class Blocking:
            def fetch(self, url):
                calls.append(url)
                release.wait(10)
                return StubResult()

        h = self.m.HealthMonitor(["https://www.example.com/"], 0.3, 8.0, Blocking())
        t0 = time.monotonic()
        r1, ok1 = h.round()
        r2, ok2 = h.round()
        took = time.monotonic() - t0
        release.set()
        self.assertFalse(ok1)
        self.assertFalse(ok2)
        self.assertEqual(len(calls), 1, calls)
        self.assertIn("in flight", r2[0]["error"])
        self.assertLess(took, 2 * (0.3 + 2.5))

    def test_no_fetcher_fails_closed(self):
        h = self.m.HealthMonitor(["https://www.example.com/"], 1.0, 8.0, None)
        res, ok = h.round()
        self.assertFalse(ok)
        self.assertFalse(res[0]["ok"])

    def test_non_200_and_slow_fail(self):
        class F:
            def __init__(self, r): self.r = r
            def fetch(self, url): return self.r
        for r in (StubResult(status=503), StubResult(status=301), StubResult(status=None, error="dns")):
            res, ok = self.m.HealthMonitor(["https://www.example.com/"], 1.0, 8.0, F(r)).round()
            self.assertFalse(ok)
        res, ok = self.m.HealthMonitor(["https://www.example.com/"], 1.0, 8.0, F(StubResult())).round()
        self.assertTrue(ok)

    def test_trickling_response_stops_at_the_wall_deadline(self):
        hsrv = fake_mcp.serve(fake_mcp.make_health_handler(fake_mcp.Health()))
        try:
            fetcher, err = self.m.make_fetcher(1.0, testing=True)
            if fetcher is None:
                self.skipTest(f"safe_fetch unavailable: {err}")
            url = f"http://www.example.com:{hsrv.server_address[1]}/trickle"
            t0 = time.monotonic()
            res, ok = self.m.HealthMonitor([url], 1.0, 8.0, fetcher).round()
            took = time.monotonic() - t0
            self.assertFalse(ok)
            self.assertLess(took, 3.6, res)
        finally:
            hsrv.shutdown()
            hsrv.server_close()


class OwnershipUnit(unittest.TestCase):
    """pause_owned with a recorded id and a different active id: no list call, no pause."""

    def test_recorded_id_mismatch_is_definitive(self):
        m = load_module()
        tmp = tempfile.mkdtemp(prefix="sfsup-u-", dir=TEST_TMP)
        try:
            calls = []

            class StubMcp:
                def json(self, tool, args=None, busy_retry=True):
                    calls.append(tool)
                    if tool == "sf_crawl_progress":
                        return {"stateName": "SpiderActiveState", "databaseId": "B"}
                    if tool == "sf_list_crawls":
                        return [{"instanceDirName": "B", "crawlName": "t1"}]
                    raise AssertionError(tool)

                def raw(self, tool, args=None):
                    calls.append(tool)
                    return "ok"

                call = None

            class A:
                name, poll, pause_verify_seconds = "t1", 0.05, 1.0
                busy_base, busy_budget = 0.05, 1.0
                out, sf_base = tmp, tmp
                export = False

            s = m.Supervisor(A())
            s.mcp = StubMcp()
            s.crawl_requested = True
            s.state.save(owned=True, database_id="A", name="t1")
            self.assertFalse(s.pause_owned("test"))
            self.assertNotIn("sf_pause_crawl", calls)
            self.assertNotIn("sf_list_crawls", calls)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class CopyUnit(unittest.TestCase):
    def test_copy_private_never_broad_and_never_follows_dst_symlink(self):
        m = load_module()
        tmp = tempfile.mkdtemp(prefix="sfsup-c-", dir=TEST_TMP)
        old = os.umask(0)
        try:
            src = os.path.join(tmp, "src")
            with open(src, "w") as f:
                f.write("data\n")
            victim = os.path.join(tmp, "victim")
            with open(victim, "w") as f:
                f.write("keep\n")
            dst = os.path.join(tmp, "dst")
            os.symlink(victim, dst)
            m.copy_private(src, dst)
            self.assertFalse(os.path.islink(dst))
            self.assertEqual(mode(dst), 0o600)
            with open(victim) as f:
                self.assertEqual(f.read(), "keep\n")
            with open(dst) as f:
                self.assertEqual(f.read(), "data\n")
            os.symlink(victim, os.path.join(tmp, "src-link"))
            with self.assertRaises(OSError):
                m.copy_private(os.path.join(tmp, "src-link"), os.path.join(tmp, "dst2"))
        finally:
            os.umask(old)
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
