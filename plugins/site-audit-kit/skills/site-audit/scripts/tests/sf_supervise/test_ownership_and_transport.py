"""Regression tests: ownership loss, uncertain starts, cleanup on any error,
failed exports, URL redaction in logs, sfcall.sh transport hardening and the plain-http path rule.

Every server here is a local fake on 127.0.0.1; nothing reaches the real Screaming Frog server.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import fake_mcp  # noqa: E402
import testcfg  # noqa: E402
import test_sf_supervise as T  # noqa: E402

SCRIPTS = T.SCRIPTS
SFCALL = os.path.join(SCRIPTS, "sfcall.sh")
FOREIGN = "foreign-crawl-db"


def tools_called(sc, name):
    return [l for l in sc.log if l[0] == "tools/call" and l[1] == name]


# ---------------------------------------------------------------- 1. ownership lost

class OwnershipLostWhileActive(T.Base):
    """Ours is recorded, then a different id is the active one, then that crawl finishes."""
    scenario_kw = {"active_polls": 4, "foreign_after": 2}

    def test_foreign_id_after_ownership_stops_with_ownership_lost(self):
        r = self.run_sup("--export")
        self.assertEqual(r.returncode, 1, r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "ownership-lost")
        self.assertEqual(st["database_id"], self.sc.my_db)
        self.assertNotIn("sf_load_crawl", self.sc.tools())
        self.assertNotIn("sf_export_seo_element_urls", self.sc.tools())
        self.assertNotIn("sf_pause_crawl", self.sc.tools())


class OwnershipLostAtIdle(T.Base):
    """Our crawl ran; the final idle reply names another database id: never accepted as ours."""
    scenario_kw = {"active_polls": 2, "finish_with_db": FOREIGN}

    def test_completion_with_another_id_is_not_ours(self):
        r = self.run_sup("--export")
        self.assertEqual(r.returncode, 1, r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "ownership-lost")
        self.assertNotIn("finished_at", st)
        self.assertNotIn("sf_load_crawl", self.sc.tools())
        self.assertNotIn("sf_export_seo_element_urls", self.sc.tools())


# ---------------------------------------------------------------- 2. uncertain start

class StartReplyDropped(T.Base):
    scenario_kw = {"active_polls": 3, "crawl_reply": "drop"}

    def test_lost_reply_is_reconciled_and_supervised(self):
        r = self.run_sup()
        self.assertEqual(r.returncode, 0, r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "done")
        self.assertTrue(st["owned"])
        self.assertEqual(st["database_id"], self.sc.my_db)
        self.assertTrue(any(e["event"] == "start_uncertain" for e in st["events"]))
        self.assertEqual(len(tools_called(self.sc, "sf_crawl")), 1)
        self.assertIn("sf_load_crawl", self.sc.tools())


class StartReplyGarbage(T.Base):
    scenario_kw = {"active_polls": 3, "crawl_reply": "garbage"}

    def test_unparsable_reply_is_reconciled(self):
        r = self.run_sup()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.state()["owned"])
        self.assertEqual(len(tools_called(self.sc, "sf_crawl")), 1)


class StartReplyDroppedForeignRunning(T.Base):
    scenario_kw = {"active_polls": None, "crawl_reply": "drop-foreign"}

    def test_unprovable_running_crawl_exits_8_without_pausing(self):
        r = self.run_sup()
        self.assertEqual(r.returncode, 8, r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "pause-not-verified")
        self.assertIn("start uncertain", st["reason"])
        self.assertNotIn("sf_pause_crawl", self.sc.tools())
        self.assertIn("Check the Screaming Frog app", r.stderr)


class StartReplyDroppedNothingStarted(T.Base):
    scenario_kw = {"crawl_reply": "drop-nostart"}

    def test_idle_through_the_grace_and_nothing_listed_exits_1(self):
        r = self.run_sup()
        self.assertEqual(r.returncode, 1, r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "failed")
        self.assertIn("nothing is running", st["error"])
        # reconciliation polled progress and listed crawls after the lost reply
        after = self.sc.tools()[self.sc.tools().index("sf_crawl") + 1:]
        self.assertIn("sf_crawl_progress", after)
        self.assertIn("sf_list_crawls", after)


class _A:
    name, poll, pause_verify_seconds, start_grace = "t1", 0.02, 0.5, 0.4
    busy_base, busy_budget = 0.02, 0.5
    export = False
    url, config, limit_hours, health = "https://www.example.com/", "/x.seospiderconfig", 1.0, []


class UnitBase(unittest.TestCase):
    def setUp(self):
        self.m = T.load_module()
        os.makedirs(T.TEST_TMP, mode=0o700, exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix="sfsup-r-", dir=T.TEST_TMP)
        a = _A()
        a.out = a.sf_base = self.tmp
        self.s = self.m.Supervisor(a)
        self.s.state.data = {"prestart_crawl_ids": []}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class StartUnit(UnitBase):
    def stub(self, crawl_rc, progress_rc=None):
        m, calls = self.m, []

        class StubMcp:
            def call(self, tool, args=None, busy_retry=True):
                calls.append(tool)
                raise m.McpError(tool, crawl_rc, "boom")

            def json(self, tool, args=None, busy_retry=True):
                calls.append(tool)
                if progress_rc is not None:
                    raise m.McpError(tool, progress_rc, "unreachable")
                if tool == "sf_crawl_progress":
                    return {"stateName": "SpiderCrawlIdleState", "databaseId": "old"}
                return []

            raw = call
        self.s.mcp = StubMcp()
        return calls

    def test_rejection_is_definitive_and_not_reconciled(self):
        calls = self.stub(4)
        with self.assertRaises(self.m.Abort) as cm:
            self.s.start()
        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(calls, ["sf_crawl"])
        self.assertFalse(self.s.crawl_requested)

    def test_uncertain_start_with_server_gone_exits_8(self):
        calls = self.stub(3, progress_rc=3)
        with self.assertRaises(self.m.Abort) as cm:
            self.s.start()
        self.assertEqual(cm.exception.code, 8)
        self.assertTrue(self.s.crawl_requested)
        self.assertIn("sf_crawl_progress", calls)
        self.assertEqual(self.s.state.data["status"], "pause-not-verified")


# ---------------------------------------------------------------- 2b. cleanup on any error

class ProgressLogUnwritable(T.Base):
    """An OSError while writing progress.log after sf_crawl must still pause our crawl."""
    scenario_kw = {"active_polls": None}

    def test_oserror_after_start_pauses_the_crawl(self):
        os.makedirs(os.path.join(self.out, "progress.log"))
        with open(os.path.join(self.out, "supervise.json"), "w") as f:
            json.dump({"name": "t1"}, f)
        r = self.run_sup()
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("sf_pause_crawl", self.sc.tools())
        st = self.state()
        self.assertEqual(st["status"], "failed")
        self.assertTrue(st["paused"])
        self.assertIn("unexpected", st["error"])


class RunUnit(UnitBase):
    def prime(self, exc, verified):
        s, seen = self.s, []
        s.prepare_out = lambda: None
        s.preflight = lambda: None

        def start():
            s.crawl_requested = True
        s.start = start

        def monitor():
            raise exc
        s.monitor = monitor

        def pause_owned(reason):
            seen.append(reason)
            return verified
        s.pause_owned = pause_owned
        old = {sg: signal.getsignal(sg) for sg in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        self.addCleanup(lambda: [signal.signal(k, v) for k, v in old.items()])
        return seen

    def test_unexpected_exception_runs_verified_pause(self):
        seen = self.prime(ValueError("surprise"), True)
        self.assertEqual(self.s.run(), 1)
        self.assertEqual(len(seen), 1)
        self.assertEqual(self.s.state.data["status"], "failed")

    def test_unexpected_exception_with_unverified_pause_exits_8(self):
        self.prime(ValueError("surprise"), False)
        self.assertEqual(self.s.run(), 8)
        self.assertEqual(self.s.state.data["status"], "pause-not-verified")

    def test_keyboard_interrupt_is_handled_as_sigint(self):
        seen = self.prime(KeyboardInterrupt(), True)
        self.assertEqual(self.s.run(), 130)
        self.assertEqual(len(seen), 1)

    def test_state_write_failure_does_not_skip_cleanup(self):
        seen = self.prime(OSError(28, "No space left on device"), False)
        real = self.m.write_private

        def broken(path, text):
            raise OSError(28, "No space left on device")
        self.m.write_private = broken
        try:
            self.assertEqual(self.s.run(), 8)
        finally:
            self.m.write_private = real
        self.assertEqual(len(seen), 1)


# ---------------------------------------------------------------- 3. failed or partial export

class ExportPartialError(T.Base):
    scenario_kw = {"active_polls": 2, "export_fail": "partial-error"}

    def sf_file(self):
        return os.path.join(self.base, "run-t1", "internal_all.ndjson")

    def test_failed_export_is_locked_and_gated(self):
        r = self.run_sup("--export", umask=0)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(T.mode(self.sf_file()), 0o600)
        calls = self.redact_calls()
        self.assertTrue(any("--fix-perms" in c and os.path.join(self.base, "run-t1") in c for c in calls), calls)
        self.assertTrue(any("--check" in c and os.path.join(self.base, "run-t1") in c for c in calls), calls)
        st = self.state()
        self.assertEqual(st["status"], "failed")
        self.assertEqual(st["redact"], "ok")

    def test_failed_export_with_check_failure_exits_7(self):
        r = self.run_sup("--export", redact_mode="fail-check")
        self.assertEqual(r.returncode, 7, r.stderr)
        self.assertEqual(self.state()["status"], "export-unredacted")

    def test_failed_export_with_redactor_missing_exits_7(self):
        r = self.run_sup("--export", redact="missing")
        self.assertEqual(r.returncode, 7, r.stderr)
        self.assertEqual(self.state()["status"], "export-unredacted")
        self.assertEqual(T.mode(self.sf_file()), 0o600)


class ExportPartialGarbage(T.Base):
    scenario_kw = {"active_polls": 2, "export_fail": "partial-garbage"}

    @unittest.skipUnless(os.path.isfile(T.REAL_REDACT), "redact_exports.py not present")
    def test_unparsable_export_reply_still_redacts_what_was_written(self):
        r = self.run_sup("--export", redact=T.REAL_REDACT)
        self.assertIn(r.returncode, (1, 7), r.stderr)
        p = os.path.join(self.base, "run-t1", "internal_all.ndjson")
        with open(p) as f:
            self.assertNotIn("SECRETVALUE123", f.read())
        self.assertEqual(T.mode(p), 0o600)


# ---------------------------------------------------------------- 4. URLs in logs

class UrlRedaction(T.Base):
    scenario_kw = {"active_polls": 2}

    def test_stored_and_printed_urls_carry_no_query_values(self):
        url = "https://www.example.com/?nocache=1"
        self.health_urls = [u + "?nocache=1" for u in self.health_urls]
        r = self.run_sup(url=url)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.out, "supervise.json")) as f:
            sj = f.read()
        with open(os.path.join(self.out, "progress.log")) as f:
            pl = f.read()
        for name, text in (("supervise.json", sj), ("progress.log", pl), ("stderr", r.stderr)):
            self.assertNotIn("nocache=1", text, name)
        self.assertIn("nocache=X", sj)
        self.assertIn("nocache=X", pl)
        # the crawl itself still gets the real URL
        self.assertEqual(tools_called(self.sc, "sf_crawl")[0][2]["crawl_url"], url)

    def test_refused_urls_are_printed_redacted(self):
        r = self.run_sup(url="https://www.example.com/?token=TOPSECRET1")
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("TOPSECRET1", r.stderr)
        self.health_urls = ["https://www.example.com/?key=TOPSECRET2"]
        r = self.run_sup()
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("TOPSECRET2", r.stderr)

    def test_dry_run_plan_redacts_urls(self):
        self.health_urls = [u + "?nocache=1" for u in self.health_urls]
        r = self.run_sup("--dry-run", url="https://www.example.com/?nocache=1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("nocache=1", r.stdout)
        self.assertIn("nocache=X", r.stdout)


class DryRunMcpUrl(T.Base):
    def test_plan_names_the_effective_mcp_url(self):
        cfg = testcfg.write_config(testcfg.merged(screaming_frog={
            "base_dir": None, "project_name": "site-audit", "mcp_url": "http://127.0.0.1:18999/cfg-mcp"}))
        env = self.env(SITE_AUDIT_CONFIG=cfg)
        env.pop("SF_MCP_URL")
        r = subprocess.run(self.argv("--dry-run"), env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("http://127.0.0.1:18999/cfg-mcp", r.stdout)
        self.assertNotIn("11435", r.stdout)
        env["SF_MCP_URL"] = "http://127.0.0.1:18998/env-mcp"
        r = subprocess.run(self.argv("--dry-run"), env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("http://127.0.0.1:18998/env-mcp", r.stdout)
        self.assertNotIn("cfg-mcp", r.stdout)


# ---------------------------------------------------------------- 5. sfcall.sh

class Sfcall(T.Base):
    def sfcall(self, *args, env=None, script=SFCALL, **env_extra):
        e = env or self.env(**env_extra)
        return subprocess.run([script, *args], env=e, capture_output=True, text=True, timeout=60)

    def test_proxy_variables_are_ignored(self):
        proxy = fake_mcp.Scenario(self.base)
        psrv = fake_mcp.serve(fake_mcp.make_handler(proxy))
        try:
            purl = f"http://127.0.0.1:{psrv.server_address[1]}"
            e = self.env(http_proxy=purl, HTTP_PROXY=purl, https_proxy=purl, all_proxy=purl)
            e.pop("no_proxy", None)
            e.pop("NO_PROXY", None)
            r = self.sfcall("sf_crawl_progress", env=e)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(proxy.log, [])
            self.assertIn("sf_crawl_progress", self.sc.tools())
        finally:
            psrv.shutdown()
            psrv.server_close()

    def test_non_loopback_or_odd_urls_refused(self):
        for u in ("http://192.0.2.1:11435/mcp", "file:///etc/passwd", "ftp://127.0.0.1/",
                  "http://127.0.0.1:11435/mcp\nX", "http://user@127.0.0.1:11435/mcp"):
            with self.subTest(url=u):
                r = self.sfcall("sf_crawl_progress", SF_MCP_URL=u)
                self.assertEqual(r.returncode, 2, r.stderr)

    def test_missing_validator_fails_closed(self):
        d = os.path.join(self.tmp, "kit")
        os.makedirs(d)
        shutil.copy2(SFCALL, os.path.join(d, "sfcall.sh"))
        with open(os.path.join(SCRIPTS, "audit_config.py")) as f:
            src = f.read()
        # an older audit_config without the helper (renamed, so the loader itself still works)
        src = re.sub(r"\bvalidate_mcp_url\b", "_renamed_helper", src)
        with open(os.path.join(d, "audit_config.py"), "w") as f:
            f.write(src)
        r = self.sfcall("sf_crawl_progress", script=os.path.join(d, "sfcall.sh"))
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("validate_mcp_url is missing", r.stderr)
        self.assertEqual(self.sc.log, [])

    def test_session_id_never_sent_to_another_server(self):
        self.assertEqual(self.sfcall("sf_crawl_progress").returncode, 0)
        other = fake_mcp.Scenario(self.base)
        osrv = fake_mcp.serve(fake_mcp.make_handler(other))
        try:
            r = self.sfcall("sf_crawl_progress", SF_MCP_URL=f"http://127.0.0.1:{osrv.server_address[1]}/mcp")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(other.log[0][0], "initialize")
            self.assertNotIn("rejected-session", [l[0] for l in other.log])
        finally:
            osrv.shutdown()
            osrv.server_close()
        # the first server's session is still reused (no second initialize)
        self.assertEqual(self.sfcall("sf_crawl_progress").returncode, 0)
        self.assertEqual(self.sc.inits, 1)

    def test_bad_arguments_refused_before_any_request(self):
        for raw in ("[1,2]", '"s"', "null", "42", '{"a":NaN}', '{"a":Infinity}', '{"a":-Infinity}'):
            with self.subTest(raw=raw):
                r = self.sfcall("sf_crawl_progress", raw)
                self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(self.sfcall("sf_crawl_progress", "{}", "extra").returncode, 2)
        self.assertEqual(self.sfcall("--list", "extra").returncode, 2)
        self.assertEqual(self.sc.log, [])


class SfcallHugeReply(T.Base):
    scenario_kw = {"huge_reply": 33 * 1024 * 1024}

    def test_oversized_reply_exits_3(self):
        r = subprocess.run([SFCALL, "sf_crawl_progress"], env=self.env(), capture_output=True, text=True,
                           timeout=120)
        self.assertEqual(r.returncode, 3, r.stderr[:300])
        self.assertIn("too large", r.stderr)


# ---------------------------------------------------------------- 6. plain-http path rule

class PlainHttpPath(unittest.TestCase):
    def setUp(self):
        self.m = T.load_module()
        self.cfg = testcfg.load()

    def test_dot_segments_and_double_slashes_refused(self):
        for path in ("/blog/../admin", "/blog/%2e%2e/admin", "/blog/%2E%2e/admin", "/blog/.%2E/admin",
                     "/blog/./x", "/blog/%2e/x", "/blog//x", "//blog/x", "/blog/..", "/blog/%2e%2e",
                     "/blog/%252e%252e/admin", "/blog%2f..%2fadmin"):
            with self.subTest(path=path):
                self.assertIsNotNone(self.m.site_url_error("http://www.example.com" + path, cfg=self.cfg))

    def test_plain_paths_under_the_prefix_still_allowed(self):
        for path in ("/blog", "/blog/", "/blog/a.b/", "/blog/..foo/", "/blog/post-1/"):
            with self.subTest(path=path):
                self.assertIsNone(self.m.site_url_error("http://www.example.com" + path, cfg=self.cfg))


if __name__ == "__main__":
    unittest.main()
