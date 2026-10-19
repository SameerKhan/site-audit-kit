"""Regression tests: an export whose outcome is uncertain (reply lost, or the spider still busy
when the export wait ends) is never gated as redacted until the spider is verified idle; server
text (progress messages, error strings, crawl names) is URL-redacted before it is stored or
printed; the effective MCP URL is validated in dry-run too.

Every server here is a local fake on 127.0.0.1; nothing reaches the real Screaming Frog server.
"""
import json
import os
import signal
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import testcfg  # noqa: E402
import test_sf_supervise as T  # noqa: E402
from test_ownership_and_transport import UnitBase, tools_called  # noqa: E402

LATE = "LATESECRET77"


def sf_file(base):
    return os.path.join(base, "run-t1", "internal_all.ndjson")


# ---------------------------------------------------------------- uncertain exports

class ExportDroppedStillWriting(T.Base):
    """The export reply is lost and the spider keeps exporting (busy) for good."""
    scenario_kw = {"active_polls": 2, "export_fail": "drop", "export_busy_polls": None}

    def test_unverified_idle_exits_7_without_redact_ok(self):
        r = self.run_sup("--export", "--idle-timeout", "1.5")
        self.assertEqual(r.returncode, 7, r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "export-unredacted")
        self.assertNotEqual(st.get("redact"), "ok")
        self.assertIn("may still be writing", r.stderr)
        self.assertEqual(self.redact_calls(), [])
        # progress was polled after the export call, even though the crawl had finished
        after = self.sc.tools()[self.sc.tools().index("sf_export_seo_element_urls") + 1:]
        self.assertIn("sf_crawl_progress", after)
        self.assertEqual(T.mode(sf_file(self.base)), 0o600)


class ExportDroppedThenIdle(T.Base):
    """The export reply is lost; the spider stays busy for three polls, then is idle."""
    scenario_kw = {"active_polls": 2, "export_fail": "drop", "export_busy_polls": 3}

    def test_gate_runs_only_after_verified_idle(self):
        r = self.run_sup("--export")
        self.assertEqual(r.returncode, 1, r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "failed")
        self.assertEqual(st["redact"], "ok")
        self.assertEqual(self.sc.export_writing, None)
        self.assertGreaterEqual(self.sc.export_busy_seen, 3)
        self.assertTrue(self.redact_calls())

    @unittest.skipUnless(os.path.isfile(T.REAL_REDACT), "redact_exports.py not present")
    def test_late_bytes_are_redacted_by_the_real_redactor(self):
        r = self.run_sup("--export", redact=T.REAL_REDACT)
        self.assertEqual(r.returncode, 1, r.stderr)
        with open(sf_file(self.base)) as f:
            text = f.read()
        self.assertIn("token=", text)
        self.assertNotIn(LATE, text)


class ExportWaitTimesOut(T.Base):
    """The export reply arrives but the spider never goes idle: the wait times out."""
    scenario_kw = {"active_polls": 2, "export_busy_polls": None}

    def test_timeout_then_unverified_idle_exits_7(self):
        r = self.run_sup("--export", "--idle-timeout", "1")
        self.assertEqual(r.returncode, 7, r.stderr)
        st = self.state()
        self.assertEqual(st["status"], "export-unredacted")
        self.assertNotEqual(st.get("redact"), "ok")
        self.assertIn("may still be writing", r.stderr)
        self.assertEqual(self.redact_calls(), [])


class SignalDuringUncertainExport(UnitBase):
    """A signal after the crawl finished, while the export may still be writing."""

    def test_signal_path_verifies_idle_before_the_gate(self):
        m, s, calls = self.m, self.s, []

        class Busy:
            def json(self, tool, args=None, busy_retry=True):
                calls.append(tool)
                return {"stateName": "SpiderActiveState", "databaseId": "db-1"}
        s.mcp = Busy()
        s.a.idle_timeout = 0.3
        s.crawl_requested = s.crawl_finished = s.export_started = True
        gated = []
        s.redact_gate = lambda paths: gated.append(paths) or "ok"
        s.signum = signal.SIGTERM
        with self.assertRaises(m.Abort) as cm:
            s.check_signal()
        self.assertEqual(cm.exception.code, 7)
        self.assertIn("may still be writing", str(cm.exception))
        self.assertIn("sf_crawl_progress", calls)
        self.assertEqual(gated, [])
        self.assertEqual(s.state.data["status"], "export-unredacted")

    def test_unknown_state_is_not_taken_as_idle(self):
        s = self.s

        class Odd:
            def json(self, tool, args=None, busy_retry=True):
                return {"stateName": "SpiderExportingState", "databaseId": "db-1"}
        s.mcp = Odd()
        s.a.idle_timeout = 0.3
        s.export_started = True
        self.assertFalse(s.export_quiet(0.3))


# ---------------------------------------------------------------- server text redaction

class ApiMessageRedacted(T.Base):
    scenario_kw = {"active_polls": 2, "api_message": "Checking https://site.example/?token=TOPSECRET"}

    def test_progress_message_urls_are_redacted_everywhere(self):
        r = self.run_sup()
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.out, "supervise.json")) as f:
            sj = f.read()
        with open(os.path.join(self.out, "progress.log")) as f:
            pl = f.read()
        for name, text in (("supervise.json", sj), ("progress.log", pl), ("stderr", r.stderr)):
            self.assertNotIn("TOPSECRET", text, name)
        self.assertIn("token=X", pl)


class ServerTextUnit(UnitBase):
    def test_free_text_urls_lose_query_values(self):
        m = self.m
        t = m.scrub_text("a https://site.example/p?token=ONE&x=2 and http://b.example/?k=TWO, end")
        self.assertNotIn("ONE", t)
        self.assertNotIn("TWO", t)
        self.assertIn("https://site.example/p?token=X&x=X", t)
        self.assertIn("http://b.example/?k=X", t)
        self.assertEqual(m.scrub_text("no url here"), "no url here")

    def test_error_text_from_the_server_is_redacted(self):
        e = self.m.McpError("sf_crawl", 4, "Tool error: cannot fetch https://site.example/?token=THREE")
        self.assertNotIn("THREE", str(e))
        self.assertIn("THREE", e.text)  # the raw text stays available for the busy check only

    def test_nested_values_are_redacted(self):
        obj = {"crawl_entry": {"crawlName": "https://site.example/?sig=FOUR", "url": "x"},
               "list": ["https://site.example/?a=FIVE"], "n": 3}
        out = json.dumps(self.m.scrub_obj(obj))
        self.assertNotIn("FOUR", out)
        self.assertNotIn("FIVE", out)
        self.assertIn('"n": 3', out)


# ---------------------------------------------------------------- effective MCP URL

class DryRunMcpUrlValidated(T.Base):
    def test_invalid_env_url_refused_in_dry_run(self):
        for u in ("https://remote.example/mcp", "http://192.0.2.1:11435/mcp", "http://127.0.0.1/mcp"):
            with self.subTest(url=u):
                r = subprocess.run(self.argv("--dry-run"), env=self.env(SF_MCP_URL=u),
                                   capture_output=True, text=True, timeout=60)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("SF_MCP_URL", r.stderr)

    def test_invalid_config_url_refused_in_dry_run(self):
        cfg = testcfg.write_config(testcfg.merged(screaming_frog={
            "base_dir": None, "project_name": "site-audit", "mcp_url": "https://remote.example/mcp"}))
        env = self.env(SITE_AUDIT_CONFIG=cfg)
        env.pop("SF_MCP_URL")
        r = subprocess.run(self.argv("--dry-run"), env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("mcp_url", r.stderr)

    def test_valid_loopback_url_still_accepted(self):
        r = subprocess.run(self.argv("--dry-run"), env=self.env(), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
