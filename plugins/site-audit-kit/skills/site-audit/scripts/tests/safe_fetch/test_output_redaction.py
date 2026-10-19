"""Regression tests: what safe_fetch prints (to_dict, CLI stdout, --cache-compare) carries no
query values and no credential headers, --cache-compare --body really includes the bodies,
and a bad log path is refused before any request is sent. Local 127.0.0.1 fixtures only.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))

import safe_fetch as sf  # noqa: E402
import testcfg  # noqa: E402

SECRET = "TOPSECRET123"


class _H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).seen.append(self.path)
        port = self.server.server_address[1]
        p = self.path.split("?", 1)[0]
        if p == "/redir":
            hdrs = {"Location": f"http://allowed.test:{port}/ok?token={SECRET}"}
            body = b""
            code = 302
        else:
            hdrs = {"Set-Cookie": f"session={SECRET}; HttpOnly",
                    "WWW-Authenticate": f'Bearer realm="{SECRET}"',
                    "Content-Location": f"/ok?sig={SECRET}",
                    "Content-Type": "text/html; charset=utf-8",
                    "X-Cache": "MISS"}
            body = b"<html>page body here</html>"
            code = 200
        self.send_response(code)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)


class OutputRedaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        _H.seen = []

    def tearDown(self):
        self.tmp.cleanup()

    def fetcher(self, **kw):
        return sf.SafeFetcher(["allowed.test"], resolver=lambda h, p: ["127.0.0.1"],
                              limiter=sf.ConcurrencyLimiter(), _test_allow_loopback=True,
                              _test_allow_any_log_dir=True,
                              log_path=os.path.join(self.tmp.name, "f.log"), **kw)

    def url(self, path):
        return f"http://allowed.test:{self.port}{path}"

    def test_to_dict_redacts_urls_chain_location_and_credential_headers(self):
        r = self.fetcher().fetch(self.url(f"/redir?key={SECRET}"))
        self.assertTrue(r.ok, r.error)
        for body in (False, True):
            d = r.to_dict(include_body=body)
            blob = json.dumps(d)
            self.assertNotIn(SECRET, blob, blob)
            self.assertTrue(d["url"].endswith("/redir?key=X"), d["url"])
            self.assertTrue(d["final_url"].endswith("/ok?token=X"), d["final_url"])
            self.assertEqual(d["chain"][0]["location"].split("?", 1)[1], "token=X")
            self.assertEqual(d["headers"]["set-cookie"], "REDACTED")
            self.assertEqual(d["headers"]["www-authenticate"], "REDACTED")
            self.assertEqual(d["headers"]["content-location"], "/ok?sig=X")
        # the in-memory result is untouched (callers may still need the real URL)
        self.assertIn(SECRET, r.final_url)

    def test_redirect_location_header_redacted_in_to_dict(self):
        r = self.fetcher(probe=False, max_redirects=0).fetch(self.url("/redir"))
        self.assertEqual(r.error, "too_many_redirects")
        d = r.to_dict()
        self.assertNotIn(SECRET, json.dumps(d))
        self.assertTrue(d["headers"]["location"].endswith("/ok?token=X"))

    def test_cache_pair_redacted_and_body_included_on_request(self):
        f = self.fetcher(cache_bust_query=f"nocache={SECRET}")
        out = f.fetch_cache_pair(self.url("/ok"))
        blob = json.dumps(out)
        self.assertNotIn(SECRET, blob, blob)
        self.assertNotIn("body", out["plain"])
        self.assertTrue(out["busted"]["url"].endswith("/ok?nocache=X"), out["busted"]["url"])
        out = f.fetch_cache_pair(self.url("/ok"), include_body=True)
        self.assertNotIn(SECRET, json.dumps(out))
        self.assertEqual(out["plain"]["body"], "<html>page body here</html>")
        self.assertEqual(out["busted"]["body"], "<html>page body here</html>")

    def _cli(self, args, results):
        """Run sf.main in-process with fetch() returning prepared results (no network)."""
        cfg = testcfg.write_config(testcfg.merged(cache_bust_query="nocache=1"))
        it = iter(results)
        saved = sf.SafeFetcher.fetch
        sf.SafeFetcher.fetch = lambda self, url, want_body=True: next(it)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                code = sf.main(["--config", cfg, "--no-log", *args])
        finally:
            sf.SafeFetcher.fetch = saved
        return code, buf.getvalue()

    def _result(self):
        return sf.FetchResult(
            url=f"https://www.example.com/p?token={SECRET}",
            final_url=f"https://www.example.com/q?token={SECRET}", status=200,
            headers={"set-cookie": f"s={SECRET}", "authorization": f"Bearer {SECRET}",
                     "proxy-authorization": SECRET, "cookie": SECRET,
                     "location": f"/q?token={SECRET}", "x-cache": "HIT"},
            body=b"<p>body</p>",
            chain=[{"url": f"https://www.example.com/p?token={SECRET}", "status": 301,
                    "location": f"/q?token={SECRET}"},
                   {"url": f"https://www.example.com/q?token={SECRET}", "status": 200}])

    def test_cli_stdout_redacted(self):
        code, out = self._cli(["--body", "https://www.example.com/p"], [self._result()])
        self.assertEqual(code, 0, out)
        self.assertNotIn(SECRET, out)
        self.assertEqual(json.loads(out)["body"], "<p>body</p>")

    def test_cli_cache_compare_redacted_and_body_included(self):
        code, out = self._cli(["--cache-compare", "--body", "https://www.example.com/p"],
                              [self._result(), self._result()])
        self.assertEqual(code, 0, out)
        self.assertNotIn(SECRET, out)
        d = json.loads(out)
        self.assertEqual(d["plain"]["body"], "<p>body</p>")
        self.assertEqual(d["busted"]["body"], "<p>body</p>")
        self.assertEqual(d["plain"]["cache"], {"x-cache": "HIT"})


class LogPathCheckedBeforeRequest(unittest.TestCase):
    """A log path that cannot be written is refused before anything is sent."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "root")
        os.mkdir(self.root)

    def tearDown(self):
        os.chmod(self.root, 0o700)
        self.tmp.cleanup()

    def test_missing_parent_refused_at_init(self):
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=os.path.join(self.root, "no-such-dir", "f.log"),
                           log_root=self.root)

    def test_parent_is_a_file_refused(self):
        p = os.path.join(self.root, "afile")
        open(p, "w").close()
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=os.path.join(p, "f.log"), log_root=self.root)

    def test_log_is_a_directory_refused(self):
        d = os.path.join(self.root, "d.log")
        os.mkdir(d)
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=d, log_root=self.root)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores modes")
    def test_unwritable_parent_refused(self):
        os.chmod(self.root, 0o500)
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=os.path.join(self.root, "f.log"), log_root=self.root)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root ignores modes")
    def test_unwritable_existing_log_refused(self):
        p = os.path.join(self.root, "f.log")
        open(p, "w").close()
        os.chmod(p, 0o400)
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=p, log_root=self.root)

    def test_no_request_sent_when_log_parent_missing(self):
        seen = []

        def resolver(h, p):
            seen.append(h)
            return ["127.0.0.1"]

        with self.assertRaises(ValueError):
            sf.fetch("http://allowed.test/", allowed_hosts=["allowed.test"], resolver=resolver,
                     _test_allow_loopback=True, log_root=self.root,
                     log_path=os.path.join(self.root, "missing", "f.log"))
        self.assertEqual(seen, [])
        self.assertFalse(os.path.exists(os.path.join(self.root, "missing")))

    def test_cli_missing_parent_is_config_error(self):
        home = os.path.join(self.tmp.name, "home")
        os.makedirs(os.path.join(home, "site-audit"))
        cfg = testcfg.write_config(testcfg.merged(run_root=os.path.join(home, "site-audit")))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = sf.main(["--config", cfg, "--log",
                            os.path.join(home, "site-audit", "nope", "f.log"),
                            "https://www.example.com/"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(buf.getvalue())["error"], "config_error")


if __name__ == "__main__":
    unittest.main()
