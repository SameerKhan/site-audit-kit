"""Tests for safe_fetch.py. Local 127.0.0.1 fixtures only; no internet.

Run: python3 -m unittest discover -s skills/site-audit/scripts/tests/safe_fetch -v
"""

import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))

import safe_fetch as sf  # noqa: E402


class _State:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []
        self.in_flight = 0
        self.max_in_flight = 0
        self.counter = {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state = None  # set per server

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if "Content-Length" not in (headers or {}):
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):  # noqa: C901
        st = self.state
        with st.lock:
            st.requests.append({"path": self.path, "headers": dict(self.headers.items())})
        p = self.path.split("?", 1)[0]
        host = self.headers.get("Host", "")
        port = self.server.server_address[1]
        try:
            if p == "/ok":
                self._send(200, b"hello world", {"Content-Type": "text/html; charset=utf-8"})
            elif p == "/redir-allowed":
                self._send(302, headers={"Location": f"http://second.test:{port}/ok"})
            elif p.startswith("/chain/"):
                n = int(p.rsplit("/", 1)[1])
                if n == 0:
                    self._send(200, b"end of chain")
                else:
                    self._send(301, headers={"Location": f"/chain/{n - 1}"})
            elif p == "/redir-evil":
                self._send(302, headers={"Location": f"http://evil.test:{port}/ok"})
            elif p == "/redir-private":
                self._send(302, headers={"Location": f"http://private.test:{port}/ok"})
            elif p == "/redir-ftp":
                self._send(302, headers={"Location": "ftp://allowed.test/x"})
            elif p == "/redir-forbidden":
                self._send(302, headers={"Location": "https://legacy.example.org/"})
            elif p == "/big-cl":
                self.send_response(200)
                self.send_header("Content-Length", str(6 * 1024 * 1024))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"x" * (6 * 1024 * 1024))
            elif p == "/big-chunked":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                piece = b"y" * 65536
                for _ in range(100):  # 6.25 MB
                    self.wfile.write(b"%x\r\n" % len(piece) + piece + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            elif p == "/trickle":
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.flush()
                for _ in range(100):
                    self.wfile.write(b"a")
                    self.wfile.flush()
                    time.sleep(1.0)
            elif p == "/slow-headers":
                time.sleep(6)
                self._send(200, b"late")
            elif p == "/trickle-headers":
                line = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Pad: " + b"p" * 50
                for b in line:
                    self.wfile.write(bytes([b]))
                    self.wfile.flush()
                    time.sleep(0.25)
            elif p == "/short-body":
                self.send_response(200)
                self.send_header("Content-Length", "1000")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"z" * 10)
                self.wfile.flush()
                self.close_connection = True
            elif p == "/short-chunked":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"a\r\n0123456789\r\n64\r\nabc")
                self.wfile.flush()
                self.close_connection = True
            elif p == "/slow-body":
                with st.lock:
                    st.in_flight += 1
                    st.max_in_flight = max(st.max_in_flight, st.in_flight)
                try:
                    self.send_response(200)
                    self.send_header("Content-Length", "4")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.flush()
                    time.sleep(0.4)  # headers sent; permit must still be held
                    self.wfile.write(b"done")
                    self.wfile.flush()
                finally:
                    with st.lock:
                        st.in_flight -= 1
            elif p == "/retry":
                with st.lock:
                    n = st.counter.get("retry", 0)
                    st.counter["retry"] = n + 1
                if n == 0:
                    self._send(429, b"slow down", {"Retry-After": "1"})
                else:
                    self._send(200, b"after retry")
            elif p == "/retry-long":
                self._send(429, b"slow down", {"Retry-After": "3600"})
            elif p == "/echo-host":
                self._send(200, host.encode())
            elif p == "/retry-trickle":
                with st.lock:
                    n = st.counter.get("retry-trickle", 0)
                    st.counter["retry-trickle"] = n + 1
                if n == 0:
                    self._send(429, b"slow down", {"Retry-After": "1"})
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", "100")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.flush()
                    for _ in range(100):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(0.5)
            elif p == "/retry-after-2":
                self._send(429, b"slow down", {"Retry-After": "2"})
            elif p == "/redir-unicode-forbidden":
                self._send(302, headers={"Location": "http://legacy.example.org\u00ad/"})
            elif p == "/redir-ipv6":
                self._send(302, headers={"Location": "http://[2606:4700:4700::1111]/"})
            elif p == "/gzip":
                import gzip as _gz
                self._send(200, _gz.compress(b"<html>hi</html>"),
                           {"Content-Encoding": "gzip", "Content-Type": "text/html"})
            else:
                self._send(404, b"nope")
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


def start_server():
    state = _State()
    handler = type("H", (Handler,), {"state": state})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, state


class Resolver:
    """Maps test names to IPs; records calls."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, host, port):
        self.calls.append(host)
        v = self.table.get(host)
        if v is None:
            raise OSError(f"NXDOMAIN {host}")
        return v(len([c for c in self.calls if c == host])) if callable(v) else list(v)


HOSTS = {"allowed.test", "second.test", "private.test"}
FORBIDDEN = "legacy.example.org"
PROBE_PATHS = {FORBIDDEN: ["/", "/old-page/"]}
OWNED = ["example.com"]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.state = start_server()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "requests.jsonl")
        self.resolver = Resolver({
            "allowed.test": ["127.0.0.1"],
            "second.test": ["127.0.0.1"],
            "evil.test": ["127.0.0.1"],
            "private.test": ["10.0.0.5"],
        })

    def tearDown(self):
        self.tmp.cleanup()

    def fetcher(self, **kw):
        kw.setdefault("allowed_hosts", HOSTS)
        kw.setdefault("forbidden_hosts", [FORBIDDEN])
        kw.setdefault("probe_paths", PROBE_PATHS)
        kw.setdefault("owned_domains", OWNED)
        kw.setdefault("resolver", self.resolver)
        kw.setdefault("log_path", self.log)
        kw.setdefault("limiter", sf.ConcurrencyLimiter())
        kw.setdefault("_test_allow_loopback", True)
        kw.setdefault("_test_allow_any_log_dir", True)
        return sf.SafeFetcher(**kw)

    def url(self, path, host="allowed.test"):
        return f"http://{host}:{self.port}{path}"

    def log_lines(self):
        with open(self.log) as f:
            return [json.loads(x) for x in f if x.strip()]


class TestBasics(Base):
    def test_normal_200(self):
        r = self.fetcher().fetch(self.url("/ok"))
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, b"hello world")
        self.assertEqual(r.text, "hello world")
        self.assertEqual(r.pinned_ip, "127.0.0.1")
        self.assertEqual(len(r.chain), 1)
        req = self.state.requests[-1]
        self.assertEqual(req["headers"]["Host"], f"allowed.test:{self.port}")
        self.assertIn("Mozilla/5.0", req["headers"]["User-Agent"])
        self.assertNotIn("Cookie", req["headers"])
        self.assertNotIn("Authorization", req["headers"])

    def test_default_refuses_loopback(self):
        f = sf.SafeFetcher(HOSTS, resolver=self.resolver, log_path=self.log,
                           limiter=sf.ConcurrencyLimiter(), _test_allow_any_log_dir=True)
        r = f.fetch("http://allowed.test/ok")  # port 80, resolves to 127.0.0.1
        self.assertFalse(r.ok)
        self.assertEqual(r.error, "address_not_allowed")
        self.assertEqual(r.connections, 0)

    def test_default_refuses_nonstandard_port(self):
        f = sf.SafeFetcher(HOSTS, resolver=self.resolver, limiter=sf.ConcurrencyLimiter())
        r = f.fetch(self.url("/ok"))
        self.assertEqual(r.error, "port_not_allowed")
        self.assertEqual(self.resolver.calls, [])

    def test_disallowed_scheme(self):
        f = self.fetcher()
        for u in ("ftp://allowed.test/x", "file:///etc/passwd", "javascript:alert(1)",
                  "gopher://allowed.test/"):
            r = f.fetch(u)
            self.assertEqual(r.error, "scheme_not_allowed", u)
            self.assertEqual(r.connections, 0)

    def test_redirect_to_disallowed_scheme(self):
        r = self.fetcher().fetch(self.url("/redir-ftp"))
        self.assertEqual(r.error, "scheme_not_allowed")
        self.assertEqual(r.chain[0]["status"], 302)

    def test_userinfo_refused(self):
        r = self.fetcher().fetch(f"http://user:pw@allowed.test:{self.port}/ok")
        self.assertEqual(r.error, "userinfo_not_allowed")

    def test_host_not_allowed(self):
        r = self.fetcher().fetch(self.url("/ok", host="evil.test"))
        self.assertEqual(r.error, "host_not_allowed")
        self.assertEqual(self.resolver.calls, [])

    def test_ip_ranges(self):
        bad = ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
               "100.64.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255",
               "::1", "::", "fc00::1", "fd00:ec2::254", "fe80::1", "ff02::1",
               "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:8.8.8.8", "64:ff9b::a00:1",
               "2002:a00:1::", "198.18.0.1", "192.0.2.1"]
        for ip in bad:
            self.assertIsNotNone(sf.ip_refusal_reason(ip), ip)
        for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "104.18.1.1"):
            self.assertIsNone(sf.ip_refusal_reason(ip), ip)
        # the test flag admits exactly 127.0.0.1, nothing else
        self.assertIsNone(sf.ip_refusal_reason("127.0.0.1", True))
        for ip in ("127.0.0.2", "::1", "10.0.0.1", "169.254.169.254"):
            self.assertIsNotNone(sf.ip_refusal_reason(ip, True), ip)

    def test_forbidden_host_always_refused_by_default(self):
        r = self.fetcher().fetch("https://legacy.example.org/")
        self.assertEqual(r.error, "host_forbidden")
        self.assertEqual(r.connections, 0)
        self.assertEqual(self.resolver.calls, [])
        with self.assertRaises(ValueError):
            sf.SafeFetcher(["legacy.example.org"], forbidden_hosts=[FORBIDDEN])
        ext = self.fetcher(allow_external=True).fetch("https://legacy.example.org/")
        self.assertEqual(ext.error, "host_forbidden")

    def test_probe_paths_only(self):
        f = self.fetcher(probe=True)
        for u in ("https://legacy.example.org/wp-login.php",
                  "https://legacy.example.org/?x=1",
                  "https://legacy.example.org/old-page"):
            r = f.fetch(u)
            self.assertEqual(r.error, "probe_path_forbidden", u)
        self.assertEqual(self.resolver.calls, [])

    def test_redirect_into_forbidden_host_refused(self):
        r = self.fetcher().fetch(self.url("/redir-forbidden"))
        self.assertEqual(r.error, "host_forbidden")
        self.assertEqual(self.resolver.calls, ["allowed.test"])

    def test_external_mode_blocks_unlisted_owned_hosts(self):
        r = self.fetcher(allow_external=True).fetch("https://app.example.com/")
        self.assertEqual(r.error, "host_not_allowed")


class TestRedirects(Base):
    def test_redirect_to_allowed_host(self):
        r = self.fetcher().fetch(self.url("/redir-allowed"))
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.final_url, self.url("/ok", host="second.test"))
        self.assertEqual([h["status"] for h in r.chain], [302, 200])
        self.assertEqual(self.resolver.calls, ["allowed.test", "second.test"])
        self.assertEqual(self.state.requests[-1]["headers"]["Host"], f"second.test:{self.port}")

    def test_redirect_to_disallowed_host(self):
        r = self.fetcher().fetch(self.url("/redir-evil"))
        self.assertEqual(r.error, "host_not_allowed")
        self.assertEqual(r.chain[-1]["refused"], "host_not_allowed")
        self.assertNotIn("evil.test", self.resolver.calls)

    def test_redirect_to_private_ip(self):
        r = self.fetcher().fetch(self.url("/redir-private"))
        self.assertEqual(r.error, "address_not_allowed")
        self.assertIn("10.0.0.5", r.error_detail)
        self.assertEqual(r.connections, 1)  # only the first hop connected

    def test_five_redirects_ok(self):
        r = self.fetcher().fetch(self.url("/chain/5"))
        self.assertTrue(r.ok, r.error)
        self.assertEqual(len(r.chain), 6)
        self.assertEqual(r.body, b"end of chain")

    def test_more_than_five_redirects(self):
        r = self.fetcher().fetch(self.url("/chain/6"))
        self.assertEqual(r.error, "too_many_redirects")
        self.assertEqual(len(r.chain), 6)
        self.assertEqual(r.connections, 6)


class TestCaps(Base):
    def test_body_over_cap_content_length(self):
        r = self.fetcher().fetch(self.url("/big-cl"))
        self.assertFalse(r.ok)
        self.assertEqual(r.error, "body_too_large")
        self.assertEqual(r.body, b"")

    def test_body_over_cap_chunked(self):
        r = self.fetcher().fetch(self.url("/big-chunked"))
        self.assertFalse(r.ok)
        self.assertEqual(r.error, "body_too_large")

    def test_trickle_stops_at_wall_deadline(self):
        t0 = time.monotonic()
        r = self.fetcher(deadline=2.5).fetch(self.url("/trickle"))
        elapsed = time.monotonic() - t0
        self.assertFalse(r.ok)
        self.assertEqual(r.error, "deadline_exceeded")
        self.assertEqual(r.status, 200)  # body failure after a 2xx header is an error
        self.assertLess(elapsed, 4.0)
        self.assertGreaterEqual(elapsed, 2.3)

    def test_slow_headers(self):
        t0 = time.monotonic()
        r = self.fetcher(deadline=1.5).fetch(self.url("/slow-headers"))
        self.assertEqual(r.error, "deadline_exceeded")
        self.assertLess(time.monotonic() - t0, 3.0)

    def test_trickled_headers_hit_deadline(self):
        t0 = time.monotonic()
        r = self.fetcher(deadline=2.0).fetch(self.url("/trickle-headers"))
        self.assertEqual(r.error, "deadline_exceeded")
        self.assertLess(time.monotonic() - t0, 3.5)

    def test_short_body_after_200_is_error(self):
        r = self.fetcher().fetch(self.url("/short-body"))
        self.assertEqual(r.status, 200)
        self.assertFalse(r.ok)
        self.assertIn(r.error, ("body_incomplete", "body_error"))

    def test_truncated_chunked_after_200_is_error(self):
        r = self.fetcher().fetch(self.url("/short-chunked"))
        self.assertEqual(r.status, 200)
        self.assertFalse(r.ok)
        self.assertIn(r.error, ("body_incomplete", "body_error"))

    def test_retry_after_honoured(self):
        t0 = time.monotonic()
        r = self.fetcher().fetch(self.url("/retry"))
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.retries, 1)
        self.assertGreaterEqual(time.monotonic() - t0, 0.9)

    def test_retry_after_over_cap_not_waited(self):
        t0 = time.monotonic()
        r = self.fetcher().fetch(self.url("/retry-long"))
        self.assertEqual(r.status, 429)
        self.assertEqual(r.retries, 0)
        self.assertLess(time.monotonic() - t0, 2.0)


class TestRebinding(Base):
    def test_mixed_answer_rejected(self):
        """A public answer followed by 127.0.0.1 in the same reply: every record is vetted."""
        res = Resolver({"allowed.test": ["93.184.216.34", "127.0.0.1"]})
        f = sf.SafeFetcher(HOSTS, resolver=res, limiter=sf.ConcurrencyLimiter())
        opened = []
        f._open_socket = lambda ip, port, t: opened.append(ip)  # must never run
        r = f.fetch("http://allowed.test/ok")
        self.assertEqual(r.error, "address_not_allowed")
        self.assertEqual(opened, [])

    def test_rebinding_resolver_cannot_swap_pinned_ip(self):
        """First lookup public, later lookups 127.0.0.1: one lookup, connect to the pin."""
        res = Resolver({"allowed.test": lambda n: ["93.184.216.34"] if n == 1 else ["127.0.0.1"]})
        f = sf.SafeFetcher(HOSTS, resolver=res, limiter=sf.ConcurrencyLimiter())
        opened = []

        def fake_open(ip, port, timeout):
            opened.append((ip, port))
            raise ConnectionRefusedError("test: no real network")

        f._open_socket = fake_open
        r = f.fetch("http://allowed.test/ok")
        self.assertEqual(res.calls, ["allowed.test"])
        self.assertEqual(opened, [("93.184.216.34", 80)])
        self.assertEqual(r.error, "connection_error")

    def test_rebinding_live_fixture_uses_pin(self):
        """Against the local fixture: later answers point to a denied IP; the pin is used."""
        res = Resolver({"allowed.test": lambda n: ["127.0.0.1"] if n == 1 else ["10.9.9.9"]})
        r = self.fetcher(resolver=res).fetch(self.url("/ok"))
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.pinned_ip, "127.0.0.1")
        self.assertEqual(res.calls, ["allowed.test"])


class TestEnvironment(Base):
    def test_proxy_env_ignored(self):
        proxy, pstate = start_server()
        purl = f"http://127.0.0.1:{proxy.server_address[1]}"
        names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
                 "all_proxy")
        saved = {k: os.environ.get(k) for k in names + ("NO_PROXY", "no_proxy", "NETRC")}
        netrc = os.path.join(self.tmp.name, "netrc")
        with open(netrc, "w") as fh:
            fh.write("machine allowed.test login u password p\n")
        try:
            for k in names:
                os.environ[k] = purl
            os.environ["NO_PROXY"] = os.environ["no_proxy"] = ""
            os.environ["NETRC"] = netrc
            before = len(self.state.requests)
            r = self.fetcher().fetch(self.url("/ok"))
            self.assertTrue(r.ok, r.error)
            self.assertEqual(pstate.requests, [])
            self.assertEqual(len(self.state.requests), before + 1)
            self.assertNotIn("Authorization", self.state.requests[-1]["headers"])
            env = {k: "x" for k in sf.PROXY_ENV_VARS}
            self.assertEqual(sorted(sf.scrub_proxy_env(env)), sorted(sf.PROXY_ENV_VARS))
            for k in sf.PROXY_ENV_VARS:  # SafeFetcher() itself cleared the real environ
                self.assertNotIn(k, os.environ)
            self.assertEqual(env, {})
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            proxy.shutdown()
            proxy.server_close()


class TestLogging(Base):
    def test_query_values_redacted_and_mode_600(self):
        r = self.fetcher().fetch(self.url("/ok?token=s3cr3t&email=a@b.c&flag"))
        self.assertTrue(r.ok, r.error)
        self.fetcher().fetch("ftp://allowed.test/?k=v")  # refusals are logged too
        with open(self.log) as fh:
            raw = fh.read()
        self.assertNotIn("s3cr3t", raw)
        self.assertNotIn("a@b.c", raw)
        lines = self.log_lines()
        self.assertEqual(len(lines), 2)
        rec = lines[0]
        # a bare part ("flag") makes the whole query X (fails closed)
        self.assertEqual(rec["url"], self.url("/ok?X"))
        for key in ("method", "url", "status", "bytes", "ms", "error"):
            self.assertIn(key, rec)
        self.assertEqual(rec["method"], "GET")
        self.assertEqual(rec["status"], 200)
        self.assertEqual(rec["bytes"], 11)
        self.assertIsNone(rec["error"])
        self.assertEqual(lines[1]["error"], "scheme_not_allowed")
        self.assertEqual(stat.S_IMODE(os.stat(self.log).st_mode), 0o600)

    def test_existing_log_tightened_to_600(self):
        with open(self.log, "w"):
            pass
        os.chmod(self.log, 0o644)
        self.fetcher().fetch(self.url("/ok"))
        self.assertEqual(stat.S_IMODE(os.stat(self.log).st_mode), 0o600)

    def test_redirect_chain_redacted_in_log(self):
        self.fetcher().fetch(self.url("/chain/1?session=abc"))
        rec = self.log_lines()[0]
        self.assertNotIn("abc", json.dumps(rec))

    def test_redact_url_helper(self):
        self.assertEqual(sf.redact_url("https://u:p@h/x?a=1&b=&c#frag"), "https://h/x?X")
        self.assertEqual(sf.redact_url("https://u:p@h/x?a=1&b=#frag"), "https://h/x?a=X&b=X")
        self.assertIn("nocache=1", sf.cache_bust_url("https://h/p?x=1", "nocache=1"))
        self.assertEqual(sf.cache_bust_url("https://h/p?nocache=0&x=1", "nocache=1"),
                         "https://h/p?x=1&nocache=1")


class TestConcurrency(Base):
    def test_per_host_limit_two_held_through_body(self):
        f = self.fetcher()
        self.state.max_in_flight = 0
        results = []
        threads = [threading.Thread(target=lambda: results.append(f.fetch(self.url("/slow-body"))))
                   for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(len(results), 6)
        self.assertTrue(all(r.ok for r in results), [r.error for r in results])
        self.assertLessEqual(self.state.max_in_flight, 2)
        self.assertEqual(self.state.max_in_flight, 2)
        self.assertEqual(f.limiter.host_max_in_flight["allowed.test"], 2)

    def test_global_limit(self):
        lim = sf.ConcurrencyLimiter(global_limit=3, per_host_limit=2)
        f = self.fetcher(limiter=lim)
        self.state.max_in_flight = 0
        threads = []
        for host in ("allowed.test", "second.test") * 3:
            threads.append(threading.Thread(target=f.fetch, args=(self.url("/slow-body", host),)))
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertLessEqual(lim.max_in_flight, 3)
        self.assertLessEqual(self.state.max_in_flight, 3)
        self.assertEqual(lim.in_flight, 0)

    def test_defaults(self):
        self.assertEqual(sf.GLOBAL_CONCURRENCY, 16)
        self.assertEqual(sf.PER_HOST_CONCURRENCY, 2)
        self.assertEqual(sf.MAX_BODY, 5 * 1024 * 1024)
        self.assertEqual(sf.MAX_REDIRECTS, 5)
        self.assertEqual(sf.CONNECT_TIMEOUT, 10.0)
        self.assertEqual(sf.WALL_DEADLINE, 30.0)
        self.assertEqual(sf.DEFAULT_ALLOWED_HOSTS, frozenset())  # nothing until configured
        f = sf.SafeFetcher()
        self.assertFalse(f._test_allow_loopback)
        self.assertEqual(f.limiter.global_limit, 16)
        self.assertEqual(f.limiter.per_host_limit, 2)


if __name__ == "__main__":
    unittest.main()
