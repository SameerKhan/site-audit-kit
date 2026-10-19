"""Regression tests for safe_fetch.py: host normalisation, deadlines, IPv6, proxies, logging,
query secrets, encodings and TLS. Local 127.0.0.1 fixtures only; no internet.
The TLS tests generate a throwaway self-signed certificate with the openssl CLI and
skip if it is not installed.
"""

import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))

import safe_fetch as sf  # noqa: E402
from test_safe_fetch import FORBIDDEN, HOSTS, Base, Handler, Resolver, _State  # noqa: E402

FORBIDDEN_VARIANTS = [
    "legacy.example.org\u00ad",          # soft hyphen at the end
    "leg\u00adacy.example.org",          # soft hyphen inside
    "legacy\u200b.example.org",          # zero-width space
    "legacy.example\u200c.org",          # zero-width non-joiner
    "legacy\u3002example\u3002org",      # ideographic full stop
    "legacy\uff0eexample\uff0eorg",      # full-width full stop
    "leg\u00aacy.example.org",           # feminine ordinal (NFKC -> a)
    "legacy.example.\u00barg",           # masculine ordinal (NFKC -> o)
    "legacy.example.org\u2060",          # word joiner
]
OWNED_VARIANTS = [
    "app.example.com\u00ad",
    "app\u3002example.com",
    "www.example\uff0ecom",
    "\u212aey.example.com",              # Kelvin sign lower()s to ASCII k
]


class TestHostNormalisation(Base):
    """Non-ASCII host variants bypass the forbidden-host / owned rules."""

    def test_unicode_variants_refused_before_dns(self):
        for mode in ({}, {"allow_external": True}, {"probe": True}):
            f = self.fetcher(**mode)
            for h in FORBIDDEN_VARIANTS + OWNED_VARIANTS:
                r = f.fetch(f"https://{h}/old-page/")
                self.assertFalse(r.ok, (mode, h))
                self.assertIn(r.error, ("host_invalid", "host_forbidden", "malformed_url"),
                              (mode, h, r.error))
                self.assertEqual(r.connections, 0, (mode, h))
        self.assertEqual(self.resolver.calls, [])

    def test_trailing_dot_and_case_normalised(self):
        f = self.fetcher(allow_external=True)
        for h in ("legacy.example.org.", "LEGACY.Example.ORG", "Legacy.example.org."):
            self.assertEqual(f.fetch(f"https://{h}/").error, "host_forbidden", h)
        for h in ("legacy.example.org..", "legacy..example.org", ".legacy.example.org"):
            self.assertIn(f.fetch(f"https://{h}/").error, ("host_invalid", "malformed_url"), h)
        self.assertEqual(self.resolver.calls, [])

    def test_forbidden_subdomains_refused_even_in_probe_mode(self):
        f = self.fetcher(probe=True)
        for h in ("sub.legacy.example.org", "a.b.legacy.example.org"):
            r = f.fetch(f"https://{h}/")
            self.assertEqual(r.error, "host_forbidden", h)
        self.assertEqual(self.resolver.calls, [])

    def test_allow_host_values_validated(self):
        for h in ("leg\u00adacy.example.org", "evil\u3002test", "x y.test", "a..b",
                  "sub.legacy.example.org", "LEGACY.example.org.", "h%41.test"):
            with self.assertRaises(ValueError, msg=repr(h)):
                sf.SafeFetcher([h], forbidden_hosts=[FORBIDDEN], limiter=sf.ConcurrencyLimiter())

    def test_redirect_to_unicode_forbidden_host_refused(self):
        r = self.fetcher(allow_external=True).fetch(self.url("/redir-unicode-forbidden"))
        self.assertFalse(r.ok)
        self.assertIn(r.error, ("host_invalid", "malformed_url"))
        self.assertEqual(self.resolver.calls, ["allowed.test"])

    def test_cli_allow_host_unicode_is_config_error(self):
        out = _run_cli(["--no-log", "--allow-host", "leg\u00adacy.example.org",
                        "https://leg\u00adacy.example.org/"])
        self.assertEqual(out[0], 2, out)
        self.assertEqual(json.loads(out[1])["error"], "config_error")


class TestDeadline(Base):
    """The 30 s cap must cover DNS, permits, retries."""

    def test_slow_resolver_bounded_by_deadline(self):
        gate = threading.Event()

        def slow(host, port):
            gate.wait(5)
            return ["127.0.0.1"]

        t0 = time.monotonic()
        r = self.fetcher(resolver=slow, deadline=1.0).fetch(self.url("/ok"))
        elapsed = time.monotonic() - t0
        gate.set()
        self.assertEqual(r.error, "deadline_exceeded")
        self.assertEqual(r.connections, 0)
        self.assertLess(elapsed, 1.8)

    def test_permit_wait_bounded_by_deadline(self):
        lim = sf.ConcurrencyLimiter(global_limit=16, per_host_limit=1)
        self.assertTrue(lim.acquire("allowed.test"))
        try:
            t0 = time.monotonic()
            r = self.fetcher(limiter=lim, deadline=1.0).fetch(self.url("/ok"))
            elapsed = time.monotonic() - t0
        finally:
            lim.release("allowed.test")
        self.assertEqual(r.error, "deadline_exceeded")
        self.assertEqual(r.connections, 0)
        self.assertLess(elapsed, 1.8)
        self.assertEqual(lim.in_flight, 0)
        # the permit is usable again afterwards
        self.assertTrue(self.fetcher(limiter=lim).fetch(self.url("/ok")).ok)

    def test_global_permit_wait_bounded_and_host_permit_returned(self):
        lim = sf.ConcurrencyLimiter(global_limit=1, per_host_limit=2)
        self.assertTrue(lim.acquire("second.test"))
        try:
            r = self.fetcher(limiter=lim, deadline=0.8).fetch(self.url("/ok"))
        finally:
            lim.release("second.test")
        self.assertEqual(r.error, "deadline_exceeded")
        sem = lim._host_sem("allowed.test")
        self.assertTrue(sem.acquire(blocking=False))
        self.assertTrue(sem.acquire(blocking=False))  # both host permits were returned
        sem.release()
        sem.release()

    def test_retry_shares_the_single_deadline(self):
        t0 = time.monotonic()
        r = self.fetcher(deadline=1.6).fetch(self.url("/retry-trickle"))
        elapsed = time.monotonic() - t0
        self.assertEqual(r.retries, 1)
        self.assertEqual(r.error, "deadline_exceeded")
        self.assertLess(elapsed, 2.2)

    def test_retry_after_that_does_not_fit_is_not_waited(self):
        t0 = time.monotonic()
        r = self.fetcher(deadline=1.5).fetch(self.url("/retry-after-2"))
        self.assertEqual(r.status, 429)
        self.assertEqual(r.retries, 0)
        self.assertLess(time.monotonic() - t0, 0.9)


class TestIPv6(Base):
    """Network-specific NAT64 is undetectable, so IPv6 is off by default."""

    NAT64_PRIVATE = "2001:4860:1234:5678::c0a8:101"  # an operator /96 mapping 192.168.1.1

    def _no_connect(self, f):
        opened = []
        f._open_socket = lambda ip, port, t: opened.append(ip) or (_ for _ in ()).throw(
            ConnectionRefusedError("test: no network"))
        return opened

    def test_ipv6_answer_refused_by_default(self):
        for addrs in ([self.NAT64_PRIVATE], ["2606:4700:4700::1111"],
                      ["93.184.216.34", "2606:4700:4700::1111"]):
            res = Resolver({"allowed.test": addrs})
            f = sf.SafeFetcher(HOSTS, resolver=res, limiter=sf.ConcurrencyLimiter())
            opened = self._no_connect(f)
            r = f.fetch("http://allowed.test/ok")
            self.assertEqual(r.error, "address_not_allowed", addrs)
            self.assertIn("ipv6", r.error_detail)
            self.assertEqual(opened, [])

    def test_ipv6_literal_refused_by_default(self):
        f = self.fetcher(allow_external=True)
        opened = self._no_connect(f)
        for u in ("http://[2606:4700:4700::1111]/", "http://[::ffff:8.8.8.8]/"):
            r = f.fetch(u)
            self.assertFalse(r.ok, u)
            self.assertIn(r.error, ("address_not_allowed", "host_invalid"), u)
        self.assertEqual(opened, [])
        r = self.fetcher(allow_external=True).fetch(self.url("/redir-ipv6"))
        self.assertIn(r.error, ("address_not_allowed", "host_invalid"))

    def test_zone_ids_refused(self):
        self.assertIsNotNone(sf.ip_refusal_reason("2606:4700:4700::1111%lo0"))
        f = self.fetcher(allow_external=True, allow_ipv6=True)
        opened = self._no_connect(f)
        for u in ("http://[2606:4700:4700::1111%25lo0]/", "http://[fe80::1%lo0]/"):
            r = f.fetch(u)
            self.assertFalse(r.ok, u)
        res = Resolver({"allowed.test": ["2606:4700:4700::1111%lo0"]})
        f2 = sf.SafeFetcher(HOSTS, resolver=res, limiter=sf.ConcurrencyLimiter(),
                            allow_ipv6=True)
        o2 = self._no_connect(f2)
        self.assertEqual(f2.fetch("http://allowed.test/").error, "address_not_allowed")
        self.assertEqual(opened + o2, [])

    def test_allow_ipv6_keeps_range_checks(self):
        res = Resolver({"allowed.test": ["2606:4700:4700::1111"],
                        "second.test": ["64:ff9b::a00:1"], "private.test": ["fc00::1"]})
        f = sf.SafeFetcher(HOSTS, resolver=res, limiter=sf.ConcurrencyLimiter(),
                           allow_ipv6=True)
        opened = self._no_connect(f)
        self.assertEqual(f.fetch("http://allowed.test/").error, "connection_error")
        self.assertEqual(opened, ["2606:4700:4700::1111"])
        for h in ("second.test", "private.test"):
            self.assertEqual(f.fetch(f"http://{h}/").error, "address_not_allowed", h)

    def test_default_resolver_is_ipv4_only(self):
        import socket
        calls = []
        real = socket.getaddrinfo

        def spy(*a, **kw):
            calls.append((a, kw))
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

        socket.getaddrinfo = spy
        try:
            self.assertEqual(sf.default_resolver("example.test", 80), ["93.184.216.34"])
        finally:
            socket.getaddrinfo = real
        a, kw = calls[0]
        fam = kw.get("family", a[2] if len(a) > 2 else 0)
        self.assertEqual(fam, socket.AF_INET)


class TestProxyScrubLibrary(Base):
    """SafeFetcher itself clears the proxy variables."""

    def test_init_scrubs_environ(self):
        saved = {k: os.environ.get(k) for k in sf.PROXY_ENV_VARS}
        try:
            os.environ["HTTPS_PROXY"] = "http://127.0.0.1:9"
            os.environ["no_proxy"] = "*"
            f = self.fetcher()
            self.assertEqual(sorted(f.scrubbed_proxy_vars), ["HTTPS_PROXY", "no_proxy"])
            for k in sf.PROXY_ENV_VARS:
                self.assertNotIn(k, os.environ)
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class _InterruptingSem:
    def acquire(self, *a, **kw):
        raise KeyboardInterrupt

    def release(self):
        raise AssertionError("never acquired")


class TestInterrupts(Base):
    """Permit leak; KeyboardInterrupt swallowed / resolver errors."""

    def test_interrupt_between_acquires_returns_host_permit(self):
        lim = sf.ConcurrencyLimiter(global_limit=4, per_host_limit=1)
        real_global = lim._global
        lim._global = _InterruptingSem()
        with self.assertRaises(KeyboardInterrupt):
            self.fetcher(limiter=lim).fetch(self.url("/ok"))
        lim._global = real_global
        self.assertTrue(lim._host_sem("allowed.test").acquire(blocking=False))
        lim._host_sem("allowed.test").release()
        self.assertEqual(lim.in_flight, 0)

    def test_keyboard_interrupt_and_systemexit_propagate(self):
        for exc in (KeyboardInterrupt, SystemExit):
            lim = sf.ConcurrencyLimiter()
            f = self.fetcher(limiter=lim)

            def boom(ip, port, t, exc=exc):
                raise exc()

            f._open_socket = boom
            with self.assertRaises(exc):
                f.fetch(self.url("/ok"))
            self.assertEqual(lim.in_flight, 0)
            self.assertTrue(lim._host_sem("allowed.test").acquire(blocking=False))

    def test_resolver_exceptions_become_refusals(self):
        for exc in (ValueError("bad"), RuntimeError("boom"), TypeError("x"), OSError("nx")):
            def res(host, port, exc=exc):
                raise exc
            r = self.fetcher(resolver=res).fetch(self.url("/ok"))
            self.assertEqual(r.error, "dns_error", exc)
            self.assertEqual(r.connections, 0)


class TestLogPath(unittest.TestCase):
    """The log must live under the run root and never be a symlink."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.tmp.name, "root")
        os.mkdir(self.root)
        self.saved = sf.LOG_ROOT
        sf.LOG_ROOT = self.root

    def tearDown(self):
        sf.LOG_ROOT = self.saved
        self.tmp.cleanup()

    def test_default_root_is_home_site_audit(self):
        self.assertEqual(self.saved, os.path.join(os.path.expanduser("~"), "site-audit"))

    def test_log_root_argument_overrides_default(self):
        other = os.path.join(self.tmp.name, "other-root")
        os.mkdir(other)
        sf.SafeFetcher(log_path=os.path.join(other, "fetch.log"), log_root=other)
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=os.path.join(self.root, "fetch.log"), log_root=other)

    def test_log_outside_root_refused(self):
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=os.path.join(self.tmp.name, "fetch.log"))
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=os.path.join(self.root, "..", "fetch.log"))

    def test_log_inside_root_accepted(self):
        run = os.path.join(self.root, "run-1")
        os.mkdir(run)
        f = sf.SafeFetcher(log_path=os.path.join(run, "fetch.log"))
        f.fetch("ftp://x/")
        self.assertTrue(os.path.exists(os.path.join(run, "fetch.log")))

    def test_symlinked_log_refused(self):
        target = os.path.join(self.tmp.name, "elsewhere.log")
        open(target, "w").close()
        link = os.path.join(self.root, "fetch.log")
        os.symlink(target, link)
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=link)
        inner = os.path.join(self.root, "inner.log")
        open(inner, "w").close()
        link2 = os.path.join(self.root, "link2.log")
        os.symlink(inner, link2)  # even a symlink that stays inside the root
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=link2)

    def test_symlinked_parent_escaping_root_refused(self):
        out = os.path.join(self.tmp.name, "out")
        os.mkdir(out)
        os.symlink(out, os.path.join(self.root, "esc"))
        with self.assertRaises(ValueError):
            sf.SafeFetcher(log_path=os.path.join(self.root, "esc", "fetch.log"))

    def test_log_swapped_to_symlink_after_init_not_followed(self):
        log = os.path.join(self.root, "fetch.log")
        f = sf.SafeFetcher(log_path=log)
        target = os.path.join(self.tmp.name, "victim")
        open(target, "w").close()
        os.symlink(target, log)
        with self.assertRaises((OSError, ValueError)):
            f.fetch("ftp://x/")
        with open(target) as fh:
            self.assertEqual(fh.read(), "")

    def test_test_flag_allows_any_dir(self):
        p = os.path.join(self.tmp.name, "anywhere.log")
        sf.SafeFetcher(log_path=p, _test_allow_any_log_dir=True).fetch("ftp://x/")
        self.assertTrue(os.path.exists(p))

    def test_cli_log_outside_root_is_config_error(self):
        code, out, _ = _run_cli(["--log", os.path.join(self.tmp.name, "x.log"), "ftp://x/"],
                                env_extra={"HOME": self.tmp.name + "/nohome"})
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["error"], "config_error")


class LogRequired(unittest.TestCase):
    """The CLI needs --log PATH, or an explicit --no-log; neither is exit 2 before any lookup."""

    def test_cli_without_log_is_usage_error(self):
        with tempfile.TemporaryDirectory() as home:
            code, out, _ = _run_cli(["https://www.example.com/"], env_extra={"HOME": home})
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out)["error"], "usage_error")
            self.assertIn("--log", json.loads(out)["error_detail"])

    def test_cli_with_no_log_runs(self):
        with tempfile.TemporaryDirectory() as home:
            code, out, _ = _run_cli(["--no-log", "https://www.example.com/"], env_extra={"HOME": home})
            self.assertEqual(code, 1)  # no config: no host allowed, refused before DNS
            self.assertEqual(json.loads(out)["error"], "host_not_allowed")

    def test_cli_log_and_no_log_conflict(self):
        with tempfile.TemporaryDirectory() as home:
            code, _, _ = _run_cli(["--no-log", "--log", os.path.join(home, "x.log"),
                                   "https://www.example.com/"], env_extra={"HOME": home})
            self.assertEqual(code, 2)


class LimitsOnlyLower(unittest.TestCase):
    """--deadline and --max-bytes (and the constructor) may only lower the limits;
    the deadline ceiling is the documented 60 s re-test maximum."""

    def test_constructor_refuses_raised_limits(self):
        for kw in ({"deadline": 61.0}, {"deadline": 3600}, {"deadline": 0}, {"deadline": -1},
                   {"deadline": float("inf")}, {"deadline": float("nan")},
                   {"max_body": sf.MAX_BODY + 1}, {"max_body": 0}, {"max_body": 10 ** 12},
                   {"connect_timeout": 11.0}):
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                with self.assertRaises(ValueError):
                    sf.SafeFetcher(**kw)

    def test_constructor_accepts_lowered_and_ceiling(self):
        f = sf.SafeFetcher(deadline=60.0, max_body=sf.MAX_BODY)
        self.assertEqual((f.deadline, f.max_body), (60.0, sf.MAX_BODY))
        f = sf.SafeFetcher(deadline=5, max_body=1024)
        self.assertEqual((f.deadline, f.max_body), (5, 1024))

    def test_test_flag_lifts_the_ceilings(self):
        f = sf.SafeFetcher(deadline=120.0, max_body=sf.MAX_BODY * 2, _test_allow_any_limits=True)
        self.assertEqual(f.deadline, 120.0)

    def test_cli_refuses_raised_limits(self):
        with tempfile.TemporaryDirectory() as home:
            for args in (["--deadline", "61"], ["--deadline", "3600"], ["--max-bytes", "5242881"],
                         ["--max-bytes", "0"]):
                with self.subTest(args=args):
                    code, out, _ = _run_cli(["--no-log", *args, "https://www.example.com/"],
                                            env_extra={"HOME": home})
                    self.assertEqual(code, 2, out)
                    self.assertEqual(json.loads(out)["error"], "config_error")
            code, out, _ = _run_cli(["--no-log", "--deadline", "60", "--max-bytes", "1000",
                                     "https://www.example.com/"], env_extra={"HOME": home})
            self.assertEqual(code, 1, out)


class TestRedactUrl(unittest.TestCase):
    """Bare, encoded and ;-separated query secrets."""

    def test_bare_encoded_and_semicolon_forms(self):
        for q in ("?SECRET2", "?token%3DSECRET3", "?secret_value;k=1", "?a=1&SECRET",
                  "?k%5B%5D=1&SECRET", "?=SECRET", "?a=1;SECRET"):
            red = sf.redact_url("https://www.example.com/p" + q)
            self.assertNotIn("SECRET", red, q)
            self.assertNotIn("secret", red, q)

    def test_plain_pairs_keep_keys(self):
        self.assertEqual(sf.redact_url("https://h/x?a=1&b=&c_d=zz"), "https://h/x?a=X&b=X&c_d=X")
        self.assertEqual(sf.redact_url("https://h/x?SECRET"), "https://h/x?X")
        self.assertEqual(sf.redact_url("https://h/x?token%3Dsecret"), "https://h/x?X")

    def test_fragment_and_userinfo_redacted(self):
        red = sf.redact_url("https://u:pw@h/x?a=1#access_token=SECRET")
        self.assertNotIn("SECRET", red)
        self.assertNotIn("pw", red)


class TestContentEncoding(Base):
    """A compressed body we did not ask for is not returned as ok."""

    def test_gzip_body_is_error(self):
        r = self.fetcher().fetch(self.url("/gzip"))
        self.assertEqual(r.status, 200)
        self.assertFalse(r.ok)
        self.assertEqual(r.error, "unexpected_content_encoding")


# ------------------------------------------------------------------- TLS fixture

def _make_cert(d):
    if not shutil.which("openssl"):
        return None
    key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
    p = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=allowed.test",
                        "-addext", "subjectAltName=DNS:allowed.test"],
                       capture_output=True, timeout=60)
    return (key, crt) if p.returncode == 0 else None


class _TLSServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def finish_request(self, request, client_address):
        try:
            request.settimeout(10)
            ss = self.tls_ctx.wrap_socket(request, server_side=True)
        except (OSError, ssl.SSLError):
            return
        try:
            self.RequestHandlerClass(ss, client_address, self)
        finally:
            try:
                ss.close()
            except OSError:
                pass


class _SlowHandshakeCtx:
    """Client context whose handshake 'takes' `delay` seconds after the socket is wrapped."""

    def __init__(self, real, delay):
        self.real, self.delay = real, delay

    def wrap_socket(self, sock, server_hostname=None, do_handshake_on_connect=True, **kw):
        ss = self.real.wrap_socket(sock, server_hostname=server_hostname,
                                   do_handshake_on_connect=False)
        time.sleep(self.delay)
        if do_handshake_on_connect:
            ss.do_handshake()
        return ss


class TestTLS(Base):
    """SNI/cert/Host use the name; handshake under the watchdog."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cdir = tempfile.mkdtemp()
        cls.pair = _make_cert(cls.cdir)
        if cls.pair is None:
            return
        cls.tstate = _State()
        cls.tstate.sni = []
        h = type("TH", (Handler,), {"state": cls.tstate})
        cls.tsrv = _TLSServer(("127.0.0.1", 0), h)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cls.pair[1], cls.pair[0])
        sctx.sni_callback = lambda sobj, name, c: cls.tstate.sni.append(name) and None
        cls.tsrv.tls_ctx = sctx
        threading.Thread(target=cls.tsrv.serve_forever, daemon=True).start()
        cls.tport = cls.tsrv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "pair", None):
            cls.tsrv.shutdown()
            cls.tsrv.server_close()
        shutil.rmtree(cls.cdir, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        if self.pair is None:
            self.skipTest("openssl CLI not available")
        self.cctx = ssl.create_default_context(cafile=self.pair[1])

    def test_sni_cert_and_host_use_the_name_while_socket_uses_the_pin(self):
        r = self.fetcher(ssl_context=self.cctx).fetch(
            f"https://allowed.test:{self.tport}/echo-host")
        self.assertTrue(r.ok, (r.error, r.error_detail))
        self.assertEqual(r.pinned_ip, "127.0.0.1")
        self.assertEqual(r.body, f"allowed.test:{self.tport}".encode())
        self.assertIn("allowed.test", self.tstate.sni)

    def test_certificate_is_checked_against_the_hostname(self):
        r = self.fetcher(ssl_context=self.cctx).fetch(f"https://second.test:{self.tport}/ok")
        self.assertEqual(r.error, "tls_error")

    def test_deadline_passing_during_handshake_stops_header_trickle(self):
        t0 = time.monotonic()
        r = self.fetcher(ssl_context=_SlowHandshakeCtx(self.cctx, 1.5), deadline=1.0).fetch(
            f"https://allowed.test:{self.tport}/trickle-headers")
        elapsed = time.monotonic() - t0
        self.assertEqual(r.error, "deadline_exceeded")
        self.assertLess(elapsed, 3.0)


def _run_cli(args, env_extra=None):
    env = {k: v for k, v in os.environ.items() if k != "SITE_AUDIT_CONFIG"}
    env.update(env_extra or {})
    p = subprocess.run([sys.executable, "-I", "-B", os.path.join(HERE, "..", "..", "safe_fetch.py")]
                       + args, capture_output=True, text=True, timeout=60, env=env)
    return p.returncode, p.stdout, p.stderr


if __name__ == "__main__":
    unittest.main()
