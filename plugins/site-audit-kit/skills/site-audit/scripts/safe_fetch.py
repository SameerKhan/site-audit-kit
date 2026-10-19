#!/usr/bin/env python3
"""safe_fetch: the audit's only HTTP client for URLs it does not fully trust.

Standard library only. Site-specific settings come from the Site Audit Kit config
(audit_config.py): allowed_hosts, owned_domains, forbidden_hosts,
forbid_subdomains_of_forbidden, probe_paths, cache_bust_query and run_root.

* GET only, http/https only, ports 80 and 443 only, no userinfo, no cookies,
  no auth headers, a normal browser User-Agent.
* Host allowlist (enumerated, never globbed). With no configuration it is EMPTY,
  so no host is allowed; the CLI's --allow-host and --external widen it for one call
  (the operator's deliberate choice). Forbidden hosts are always refused, except in the
  explicit ``probe`` mode, which allows only the configured probe paths of a
  forbidden host and never follows a redirect. ``allow_external=True`` (outbound
  link probes, an egress probe) accepts any host that is not an owned host, still
  with every IP check. Subdomains of a forbidden host are refused in every mode
  when ``forbid_subdomains`` is true (the default).
* Host names are normalised ONCE (lowercase, one trailing dot stripped) and must
  then be pure ASCII ``[a-z0-9-]`` labels joined by dots, or an IP literal.
  Anything else (soft hyphen, zero-width characters, full-width dots, NFKC
  look-alikes such as U+00AA, percent signs, zone ids) is refused before any
  policy check or DNS lookup, for the initial URL, every redirect and every
  allowlist entry: Python's idna codec would otherwise map such a name onto a
  real host after the policy compared the raw string. No IDNA support.
* IPv4 only by default: the default resolver asks for A records only and IPv6
  answers or literals are refused, because a network-specific NAT64 prefix can
  translate a "global" IPv6 address to a private IPv4 one and cannot be detected.
  ``allow_ipv6=True`` re-enables IPv6 with every IPv6 range check.
* DNS resolved ONCE per hop through a pluggable resolver. Every returned
  address is validated (loopback, RFC1918, link-local incl. metadata, CGNAT,
  0.0.0.0/8, multicast, reserved, unspecified, fc00::/7, fe80::/10,
  IPv4-mapped / NAT64 / 6to4 / Teredo IPv6, explicit metadata addresses); one
  bad record rejects the hop. The socket then connects to the vetted IP
  itself, while the Host header and TLS SNI/certificate check use the original
  hostname, so a rebinding resolver cannot swap the address after vetting.
  (A per-connection pinned connect gives the same guarantee as patching
  socket.getaddrinfo without touching a process-global function, which is unsafe
  with 16 concurrent threads. The URL is never rewritten to an IP, so SNI is
  intact.)
* Environment proxies are never consulted: http.client is used directly (no
  urllib opener, no ProxyHandler), and the proxy variables are additionally
  cleared from os.environ by ``SafeFetcher.__init__`` (recorded in
  ``scrubbed_proxy_vars``), the CLI and ``scrub_proxy_env()``. ~/.netrc is
  never read (http.client has no netrc support; no auth header is ever sent).
* Redirects followed manually, at most 5, each hop re-validated (scheme, port,
  host allowlist, forbidden-host rule, DNS + IP checks). The chain is recorded.
* Caps: 10 s connect, 30 s TOTAL wall deadline per fetch() call. ONE deadline
  covers DNS (the resolver runs in a worker thread and is abandoned when the
  deadline passes), permit waits, connect, the TLS handshake, headers, body,
  every redirect hop and any Retry-After wait and retry. A watchdog shuts the
  (TLS) socket down at the deadline, so a server trickling one byte per second
  is cut off. 5 MB body (Content-Length checked up front, streamed bytes
  counted, abort beyond the cap). Retry-After honoured on 429/503 up to
  ``retry_after_cap`` seconds and only if it fits in the remaining deadline (one
  retry by default; the wait happens with no permit held).
* ``Accept-Encoding: identity`` is sent; a body that arrives with any other
  Content-Encoding is an error (``unexpected_content_encoding``), never OK.
* Concurrency: global 16, per host 2, the permit held until the body is fully
  read or discarded (connection closed).
* A body failure after a 2xx header is an error, never OK.
* Limits may only be lowered: ``deadline`` must be > 0 and at most
  ``MAX_DEADLINE`` (60 s, the documented maximum for slow re-tests; the default
  is 30 s) and ``max_body`` > 0 and at most 5 MB, else ValueError (CLI exit 2).
* Every request (including refusals) is logged, when a log path is given, as one
  JSON line: method, URL
  with every query VALUE replaced by X (the whole query becomes X unless every
  part is a plain ``key=value``), fragment and userinfo dropped, final status,
  bytes, ms, error, and the redacted redirect chain. The log must resolve
  (realpath) under the configured run_root (default ``~/site-audit/``) and must
  not be a symlink; it is created with mode 600 (and chmod'ed to 600 if it
  already exists).
* KeyboardInterrupt and SystemExit propagate (permits are still released).

TEST HOOK (never set in production; the CLI does not expose it):
``SafeFetcher(..., _test_allow_loopback=True)`` additionally accepts exactly the
address 127.0.0.1 and any port, so unit tests can drive local http.server
fixtures with an injected resolver and an injected allowlist. Every other
check (all other private ranges, ::1, allowlist, scheme, caps) still applies.
With the default (False), 127.0.0.1 is refused like any other loopback.
``_test_allow_any_limits=True`` lifts the deadline and body-size ceilings.
``_test_allow_any_log_dir=True`` lifts the run_root log rule (the symlink
refusal still applies).

CLI:
    safe_fetch.py URL (--log PATH | --no-log) [--config PATH] [--allow-host H]...
                      [--only-hosts] [--external] [--probe] [--cache-compare] [--body]
                      [--deadline S] [--max-bytes N]
--log is required: without it (and without an explicit --no-log) the CLI exits 2
before any lookup. --deadline may be at most 60 and --max-bytes at most 5242880.
With no config no host is allowed; --allow-host and --external widen that, and
are the operator's deliberate choice.
Prints a JSON summary (no body unless --body). Exit 0 if ok, 1 if not, 2 usage
or configuration error.
"""

from __future__ import annotations

import argparse
import email.utils
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import http.client
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit, quote

# ----------------------------------------------------------------- constants

# Library default: no host is allowed. The CLI fills the allowlist from the config.
DEFAULT_ALLOWED_HOSTS = frozenset()

CONNECT_TIMEOUT = 10.0
WALL_DEADLINE = 30.0
MAX_BODY = 5 * 1024 * 1024
#: Ceiling for ``deadline``: the default is 30 s; slow re-tests may raise it to 60 s, no further.
MAX_DEADLINE = 60.0
MAX_REDIRECTS = 5
RETRY_AFTER_CAP = 30.0
MAX_RETRIES = 1
GLOBAL_CONCURRENCY = 16
PER_HOST_CONCURRENCY = 2
ALLOWED_PORTS = frozenset({80, 443})
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

#: Default log root when no ``log_root`` is passed (the config's default run_root).
LOG_ROOT = os.path.join(os.path.expanduser("~"), "site-audit")

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_PLAIN_QUERY_KEY_RE = re.compile(r"^[A-Za-z0-9_.~\-\[\]]+$")

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                  "http_proxy", "https_proxy", "all_proxy", "no_proxy")

CACHE_HEADERS = ("cf-cache-status", "x-flying-press-cache", "x-flyingpress-cache",
                 "x-cache", "x-cache-status", "age", "cache-control", "x-wp-cf-super-cache",
                 "x-wp-cf-super-cache-active", "x-wp-cf-super-cache-cache-control",
                 "x-litespeed-cache", "x-proxy-cache")

_METADATA_IPS = frozenset({
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("fd00:ec2::254"),
    ipaddress.ip_address("100.100.100.200"),
})

_DENY_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
    "100::/64", "2001::/32", "2001:db8::/32", "2002::/16", "fc00::/7",
    "fe80::/10", "fec0::/10", "ff00::/8",
))

_LOOPBACK_TEST_IP = ipaddress.ip_address("127.0.0.1")


class FetchRefused(Exception):
    """Policy refusal (raised before any connection for that hop)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# ----------------------------------------------------------------- helpers

def scrub_proxy_env(environ=None) -> List[str]:
    """Remove every proxy variable from the environment. Returns the names removed."""
    env = os.environ if environ is None else environ
    removed = [k for k in PROXY_ENV_VARS if k in env]
    for k in removed:
        env.pop(k, None)
    return removed


def redact_url(url: str) -> str:
    """Replace every query VALUE with X (plain keys kept), drop userinfo and fragment.

    Fails closed: unless every non-empty ``&`` part is ``key=value`` with a plain
    key (no ``%``, ``;``, ``=`` or other punctuation in the key), the whole query is
    replaced by ``X``. This covers bare ``?SECRET``, ``?token%3Dsecret`` and
    ``;``-separated forms.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    netloc = parts.netloc.rsplit("@", 1)[-1]
    query = parts.query
    if query:
        out = []
        plain = True
        for piece in query.split("&"):
            if piece == "":
                continue
            key, eq, _val = piece.partition("=")
            if not eq or not _PLAIN_QUERY_KEY_RE.match(key):
                plain = False
                break
            out.append(f"{key}=X")
        query = "&".join(out) if plain else "X"
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def cache_bust_url(url: str, query: str) -> str:
    """Append the cache-bypass ``key=value`` pair (replacing an existing value of that key)."""
    if not isinstance(query, str) or "=" not in query:
        raise ValueError("cache-bypass query must be one key=value pair")
    ck, _, cv = query.partition("=")
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != ck]
    pairs.append((ck, cv))
    query = "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def ip_refusal_reason(ip_text: str, allow_test_loopback: bool = False) -> Optional[str]:
    """None if the address is a public, routable unicast address; else a reason."""
    if not isinstance(ip_text, str) or "%" in ip_text:
        return "zone_id_not_allowed" if isinstance(ip_text, str) else "unparseable_address"
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return "unparseable_address"
    if allow_test_loopback and ip == _LOOPBACK_TEST_IP:
        return None
    if ip in _METADATA_IPS:
        return "cloud_metadata"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return "ipv4_mapped_ipv6"
    for net in _DENY_NETS:
        if ip.version == net.version and ip in net:
            return f"denied_range:{net}"
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified or not ip.is_global):
        return "non_global"
    return None


def default_resolver(host: str, port: int, family: int = socket.AF_INET) -> List[str]:
    """A records only by default (IPv4-only policy); AF_UNSPEC when IPv6 is allowed."""
    infos = socket.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM,
                               proto=socket.IPPROTO_TCP)
    seen: List[str] = []
    for _fam, _t, _p, _c, sockaddr in infos:
        addr = sockaddr[0]
        if addr not in seen:
            seen.append(addr)
    return seen


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        dt = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    return max(0.0, dt.timestamp() - time.time())


def normalize_host(h: str) -> str:
    """Normalise once and validate; raise FetchRefused("host_invalid") on anything odd.

    Returns a lowercase ASCII host name (one trailing dot stripped) made of
    ``[a-z0-9-]`` labels, or a canonical IP literal (brackets removed). The ASCII
    check runs BEFORE lowercasing, because str.lower() maps some non-ASCII
    characters (KELVIN SIGN) onto ASCII letters.
    """
    if not isinstance(h, str) or not h:
        raise FetchRefused("host_invalid", "empty host")
    if not h.isascii():
        raise FetchRefused("host_invalid", f"non-ASCII host {h!r}")
    h = h.lower()
    if h.startswith("[") and h.endswith("]"):
        inner = h[1:-1]
        if "%" in inner:
            raise FetchRefused("host_invalid", "IPv6 zone id")
        try:
            return str(ipaddress.IPv6Address(inner))
        except ValueError:
            raise FetchRefused("host_invalid", f"bad IPv6 literal {h!r}")
    if "%" in h:
        raise FetchRefused("host_invalid", f"percent sign or zone id in host {h!r}")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    if h.endswith("."):
        h = h[:-1]
    if not h or len(h) > 253:
        raise FetchRefused("host_invalid", "bad host length")
    labels = h.split(".")
    for lab in labels:
        if not _LABEL_RE.match(lab):
            raise FetchRefused("host_invalid", f"bad label {lab!r} in {h!r}")
    return h


def _is_sub(host: str, parents: Iterable[str]) -> bool:
    return any(host.endswith("." + p) for p in parents)


# ----------------------------------------------------------------- limiter

class ConcurrencyLimiter:
    """Global + per-host permits. Acquire per-host first, then global."""

    def __init__(self, global_limit: int = GLOBAL_CONCURRENCY,
                 per_host_limit: int = PER_HOST_CONCURRENCY):
        self.global_limit = global_limit
        self.per_host_limit = per_host_limit
        self._global = threading.BoundedSemaphore(global_limit)
        self._hosts: Dict[str, threading.BoundedSemaphore] = {}
        self._lock = threading.Lock()
        self.in_flight = 0
        self.max_in_flight = 0
        self.host_in_flight: Dict[str, int] = {}
        self.host_max_in_flight: Dict[str, int] = {}

    def _host_sem(self, host: str) -> threading.BoundedSemaphore:
        with self._lock:
            sem = self._hosts.get(host)
            if sem is None:
                sem = threading.BoundedSemaphore(self.per_host_limit)
                self._hosts[host] = sem
            return sem

    def acquire(self, host: str, timeout: Optional[float] = None) -> bool:
        """Take the host then the global permit. False if ``timeout`` passes first.

        A failure (timeout or exception, including KeyboardInterrupt) while
        waiting for the global permit returns the host permit.
        """
        hs = self._host_sem(host)
        t_end = None if timeout is None else time.monotonic() + max(0.0, timeout)

        def left() -> Optional[float]:
            return None if t_end is None else max(0.0, t_end - time.monotonic())

        if not hs.acquire(timeout=left()):
            return False
        done = False
        try:
            if not self._global.acquire(timeout=left()):
                return False
            done = True
        finally:
            if not done:
                hs.release()
        with self._lock:
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
            n = self.host_in_flight.get(host, 0) + 1
            self.host_in_flight[host] = n
            self.host_max_in_flight[host] = max(self.host_max_in_flight.get(host, 0), n)
        return True

    def release(self, host: str) -> None:
        with self._lock:
            self.in_flight -= 1
            self.host_in_flight[host] = self.host_in_flight.get(host, 1) - 1
        self._global.release()
        self._host_sem(host).release()


_DEFAULT_LIMITER = ConcurrencyLimiter()


# ----------------------------------------------------------------- results

@dataclass
class FetchResult:
    url: str
    final_url: Optional[str] = None
    status: Optional[int] = None
    reason: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    header_list: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    chain: List[dict] = field(default_factory=list)
    error: Optional[str] = None
    error_detail: Optional[str] = None
    elapsed_ms: int = 0
    timing: Dict[str, float] = field(default_factory=dict)
    pinned_ip: Optional[str] = None
    connections: int = 0
    resolver_calls: int = 0
    retries: int = 0

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None

    @property
    def bytes_read(self) -> int:
        return len(self.body)

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        for part in ctype.split(";")[1:]:
            k, _, v = part.strip().partition("=")
            if k.lower() == "charset" and v:
                charset = v.strip('"\' ')
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    def to_dict(self, include_body: bool = False) -> dict:
        d = {
            "ok": self.ok,
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "reason": self.reason,
            "headers": self.headers,
            "chain": self.chain,
            "error": self.error,
            "error_detail": self.error_detail,
            "bytes": self.bytes_read,
            "elapsed_ms": self.elapsed_ms,
            "timing": self.timing,
            "pinned_ip": self.pinned_ip,
            "connections": self.connections,
            "resolver_calls": self.resolver_calls,
            "retries": self.retries,
        }
        if include_body:
            d["body"] = self.text
        return d


class _Deadline:
    def __init__(self, seconds: float):
        self.start = time.monotonic()
        self.end = self.start + seconds

    def remaining(self) -> float:
        return self.end - time.monotonic()

    def expired(self) -> bool:
        return self.remaining() <= 0


class _Watchdog:
    """Shuts a socket down at the wall deadline, unblocking any read."""

    def __init__(self, deadline: _Deadline):
        self.deadline = deadline
        self.fired = False
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None

    def arm(self, sock: socket.socket) -> None:
        with self._lock:
            self._sock = sock
        rem = max(0.0, self.deadline.remaining())
        self._timer = threading.Timer(rem, self._fire)
        self._timer.daemon = True
        self._timer.start()

    def set_sock(self, sock) -> bool:
        """Point the watchdog at a new socket object (e.g. the SSLSocket).

        Returns False (and closes the socket) if the deadline already fired.
        """
        with self._lock:
            self._sock = sock
            fired = self.fired
        if fired:
            try:
                sock.close()
            except OSError:
                pass
            return False
        return True

    def _fire(self) -> None:
        with self._lock:
            self.fired = True
            s = self._sock
        if s is not None:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def disarm(self) -> None:
        if self._timer is not None:
            self._timer.cancel()


# ----------------------------------------------------------------- fetcher

class SafeFetcher:
    def __init__(self,
                 allowed_hosts: Optional[Iterable[str]] = None,
                 *,
                 allow_external: bool = False,
                 probe: bool = False,
                 forbidden_hosts: Iterable[str] = (),
                 forbid_subdomains: bool = True,
                 probe_paths: Optional[Dict[str, Iterable[str]]] = None,
                 owned_domains: Iterable[str] = (),
                 cache_bust_query: Optional[str] = None,
                 log_root: Optional[str] = None,
                 resolver: Optional[Callable[[str, int], Sequence[str]]] = None,
                 log_path: Optional[str] = None,
                 connect_timeout: float = CONNECT_TIMEOUT,
                 deadline: float = WALL_DEADLINE,
                 max_body: int = MAX_BODY,
                 max_redirects: int = MAX_REDIRECTS,
                 retry_after_cap: float = RETRY_AFTER_CAP,
                 max_retries: int = MAX_RETRIES,
                 limiter: Optional[ConcurrencyLimiter] = None,
                 user_agent: str = USER_AGENT,
                 ssl_context: Optional[ssl.SSLContext] = None,
                 allow_ipv6: bool = False,
                 _test_allow_loopback: bool = False,
                 _test_allow_any_log_dir: bool = False,
                 _test_allow_any_limits: bool = False):
        # Limits may only be lowered (deadline up to the documented 60 s re-test maximum).
        if not _test_allow_any_limits:
            if not (isinstance(deadline, (int, float)) and 0 < deadline <= MAX_DEADLINE):
                raise ValueError(f"deadline must be > 0 and at most {MAX_DEADLINE:g} s (got {deadline!r})")
            if not (isinstance(max_body, int) and 0 < max_body <= MAX_BODY):
                raise ValueError(f"max_body must be > 0 and at most {MAX_BODY} bytes (got {max_body!r})")
            if not (isinstance(connect_timeout, (int, float)) and 0 < connect_timeout <= CONNECT_TIMEOUT):
                raise ValueError(f"connect_timeout must be > 0 and at most {CONNECT_TIMEOUT:g} s")
        # Clear the proxy variables for library use too, not only the CLI.
        self.scrubbed_proxy_vars = scrub_proxy_env()
        self.forbid_subdomains = bool(forbid_subdomains)
        self.forbidden_hosts = self._norm_set(forbidden_hosts, "forbidden host")
        self.owned_domains = self._norm_set(owned_domains, "owned domain")
        pp: Dict[str, frozenset] = {}
        for h, paths in (probe_paths or {}).items():
            (n1,) = tuple(self._norm_set([h], "probe host"))
            if n1 not in self.forbidden_hosts:
                raise ValueError(f"probe host {n1} is not a forbidden host")
            if isinstance(paths, str):
                paths = [paths]
            for path in paths:
                if (not isinstance(path, str) or not path.startswith("/") or not path.isascii()
                        or any(c in path for c in "?# \r\n\t")):
                    raise ValueError(f"bad probe path {path!r}")
            pp[n1] = frozenset(paths)
        self.probe_paths = pp
        hosts = DEFAULT_ALLOWED_HOSTS if allowed_hosts is None else allowed_hosts
        if isinstance(hosts, str):
            hosts = [hosts]
        normed = set()
        for h in self._norm_set(hosts, "allowlist host"):
            if self._forbidden(h) or self._forbidden_sub(h):
                raise ValueError(f"{h} may not be allowlisted: it is a forbidden host"
                                 + (" or one of its subdomains" if self.forbid_subdomains else "")
                                 + " (use probe=True for a forbidden host's probe paths)")
            normed.add(h)
        self.allowed_hosts = frozenset(normed)
        self.cache_bust_query = cache_bust_query
        self.log_root = log_root
        self.allow_ipv6 = bool(allow_ipv6)
        self._test_allow_any_log_dir = bool(_test_allow_any_log_dir)
        self.log_path = self._validate_log_path(log_path) if log_path else None
        self.allow_external = allow_external
        self.probe = probe
        self.resolver = resolver or self._default_resolve
        self.connect_timeout = connect_timeout
        self.deadline = deadline
        self.max_body = max_body
        self.max_redirects = max_redirects
        self.retry_after_cap = retry_after_cap
        self.max_retries = max_retries
        self.limiter = limiter or _DEFAULT_LIMITER
        self.user_agent = user_agent
        self.ssl_context = ssl_context or ssl.create_default_context()
        self._test_allow_loopback = bool(_test_allow_loopback)
        self._log_lock = threading.Lock()

    @classmethod
    def from_config(cls, cfg: dict, **kw) -> "SafeFetcher":
        """Build a fetcher from a loaded Site Audit Kit config; keyword arguments win."""
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import audit_config  # noqa: E402 - sibling module
        opts = dict(
            allowed_hosts=cfg["allowed_hosts"],
            forbidden_hosts=cfg["forbidden_hosts"],
            forbid_subdomains=cfg["forbid_subdomains_of_forbidden"],
            probe_paths=cfg["probe_paths"],
            owned_domains=cfg["owned_domains"],
            cache_bust_query=cfg["cache_bust_query"],
            log_root=audit_config.run_root(cfg),
        )
        opts.update(kw)
        return cls(**opts)

    # ---- policy

    @staticmethod
    def _norm_set(hosts: Iterable[str], what: str) -> frozenset:
        if isinstance(hosts, str):
            hosts = [hosts]
        out = set()
        for h in hosts:
            try:
                out.add(normalize_host(h.strip() if isinstance(h, str) else h))
            except FetchRefused as e:
                raise ValueError(f"invalid {what} {h!r}: {e.detail}")
        return frozenset(out)

    def _forbidden(self, host: str) -> bool:
        return host in self.forbidden_hosts

    def _forbidden_sub(self, host: str) -> bool:
        return self.forbid_subdomains and _is_sub(host, self.forbidden_hosts)

    def _default_resolve(self, host: str, port: int) -> List[str]:
        return default_resolver(host, port,
                                socket.AF_UNSPEC if self.allow_ipv6 else socket.AF_INET)

    def _validate_log_path(self, path: str) -> str:
        """The log must resolve under the log root (unless the test flag) and not be a symlink."""
        if not isinstance(path, str) or not path:
            raise ValueError("log path must be a non-empty string")
        ap = os.path.abspath(os.path.expanduser(path))
        if os.path.islink(ap):
            raise ValueError(f"log path {ap} is a symlink")
        if not self._test_allow_any_log_dir:
            root = os.path.realpath(getattr(self, "log_root", None) or LOG_ROOT)
            real = os.path.realpath(ap)
            if not real.startswith(root + os.sep):
                raise ValueError(f"log path {ap} must resolve under {root}/ (got {real})")
        return ap

    def _check_url(self, url: str, *, is_redirect: bool) -> Tuple[str, str, int, str]:
        """Return (scheme, host, port, path_with_query) or raise FetchRefused."""
        if any(c in url for c in "\r\n\t\x00") or " " in url.strip():
            raise FetchRefused("malformed_url", "control character or whitespace")
        try:
            parts = urlsplit(url.strip())
        except ValueError as e:
            raise FetchRefused("malformed_url", str(e))
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise FetchRefused("scheme_not_allowed", scheme or "<none>")
        if "@" in parts.netloc or parts.username is not None or parts.password is not None:
            raise FetchRefused("userinfo_not_allowed")
        if not parts.netloc.isascii():
            # checked on the RAW netloc: urlsplit().hostname has already lower()ed it,
            # which maps e.g. KELVIN SIGN onto ASCII k
            raise FetchRefused("host_invalid", "non-ASCII host")
        raw_host = parts.netloc
        if raw_host.startswith("["):
            raw_host = raw_host[: raw_host.find("]") + 1] if "]" in raw_host else raw_host
        else:
            raw_host = raw_host.rsplit(":", 1)[0] if ":" in raw_host else raw_host
        if not raw_host:
            raise FetchRefused("malformed_url", "no host")
        host = normalize_host(raw_host)
        if ":" in host and not self.allow_ipv6:
            raise FetchRefused("address_not_allowed", f"{host} (ipv6 literal; IPv4-only mode)")
        try:
            port = parts.port
        except ValueError as e:
            raise FetchRefused("malformed_url", f"bad port: {e}")
        if port is None:
            port = 443 if scheme == "https" else 80
        if port not in ALLOWED_PORTS and not self._test_allow_loopback:
            raise FetchRefused("port_not_allowed", str(port))
        path = parts.path or "/"
        pq = path + (("?" + parts.query) if parts.query else "")

        if self._forbidden_sub(host):
            raise FetchRefused("host_forbidden", f"{host} (subdomain of a forbidden host)")
        if self._forbidden(host):
            if not self.probe:
                raise FetchRefused("host_forbidden", host)
            if is_redirect:
                raise FetchRefused("probe_redirect_not_followed")
            if parts.query or path not in self.probe_paths.get(host, ()):
                raise FetchRefused("probe_path_forbidden", path)
            return scheme, host, port, pq
        if self.probe:
            raise FetchRefused("probe_mode_other_host", host)

        if host in self.allowed_hosts:
            return scheme, host, port, pq
        if self.allow_external:
            owned = self.owned_domains | self.allowed_hosts
            if any(host == s or host.endswith("." + s) for s in owned):
                raise FetchRefused("host_not_allowed", f"{host} (owned host not on allowlist)")
            return scheme, host, port, pq
        raise FetchRefused("host_not_allowed", host)

    def _run_resolver(self, host: str, port: int, dl: _Deadline) -> List[str]:
        """Run the resolver in a worker thread, bounded by the remaining deadline.

        A resolver still running at the deadline is abandoned (daemon thread); its
        late answer is discarded. Any exception from the resolver is a refusal.
        """
        box: Dict[str, object] = {}

        def work() -> None:
            try:
                box["addrs"] = list(self.resolver(host, port))
            except BaseException as e:  # noqa: BLE001 - reported as dns_error below
                box["err"] = e

        rem = dl.remaining()
        if rem <= 0:
            raise FetchRefused("deadline_exceeded", "before DNS")
        t = threading.Thread(target=work, name="safe_fetch-dns", daemon=True)
        t.start()
        t.join(rem)
        if t.is_alive():
            raise FetchRefused("deadline_exceeded", f"DNS for {host} still running at deadline")
        if "err" in box:
            e = box["err"]
            raise FetchRefused("dns_error", f"{type(e).__name__}: {e}")
        addrs = box.get("addrs")
        if not isinstance(addrs, list):
            raise FetchRefused("dns_error", "resolver returned nothing")
        return addrs

    def _resolve_and_vet(self, host: str, port: int, result: FetchResult,
                         dl: Optional[_Deadline] = None) -> List[str]:
        dl = dl or _Deadline(self.deadline)
        # IP literal: vet it directly, no resolver call.
        try:
            ipaddress.ip_address(host)
            addrs = [host]
        except ValueError:
            result.resolver_calls += 1
            addrs = self._run_resolver(host, port, dl)
        if not addrs:
            raise FetchRefused("dns_error", "no addresses")
        vetted: List[str] = []
        for a in addrs:
            if not isinstance(a, str):
                raise FetchRefused("address_not_allowed", f"{a!r} (not a string)")
            reason = ip_refusal_reason(a, self._test_allow_loopback)
            if reason:
                raise FetchRefused("address_not_allowed", f"{a} ({reason})")
            ip = ipaddress.ip_address(a)
            if ip.version == 6 and not self.allow_ipv6:
                raise FetchRefused("address_not_allowed", f"{a} (ipv6 answer; IPv4-only mode)")
            c = str(ip)
            if c not in vetted:
                vetted.append(c)
        return vetted

    # ---- network

    def _open_socket(self, ip: str, port: int, timeout: float) -> socket.socket:
        """Connect to the vetted IP. Tests may override this to observe the pin."""
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((ip, port))
        except BaseException:
            sock.close()
            raise
        return sock

    def _one_hop(self, scheme: str, host: str, port: int, pq: str, addrs: List[str],
                 dl: _Deadline, result: FetchResult, want_body: bool) -> dict:
        """One GET. Holds the host + global permit until the body is read/discarded."""
        hop = {"status": None, "headers": [], "body": b"", "error": None, "detail": None,
               "ip": None}
        wd = _Watchdog(dl)
        sock = None
        conn = None
        resp = None
        acquired = False
        try:
            acquired = self.limiter.acquire(host, timeout=max(0.0, dl.remaining()))
            if not acquired:
                hop["error"] = "deadline_exceeded"
                hop["detail"] = f"{self.deadline:g}s wall deadline (waiting for a permit)"
                return hop
            t0 = time.monotonic()
            last_err: Optional[BaseException] = None
            for ip in addrs:
                rem = dl.remaining()
                if rem <= 0:
                    break
                try:
                    result.connections += 1
                    sock = self._open_socket(ip, port, min(self.connect_timeout, rem))
                    hop["ip"] = ip
                    break
                except OSError as e:
                    last_err = e
                    sock = None
            if sock is None:
                if dl.expired():
                    raise TimeoutError("deadline exceeded during connect")
                raise ConnectionError(f"connect failed: {last_err!r}")
            result.timing.setdefault("connect_ms", round((time.monotonic() - t0) * 1000, 1))
            wd.arm(sock)
            sock.settimeout(max(0.01, dl.remaining()))
            if scheme == "https":
                # wrap WITHOUT handshaking, point the watchdog at the SSLSocket (wrap
                # detaches the raw socket), then handshake under the watchdog.
                tls = self.ssl_context.wrap_socket(sock, server_hostname=host,
                                                   do_handshake_on_connect=False)
                sock = tls
                if not wd.set_sock(tls):
                    raise TimeoutError("wall deadline exceeded before TLS handshake")
                tls.settimeout(max(0.01, dl.remaining()))
                tls.do_handshake()
                if wd.fired:
                    raise TimeoutError("wall deadline exceeded during TLS handshake")
            conn = http.client.HTTPConnection(host, port, timeout=max(0.01, dl.remaining()))
            conn.sock = sock  # pinned: http.client never resolves or connects itself
            default_port = 443 if scheme == "https" else 80
            host_hdr = host if port == default_port else f"{host}:{port}"
            if ":" in host and not host.startswith("["):
                host_hdr = f"[{host}]" if port == default_port else f"[{host}]:{port}"
            conn.putrequest("GET", pq, skip_host=True, skip_accept_encoding=True)
            for k, v in (("Host", host_hdr), ("User-Agent", self.user_agent),
                         ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
                                    "*/*;q=0.8"),
                         ("Accept-Language", "en-US,en;q=0.9"),
                         ("Accept-Encoding", "identity"),
                         ("Connection", "close")):
                conn.putheader(k, v)
            conn.endheaders()
            resp = conn.getresponse()
            if wd.fired:
                raise TimeoutError("wall deadline exceeded during headers")
            result.timing.setdefault("headers_ms", round((time.monotonic() - dl.start) * 1000, 1))
            hop["status"] = resp.status
            hop["reason"] = resp.reason
            hop["headers"] = list(resp.getheaders())
            if not want_body or (resp.status in REDIRECT_CODES and resp.getheader("Location")):
                return hop  # body discarded: finally closes before releasing the permit
            cenc = (resp.getheader("Content-Encoding") or "").strip().lower()
            if cenc not in ("", "identity"):
                hop["error"] = "unexpected_content_encoding"
                hop["detail"] = f"Content-Encoding {cenc!r} (identity was requested)"
                return hop
            clen = resp.getheader("Content-Length")
            if clen is not None and clen.strip().isdigit() and int(clen) > self.max_body:
                hop["error"] = "body_too_large"
                hop["detail"] = f"Content-Length {clen} > {self.max_body}"
                return hop
            chunks: List[bytes] = []
            total = 0
            reader = getattr(resp, "read1", None) or resp.read
            while True:
                if dl.expired() or wd.fired:
                    raise TimeoutError("wall deadline exceeded during body")
                if resp.fp is not None:
                    try:
                        sock.settimeout(max(0.01, dl.remaining()))
                    except OSError:
                        pass
                chunk = reader(65536)
                if wd.fired:
                    raise TimeoutError("wall deadline exceeded during body")
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_body:
                    hop["error"] = "body_too_large"
                    hop["detail"] = f"more than {self.max_body} bytes"
                    return hop
                chunks.append(chunk)
            if clen is not None and clen.strip().isdigit() and total != int(clen):
                hop["error"] = "body_incomplete"
                hop["detail"] = f"{total} of {clen} bytes before EOF"
                return hop
            hop["body"] = b"".join(chunks)
            return hop
        except FetchRefused:
            raise
        except Exception as e:  # noqa: BLE001 - every failure becomes a result;
            # KeyboardInterrupt / SystemExit propagate (finally still releases)
            if wd.fired or dl.expired():
                hop["error"] = "deadline_exceeded"
                hop["detail"] = f"{self.deadline:g}s wall deadline ({type(e).__name__})"
            elif isinstance(e, ssl.SSLError):
                hop["error"] = "tls_error"
                hop["detail"] = str(e)
            elif isinstance(e, (socket.timeout, TimeoutError)):
                hop["error"] = "timeout"
                hop["detail"] = str(e)
            elif isinstance(e, http.client.IncompleteRead):
                hop["error"] = "body_incomplete"
                hop["detail"] = f"{len(e.partial)} bytes read, more expected"
            elif isinstance(e, (http.client.HTTPException, ConnectionError, OSError)):
                hop["error"] = "body_error" if hop["status"] is not None else "connection_error"
                hop["detail"] = f"{type(e).__name__}: {e}"
            else:
                hop["error"] = "internal_error"
                hop["detail"] = f"{type(e).__name__}: {e}"
            return hop
        finally:
            wd.disarm()
            for closer in (resp, conn, sock):
                if closer is not None:
                    try:
                        closer.close()
                    except Exception:  # noqa: BLE001
                        pass
            if acquired:
                self.limiter.release(host)

    # ---- public API

    def fetch(self, url: str, *, want_body: bool = True) -> FetchResult:
        result = FetchResult(url=url)
        t_start = time.monotonic()
        dl = _Deadline(self.deadline)  # ONE deadline for every hop, wait and retry
        attempt = 0
        try:
            while True:
                self._fetch_once(url, result, want_body, dl)
                if (self.max_retries > attempt and result.error is None
                        and result.status in (429, 503)):
                    wait = _parse_retry_after(result.headers.get("retry-after"))
                    if (wait is not None and wait <= self.retry_after_cap
                            and wait < dl.remaining()):
                        attempt += 1
                        result.retries = attempt
                        time.sleep(wait)  # no permit held while waiting
                        result.chain.append({"retry_after_wait_s": round(wait, 2)})
                        continue
                    if wait is not None:
                        result.chain.append({"retry_after_not_waited_s": round(wait, 2)})
                break
        finally:
            result.elapsed_ms = int((time.monotonic() - t_start) * 1000)
            self._log(result)
        return result

    def _fetch_once(self, url: str, result: FetchResult, want_body: bool,
                    dl: _Deadline) -> None:
        result.status = None
        result.error = None
        result.error_detail = None
        result.body = b""
        current = url
        redirects = 0
        is_redirect = False
        while True:
            try:
                scheme, host, port, pq = self._check_url(current, is_redirect=is_redirect)
                addrs = self._resolve_and_vet(host, port, result, dl)
            except FetchRefused as r:
                result.error = r.code
                result.error_detail = r.detail or None
                result.chain.append({"url": current, "refused": r.code})
                return
            if dl.expired():
                result.error = "deadline_exceeded"
                result.error_detail = f"{self.deadline:g}s wall deadline"
                return
            hop = self._one_hop(scheme, host, port, pq, addrs, dl, result, want_body)
            result.pinned_ip = hop.get("ip")
            status = hop["status"]
            hdrs = hop["headers"]
            hdict: Dict[str, str] = {}
            for k, v in hdrs:
                lk = k.lower()
                hdict[lk] = f"{hdict[lk]}, {v}" if lk in hdict else v
            entry = {"url": current, "status": status, "ip": hop.get("ip")}
            location = hdict.get("location")
            if status in REDIRECT_CODES and location:
                entry["location"] = location
            if hop["error"]:
                entry["error"] = hop["error"]
            result.chain.append(entry)
            result.final_url = current
            result.status = status
            result.reason = hop.get("reason")
            result.headers = hdict
            result.header_list = hdrs
            if hop["error"]:
                result.error = hop["error"]
                result.error_detail = hop["detail"]
                return
            if status in REDIRECT_CODES and location:
                if self.probe:
                    # probe mode: record status + Location, never request the target.
                    return
                if redirects >= self.max_redirects:
                    result.error = "too_many_redirects"
                    result.error_detail = f"more than {self.max_redirects}"
                    return
                redirects += 1
                current = urljoin(current, location.strip())
                is_redirect = True
                continue
            result.body = hop["body"]
            return

    def fetch_cache_pair(self, url: str) -> dict:
        """Fetch plain and with the configured cache-bypass query; compare cache headers.

        A page cache can serve copies weeks older than the origin, so something seen only in
        the plain fetch may already be fixed at the origin."""
        if not self.cache_bust_query:
            raise ValueError("no cache_bust_query configured")
        plain = self.fetch(url)
        busted = self.fetch(cache_bust_url(url, self.cache_bust_query))

        def cache_view(r: FetchResult) -> dict:
            return {h: r.headers[h] for h in CACHE_HEADERS if h in r.headers}

        def origin_fresh(r: FetchResult) -> bool:
            blob = " ".join(cache_view(r).values()).upper()
            return any(tok in blob for tok in ("MISS", "BYPASS", "DYNAMIC", "EXPIRED"))

        return {
            "plain": {**plain.to_dict(), "cache": cache_view(plain)},
            "busted": {**busted.to_dict(), "cache": cache_view(busted)},
            "origin_freshness_established": origin_fresh(plain) or origin_fresh(busted),
        }

    # ---- logging

    def _log(self, r: FetchResult) -> None:
        if not self.log_path:
            return
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "method": "GET",
            "url": redact_url(r.url),
            "final_url": redact_url(r.final_url) if r.final_url else None,
            "status": r.status,
            "bytes": r.bytes_read,
            "ms": r.elapsed_ms,
            "error": r.error,
            "chain": [
                {k: (redact_url(v) if k in ("url", "location") and isinstance(v, str) else v)
                 for k, v in hop.items()}
                for hop in r.chain
            ],
        }
        line = json.dumps(rec, separators=(",", ":")) + "\n"
        with self._log_lock:
            self._validate_log_path(self.log_path)  # parent swapped to a symlink since init?
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.log_path, flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)


def fetch(url: str, **kwargs) -> FetchResult:
    """Convenience: SafeFetcher(**kwargs).fetch(url)."""
    want_body = kwargs.pop("want_body", True)
    return SafeFetcher(**kwargs).fetch(url, want_body=want_body)


# ----------------------------------------------------------------- CLI

def main(argv: Optional[List[str]] = None) -> int:
    scrub_proxy_env()
    p = argparse.ArgumentParser(description="Policy-bound GET fetcher for site audits.")
    p.add_argument("url")
    p.add_argument("--config", help="config file (else $SITE_AUDIT_CONFIG, else "
                                    "~/.config/site-audit-kit/config.json)")
    lg = p.add_mutually_exclusive_group()
    lg.add_argument("--log", help="JSON-lines request log under run_root (created mode 600); "
                                  "required unless --no-log is given")
    lg.add_argument("--no-log", action="store_true",
                    help="explicitly run without a request log")
    p.add_argument("--allow-host", action="append", default=[],
                   help="add a host to the configured allowlist (repeatable)")
    p.add_argument("--only-hosts", action="store_true",
                   help="use only the --allow-host hosts, not the configured ones")
    p.add_argument("--external", action="store_true",
                   help="allow any public host that is not owned (outbound link checks)")
    p.add_argument("--probe", action="store_true",
                   help="only a forbidden host's configured probe paths, no redirects followed")
    p.add_argument("--cache-compare", action="store_true",
                   help="fetch plain and with cache_bust_query, compare cache headers")
    p.add_argument("--body", action="store_true", help="include the body text in the output")
    p.add_argument("--deadline", type=float, default=WALL_DEADLINE,
                   help=f"wall deadline per request in seconds (at most {MAX_DEADLINE:g})")
    p.add_argument("--max-bytes", type=int, default=MAX_BODY,
                   help=f"body cap in bytes (at most {MAX_BODY})")
    a = p.parse_args(argv)
    if not a.log and not a.no_log:
        print(json.dumps({"ok": False, "error": "usage_error",
                          "error_detail": "--log PATH is required (or pass --no-log explicitly)"}))
        return 2
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import audit_config  # noqa: E402 - sibling module
    try:
        cfg = audit_config.load_config(a.config)
        hosts = set() if a.only_hosts else set(cfg["allowed_hosts"])
        hosts.update(a.allow_host)
        f = SafeFetcher.from_config(cfg, allowed_hosts=hosts, allow_external=a.external,
                                    probe=a.probe, log_path=a.log, deadline=a.deadline,
                                    max_body=a.max_bytes)
        if a.cache_compare and not f.cache_bust_query:
            raise ValueError("--cache-compare needs cache_bust_query in the config")
    except (ValueError, audit_config.ConfigError) as e:
        print(json.dumps({"ok": False, "error": "config_error", "error_detail": str(e)}))
        return 2
    if a.cache_compare:
        out = f.fetch_cache_pair(a.url)
        print(json.dumps(out, indent=2))
        return 0 if out["plain"]["ok"] and out["busted"]["ok"] else 1
    r = f.fetch(a.url)
    print(json.dumps(r.to_dict(include_body=a.body), indent=2))
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
