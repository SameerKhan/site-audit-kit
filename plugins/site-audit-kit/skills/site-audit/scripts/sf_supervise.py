#!/usr/bin/env python3
"""Supervise one Screaming Frog MCP crawl of your own site from start to export.

Usage:
  sf_supervise.py --name RUNNAME --url START_URL --config /ABS/PATH.seospiderconfig
                  [--limit-hours 4] [--poll 60] [--health URL]... [--out DIR] [--export]
                  [--sf-base DIR] [--site-config PATH] [--dry-run]

Site settings come from the Site Audit Kit config (--site-config, else $SITE_AUDIT_CONFIG,
else ~/.config/site-audit-kit/config.json): crawl.hosts, crawl.http_paths, crawl.health_urls,
cache_bust_query, run_root, screaming_frog.base_dir and screaming_frog.project_name. With no
config, no host is allowed and nothing is crawled. (--config is the Screaming Frog profile.)

Steps:
  1. Preflight: the arguments are valid (below); sf_crawl_progress shows the spider idle
     (anything active, analysing, paused or unknown => exit 2); sf_list_crawls is recorded as the
     pre-start crawl list; <out>/supervise.json (mode 600) is written with owned=false.
  2. sf_crawl with crawl_url, config_path, crawl_name = RUNNAME, project_name = the configured
     screaming_frog.project_name.
     Ownership: at the first SpiderActiveState the running databaseId is recorded as OURS only if
     sf_list_crawls lists that id with crawlName == RUNNAME and the id was NOT in the pre-start
     list. Otherwise exit 1 (status "ownership-unproven"), nothing recorded, nothing paused.
     Once an id is recorded, any other running id is not ours (no same-name fallback).
     Start uncertain: if sf_crawl fails after the request may have been sent (timeout, dropped
     connection, HTTP error, unparsable reply; anything but a local refusal or a tool error),
     sf_crawl_progress + sf_list_crawls are checked for up to the start grace (600 s): a running
     crawl proven ours as above is adopted and supervised; any other running crawl, or no way to
     verify, => exit 8 (status "pause-not-verified", nothing paused); idle throughout and the list
     readable => exit 1 (status "failed", nothing is running).
  3. Poll sf_crawl_progress every --poll seconds, one JSON line per poll in <out>/progress.log
     (600): time, state, done, waiting, api message, analysis %, health results. Every round also
     fetches each --health URL (default: crawl.health_urls from the config) through
     safe_fetch.SafeFetcher with a --health-timeout WALL deadline (default 15 s) and at most one
     request in flight per URL; a URL fails on non-200, an error, or a response slower than
     --health-slow (8 s). Two consecutive failed rounds => pause, exit 5. Five consecutive
     unreachable-server polls => exit 3 (crawl state unknown, NOT paused). Once ours is recorded,
     a reply (active or idle) naming any other databaseId => exit 1, status "ownership-lost";
     nothing is paused, loaded or exported.
  4. Finished = our crawl was seen active, then the state is idle (or crawl-analysis complete)
     with databaseId == the recorded id AND post-crawl analysis is 100%. The --limit-hours hard
     limit (at most 4) => pause, partial, exit 6.
  5. TERM / INT / HUP => pause the crawl this process owns (owned in supervise.json AND the
     running databaseId equals the recorded id), verify through sf_crawl_progress that it is no
     longer active (retrying up to --pause-verify-seconds), exit 128+signal (143 TERM, 130 INT,
     129 HUP). A signal is checked after every step, including during export and redaction and
     before exit 0.
  6. Success: sf_list_crawls must list the RECORDED id with crawlName == RUNNAME (else exit 1; never
     another same-name crawl), then sf_load_crawl. With --export: Internal:All via
     sf_export_seo_element_urls to run-RUNNAME/internal_all.ndjson (path RELATIVE to the SF base
     dir); right after the call the SF folder is locked down (files 600, dirs 700, also on signal
     and error paths); the file is copied to <out> created 600 from the first byte; then
     redact_exports.py --fix-perms on both copies, then redact_exports.py --check on both copies.
     A missing redactor, a failing run or a --check that does not exit 0 => exit 7,
     status "export-unredacted". A failed or partial export (the call fails, its reply is lost or
     unparsable, the file is missing, the copy fails) still gets the lockdown and the redaction
     gate on whatever was written: clean => exit 1 (status "failed", redact "ok"), else exit 7.
     When the export outcome is uncertain (its reply lost or unparsable, or the wait for idle
     after it ended early), sf_crawl_progress is polled first, also on the signal and error
     paths and even when the crawl itself had finished, until the spider is positively idle
     (up to --idle-timeout; on a signal at most --pause-verify-seconds). Not verified => no
     redaction is reported: exit 7, status "export-unredacted", the export may still be writing.
     Any unexpected error (including an OSError writing supervise.json or progress.log) after
     sf_crawl runs the same verified pause as a signal: verified => exit 1, else exit 8.
     URLs written to supervise.json, progress.log, stderr and the dry-run plan have every query
     value replaced by X (safe_fetch.redact_url); only sf_crawl receives the real start URL.
     Text from the server (progress messages, error strings, crawl names, replies) gets the same
     treatment for every http(s) URL inside it before it is stored or printed.
  7. MCP tool ALLOWLIST (a subset of screaming_frog.allowed_tools): sf_crawl_progress, sf_crawl,
     sf_pause_crawl, sf_list_crawls, sf_load_crawl, sf_export_seo_element_urls. Any other name
     raises before a request is made.
  8. --dry-run validates the arguments, prints the plan (with the effective MCP URL: SF_MCP_URL,
     else screaming_frog.mcp_url) and exits 0 without any MCP call. The effective MCP URL is
     checked with audit_config.validate_mcp_url (loopback http with a port), in dry-run too.

Argument rules (exit 2 otherwise):
  --url     https on a crawl.hosts host, or plain http under a crawl.http_paths prefix (that
            path may hold no '.' or '..' segment, raw or percent-encoded, and no '//'); no
            userinfo, no port, no fragment, and no query except cache_bust_query exactly.
  --health  the same hosts and rules (test mode also allows http and a port).
  --out     under <run_root>/sf/ (not that folder itself), no symlink in any component below
            $HOME, and either absent, empty, or holding a supervise.json with the same run name.
  --sf-base exactly screaming_frog.base_dir; run-RUNNAME under it must not be a symlink.
  numbers   --limit-hours, --poll, --health-timeout, --health-slow and the hidden timing flags
            must be finite and > 0; --limit-hours <= 4; SF_TIMEOUT likewise.

Every MCP call goes through the sfcall.sh next to this file, with SITE_AUDIT_SUPERVISED=1 set
for that call only (sfcall.sh refuses state-changing tools without it). SF_MCP_URL and HOME are
passed through to it. Exports are redacted by the redact_exports.py next to this file.
TEST ONLY: SF_SUPERVISE_TESTING=1 allows any --sf-base, health URLs with http and a port
(fetched with a resolver that answers 127.0.0.1 only, safe_fetch's loopback test hook), and
the SF_SFCALL and SF_REDACT_SCRIPT overrides of those two script paths. Without it both
overrides are ignored.

Exit codes:
  0   done (crawl complete, loaded; with --export: exported, redacted, --check clean)
  1   failure (crawl did not start, ownership unproven or lost, recorded crawl id missing,
      export failed but what it wrote is redacted, unexpected error with our crawl verified stopped);
      after ownership-unproven or ownership-lost the spider's state is unknown: check the app
  2   usage or preflight refusal
  3   MCP server unreachable (at preflight, or 5 consecutive polls); crawl NOT paused
  5   site health failure, crawl verified paused
  6   hard limit, crawl verified paused, partial
  7   export-unredacted: redactor missing or failed, --check not clean, or the export may still
      be writing (spider not verified idle after it); copies are 600
  8   pause not verified (server gone, crawl not provably ours, the pause never landed, or an
      uncertain sf_crawl start that could not be reconciled);
      replaces 5, 6 and 128+n whenever the crawl could not be verified stopped
  128+n  stopped by signal n; our crawl verified paused (or not running)
Python 3 standard library only.
"""
import argparse
import datetime
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import unquote, urlsplit, urlunsplit

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLED_SFCALL = os.path.join(HERE, "sfcall.sh")
BUNDLED_REDACT = os.path.join(HERE, "redact_exports.py")
TEST_ENV = "SF_SUPERVISE_TESTING"
SUPERVISED_ENV = "SITE_AUDIT_SUPERVISED"


TESTS_DIR = os.path.join(HERE, "tests")


def _test_override(var):
    """A script override, honoured only under the test switch AND only for a file inside the
    kit's own tests folder, so the switch alone cannot swap in an arbitrary redactor."""
    if not testing():
        return None
    p = os.environ.get(var)
    if not p:
        return None
    real = os.path.realpath(p)
    if real in (os.path.realpath(BUNDLED_SFCALL), os.path.realpath(BUNDLED_REDACT)):
        return p
    if os.path.commonpath([real, os.path.realpath(TESTS_DIR)]) != os.path.realpath(TESTS_DIR):
        raise SystemExit(f"{var} must point inside {TESTS_DIR}")
    return p


def sfcall_path():
    """The bundled sfcall.sh; SF_SFCALL is honoured only under SF_SUPERVISE_TESTING=1."""
    return _test_override("SF_SFCALL") or BUNDLED_SFCALL


def redact_path():
    """The bundled redact_exports.py; SF_REDACT_SCRIPT is honoured only under
    SF_SUPERVISE_TESTING=1."""
    return _test_override("SF_REDACT_SCRIPT") or BUNDLED_REDACT
# The only Screaming Frog MCP tools this script may request (all in the default allowlist).
ALLOWED_TOOLS = frozenset({"sf_crawl_progress", "sf_crawl", "sf_pause_crawl", "sf_list_crawls",
                           "sf_load_crawl", "sf_export_seo_element_urls"})
_CFG = None


def config():
    """The Site Audit Kit config (loaded once; $SITE_AUDIT_CONFIG is honoured)."""
    global _CFG
    if _CFG is None:
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import audit_config  # noqa: E402 - sibling module
        _CFG = audit_config.load_config()
    return _CFG


def sf_root():
    """<run_root>/sf, expanded against the current $HOME."""
    import audit_config  # noqa: E402 - imported by config()
    return os.path.join(audit_config.run_root(config()), "sf")


def red(url):
    """url for logs, state and the plan: every query value replaced by X, no userinfo or fragment
    (safe_fetch.redact_url). Falls back to replacing the whole query when safe_fetch is unavailable."""
    try:
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import safe_fetch  # noqa: E402 - sibling module
        return safe_fetch.redact_url(url)
    except Exception:  # noqa: BLE001 - never let logging fail open
        try:
            parts = urlsplit(str(url))
        except ValueError:
            return "<unparseable-url>"
        return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path,
                           "X" if parts.query else "", ""))


URL_IN_TEXT_RE = re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")


def scrub_text(text):
    """Free text (server replies, error strings, crawl names) with every http(s) URL in it
    passed through red(): query values become X, no userinfo or fragment."""
    return URL_IN_TEXT_RE.sub(lambda mo: red(mo.group(0)), str(text))


def scrub_obj(obj):
    """A copy of obj (dicts, lists, strings) with scrub_text applied to every string."""
    if isinstance(obj, str):
        return scrub_text(obj)
    if isinstance(obj, dict):
        return {scrub_text(k) if isinstance(k, str) else k: scrub_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub_obj(v) for v in obj]
    return obj


def effective_mcp_url():
    """(url, source): SF_MCP_URL when set, else screaming_frog.mcp_url (what sfcall.sh uses).
    Both are validated with audit_config.validate_mcp_url (raises ConfigError when invalid)."""
    import audit_config  # noqa: E402 - imported by config()
    cfg_url = config()["screaming_frog"]["mcp_url"]
    if cfg_url:
        audit_config.validate_mcp_url(cfg_url)
    env = os.environ.get("SF_MCP_URL")
    if env:
        return audit_config.validate_mcp_url(env), "SF_MCP_URL"
    return audit_config.validate_mcp_url(cfg_url), "config screaming_frog.mcp_url"


def path_error(path):
    """None if an http path is free of dot segments and empty segments, else the reason. Checked
    raw and after each round of percent-decoding, so %2e%2e and %252e%252e are caught too."""
    seen = path
    for _ in range(5):
        if "//" in seen:
            return "the path has an empty segment ('//')"
        if any(seg in (".", "..") for seg in seen.split("/")):
            return "the path has a dot segment ('.' or '..')"
        nxt = unquote(seen)
        if nxt == seen:
            return None
        seen = nxt
    return "the path is percent-encoded too many times"
BUSY_RE = re.compile(r"spider busy|cannot be called currently|\bbusy\b", re.I)
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
MAX_LIMIT_HOURS = 4.0
UNREACHABLE_POLLS = 5
REDACT_TIMEOUT = 1800.0

EXPORT_UNSETTLED_MSG = ("the export may still be writing: the spider was not verified idle after "
                        "sf_export_seo_element_urls, so nothing was redacted or checked. Do not use or "
                        "share the export folder or the run folder; check the Screaming Frog app")

(EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_UNREACHABLE, EXIT_HEALTH, EXIT_LIMIT, EXIT_UNREDACTED,
 EXIT_PAUSE_UNVERIFIED) = 0, 1, 2, 3, 5, 6, 7, 8


def testing():
    return os.environ.get(TEST_ENV) == "1"


class Abort(Exception):
    """Stop the run with an exit code (state already recorded)."""
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


class McpError(Exception):
    def __init__(self, tool, rc, text):
        # str(e) reaches logs and state, so URLs in the server's text are redacted there; the raw
        # text stays in .text for the busy check only.
        super().__init__(scrub_text(f"{tool}: sfcall exit {rc}: {text[:400]}"))
        self.tool, self.rc, self.text = tool, rc, text


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def log(msg):
    print(f"[sf_supervise {datetime.datetime.now():%H:%M:%S}] {scrub_text(msg)}", file=sys.stderr, flush=True)


def write_private(path, text):
    """Atomic write, mode 600 from creation (mkstemp is 600)."""
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise


def copy_private(src, dst):
    """Copy src to dst: never follows a symlink at src, the temp file is 600 from its first byte,
    and os.replace swaps it in (a symlink at dst is replaced, never written through)."""
    fd_in = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    tmp = None
    try:
        if not stat.S_ISREG(os.fstat(fd_in).st_mode):
            raise OSError(f"not a regular file: {src}")
        d = os.path.dirname(dst)
        for _ in range(100):
            tmp = os.path.join(d, f".tmp-copy-{os.getpid()}-{os.urandom(4).hex()}")
            try:
                fd_out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                break
            except FileExistsError:
                continue
        else:
            raise OSError("cannot create a temp file")
        try:
            os.fchmod(fd_out, 0o600)
            while True:
                buf = os.read(fd_in, 1 << 20)
                if not buf:
                    break
                while buf:
                    n = os.write(fd_out, buf)
                    buf = buf[n:]
            os.fsync(fd_out)
        finally:
            os.close(fd_out)
        os.replace(tmp, dst)
        tmp = None
    finally:
        os.close(fd_in)
        if tmp:
            try: os.unlink(tmp)
            except OSError: pass


def lock_tree(path):
    """Directories 700, regular files 600, symlinks never followed. Best effort, never raises."""
    try:
        st = os.lstat(path)
    except OSError:
        return
    if stat.S_ISLNK(st.st_mode):
        return
    if stat.S_ISREG(st.st_mode):
        try: os.chmod(path, 0o600)
        except OSError: pass
        return
    if not stat.S_ISDIR(st.st_mode):
        return
    try: os.chmod(path, 0o700)
    except OSError: pass
    for root, dirs, files in os.walk(path, followlinks=False):
        for n in dirs + files:
            p = os.path.join(root, n)
            try:
                s = os.lstat(p)
                if stat.S_ISDIR(s.st_mode):
                    os.chmod(p, 0o700)
                elif stat.S_ISREG(s.st_mode):
                    os.chmod(p, 0o600)
            except OSError:
                pass


# ---------------------------------------------------------------- validation

def site_url_error(url, allow_test=False, cfg=None):
    """None if url is an allowed crawl/health URL for the configured site, else the reason."""
    cfg = cfg or config()
    site_hosts = frozenset(cfg["crawl"]["hosts"])
    bust = cfg["cache_bust_query"]
    if not isinstance(url, str) or not url or any(c in url for c in "\\ \t\r\n\x00") or \
            any(ord(c) < 32 or ord(c) == 127 for c in url):
        return "contains whitespace, a backslash or a control character"
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as e:
        return f"unparseable: {e}"
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return "scheme must be https (or http under a configured crawl.http_paths prefix)"
    if "@" in parts.netloc:
        return "userinfo is not allowed"
    if (parts.query and parts.query != bust) or parts.fragment:
        # URLs are written verbatim to supervise.json, progress.log and stderr, so only the
        # cache-bypass parameter is accepted; anything else could carry a secret into the logs.
        return (f"only the query ?{bust} is allowed (no other query or fragment)" if bust
                else "no query or fragment is allowed (no cache_bust_query configured)")
    host = (parts.hostname or "").lower()
    if not site_hosts:
        return "no crawl.hosts configured; nothing may be crawled"
    if host not in site_hosts:
        return f"host must be one of {', '.join(sorted(site_hosts))}"
    if port is not None or parts.netloc.lower() != host:
        if not (allow_test and port is not None and parts.netloc.lower() == f"{host}:{port}"):
            return "an explicit port is not allowed"
        return None  # test mode: any scheme/path on the allowed host with a port (loopback only)
    if scheme == "http":
        path = parts.path
        perr = path_error(path)
        if perr:
            return perr
        if not any(e["host"] == host and (path == e["path_prefix"] or path.startswith(e["path_prefix"] + "/"))
                   for e in cfg["crawl"]["http_paths"]):
            return "plain http is only allowed under a configured crawl.http_paths prefix"
    return None


def out_error(out, name):
    """None if --out is acceptable, else the reason. out is absolute and normalised."""
    home = os.path.abspath(os.path.expanduser("~"))
    root = sf_root()
    if not out.startswith(root + os.sep):
        return f"--out must be a folder under {root}/"
    cur = home
    parts = os.path.relpath(out, home).split(os.sep)
    for i, part in enumerate(parts):
        cur = os.path.join(cur, part)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            break
        except OSError as e:
            return f"cannot inspect {cur}: {e}"
        if stat.S_ISLNK(st.st_mode):
            return f"--out has a symlink component: {cur}"
        if not stat.S_ISDIR(st.st_mode):
            return f"--out component is not a directory: {cur}"
    if os.path.lexists(out):
        real_root = os.path.realpath(root)
        if not os.path.realpath(out).startswith(real_root + os.sep):
            return f"--out resolves outside {root}"
        entries = os.listdir(out)
        if entries:
            sj = os.path.join(out, "supervise.json")
            try:
                st = os.lstat(sj)
            except FileNotFoundError:
                return f"--out {out} exists with other content and no supervise.json; refusing to touch it"
            if not stat.S_ISREG(st.st_mode):
                return f"{sj} is not a regular file"
            try:
                with open(sj) as f:
                    prev = json.load(f)
            except (OSError, ValueError) as e:
                return f"{sj} is unreadable: {e}"
            if not isinstance(prev, dict) or prev.get("name") != name:
                return f"--out {out} belongs to another run ({prev.get('name') if isinstance(prev, dict) else '?'})"
            # A reused folder may hold only what this supervisor writes, so the redactor and
            # chmod passes never touch unrelated files.
            own = {"supervise.json", "progress.log", "fetch.log", "internal_all.ndjson"}
            extra = sorted(e for e in entries if e not in own and not e.startswith((".redact-", ".tmp-")))
            if extra:
                return f"--out {out} holds files this supervisor did not write ({', '.join(extra[:5])}); refusing to touch it"
    return None


def make_fetcher(timeout, testing=False, log_path=None):
    """(SafeFetcher, None) or (None, reason). Health checks fail closed when this fails."""
    try:
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import safe_fetch  # noqa: E402
    except Exception as e:  # missing or broken module
        return None, f"cannot import safe_fetch: {type(e).__name__}: {e}"
    cfg = config()
    kw = {"allowed_hosts": sorted(cfg["crawl"]["hosts"]), "deadline": timeout,
          "connect_timeout": min(10.0, timeout),
          "forbidden_hosts": cfg["forbidden_hosts"],
          "forbid_subdomains": cfg["forbid_subdomains_of_forbidden"],
          "log_root": os.path.dirname(sf_root())}
    if log_path:
        kw["log_path"] = log_path
    if testing:
        kw.update(resolver=lambda host, port: ["127.0.0.1"], _test_allow_loopback=True)
    try:
        return safe_fetch.SafeFetcher(**kw), None
    except Exception as e:
        return None, f"cannot build SafeFetcher: {type(e).__name__}: {e}"


# ---------------------------------------------------------------- state

class State:
    def __init__(self, path):
        self.path = path
        self.data = {}
        self.tolerant = False  # set during cleanup: a failed write is logged, never raised


    def load(self):
        try:
            with open(self.path) as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {}
        if not isinstance(self.data, dict):
            self.data = {}
        return self.data

    def save(self, **kw):
        self.data.update(kw)
        self.data["updated_at"] = now_iso()
        try:
            write_private(self.path, json.dumps(scrub_obj(self.data), indent=2) + "\n")
        except OSError as e:
            if not self.tolerant:
                raise
            log(f"LOUD: cannot write {self.path}: {e}")

    def event(self, kind, **kw):
        ev = {"time": now_iso(), "event": kind}
        ev.update(kw)
        self.data.setdefault("events", []).append(ev)
        self.save()


# ---------------------------------------------------------------- MCP via sfcall.sh

def sf_timeout():
    return float(os.environ.get("SF_TIMEOUT", "120"))


class Mcp:
    def __init__(self, busy_base=2.0, busy_budget=600.0, stop=None):
        self.busy_base = busy_base
        self.busy_budget = busy_budget
        self.stop = stop  # callable -> bool, lets busy waits end early on a signal

    def raw(self, tool, args=None):
        if tool not in ALLOWED_TOOLS:
            raise RuntimeError(f"refusing Screaming Frog tool {tool!r}: not on this script's allowlist")
        sfcall = sfcall_path()
        argv = [sfcall, tool, json.dumps(args or {})]
        try:
            # own session: a Ctrl-C to the terminal's process group must not kill an in-flight call
            p = subprocess.run(argv, capture_output=True, text=True, timeout=sf_timeout() + 30,
                               start_new_session=True, env=dict(os.environ, **{SUPERVISED_ENV: "1"}))
        except subprocess.TimeoutExpired:
            raise McpError(tool, 3, "sfcall timed out")
        except OSError as e:
            raise McpError(tool, 3, f"cannot run {sfcall}: {e}")
        if p.returncode != 0:
            raise McpError(tool, p.returncode, (p.stdout or "") + (p.stderr or ""))
        try:
            msg = json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise McpError(tool, 3, "unparseable sfcall output: " + p.stdout[:200])
        content = (msg.get("result") or {}).get("content") or []
        return "".join(c.get("text", "") for c in content if isinstance(c, dict))

    def call(self, tool, args=None, busy_retry=True):
        """Call a tool; retry 'Spider busy' with exponential backoff (capped at 30 s per wait)."""
        t0 = time.monotonic()
        delay = self.busy_base
        while True:
            try:
                return self.raw(tool, args)
            except McpError as e:
                if not (busy_retry and e.rc == 4 and BUSY_RE.search(e.text)):
                    raise
                if time.monotonic() - t0 + delay > self.busy_budget:
                    raise
                if self.stop and self.stop():
                    raise
                log(f"{tool}: spider busy, retrying in {delay:.2f}s")
                time.sleep(delay)
                delay = min(delay * 2, 30.0)

    def json(self, tool, args=None, busy_retry=True):
        text = self.call(tool, args, busy_retry)
        try:
            return json.loads(text)
        except ValueError:
            raise McpError(tool, 4, "non-JSON result: " + text[:300])


def state_name(prog):
    return str((prog or {}).get("stateName") or "")


def is_active(prog):
    """Crawling or running crawl analysis (the spider is not free)."""
    s = state_name(prog).lower()
    return "active" in s or ("analysis" in s and "complete" not in s)


def is_idle(prog):
    s = state_name(prog).lower()
    return "idle" in s or "crawlanalysiscomplete" in s.replace("-", "").replace("_", "")


def analysis_pct(prog):
    try:
        return float(((prog or {}).get("postCrawlAnalysisProgress") or {}).get("percentComplete"))
    except (TypeError, ValueError):
        return None


def summary(prog):
    """The fields logged per poll; every string from the server is URL-redacted (scrub_obj)."""
    cp = (prog or {}).get("crawlProgress") or {}
    ap = (prog or {}).get("apiProgress") or {}
    if not isinstance(cp, dict):
        cp = {}
    if not isinstance(ap, dict):
        ap = {}
    return scrub_obj({"state": state_name(prog) or None, "done": cp.get("completed"),
                      "waiting": cp.get("waiting"), "crawl_pct": cp.get("percentComplete"),
                      "api": ap.get("message"), "api_pct": ap.get("percentComplete"),
                      "analysis": analysis_pct(prog), "database_id": (prog or {}).get("databaseId")})


# ---------------------------------------------------------------- health

class HealthMonitor:
    """One round = one GET per URL through SafeFetcher, all in parallel, bounded by a wall deadline
    (timeout + 2 s). A URL whose previous request is still running is not requested again."""

    def __init__(self, urls, timeout, slow, fetcher, fetcher_error=None):
        self.urls = list(urls)
        self.timeout = timeout
        self.slow = slow
        self.fetcher = fetcher
        self.fetcher_error = fetcher_error or "safe_fetch unavailable"
        self.inflight = {}
        self.lock = threading.Lock()

    @staticmethod
    def _fail(url, err, secs=None):
        return {"url": red(url), "status": None, "seconds": secs, "ok": False, "error": err}

    def _one(self, url, box):
        t0 = time.monotonic()
        try:
            r = self.fetcher.fetch(url)
            secs = round(time.monotonic() - t0, 3)
            status = getattr(r, "status", None)
            err = getattr(r, "error", None)
            ok = bool(getattr(r, "ok", False)) and status == 200 and err is None and secs <= self.slow
            out = {"url": red(url), "status": status, "seconds": secs, "ok": ok,
                   "elapsed_ms": getattr(r, "elapsed_ms", None)}
            if err:
                out["error"] = str(err)[:160]
            elif status == 200 and secs > self.slow:
                out["error"] = f"slower than {self.slow}s"
        except Exception as e:
            out = self._fail(url, f"{type(e).__name__}: {str(e)[:120]}", round(time.monotonic() - t0, 3))
        box["r"] = out

    def round(self):
        if self.fetcher is None:
            res = [self._fail(u, self.fetcher_error) for u in self.urls]
            return res, False
        deadline = time.monotonic() + self.timeout + 2.0
        results = [None] * len(self.urls)
        started = []
        with self.lock:
            for i, u in enumerate(self.urls):
                prev = self.inflight.get(u)
                if prev is not None and prev.is_alive():
                    results[i] = self._fail(u, "previous request still in flight; not sent again")
                    continue
                box = {}
                t = threading.Thread(target=self._one, args=(u, box), daemon=True)
                self.inflight[u] = t
                t.start()
                started.append((i, u, t, box))
        for i, u, t, box in started:
            t.join(max(0.0, deadline - time.monotonic()))
            results[i] = box.get("r") or self._fail(u, f"no answer within the {self.timeout}s wall deadline",
                                                    round(self.timeout + 2.0, 3))
        return results, all(r["ok"] for r in results)


# ---------------------------------------------------------------- supervisor

class Supervisor:
    def __init__(self, a):
        self.a = a
        self.out = a.out
        self.state = State(os.path.join(self.out, "supervise.json"))
        self.progress_log = os.path.join(self.out, "progress.log")
        self.signum = None
        self.mcp = Mcp(busy_base=a.busy_base, busy_budget=a.busy_budget, stop=lambda: self.signum is not None)
        self.sf_export_rel = f"run-{a.name}"
        self.sf_dir = os.path.join(a.sf_base, self.sf_export_rel)
        self.crawl_requested = False   # sf_crawl was sent (it may have started a crawl)
        self.crawl_finished = False    # our crawl reached idle + analysis 100%
        self.export_started = False    # sf_export_seo_element_urls was sent
        self.export_settled = False    # ...and the spider was verified idle afterwards
        self.redact_result = None      # result of the last redaction gate
        self.health = None

    # -- signals
    def on_signal(self, signum, frame):
        if self.signum is None:
            self.signum = signum
            log(f"received {signal.Signals(signum).name}; will pause the crawl this run owns")

    def sleep(self, secs):
        end = time.monotonic() + secs
        while time.monotonic() < end:
            if self.signum is not None:
                return
            time.sleep(min(0.05, max(0.0, end - time.monotonic())))

    def check_signal(self):
        if self.signum is None:
            return
        name = signal.Signals(self.signum).name
        self.state.event("signal", signal=name)
        if self.export_started:
            lock_tree(self.sf_dir)
        if not self.crawl_requested:
            self.state.save(status="interrupted", signal=name)
            raise Abort(128 + self.signum, f"stopped by {name} before the crawl started")
        verified = True if self.crawl_finished else self.pause_owned(f"signal {name}")
        self.state.save(signal=name, paused_on_signal=verified)
        if self.export_started:
            if not self.export_quiet(min(self.a.idle_timeout, self.a.pause_verify_seconds)):
                lock_tree(self.sf_dir)
                self.redact_result = "export-may-be-writing"
                self.state.save(status="export-unredacted", redact=self.redact_result)
                raise Abort(EXIT_UNREDACTED, f"stopped by {name}; {EXPORT_UNSETTLED_MSG}")
            if self.redact_result != "ok":
                self.redact_result = self.redact_gate([self.sf_dir, self.out])
            if self.redact_result != "ok":
                self.state.save(status="export-unredacted", redact=self.redact_result)
                raise Abort(EXIT_UNREDACTED, f"stopped by {name}; exports NOT verified redacted "
                                             f"({self.redact_result})")
            self.state.save(redact="ok")
        if not verified:
            self.state.save(status="pause-not-verified", reason=f"signal {name}")
            raise Abort(EXIT_PAUSE_UNVERIFIED, f"stopped by {name}; the crawl was NOT verified paused. "
                                               "Check the Screaming Frog app now.")
        self.state.save(status="interrupted")
        raise Abort(128 + self.signum, f"stopped by {name}; our crawl is not running (verified)")

    # -- progress
    def progress(self):
        return self.mcp.json("sf_crawl_progress", busy_retry=False)

    def list_crawls(self):
        crawls = self.mcp.json("sf_list_crawls", {"limit": 50})
        if not isinstance(crawls, list):
            raise McpError("sf_list_crawls", 4, "result is not a list")
        return [c for c in crawls if isinstance(c, dict)]

    def append_progress(self, rec):
        fd = os.open(self.progress_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (json.dumps(scrub_obj(rec)) + "\n").encode())
        finally:
            os.close(fd)

    # -- ownership
    def claim(self, prog):
        """Record the running crawl as ours only when proven. Returns (ok, why)."""
        dbid = (prog or {}).get("databaseId")
        if not dbid:
            return False, "progress shows no databaseId"
        if dbid in (self.state.data.get("prestart_crawl_ids") or []):
            return False, f"running crawl {dbid} was already listed before our sf_crawl"
        try:
            crawls = self.list_crawls()
        except McpError as e:
            return False, f"sf_list_crawls failed: {e}"
        entry = next((c for c in crawls if c.get("instanceDirName") == dbid), None)
        if entry is None:
            return False, f"running crawl {dbid} is not in sf_list_crawls"
        if entry.get("crawlName") != self.a.name:
            return False, f"running crawl {dbid} is named {entry.get('crawlName')!r}, not {self.a.name!r}"
        self.state.save(owned=True, database_id=dbid, owned_at=now_iso())
        self.state.event("owned", database_id=dbid)
        return True, ""

    def claim_for_signal(self, reason):
        """A signal arrived after sf_crawl but before ownership was recorded: try to prove it now
        (up to 10 s waiting for the crawl to show as active). True only if ownership is proven."""
        end = time.monotonic() + min(10.0, self.a.pause_verify_seconds + 5.0)
        while time.monotonic() < end:
            try:
                prog = self.progress()
            except McpError as e:
                self.state.event("pause_failed", reason=reason, why=f"progress unavailable: {e}")
                return False
            if is_active(prog):
                ok, why = self.claim(prog)
                if not ok:
                    self.state.event("pause_skipped", reason=reason, why=why,
                                     database_id=prog.get("databaseId"))
                    log(f"LOUD: {why}; NOT pausing it")
                return ok
            time.sleep(0.2)
        self.state.event("pause_failed", reason=reason, why="crawl never showed as active; ownership unproven")
        return False

    def pause_owned(self, reason):
        """Pause our crawl and verify it is no longer active. True only when verified (or when no
        crawl of ours can be running). Never pauses a crawl whose id is not the recorded one."""
        st = State(self.state.path).load()
        if not (st.get("owned") and st.get("database_id")):
            if not self.crawl_requested:
                return True
            if not self.claim_for_signal(reason):
                return False
            st = State(self.state.path).load()
        mine = st.get("database_id")
        try:
            prog = self.progress()
        except McpError as e:
            self.state.event("pause_failed", reason=reason, why=f"progress unavailable: {e}")
            log(f"cannot read progress to pause: {e}")
            return False
        if not is_active(prog):
            self.state.event("pause_not_needed", reason=reason, state=state_name(prog))
            return True
        if prog.get("databaseId") != mine:
            self.state.event("pause_skipped", reason=reason, why="running crawl is not ours",
                             database_id=prog.get("databaseId"), ours=mine)
            log(f"LOUD: the running crawl {prog.get('databaseId')} is not ours ({mine}); NOT pausing it")
            return False
        deadline = time.monotonic() + self.a.pause_verify_seconds
        interval = min(2.0, max(0.05, self.a.poll))
        attempts = 0
        unreachable = 0
        while time.monotonic() < deadline:
            attempts += 1
            try:
                self.mcp.raw("sf_pause_crawl")
                unreachable = 0
            except McpError as e:
                log(f"sf_pause_crawl attempt {attempts} failed: {e}")
                unreachable = unreachable + 1 if e.rc == 3 else 0
                if unreachable >= 3:
                    break
            for _ in range(5):
                time.sleep(interval)
                try:
                    prog = self.progress()
                    unreachable = 0
                except McpError as e:
                    log(f"progress after pause failed: {e}")
                    unreachable = unreachable + 1 if e.rc == 3 else 0
                    if unreachable >= 3:
                        break
                    continue
                if not is_active(prog):
                    self.state.event("paused", reason=reason, attempts=attempts, state=state_name(prog))
                    log(f"crawl paused ({reason}); state now {state_name(prog)}")
                    return True
                if prog.get("databaseId") != mine:
                    self.state.event("pause_failed", reason=reason, why="a different crawl is now running")
                    return False
                if time.monotonic() >= deadline:
                    break
            if unreachable >= 3:
                break
        why = "server unreachable" if unreachable >= 3 else "still active after retries"
        self.state.event("pause_failed", reason=reason, attempts=attempts, why=why)
        log(f"LOUD: pause NOT verified ({why}) after {attempts} attempt(s); pause it in the app")
        return False

    # -- phases
    def preflight(self):
        prev = self.state.load()
        pid = prev.get("pid")
        if prev.get("status") in ("starting", "running") and pid and pid != os.getpid():
            try:
                os.kill(pid, 0)
                raise Abort(EXIT_USAGE, f"another supervisor (pid {pid}) is recorded as running in {self.state.path}")
            except ProcessLookupError:
                pass
            except PermissionError:
                raise Abort(EXIT_USAGE, f"pid {pid} recorded in {self.state.path} is alive")
        if self.a.export and os.path.islink(self.sf_dir):
            raise Abort(EXIT_USAGE, f"{self.sf_dir} is a symlink; refusing to export through it")
        fetcher, ferr = make_fetcher(self.a.health_timeout, testing(),
                                     None if testing() else os.path.join(self.out, "fetch.log"))
        if fetcher is None:
            raise Abort(EXIT_USAGE, f"health checks unavailable ({ferr}); not starting a crawl without them")
        self.health = HealthMonitor(self.a.health, self.a.health_timeout, self.a.health_slow, fetcher)
        try:
            prog = self.progress()
        except McpError as e:
            raise Abort(EXIT_UNREACHABLE if e.rc == 3 else EXIT_FAIL, f"preflight sf_crawl_progress failed: {e}")
        if not is_idle(prog) or is_active(prog):
            raise Abort(EXIT_USAGE, f"preflight: spider is not idle (state {state_name(prog) or 'unknown'}); "
                                    "another crawl may be running or paused. Not starting.")
        try:
            prestart = [c.get("instanceDirName") for c in self.list_crawls() if c.get("instanceDirName")]
        except McpError as e:
            raise Abort(EXIT_UNREACHABLE if e.rc == 3 else EXIT_FAIL, f"preflight sf_list_crawls failed: {e}")
        self.state.data = {}
        self.state.save(name=self.a.name, url=red(self.a.url), config=self.a.config, out=self.out,
                        sf_export_dir=self.sf_dir, pid=os.getpid(), owned=False, status="starting",
                        started_at=now_iso(), preflight_state=state_name(prog),
                        preflight_database_id=prog.get("databaseId"), prestart_crawl_ids=prestart,
                        limit_hours=self.a.limit_hours, poll=self.a.poll,
                        health=[red(u) for u in self.a.health])
        self.state.event("preflight_ok", state=state_name(prog))
        return prog

    def start(self):
        args = {"crawl_url": self.a.url, "config_path": self.a.config,
                "crawl_name": self.a.name, "project_name": config()["screaming_frog"]["project_name"]}
        self.crawl_requested = True
        try:
            text = self.mcp.call("sf_crawl", args, busy_retry=False)
        except McpError as e:
            if e.rc in (2, 4):
                # refused locally (2) or answered with a tool / JSON-RPC error (4): nothing started
                self.crawl_requested = False
                self.state.save(status="failed", error=f"sf_crawl failed: {self._scrub(str(e))}")
                raise Abort(EXIT_FAIL, f"sf_crawl failed: {self._scrub(str(e))}")
            # timeout, dropped connection, HTTP error or an unparsable reply: the request may have
            # been executed, so never assume that nothing started.
            self.reconcile_start(e)
            return
        # Not owned yet: ownership is proven at the first SpiderActiveState (claim()).
        self.state.save(status="running", crawl_requested=True, crawl_started_at=now_iso())
        self.state.event("crawl_requested", reply=self._scrub(text)[:300])
        log(f"crawl {self.a.name} requested: {self._scrub(text)[:200]}")

    def _scrub(self, text):
        """text with the start URL, and every other URL in it, in redacted form."""
        text = str(text).replace(self.a.url, red(self.a.url)) if self.a.url else str(text)
        return scrub_text(text)

    def reconcile_start(self, err):
        """sf_crawl failed after the request may have been sent. For up to --start-grace seconds:
        a running crawl that claim() proves ours is adopted and supervised; any other running crawl
        => exit 8 (not provably ours, not paused). Idle for the whole window AND sf_list_crawls
        readable => exit 1 (nothing of ours is running). Anything unverifiable => exit 8."""
        why = self._scrub(str(err))[:300]
        self.state.save(status="start-uncertain", crawl_requested=True, error=f"sf_crawl failed: {why}")
        self.state.event("start_uncertain", why=why)
        log(f"LOUD: sf_crawl failed after the request may have been sent ({why}); "
            f"checking for up to {self.a.start_grace}s whether a crawl started")
        end = time.monotonic() + self.a.start_grace
        last = "no reply"
        idle = False
        while True:
            self.check_signal()
            try:
                prog = self.progress()
            except McpError as e:
                prog, idle, last = None, False, f"progress unavailable: {str(e)[:200]}"
            if prog is not None and is_active(prog):
                ok, cwhy = self.claim(prog)
                if ok:
                    self.state.save(status="running", crawl_started_at=now_iso(), start_reconciled=True)
                    self.state.event("start_reconciled", database_id=prog.get("databaseId"))
                    log(f"crawl {self.a.name} found running as {prog.get('databaseId')}; supervising it")
                    return
                msg = (f"start uncertain: sf_crawl failed ({why}) and a crawl is running whose ownership "
                       f"cannot be proven ({cwhy}); NOT pausing it. Check the Screaming Frog app now.")
                self.state.save(status="pause-not-verified", reason=msg, paused=False)
                raise Abort(EXIT_PAUSE_UNVERIFIED, msg)
            if prog is not None:
                idle, last = is_idle(prog), f"state {state_name(prog) or 'unknown'}"
            if time.monotonic() >= end:
                break
            self.sleep(min(self.a.poll, 1.0))
        if idle:
            try:
                crawls = self.list_crawls()
            except McpError as e:
                crawls, last = None, f"sf_list_crawls failed: {str(e)[:200]}"
            if crawls is not None:
                pre = set(self.state.data.get("prestart_crawl_ids") or [])
                new = [c.get("instanceDirName") for c in crawls
                       if c.get("crawlName") == self.a.name and c.get("instanceDirName") not in pre]
                self.crawl_requested = False
                msg = (f"sf_crawl failed ({why}); the spider stayed idle for {self.a.start_grace}s, so "
                       "nothing is running" + (f" (new crawl(s) named {self.a.name} listed but not running: "
                                               f"{', '.join(map(str, new))})" if new else
                                               f" and no new crawl named {self.a.name} is listed"))
                self.state.save(status="failed", error=msg, new_crawl_ids=new)
                raise Abort(EXIT_FAIL, msg)
        msg = (f"start uncertain: sf_crawl failed ({why}) and it could not be verified that no crawl "
               f"started ({last}). Check the Screaming Frog app now.")
        self.state.save(status="pause-not-verified", reason=msg, paused=False)
        raise Abort(EXIT_PAUSE_UNVERIFIED, msg)

    def monitor(self):
        t0 = time.monotonic()
        deadline = t0 + self.a.limit_hours * 3600
        # an uncertain start reconciled by reconcile_start() was already seen active and claimed
        seen_active = bool(self.state.data.get("owned") and self.state.data.get("database_id"))
        fails = 0
        progress_errors = 0
        unreachable = 0
        while True:
            self.check_signal()
            prog, perr = None, None
            try:
                prog = self.progress()
                progress_errors = unreachable = 0
            except McpError as e:
                perr = str(e)[:300]
                progress_errors += 1
                unreachable = unreachable + 1 if e.rc == 3 else 0
            results, healthy = self.health.round()
            fails = 0 if healthy else fails + 1
            rec = {"time": now_iso()}
            rec.update(summary(prog))
            if perr: rec["progress_error"] = perr
            rec["health"] = results
            rec["health_ok"] = healthy
            rec["health_fail_rounds"] = fails
            self.append_progress(rec)
            self.check_signal()
            if unreachable >= UNREACHABLE_POLLS:
                msg = (f"MCP server unreachable for {unreachable} consecutive polls; crawl state unknown "
                       "and NOT paused. Check the Screaming Frog app.")
                self.state.save(status="mcp-unreachable", reason=msg, paused=False)
                raise Abort(EXIT_UNREACHABLE, msg)
            if prog is not None and is_active(prog) and state_name(prog).startswith("SpiderActiveState") \
                    and not seen_active:
                ok, why = self.claim(prog)
                if not ok:
                    msg = (f"ownership unproven: {why}. This run does NOT own the running crawl and will "
                           "not pause it; check the Screaming Frog app.")
                    self.state.save(status="ownership-unproven", owned=False, error=why)
                    raise Abort(EXIT_FAIL, msg)
                seen_active = True
                self.state.save(seen_active_at=now_iso())
                self.state.event("active", database_id=prog.get("databaseId"))
            mine = self.state.data.get("database_id")
            if seen_active and prog is not None and (is_active(prog) or is_idle(prog)) \
                    and prog.get("databaseId") != mine:
                # Once ours is recorded, any other id (active or idle) means the spider is no longer
                # on our crawl: its state says nothing about ours. Stop; never load or export.
                other = prog.get("databaseId")
                msg = (f"ownership lost: the spider now reports database id {other!r} "
                       f"({state_name(prog) or 'unknown'}), not ours ({mine}). Not pausing, loading or "
                       "exporting anything; check the Screaming Frog app.")
                self.state.event("ownership_lost", database_id=other, ours=mine, state=state_name(prog))
                self.state.save(status="ownership-lost", error=msg)
                raise Abort(EXIT_FAIL, msg)
            if fails >= 2:
                bad = [r for r in results if not r["ok"]]
                reason = "site health failed two consecutive rounds: " + "; ".join(
                    f"{r['url']} status={r['status']} {r['seconds']}s" for r in bad)
                log(reason)
                paused = self.pause_owned("health")
                if not paused:
                    self.state.save(status="pause-not-verified", reason=reason, paused=False)
                    raise Abort(EXIT_PAUSE_UNVERIFIED, reason + "; the crawl was NOT verified paused")
                self.state.save(status="paused-health", reason=reason, paused=True)
                raise Abort(EXIT_HEALTH, reason + "; crawl paused")
            if seen_active and prog is not None and not is_active(prog) and is_idle(prog) \
                    and prog.get("databaseId") == mine \
                    and analysis_pct(prog) is not None and analysis_pct(prog) >= 100:
                self.crawl_finished = True
                self.state.save(status="crawl-complete", finished_at=now_iso(), final=summary(prog))
                self.state.event("finished", **{k: v for k, v in summary(prog).items() if k != "database_id"})
                log(f"crawl finished: {summary(prog)}")
                return prog
            if not seen_active and time.monotonic() - t0 > self.a.start_grace:
                self.state.save(status="failed", error="crawl never became active")
                raise Abort(EXIT_FAIL, f"crawl never reached SpiderActiveState within {self.a.start_grace}s "
                                       "(check the config file and the app)")
            if progress_errors >= 5:
                log(f"LOUD: {progress_errors} consecutive progress failures; still supervising")
            if time.monotonic() >= deadline:
                reason = f"hard limit {self.a.limit_hours}h reached"
                log(reason)
                paused = self.pause_owned("hard limit")
                if not paused:
                    self.state.save(status="pause-not-verified", reason=reason, paused=False, partial=True)
                    raise Abort(EXIT_PAUSE_UNVERIFIED, reason + "; the crawl was NOT verified paused")
                self.state.save(status="partial", reason=reason, paused=True, partial=True)
                raise Abort(EXIT_LIMIT, reason + "; crawl paused and marked partial")
            self.sleep(self.a.poll)

    def wait_idle(self, what, timeout=None, strict=False):
        """Poll until the spider is not active (strict: positively idle, an unknown state does not
        count). Abort on timeout or 5 unreachable polls."""
        timeout = self.a.idle_timeout if timeout is None else timeout
        end = time.monotonic() + timeout
        unreachable = 0
        while True:
            self.check_signal()
            try:
                prog = self.progress()
                unreachable = 0
                if not is_active(prog) and (is_idle(prog) or not strict):
                    return prog
            except McpError as e:
                unreachable = unreachable + 1 if e.rc == 3 else 0
                log(f"progress while waiting for idle ({what}): {e}")
                if unreachable >= UNREACHABLE_POLLS:
                    self.state.save(status="mcp-unreachable", reason=f"unreachable while waiting after {what}")
                    raise Abort(EXIT_UNREACHABLE, f"MCP server unreachable while waiting for idle ({what})")
            if time.monotonic() >= end:
                raise Abort(EXIT_FAIL, f"spider not idle {timeout}s after {what}")
            self.sleep(min(self.a.poll, 5.0))

    def export_quiet(self, timeout):
        """True when the export is known to have stopped writing: wait_idle("export") returned,
        or sf_crawl_progress shows the spider positively idle within timeout seconds. Never
        checks for a signal (it runs inside the signal and error cleanup)."""
        if self.export_settled:
            return True
        end = time.monotonic() + timeout
        last = "no reply"
        while True:
            try:
                prog = self.progress()
                if is_idle(prog) and not is_active(prog):
                    self.export_settled = True
                    self.state.event("export_idle_verified", state=state_name(prog))
                    return True
                last = f"state {state_name(prog) or 'unknown'}"
            except McpError as e:
                last = f"progress unavailable: {str(e)[:200]}"
            except Exception as e:  # noqa: BLE001 - cleanup path: unverified, never raised
                last = f"{type(e).__name__}: {str(e)[:200]}"
            if time.monotonic() >= end:
                break
            time.sleep(min(max(self.a.poll, 0.05), 1.0))
        self.state.event("export_idle_unverified", why=last, seconds=timeout)
        log(f"LOUD: the spider was not verified idle {timeout}s after the export ({last})")
        return False

    def find_crawl_id(self):
        mine = self.state.data.get("database_id")
        if not mine:
            raise Abort(EXIT_FAIL, "no owned crawl id recorded; refusing to pick a crawl by name")
        crawls = self.list_crawls()
        entry = next((c for c in crawls if c.get("instanceDirName") == mine), None)
        if entry is None:
            raise Abort(EXIT_FAIL, f"our crawl {mine} is not in sf_list_crawls; refusing to fall back to "
                                   f"another crawl named {self.a.name}")
        if entry.get("crawlName") != self.a.name:
            raise Abort(EXIT_FAIL, f"crawl {mine} is listed as {entry.get('crawlName')!r}, not {self.a.name!r}")
        return mine, entry

    def prepare_sf_dir(self):
        if os.path.lexists(self.sf_dir):
            st = os.lstat(self.sf_dir)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise Abort(EXIT_FAIL, f"{self.sf_dir} is a symlink or not a directory; not exporting")
        else:
            os.mkdir(self.sf_dir, 0o700)
        st = os.lstat(self.sf_dir)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise Abort(EXIT_FAIL, f"{self.sf_dir} changed under us; not exporting")
        os.chmod(self.sf_dir, 0o700)

    def load_and_export(self):
        self.wait_idle("crawl end")
        crawl_id, entry = self.find_crawl_id()
        self.state.save(crawl_id=crawl_id, crawl_entry=entry)
        self.check_signal()
        text = self.mcp.call("sf_load_crawl", {"crawl_id": crawl_id})
        self.state.event("loaded", crawl_id=crawl_id, reply=text[:200])
        self.check_signal()
        self.wait_idle("sf_load_crawl")
        if not self.a.export:
            self.check_signal()
            self.state.save(status="done")
            return
        self.prepare_sf_dir()
        rel = f"{self.sf_export_rel}/internal_all.ndjson"
        self.check_signal()
        self.export_started = True
        try:
            res = self.mcp.json("sf_export_seo_element_urls",
                                {"seo_element_name": "Internal", "filter_name": "All", "file_path": rel})
        finally:
            lock_tree(self.sf_dir)
        self.check_signal()
        src = (res.get("path") if isinstance(res, dict) else None) or os.path.join(self.a.sf_base, rel)
        dir_real = os.path.realpath(self.sf_dir)
        src_real = os.path.realpath(src)
        if not src_real.startswith(dir_real + os.sep):
            raise Abort(EXIT_FAIL, f"export landed outside {self.sf_dir}: {src}")
        try:
            sst = os.lstat(src_real)
        except OSError:
            raise Abort(EXIT_FAIL, f"export reported {src} but the file does not exist")
        if not stat.S_ISREG(sst.st_mode):
            raise Abort(EXIT_FAIL, f"export {src} is not a regular file")
        self.wait_idle("export", strict=True)
        self.export_settled = True
        lock_tree(self.sf_dir)
        dst = os.path.join(self.out, "internal_all.ndjson")
        copy_private(src_real, dst)
        lock_tree(self.out)
        self.state.event("exported", element="Internal:All", sf_copy=src_real, local_copy=dst,
                         total_records=res.get("total_records") if isinstance(res, dict) else None)
        self.check_signal()
        self.redact_result = self.redact_gate([self.sf_dir, self.out])
        if self.redact_result != "ok":
            self.state.save(status="export-unredacted", exports=[dst], redact=self.redact_result)
            raise Abort(EXIT_UNREDACTED, f"exports are NOT verified redacted ({self.redact_result}); "
                                         "do not use or share them")
        self.state.save(status="exported", exports=[dst], redact="ok")
        self.check_signal()

    def _redactor(self, paths, mode_flag):
        try:
            p = subprocess.run([sys.executable, redact_path(), *paths, mode_flag], capture_output=True, text=True,
                               timeout=REDACT_TIMEOUT, start_new_session=True)
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except OSError as e:
            return None, f"error: {e}"
        return p, None

    def redact_gate(self, paths):
        """--fix-perms then --check on both copies. Returns "ok" only when --check exits 0."""
        for p in paths:
            lock_tree(p)
        redact = redact_path()
        if not os.path.isfile(redact):
            msg = (f"{redact} not found; exports were NOT redacted. Run redact_exports.py --fix-perms and "
                   f"--check on {' and '.join(paths)} before using or sharing anything.")
            print("!" * 78 + "\n" + msg + "\n" + "!" * 78, file=sys.stderr, flush=True)
            self.state.event("redact_missing", script=redact)
            return "missing"
        p, err = self._redactor(paths, "--fix-perms")
        if err:
            self.state.event("redact_failed", step="fix", why=err)
            return f"fix-failed:{err}"
        self.state.event("redacted", rc=p.returncode, stderr=(p.stderr or "")[-300:])
        if p.returncode != 0:
            print(f"WARNING: redact_exports.py exited {p.returncode}: {scrub_text((p.stderr or '')[-300:])}",
                  file=sys.stderr)
            return f"fix-failed:{p.returncode}"
        p, err = self._redactor(paths, "--check")
        if err:
            self.state.event("redact_check_failed", why=err)
            return f"check-failed:{err}"
        self.state.event("redact_checked", rc=p.returncode)
        if p.returncode != 0:
            print(f"WARNING: redact_exports.py --check exited {p.returncode}; unredacted values remain "
                  f"in {' or '.join(paths)}", file=sys.stderr)
            return f"check-failed:{p.returncode}"
        return "ok"

    def prepare_out(self):
        home = os.path.abspath(os.path.expanduser("~"))
        cur = home
        for part in os.path.relpath(self.out, home).split(os.sep):
            cur = os.path.join(cur, part)
            if not os.path.lexists(cur):
                os.mkdir(cur, 0o700)
            st = os.lstat(cur)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise Abort(EXIT_USAGE, f"{cur} is a symlink or not a directory")
        os.chmod(self.out, 0o700)
        err = out_error(self.out, self.a.name)
        if err:
            raise Abort(EXIT_USAGE, err)

    def run(self):
        for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(s, self.on_signal)
        try:
            try:
                self.prepare_out()
                self.preflight()
                self.check_signal()
                self.start()
                self.monitor()
                self.load_and_export()
                self.check_signal()
                log(f"done: {self.state.path}")
                code = EXIT_OK
            except Abort as e:
                log(str(e))
                code = e.code
            except (KeyboardInterrupt, SystemExit) as e:
                # handled like the matching signal: verified pause of our crawl, then 128+n or 8
                if self.signum is None:
                    self.signum = signal.SIGINT if isinstance(e, KeyboardInterrupt) else signal.SIGTERM
                code = self.cleanup_signal()
            except Exception as e:  # noqa: BLE001 - McpError, OSError and any bug: same cleanup
                code = self.cleanup_error(e)
            return self.final_export_gate(code)
        finally:
            if self.export_started:
                lock_tree(self.sf_dir)

    def cleanup_signal(self):
        self.state.tolerant = True
        try:
            self.check_signal()
        except Abort as a:
            log(str(a))
            return a.code
        except Exception as e:  # noqa: BLE001
            log(f"LOUD: cleanup after the signal failed: {type(e).__name__}: {e}")
            return EXIT_PAUSE_UNVERIFIED if self.crawl_requested and not self.crawl_finished else 128 + self.signum
        return 128 + self.signum

    def cleanup_error(self, e):
        """Any unexpected error: never leave a crawl we may have started running unverified."""
        self.state.tolerant = True
        what = "failed" if isinstance(e, McpError) else "unexpected error"
        msg = self._scrub(f"{what}: {type(e).__name__}: {e}")[:500]
        log(f"LOUD: {msg}")
        if self.crawl_requested and not self.crawl_finished:
            try:
                verified = self.pause_owned(what)
            except Exception as e2:  # noqa: BLE001
                log(f"LOUD: pause after the error failed: {type(e2).__name__}: {e2}")
                verified = False
            if not verified:
                self.state.save(status="pause-not-verified", error=msg, paused=False)
                log("LOUD: the crawl was NOT verified paused. Check the Screaming Frog app now.")
                return EXIT_PAUSE_UNVERIFIED
            self.state.save(status="failed", error=msg, paused=True)
            log("our crawl is not running (verified)")
            return EXIT_FAIL
        self.state.save(status="failed", error=msg)
        return EXIT_FAIL

    def final_export_gate(self, code):
        """An export that was started but did not finish cleanly (failed or partial call, missing
        file, copy error, any error) still gets the lockdown and the redaction gate on whatever was
        written. Not clean => exit 7, status export-unredacted."""
        if code == EXIT_OK or not self.export_started or self.redact_result is not None:
            return code
        self.state.tolerant = True
        lock_tree(self.sf_dir)
        lock_tree(self.out)
        # The export may still be writing (reply lost, wait timed out): verify idle first,
        # whether or not the crawl itself had finished.
        if not self.export_quiet(self.a.idle_timeout):
            lock_tree(self.sf_dir)
            lock_tree(self.out)
            self.redact_result = "export-may-be-writing"
            self.state.save(status="export-unredacted", redact=self.redact_result)
            log(f"LOUD: {EXPORT_UNSETTLED_MSG}")
            return EXIT_UNREDACTED
        try:
            self.redact_result = self.redact_gate([self.sf_dir, self.out])
        except Exception as e:  # noqa: BLE001
            self.redact_result = f"error:{type(e).__name__}"
        if self.redact_result != "ok":
            self.state.save(status="export-unredacted", redact=self.redact_result)
            log(f"LOUD: the export did not finish and what it wrote is NOT verified redacted "
                f"({self.redact_result}); do not use or share {self.sf_dir} or {self.out}")
            return EXIT_UNREDACTED
        self.state.save(redact="ok")
        return code


# ---------------------------------------------------------------- CLI

def parse(argv):
    p = argparse.ArgumentParser(description="Supervise one Screaming Frog MCP crawl.",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Steps:")[0])
    p.add_argument("--name", required=True, help="run name, e.g. 20260101-r1-a1 (also the crawl name)")
    p.add_argument("--url", required=True, help="start URL (https, on a configured crawl.hosts host)")
    p.add_argument("--config", required=True, help="ABSOLUTE path of the .seospiderconfig file")
    p.add_argument("--limit-hours", type=float, default=4.0, help="hard limit, at most 4")
    p.add_argument("--poll", type=float, default=60.0, help="seconds between progress polls")
    p.add_argument("--health", action="append", default=None, help="health URL (repeatable; replaces the defaults)")
    p.add_argument("--health-timeout", type=float, default=15.0, help="wall deadline per health request")
    p.add_argument("--health-slow", type=float, default=8.0, help="a response slower than this fails")
    p.add_argument("--out", default=None, help="default <run_root>/sf/run-RUNNAME")
    p.add_argument("--sf-base", default=os.environ.get("SF_BASE_DIR"),
                   help="Screaming Frog MCP allowed base directory (must equal screaming_frog.base_dir)")
    p.add_argument("--site-config", default=None,
                   help="Site Audit Kit config (else $SITE_AUDIT_CONFIG, else "
                        "~/.config/site-audit-kit/config.json)")
    p.add_argument("--export", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--start-grace", type=float, default=600.0, help=argparse.SUPPRESS)
    p.add_argument("--pause-verify-seconds", type=float, default=60.0, help=argparse.SUPPRESS)
    p.add_argument("--idle-timeout", type=float, default=900.0, help=argparse.SUPPRESS)
    p.add_argument("--busy-base", type=float, default=2.0, help=argparse.SUPPRESS)
    p.add_argument("--busy-budget", type=float, default=600.0, help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    test = testing()
    errs = []
    if a.site_config:
        # sfcall.sh and the redactor read the same file through the environment.
        os.environ["SITE_AUDIT_CONFIG"] = os.path.abspath(os.path.expanduser(a.site_config))
    try:
        cfg = config()
    except Exception as e:  # noqa: BLE001 - any config problem is a usage error
        print(f"sf_supervise: config error: {scrub_text(e)}", file=sys.stderr)
        sys.exit(EXIT_USAGE)
    default_base = cfg["screaming_frog"]["base_dir"]
    default_base = os.path.abspath(os.path.expanduser(default_base)) if default_base else None
    if not NAME_RE.match(a.name):
        errs.append("--name must be letters, digits, '.', '_' or '-' (e.g. 20260101-r1-a1)")
    if not os.path.isabs(a.config):
        errs.append(f"--config must be an ABSOLUTE path (a relative path fails in sf_crawl): {a.config}")
    elif not os.path.isfile(a.config):
        errs.append(f"--config does not exist: {a.config}")
    elif not a.config.endswith(".seospiderconfig"):
        errs.append(f"--config is not a .seospiderconfig file: {a.config}")
    e = site_url_error(a.url)
    if e:
        errs.append(f"--url {red(a.url)!r} refused: {e}")
    for flag in ("limit_hours", "poll", "health_timeout", "health_slow", "start_grace",
                 "pause_verify_seconds", "idle_timeout", "busy_base", "busy_budget"):
        v = getattr(a, flag)
        if not (math.isfinite(v) and v > 0):
            errs.append(f"--{flag.replace('_', '-')} must be a finite number > 0 (got {v})")
    if math.isfinite(a.limit_hours) and a.limit_hours > MAX_LIMIT_HOURS:
        errs.append(f"--limit-hours must be at most {MAX_LIMIT_HOURS:g} (the hard limit)")
    if math.isfinite(a.health_timeout) and a.health_timeout > 60:
        errs.append("--health-timeout must be at most 60 (safe_fetch's deadline ceiling)")
    try:
        t = sf_timeout()
        if not (math.isfinite(t) and t > 0):
            raise ValueError
    except ValueError:
        errs.append(f"SF_TIMEOUT must be a finite number > 0 (got {os.environ.get('SF_TIMEOUT')!r})")
    a.health = a.health or list(cfg["crawl"]["health_urls"])
    if not a.health:
        errs.append("no health URL: pass --health or set crawl.health_urls in the config")
    for u in a.health:
        e = site_url_error(u, allow_test=test)
        if e:
            errs.append(f"--health {red(u)!r} refused: {e}")
    a.out = os.path.abspath(os.path.expanduser(a.out or os.path.join(sf_root(), f"run-{a.name}")))
    if NAME_RE.match(a.name):
        e = out_error(a.out, a.name)
        if e:
            errs.append(e)
    a.sf_base = os.path.abspath(os.path.expanduser(a.sf_base or default_base or ""))
    if not test and not default_base:
        errs.append("screaming_frog.base_dir is not set in the config")
    elif a.sf_base != default_base and not test:
        errs.append(f"--sf-base must be {default_base} (got {a.sf_base})")
    elif not os.path.isdir(a.sf_base) and not a.dry_run:
        errs.append(f"--sf-base does not exist: {a.sf_base}")
    try:
        effective_mcp_url()
    except Exception as e:  # noqa: BLE001 - audit_config.ConfigError
        src = "SF_MCP_URL" if os.environ.get("SF_MCP_URL") else "screaming_frog.mcp_url"
        errs.append(f"{src} refused: {scrub_text(e)}")
    if errs:
        for e in errs: print("sf_supervise: " + scrub_text(e), file=sys.stderr)
        sys.exit(EXIT_USAGE)
    return a


def plan(a):
    rel = f"run-{a.name}/internal_all.ndjson"
    mcp_url, mcp_src = effective_mcp_url()
    crawl_args = {"crawl_url": red(a.url), "config_path": a.config, "crawl_name": a.name,
                  "project_name": config()["screaming_frog"]["project_name"]}
    lines = [
        "sf_supervise plan (dry run: no MCP call, no crawl)",
        f"  run name        {a.name}",
        f"  start URL       {red(a.url)}  (query values shown as X)",
        f"  config          {a.config} (absolute, exists)",
        f"  out dir         {a.out} (700; supervise.json + progress.log 600)",
        f"  sfcall          {sfcall_path()} ({'present' if os.access(sfcall_path(), os.X_OK) else 'MISSING'}); "
        f"MCP server {red(mcp_url)} (from {mcp_src})",
        f"  limits          poll {a.poll}s, hard limit {a.limit_hours}h, health wall deadline {a.health_timeout}s, "
        f"slow > {a.health_slow}s",
        "  health URLs     " + ", ".join(red(u) for u in a.health) + " (safe_fetch.SafeFetcher)",
        "",
        "  1. preflight    sf_crawl_progress must show an idle spider (else exit 2); sf_list_crawls recorded;"
        " supervise.json owned=false",
        f"  2. start        sf_crawl {json.dumps(crawl_args)}",
        "                  a lost or unparsable reply => reconcile for the start grace: our crawl found =>"
        " supervised; another running crawl or no verification => exit 8; idle throughout => exit 1",
        "                  owned=true only when the running id is listed with this name and was not listed"
        " before (else exit 1)",
        f"  3. poll         sf_crawl_progress + health every {a.poll}s -> progress.log; 2 failed health rounds"
        " => pause, exit 5; 5 unreachable polls => exit 3",
        "  4. finish       our crawl seen active, then idle AND post-crawl analysis 100%;"
        f" after {a.limit_hours}h => pause, partial, exit 6",
        "  5. signals      TERM/INT/HUP => pause our crawl only (recorded database id), verify inactive, exit 128+n",
        "                  any pause that cannot be verified => exit 8; any other id after ownership =>"
        " ownership-lost, exit 1",
        f"  6. load         sf_list_crawls must list the recorded id named {a.name} -> sf_load_crawl crawl_id",
    ]
    if a.export:
        lines += [
            f"     export       sf_export_seo_element_urls Internal/All file_path={rel} (relative to {a.sf_base})",
            f"                  SF folder locked 700/600 right after; copy -> {os.path.join(a.out, 'internal_all.ndjson')}"
            " (600 from the first byte)",
            f"                  redact: {redact_path()} ({'present' if os.path.isfile(redact_path()) else 'MISSING: the run will end with exit 7'}) "
            f"--fix-perms then --check on {os.path.join(a.sf_base, 'run-' + a.name)} and {a.out}; not clean => exit 7",
        ]
    else:
        lines.append("     export       skipped (no --export)")
    lines += ["", "  tools allowed:  " + ", ".join(sorted(ALLOWED_TOOLS)) + " (anything else raises)"]
    return "\n".join(lines)


def main(argv=None):
    a = parse(sys.argv[1:] if argv is None else argv)
    if a.dry_run:
        print(plan(a))
        return EXIT_OK
    return Supervisor(a).run()


if __name__ == "__main__":
    sys.exit(main())
