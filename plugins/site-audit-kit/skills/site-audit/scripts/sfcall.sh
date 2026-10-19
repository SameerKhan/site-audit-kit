#!/bin/sh
# Usage: sfcall.sh --list | sfcall.sh <tool_name> ['<json-object-arguments>']
# Drives Screaming Frog's MCP server over HTTP. Reuses one session id per server URL in
# <run_root>/sf/.sid-<hash of the URL>, so a session id is never sent to a different server.
# Exit codes: 0 ok; 2 bad usage (extra arguments, arguments that are not a JSON object, NaN or
# Infinity), configuration, an MCP URL that is not loopback http (audit_config.validate_mcp_url,
# also applied to SF_MCP_URL), or a tool that is not on the allowlist; 3 server unreachable,
# HTTP error, or a reply larger than 32 MiB; 4 JSON-RPC or tool error (printed to stderr).
# Proxy environment variables (http_proxy, HTTPS_PROXY, all_proxy, ...) are never used.
# Settings come from the Site Audit Kit config (screaming_frog.mcp_url, .allowed_tools and
# run_root; config from $SITE_AUDIT_CONFIG, else ~/.config/site-audit-kit/config.json).
# SF_MCP_URL and SF_TIMEOUT override the URL and the timeout.
# Only read-only tools run by default. State-changing tools (sf_crawl, sf_resume_crawl,
# sf_load_crawl, sf_pause_crawl, sf_export_*, sf_generate_bulk_export, sf_generate_report)
# are refused unless SITE_AUDIT_SUPERVISED=1, which sf_supervise.py sets for its own calls.
# Crawls go through sf_supervise.py only.
# Hardening: no '{\}' when no arguments are given, a non-zero exit on every failure, a locked
# session-id file safe under parallel calls, and a tool call is only re-sent when the server
# rejected it unexecuted for an unknown session (never because its result text mentions one).
umask 077
SITE_AUDIT_KIT_SCRIPTS=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 2
export SITE_AUDIT_KIT_SCRIPTS
exec python3 - "$@" <<'PY'
import fcntl, hashlib, json, os, sys, uuid, urllib.request, urllib.error
sys.path.insert(0, os.environ["SITE_AUDIT_KIT_SCRIPTS"])

def die(code, msg):
    print(msg, file=sys.stderr); sys.exit(code)

try:
    import audit_config
    CFG = audit_config.load_config()
except Exception as e:
    die(2, f"sfcall: config error: {e}")
MAX_BODY = 32 * 1024 * 1024

def check_url(url, where):
    """Validate an MCP URL with audit_config.validate_mcp_url (fail closed when it is missing)."""
    v = getattr(audit_config, "validate_mcp_url", None)
    if not callable(v):
        die(2, "sfcall: audit_config.validate_mcp_url is missing; refusing to call any MCP server "
               "(update the Site Audit Kit scripts together)")
    try:
        res = v(url)
    except Exception as e:
        die(2, f"sfcall: {where} refused: {e}")
    if res is False or (isinstance(res, str) and res != url and not res.startswith("http")):
        die(2, f"sfcall: {where} refused: {res if isinstance(res, str) else 'not a loopback MCP URL'}")

if CFG["screaming_frog"].get("mcp_url"):
    check_url(CFG["screaming_frog"]["mcp_url"], "screaming_frog.mcp_url")
URL = os.environ.get("SF_MCP_URL") or CFG["screaming_frog"]["mcp_url"]
check_url(URL, "SF_MCP_URL" if os.environ.get("SF_MCP_URL") else "screaming_frog.mcp_url")
try:
    TIMEOUT = float(os.environ.get("SF_TIMEOUT", "120"))
except ValueError:
    die(2, "sfcall: SF_TIMEOUT must be a number")
D = os.path.join(audit_config.run_root(CFG), "sf")
os.makedirs(D, mode=0o700, exist_ok=True); os.chmod(D, 0o700)
SID = os.path.join(D, ".sid-" + hashlib.sha256(URL.encode()).hexdigest()[:24])
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never a proxy
HDRS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

def post(body, sid=None):
    h = dict(HDRS)
    if sid: h["Mcp-Session-Id"] = sid
    req = urllib.request.Request(URL, data=json.dumps(body, allow_nan=False).encode(), headers=h,
                                 method="POST")
    try:
        with OPENER.open(req, timeout=TIMEOUT) as r:
            return r.status, r.headers, read_capped(r)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, read_capped(e)
    except Exception as e:
        die(3, f"sfcall: cannot reach {URL}: {e}")

def read_capped(r):
    data = r.read(MAX_BODY + 1)
    if len(data) > MAX_BODY:
        die(3, f"sfcall: reply from {URL} is too large (over {MAX_BODY} bytes); refusing it")
    return data.decode("utf-8", "replace")

def messages(text):
    """JSON-RPC messages from a plain JSON or SSE body (CRLF tolerated)."""
    text = text.replace("\r", "")
    try:
        return [json.loads(text)]
    except ValueError:
        out = []
        for line in text.split("\n"):
            if line.startswith("data:"):
                try: out.append(json.loads(line[5:].strip()))
                except ValueError: pass
        return out

def session_error(status, text):
    """True only when the server rejected the request for an unknown session, so it was never
    executed: an error object (never result text) whose message starts with 'Session not found'."""
    for m in messages(text):
        if "result" in m:
            return False
        err = m.get("error") or m.get("jsonRpcError")
        if isinstance(err, dict) and str(err.get("message", "")).lower().startswith("session not found"):
            return True
    return False

def init():
    rid = "init-" + uuid.uuid4().hex
    st, hdr, text = post({"jsonrpc": "2.0", "id": rid, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "site-audit-sfcall", "version": "2"}}})
    sid = (hdr.get("Mcp-Session-Id") or hdr.get("mcp-session-id") or "").strip()
    ok = any(m.get("id") == rid and "result" in m for m in messages(text))
    if st >= 400 or not sid or "\n" in sid or not ok:
        die(3, f"sfcall: initialize failed (HTTP {st}): {text[:300]}")
    st2, _, text2 = post({"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    if st2 >= 400:
        die(3, f"sfcall: initialized notification failed (HTTP {st2}): {text2[:300]}")
    tmp = SID + f".{os.getpid()}"
    with open(tmp, "w") as f: f.write(sid)
    os.replace(tmp, SID)
    return sid

def get_sid(force=False):
    with open(SID + ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not force and os.path.exists(SID):
            sid = open(SID).read().strip().split("\n")[0]
            if sid: return sid
        return init()

USAGE = "usage: sfcall.sh --list | sfcall.sh <tool_name> ['<json-object-arguments>']"
args = sys.argv[1:]
if not args: die(2, USAGE)
if args[0] == "--list":
    if len(args) != 1: die(2, USAGE)
    body = {"jsonrpc": "2.0", "id": uuid.uuid4().hex, "method": "tools/list"}
else:
    if audit_config.sf_supervised_only(args[0]) and os.environ.get(audit_config.SUPERVISED_ENV) != "1":
        die(2, f"sfcall: tool {args[0]!r} changes state; run crawls and exports through "
               f"sf_supervise.py (it sets {audit_config.SUPERVISED_ENV}=1)")
    if not audit_config.sf_tool_allowed(args[0], CFG):
        die(2, f"sfcall: tool {args[0]!r} is not on screaming_frog.allowed_tools")
    if len(args) > 2: die(2, USAGE)
    raw = args[1] if len(args) > 1 and args[1].strip() else "{}"
    def no_constant(c):
        raise ValueError(f"{c} is not allowed")
    try: arguments = json.loads(raw, parse_constant=no_constant)
    except ValueError as e: die(2, f"sfcall: arguments are not valid JSON: {e}")
    if not isinstance(arguments, dict): die(2, "sfcall: arguments must be a JSON object")
    body = {"jsonrpc": "2.0", "id": uuid.uuid4().hex, "method": "tools/call", "params": {"name": args[0], "arguments": arguments}}

sid = get_sid()
st, _, text = post(body, sid)
if session_error(st, text):   # the request was rejected unexecuted, so one retry is safe
    sid = get_sid(force=True)
    st, _, text = post(body, sid)
if st >= 400:
    die(3, f"sfcall: HTTP {st}: {text[:300]}")
msgs = [m for m in messages(text) if m.get("id") == body["id"]]
if not msgs:
    die(3, f"sfcall: no response for request (HTTP {st}): {text[:300]}")
m = msgs[-1]
print(json.dumps(m))
err = m.get("error") or m.get("jsonRpcError")
if err or (m.get("result") or {}).get("isError"):
    print(f"sfcall: error: {json.dumps(err or m['result'])[:500]}", file=sys.stderr)
    sys.exit(4)
PY
