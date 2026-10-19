#!/usr/bin/env python3
"""audit_config: the one JSON configuration every Site Audit Kit tool reads.

Standard library only. Resolution order:

1. an explicit path (each tool's ``--config``);
2. the environment variable ``SITE_AUDIT_CONFIG``;
3. ``~/.config/site-audit-kit/config.json``.

An explicit path or an environment path that does not exist is an error (a typo must never
fall back to other settings). A missing default file is NOT an error: the tools then run with
``DEFAULTS``, which allow no host at all, so nothing is fetched, crawled or queried until the
file exists (an explicit command-line override such as ``safe_fetch.py --allow-host`` or
``--external`` is the operator's deliberate choice).

The file must be a regular file (a FIFO or device is refused without blocking), not a symlink,
owned by the current user and not writable by group or others: whoever can write it can widen
the host allowlist. It must be UTF-8 without a byte-order mark, at most 1 MiB (a larger file is
refused, never truncated), and hold no duplicate key at any level. An empty ``--config`` or an
empty ``SITE_AUDIT_CONFIG`` is an error, never a fall-through to the next source.

Unknown keys are refused (a misspelt key would otherwise be silently ignored). Lists replace
the default list; objects are merged key by key with the defaults.

``python3 audit_config.py [--config PATH]`` prints the effective configuration and exits 0, or
prints the error and exits 2.
"""
from __future__ import annotations

import copy
import fcntl
import ipaddress
import json
import os
import re
import stat
import sys
from urllib.parse import urlsplit

ENV_VAR = "SITE_AUDIT_CONFIG"
DEFAULT_PATH = os.path.join("~", ".config", "site-audit-kit", "config.json")

#: Default WordPress allowlists for sql_guard (generic WordPress core and common SEO plugins).
WP_OPTION_NAMES = ["siteurl", "home", "permalink_structure", "blog_public"]
WP_META_KEYS = ["_wp_page_template"]
WP_META_PREFIXES = ["rank_math_", "_yoast_wpseo_"]
WP_TEMPLATE_POST_TYPES = []
WP_EXTRA_TABLES = ["terms", "term_taxonomy", "term_relationships"]

#: Screaming Frog MCP tools that sfcall.sh may call by default: read-only listing and progress
#: tools only. Everything that writes or reads arbitrary files, runs code, opens a browser,
#: fetches a URL outside a crawl or deletes crawls is left out.
SF_DEFAULT_TOOLS = [
    "sf_crawl_progress", "sf_list_crawls", "sf_list_available_filters_for_seo_element",
    "sf_list_available_data_fields_for_seo_element_and_filter", "sf_list_available_bulk_exports",
    "sf_list_available_reports", "sf_list_allowed_base_directory", "sf_list_directories",
]

#: State-changing tools sfcall.sh may call under SITE_AUDIT_SUPERVISED=1 even when they are not
#: listed in allowed_tools (start, resume, load or pause a crawl; write an export or report).
#: sf_supervise.py sets that variable for its own calls only. Every other tool outside
#: SF_READ_ONLY_TOOLS is supervised-only too, but needs listing in allowed_tools as well.
#: Crawls go through sf_supervise.py only.
SF_SUPERVISED_TOOLS = [
    "sf_crawl", "sf_resume_crawl", "sf_load_crawl", "sf_pause_crawl",
    "sf_export_seo_element_urls", "sf_generate_bulk_export", "sf_generate_report",
]
SUPERVISED_ENV = "SITE_AUDIT_SUPERVISED"

#: The only tools that run without SITE_AUDIT_SUPERVISED=1: this exact set plus
#: sf_list_available_<name>. Everything else, including any tool name this kit does not know,
#: is treated as state-changing.
SF_READ_ONLY_TOOLS = frozenset({
    "sf_crawl_progress", "sf_list_crawls", "sf_list_allowed_base_directory", "sf_list_directories",
})
_SF_READ_ONLY_RE = re.compile(r"sf_list_available_[a-z0-9_]+")
#: Names that always mean "writes or changes state" (kept as a second check on the read-only set).
_SF_STATE_RE = re.compile(
    r"^sf_(export|bulk|generate|create|write|save|delete|clear|resume|pause|load|crawl)_?")


def sf_read_only(tool):
    """True only for the explicit read-only tools (SF_READ_ONLY_TOOLS, sf_list_available_*)."""
    if not isinstance(tool, str):
        return False
    if tool in SF_READ_ONLY_TOOLS:
        return True
    return _SF_READ_ONLY_RE.fullmatch(tool) is not None and not _SF_STATE_RE.match(tool)


_SF_NAME_RE = re.compile(r"sf_[a-z0-9_]+")


def sf_supervised_only(tool):
    """True for every sf_* tool sfcall.sh only runs under SITE_AUDIT_SUPERVISED=1: anything that
    is not an explicit read-only tool (writes, exports, crawl control and unknown sf_* names).
    SF_NEVER_TOOLS and names that are not sf_* tool names return False here because they are
    never callable at all (sf_tool_allowed refuses them whatever the config or environment)."""
    if not isinstance(tool, str) or not _SF_NAME_RE.fullmatch(tool) or tool in SF_NEVER_TOOLS:
        return False
    return not sf_read_only(tool)


# Never callable through sfcall.sh, whatever the config says: they run code, read or write
# arbitrary files, open a browser, delete crawl data, or fetch a URL outside safe_fetch.
SF_NEVER_TOOLS = frozenset({
    "sf_run_node_js_script", "sf_npm_install", "sf_write_text_file", "sf_read_text_file",
    "sf_open_url_in_browser", "sf_clear_crawl", "sf_url_content", "sf_url_info",
    "sf_url_links", "sf_get_url_screenshot",
})


def sf_tool_allowed(tool, cfg, env=None):
    """Whether sfcall.sh may call tool under cfg. Read-only tools need screaming_frog.allowed_tools;
    state-changing tools need SITE_AUDIT_SUPERVISED=1 (then the configured list or
    SF_SUPERVISED_TOOLS)."""
    env = os.environ if env is None else env
    if not isinstance(tool, str) or not _SF_NAME_RE.fullmatch(tool) or tool in SF_NEVER_TOOLS:
        return False
    listed = tool in cfg["screaming_frog"]["allowed_tools"]
    if sf_supervised_only(tool):
        return env.get(SUPERVISED_ENV) == "1" and (listed or tool in SF_SUPERVISED_TOOLS)
    return listed


DEFAULTS = {
    # Hosts safe_fetch may fetch. Enumerated, never globbed. Empty: no host is allowed.
    "allowed_hosts": [],
    # Domains you own: never treated as "external" in --external mode (they must be on
    # allowed_hosts to be fetched).
    "owned_domains": [],
    # Hosts that are always refused (for example a compromised or retired subdomain).
    "forbidden_hosts": [],
    # When true, every subdomain of a forbidden host is refused too, in every mode.
    "forbid_subdomains_of_forbidden": True,
    # Optional: {forbidden_host: [exact paths]} fetchable only in --probe mode (no query, no
    # redirect followed). Lets you check that a forbidden host still answers as expected.
    "probe_paths": {},
    # Optional cache-bypass query, e.g. "nocache=1". None: no cache comparison, and crawl or
    # health URLs may carry no query at all.
    "cache_bust_query": None,
    # Every run directory, log and export lives under this folder (mode 700).
    "run_root": "~/site-audit",
    "crawl": {
        # Hosts a Screaming Frog crawl may start from (each must also be in allowed_hosts).
        "hosts": [],
        # Plain-http exceptions: [{"host": "www.example.com", "path_prefix": "/blog"}].
        "http_paths": [],
        # Health URLs polled during a crawl (default for sf_supervise --health).
        "health_urls": [],
    },
    "health": {
        # URLs that must answer 200 before crawling (run_manifest).
        "status_urls": [],
        # URLs that must answer 200 with an HTML document before crawling (run_manifest).
        "html_urls": [],
    },
    "screaming_frog": {
        "mcp_url": "http://127.0.0.1:11435/mcp",
        # The MCP server's allowed base directory. Required before sf_supervise will run.
        "base_dir": None,
        # Where your .seospiderconfig profiles live (default: base_dir).
        "profiles_dir": None,
        "project_name": "site-audit",
        # Read-only tools sfcall.sh may call (tools/list is always allowed). State-changing
        # tools also need SITE_AUDIT_SUPERVISED=1, which only sf_supervise.py sets.
        "allowed_tools": SF_DEFAULT_TOOLS,
    },
    "baseline": {
        # Folder holding previous findings files. None: no baseline (first run).
        "dir": None,
        # Findings file names. Both named groups are required: date (YYYY-MM-DD) and n (the
        # same-day suffix; the group itself may sit in an optional part of the pattern).
        "findings_regex": r"^site-audit-(?P<date>\d{4}-\d{2}-\d{2})(?:-(?P<n>\d+))?\.md$",
        # Companion files: <findings stem>-<suffix>.md
        "companion_suffixes": ["runbook", "decisions", "baseline-delta"],
        # A findings file counts as a baseline only with a "## <review_heading>" section.
        "review_heading": "review record",
        # Optional file in dir used when no reviewed findings file exists.
        "fallback_file": None,
        "fallback_date": None,
        "fallback_also_read": [],
        # Crawl note files written after a baseline. Named groups: date and optional n.
        "notes_regex": (r"^screaming-frog-run[0-9A-Za-z_-]*?-(?P<date>\d{4}-\d{2}-\d{2})"
                        r"(?:-(?P<n>\d+))?\.md$"),
        # A note whose name matches this gets the row prefix R<group 1> (a group is required).
        "notes_run_regex": r"^screaming-frog-run(\d+)-\d{4}-\d{2}-\d{2}",
        # Optional markdown file with a "| ID | P/A | finding | measured in |" table (null or a
        # non-empty path).
        "method_table_file": None,
        # The "## " heading that starts the method table section.
        "method_table_heading": "re-test table",
    },
    "models": {
        # Independent reviewer legs. An empty model means "not configured" (advisory). binary:
        # a path, or null for the default name; "" is refused once the model is set.
        "gemini": {"model": "", "binary": "", "list_args": []},
        # The Codex model is pinned with `-c model=<model>` on every call; no Codex
        # configuration file is ever read.
        "codex": {"model": "", "binary": "codex"},
    },
    "db": {
        # A Python file that defines DATABASES = {alias: {...}}. Parsed as an AST, never run.
        "config_file": None,
        # Aliases of the read-only DB users that must exist in DATABASES.
        "readonly_aliases": [],
        "public_post_types": ["post", "page"],
        # {name: install}; see README for the install keys.
        "installs": {},
    },
    "redaction": {
        # Parameter names added to redact_exports.py's built-in list.
        "extra_params": [],
    },
}

INSTALL_DEFAULTS = {
    "prefix": "wp_",
    # true: the connection's default database is a read-only schema of views.
    "views": False,
    # The one schema qualifier accepted (the view schema, or the WordPress database).
    "schema": None,
    "public_post_types": None,  # None: db.public_post_types
    "attended_only": False,
    "option_names": WP_OPTION_NAMES,
    "meta_keys": WP_META_KEYS,
    "meta_prefixes": WP_META_PREFIXES,
    "template_post_types": WP_TEMPLATE_POST_TYPES,
    "extra_tables": WP_EXTRA_TABLES,
    # Optional per-table column allowlists (subsets of the WordPress core columns).
    "columns": {},
    # Hosts the revision-residue count may search for. Empty: the exception is off.
    "residue_hosts": [],
    "residue_meta_key": "_elementor_data",
}


class ConfigError(ValueError):
    """The configuration could not be read or is invalid (a ValueError, so callers that
    already refuse on ValueError keep failing closed)."""


#: Largest config file accepted (a larger one is refused, never truncated).
MAX_CONFIG_BYTES = 1 << 20
#: Deepest JSON nesting accepted anywhere in the file (including "_comment").
MAX_CONFIG_DEPTH = 32

_HOST_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _host_ok(h):
    if not isinstance(h, str) or not h or not h.isascii() or h != h.lower() or len(h) > 253:
        return False
    return all(_HOST_LABEL.match(lab) for lab in h.split("."))


def _dns_name_ok(h):
    """A host name for allowed_hosts: valid syntax, at least two labels, a non-numeric last
    label, and not an IP literal (IPs, decimal or hex integers and single labels are refused)."""
    if not _host_ok(h) or "." not in h:
        return False
    try:
        ipaddress.ip_address(h)
        return False
    except ValueError:
        pass
    return not h.rsplit(".", 1)[1].isdigit()


_MCP_HOSTS = ("127.0.0.1", "::1", "localhost")
_URL_PATH = re.compile(r"(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?")


def _plain_ascii(s):
    return isinstance(s, str) and s.isascii() and all(0x20 < ord(c) < 0x7f for c in s) \
        and "\\" not in s


def validate_mcp_url(url):
    """Return url when it is http:// to a loopback host (127.0.0.1, [::1] or localhost) with an
    explicit port and an optional path; raise ConfigError otherwise. No userinfo, query,
    fragment, whitespace or control character. sfcall.sh validates SF_MCP_URL with this too."""
    if not _plain_ascii(url) or not url.startswith("http://"):
        raise ConfigError(f"must be http://<127.0.0.1|[::1]|localhost>:<port>[/path], got {url!r}")
    if "?" in url or "#" in url or "@" in url:
        raise ConfigError(f"may not carry a query, fragment or userinfo: {url!r}")
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    host = parts.hostname
    if port is None or not 1 <= port <= 65535 or host not in _MCP_HOSTS:
        raise ConfigError(f"must name a loopback host (127.0.0.1, [::1], localhost) and an "
                          f"explicit port 1-65535: {url!r}")
    expected = f"[::1]:{port}" if host == "::1" else f"{host}:{port}"
    if parts.netloc.lower() != expected or not _URL_PATH.fullmatch(parts.path):
        raise ConfigError(f"is not a plain loopback URL: {url!r}")
    return url


def _check_url(u, name, cache_q):
    """An http(s) URL with a valid host, no userinfo or fragment, and either no query or exactly
    cache_q (query values are printed and stored verbatim, so nothing else may ride along)."""
    if not _plain_ascii(u) or not (u.startswith("https://") or u.startswith("http://")):
        raise ConfigError(f"{name}: {u!r} is not a plain http(s) URL")
    parts = urlsplit(u)
    netloc = parts.netloc
    if "@" in netloc or "#" in u:
        raise ConfigError(f"{name}: {u!r} may not carry userinfo or a fragment")
    host = netloc.rsplit(":", 1)[0] if ":" in netloc else netloc
    try:
        port = parts.port
    except ValueError:
        port = -1
    if not _host_ok(host) or (port is not None and not 1 <= port <= 65535) \
            or (":" in netloc and port is None):
        raise ConfigError(f"{name}: {u!r} has an invalid host or port")
    if "?" in u and (cache_q is None or parts.query != cache_q):
        raise ConfigError(f"{name}: {u!r} may carry no query other than cache_bust_query "
                          f"({cache_q!r})")
    return u


_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]{1,191}")
#: WordPress core columns a per-install column allowlist may narrow to (post_password never).
_CORE_COLUMNS = {
    "posts": frozenset({
        "id", "post_author", "post_date", "post_date_gmt", "post_content", "post_title",
        "post_excerpt", "post_status", "comment_status", "ping_status", "post_name", "to_ping",
        "pinged", "post_modified", "post_modified_gmt", "post_content_filtered", "post_parent",
        "guid", "menu_order", "post_type", "post_mime_type", "comment_count"}),
    "postmeta": frozenset({"meta_id", "post_id", "meta_key", "meta_value"}),
    "options": frozenset({"option_id", "option_name", "option_value", "autoload"}),
}


def _validate_install(name, inst):
    """Refuse any db.installs.<name> value of the wrong type or shape (defaults filled in)."""
    w = f"db.installs.{name}"
    st = dict(INSTALL_DEFAULTS)
    st.update(inst)

    def strs(key, rx=_KEY_RE, nullable=False):
        v = st[key]
        if v is None and nullable:
            return
        if not isinstance(v, list) or not all(isinstance(x, str) and rx.fullmatch(x) for x in v):
            raise ConfigError(f"{w}.{key} must be a list of non-empty names "
                              f"(letters, digits, '_', '.', ':' or '-'): {v!r}")

    if not (isinstance(st["prefix"], str) and re.fullmatch(r"[A-Za-z0-9_]{1,32}", st["prefix"])):
        raise ConfigError(f"{w}.prefix must be 1-32 letters, digits or '_': {st['prefix']!r}")
    for k in ("views", "attended_only"):
        if not isinstance(st[k], bool):
            raise ConfigError(f"{w}.{k} must be true or false")
    sc = st["schema"]
    if sc is not None and not (isinstance(sc, str) and re.fullmatch(r"[A-Za-z0-9_]{1,64}", sc)):
        raise ConfigError(f"{w}.schema must be null or a plain schema name: {sc!r}")
    if st["views"] and not sc:
        raise ConfigError(f"{w}: views=true needs schema")
    strs("public_post_types", re.compile(r"[A-Za-z0-9_-]{1,64}"), nullable=True)
    for k in ("option_names", "meta_keys", "meta_prefixes", "template_post_types"):
        strs(k)
    strs("extra_tables", re.compile(r"[A-Za-z0-9_]{1,64}"))
    cols = st["columns"]
    if not isinstance(cols, dict):
        raise ConfigError(f"{w}.columns must be an object")
    for base, lst in cols.items():
        if base not in _CORE_COLUMNS:
            raise ConfigError(f"{w}.columns key must be posts, postmeta or options: {base!r}")
        if not (isinstance(lst, list) and lst and all(isinstance(c, str) and c for c in lst)
                and {c.lower() for c in lst} <= _CORE_COLUMNS[base]):
            raise ConfigError(f"{w}.columns.{base} must be a list of WordPress core columns "
                              "(post_password is never allowed)")
    if not isinstance(st["residue_hosts"], list) or not all(_host_ok(h) for h in st["residue_hosts"]):
        raise ConfigError(f"{w}.residue_hosts must be a list of host names")
    rmk = st["residue_meta_key"]
    if not (isinstance(rmk, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,191}", rmk)):
        raise ConfigError(f"{w}.residue_meta_key must be a plain meta key")


def expand(path, home=None):
    """Expand a leading ~ (against ``home`` when given, else $HOME)."""
    if not isinstance(path, str):
        return path
    if home is not None and (path == "~" or path.startswith("~/")):
        return os.path.join(home, path[2:]) if path != "~" else home
    return os.path.expanduser(path)


def resolve_path(explicit=None, environ=None):
    """(path, source) where source is 'argument', 'environment' or 'default'."""
    env = os.environ if environ is None else environ
    if explicit is not None:
        if not isinstance(explicit, str) or not explicit.strip():
            raise ConfigError("--config is empty (give a path, or leave the option out)")
        return os.path.abspath(expand(explicit)), "argument"
    if ENV_VAR in env:
        if not env[ENV_VAR].strip():
            raise ConfigError(f"${ENV_VAR} is set but empty (unset it or give a path)")
        return os.path.abspath(expand(env[ENV_VAR])), "environment"
    return os.path.abspath(expand(DEFAULT_PATH)), "default"


def _merge(base, over, where):
    out = copy.deepcopy(base)
    for k, v in over.items():
        if k not in base:
            raise ConfigError(f"unknown key {where}{k!r}")
        if isinstance(base[k], dict) and base[k] and k not in ("probe_paths",):
            if not isinstance(v, dict):
                raise ConfigError(f"{where}{k} must be an object")
            out[k] = _merge(base[k], v, f"{where}{k}.")
        else:
            out[k] = copy.deepcopy(v)
    return out


def _str_list(v, name, check=None):
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ConfigError(f"{name} must be a list of non-empty strings")
    if check:
        for x in v:
            if not check(x):
                raise ConfigError(f"{name}: invalid entry {x!r}")
    return v


def _regex(v, name, groups=()):
    try:
        rx = re.compile(v)
    except (re.error, TypeError) as e:
        raise ConfigError(f"{name} is not a valid regular expression: {e}")
    for g in groups:
        if g not in rx.groupindex:
            raise ConfigError(f"{name} needs a named group (?P<{g}>...)")
    return rx


def validate(cfg):
    """Raise ConfigError on any invalid value. Returns cfg."""
    host_names = ("allowed_hosts", "owned_domains", "forbidden_hosts")
    for k in host_names:
        _str_list(cfg[k], k, _host_ok)
    for h in cfg["allowed_hosts"]:
        if not _dns_name_ok(h):
            raise ConfigError(f"allowed_hosts: {h!r} is an IP literal, a single label or numeric; "
                              "list fully qualified DNS names only")
    allowed = set(cfg["allowed_hosts"])
    forb = set(cfg["forbidden_hosts"])
    if allowed & forb:
        raise ConfigError(f"hosts both allowed and forbidden: {sorted(allowed & forb)}")
    if cfg["forbid_subdomains_of_forbidden"]:
        for h in allowed:
            if any(h.endswith("." + f) for f in forb):
                raise ConfigError(f"allowed host {h} is a subdomain of a forbidden host")
    if not isinstance(cfg["forbid_subdomains_of_forbidden"], bool):
        raise ConfigError("forbid_subdomains_of_forbidden must be true or false")
    pp = cfg["probe_paths"]
    if not isinstance(pp, dict):
        raise ConfigError("probe_paths must be an object")
    for h, paths in pp.items():
        if h not in forb:
            raise ConfigError(f"probe_paths key {h!r} is not a forbidden host")
        _str_list(paths, f"probe_paths[{h}]",
                  lambda p: p.startswith("/") and "?" not in p and "#" not in p and p.isascii())
    q = cfg["cache_bust_query"]
    if q is not None and not (isinstance(q, str) and re.fullmatch(r"[A-Za-z0-9_.-]+=[A-Za-z0-9_.-]+", q)):
        raise ConfigError("cache_bust_query must be null or one plain key=value pair")
    rr = cfg["run_root"]
    if not (isinstance(rr, str) and (rr.startswith("/") or rr.startswith("~/"))
            and os.path.isabs(expand(rr)) and os.path.normpath(expand(rr)).strip("/")
            and rr.rstrip("/") != "~"):
        raise ConfigError("run_root must be an absolute path (or ~/...) below the root directory")
    c = cfg["crawl"]
    _str_list(c["hosts"], "crawl.hosts", _host_ok)
    stray = set(c["hosts"]) - allowed
    if stray:
        raise ConfigError(f"crawl.hosts must also be in allowed_hosts: {sorted(stray)}")
    if not isinstance(c["http_paths"], list):
        raise ConfigError("crawl.http_paths must be a list")
    for e in c["http_paths"]:
        if (not isinstance(e, dict) or set(e) != {"host", "path_prefix"}
                or e["host"] not in c["hosts"] or not isinstance(e["path_prefix"], str)
                or not e["path_prefix"].startswith("/") or e["path_prefix"] == "/"
                or e["path_prefix"].endswith("/")):
            raise ConfigError("crawl.http_paths entries are {\"host\": <a crawl host>, "
                              "\"path_prefix\": \"/section\"} (not \"/\", no trailing slash)")
    for sect, k in (("crawl", "health_urls"), ("health", "status_urls"), ("health", "html_urls")):
        _str_list(cfg[sect][k], f"{sect}.{k}")
        for u in cfg[sect][k]:
            _check_url(u, f"{sect}.{k}", q)
    s = cfg["screaming_frog"]
    try:
        validate_mcp_url(s["mcp_url"])
    except ConfigError as e:
        raise ConfigError(f"screaming_frog.mcp_url {e}") from None
    for k in ("base_dir", "profiles_dir"):
        if s[k] is not None and not (isinstance(s[k], str) and s[k]):
            raise ConfigError(f"screaming_frog.{k} must be null or a path")
    if not (isinstance(s["project_name"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", s["project_name"])):
        raise ConfigError("screaming_frog.project_name must be letters, digits, '.', '_' or '-'")
    _str_list(s["allowed_tools"], "screaming_frog.allowed_tools",
              lambda t: re.fullmatch(r"sf_[a-z0-9_]+", t) is not None)
    b = cfg["baseline"]
    if b["dir"] is not None and not (isinstance(b["dir"], str) and b["dir"]):
        raise ConfigError("baseline.dir must be null or a path")
    _regex(b["findings_regex"], "baseline.findings_regex", ("date", "n"))
    _regex(b["notes_regex"], "baseline.notes_regex", ("date",))
    if _regex(b["notes_run_regex"], "baseline.notes_run_regex").groups < 1:
        raise ConfigError("baseline.notes_run_regex needs a capture group (the run number)")
    if not (isinstance(b["method_table_heading"], str) and b["method_table_heading"].strip()):
        raise ConfigError("baseline.method_table_heading must be a non-empty string")
    _str_list(b["companion_suffixes"], "baseline.companion_suffixes",
              lambda x: re.fullmatch(r"[A-Za-z0-9_-]+", x) is not None)
    if not (isinstance(b["review_heading"], str) and b["review_heading"].strip()):
        raise ConfigError("baseline.review_heading must be a non-empty string")
    for k in ("fallback_file",):
        if b[k] is not None and not (isinstance(b[k], str) and b[k] and os.sep not in b[k]):
            raise ConfigError(f"baseline.{k} must be null or a file name inside baseline.dir")
    _str_list(b["fallback_also_read"], "baseline.fallback_also_read", lambda x: os.sep not in x)
    if b["fallback_date"] is not None and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(b["fallback_date"])):
        raise ConfigError("baseline.fallback_date must be null or YYYY-MM-DD")
    if b["method_table_file"] is not None and not (isinstance(b["method_table_file"], str)
                                                   and b["method_table_file"]):
        raise ConfigError("baseline.method_table_file must be null or a non-empty path")
    m = cfg["models"]
    for leg in ("gemini", "codex"):
        if not isinstance(m[leg].get("model"), str):
            raise ConfigError(f"models.{leg}.model must be a string (empty: not configured)")
        binary = m[leg].get("binary")
        if binary is not None and not isinstance(binary, str):
            raise ConfigError(f"models.{leg}.binary must be null (default name) or a path")
        if binary == "" and isinstance(m[leg].get("model"), str) and m[leg]["model"]:
            raise ConfigError(f"models.{leg}.binary is empty for a configured model; give a path "
                              "or null for the default binary name")
        if m[leg]["model"] and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}", m[leg]["model"]):
            raise ConfigError(f"models.{leg}.model has unexpected characters")
    if m["gemini"]["list_args"]:
        _str_list(m["gemini"]["list_args"], "models.gemini.list_args")
    elif m["gemini"]["list_args"] != []:
        raise ConfigError("models.gemini.list_args must be a list")
    d = cfg["db"]
    if d["config_file"] is not None and not (isinstance(d["config_file"], str) and d["config_file"]):
        raise ConfigError("db.config_file must be null or a non-empty path")
    _str_list(d["readonly_aliases"], "db.readonly_aliases")
    _str_list(d["public_post_types"], "db.public_post_types")
    if not isinstance(d["installs"], dict):
        raise ConfigError("db.installs must be an object")
    for name, inst in d["installs"].items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise ConfigError(f"db.installs: bad install name {name!r}")
        if not isinstance(inst, dict):
            raise ConfigError(f"db.installs.{name} must be an object")
        unknown = set(inst) - set(INSTALL_DEFAULTS)
        if unknown:
            raise ConfigError(f"db.installs.{name}: unknown key(s) {sorted(unknown)}")
        _validate_install(name, inst)
    if cfg["redaction"]["extra_params"] != []:
        _str_list(cfg["redaction"]["extra_params"], "redaction.extra_params")
    return cfg


def _read_private(path):
    """The file's text. Opened non-blocking and without following a symlink, so a FIFO or
    device is refused by the fstat check instead of hanging the open."""
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as e:
        raise ConfigError(f"cannot open config {path}: {e.strerror or e}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"config {path} is not a regular file")
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise ConfigError(f"config {path} is not owned by the current user")
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise ConfigError(f"config {path} is writable by group or others "
                              f"(mode {oct(stat.S_IMODE(st.st_mode))}); chmod 600 it")
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~getattr(os, "O_NONBLOCK", 0))
        data = b""
        while len(data) <= MAX_CONFIG_BYTES:
            chunk = os.read(fd, MAX_CONFIG_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
    except OSError as e:
        raise ConfigError(f"cannot read config {path}: {e.strerror or e}")
    finally:
        os.close(fd)
    if len(data) > MAX_CONFIG_BYTES:
        raise ConfigError(f"config {path} is larger than 1 MiB; refused (not truncated)")
    if data.startswith(b"\xef\xbb\xbf") or data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        raise ConfigError(f"config {path} starts with a byte-order mark; save it as UTF-8 "
                          "without a BOM")
    if b"\x00" in data:
        raise ConfigError(f"config {path} contains NUL bytes (UTF-16?); save it as UTF-8")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ConfigError(f"config {path} is not valid UTF-8 (byte {e.start})") from None


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ConfigError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _too_deep(data):
    stack = [(data, 1)]
    while stack:
        v, d = stack.pop()
        if d > MAX_CONFIG_DEPTH:
            return True
        if isinstance(v, dict):
            stack.extend((x, d + 1) for x in v.values())
        elif isinstance(v, list):
            stack.extend((x, d + 1) for x in v)
    return False


def load_config(path=None, environ=None):
    """Return the effective configuration (a dict). ``cfg['_source']`` records where it came
    from: the file path, or 'defaults' when the default file does not exist."""
    p, source = resolve_path(path, environ)
    try:
        if os.path.islink(p):
            raise ConfigError(f"config {p} is a symlink")
        text = _read_private(p)
    except FileNotFoundError:
        if source != "default":
            raise ConfigError(f"config {p} (from the {source}) does not exist")
        cfg = copy.deepcopy(DEFAULTS)
        cfg["_source"] = "defaults"
        return cfg
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicates)
    except ConfigError as e:
        raise ConfigError(f"config {p}: {e}") from None
    except (ValueError, RecursionError) as e:
        raise ConfigError(f"config {p} is not valid JSON: {str(e)[:200]}") from None
    if _too_deep(data):
        raise ConfigError(f"config {p} nests deeper than {MAX_CONFIG_DEPTH} levels")
    if not isinstance(data, dict):
        raise ConfigError(f"config {p} must hold a JSON object")
    data.pop("_comment", None)
    cfg = _merge(DEFAULTS, data, "")
    validate(cfg)
    cfg["_source"] = p
    return cfg


def install_settings(cfg, name):
    """The full settings of one db install (defaults filled in), or KeyError."""
    inst = cfg["db"]["installs"][name]
    out = copy.deepcopy(INSTALL_DEFAULTS)
    out.update(copy.deepcopy(inst))
    if out["public_post_types"] is None:
        out["public_post_types"] = list(cfg["db"]["public_post_types"])
    return out


def run_root(cfg, home=None):
    return os.path.abspath(expand(cfg["run_root"], home))


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Print the effective Site Audit Kit configuration.")
    ap.add_argument("--config", help=f"config file (else ${ENV_VAR}, else {DEFAULT_PATH})")
    a = ap.parse_args(argv)
    try:
        cfg = load_config(a.config)
    except ConfigError as e:
        print(f"audit_config: {e}", file=sys.stderr)
        return 2
    print(json.dumps(cfg, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
