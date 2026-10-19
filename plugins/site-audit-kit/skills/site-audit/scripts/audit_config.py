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

The file must be a regular file, not a symlink, owned by the current user and not writable by
group or others: whoever can write it can widen the host allowlist.

Unknown keys are refused (a misspelt key would otherwise be silently ignored). Lists replace
the default list; objects are merged key by key with the defaults.

``python3 audit_config.py [--config PATH]`` prints the effective configuration and exits 0, or
prints the error and exits 2.
"""
from __future__ import annotations

import copy
import json
import os
import re
import stat
import sys

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

#: State-changing tools (start, resume, load or pause a crawl; write an export or report).
#: sfcall.sh refuses these unless SITE_AUDIT_SUPERVISED=1 is set in its environment, which
#: sf_supervise.py sets for its own calls only; listing one in allowed_tools is not enough.
#: Crawls go through sf_supervise.py only.
SF_SUPERVISED_TOOLS = [
    "sf_crawl", "sf_resume_crawl", "sf_load_crawl", "sf_pause_crawl",
    "sf_export_seo_element_urls", "sf_generate_bulk_export", "sf_generate_report",
]
SUPERVISED_ENV = "SITE_AUDIT_SUPERVISED"


def sf_supervised_only(tool):
    """True for a tool sfcall.sh only runs under SITE_AUDIT_SUPERVISED=1: the listed
    state-changing tools and any sf_export_* tool."""
    return tool in SF_SUPERVISED_TOOLS or tool.startswith("sf_export_")


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
    if tool in SF_NEVER_TOOLS:
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
        # Findings file names. Named groups: date (YYYY-MM-DD) and optional n (same-day suffix).
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
        # A note whose name matches this gets the row prefix R<group 1>.
        "notes_run_regex": r"^screaming-frog-run(\d+)-\d{4}-\d{2}-\d{2}",
        # Optional markdown file with a "| ID | P/A | finding | measured in |" table.
        "method_table_file": None,
        # The "## " heading that starts the method table section.
        "method_table_heading": "re-test table",
    },
    "models": {
        # Independent reviewer legs. An empty model means "not configured" (advisory).
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


class ConfigError(Exception):
    """The configuration could not be read or is invalid."""


_HOST_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _host_ok(h):
    if not isinstance(h, str) or not h or not h.isascii() or h != h.lower() or len(h) > 253:
        return False
    return all(_HOST_LABEL.match(lab) for lab in h.split("."))


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
    if explicit:
        return os.path.abspath(expand(explicit)), "argument"
    if env.get(ENV_VAR):
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
    if not isinstance(cfg["run_root"], str) or not cfg["run_root"]:
        raise ConfigError("run_root must be a non-empty path")
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
    for k in ("health_urls",):
        _str_list(c[k], f"crawl.{k}")
    for k in ("status_urls", "html_urls"):
        _str_list(cfg["health"][k], f"health.{k}")
    s = cfg["screaming_frog"]
    if not isinstance(s["mcp_url"], str) or not re.match(r"^https?://", s["mcp_url"]):
        raise ConfigError("screaming_frog.mcp_url must be an http(s) URL")
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
    _regex(b["findings_regex"], "baseline.findings_regex", ("date",))
    _regex(b["notes_regex"], "baseline.notes_regex", ("date",))
    _regex(b["notes_run_regex"], "baseline.notes_run_regex")
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
    if b["method_table_file"] is not None and not isinstance(b["method_table_file"], str):
        raise ConfigError("baseline.method_table_file must be null or a path")
    m = cfg["models"]
    for leg in ("gemini", "codex"):
        if not isinstance(m[leg].get("model"), str):
            raise ConfigError(f"models.{leg}.model must be a string (empty: not configured)")
        if not isinstance(m[leg].get("binary"), str):
            raise ConfigError(f"models.{leg}.binary must be a string")
        if m[leg]["model"] and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}", m[leg]["model"]):
            raise ConfigError(f"models.{leg}.model has unexpected characters")
    if m["gemini"]["list_args"]:
        _str_list(m["gemini"]["list_args"], "models.gemini.list_args")
    elif m["gemini"]["list_args"] != []:
        raise ConfigError("models.gemini.list_args must be a list")
    d = cfg["db"]
    if d["config_file"] is not None and not isinstance(d["config_file"], str):
        raise ConfigError("db.config_file must be null or a path")
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
    if cfg["redaction"]["extra_params"] != []:
        _str_list(cfg["redaction"]["extra_params"], "redaction.extra_params")
    return cfg


def _read_private(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
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
        with os.fdopen(fd, "rb") as f:
            fd = None
            return f.read(1 << 20).decode("utf-8")
    finally:
        if fd is not None:
            os.close(fd)


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
        data = json.loads(text)
    except ValueError as e:
        raise ConfigError(f"config {p} is not valid JSON: {e}")
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
