#!/usr/bin/env python3
"""sql_guard: the statement guard and grant classifier for read-only audit DB access.

Standard library only. No database driver is imported here; ``GuardedConnection`` wraps a
connection object you already opened (mysql.connector style: ``conn.cursor()``,
``cursor.execute(sql)``, ``cursor.fetchall()``, ``cursor.description``, ``cursor.close()``).

Installs (one per WordPress database you audit) come from the Site Audit Kit config
(``db.installs``), each with its table prefix, schema, public post types and the option names,
meta keys and extra tables it may read. The defaults are generic WordPress core plus the Rank
Math and Yoast meta prefixes.

Three entry points, all fail closed:

``classify_grants(lines, allowed_databases=None) -> (is_select_only, reasons)``
    SELECT-only means every ``SHOW GRANTS`` line is ``USAGE`` or ``SELECT`` (global,
    database, table or column level) and there is no role grant, no ``PROXY``, no ``FILE``, no
    dynamic privilege and no ``WITH GRANT OPTION``. Any line that cannot be parsed makes the
    identity not SELECT-only. ``allowed_databases`` optionally narrows further (the read-only DB
    user check: every SELECT grant must name e.g. ``audit_site`` exactly; a database-level
    grant must print the name with escaped underscores, ``audit\\_site``.*, because an
    unescaped ``_`` there is a wildcard). Grant text in reasons is passed through
    ``redact_grant``.

``check_statement(sql, install, ...) -> Verdict``
    A real tokenizer plus a structural parser for the SELECT subset an audit needs. It
    enforces the statement guard and the table, column and row allowlist of the given install.
    ``Verdict`` is truthy only when the statement is allowed; ``verdict.reasons`` says why not.

``GuardedConnection(conn, install, log_path, *, attended=False)``
    Issues ``SET SESSION TRANSACTION READ ONLY`` first, verifies it took effect, then
    establishes the identity (``CURRENT_USER()`` plus ``SHOW GRANTS`` through
    ``classify_grants``) and refuses to start unless it is SELECT-only. Only with
    ``attended=True`` (an operator watching) does a non-SELECT-only identity continue, with a
    loud warning on stderr and in the log. After that it lets only
    ``check_statement``-approved SQL through ``execute``. Every statement (never the result
    rows) is appended to ``log_path`` (mode 600) as one JSON line.

The guard is a filter, not a permission: the real boundary is a SELECT-only database user
(the read-only DB user).

Rules that are deliberately fail closed because they cannot be checked mechanically are
listed in ``FAIL_CLOSED_RULES`` (and repeated in the rejection reason when they fire).

CLI (for a quick manual check, no DB involved):
    python3 sql_guard.py [--config PATH] --install site "SELECT ID FROM wp_posts WHERE post_type='page'"
    python3 sql_guard.py --grants grants.txt
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

__all__ = [
    "classify_grants",
    "redact_grant",
    "load_installs",
    "check_statement",
    "Verdict",
    "InstallPolicy",
    "GuardedConnection",
    "GuardRejected",
    "GuardSetupError",
    "FUNCTION_ALLOWLIST",
    "FAIL_CLOSED_RULES",
]

# --------------------------------------------------------------------------------------
# Policy data (statement guard and WordPress table allowlist)
# --------------------------------------------------------------------------------------

#: Functions the statement guard accepts. Extend only with a built-in function confirmed to
#: have no side effects, and record the addition in the run log.
FUNCTION_ALLOWLIST = frozenset({
    "COUNT", "SUM", "MIN", "MAX", "AVG", "LENGTH", "CHAR_LENGTH", "LOWER", "UPPER",
    "SUBSTRING", "SUBSTRING_INDEX", "LEFT", "RIGHT", "CONCAT", "CONCAT_WS", "GROUP_CONCAT",
    "COALESCE", "IFNULL", "IF", "NULLIF", "REPLACE", "LOCATE", "INSTR", "TRIM", "DATE",
    "DATE_FORMAT", "CAST", "CONVERT", "HEX", "DISTINCT", "CURRENT_USER", "VERSION",
    "DATABASE",
})
_ZERO_ARG_FUNCS = frozenset({"CURRENT_USER", "VERSION", "DATABASE"})

# Table base names (without the prefix).
_POSTS, _POSTMETA, _OPTIONS = "posts", "postmeta", "options"
_RESTRICTED_BASES = frozenset({_POSTS, _POSTMETA, _OPTIONS})
#: Default extra (unrestricted) tables; an install's ``extra_tables`` replaces this.
_UNRESTRICTED_BASES = frozenset({"terms", "term_taxonomy", "term_relationships"})
#: Never readable, whatever the config says (any other table not on the allowlist is rejected
#: too; these get a sharper message).
_FORBIDDEN_BASES = frozenset({"users", "usermeta", "comments", "commentmeta"})

_POSTS_COLUMNS = frozenset({
    "id", "post_type", "post_status", "post_name", "post_title", "post_parent",
    "post_date", "post_modified",
})
_POSTS_CONTENT = "post_content"
_POSTMETA_COLUMNS = frozenset({"meta_id", "post_id", "meta_key", "meta_value"})
_OPTIONS_COLUMNS = frozenset({"option_id", "option_name", "option_value", "autoload"})
_ALLOWED_COLUMNS = {
    _POSTS: _POSTS_COLUMNS | {_POSTS_CONTENT},
    _POSTMETA: _POSTMETA_COLUMNS,
    _OPTIONS: _OPTIONS_COLUMNS,
}
#: Full WordPress core schemas of the restricted tables, used so a select-list alias can
#: never shadow a real restricted column.
_RESTRICTED_FULL_COLUMNS = frozenset({
    "id", "post_author", "post_date", "post_date_gmt", "post_content", "post_title",
    "post_excerpt", "post_status", "comment_status", "ping_status", "post_password",
    "post_name", "to_ping", "pinged", "post_modified", "post_modified_gmt",
    "post_content_filtered", "post_parent", "guid", "menu_order", "post_type",
    "post_mime_type", "comment_count", "meta_id", "post_id", "meta_key", "meta_value",
    "option_id", "option_name", "option_value", "autoload",
})

#: WordPress defaults; each install may replace them in the config.
ALLOWED_OPTION_NAMES = frozenset({"siteurl", "home", "permalink_structure", "blog_public"})
ALLOWED_META_KEYS = frozenset({"_wp_page_template"})
ALLOWED_META_PREFIXES = ("rank_math_", "_yoast_wpseo_")
TEMPLATE_POST_TYPES = frozenset()
#: Conservative default. Pass the real list (``wp post-type list --public=1``) per install.
DEFAULT_PUBLIC_POST_TYPES = ("post", "page")
#: Full core column sets, so a configured column allowlist can only narrow to real columns.
_CORE_COLUMNS = {
    _POSTS: frozenset({
        "id", "post_author", "post_date", "post_date_gmt", "post_content", "post_title",
        "post_excerpt", "post_status", "comment_status", "ping_status", "post_password",
        "post_name", "to_ping", "pinged", "post_modified", "post_modified_gmt",
        "post_content_filtered", "post_parent", "guid", "menu_order", "post_type",
        "post_mime_type", "comment_count"}),
    _POSTMETA: frozenset({"meta_id", "post_id", "meta_key", "meta_value"}),
    _OPTIONS: frozenset({"option_id", "option_name", "option_value", "autoload"}),
}
#: Never allowed even when a config lists them.
_NEVER_COLUMNS = frozenset({"post_password"})

_SYSTEM_SCHEMAS = frozenset({"information_schema", "mysql", "performance_schema", "sys"})

FAIL_CLOSED_RULES = {
    "star_over_restricted": "SELECT * (or alias.*) over wp_posts, wp_postmeta or wp_options "
                            "on an admin connection: the column list cannot be proven.",
    "unqualified_multi_table": "An unqualified column in a query block that reads a "
                               "restricted table together with another table: which table "
                               "owns it cannot be proven. Qualify it (p.post_title).",
    "unqualified_in_nested": "An unqualified column inside a subquery nested in a query on a "
                             "restricted table: MySQL may resolve it to the outer restricted "
                             "table. Qualify it.",
    "row_filter_shape": "Row restrictions (wp_options names, post_content publish/public, "
                        "wp_postmeta keys and published parent, revision exclusion) are only "
                        "recognised as top-level AND conjuncts of the exact forms "
                        "col = 'lit', col IN ('lit', ...), col LIKE 'prefix%', "
                        "col <> 'revision', col NOT IN (...), a.post_id = p.ID. Anything "
                        "else (OR, CASE, functions, subqueries, ESCAPE, COLLATE, strings with "
                        "backslash escapes) does not count as a filter.",
    "left_join_filters": "ON conditions of a LEFT JOIN restrict only the joined (right) "
                         "table; RIGHT, NATURAL and FULL joins and parenthesised join lists "
                         "are rejected outright.",
    "comment_in_identifier": "Comment markers inside backtick identifiers: rule 0 allows "
                             "them only inside string literals.",
    "double_quotes": "Double-quoted strings: under ANSI_QUOTES they are identifiers.",
    "backslash_ambiguity": "A string whose boundaries differ with and without "
                           "NO_BACKSLASH_ESCAPES (e.g. 'it\\'s'): use '' to escape a quote.",
    "non_ascii": "Non-ASCII characters outside string literals and backtick identifiers.",
    "charset_introducer": "Charset introducers (_utf8mb4'x').",
    "recursive_cte": "WITH RECURSIVE (unbounded on MariaDB).",
    "cte_column_list": "CTE or derived-table column lists.",
    "index_hints": "Index hints, PARTITION, LATERAL, JSON_TABLE and other table functions.",
    "params": "DB-API parameters: the client interpolates them after the check, so the "
              "checked text would not be the executed text.",
    "qualified_schema": "Schema-qualified names other than the install's own read-only "
                        "schema (or its configured WordPress database on an admin "
                        "connection).",
    "residue_shape": "The revision-residue exception accepts only COUNT(*) / COUNT(DISTINCT "
                     "<id>) over revision rows of wp_posts (optionally joined to wp_postmeta "
                     "by m.post_id = p.ID with meta_key = <the install's residue_meta_key>), "
                     "filtered by LIKE '%<host>%' for the install's configured residue_hosts "
                     "and nothing else.",
    "postmeta_join_form": "wp_postmeta on an admin connection is allowed only when joined "
                          "(inner join or WHERE) to a wp_posts alias in the same block by "
                          "m.post_id = p.ID, with that alias filtered to post_status = "
                          "'publish' and public types or builder templates; a subquery "
                          "(post_id IN (SELECT ...)) does not count.",
}


@dataclass(frozen=True)
class InstallPolicy:
    """How one install is reached and what it may read.

    ``views=True`` means the connection's default database is a read-only schema whose views
    already enforce the column and row restrictions. The guard still applies every column and
    row check it applies on an admin connection (defence in depth: a wrongly defined view must
    not widen access), so the same audit query text works in both modes. ``views`` only adds
    the ``DATABASE()`` check in ``GuardedConnection``. ``schema`` is the only schema qualifier
    accepted (the read-only schema, or the WordPress database name on an admin connection if
    you set it).

    ``option_names``, ``meta_keys``, ``meta_prefixes``, ``template_post_types`` and
    ``extra_tables`` are the row and table allowlist. ``columns`` optionally narrows the
    readable columns of posts, postmeta or options. ``residue_hosts`` enables the
    revision-residue count for those hosts only (empty: the exception is off).
    """

    name: str
    prefix: str = "wp_"
    views: bool = False
    schema: Optional[str] = None
    public_post_types: Sequence[str] = DEFAULT_PUBLIC_POST_TYPES
    attended_only: bool = False
    option_names: frozenset = ALLOWED_OPTION_NAMES
    meta_keys: frozenset = ALLOWED_META_KEYS
    meta_prefixes: tuple = ALLOWED_META_PREFIXES
    template_post_types: frozenset = TEMPLATE_POST_TYPES
    extra_tables: frozenset = _UNRESTRICTED_BASES
    columns: tuple = ()
    residue_hosts: tuple = ()
    residue_meta_key: str = "_elementor_data"

    @property
    def allowed_bases(self):
        return _RESTRICTED_BASES | frozenset(self.extra_tables)

    def allowed_columns(self, base):
        default = {_POSTS: _POSTS_COLUMNS | {_POSTS_CONTENT}, _POSTMETA: _POSTMETA_COLUMNS,
                   _OPTIONS: _OPTIONS_COLUMNS}[base]
        override = dict(self.columns).get(base)
        return frozenset(override) if override is not None else default

    @property
    def residue_patterns(self):
        return frozenset(f"%{h}%" for h in self.residue_hosts)


_PREFIX_RE = re.compile(r"[A-Za-z0-9_]{1,32}")
_SCHEMA_RE = re.compile(r"[A-Za-z0-9_]{1,64}")
_EXTRA_TABLE_RE = re.compile(r"[a-z0-9_]{1,64}")
#: Core tables an extra table may never resolve to, under any prefix: an extra table whose
#: FULL name (prefix + extra table) ends with one of these is refused, so a split such as
#: prefix "wp" + extra "_users", or prefix "wp_po" + extra "sts", cannot reopen them.
_PROTECTED_BASES = _FORBIDDEN_BASES | _RESTRICTED_BASES


def _check_prefix(prefix, where="table prefix"):
    if not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix):
        raise ValueError(f"bad {where} {prefix!r} (1 to 32 of A-Z a-z 0-9 _)")
    return prefix


def _check_extra_tables(prefix, extra, where):
    """Refuse any extra table whose full resolved name is a protected core table."""
    pre = _check_prefix(prefix).lower()
    for t in extra:
        if not isinstance(t, str) or not _EXTRA_TABLE_RE.fullmatch(t):
            raise ValueError(f"{where}: bad extra table {t!r} (lowercase a-z 0-9 _ only)")
        full = pre + t
        hit = sorted(b for b in _PROTECTED_BASES if full.endswith(b))
        if hit:
            raise ValueError(f"{where}: extra table {t!r} resolves to {full!r}, which ends with "
                             f"the core table name {hit[0]!r} (users, usermeta, comments, "
                             "commentmeta, posts, postmeta and options can never be extra tables)")


def _validate_policy(pol, where=None):
    """Type and value checks every InstallPolicy must pass, however it was built.

    Run on every resolution (config, a hand-built InstallPolicy, a --prefix override), so the
    prefix and extra tables are always checked together."""
    where = where or f"install {pol.name}"
    if not isinstance(pol.name, str) or not pol.name:
        raise ValueError("install name must be a non-empty string")
    _check_prefix(pol.prefix)
    for key in ("views", "attended_only"):
        if not isinstance(getattr(pol, key), bool):
            raise ValueError(f"{where}: {key} must be true or false (a JSON boolean)")
    if pol.schema is not None and not (isinstance(pol.schema, str)
                                       and _SCHEMA_RE.fullmatch(pol.schema)):
        raise ValueError(f"{where}: bad schema name {pol.schema!r}")
    if pol.views and not pol.schema:
        raise ValueError(f"{where}: views=true needs schema")
    for key in ("public_post_types", "option_names", "meta_keys", "meta_prefixes",
                "template_post_types", "residue_hosts"):
        v = getattr(pol, key)
        if isinstance(v, (str, bytes)) or not isinstance(v, (list, tuple, frozenset, set)) \
                or not all(isinstance(x, str) and x for x in v):
            raise ValueError(f"{where}: {key} must be a list of strings")
    if isinstance(pol.extra_tables, (str, bytes)) or \
            not isinstance(pol.extra_tables, (list, tuple, frozenset, set)):
        raise ValueError(f"{where}: extra_tables must be a list of strings")
    _check_extra_tables(pol.prefix, pol.extra_tables, where)
    for base, cols in pol.columns:
        if base not in _CORE_COLUMNS or isinstance(cols, (str, bytes)) or \
                not all(isinstance(c, str) for c in cols):
            raise ValueError(f"{where}: bad columns entry {base!r}")
        if not frozenset(cols) <= _CORE_COLUMNS[base] or frozenset(cols) & _NEVER_COLUMNS:
            raise ValueError(f"{where}: columns.{base} must be WordPress core columns "
                             "(post_password is never allowed)")
    if not isinstance(pol.residue_meta_key, str) or \
            not re.fullmatch(r"[A-Za-z0-9_-]+", pol.residue_meta_key):
        raise ValueError(f"{where}: residue_meta_key must be a plain meta key")
    return pol


def _policy_from_settings(name, st):
    """Build and validate an InstallPolicy from one install's config settings.

    Values are type checked, never coerced: views and attended_only must be JSON booleans,
    every list a list of non-empty strings, prefix 1 to 32 of [A-Za-z0-9_], schema a plain
    identifier."""
    where = f"install {name}"

    def strs(key):
        v = st.get(key)
        if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
            raise ValueError(f"{where}: {key} must be a list of strings")
        return tuple(v)

    for key in ("views", "attended_only"):
        if not isinstance(st.get(key), bool):
            raise ValueError(f"{where}: {key} must be true or false (a JSON boolean), "
                             f"got {st.get(key)!r}")
    prefix = _check_prefix(st.get("prefix"), f"{where}: table prefix")
    # Table names are compared lowercased (MySQL on macOS and Windows folds case).
    extra = frozenset(x.lower() for x in strs("extra_tables"))
    bad = extra & _PROTECTED_BASES
    if bad:
        raise ValueError(f"{where}: extra_tables may not name {sorted(bad)}")
    _check_extra_tables(prefix, extra, where)
    cols = st.get("columns")
    if not isinstance(cols, dict):
        raise ValueError(f"{where}: columns must be an object")
    col_items = []
    for base, lst in cols.items():
        if base not in _CORE_COLUMNS:
            raise ValueError(f"{where}: columns key must be posts, postmeta or options")
        if not isinstance(lst, list) or not all(isinstance(c, str) and c for c in lst):
            raise ValueError(f"{where}: columns.{base} must be a list of strings")
        low = frozenset(c.lower() for c in lst)
        if not low <= _CORE_COLUMNS[base] or low & _NEVER_COLUMNS:
            raise ValueError(f"{where}: columns.{base} must be WordPress core columns "
                             "(post_password is never allowed)")
        col_items.append((base, low))
    hosts = strs("residue_hosts")
    for h in hosts:
        if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", h) or "%" in h or "_" in h:
            raise ValueError(f"{where}: bad residue host {h!r}")
    rmk = st.get("residue_meta_key")
    if not isinstance(rmk, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", rmk):
        raise ValueError(f"{where}: residue_meta_key must be a plain meta key")
    schema = st.get("schema")
    if schema is not None and not (isinstance(schema, str) and _SCHEMA_RE.fullmatch(schema)):
        raise ValueError(f"{where}: bad schema name {schema!r}")
    if st["views"] and not schema:
        raise ValueError(f"{where}: views=true needs schema")
    return _validate_policy(InstallPolicy(
        name=name, prefix=prefix, views=st["views"], schema=schema,
        public_post_types=strs("public_post_types"), attended_only=st["attended_only"],
        option_names=frozenset(strs("option_names")), meta_keys=frozenset(strs("meta_keys")),
        meta_prefixes=strs("meta_prefixes"), template_post_types=frozenset(strs("template_post_types")),
        extra_tables=extra, columns=tuple(sorted(col_items)), residue_hosts=hosts,
        residue_meta_key=rmk))


def load_installs(cfg=None):
    """{name: InstallPolicy} from a loaded config (or the default config resolution)."""
    import os as _os
    sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import audit_config  # noqa: E402 - sibling module
    if cfg is None:
        cfg = audit_config.load_config()
    return {name: _policy_from_settings(name, audit_config.install_settings(cfg, name))
            for name in cfg["db"]["installs"]}


_INSTALL_CACHE = {}


def _installs():
    """Installs from the config the environment points at (cached per path and mtime)."""
    import os as _os
    sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    import audit_config  # noqa: E402
    path, _src = audit_config.resolve_path()
    try:
        key = (path, _os.stat(path).st_mtime_ns)
    except OSError:
        key = (path, None)
    if key not in _INSTALL_CACHE:
        _INSTALL_CACHE.clear()
        _INSTALL_CACHE[key] = load_installs()
    return _INSTALL_CACHE[key]


def _resolve_policy(install, prefix=None, public_post_types=None, schema=None) -> InstallPolicy:
    if isinstance(install, InstallPolicy):
        pol = install
    else:
        try:
            known = _installs()
        except Exception as e:  # noqa: BLE001 - a config problem refuses every statement
            raise ValueError(f"cannot load installs from the config: {e}") from None
        try:
            pol = known[str(install)]
        except KeyError:
            raise ValueError(f"unknown install {install!r}; known: {sorted(known)}") from None
    changes = {}
    if prefix is not None:
        changes["prefix"] = prefix
    if public_post_types is not None:
        changes["public_post_types"] = tuple(public_post_types)
    if schema is not None:
        changes["schema"] = schema
    if changes:
        pol = InstallPolicy(**{**pol.__dict__, **changes})
    # Always revalidate: a --prefix override or a hand-built InstallPolicy goes through the
    # same prefix + extra-table full-name check as the config.
    return _validate_policy(pol)


# --------------------------------------------------------------------------------------
# SHOW GRANTS classification
# --------------------------------------------------------------------------------------

_GRANT_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<sq>'(?:[^'\\]|\\.|'')*')
  | (?P<dq>"(?:[^"\\]|\\.|"")*")
  | (?P<bt>`(?:[^`]|``)*`)
  | (?P<word>[A-Za-z0-9_$%:\-]+)
  | (?P<p>[(),.@*=;])
""", re.X | re.S)

_RESOURCE_LIMITS = frozenset({
    "MAX_QUERIES_PER_HOUR", "MAX_UPDATES_PER_HOUR", "MAX_CONNECTIONS_PER_HOUR",
    "MAX_USER_CONNECTIONS", "MAX_STATEMENT_TIME",
})
_STATIC_PRIVS = frozenset({
    "ALL", "ALL PRIVILEGES", "ALTER", "ALTER ROUTINE", "CREATE", "CREATE ROLE",
    "CREATE ROUTINE", "CREATE TABLESPACE", "CREATE TEMPORARY TABLES", "CREATE USER",
    "CREATE VIEW", "DELETE", "DELETE HISTORY", "DROP", "DROP ROLE", "EVENT", "EXECUTE",
    "FILE", "GRANT OPTION", "INDEX", "INSERT", "LOCK TABLES", "PROCESS", "PROXY",
    "REFERENCES", "RELOAD", "REPLICATION CLIENT", "REPLICATION SLAVE", "SELECT",
    "SHOW DATABASES", "SHOW VIEW", "SHUTDOWN", "SUPER", "TRIGGER", "UPDATE", "USAGE",
    "BINLOG ADMIN", "BINLOG MONITOR", "BINLOG REPLAY", "CONNECTION ADMIN",
    "FEDERATED ADMIN", "READ_ONLY ADMIN", "REPLICATION MASTER ADMIN",
    "REPLICATION SLAVE ADMIN", "SET USER", "SLAVE MONITOR", "REPLICA MONITOR",
})


class _GrantParseError(Exception):
    pass


@dataclass
class _GTok:
    kind: str  # 'q' (any quoted), 'word', 'p'
    text: str  # unquoted value for q, raw for word/p
    quote: str = ""

    @property
    def up(self):
        return self.text.upper() if self.kind == "word" else None


def _grant_tokens(line: str):
    toks = []
    pos = 0
    while pos < len(line):
        m = _GRANT_TOKEN_RE.match(line, pos)
        if not m:
            raise _GrantParseError(f"unexpected character {line[pos]!r} at {pos}")
        pos = m.end()
        kind = m.lastgroup
        txt = m.group(kind)
        if kind == "ws":
            continue
        if kind in ("sq", "dq", "bt"):
            q = txt[0]
            body = txt[1:-1].replace(q * 2, q)
            toks.append(_GTok("q", body, q))
        else:
            toks.append(_GTok(kind, txt))
    return toks


def _show(t) -> str:
    """A token for an error message. Quoted tokens are never echoed: in a grant line they can
    be a password hash or an authentication string."""
    return "<quoted string>" if t.kind == "q" else repr(t.text)


_REDACT_AT_RE = re.compile(r"\b(?:IDENTIFIED|PASSWORD)\b", re.I)
_REDACT_STR_RE = re.compile(r"""'(?:[^'\\]|\\.|'')*(?:'|\\?$)|"(?:[^"\\]|\\.|"")*(?:"|\\?$)""", re.S)


def redact_grant(line: str) -> str:
    """Return ``line`` safe to log or show: everything from the first ``IDENTIFIED`` or
    ``PASSWORD`` word onwards (``IDENTIFIED BY [PASSWORD] '...'``, ``IDENTIFIED WITH plugin
    AS '...'``, ``IDENTIFIED VIA plugin USING '...'``, ``PASSWORD('...')``) is replaced by
    ``<redacted>``. Matching is on the raw text, quotes included, so it also fires when the
    word sits inside a quoted name. Then every single- or double-quoted string left (an
    unterminated one runs to the end of the line) becomes ``'<redacted>'``: in a line the
    parser could not read, a quoted token can be anything. Backtick names are kept, so the
    user and host stay readable in the MySQL 8 / MariaDB form. Over-redaction is the
    intended failure mode."""
    if not isinstance(line, str):
        line = str(line)
    m = _REDACT_AT_RE.search(line)
    if m:
        line = line[:m.start()] + m.group(0).upper() + " <redacted>"
    return _REDACT_STR_RE.sub(lambda mm: mm.group(0)[0] + "<redacted>" + mm.group(0)[0], line)


def _classify_priv(name: str) -> str:
    if name in ("USAGE", "SELECT"):
        return ""
    if name in ("ALL", "ALL PRIVILEGES"):
        return "ALL PRIVILEGES"
    if name == "FILE":
        return "FILE privilege (SELECT ... INTO OUTFILE / LOAD_FILE)"
    if name == "PROXY":
        return "PROXY privilege"
    if name == "GRANT OPTION":
        return "GRANT OPTION"
    if name in _STATIC_PRIVS:
        return f"{name} privilege"
    if "_" in name or name.endswith("ADMIN"):
        return f"dynamic privilege {name}"
    return f"unknown privilege {name}"


def _parse_grant_line(line: str):
    """Return (ok, reason, info). ok=False means not SELECT-only (reason says why)."""
    toks = _grant_tokens(line)
    if not toks:
        raise _GrantParseError("empty line")
    if toks[-1].kind == "p" and toks[-1].text == ";":
        toks = toks[:-1]
    if toks[0].up != "GRANT":
        first = toks[0].text.upper()
        if first == "REVOKE":
            return False, "REVOKE line (partial revokes imply a broader grant)", None
        if first == "SET" and len(toks) > 2 and toks[1].up == "DEFAULT" and toks[2].up == "ROLE":
            return False, "default role set (role grant)", None
        raise _GrantParseError("line does not start with GRANT")
    i = 1
    if i < len(toks) and toks[i].up == "PROXY":
        return False, "PROXY grant", None

    # ---- privilege list, up to ON at depth 0. No ON at all means a role grant.
    depth = 0
    on_idx = None
    to_idx = None
    for j in range(i, len(toks)):
        t = toks[j]
        if t.kind == "p" and t.text == "(":
            depth += 1
        elif t.kind == "p" and t.text == ")":
            depth -= 1
        elif depth == 0 and t.up == "ON" and on_idx is None:
            on_idx = j
            break
        elif depth == 0 and t.up == "TO":
            to_idx = j
            break
    if on_idx is None:
        if to_idx is not None:
            return False, "role grant (GRANT <role> TO <user>)", None
        raise _GrantParseError("no ON or TO clause")

    privs = []
    cur_words = []
    cur_cols = None
    j = i
    while j < on_idx:
        t = toks[j]
        if t.kind == "word":
            if cur_cols is not None:
                raise _GrantParseError("privilege word after column list")
            cur_words.append(t.up)
            j += 1
        elif t.kind == "p" and t.text == "(":
            if not cur_words:
                raise _GrantParseError("column list without privilege")
            k = j + 1
            cols = []
            expect_name = True
            while k < on_idx and not (toks[k].kind == "p" and toks[k].text == ")"):
                tk = toks[k]
                if expect_name and tk.kind in ("word", "q"):
                    cols.append(tk.text)
                    expect_name = False
                elif not expect_name and tk.kind == "p" and tk.text == ",":
                    expect_name = True
                else:
                    raise _GrantParseError("bad column list")
                k += 1
            if k >= on_idx or expect_name:
                raise _GrantParseError("unterminated or empty column list")
            cur_cols = cols
            j = k + 1
        elif t.kind == "p" and t.text == ",":
            if not cur_words:
                raise _GrantParseError("empty privilege")
            privs.append((" ".join(cur_words), cur_cols))
            cur_words, cur_cols = [], None
            j += 1
        else:
            raise _GrantParseError(f"unexpected token {_show(t)} in privilege list")
    if not cur_words:
        raise _GrantParseError("empty privilege list")
    privs.append((" ".join(cur_words), cur_cols))

    for name, cols in privs:
        why = _classify_priv(name)
        if why:
            return False, why, None
        if cols is not None and name != "SELECT":
            return False, f"column list on {name}", None

    # ---- object
    j = on_idx + 1
    if j < len(toks) and toks[j].up in ("FUNCTION", "PROCEDURE", "PACKAGE"):
        return False, f"grant on a {toks[j].up}", None
    if j < len(toks) and toks[j].up == "TABLE":
        j += 1

    def name_part(k):
        if k >= len(toks):
            raise _GrantParseError("missing object name")
        t = toks[k]
        if t.kind == "q" and t.quote in ("`", "'", '"'):
            return t.text, k + 1
        if t.kind == "word":
            return t.text, k + 1
        if t.kind == "p" and t.text == "*":
            return "*", k + 1
        raise _GrantParseError(f"bad object name {_show(t)}")

    first, j = name_part(j)
    second = None
    if j < len(toks) and toks[j].kind == "p" and toks[j].text == ".":
        second, j = name_part(j + 1)
    if second is None:
        db, tbl = (None, first)
    else:
        db, tbl = first, second
    if db == "*" and tbl != "*":
        raise _GrantParseError("*.table is not a valid object")
    if db == "*" or (db is None and tbl == "*"):
        level = "global" if db == "*" else "database (current)"
    elif tbl == "*":
        level = "database"
    else:
        level = "table"
    if any(cols is not None for _, cols in privs):
        level = "column"

    # ---- TO user
    if j >= len(toks) or toks[j].up != "TO":
        raise _GrantParseError("expected TO after the object")
    j += 1
    if j >= len(toks) or toks[j].kind not in ("q", "word"):
        raise _GrantParseError("missing grantee")
    user = toks[j].text
    j += 1
    host = None
    if j < len(toks) and toks[j].kind == "p" and toks[j].text == "@":
        j += 1
        parts = []
        while j < len(toks) and (toks[j].kind == "q" or toks[j].kind == "word"
                                 or (toks[j].kind == "p" and toks[j].text == ".")):
            if toks[j].kind == "word" and toks[j].up in ("IDENTIFIED", "REQUIRE", "WITH"):
                break
            parts.append(toks[j].text)
            j += 1
            if parts and toks[j - 1].kind == "q":
                break
        if not parts:
            raise _GrantParseError("missing host")
        host = "".join(parts)
    if j < len(toks) and toks[j].kind == "p" and toks[j].text == ",":
        raise _GrantParseError("several grantees on one line")

    # ---- trailing clauses
    while j < len(toks):
        t = toks[j]
        if t.up == "IDENTIFIED":
            j += 1
            if j < len(toks) and toks[j].up == "BY":
                j += 1
                if j < len(toks) and toks[j].up == "PASSWORD":
                    j += 1
                if j >= len(toks) or toks[j].kind != "q":
                    raise _GrantParseError("IDENTIFIED BY without a string")
                j += 1
            elif j < len(toks) and toks[j].up in ("VIA", "WITH"):
                while True:
                    j += 1  # skip VIA / WITH / OR
                    if j >= len(toks) or toks[j].kind not in ("word", "q"):
                        raise _GrantParseError("missing auth plugin")
                    j += 1
                    if j < len(toks) and toks[j].up in ("USING", "BY", "AS"):
                        j += 1
                        if j < len(toks) and toks[j].up == "PASSWORD":
                            j += 1
                            if not (j + 2 < len(toks) and toks[j].text == "("
                                    and toks[j + 1].kind == "q" and toks[j + 2].text == ")"):
                                raise _GrantParseError("bad PASSWORD(...) form")
                            j += 3
                        else:
                            if j >= len(toks) or toks[j].kind != "q":
                                raise _GrantParseError("USING without a string")
                            j += 1
                    if j < len(toks) and toks[j].up == "OR":
                        continue
                    break
            else:
                raise _GrantParseError("unknown IDENTIFIED form")
        elif t.up == "REQUIRE":
            j += 1
            if j < len(toks) and toks[j].up in ("NONE", "SSL", "X509"):
                j += 1
            else:
                seen = False
                while j < len(toks) and toks[j].up in ("ISSUER", "SUBJECT", "CIPHER"):
                    if j + 1 >= len(toks) or toks[j + 1].kind != "q":
                        raise _GrantParseError("REQUIRE option without a string")
                    j += 2
                    seen = True
                    if j < len(toks) and toks[j].up == "AND":
                        j += 1
                if not seen:
                    raise _GrantParseError("unknown REQUIRE form")
        elif t.up == "WITH":
            j += 1
            if j >= len(toks):
                raise _GrantParseError("dangling WITH")
            seen = False
            while j < len(toks):
                w = toks[j].up
                if w == "GRANT" and j + 1 < len(toks) and toks[j + 1].up == "OPTION":
                    return False, "WITH GRANT OPTION", None
                if w == "ADMIN" and j + 1 < len(toks) and toks[j + 1].up == "OPTION":
                    return False, "WITH ADMIN OPTION (role administration)", None
                if w in _RESOURCE_LIMITS:
                    if j + 1 >= len(toks) or not re.fullmatch(r"[0-9]+", toks[j + 1].text):
                        raise _GrantParseError(f"{w} without a number")
                    j += 2
                    # MariaDB MAX_STATEMENT_TIME may be fractional: 1.5 tokenizes as 1 . 5
                    if (j + 1 < len(toks) and toks[j].kind == "p" and toks[j].text == "."
                            and re.fullmatch(r"[0-9]+", toks[j + 1].text)):
                        j += 2
                    seen = True
                    continue
                break
            if not seen:
                raise _GrantParseError("unknown WITH clause")
        else:
            raise _GrantParseError(f"unexpected trailing token {_show(t)}")

    return True, "", {
        "privileges": [n for n, _ in privs],
        "level": level,
        "database": db,
        "table": tbl,
        "user": user,
        "host": host,
    }


def _grant_db_exact(info):
    """The one database a grant line certainly names, for the read-only schema comparison, or
    ``(None, why)``.

    At database level (``db.*``) MySQL and MariaDB read ``_`` and ``%`` in the name as
    wildcards and ``\\_`` / ``\\%`` as the literal characters, and ``SHOW GRANTS`` prints the
    name as it was granted. So ``audit\\_site`` is exactly ``audit_site`` and is accepted,
    while an unescaped ``audit_site.*`` is a pattern that also matches e.g. ``auditXsite`` and
    is refused (fail closed). At table and column level the name is
    literal, so a backslash there names some other database and simply fails equality."""
    db = info["database"]
    if db in (None, "*"):
        return None, ""
    if info["table"] != "*":
        return db, ""
    out = []
    i = 0
    while i < len(db):
        c = db[i]
        if c == "\\":
            if i + 1 < len(db) and db[i + 1] in "_%\\":
                out.append(db[i + 1])
                i += 2
                continue
            return None, "unrecognised backslash escape in a database-level grant"
        if c in "_%":
            return None, ("database-level grant names a wildcard pattern; grant on the "
                          "views or write the name with escaped underscores")
        out.append(c)
        i += 1
    return "".join(out), ""


def classify_grants(lines, allowed_databases=None):
    """Classify ``SHOW GRANTS FOR CURRENT_USER()`` output.

    ``lines``: an iterable of strings, bytes, or DB-API rows (first column used).
    Returns ``(is_select_only, reasons)``. ``reasons`` lists every failing line (or, when
    the identity is SELECT-only, a one-line summary per grant).
    """
    reasons = []
    notes = []
    ok_all = True
    count = 0
    if lines is None:
        return False, ["no grant lines (None)"]
    allowed = None if allowed_databases is None else set(allowed_databases)
    for idx, raw in enumerate(lines, 1):
        if isinstance(raw, (tuple, list)):
            if len(raw) != 1:
                ok_all = False
                reasons.append(f"line {idx}: expected one column per row, got {len(raw)}")
                continue
            raw = raw[0]
        if isinstance(raw, (bytes, bytearray)):
            try:
                raw = bytes(raw).decode("utf-8")
            except UnicodeDecodeError:
                ok_all = False
                reasons.append(f"line {idx}: not valid UTF-8; cannot classify")
                continue
        if not isinstance(raw, str):
            ok_all = False
            reasons.append(f"line {idx}: not a string ({type(raw).__name__}); cannot classify")
            continue
        count += 1
        line = raw.strip()
        try:
            ok, why, info = _parse_grant_line(line)
        except _GrantParseError as e:
            ok_all = False
            reasons.append(f"line {idx}: unparseable ({e}); fail closed: "
                           f"{redact_grant(line)[:160]}")
            continue
        if not ok:
            ok_all = False
            reasons.append(f"line {idx}: {why}: {redact_grant(line)[:160]}")
            continue
        if allowed is not None and "SELECT" in info["privileges"]:
            db, why = _grant_db_exact(info)
            if db is None or db not in allowed:
                ok_all = False
                reasons.append(
                    f"line {idx}: SELECT on {info['database'] or '<current db>'}."
                    f"{info['table']} is outside the allowed schemas {sorted(allowed)}"
                    + (f" ({why})" if why else ""))
                continue
        notes.append(f"line {idx}: {'/'.join(info['privileges'])} at {info['level']} level "
                     f"on {info['database'] or '*'}.{info['table']}")
    if count == 0:
        return False, reasons + ["no grant lines; cannot classify"]
    if not ok_all:
        return False, reasons
    return True, notes


# --------------------------------------------------------------------------------------
# SQL tokenizer
# --------------------------------------------------------------------------------------

class _Reject(Exception):
    def __init__(self, reason, rule=None):
        if rule and rule in FAIL_CLOSED_RULES:
            reason = f"{reason} [fail closed: {FAIL_CLOSED_RULES[rule]}]"
        super().__init__(reason)
        self.reason = reason


@dataclass
class _Tok:
    kind: str          # ident, qident, string, number, op
    value: str         # ident text / qident name / string raw body / number / op
    pos: int
    end: int
    prefix: str = ""   # for strings: '', 'x', 'b', 'n'

    @property
    def upper(self):
        return self.value.upper() if self.kind == "ident" else ""

    def __repr__(self):
        return f"{self.kind}:{self.value!r}"


class _Group:
    __slots__ = ("children", "pos")

    def __init__(self, children, pos):
        self.children = children
        self.pos = pos

    def __repr__(self):
        return f"Group({self.children!r})"


_WS = " \t\n\r\f\v"
_IDENT_START = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$")
_IDENT_CHARS = _IDENT_START | frozenset("0123456789")
_NUM_RE = re.compile(r"0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+\.?[0-9]*(?:[eE][+-]?[0-9]+)?"
                     r"|\.[0-9]+(?:[eE][+-]?[0-9]+)?", re.ASCII)
_OPS3 = ("<=>", "->>")
_OPS2 = ("<=", ">=", "<>", "!=", "<<", ">>", "&&", "||", "->")
_OPS1 = frozenset("=<>!~+-*/%&|^(),.;")
_MAX_LEN = 200_000
_MAX_DEPTH = 48


def _scan_string(sql, i, bs):
    j = i + 1
    n = len(sql)
    while j < n:
        c = sql[j]
        if bs and c == "\\":
            j += 2
            continue
        if c == "'":
            if j + 1 < n and sql[j + 1] == "'":
                j += 2
                continue
            return j + 1, sql[i + 1:j]
        j += 1
    raise _Reject("unterminated string literal")


def _tokenize(sql, bs):
    toks = []
    i = 0
    n = len(sql)
    while i < n:
        c = sql[i]
        if c in _WS:
            i += 1
            continue
        if ord(c) > 127:
            raise _Reject(f"non-ASCII character U+{ord(c):04X} outside a string literal "
                          f"at offset {i}", "non_ascii")
        if c == "#":
            raise _Reject("comment ('#') outside a string literal")
        if sql.startswith("--", i):
            raise _Reject("comment ('--') outside a string literal")
        if sql.startswith("/*", i):
            kind = "executable comment ('/*!' or '/*M!')" if sql[i + 2:i + 3] in ("!", "M") \
                else "optimizer hint ('/*+')" if sql[i + 2:i + 3] == "+" else "comment ('/*')"
            raise _Reject(f"{kind} outside a string literal")
        if sql.startswith("*/", i):
            raise _Reject("comment terminator ('*/') outside a string literal")
        if c == '"':
            raise _Reject("double-quoted string or identifier", "double_quotes")
        if c == "'":
            j, raw = _scan_string(sql, i, bs)
            toks.append(_Tok("string", raw, i, j))
            i = j
            continue
        if c in "xXbBnN" and i + 1 < n and sql[i + 1] == "'":
            j, raw = _scan_string(sql, i + 1, bs)
            p = c.lower()
            if p == "x" and not re.fullmatch(r"[0-9a-fA-F]*", raw):
                raise _Reject("malformed X'' literal")
            if p == "b" and not re.fullmatch(r"[01]*", raw):
                raise _Reject("malformed B'' literal")
            toks.append(_Tok("string", raw, i, j, prefix=p))
            i = j
            continue
        if c == "`":
            j = i + 1
            buf = []
            while True:
                k = sql.find("`", j)
                if k < 0:
                    raise _Reject("unterminated backtick identifier")
                if sql.startswith("``", k):
                    buf.append(sql[j:k] + "`")
                    j = k + 2
                    continue
                buf.append(sql[j:k])
                j = k + 1
                break
            name = "".join(buf)
            if not name:
                raise _Reject("empty backtick identifier")
            if any(mark in name for mark in ("#", "--", "/*", "*/")):
                # Harmless to MySQL (a quoted identifier is never a comment), but the
                # guard allows comment markers only inside string literals, and no
                # WordPress table, column or alias needs one.
                raise _Reject("comment marker ('#', '--', '/*' or '*/') inside a backtick "
                              "identifier", "comment_in_identifier")
            toks.append(_Tok("qident", name, i, j))
            i = j
            continue
        prev = toks[-1] if toks else None
        is_dot_number = (c == "." and i + 1 < n and sql[i + 1] in "0123456789"
                         and not (prev and prev.end == i and prev.kind in ("ident", "qident")))
        if c in "0123456789" or is_dot_number:
            m = _NUM_RE.match(sql, i)
            if not m:
                raise _Reject(f"malformed number at offset {i}")
            j = m.end()
            if j < n and (sql[j] in _IDENT_CHARS or sql[j] == "."):
                raise _Reject(f"identifier or number glued to a number at offset {i} "
                              f"({sql[i:j + 1]!r}); MySQL may read it as an identifier")
            toks.append(_Tok("number", sql[i:j], i, j))
            i = j
            continue
        if c in _IDENT_START:
            j = i + 1
            while j < n and sql[j] in _IDENT_CHARS:
                j += 1
            if j < n and sql[j] == "'":
                raise _Reject(f"charset introducer or identifier glued to a string at "
                              f"offset {i}", "charset_introducer")
            toks.append(_Tok("ident", sql[i:j], i, j))
            i = j
            continue
        if sql.startswith(":=", i):
            raise _Reject("assignment operator ':='")
        if c == "@":
            raise _Reject("user or system variable ('@')")
        if c == "?":
            raise _Reject("placeholder '?'", "params")
        if c in "{}":
            raise _Reject("ODBC escape braces")
        if c == "\\":
            raise _Reject("backslash outside a string literal")
        op = None
        for cand in _OPS3:
            if sql.startswith(cand, i):
                op = cand
                break
        if op is None:
            for cand in _OPS2:
                if sql.startswith(cand, i):
                    op = cand
                    break
        if op is None and c in _OPS1:
            op = c
        if op is None:
            raise _Reject(f"unexpected character {c!r} at offset {i}")
        toks.append(_Tok("op", op, i, i + len(op)))
        i += len(op)
    return toks


def _tree(toks):
    stack = [[]]
    opens = []
    for t in toks:
        if t.kind == "op" and t.value == "(":
            opens.append(t.pos)
            stack.append([])
            if len(stack) > _MAX_DEPTH:
                raise _Reject(f"parentheses nested deeper than {_MAX_DEPTH}")
        elif t.kind == "op" and t.value == ")":
            if len(stack) == 1:
                raise _Reject("unbalanced ')'")
            ch = stack.pop()
            stack[-1].append(_Group(ch, opens.pop()))
        else:
            stack[-1].append(t)
    if len(stack) != 1:
        raise _Reject("unbalanced '('")
    return stack[0]


# --------------------------------------------------------------------------------------
# Keyword sets
# --------------------------------------------------------------------------------------

#: Bare words that are never allowed anywhere (statement, DML/DDL, locking, file, session
#: and procedural keywords, plus constructs that read tables without FROM).
_DENY = frozenset({
    "INTO", "OUTFILE", "DUMPFILE", "INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE",
    "UPSERT", "CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME", "GRANT", "REVOKE", "SET",
    "CALL", "DO", "HANDLER", "LOAD", "LOCK", "UNLOCK", "SHARE", "KILL", "SHUTDOWN", "FLUSH",
    "RESET", "PURGE", "CHANGE", "START", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT",
    "RELEASE", "XA", "PREPARE", "EXECUTE", "DEALLOCATE", "DECLARE", "USE", "INSTALL",
    "UNINSTALL", "ANALYZE", "OPTIMIZE", "REPAIR", "CHECK", "CHECKSUM", "BACKUP", "RESTORE",
    "PROCEDURE", "FUNCTION", "TRIGGER", "EVENT", "VIEW", "TABLE", "TABLES", "VALUES",
    "SIGNAL", "RESIGNAL", "GET", "WINDOW", "OVER", "PARTITION", "RECURSIVE", "NOWAIT",
    "LOCKED", "SKIP", "LATERAL", "BINLOG", "CACHE", "IMPORT", "CLONE", "HELP", "RETURN",
    "LEAVE", "LOOP", "WHILE", "REPEAT", "ITERATE", "OPEN", "CLOSE", "FETCH", "SYSTEM_TIME",
    "DESCRIBE", "OUTPUT", "RETURNING", "MATCH", "AGAINST", "ROW", "CHARACTER", "CHARSET",
})
_DENY_MSG = {
    "INTO": "INTO (OUTFILE, DUMPFILE, @var or a table) is never allowed",
    "OUTFILE": "INTO OUTFILE writes to the DB host's disk",
    "DUMPFILE": "INTO DUMPFILE writes to the DB host's disk",
    "UPDATE": "UPDATE (including FOR UPDATE) is not allowed",
    "SHARE": "FOR SHARE / LOCK IN SHARE MODE takes locks",
    "LOCK": "LOCK (LOCK IN SHARE MODE, LOCK TABLES) takes locks",
    "SET": "SET is not allowed (the connection helper issues the only SET itself)",
    "TABLE": "the TABLE statement reads a whole table without FROM",
    "RECURSIVE": "WITH RECURSIVE is not allowed",
    "PROCEDURE": "SELECT ... PROCEDURE is not allowed",
}

_SELECT_MODIFIERS = frozenset({
    "ALL", "DISTINCT", "DISTINCTROW", "HIGH_PRIORITY", "STRAIGHT_JOIN", "SQL_SMALL_RESULT",
    "SQL_BIG_RESULT", "SQL_BUFFER_RESULT", "SQL_NO_CACHE", "SQL_CACHE", "SQL_CALC_FOUND_ROWS",
})
_CLAUSES = ("FROM", "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT")
_SETOPS = frozenset({"UNION", "INTERSECT", "EXCEPT"})
#: Words that can never be a column reference or alias.
_STRUCT = frozenset({
    "SELECT", "FROM", "WHERE", "GROUP", "HAVING", "ORDER", "BY", "LIMIT", "OFFSET", "UNION",
    "INTERSECT", "EXCEPT", "JOIN", "INNER", "CROSS", "LEFT", "RIGHT", "FULL", "NATURAL",
    "OUTER", "STRAIGHT_JOIN", "ON", "USING", "AS", "WITH", "DISTINCT", "DISTINCTROW", "ALL",
    "ANY", "SOME", "EXISTS", "IN", "IS", "BETWEEN", "ASC", "DESC", "ROLLUP", "SEPARATOR",
    "FOR", "BOTH", "LEADING", "TRAILING", "INTERVAL", "DUAL", "SHOW", "EXPLAIN", "SOUNDS",
    "AND", "OR", "XOR", "NOT", "LIKE", "REGEXP", "RLIKE", "DIV", "MOD", "ESCAPE", "CASE",
    "WHEN", "THEN", "ELSE", "END", "COLLATE", "BINARY", "NULL", "TRUE", "FALSE", "UNKNOWN",
    "FORCE", "IGNORE", "INDEX", "KEY",
}) | _SELECT_MODIFIERS
_FROM_STOP = frozenset({
    "ON", "USING", "JOIN", "INNER", "CROSS", "LEFT", "RIGHT", "FULL", "NATURAL",
    "STRAIGHT_JOIN", "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "UNION", "INTERSECT",
    "EXCEPT", "FOR", "USE", "FORCE", "IGNORE", "AS",
})
_BIN_WORDS = frozenset({"AND", "OR", "XOR", "LIKE", "REGEXP", "RLIKE", "DIV", "MOD", "ESCAPE"})
_BIN_OPS = frozenset({
    "=", "<", ">", "<=", ">=", "<>", "!=", "<=>", "+", "-", "*", "/", "%", "&", "|", "^",
    "<<", ">>", "&&", "||", "->", "->>",
})
_INTERVAL_UNITS = frozenset({
    "MICROSECOND", "SECOND", "MINUTE", "HOUR", "DAY", "WEEK", "MONTH", "QUARTER", "YEAR",
    "SECOND_MICROSECOND", "MINUTE_MICROSECOND", "MINUTE_SECOND", "HOUR_MICROSECOND",
    "HOUR_SECOND", "HOUR_MINUTE", "DAY_MICROSECOND", "DAY_SECOND", "DAY_MINUTE", "DAY_HOUR",
    "YEAR_MONTH",
})
_CAST_TYPES = frozenset({
    "BINARY", "CHAR", "NCHAR", "DATE", "DATETIME", "TIME", "DECIMAL", "SIGNED", "UNSIGNED",
    "INTEGER", "INT", "JSON", "DOUBLE", "FLOAT", "REAL",
})


def _kw(node, *words):
    return isinstance(node, _Tok) and node.kind == "ident" and node.upper in words


def _op(node, *vals):
    return isinstance(node, _Tok) and node.kind == "op" and node.value in vals


def _is_name(node):
    return isinstance(node, _Tok) and node.kind in ("ident", "qident")


def _name_of(node):
    return node.value


def _split_top(nodes, sep=","):
    out = [[]]
    for n in nodes:
        if _op(n, sep):
            out.append([])
        else:
            out[-1].append(n)
    return out


def _is_query_group(g):
    ch = g.children
    if not ch:
        return False
    f = ch[0]
    if _kw(f, "SELECT", "WITH"):
        return True
    if isinstance(f, _Group) and _is_query_group(f):
        return len(ch) == 1 or _kw(ch[1], "UNION", "INTERSECT", "EXCEPT", "ORDER", "LIMIT")
    return False


# --------------------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------------------

@dataclass
class _TRef:
    alias: str
    kind: str                 # base, cte, derived, dual
    name: str = ""            # table name as written, lower case
    base: str = ""            # base name without prefix, for kind == base
    join: str = "first"       # first, comma, inner, left


class _Block:
    _ids = 0

    def __init__(self, parent):
        _Block._ids += 1
        self.id = _Block._ids
        self.parent = parent
        self.tables = {}          # alias -> _TRef
        self.colrefs = []         # (parts tuple, ctx)
        self.stars = []           # None or qualifier parts
        self.aliases = set()
        self.conj_global = []     # list of node lists
        self.conj_own = {}        # alias -> list of node lists (LEFT JOIN ON)
        self.items = []           # raw select-list items
        self.modifiers = []       # SELECT modifiers (DISTINCT, SQL_NO_CACHE, ...)
        self.clause_keys = set()  # clauses present (SELECT, FROM, WHERE, ...)
        self.where = None         # raw WHERE nodes
        self.on_raw = []          # (join kind, alias, raw ON nodes)
        self.using = False        # a JOIN ... USING (...) was seen

    def chain(self):
        b = self
        while b is not None:
            yield b
            b = b.parent


class _Parser:
    def __init__(self, policy: InstallPolicy, residue: bool):
        self.p = policy
        self.residue = residue
        self.blocks = []
        self.tables_read = set()
        self.prefix = policy.prefix.lower()
        #: block id -> (parent block, subquery group) for a subquery that is the operand of
        #: [NOT] EXISTS in a WHERE clause and produced exactly one query block.
        self.exists_sub = {}

    # ---- names ------------------------------------------------------------------
    def _check_new_name(self, name, what, own_table=None):
        low = name.lower()
        if low in _SYSTEM_SCHEMAS:
            raise _Reject(f"{what} name {name!r} collides with a system schema")
        if low.startswith(self.prefix) and low != own_table:
            raise _Reject(f"{what} name {name!r} looks like a WordPress table; pick another")
        if low in ("dual",):
            raise _Reject(f"{what} name {name!r} is reserved")

    def _classify_table(self, name):
        low = name.lower()
        if not low.startswith(self.prefix):
            raise _Reject(f"table {name!r} is not on the allowlist")
        base = low[len(self.prefix):]
        if base in _FORBIDDEN_BASES:
            raise _Reject(f"table {name!r} holds user or comment data and is never read")
        if base not in self.p.allowed_bases:
            raise _Reject(f"table {name!r} is not on the allowlist")
        return base

    def _check_schema(self, schema):
        if schema.lower() in _SYSTEM_SCHEMAS:
            raise _Reject(f"system schema {schema!r} is never read")
        if self.p.schema is None or schema != self.p.schema:
            raise _Reject(f"schema-qualified name {schema!r} is not this install's schema",
                          "qualified_schema")

    # ---- statement --------------------------------------------------------------
    def statement(self, nodes):
        if not nodes:
            raise _Reject("empty statement")
        if _kw(nodes[0], "SHOW"):
            ok = (len(nodes) == 2 and _kw(nodes[1], "GRANTS")) or (
                len(nodes) in (4, 5) and _kw(nodes[1], "GRANTS") and _kw(nodes[2], "FOR")
                and _kw(nodes[3], "CURRENT_USER")
                and (len(nodes) == 4 or (isinstance(nodes[4], _Group) and not nodes[4].children)))
            if not ok:
                raise _Reject("only SHOW GRANTS [FOR CURRENT_USER()] is allowed among SHOW "
                              "statements")
            return "show_grants"
        kind = "select"
        if _kw(nodes[0], "EXPLAIN"):
            nodes = nodes[1:]
            kind = "explain"
            if not nodes or not (_kw(nodes[0], "SELECT", "WITH") or isinstance(nodes[0], _Group)):
                raise _Reject("EXPLAIN is allowed only directly before a SELECT")
        if not (_kw(nodes[0], "SELECT", "WITH") or
                (isinstance(nodes[0], _Group) and _is_query_group(nodes[0]))):
            first = nodes[0].value if isinstance(nodes[0], _Tok) else "("
            raise _Reject(f"statement must start with SELECT or WITH ... SELECT, not {first!r}")
        self.query_expr(nodes, None, frozenset())
        return kind

    # ---- query expressions ------------------------------------------------------
    def query_expr(self, nodes, parent, ctes):
        i = 0
        n = len(nodes)
        if n and _kw(nodes[0], "WITH"):
            i = 1
            local = set(ctes)
            while True:
                if i >= n or not _is_name(nodes[i]) or (
                        nodes[i].kind == "ident" and nodes[i].upper in _STRUCT):
                    raise _Reject("malformed WITH clause")
                name = _name_of(nodes[i])
                self._check_new_name(name, "CTE")
                i += 1
                if i < n and isinstance(nodes[i], _Group):
                    raise _Reject("CTE column lists are not supported", "cte_column_list")
                if i >= n or not _kw(nodes[i], "AS"):
                    raise _Reject("expected AS in WITH clause")
                i += 1
                if i >= n or not isinstance(nodes[i], _Group) or not _is_query_group(nodes[i]):
                    raise _Reject("expected (SELECT ...) in WITH clause")
                self.query_expr(nodes[i].children, parent, frozenset(local))
                local.add(name.lower())
                i += 1
                if i < n and _op(nodes[i], ","):
                    i += 1
                    continue
                break
            ctes = frozenset(local)
        rest = nodes[i:]
        if not rest:
            raise _Reject("WITH without a query")
        segments = [[]]
        for x in rest:
            if _kw(x, *_SETOPS):
                segments.append([])
            else:
                segments[-1].append(x)
        last = len(segments) - 1
        for idx, seg in enumerate(segments):
            if idx > 0 and seg and _kw(seg[0], "ALL", "DISTINCT"):
                seg = seg[1:]
            if not seg:
                raise _Reject("empty query in a set operation")
            if _kw(seg[0], "SELECT"):
                self.select(seg, parent, ctes)
            elif isinstance(seg[0], _Group) and _is_query_group(seg[0]):
                self.query_expr(seg[0].children, parent, ctes)
                tail = seg[1:]
                if tail:
                    if idx != last:
                        raise _Reject("ORDER BY / LIMIT inside a set operation")
                    self.tail(tail, parent, ctes)
            else:
                raise _Reject("expected SELECT")

    def tail(self, nodes, parent, ctes):
        b = _Block(parent)
        self.blocks.append(b)
        parts = self._clauses(nodes, allowed=("ORDER", "LIMIT"), leading=None)
        self._order_limit(parts, b, ctes)

    def _clauses(self, nodes, allowed, leading):
        parts = {}
        cur = leading
        if leading is not None:
            parts[leading] = []
        for x in nodes:
            if isinstance(x, _Tok) and x.kind == "ident" and x.upper in _CLAUSES:
                u = x.upper
                if u not in allowed:
                    raise _Reject(f"unexpected {u}")
                if u in parts:
                    raise _Reject(f"duplicate {u} clause")
                if cur in _CLAUSES and _CLAUSES.index(u) < _CLAUSES.index(cur):
                    raise _Reject(f"{u} clause out of order")
                cur = u
                parts[u] = []
                continue
            if cur is None:
                raise _Reject("unexpected tokens before ORDER BY / LIMIT")
            parts[cur].append(x)
        return parts

    def select(self, nodes, parent, ctes):
        b = _Block(parent)
        self.blocks.append(b)
        i = 1
        while i < len(nodes) and _kw(nodes[i], *_SELECT_MODIFIERS):
            i += 1
        parts = self._clauses(nodes[i:], allowed=_CLAUSES, leading="SELECT")
        b.modifiers = list(nodes[1:i])
        b.clause_keys = set(parts)
        b.where = parts.get("WHERE")
        if "FROM" in parts:
            if not parts["FROM"]:
                raise _Reject("empty FROM clause")
            self.from_clause(parts["FROM"], b, ctes)
        items = _split_top(parts["SELECT"])
        b.items = items
        if not parts["SELECT"]:
            raise _Reject("empty select list")
        for item in items:
            self.select_item(item, b, ctes)
        if "WHERE" in parts:
            w = parts["WHERE"]
            self.walk_expr(w, b, ctes, "where")
            b.conj_global.extend(_conjuncts(w))
        if "GROUP" in parts:
            g = parts["GROUP"]
            if not g or not _kw(g[0], "BY"):
                raise _Reject("GROUP without BY")
            g = g[1:]
            if len(g) >= 2 and _kw(g[-2], "WITH") and _kw(g[-1], "ROLLUP"):
                g = g[:-2]
            for it in _split_top(g):
                if it and _kw(it[-1], "ASC", "DESC"):
                    it = it[:-1]
                self.walk_expr(it, b, ctes, "group")
        if "HAVING" in parts:
            self.walk_expr(parts["HAVING"], b, ctes, "having")
        self._order_limit(parts, b, ctes)

    def _order_limit(self, parts, b, ctes):
        if "ORDER" in parts:
            o = parts["ORDER"]
            if not o or not _kw(o[0], "BY"):
                raise _Reject("ORDER without BY")
            for it in _split_top(o[1:]):
                if it and _kw(it[-1], "ASC", "DESC"):
                    it = it[:-1]
                self.walk_expr(it, b, ctes, "order")
        if "LIMIT" in parts:
            lim = parts["LIMIT"]
            nums = [x for x in lim if isinstance(x, _Tok) and x.kind == "number"]
            shape_ok = (
                (len(lim) == 1 and len(nums) == 1)
                or (len(lim) == 3 and len(nums) == 2 and (_op(lim[1], ",") or _kw(lim[1], "OFFSET"))
                    and lim[0].kind == "number" and lim[2].kind == "number"))
            if not shape_ok or any(not re.fullmatch(r"\d+", t.value) for t in nums):
                raise _Reject("LIMIT accepts only integer literals (LIMIT n, LIMIT m, n, "
                              "LIMIT n OFFSET m)")

    def select_item(self, item, b, ctes):
        if not item:
            raise _Reject("empty select-list item")
        if len(item) == 1 and _op(item[0], "*"):
            b.stars.append(None)
            return
        if (len(item) in (3, 5) and _op(item[-1], "*") and _op(item[-2], ".")
                and all(_is_name(item[k]) for k in range(0, len(item) - 2, 2))
                and all(_op(item[k], ".") for k in range(1, len(item) - 1, 2))):
            b.stars.append(tuple(_name_of(item[k]) for k in range(0, len(item) - 2, 2)))
            return
        expr, alias = _strip_alias(item)
        if alias is not None:
            b.aliases.add(alias.lower())
        self.walk_expr(expr, b, ctes, "select")

    # ---- FROM -------------------------------------------------------------------
    def from_clause(self, nodes, b, ctes):
        i = 0
        n = len(nodes)
        join = "first"
        while True:
            i, alias = self.table_factor(nodes, i, b, ctes, join)
            if join in ("inner", "left") and i < n:
                if _kw(nodes[i], "ON"):
                    j = _scan_on_end(nodes, i + 1)
                    expr = nodes[i + 1:j]
                    self.walk_expr(expr, b, ctes, "on")
                    b.on_raw.append((join, alias, expr))
                    conj = _conjuncts(expr)
                    if join == "left":
                        b.conj_own.setdefault(alias, []).extend(conj)
                    else:
                        b.conj_global.extend(conj)
                    i = j
                elif _kw(nodes[i], "USING"):
                    if i + 1 >= n or not isinstance(nodes[i + 1], _Group):
                        raise _Reject("USING needs a column list")
                    cols = _split_top(nodes[i + 1].children)
                    for c in cols:
                        if len(c) != 1 or not _is_name(c[0]):
                            raise _Reject("bad USING column list")
                        b.colrefs.append(((_name_of(c[0]),), "using"))
                    b.using = True
                    i += 2
            if i >= n:
                break
            t = nodes[i]
            if _op(t, ","):
                join = "comma"
                i += 1
            elif _kw(t, "JOIN", "STRAIGHT_JOIN"):
                join = "inner"
                i += 1
            elif _kw(t, "INNER", "CROSS"):
                if i + 1 >= n or not _kw(nodes[i + 1], "JOIN"):
                    raise _Reject(f"expected JOIN after {t.upper}")
                join = "inner"
                i += 2
            elif _kw(t, "LEFT"):
                i += 1
                if i < n and _kw(nodes[i], "OUTER"):
                    i += 1
                if i >= n or not _kw(nodes[i], "JOIN"):
                    raise _Reject("expected JOIN after LEFT")
                join = "left"
                i += 1
            elif _kw(t, "RIGHT", "NATURAL", "FULL"):
                raise _Reject(f"{t.upper} joins are not supported", "left_join_filters")
            elif _kw(t, "USE", "FORCE", "IGNORE"):
                raise _Reject("index hints are not supported", "index_hints")
            else:
                raise _Reject(f"unexpected {t.value if isinstance(t, _Tok) else '('!r} in FROM")

    def table_factor(self, nodes, i, b, ctes, join):
        n = len(nodes)
        if i >= n:
            raise _Reject("missing table in FROM")
        t = nodes[i]
        if isinstance(t, _Group):
            if not _is_query_group(t):
                raise _Reject("parenthesised join or table lists are not supported",
                              "left_join_filters")
            # A derived table cannot see its siblings; it can see enclosing query blocks.
            self.query_expr(t.children, b.parent, ctes)
            i += 1
            i, alias = self._alias(nodes, i, required=True)
            if i < n and isinstance(nodes[i], _Group):
                raise _Reject("derived-table column lists are not supported", "cte_column_list")
            tref = _TRef(alias.lower(), "derived")
        elif _is_name(t):
            if t.kind == "ident" and t.upper in _STRUCT and t.upper != "DUAL":
                raise _Reject(f"unexpected keyword {t.value!r} where a table was expected")
            parts = [_name_of(t)]
            i += 1
            while i + 1 < n and _op(nodes[i], ".") and _is_name(nodes[i + 1]):
                parts.append(_name_of(nodes[i + 1]))
                i += 2
            if i < n and _op(nodes[i], "."):
                raise _Reject("malformed table name")
            if len(parts) > 2:
                raise _Reject("malformed table name")
            if i < n and isinstance(nodes[i], _Group):
                raise _Reject("table functions and PARTITION are not supported", "index_hints")
            if len(parts) == 2:
                self._check_schema(parts[0])
                tbl = parts[1]
                base = self._classify_table(tbl)
                tref = _TRef("", "base", tbl.lower(), base)
            else:
                tbl = parts[0]
                low = tbl.lower()
                if low in ctes and not low.startswith(self.prefix):
                    tref = _TRef("", "cte", low)
                elif low == "dual" and t.kind == "ident":
                    tref = _TRef("", "dual", low)
                else:
                    base = self._classify_table(tbl)
                    tref = _TRef("", "base", low, base)
            i, alias = self._alias(nodes, i, required=False)
            if alias is None:
                tref.alias = tref.name
            else:
                self._check_new_name(alias, "table alias",
                                     own_table=tref.name if tref.kind == "base" else None)
                tref.alias = alias.lower()
            if i < n and _kw(nodes[i], "USE", "FORCE", "IGNORE"):
                raise _Reject("index hints are not supported", "index_hints")
            if i < n and isinstance(nodes[i], _Group):
                raise _Reject("unexpected '(' after a table", "index_hints")
        else:
            raise _Reject(f"unexpected {t.value!r} where a table was expected")
        if tref.alias in b.tables:
            raise _Reject(f"duplicate table alias {tref.alias!r}")
        tref.join = join
        b.tables[tref.alias] = tref
        if tref.kind == "base":
            self.tables_read.add(tref.name)
        return i, tref.alias

    def _alias(self, nodes, i, required):
        n = len(nodes)
        if i < n and _kw(nodes[i], "AS"):
            if i + 1 >= n or not _is_name(nodes[i + 1]) or (
                    nodes[i + 1].kind == "ident" and nodes[i + 1].upper in _STRUCT):
                raise _Reject("AS without an alias")
            return i + 2, _name_of(nodes[i + 1])
        if i < n and _is_name(nodes[i]) and not (
                nodes[i].kind == "ident" and (nodes[i].upper in _FROM_STOP
                                              or nodes[i].upper in _STRUCT)):
            return i + 1, _name_of(nodes[i])
        if required:
            raise _Reject("a derived table needs an alias")
        return i, None

    # ---- expressions ------------------------------------------------------------
    def walk_group(self, g, b, ctes, ctx):
        if _is_query_group(g):
            self.query_expr(g.children, b, ctes)
            return
        if not g.children:
            raise _Reject("empty parentheses")
        for it in _split_top(g.children):
            self.walk_expr(it, b, ctes, ctx)

    def walk_expr(self, nodes, b, ctes, ctx, func=None):
        if not nodes:
            raise _Reject(f"empty expression ({ctx})")
        OPERAND, OPERATOR = 0, 1
        state = OPERAND
        i = 0
        n = len(nodes)
        case_depth = 0
        pending_interval = False
        prev = None
        while i < n:
            x = nodes[i]
            nxt = nodes[i + 1] if i + 1 < n else None
            if isinstance(x, _Group):
                if state != OPERAND:
                    raise _Reject("unexpected '(' after an operand")
                self.walk_group(x, b, ctes, ctx)
                state = OPERATOR
                prev = x
                i += 1
                continue
            k = x.kind
            if k == "string":
                if state == OPERAND:
                    state = OPERATOR
                elif not (isinstance(prev, _Tok) and prev.kind == "string"):
                    raise _Reject(f"unexpected string literal at offset {x.pos}")
                prev = x
                i += 1
                continue
            if k == "number":
                if state != OPERAND:
                    raise _Reject(f"unexpected number at offset {x.pos}")
                state = OPERATOR
                prev = x
                i += 1
                continue
            if k == "op":
                v = x.value
                if state == OPERAND:
                    if v in ("-", "+", "!", "~"):
                        prev = x
                        i += 1
                        continue
                    if v == "*":
                        raise _Reject("'*' is allowed only as a whole select item or COUNT(*)")
                    raise _Reject(f"unexpected {v!r} at offset {x.pos}")
                if v in _BIN_OPS:
                    state = OPERAND
                    prev = x
                    i += 1
                    continue
                raise _Reject(f"unexpected {v!r} at offset {x.pos}")
            if k == "qident":
                if state != OPERAND:
                    raise _Reject(f"unexpected identifier {x.value!r}")
                if isinstance(nxt, _Group):
                    raise _Reject("quoted function names (stored functions) are not allowed")
                i = self._colref(nodes, i, b, ctx)
                state = OPERATOR
                prev = nodes[i - 1]
                continue
            # bare identifier
            U = x.upper
            if isinstance(nxt, _Group):
                if state == OPERAND:
                    if U == "EXISTS" or U in ("ANY", "SOME", "ALL"):
                        if not _is_query_group(nxt):
                            raise _Reject(f"{U} needs a subquery")
                        before = len(self.blocks)
                        self.query_expr(nxt.children, b, ctes)
                        new = self.blocks[before:]
                        if U == "EXISTS" and ctx == "where" and len(new) == 1 \
                                and new[0].parent is b:
                            self.exists_sub[new[0].id] = (b, nxt)
                        state = OPERATOR
                        prev = nxt
                        i += 2
                        continue
                    if U in ("NOT", "BINARY", "INTERVAL", "CASE", "WHEN", "THEN", "ELSE"):
                        pass  # keyword; the group is the next operand
                    elif U in FUNCTION_ALLOWLIST:
                        self.walk_func(U, nxt, b, ctes, ctx)
                        state = OPERATOR
                        prev = nxt
                        i += 2
                        continue
                    else:
                        raise _Reject(f"function {x.value}() is not on the allowlist")
                else:
                    if U == "IN":
                        self.walk_group(nxt, b, ctes, ctx)
                        state = OPERATOR
                        prev = nxt
                        i += 2
                        continue
                    if U in _BIN_WORDS or U in ("WHEN", "THEN", "ELSE", "BETWEEN"):
                        pass
                    else:
                        raise _Reject(f"unexpected {x.value!r} before '('")
            if state == OPERAND:
                if U in ("NULL", "TRUE", "FALSE"):
                    state = OPERATOR
                elif U in ("NOT", "BINARY"):
                    pass
                elif U == "CASE":
                    case_depth += 1
                elif U in ("WHEN", "THEN", "ELSE") and case_depth:
                    pass
                elif U == "INTERVAL":
                    pending_interval = True
                elif U in ("DATE", "TIME", "TIMESTAMP") and isinstance(nxt, _Tok) \
                        and nxt.kind == "string":
                    i += 1
                    state = OPERATOR
                elif U in _STRUCT:
                    raise _Reject(f"unexpected keyword {x.value!r}")
                else:
                    i = self._colref(nodes, i, b, ctx)
                    state = OPERATOR
                    prev = nodes[i - 1]
                    continue
            else:
                if U in _BIN_WORDS or U == "BETWEEN":
                    state = OPERAND
                elif U == "NOT":
                    if not _kw(nxt, "IN", "LIKE", "BETWEEN", "REGEXP", "RLIKE"):
                        raise _Reject("unexpected NOT")
                elif U == "IS":
                    j = i + 1
                    if j < n and _kw(nodes[j], "NOT"):
                        j += 1
                    if j >= n or not _kw(nodes[j], "NULL", "TRUE", "FALSE", "UNKNOWN"):
                        raise _Reject("IS must be followed by [NOT] NULL/TRUE/FALSE/UNKNOWN")
                    prev = nodes[j]
                    i = j + 1
                    continue
                elif U == "SOUNDS":
                    if not _kw(nxt, "LIKE"):
                        raise _Reject("SOUNDS without LIKE")
                    i += 2
                    state = OPERAND
                    continue
                elif U in ("WHEN", "THEN", "ELSE") and case_depth:
                    state = OPERAND
                elif U == "END" and case_depth:
                    case_depth -= 1
                elif U == "COLLATE":
                    if not (isinstance(nxt, _Tok) and nxt.kind in ("ident", "qident", "string")):
                        raise _Reject("COLLATE needs a collation name")
                    i += 2
                    continue
                elif pending_interval and U in _INTERVAL_UNITS:
                    pending_interval = False
                elif U in ("ASC", "DESC") and func == "GROUP_CONCAT":
                    pass
                else:
                    raise _Reject(f"unexpected {x.value!r} at offset {x.pos}")
            prev = x
            i += 1
        if state != OPERATOR or case_depth or pending_interval:
            raise _Reject(f"incomplete expression ({ctx})")

    def _colref(self, nodes, i, b, ctx):
        n = len(nodes)
        parts = [_name_of(nodes[i])]
        i += 1
        while i + 1 < n and _op(nodes[i], ".") and _is_name(nodes[i + 1]):
            parts.append(_name_of(nodes[i + 1]))
            i += 2
        if i < n and _op(nodes[i], "."):
            raise _Reject("qualified '*' or malformed name in an expression")
        if i < n and isinstance(nodes[i], _Group):
            raise _Reject("qualified function names (stored functions) are not allowed")
        if len(parts) > 3:
            raise _Reject("name with more than three parts")
        if len(parts) == 3:
            self._check_schema(parts[0])
        b.colrefs.append((tuple(parts), ctx))
        return i

    def walk_func(self, U, g, b, ctes, ctx):
        ch = g.children
        if U in _ZERO_ARG_FUNCS:
            if ch:
                raise _Reject(f"{U}() takes no arguments")
            return
        if not ch:
            raise _Reject(f"{U}() needs arguments")
        if U == "COUNT" and len(ch) == 1 and _op(ch[0], "*"):
            return
        if U in ("COUNT", "SUM", "MIN", "MAX", "AVG", "GROUP_CONCAT") and _kw(ch[0], "DISTINCT"):
            ch = ch[1:]
            if not ch:
                raise _Reject(f"{U}(DISTINCT) needs an argument")
        if U == "GROUP_CONCAT":
            sep_idx = next((k for k, x in enumerate(ch) if _kw(x, "SEPARATOR")), None)
            if sep_idx is not None:
                sep = ch[sep_idx + 1:]
                if len(sep) != 1 or not (isinstance(sep[0], _Tok) and sep[0].kind == "string"):
                    raise _Reject("GROUP_CONCAT SEPARATOR needs one string literal")
                ch = ch[:sep_idx]
            ord_idx = next((k for k, x in enumerate(ch) if _kw(x, "ORDER")), None)
            order = []
            if ord_idx is not None:
                if ord_idx + 1 >= len(ch) or not _kw(ch[ord_idx + 1], "BY"):
                    raise _Reject("ORDER without BY in GROUP_CONCAT")
                order = ch[ord_idx + 2:]
                ch = ch[:ord_idx]
                if not order:
                    raise _Reject("empty ORDER BY in GROUP_CONCAT")
            for a in _split_top(ch):
                self.walk_expr(a, b, ctes, ctx)
            for o in _split_top(order) if order else []:
                if o and _kw(o[-1], "ASC", "DESC"):
                    o = o[:-1]
                self.walk_expr(o, b, ctes, ctx)
            return
        if U == "TRIM":
            seq = ch
            spec = False
            if _kw(seq[0], "BOTH", "LEADING", "TRAILING"):
                spec = True
                seq = seq[1:]
            idx = next((k for k, x in enumerate(seq) if _kw(x, "FROM")), None)
            if idx is None:
                if spec or len(_split_top(seq)) != 1:
                    raise _Reject("malformed TRIM()")
                self.walk_expr(seq, b, ctes, ctx)
            else:
                before, after = seq[:idx], seq[idx + 1:]
                if before:
                    self.walk_expr(before, b, ctes, ctx)
                elif not spec:
                    raise _Reject("malformed TRIM()")
                self.walk_expr(after, b, ctes, ctx)
            return
        if U == "SUBSTRING":
            fi = next((k for k, x in enumerate(ch) if _kw(x, "FROM")), None)
            if fi is None:
                args = _split_top(ch)
                if len(args) not in (2, 3):
                    raise _Reject("SUBSTRING() takes 2 or 3 arguments")
                for a in args:
                    self.walk_expr(a, b, ctes, ctx)
            else:
                rest = ch[fi + 1:]
                fo = next((k for k, x in enumerate(rest) if _kw(x, "FOR")), None)
                self.walk_expr(ch[:fi], b, ctes, ctx)
                if fo is None:
                    self.walk_expr(rest, b, ctes, ctx)
                else:
                    self.walk_expr(rest[:fo], b, ctes, ctx)
                    self.walk_expr(rest[fo + 1:], b, ctes, ctx)
            return
        if U == "CAST":
            idx = max((k for k, x in enumerate(ch) if _kw(x, "AS")), default=None)
            if idx is None:
                raise _Reject("CAST() needs AS <type>")
            self.walk_expr(ch[:idx], b, ctes, ctx)
            _check_type(ch[idx + 1:])
            return
        if U == "CONVERT":
            ui = next((k for k, x in enumerate(ch) if _kw(x, "USING")), None)
            if ui is not None:
                self.walk_expr(ch[:ui], b, ctes, ctx)
                cs = ch[ui + 1:]
                if len(cs) != 1 or not (isinstance(cs[0], _Tok)
                                        and cs[0].kind in ("ident", "qident", "string")):
                    raise _Reject("CONVERT ... USING needs a charset name")
                return
            args = _split_top(ch)
            if len(args) != 2:
                raise _Reject("CONVERT() takes (expr, type) or (expr USING charset)")
            self.walk_expr(args[0], b, ctes, ctx)
            _check_type(args[1])
            return
        for a in _split_top(ch):
            self.walk_expr(a, b, ctes, ctx)

    # ---- post checks (admin connections) ----------------------------------------
    def post_checks(self):
        # Read-only views installs get the same column and row checks as admin connections:
        # defence in depth, so the guard never relies on the view definitions being right.
        used = {}  # (block id, alias) -> set(columns)
        owner = {}  # (block id, alias) -> block
        for b in self.blocks:
            restricted = {a: t for a, t in b.tables.items()
                          if t.kind == "base" and t.base in _RESTRICTED_BASES}
            for a in restricted:
                used.setdefault((b.id, a), set())
                owner[(b.id, a)] = b
            for q in b.stars:
                if q is None:
                    if restricted:
                        raise _Reject(f"SELECT * over {sorted(t.name for t in restricted.values())}",
                                      "star_over_restricted")
                else:
                    alias = self._qualifier_alias(b, q, own_only=True)
                    if alias in restricted:
                        raise _Reject(f"{'.'.join(q)}.* over a restricted table",
                                      "star_over_restricted")
            for parts, ctx in b.colrefs:
                hit = self._resolve(b, parts, ctx)
                if hit is None:
                    continue
                blk, alias, col = hit
                tref = blk.tables[alias]
                allowed = self.p.allowed_columns(tref.base)
                if col not in allowed:
                    raise _Reject(f"column {tref.name}.{col} is not on the allowlist")
                used.setdefault((blk.id, alias), set()).add(col)
                owner[(blk.id, alias)] = blk
        for key, cols in used.items():
            blk = owner[key]
            alias = key[1]
            tref = blk.tables[alias]
            facts = self._facts(blk, alias)
            if tref.base == _OPTIONS:
                self._check_options(tref, facts)
            elif tref.base == _POSTS:
                self._check_posts(tref, facts, cols)
            elif tref.base == _POSTMETA:
                self._check_postmeta(blk, tref, facts)

    def _qualifier_alias(self, b, q, own_only=False):
        blocks = [b] if own_only else list(b.chain())
        if len(q) == 1:
            low = q[0].lower()
            for blk in blocks:
                if low in blk.tables:
                    return low
            raise _Reject(f"unknown table qualifier {q[0]!r}")
        self._check_schema(q[0])
        low = q[1].lower()
        for blk in blocks:
            t = blk.tables.get(low)
            if t is not None and t.kind == "base" and t.name == low:
                return low
        raise _Reject(f"unknown table qualifier {'.'.join(q)!r}")

    def _resolve(self, b, parts, ctx):
        """Return (block, alias, column) when a colref hits a restricted table, else None."""
        col = parts[-1].lower()
        if len(parts) == 1:
            # ORDER BY prefers select aliases; HAVING prefers a GROUP BY column, which is
            # checked where it appears. GROUP BY may pick a table column, so no exemption.
            if (ctx in ("order", "having") and col in b.aliases
                    and col not in _RESTRICTED_FULL_COLUMNS):
                return None
            own_restricted = [a for a, t in b.tables.items()
                              if t.kind == "base" and t.base in _RESTRICTED_BASES]
            if own_restricted:
                if len(b.tables) == 1:
                    return b, own_restricted[0], col
                raise _Reject(f"unqualified column {parts[0]!r}", "unqualified_multi_table")
            for anc in list(b.chain())[1:]:
                if any(t.kind == "base" and t.base in _RESTRICTED_BASES
                       for t in anc.tables.values()):
                    raise _Reject(f"unqualified column {parts[0]!r}", "unqualified_in_nested")
            return None
        q = parts[:-1]
        if len(q) == 1:
            low = q[0].lower()
            for blk in b.chain():
                t = blk.tables.get(low)
                if t is not None:
                    if t.kind == "base" and t.base in _RESTRICTED_BASES:
                        return blk, low, col
                    return None
            raise _Reject(f"unknown table qualifier {q[0]!r}")
        self._check_schema(q[0])
        low = q[1].lower()
        for blk in b.chain():
            t = blk.tables.get(low)
            if t is not None and t.kind == "base" and t.name == low:
                if t.base in _RESTRICTED_BASES:
                    return blk, low, col
                return None
        raise _Reject(f"unknown table qualifier {'.'.join(q)!r}")

    def _facts(self, blk, alias):
        conj = list(blk.conj_global) + list(blk.conj_own.get(alias, []))
        out = []
        for c in conj:
            f = _fact(c, blk)
            if f is not None:
                out.append(f)
        return out

    def _check_options(self, tref, facts):
        for f in facts:
            if f[0] in ("eq", "in") and f[1] == (tref.alias, "option_name"):
                if f[2] and set(f[2]) <= self.p.option_names:
                    return
            if f[0] == "like" and f[1] == (tref.alias, "option_name"):
                exact, _prefix = _like_parse(f[2])
                if exact is not None and exact in self.p.option_names:
                    return
        raise _Reject(f"{tref.name} is readable only with option_name = / IN limited to "
                      f"{sorted(self.p.option_names)}", "row_filter_shape")

    def _post_type_vals(self, facts, alias):
        return [set(f[2]) for f in facts if f[0] in ("eq", "in") and f[1] == (alias, "post_type")]

    def _post_status_vals(self, facts, alias):
        return [set(f[2]) for f in facts
                if f[0] in ("eq", "in") and f[1] == (alias, "post_status")]

    def _published(self, facts, alias):
        return any(v and v <= {"publish"} for v in self._post_status_vals(facts, alias))

    def _excludes_revisions(self, facts, alias):
        for f in facts:
            if f[1] == (alias, "post_type"):
                if f[0] in ("eq", "in") and f[2] and all(_plain_not(v, "revision") for v in f[2]):
                    return True
                if f[0] == "ne" and f[2] == "revision":
                    return True
                if f[0] == "notin" and "revision" in f[2]:
                    return True
            if f[1] == (alias, "post_status") and f[0] in ("eq", "in") and f[2] \
                    and all(_plain_not(v, "inherit") for v in f[2]):
                return True
        return False

    def _check_posts(self, tref, facts, cols):
        a = tref.alias
        if not self._excludes_revisions(facts, a):
            raise _Reject(f"{tref.name} reads must exclude revisions (post_type <> 'revision', "
                          f"post_type = / IN (...), or post_status = 'publish')",
                          "row_filter_shape")
        if _POSTS_CONTENT in cols:
            public = set(self.p.public_post_types)
            if not self._published(facts, a):
                raise _Reject(f"{tref.name}.post_content needs post_status = 'publish'",
                              "row_filter_shape")
            if not any(v and v <= public for v in self._post_type_vals(facts, a)):
                raise _Reject(f"{tref.name}.post_content needs post_type = / IN limited to the "
                              f"public post types {sorted(public)}", "row_filter_shape")

    def _check_postmeta(self, blk, tref, facts):
        a = tref.alias
        key_ok = False
        for f in facts:
            if f[1] != (a, "meta_key"):
                continue
            if f[0] in ("eq", "in") and f[2] and all(_meta_key_ok(v, self.p) for v in f[2]):
                key_ok = True
            elif f[0] == "like":
                exact, prefix = _like_parse(f[2])
                if exact is not None and _meta_key_ok(exact, self.p):
                    key_ok = True
                elif prefix is not None and any(prefix.startswith(p)
                                                for p in self.p.meta_prefixes):
                    key_ok = True
        if not key_ok:
            raise _Reject(f"{tref.name} needs meta_key = / IN / LIKE 'prefix%' limited to "
                          f"{sorted(self.p.meta_keys)} and "
                          f"{', '.join(x + '*' for x in self.p.meta_prefixes) or 'no prefix'} "
                          "(in LIKE, '_' is a one-character wildcard, so write "
                          "LIKE 'rank\\_math\\_%' or LIKE '\\_yoast\\_wpseo\\_%')",
                          "row_filter_shape")
        allowed_types = set(self.p.public_post_types) | set(self.p.template_post_types)
        for f in facts:
            if f[0] != "join":
                continue
            for mine, other in ((f[1], f[2]), (f[2], f[1])):
                if mine != (a, "post_id") or other[1] != "id":
                    continue
                p = blk.tables.get(other[0])
                if p is None or p.kind != "base" or p.base != _POSTS:
                    continue
                pf = self._facts(blk, p.alias)
                if self._published(pf, p.alias) and any(
                        v and v <= allowed_types for v in self._post_type_vals(pf, p.alias)):
                    return
        if self._correlated_exists_ok(blk, a, facts, allowed_types):
            return
        raise _Reject(f"{tref.name} must be joined by {a}.post_id = <posts alias>.ID to "
                      f"{self.p.prefix}posts filtered to post_status = 'publish' and public "
                      f"types or builder templates", "postmeta_join_form")


    def _correlated_exists_ok(self, blk, a, facts, allowed_types):
        """The NOT EXISTS / EXISTS form of "published posts missing an SEO description":

            ... FROM wp_posts p WHERE <p published, public> AND [NOT] EXISTS
                (SELECT 1 FROM wp_postmeta m WHERE m.post_id = p.ID AND m.meta_key = ...)

        Accepted only when all of these hold, which together mean the subquery can only
        reveal whether an allowlisted key exists for a row the outer query may already read:
        the subquery is the whole operand of [NOT] EXISTS, a top-level AND conjunct of the
        directly enclosing block's WHERE, and is one query block with no nested subquery;
        its select list is a single number literal (EXISTS never returns values); it
        correlates by m.post_id = <outer posts alias>.ID; and that outer alias is filtered to
        post_status = 'publish' and public types or builder templates. The meta_key filter is
        checked by the caller as for any wp_postmeta read."""
        sub = self.exists_sub.get(blk.id)
        if sub is None:
            return False
        parent, grp = sub
        if blk.parent is not parent:
            return False
        top_level = False
        for part in parent.conj_global:
            seq = [x for x in part]
            if (len(seq) == 2 and _kw(seq[0], "EXISTS") and seq[1] is grp) or (
                    len(seq) == 3 and _kw(seq[0], "NOT") and _kw(seq[1], "EXISTS")
                    and seq[2] is grp):
                top_level = True
                break
        if not top_level:
            return False
        if not (len(blk.items) == 1 and len(blk.items[0]) == 1
                and isinstance(blk.items[0][0], _Tok) and blk.items[0][0].kind == "number"):
            return False
        for f in facts:
            if f[0] != "join":
                continue
            for mine, other in ((f[1], f[2]), (f[2], f[1])):
                if mine != (a, "post_id") or other[1] != "id":
                    continue
                q = other[0]
                if not (isinstance(q, tuple) and q[0] == "outer" and q[1] == parent.id):
                    continue
                p = parent.tables.get(q[2])
                if p is None or p.kind != "base" or p.base != _POSTS:
                    continue
                pf = self._facts(parent, p.alias)
                if self._published(pf, p.alias) and any(
                        v and v <= allowed_types for v in self._post_type_vals(pf, p.alias)):
                    return True
        return False

    # ---- revision residue (installs with residue_hosts) -----------------------------
    def residue_checks(self, kind):
        """The one exception: a count over revision rows for the install's configured hostile
        hosts (for example, spam links injected into old revisions). Accepted shape, and
        nothing else:

            SELECT COUNT(*) | COUNT(DISTINCT <id column>) [AS a] [, ...]
            FROM wp_posts p [ [INNER] JOIN wp_postmeta m ON m.post_id = p.ID ]
            WHERE p.post_type = 'revision'
              [AND m.meta_key = <residue_meta_key>]
              AND <host test>

        where <host test> is ``col LIKE '%<host>%'`` or a parenthesised OR of such tests,
        ``col`` is p.post_content (or m.meta_value when joined) and ``<host>`` is one of the
        install's ``residue_hosts``. Every WHERE / ON conjunct must be one of these; no subquery, set
        operation, CTE, GROUP BY, HAVING, ORDER BY, LIMIT or SELECT modifier. The result is a
        number, never post_content or meta_value."""
        def bad(why):
            raise _Reject(f"residue query: {why}", "residue_shape")
        if kind != "select":
            bad("must be a plain SELECT")
        if len(self.blocks) != 1:
            bad("one query block only (no subquery, set operation, CTE or derived table)")
        b = self.blocks[0]
        if b.modifiers:
            bad("no SELECT modifiers")
        if b.clause_keys - {"SELECT", "FROM", "WHERE"} or "WHERE" not in b.clause_keys:
            bad("SELECT ... FROM ... WHERE only (no GROUP BY, HAVING, ORDER BY, LIMIT)")
        if b.stars or b.using:
            bad("no '*' select item and no JOIN ... USING")
        tables = list(b.tables.values())
        posts = [t for t in tables if t.kind == "base" and t.base == _POSTS]
        metas = [t for t in tables if t.kind == "base" and t.base == _POSTMETA]
        if len(posts) != 1 or len(metas) > 1 or len(tables) != 1 + len(metas):
            bad(f"reads {self.p.prefix}posts, optionally joined to {self.p.prefix}postmeta, "
                "and nothing else")
        if any(t.join == "left" for t in tables):
            bad("inner join only")
        p = posts[0]
        m = metas[0] if metas else None
        count_cols = {(p.alias, "id"), (p.alias, "post_parent")}
        content_cols = {(p.alias, "post_content")}
        if m is not None:
            count_cols |= {(m.alias, "post_id"), (m.alias, "meta_id")}
            content_cols.add((m.alias, "meta_value"))
        for item in b.items:
            expr, _alias = _strip_alias(item)
            ok = False
            if len(expr) == 2 and _kw(expr[0], "COUNT") and isinstance(expr[1], _Group):
                ch = expr[1].children
                if len(ch) == 1 and _op(ch[0], "*"):
                    ok = True
                elif len(ch) >= 2 and _kw(ch[0], "DISTINCT"):
                    ok = _simple_col(ch[1:], b) in count_cols
            if not ok:
                bad("the select list may hold only COUNT(*) and COUNT(DISTINCT <id column>)")
        parts = _strict_conjuncts(b.where)
        for _join, _alias, on in b.on_raw:
            parts.extend(_strict_conjuncts(on))
        seen = {"type": False, "host": False, "join": m is None, "key": m is None}
        for part in parts:
            f = _fact(part, b)
            if f == ("eq", (p.alias, "post_type"), ("revision",)):
                seen["type"] = True
            elif m is not None and f == ("eq", (m.alias, "meta_key"), (self.p.residue_meta_key,)):
                seen["key"] = True
            elif m is not None and f is not None and f[0] == "join" and {f[1], f[2]} == {
                    (m.alias, "post_id"), (p.alias, "id")}:
                seen["join"] = True
            elif _host_test(part, b, content_cols, self.p.residue_patterns):
                seen["host"] = True
            else:
                bad("every WHERE / ON condition must be post_type = 'revision', "
                    f"meta_key = '{self.p.residue_meta_key}', m.post_id = p.ID or a LIKE "
                    f"'%<host>%' test for {list(self.p.residue_hosts)}")
        missing = [k for k, v in seen.items() if not v]
        if missing:
            bad(f"missing required condition(s): {', '.join(missing)}")


def _simple_col(nodes, b):
    """(alias, column) for a bare column reference, or None."""
    if len(nodes) == 1 and _is_name(nodes[0]) and not (
            nodes[0].kind == "ident" and nodes[0].upper in _STRUCT):
        if len(b.tables) != 1:
            return None
        return next(iter(b.tables)), nodes[0].value.lower()
    if (len(nodes) == 3 and _is_name(nodes[0]) and _op(nodes[1], ".") and _is_name(nodes[2])
            and nodes[0].value.lower() in b.tables):
        return nodes[0].value.lower(), nodes[2].value.lower()
    return None


def _strict_conjuncts(nodes):
    """Split on top-level AND (or &&), descending into parenthesised AND groups. Unlike
    ``_conjuncts`` nothing is dropped: a top-level OR group comes back as one part (for
    ``_host_test``), and XOR, CASE or BETWEEN anywhere is refused."""
    if not nodes:
        raise _Reject("residue query: empty condition", "residue_shape")
    for x in nodes:
        if _kw(x, "XOR", "CASE", "BETWEEN"):
            raise _Reject("residue query: XOR, CASE and BETWEEN are not allowed",
                          "residue_shape")
    if any(_kw(x, "OR") or _op(x, "||") for x in nodes):
        return [list(nodes)]
    parts = [[]]
    for x in nodes:
        if _kw(x, "AND") or _op(x, "&&"):
            parts.append([])
        else:
            parts[-1].append(x)
    out = []
    for prt in parts:
        if not prt:
            raise _Reject("residue query: empty condition", "residue_shape")
        if len(prt) == 1 and isinstance(prt[0], _Group) and not _is_query_group(prt[0]):
            ch = prt[0].children
            if any(_kw(x, "OR") or _op(x, "||") for x in ch):
                out.append(prt)
            else:
                out.extend(_strict_conjuncts(ch))
            continue
        out.append(prt)
    return out


def _host_test(part, b, content_cols, patterns):
    """True for ``col LIKE '%host%'`` or a parenthesised OR of those (configured hosts only)."""
    seq = part
    if len(seq) == 1 and isinstance(seq[0], _Group) and not _is_query_group(seq[0]):
        seq = seq[0].children
    alts = [[]]
    for x in seq:
        if _kw(x, "OR") or _op(x, "||"):
            alts.append([])
        else:
            alts[-1].append(x)
    for alt in alts:
        if len(alt) == 1 and isinstance(alt[0], _Group) and not _is_query_group(alt[0]):
            if not _host_test(alt, b, content_cols, patterns):
                return False
            continue
        if any(_kw(x, "AND") or _op(x, "&&") for x in alt):
            return False
        f = _fact(alt, b)
        if not (f is not None and f[0] == "like" and f[1] in content_cols
                and f[2] in patterns):
            return False
    return True


def _plain_not(v, word):
    """True if literal v certainly does not collation-match ``word``."""
    if not v.isascii():
        return False  # accent-insensitive collations could match; fail closed
    return v.lower().rstrip(" ") != word


def _meta_key_ok(v, pol):
    return v in pol.meta_keys or any(v.startswith(p) for p in pol.meta_prefixes)


def _like_parse(raw):
    """Parse a LIKE pattern body. Returns (exact, prefix): exact if no wildcard, prefix if
    the only wildcard is one trailing '%'. (None, None) if anything else."""
    out = []
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c == "\\":
            if i + 1 < n and raw[i + 1] in "_%":
                out.append(raw[i + 1])
                i += 2
                continue
            return None, None
        if c == "'" and raw.startswith("''", i):
            out.append("'")
            i += 2
            continue
        if c == "_":
            return None, None
        if c == "%":
            if i == n - 1:
                return None, "".join(out)
            return None, None
        out.append(c)
        i += 1
    return "".join(out), None


def _check_type(nodes):
    if not nodes or not _kw(nodes[0], *_CAST_TYPES):
        raise _Reject("CAST/CONVERT target must be a plain type")
    i = 1
    if nodes[0].upper in ("SIGNED", "UNSIGNED") and i < len(nodes) and _kw(nodes[i], "INTEGER", "INT"):
        i += 1
    if i < len(nodes) and isinstance(nodes[i], _Group):
        args = _split_top(nodes[i].children)
        if not (1 <= len(args) <= 2) or any(
                len(a) != 1 or not (isinstance(a[0], _Tok) and a[0].kind == "number") for a in args):
            raise _Reject("bad type length")
        i += 1
    if i != len(nodes):
        raise _Reject("unexpected tokens after the CAST/CONVERT type")


def _strip_alias(item):
    if len(item) >= 2 and _kw(item[-2], "AS"):
        a = item[-1]
        if isinstance(a, _Tok) and (a.kind in ("qident", "string")
                                    or (a.kind == "ident" and a.upper not in _STRUCT)):
            return item[:-2], a.value
        raise _Reject("AS without a valid alias")
    if len(item) >= 2:
        a, before = item[-1], item[-2]
        is_alias_tok = isinstance(a, _Tok) and (
            a.kind == "qident" or (a.kind == "ident" and a.upper not in _STRUCT
                                   and a.upper not in _INTERVAL_UNITS))
        ends_operand = isinstance(before, _Group) or (isinstance(before, _Tok) and (
            before.kind in ("qident", "number", "string")
            or (before.kind == "ident" and (before.upper not in _STRUCT
                                            or before.upper in ("END", "NULL", "TRUE", "FALSE")))))
        if is_alias_tok and ends_operand:
            return item[:-1], a.value
    return item, None


def _scan_on_end(nodes, j):
    n = len(nodes)
    while j < n:
        x = nodes[j]
        if _op(x, ","):
            return j
        if _kw(x, "JOIN", "INNER", "CROSS", "STRAIGHT_JOIN", "NATURAL", "FULL"):
            return j
        if _kw(x, "LEFT", "RIGHT") and not (j + 1 < n and isinstance(nodes[j + 1], _Group)):
            return j
        j += 1
    return j


def _conjuncts(nodes):
    """Top-level AND conjuncts of an expression; [] if any top-level OR/XOR/|| exists
    (OR binds looser than AND, so no single conjunct is then guaranteed)."""
    if any(_kw(x, "OR", "XOR") or _op(x, "||") for x in nodes):
        return []
    parts = [[]]
    between = 0
    case_depth = 0
    for x in nodes:
        if _kw(x, "CASE"):
            case_depth += 1
        elif _kw(x, "END") and case_depth:
            case_depth -= 1
        if _kw(x, "BETWEEN"):
            between += 1
        elif _kw(x, "AND") or _op(x, "&&"):
            if between:
                between -= 1
            elif case_depth == 0:
                parts.append([])
                continue
        parts[-1].append(x)
    out = []
    for p in parts:
        if any(_kw(x, "CASE") for x in p):
            continue
        if len(p) == 1 and isinstance(p[0], _Group) and not _is_query_group(p[0]):
            out.extend(_conjuncts(p[0].children))
            continue
        out.append(p)
    return out


def _lit(node):
    if not isinstance(node, _Tok):
        return None
    if node.kind == "number":
        return node.value
    if node.kind == "string" and not node.prefix and "\\" not in node.value:
        return node.value.replace("''", "'")
    return None


def _fact(part, b):
    seq = [x for x in part if not _kw(x, "BINARY")]

    def colref(i):
        if i >= len(seq) or not _is_name(seq[i]) or (
                seq[i].kind == "ident" and seq[i].upper in _STRUCT):
            return None, i
        parts = [_name_of(seq[i])]
        i += 1
        while i + 1 < len(seq) and _op(seq[i], ".") and _is_name(seq[i + 1]):
            parts.append(_name_of(seq[i + 1]))
            i += 2
        if len(parts) == 1:
            if len(b.tables) != 1:
                return None, i
            return (next(iter(b.tables)), parts[0].lower()), i
        if len(parts) == 2 and parts[0].lower() in b.tables:
            return (parts[0].lower(), parts[1].lower()), i
        if len(parts) == 2:
            # A correlated reference to an enclosing block (MySQL resolves the innermost
            # match first, as this loop does). Tagged so it never equals a local alias.
            for anc in list(b.chain())[1:]:
                if parts[0].lower() in anc.tables:
                    return (("outer", anc.id, parts[0].lower()), parts[1].lower()), i
        return None, i

    c1, i = colref(0)
    if c1 is not None:
        rest = seq[i:]
        if len(rest) == 2 and _op(rest[0], "=", "<=>") and _lit(rest[1]) is not None:
            return ("eq", c1, (_lit(rest[1]),))
        if len(rest) == 2 and _op(rest[0], "<>", "!=") and _lit(rest[1]) is not None:
            return ("ne", c1, _lit(rest[1]))
        if len(rest) == 2 and _kw(rest[0], "IN") and isinstance(rest[1], _Group):
            vals = _lit_list(rest[1])
            if vals is not None:
                return ("in", c1, tuple(vals))
        if len(rest) == 3 and _kw(rest[0], "NOT") and _kw(rest[1], "IN") \
                and isinstance(rest[2], _Group):
            vals = _lit_list(rest[2])
            if vals is not None:
                return ("notin", c1, tuple(vals))
        if len(rest) == 2 and _kw(rest[0], "LIKE") and isinstance(rest[1], _Tok) \
                and rest[1].kind == "string" and not rest[1].prefix:
            return ("like", c1, rest[1].value)
        if len(rest) >= 2 and _op(rest[0], "="):
            c2, j = colref(i + 1)
            if c2 is not None and j == len(seq):
                return ("join", c1, c2)
        return None
    if len(seq) >= 3 and _lit(seq[0]) is not None and _op(seq[1], "=", "<=>", "<>", "!="):
        c2, j = colref(2)
        if c2 is not None and j == len(seq):
            if _op(seq[1], "=", "<=>"):
                return ("eq", c2, (_lit(seq[0]),))
            return ("ne", c2, _lit(seq[0]))
    return None


def _lit_list(g):
    vals = []
    for it in _split_top(g.children):
        if len(it) != 1 or _lit(it[0]) is None:
            return None
        vals.append(_lit(it[0]))
    return vals or None


# --------------------------------------------------------------------------------------
# check_statement
# --------------------------------------------------------------------------------------

@dataclass
class Verdict:
    allowed: bool
    reasons: list = field(default_factory=list)
    kind: str = ""
    tables: list = field(default_factory=list)
    install: str = ""

    def __bool__(self):
        return self.allowed


def check_statement(sql, install, *, prefix=None, public_post_types=None, schema=None,
                    residue=False) -> Verdict:
    """Decide whether ``sql`` may run on ``install``.

    ``install``: the name of an install in the config's ``db.installs``, or an
    ``InstallPolicy``. ``prefix`` overrides the table prefix, ``public_post_types`` the public
    post-type list, ``schema`` the one accepted schema qualifier. ``residue=True`` enables the
    single exception (a revision-residue count) and is accepted only on an admin install with
    ``residue_hosts``. With it, the statement must be exactly the residue count shape (see
    ``_Parser.residue_checks``: COUNT(*) / COUNT(DISTINCT <id>) over revision rows, LIKE
    '%<host>%' for the install's residue hosts) and every other statement is refused.
    """
    try:
        pol = _resolve_policy(install, prefix, public_post_types, schema)
    except ValueError as e:
        return Verdict(False, [str(e)])
    name = pol.name
    try:
        if not isinstance(sql, str):
            raise _Reject("statement is not a string")
        if len(sql) > _MAX_LEN:
            raise _Reject(f"statement longer than {_MAX_LEN} characters")
        if "\x00" in sql:
            raise _Reject("NUL byte in statement")
        if residue and (not pol.residue_hosts or pol.views):
            raise _Reject("the residue exception applies only to an admin install with "
                          "residue_hosts configured")
        toks = _tokenize(sql, bs=True)
        try:
            toks_nobs = _tokenize(sql, bs=False)
        except _Reject:
            toks_nobs = None
        if toks_nobs is None or [(t.kind, t.pos, t.end) for t in toks] != \
                [(t.kind, t.pos, t.end) for t in toks_nobs]:
            raise _Reject("string literal boundaries differ with NO_BACKSLASH_ESCAPES",
                          "backslash_ambiguity")
        semis = [k for k, t in enumerate(toks) if t.kind == "op" and t.value == ";"]
        if semis:
            if len(semis) > 1 or semis[0] != len(toks) - 1:
                raise _Reject("more than one statement (';' outside a string literal)")
            toks = toks[:-1]
        if not toks:
            raise _Reject("empty statement")
        for k in range(len(toks) - 1):
            if toks[k].kind == "ident" and toks[k].upper == "FOR" and \
                    toks[k + 1].kind == "ident" and toks[k + 1].upper in ("UPDATE", "SHARE"):
                raise _Reject("FOR UPDATE / FOR SHARE takes locks")
        for k, t in enumerate(toks):
            if t.kind != "ident":
                continue
            u = t.upper
            if u == "REPLACE" and k + 1 < len(toks) and toks[k + 1].kind == "op" \
                    and toks[k + 1].value == "(":
                continue
            # After "name." MySQL reads any word as an identifier (information_schema.tables,
            # r.update); the structural parser still has to accept it as a name.
            if k >= 2 and toks[k - 1].kind == "op" and toks[k - 1].value == "." \
                    and toks[k - 1].pos == toks[k - 2].end and toks[k].pos == toks[k - 1].end \
                    and toks[k - 2].kind in ("ident", "qident"):
                continue
            if u in _DENY:
                raise _Reject(f"keyword {u}: " + _DENY_MSG.get(u, "not allowed in a "
                                                                    "read-only audit"))
            if u in ("SHOW", "EXPLAIN") and k != 0:
                raise _Reject(f"{u} is allowed only at the start of the statement")
        nodes = _tree(toks)
        parser = _Parser(pol, residue)
        kind = parser.statement(nodes)
        if residue:
            parser.residue_checks(kind)
        else:
            parser.post_checks()
        return Verdict(True, [], kind, sorted(parser.tables_read), name)
    except _Reject as e:
        return Verdict(False, [e.reason], "", [], name)
    except RecursionError:
        return Verdict(False, ["statement too deeply nested"], "", [], name)
    except Exception as e:  # any guard bug fails closed
        return Verdict(False, [f"internal guard error ({type(e).__name__}: {e}); fail closed"],
                       "", [], name)


# --------------------------------------------------------------------------------------
# GuardedConnection
# --------------------------------------------------------------------------------------

class GuardRejected(Exception):
    """A statement was refused by the guard. ``.verdict`` holds the reasons."""

    def __init__(self, message, verdict=None):
        super().__init__(message)
        self.verdict = verdict


class GuardSetupError(Exception):
    """The session could not be made read-only or verified; nothing else will run."""


_INTERNAL_SET = "SET SESSION TRANSACTION READ ONLY"
_RO_PROBES = ("SELECT @@SESSION.transaction_read_only", "SELECT @@SESSION.tx_read_only")


class GuardedConnection:
    """Wrap an open DB-API connection so only guard-approved SQL reaches it.

    On construction (and on ``reassert()``, which you must call after any reconnect):
    ``SET SESSION TRANSACTION READ ONLY``, verify ``transaction_read_only`` (MySQL 8) or
    ``tx_read_only`` (MariaDB 10.4) is 1, for a views install verify ``DATABASE()`` is its
    read-only schema, then run ``identity()`` and require ``select_only`` (for a views install
    every SELECT grant must also name only its read-only schema, or the
    ``allowed_databases`` you pass). Any failure raises ``GuardSetupError`` and no user
    statement ever runs. ``attended=True`` (it must be passed explicitly) lets a
    non-SELECT-only identity (an admin alias behind the guard) continue: a ``WARNING`` line
    goes to stderr and an ``identity_override`` record to the log. ``self.identity_result``
    holds the last identity check.

    ``execute(sql)`` runs one approved statement and returns ``fetchall()`` rows; column names
    are in ``.description``. Parameters are refused (the driver would interpolate them after
    the check). Each statement, its verdict and its row count (never the rows) is appended
    to ``log_path`` as JSON, file mode 600.
    """

    def __init__(self, conn, install, log_path, *, prefix=None, public_post_types=None,
                 schema=None, attended=False, allowed_databases=None):
        if not isinstance(attended, bool):
            raise GuardSetupError("attended must be True or False")
        self._conn = conn
        self._policy = _resolve_policy(install, prefix, public_post_types, schema)
        if getattr(self._policy, "attended_only", False) and not attended:
            raise GuardSetupError(
                f"install {self._policy.name!r} is marked attended_only; pass attended=True "
                "only when a person is present to supervise this connection")
        self._attended = attended
        self._allowed_databases = allowed_databases
        self._identity_ok = False
        self.identity_result = None
        self._log_fd = None
        self.description = None
        self._open_log(log_path)
        try:
            self._setup()
        except Exception:
            self.close()
            raise

    # ---- logging ----------------------------------------------------------------
    def _open_log(self, path):
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise GuardSetupError(f"log path {path!r} is not a regular file")
            os.fchmod(fd, 0o600)
        except Exception:
            os.close(fd)
            raise
        self._log_fd = fd
        self.log_path = path

    def _log(self, **rec):
        if self._log_fd is None:
            raise GuardSetupError("log is closed")
        rec = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
               "install": self._policy.name, **rec}
        data = (json.dumps(rec, ensure_ascii=True) + "\n").encode("ascii")
        os.write(self._log_fd, data)

    # ---- session setup ----------------------------------------------------------
    def _raw_scalar(self, sql):
        cur = self._conn.cursor()
        try:
            cur.execute(sql)
            rows = cur.fetchall()
        finally:
            cur.close()
        return rows[0][0] if rows and rows[0] else None

    def _setup(self):
        cur = self._conn.cursor()
        try:
            self._log(verdict="internal", sql=_INTERNAL_SET)
            cur.execute(_INTERNAL_SET)
        finally:
            cur.close()
        value = None
        for probe in _RO_PROBES:
            try:
                value = self._raw_scalar(probe)
            except Exception as e:  # variable name differs by server; try the next
                self._log(verdict="internal", sql=probe, error=type(e).__name__)
                continue
            self._log(verdict="internal", sql=probe, value=str(value))
            break
        if str(value) not in ("1", "ON", "True"):
            raise GuardSetupError("session is not read-only after SET SESSION TRANSACTION "
                                  f"READ ONLY (got {value!r})")
        if self._policy.views:
            rows = self._run("SELECT DATABASE()")
            db = rows[0][0] if rows and rows[0] else None
            if db != self._policy.schema:
                raise GuardSetupError(f"default database is {db!r}, expected the read-only schema "
                                      f"{self._policy.schema!r}")
        self._establish_identity()

    def _establish_identity(self):
        """Refuse every user statement unless the identity is proven SELECT-only."""
        self._identity_ok = False
        try:
            result = self.identity(self._allowed_databases)
        except GuardSetupError:
            raise
        except Exception as e:  # noqa: BLE001 - no identity, no statements
            raise GuardSetupError(f"identity check failed ({type(e).__name__}); "
                                  "nothing else will run") from None
        if result["select_only"]:
            self._identity_ok = True
            return
        if not self._attended:
            raise GuardSetupError(
                "identity is not SELECT-only (" + "; ".join(result["reasons"]) + "); refusing "
                "every statement. Use the read-only DB user, or pass attended=True when an "
                "operator is watching")
        msg = (f"WARNING: sql_guard install {self._policy.name!r}: identity "
               f"{result['current_user']!r} is NOT SELECT-only; continuing only because "
               "attended=True. The statement guard is now the only boundary.")
        print(msg, file=sys.stderr, flush=True)
        self._log(verdict="identity_override", sql="(attended)", warning=msg)
        self._identity_ok = True

    def reassert(self):
        """Re-run the read-only setup and the identity check. Call after any reconnect or
        tunnel fallback."""
        self._identity_ok = False
        self._setup()

    # ---- execution --------------------------------------------------------------
    def check(self, sql, *, residue=False) -> Verdict:
        return check_statement(sql, self._policy, residue=residue)

    def execute(self, sql, params=None, *, residue=False):
        if not self._identity_ok:
            if self._log_fd is not None:
                self._log(verdict="rejected", sql=sql if isinstance(sql, str) else repr(sql),
                          reasons=["identity not established"])
            raise GuardSetupError("identity not established (or not SELECT-only); "
                                  "no statement may run")
        return self._run(sql, params, residue=residue)

    def _run(self, sql, params=None, *, residue=False):
        """Guard check and run, without the identity gate (setup and identity() only)."""
        if params is not None:
            self._log(verdict="rejected", sql=sql if isinstance(sql, str) else repr(sql),
                      reasons=["parameters refused"])
            raise GuardRejected(FAIL_CLOSED_RULES["params"])
        verdict = self.check(sql, residue=residue)
        if not verdict:
            self._log(verdict="rejected", sql=sql if isinstance(sql, str) else repr(sql),
                      reasons=verdict.reasons)
            raise GuardRejected("; ".join(verdict.reasons), verdict)
        self._log(verdict="allowed", sql=sql, kind=verdict.kind, tables=verdict.tables)
        cur = self._conn.cursor()
        try:
            cur.execute(sql)
            rows = cur.fetchall()
            self.description = cur.description
        except Exception as e:
            self._log(verdict="error", sql=sql, error=type(e).__name__)
            raise
        finally:
            cur.close()
        self._log(verdict="done", sql=sql, rows=len(rows))
        return rows

    def identity(self, allowed_databases=None):
        """Identity check: CURRENT_USER() and the SHOW GRANTS classification.

        Runs on construction and on ``reassert()``; you may call it again for the report.
        For a views install the grants must also name only its read-only schema."""
        if allowed_databases is None and self._policy.views:
            allowed_databases = [self._policy.schema]
        user_rows = self._run("SELECT CURRENT_USER()")
        grant_rows = self._run("SHOW GRANTS FOR CURRENT_USER()")
        ok, reasons = classify_grants(grant_rows, allowed_databases=allowed_databases)
        current = user_rows[0][0] if user_rows and user_rows[0] else None
        if isinstance(current, (bytes, bytearray)):
            try:
                current = bytes(current).decode("utf-8")
            except UnicodeDecodeError:
                current = None
        if len(user_rows or []) != 1 or not isinstance(current, str) or not current.strip():
            # No identity established: never report SELECT-only (fail closed).
            ok = False
            reasons = list(reasons) + [
                "SELECT CURRENT_USER() returned no usable row; identity not established"]
            current = None
        result = {
            "current_user": current,
            "select_only": ok,
            "reasons": reasons,
            "grant_lines": len(grant_rows),
        }
        self._log(verdict="identity", sql="(summary)", select_only=ok,
                  current_user=str(result["current_user"]), reasons=reasons)
        self.identity_result = result
        return result

    def close(self):
        self._identity_ok = False
        if self._log_fd is not None:
            try:
                os.close(self._log_fd)
            finally:
                self._log_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------

def _main(argv: Optional[Iterable[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Check a statement or SHOW GRANTS output.")
    ap.add_argument("--config", help="config file (else $SITE_AUDIT_CONFIG, else "
                                     "~/.config/site-audit-kit/config.json)")
    ap.add_argument("--install", help="an install name from the config's db.installs")
    ap.add_argument("--prefix", help="table prefix for this check (an operator setting)")
    ap.add_argument("--public-types",
                    help="comma-separated public post types; may only NARROW the install's "
                         "configured list (the intersection is used)")
    ap.add_argument("--residue", action="store_true",
                    help="the revision-residue count exception (installs with residue_hosts)")
    ap.add_argument("--grants", metavar="FILE", help="classify SHOW GRANTS lines from FILE")
    ap.add_argument("--allowed-db", action="append")
    ap.add_argument("sql", nargs="?")
    a = ap.parse_args(list(argv) if argv is not None else None)
    if a.grants:
        with open(a.grants, encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        ok, reasons = classify_grants(lines, allowed_databases=a.allowed_db)
        print(json.dumps({"select_only": ok, "reasons": reasons}, indent=2))
        return 0 if ok else 1
    if not a.sql or not a.install:
        ap.error("give --install NAME and a statement, or --grants FILE")
    if a.config:
        os.environ["SITE_AUDIT_CONFIG"] = os.path.abspath(os.path.expanduser(a.config))
    types = None
    if a.public_types:
        try:
            configured = tuple(_resolve_policy(a.install).public_post_types)
        except ValueError:
            configured = None  # check_statement reports the install error itself
        if configured is not None:
            wanted = {t.strip() for t in a.public_types.split(",") if t.strip()}
            types = [t for t in configured if t in wanted]  # never wider than the config
            if not types:
                print(json.dumps({"allowed": False, "kind": None, "tables": [],
                                  "reasons": [f"--public-types {a.public_types!r} shares no type with "
                                              f"the configured list {list(configured)}"]}, indent=2))
                return 2
    v = check_statement(a.sql, a.install, prefix=a.prefix, public_post_types=types,
                        residue=a.residue)
    print(json.dumps({"allowed": v.allowed, "kind": v.kind, "tables": v.tables,
                      "reasons": v.reasons}, indent=2))
    return 0 if v.allowed else 1


if __name__ == "__main__":
    sys.exit(_main())
