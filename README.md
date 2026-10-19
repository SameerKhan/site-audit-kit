# Site Audit Kit

A Claude Code plugin for technical SEO audits of **your own** website, with guard rails that
keep the audit from becoming the incident. It ships one skill, `site-audit`, and a set of
small, tested tools the skill drives:

| Tool | What it is for |
|---|---|
| `run_manifest.py` | Pins a run before it starts: run folder, baseline, re-test rows, models, tools, crawler, health URLs |
| `safe_fetch.py` | The only HTTP client the audit uses for your site and for outbound link checks |
| `sql_guard.py` | Read-only statement guard and grant classifier for WordPress databases |
| `sf_supervise.py` | Runs one Screaming Frog crawl through its MCP server, start to redacted export |
| `redact_exports.py` | Removes token, password, session, email and similar values from exports, in place |
| `sfcall.sh` | Calls Screaming Frog's MCP server on loopback: read-only tools by hand, everything else only for `sf_supervise.py` |
| `bound.sh` | A hard time limit for any command, for systems without GNU `timeout` |
| `audit_config.py` | Loads and validates the one JSON config every tool reads |


Everything is Python 3.9+ standard library plus `sh` and `perl` (for `bound.sh`). No
dependency is installed, and none is needed: `sql_guard.py` wraps a database connection you
open with your own driver. No test touches the internet.

**With no config the tools allow no hosts.** With no config file, the host allowlist is empty,
no crawl host is set, no database install exists and no Screaming Frog base folder is known, so
fetches, crawls and queries are refused. Explicit command-line overrides (`safe_fetch.py
--allow-host` and `--external`) widen that for one call; using them is the operator's
deliberate choice, not a default. The one exception is the local Screaming Frog server:
`run_manifest.py` and `sfcall.sh` still call the default loopback MCP URL
(`http://127.0.0.1:11435/mcp`) with read-only tools to record its state. The shipped
`config.example.json` uses only names under the reserved `.example` domain, which never
resolve, and defines no database install, so it stays inert until you edit it.

**What the guarantees cover.** They protect against accidents and against untrusted content (pages,
redirects, DNS answers, crawl data, SQL written by an agent). They do not defend against the
person running the tools: command-line overrides, the `SITE_AUDIT_SUPERVISED` and
`SF_SUPERVISE_TESTING` switches, `attended=True` and a custom `InstallPolicy` passed to
`sql_guard` in code are trusted operator inputs, as is editing the scripts. For databases, the
real boundary is a read-only database user; `sql_guard.py` is a filter in front of it.

## Install

In Claude Code:

```
/plugin marketplace add SameerKhan/site-audit-kit
/plugin install site-audit-kit@site-audit-kit
```

Or copy the skill by hand:

```
git clone https://github.com/SameerKhan/site-audit-kit
mkdir -p ~/.claude/skills
cp -R site-audit-kit/plugins/site-audit-kit/skills/site-audit ~/.claude/skills/
```

Then point `SKILL_DIR` at the installed skill folder (the folder that holds `SKILL.md`) and
create your config:

```
# plugin install (Claude Code keeps plugins under ~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/):
SKILL_DIR=$(ls -d ~/.claude/plugins/cache/site-audit-kit/site-audit-kit/*/skills/site-audit | tail -n 1)
# manual copy:
SKILL_DIR=~/.claude/skills/site-audit

mkdir -p ~/.config/site-audit-kit
cp "$SKILL_DIR/config.example.json" ~/.config/site-audit-kit/config.json
chmod 600 ~/.config/site-audit-kit/config.json
# edit it: replace every your-site.example value with your own hosts
python3 "$SKILL_DIR/scripts/audit_config.py"   # prints the effective config (exit 0) or the error (exit 2)
```

Ask Claude to "audit my website" (or "run a technical SEO check of my blog") and the skill
takes it from there.

## Threat model

An audit fetches pages it does not control, follows redirects it did not choose, reads
databases that hold user data, drives a desktop crawler that can write files and run code, and
produces exports full of URLs harvested from analytics. The kit assumes:

- **Pages and redirects are hostile.** A page or redirect can point at `169.254.169.254`, at
  `localhost`, at a private network, at a look-alike Unicode host name or at a host you retired
  after a compromise. A DNS answer can change between the check and the connection
  (rebinding). A server can trickle one byte a second or send gigabytes.
- **Exports leak.** Crawl and analytics exports routinely contain password-reset tokens, magic
  links, session ids and email addresses in query strings. Anything that reaches a report, a
  ticket, a chat or another model is effectively published. The same holds for what a tool
  prints: the model reads stdout.
- **The model can make mistakes.** A statement the model writes may be a write, a lock, a
  sleep or a read of the users table. A crawl may run for hours or start on the wrong host. A
  signal may arrive mid-crawl, or a reply may be lost after a crawl was started. The tools
  enforce the rules mechanically instead of trusting the prompt.
- **Local configuration is trusted only if it is private.** The config file must be owned by
  you and not writable by group or others; a symlinked config is refused. Whoever can write it
  can widen the allowlist.

Out of scope: a malicious local user with your privileges, a compromised Python interpreter,
and the Screaming Frog application itself (the kit limits which of its MCP tools are called,
not what the application does or stores).

## What each tool guarantees

### safe_fetch.py

- GET only; `http`/`https` only; ports 80 and 443 only; no userinfo, cookies or auth headers;
  `~/.netrc` and proxy variables are never used (proxy variables are removed from the
  environment).
- Host allowlist, enumerated, never globbed. Host names must be plain ASCII labels; soft
  hyphens, zero-width characters, full-width dots and NFKC look-alikes are refused before any
  policy check or DNS lookup.
- `forbidden_hosts` are always refused (and their subdomains, unless you turn that off).
  `--probe` fetches only the exact `probe_paths` of a forbidden host and never follows its
  redirects. `--external` allows any public host that is not one of yours.
- DNS is resolved once per hop; every address is checked (loopback, RFC 1918, link-local,
  cloud metadata, CGNAT, multicast, reserved, NAT64, 6to4, Teredo, IPv4-mapped); one bad
  record refuses the hop. The socket connects to the vetted IP while TLS SNI, the certificate
  check and the Host header use the name, so a rebinding resolver cannot swap the address.
  IPv4 only by default (network-specific NAT64 cannot be detected).
- At most 5 redirects, each re-validated. One 30 s wall deadline per fetch covers DNS, permit
  waits, connect, TLS, headers, body, redirects and retries; a watchdog cuts trickling servers
  off. 5 MB body cap. `--deadline` (and the library's `deadline`) accepts any value above 0 up
  to 60 s, so a slow re-test may raise it above the 30 s default; `--max-bytes` (`max_body`)
  may only lower the 5 MB cap. Anything outside those bounds is refused (exit 2). A body
  failure after a 2xx is an error. Compressed bodies are refused (`identity` is requested).
- 16 requests at once overall, 2 per host. The CLI requires `--log PATH` (exit 2 without it)
  unless you pass `--no-log` explicitly. The log path is checked before any request is sent:
  it must resolve under `run_root`, must not be a symlink, and its folder must already exist
  and be writable (the run manifest creates the run folder). Every request, refusals included,
  is logged as one JSON line with every query value replaced by `X`; the file is mode 600.
- What it prints is redacted too. The CLI output (`FetchResult.to_dict()`) shows the URL, the
  final URL, every redirect-chain entry and the `Location` and `Content-Location` headers with
  every query value replaced by `X`, and `Set-Cookie`, `Cookie`, `Authorization`,
  `Proxy-Authorization`, `WWW-Authenticate` and `Proxy-Authenticate` as `REDACTED`. The body
  is printed only with `--body`, as served. `--cache-compare --body` includes both bodies.
- Exit codes: 0 ok, 1 the fetch failed or was refused, 2 usage or configuration error.

### sql_guard.py

- `classify_grants`: SELECT-only means every `SHOW GRANTS` line is `USAGE` or `SELECT`, with no
  role grant, `PROXY`, `FILE`, dynamic privilege or `WITH GRANT OPTION`; anything it cannot
  parse fails. For a read-only views install it also requires every grant to name that schema
  exactly (escaped underscores at database level, because `_` is a wildcard there). Password
  hashes are redacted from every reason.
- `check_statement`: a real tokenizer and structural parser for the SELECT subset an audit
  needs. Only allowlisted functions; no comments, multiple statements, locks, `INTO`, variables,
  double-quoted strings, charset introducers, recursive CTEs, index hints or table functions.
  Only the install's tables: posts, postmeta and options with row filters (published, public
  post types, revisions excluded, allowlisted option names and meta keys), plus configured
  extra tables. `users`, `usermeta`, `comments`, `commentmeta` and `post_password` can never be
  allowed, even by config. Anything ambiguous is refused (`FAIL_CLOSED_RULES` lists why).
- Extra tables are checked by their full name. An extra table is refused when the table prefix
  plus its name ends with `users`, `usermeta`, `comments`, `commentmeta`, `posts`, `postmeta`
  or `options`, so splitting a name between the prefix and the extra table (prefix `wp` with
  `_users`, or `wp_po` with `sts`) cannot reopen a protected table. The same check runs for
  config installs, a hand-built `InstallPolicy` and the CLI's `--prefix`.
- Install values are type checked, never coerced: `views` and `attended_only` must be JSON
  booleans; every list must be a list of non-empty strings; `prefix` is 1 to 32 of
  `A-Z a-z 0-9 _`; `schema` is a plain identifier (letters, digits, `_`); extra table names are
  `A-Z a-z 0-9 _`, compared lowercased (a hand-built `InstallPolicy` must use lowercase).
- `GuardedConnection(conn, install, log_path, *, prefix=None, public_post_types=None,
  schema=None, attended=False, allowed_databases=None)`. On construction (and on
  `reassert()`, which you call after any reconnect) it sets `SESSION TRANSACTION READ ONLY` and
  verifies it took effect, checks the default database of a views install, then runs the
  identity check (`CURRENT_USER()` plus `SHOW GRANTS` through `classify_grants`). Unless the
  identity is proven SELECT-only it raises `GuardSetupError` and no statement ever runs. Only
  `attended=True`, passed explicitly as a real boolean, lets a non-SELECT-only identity
  continue: a `WARNING` line goes to stderr and an `identity_override` record to the log. An
  install marked `attended_only` refuses to start without `attended=True`. `execute(sql)` runs
  one approved statement and returns the rows; DB-API parameters are refused. Every statement
  (never the rows) is logged to a mode-600 file.
- The guard is a filter, not a permission. The real boundary is a SELECT-only database user.
- Trusted inputs: the `prefix`, `public_post_types` and `schema` overrides of `check_statement`
  and `GuardedConnection`, `attended=True`, and any custom `InstallPolicy` object you pass
  instead of an install name, come from the operator and are not checked against the config
  (a custom policy still passes the type and extra-table checks). Do not build them from page
  content or model output. On the CLI, `--public-types` may only narrow the install's
  configured list (the intersection is used) and `--prefix` sets the table prefix.
- CLI exit codes: 0 allowed (or SELECT-only for `--grants`), 1 refused, 2 usage error.

The kit opens no database connection and ships no driver. Bring your own DB-API driver (for
example mysql-connector-python or PyMySQL; the kit installs neither) and pass the open
connection in:

```
import sys
sys.path.insert(0, "/path/to/skills/site-audit/scripts")
import mysql.connector                     # your own driver
from sql_guard import GuardedConnection, GuardSetupError

conn = mysql.connector.connect(option_files="/home/you/.my.cnf", option_groups=["audit_site"])
try:
    g = GuardedConnection(conn, "site", "/home/you/site-audit/run-XXXXXXXX/sql.log")
except GuardSetupError as e:
    raise SystemExit(f"not a SELECT-only identity: {e}")
rows = g.execute("SELECT ID, post_title FROM wp_posts "
                 "WHERE post_type = 'page' AND post_status = 'publish'")
```

Keep the credentials in your driver's option file, not in code, a prompt or a chat.

### sf_supervise.py

- Refuses to start unless the spider is idle, the start and health URLs are on your configured
  crawl hosts (no port, no userinfo, no query except the cache-bypass query; a plain-http path
  may hold no `.` or `..` segment, raw or percent-encoded, and no `//`), the profile path is
  absolute and the export folder is safe.
- Owns a crawl only when Screaming Frog lists the running crawl id under this run's name and
  that id did not exist before; it never pauses or loads a crawl it cannot prove is its own.
  Once it owns one, a progress reply naming any other crawl id stops it (`ownership-lost`, exit
  1): nothing is paused, loaded or exported, and completion counts only for the owned id.
- A lost `sf_crawl` reply (timeout, dropped connection, HTTP error, unparsable reply) is "start
  uncertain", never "nothing started": for up to 600 s it checks progress and the crawl list.
  A crawl it can prove is its own is adopted and supervised; any other running crawl, or no way
  to verify, is exit 8; idle throughout is exit 1.
- Polls health URLs through `safe_fetch`; two failed rounds pause the crawl. Enforces a hard
  time limit (at most 4 hours). TERM, INT and HUP pause the owned crawl and verify the pause.
  Any unexpected error after the start (including a failed write of its state files) runs the
  same verified pause.
- Calls only six MCP tools (`sf_crawl_progress`, `sf_crawl`, `sf_pause_crawl`,
  `sf_list_crawls`, `sf_load_crawl`, `sf_export_seo_element_urls`), through the bundled
  `sfcall.sh` with `SITE_AUDIT_SUPERVISED=1` set for its own calls. The redactor is the bundled
  `redact_exports.py`; the `SF_SFCALL` and `SF_REDACT_SCRIPT` overrides are honoured only under
  the test switch `SF_SUPERVISE_TESTING=1` and only for files inside the kit's own `tests/`
  folder.
- With `--export` it exports Internal:All to `<screaming_frog.base_dir>/run-<name>/`, locks
  that folder to 700/600 at once, copies the file with mode 600 from the first byte into its
  `--out` folder (default `<run_root>/sf/run-<name>`), then runs `redact_exports.py
  --fix-perms` and `--check` on both copies, so the copy in `base_dir` is redacted in place
  too. Anything short of a clean `--check` is exit 7. A failed or partial export still gets the
  lockdown and the redaction gate on whatever was written.
- URLs in `supervise.json`, `progress.log`, stderr and the `--dry-run` plan have every query
  value replaced by `X`; only `sf_crawl` receives the real start URL. The dry-run plan shows
  the effective MCP URL (`SF_MCP_URL`, else `screaming_frog.mcp_url`).
- The kit cannot delete stored crawls: `sf_clear_crawl` is never callable. Screaming Frog keeps
  each crawl, unredacted, in its own crawl store; delete it in the Screaming Frog app when you
  no longer need it.

| Exit | Meaning | `status` in supervise.json |
|---|---|---|
| 0 | Done: crawl complete and loaded; with `--export` exported, redacted and `--check` clean | `done`, `exported` |
| 1 | Failure: did not start, ownership unproven or lost, recorded crawl id missing, export failed but what it wrote is redacted, unexpected error with our crawl verified stopped | `failed`, `ownership-unproven`, `ownership-lost` |
| 2 | Usage or preflight refusal | |
| 3 | MCP server unreachable (at preflight, or 5 polls in a row); the crawl was NOT paused | `mcp-unreachable` |
| 5 | Site health failure; crawl verified paused | `paused-health` |
| 6 | Hard limit; crawl verified paused, partial | `partial` |
| 7 | Export not verified redacted, or the export may still be writing (the spider was not verified idle after it) | `export-unredacted` |
| 8 | Pause not verified: server gone, crawl not provably ours, the pause never landed, or an uncertain start that could not be reconciled. Replaces 5, 6 and 128+n whenever the crawl could not be verified stopped | `pause-not-verified` |
| 128+n | Stopped by signal n (143 TERM, 130 INT, 129 HUP); our crawl verified paused or not running | `interrupted` |

Statuses while it runs: `starting`, `running`, `start-uncertain`, `crawl-complete`.

### redact_exports.py

- Replaces the value of every built-in sensitive parameter (tokens, keys, passwords, signatures,
  sessions, one-time links, email) with `REDACTED`, keeping the key, in every encoding a URL
  ends up in: plain, HTML entities, JSON escapes, percent-encoding at any depth, UTF-16/32.
- The built-in list can only be extended (`--extra-params`, `redaction.extra_params`); no
  option replaces or shortens it.
- `--check` changes nothing. Binary files are never rewritten but are scanned; a value inside
  one fails the run.
- A regular file with more than one hard link is never rewritten or chmodded (its other links,
  possibly outside the tree, would keep the raw bytes). It is listed as `UNSCANNED` and the run
  exits 1, in both modes. Copy it out (`cp`, not `ln`) and run again.
- Never follows a symlink, writes through a mode-600 temp file and an atomic rename, never
  prints a value. `--fix-perms` makes folders 700 and files 600 first, through the open
  descriptor. An entry that cannot be opened (mode 000) is changed with the platform's
  no-follow chmod (macOS); where Python has none (Linux), through an `O_NOFOLLOW` descriptor,
  or for an entry that cannot be opened for reading, an `O_PATH` descriptor changed via
  `/proc/self/fd`. Where neither is available it is an error (exit 2), never a chmod by name.
- Exit codes (both modes): 0 clean or fully redacted; 1 a value remains (`--check`), a file was
  `UNSCANNED`, or a binary file holds a value; 2 usage error, refused path, or I/O error.

### run_manifest.py

- Loads the config, then checks the run folder (inside `run_root`, owned by you, mode 700)
  before any network, subprocess or file check; when that fails, nothing else runs and nothing
  is written. It creates the run folder (and `run_root`, mode 700) when absent.
- REQUIRED tools are `perl` and `python3` (curl is not used).
- Picks the newest findings file that has a real review record (not one inside a code block,
  a comment, or marked "not done"), reads only regular files directly inside the baseline
  folder, and turns its findings into re-test rows.
- For every configured reviewer model it checks that the CLI is present and answers (and, for
  Gemini with `list_args`, that the CLI lists the model); it does not prove the model itself is
  usable. No silent substitution. The Codex model is pinned by a `-c model=<model>` override;
  no Codex configuration file is read.
- Parses the DB config file as a syntax tree only; it is never imported or run.
- Fetches health URLs only through `safe_fetch`. In `manifest.json` they are lists of
  `{url, status, ...}` entries (`live.status`, `live.html`) with every query value replaced by
  `X`, and the summary prints them the same way.
- Exit codes: 0 every REQUIRED item passed, 2 a REQUIRED item failed.

### sfcall.sh and bound.sh

- `sfcall.sh --list` or `sfcall.sh <tool> ['<json-object>']`. The arguments must be one JSON
  object (no array, string or number, no `NaN` or `Infinity`, no extra positional arguments).
- The MCP URL (`screaming_frog.mcp_url`, and the `SF_MCP_URL` override, validated the same way)
  must be `http://` to `127.0.0.1`, `[::1]` or `localhost` with an explicit port and an optional
  path; no userinfo, query, fragment or whitespace. Proxy variables (`http_proxy`,
  `HTTPS_PROXY`, `all_proxy` and the rest) are never used. A reply larger than 32 MiB is
  refused (exit 3).
- Read-only tools run by hand when they are in `screaming_frog.allowed_tools`:
  `sf_crawl_progress`, `sf_list_crawls`, `sf_list_allowed_base_directory`,
  `sf_list_directories` and `sf_list_available_*`. Every other `sf_*` tool, including any name
  the kit does not know, is supervised-only: refused unless `SITE_AUDIT_SUPERVISED=1` is set,
  which `sf_supervise.py` sets for its own calls. Under that switch, `sf_crawl`,
  `sf_resume_crawl`, `sf_load_crawl`, `sf_pause_crawl`, `sf_export_seo_element_urls`,
  `sf_generate_bulk_export` and `sf_generate_report` run even when not listed; any other
  supervised-only tool must also be listed. **Crawls go through `sf_supervise.py` only.**
- Never callable, whatever the config or environment (`SF_NEVER_TOOLS` in `audit_config.py`):
  `sf_run_node_js_script`, `sf_npm_install`, `sf_write_text_file`, `sf_read_text_file`,
  `sf_open_url_in_browser`, `sf_clear_crawl`, `sf_url_content`, `sf_url_info`, `sf_url_links`,
  `sf_get_url_screenshot`.
- The session id is kept per server URL in `<run_root>/sf/.sid-<hash of the URL>` (with a lock
  file next to it), so a session id is never sent to a different server.
- Exit codes: 0 ok; 2 usage, configuration, a refused MCP URL or a tool that is not allowed;
  3 server unreachable, HTTP error or a reply over 32 MiB; 4 JSON-RPC or tool error.
- `bound.sh <seconds> <command>` runs a command in its own process group and kills the whole
  group at the deadline or when it is itself killed, so nothing is orphaned. Exit 124 on
  timeout, 127 if the command cannot start, 128+n if it died from signal n, 2 on bad usage,
  else the command's own code.

## Config reference

The file is JSON. Resolution: `--config PATH`, else `$SITE_AUDIT_CONFIG`, else
`~/.config/site-audit-kit/config.json`. An explicit or environment path that does not exist is
an error, and so is an empty `--config` or an empty `SITE_AUDIT_CONFIG` (never a fall-through to
the next source); a missing default file means the defaults below. Unknown keys are refused.
Objects merge with the defaults; lists replace them. A top-level `_comment` key is ignored.
`sfcall.sh` has no `--config`; it reads `$SITE_AUDIT_CONFIG` or the default file.

The file itself must be:

- a regular file (a FIFO or device is refused without blocking), not a symlink, owned by you
  and not writable by group or others;
- UTF-8 without a byte-order mark (UTF-16 and NUL bytes are refused), at most 1 MiB (a larger
  file is refused, never truncated);
- valid JSON with no duplicate key at any level, nested at most 32 levels deep (including
  `_comment`), with an object at the top.

`python3 audit_config.py [--config PATH]` prints the effective configuration and exits 0, or
prints the error and exits 2. Every rule below is checked there, so a broken value is reported
before any tool runs.

| Key | Default | Meaning and rules |
|---|---|---|
| `allowed_hosts` | `[]` | Hosts `safe_fetch` may fetch. Fully qualified lowercase ASCII DNS names only: no wildcard, IP literal, single label or numeric last label |
| `owned_domains` | `[]` | Your domains; never treated as external in `--external` mode (lowercase ASCII host names) |
| `forbidden_hosts` | `[]` | Hosts always refused (for example a compromised subdomain); may not overlap `allowed_hosts` |
| `forbid_subdomains_of_forbidden` | `true` | Refuse every subdomain of a forbidden host too (a JSON boolean) |
| `probe_paths` | `{}` | `{forbidden_host: ["/exact/path"]}` fetchable only with `--probe`; paths start with `/`, no query or fragment |
| `cache_bust_query` | `null` | One plain `key=value` that bypasses your page cache; also the only query crawl and health URLs may carry |
| `run_root` | `"~/site-audit"` | Every run folder, log and local export copy lives here (mode 700). The Screaming Frog export itself is first written under `screaming_frog.base_dir`, outside `run_root`, and that copy stays there (locked 700/600 and redacted in place). Must be absolute or start with `~/`, and may not be `/` or `~` itself |
| `crawl.hosts` | `[]` | Hosts a crawl may start from; must also be in `allowed_hosts` |
| `crawl.http_paths` | `[]` | Plain-http exceptions: `[{"host": <a crawl host>, "path_prefix": "/blog"}]` (not `/`, no trailing slash) |
| `crawl.health_urls` | `[]` | URLs polled during a crawl (default for `--health`) |
| `health.status_urls` | `[]` | Must answer 200 before crawling |
| `health.html_urls` | `[]` | Must answer 200 with HTML before crawling; crawls are held until set |
| `screaming_frog.mcp_url` | `"http://127.0.0.1:11435/mcp"` | The MCP server: `http://` to `127.0.0.1`, `[::1]` or `localhost` with an explicit port and an optional path; no userinfo, query or fragment. `SF_MCP_URL` overrides it and is validated the same way |
| `screaming_frog.base_dir` | `null` | The server's allowed base folder; required for crawls (`null` or a non-empty path) |
| `screaming_frog.profiles_dir` | `null` | Folder of `.seospiderconfig` profiles (default: `base_dir`; `null` or a non-empty path) |
| `screaming_frog.project_name` | `"site-audit"` | Project name passed to `sf_crawl` (1 to 64 of letters, digits, `.`, `_`, `-`) |
| `screaming_frog.allowed_tools` | the read-only tools | Tools `sfcall.sh` may call by hand; supervised-only tools also need `SITE_AUDIT_SUPERVISED=1` |
| `baseline.dir` | `null` | Folder of previous findings files (`--baseline-dir` overrides; `null` or a non-empty path) |
| `baseline.findings_regex` | `^site-audit-(?P<date>...)(?:-(?P<n>\d+))?\.md$` | Findings file names; must compile and have the named groups `date` and `n` |
| `baseline.companion_suffixes` | `["runbook", "decisions", "baseline-delta"]` | Companion files `<stem>-<suffix>.md` |
| `baseline.review_heading` | `"review record"` | The `##`/`###` heading that marks a reviewed findings file (non-empty) |
| `baseline.fallback_file` | `null` | File name in `baseline.dir` used when no reviewed findings file exists (no path separator) |
| `baseline.fallback_date` | `null` | Date of the fallback file (`YYYY-MM-DD`) |
| `baseline.fallback_also_read` | `[]` | Extra file names listed alongside the fallback |
| `baseline.notes_regex` | `^screaming-frog-run...-(?P<date>...)...\.md$` | Crawl note files newer than the baseline; needs the named group `date` |
| `baseline.notes_run_regex` | `^screaming-frog-run(\d+)-\d{4}-\d{2}-\d{2}` | Row prefix `R<group 1>` for a note; must compile and have at least one capture group |
| `baseline.method_table_file` | `null` | Markdown with `\| ID \| P/A \| finding \| measured in \|` rows (`null` or a non-empty path) |
| `baseline.method_table_heading` | `"re-test table"` | The `##` heading of that table (a non-empty string) |
| `models.gemini` | `{"model": "", "binary": "", "list_args": []}` | Reviewer leg; empty model means not configured. With `list_args`, `binary list_args` must list the model |
| `models.codex` | `{"model": "", "binary": "codex"}` | Reviewer leg pinned with `-c model=<model>`; `~/.codex` is never read |
| `db.config_file` | `null` | Python file defining `DATABASES = {alias: {...}}`, parsed, never run (`null` or a non-empty path) |
| `db.readonly_aliases` | `[]` | Aliases of the read-only DB user that must exist in `DATABASES` |
| `db.public_post_types` | `["post", "page"]` | Default public post types for every install |
| `db.installs` | `{}` | `{name: install}`, see below; names are 1 to 64 of letters, digits, `_`, `-` |
| `redaction.extra_params` | `[]` | Parameter names added to the redactor's built-in list |

More rules:

- **Health URLs** (`crawl.health_urls`, `health.status_urls`, `health.html_urls`): plain
  printable ASCII `http://` or `https://` URLs with a valid host and port, no userinfo, no
  fragment, and no query unless it is exactly `cache_bust_query`.
- **`null` and `""`.** For an optional path, `null` means unset and `""` is refused. For a model
  `binary`, `null` means the default binary name and `""` is refused once that model is set.
  A model name is a string (empty: not configured).

Install keys (`db.installs.<name>`), all optional. Both `audit_config.py` and `sql_guard.py`
check the types; nothing is coerced.

| Key | Default | Meaning and type |
|---|---|---|
| `prefix` | `"wp_"` | Table prefix: 1 to 32 of `A-Z a-z 0-9 _` |
| `views` | `false` | JSON boolean: the connection's default database is a read-only schema of views |
| `schema` | `null` | The only schema qualifier accepted (required with `views`); a plain identifier |
| `public_post_types` | `db.public_post_types` | `null` or a list of post type names whose `post_content` may be read |
| `attended_only` | `false` | JSON boolean: `GuardedConnection` refuses this install unless `attended=True` |
| `option_names` | `siteurl`, `home`, `permalink_structure`, `blog_public` | List of readable `wp_options` names |
| `meta_keys` | `_wp_page_template` | List of readable `wp_postmeta` keys |
| `meta_prefixes` | `rank_math_`, `_yoast_wpseo_` | List of readable `wp_postmeta` key prefixes (no `""` or `%`) |
| `template_post_types` | `[]` | List of builder template types whose meta may be read |
| `extra_tables` | `terms`, `term_taxonomy`, `term_relationships` | List of extra readable tables (`A-Z a-z 0-9 _`, compared lowercased); refused when prefix plus name ends with a protected core table (see `sql_guard.py`) |
| `columns` | `{}` | Narrow `posts`, `postmeta` or `options` to a non-empty list of core columns (never `post_password`) |
| `residue_hosts` | `[]` | List of host names; enables one exception: a COUNT of revision rows containing these hosts |
| `residue_meta_key` | `"_elementor_data"` | Meta key the residue count may join on |

## Running the tests

From the repository root, everything CI runs (invariants plus all six suites):

```
bash scripts/check.sh
```

One suite at a time:

```
cd plugins/site-audit-kit/skills/site-audit/scripts
python3 -m unittest discover -s tests/safe_fetch   # or config, sql_guard, redact, manifest, sf_supervise
```

Every suite points `SITE_AUDIT_CONFIG` at a throwaway file, so your own config never changes a
result. The `safe_fetch` and `sf_supervise` suites start local `127.0.0.1` servers (a fake MCP
server and fake health pages); the TLS tests need the `openssl` command and skip without it.
CI runs `scripts/check.sh` on Python 3.9 and 3.12. One live test exists and is off by default:
set `SITE_AUDIT_MANIFEST_LIVE=1` (and optionally `SITE_AUDIT_LIVE_CONFIG`) to run one manifest
build against your real configuration and network.

## Limits and non-goals

- **Your own sites only.** The kit is built to audit hosts you list. It is not a scanner for
  other people's sites and has no stealth, rate-evasion or authentication features.
- **Not an SEO oracle.** The tools make measurement safe; they do not decide what matters. The
  skill still needs judgement, a second method for every claim, and a review before anyone acts.
- **WordPress and MySQL/MariaDB only** for `sql_guard`, and only the SELECT subset an audit
  needs. It does not open connections; you bring a DB-API connection.
- **Screaming Frog with its MCP server** for crawls, on loopback only. Only the Internal:All
  export is supported; bulk exports and reports are out of scope for this version. The kit
  cannot delete stored crawls.
- **IPv4 by default.** IPv6 is available in the library (`allow_ipv6=True`) but not on the CLI.
- **No IDNA.** Internationalised host names are refused rather than converted.
- **The guard is not the boundary.** Use a SELECT-only database user; `sql_guard` is defence
  in depth on top of it.
- **No ticketing, chat or publishing.** The kit writes files under `run_root`, your baseline
  folder and Screaming Frog's `base_dir`. Filing or sharing results is up to you.
