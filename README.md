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
| `sfcall.sh` | Calls Screaming Frog's MCP server over HTTP: read-only tools directly, crawl and export tools only for `sf_supervise.py` |
| `bound.sh` | A hard time limit for any command, for systems without GNU `timeout` |
| `audit_config.py` | Loads and validates the one JSON config every tool reads |

Everything is Python 3.9+ standard library plus `sh` and `perl` (for `bound.sh`). No
dependency is installed. No test touches the internet.

**With no config the tools allow no hosts.** With no config file, the host allowlist is empty,
no crawl host is set, no database install exists and no Screaming Frog base folder is known, so
fetches, crawls and queries are refused. Explicit command-line overrides (`safe_fetch.py
--allow-host` and `--external`) widen that for one call; using them is the operator's
deliberate choice, not a default. The shipped `config.example.json` uses only names under the
reserved `.example` domain, which never resolve, and defines no database install, so it stays
inert until you edit it.

**What the guarantees cover.** They protect against accidents and against untrusted content (pages,
redirects, DNS answers, crawl data, SQL written by an agent). They do not defend against the
person running the tools: command-line overrides, the `SITE_AUDIT_SUPERVISED` and
`SF_SUPERVISE_TESTING` switches, and a custom `InstallPolicy` passed to `sql_guard` in code are
trusted operator inputs, as is editing the scripts. For databases, the real boundary is a
read-only database user; `sql_guard.py` is a filter in front of it.

## Install

In Claude Code:

```
/plugin marketplace add SameerKhan/site-audit-kit
/plugin install site-audit-kit@site-audit-kit
```

Or copy the skill by hand: `git clone https://github.com/SameerKhan/site-audit-kit` and
`cp -r site-audit-kit/plugins/site-audit-kit/skills/site-audit ~/.claude/skills/`.

Then create your config (paths below are inside the installed skill folder):

```
mkdir -p ~/.config/site-audit-kit
cp skills/site-audit/config.example.json ~/.config/site-audit-kit/config.json
chmod 600 ~/.config/site-audit-kit/config.json
# edit it: replace every your-site.example value with your own hosts
python3 skills/site-audit/scripts/audit_config.py      # prints the effective config or the error
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
  ticket, a chat or another model is effectively published.
- **The model can make mistakes.** A statement the model writes may be a write, a lock, a
  sleep or a read of the users table. A crawl may run for hours or start on the wrong host. A
  signal may arrive mid-crawl. The tools enforce the rules mechanically instead of trusting the
  prompt.
- **Local configuration is trusted only if it is private.** The config file must be owned by
  you and not writable by group or others; a symlinked config is refused. Whoever can write it
  can widen the allowlist.

Out of scope: a malicious local user with your privileges, a compromised Python interpreter,
and the Screaming Frog application itself (the kit limits which of its MCP tools are called,
not what the application does).

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
  off. 5 MB body cap. `--deadline` and `--max-bytes` (and the library constructor) may only
  lower these: the deadline may go up to a documented maximum of 60 s for slow re-tests, the
  body cap never above 5 MB; anything higher is refused (exit 2). A body failure after a 2xx is an error. Compressed bodies are refused
  (`identity` is requested).
- 16 requests at once overall, 2 per host. The CLI requires `--log PATH` (exit 2 without it)
  unless you pass `--no-log` explicitly. With a log, every request, refusals included, is
  logged as one JSON line with every query value replaced by `X`; the log must live under
  `run_root`, is never a symlink and is mode 600.

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
- `GuardedConnection`: sets `SESSION TRANSACTION READ ONLY` and verifies it took effect before
  any statement, checks the default database of a views install, refuses DB-API parameters,
  and logs every statement (never the rows) to a mode-600 file.
- The guard is a filter, not a permission. The real boundary is a SELECT-only database user.
- Trusted inputs: the `prefix`, `public_post_types` and `schema` overrides of `check_statement`
  and `GuardedConnection`, and any custom `InstallPolicy` object you pass instead of an install
  name, come from the operator and are not checked against the config. Do not build them from
  page content or model output. On the CLI, `--public-types` may only narrow the install's
  configured list (the intersection is used) and `--prefix` sets the table prefix.

### sf_supervise.py

- Refuses to start unless the spider is idle, the start and health URLs are on your configured
  crawl hosts (no port, no userinfo, no query except the cache-bypass query), the profile path
  is absolute and the export folder is safe.
- Owns a crawl only when Screaming Frog lists the running crawl id under this run's name and
  that id did not exist before; it never pauses or loads a crawl it cannot prove is its own.
- Polls health URLs through `safe_fetch`; two failed rounds pause the crawl. Enforces a hard
  time limit (at most 4 hours). TERM, INT and HUP pause the owned crawl and verify the pause.
- Calls only six MCP tools, through the bundled `sfcall.sh` with `SITE_AUDIT_SUPERVISED=1` set for
  its own calls. The redactor is the bundled `redact_exports.py`; the `SF_SFCALL` and
  `SF_REDACT_SCRIPT` overrides are honoured only under the test switch
  `SF_SUPERVISE_TESTING=1` and only for files inside the kit's own `tests/` folder. Exports land in a folder that is locked to 700/600 at once, are
  copied with mode 600 from the first byte, then redacted and checked; anything short of a
  clean `--check` is exit 7.

### redact_exports.py

- Replaces the value of every built-in sensitive parameter (tokens, keys, passwords, signatures,
  sessions, one-time links, email) with `REDACTED`, keeping the key, in every encoding a URL
  ends up in: plain, HTML entities, JSON escapes, percent-encoding at any depth, UTF-16/32.
- The built-in list can only be extended (`--extra-params`, `redaction.extra_params`); no
  option replaces or shortens it.
- `--check` changes nothing. Exit 1: a file was left unscanned or a value remains. Exit 2: a
  usage, config or I/O error (for example a path that cannot be opened). Binary files are never
  rewritten but are scanned; a value inside one fails the run.
- Never follows a symlink, writes through a mode-600 temp file and an atomic rename, never
  prints a value. `--fix-perms` makes folders 700 and files 600 first.

### run_manifest.py

- Loads the config, then checks the run folder (inside `run_root`, owned by you, mode 700)
  before any network, subprocess or file check; when that fails, nothing else runs and nothing
  is written.
- Picks the newest findings file that has a real review record (not one inside a code block,
  a comment, or marked "not done"), reads only regular files directly inside the baseline
  folder, and turns its findings into re-test rows.
- For every configured reviewer model it checks that the CLI is present and answers (and, for
  Gemini with `list_args`, that the CLI lists the model); it does not prove the model itself is
  usable. No silent substitution. The Codex model is pinned by a `-c model=<model>` override;
  no Codex configuration file is read.
- Parses the DB config file as a syntax tree only; it is never imported or run.
- Fetches health URLs only through `safe_fetch`.

### sfcall.sh and bound.sh

- `sfcall.sh` refuses any MCP tool not in `screaming_frog.allowed_tools`. The default list is
  read-only (progress and listing tools). State-changing tools (`sf_crawl`, `sf_resume_crawl`,
  `sf_load_crawl`, `sf_pause_crawl`, every `sf_export_*`, `sf_generate_bulk_export`,
  `sf_generate_report`) are refused unless `SITE_AUDIT_SUPERVISED=1` is set, which
  `sf_supervise.py` sets for its own calls; listing one in `allowed_tools` is not enough.
  **Crawls go through `sf_supervise.py` only.** Tools that delete crawls, write or read
  arbitrary files, run scripts, open a browser or fetch a single URL outside a crawl are
  refused whatever the config says (`SF_NEVER_TOOLS` in `audit_config.py`). It exits non-zero on every failure and keeps its session id in a locked file
  under `run_root`.
- `bound.sh` runs a command in its own process group and kills the whole group at the deadline
  or when it is itself killed, so nothing is orphaned.

## Config reference

The file is JSON. Resolution: `--config PATH`, else `$SITE_AUDIT_CONFIG`, else
`~/.config/site-audit-kit/config.json`. An explicit or environment path that does not exist is
an error; a missing default file means the defaults below. Unknown keys are refused. Objects
merge with the defaults; lists replace them. A top-level `_comment` key is ignored.

| Key | Default | Meaning |
|---|---|---|
| `allowed_hosts` | `[]` | Hosts `safe_fetch` may fetch (lowercase ASCII, no wildcards) |
| `owned_domains` | `[]` | Your domains; never treated as external in `--external` mode |
| `forbidden_hosts` | `[]` | Hosts always refused (for example a compromised subdomain) |
| `forbid_subdomains_of_forbidden` | `true` | Refuse every subdomain of a forbidden host too |
| `probe_paths` | `{}` | `{forbidden_host: ["/exact/path"]}` fetchable only with `--probe` |
| `cache_bust_query` | `null` | One `key=value` that bypasses your page cache; also the only query crawl and health URLs may carry |
| `run_root` | `"~/site-audit"` | Every run folder, log and export lives here (mode 700) |
| `crawl.hosts` | `[]` | Hosts a crawl may start from; must also be in `allowed_hosts` |
| `crawl.http_paths` | `[]` | Plain-http exceptions: `[{"host": ..., "path_prefix": "/blog"}]` |
| `crawl.health_urls` | `[]` | URLs polled during a crawl (default for `--health`) |
| `health.status_urls` | `[]` | Must answer 200 before crawling |
| `health.html_urls` | `[]` | Must answer 200 with HTML before crawling; crawls are held until set |
| `screaming_frog.mcp_url` | `"http://127.0.0.1:11435/mcp"` | The MCP server (`SF_MCP_URL` overrides) |
| `screaming_frog.base_dir` | `null` | The server's allowed base folder; required for crawls |
| `screaming_frog.profiles_dir` | `null` | Folder of `.seospiderconfig` profiles (default: `base_dir`) |
| `screaming_frog.project_name` | `"site-audit"` | Project name passed to `sf_crawl` |
| `screaming_frog.allowed_tools` | progress and listing tools (read-only) | Tools `sfcall.sh` may call; state-changing tools also need `SITE_AUDIT_SUPERVISED=1` |
| `baseline.dir` | `null` | Folder of previous findings files (`--baseline-dir` overrides) |
| `baseline.findings_regex` | `^site-audit-(?P<date>...)(?:-(?P<n>\d+))?\.md$` | Findings file names; groups `date` and optional `n` |
| `baseline.companion_suffixes` | `["runbook", "decisions", "baseline-delta"]` | Companion files `<stem>-<suffix>.md` |
| `baseline.review_heading` | `"review record"` | The `##`/`###` heading that marks a reviewed findings file |
| `baseline.fallback_file` | `null` | File in `baseline.dir` used when no reviewed findings file exists |
| `baseline.fallback_date` | `null` | Date of the fallback file (`YYYY-MM-DD`) |
| `baseline.fallback_also_read` | `[]` | Extra files listed alongside the fallback |
| `baseline.notes_regex` | `^screaming-frog-run...-(?P<date>...)...\.md$` | Crawl note files newer than the baseline |
| `baseline.notes_run_regex` | `^screaming-frog-run(\d+)-\d{4}-\d{2}-\d{2}` | Row prefix `R<n>` for a note |
| `baseline.method_table_file` | `null` | Markdown with `\| ID \| P/A \| finding \| measured in \|` rows |
| `baseline.method_table_heading` | `"re-test table"` | The `##` heading of that table |
| `models.gemini` | `{"model": "", "binary": "", "list_args": []}` | Reviewer leg; empty model means not configured. With `list_args`, `binary list_args` must list the model |
| `models.codex` | `{"model": "", "binary": "codex"}` | Reviewer leg pinned with `-c model=<model>`; `~/.codex` is never read |
| `db.config_file` | `null` | Python file defining `DATABASES = {alias: {...}}`, parsed, never run |
| `db.readonly_aliases` | `[]` | Aliases of the read-only DB user that must exist in `DATABASES` |
| `db.public_post_types` | `["post", "page"]` | Default public post types for every install |
| `db.installs` | `{}` | `{name: install}`, see below |
| `redaction.extra_params` | `[]` | Parameter names added to the redactor's built-in list |

Install keys (`db.installs.<name>`), all optional:

| Key | Default | Meaning |
|---|---|---|
| `prefix` | `"wp_"` | Table prefix |
| `views` | `false` | The connection's default database is a read-only schema of views |
| `schema` | `null` | The only schema qualifier accepted (required with `views`) |
| `public_post_types` | `db.public_post_types` | Post types whose `post_content` may be read |
| `attended_only` | `false` | Marks an install to read only with the user present (informational; the skill honours it) |
| `option_names` | `siteurl`, `home`, `permalink_structure`, `blog_public` | Readable `wp_options` rows |
| `meta_keys` | `_wp_page_template` | Readable `wp_postmeta` keys |
| `meta_prefixes` | `rank_math_`, `_yoast_wpseo_` | Readable `wp_postmeta` key prefixes |
| `template_post_types` | `[]` | Builder template types whose meta may be read |
| `extra_tables` | `terms`, `term_taxonomy`, `term_relationships` | Extra readable tables (never users, usermeta, comments, commentmeta) |
| `columns` | `{}` | Narrow `posts`, `postmeta` or `options` columns (core columns only, never `post_password`) |
| `residue_hosts` | `[]` | Enables one exception: a COUNT of revision rows containing these hosts |
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
`sf_supervise` takes about 90 seconds. One live test exists and is off by default: set
`SITE_AUDIT_MANIFEST_LIVE=1` (and optionally `SITE_AUDIT_LIVE_CONFIG`) to run one manifest
build against your real configuration and network.

## Limits and non-goals

- **Your own sites only.** The kit is built to audit hosts you list. It is not a scanner for
  other people's sites and has no stealth, rate-evasion or authentication features.
- **Not an SEO oracle.** The tools make measurement safe; they do not decide what matters. The
  skill still needs judgement, a second method for every claim, and a review before anyone acts.
- **WordPress and MySQL/MariaDB only** for `sql_guard`, and only the SELECT subset an audit
  needs. It does not open connections; you bring a DB-API connection.
- **Screaming Frog with its MCP server** for crawls. Other crawlers are not supported.
- **IPv4 by default.** IPv6 is available in the library (`allow_ipv6=True`) but not on the CLI.
- **No IDNA.** Internationalised host names are refused rather than converted.
- **The guard is not the boundary.** Use a SELECT-only database user; `sql_guard` is defence
  in depth on top of it.
- **No ticketing, chat or publishing.** The kit writes files under `run_root` and your baseline
  folder. Filing or sharing results is up to you.
