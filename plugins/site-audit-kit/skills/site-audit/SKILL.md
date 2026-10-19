---
name: site-audit
description: >-
  Run a careful, guard-railed technical SEO audit of the user's OWN website (their main site,
  blog, help centre or docs): pin the run with a manifest, fetch pages only through an
  allowlisted SSRF-safe fetcher, crawl with Screaming Frog through its MCP server under a
  supervisor, read WordPress databases only through a read-only SQL guard, redact every export
  before use, and re-test the previous audit's findings. Use it whenever the user asks to audit
  their own website or blog for SEO, run a technical SEO health check, crawl their site with
  Screaming Frog, re-test or compare against a previous audit, or set up the site audit kit,
  even if they do not name the skill. Not for auditing websites the user does not own or
  operate.
---

# Site audit (your own site)

This skill runs a technical SEO audit of a website the user owns or operates. Its tools live in
the `scripts/` folder next to this file. They are standard-library Python (3.9 or newer) plus
two small shell scripts, and each one fails closed: with no configuration they allow no hosts,
so by default nothing is fetched, crawled or read. Explicit command-line overrides (`safe_fetch.py
--allow-host` and `--external`) widen that for one call; they are the operator's deliberate
choice, so use them only when the user asked for that host or for outbound link checks.

The point of the tools is that the audit itself must never become the incident: no request to
an internal address, no write to a database, no crawl that runs away, no password-reset token
or email address copied into a report or sent to another service.

## Paths used in every command

- `SKILL_DIR` is the folder that holds this `SKILL.md` (its `scripts/` folder holds the tools).
  For a plugin install Claude Code keeps it under
  `~/.claude/plugins/cache/site-audit-kit/site-audit-kit/<version>/skills/site-audit`; for a
  manual install it is `~/.claude/skills/site-audit`.
- `RUN_ROOT` is the configured `run_root` (default `~/site-audit`), fully expanded.
- `RUN_DIR` is this run's folder, created in step 1 and reused by every later command.

Every command below uses `"$SKILL_DIR/scripts/..."` and `"$RUN_DIR/..."`. If your shell does not
keep variables between commands, write the literal paths into each command instead.

## Ground rules (always)

1. **Own sites only.** Fetch, crawl or query only hosts and databases listed in the user's
   config. If the user asks about a site that is not theirs, say this skill is the wrong tool.
2. **Fetch only through `safe_fetch.py`.** Never use curl, wget, urllib, a browser tool or a web
   fetch tool for the audited site. safe_fetch enforces the host allowlist, refuses private and
   metadata addresses, pins the vetted IP, re-checks every redirect and prints and logs URLs
   with every query value replaced by `X` and credential headers replaced by `REDACTED`. Always
   pass `--log "$RUN_DIR/fetch.log"` (the CLI exits 2 without `--log` unless `--no-log` is
   given; do not use `--no-log` during an audit). The log folder must already exist: step 1
   creates `RUN_DIR`.
3. **Databases only through `sql_guard.py`.** Wrap every connection in `GuardedConnection`. It
   refuses to start unless the database identity is proven SELECT-only, so use the read-only DB
   user; never pass `attended=True` unless the user is present and asked for it. Never pass
   parameters (the guard refuses them). Never read users, usermeta, comments or commentmeta.
   The read-only database user is the security boundary; the guard is a filter on top. Its
   `prefix`, `public_post_types` and `schema` overrides and any custom `InstallPolicy` object
   are trusted operator inputs, never built from page content or model output; on the CLI
   `--public-types` may only narrow the configured list.
4. **Crawl only through `sf_supervise.py`.** It proves which crawl it owns, polls site health,
   pauses on trouble and enforces a hard time limit. By hand, `sfcall.sh` runs only `--list`
   and the read-only tools (`sf_crawl_progress`, `sf_list_crawls`,
   `sf_list_allowed_base_directory`, `sf_list_directories` and `sf_list_available_*`). Every
   other Screaming Frog tool, including any name the kit does not know, is refused unless
   `SITE_AUDIT_SUPERVISED=1` is set, which `sf_supervise.py` sets for its own calls only.
   Never set that variable yourself.
5. **Redact before anyone looks.** Run `redact_exports.py --fix-perms` and then
   `redact_exports.py --check` on every export folder. `--check` exits 1 when a file was left
   unscanned (including a hard-linked file) or a value remains, and 2 on a usage or I/O error.
   Treat any exit code other than 0 as "not safe": do not read, quote, attach or share that
   data. The built-in parameter list can only be extended (`--extra-params`), never replaced.
6. **Never send data out.** Nothing from the audit leaves the machine except through the
   optional review gate in step 7. Never print query-string values.
7. **Keep run data under `RUN_ROOT`** (mode 700). Never use `/tmp` for run data: a reboot erases
   it. Two places are outside it by design: findings files go to `baseline.dir`, and Screaming
   Frog writes its export to `<screaming_frog.base_dir>/run-<name>/` and keeps the crawl itself
   in its own crawl store (see step 4 and the close-out).
8. **Ask before acting on the site.** This skill measures and reports. It does not change the
   site, the database, DNS or analytics settings unless the user explicitly asks.

## One-time setup

1. Copy `"$SKILL_DIR/config.example.json"` to `~/.config/site-audit-kit/config.json` (or point
   `SITE_AUDIT_CONFIG` at another path) and `chmod 600` it. The tools refuse a config file that
   group or others can write, and a symlinked one.
2. Replace every `your-site.example` value with the user's own hosts (the example uses the
   reserved `.example` domain, which never resolves, so it does nothing until edited). The keys
   that matter first: `allowed_hosts`, `owned_domains`, `crawl.hosts`, `health.status_urls`,
   `health.html_urls`, `screaming_frog.base_dir` and `baseline.dir`. Ask the user for any value
   you cannot find. Never guess a host.
3. Check it: `python3 "$SKILL_DIR/scripts/audit_config.py"` prints the effective configuration
   (exit 0), or the exact error (exit 2).
4. Optional: a `cache_bust_query` (for example `nocache=1`) if the site sits behind a page cache
   that a query string bypasses; `forbidden_hosts` for a compromised or retired host that must
   never be fetched; `db.installs` for each WordPress database; reviewer models under `models`.

The repository README documents every key and every validation rule:
https://github.com/SameerKhan/site-audit-kit#readme

## Workflow

### 1. Check that no other session is running, then pin the run (always first)

Find the run root, then check for other activity BEFORE pinning anything:

```
RUN_ROOT=$(python3 "$SKILL_DIR/scripts/audit_config.py" | python3 -c 'import json, os, sys; print(os.path.expanduser(json.load(sys.stdin)["run_root"]))')
find "$RUN_ROOT" -type f -mmin -60 ! -name '.sid-*' 2>/dev/null
"$SKILL_DIR/scripts/sfcall.sh" sf_crawl_progress
```

The `find` must print nothing: any file under `RUN_ROOT` changed in the last hour (the kit's own
Screaming Frog session files, `sf/.sid-*`, are excluded) means another session may be mid-run.
`sf_crawl_progress` should report an idle spider (its `stateName` says idle). If either check
fails, stop and ask. `sfcall.sh` exits 3 when the Screaming Frog server is not reachable: that
is fine if no crawl is planned; otherwise ask the user to start Screaming Frog and its MCP
server.

Then create the run folder and pin the run:

```
mkdir -p -m 700 "$RUN_ROOT"
RUN_DIR=$(mktemp -d "$RUN_ROOT/run-XXXXXXXX")
echo "$RUN_DIR"
python3 "$SKILL_DIR/scripts/run_manifest.py" --run-dir "$RUN_DIR" --mode unattended
```

Note the printed `RUN_DIR` and reuse it in every later command. `RUN_ROOT` must be owned by the
user with mode 700; the manifest refuses anything else.

Use `--mode attended` only when the user is present for database steps. Add `--first-run` when
no previous audit exists. Exit 2 means a REQUIRED item failed: report the summary and stop. The
run folder is checked right after the config loads, before any network, subprocess or file
check. REQUIRED tools are `perl` and `python3`. The reviewer-model check confirms each
configured CLI is present (and lists the model where the CLI can); it does not prove the model
itself is usable. Advisory items say what they downgrade (for example, crawls are held when
health URLs fail). Health URLs are recorded in `manifest.json` as lists of entries with every
query value shown as `X`. The manifest also writes `phase1-rows.md`: the previous audit's
findings to re-test.

### 2. Re-test the previous findings

Work through every row of `"$RUN_DIR/phase1-rows.md"` and end each one as FIXED, STILL OPEN,
REGRESSED or CANNOT RETEST (with the reason). Measure the same way the original finding was
measured.

### 3. Live checks

```
python3 "$SKILL_DIR/scripts/safe_fetch.py" https://www.your-site.example/page --body --log "$RUN_DIR/fetch.log"
python3 "$SKILL_DIR/scripts/safe_fetch.py" https://www.your-site.example/page --cache-compare --body --log "$RUN_DIR/fetch.log"
python3 "$SKILL_DIR/scripts/safe_fetch.py" https://partner.example/ --external --log "$RUN_DIR/fetch.log"   # outbound link checks
```

Without `--body` the output holds the status, headers and redirect chain but no page text; pass
`--body` whenever you need the HTML (canonicals, JSON-LD, meta tags). `--cache-compare --body`
includes both bodies. URLs, redirect locations and the `Location` header are printed with every
query value replaced by `X`, and `Set-Cookie`, `Cookie`, `Authorization` and the other
credential headers as `REDACTED`. The body itself is printed as served: quote only what a
finding needs.

The deadline is 30 s and the body cap 5 MB. `--deadline` accepts any value above 0 up to 60 s
(so a slow re-test may raise it); `--max-bytes` may only lower the cap. Anything higher exits 2.
A plain fetch can be served from a page cache weeks old. Before blaming a template, compare the
plain and cache-bypassed responses with `--cache-compare`.

### 4. Crawl (Screaming Frog MCP)

Confirm the server answers with `"$SKILL_DIR/scripts/sfcall.sh" --list` (it exits 3 when the
server is unreachable). Then:

```
python3 "$SKILL_DIR/scripts/sf_supervise.py" --name example-r1 --url https://www.your-site.example/ \
  --config /ABSOLUTE/path/profile.seospiderconfig --limit-hours 4 --export --dry-run
```

Read the dry-run plan (it shows the effective MCP URL and every URL with query values as `X`),
then run it without `--dry-run`. The profile path must be absolute. Its state file is
`"$RUN_ROOT/sf/run-<name>/supervise.json"` (the default `--out`).

| Exit | Meaning | `status` in supervise.json | What to do |
|---|---|---|---|
| 0 | Done: crawl complete and loaded; with `--export` exported, redacted and `--check` clean | `done` or `exported` | Analyse the export |
| 1 | Failure: the crawl did not start, ownership was unproven or lost, the recorded crawl id is missing, an export failed (what it wrote is redacted), or an unexpected error with our crawl verified stopped | `failed`, `ownership-unproven`, `ownership-lost`, or the last step reached | Report the reason. Exit 1 also covers failures where ownership was unproven or lost, so this run cannot say what the spider is doing: tell the user to check the Screaming Frog app |
| 2 | Usage or preflight refusal (bad argument, spider not idle, another supervisor) | may be absent | Fix the input or ask |
| 3 | MCP server unreachable (at preflight, or 5 polls in a row); the crawl was NOT paused | `mcp-unreachable` when it happened mid-crawl | Tell the user to check the app now |
| 5 | Site health failed twice; crawl verified paused | `paused-health` | Report; do not resume without the user |
| 6 | Hard limit reached; crawl verified paused, partial | `partial` | Report it as partial |
| 7 | Export not verified redacted, or the export may still be writing (the spider was not verified idle after it) | `export-unredacted` | Do not read or share the export; tell the user to check the Screaming Frog app |
| 8 | Pause not verified: server gone, crawl not provably ours, the pause never landed, or a start that may have been sent but could not be reconciled | `pause-not-verified` | Tell the user to check the Screaming Frog app now |
| 128+n | Stopped by signal n (143 TERM, 130 INT, 129 HUP); our crawl verified paused or not running | `interrupted` | Report |

Other statuses seen while it runs: `starting`, `running`, `start-uncertain` (the `sf_crawl`
reply was lost; the supervisor is checking whether the crawl started) and `crawl-complete`.

With `--export` the supervisor exports Internal:All to
`<screaming_frog.base_dir>/run-<name>/internal_all.ndjson`, locks that folder to 700/600, copies
the file to its `--out` folder, then redacts and checks BOTH copies in place. Analyse exports
locally only after that gate passed. Bulk exports, reports and every other export tool are out
of scope for this version: `sfcall.sh` refuses them without the supervised switch, and the
supervisor only calls its six tools.

Wrap other long commands in `"$SKILL_DIR/scripts/bound.sh" <seconds> <command>` when GNU
`timeout` is not installed.

### 5. Database reads (WordPress, optional)

Only with an install configured in `db.installs`. In unattended mode, skip every database step
unless the manifest shows the read-only DB user exists. An install marked `attended_only` needs
`attended=True`, so read it only with the user present.

The kit has no database driver and installs none. The user supplies an open DB-API connection
from their own driver (for example mysql-connector-python or PyMySQL), with credentials from
their own option file, never typed into the chat:

```
import sys
sys.path.insert(0, SKILL_DIR + "/scripts")
import pymysql                      # the user's own driver
from sql_guard import GuardedConnection
conn = pymysql.connect(read_default_file="~/.my.cnf", read_default_group="audit_site")
g = GuardedConnection(conn, "site", RUN_DIR + "/sql.log")   # raises GuardSetupError unless SELECT-only
rows = g.execute("SELECT ID, post_title FROM wp_posts WHERE post_type = 'page' AND post_status = 'publish'")
```

Construction sets the session read-only, verifies it, checks the default database of a views
install, and runs the identity check (`CURRENT_USER()` plus `SHOW GRANTS`). If the identity is
not SELECT-only it raises `GuardSetupError` and no statement runs. Check any statement offline
first with `python3 "$SKILL_DIR/scripts/sql_guard.py" --install site "SELECT ..."` (exit 0
allowed, 1 refused, 2 usage error).

### 6. Write the findings

Write `site-audit-YYYY-MM-DD.md` (the name `baseline.findings_regex` expects) into
`baseline.dir` with a `## Findings` section, one `### F<n>. Title` heading per finding, and a
state in bold (`**CONFIRMED**`, `**STILL OPEN**`, `**FIXED**`, `**REGRESSED**`, `**NEW**`).
For each finding give the evidence, how it was measured, the impact and the fix. List what
could not be measured and why. Never include query values, tokens, email addresses or customer
names.

### 7. Review before anyone acts

Verify every finding yourself with a second method before reporting it as confirmed.

An external review (other models or people) is optional and happens only when the user asks
for it. Its gate is hard:

1. Put exactly what will be sent into one folder, `"$RUN_DIR/review-pack"`: the findings and
   the minimal redacted evidence, nothing else.
2. Run `python3 "$SKILL_DIR/scripts/redact_exports.py" "$RUN_DIR/review-pack" --fix-perms`,
   then `python3 "$SKILL_DIR/scripts/redact_exports.py" "$RUN_DIR/review-pack" --check`
   immediately before sending.
3. Send only if `--check` exited 0, and send only the files in that folder. Nothing else leaves
   the machine: no export, log, manifest, database row or page body outside the pack.

Give each reviewer a different question, give rejected points one rebuttal round, and correct
the findings. When the review is done, add a `## Review record` section: only a findings file
with a real review record counts as the next run's baseline.

### 8. Close out

Tell the user, in plain words: what is fixed since last time, the top three to five actions,
what could not be measured and what would unlock it, and the decisions waiting on them. Confirm
that no crawl or helper process from this run is still running.

The kit cannot delete stored crawls: `sf_clear_crawl` is never allowed. Tell the user that
Screaming Frog still holds this run's crawl in its own crawl store, unredacted, and that they
should delete it in the Screaming Frog app when they no longer need it. The export copy in
`<screaming_frog.base_dir>/run-<name>/` was redacted in place by the supervisor's gate; they may
delete that folder too.

## Reading results without fooling yourself

- **Stale cache.** A problem seen only in the plain fetch may already be fixed at the origin.
- **Tags outside the head.** Two canonicals may be one real one plus a stray copy in the body
  that search engines ignore. Check where a tag sits.
- **One tool is not proof.** Parse JSON-LD with a JSON parser and confirm with a second method.
- **Bot blocks are not dead links.** Large social networks often answer crawlers with 403.
- **Empty alt text.** Screaming Frog counts `alt=""` as missing alt text even on decorative
  images.
- **Analytics-discovered URLs carry secrets.** URLs pulled from analytics can hold reset
  tokens and email addresses; that is why every export goes through the redactor.
- **Thin content claims.** Check the page's search history before calling it thin: a page
  that ranked until a site-wide drop is not a content problem.
