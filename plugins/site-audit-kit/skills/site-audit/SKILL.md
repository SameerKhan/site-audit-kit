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

## Ground rules (always)

1. **Own sites only.** Fetch, crawl or query only hosts and databases listed in the user's
   config. If the user asks about a site that is not theirs, say this skill is the wrong tool.
2. **Fetch only through `safe_fetch.py`.** Never use curl, wget, urllib, a browser tool or a web
   fetch tool for the audited site. safe_fetch enforces the host allowlist, refuses private and
   metadata addresses, pins the vetted IP, re-checks every redirect and logs with query values
   removed. Always pass `--log RUN_DIR/fetch.log` (the CLI exits 2 without `--log` unless
   `--no-log` is given; do not use `--no-log` during an audit).
3. **Databases only through `sql_guard.py`.** Wrap every connection in `GuardedConnection`,
   use the read-only DB user whenever one exists, and never pass parameters (the guard refuses
   them). Never read users, usermeta, comments or commentmeta. The read-only database user is
   the security boundary; the guard is a filter on top. Its `prefix`, `public_post_types` and
   `schema` overrides and any custom `InstallPolicy` object are trusted operator inputs, never
   built from page content or model output; on the CLI `--public-types` may only narrow the
   configured list.
4. **Crawl only through `sf_supervise.py`.** It proves which crawl it owns, polls site health,
   pauses on trouble and enforces a hard time limit. `sfcall.sh` runs only read-only tools by
   hand; it refuses crawl, load, pause, resume and export tools unless `sf_supervise.py` calls
   it (it sets `SITE_AUDIT_SUPERVISED=1` for its own calls). Never set that variable yourself.
5. **Redact before anyone looks.** Run `redact_exports.py --fix-perms` and then
   `redact_exports.py --check` on every export folder. `--check` exits 1 when a file was left
   unscanned or a value remains and 2 on a usage or I/O error. Treat any exit code other than 0
   as "not safe": do not read, quote, attach or share that data. The built-in parameter list
   can only be extended (`--extra-params`), never replaced.
6. **Never send unredacted data out.** Other models, reviewers, tickets, chat messages and
   shared pages get only redacted, minimal evidence. Never print query-string values.
7. **Keep everything under `run_root`** (default `~/site-audit`, mode 700). Never use `/tmp`
   for run data: a reboot erases it.
8. **Ask before acting on the site.** This skill measures and reports. It does not change the
   site, the database, DNS or analytics settings unless the user explicitly asks.

## One-time setup

1. Copy `config.example.json` to `~/.config/site-audit-kit/config.json` (or point
   `SITE_AUDIT_CONFIG` at another path) and `chmod 600` it. The tools refuse a config file that
   group or others can write, and a symlinked one.
2. Replace every `your-site.example` value with the user's own hosts (the example uses the
   reserved `.example` domain, which never resolves, so it does nothing until edited). The keys that matter first:
   `allowed_hosts`, `owned_domains`, `crawl.hosts`, `health.status_urls`, `health.html_urls`,
   `screaming_frog.base_dir` and `baseline.dir`. Ask the user for any value you cannot find.
   Never guess a host.
3. Check it: `python3 scripts/audit_config.py` prints the effective configuration, or the exact
   error and exit code 2.
4. Optional: a `cache_bust_query` (for example `nocache=1`) if the site sits behind a page cache
   that a query string bypasses; `forbidden_hosts` for a compromised or retired host that must
   never be fetched; `db.installs` for each WordPress database; reviewer models under `models`.

The README next to the plugin documents every key.

## Workflow

### 1. Pin the run (always first)

```
mkdir -p -m 700 ~/site-audit
python3 scripts/run_manifest.py --run-dir "$(mktemp -d ~/site-audit/run-XXXXXXXX)" --mode unattended
```

(Use the configured `run_root` if it is not `~/site-audit`.)

Use `--mode attended` only when the user is present for database steps. Add `--first-run` when
no previous audit exists. Exit 2 means a REQUIRED item failed: report the summary and stop. The run folder is checked
right after the config loads, before any network, subprocess or file check. The reviewer-model
check confirms each configured CLI is present (and lists the model where the CLI can); it does
not prove the model itself is usable.
Advisory items say what they downgrade (for example, crawls are held when health URLs fail).
The manifest also writes `phase1-rows.md`: the previous audit's findings to re-test.

Before starting, check that no other session is mid-run: `sfcall.sh sf_crawl_progress` should
show an idle spider, and nothing under `run_root` should have changed in the last hour. If
either is not true, stop and ask.

### 2. Re-test the previous findings

Work through every row of `phase1-rows.md` and end each one as FIXED, STILL OPEN, REGRESSED or
CANNOT RETEST (with the reason). Measure the same way the original finding was measured.

### 3. Live checks

```
python3 scripts/safe_fetch.py https://www.your-site.example/page --log RUN_DIR/fetch.log
python3 scripts/safe_fetch.py https://www.your-site.example/page --cache-compare --log RUN_DIR/fetch.log
python3 scripts/safe_fetch.py https://partner.example/ --external --log RUN_DIR/fetch.log   # outbound link checks
```

The deadline is 30 s and the body cap 5 MB; `--deadline` and `--max-bytes` may only lower them
(a slow re-test may raise the deadline to at most 60 s). A plain fetch can be served from a
page cache weeks old. Before blaming a template, compare the
plain and cache-bypassed responses with `--cache-compare`.

### 4. Crawl (Screaming Frog MCP)

Confirm the server answers with `scripts/sfcall.sh --list` (it exits non-zero when the server
is unreachable). Then:

```
python3 scripts/sf_supervise.py --name example-r1 --url https://www.your-site.example/ \
  --config /ABSOLUTE/path/profile.seospiderconfig --limit-hours 4 --export --dry-run
```

Read the dry-run plan, then run it without `--dry-run`. The profile path must be absolute.
Exit codes: 0 done; 5 site health failed and the crawl was paused; 6 hard limit reached
(partial); 7 export not verified redacted; 8 the pause could not be verified (tell the user to
check the app now); 128+n stopped by a signal. Wrap other long commands in
`scripts/bound.sh <seconds> <command>` when GNU `timeout` is not installed.

Analyse exports locally after `--check` passed. Run bulk exports one at a time.

### 5. Database reads (WordPress, optional)

Only with an install configured in `db.installs`. In unattended mode, skip every database step
unless the manifest shows the read-only DB user exists, and read an install marked
`attended_only` only with the user present. Check the identity first:
`GuardedConnection(conn, "site", log_path).identity()` must report `select_only: true`. Check
any statement offline with `python3 scripts/sql_guard.py --install site "SELECT ..."`.

### 6. Write the findings

Write `site-audit-YYYY-MM-DD.md` (the name `baseline.findings_regex` expects) into
`baseline.dir` with a `## Findings` section, one `### F<n>. Title` heading per finding, and a
state in bold (`**CONFIRMED**`, `**STILL OPEN**`, `**FIXED**`, `**REGRESSED**`, `**NEW**`).
For each finding give the evidence, how it was measured, the impact and the fix. List what
could not be measured and why. Never include query values, tokens, email addresses or customer
names.

### 7. Review before anyone acts

Verify every finding yourself with a second method before reporting it as confirmed. If the user
wants independent reviewers (other models), give each one a different question and only
redacted evidence, give rejected points one rebuttal round, and correct the findings. When the
review is done, add a `## Review record` section: only a findings file with a real review
record counts as the next run's baseline.

### 8. Close out

Tell the user, in plain words: what is fixed since last time, the top three to five actions,
what could not be measured and what would unlock it, and the decisions waiting on them. Confirm
that no crawl or helper process from this run is still running, and that stored crawls holding
unredacted data were deleted or are kept only under `run_root`.

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
