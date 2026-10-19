# Changelog

Plugin versions live in `plugins/site-audit-kit/.claude-plugin/plugin.json`.

## 1.0.1 (2026-10-19)

Security fixes:

- `sql_guard.py`: extra tables are checked by their full name (prefix plus table), so a split
  such as prefix `wp` with extra table `_users` can no longer reopen `users`, `usermeta`,
  `comments`, `commentmeta`, `posts`, `postmeta` or `options`.
- `sql_guard.py`: `GuardedConnection` runs the identity check at construction and refuses every
  statement unless the identity is SELECT-only; `attended=True` overrides it with a warning, and
  `attended_only` installs require it. Install values are type checked, never coerced.
- `safe_fetch.py`: printed output is redacted like the log (query values as `X`, credential
  headers as `REDACTED`); the log path is validated before any request is sent.
- `redact_exports.py`: a hard-linked file is never rewritten or chmodded and is reported as
  `UNSCANNED` (exit 1), including a link made during the rewrite (the original's link count is
  checked after the swap); on Linux, permissions are changed only through no-follow descriptors,
  else the run fails (exit 2).
- `sf_supervise.py`: a lost `sf_crawl` reply is treated as an uncertain start and reconciled;
  a different crawl id after ownership stops the run (`ownership-lost`); unexpected errors run
  the verified pause; a failed or partial export still goes through the redaction gate; URLs in
  its state files, logs and dry-run plan are redacted, and so is every URL inside text the
  server sends (progress messages, error strings, crawl names). An export whose reply is lost or
  whose wait times out is gated only after the spider is verified idle; otherwise the run ends
  with exit 7 (`export-unredacted`, the export may still be writing). The effective MCP URL is
  validated in dry-run too.
- `sfcall.sh`: the MCP URL (including `SF_MCP_URL`) must be loopback `http` with an explicit
  port; proxy variables are ignored; session ids are kept per server URL; arguments must be a
  JSON object; replies over 32 MiB are refused. Only an explicit set of read-only tools runs by
  hand; every other tool, including unknown names, needs the supervised switch.
- `run_manifest.py`: health URLs are stored and printed redacted, as lists of entries;
  `sfcall.sh` children get `SITE_AUDIT_CONFIG` set to the config file the manifest loaded.

Other fixes:

- `audit_config.py`: stricter loading (UTF-8 without BOM, at most 1 MiB, no duplicate keys,
  nesting limit, FIFOs refused, empty `--config` or `SITE_AUDIT_CONFIG` is an error) and new
  value checks (fully qualified `allowed_hosts`, health URL rules, absolute `run_root`, regex
  groups, install value types, `null` versus empty paths).
- `run_manifest.py`: `curl` is no longer required.
- `safe_fetch.py`: `--cache-compare --body` now includes both bodies.
- `sf_supervise.py`: plain-http paths with dot segments or `//` are refused; the dry-run plan
  shows the effective MCP URL.
- Docs: one consistent set of paths (`SKILL_DIR`, `RUN_ROOT`, `RUN_DIR`), the idle check before
  the manifest, all supervisor exit codes and statuses, a hard redaction gate before any
  optional external review, and an honest note that stored crawls must be deleted in the
  Screaming Frog app.
- CI: least-privilege token, actions pinned to commit SHAs, a job timeout, Python 3.9 and 3.12;
  `scripts/check.sh` cleans up its temporary HOME on exit and on signals.

Reviewed with /tri-review.

## 1.0.0 (2026-10-19)

- First release: `safe_fetch.py` (guarded fetcher), `sql_guard.py` (read-only SQL filter for
  WordPress databases), `sf_supervise.py` (supervised Screaming Frog MCP crawl),
  `redact_exports.py` (export redactor with a fail-closed check), `run_manifest.py` (pins a run
  before it starts), the `site-audit` skill and about 410 tests. Reviewed with a multi-model
  review before release.
