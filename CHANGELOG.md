# Changelog

Plugin versions live in `plugins/site-audit-kit/.claude-plugin/plugin.json`.

## 1.0.0 (2026-10-19)

- First release: `safe_fetch.py` (guarded fetcher), `sql_guard.py` (read-only SQL filter for
  WordPress databases), `sf_supervise.py` (supervised Screaming Frog MCP crawl),
  `redact_exports.py` (export redactor with a fail-closed check), `run_manifest.py` (pins a run
  before it starts), the `site-audit` skill and about 410 tests. Reviewed with a multi-model
  review before release.
