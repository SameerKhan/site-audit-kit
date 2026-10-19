#!/usr/bin/env bash
# Repository invariants and the full test suite. CI runs this on every push.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
err() { echo "FAIL: $*"; fail=1; }
KIT=plugins/site-audit-kit
PLUGIN=$KIT/.claude-plugin/plugin.json
SKILL=$KIT/skills/site-audit

# 1. Manifests and the example config are valid JSON.
for f in .claude-plugin/marketplace.json "$PLUGIN" "$SKILL/config.example.json"; do
  python3 -m json.tool "$f" >/dev/null 2>&1 || err "invalid JSON: $f"
done

# 2. The skill name matches its folder.
[ "$(sed -n 's/^name: *//p' "$SKILL/SKILL.md" | head -1)" = "site-audit" ] || err "SKILL.md name is not site-audit"

# 3. The plugin version is the newest CHANGELOG entry.
version=$(python3 -c "import json;print(json.load(open('$PLUGIN'))['version'])")
top=$(sed -n 's/^## \([0-9][0-9.]*\) .*/\1/p' CHANGELOG.md | head -1)
[ "$version" = "$top" ] || err "plugin.json is $version but the newest CHANGELOG entry is $top"

# 4. No em or en dashes in any text file (house style).
python3 - <<'PY' || err "dash found"
import pathlib, sys
hits = [f"{f}:{n}" for f in sorted(pathlib.Path(".").rglob("*"))
        if f.is_file() and ".git" not in f.parts
        and f.suffix in {".md", ".sh", ".json", ".yml", ".yaml", ".py"}
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1)
        if chr(0x2014) in line or chr(0x2013) in line]
if hits: print("\n".join(hits[:5]))
sys.exit(1 if hits else 0)
PY

# 5. No compiled Python is tracked.
if git ls-files 2>/dev/null | grep -E '(__pycache__/|\.pyc$)'; then err "compiled Python is tracked"; fi

# 6. Every test suite passes with an empty HOME and no config.
home=$(mktemp -d)
cleanup() { rm -rf "$home" "$SKILL/scripts/tests/_tmp"; }
trap cleanup EXIT
trap 'cleanup; trap - EXIT; exit 130' INT
trap 'cleanup; trap - EXIT; exit 143' TERM
trap 'cleanup; trap - EXIT; exit 129' HUP
for suite in config safe_fetch sql_guard redact manifest sf_supervise; do
  (cd "$SKILL/scripts" && env -u SITE_AUDIT_CONFIG HOME="$home" PYTHONDONTWRITEBYTECODE=1 \
    python3 -m unittest discover -s "tests/$suite" > "$home/$suite.log" 2>&1) \
    || { err "tests failed: $suite"; grep -E '^(FAIL|ERROR):' -A 25 "$home/$suite.log" | head -80; }
done
cleanup

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "all checks passed"
