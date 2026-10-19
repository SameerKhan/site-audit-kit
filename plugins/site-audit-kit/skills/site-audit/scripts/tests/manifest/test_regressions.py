"""Regression tests for run_manifest.py: run-dir abort, fetch path, baseline selection,
findings parsing, DATABASES parsing. Offline: every command and fetch is stubbed."""
import ast
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)
import run_manifest as rm  # noqa: E402
from test_run_manifest import ALIASES, BC, CFG, WWW, FakeEnv, REVIEWED, md  # noqa: E402
import testcfg  # noqa: E402
FALLBACK = BC["fallback_file"]

REV = "\n## Review record\n| leg | verdict |\n"
FIND = "## Findings\n\n### F1. Thing one\n**STILL OPEN**\n\n### F2 and F3. Pair\n\n## Other\n"


def mkrepo(files):
    """A throwaway baseline dir holding files."""
    r = tempfile.mkdtemp()
    m = r
    for n, c in files.items():
        with open(os.path.join(m, n), "w") as f:
            f.write(c)
    return r


class RunDirAbortsFirst(unittest.TestCase):
    """A failed run-dir check must abort before any other check."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.outside = tempfile.mkdtemp()
        self.repo = mkrepo({"site-audit-2030-03-08.md": REVIEWED})

    def tearDown(self):
        for d in (self.home, self.outside, self.repo):
            shutil.rmtree(d)

    def test_outside_root_runs_nothing_and_writes_nothing(self):
        env = FakeEnv(self.home)
        opened = []
        real_open = open

        def spy_open(p, *a, **k):
            opened.append(str(p))
            return real_open(p, *a, **k)

        with mock.patch("builtins.open", spy_open), \
                mock.patch.object(rm.subprocess, "run", side_effect=AssertionError("subprocess")):
            man = rm.build(os.path.join(self.outside, "run-x"), "unattended", self.repo, env=env,
                           cfg=CFG, sfcall="/x/sfcall.sh")
        self.assertEqual(env.calls, [], "no command or fetch may run after a run-dir failure")
        self.assertEqual(opened, [], "no file may be read after a run-dir failure")
        self.assertEqual([f["item"] for f in man.failed_required], ["run_dir"])
        self.assertEqual(os.listdir(self.outside), [])
        self.assertFalse(os.path.exists(os.path.join(self.home, "site-audit")),
                         "the root must not be created for a run dir outside it")
        self.assertNotIn("baseline", man.data)

    def test_bad_mode_dir_runs_nothing(self):
        root = os.path.join(self.home, "site-audit")
        os.makedirs(root, mode=0o700)
        rd = os.path.join(root, "run-y")
        os.makedirs(rd)
        os.chmod(rd, 0o755)
        env = FakeEnv(self.home)
        man = rm.build(rd, "unattended", self.repo, env=env, cfg=CFG,
                       sfcall="/x/sfcall.sh")
        self.assertEqual(env.calls, [])
        self.assertEqual(os.listdir(rd), [])
        self.assertEqual([f["item"] for f in man.failed_required], ["run_dir"])

    def test_main_exit_2_and_no_calls(self):
        import io
        env = FakeEnv(self.home)
        rc = rm.main(["--run-dir", os.path.join(self.outside, "r"), "--mode", "unattended",
                      "--baseline-dir", self.repo], env=env, out=io.StringIO(),
                     cfg=CFG, sfcall="/x/sfcall.sh")
        self.assertEqual(rc, 2)
        self.assertEqual(env.calls, [])


class FakeResult:
    def __init__(self, status=200, headers=None, body=b"", error=None, final_url=None):
        self.status, self.headers, self.body, self.error = status, headers or {}, body, error
        self.final_url = final_url

    @property
    def ok(self):
        return self.error is None and self.status is not None


class LiveUsesSafeFetch(unittest.TestCase):
    """Live checks must go through safe_fetch.SafeFetcher, not urllib."""

    def test_env_http_get_uses_safefetcher_with_run_dir_log(self):
        made = {}

        class Spy:
            def __init__(self, *a, **k):
                made["kw"] = k
                made["a"] = a

            def fetch(self, url, **kw):
                made.setdefault("urls", []).append(url)
                return FakeResult(200, {"content-type": "text/html"}, b"<html>" + b"x" * 100000)

        import safe_fetch
        env = rm.Env()
        env.fetch_log = "/nonexistent-run/fetch.log"
        with mock.patch.object(safe_fetch, "SafeFetcher", Spy), \
                mock.patch("urllib.request.urlopen", side_effect=AssertionError("urllib used")):
            st, ctype, body, err = env.http_get(WWW + "/")
        self.assertEqual((st, ctype, err), (200, "text/html", None))
        self.assertEqual(len(body), 65536)
        self.assertEqual(made["kw"].get("log_path"), "/nonexistent-run/fetch.log")
        self.assertEqual(made["urls"], [WWW + "/"])

    def test_refused_redirect_is_status_0_with_error(self):
        class Spy:
            def __init__(self, *a, **k):
                pass

            def fetch(self, url, **kw):
                return FakeResult(302, {"location": "http://169.254.169.254/"}, b"",
                                  error="redirect_refused")

        import safe_fetch
        env = rm.Env()
        env.fetch_log = None
        with mock.patch.object(safe_fetch, "SafeFetcher", Spy):
            st, _c, _b, err = env.http_get(WWW + "/")
        self.assertEqual(st, 0)
        self.assertEqual(err, "redirect_refused")

    def test_no_urllib_import(self):
        with open(rm.__file__) as f:
            tree = ast.parse(f.read())
        mods = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        mods |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertFalse({m for m in mods if m and m.startswith("urllib")}, mods)

    def test_build_sets_fetch_log_and_records_errors(self):
        home = tempfile.mkdtemp()
        os.makedirs(os.path.join(home, "site-audit"), mode=0o700)
        repo = mkrepo({"site-audit-2030-03-08.md": FIND + REV})
        tk = tempfile.mkdtemp()
        try:
            env = FakeEnv(home, http={WWW + "/": (0, "", b"", "redirect_refused")})
            rd = os.path.join(home, "site-audit", "run-z")
            man = rm.build(rd, "unattended", repo, env=env, cfg=CFG, sfcall="/x/sfcall.sh")
            self.assertEqual(env.fetch_log, os.path.join(os.path.realpath(rd), "fetch.log"))
            self.assertEqual([e["error"] for e in man.data["live"]["html"] if e["url"] == WWW + "/"],
                             ["redirect_refused"])
            self.assertTrue(man.data["live"]["sf_crawls_held"])
        finally:
            for d in (home, repo, tk):
                shutil.rmtree(d)


class CodexPinNoConfigRead(unittest.TestCase):
    """Rule: ~/.codex/ is never opened. The pin is the -c model override."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.home, ".codex"))
        with open(os.path.join(self.home, ".codex", "config.toml"), "w") as f:
            f.write('model = "gpt-4o"\n')

    def tearDown(self):
        shutil.rmtree(self.home)

    def test_config_never_opened_and_pin_is_override(self):
        env = FakeEnv(self.home)
        opened = []
        real_open = open

        def spy_open(p, *a, **k):
            opened.append(str(p))
            return real_open(p, *a, **k)

        man = rm.Manifest()
        with mock.patch("builtins.open", spy_open):
            rm.check_models(env, man, CFG)
        self.assertFalse([p for p in opened if ".codex" in p], opened)
        self.assertEqual(man.data["models"]["codex"], "example-codex-model")
        self.assertEqual(man.data["models"]["codex_pinned_via"], "-c model=example-codex-model")
        self.assertIn(["/usr/bin/codex", "--version"], env.calls)
        self.assertFalse(hasattr(rm.Env, "codex_model_line"))
        with open(rm.__file__) as f:
            self.assertNotIn("config.toml", f.read())

    def test_codex_missing_fails(self):
        env = FakeEnv(self.home, tools={"perl": "/usr/bin/perl"})
        man = rm.Manifest()
        rm.check_models(env, man, CFG)
        self.assertEqual(next(i for i in man.items if i["item"] == "model_codex")["status"], "FAIL")
        self.assertIsNone(man.data["models"]["codex"])

    def test_codex_version_fails(self):
        env = FakeEnv(self.home, codex_rc=1)
        man = rm.Manifest()
        rm.check_models(env, man, CFG)
        self.assertEqual(next(i for i in man.items if i["item"] == "model_codex")["status"], "FAIL")

    def test_codex_version_timeout_is_15s(self):
        env = FakeEnv(self.home)
        rm.check_models(env, rm.Manifest(), CFG)
        self.assertEqual(env.timeouts.get("codex"), 15)


class ReviewRecordHeading(unittest.TestCase):
    """'Review record' must be a real ##/### heading with content under it."""

    def pick(self, newest_body):
        r = mkrepo({"site-audit-2030-03-19.md": FIND + newest_body,
                    "site-audit-2030-03-01.md": FIND + REV})
        try:
            return rm.select_baseline(r, "2030-03-19", BC)["file"]
        finally:
            shutil.rmtree(r)

    def test_real_heading_with_table(self):
        self.assertEqual(self.pick(REV), "site-audit-2030-03-19.md")

    def test_real_heading_with_paragraph_and_h3(self):
        self.assertEqual(self.pick("\n### Review record: independent review\n\nAll three legs ran.\n"),
                         "site-audit-2030-03-19.md")

    def test_inside_backtick_fence(self):
        self.assertEqual(self.pick("\n```\n## Review record\n| a |\n```\n"), "site-audit-2030-03-01.md")

    def test_inside_tilde_fence_and_indented(self):
        self.assertEqual(self.pick("\n~~~\n### Review record\nx\n~~~\n    ## Review record\n    x\n"),
                         "site-audit-2030-03-01.md")

    def test_inside_html_comment(self):
        self.assertEqual(self.pick("\n<!--\n## Review record\n| a |\n-->\n"), "site-audit-2030-03-01.md")

    def test_plain_text(self):
        self.assertEqual(self.pick("\nReview record: pending\n"), "site-audit-2030-03-01.md")

    def test_not_done_heading(self):
        for h in ("## Review record: not done yet", "## Review record (TODO)", "## Review record - pending",
                  "### Review record: TBD"):
            self.assertEqual(self.pick(f"\n{h}\n| a |\n"), "site-audit-2030-03-01.md", h)

    def test_not_done_body(self):
        self.assertEqual(self.pick("\n## Review record\n\nNot done yet.\n"), "site-audit-2030-03-01.md")

    def test_empty_under_heading(self):
        self.assertEqual(self.pick("\n## Review record\n\n"), "site-audit-2030-03-01.md")
        self.assertEqual(self.pick("\n## Review record\n## Next\nbody\n"), "site-audit-2030-03-01.md")

    def test_h1_and_h4_rejected(self):
        self.assertEqual(self.pick("\n# Review record\n| a |\n"), "site-audit-2030-03-01.md")
        self.assertEqual(self.pick("\n#### Review record\n| a |\n"), "site-audit-2030-03-01.md")

    def test_setext_rejected(self):
        self.assertEqual(self.pick("\nReview record\n=============\n| a |\n"), "site-audit-2030-03-01.md")

    def test_collision_suffix_still_newer(self):
        r = mkrepo({"site-audit-2030-03-19.md": FIND + REV, "site-audit-2030-03-19-2.md": FIND + REV})
        try:
            self.assertEqual(rm.select_baseline(r, "2030-03-19", BC)["file"], "site-audit-2030-03-19-2.md")
        finally:
            shutil.rmtree(r)


class SymlinkContainment(unittest.TestCase):
    """Baseline and note symlinks must not escape the baseline dir."""

    def setUp(self):
        self.repo = mkrepo({"site-audit-2030-03-01.md": FIND + REV})
        self.m = self.repo
        self.ext = tempfile.mkdtemp()
        self.secret = os.path.join(self.ext, "secret.md")
        with open(self.secret, "w") as f:
            f.write("## Findings\n\n### F9. SECRET-OUTSIDE\n\n" + REV)

    def tearDown(self):
        shutil.rmtree(self.repo)
        shutil.rmtree(self.ext)

    def test_symlinked_baseline_skipped_and_reported(self):
        os.symlink(self.secret, os.path.join(self.m, "site-audit-2030-03-19.md"))
        b = rm.select_baseline(self.repo, "2030-03-19", BC)
        self.assertEqual(b["file"], "site-audit-2030-03-01.md")
        self.assertIn("site-audit-2030-03-19.md", b["skipped_unsafe"])

    def test_symlink_inside_baseline_dir_also_skipped(self):
        os.symlink(os.path.join(self.m, "site-audit-2030-03-01.md"), os.path.join(self.m, "site-audit-2030-03-19.md"))
        b = rm.select_baseline(self.repo, "2030-03-19", BC)
        self.assertEqual(b["file"], "site-audit-2030-03-01.md")
        self.assertIn("site-audit-2030-03-19.md", b["skipped_unsafe"])

    def test_symlinked_baseline_dir_refused(self):
        r2 = tempfile.mkdtemp()
        try:
            os.symlink(self.m, os.path.join(r2, "baseline"))
            b = rm.select_baseline(os.path.join(r2, "baseline"), "2030-03-19", BC)
            self.assertIsNone(b["kind"])
            self.assertTrue(b.get("unsafe_baseline_dir"))
        finally:
            shutil.rmtree(r2)

    def test_symlinked_note_and_companion_skipped(self):
        os.symlink(self.secret, os.path.join(self.m, "screaming-frog-run1-2030-03-10.md"))
        os.symlink(self.secret, os.path.join(self.m, "site-audit-2030-03-01-runbook.md"))
        b = rm.select_baseline(self.repo, "2030-03-19", BC)
        self.assertEqual(b["screaming_frog_notes"], [])
        self.assertEqual(b["companions"], {})
        self.assertIn("screaming-frog-run1-2030-03-10.md", b["skipped_unsafe"])
        self.assertIn("site-audit-2030-03-01-runbook.md", b["skipped_unsafe"])
        rows = rm.phase1_rows(b, "")
        self.assertFalse([x for x in rows if "SECRET" in x["finding"]])

    def test_symlinked_fallback_skipped(self):
        r2 = mkrepo({})
        try:
            os.symlink(self.secret, os.path.join(r2, FALLBACK))
            b = rm.select_baseline(r2, "2030-03-19", BC)
            self.assertIsNone(b["kind"])
            self.assertIn(FALLBACK, b["skipped_unsafe"])
        finally:
            shutil.rmtree(r2)

    def test_phase1_rows_refuses_unsafe_path_even_if_passed(self):
        b = {"kind": "previous-audit", "file": "x.md", "path": self.secret, "baseline_dir": self.m,
             "screaming_frog_notes": []}
        self.assertEqual(rm.phase1_rows(b, ""), [])


class Phase1Parsing(unittest.TestCase):
    """Findings section and ID forms."""

    def ids(self, text, notes=None, prompt=""):
        r = mkrepo({"site-audit-2030-03-19.md": text, **(notes or {})})
        try:
            b = rm.select_baseline(r, "2030-03-19", BC)
            return [x["id"] for x in rm.phase1_rows(b, prompt)]
        finally:
            shutil.rmtree(r)

    def test_heading_suffix(self):
        self.assertEqual(self.ids(FIND.replace("## Findings\n", "## Findings (re-tested 2030-03-19)\n") + REV),
                         ["F1", "F2", "F3"])

    def test_heading_comma_suffix_and_lowercase(self):
        self.assertEqual(self.ids(FIND.replace("## Findings\n", "## findings, by value\n") + REV),
                         ["F1", "F2", "F3"])

    def test_findings_last_section(self):
        self.assertEqual(self.ids(REV + "\n## Findings\n\n### F1. a\n### F2. b\n"), ["F1", "F2"])

    def test_fenced_findings_example_ignored(self):
        t = "```\n## Findings\n### F9. fake\n## x\n```\n" + FIND + REV
        self.assertEqual(self.ids(t), ["F1", "F2", "F3"])

    def test_fenced_heading_inside_section_ignored(self):
        t = "## Findings\n\n### F1. a\n```\n### F9. fake\n## Not the end\n```\n### F2. b\n" + REV
        self.assertEqual(self.ids(t), ["F1", "F2"])

    def test_id_forms(self):
        t = ("## Findings\n\n### F1a. sub\n### F12-F14. range\n### **F15.** bold\n### F16: colon\n"
             "### F100. three digits\n### F1, F4 and F7. trio\n### S1 (partial). video\n"
             "**F20.** bold paragraph lead\n" + REV)
        self.assertEqual(self.ids(t), ["F1a", "F12", "F13", "F14", "F15", "F16", "F100", "F1", "F4", "F7",
                                       "S1", "F20"])

    def test_en_dash_range_and_titles(self):
        r = mkrepo({"site-audit-2030-03-19.md": "## Findings\n\n### F2\u2013F3. Pair: x\n### **F5.** Bold one\n" + REV})
        try:
            rows = rm.phase1_rows(rm.select_baseline(r, "2030-03-19", BC), "")
            self.assertEqual([(x["id"], x["finding"]) for x in rows],
                             [("F2", "Pair: x"), ("F3", "Pair: x"), ("F5", "Bold one")])
        finally:
            shutil.rmtree(r)

    def test_unparsed_headings_reported(self):
        r = mkrepo({"site-audit-2030-03-19.md": "## Findings\n\n### F1. a\n### Mystery heading\n" + REV})
        try:
            rows, problems = rm.phase1_parse(rm.select_baseline(r, "2030-03-19", BC), "")
            self.assertEqual([x["id"] for x in rows], ["F1"])
            self.assertEqual(problems, ["Mystery heading"])
        finally:
            shutil.rmtree(r)

    def test_note_ids_never_collide(self):
        note = "## Findings\n\n**1. One.** b\n\n**2. Two.** b\n"
        notes = {"screaming-frog-run1-2030-03-19.md": note,
                 "screaming-frog-runA-2030-03-19.md": note,
                 "screaming-frog-runB-2030-03-19.md": note,
                 "screaming-frog-run1-2030-03-19-2.md": note}
        got = self.ids(FIND + REV, notes)
        self.assertEqual(len(got), len(set(got)), got)
        self.assertEqual(len(got), 3 + 8)
        self.assertIn("R1-1", got)
        self.assertIn("screaming-frog-runA-2030-03-19-1", got)
        self.assertNotIn("R?-1", got)

    def test_note_findings_last_section(self):
        got = self.ids(FIND + REV, {"screaming-frog-run2-2030-03-19.md": "# x\n## Findings, by value\n\n**1. Last.**\n"})
        self.assertIn("R2-1", got)


class Phase1RequiredAndFallback(unittest.TestCase):
    """Zero rows from a previous audit is REQUIRED; file is always written."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.home, "site-audit"), mode=0o700)
        self.tk = tempfile.mkdtemp()
        self.rd = os.path.join(self.home, "site-audit", "run-p")
        self.method = os.path.join(self.tk, "method-table.md")
        rows = [("F%d" % i, "A" if i == 3 else "P", "duplicate pages lack a canonical" if i == 3
                 else "finding %d" % i, "3" if i == 3 else "1a") for i in range(1, 21)]
        rows += [("S%d" % i, "P", "site-wide check %d" % i, "2") for i in range(1, 7)]
        with open(self.method, "w") as f:
            f.write("# Method\n\n## Re-test table\n\n| ID | Type | Finding | Measured in |\n|---|---|---|---|\n")
            f.write("".join(f"| {a} | {b} | {c} | {d} |\n" for a, b, c, d in rows))
            f.write("\n## Later section\n\n| F99 | A | not a re-test row | 9 |\n")
        self.cfg = testcfg.load(testcfg.merged(baseline={"method_table_file": self.method}))

    def tearDown(self):
        shutil.rmtree(self.home)
        shutil.rmtree(self.tk)

    def build(self, files, cfg=None):
        repo = mkrepo(files)
        try:
            return rm.build(self.rd, "unattended", repo, env=FakeEnv(self.home), cfg=cfg or self.cfg,
                            sfcall="/x/sfcall.sh")
        finally:
            shutil.rmtree(repo)

    def test_zero_rows_is_required_failure_and_file_written(self):
        man = self.build({"site-audit-2030-03-08.md": "# Audit\n\n## Summary\ntext\n" + REV})
        self.assertIn("phase1_rows", [f["item"] for f in man.failed_required])
        p = os.path.join(self.rd, "phase1-rows.md")
        self.assertTrue(os.path.isfile(p))
        with open(p) as f:
            txt = f.read()
        self.assertIn("FAILED", txt)
        self.assertIn("site-audit-2030-03-08.md", txt)

    def test_rows_written(self):
        man = self.build({"site-audit-2030-03-08.md": FIND + REV})
        self.assertEqual(man.failed_required, [])
        with open(os.path.join(self.rd, "phase1-rows.md")) as f:
            self.assertIn("| F2 |", f.read())

    def test_unparsed_heading_is_advisory_warning(self):
        man = self.build({"site-audit-2030-03-08.md": "## Findings\n\n### F1. a\n### Odd one\n" + REV})
        self.assertEqual(man.failed_required, [])
        st = next(i for i in man.items if i["item"] == "phase1_unparsed")
        self.assertEqual(st["status"], "warn")
        self.assertIn("Odd one", st["detail"])

    def test_fallback_rows_from_prompt_table(self):
        man = self.build({FALLBACK: "# Older audit\nno structure\n"})
        ids = [x["id"] for x in man.data["phase1_rows"]]
        self.assertEqual(ids[:3], ["F1", "F2", "F3"])
        self.assertIn("S6", ids)
        self.assertEqual(len([i for i in ids if not i.startswith("R")]), 26)
        f3 = next(x for x in man.data["phase1_rows"] if x["id"] == "F3")
        self.assertEqual((f3["type"], f3["measured_in"]), ("A", "3"))
        self.assertIn("duplicate pages", f3["finding"])
        self.assertEqual(man.failed_required, [])

    def test_fallback_without_prompt_table_fails_closed(self):
        cfg = testcfg.load(testcfg.merged(baseline={"method_table_file": "/nonexistent/method-table.md"}))
        man = self.build({FALLBACK: "# Older audit\n"}, cfg)
        self.assertIn("phase1_rows", [f["item"] for f in man.failed_required])
        self.assertTrue(os.path.isfile(os.path.join(self.rd, "phase1-rows.md")))

    def test_measured_in_only_from_method_table(self):
        prompt = ("## Re-test table: methods\n\n| ID | Type | F | M |\n|---|---|---|---|\n| F1 | P | a | 1a |\n"
                  "\n## Phase 9\n\n| F2 | A | other table | 9 |\n")
        self.assertEqual(rm._measured_in(prompt), {"F1": ("P", "1a")})

    def test_method_table_heading_is_configurable(self):
        text = "## Checks\n\n| F7 | A | x | 4 |\n\n## Re-test table\n\n| F8 | P | y | 1 |\n"
        self.assertEqual(rm._measured_in(text, "Checks"), {"F7": ("A", "4")})
        self.assertEqual(rm._measured_in(text), {"F8": ("P", "1")})


class ReadonlyAliasesModuleLevelOnly(unittest.TestCase):
    """Only module-level assignments to DATABASES count."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.marker = os.path.join(self.d, "RAN")

    def tearDown(self):
        shutil.rmtree(self.d)

    def aliases(self, body):
        with open(os.path.join(self.d, "db_config.py"), "w") as f:
            f.write(f"open({self.marker!r}, 'w').write('x')\n" + body)
        r = rm.detect_readonly_db(os.path.join(self.d, "db_config.py"), ALIASES)
        self.assertFalse(os.path.exists(self.marker))
        return r["aliases"]

    def test_if_false_not_counted(self):
        self.assertEqual(self.aliases('DATABASES = {}\nif False:\n    DATABASES["blog_ro"] = {}\n'
                                      '    DATABASES.update(site_ro={})\n'),
                         {"site_ro": False, "blog_ro": False})

    def test_function_class_loop_try_not_counted(self):
        body = ('DATABASES = {}\ndef f():\n    DATABASES["site_ro"] = {}\n'
                'class C:\n    DATABASES = {"blog_ro": {}}\n'
                'for _ in []:\n    DATABASES["blog_ro"] = {}\n'
                'try:\n    DATABASES.update({"site_ro": {}})\nexcept Exception:\n    pass\n')
        self.assertEqual(self.aliases(body), {"site_ro": False, "blog_ro": False})

    def test_other_names_not_counted(self):
        self.assertEqual(self.aliases('DATABASES = {}\nDB_CONF = {"site_ro": 1}\n'
                                      'ALIASES = {"blog_ro": 1}\nOLD_DATABASES = {"blog_ro": 1}\n'),
                         {"site_ro": False, "blog_ro": False})

    def test_reassignment_resets(self):
        self.assertEqual(self.aliases('DATABASES = {"site_ro": {}, "blog_ro": {}}\nDATABASES = {}\n'),
                         {"site_ro": False, "blog_ro": False})

    def test_module_level_forms_counted(self):
        body = ('DATABASES: dict = {"site_ro": {}}\nDATABASES["blog_ro"] = {}\n')
        self.assertEqual(self.aliases(body), {"site_ro": True, "blog_ro": True})
        body = 'DATABASES = {}\nDATABASES.update(site_ro={})\nDATABASES.setdefault("blog_ro", {})\n'
        self.assertEqual(self.aliases(body), {"site_ro": True, "blog_ro": True})
        body = 'DATABASES = {}\nDATABASES |= {"site_ro": {}, "blog_ro": {}}\n'
        self.assertEqual(self.aliases(body), {"site_ro": True, "blog_ro": True})


class Docstring(unittest.TestCase):
    """The read-only claim must admit sfcall.sh --list writes its session id."""

    def test_docstring(self):
        doc = rm.__doc__
        self.assertNotIn("config.toml", doc)
        self.assertIn("session id", doc)
        self.assertIn("safe_fetch", doc)
        self.assertIn("codex --version", doc)


if __name__ == "__main__":
    unittest.main()
