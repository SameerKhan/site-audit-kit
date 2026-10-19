"""Regression tests for the config loader: install values, MCP URL, supervised tools, file reading, value shapes, host shapes. No network.

Run: python3 -m unittest discover -s skills/site-audit/scripts/tests/config
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, SCRIPTS)
sys.path.insert(0, os.path.dirname(HERE))
import audit_config as ac  # noqa: E402
import testcfg  # noqa: E402

CLI = os.path.join(SCRIPTS, "audit_config.py")


def write_bytes(directory, data, name="config.json"):
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)
    return path


def cli(args, env_extra=None, drop_env=True, timeout=20):
    """Run audit_config.py with a temp HOME; return the CompletedProcess."""
    home = tempfile.mkdtemp(prefix="site-audit-home-")
    try:
        env = {k: v for k, v in os.environ.items() if k != "SITE_AUDIT_CONFIG" or not drop_env}
        env.pop("SITE_AUDIT_CONFIG", None)
        env["HOME"] = home
        env.update(env_extra or {})
        return subprocess.run([sys.executable, "-I", "-B", CLI, *args], capture_output=True,
                              text=True, timeout=timeout, env=env)
    finally:
        shutil.rmtree(home, ignore_errors=True)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="site-audit-cfg-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def bad(self, data, pattern=None):
        with self.assertRaises(ac.ConfigError) as cm:
            ac.load_config(testcfg.write_config(data))
        if pattern:
            self.assertRegex(str(cm.exception), pattern)
        return cm.exception

    def good(self, data):
        return ac.load_config(testcfg.write_config(data))


# ---------------------------------------------------------------- 1. db.installs values
class InstallValues(Base):
    def with_install(self, **kv):
        cfg = copy.deepcopy(testcfg.BASE)
        cfg["db"]["installs"] = {"x": kv}
        return cfg

    def test_bad_install_values_refused(self):
        cases = [
            {"prefix": "wp_; DROP"}, {"prefix": ""}, {"prefix": 5}, {"prefix": "a" * 33},
            {"prefix": None}, {"prefix": "wp-"},
            {"views": "yes"}, {"views": 1}, {"attended_only": "false"}, {"attended_only": 0},
            {"option_names": "siteurl"}, {"option_names": [""]}, {"option_names": [1]},
            {"option_names": None}, {"option_names": ["a b"]}, {"option_names": ["a'b"]},
            {"meta_keys": ["x%"]}, {"meta_keys": "k"},
            {"meta_prefixes": [""]}, {"meta_prefixes": ["%"]}, {"meta_prefixes": ["rank%"]},
            {"meta_prefixes": "rank_math_"},
            {"template_post_types": [""]}, {"template_post_types": {}},
            {"extra_tables": ["wp terms"]}, {"extra_tables": [""]}, {"extra_tables": "terms"},
            {"columns": {"users": ["user_pass"]}}, {"columns": {"posts": ["post_password"]}},
            {"columns": {"posts": "id"}}, {"columns": {"posts": ["nope"]}}, {"columns": []},
            {"columns": {"posts": [""]}}, {"columns": None},
            {"residue_hosts": ["%"]}, {"residue_hosts": "a.example"}, {"residue_hosts": ["a_b.example"]},
            {"residue_meta_key": ""}, {"residue_meta_key": "a b"}, {"residue_meta_key": None},
            {"schema": "x;y"}, {"schema": 5}, {"schema": ""},
            {"views": True},  # views needs schema
            {"public_post_types": "post"}, {"public_post_types": [""]},
        ]
        for kv in cases:
            with self.subTest(install=kv):
                self.bad(self.with_install(**kv), r"db\.installs\.x")

    def test_good_install_values_load(self):
        for kv in ({}, {"views": True, "schema": "audit_x"}, {"columns": {"posts": ["ID", "post_title"]}},
                   {"public_post_types": None}, {"public_post_types": ["post", "product"]},
                   {"prefix": "wp2_"}, {"schema": None}, {"meta_prefixes": []},
                   {"residue_hosts": ["spam.example"]}):
            with self.subTest(install=kv):
                cfg = self.good(self.with_install(**kv))
                self.assertIn("x", cfg["db"]["installs"])

    def test_base_fixture_installs_still_load(self):
        cfg = testcfg.load()
        self.assertEqual(set(cfg["db"]["installs"]), {"site", "blog", "docs", "site_ro", "blog_ro"})

    def test_cli_refuses_broken_install(self):
        path = testcfg.write_config(self.with_install(meta_prefixes=[""]))
        p = cli(["--config", path])
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertIn("meta_prefixes", p.stderr)


# ---------------------------------------------------------------- 2. mcp_url
class McpUrl(Base):
    BAD = [
        "http://evil.example.com:80/mcp", "https://127.0.0.1:11435/mcp", "http://10.0.0.5:11435/mcp",
        "http://127.0.0.1/mcp", "http://127.0.0.1:11435/mcp\nX", "http://127.0.0.1:11435/mcp ",
        " http://127.0.0.1:11435/mcp", "http://user@127.0.0.1:11435/mcp",
        "http://user:pw@127.0.0.1:11435/mcp", "http://127.0.0.1:11435/mcp?x=1",
        "http://127.0.0.1:11435/mcp#f", "http://127.0.0.1:11435/mcp?", "http://127.0.0.1:0/mcp",
        "http://127.0.0.1:99999/mcp", "http://127.0.0.1:011435/mcp", "http://127.0.0.1:/mcp",
        "http://127.0.0.1.evil.example:11435/", "http://localhost.:11435/", "http://[::2]:1/",
        "HTTP://127.0.0.1:11435/mcp", "http://127.0.0.1:11435\\@evil.example/",
        "http://0x7f000001:11435/", "http://2130706433:11435/", "http://127.1:11435/",
        "file:///etc/passwd", "", "http://127.0.0.1:11435/m cp", "http://127.0.0.1:11435/mcp\t",
        "http://[::1]/mcp", "http://::1:11435/mcp", None, 5,
    ]
    GOOD = ["http://127.0.0.1:11435/mcp", "http://localhost:8080", "http://[::1]:11435/mcp",
            "http://127.0.0.1:11435", "http://127.0.0.1:11435/", "http://LOCALHOST:1/x/y"]

    def test_validate_mcp_url_helper(self):
        for u in self.BAD:
            with self.subTest(url=u), self.assertRaises(ac.ConfigError):
                ac.validate_mcp_url(u)
        for u in self.GOOD:
            with self.subTest(url=u):
                self.assertEqual(ac.validate_mcp_url(u), u)

    def test_config_mcp_url_must_be_loopback(self):
        for u in self.BAD:
            with self.subTest(url=u):
                self.bad(testcfg.merged(screaming_frog={"mcp_url": u}), "mcp_url")
        for u in self.GOOD:
            with self.subTest(url=u):
                self.assertEqual(self.good(testcfg.merged(screaming_frog={"mcp_url": u}))
                                 ["screaming_frog"]["mcp_url"], u)

    def test_default_mcp_url_is_valid(self):
        ac.validate_mcp_url(ac.DEFAULTS["screaming_frog"]["mcp_url"])


# ---------------------------------------------------------------- 3. supervised tools
class SupervisedTools(unittest.TestCase):
    STATE = ["sf_bulk_export_page_content", "sf_create_directory", "sf_generate_bulk_export",
             "sf_generate_report", "sf_export_seo_element_urls", "sf_export_crawl",
             "sf_export_embeddings", "sf_crawl", "sf_resume_crawl", "sf_pause_crawl",
             "sf_load_crawl", "sf_save_crawl", "sf_delete_crawl", "sf_bulk_anything",
             "sf_create", "sf_crawl_start", "sf_some_future_tool"]
    #: Never callable at all (not sf_* names, or SF_NEVER_TOOLS), with or without the switch.
    NEVER = ["sf_write_text_file", "sf_clear_crawl", "sf_url_info", "sf_list_available_x;rm",
             "anything", "", "sf_list_crawls ", "SF_LIST_CRAWLS", None]
    READ = ["sf_crawl_progress", "sf_list_crawls", "sf_list_available_filters_for_seo_element",
            "sf_list_available_data_fields_for_seo_element_and_filter",
            "sf_list_available_bulk_exports", "sf_list_available_reports",
            "sf_list_allowed_base_directory", "sf_list_directories"]

    def test_state_changing_and_unknown_tools_are_supervised_only(self):
        for t in self.STATE:
            with self.subTest(tool=t):
                self.assertTrue(ac.sf_supervised_only(t), t)

    def test_never_tools_and_bad_names_never_run(self):
        for t in self.NEVER:
            cfg = {"screaming_frog": {"allowed_tools": [t]}}
            with self.subTest(tool=t):
                self.assertFalse(ac.sf_tool_allowed(t, cfg, {}))
                self.assertFalse(ac.sf_tool_allowed(t, cfg, {"SITE_AUDIT_SUPERVISED": "1"}))
                self.assertFalse(ac.sf_read_only(t))

    def test_unsupervised_call_needs_a_read_only_tool(self):
        for t in self.STATE + self.NEVER:
            cfg = {"screaming_frog": {"allowed_tools": [t] + list(ac.SF_DEFAULT_TOOLS)}}
            with self.subTest(tool=t):
                self.assertFalse(ac.sf_tool_allowed(t, cfg, {}))

    def test_read_only_set_is_small_and_explicit(self):
        for t in self.READ:
            with self.subTest(tool=t):
                self.assertFalse(ac.sf_supervised_only(t), t)
        for t in ac.SF_DEFAULT_TOOLS:
            self.assertFalse(ac.sf_supervised_only(t), t)

    def test_listing_a_state_tool_is_not_enough(self):
        for t in ("sf_bulk_export_page_content", "sf_create_directory", "sf_some_future_tool"):
            cfg = {"screaming_frog": {"allowed_tools": [t]}}
            with self.subTest(tool=t):
                self.assertFalse(ac.sf_tool_allowed(t, cfg, {}))
                # under the switch a listed write tool is allowed; an unlisted one is not
                self.assertTrue(ac.sf_tool_allowed(t, cfg, {"SITE_AUDIT_SUPERVISED": "1"}))
                self.assertFalse(ac.sf_tool_allowed(t, {"screaming_frog": {"allowed_tools": []}},
                                                    {"SITE_AUDIT_SUPERVISED": "1"}))


# ---------------------------------------------------------------- 4. file reading
class FileReading(Base):
    def test_duplicate_keys_refused_anywhere(self):
        texts = [
            '{"allowed_hosts": ["a.example"], "allowed_hosts": ["evil.example"]}',
            '{"forbidden_hosts": ["old.example"], "forbidden_hosts": []}',
            '{"crawl": {"hosts": [], "hosts": []}}',
            '{"db": {"installs": {"s": {"prefix": "wp_", "prefix": "x_"}}}}',
            '{"_comment": {"a": 1, "a": 2}}',
        ]
        for t in texts:
            with self.subTest(text=t):
                with self.assertRaisesRegex(ac.ConfigError, "duplicate"):
                    ac.load_config(write_bytes(self.tmp, t.encode()))

    def test_fifo_refused_without_blocking(self):
        fifo = os.path.join(self.tmp, "config.json")
        os.mkfifo(fifo, 0o600)
        try:
            p = cli(["--config", fifo], timeout=10)
        except subprocess.TimeoutExpired:
            self.fail("audit_config.py blocked on a FIFO")
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn("not a regular file", p.stderr)
        p = cli([], env_extra={"SITE_AUDIT_CONFIG": fifo}, timeout=10)
        self.assertEqual(p.returncode, 2, p.stderr)

    def test_directory_refused(self):
        with self.assertRaises(ac.ConfigError):
            ac.load_config(self.tmp)

    def test_bad_encodings_are_config_errors(self):
        body = json.dumps({"allowed_hosts": []})
        cases = {
            "latin1": b'{"_comment": "caf\xe9"}',
            "utf16-bom": body.encode("utf-16"),
            "utf16le": body.encode("utf-16-le"),
            "utf8-bom": b"\xef\xbb\xbf" + body.encode(),
            "nul": b'{"_comment": "a\x00b"}',
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                path = write_bytes(self.tmp, data)
                with self.assertRaises(ac.ConfigError):
                    ac.load_config(path)
                p = cli(["--config", path])
                self.assertEqual(p.returncode, 2, p.stderr)
                self.assertNotIn("Traceback", p.stderr)

    def test_deep_nesting_is_a_config_error(self):
        for depth in (100000, 200):
            with self.subTest(depth=depth):
                path = write_bytes(self.tmp, b'{"_comment": ' + b"[" * depth + b"]" * depth + b"}")
                p = cli(["--config", path])
                self.assertEqual(p.returncode, 2, p.stderr[-500:])
                self.assertNotIn("Traceback", p.stderr)

    def test_oversized_file_refused_not_truncated(self):
        data = b'{"allowed_hosts": []}' + b" " * (1 << 20) + b"GARBAGE"
        with self.assertRaisesRegex(ac.ConfigError, "1 MiB"):
            ac.load_config(write_bytes(self.tmp, data))
        data = b'{"allowed_hosts": []' + b" " * (1 << 20) + b"}"
        with self.assertRaisesRegex(ac.ConfigError, "1 MiB"):
            ac.load_config(write_bytes(self.tmp, data))

    def test_file_just_under_the_limit_loads(self):
        head = b'{"allowed_hosts": []}'
        data = head + b" " * ((1 << 20) - len(head))
        self.assertEqual(ac.load_config(write_bytes(self.tmp, data))["allowed_hosts"], [])

    def test_empty_config_path_never_falls_through(self):
        with self.assertRaises(ac.ConfigError):
            ac.load_config("")
        with self.assertRaises(ac.ConfigError):
            ac.load_config(None, {"SITE_AUDIT_CONFIG": ""})
        with self.assertRaises(ac.ConfigError):
            ac.load_config(None, {"SITE_AUDIT_CONFIG": "   "})
        good = testcfg.write_config(testcfg.BASE)
        p = cli(["--config", ""], env_extra={"SITE_AUDIT_CONFIG": good})
        self.assertEqual(p.returncode, 2, p.stdout)
        p = cli([], env_extra={"SITE_AUDIT_CONFIG": ""})
        self.assertEqual(p.returncode, 2, p.stdout)
        self.assertNotIn("Traceback", p.stderr)


# ---------------------------------------------------------------- 5. baseline, URLs, paths
class ValueShapes(Base):
    def test_method_table_heading(self):
        for v in (None, "", "   ", 5, ["x"]):
            with self.subTest(v=v):
                self.bad(testcfg.merged(baseline={"method_table_heading": v}), "method_table_heading")

    def test_notes_run_regex_needs_a_group(self):
        for v in ("^screaming-frog-run", "(", r"^run(?:\d+)", 5):
            with self.subTest(v=v):
                self.bad(testcfg.merged(baseline={"notes_run_regex": v}), "notes_run_regex")
        self.good(testcfg.merged(baseline={"notes_run_regex": r"^run(\d+)"}))

    def test_findings_regex_needs_date_and_n(self):
        self.bad(testcfg.merged(baseline={"findings_regex": r"^a-(?P<date>\d{4}-\d{2}-\d{2})\.md$"}),
                 "findings_regex")
        self.good(testcfg.merged(baseline={
            "findings_regex": r"^a-(?P<date>\d{4}-\d{2}-\d{2})(?:-(?P<n>\d+))?\.md$"}))

    def test_health_urls(self):
        bad = ["file:///etc/passwd", "http://u:p@www.example.com/", "http://u@www.example.com/",
               "https://www.example.com/?token=abc", "https://www.example.com/?nocache=1&x=2",
               "https://www.example.com/?", "https://www.example.com/#x", "www.example.com/",
               "https://www.example.com/ x", "https://www.example.com/\n", "https:///path",
               "https://www.example.com:99999/", "ftp://www.example.com/", "https://WWW.example.com/"]
        for u in bad:
            for key in ("crawl.health_urls", "health.status_urls", "health.html_urls"):
                sect, k = key.split(".")
                with self.subTest(url=u, key=key):
                    self.bad(testcfg.merged(**{sect: {k: [u]}}), key.replace(".", r"\."))
        for u in ("https://www.example.com/", "http://www.example.com:8080/x",
                  "https://www.example.com/blog/?nocache=1"):
            with self.subTest(url=u):
                self.good(testcfg.merged(health={"html_urls": [u]}))

    def test_query_refused_when_no_cache_bust_query(self):
        self.bad(testcfg.merged(cache_bust_query=None), "health_urls|status_urls|html_urls")
        self.good(testcfg.merged(cache_bust_query=None,
                                 crawl={"health_urls": ["https://www.example.com/"]},
                                 health={"status_urls": [], "html_urls": ["https://www.example.com/"]}))

    def test_run_root_must_be_absolute(self):
        for v in ("relative/dir", "site-audit", "./x", "/", "//", "~", "", "~nosuchuser-x/a", 5):
            with self.subTest(v=v):
                self.bad(testcfg.merged(run_root=v), "run_root")
        for v in ("~/site-audit", "/var/tmp/site-audit-x"):
            with self.subTest(v=v):
                self.good(testcfg.merged(run_root=v))

    def test_empty_string_paths_refused(self):
        self.bad(testcfg.merged(baseline={"method_table_file": ""}), "method_table_file")
        self.bad(testcfg.merged(db={"config_file": ""}), "config_file")
        self.bad(testcfg.merged(models={"codex": {"model": "example-codex-model", "binary": ""},
                                        "gemini": testcfg.BASE["models"]["gemini"]}), "binary")
        self.bad(testcfg.merged(models={"gemini": {"model": "example-gemini-pro", "binary": "",
                                                   "list_args": []},
                                        "codex": testcfg.BASE["models"]["codex"]}), "binary")
        # null means "use the default binary name"; an unconfigured leg may keep ""
        cfg = self.good(testcfg.merged(models={
            "gemini": {"model": "example-gemini-pro", "binary": None, "list_args": []},
            "codex": {"model": "", "binary": ""}}))
        self.assertIsNone(cfg["models"]["gemini"]["binary"])
        self.good(testcfg.merged(baseline={"method_table_file": None}, db={"config_file": None}))


# ---------------------------------------------------------------- 6. allowed host shapes
class AllowedHostShapes(Base):
    def test_ip_literals_single_labels_and_numbers_refused(self):
        for h in ("127.0.0.1", "169.254.169.254", "localhost", "2130706433", "intranet",
                  "10.1", "0x7f000001", "example.123"):
            with self.subTest(host=h):
                self.bad(testcfg.merged(allowed_hosts=testcfg.BASE["allowed_hosts"] + [h]),
                         "allowed_hosts")

    def test_dns_names_still_load(self):
        self.good(testcfg.merged(allowed_hosts=testcfg.BASE["allowed_hosts"] + ["a1.example",
                                                                             "x-y.example.org"]))


class ExampleStillValid(unittest.TestCase):
    def test_example_loads_under_the_stricter_rules(self):
        example = os.path.abspath(os.path.join(SCRIPTS, "..", "config.example.json"))
        with open(example, "rb") as f:
            raw = f.read()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        cfg = ac.load_config(testcfg.write_config(json.loads(raw)))
        ac.validate_mcp_url(cfg["screaming_frog"]["mcp_url"])


if __name__ == "__main__":
    unittest.main()
