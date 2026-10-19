"""Tests for audit_config.py: resolution order, safe defaults, validation. No network.

Run: python3 -m unittest discover -s skills/site-audit/scripts/tests/config
"""
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
import safe_fetch as sf  # noqa: E402
import testcfg  # noqa: E402


class Resolution(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_order_argument_then_env_then_default(self):
        env = {"SITE_AUDIT_CONFIG": "/env/path.json", "HOME": self.tmp}
        self.assertEqual(ac.resolve_path("/arg.json", env), ("/arg.json", "argument"))
        self.assertEqual(ac.resolve_path(None, env), ("/env/path.json", "environment"))
        p, src = ac.resolve_path(None, {})
        self.assertEqual(src, "default")
        self.assertTrue(p.endswith(os.path.join(".config", "site-audit-kit", "config.json")))

    def test_missing_default_gives_safe_defaults(self):
        saved = os.environ.pop("SITE_AUDIT_CONFIG", None)
        saved_home = os.environ.get("HOME")
        os.environ["HOME"] = self.tmp
        try:
            cfg = ac.load_config()
        finally:
            os.environ["HOME"] = saved_home
            if saved is not None:
                os.environ["SITE_AUDIT_CONFIG"] = saved
        self.assertEqual(cfg["_source"], "defaults")
        self.assertEqual(cfg["allowed_hosts"], [])
        self.assertEqual(cfg["crawl"]["hosts"], [])
        self.assertEqual(cfg["db"]["installs"], {})
        self.assertIsNone(cfg["cache_bust_query"])
        self.assertIsNone(cfg["screaming_frog"]["base_dir"])
        self.assertEqual(cfg["run_root"], "~/site-audit")

    def test_missing_explicit_or_env_path_is_an_error(self):
        with self.assertRaises(ac.ConfigError):
            ac.load_config(os.path.join(self.tmp, "nope.json"))
        with self.assertRaises(ac.ConfigError):
            ac.load_config(None, {"SITE_AUDIT_CONFIG": os.path.join(self.tmp, "nope.json")})

    def test_valid_file_loads_and_merges(self):
        cfg = testcfg.load()
        self.assertIn("www.example.com", cfg["allowed_hosts"])
        self.assertEqual(cfg["screaming_frog"]["mcp_url"], ac.DEFAULTS["screaming_frog"]["mcp_url"])
        self.assertEqual(ac.install_settings(cfg, "site")["prefix"], "wp_")
        self.assertEqual(ac.install_settings(cfg, "site")["public_post_types"], ["post", "page"])

    def test_example_config_is_valid(self):
        example = os.path.abspath(os.path.join(SCRIPTS, "..", "config.example.json"))
        with open(example) as f:
            data = json.load(f)
        cfg = ac.load_config(testcfg.write_config(data))
        self.assertTrue(cfg["allowed_hosts"])

    def test_example_config_is_inert(self):
        """Every host and URL in the shipped example sits under the reserved .example TLD,
        which never resolves, so the example fetches and crawls nothing until edited."""
        from urllib.parse import urlsplit
        example = os.path.abspath(os.path.join(SCRIPTS, "..", "config.example.json"))
        with open(example) as f:
            data = json.load(f)
        hosts = (data["allowed_hosts"] + data["owned_domains"] + data["forbidden_hosts"]
                 + list(data["probe_paths"]) + data["crawl"]["hosts"]
                 + [p["host"] for p in data["crawl"]["http_paths"]])
        urls = data["crawl"]["health_urls"] + data["health"]["status_urls"] + data["health"]["html_urls"]
        hosts += [urlsplit(u).hostname for u in urls]
        self.assertTrue(hosts)
        for h in hosts:
            with self.subTest(host=h):
                self.assertTrue(h == "example" or h.endswith(".example"), h)
        with open(example) as f:
            self.assertNotIn("example.com", f.read())


class FilePermissions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = testcfg.write_config(testcfg.BASE, self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_group_or_world_writable_refused(self):
        for mode in (0o620, 0o602, 0o666):
            os.chmod(self.path, mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(ac.ConfigError):
                ac.load_config(self.path)
        os.chmod(self.path, 0o644)
        ac.load_config(self.path)  # world-readable is allowed (no secrets belong in it)

    def test_symlink_refused(self):
        link = os.path.join(self.tmp, "link.json")
        os.symlink(self.path, link)
        with self.assertRaises(ac.ConfigError):
            ac.load_config(link)

    def test_not_json_refused(self):
        with open(self.path, "w") as f:
            f.write("{not json")
        with self.assertRaises(ac.ConfigError):
            ac.load_config(self.path)


class Validation(unittest.TestCase):
    def bad(self, **over):
        with self.assertRaises(ac.ConfigError):
            testcfg.load(testcfg.merged(**over))

    def test_unknown_keys_refused(self):
        self.bad(allowed_host=["www.example.com"])
        self.bad(crawl={"hostz": []})
        self.bad(screaming_frog={"url": "http://127.0.0.1:1/mcp"})

    def test_host_syntax(self):
        for h in ("WWW.example.com", "exa mple.com", "*.example.com", "exämple.com", "a..b", ""):
            with self.subTest(host=h):
                self.bad(allowed_hosts=[h])

    def test_allowed_and_forbidden_overlap_refused(self):
        self.bad(forbidden_hosts=["www.example.com"])
        self.bad(forbidden_hosts=["example.com"])  # www.example.com is its subdomain
        cfg = testcfg.load(testcfg.merged(forbidden_hosts=["example.com"], probe_paths={},
                                          forbid_subdomains_of_forbidden=False,
                                          allowed_hosts=["www.example.com", "help.example.com"]))
        self.assertFalse(cfg["forbid_subdomains_of_forbidden"])

    def test_probe_paths_must_belong_to_forbidden_hosts(self):
        self.bad(probe_paths={"www.example.com": ["/"]})
        self.bad(probe_paths={"legacy.example.org": ["/?x=1"]})
        self.bad(probe_paths={"legacy.example.org": ["no-slash"]})

    def test_crawl_hosts_must_be_allowed(self):
        self.bad(crawl={"hosts": ["shop.example.com"]})
        self.bad(crawl={"http_paths": [{"host": "www.example.com", "path_prefix": "/"}]})
        self.bad(crawl={"http_paths": [{"host": "other.example.com", "path_prefix": "/blog"}]})

    def test_cache_bust_query_shape(self):
        for q in ("nocache", "a=1&b=2", "x=<script>", ""):
            with self.subTest(q=q):
                self.bad(cache_bust_query=q)

    def test_regexes_need_named_groups(self):
        self.bad(baseline={"findings_regex": r"^audit-(\d{4}-\d{2}-\d{2})\.md$"})
        self.bad(baseline={"notes_regex": "("})

    def test_models_and_tools(self):
        self.bad(models={"codex": {"model": "bad model; rm -rf", "binary": "codex"}})
        self.bad(screaming_frog={"allowed_tools": ["rm -rf"]})
        self.bad(screaming_frog={"mcp_url": "file:///etc/passwd"})


class FetcherFromConfig(unittest.TestCase):
    def test_defaults_allow_nothing(self):
        f = sf.SafeFetcher.from_config(ac.DEFAULTS)
        for url in ("https://www.example.com/", "http://example.org/", "https://127.0.0.1/"):
            r = f.fetch(url)
            self.assertFalse(r.ok, url)
            self.assertEqual(r.connections, 0, url)
            self.assertIn(r.error, ("host_not_allowed", "address_not_allowed"), url)

    def test_from_config_carries_every_setting(self):
        cfg = testcfg.load()
        f = sf.SafeFetcher.from_config(cfg)
        self.assertIn("www.example.com", f.allowed_hosts)
        self.assertEqual(f.forbidden_hosts, frozenset({"legacy.example.org"}))
        self.assertEqual(f.cache_bust_query, "nocache=1")
        self.assertEqual(f.probe_paths["legacy.example.org"], frozenset({"/", "/old-page/"}))
        self.assertTrue(f.log_root.endswith("site-audit"))

    def test_cli_with_no_config_refuses_before_any_lookup(self):
        home = tempfile.mkdtemp()
        try:
            env = {k: v for k, v in os.environ.items() if k != "SITE_AUDIT_CONFIG"}
            env["HOME"] = home
            p = subprocess.run([sys.executable, "-I", "-B", os.path.join(SCRIPTS, "safe_fetch.py"),
                                "--no-log", "https://www.example.com/"], capture_output=True, text=True,
                               timeout=60, env=env)
            out = json.loads(p.stdout)
            self.assertEqual(p.returncode, 1)
            self.assertEqual(out["error"], "host_not_allowed")
            self.assertEqual(out["resolver_calls"], 0)
        finally:
            shutil.rmtree(home)

    def test_cli_cache_compare_needs_query(self):
        home = tempfile.mkdtemp()
        try:
            env = {k: v for k, v in os.environ.items() if k != "SITE_AUDIT_CONFIG"}
            env["HOME"] = home
            p = subprocess.run([sys.executable, "-I", "-B", os.path.join(SCRIPTS, "safe_fetch.py"),
                                "--no-log", "--cache-compare", "https://www.example.com/"],
                               capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(p.returncode, 2)
            self.assertEqual(json.loads(p.stdout)["error"], "config_error")
        finally:
            shutil.rmtree(home)

    def test_config_cli_prints_defaults(self):
        home = tempfile.mkdtemp()
        try:
            env = {k: v for k, v in os.environ.items() if k != "SITE_AUDIT_CONFIG"}
            env["HOME"] = home
            p = subprocess.run([sys.executable, "-I", "-B", os.path.join(SCRIPTS, "audit_config.py")],
                               capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout)["_source"], "defaults")
            p = subprocess.run([sys.executable, "-I", "-B", os.path.join(SCRIPTS, "audit_config.py"),
                                "--config", os.path.join(home, "missing.json")],
                               capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(p.returncode, 2)
        finally:
            shutil.rmtree(home)


if __name__ == "__main__":
    unittest.main()


class NeverTools(unittest.TestCase):
    """Tools that run code, touch arbitrary files, open a browser, delete crawls or fetch
    outside safe_fetch are refused even when the config lists them and the supervised
    switch is set."""

    def test_never_tools_refused_whatever_the_config(self):
        import audit_config as ac
        for tool in sorted(ac.SF_NEVER_TOOLS):
            cfg = {"screaming_frog": {"allowed_tools": [tool]}}
            self.assertFalse(ac.sf_tool_allowed(tool, cfg, {"SITE_AUDIT_SUPERVISED": "1"}), tool)
            self.assertFalse(ac.sf_tool_allowed(tool, cfg, {}), tool)
