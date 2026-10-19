"""Shared test configuration for the Site Audit Kit suites. No network, no real config.

Every suite points SITE_AUDIT_CONFIG at a throwaway file built here, so a config in the
developer's home directory can never change a test result.
"""
import atexit
import copy
import json
import os
import shutil
import tempfile

_DIRS = []

# Builder-plugin and SEO-plugin allowlists used by the sql_guard fixtures (all generic
# WordPress plugin names; the kit's own defaults are narrower).
_WP_INSTALL = {
    "option_names": ["siteurl", "home", "permalink_structure", "blog_public",
                     "rank-math-options-titles"],
    "meta_keys": ["_bricks_page_content_2", "_bricks_page_header_2", "_bricks_page_footer_2",
                  "_elementor_data", "_wp_page_template"],
    "meta_prefixes": ["rank_math_", "_yoast_wpseo_"],
    "template_post_types": ["bricks_template", "elementor_library"],
    "extra_tables": ["terms", "term_taxonomy", "term_relationships", "rank_math_redirections",
                     "rank_math_redirections_cache", "rank_math_404_logs"],
}

RESIDUE_HOSTS = ["spam-one.example", "spam-two.example", "spam-three.example"]

BASE = {
    "allowed_hosts": ["www.example.com", "help.example.com", "example.com"],
    "owned_domains": ["example.com"],
    "forbidden_hosts": ["legacy.example.org"],
    "probe_paths": {"legacy.example.org": ["/", "/old-page/"]},
    "cache_bust_query": "nocache=1",
    "run_root": "~/site-audit",
    "crawl": {
        "hosts": ["www.example.com", "help.example.com"],
        "http_paths": [{"host": "www.example.com", "path_prefix": "/blog"}],
        "health_urls": ["https://www.example.com/?nocache=1",
                        "https://www.example.com/blog/?nocache=1"],
    },
    "health": {
        "status_urls": ["https://www.example.com/.well-known/security.txt",
                        "https://www.example.com/robots.txt"],
        "html_urls": ["https://www.example.com/", "https://www.example.com/blog/?nocache=1"],
    },
    "screaming_frog": {"base_dir": None, "profiles_dir": None, "project_name": "site-audit"},
    "baseline": {
        "fallback_file": "fallback-findings.md",
        "fallback_date": "2030-01-01",
        "fallback_also_read": ["fallback-notes.md"],
    },
    "models": {
        "gemini": {"model": "example-gemini-pro", "binary": "~/bin/gemini", "list_args": ["models"]},
        "codex": {"model": "example-codex-model", "binary": "codex"},
    },
    "db": {
        "readonly_aliases": ["site_ro", "blog_ro"],
        "public_post_types": ["post", "page"],
        "installs": {
            "site": dict(_WP_INSTALL),
            "blog": dict(_WP_INSTALL),
            "docs": dict(_WP_INSTALL, attended_only=True, residue_hosts=RESIDUE_HOSTS),
            "site_ro": dict(_WP_INSTALL, views=True, schema="audit_site"),
            "blog_ro": dict(_WP_INSTALL, views=True, schema="audit_blog"),
        },
    },
}


def merged(**over):
    """BASE with top-level keys replaced (nested dicts merged one level deep)."""
    cfg = copy.deepcopy(BASE)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict) and k not in ("probe_paths",):
            cfg[k] = {**cfg[k], **v}
        else:
            cfg[k] = v
    return cfg


def write_config(data, directory=None):
    """Write data as a mode-600 config file; return its path."""
    if directory is None:
        directory = tempfile.mkdtemp(prefix="site-audit-cfg-")
        _DIRS.append(directory)
    path = os.path.join(directory, "config.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, 0o600)
    return path


def use_config(data=None):
    """Point SITE_AUDIT_CONFIG at a fresh file holding data (default BASE); return the path."""
    path = write_config(BASE if data is None else data)
    os.environ["SITE_AUDIT_CONFIG"] = path
    return path


def load(data=None):
    """The validated config dict for data (default BASE), via audit_config."""
    import audit_config
    return audit_config.load_config(write_config(BASE if data is None else data))


@atexit.register
def _cleanup():
    for d in _DIRS:
        shutil.rmtree(d, ignore_errors=True)
