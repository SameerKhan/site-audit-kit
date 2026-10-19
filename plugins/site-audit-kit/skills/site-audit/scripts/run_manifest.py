#!/usr/bin/env python3
"""Resolve, check and record everything a site audit run depends on, before it starts.

Usage:
  run_manifest.py --run-dir DIR --mode attended|unattended [--config PATH]
                  [--baseline-dir PATH] [--first-run] [--json]

Settings come from the Site Audit Kit config (--config, else $SITE_AUDIT_CONFIG, else
~/.config/site-audit-kit/config.json); see audit_config.py and the README. Every child process
(sfcall.sh included) runs with SITE_AUDIT_CONFIG set to the absolute path of the file loaded
here, so it reads the same settings.

Writes DIR/manifest.json and DIR/manifest-summary.txt (both mode 600) and prints the summary
(or the JSON with --json). Fails closed: exit 2 when any REQUIRED item is missing, 0 otherwise.

REQUIRED: the run dir under the configured run_root (default ~/site-audit) with mode 700
(created if absent; checked right after the config loads, before any network, subprocess or file
check, and when it fails nothing else runs: no command, no fetch, no file read, nothing
written); a valid mode; a baseline audit (or the configured fallback; with --first-run a missing
baseline is recorded instead); Phase 1 re-test rows parsed from that baseline (zero rows is a
failure; phase1-rows.md is written either way and says why); for every CONFIGURED review model,
its CLI present and answering (and listing the model where the CLI can; this does not prove the
model itself is usable; no silent substitution); perl and python3. Everything else is
ADVISORY: it is recorded with what it downgrades (for example the Screaming Frog crawls are held
when the status or HTML health URLs fail).

Side effects, all of them: the run dir itself and its files (manifest.json, manifest-summary.txt,
phase1-rows.md, fetch.log; mode 600). Outside the run dir only one write happens, and not by this
script: `sfcall.sh --list` creates or refreshes its MCP session id file and lock under
<run_root>/sf/. Commands run: scripts/sfcall.sh --list and sf_list_crawls; `ps -ax -o
args=` (portable across macOS and Linux procps; filtered here for Screaming Frog, and only the
-Xmx flag is kept); the configured Gemini CLI's model listing (or its
--version); `codex --version` (15 s). The Codex model is pinned by the `-c model=<model>`
override every Codex leg passes, so no Codex configuration file is opened. HTTP: GET of the
configured health URLs, only through safe_fetch.SafeFetcher (configured host allowlist, every
redirect re-validated, logged to RUN_DIR/fetch.log). The DB config file is parsed as an AST,
never imported or executed, and none of its values are read into the manifest. Baseline,
companion and Screaming Frog note files are read only when they are regular, non-symlinked files
directly inside the baseline dir. Profile files are listed by name only. Every external call goes
through the Env object so tests can run offline.
"""
import argparse
import ast
import datetime as _dt
import glob
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
import audit_config  # noqa: E402 - sibling module

FALLBACK_STATE = "OPEN (fallback baseline)"
REQUIRED_TOOLS = ("perl", "python3")
OPTIONAL_TOOLS = ("gcloud", "codex", "dig", "timeout", "gtimeout")

ANY_HEADING_RE = re.compile(r"^ {0,3}#{1,6}(?:[ \t]|$)")
NOT_DONE_HEAD_RE = re.compile(
    r"\b(not\s+(?:yet\s+)?(?:done|run|started|complete|completed|written|finished)|pending|to\s?do|tbd"
    r"|to\s+be\s+(?:done|completed|written|added)|incomplete|placeholder|in\s+progress)\b", re.I)
NOT_DONE_BODY_RE = re.compile(
    r"^\W*(not\s+(?:yet\s+)?(?:done|run|started|complete|completed|written|finished)|pending|to\s?do|tbd"
    r"|to\s+be\s+(?:done|completed|written|added)|placeholder)\b", re.I)


def review_heading_re(phrase):
    """'## <phrase>' or '### <phrase>' (case-insensitive), with the rest of the line captured."""
    return re.compile(r"^ {0,3}#{2,3}[ \t]+" + re.escape(phrase.strip()) + r"\b(.*)$", re.I)


def bconf(cfg=None):
    """The baseline section of a config (defaults when cfg is None)."""
    return (cfg or audit_config.DEFAULTS)["baseline"]


REVIEW_HEADING_RE = review_heading_re(bconf()["review_heading"])


# --------------------------------------------------------------------------- environment

class Env:
    """Every side effect the manifest needs. Tests replace these methods."""

    home = os.path.expanduser("~")
    fetch_log = None  # set by build() to RUN_DIR/fetch.log once the run dir is verified
    allowed_hosts = ()  # set by build() from the config's allowed_hosts
    child_env = None  # set by build(): extra environment for every child (SITE_AUDIT_CONFIG)

    def now(self):
        return _dt.datetime.now(_dt.timezone.utc)

    def run(self, argv, timeout=60):
        """Return (exit_code, stdout). exit 127 if the program is missing, 124 on timeout."""
        try:
            env = dict(os.environ, **self.child_env) if self.child_env else None
            p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                               timeout=timeout, text=True, errors="replace", env=env)
            return p.returncode, p.stdout
        except FileNotFoundError:
            return 127, ""
        except subprocess.TimeoutExpired:
            return 124, ""

    def which(self, name):
        return shutil.which(name)

    def http_get(self, url, timeout=15):
        """Return (status, content_type, first 64 KB of body, error). Only through
        safe_fetch.SafeFetcher: the configured host allowlist, redirects re-validated hop by hop,
        logged to self.fetch_log. status 0 (with the error code) whenever the fetcher refused or
        failed."""
        try:
            sf = _load_safe_fetch()
            fetcher = sf.SafeFetcher(allowed_hosts=list(self.allowed_hosts), log_path=self.fetch_log,
                                     log_root=getattr(self, "run_root", None),
                                     deadline=float(timeout))
            r = fetcher.fetch(url)
        except Exception as e:  # noqa: BLE001  fail closed: an unusable fetcher is a failed check
            return 0, "", b"", f"fetcher error: {type(e).__name__}"
        headers = {str(k).lower(): v for k, v in (getattr(r, "headers", None) or {}).items()}
        ctype = headers.get("content-type", "") or ""
        body = (getattr(r, "body", b"") or b"")[:65536]
        if not r.ok:
            return 0, ctype, body, getattr(r, "error", None) or "fetch failed"
        return r.status, ctype, body, None

    def read_text(self, path):
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()


def _load_safe_fetch():
    """The safe_fetch module from THIS scripts dir (never whatever sys.path would find first)."""
    want = os.path.realpath(os.path.join(SCRIPT_DIR, "safe_fetch.py"))
    mod = sys.modules.get("safe_fetch")
    if mod is not None and os.path.realpath(getattr(mod, "__file__", "") or "") == want:
        return mod
    import importlib.util
    spec = importlib.util.spec_from_file_location("safe_fetch", want)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["safe_fetch"] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop("safe_fetch", None)
        raise
    return mod


# --------------------------------------------------------------------------- results

class Manifest:
    def __init__(self):
        self.items = []
        self.data = {}

    def add(self, name, ok, required, detail, consequence=None, status=None):
        st = status or ("ok" if ok else ("FAIL" if required else "warn"))
        self.items.append({"item": name, "required": required, "status": st, "detail": detail,
                           **({"consequence": consequence} if consequence else {})})
        return ok

    @property
    def failed_required(self):
        return [i for i in self.items if i["required"] and i["status"] == "FAIL"]


# --------------------------------------------------------------------------- checks

def run_root_for(env, cfg=None):
    """The configured run_root, with a leading ~ expanded against env.home."""
    return os.path.abspath(audit_config.expand((cfg or audit_config.DEFAULTS)["run_root"], env.home))


def check_run_dir(run_dir, env, m, cfg=None):
    """Containment is decided BEFORE anything is created, so a bad run dir writes nothing."""
    root = run_root_for(env, cfg)
    abs_rd = os.path.abspath(run_dir)
    info = {"path": abs_rd}
    m.data["run_dir"] = info
    try:
        if os.path.islink(root) or (os.path.lexists(root) and not os.path.isdir(root)):
            return m.add("run_dir", False, True, f"{root} is not a real directory")
        real_root = os.path.realpath(root)
        target = os.path.realpath(abs_rd)
        if os.path.commonpath([real_root, target]) != real_root or target == real_root:
            return m.add("run_dir", False, True, f"run dir must be inside {root}")
        if os.path.islink(abs_rd):
            return m.add("run_dir", False, True, "run dir is a symlink")
        os.makedirs(root, mode=0o700, exist_ok=True)
        if os.path.islink(root) or os.path.realpath(root) != real_root:
            return m.add("run_dir", False, True, f"{root} changed while it was being created")
        rst = os.lstat(root)
        if rst.st_uid != os.getuid() or stat.S_IMODE(rst.st_mode) != 0o700:
            return m.add("run_dir", False, True,
                         f"{root} must be owned by the current user with mode 0o700 "
                         f"(is uid {rst.st_uid}, mode {oct(stat.S_IMODE(rst.st_mode))})")
        created = not os.path.lexists(target)
        os.makedirs(target, mode=0o700, exist_ok=True)
        if os.path.realpath(abs_rd) != target:
            return m.add("run_dir", False, True, "run dir changed while it was being created")
        st = os.lstat(target)
        if not stat.S_ISDIR(st.st_mode):
            return m.add("run_dir", False, True, "run dir is not a directory")
        if st.st_uid != os.getuid():
            return m.add("run_dir", False, True, "run dir is not owned by the current user")
        if stat.S_IMODE(st.st_mode) != 0o700:
            return m.add("run_dir", False, True,
                         f"run dir mode is {oct(stat.S_IMODE(st.st_mode))}, must be 0o700")
        info.update({"realpath": target, "created": created, "mode": "0o700"})
        return m.add("run_dir", True, True, f"{target} (mode 700{', created' if created else ''})")
    except (OSError, ValueError) as e:
        return m.add("run_dir", False, True,
                     f"cannot create or inspect run dir: {getattr(e, 'strerror', None) or e}")


# --------------------------------------------------------------------------- markdown helpers

_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")


def visible_lines(text):
    """The file's lines with everything that is not rendered prose blanked to None: fenced code
    (``` and ~~~), HTML comments (also partial-line ones). Indices match the original lines."""
    out = []
    fence = None
    in_comment = False
    for line in text.splitlines():
        if fence:
            mm = _FENCE_RE.match(line)
            if mm and mm.group(1)[0] == fence[0] and len(mm.group(1)) >= len(fence) \
                    and not line.strip()[len(mm.group(1)):].strip():
                fence = None
            out.append(None)
            continue
        if not in_comment:
            mm = _FENCE_RE.match(line)
            if mm and not (mm.group(1)[0] == "`" and "`" in line.strip()[len(mm.group(1)):]):
                fence = mm.group(1)
                out.append(None)
                continue
        kept, rest = [], line
        while rest:
            if in_comment:
                end = rest.find("-->")
                if end < 0:
                    rest = ""
                else:
                    rest, in_comment = rest[end + 3:], False
            else:
                start = rest.find("<!--")
                if start < 0:
                    kept.append(rest)
                    rest = ""
                else:
                    kept.append(rest[:start])
                    rest, in_comment = rest[start + 4:], True
        vis = "".join(kept)
        out.append(vis if vis.strip() or not (in_comment or "<!--" in line) else None)
    return out


def _is_content(line):
    """A rendered table or paragraph line: not blank, not a heading, not indented code."""
    if line is None or not line.strip():
        return False
    if line.startswith("\t") or line.startswith("    "):
        return False
    return not ANY_HEADING_RE.match(line) and not re.fullmatch(r" {0,3}([-*_=])(\s*\1){2,}\s*", line)


def review_record_ok(text, heading_re=None):
    """True when the file has a real '## Review record' or '### Review record' heading (the
    configured review_heading) outside code and comments, whose heading does not say it is not
    done, with at least one table or paragraph line under it before the next heading (and that
    line does not say 'not done')."""
    heading_re = heading_re or REVIEW_HEADING_RE
    lines = visible_lines(text)
    for i, line in enumerate(lines):
        if line is None:
            continue
        hm = heading_re.match(line)
        if not hm or NOT_DONE_HEAD_RE.search(hm.group(1)):
            continue
        for nxt in lines[i + 1:]:
            if nxt is not None and ANY_HEADING_RE.match(nxt):
                break
            if _is_content(nxt):
                if not NOT_DONE_BODY_RE.search(nxt.lstrip("> ")):
                    return True
                break
    return False


def _open_nofollow_text(path):
    """Read a regular file without following a symlink at the last component, so a file
    swapped for a link after the containment check is refused (no check-then-open race)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        with os.fdopen(fd, "rb") as f:
            fd = None
            return f.read().decode("utf-8", "replace")
    finally:
        if fd is not None:
            os.close(fd)


def has_review_record(path, heading_re=None):
    try:
        return review_record_ok(_open_nofollow_text(path), heading_re)
    except OSError:
        return False


# --------------------------------------------------------------------------- baseline

def safe_baseline_file(bdir_real, name):
    """A regular, non-symlinked file directly inside the (real) baseline dir."""
    if not bdir_real or os.sep in name or name in (".", ".."):
        return False
    p = os.path.join(bdir_real, name)
    return (not os.path.islink(p) and os.path.isfile(p)
            and os.path.realpath(p) == os.path.join(bdir_real, name))


def safe_baseline_path(baseline, path):
    """Re-check containment at read time for any path handed to the Phase 1 parser."""
    bdir = baseline.get("baseline_dir")
    if not bdir or not path:
        return False
    real = os.path.realpath(bdir)
    return (os.path.dirname(os.path.abspath(path)) in (os.path.abspath(bdir), real)
            and safe_baseline_file(real, os.path.basename(path)))


def find_companions(bdir, name, n, suffixes, unsafe=None):
    """Companions of findings file ``name``: <stem>-<suffix>.md, and for a same-day suffix n
    also <stem without -n>-<suffix>-<n>.md."""
    stem = name[:-3] if name.endswith(".md") else name
    out = {}
    for kind in suffixes:
        cands = [f"{stem}-{kind}.md"]
        if n and stem.endswith(f"-{n}"):  # also accept the suffix after the kind
            cands.append(f"{stem[:-len(str(n)) - 1]}-{kind}-{n}.md")
        for c in cands:
            if not os.path.lexists(os.path.join(bdir, c)):
                continue
            if safe_baseline_file(bdir, c):
                out[kind] = c
                break
            if unsafe is not None and c not in unsafe:
                unsafe.append(c)
    return out


def select_baseline(baseline_dir, today=None, bcfg=None):
    """Return a dict describing the baseline. Pure filesystem logic, no network.
    Same-day collision files (<name>-D-N.md) are later runs than <name>-D.md, so the highest N
    with a completed review record wins. Symlinked files, or files whose realpath leaves the
    baseline dir, are never read: they are listed in skipped_unsafe. A symlinked baseline dir is
    refused outright."""
    bc = bcfg or bconf()
    findings_re = re.compile(bc["findings_regex"])
    notes_re = re.compile(bc["notes_regex"])
    heading_re = review_heading_re(bc["review_heading"])
    fallback = bc.get("fallback_file")
    res = {"baseline_dir": baseline_dir, "skipped_incomplete": [], "skipped_unsafe": [],
           "considered": []}
    if not baseline_dir:
        res.update({"kind": None, "not_configured": True})
        return res
    bdir = os.path.abspath(baseline_dir)
    if os.path.islink(bdir) or (os.path.lexists(bdir) and not os.path.isdir(bdir)):
        res.update({"kind": None, "unsafe_baseline_dir": True})
        return res
    bdir = os.path.realpath(bdir)
    res["baseline_dir"] = bdir
    try:
        names = sorted(os.listdir(bdir))
    except OSError:
        names = []
    unsafe = res["skipped_unsafe"]
    cands = []
    for nm in names:
        mm = findings_re.match(nm)
        if not mm:
            continue
        if not safe_baseline_file(bdir, nm):
            if os.path.lexists(os.path.join(bdir, nm)):
                unsafe.append(nm)
            continue
        gd = mm.groupdict()
        date, n = gd["date"], int(gd["n"]) if gd.get("n") else 0
        if today and date > today:
            continue
        cands.append((date, n, nm))
    cands.sort(reverse=True)
    res["considered"] = [c[2] for c in cands]
    for date, n, nm in cands:
        if has_review_record(os.path.join(bdir, nm), heading_re):
            res.update({
                "kind": "previous-audit", "file": nm, "path": os.path.join(bdir, nm),
                "date": date, "collision_suffix": n or None,
                "companions": find_companions(bdir, nm, n, bc["companion_suffixes"], unsafe),
            })
            break
        res["skipped_incomplete"].append(nm)
    if "file" not in res:
        if not fallback or not safe_baseline_file(bdir, fallback):
            if fallback and os.path.lexists(os.path.join(bdir, fallback)):
                unsafe.append(fallback)
            res["kind"] = None
            return res
        also = []
        for extra in bc.get("fallback_also_read") or []:
            if safe_baseline_file(bdir, extra):
                also.append(extra)
            elif os.path.lexists(os.path.join(bdir, extra)):
                unsafe.append(extra)
        res.update({"kind": "fallback", "file": fallback, "path": os.path.join(bdir, fallback),
                    "date": bc.get("fallback_date") or "0000-00-00",
                    "collision_suffix": None, "companions": {}, "also_read": also})
    notes = []
    for nm in names:
        mm = notes_re.match(nm)
        if not mm or mm.group("date") < res["date"]:
            continue
        if safe_baseline_file(bdir, nm):
            notes.append((mm.group("date"), int(mm.groupdict().get("n") or 0), nm))
        elif os.path.lexists(os.path.join(bdir, nm)):
            unsafe.append(nm)
    res["screaming_frog_notes"] = [nm for _d, _n, nm in sorted(notes)]
    return res


def check_baseline(baseline_dir, env, m, cfg=None, first_run=False):
    bc = bconf(cfg)
    b = select_baseline(baseline_dir, env.now().astimezone().strftime("%Y-%m-%d"), bc)  # local date
    m.data["baseline"] = b
    if not b.get("kind"):
        if b.get("unsafe_baseline_dir"):
            return m.add("baseline", False, True,
                         f"{b['baseline_dir']} is a symlink or not a directory; not read")
        if first_run:
            return m.add("baseline", True, True, "none (--first-run: no Phase 1 re-test)",
                         status="first_run")
        if b.get("not_configured"):
            return m.add("baseline", False, True,
                         "baseline.dir is not configured (pass --baseline-dir, or --first-run "
                         "for a first audit)")
        extra = f"; not read (symlink or outside): {', '.join(b['skipped_unsafe'])}" \
            if b.get("skipped_unsafe") else ""
        fb = bc.get("fallback_file")
        return m.add("baseline", False, True,
                     "no completed findings file (with a review record)"
                     + (f" and no {fb}" if fb else "") + f" in {b['baseline_dir']}{extra}"
                     + " (use --first-run for a first audit)")
    d = f"{b['file']} ({b['kind']}, {b['date']})"
    if b["skipped_incomplete"]:
        d += f"; skipped without a review record: {', '.join(b['skipped_incomplete'])}"
    ok = m.add("baseline", True, True, d)
    if b.get("skipped_unsafe"):
        m.add("baseline_unsafe_files", False, False,
              f"not read (symlink or outside the baseline dir): {', '.join(b['skipped_unsafe'])}",
              "report it; a real file must replace the link before it can be a baseline")
    return ok


def _parse_crawls(stdout):
    """sfcall prints one JSON-RPC message; the tool result text is a JSON array of crawls."""
    try:
        msg = json.loads(stdout.strip().splitlines()[-1])
        text = "".join(c.get("text", "") for c in msg["result"]["content"] if c.get("type") == "text")
        arr = json.loads(text)
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    out = []
    for c in arr if isinstance(arr, list) else []:
        if isinstance(c, dict):
            out.append({"name": c.get("crawlName"), "id": c.get("instanceDirName"),
                        "date": c.get("time"), "urls_crawled": c.get("urlsCrawled"),
                        "percent_complete": c.get("percentageComplete")})
    return out


def screaming_frog_processes(ps_output):
    """Command lines from `ps -ax -o args=` that belong to Screaming Frog (macOS app bundle or
    the Linux screamingfrogseospider package), matched case-insensitively."""
    return [ln.strip() for ln in (ps_output or "").splitlines()
            if "screamingfrog" in ln.lower().replace(" ", "")]


def check_screaming_frog(env, m, sfcall=None, cfg=None):
    sfcall = sfcall or os.path.join(SCRIPT_DIR, "sfcall.sh")
    sfc = (cfg or audit_config.DEFAULTS)["screaming_frog"]
    pdir = sfc.get("profiles_dir") or sfc.get("base_dir")
    sf = {}
    m.data["screaming_frog"] = sf
    rc, _ = env.run([sfcall, "--list"], timeout=60)
    sf["server_reachable"] = rc == 0
    sf["list_exit_code"] = rc
    m.add("sf_server", rc == 0, False, f"sfcall.sh --list exit {rc}",
          None if rc == 0 else "Screaming Frog runs and Run 0 exports are NOT MEASURED")
    profiles = sorted(os.path.basename(p)[: -len(".seospiderconfig")]
                      for p in glob.glob(os.path.join(audit_config.expand(pdir, env.home),
                                                      "*.seospiderconfig"))) if pdir else []
    sf["profiles"] = profiles
    sf["profiles_dir"] = pdir
    m.add("sf_profiles", bool(profiles), False,
          ", ".join(profiles) or ("none found" if pdir else "screaming_frog.profiles_dir not configured"),
          None if profiles else "every crawl needs a saved .seospiderconfig profile first")
    crawls = None
    if rc == 0:
        rc2, out = env.run([sfcall, "sf_list_crawls", '{"limit":10}'], timeout=120)
        crawls = _parse_crawls(out) if rc2 == 0 else None
    sf["stored_crawls"] = crawls or []
    m.add("sf_crawls", crawls is not None, False,
          (f"{len(crawls)} stored; newest {crawls[0]['name']} ({crawls[0]['date']})" if crawls
           else "none listed" if crawls is not None else "could not list"))
    rc3, out3 = env.run(["ps", "-ax", "-o", "args="], timeout=15)
    sf_lines = screaming_frog_processes(out3) if rc3 == 0 else []
    xmx = sorted(set(re.findall(r"-Xmx(\d+[kKmMgG]?)", "\n".join(sf_lines))))
    sf["jvm_xmx"] = xmx[0] if len(xmx) == 1 else (xmx or None)
    sf["app_running"] = bool(sf_lines)
    m.add("sf_jvm", bool(xmx), False,
          f"-Xmx{xmx[0]}" if len(xmx) == 1 else (f"several: {xmx}" if xmx else "app not running"),
          None if xmx else "memory setting unknown (8g expected)")


def check_models(env, m, cfg=None):
    """For each CONFIGURED reviewer model, check that its CLI is present and answers, and, for
    Gemini with list_args, that the CLI lists the model (REQUIRED, no silent substitution). This
    does not prove the model is usable. An unconfigured one is recorded as not_configured."""
    mc = (cfg or audit_config.DEFAULTS)["models"]
    g, c = mc["gemini"], mc["codex"]
    md = {"pinned": {"gemini": g["model"] or None, "codex": c["model"] or None}}
    m.data["models"] = md
    if not g["model"]:
        md["gemini"] = None
        m.add("model_gemini", True, False, "not configured (models.gemini.model is empty)",
              status="not_configured")
    else:
        binary = audit_config.expand(g["binary"] or "gemini", env.home)
        argv = [binary] + (list(g["list_args"]) if g["list_args"] else ["--version"])
        rc, out = env.run(argv, timeout=90)
        if g["list_args"]:
            names = [ln.split()[0] for ln in out.splitlines()
                     if ln.strip() and re.match(r"^[a-z0-9][\w.-]*\s", ln + " ")]
            md["gemini_available"] = names
            ok_g = rc == 0 and g["model"] in names
            detail = (f"{g['model']} listed by {os.path.basename(binary)}" if ok_g
                      else f"{g['model']} not listed (exit {rc}); no substitution allowed")
        else:
            ok_g = rc == 0
            detail = (f"{g['model']} pinned; {os.path.basename(binary)} --version ok" if ok_g
                      else f"{os.path.basename(binary)} --version exit {rc}; {g['model']} cannot run")
        md["gemini"] = g["model"] if ok_g else None
        m.add("model_gemini", ok_g, True, detail)
    # Codex: every Codex leg passes `-c model=<model>`, so the pin is that override. No Codex
    # configuration file is opened (~/.codex/ is never read). Only check that the binary exists
    # and answers codex --version.
    if not c["model"]:
        md["codex"] = None
        m.add("model_codex", True, False, "not configured (models.codex.model is empty)",
              status="not_configured")
        return
    override = f"-c model={c['model']}"
    codex = env.which(c["binary"] or "codex")
    rc_c, out_c = env.run([codex, "--version"], timeout=15) if codex else (127, "")
    ok_c = bool(codex) and rc_c == 0
    md["codex_binary"] = codex
    md["codex_version"] = (out_c.strip().splitlines() or [""])[0][:80] if ok_c else None
    md["codex_pinned_via"] = override
    md["codex"] = c["model"] if ok_c else None
    m.add("model_codex", ok_c, True,
          f"{c['model']} pinned via `{override}`; {md['codex_version']}" if ok_c
          else (f"codex binary not found; {c['model']} cannot run" if not codex
                else f"`codex --version` exit {rc_c}; {c['model']} cannot run, no substitution allowed"))


def _db_alias_names(tree):
    """Alias names DEFINED at module level in the DB config file. Only top-level statements of the
    module count (nothing inside if/def/class/for/while/with/try), and only the name DATABASES:
    `DATABASES = {...}` / `dict(...)` (a re-assignment starts over), `DATABASES: T = ...`,
    `DATABASES["x"] = ...`, `DATABASES |= {...}`, `DATABASES.update(...)` and
    `DATABASES.setdefault("x", ...)`. Never evaluates code."""
    found = set()

    def is_db(node):
        return isinstance(node, ast.Name) and node.id == "DATABASES"

    def keys(node):
        out = set()
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    out.add(k.value)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
            for a in node.args:
                out |= keys(a)
            for kw in node.keywords:
                if kw.arg:
                    out.add(kw.arg)
        return out

    def sub_key(t):
        if isinstance(t, ast.Subscript) and is_db(t.value):
            sl = t.slice
            sl = getattr(sl, "value", sl) if type(sl).__name__ == "Index" else sl
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                return sl.value
        return None

    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if node.value is None:
                continue
            for t in targets:
                if is_db(t):
                    found = keys(node.value)
                elif sub_key(t) is not None:
                    found.add(sub_key(t))
        elif isinstance(node, ast.AugAssign) and is_db(node.target) and isinstance(node.op, ast.BitOr):
            found |= keys(node.value)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            c = node.value
            if isinstance(c.func, ast.Attribute) and is_db(c.func.value):
                if c.func.attr == "setdefault" and c.args and isinstance(c.args[0], ast.Constant) \
                        and isinstance(c.args[0].value, str):
                    found.add(c.args[0].value)
                elif c.func.attr == "update":
                    for a in c.args:
                        found |= keys(a)
                    for kw in c.keywords:
                        if kw.arg:
                            found.add(kw.arg)
    return found


def detect_readonly_db(config_file, aliases):
    """Return {'file': path, 'parsed': bool, 'aliases': {alias: bool}}. AST only, no import."""
    path = audit_config.expand(config_file) if config_file else None
    res = {"file": path, "present": bool(path) and os.path.isfile(path), "parsed": False,
           "aliases": {a: False for a in aliases}}
    if not res["present"]:
        return res
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            tree = ast.parse(f.read(), filename=os.path.basename(path))
    except (OSError, SyntaxError, ValueError):
        return res
    res["parsed"] = True
    names = _db_alias_names(tree)
    res["aliases"] = {a: a in names for a in aliases}
    try:
        res["file_mode"] = oct(stat.S_IMODE(os.stat(path).st_mode))
    except OSError:
        pass
    return res


def check_readonly_db(mode, env, m, cfg=None):
    dc = (cfg or audit_config.DEFAULTS)["db"]
    aliases = list(dc["readonly_aliases"])
    d = detect_readonly_db(dc["config_file"], aliases)
    both = bool(aliases) and all(d["aliases"].values())
    d["defined"] = both
    if both:
        d["db_steps"] = "run through the read-only DB user aliases (SHOW GRANTS still decides inside the run)"
    elif mode == "unattended":
        d["db_steps"] = "NOT MEASURED (read-only DB user not configured)"
    else:
        d["db_steps"] = "attended: admin aliases behind the statement guard"
    m.data["readonly_db"] = d
    detail = ("db.readonly_aliases not configured" if not aliases else
              "db.config_file not configured" if not dc["config_file"] else
              f"{os.path.basename(d['file'])} missing" if not d["present"] else
              f"{os.path.basename(d['file'])} did not parse" if not d["parsed"] else
              ", ".join(f"{a} {'defined' if v else 'absent'}" for a, v in d["aliases"].items()))
    m.add("readonly_db", both, False, detail, None if both else d["db_steps"],
          status="ok" if both else "not_measured" if mode == "unattended" else "warn")
    if d.get("file_mode") and int(d["file_mode"], 8) & 0o077:
        m.add("db_config_perms", False, False,
              f"{os.path.basename(d['file'])} is mode {d['file_mode']} (group/world readable; holds credentials)",
              "report it; this run does not change it")


def _get(env, url):
    r = tuple(env.http_get(url, timeout=15))
    return r if len(r) == 4 else (*r[:3], None)


def _redact(url):
    """A health URL as stored and printed: every query value replaced by X (safe_fetch's rule).
    Fails closed to a placeholder if safe_fetch cannot be loaded."""
    try:
        return _load_safe_fetch().redact_url(url)
    except Exception:  # noqa: BLE001
        return "<url hidden: safe_fetch unavailable>"


def check_live(env, m, cfg=None):
    """GET the configured health URLs. Stored as lists of {url, status, ...} entries with the
    URL redacted (two URLs may redact to the same string, so they are not dict keys)."""
    hc = (cfg or audit_config.DEFAULTS)["health"]
    live = {"status": [], "html": []}
    m.data["live"] = live
    st_ok = True
    for url in hc["status_urls"]:
        st, ctype, body, err = _get(env, url)
        note = "rate limited (429)" if st == 429 else ""
        live["status"].append({"url": _redact(url), "status": st, **({"note": note} if note else {}),
                               **({"error": err} if err else {})})
        st_ok = st_ok and st == 200
    if hc["status_urls"]:
        m.add("status_urls", st_ok, False,
              ", ".join(f"{v['url']} {v['status']}" for v in live["status"]),
              None if st_ok else "hold the Screaming Frog crawls and report")
    else:
        m.add("status_urls", True, False, "none configured (health.status_urls)", status="not_configured")
    html_ok = True
    for url in hc["html_urls"]:
        st, ctype, body, err = _get(env, url)
        is_html = st == 200 and "text/html" in (ctype or "").lower() and re.search(
            rb"<html|<!doctype html", body or b"", re.I) is not None
        live["html"].append({"url": _redact(url), "status": st,
                             "content_type": (ctype or "").split(";")[0], "html": is_html,
                             **({"error": err} if err else {})})
        html_ok = html_ok and is_html
    if hc["html_urls"]:
        m.add("normal_html", html_ok, False,
              ", ".join(f"{v['url']} {v['status']} {'html' if v['html'] else 'NOT html'}"
                        for v in live["html"]),
              None if html_ok else "do not crawl until normal pages return HTML")
    else:
        html_ok = False
        m.add("normal_html", False, False, "none configured (health.html_urls)",
              "configure health.html_urls; crawls are held until normal pages are checked")
    live["sf_crawls_held"] = not (st_ok and html_ok)


def check_tools(env, m, cfg=None):
    mc = (cfg or audit_config.DEFAULTS)["models"]
    tools = {}
    for t in REQUIRED_TOOLS + OPTIONAL_TOOLS:
        tools[t] = env.which(t)
    gem = mc["gemini"]["binary"]
    if mc["gemini"]["model"] and gem:
        cand = audit_config.expand(gem, env.home)
        tools["gemini"] = cand if os.path.isabs(cand) and os.path.isfile(cand) else env.which(gem)
    bound = os.path.join(SCRIPT_DIR, "bound.sh")
    tools["bound.sh"] = bound if os.path.isfile(bound) else None
    m.data["tools"] = tools
    missing_req = [t for t in REQUIRED_TOOLS if not tools[t]]
    m.add("tools_required", not missing_req, True,
          "perl, python3 present" if not missing_req else f"missing: {', '.join(missing_req)}")
    opt = ["gcloud", "dig"] + (["codex"] if mc["codex"]["model"] else []) + \
        (["gemini"] if "gemini" in tools else [])
    missing_opt = [t for t in opt if not tools[t]]
    m.add("tools_optional", not missing_opt, False,
          f"{', '.join(opt)} present" if not missing_opt else f"missing: {', '.join(missing_opt)}")
    has_timeout = bool(tools["timeout"] or tools["gtimeout"])
    bounder = ("timeout" if tools["timeout"] else "gtimeout" if tools["gtimeout"]
               else "bound.sh" if tools["bound.sh"] else None)
    m.data["bounder"] = bounder
    m.add("bounder", bounder is not None, True,
          f"{bounder}" + ("" if has_timeout else " (GNU timeout absent, using the perl bounder)"))


# --------------------------------------------------------------------------- output

def summary_text(man):
    d = man.data
    lines = [f"Site audit run manifest  {d['timestamp']}  mode={d['mode']}",
             f"run dir: {d.get('run_dir', {}).get('path')}", ""]
    for i in man.items:
        tag = "REQUIRED" if i["required"] else "advisory"
        lines.append(f"[{i['status']:>12}] {tag:8} {i['item']}: {i['detail']}")
        if i.get("consequence") and i["status"] != "ok":
            lines.append(f"{'':24}-> {i['consequence']}")
    b = d.get("baseline", {})
    if b.get("kind"):
        lines += ["", f"baseline: {b['file']} ({b['date']})",
                  f"  companions: {', '.join(b['companions'].values()) or 'none'}",
                  f"  later Screaming Frog notes: {', '.join(b.get('screaming_frog_notes', [])) or 'none'}"]
    crawls = d.get("screaming_frog", {}).get("stored_crawls") or []
    if crawls:
        lines.append("stored crawls (newest first):")
        lines += [f"  {c['name']}  id={c['id']}  {c['date']}" for c in crawls]
    fails = man.failed_required
    lines += ["", "RESULT: " + ("FAIL (required: " + ", ".join(f["item"] for f in fails) + ")"
                                if fails else "OK")]
    return "\n".join(lines) + "\n"


def write_private(path, text):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".manifest-", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


_TOK = r"[FSN]\d{1,3}[a-z]?"
_DASHES = "-\u2013\u2014"  # hyphen, en dash, em dash (escaped: no literal dashes in source)
_RANGE = rf"{_TOK}(?:\s*[{_DASHES}]\s*(?:[FSN])?\d{{1,3}}[a-z]?)?"
_PAREN = r"(?:\s*\([^)\n]*\))?"
_IDS = rf"{_RANGE}{_PAREN}(?:\s*(?:,|&|/|\band\b)\s*(?:and\s+)?{_RANGE}{_PAREN})*"
ID_HEAD_RE = re.compile(rf"^(?:\*\*)?\s*(?P<ids>{_IDS})\s*(?:\*\*)?\s*[.:](?:\*\*)?\s*(?P<title>.*)$")
ID_BOLD_LINE_RE = re.compile(rf"^ {{0,3}}\*\*\s*(?P<ids>{_IDS})\s*(?:[.:]\s*\*\*|\*\*\s*[.:])\s*(?P<title>.*)$")
ID_SCAN_RE = re.compile(rf"(?<![\w-])({_TOK})(?:\s*[{_DASHES}]\s*([FSN])?(\d{{1,3}})([a-z]?))?(?![\w])")
ID_RE = re.compile(rf"\b({_TOK})\b")
STATE_RE = re.compile(r"\*\*(CONFIRMED|STILL OPEN|REGRESSED|FIXED|NEW|PARTIAL)[^*]*\*\*")
FINDINGS_H2_RE = re.compile(r"^##[ \t]+(?:\d+[.)]?[ \t]+)?findings\b", re.I)
H2_RE = re.compile(r"^##(?!#)[ \t]")
H3_RE = re.compile(r"^###(?!#)[ \t]+(.*)$")


def expand_ids(text):
    """'F12-F14, S1 (partial) and F1a' -> ['F12', 'F13', 'F14', 'S1', 'F1a']."""
    out = []
    text = re.sub(r"\([^)\n]*\)", " ", text)
    for mm in ID_SCAN_RE.finditer(text):
        first, letter2, num2, suf2 = mm.group(1), mm.group(2), mm.group(3), mm.group(4)
        out.append(first)
        if num2 is None:
            continue
        l1, n1, s1 = first[0], int(re.match(r"[FSN](\d+)", first).group(1)), first[-1].isalpha() and \
            first[-1].islower()
        l2 = letter2 or l1
        n2 = int(num2)
        last = f"{l2}{n2}{suf2}"
        if l2 == l1 and not s1 and not suf2 and n1 < n2 <= n1 + 50:
            out.extend(f"{l1}{k}" for k in range(n1 + 1, n2 + 1))
        elif last != first:
            out.append(last)
    return out


def _section(text, start_re):
    """Visible lines of the first '## ' section whose heading matches start_re, up to the next
    '## ' heading or EOF. Fenced code and HTML comments are skipped everywhere."""
    vis = visible_lines(text)
    out, inside = [], False
    for line in vis:
        if line is None:
            if inside:
                out.append("")
            continue
        if inside:
            if H2_RE.match(line):
                break
            out.append(line)
        elif start_re.match(line):
            inside = True
    return out if inside else None


def _method_heading_re(heading=None):
    h = heading if isinstance(heading, str) and heading.strip() else None
    if h is None:
        h = bconf()["method_table_heading"]  # the default heading (the loader refuses others)
    return re.compile(r"^##[ \t]+" + re.escape(h.strip()) + r"\b", re.I)


def _measured_in(prompt_text, heading=None):
    """ID -> (type, 'Measured in') from the method table (the section under the configured
    method_table_heading only, when the text has that heading)."""
    sec = _section(prompt_text, _method_heading_re(heading))
    lines = sec if sec is not None else prompt_text.splitlines()
    out = {}
    for line in lines:
        c = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(c) == 4 and re.fullmatch(_TOK, c[0]) and c[1] in ("P", "A"):
            out[c[0]] = (c[1], c[3])
    return out


def _prompt_rows(prompt_text, heading=None):
    sec = _section(prompt_text, _method_heading_re(heading))
    rows = []
    for line in sec if sec is not None else prompt_text.splitlines():
        c = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(c) == 4 and re.fullmatch(_TOK, c[0]) and c[1] in ("P", "A"):
            rows.append((c[0], c[1], c[2], c[3]))
    return rows


def _read_safe(baseline, path):
    if not safe_baseline_path(baseline, path):
        return None
    try:
        return _open_nofollow_text(path)
    except OSError:
        return None


def phase1_parse(baseline, prompt_text="", bcfg=None):
    """Return (rows, problems). Rows are the Phase 1 re-test list generated from the baseline;
    problems are '### ' headings under Findings that yielded no ID (read those by hand).

    Previous audit: the first '## Findings...' heading outside code (any suffix, any case,
    optionally numbered) up to the next '## ' heading or EOF. Each '### <IDs>. title' heading
    (IDs like F1, F1a, F100, F12-F14, 'F14 and S1', 'S1 (partial)', **F1.**, F1:) gives one row
    per ID, as does a paragraph line led by '**<IDs>.**'; the 'Carried over' and 'Fixed since'
    subsections add CANNOT RETEST and FIXED rows. Fallback baseline: the rows of the method
    table (baseline.method_table_file). Screaming Frog notes: each '**n. Title.**' under the
    note's Findings section as R<run>-<n> (run from baseline.notes_run_regex), or <file stem>-<n>
    when the name has no run number or that run number was already used, so IDs never collide."""
    bc = bcfg or bconf()
    rows, seen, problems = [], set(), []
    known = _measured_in(prompt_text, bc["method_table_heading"])

    def add(rid, title, last, src, typ=None, mi=None):
        if rid in seen:
            return
        seen.add(rid)
        t, m_in = known.get(rid, ("?", "decide from the baseline entry's method"))
        rows.append({"id": rid, "type": typ or t, "finding": title, "last_state": last,
                     "measured_in": mi or m_in, "source": src, "result": None})

    if baseline.get("kind") == "fallback":
        for rid, typ, finding, mi in _prompt_rows(prompt_text, bc["method_table_heading"]):
            add(rid, finding, FALLBACK_STATE, "method table", typ, mi)
    else:
        path = baseline.get("path")
        text = _read_safe(baseline, path)
        if text is None:
            return rows, problems
        sec = _section(text, FINDINGS_H2_RE) or []
        blocks, cur = [], None
        for line in sec:
            hm = H3_RE.match(line)
            if hm:
                cur = [hm.group(1).strip(), []]
                blocks.append(cur)
            elif cur is not None:
                cur[1].append(line)
            else:
                blocks.append(cur := ["", [line]])
        src = baseline.get("file")
        for head, body in blocks:
            rest = "\n".join(body)
            low = head.lower()
            if low.startswith("carried over"):
                for rid in expand_ids(rest):
                    add(rid, "carried over without a measurement", "CANNOT RETEST", src)
                continue
            if low.startswith("fixed since"):
                for mm in re.finditer(rf"^\s*[-*] \*\*({_IDS})\*\*:?\s*(.*)", rest, re.M):
                    for rid in expand_ids(mm.group(1)):
                        add(rid, mm.group(2).strip()[:160], "FIXED (re-test for regression)", src)
                continue
            if head:
                hm = ID_HEAD_RE.match(head)
                if hm and expand_ids(hm.group("ids")):
                    st = STATE_RE.search(rest[:600])
                    title = hm.group("title").strip().strip("*").strip()
                    for rid in expand_ids(hm.group("ids")):
                        add(rid, title, st.group(1) if st else "OPEN", src)
                else:
                    problems.append(head)
            for i, line in enumerate(body):
                bm = ID_BOLD_LINE_RE.match(line)
                if bm and expand_ids(bm.group("ids")):
                    st = STATE_RE.search("\n".join(body[i:])[:600])
                    title = bm.group("title").strip().strip("*").strip()
                    for rid in expand_ids(bm.group("ids")):
                        add(rid, title, st.group(1) if st else "OPEN", src)
    used_prefixes = set()
    try:
        run_re = re.compile(bc["notes_run_regex"])
    except (TypeError, re.error):
        run_re = None  # unusable: every note uses its file stem (the loader refuses this)
    for nm in baseline.get("screaming_frog_notes", []):
        t = _read_safe(baseline, os.path.join(baseline.get("baseline_dir", ""), nm))
        if t is None:
            continue
        rn = run_re.match(nm) if run_re is not None else None
        # no group 1, or group 1 unmatched: no run number, never an IndexError
        run_no = rn.group(1) if rn and rn.re.groups >= 1 else None
        prefix = f"R{run_no}" if run_no else nm[:-3]
        if prefix in used_prefixes:
            prefix = nm[:-3]
        used_prefixes.add(prefix)
        fsec = "\n".join(_section(t, FINDINGS_H2_RE) or [])
        for mm in re.finditer(r"^\*\*(\d+)\.\s+(.+?)\*\*", fsec, re.M | re.S):
            add(f"{prefix}-{mm.group(1)}", " ".join(mm.group(2).split())[:200], "OPEN", nm)
    return rows, problems


def phase1_rows(baseline, prompt_text=""):
    """The Phase 1 re-test rows (see phase1_parse)."""
    return phase1_parse(baseline, prompt_text)[0]


def phase1_markdown(rows, baseline, problems=None, failure=None):
    if not baseline.get("file") and not failure:
        return ("# Phase 1 rows: none\n\nNo baseline (first run). There is nothing to re-test; "
                "the findings of this run become the next run's baseline.\n")
    lines = [f"# Phase 1 rows generated from {baseline.get('file')} ({baseline.get('date')})", ""]
    if failure:
        lines += ["**FAILED: " + failure + "**", "",
                  "The manifest exited 2. Do not start Phase 1 from this file: read the baseline's",
                  "findings by hand, record why the parse failed, and fix the baseline or the parser.", ""]
    lines += ["Generated by run_manifest.py. Every row ends FIXED / STILL OPEN / REGRESSED /",
              "CANNOT RETEST (reason). Rows whose type is ? need their method read from the baseline.", ""]
    if problems:
        lines += ["Headings under Findings that gave no ID (read these entries by hand):", ""]
        lines += [f"- {h}" for h in problems] + [""]
    lines += ["| ID | Type | Finding as last recorded | Last state | Measured in | Source |",
              "|---|---|---|---|---|---|"]
    for r in rows:
        f = r["finding"].replace("|", "\\|")
        lines.append(f"| {r['id']} | {r['type']} | {f} | {r['last_state']} | {r['measured_in']} | {r['source']} |")
    return "\n".join(lines) + "\n"


def build(run_dir, mode, baseline_dir=None, env=None, cfg=None, sfcall=None, first_run=False):
    env = env or Env()
    cfg = cfg or audit_config.load_config()
    src = cfg.get("_source")
    if src and src != "defaults":
        # children (sfcall.sh) must read the same file the manifest loaded, not whatever
        # $SITE_AUDIT_CONFIG or the default path would give them
        env.child_env = {audit_config.ENV_VAR: os.path.abspath(src)}
    if baseline_dir is None:
        baseline_dir = audit_config.expand(cfg["baseline"]["dir"], env.home) if cfg["baseline"]["dir"] else None
    man = Manifest()
    man.data.update({"timestamp": env.now().strftime("%Y-%m-%dT%H:%M:%SZ"), "mode": mode,
                     "baseline_dir": baseline_dir, "config": cfg.get("_source"), "schema": 3})
    # The run dir is checked before any network, subprocess or file check (only the config is
    # loaded first); when it fails, nothing else runs and nothing is written.
    dir_ok = check_run_dir(run_dir, env, man, cfg)
    ok_mode = mode in ("attended", "unattended")
    man.add("mode", ok_mode, True, mode if ok_mode else f"invalid mode {mode!r}")
    p1_failure = None
    if dir_ok and ok_mode:
        rd = man.data["run_dir"]["realpath"]
        env.fetch_log = os.path.join(rd, "fetch.log")
        env.allowed_hosts = tuple(cfg["allowed_hosts"])
        env.run_root = run_root_for(env, cfg)
        check_baseline(baseline_dir, env, man, cfg, first_run)
        check_models(env, man, cfg)
        check_tools(env, man, cfg)
        check_readonly_db(mode, env, man, cfg)
        check_screaming_frog(env, man, sfcall, cfg)
        check_live(env, man, cfg)
        b = man.data.get("baseline") or {}
        ptxt = ""
        mt = cfg["baseline"]["method_table_file"]
        if mt:
            try:
                ptxt = _open_nofollow_text(audit_config.expand(mt, env.home))
            except OSError:
                ptxt = ""
        rows, problems = phase1_parse(b, ptxt, cfg["baseline"]) if b.get("kind") else ([], [])
        man.data["phase1_rows"] = rows
        man.data["phase1_unparsed_headings"] = problems
        if b.get("kind"):
            src = ("the method table (baseline.method_table_file)" if b["kind"] == "fallback"
                   else b.get("file"))
            if not rows:
                p1_failure = (f"0 rows parsed from {src}"
                              + ("" if b["kind"] == "fallback" or problems else
                                 " (no '## Findings' section with ID headings outside code blocks)"))
            man.add("phase1_rows", bool(rows), True,
                    f"{len(rows)} rows from {src} and {len(b.get('screaming_frog_notes', []))} "
                    "Screaming Frog notes" if rows else p1_failure,
                    None if rows else "read the baseline's findings by hand and record why the parse failed")
            if problems:
                man.add("phase1_unparsed", False, False,
                        f"{len(problems)} heading(s) under Findings gave no ID: " + "; ".join(problems[:10]),
                        "read those entries by hand and add them to the method table")
        elif first_run and not b.get("unsafe_baseline_dir"):
            p1_failure = None
        else:
            p1_failure = "no baseline was selected"
    man.data["checks"] = man.items
    man.data["result"] = "FAIL" if man.failed_required else "OK"
    man.data["failed_required"] = [f["item"] for f in man.failed_required]
    if dir_ok:
        rd = man.data["run_dir"]["realpath"]
        write_private(os.path.join(rd, "manifest.json"), json.dumps(man.data, indent=2) + "\n")
        write_private(os.path.join(rd, "manifest-summary.txt"), summary_text(man))
        if ok_mode:
            write_private(os.path.join(rd, "phase1-rows.md"),
                          phase1_markdown(man.data.get("phase1_rows") or [], man.data.get("baseline") or {},
                                          man.data.get("phase1_unparsed_headings"), p1_failure))
    return man


def main(argv=None, env=None, out=sys.stdout, **build_opts):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--config", help="config file (else $SITE_AUDIT_CONFIG, else "
                                     "~/.config/site-audit-kit/config.json)")
    ap.add_argument("--baseline-dir", help="folder of previous findings files (else baseline.dir)")
    ap.add_argument("--first-run", action="store_true",
                    help="no previous audit exists: record that instead of failing")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    os.umask(0o077)
    if "cfg" not in build_opts:
        try:
            build_opts["cfg"] = audit_config.load_config(a.config)
        except audit_config.ConfigError as e:
            out.write(f"run_manifest: config error: {e}\n")
            return 2
    man = build(a.run_dir, a.mode, a.baseline_dir, env=env, first_run=a.first_run, **build_opts)
    out.write(json.dumps(man.data, indent=2) + "\n" if a.json else summary_text(man))
    return 2 if man.failed_required else 0


if __name__ == "__main__":
    sys.exit(main())
