#!/usr/bin/env python3
"""Redact the values of sensitive query parameters in crawl exports, in place.

Usage:
  redact_exports.py PATH... [--check] [--extra-params a,b] [--fix-perms]
                    [--config PATH]

Walks every PATH (files and directories, recursively) and replaces the VALUE of each sensitive
parameter with REDACTED while keeping the key:

  https://x/reset?token=abc123&lang=en   ->   https://x/reset?token=REDACTED&lang=en

The gate before anyone uses or shares an export is `--check` exiting 0, so this tool fails
closed: a file it cannot read as text is never silently passed.

Parameter names in the config's redaction.extra_params (config from --config, else
$SITE_AUDIT_CONFIG, else ~/.config/site-audit-kit/config.json; a missing default file adds
nothing) and in --extra-params are added to the built-in list. Nothing can remove a built-in
name: there is no option that replaces or shortens the list.

What is scanned
  * UTF-8 / ASCII / 8-bit text (no NUL bytes, no C0 control bytes other than tab, LF, VT, FF, CR,
    ESC): processed as bytes, line by line, so non-UTF-8 bytes survive unchanged.
  * UTF-16 and UTF-32 (LE or BE, with or without a BOM; without one the NUL-byte pattern picks the
    candidate and a strict decode of the WHOLE file must succeed with no U+0000): decoded,
    scanned, and re-encoded in the same encoding.
  * Known-binary extensions (png jpg jpeg gif webp avif ico pdf zip gz xz bz2 7z woff woff2 ttf
    otf mp4 webm mov sqlite db seospider): never rewritten, listed as skipped-binary on stderr,
    but byte-scanned; a plain value found inside one is reported and fails the run.
  * Anything else (NUL bytes that are not UTF-16/32, control bytes, a symlink, a FIFO, a file
    that cannot be opened): listed on stdout as `UNSCANNED: path (reason)` and the run exits 1.
    Leftover `.redact-*.tmp` files from an interrupted run are scanned like any other file.

Recognised forms (case-insensitive)
  separator before the key: ? & # ; / (also start of line, comma, quote, apostrophe, any
    whitespace: a key at the very start of a CSV cell, JSON string or word, e.g. "seen token=x"), HTML (&amp; &#38; &#x26; &#63; &#35; &#59;
    &quest; &num; &semi;), JSON escapes with any number of backslashes (\\u0026 \\\\u0026 ...
    for & ? # ; /), percent-encoded at any depth (%26 %3F %23 %3B %2F, %2526 ...).
  key: any listed name, each letter optionally percent-encoded (%74oken), optionally followed by
    [] / [x] / %5B%5D and by + or %20.
  equals: = %3D %253D ... \\u003d \\\\u003d &#61; &#x3d; &equals;

Value boundary rule (where a value ends)
  * Always: whitespace, any C0 control byte or NUL, " ' < > ` and the plain separators & and #.
  * A JSON backslash escape: \\/ (any number of backslashes) continues; \\uXXXX continues unless the
    escaped character is itself a stop character (so \\u0026 and \\\\u0026 end the value, \\u0061
    and \\u0040 do not); any other escape (\\" \\n \\\\x) ends it.
  * Percent-encoded context: when the separator and the equals sign are both percent-encoded, the
    context depth L is the smaller of the two depths (%26 = 1, %2526 = 2). The value then ends at
    an encoded & # space " ' < > of depth <= L, so %2526 inside a depth-1 value is part of the
    value, but %26 ends it. Plain context (L = 0) never stops at a percent sequence: in
    ?token=a%26b the %26 is part of the value, exactly as a URL parser reads it.
  * Matrix parameters (separator ;): the value also ends at ; / ? = (plain, or encoded at depth
    <= L), so /app;sid=X/reset?lang=en keeps /reset?lang=en.
  * Comma: ends the value only in an UNQUOTED field of a .csv file (comma-separated fields never
    merge; a CSV writer quotes any field that contains a comma). Everywhere else (quoted CSV
    fields, TSV, JSON, HTML/XML, plain text, unknown extensions) a comma is part of the value.
  * { [ ( open a bracketed run that continues to its balanced closer on the same line, so
    state={"csrf":"x"} and password=(abc) are redacted to their real end. The search gives up
    (the bracket is then an ordinary character) at a line end, at an unescaped " in JSON/HTML
    files, at the end of a quoted CSV field, or at a comma in an unquoted CSV field.
    | ) ] } on their own do not stop a value (Laravel 1|token is one value).
  * A value that starts with a quote (token="abc", token=\\"abc\\", or "" inside a quoted CSV
    field) is the quoted content, if it contains no separator-like character.
  * A CSV value that reaches the end of a line inside a still-open quoted field continues at the
    start of the next line (multi-line quoted cells).
  Over-redaction is preferred to a leak: a plain-context value may swallow later text that a
  stricter parser would have kept.

Modes
  default      rewrite files that contain unredacted values: a temp file created mode 600 in the
               same directory (O_EXCL, O_NOFOLLOW), fsync, os.replace, fsync of the directory.
  --check      read only; exit 1 and list path:line: key for every unredacted value.
  --fix-perms  BEFORE any scanning, every directory walked becomes 700 and every file 600 (via the
               open descriptor, never following a symlink). With --check it changes no content.

Symlinks are never followed. A top-level PATH that is a symlink (with or without a trailing
slash) is refused with exit 2 before anything is touched. Every file is opened with O_NOFOLLOW
relative to an open descriptor of its directory.

Values are never printed in any mode.
Exit: 0 clean / fully redacted; 1 unredacted values found (--check), or a file was UNSCANNED,
or a binary file holds a value (both modes); 2 usage error, refused PATH, or I/O error.
"""
import argparse
import bisect
import codecs
import errno
import io
import os
import re
import secrets
import stat
import sys

DEFAULT_PARAMS = (
    # tokens and keys
    "token", "access_token", "refresh_token", "id_token", "reset_token", "auth_token", "jwt",
    "oauth_token", "oauth_verifier", "code_verifier", "code", "auth_code", "state", "nonce",
    "otp", "ticket", "assertion", "saml", "samlresponse", "samlrequest",
    "key", "api_key", "apikey", "api-key", "x-api-key", "access_key", "secret_key", "private_key",
    "secret", "client_secret", "credential", "credentials", "auth", "authorization",
    # passwords
    "password", "passwd", "pass", "pwd",
    # signatures
    "signature", "sig", "hash", "x-amz-signature", "x-amz-credential", "x-amz-security-token",
    "x-goog-signature", "x-goog-credential",
    # sessions
    "session", "sessionid", "session_id", "sid", "jsessionid", "phpsessid",
    # one-time links
    "verification", "verify", "magic", "magic_link", "invite", "invitation", "confirmation",
    "confirm", "reset", "recovery",
    # personal data
    "email", "e",
)
REDACTED = b"REDACTED"
SNIFF = 65536
CHUNK = 1 << 20
BRACKET_MAX = 65536
QUOTED_MAX = 4096

KNOWN_BINARY = frozenset(
    "png jpg jpeg gif webp avif ico pdf zip gz xz bz2 7z woff woff2 ttf otf mp4 webm mov "
    "sqlite db seospider".split())
CSV_EXT = {"csv": b",", "tsv": b"\t"}
JSON_EXT = frozenset("json ndjson jsonl har".split())
MARKUP_EXT = frozenset("html htm xhtml xml svg".split())

# Bytes allowed in a text file besides printable ones: tab LF VT FF CR ESC, and 0x20-0xff.
_TEXT_BYTES = bytes([9, 10, 11, 12, 13, 27]) + bytes(range(0x20, 0x100))

# ----------------------------------------------------------------------------- the pattern

_DELIM = (
    rb"(?:%(?P<dl>(?:25)*)(?P<dc>3f|26|23|3b|2f)"
    rb"|(?P<jd>\\+u00(?:26|3f|23|3b|2f))"
    rb"|(?P<hd>&amp;|&#0*(?:38|63|35|59|47);|&#x0*(?:26|3f|23|3b|2f);|&(?:quest|num|semi|sol);)"
    rb"|(?P<pd>[?&#;/,\"' \t\r\n\v\f]|\xef\xbb\xbf)"
    rb"|^)"
)
_EQ = rb"(?:%(?P<el>(?:25)*)3d|\\+u003d|&#0*61;|&#x0*3d;|&equals;|=)"
_KEY_SUFFIX = (rb"(?:\[[A-Za-z0-9_.\-]{0,32}\]|%(?:25)*5b[A-Za-z0-9_.\-]{0,32}%(?:25)*5d)*"
               rb"(?:\+|%(?:25)*20)*")
_MATRIX_HTML = re.compile(rb"&#0*59;|&#x0*3b;|&semi;", re.I)
_PCT_RUN = re.compile(rb"%((?:25)*)([0-9a-fA-F]{2})")


def _char_regex(ch):
    """One key character: itself, or percent-encoded at any depth (either letter case)."""
    codes = {f"{ord(ch):02x}"}
    if ch.isalpha():
        codes.add(f"{ord(ch.upper()):02x}")
    enc = b"|".join(sorted(c.encode() for c in codes))
    return rb"(?:" + re.escape(ch.encode()) + rb"|%(?:25)*(?:" + enc + rb"))"


def _trie_regex(keys):
    """Alternation of keys as a trie, so the regex engine never retries 70 keys per position."""
    trie = {}
    for k in keys:
        node = trie
        for ch in k:
            node = node.setdefault(ch, {})
        node[""] = {}

    def emit(node):
        alts = []
        end = "" in node
        for ch in sorted(c for c in node if c):
            alts.append(_char_regex(ch) + emit(node[ch]))
        if not alts:
            return b""
        body = alts[0] if len(alts) == 1 else rb"(?:" + b"|".join(alts) + rb")"
        return rb"(?:" + body + rb")?" if end else body

    return emit(trie)


def build_pattern(params):
    """Compiled matcher. It is applied to line.lower() (same length, same offsets), so the
    pattern itself is lowercase and needs no re.I."""
    keys = sorted({p.strip().lower() for p in params if p.strip()})
    if not keys:
        raise ValueError("empty parameter list")
    for k in keys:
        if not re.fullmatch(r"[a-z0-9_.\-]+", k):
            raise ValueError(f"unsupported parameter name: {k!r}")
    return re.compile(_DELIM + rb"(?P<key>" + _trie_regex(keys) + rb")" + _KEY_SUFFIX + _EQ)


def _context_of(m):
    """(depth, matrix) of a match. depth = percent-encoding depth of the value's context: the
    smaller of the separator's and the equals sign's depth (a plain separator counts 0); a key
    at the start of a field has only the equals sign's depth. matrix = separator was ;."""
    elev = len(m.group("el")) // 2 + 1 if m.group("el") is not None else 0
    if m.group("dc") is not None:
        level = min(len(m.group("dl")) // 2 + 1, elev)
        matrix = m.group("dc").lower() == b"3b"
    elif m.group("jd") or m.group("hd") or m.group("pd") is not None:
        level = 0
        matrix = bool((m.group("jd") or b"").lower().endswith(b"3b")
                      or _MATRIX_HTML.fullmatch(m.group("hd") or b"")
                      or m.group("pd") == b";")
    else:
        level, matrix = elev, False
    return level, matrix


def _key_name(raw):
    s = raw
    for _ in range(4):
        s2 = _PCT_RUN.sub(lambda m: bytes([int(m.group(2), 16)]), s)
        if s2 == s:
            break
        s = s2
    return s.decode("ascii", "replace").lower()


# ----------------------------------------------------------------------------- value scanning

_STOP0 = frozenset(list(range(0x00, 0x21)) + [0x7F] + list(b"\"'<>`&#"))
_INTEREST = re.compile(rb"[\x00-\x20\x7f\"'<>`&#\\%{\[(,;/?=]")
_BRACKET_INTEREST = re.compile(rb"[\r\n\x00\"{}\[\]()\,]")
_OPEN = {0x7B: 0x7D, 0x5B: 0x5D, 0x28: 0x29}
_CLOSE = frozenset(_OPEN.values())
_UESC = re.compile(rb"u([0-9a-fA-F]{4})")
_QUOTED_OK = re.compile(rb"[^\s\"'\\,:;{}\[\]()<>&`]+\Z")
_ENC_STOP_CACHE = {}


def _enc_stop(level, matrix):
    k = (level, matrix)
    r = _ENC_STOP_CACHE.get(k)
    if r is None:
        codes = b"26|23|20|22|27|3c|3e" + (b"|3b|2f|3f|3d" if matrix else b"")
        r = re.compile(rb"%(?:25){0," + str(level - 1).encode() + rb"}(?:" + codes + rb")", re.I)
        _ENC_STOP_CACHE[k] = r
    return r


class Ctx:
    __slots__ = ("level", "matrix", "comma", "bracket_comma", "quote_term", "limit", "csvq", "kind")

    def __init__(self, kind, level=0, matrix=False, csvq=False, limit=None, sep=b","):
        self.kind = kind
        self.level = level
        self.matrix = matrix
        self.csvq = csvq            # inside a quoted CSV field
        self.limit = limit          # index of that field's closing quote (exclusive end)
        # A comma is a field separator only in an unquoted field of a comma-separated file.
        self.comma = kind == "csv" and not csvq and sep == b","
        self.bracket_comma = self.comma
        self.quote_term = kind in ("json", "markup")

    def is_stop_cp(self, cp):
        if cp in _STOP0 or cp == 0x5C:
            return True
        if cp == 0x2C and self.comma:
            return True
        return self.matrix and cp in (0x3B, 0x2F, 0x3F, 0x3D)


def _escaped(line, j):
    k = j - 1
    while k >= 0 and line[k] == 0x5C:
        k -= 1
    return (j - 1 - k) % 2 == 1


def _bracket_close(line, i, n, ctx):
    stack = [_OPEN[line[i]]]
    j = i + 1
    end = min(n, i + BRACKET_MAX)
    while j < end:
        m = _BRACKET_INTEREST.search(line, j, end)
        if not m:
            return -1
        j = m.start()
        c = line[j]
        if c in (0x0D, 0x0A, 0x00):
            return -1
        if c == 0x22:
            if ctx.quote_term and not _escaped(line, j):
                return -1
        elif c == 0x2C:
            if ctx.bracket_comma:
                return -1
        elif c in _OPEN:
            stack.append(_OPEN[c])
        elif c in _CLOSE:
            if stack[-1] != c:
                return -1
            stack.pop()
            if not stack:
                return j
        j += 1
    return -1


def _quoted_value(line, vs, n, ctx):
    """Return (start, end) of a quoted value starting at vs, or None if vs is not a quote."""
    if ctx.csvq and line.startswith(b'""', vs):
        qt = b'""'
    elif line.startswith(b'\\"', vs):
        qt = b'\\"'
    elif line.startswith(b"&quot;", vs):
        qt = b"&quot;"
    elif vs < n and line[vs] in (0x22, 0x27) and ctx.kind != "json" and not (
            ctx.csvq and line[vs] == 0x22):
        qt = line[vs:vs + 1]
    else:
        return None
    cs = vs + len(qt)
    ce = line.find(qt, cs, min(n, cs + QUOTED_MAX))
    if ce > cs and _QUOTED_OK.match(line, cs, ce):
        return cs, ce
    return vs, vs


def value_span(line, vs, ctx, allow_quoted=True):
    """(start, end) of the parameter value that begins at vs. See the module docstring."""
    n = len(line) if ctx.limit is None else min(len(line), ctx.limit)
    if allow_quoted:
        q = _quoted_value(line, vs, n, ctx)
        if q is not None:
            return q
    enc = _enc_stop(ctx.level, ctx.matrix) if ctx.level else None
    i = vs
    while i < n:
        m = _INTEREST.search(line, i, n)
        if not m:
            i = n
            break
        i = m.start()
        c = line[i]
        if c in _STOP0:
            break
        if c == 0x2C:
            if ctx.comma:
                break
        elif c in (0x3B, 0x2F, 0x3F, 0x3D):
            if ctx.matrix:
                break
        elif c == 0x5C:
            j = i
            while j < n and line[j] == 0x5C:
                j += 1
            if j < n and line[j] == 0x2F:
                i = j + 1
                continue
            mu = _UESC.match(line, j, n)
            if mu and not ctx.is_stop_cp(int(mu.group(1), 16)):
                i = mu.end()
                continue
            break
        elif c == 0x25:
            if enc is not None and enc.match(line, i, n):
                break
        elif c in _OPEN:
            j = _bracket_close(line, i, n, ctx)
            if j > 0:
                i = j + 1
                continue
        i += 1
    return vs, min(i, n)


# ----------------------------------------------------------------------------- CSV quote state

def _csv_close(line, p, n):
    """Index of the closing quote of a quoted field whose content starts at p, or -1."""
    while True:
        j = line.find(b'"', p, n)
        if j < 0:
            return -1
        if j + 1 < n and line[j + 1] == 0x22:
            p = j + 2
            continue
        return j


def csv_regions(line, sep, start_inside):
    """Quoted-field content regions [(start, end)] of one physical line, and whether the line
    ends inside an open quoted field (end == len(line) for that region)."""
    n = len(line)
    regions = []
    i = 0
    if start_inside:
        j = _csv_close(line, 0, n)
        if j < 0:
            return [(0, n)], True
        regions.append((0, j))
        k = line.find(sep, j + 1)
        if k < 0:
            return regions, False
        i = k + 1
    while i < n:
        if line[i] == 0x22:
            j = _csv_close(line, i + 1, n)
            if j < 0:
                regions.append((i + 1, n))
                return regions, True
            regions.append((i + 1, j))
            i = j + 1
        k = line.find(sep, i)
        if k < 0:
            break
        i = k + 1
    return regions, False


class Scanner:
    """Finds sensitive values line by line, carrying CSV quote state across lines."""

    def __init__(self, pattern, kind="text", sep=b","):
        self.pattern = pattern
        self.kind = kind
        self.sep = sep
        self.in_quote = False
        self.carry = None  # (key, level, matrix) of a value continuing on the next line

    def spans(self, line):
        """Yield (key, value_start, value_end) for every candidate value on this line."""
        regions, ends_inside = ([], False)
        starts = []
        if self.kind == "csv":
            regions, ends_inside = csv_regions(line, self.sep, self.in_quote)
            starts = [r[0] for r in regions]
        eol = len(line.rstrip(b"\r\n"))

        def ctx_at(pos, level, matrix):
            if self.kind == "csv":
                k = bisect.bisect_right(starts, pos) - 1
                if k >= 0 and regions[k][0] <= pos <= regions[k][1]:
                    return Ctx("csv", level, matrix, csvq=True, limit=regions[k][1],
                               sep=self.sep), k
                return Ctx("csv", level, matrix, sep=self.sep), None
            return Ctx(self.kind, level, matrix), None

        def maybe_carry(key, ve, region_idx, level, matrix):
            if (self.kind == "csv" and ends_inside and region_idx is not None
                    and region_idx == len(regions) - 1 and ve >= eol):
                self.carry = (key, level, matrix)

        out = []
        pos = 0
        carry, self.carry = self.carry, None
        if carry is not None:
            key, level, matrix = carry
            ctx, ridx = ctx_at(0, level, matrix)
            _, ve = value_span(line, 0, ctx, allow_quoted=False)
            out.append((key, 0, ve))
            maybe_carry(key, ve, ridx, level, matrix)
            pos = ve
        low = line.lower()
        while True:
            m = self.pattern.search(low, pos)
            if not m:
                break
            level, matrix = _context_of(m)
            key = _key_name(m.group("key"))  # from the lowercased copy
            vs = m.end()
            ctx, ridx = ctx_at(vs, level, matrix)
            s, e = value_span(line, vs, ctx)
            out.append((key, s, e))
            maybe_carry(key, max(e, vs), ridx, level, matrix)
            pos = max(e, m.end())
        self.in_quote = ends_inside
        return out


def is_unredacted(value):
    return bool(value) and value != REDACTED


def scan_line(line, pattern, kind="text"):
    """Yield (key, value_start, value_end) for each sensitive parameter on one line."""
    for key, s, e in Scanner(pattern, kind).spans(line):
        if e > s:
            yield key, s, e


def _apply(line, spans):
    out, last, count, keys = [], 0, 0, []
    for key, s, e in spans:
        if is_unredacted(line[s:e]):
            out.append(line[last:s])
            out.append(REDACTED)
            last = e
            count += 1
            keys.append(key)
    if not count:
        return line, 0, keys
    out.append(line[last:])
    return b"".join(out), count, keys


def redact_line(line, pattern, kind="text"):
    """Return (new_line, count_of_values_replaced)."""
    new, count, _ = _apply(line, Scanner(pattern, kind).spans(line))
    return new, count


# ----------------------------------------------------------------------------- classification

def _ext(name):
    base = name.lower()
    if base.endswith(".tmp") and base.startswith(".redact-"):
        return ""
    return base.rsplit(".", 1)[-1] if "." in base else ""


def _kind_for(ext):
    if ext in CSV_EXT:
        return "csv", CSV_EXT[ext]
    if ext in JSON_EXT:
        return "json", b","
    if ext in MARKUP_EXT:
        return "markup", b","
    return "text", b","


def _bom_codec(head):
    if head.startswith(b"\xff\xfe\x00\x00"):
        return "utf-32-le"
    if head.startswith(b"\x00\x00\xfe\xff"):
        return "utf-32-be"
    if head.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if head.startswith(b"\xfe\xff"):
        return "utf-16-be"
    return None


_BAD_TEXT = re.compile("[\x00-\x08\x0e-\x1a\x1c-\x1f]")


def _decodes_cleanly(f, codec):
    f.seek(0)
    dec = codecs.getincrementaldecoder(codec)(errors="strict")
    try:
        while True:
            chunk = f.read(CHUNK)
            text = dec.decode(chunk, final=not chunk)
            if _BAD_TEXT.search(text):
                return False
            if not chunk:
                return True
    except UnicodeDecodeError:
        return False


def classify(f, ext):
    """('binary'|'bytes'|'decoded'|'unscanned', codec_or_reason)."""
    if ext in KNOWN_BINARY:
        return "binary", None
    f.seek(0)
    head = f.read(SNIFF)
    codec = _bom_codec(head)
    if codec:
        if _decodes_cleanly(f, codec):
            return "decoded", codec
        return "unscanned", f"{codec} BOM but does not decode as {codec}"
    has_nul = b"\x00" in head
    has_ctrl = bool(head.translate(None, _TEXT_BYTES).replace(b"\x00", b""))
    while not has_nul:
        chunk = f.read(CHUNK)
        if not chunk:
            break
        has_nul = b"\x00" in chunk
        has_ctrl = has_ctrl or bool(chunk.translate(None, _TEXT_BYTES).replace(b"\x00", b""))
    if not has_nul:
        if has_ctrl:
            return "unscanned", "control bytes, not text"
        return "bytes", None
    h = head[: len(head) - len(head) % 4]
    ev, od = h[0::2].count(0), h[1::2].count(0)
    cands = ["utf-32-le", "utf-32-be"]
    # Without a BOM, UTF-16 is only believed when NULs are dense (>= 20% of the sniffed bytes,
    # i.e. mostly-ASCII text) and >= 95% of them sit on one byte parity. A stray NUL in an
    # ASCII file must not turn it into "UTF-16" that decodes to CJK and scans clean.
    nuls = ev + od
    if h and nuls >= 0.2 * len(h):
        if od >= 0.95 * nuls:
            cands.append("utf-16-le")
        elif ev >= 0.95 * nuls:
            cands.append("utf-16-be")
    for c in cands:
        if _decodes_cleanly(f, c):
            return "decoded", c
    return "unscanned", "contains NUL bytes and is not UTF-16/UTF-32 text"


# ----------------------------------------------------------------------------- file processing

O_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
O_DIR = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)


class Run:
    def __init__(self, pattern, check, fix_perms, out, err):
        self.pattern = pattern
        self.check = check
        self.fix_perms = fix_perms
        self.out = out
        self.err = err
        self.s = {"files": 0, "decoded": 0, "binary": 0, "unscanned": 0, "values": 0,
                  "files_with_hits": 0, "rewritten": 0, "perms_fixed": 0, "leftover_tmp": 0}
        self.errors = []
        self.binary_hits = 0

    def report(self, line):
        print(line, file=self.out)

    def note(self, line):
        print(f"redact_exports: {line}", file=self.err)

    def unscanned(self, path, reason):
        self.s["unscanned"] += 1
        self.report(f"UNSCANNED: {path} ({reason})")

    # ---- permissions (pre-pass) -------------------------------------------------------------
    def _fchmod(self, fd, mode, path):
        try:
            if stat.S_IMODE(os.fstat(fd).st_mode) != mode:
                os.fchmod(fd, mode)
                self.s["perms_fixed"] += 1
        except OSError as e:
            self.errors.append(f"{path}: chmod failed: {e.strerror}")

    def _chmod_nofollow(self, dirfd, name, mode, path):
        try:
            os.chmod(name, mode, dir_fd=dirfd, follow_symlinks=False)
            self.s["perms_fixed"] += 1
            return True
        except (OSError, NotImplementedError) as e:
            self.errors.append(f"{path}: chmod failed: {getattr(e, 'strerror', e)}")
            return False

    def _open_dir(self, dirfd, name, path, st):
        try:
            fd = os.open(name, O_DIR, dir_fd=dirfd)
        except PermissionError:
            if not (self.fix_perms and self._chmod_nofollow(dirfd, name, 0o700, path)):
                self.errors.append(f"{path}: cannot open directory")
                return None
            fd = os.open(name, O_DIR, dir_fd=dirfd)
        if not os.path.samestat(os.fstat(fd), st):
            os.close(fd)
            self.errors.append(f"{path}: directory changed while walking")
            return None
        if self.fix_perms:
            self._fchmod(fd, 0o700, path)
        return fd

    def perms_pass(self, dirfd, dpath):
        for name, path, st in self._entries(dirfd, dpath, quiet=True):
            if stat.S_ISDIR(st.st_mode):
                fd = self._open_dir(dirfd, name, path, st)
                if fd is not None:
                    try:
                        self.perms_pass(fd, path)
                    finally:
                        os.close(fd)
            elif stat.S_ISREG(st.st_mode):
                self._perm_file(dirfd, name, path)

    def _perm_file(self, dirfd, name, path):
        try:
            fd = os.open(name, O_READ, dir_fd=dirfd)
        except PermissionError:
            self._chmod_nofollow(dirfd, name, 0o600, path)
            return
        except OSError:
            return  # symlink swapped in or vanished: the scan pass reports it
        try:
            if stat.S_ISREG(os.fstat(fd).st_mode):
                self._fchmod(fd, 0o600, path)
        finally:
            os.close(fd)

    # ---- walking ---------------------------------------------------------------------------
    def _entries(self, dirfd, dpath, quiet=False):
        try:
            names = sorted(os.listdir(dirfd))
        except OSError as e:
            if not quiet:
                self.errors.append(f"{dpath}: cannot list directory: {e.strerror}")
            return
        for name in names:
            path = os.path.join(dpath, name)
            try:
                st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            except OSError as e:
                if not quiet:
                    self.errors.append(f"{path}: {e.strerror}")
                continue
            yield name, path, st

    def scan_dir(self, dirfd, dpath):
        for name, path, st in self._entries(dirfd, dpath):
            if stat.S_ISLNK(st.st_mode):
                self.unscanned(path, "symlink, not followed")
            elif stat.S_ISDIR(st.st_mode):
                fd = self._open_dir(dirfd, name, path, st)
                if fd is not None:
                    try:
                        self.scan_dir(fd, path)
                    finally:
                        os.close(fd)
            elif stat.S_ISREG(st.st_mode):
                self.scan_file(dirfd, name, path)
            else:
                self.unscanned(path, "not a regular file")

    # ---- one file --------------------------------------------------------------------------
    def scan_file(self, dirfd, name, path):
        try:
            fd = os.open(name, O_READ, dir_fd=dirfd)
        except OSError as e:
            if e.errno == errno.ELOOP:
                self.unscanned(path, "symlink, not followed")
            else:
                self.errors.append(f"{path}: cannot open: {e.strerror}")
                self.unscanned(path, "cannot open")
            return
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                self.unscanned(path, "not a regular file")
                return
            if self.fix_perms:
                self._fchmod(fd, 0o600, path)
            if name.startswith(".redact-") and name.endswith(".tmp"):
                self.s["leftover_tmp"] += 1
                self.note(f"leftover temp file from an interrupted run, scanned: {path}")
            raw = io.FileIO(fd, "rb", closefd=False)
            f = io.BufferedReader(raw, CHUNK)
            ext = _ext(name)
            kind, info = classify(f, ext)
            if kind == "unscanned":
                self.unscanned(path, info)
                return
            if kind == "binary":
                self.s["binary"] += 1
                self.note(f"skipped-binary (never rewritten, byte-scanned): {path}")
                keys = self._raw_keys(f)
                if keys:
                    self.binary_hits += len(keys)
                    self.report(f"{path}: {','.join(sorted(keys))} (binary file, not rewritten)")
                return
            self.s["files"] += 1
            if kind == "decoded":
                self.s["decoded"] += 1
                # Cross-check: plain ASCII visible in the raw bytes of a UTF-16/32 file is either
                # a misclassified file or bytes outside the text; never pass or rewrite it.
                keys = self._raw_keys(f)
                if keys:
                    self.binary_hits += len(keys)
                    self.report(f"{path}: {','.join(sorted(keys))} (plain bytes inside a "
                                f"{info} file, not rewritten)")
                    return
            ftype, sep = _kind_for(ext)
            f.seek(0)
            if self.check:
                hits = self._scan_stream(f, path, ftype, sep, info, None)
                if hits:
                    self.s["values"] += hits
                    self.s["files_with_hits"] += 1
            else:
                self._redact(f, fd, st, dirfd, name, path, ftype, sep, info)
        except UnicodeError:
            self.unscanned(path, "stopped decoding mid-file")
        except OSError as e:
            self.errors.append(f"{path}: {e.strerror or e}")
        finally:
            os.close(fd)

    def _lines(self, f, codec):
        if codec is None:
            yield from f
            return
        t = io.TextIOWrapper(f, encoding=codec, errors="strict", newline="")
        try:
            for s in t:
                yield s.encode("utf-8")
        finally:
            t.detach()

    def _scan_stream(self, f, path, ftype, sep, codec, sink):
        sc = Scanner(self.pattern, ftype, sep)
        hits = 0
        for lineno, line in enumerate(self._lines(f, codec), 1):
            new, c, keys = _apply(line, sc.spans(line))
            if sink is not None:
                sink.write(new if codec is None else new.decode("utf-8").encode(codec))
            if c:
                hits += c
                if sink is None:
                    self.report(f"{path}:{lineno}: {','.join(sorted(set(keys)))}")
        return hits

    def _raw_keys(self, f):
        """Byte-scan a whole file in overlapping chunks (no line is ever held whole)."""
        f.seek(0)
        keys, tail = set(), b""
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            buf = tail + chunk
            for key, s, e in Scanner(self.pattern, "text").spans(buf):
                if is_unredacted(buf[s:e]):
                    keys.add(key)
            tail = buf[-4096:]
        return keys

    def _redact(self, f, fd, st, dirfd, name, path, ftype, sep, codec):
        tmp = None
        tfd = -1
        for _ in range(16):
            cand = f".redact-{secrets.token_hex(8)}.tmp"
            try:
                tfd = os.open(cand, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                              | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dirfd)
                tmp = cand
                break
            except FileExistsError:
                continue
        if tmp is None:
            raise OSError(errno.EEXIST, "could not create a temp file")
        try:
            os.fchmod(tfd, 0o600)
            with io.FileIO(tfd, "wb", closefd=False) as rawout, \
                    io.BufferedWriter(rawout, CHUNK) as out:
                try:
                    replaced = self._scan_stream(f, path, ftype, sep, codec, out)
                except UnicodeError:
                    self.unscanned(path, "stopped decoding mid-file; not rewritten")
                    return
                out.flush()
                os.fsync(tfd)
            if not replaced:
                return
            now = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            if not os.path.samestat(now, st):
                self.errors.append(f"{path}: changed during redaction; not replaced")
                return
            if st.st_nlink > 1:
                self.note(f"{path} has {st.st_nlink} hard links; other links keep the old bytes")
            os.replace(tmp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
            tmp = None
            os.fsync(dirfd)
            self.s["values"] += replaced
            self.s["files_with_hits"] += 1
            self.s["rewritten"] += 1
        finally:
            os.close(tfd)
            if tmp is not None:
                try:
                    os.unlink(tmp, dir_fd=dirfd)
                except OSError:
                    pass


def _resolve_tops(paths, err):
    """Validate every PATH before anything is touched. Returns [(kind, path, stripped)] or None."""
    tops, bad = [], False
    for p in paths:
        stripped = p.rstrip("/") or "/"
        try:
            st1 = os.lstat(p)
            st2 = os.lstat(stripped)
        except OSError as e:
            print(f"redact_exports: error: {p}: {e.strerror}", file=err)
            bad = True
            continue
        if stat.S_ISLNK(st1.st_mode) or stat.S_ISLNK(st2.st_mode):
            print(f"redact_exports: error: {p}: refusing a symlinked PATH; pass the real path",
                  file=err)
            bad = True
            continue
        if stat.S_ISDIR(st2.st_mode):
            tops.append(("dir", p, stripped, st2))
        elif stat.S_ISREG(st2.st_mode):
            tops.append(("file", p, stripped, st2))
        else:
            print(f"redact_exports: error: {p}: not a regular file or directory", file=err)
            bad = True
    return None if bad else tops


def run(argv=None, out=sys.stdout, err=sys.stderr):
    ap = argparse.ArgumentParser(description="Redact sensitive query-parameter values in exports.")
    ap.add_argument("paths", nargs="+", metavar="PATH")
    ap.add_argument("--check", action="store_true",
                    help="report only; exit 1 if anything is unredacted or unscanned")
    ap.add_argument("--extra-params", help="comma-separated parameter names added to the list")
    ap.add_argument("--fix-perms", action="store_true",
                    help="files 600, directories 700, applied before scanning")
    ap.add_argument("--config", help="config file (adds redaction.extra_params)")
    a = ap.parse_args(argv)

    params = list(DEFAULT_PARAMS)  # only ever extended, never replaced
    if a.extra_params:
        params += a.extra_params.split(",")
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import audit_config  # noqa: E402 - sibling module
        params += list(audit_config.load_config(a.config)["redaction"]["extra_params"])
    except Exception as e:  # noqa: BLE001 - a broken config is a usage error, never ignored
        print(f"redact_exports: config error: {e}", file=err)
        return 2
    try:
        pattern = build_pattern(params)
    except ValueError as e:
        print(f"redact_exports: {e}", file=err)
        return 2

    tops = _resolve_tops(a.paths, err)
    if tops is None:
        return 2
    r = Run(pattern, a.check, a.fix_perms, out, err)

    def each_top(fn_dir, fn_file):
        for kind, p, stripped, st in tops:
            try:
                if kind == "dir":
                    fd = os.open(stripped, O_DIR)
                    try:
                        if not os.path.samestat(os.fstat(fd), st):
                            r.errors.append(f"{p}: changed before it could be opened")
                            continue
                        fn_dir(fd, stripped)
                    finally:
                        os.close(fd)
                else:
                    parent = os.path.dirname(stripped) or "."
                    pfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        fn_file(pfd, os.path.basename(stripped), stripped)
                    finally:
                        os.close(pfd)
            except OSError as e:
                r.errors.append(f"{p}: {e.strerror or e}")

    if a.fix_perms:
        def perm_dir(fd, path):
            r._fchmod(fd, 0o700, path)
            r.perms_pass(fd, path)
        each_top(perm_dir, r._perm_file)
    each_top(r.scan_dir, r.scan_file)

    s = r.s
    verb = "unredacted values found" if a.check else "values redacted"
    print(f"redact_exports: {s['files']} text files scanned ({s['decoded']} UTF-16/32), "
          f"{s['binary']} binary skipped, {s['unscanned']} UNSCANNED; {s['values']} {verb} in "
          f"{s['files_with_hits']} files"
          + ("" if a.check else f"; {s['rewritten']} files rewritten")
          + (f"; {r.binary_hits} values inside binary files (not rewritten)" if r.binary_hits else "")
          + (f"; {s['leftover_tmp']} leftover temp files scanned" if s["leftover_tmp"] else "")
          + (f"; {s['perms_fixed']} permissions fixed" if a.fix_perms else ""), file=err)
    for e in r.errors:
        print(f"redact_exports: error: {e}", file=err)
    if r.errors:
        return 2
    if s["unscanned"] or r.binary_hits or (a.check and s["values"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
