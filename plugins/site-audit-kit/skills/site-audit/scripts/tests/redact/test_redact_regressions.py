"""Regression tests for redact_exports.py: binary detection, encodings, structured files,
sensitive parameter names and check mode.
Run: python3 -m unittest discover -s skills/site-audit/scripts/tests/redact
"""
import csv
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, SCRIPTS)
sys.path.insert(0, os.path.dirname(HERE))
import testcfg  # noqa: E402
testcfg.use_config()
import redact_exports as rx  # noqa: E402

SECRET = "s3cr3tVALUE9"
PAT = rx.build_pattern(rx.DEFAULT_PARAMS)


def red(text, kind="text"):
    return rx.redact_line(text.encode(), PAT, kind)[0].decode()


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    rc = rx.run(list(args), out=out, err=err)
    return rc, out.getvalue(), err.getvalue()


class TmpDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.chmod(self.tmp, 0o755)

    def tearDown(self):
        for root, dirs, files in os.walk(self.tmp):
            for d in dirs:
                try:
                    os.chmod(os.path.join(root, d), 0o700, follow_symlinks=False)
                except OSError:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, data, mode=0o644):
        p = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        os.chmod(p, mode)
        return p

    def read(self, p):
        with open(p, "rb") as f:
            return f.read()

    def assert_gone(self, p, secret=SECRET, enc="utf-8"):
        self.assertNotIn(secret.encode(enc), self.read(p))


# ---------------------------------------------------------------- 1. "binary" skipping

class EncodingAndBinary(TmpDir):
    URL = f"https://x/r?token={SECRET}&a=1\n"

    def test_utf16_with_bom_is_decoded_and_redacted(self):
        for codec, name in (("utf-16", "bom16.csv"), ("utf-32", "bom32.csv")):
            with self.subTest(codec=codec):
                p = self.write(name, self.URL.encode(codec))
                rc, out, _ = run_cli("--check", p)
                self.assertEqual(rc, 1)
                self.assertIn(f"{p}:1: token", out)
                self.assertEqual(run_cli(p)[0], 0)
                data = self.read(p)
                self.assertEqual(data, self.URL.replace(SECRET, "REDACTED").encode(codec))
                self.assertEqual(run_cli("--check", p)[0], 0)

    def test_utf16_32_without_bom_by_nul_pattern(self):
        for codec in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
            with self.subTest(codec=codec):
                p = self.write(f"{codec}.csv", (self.URL * 3).encode(codec))
                self.assertEqual(run_cli("--check", p)[0], 1)
                self.assertEqual(run_cli(p)[0], 0)
                self.assertEqual(self.read(p),
                                 (self.URL * 3).replace(SECRET, "REDACTED").encode(codec))

    def test_nul_in_ascii_file_is_unscanned_and_fails_both_modes(self):
        p = self.write("nul_early.csv", b"a\x00b\nhttps://x/r?token=" + SECRET.encode() + b"\n")
        before = self.read(p)
        rc, out, _ = run_cli("--check", p)
        self.assertEqual(rc, 1)
        self.assertIn(f"UNSCANNED: {p}", out)
        self.assertNotIn(SECRET, out)
        rc, out, _ = run_cli(p)
        self.assertEqual(rc, 1, "redaction mode must not report success over an unscanned file")
        self.assertEqual(self.read(p), before, "never rewrite a file that could not be decoded")

    def test_nul_after_sniff_window_is_unscanned(self):
        p = self.write("late.ndjson", b"A" * 70000 + b"\n/r?token=" + SECRET.encode()
                       + b"\x00keep_me\n")
        before = self.read(p)
        self.assertEqual(run_cli("--check", p)[0], 1)
        self.assertEqual(run_cli(p)[0], 1)
        self.assertEqual(self.read(p), before)

    def test_nul_stops_a_value_scan(self):
        line = b"/r?token=" + SECRET.encode() + b"\x00keep_me"
        self.assertEqual(rx.redact_line(line, PAT)[0], b"/r?token=REDACTED\x00keep_me")

    def test_known_binary_extension_listed_and_never_rewritten(self):
        clean = self.write("img.png", b"\x89PNG\r\n\x1a\n\x00\x00IHDR")
        rc, out, err = run_cli("--check", clean)
        self.assertEqual(rc, 0)
        self.assertIn(f"skipped-binary (never rewritten, byte-scanned): {clean}", err)
        self.assertIn("1 binary skipped", err)

    def test_known_binary_holding_a_plain_value_fails(self):
        p = self.write("crawl.seospider", b"SQLite format 3\x00..https://x/r?token="
                       + SECRET.encode() + b"&a=1\x00")
        before = self.read(p)
        rc, out, _ = run_cli("--check", p)
        self.assertEqual(rc, 1)
        self.assertIn("token (binary file, not rewritten)", out)
        self.assertEqual(run_cli(p)[0], 1)
        self.assertEqual(self.read(p), before)

    def test_unknown_binary_without_extension_match_is_unscanned(self):
        p = self.write("export.xlsx", b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + os.urandom(4000))
        rc, out, _ = run_cli("--check", p)
        self.assertEqual(rc, 1)
        self.assertIn(f"UNSCANNED: {p}", out)

    def test_pdf_without_nul_is_not_rewritten(self):
        # A structured binary with no early NUL used to be rewritten byte-for-byte.
        p = self.write("report.pdf", b"%PDF-1.4\n<< /URI (https://x/r?token=" + SECRET.encode()
                       + b") >>\n")
        before = self.read(p)
        self.assertEqual(run_cli(p)[0], 1)
        self.assertEqual(self.read(p), before)

    def test_control_bytes_file_is_unscanned(self):
        p = self.write("odd.dat", b"\x01\x02\x03 /r?token=" + SECRET.encode() + b"\n")
        rc, out, _ = run_cli("--check", p)
        self.assertEqual(rc, 1)
        self.assertIn("UNSCANNED", out)

    def test_cp1252_text_is_still_scanned(self):
        p = self.write("latin.csv", b"caf\xe9,https://x/r?token=" + SECRET.encode() + b"\n")
        self.assertEqual(run_cli(p)[0], 0)
        self.assertEqual(self.read(p), b"caf\xe9,https://x/r?token=REDACTED\n")

    def test_ascii_hidden_inside_utf16_file_fails(self):
        p = self.write("mixed.csv", "abc\n".encode("utf-16") * 50 + b"?token=" + SECRET.encode())
        rc, out, _ = run_cli("--check", p)
        self.assertEqual(rc, 1)


# ---------------------------------------------------------------- 2. value boundaries

class Boundaries(unittest.TestCase):
    def test_json_unicode_escape_at_value_start_and_inside(self):
        s = '{"url":"https://x/reset?token=\\u0061bc123secret&email=alice\\u0040example.com"}'
        self.assertEqual(red(s, "json"), '{"url":"https://x/reset?token=REDACTED&email=REDACTED"}')

    def test_escaped_stop_char_still_ends_value(self):
        s = '{"u":"/r?token=' + SECRET + '\\u0026x=1\\u0022"}'
        self.assertEqual(red(s, "json"), '{"u":"/r?token=REDACTED\\u0026x=1\\u0022"}')

    def test_brackets_braces_parens_pipe(self):
        s = ('https://x/cb?state={"csrf":"secret123"}&token=1|sanctum_secret_abc123'
             '&password=(Pass123)&x=[a]&lang=en')
        self.assertEqual(red(s), "https://x/cb?state=REDACTED&token=REDACTED&password=REDACTED"
                                 "&x=[a]&lang=en")

    def test_bracket_inside_value(self):
        self.assertEqual(red(f"/r?token=ab[{SECRET}]cd&k=1"), "/r?token=REDACTED&k=1")
        self.assertEqual(red(f"/r?sig=a)b}}{SECRET}&k=1"), "/r?sig=REDACTED&k=1")

    def test_bracket_does_not_cross_json_string_end(self):
        s = '{"u":"/r?state={abc","v":"}"}'
        self.assertEqual(red(s, "json"), '{"u":"/r?state=REDACTED","v":"}"}')

    def test_double_encoded_inside_single_encoded_value(self):
        s = ("https://x/login?next=https%3A%2F%2Fx%2Fcb%3Fpassword%3D%2523Secret123"
             "%26token%3Dp%2526sswordSecret&password%3D%26PlainSecret")
        got = red(s)
        for frag in ("Secret123", "sswordSecret", "PlainSecret"):
            self.assertNotIn(frag, got)
        self.assertEqual(got, "https://x/login?next=https%3A%2F%2Fx%2Fcb%3Fpassword%3DREDACTED"
                              "%26token%3DREDACTED&password%3DREDACTED")

    def test_encoded_value_keeps_sibling_encoded_params(self):
        s = f"/l?next=%2Fcb%3Ftoken%3D{SECRET}%26page%3D2%22x"
        self.assertEqual(red(s), "/l?next=%2Fcb%3Ftoken%3DREDACTED%26page%3D2%22x")

    def test_matrix_param_stops_at_path_query_and_equals(self):
        s = f"https://x/app;sid={SECRET}/reset?lang=en&url=https://y/cb"
        self.assertEqual(red(s), "https://x/app;sid=REDACTED/reset?lang=en&url=https://y/cb")
        self.assertEqual(red(f"/a;jsessionid={SECRET}?x=1"), "/a;jsessionid=REDACTED?x=1")
        self.assertEqual(red(f"/a%3Bsid%3D{SECRET}%2Fb"), "/a%3Bsid%3DREDACTED%2Fb")

    def test_plain_value_keeps_percent_sequences(self):
        # An encoded separator is not a separator: in ?token=a%26b the %26 is part of the value.
        self.assertEqual(red(f"/r?token={SECRET}%26page%3D2&x=1"), "/r?token=REDACTED&x=1")

    def test_comma_in_value_json_and_quoted_csv(self):
        self.assertEqual(red('{"u":"/r?token=abc,' + SECRET + '"}', "json"),
                         '{"u":"/r?token=REDACTED"}')
        self.assertEqual(red(f'"https://x/r?token=abc,{SECRET}",3\n', "csv"),
                         '"https://x/r?token=REDACTED",3\n')
        # The same input, in a plain-text / unknown-extension file: no tail survives.
        self.assertEqual(red(f"see ?token=abc,{SECRET} now"), "see ?token=REDACTED now")
        self.assertEqual(red(f"https://x/r?token=abc,{SECRET}\tnext", "csv"),
                         "https://x/r?token=REDACTED,SECRET\tnext".replace("SECRET", SECRET))

    def test_tsv_comma_is_part_of_value(self):
        sc = rx.Scanner(PAT, "csv", b"\t")
        line = f"https://x/r?token=abc,{SECRET}\t200\n".encode()
        self.assertEqual(rx._apply(line, sc.spans(line))[0], b"https://x/r?token=REDACTED\t200\n")

    def test_csv_unquoted_fields_never_merge(self):
        rows = [["Address", "Status", "Note"],
                [f"https://x/r?token={SECRET}&a=1", "200", "ok"],
                [f"https://x/r?state={{{SECRET}}}", "301", "a,b"],
                [f"https://x/r?code=({SECRET})", "404", ""],
                [f"https://x/r?e=alï{SECRET}", "200", "x"]]
        for quoting in (csv.QUOTE_MINIMAL, csv.QUOTE_ALL):
            with self.subTest(quoting=quoting):
                buf = io.StringIO()
                csv.writer(buf, quoting=quoting).writerows(rows)
                lines = buf.getvalue().encode().splitlines(keepends=True)
                sc = rx.Scanner(PAT, "csv")
                new = b"".join(rx._apply(ln, sc.spans(ln))[0] for ln in lines).decode()
                self.assertNotIn(SECRET, new)
                got = list(csv.reader(io.StringIO(new)))
                self.assertEqual([len(r) for r in got], [3] * 5)
                self.assertEqual([r[1] for r in got[1:]], ["200", "301", "404", "200"])
                self.assertEqual(got[2][2], "a,b")
                self.assertEqual(got[1][0], "https://x/r?token=REDACTED&a=1")

    def test_quoted_value(self):
        self.assertEqual(red(f'https://x/r?token="{SECRET}"'), 'https://x/r?token="REDACTED"')
        self.assertEqual(red('{"q":"x?token=\\"' + SECRET + '\\""}', "json"),
                         '{"q":"x?token=\\"REDACTED\\""}')

    def test_quote_after_key_is_not_a_quoted_value_in_json(self):
        s = '{"a":"/r?token=","b":"' + SECRET + '"}'
        self.assertEqual(red(s, "json"), s)


# ---------------------------------------------------------------- 3. delimiters and encodings

class Delimiters(unittest.TestCase):
    def test_encoded_and_escaped_semicolon_before_key(self):
        for s, want in (
                (f"/l?next=https%3A%2F%2Fx%2Fapp%3Bsid%3D{SECRET}&o=1",
                 "/l?next=https%3A%2F%2Fx%2Fapp%3Bsid%3DREDACTED&o=1"),
                (f"/l?n=%2Fa%253Bsid%253D{SECRET}%2526b", "/l?n=%2Fa%253Bsid%253DREDACTED%2526b"),
                (f'{{"o":"x\\u003btoken={SECRET}"}}', '{"o":"x\\u003btoken=REDACTED"}'),
                (f"/a;token={SECRET};b=1", "/a;token=REDACTED;b=1")):
            with self.subTest(s=s):
                self.assertEqual(red(s), want)

    def test_double_escaped_json(self):
        s = '{"body":"{\\"url\\":\\"https://x/reset?token\\\\u003d' + SECRET + '\\"}"}'
        self.assertEqual(red(s, "json"),
                         '{"body":"{\\"url\\":\\"https://x/reset?token\\\\u003dREDACTED\\"}"}')
        s2 = '{"b":"/r?a=1\\\\u0026code\\\\u003d' + SECRET + '\\\\u0026x=1"}'
        self.assertEqual(red(s2, "json"), '{"b":"/r?a=1\\\\u0026code\\\\u003dREDACTED\\\\u0026x=1"}')

    def test_array_suffix_and_encoded_key_names(self):
        for s, want in (
                (f"/r?token[]={SECRET}", "/r?token[]=REDACTED"),
                (f"/r?token[0]={SECRET}&x=1", "/r?token[0]=REDACTED&x=1"),
                (f"/r?email%5B%5D={SECRET}", "/r?email%5B%5D=REDACTED"),
                (f"/r?%74oken={SECRET}", "/r?%74oken=REDACTED"),
                (f"/r?%54OKEN={SECRET}", "/r?%54OKEN=REDACTED"),
                (f"/r?to%6Ben={SECRET}", "/r?to%6Ben=REDACTED"),
                (f"/r?token+={SECRET}", "/r?token+=REDACTED"),
                (f"/l?u=%3F%2574oken%3D{SECRET}", "/l?u=%3F%2574oken%3DREDACTED")):
            with self.subTest(s=s):
                self.assertEqual(red(s), want)

    def test_html_named_entities(self):
        self.assertEqual(red(f'<a href="/r?a=1&amp;token&equals;{SECRET}">'),
                         '<a href="/r?a=1&amp;token&equals;REDACTED">')
        self.assertEqual(red(f"/r&quest;token={SECRET}&amp;x"), "/r&quest;token=REDACTED&amp;x")
        self.assertEqual(red(f"/r&#63;code={SECRET}&#38;x"), "/r&#63;code=REDACTED&#38;x")

    def test_key_at_start_of_value(self):
        for s, want in (
                (f"token={SECRET}&a=1", "token=REDACTED&a=1"),
                (f"https://x/r,token={SECRET} 3", "https://x/r,token=REDACTED 3"),
                (f'"token={SECRET}"', '"token=REDACTED"'),
                (f"https://x/reset/token={SECRET}", "https://x/reset/token=REDACTED")):
            with self.subTest(s=s):
                self.assertEqual(red(s), want)

    def test_multiline_quoted_csv_cell(self):
        lines = [b'"https://x/r?token=\n', SECRET.encode() + b'",1\n', b"https://x/clean,2\n"]
        sc = rx.Scanner(PAT, "csv")
        new = [rx._apply(ln, sc.spans(ln))[0] for ln in lines]
        self.assertEqual(new, [b'"https://x/r?token=\n', b'REDACTED",1\n', b"https://x/clean,2\n"])
        sc = rx.Scanner(PAT, "csv")
        lines = [b'"https://x/r?token=ab\n', SECRET.encode() + b'&x=1",1\n']
        new = [rx._apply(ln, sc.spans(ln))[0] for ln in lines]
        self.assertEqual(new, [b'"https://x/r?token=REDACTED\n', b'REDACTED&x=1",1\n'])

    def test_unquoted_csv_line_end_does_not_carry(self):
        lines = [b"https://x/r?token=" + SECRET.encode() + b"\n", b"https://x/next,2\n"]
        sc = rx.Scanner(PAT, "csv")
        new = [rx._apply(ln, sc.spans(ln))[0] for ln in lines]
        self.assertEqual(new, [b"https://x/r?token=REDACTED\n", b"https://x/next,2\n"])


# ---------------------------------------------------------------- 4. names

class Names(unittest.TestCase):
    NEW = ("jwt", "ticket", "verification", "verify", "hash", "auth_token", "access_key",
           "secret_key", "private_key", "credential", "credentials", "apikey", "api_key",
           "api-key", "x-api-key", "x-amz-signature", "x-amz-credential", "x-goog-signature",
           "sig", "signature", "magic", "magic_link", "invite", "invitation", "confirmation",
           "confirm", "reset", "recovery", "oauth_token", "oauth_verifier", "code_verifier",
           "assertion", "saml", "samlresponse")

    def test_new_names(self):
        for k in self.NEW:
            with self.subTest(k=k):
                self.assertEqual(red(f"/p?x=1&{k}={SECRET}"), f"/p?x=1&{k}=REDACTED")
                self.assertEqual(red(f"/p?{k.upper()}={SECRET}"), f"/p?{k.upper()}=REDACTED")

    def test_lookalikes_still_untouched(self):
        s = "/p?keyword=1&hashtag=2&resetting=3&my-token=4&zip_code=5&email_opt=6&designer=7"
        self.assertEqual(red(s), s)

    def test_params_and_extra_params(self):
        pat = rx.build_pattern(["foo"])
        self.assertEqual(rx.redact_line(b"/a?foo=1&token=2", pat)[0], b"/a?foo=REDACTED&token=2")
        rc, _, _ = run_cli("--extra-params", "bad name", "/nonexistent")
        self.assertEqual(rc, 2)

    def test_no_option_replaces_the_built_in_list(self):
        # --params (which replaced the list) is gone: argparse refuses it as a usage error
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as cm:
            run_cli("--params", "foo", "/nonexistent")
        self.assertEqual(cm.exception.code, 2)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "x.csv")
        with open(p, "w") as f:
            f.write(f"/a?foo=1&token={SECRET}\n")
        rc, _, _ = run_cli("--check", "--extra-params", "foo", p)
        self.assertEqual(rc, 1)
        self.assertEqual(run_cli("--extra-params", "foo", p)[0], 0)
        with open(p) as f:
            self.assertEqual(f.read(), "/a?foo=REDACTED&token=REDACTED\n")


# ---------------------------------------------------------------- 5-7. filesystem

class FileSystem(TmpDir):
    def test_top_level_symlink_refused_both_modes(self):
        real = os.path.join(self.tmp, "real")
        self.write("real/a.csv", f"/r?token={SECRET}\n")
        link = os.path.join(self.tmp, "link")
        os.symlink(real, link)
        for args in (["--check", link], [link], [link + "/"], ["--check", link + "/"],
                     ["--fix-perms", link + "/"]):
            with self.subTest(args=args):
                rc, out, err = run_cli(*args)
                self.assertEqual(rc, 2)
                self.assertIn("refusing a symlinked PATH", err)
        self.assertIn(SECRET.encode(), self.read(os.path.join(real, "a.csv")))
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(real, "a.csv")).st_mode), 0o644)

    def test_symlink_refused_before_anything_is_touched(self):
        good = self.write("good/a.csv", f"/r?token={SECRET}\n")
        os.symlink(os.path.join(self.tmp, "good"), os.path.join(self.tmp, "l"))
        rc, _, _ = run_cli(os.path.join(self.tmp, "good"), os.path.join(self.tmp, "l"))
        self.assertEqual(rc, 2)
        self.assertIn(SECRET.encode(), self.read(good))

    def test_inner_symlinks_are_unscanned_not_followed(self):
        outside = tempfile.mkdtemp()
        try:
            target = os.path.join(outside, "t.txt")
            with open(target, "w") as f:
                f.write(f"/r?token={SECRET}\n")
            os.chmod(target, 0o644)
            os.chmod(outside, 0o755)
            os.symlink(target, os.path.join(self.tmp, "link.txt"))
            os.symlink(outside, os.path.join(self.tmp, "linkdir"))
            rc, out, _ = run_cli("--check", "--fix-perms", self.tmp)
            self.assertEqual(rc, 1)
            self.assertIn("UNSCANNED: " + os.path.join(self.tmp, "link.txt"), out)
            self.assertIn("UNSCANNED: " + os.path.join(self.tmp, "linkdir"), out)
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(os.stat(outside).st_mode), 0o755)
            rc, _, _ = run_cli(self.tmp)
            self.assertEqual(rc, 1)
            with open(target) as f:
                self.assertIn(SECRET, f.read())
        finally:
            shutil.rmtree(outside)

    def test_file_swapped_for_symlink_is_not_followed(self):
        # O_NOFOLLOW at open: simulate the swap between listing and open.
        outside = tempfile.mkdtemp()
        try:
            target = os.path.join(outside, "t.txt")
            with open(target, "w") as f:
                f.write(f"/r?token={SECRET}\n")
            self.write("a.csv", f"/r?token={SECRET}\n")
            r = rx.Run(PAT, False, True, io.StringIO(), io.StringIO())
            dfd = os.open(self.tmp, os.O_RDONLY)
            try:
                os.unlink(os.path.join(self.tmp, "a.csv"))
                os.symlink(target, os.path.join(self.tmp, "a.csv"))
                r.scan_file(dfd, "a.csv", os.path.join(self.tmp, "a.csv"))
                r._perm_file(dfd, "a.csv", os.path.join(self.tmp, "a.csv"))
            finally:
                os.close(dfd)
            self.assertEqual(r.s["unscanned"], 1)
            with open(target) as f:
                self.assertIn(SECRET, f.read())
            self.assertNotEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
        finally:
            shutil.rmtree(outside)

    def test_rewrite_is_mode_600_and_no_temp_left(self):
        p = self.write("a.csv", f"/r?token={SECRET}\n", mode=0o644)
        old = os.umask(0)
        try:
            self.assertEqual(run_cli(p)[0], 0)
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.assertEqual(os.listdir(self.tmp), ["a.csv"])

    def test_fix_perms_happens_before_scanning(self):
        a = self.write("d/a.csv", f"/r?token={SECRET}\n", mode=0o644)
        b = self.write("d/b.csv", "clean\n", mode=0o644)
        seen = []
        orig = rx.Run.scan_file

        def spy(self_, dirfd, name, path):
            seen.append({q: stat.S_IMODE(os.stat(q).st_mode) for q in (a, b)})
            return orig(self_, dirfd, name, path)

        rx.Run.scan_file = spy
        try:
            run_cli("--check", "--fix-perms", self.tmp)
        finally:
            rx.Run.scan_file = orig
        self.assertTrue(seen)
        self.assertEqual(seen[0], {a: 0o600, b: 0o600}, "every file 600 before the first scan")

    def test_fix_perms_reaches_unreadable_dirs_and_files(self):
        p = self.write("d/a.csv", f"/r?token={SECRET}\n", mode=0o000)
        os.chmod(os.path.join(self.tmp, "d"), 0o000)
        rc, out, err = run_cli("--fix-perms", self.tmp)
        self.assertEqual(rc, 0, err)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.tmp, "d")).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.assert_gone(p)

    def test_unreadable_without_fix_perms_is_an_error(self):
        self.write("a.csv", f"/r?token={SECRET}\n", mode=0o000)
        rc, out, err = run_cli("--check", self.tmp)
        self.assertEqual(rc, 2)

    def test_directory_fsync_after_replace(self):
        p = self.write("a.csv", f"/r?token={SECRET}\n")
        calls = []
        orig = os.fsync

        def spy(fd):
            calls.append(stat.S_ISDIR(os.fstat(fd).st_mode))
            return orig(fd)

        rx.os.fsync = spy
        try:
            run_cli(p)
        finally:
            rx.os.fsync = orig
        self.assertEqual(calls, [False, True])

    def test_leftover_temp_files_are_scanned(self):
        t = self.write(".redact-ab12cd34ef567890.tmp", f"https://x/reset?token={SECRET}\n")
        rc, out, err = run_cli("--check", self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn(f"{t}:1: token", out)
        self.assertIn("leftover temp file", err)
        self.assertEqual(run_cli(self.tmp)[0], 0)
        self.assert_gone(t)

    def test_fifo_is_unscanned_and_does_not_block(self):
        os.mkfifo(os.path.join(self.tmp, "pipe"))
        rc, out, _ = run_cli("--check", self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn("not a regular file", out)

    def test_hard_link_inside_tree_gets_new_inode(self):
        p = self.write("a.csv", f"/r?token={SECRET}\n")
        outside = tempfile.mkdtemp()
        try:
            o = os.path.join(outside, "o.csv")
            os.link(p, o)
            rc, _, err = run_cli(p)
            self.assertEqual(rc, 0)
            self.assertIn("hard links", err)
            self.assert_gone(p)
            self.assertNotEqual(os.stat(p).st_ino, os.stat(o).st_ino)
        finally:
            shutil.rmtree(outside)

    def test_values_never_printed(self):
        self.write("a.csv", f"/r?token={SECRET}\n")
        self.write("b.bin", b"\x00\x01?token=" + SECRET.encode())
        self.write("c.png", b"\x89PNG\x00?token=" + SECRET.encode())
        for args in (["--check", self.tmp], [self.tmp]):
            rc, out, err = run_cli(*args)
            self.assertNotIn(SECRET, out + err)

    def test_ndjson_end_to_end_stays_valid(self):
        recs = [{"Address": f"https://x/r?state={{\"csrf\":\"{SECRET}\"}}&e=a@b.c,{SECRET}",
                 "Title": "a, b"},
                {"Address": f"https://x/l?next=%2Fcb%3Ftoken%3D{SECRET}%26lang%3Den"}]
        p = self.write("internal_all.ndjson", "\n".join(json.dumps(r) for r in recs) + "\n")
        self.assertEqual(run_cli(p)[0], 0)
        got = [json.loads(ln) for ln in self.read(p).decode().splitlines()]
        self.assertEqual(got[0]["Address"], "https://x/r?state=REDACTED&e=REDACTED")
        self.assertEqual(got[0]["Title"], "a, b")
        self.assertEqual(got[1]["Address"], "https://x/l?next=%2Fcb%3Ftoken%3DREDACTED%26lang%3Den")
        self.assertEqual(run_cli("--check", p)[0], 0)

    def test_idempotent_over_all_forms(self):
        body = "\n".join([
            f"/r?token={SECRET}&state={{a:{SECRET}}}", f"/a;sid={SECRET}/x",
            f'"https://x/r?token=\n{SECRET}",1', f"/l?n=%3Fcode%3D{SECRET}%26a%3D1"]) + "\n"
        p = self.write("x.csv", body)
        self.assertEqual(run_cli(p)[0], 0)
        first = self.read(p)
        self.assertNotIn(SECRET.encode(), first)
        ino = os.stat(p).st_ino
        rc, _, err = run_cli(p)
        self.assertEqual((rc, self.read(p), os.stat(p).st_ino), (0, first, ino))

    def test_script_entrypoint_isolated(self):
        p = self.write("e.csv", f"/r?token={SECRET}\n".encode("utf-16"))
        r = subprocess.run([sys.executable, "-I", "-B", os.path.join(SCRIPTS, "redact_exports.py"),
                            "--check", p], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(SECRET, r.stdout + r.stderr)


# ---------------------------------------------------------------- seeded fuzz over all forms

class Fuzz(TmpDir):
    def test_seeded_forms_in_json_csv_text(self):
        import random
        from urllib.parse import quote
        rnd = random.Random(1234567)
        keys = [k for k in rx.DEFAULT_PARAMS if len(k) > 1]
        specials = "{}()[]|~!*$@"
        cases = []
        for i in range(400):
            core = "Zq" + "".join(rnd.choice("ABCDEFGHJKMNPQRSTUVWXYZ23456789") for _ in range(10))
            sec = core
            if rnd.random() < 0.5:
                j = rnd.randrange(len(sec))
                sec = sec[:j] + rnd.choice(specials) + sec[j:]
            key = rnd.choice(keys)
            form = rnd.choice(["plain", "frag", "matrix", "enc1", "enc2", "jsonesc", "html",
                               "start"])
            if form == "plain":
                url = f"https://x/r?a=1&{key}={sec}&b=2"
            elif form == "frag":
                url = f"https://x/r#{key}={sec}&b=2"
            elif form == "matrix":
                url = f"https://x/app;{key}={sec}/next?b=2"
            elif form == "enc1":
                url = f"https://x/l?next=%2Fcb%3F{key}%3D{quote(sec, safe='')}%26b%3D2&c=3"
            elif form == "enc2":
                url = (f"https://x/l?n=%252Fcb%253F{key}%253D{quote(quote(sec, safe=''), safe='')}"
                       f"%2526b%253D2")
            elif form == "jsonesc":
                url = f"https://x/r?a=1\\u0026{key}\\u003d{sec}\\u0026b=2"
            elif form == "html":
                url = f"https://x/r?a=1&amp;{key}={sec}&amp;b=2"
            else:
                url = f"{key}={sec}"
            if rnd.random() < 0.3:
                k = rnd.randrange(len(key))
                url = url.replace(key, key[:k] + f"%{ord(key[k]):02X}" + key[k + 1:], 1)
            cases.append((core, url))
        recs = [{"Address": u, "Title": "t, x", "n": i} for i, (_, u) in enumerate(cases)]
        pj = self.write("f.ndjson", "\n".join(json.dumps(r) for r in recs) + "\n")
        buf = io.StringIO()
        csv.writer(buf).writerows([[u, "200", "a,b"] for _, u in cases])
        pc = self.write("f.csv", buf.getvalue())
        pt = self.write("f.txt", "\n".join(f"seen {u} today" for _, u in cases) + "\n")
        rc, out, err = run_cli(self.tmp)
        self.assertEqual(rc, 0, err)
        for p in (pj, pc, pt):
            data = self.read(p).decode()
            left = [u for c, u in cases if c in data]
            self.assertEqual(left, [], f"{os.path.basename(p)}: {left[:3]}")
        got = [json.loads(ln) for ln in self.read(pj).decode().splitlines()]
        self.assertEqual([g["n"] for g in got], list(range(400)))
        self.assertTrue(all(g["Title"] == "t, x" for g in got))
        rows = list(csv.reader(io.StringIO(self.read(pc).decode())))
        self.assertEqual([len(r) for r in rows], [3] * 400)
        self.assertTrue(all(r[1:] == ["200", "a,b"] for r in rows))
        self.assertEqual(run_cli("--check", self.tmp)[0], 0)


if __name__ == "__main__":
    unittest.main()
