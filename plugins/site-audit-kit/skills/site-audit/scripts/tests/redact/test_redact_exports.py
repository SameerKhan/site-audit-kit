"""Tests for redact_exports.py. Run: python3 -m unittest discover -s skills/site-audit/scripts/tests/redact"""
import csv
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, SCRIPTS)
sys.path.insert(0, os.path.dirname(HERE))
import testcfg  # noqa: E402
testcfg.use_config()
import redact_exports as rx  # noqa: E402

SECRET = "s3cr3tVALUE9"
PAT = rx.build_pattern(rx.DEFAULT_PARAMS)


def red(text):
    return rx.redact_line(text.encode(), PAT)[0].decode()


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    rc = rx.run(list(args), out=out, err=err)
    return rc, out.getvalue(), err.getvalue()


class LineTests(unittest.TestCase):
    def test_plain_query(self):
        self.assertEqual(red(f"https://x.com/r?token={SECRET}&lang=en"),
                         "https://x.com/r?token=REDACTED&lang=en")

    def test_keeps_key_case_and_other_params(self):
        self.assertEqual(red(f"/a?Lang=en&ACCESS_TOKEN={SECRET}#top"),
                         "/a?Lang=en&ACCESS_TOKEN=REDACTED#top")

    def test_every_default_key(self):
        for k in rx.DEFAULT_PARAMS:
            with self.subTest(k=k):
                self.assertEqual(red(f"/p?x=1&{k}={SECRET}"), f"/p?x=1&{k}=REDACTED")

    def test_lookalike_keys_untouched(self):
        s = f"/p?keyword={SECRET}&ref=a&sessions=2&tokens=3&zip_code=4&statement=5"
        self.assertEqual(red(s), s)

    def test_fragment_and_semicolon(self):
        self.assertEqual(red(f"/cb#access_token={SECRET}&x=1"), "/cb#access_token=REDACTED&x=1")
        # jsessionid is a sensitive name.
        self.assertEqual(red(f"/a;jsessionid=1;sid={SECRET}"), "/a;jsessionid=REDACTED;sid=REDACTED")
        self.assertEqual(red(f"/a;lang=1;sid={SECRET}"), "/a;lang=1;sid=REDACTED")

    def test_html_entities(self):
        self.assertEqual(red(f'<a href="/r?a=1&amp;token={SECRET}&amp;b=2">'),
                         '<a href="/r?a=1&amp;token=REDACTED&amp;b=2">')
        self.assertEqual(red(f"/r?a=1&#38;code={SECRET}"), "/r?a=1&#38;code=REDACTED")
        self.assertEqual(red(f"/r?a=1&#x26;state={SECRET}"), "/r?a=1&#x26;state=REDACTED")

    def test_percent_encoded(self):
        s = f"/login?next=https%3A%2F%2Fa.com%2Freset%3Ftoken%3D{SECRET}%26lang%3Den"
        self.assertEqual(red(s), "/login?next=https%3A%2F%2Fa.com%2Freset%3Ftoken%3DREDACTED%26lang%3Den")

    def test_percent_encoded_lowercase_and_ampersand(self):
        self.assertEqual(red(f"/l?u=%2fx%3fa%3d1%26email%3d{SECRET}%26b%3d2"),
                         "/l?u=%2fx%3fa%3d1%26email%3dREDACTED%26b%3d2")

    def test_double_encoded(self):
        s = f"/l?u=%253Ftoken%253D{SECRET}%2526x%253D1"
        self.assertEqual(red(s), "/l?u=%253Ftoken%253DREDACTED%2526x%253D1")

    def test_json_unicode_escapes(self):
        s = '{"u":"https://a.com/r?a=1\\u0026token=' + SECRET + '\\u0026b=2"}'
        self.assertEqual(red(s), '{"u":"https://a.com/r?a=1\\u0026token=REDACTED\\u0026b=2"}')

    def test_json_escaped_slash_inside_value(self):
        s = '{"u":"/r?sig=ab\\/' + SECRET + '"}'
        self.assertEqual(red(s), '{"u":"/r?sig=REDACTED"}')

    def test_plain_value_keeps_encoded_ampersand_inside(self):
        self.assertEqual(red(f"/r?token=ab%26{SECRET}&x=1"), "/r?token=REDACTED&x=1")

    def test_empty_value_left_alone(self):
        self.assertEqual(rx.redact_line(b"/r?token=&x=1", PAT), (b"/r?token=&x=1", 0))

    def test_multiple_in_one_line(self):
        line, n = rx.redact_line(f"/a?code={SECRET}&state={SECRET} /b?e={SECRET}".encode(), PAT)
        self.assertEqual(n, 3)
        self.assertNotIn(SECRET.encode(), line)

    def test_non_utf8_bytes_survive(self):
        line = b"\xff\xfe caf\xe9 /r?token=" + SECRET.encode() + b" \xff"
        new, n = rx.redact_line(line, PAT)
        self.assertEqual(n, 1)
        self.assertEqual(new, b"\xff\xfe caf\xe9 /r?token=REDACTED \xff")

    def test_custom_params(self):
        pat = rx.build_pattern(["foo"])
        self.assertEqual(rx.redact_line(b"/a?foo=1&token=2", pat)[0], b"/a?foo=REDACTED&token=2")

    def test_idempotent_line(self):
        once = red(f"/a?token={SECRET}%3Fcode%3D{SECRET}")
        self.assertEqual(red(once), once)
        self.assertEqual(rx.redact_line(once.encode(), PAT)[1], 0)


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.chmod(self.tmp, 0o755)

    def tearDown(self):
        subprocess.run(["rm", "-rf", self.tmp])

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

    def test_csv_quoting_preserved(self):
        rows = [["Address", "Inlinks", "Note"],
                [f"https://a.com/r?token={SECRET}&x=1", "3", 'say "hi", ok'],
                [f"https://a.com/b?a=1,2&email={SECRET}", "1", ""]]
        buf = io.StringIO()
        csv.writer(buf, quoting=csv.QUOTE_ALL).writerows(rows)
        buf2 = io.StringIO()
        csv.writer(buf2).writerows(rows)  # minimal quoting: URL fields unquoted
        for name, data in (("all.csv", buf.getvalue()), ("min.csv", buf2.getvalue())):
            with self.subTest(name=name):
                p = self.write(name, data)
                self.assertEqual(run_cli(p)[0], 0)
                got = list(csv.reader(io.StringIO(self.read(p).decode())))
                self.assertEqual(len(got), 3)
                self.assertEqual([len(r) for r in got], [3, 3, 3])
                self.assertEqual(got[1], ["https://a.com/r?token=REDACTED&x=1", "3", 'say "hi", ok'])
                self.assertEqual(got[2][0], "https://a.com/b?a=1,2&email=REDACTED")

    def test_ndjson_stays_valid(self):
        recs = [{"Address": f"https://a.com/x?code={SECRET}&state={SECRET}", "n": i} for i in range(50)]
        recs.append({"Address": "https://a.com/clean", "html": f'<a href="/r?a=1&amp;sig={SECRET}">'})
        p = self.write("internal_all.ndjson", "\n".join(json.dumps(r) for r in recs) + "\n")
        self.assertEqual(run_cli(p)[0], 0)
        lines = self.read(p).decode().splitlines()
        self.assertEqual(len(lines), 51)
        parsed = [json.loads(ln) for ln in lines]
        self.assertEqual(parsed[0]["Address"], "https://a.com/x?code=REDACTED&state=REDACTED")
        self.assertNotIn(SECRET, self.read(p).decode())

    def test_huge_line_streaming(self):
        filler = "a" * (8 * 1024 * 1024)
        line = f"{filler} /r?token={SECRET} {filler}\n"
        p = self.write("big.txt", line * 2 + "tail?pwd=" + SECRET)
        rc, out, err = run_cli(p)
        self.assertEqual(rc, 0)
        data = self.read(p)
        self.assertNotIn(SECRET.encode(), data)
        self.assertEqual(data.count(b"REDACTED"), 3)
        self.assertEqual(len(data), 2 * len(line) + len("tail?pwd=REDACTED")
                         - 2 * (len(SECRET) - len("REDACTED")))

    def test_idempotent_file(self):
        p = self.write("a.log", f"GET /r?token={SECRET}\n")
        run_cli(p)
        first = self.read(p)
        ino = os.stat(p).st_ino
        rc, out, err = run_cli(p)
        self.assertEqual(rc, 0)
        self.assertEqual(self.read(p), first)
        self.assertEqual(os.stat(p).st_ino, ino, "a clean file must not be rewritten")
        self.assertIn("0 files rewritten", err)

    def test_check_exit_codes_and_no_values_printed(self):
        p = self.write("d/x.md", f"line1\nsee https://a.com/?reset_token={SECRET}\n")
        rc, out, err = run_cli("--check", self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn(f"{p}:2: reset_token", out)
        self.assertNotIn(SECRET, out + err)
        self.assertIn(SECRET.encode(), self.read(p), "--check must not modify")
        rc, out, err = run_cli(self.tmp)
        self.assertEqual(rc, 0)
        self.assertNotIn(SECRET, out + err)
        rc, out, err = run_cli("--check", self.tmp)
        self.assertEqual((rc, out), (0, ""))

    def test_binary_skipped(self):
        # Fail closed: a known-binary file is never rewritten, but a plain
        # value visible in its bytes fails --check and redaction mode.
        p = self.write("img.png", b"\x89PNG\x00\x00?token=" + SECRET.encode())
        rc, out, err = run_cli("--check", p)
        self.assertEqual(rc, 1)
        self.assertIn("1 binary skipped", err)
        self.assertIn(f"{p}: token (binary file, not rewritten)", out)
        self.assertEqual(run_cli(p)[0], 1)
        self.assertIn(SECRET.encode(), self.read(p))
        clean = self.write("ok.png", b"\x89PNG\x00\x00IHDR")
        self.assertEqual(run_cli("--check", clean)[0], 0)

    def test_permissions(self):
        p = self.write("sub/a.csv", f"/r?token={SECRET}\n", mode=0o644)
        clean = self.write("sub/b.txt", "nothing\n", mode=0o664)
        os.chmod(os.path.join(self.tmp, "sub"), 0o755)
        run_cli(p)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600, "rewritten files are 600")
        self.assertEqual(stat.S_IMODE(os.stat(clean).st_mode), 0o664)
        rc, _, err = run_cli("--fix-perms", self.tmp)
        self.assertEqual(rc, 0)
        self.assertEqual(stat.S_IMODE(os.stat(clean).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.tmp).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.tmp, "sub")).st_mode), 0o700)

    def test_no_temp_files_left_and_symlink_not_followed(self):
        outside = tempfile.mkdtemp()
        try:
            target = os.path.join(outside, "t.txt")
            with open(target, "w") as f:
                f.write(f"/r?token={SECRET}\n")
            os.symlink(target, os.path.join(self.tmp, "link.txt"))
            self.write("x.txt", f"/r?token={SECRET}\n")
            run_cli(self.tmp)
            with open(target) as f:
                self.assertIn(SECRET, f.read())
            self.assertEqual(sorted(os.listdir(self.tmp)), ["link.txt", "x.txt"])
        finally:
            subprocess.run(["rm", "-rf", outside])

    def test_missing_path_is_error(self):
        rc, _, err = run_cli(os.path.join(self.tmp, "nope"))
        self.assertEqual(rc, 2)

    def test_script_entrypoint(self):
        p = self.write("e.txt", f"/r?token={SECRET}\n")
        r = subprocess.run([sys.executable, os.path.join(SCRIPTS, "redact_exports.py"), "--check", p],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(SECRET, r.stdout + r.stderr)


class ConfigExtraParams(unittest.TestCase):
    """redaction.extra_params from the config extends the list; a broken config is exit 2."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.p = os.path.join(self.tmp, "export.csv")
        with open(self.p, "w") as f:
            f.write(f"url\nhttps://www.example.com/a?member_ref={SECRET}&lang=en\n")

    def tearDown(self):
        subprocess.run(["rm", "-rf", self.tmp])

    def test_extra_param_from_config_is_redacted(self):
        self.assertEqual(run_cli("--check", self.p)[0], 0)  # not sensitive by default
        cfg = testcfg.write_config(testcfg.merged(redaction={"extra_params": ["member_ref"]}))
        self.assertEqual(run_cli("--check", "--config", cfg, self.p)[0], 1)
        self.assertEqual(run_cli("--config", cfg, self.p)[0], 0)
        with open(self.p) as f:
            self.assertNotIn(SECRET, f.read())
        self.assertEqual(run_cli("--check", "--config", cfg, self.p)[0], 0)

    def test_missing_explicit_config_is_usage_error(self):
        rc, _out, err = run_cli("--check", "--config", os.path.join(self.tmp, "nope.json"), self.p)
        self.assertEqual(rc, 2)
        self.assertIn("config", err)


if __name__ == "__main__":
    unittest.main()
