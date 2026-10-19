"""run_manifest hardening: run root mode, no-follow reads, portable process listing."""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import run_manifest as r


class Env:
    def __init__(self, home):
        self.home = home


class RootMode(unittest.TestCase):
    def run_check(self, mode):
        home = tempfile.mkdtemp()
        root = os.path.join(home, "site-audit")
        os.mkdir(root)
        os.chmod(root, mode)
        m = r.Manifest()
        r.check_run_dir(os.path.join(root, "run-abcd1234"), Env(home), m)
        return m.items[-1]

    def test_wide_root_refused(self):
        item = self.run_check(0o777)
        self.assertNotEqual(item["status"], "ok")
        self.assertIn("0o700", item["detail"])

    def test_private_root_ok(self):
        self.assertEqual(self.run_check(0o700)["status"], "ok")


class NoFollow(unittest.TestCase):
    def test_symlink_read_refused(self):
        d = tempfile.mkdtemp()
        target = os.path.join(d, "outside.md")
        with open(target, "w") as f:
            f.write("## Review record\n| a |\n")
        link = os.path.join(d, "site-audit-2030-03-08.md")
        os.symlink(target, link)
        self.assertFalse(r.has_review_record(link))
        with self.assertRaises(OSError):
            r._open_nofollow_text(link)


class PortableProcessListing(unittest.TestCase):
    """Screaming Frog is found in `ps -ax -o args=` output on macOS and Linux alike."""

    def test_filters_screaming_frog_lines(self):
        out = ("/sbin/launchd\n"
               "/usr/bin/java -Xmx2g -jar unrelated.jar\n"
               "/Applications/Screaming Frog SEO Spider.app/Contents/MacOS/jre/bin/java -Xmx8g -jar s\n"
               "/usr/share/screamingfrogseospider/jre/bin/java -Xmx4g -jar s\n")
        lines = r.screaming_frog_processes(out)
        self.assertEqual(len(lines), 2)
        self.assertFalse([ln for ln in lines if "unrelated" in ln])

    def test_nothing_running(self):
        self.assertEqual(r.screaming_frog_processes("/sbin/launchd\nbash\n"), [])
        self.assertEqual(r.screaming_frog_processes(""), [])

    def test_no_pgrep_in_source(self):
        with open(r.__file__) as f:
            self.assertNotIn('"pgrep"', f.read())


if __name__ == "__main__":
    unittest.main()
