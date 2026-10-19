"""Regression tests for redact_exports.py: hard-linked files are never rewritten (both modes
exit 1, UNSCANNED), and the chmod path used where no no-follow chmod exists (Linux) never
follows a symlink swapped in mid-run: it works on an O_NOFOLLOW descriptor (O_PATH plus
/proc/self/fd on Linux) or fails closed with exit 2, never chmod by name.
"""
import io
import os
import shutil
import stat
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
HAVE_PROC_PATH = bool(getattr(os, "O_PATH", 0)) and os.path.isdir("/proc/self/fd")
ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
REAL_CHMOD = os.chmod  # saved before any test patches os.chmod


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    rc = rx.run(list(args), out=out, err=err)
    return rc, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.chmod(self.tmp, 0o755)
        self.outside = tempfile.mkdtemp()
        os.chmod(self.outside, 0o755)

    def tearDown(self):
        for top in (self.tmp, self.outside):
            for root, dirs, files in os.walk(top):
                for n in dirs + files:
                    p = os.path.join(root, n)
                    if not os.path.islink(p):
                        try:
                            REAL_CHMOD(p, 0o700)
                        except OSError:
                            pass
            shutil.rmtree(top, ignore_errors=True)

    def write(self, rel, data, mode=0o644, top=None):
        p = os.path.join(top or self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(data)
        os.chmod(p, mode)
        return p

    def read(self, p):
        with open(p) as f:
            return f.read()

    def mode(self, p):
        return stat.S_IMODE(os.stat(p).st_mode)


class HardLinks(Base):
    def test_hard_linked_file_never_rewritten_both_modes(self):
        p = self.write("a.csv", f"/r?token={SECRET}\n")
        o = os.path.join(self.outside, "o.csv")
        os.link(p, o)
        ino = os.stat(p).st_ino
        for args in (["--check", self.tmp], [self.tmp], [p], ["--check", p],
                     ["--fix-perms", self.tmp]):
            with self.subTest(args=args):
                rc, out, err = run_cli(*args)
                self.assertEqual(rc, 1, (out, err))
                self.assertIn(f"UNSCANNED: {p} (hard-linked", out)
                self.assertIn("copy it out first", out)
                self.assertNotIn(SECRET, out + err)
                self.assertEqual(os.stat(p).st_ino, ino)
                self.assertIn(SECRET, self.read(p))
                self.assertIn(SECRET, self.read(o))
        # --fix-perms leaves the shared inode alone (it would change the other link too)
        self.assertEqual(self.mode(o), 0o644)

    def test_clean_hard_linked_file_still_fails_check(self):
        p = self.write("a.csv", "nothing here\n")
        os.link(p, os.path.join(self.outside, "o.csv"))
        rc, out, _ = run_cli("--check", self.tmp)
        self.assertEqual(rc, 1)
        self.assertIn("UNSCANNED", out)

    def test_link_created_during_redaction_not_replaced(self):
        p = self.write("a.csv", f"/r?token={SECRET}\n")
        o = os.path.join(self.outside, "o.csv")
        orig = rx.Run._scan_stream

        def spy(self_, f, path, ftype, sep, codec, sink):
            if sink is not None and not os.path.exists(o):
                os.link(p, o)
            return orig(self_, f, path, ftype, sep, codec, sink)

        with mock.patch.object(rx.Run, "_scan_stream", spy):
            rc, out, err = run_cli(self.tmp)
        self.assertNotEqual(rc, 0)
        self.assertIn(SECRET, self.read(o))
        self.assertEqual(os.stat(p).st_ino, os.stat(o).st_ino)

    def test_link_created_just_before_replace_fails_both_modes(self):
        """A hard link made after the last link-count check, right before the swap."""
        for extra in ([], ["--fix-perms"]):
            with self.subTest(args=extra):
                p = self.write("a.csv", f"/r?token={SECRET}\n")
                o = os.path.join(self.outside, "o.csv")
                if os.path.exists(o):
                    os.unlink(o)
                real = os.replace

                def replace(src, dst, *a, **kw):
                    if str(dst) == "a.csv" and not os.path.exists(o):
                        os.link(p, o)
                    return real(src, dst, *a, **kw)

                with mock.patch.object(rx.os, "replace", replace):
                    rc, out, err = run_cli(*extra, self.tmp)
                self.assertEqual(rc, 1, (out, err))
                self.assertIn(f"UNSCANNED: {p} (hard link appeared during the rewrite", out)
                self.assertNotIn(SECRET, out + err)
                self.assertIn(SECRET, self.read(o))


def _no_nofollow_chmod(calls):
    """os.chmod as on Linux: follow_symlinks=False raises NotImplementedError."""
    real = REAL_CHMOD

    def chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
        if not follow_symlinks:
            raise NotImplementedError("chmod: follow_symlinks unavailable on this platform")
        calls.append((path, dir_fd))
        return real(path, mode, dir_fd=dir_fd)
    return chmod


@unittest.skipIf(ROOT, "root ignores modes")
class LinuxChmodFallback(Base):
    def _by_name(self, calls):
        """chmod calls that addressed an entry by name (anything but /proc/self/fd/N)."""
        return [c for c in calls if not str(c[0]).startswith("/proc/self/fd/")]

    def test_unreadable_entries(self):
        p = self.write("d/a.csv", f"/r?token={SECRET}\n", mode=0o000)
        d = os.path.join(self.tmp, "d")
        os.chmod(d, 0o000)
        calls = []
        with mock.patch.object(rx.os, "chmod", _no_nofollow_chmod(calls)):
            rc, out, err = run_cli("--fix-perms", self.tmp)
        self.assertEqual(self._by_name(calls), [])
        if HAVE_PROC_PATH:
            self.assertEqual(rc, 0, err)
            self.assertEqual(self.mode(d), 0o700)
            self.assertEqual(self.mode(p), 0o600)
            self.assertNotIn(SECRET, self.read(p))
        else:
            self.assertEqual(rc, 2, err)
            self.assertIn("cannot change permissions safely", err)
            self.assertEqual(self.mode(d), 0o000)

    def _race(self, victim_is_dir):
        # The review's simulation: the entry is swapped for a symlink to a path outside the
        # tree at the moment the platform's no-follow chmod turns out to be missing.
        if victim_is_dir:
            victim = os.path.join(self.outside, "victim")
            os.mkdir(victim)
            os.chmod(victim, 0o755)
            entry = os.path.join(self.tmp, "sub")
            os.mkdir(entry)
            os.chmod(entry, 0o000)
        else:
            victim = self.write("victim.txt", "x\n", mode=0o644, top=self.outside)
            entry = self.write("f.csv", "x\n", mode=0o000)
        name = os.path.basename(entry)
        state = {"armed": False, "swapped": False}
        real_open = os.open

        def swap():
            if not state["swapped"]:
                state["swapped"] = True
                REAL_CHMOD(entry, 0o700)
                (shutil.rmtree if victim_is_dir else os.unlink)(entry)
                os.symlink(victim, entry)

        # The swap lands after the no-follow chmod turned out to be missing and the entry
        # was checked: right before the entry is next touched by name (a chmod, as the old
        # fallback did, or an open, as the descriptor path does).
        def chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
            if not follow_symlinks:
                state["armed"] = True
                raise NotImplementedError("chmod: follow_symlinks unavailable on this platform")
            if state["armed"] and path == name:
                swap()
            calls.append((path, dir_fd))
            return REAL_CHMOD(path, mode, dir_fd=dir_fd)

        def opener(path, flags, mode=0o777, *, dir_fd=None):
            if state["armed"] and path == name:
                swap()
            return real_open(path, flags, mode, dir_fd=dir_fd)

        calls = []
        with mock.patch.object(rx.os, "chmod", chmod), mock.patch.object(rx.os, "open", opener):
            rc, out, err = run_cli("--fix-perms", self.tmp)
        self.assertTrue(state["swapped"])
        self.assertTrue(os.path.islink(entry))
        self.assertEqual(self.mode(victim), 0o755 if victim_is_dir else 0o644)
        self.assertEqual(self._by_name(calls), [])
        self.assertNotEqual(rc, 0, (out, err))

    def test_race_file_swapped_for_symlink(self):
        self._race(False)

    def test_race_dir_swapped_for_symlink(self):
        self._race(True)

    def test_no_proc_fails_closed(self):
        self.write("a.csv", "x\n", mode=0o000)
        calls = []
        with mock.patch.object(rx.os, "chmod", _no_nofollow_chmod(calls)), \
                mock.patch.object(rx, "_PROC_FD", "/nonexistent-proc/self/fd"):
            rc, out, err = run_cli("--fix-perms", self.tmp)
        self.assertEqual(rc, 2)
        self.assertIn("cannot change permissions safely", err)
        self.assertEqual(self._by_name(calls), [])
        self.assertEqual(self.mode(os.path.join(self.tmp, "a.csv")), 0o000)


if __name__ == "__main__":
    unittest.main()
