"""Phase 1 rows generated from the baseline (run_manifest.phase1_rows)."""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import run_manifest as r

FINDINGS = """# Example audit: findings (2030-01-01)
## Findings
### N1. Example heading one
**S1** · **CONFIRMED** (live)
### F14 and S1. Widgets page lacks a title
text
### S1 (partial). Example heading three
text
### Carried over without a measurement
F16 (example item) and F19 (another item): CANNOT RETEST.
### Fixed since the baseline
- **F2**: example item no longer present.
## Rejected during verification
### F99. must not appear
## Review record
"""
NOTE = """# Run 1
## Findings, by value

**1. Gadgets page has a
long heading.** body

**2. Example note two.** body
## Privacy
**3. not a finding.**
"""
PROMPT = "| F14 | A | widgets title | 3 |\n| S1 | P | example check | 1a |\n"


class Phase1Rows(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        with open(os.path.join(self.d, "site-audit-2030-01-01.md"), "w") as f: f.write(FINDINGS)
        with open(os.path.join(self.d, "screaming-frog-run1-2030-01-03.md"), "w") as f: f.write(NOTE)
        self.b = {"kind": "previous-audit", "file": "site-audit-2030-01-01.md", "date": "2030-01-01",
                  "path": os.path.join(self.d, "site-audit-2030-01-01.md"), "baseline_dir": self.d,
                  "screaming_frog_notes": ["screaming-frog-run1-2030-01-03.md"]}

    def rows(self):
        return {x["id"]: x for x in r.phase1_rows(self.b, PROMPT)}

    def test_ids_and_order(self):
        ids = [x["id"] for x in r.phase1_rows(self.b, PROMPT)]
        self.assertEqual(ids, ["N1", "F14", "S1", "F16", "F19", "F2", "R1-1", "R1-2"])

    def test_two_ids_in_one_heading_and_no_duplicates(self):
        rows = self.rows()
        self.assertEqual(rows["S1"]["finding"], "Widgets page lacks a title")

    def test_states(self):
        rows = self.rows()
        self.assertEqual(rows["N1"]["last_state"], "CONFIRMED")
        self.assertEqual(rows["F14"]["last_state"], "OPEN")
        self.assertEqual(rows["F16"]["last_state"], "CANNOT RETEST")
        self.assertTrue(rows["F2"]["last_state"].startswith("FIXED"))

    def test_measured_in_from_method_table_else_marked(self):
        rows = self.rows()
        self.assertEqual((rows["F14"]["type"], rows["F14"]["measured_in"]), ("A", "3"))
        self.assertEqual(rows["N1"]["type"], "?")

    def test_rejected_section_and_non_findings_ignored(self):
        rows = self.rows()
        self.assertNotIn("F99", rows)
        self.assertNotIn("R1-3", rows)

    def test_multiline_bold_title_joined(self):
        self.assertEqual(self.rows()["R1-1"]["finding"], "Gadgets page has a long heading.")

    def test_markdown_escapes_pipes(self):
        md = r.phase1_markdown([{"id": "X1", "type": "?", "finding": "a|b", "last_state": "OPEN",
                                 "measured_in": "1a", "source": "s"}], self.b)
        self.assertIn("a\\|b", md)

    def test_missing_file_gives_no_rows(self):
        self.assertEqual(r.phase1_rows({"path": "/nonexistent"}, ""), [])


if __name__ == "__main__":
    unittest.main()
