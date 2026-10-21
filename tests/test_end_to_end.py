import csv
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from fraudscreen.__main__ import main
from fraudscreen.signs import SIGNS
from tests import synth as S


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name, "pull_synth")
        cls.expected = S.build_folder(cls.root)
        cls.out = Path(cls.tmp.name, "report.md")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cls.code = main(["--data", str(cls.root), "--out", str(cls.out), "--workers", "2"])
        cls.stdout = buf.getvalue()
        cls.md = cls.out.read_text()
        with open(cls.out.with_suffix(".csv"), newline="") as fh:
            cls.rows = {r["participant"]: r for r in csv.DictReader(fh)}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def fired(self, pid):
        row = next((r for k, r in self.rows.items() if pid in k), None)
        self.assertIsNotNone(row, pid)
        return {s.id for s in SIGNS if row[f"{s.id}_fired"] == "1"}

    def test_run_succeeds(self):
        self.assertEqual(self.code, 0, self.stdout)

    def test_each_planted_case_ticks_exactly_its_signs(self):
        mismatches = {}
        for pid, exp in self.expected.items():
            got = self.fired(pid)
            if got != exp:
                mismatches[pid[:8]] = (sorted(exp), sorted(got))
        self.assertEqual(mismatches, {})

    def test_clean_participants_absent_from_table(self):
        for pid, exp in self.expected.items():
            if not exp:
                self.assertNotIn(pid, self.md.split("## Evidence")[0].split("| Participant")[1])

    def test_header_counts(self):
        self.assertIn("Mode: raw", self.md)
        self.assertIn("skipped: internal 1", self.md)
        n = len(self.expected)
        self.assertIn(f"Participants screened: {n}", self.md)
        self.assertIn(f"Installs: {n + 3}", self.md)   # +Edge sibling, +WEIx prefix, +AIMECcplc second-study install; the internal id is skipped, the lower-case variant merged


if __name__ == "__main__":
    unittest.main()
