import csv
import io
import re
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
        cls.out = Path(cls.tmp.name, "report.html")
        buf = io.StringIO()
        with redirect_stdout(buf):
            cls.code = main(["--data", str(cls.root), "--out", str(cls.out), "--workers", "2"])
        cls.stdout = buf.getvalue()
        cls.html = cls.out.read_text()
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

    def test_flagged_cards_are_exactly_the_strong_cases(self):
        """A card for every participant with a major sign, and for nobody else."""
        strong = {s.id for s in SIGNS if s.tier == "major"}
        want = {pid for pid, exp in self.expected.items() if exp & strong}
        got = set(re.findall(r'id="p-([0-9a-f]{24})"', self.html))
        self.assertEqual(got, want)

    def test_support_only_participants_have_no_card_but_are_listed(self):
        strong = {s.id for s in SIGNS if s.tier == "major"}
        for pid, exp in self.expected.items():
            if exp and not exp & strong:
                self.assertIn(pid, self.html, pid)
                self.assertNotIn(f'id="p-{pid}"', self.html, pid)
            if not exp:
                self.assertNotIn(pid, self.html, pid)

    def test_headlines_carry_specifics(self):
        for text in ("Device clock set to Africa/Nairobi on 10 days, 100% of 18 observation minutes", "Google sign-ins routed through google.co.ke on 2 days",
                     "Chrome installed with a VE locale", "start.adspower.net launch page opened 1 of",
                     "In the same running browser as", "study pages opened locally under another Prolific id"):
            self.assertIn(text, self.html, text)

    def test_header_counts(self):
        self.assertIn("Mode: raw", self.html)
        self.assertIn("skipped: internal 1", self.html)
        n = len(self.expected)
        self.assertIn(f"Participants screened: {n}", self.html)
        self.assertIn(f"Installs: {n + 3}", self.html)   # +Edge sibling, +WEIx prefix, +AIMECcplc second-study install; the internal id is skipped, the lower-case variant merged


if __name__ == "__main__":
    unittest.main()
