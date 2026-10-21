import csv
import tempfile
import unittest
from pathlib import Path

from fraudscreen.fleet import Fleet
from fraudscreen.report import render_markdown, write_csv
from fraudscreen.signs import SIGNS, Evidence, SignResult
from tests import synth as S

A, B, C = S.PID_A, S.PID_B, S.PID_C


def res(fired=(), counts=None, unavailable=(), linked=None):
    out = {s.id: SignResult(s.id) for s in SIGNS}
    for sid in fired:
        out[sid].fired = True
        out[sid].count = (counts or {}).get(sid, 1)
        out[sid].evidence.append(Evidence("2026-09-14 00:23:15Z", "https://x.example/p", "f.json"))
        out[sid].notes.append("note one")
        if linked and sid in linked:
            out[sid].linked.append(linked[sid])
    for sid in unavailable:
        out[sid].available = False
    return out


META = dict(folder="pull_x", mode="raw", files=10, installs=3, participants=3, skipped={"internal": 1},
            date_range="2026-09-14..2026-10-13", version="0.1.0", seconds=1.5, arms_available=True)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.pa = S.mk_participant(A, status=[S.mk_status()], prefixes=("WEIb",))
        self.pa["arm"] = "WebEatsItself_CC"
        self.pb = S.mk_participant(B, status=[S.mk_status()], prefixes=("AIMECcplc", "AIMECeplc"), browsers=("Chrome", "Edge"), study="AIM-EC")
        self.pb["arm"] = "AIMarket_EcosystemSurvey_Control"
        self.pc = S.mk_participant(C, status=[S.mk_status()])
        self.pc["arm"] = "?4016cabf"
        self.results = {A: res(["m4"], {"m4": 3}), B: res(["M1", "M2", "m1"], linked={"M2": A}), C: res()}
        self.fleet = Fleet(n_screened=3, n_in_percentiles=3)

    def test_table_only_lists_fired_and_sorting(self):
        md = render_markdown(self.results, [self.pa, self.pb, self.pc], self.fleet, META)
        rows = [l for l in md.splitlines() if l.startswith("| ") and ("(WEIb)" in l or "(AIMEC" in l)]
        self.assertEqual(len(rows), 2)
        self.assertIn(B + " (AIMECcplc/eplc)", rows[0])
        self.assertIn(A + " (WEIb)", rows[1])
        self.assertNotIn(C, md)
        self.assertIn("| 2 |", rows[0])
        self.assertIn("✓3", rows[1])

    def test_na_cell_and_legend(self):
        results = {A: res(["m4"], unavailable=["m12"])}
        md = render_markdown(results, [self.pa], self.fleet, dict(META, mode="redacted"))
        row = [l for l in md.splitlines() if A + " (WEIb)" in l][0]
        self.assertIn("n/a", row)
        self.assertIn("M1 Second Prolific id used in the monitored browser", md)
        self.assertIn("## Evidence", md)

    def test_evidence_block_format(self):
        md = render_markdown(self.results, [self.pa, self.pb, self.pc], self.fleet, META)
        self.assertIn("### " + B + " (AIMECcplc/eplc)", md)
        self.assertIn("**M2 Two enrolled participants in one running browser**", md)
        self.assertIn("Rule: ", md)
        self.assertIn("- 2026-09-14 00:23:15Z · https://x.example/p · f.json", md)
        self.assertIn("Count: 1", md)
        self.assertIn("Innocent reading: Two household members each keep a profile in the same Chrome window.", md)
        self.assertIn("Linked to: " + A, md)
        self.assertIn("## Appendix A", md)
        self.assertIn("## Appendix B", md)
        self.assertIn("## Appendix C", md)
        self.assertIn("| M1 | major |", md)
        self.assertIn("1 / 3", md)   # M1 fired for 1 of 3 screened

    def test_csv_columns(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "out.csv")
            write_csv(path, self.results, [self.pa, self.pb, self.pc])
            rows = list(csv.DictReader(open(path, newline="")))
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0]["participant"], B + " (AIMECcplc/eplc)")
            self.assertEqual(rows[0]["major_count"], "2")
            self.assertEqual(rows[0]["M1_fired"], "1")
            self.assertEqual(rows[1]["m4_count"], "3")
            self.assertEqual(rows[2]["major_count"], "0")
            self.assertIn("linked", rows[0])


if __name__ == "__main__":
    unittest.main()
