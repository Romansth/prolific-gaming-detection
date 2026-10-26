import csv
import json
import tempfile
import unittest
from pathlib import Path

from fraudscreen.fleet import Fleet
from fraudscreen.report import build_model, render_html, write_csv
from fraudscreen.signs import SIGNS, Evidence, SignResult
from tests import synth as S

A, B, C = S.PID_A, S.PID_B, S.PID_C


def res(fired=(), counts=None, unavailable=(), linked=None, headline=None):
    out = {s.id: SignResult(s.id) for s in SIGNS}
    for sid in fired:
        out[sid].fired = True
        out[sid].count = (counts or {}).get(sid, 1)
        out[sid].evidence.append(Evidence("2026-09-14 00:23:15Z", "https://x.example/p", "f.json"))
        out[sid].notes.append("note one")
        out[sid].headline = (headline or {}).get(sid, "")
        out[sid].rows = 1
        if linked and sid in linked:
            out[sid].linked.append(linked[sid])
    for sid in unavailable:
        out[sid].available = False
    return out


META = dict(folder="pull_x", mode="raw", files=10, installs=3, participants=3, skipped={"internal": 1}, run_date="2026-10-26",
            date_range="2026-09-14..2026-10-13", version="0.1.0", seconds=1.5, arms_available=True)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.pa = S.mk_participant(A, status=[S.mk_status()], prefixes=("WEIb",))
        self.pa["arm"] = "WebEatsItself_CC"
        self.pb = S.mk_participant(B, status=[S.mk_status()], prefixes=("AIMECcplc", "AIMECeplc"), browsers=("Chrome", "Edge"), study="AIM-EC")
        self.pb["arm"] = "AIMarket_EcosystemSurvey_Control"
        self.pc = S.mk_participant(C, status=[S.mk_status()])
        self.pc["arm"] = "?4016cabf"
        self.results = {A: res(["m4"], {"m4": 3}), B: res(["M1", "M2", "m1"], linked={"M2": A}, headline={"M2": "In the same running browser as " + A}), C: res()}
        self.fleet = Fleet(n_screened=3, n_in_percentiles=3)
        self.parts = [self.pa, self.pb, self.pc]

    def test_model_flags_only_strong_patterns(self):
        m = build_model(self.results, self.parts, self.fleet, META)
        self.assertEqual([c["key"] for c in m["flagged"]], [B])
        card = m["flagged"][0]
        self.assertEqual([s["id"] for s in card["strong"]], ["M1", "M2"])
        self.assertEqual([s["id"] for s in card["support"]], ["m1"])
        self.assertEqual(card["label"], B + " (AIMECcplc/AIMECeplc)")
        self.assertEqual(card["linked"], [A])
        self.assertEqual([r["key"] for r in m["support_only"]], [A])
        self.assertEqual((m["n_screened"], m["n_flagged"], m["n_support_only"], m["n_clean"]), (3, 1, 1, 1))

    def test_connected_participants_sit_together(self):
        y, x, z = "65000000000000000000000a", "65000000000000000000000b", "65000000000000000000000c"
        parts = [S.mk_participant(k, status=[S.mk_status()]) for k in (y, x, z)]
        results = {y: res(["M2"], linked={"M2": z}), x: res(["M4"]), z: res(["M2"], linked={"M2": y})}
        m = build_model(results, parts, self.fleet, META)
        self.assertEqual([c["key"] for c in m["flagged"]], [y, z, x])

    def test_html_cards_sections_and_escaping(self):
        self.results[B]["M1"].evidence[0] = Evidence("2026-09-14 00:23:15Z", "https://x.example/p?a=1&b=2", "f.json")
        html = render_html(build_model(self.results, self.parts, self.fleet, META))
        self.assertIn("<title>Participant screen: pull_x</title>", html)
        self.assertIn(f'id="p-{B}"', html)
        self.assertNotIn(f'id="p-{A}"', html)
        self.assertIn(A, html)                                   # the support-only table names A
        self.assertNotIn(C, html)                                # nothing seen: not on the page
        self.assertIn("https://x.example/p?a=1&amp;b=2", html)
        self.assertNotIn("?a=1&b=2", html)
        self.assertIn("Mode: raw", html)
        self.assertIn("In the same running browser as " + A, html)
        self.assertIn("Two household members each keep a profile in the same Chrome window.", html)
        self.assertIn("Concealment tool sites", html)            # the support-only row names the pattern
        self.assertIn("1 / 3", html)                             # catalogue: M1 fired for 1 of 3 screened
        self.assertIn(f'href="#p-{B}"', html)                    # the overview links to the card

    def test_catalogue_counts_unavailable(self):
        results = {A: res(["M1"], unavailable=["m12"])}
        html = render_html(build_model(results, [self.pa], self.fleet, dict(META, mode="redacted")))
        self.assertIn("not available for 1", html)
        self.assertIn("Mode: redacted", html)

    def test_support_line_falls_back_to_first_note(self):
        m = build_model(self.results, self.parts, self.fleet, META)
        self.assertEqual(m["flagged"][0]["support"][0]["line"], "note one")
        self.assertEqual(m["flagged"][0]["strong"][0]["headline"], "note one")   # M1 given no headline here

    def test_nobody_flagged_still_renders(self):
        html = render_html(build_model({A: res(["m4"])}, [self.pa], self.fleet, META))
        self.assertIn("No participant is flagged", html)
        self.assertIn(A, html)

    def test_email_masked_in_model(self):
        r = res(["M4"])
        r["M4"].evidence[0] = Evidence("2026-09-14 00:23:15Z", "https://accounts.google.co.ke/x?login_hint=jane.doe%40example.com", "")
        m = build_model({A: r}, [self.pa], self.fleet, META)
        self.assertNotIn("jane.doe", json.dumps(m))
        self.assertIn("[email]", json.dumps(m))

    def test_total_line_only_when_evidence_rows_were_cut(self):
        """M5 keeps one summary row and a count of observation minutes: no 'first 1 are shown'. A sign
        that added seven rows (five kept) says so."""
        r = res(["M5", "M1"], counts={"M5": 18, "M1": 7})
        r["M5"].rows = 1
        r["M1"].rows = 7
        r["M1"].evidence = [Evidence("2026-09-14 00:23:15Z", f"https://x.example/{i}", "f.json") for i in range(5)]
        html = render_html(build_model({A: r}, [self.pa], self.fleet, META))
        self.assertNotIn("18 in total", html)
        self.assertNotIn("first 1 are shown", html)
        self.assertIn("7 in total; the first 5 are shown", html)

    def test_lead_carries_the_run_date(self):
        html = render_html(build_model(self.results, self.parts, self.fleet, META))
        self.assertIn("Run on 2026-10-26", html)

    def test_csv_columns(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "out.csv")
            write_csv(path, self.results, self.parts)
            rows = list(csv.DictReader(open(path, newline="")))
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0]["participant"], B + " (AIMECcplc/AIMECeplc)")
            self.assertEqual(rows[0]["major_count"], "2")
            self.assertEqual(rows[0]["flagged"], "1")
            self.assertEqual(rows[0]["M1_fired"], "1")
            self.assertEqual(rows[1]["flagged"], "0")
            self.assertEqual(rows[1]["m4_count"], "3")
            self.assertEqual(rows[2]["major_count"], "0")
            self.assertIn("linked", rows[0])


if __name__ == "__main__":
    unittest.main()
