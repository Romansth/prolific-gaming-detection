import datetime as dt
import re
import tempfile
import unittest
from pathlib import Path

from fraudscreen import participants as P
from fraudscreen.records import new_install
from fraudscreen.scan import scan_folder
from tests import synth as S

PID = "6a0e29aee7c2fddfc1bf8b06"   # ObjectId 2026-05-20
PID2 = "65f1c0de2b7a4e9f8c3d1a20"


def inst_with(ident, ts=S.T0, visits=()):
    i = new_install(ident)
    i["status"].append(S.status(ident, ts=ts))  # not a Status tuple; tests below use scan output instead
    return i


class ParseTests(unittest.TestCase):
    def test_parse_raw_and_redacted(self):
        self.assertEqual(P.parse_ident("AIMECeplc_" + PID + "1231"),
                         P.ParsedIdent("AIMECeplc", PID, "AIM-EC", "Edge", "aimeceplc_" + PID + "1231"))
        self.assertEqual(P.parse_ident("weib_" + PID), P.ParsedIdent("weib", PID, "WEI", "", "weib_" + PID))
        self.assertEqual(P.parse_ident("weib_pid_0123456789abcdef1230"),
                         P.ParsedIdent("weib", "pid_0123456789abcdef", "WEI", "", "weib_pid_0123456789abcdef1230"))
        self.assertEqual(P.parse_ident("ident_0123456789abcdef", {"ident_0123456789abcdef": ("AIMMSplb_", "pid_fedcba9876543210", "2024-08", "ident_1111111111111111")}),
                         P.ParsedIdent("AIMMSplb", "pid_fedcba9876543210", "AIM-MS", "", "ident_1111111111111111"))
        self.assertIsNone(P.parse_ident("WEIplaywrightCC_test07300000000000"))
        self.assertIsNone(P.parse_ident("unknown-id"))

    def test_parse_uppercase_pid_and_digit_prefix(self):
        """The redactor's IDENT_RE accepts both; the raw screen must not drop what the redactor keeps."""
        self.assertEqual(P.parse_ident("WEIb2_" + PID.upper() + "1230").pid, PID)
        self.assertEqual(P.parse_ident("WEIb2_" + PID.upper() + "1230").prefix, "WEIb2")


class GroupTests(unittest.TestCase):
    def _folder(self, d, files):
        for ident, gen, day, pts, variant in files:
            S.write_file(d, ident, gen, day, pts, variant)
        return scan_folder(Path(d), workers=1, raw_mode=True)

    def test_case_variants_merge_to_one_install(self):
        with tempfile.TemporaryDirectory() as d:
            up, lo = "WEIb_" + PID + "1230", "weib_" + PID + "1230"
            installs = self._folder(d, [
                (up, "rex-history-visit", "2026-09-14", [S.visit(up, "https://a.example/p", 1)], "plain"),
                (lo, "rex-history-visit", "2026-09-28", [S.visit(lo, "https://a.example/q", 2, ts=S.T0 + 99)], "recorded"),
                (up, "pdk-system-status", "2026-09-14", [S.status(up)], "plain")])
            parts, skipped = P.group(installs, None, P.default_exclude())
            self.assertEqual(len(parts), 1)
            self.assertEqual(len(parts[0]["installs"]), 1)
            self.assertEqual(len(parts[0]["installs"][0]["visits"]), 2)
            self.assertEqual(parts[0]["key"], PID)

    def test_chrome_and_edge_merge_to_one_participant(self):
        with tempfile.TemporaryDirectory() as d:
            c, e = "AIMECcplc_" + PID + "1231", "AIMECeplc_" + PID + "1231"
            installs = self._folder(d, [
                (c, "pdk-system-status", "2026-09-14", [S.status(c)], "plain"),
                (e, "pdk-system-status", "2026-09-14", [S.status(e, ua=S.EDGE_UA)], "plain")])
            parts, _ = P.group(installs, None, P.default_exclude())
            self.assertEqual(len(parts), 1)
            self.assertEqual(parts[0]["browsers"], {"Chrome", "Edge"})
            self.assertEqual(parts[0]["study"], "AIM-EC")
            self.assertFalse(parts[0]["duplicate_enrolment"])

    def test_internal_and_unshaped_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            t, u, ok = "WEIplaywrightCC_test07300000000000", "WEIb_notahexid", "WEIb_" + PID2 + "1230"
            installs = self._folder(d, [
                (t, "pdk-system-status", "2026-09-14", [S.status(t)], "plain"),
                (u, "pdk-system-status", "2026-09-14", [S.status(u)], "plain"),
                (ok, "pdk-system-status", "2026-09-14", [S.status(ok)], "plain")])
            parts, skipped = P.group(installs, None, P.default_exclude())
            self.assertEqual([p["key"] for p in parts], [PID2])
            self.assertEqual(skipped["internal"], 1)
            self.assertEqual(skipped["no_prolific_id"], 1)

    def test_account_age_raw(self):
        with tempfile.TemporaryDirectory() as d:
            i = "WEIb_" + PID + "1230"
            installs = self._folder(d, [(i, "pdk-system-status", "2026-09-14", [S.status(i)], "plain")])
            parts, _ = P.group(installs, None, P.default_exclude())
            p = parts[0]
            self.assertEqual(p["account_created"], dt.date(2026, 5, 20))
            self.assertEqual(p["account_resolution"], "day")
            self.assertAlmostEqual(P.account_age_days(p), (S.T0 - int(PID[:8], 16)) / 86400, delta=1.0)

    def test_enrolment_time_prefers_registration_over_history(self):
        """Backfilled history predates the install; account age is measured from enrolment."""
        with tempfile.TemporaryDirectory() as d:
            i = "WEIb_" + PID + "1230"
            installs = self._folder(d, [(i, "ai-market-add-identifier", "2026-09-14", [S.add_identifier(i, ts=S.T0)], "plain"),
                                        (i, "rex-history-visit", "2026-09-14", S.news(i, 3, ts0=S.T0 - 90 * 86400), "plain")])
            p, _ = P.group(installs, None, P.default_exclude())
            self.assertEqual(p[0]["first_upload"], S.T0)
            self.assertAlmostEqual(P.account_age_days(p[0]), (S.T0 - int(PID[:8], 16)) / 86400, delta=0.01)

    def test_account_month_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            i = "WEIb_ident_0123456789abcdef"
            Path(d, "identifiers.csv").write_text("ident,prefix,pid,pid_created\nident_0123456789abcdef,WEIb_,pid_fedcba9876543210,2026-09\n")
            installs = self._folder(d, [(i, "pdk-system-status", "2026-09-14", [S.status(i)], "plain")])
            parts, _ = P.group(installs, Path(d, "identifiers.csv"), P.default_exclude())
            p = parts[0]
            self.assertEqual(p["key"], "pid_fedcba9876543210")
            self.assertEqual((p["account_created"], p["account_resolution"]), (dt.date(2026, 9, 1), "month"))
            self.assertIsNone(P.account_age_days(p))
            self.assertTrue(P.account_month_close(p))

    def test_duplicate_enrolment(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = "WEIb_" + PID + "1230", "WEIx_" + PID + "1231"
            installs = self._folder(d, [(a, "pdk-system-status", "2026-09-14", [S.status(a)], "plain"),
                                        (b, "pdk-system-status", "2026-09-14", [S.status(b)], "plain")])
            parts, _ = P.group(installs, None, P.default_exclude())
            self.assertEqual(len(parts), 1)
            self.assertTrue(parts[0]["duplicate_enrolment"])
            self.assertEqual(parts[0]["prefixes"], {"WEIb", "WEIx"})

    def test_duplicate_enrolment_only_within_one_study(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = "WEIb_" + PID + "1230", "AIMECcplc_" + PID + "1231"
            installs = self._folder(d, [(a, "pdk-system-status", "2026-09-14", [S.status(a)], "plain"),
                                        (b, "pdk-system-status", "2026-09-14", [S.status(b)], "plain")])
            parts, _ = P.group(installs, None, P.default_exclude())
            self.assertFalse(parts[0]["duplicate_enrolment"])

    def test_hidden_prefix_is_not_a_duplicate_enrolment(self):
        """The redactor blanks a rare cohort prefix; an Edge twin with a blank label is not a second enrolment."""
        with tempfile.TemporaryDirectory() as d:
            up, lo, pid = "ident_" + "1" * 16, "ident_" + "2" * 16, "pid_" + "a" * 16
            Path(d, "identifiers.csv").write_text("ident,prefix,pid,pid_created,install\n"
                                                  f"{up},AIMECcplc,{pid},2024-03,{up}\n{lo},,{pid},2024-03,{lo}\n")
            installs = {}
            for k in (up, lo):
                installs[k] = new_install(k); installs[k]["status"] = [S.mk_status()]
            parts, _ = P.group(installs, Path(d, "identifiers.csv"), P.default_exclude())
            self.assertFalse(parts[0]["duplicate_enrolment"])
            self.assertTrue(parts[0]["prefix_hidden"])

    def test_dedupe_within_one_install_keeps_synced_reading(self):
        inst = new_install("WEIb_" + PID + "1230")
        inst["visits"] = [S.mk_visit("https://x.example/", ts=S.T0, is_local=True, visit_id=1),
                          S.mk_visit("https://x.example/", ts=S.T0, is_local=False, visit_id=2)]
        inst["status"] = [S.mk_status()]
        other = new_install("WEIx_" + PID + "1231"); other["status"] = [S.mk_status()]
        parts, _ = P.group({inst["ident"]: inst, other["ident"]: other}, None, [])
        visits = [v for i in parts[0]["installs"] for v in i["visits"]]
        self.assertEqual([v.is_local for v in visits], [False])


if __name__ == "__main__":
    unittest.main()
