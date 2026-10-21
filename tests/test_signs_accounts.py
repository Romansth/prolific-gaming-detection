import datetime as dt
import unittest

from fraudscreen.fleet import Fleet
from fraudscreen.signs import Context
from fraudscreen.signs.accounts import score_accounts
from tests import synth as S

A, B, C = S.PID_A, S.PID_B, S.PID_C
T = S.T0


def ctx(*parts, raw=True, fleet=None):
    return Context(participants=list(parts), fleet=fleet or Fleet(enrolled_ids={p["key"] for p in parts}), raw_mode=raw)


class M1Tests(unittest.TestCase):
    def test_m1_local_completion_page_fires(self):
        p = S.mk_participant(A, visits=[
            S.mk_visit(f"https://app.prolific.com/submissions/complete?cc=X&PROLIFIC_PID={B}&STUDY_ID={C}", ts=T, visit_id=1),
            S.mk_visit(f"https://mit.co1.qualtrics.com/jfe/form/SV_x?PROLIFIC_PID={B}&STUDY_ID={C}", ts=T - 300, visit_id=2),
            S.mk_visit(f"https://app.prolific.com/studies?x=1&PROLIFIC_PID={A}", ts=T - 3600, visit_id=3),
            S.mk_visit("https://auth.prolific.com/u/login?state=abc", ts=T - 1800, visit_id=4),
        ])
        r = score_accounts(p, ctx(p))
        self.assertTrue(r["M1"].fired)
        self.assertEqual(r["M1"].count, 2)
        self.assertIn("submissions/complete", r["M1"].evidence[0].what)
        self.assertIn("enrolled: no", r["M1"].notes)
        self.assertTrue(any(n.startswith("logins within 60 min: 1") for n in r["M1"].notes))
        self.assertTrue(any("own 1" in n and "foreign 2" in n for n in r["M1"].notes))
        self.assertFalse(r["m2"].fired)

    def test_m1_not_on_synced_only_but_m2_fires(self):
        p = S.mk_participant(A, visits=[
            S.mk_visit(f"https://app.prolific.com/submissions/complete?PROLIFIC_PID={B}", ts=T, is_local=False)])
        r = score_accounts(p, ctx(p))
        self.assertFalse(r["M1"].fired)
        self.assertTrue(r["m2"].fired)

    def test_m1_ignores_vendor_session_id_in_raw_mode(self):
        fresh = "%08x" % int(T - 120) + "0" * 16   # minted two minutes before the visit
        p = S.mk_participant(A, visits=[S.mk_visit(f"https://x.example/s?PROLIFIC_PID={fresh}", ts=T)])
        self.assertFalse(score_accounts(p, ctx(p))["M1"].fired)
        self.assertTrue(score_accounts(p, ctx(p, raw=False))["M1"].fired)

    def test_m1_own_id_and_other_params_do_not_fire(self):
        p = S.mk_participant(A, visits=[
            S.mk_visit(f"https://app.prolific.com/submissions/complete?PROLIFIC_PID={A}", ts=T),
            S.mk_visit(f"https://rx.samplicio.us/?pid={B}&sid=1", ts=T + 1, visit_id=2),
            S.mk_visit(f"https://conjointly.online/study/1/x?id={A}&STUDY_ID={C}", ts=T + 2, visit_id=3)])
        self.assertFalse(score_accounts(p, ctx(p))["M1"].fired)

    def test_m1_enrolled_foreign_id_and_redacted_tokens(self):
        pa = S.mk_participant("pid_" + "a" * 16, visits=[S.mk_visit("https://app.prolific.com/submissions/complete?PROLIFIC_PID=pid_" + "b" * 16, ts=T)])
        pb = S.mk_participant("pid_" + "b" * 16, visits=[S.mk_visit("https://a.example/", ts=T)])
        r = score_accounts(pa, ctx(pa, pb, raw=False))
        self.assertTrue(r["M1"].fired)
        self.assertIn("enrolled: yes", r["M1"].notes)
        self.assertEqual(r["M1"].linked, ["pid_" + "b" * 16])


class OtherTests(unittest.TestCase):
    def test_m3_same_foreign_id_two_participants_links_both(self):
        pa = S.mk_participant(A, visits=[S.mk_visit(f"https://x.example/s?PROLIFIC_PID={B}", ts=T)])
        pc = S.mk_participant(C, visits=[S.mk_visit(f"https://y.example/s?PROLIFIC_PID={B}", ts=T)])
        fleet = Fleet(enrolled_ids={A, C}, foreign_id_owners={B: {A, C}})
        r = score_accounts(pa, ctx(pa, pc, fleet=fleet))
        self.assertTrue(r["m3"].fired)
        self.assertEqual(r["m3"].linked, [C])

    def test_m3_mutual_ids(self):
        pa = S.mk_participant(A, visits=[S.mk_visit(f"https://x.example/s?PROLIFIC_PID={C}", ts=T)])
        pc = S.mk_participant(C, visits=[S.mk_visit(f"https://y.example/s?PROLIFIC_PID={A}", ts=T)])
        fleet = Fleet(enrolled_ids={A, C}, foreign_id_owners={C: {A}, A: {C}})
        self.assertTrue(score_accounts(pa, ctx(pa, pc, fleet=fleet))["m3"].fired)

    def test_m6_age_under_30_days_and_batch(self):
        young = "%08x" % int(T - 5 * 86400) + "0" * 16
        other = "%08x" % int(T - 5 * 86400 + 90) + "1" * 16
        p = S.mk_participant(young, status=[S.mk_status(ts=T)])
        q = S.mk_participant(other, status=[S.mk_status(ts=T)])
        r = score_accounts(p, ctx(p, q))
        self.assertTrue(r["m6"].fired)
        self.assertTrue(any("5 days" in n for n in r["m6"].notes))
        self.assertEqual(r["m6"].linked, [other])
        old = S.mk_participant(A, status=[S.mk_status(ts=T)])
        self.assertFalse(score_accounts(old, ctx(old))["m6"].fired)

    def test_m6_month_resolution_note(self):
        p = S.mk_participant("pid_" + "c" * 16, status=[S.mk_status(ts=T)], account_created=dt.date(2026, 9, 1), resolution="month")
        r = score_accounts(p, ctx(p, raw=False))
        self.assertTrue(r["m6"].fired)
        self.assertTrue(any("month resolution" in n for n in r["m6"].notes))

    def test_m7_duplicate_enrolment(self):
        p = S.mk_participant(A, status=[S.mk_status()], duplicate=True, prefixes=("WEIb", "WEIx"))
        self.assertTrue(score_accounts(p, ctx(p))["m7"].fired)
        self.assertFalse(score_accounts(S.mk_participant(A, status=[S.mk_status()]), ctx(p))["m7"].fired)


if __name__ == "__main__":
    unittest.main()
