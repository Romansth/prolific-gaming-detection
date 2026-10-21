import datetime as dt
import unittest

from fraudscreen.fleet import Fleet, build_fleet
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

    def test_m6_measures_from_enrolment_not_history(self):
        """Backfilled history from before the account existed must not make the account look young."""
        created = int(T - 60 * 86400)
        pid = "%08x" % created + "0" * 16
        old_history = [S.mk_visit(f"https://news.example/{i}", ts=T - 90 * 86400 + i, visit_id=i + 1) for i in range(3)]
        p = S.mk_participant(pid, visits=old_history, status=[S.mk_status(ts=T)], registered_at=T)
        p["first_upload"] = T; p["account_created_ts"] = created
        self.assertFalse(score_accounts(p, ctx(p))["m6"].fired)
        p["account_created_ts"] = int(T - 29.5 * 86400)
        r = score_accounts(p, ctx(p))
        self.assertTrue(r["m6"].fired)
        self.assertTrue(any("30 days old" in n or "29 days old" in n for n in r["m6"].notes))

    def test_m6_batch_rule_noted_as_unavailable_in_redacted_mode(self):
        p = S.mk_participant("pid_" + "c" * 16, status=[S.mk_status(ts=T)], account_created=dt.date(2026, 9, 1), resolution="month")
        self.assertTrue(any("needs raw ids" in n for n in score_accounts(p, ctx(p, raw=False))["m6"].notes))

    def test_m3_mutual_young_ids_is_symmetric(self):
        """The fleet's owner map applies the same raw-mode age filter as the per-participant scan."""
        young = "%08x" % int(T - 3600) + "9" * 16
        pa = S.mk_participant(A, visits=[S.mk_visit(f"https://x.example/s?PROLIFIC_PID={young}", ts=T)])
        pb = S.mk_participant(young, visits=[S.mk_visit(f"https://y.example/s?PROLIFIC_PID={A}", ts=T)])
        fleet = build_fleet([pa, pb], 1, raw_mode=True)
        fired = {score_accounts(p, Context([pa, pb], fleet, True))["m3"].fired for p in (pa, pb)}
        self.assertEqual(len(fired), 1)

    def test_m1_reads_enrolled_tokens_from_opaque_urls_only(self):
        """Redacted data: an opaque URL lists its ids; only an enrolled participant's token counts,
        since a study or session id is also 24-hex and gets a pid token too."""
        other, study = "pid_" + "b" * 16, "pid_" + "5" * 16
        own = "pid_" + "a" * 16
        v = S.mk_visit(f"https://host_x/url_y?ids={study},{other},ident_{'c' * 16}", ts=T)
        p = S.mk_participant(own, visits=[v])
        q = S.mk_participant(other, visits=[])
        r = score_accounts(p, Context([p, q], Fleet(enrolled_ids={own, other}), False))
        self.assertTrue(r["M1"].fired)
        self.assertEqual(r["M1"].linked, [other])
        self.assertNotIn(study, " ".join(r["M1"].notes))

    def test_m7_unavailable_when_a_label_is_hidden(self):
        """Redacted data: the redactor blanks a rare cohort label, so m7 shows n/a with a reason, not a blank."""
        p = S.mk_participant(A, status=[S.mk_status()], prefixes=("AIMECcplc", ""))
        p["prefix_hidden"] = True
        r = score_accounts(p, ctx(p, raw=False))["m7"]
        self.assertFalse(r.available)
        self.assertFalse(r.fired)
        self.assertIn("hidden", r.notes[0])

    def test_m7_duplicate_enrolment(self):
        p = S.mk_participant(A, status=[S.mk_status()], duplicate=True, prefixes=("WEIb", "WEIx"))
        self.assertTrue(score_accounts(p, ctx(p))["m7"].fired)
        self.assertFalse(score_accounts(S.mk_participant(A, status=[S.mk_status()]), ctx(p))["m7"].fired)


if __name__ == "__main__":
    unittest.main()
