import hashlib
import unittest

from fraudscreen.fleet import Fleet
from fraudscreen.records import Conversation
from fraudscreen.signs import Context
from fraudscreen.signs.behaviour import score_behaviour, study_windows
from tests import synth as S

A, B, C = S.PID_A, S.PID_B, S.PID_C
T = S.T0


def run(p, fleet=None, raw=True, others=()):
    parts = [p] + list(others)
    return score_behaviour(p, Context(parts, fleet or Fleet(enrolled_ids={q["key"] for q in parts}), raw))


def study(pid, sess, t0, done=True, typed=False, chat_at=None):
    vs = [S.mk_visit(f"https://x.qualtrics.com/jfe/form/SV_1?PROLIFIC_PID={pid}&STUDY_ID={C}&SESSION_ID={sess}", ts=t0,
                     transition="typed" if typed else "link", visit_id=hash(sess) % 100000)]
    if chat_at is not None:
        vs.append(S.mk_visit("https://chatgpt.com/c/abc", ts=t0 + chat_at, visit_id=hash(sess + "c") % 100000))
    if done:
        vs.append(S.mk_visit(f"https://app.prolific.com/submissions/complete?cc=X&PROLIFIC_PID={pid}&SESSION_ID={sess}", ts=t0 + 600, visit_id=hash(sess + "d") % 100000))
    return vs


class BehaviourTests(unittest.TestCase):
    def test_study_windows(self):
        vs = study(A, "s1", T) + study(A, "s2", T + 10000, done=False)
        self.assertEqual(study_windows(S.mk_participant(A, visits=vs)), [(T, T + 600), (T + 10000, T + 10000 + 5400)])

    def test_m11_fresh_profile_ids_near_one(self):
        vs = [S.mk_visit("https://a.example/%d" % i, ts=T + i, visit_id=i + 5, hist_id=i + 3) for i in range(60)]
        p = S.mk_participant(A, visits=vs, status=[S.mk_status(ts=T - 60)], registered_at=T - 30)
        r = run(p)
        self.assertTrue(r["m11"].fired)
        self.assertTrue(any(n.startswith("fresh profile") for n in r["m11"].notes))
        old = [S.mk_visit("https://a.example/%d" % i, ts=T + i, visit_id=160446 + i, hist_id=67774 + i) for i in range(60)]
        self.assertFalse(run(S.mk_participant(A, visits=old, status=[S.mk_status(ts=T - 60)], registered_at=T - 30))["m11"].fired)

    def test_m11_survey_only_share(self):
        vs = [S.mk_visit("https://app.prolific.com/studies", ts=T + i, visit_id=1000 + i) for i in range(90)] + \
             [S.mk_visit("https://news.example/%d" % i, ts=T + 1000 + i, visit_id=2000 + i) for i in range(10)]
        r = run(S.mk_participant(A, visits=vs), Fleet(enrolled_ids={A}, infra_p95=0.6))
        self.assertTrue(r["m11"].fired)
        self.assertTrue(any(n.startswith("survey-only") for n in r["m11"].notes))

    def test_m11_typed_links(self):
        vs = []
        for i in range(10):
            vs += study(A, "s%d" % i, T + i * 2000, typed=(i < 4))
        r = run(S.mk_participant(A, visits=vs))
        self.assertTrue(any(n.startswith("typed study links: 4 of 10") for n in r["m11"].notes))
        self.assertTrue(r["m11"].fired)

    def test_m14_modal_gap_excludes_dashboard_reloads(self):
        auto = [S.mk_visit("https://connect.cloudresearch.com/participant/dashboard/", ts=T + 10 * i, visit_id=i + 1) for i in range(80)]
        self.assertFalse(run(S.mk_participant(A, visits=auto))["m14"].fired)
        bot = [S.mk_visit("https://kalshi.com/markets", ts=T + 10 * i, visit_id=i + 1) for i in range(80)]
        r = run(S.mk_participant(A, visits=bot))
        self.assertTrue(r["m14"].fired)
        self.assertTrue(any("modal gap 10 s" in n for n in r["m14"].notes))
        headless = S.mk_participant(A, visits=[S.mk_visit("https://a.example/", ts=T)])
        headless["installs"][0]["headless"] = True
        self.assertTrue(run(headless)["m14"].fired)

    def test_m15_chat_in_windows(self):
        vs = []
        for i in range(12):
            vs += study(A, "s%d" % i, T + i * 5000, chat_at=(60 if i < 6 else None))
        r = run(S.mk_participant(A, visits=vs), Fleet(enrolled_ids={A}, chat_p95=0.2))
        self.assertTrue(r["m15"].fired)
        self.assertTrue(any("6 of 12 study windows" in n for n in r["m15"].notes))
        conv = S.mk_participant(A, visits=[v for v in vs if "chatgpt" not in v.host],
                                conversations=[Conversation("chatgpt", T + i * 5000 + 30) for i in range(8)])
        self.assertTrue(run(conv, Fleet(enrolled_ids={A}, chat_p95=0.2))["m15"].fired)

    def test_m12_shared_identity_and_unavailable_in_redacted_mode(self):
        h = hashlib.sha1(b"someone@example.org").hexdigest()
        pa = S.mk_participant(A, visits=[S.mk_visit("https://a.example/", ts=T)], mail_identities=[("email", h)])
        pb = S.mk_participant(B, visits=[S.mk_visit("https://b.example/", ts=T)], mail_identities=[("email", h)])
        fleet = Fleet(enrolled_ids={A, B}, mail_identities={("email", h): {A, B}})
        r = run(pa, fleet, others=[pb])
        self.assertTrue(r["m12"].fired)
        self.assertEqual(r["m12"].linked, [B])
        self.assertNotIn("someone", str(r["m12"].evidence))
        red = run(pa, fleet, raw=False, others=[pb])
        self.assertFalse(red["m12"].available)


if __name__ == "__main__":
    unittest.main()
