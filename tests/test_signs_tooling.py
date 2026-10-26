import unittest

from fraudscreen.fleet import Fleet
from fraudscreen.signs import Context
from fraudscreen.signs.tooling import score_tooling, sessions
from tests import synth as S

A = S.PID_A
T = S.T0
LAUNCH = "https://start.adspower.net/?id=k1edmect&host=127.0.0.1:20725"


def run(p):
    return score_tooling(p, Context([p], Fleet(enrolled_ids={p["key"]}), True))


class ToolingTests(unittest.TestCase):
    def test_sessions_split_on_20_min_gap(self):
        vs = [S.mk_visit("https://a.example/", ts=T), S.mk_visit("https://a.example/", ts=T + 60),
              S.mk_visit("https://a.example/", ts=T + 60 + 1201), S.mk_visit("https://a.example/", ts=T + 60 + 1202)]
        self.assertEqual(sessions(vs), [(0, 2), (2, 4)])

    def test_m3_launch_page_at_session_start(self):
        vs = [S.mk_visit(LAUNCH, ts=T, transition="auto_toplevel"), S.mk_visit("https://app.prolific.com/studies", ts=T + 2, visit_id=2),
              S.mk_visit("https://whoer.to/", ts=T + 4, visit_id=3, transition="auto_toplevel"),
              S.mk_visit("https://b.example/", ts=T + 5000, visit_id=4),
              S.mk_visit(LAUNCH, ts=T + 90000, visit_id=5, transition="link")]
        r = run(S.mk_participant(A, visits=vs))
        self.assertTrue(r["M3"].fired)
        self.assertEqual(r["M3"].count, 2)
        self.assertIn("2 of 3 sessions", r["M3"].notes)
        self.assertTrue(r["m4"].fired)
        self.assertTrue(any(n.startswith("ipcheck: 1 visit, 1 day, typed 0") for n in r["m4"].notes))

    def test_m3_marketing_page_is_m4_not_m3(self):
        vs = [S.mk_visit("https://www.adspower.net/pricing", ts=T)]
        r = run(S.mk_participant(A, visits=vs))
        self.assertFalse(r["M3"].fired)
        self.assertTrue(r["m4"].fired)

    def test_m4_vpn_account_host_fires_marketing_does_not(self):
        acct = run(S.mk_participant(A, visits=[S.mk_visit("https://my.nordaccount.com/dashboard", ts=T)]))
        self.assertTrue(acct["m4"].fired)
        mkt = run(S.mk_participant(A, visits=[S.mk_visit("https://nordvpn.com/pricing", ts=T), S.mk_visit("https://hola.com/", ts=T + 1, visit_id=2)]))
        self.assertFalse(mkt["m4"].fired)
        self.assertTrue(any("vpn_marketing: 1" in n for n in mkt["m4"].notes))

    def test_m4_notes_typed_days_and_session_start(self):
        vs = [S.mk_visit("https://whoer.net/", ts=T, transition="typed"), S.mk_visit("https://whoer.net/", ts=T + 86400, visit_id=2, transition="typed"),
              S.mk_visit("https://a.example/", ts=T + 86400 + 10, visit_id=3)]
        r = run(S.mk_participant(A, visits=vs))
        self.assertTrue(any(n.startswith("ipcheck: 2 visits, 2 days, typed 2, at session start 2") for n in r["m4"].notes))



class HeadlineTests(unittest.TestCase):
    def test_m3_headline_counts_sessions(self):
        vs = [S.mk_visit(LAUNCH, ts=T, transition="auto_toplevel"), S.mk_visit("https://app.prolific.com/studies", ts=T + 2, visit_id=2),
              S.mk_visit("https://b.example/", ts=T + 5000, visit_id=4)]
        r = run(S.mk_participant(A, visits=vs))
        self.assertEqual(r["M3"].headline, "Antidetect browser: the start.adspower.net launch page opened 1 of 2 browsing sessions")

    def test_m4_headline_counts_visits_by_category(self):
        vs = [S.mk_visit("https://whoer.net/", ts=T + i * 86400, visit_id=i + 1, transition="typed") for i in range(3)]
        vs.append(S.mk_visit("https://temp-mail.org/en/", ts=T + 5, visit_id=9))
        r = run(S.mk_participant(A, visits=vs))
        self.assertEqual(r["m4"].headline, "4 visits to concealment-tool sites (ipcheck 3, tempmail 1): whoer.net, temp-mail.org")


if __name__ == "__main__":
    unittest.main()
