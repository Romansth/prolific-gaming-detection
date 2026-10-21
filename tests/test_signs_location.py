import unittest

from fraudscreen import tz
from fraudscreen.fleet import Fleet
from fraudscreen.signs import Context
from fraudscreen.signs.location import context_notes, score_location
from tests import synth as S

A = S.PID_A
T = S.T0
DAY = 86400


def run(p, fleet=None, raw=True):
    return score_location(p, Context([p], fleet or Fleet(enrolled_ids={A}, night_p95=0.10), raw))


class LocationTests(unittest.TestCase):
    def setUp(self):
        self._saved = tz.USE_ZONEINFO
        tz.USE_ZONEINFO = False

    def tearDown(self):
        tz.USE_ZONEINFO = self._saved

    def test_m4_two_days_week_apart(self):
        vs = [S.mk_visit("https://accounts.google.co.ke/accounts/SetSID?ssdc=1", ts=T),
              S.mk_visit("https://accounts.google.co.ke/accounts/SetSID?ssdc=1", ts=T + 12 * DAY, visit_id=2)]
        r = run(S.mk_participant(A, visits=vs, status=[S.mk_status()]))
        self.assertTrue(r["M4"].fired)
        self.assertFalse(r["m16"].fired)
        self.assertTrue(any(n.startswith("US consumer sites visited: 0") for n in r["M4"].notes))

    def test_m16_single_day_or_cluster(self):
        vs = [S.mk_visit("https://accounts.google.com.mx/accounts/SetSID", ts=T),
              S.mk_visit("https://accounts.google.com.mx/accounts/SetSID", ts=T + 1 * DAY, visit_id=2),
              S.mk_visit("https://www.skyscanner.com.mx/x", ts=T + 2 * DAY, visit_id=3)]
        r = run(S.mk_participant(A, visits=vs, status=[S.mk_status()]))
        self.assertFalse(r["M4"].fired)
        self.assertTrue(r["m16"].fired)
        self.assertTrue(any(n.startswith("travel sites within 3 days of a location hit: 1") for n in r["m16"].notes))

    def test_m4_consent_gl_ng_and_ignores_search_gl(self):
        vs = [S.mk_visit("https://consent.google.com/m?continue=https://x&gl=NG&hl=en", ts=T),
              S.mk_visit("https://consent.google.com/m?continue=https://x&gl=NG&hl=en", ts=T + 8 * DAY, visit_id=2),
              S.mk_visit("https://www.google.com/search?q=x&gl=NG", ts=T + DAY, visit_id=3)]
        r = run(S.mk_participant(A, visits=vs, status=[S.mk_status()]))
        self.assertTrue(r["M4"].fired)
        self.assertEqual(r["M4"].count, 2)
        us = run(S.mk_participant(A, visits=[S.mk_visit("https://accounts.google.com/signin", ts=T), S.mk_visit("https://consent.google.com/m?gl=US", ts=T + 1, visit_id=2)], status=[S.mk_status()]))
        self.assertFalse(us["M4"].fired or us["m16"].fired)

    def test_m4_not_on_synced_visits(self):
        vs = [S.mk_visit("https://accounts.google.co.ke/accounts/SetSID", ts=T, is_local=False)]
        r = run(S.mk_participant(A, visits=vs, status=[S.mk_status()]))
        self.assertFalse(r["M4"].fired or r["m16"].fired)

    def test_m5_persistent_vs_m17(self):
        st = [S.mk_status(ts=T + i * DAY, tz="Africa/Nairobi") for i in range(8)]
        r = run(S.mk_participant(A, status=st))
        self.assertTrue(r["M5"].fired)
        self.assertFalse(r["m17"].fired)
        brief = [S.mk_status(ts=T + i * DAY, tz="America/New_York") for i in range(10)] + [S.mk_status(ts=T + 3 * DAY + 100, tz="Europe/London")]
        r2 = run(S.mk_participant(A, status=brief))
        self.assertFalse(r2["M5"].fired)
        self.assertTrue(r2["m17"].fired)
        etc = run(S.mk_participant(A, status=[S.mk_status(ts=T + i * DAY, tz="Etc/GMT+6") for i in range(8)]))
        self.assertFalse(etc["M5"].fired or etc["m17"].fired)

    def test_m6_rlz_ve(self):
        vs = [S.mk_visit("https://www.google.com/search?q=x&rlz=1C1ONGR_enVE1180VE1180", ts=T),
              S.mk_visit("https://www.google.com/search?q=y&rlz=1C1GCEU_enUS1000US1000", ts=T + 1, visit_id=2)]
        r = run(S.mk_participant(A, visits=vs, status=[S.mk_status()]))
        self.assertTrue(r["M6"].fired)
        self.assertEqual(r["M6"].count, 1)
        self.assertFalse(run(S.mk_participant(A, visits=vs[1:], status=[S.mk_status()]))["M6"].fired)

    def test_m8_night_owl_with_better_offset(self):
        # visits at 06:00-10:00 UTC = 02:00-06:00 New York; a +1 zone would put them at 07:00-11:00
        vs = [S.mk_visit("https://a.example/%d" % i, ts=T - (T % DAY) + i * DAY + 6 * 3600 + (i % 4) * 3600, visit_id=i + 1) for i in range(100)]
        p = S.mk_participant(A, visits=vs, status=[S.mk_status(tz="America/New_York")])
        r = run(p, Fleet(enrolled_ids={A}, night_p95=0.10))
        self.assertTrue(r["m8"].fired)
        self.assertTrue(any("best-fitting offset" in n for n in r["m8"].notes))
        day = [S.mk_visit("https://a.example/%d" % i, ts=T - (T % DAY) + i * DAY + 18 * 3600, visit_id=i + 1) for i in range(100)]
        self.assertFalse(run(S.mk_participant(A, visits=day, status=[S.mk_status(tz="America/New_York")]))["m8"].fired)

    def test_m9_switch_within_3h(self):
        st = [S.mk_status(ts=T, tz="America/Chicago"), S.mk_status(ts=T + 3600, tz="America/Los_Angeles"), S.mk_status(ts=T + 7200, tz="America/Chicago")]
        self.assertTrue(run(S.mk_participant(A, status=st))["m9"].fired)
        slow = [S.mk_status(ts=T, tz="America/Chicago"), S.mk_status(ts=T + 2 * DAY, tz="America/New_York")]
        self.assertFalse(run(S.mk_participant(A, status=slow))["m9"].fired)

    def test_m13_hl_and_raw_patterns(self):
        vs = [S.mk_visit("https://www.google.com/search?q=22152+zip+usa&hl=es", ts=T)]
        r = run(S.mk_participant(A, visits=vs, status=[S.mk_status()]), raw=True)
        self.assertTrue(r["m13"].fired)
        self.assertTrue(any("zip code lookup" in n for n in r["m13"].notes))
        self.assertNotIn("22152", str(r["m13"].evidence) + str(r["m13"].notes))
        red = run(S.mk_participant(A, visits=[S.mk_visit("https://www.google.com/search?q=q_abc&hl=es", ts=T)], status=[S.mk_status()]), raw=False)
        self.assertTrue(red["m13"].fired)
        plain = run(S.mk_participant(A, visits=[S.mk_visit("https://www.google.com/search?q=weather&hl=en", ts=T)], status=[S.mk_status()]))
        self.assertFalse(plain["m13"].fired)

    def test_context_notes_counts(self):
        vs = [S.mk_visit("https://secure.chase.com/", ts=T), S.mk_visit("https://www.walmart.com/", ts=T + 1, visit_id=2),
              S.mk_visit("https://www.kayak.com/", ts=T + 2, visit_id=3)]
        notes = context_notes(S.mk_participant(A, visits=vs), [T])
        self.assertEqual(notes, ["US consumer sites visited: 2", "travel sites within 3 days of a location hit: 1"])


if __name__ == "__main__":
    unittest.main()
