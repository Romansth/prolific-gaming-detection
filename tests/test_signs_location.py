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

    def test_m4_calendar_days_and_territories(self):
        a = S.mk_visit("https://accounts.google.co.ke/x", ts=T - (T % DAY) + 23 * 3600)
        b = S.mk_visit("https://accounts.google.co.ke/x", ts=T - (T % DAY) + 7 * DAY + 3600, visit_id=2)
        r = run(S.mk_participant(A, visits=[a, b]))
        self.assertTrue(r["M4"].fired)
        pr = run(S.mk_participant(A, visits=[S.mk_visit("https://accounts.google.com.pr/x", ts=T)]))
        self.assertFalse(pr["M4"].fired or pr["m16"].fired)

    def test_m5_counts_observation_days_not_visit_dates(self):
        """One collection made under a London clock covers 20 days of history: London was seen once."""
        backfill = [S.mk_visit(f"https://news.example/{i}", ts=T - i * DAY, visit_id=i + 1, tz="Europe/London")._replace(obs_s=T) for i in range(20)]
        st = [S.mk_status(ts=T + i * 60) for i in range(60)]
        r = run(S.mk_participant(A, visits=backfill, status=st))
        self.assertFalse(r["M5"].fired)
        self.assertTrue(r["m17"].fired)
        self.assertTrue(any(n.startswith("1 days, 2% of 61 observation minutes") for n in r["m17"].notes), r["m17"].notes)

    def test_m5_uses_local_dates(self):
        """Nairobi points at 23:30 and 00:30 local fall on one UTC date but two local dates: 7 local
        dates over 4 UTC dates, with US points keeping the share under half so only the days decide."""
        base = T - (T % DAY)
        st = [S.mk_status(ts=base + k * DAY + 20.5 * 3600, tz="Africa/Nairobi") for k in (0, 2, 4, 6)]
        st += [S.mk_status(ts=base + k * DAY + 21.5 * 3600, tz="Africa/Nairobi") for k in (0, 2, 4)]
        st += [S.mk_status(ts=base + 12 * 3600 + i * 60) for i in range(20)]
        r = run(S.mk_participant(A, status=st))
        self.assertTrue(r["M5"].fired)
        self.assertTrue(any(n.startswith("7 days, 26%") for n in r["M5"].notes), r["M5"].notes)

    def test_m6_rlz_hyphenated_and_lowercase_locales(self):
        for rlz, cc in (("1C1CHBF_en-GBGB917GB917", "GB"), ("1C1CHBD_pt-BRBR1010BR1010", "BR"), ("1C1GCEU_es-419MX1000MX1000", "MX"),
                        ("1c1onGR_enve1180ve1180", "VE"), ("1C1VDKB_filPH950PH950", "PH")):
            r = run(S.mk_participant(A, visits=[S.mk_visit(f"https://www.google.com/search?q=x&rlz={rlz}", ts=T)]))
            self.assertTrue(r["M6"].fired, rlz)
            self.assertIn(f"codes: {cc}=1", r["M6"].notes[0])
        us = run(S.mk_participant(A, visits=[S.mk_visit("https://www.google.com/search?q=x&rlz=1C1GCEA_enPR1000PR1000", ts=T)]))
        self.assertFalse(us["M6"].fired)

    def test_m13_english_variants_do_not_fire(self):
        for hl in ("en-GB", "en_CA", "EN"):
            self.assertFalse(run(S.mk_participant(A, visits=[S.mk_visit(f"https://www.google.com/search?q=x&hl={hl}", ts=T)]))["m13"].fired, hl)
        self.assertTrue(run(S.mk_participant(A, visits=[S.mk_visit("https://www.google.com/search?q=x&hl=es-419", ts=T)]))["m13"].fired)

    def test_m9_ignores_empty_zone_and_aliases(self):
        st = [S.mk_status(ts=T), S.mk_status(ts=T + 600, tz=""), S.mk_status(ts=T + 1200),
              S.mk_status(ts=T + 1800, tz="Asia/Calcutta"), S.mk_status(ts=T + 2400, tz="Asia/Kolkata")]
        r = run(S.mk_participant(A, status=st))
        self.assertEqual([e.what for e in r["m9"].evidence],
                         ["America/New_York at 2026-09-14 00:43:15Z -> Asia/Calcutta at 2026-09-14 00:53:15Z"])

    def test_m8_evidence_shows_applied_threshold(self):
        vs = [S.mk_visit("https://a.example/%d" % i, ts=T - (T % DAY) + i * DAY + 6 * 3600 + (i % 4) * 3600, visit_id=i + 1) for i in range(100)]
        p = S.mk_participant(A, visits=vs, status=[S.mk_status(tz="America/New_York")])
        r = run(p, Fleet(enrolled_ids={A}, night_p95=0.05))
        self.assertTrue(r["m8"].fired)
        self.assertIn("threshold 20%", r["m8"].evidence[0].what)

    def test_context_notes_counts(self):
        vs = [S.mk_visit("https://secure.chase.com/", ts=T), S.mk_visit("https://www.walmart.com/", ts=T + 1, visit_id=2),
              S.mk_visit("https://www.kayak.com/", ts=T + 2, visit_id=3)]
        notes = context_notes(S.mk_participant(A, visits=vs), [T])
        self.assertEqual(notes, ["US consumer sites visited: 2", "travel sites within 3 days of a location hit: 1"])


if __name__ == "__main__":
    unittest.main()
