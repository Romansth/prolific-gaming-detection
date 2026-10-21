import datetime as dt
import unittest

from fraudscreen import tz


def ts(y, mo, d, h, mi=0):
    return dt.datetime(y, mo, d, h, mi, tzinfo=dt.timezone.utc).timestamp()


class TzTests(unittest.TestCase):
    def setUp(self):
        self._saved = tz.USE_ZONEINFO
        tz.USE_ZONEINFO = False

    def tearDown(self):
        tz.USE_ZONEINFO = self._saved

    def test_posix_and_odd_us_names_and_case(self):
        """TZ=EST5EDT on a Linux box, legacy aliases, and a lower-cased name are all US clocks."""
        for z in ("EST5EDT", "PST8PDT", "HST", "America/Knox_IN", "Navajo", "Pacific/Midway", "america/new_york"):
            self.assertTrue(tz.is_us_zone(z), z)
        self.assertAlmostEqual(tz.offset_hours("EST5EDT", ts(2026, 9, 14, 0)), -4)   # September: DST

    def test_us_zone_set(self):
        for z in ("America/New_York", "America/Indiana/Indianapolis", "US/Eastern", "Pacific/Honolulu",
                  "Etc/GMT+6", "America/Puerto_Rico", "America/Kentucky/Louisville"):
            self.assertTrue(tz.is_us_zone(z), z)
        for z in ("Africa/Nairobi", "Etc/GMT+3", "Etc/GMT-5", "Europe/London", "America/Mexico_City", ""):
            self.assertFalse(tz.is_us_zone(z), z)

    def test_dst_boundaries(self):
        self.assertEqual(tz.local_hour(ts(2026, 3, 8, 6, 59), "America/New_York"), 1)   # 01:59 EST
        self.assertEqual(tz.local_hour(ts(2026, 3, 8, 7, 0), "America/New_York"), 3)    # jumps to 03:00 EDT
        self.assertEqual(tz.local_hour(ts(2026, 7, 1, 12, 0), "America/New_York"), 8)   # EDT
        self.assertEqual(tz.local_hour(ts(2026, 11, 1, 6, 30), "America/New_York"), 1)  # back to EST
        self.assertEqual(tz.local_hour(ts(2026, 7, 1, 12, 0), "America/Phoenix"), 5)    # no DST
        self.assertEqual(tz.local_hour(ts(2026, 7, 1, 12, 0), "Pacific/Honolulu"), 2)

    def test_etc_sign_inverted(self):
        self.assertEqual(tz.local_hour(ts(2026, 7, 1, 12, 0), "Etc/GMT+6"), 6)
        self.assertEqual(tz.local_hour(ts(2026, 7, 1, 12, 0), "Etc/GMT-3"), 15)

    def test_other_zones_and_unknown(self):
        self.assertEqual(tz.local_hour(ts(2026, 7, 1, 12, 0), "Africa/Nairobi"), 15)
        self.assertEqual(tz.local_hour(ts(2026, 7, 1, 12, 0), "Asia/Kolkata"), 17)
        self.assertEqual(tz.local_hour(ts(2026, 7, 1, 12, 0), "Mars/Olympus"), 12)
        self.assertTrue(tz.is_unknown("Mars/Olympus"))
        self.assertFalse(tz.is_unknown("Africa/Nairobi"))


if __name__ == "__main__":
    unittest.main()
