import unittest

from fraudscreen.fleet import build_fleet, infra_share, night_share
from tests import synth as S

A, B, C = S.PID_A, S.PID_B, S.PID_C
T = S.T0


def heavy(pid, n, infra=False, night=False, status=True):
    vs = []
    for i in range(n):
        ts = T + 86400 * (i % 10) + (3 * 3600 if night else 15 * 3600) + i   # 03:00 or 15:00 local (New York = UTC-4 in Sep)
        url = "https://app.prolific.com/studies" if infra else "https://news.example/%d" % i
        vs.append(S.mk_visit(url, ts=ts + 4 * 3600, visit_id=i + 1))
    st = [S.mk_status(ts=T, disks=(("disk-" + pid[:4], 256005632000),))] if status else []
    return S.mk_participant(pid, visits=vs, status=st)


class FleetTests(unittest.TestCase):
    def test_percentiles_use_min_visits(self):
        big = heavy(A, 100, night=True)
        big2 = heavy(C, 100, night=True)
        small = heavy(B, 10, night=True)
        quiet = [heavy("%024x" % (0x650000000000000000000000 + i), 100) for i in range(18)]
        f = build_fleet([big, big2, small] + quiet, min_visits=50)   # 20 in the percentile set, the small one out
        self.assertEqual(f.n_screened, 21)
        self.assertEqual(f.n_in_percentiles, 20)
        self.assertAlmostEqual(night_share(big, "America/New_York"), 1.0)
        self.assertAlmostEqual(night_share(quiet[0], "America/New_York"), 0.0)
        self.assertGreater(f.night_p95, 0.5)
        self.assertEqual(infra_share(heavy(C, 60, infra=True)), 1.0)

    def test_percentiles_need_twenty_participants(self):
        """With 11 or fewer participants the 95th percentile is the maximum, so the participant who
        sets it could never exceed it; below 20 the floor alone is the threshold."""
        owl = heavy(A, 100, night=True)
        quiet = [heavy("%024x" % (0x650000000000000000000000 + i), 100) for i in range(10)]
        f = build_fleet([owl] + quiet, min_visits=50)
        self.assertEqual((f.night_p95, f.percentiles_valid), (0.0, False))
        more = [heavy("%024x" % (0x660000000000000000000000 + i), 100) for i in range(19)]
        self.assertTrue(build_fleet([owl] + more, min_visits=50).percentiles_valid)

    def test_enrolled_ids_and_owners(self):
        pa = S.mk_participant(A, visits=[S.mk_visit(f"https://x.example/s?PROLIFIC_PID={C}", ts=T)], status=[S.mk_status(disks=(("disk-" + A[:4], 256005632000),))])
        pb = S.mk_participant(B, visits=[S.mk_visit(f"https://y.example/s?PROLIFIC_PID={C}", ts=T)])
        f = build_fleet([pa, pb], min_visits=1)
        self.assertEqual(f.enrolled_ids, {A, B})
        self.assertEqual(f.foreign_id_owners, {C: {A, B}})
        self.assertIn("disk-" + A[:4], f.transient_ids)
        self.assertTrue(any(k.startswith("Win|") for k in f.hw_keys))


if __name__ == "__main__":
    unittest.main()
