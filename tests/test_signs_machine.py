import unittest

from fraudscreen.fleet import Fleet
from fraudscreen.signs import Context
from fraudscreen.signs.machine import hw_key, score_machine
from tests import synth as S

A, B = S.PID_A, S.PID_B
T = S.T0


def fleet_for(*parts):
    f = Fleet(enrolled_ids={p["key"] for p in parts})
    for p in parts:
        times = {}
        for inst in p["installs"]:
            for s in inst["status"]:
                k = hw_key(s)
                if k:
                    f.hw_keys.setdefault(k, set()).add(p["key"])
                for did in [d for d, _ in s.disks] + [d for d, _, _, _ in s.displays]:
                    times.setdefault(did, []).append(s.ts)
        for did, ts in times.items():
            f.transient_ids.setdefault(did, []).append((p["key"], sorted(ts)))
    return f


class MachineTests(unittest.TestCase):
    def test_hw_key_windows_only(self):
        self.assertEqual(hw_key(S.mk_status(disks=(("x", 256005632000), ("u", 1000)))),
                         "Win|Intel(R) Core(TM) i5-5200U CPU @ 2.20GHz|x4|x86_64|mem6311489536|disk256005632000")
        self.assertIsNone(hw_key(S.mk_status(plat="Mac")))
        self.assertIsNone(hw_key(S.mk_status(plat="CrOS")))
        self.assertIsNotNone(hw_key(S.mk_status(plat="Linux")))

    def test_m2_shared_transient_id_overlapping_spans(self):
        pa = S.mk_participant(A, status=[S.mk_status(ts=T + i * 60, disks=(("bf5b9a96", 1022317891584),)) for i in range(5)])
        pb = S.mk_participant(B, status=[S.mk_status(ts=T + 120 + i * 60, disks=(("bf5b9a96", 1022317891584),)) for i in range(5)])
        r = score_machine(pa, Context([pa, pb], fleet_for(pa, pb), True))
        self.assertTrue(r["M2"].fired)
        self.assertEqual(r["M2"].linked, [B])
        self.assertIn("bf5b9a96", r["M2"].evidence[0].what)

    def test_m1_skips_status_without_hardware_fields(self):
        """Every Windows record with no cpu, memory or processor count shares one empty key."""
        self.assertIsNone(hw_key(S.mk_status(cpu="", nproc=-1, mem=-1)))
        self.assertIsNone(hw_key(S.mk_status(mem=0)))

    def test_m1_ignores_removable_disks(self):
        s = S.mk_status(disks=(("fixed-1", 256005632000), ("usb", 31000000000)))._replace(removable=frozenset({"usb"}))
        self.assertEqual(hw_key(s), hw_key(S.mk_status(disks=(("fixed-1", 256005632000),))))

    def test_m2_needs_the_same_minute_not_the_same_range(self):
        """An id seen on day 0 and day 10 by A and on day 5 by B never appears in one running browser."""
        pa = S.mk_participant(A, status=[S.mk_status(ts=T, disks=(("same-id-xx", 1),)), S.mk_status(ts=T + 10 * 86400, disks=(("same-id-xx", 1),))])
        pb = S.mk_participant(B, status=[S.mk_status(ts=T + 5 * 86400, disks=(("same-id-xx", 1),))])
        self.assertFalse(score_machine(pa, Context([pa, pb], fleet_for(pa, pb), True))["M2"].fired)
        pc = S.mk_participant(B, status=[S.mk_status(ts=T + 30, disks=(("same-id-xx", 1),))])
        self.assertTrue(score_machine(pa, Context([pa, pc], fleet_for(pa, pc), True))["M2"].fired)

    def test_m5_ignores_unknown_display_size(self):
        st = [S.mk_status(ts=T + i, displays=(("d", -1, -1, "Generic PnP Monitor"),)) for i in range(5)]
        st += [S.mk_status(ts=T + 10 + i, displays=(("e", 1000 + i, 700, "Generic PnP Monitor"),)) for i in range(4)]
        p = S.mk_participant(A, status=st)
        self.assertFalse(score_machine(p, Context([p], fleet_for(p), True))["m5"].fired)

    def test_m2_not_when_spans_disjoint(self):
        pa = S.mk_participant(A, status=[S.mk_status(ts=T, disks=(("same-id", 1),))])
        pb = S.mk_participant(B, status=[S.mk_status(ts=T + 7200, disks=(("same-id", 1),))])
        self.assertFalse(score_machine(pa, Context([pa, pb], fleet_for(pa, pb), True))["M2"].fired)

    def test_m1_windows_key_shared_mac_ignored(self):
        pa = S.mk_participant(A, status=[S.mk_status(ts=T, disks=(("d1", 256005632000),))])
        pb = S.mk_participant(B, status=[S.mk_status(ts=T + 10 * 86400, disks=(("d2", 256005632000),))])
        r = score_machine(pa, Context([pa, pb], fleet_for(pa, pb), True))
        self.assertTrue(r["m1"].fired)
        self.assertEqual(r["m1"].linked, [B])
        self.assertTrue(any("overlap: no" in n for n in r["m1"].notes))
        ma = S.mk_participant(A, status=[S.mk_status(ts=T, plat="Mac", cpu="Apple M1", mem=8589934592, disks=(("m1", 245107195904),))])
        mb = S.mk_participant(B, status=[S.mk_status(ts=T, plat="Mac", cpu="Apple M1", mem=8589934592, disks=(("m2", 245107195904),))])
        self.assertFalse(score_machine(ma, Context([ma, mb], fleet_for(ma, mb), True))["m1"].fired)

    def test_m5_vm_cpu_string_and_display_churn(self):
        p = S.mk_participant(A, status=[S.mk_status(cpu="QEMU Virtual CPU version 2.5+")])
        self.assertTrue(score_machine(p, Context([p], fleet_for(p), True))["m5"].fired)
        q = S.mk_participant(A, status=[S.mk_status(displays=(("d", 854, 480, "Generic Non-PnP Monitor"),))])
        self.assertTrue(score_machine(q, Context([q], fleet_for(q), True))["m5"].fired)
        sizes = [(1280, 720), (1920, 1080), (1707, 960), (2560, 1440), (3840, 2160)]
        c = S.mk_participant(A, status=[S.mk_status(ts=T + i * 86400, displays=(("d", w, h, "Generic PnP Monitor"),)) for i, (w, h) in enumerate(sizes)])
        self.assertTrue(score_machine(c, Context([c], fleet_for(c), True))["m5"].fired)
        ok = S.mk_participant(A, status=[S.mk_status(ts=T + i * 86400, displays=(("d", w, h, "Generic PnP Monitor"),)) for i, (w, h) in enumerate(sizes[:4])])
        self.assertFalse(score_machine(ok, Context([ok], fleet_for(ok), True))["m5"].fired)

    def test_m10_two_cpus_same_hour(self):
        st = [S.mk_status(ts=T, cpu="CPU One", bundle=1), S.mk_status(ts=T + 600, cpu="CPU Two", bundle=2)]
        vs = [S.mk_visit("https://a.example/", ts=T + 5, bundle=1), S.mk_visit("https://b.example/", ts=T + 605, visit_id=2, bundle=2)]
        p = S.mk_participant(A, visits=vs, status=st)
        r = score_machine(p, Context([p], fleet_for(p), True))
        self.assertTrue(r["m10"].fired)
        nob = S.mk_participant(A, visits=[S.mk_visit("https://a.example/", ts=T + 5), S.mk_visit("https://b.example/", ts=T + 605, visit_id=2)],
                               status=[S.mk_status(ts=T, cpu="CPU One"), S.mk_status(ts=T + 600, cpu="CPU Two")])
        r2 = score_machine(nob, Context([nob], fleet_for(nob), True))
        self.assertTrue(r2["m10"].fired)
        self.assertTrue(any("nearest status point" in n for n in r2["m10"].notes))
        one = S.mk_participant(A, visits=vs, status=[S.mk_status(ts=T, cpu="CPU One", bundle=1), S.mk_status(ts=T + 600, cpu="CPU One", bundle=2)])
        self.assertFalse(score_machine(one, Context([one], fleet_for(one), True))["m10"].fired)

    def test_no_status_points_marks_unavailable(self):
        p = S.mk_participant(A, visits=[S.mk_visit("https://a.example/")])
        r = score_machine(p, Context([p], fleet_for(p), True))
        for sid in ("M2", "m1", "m5", "m10"):
            self.assertFalse(r[sid].available)
            self.assertFalse(r[sid].fired)
            self.assertEqual(r[sid].notes, ["no status points"])


if __name__ == "__main__":
    unittest.main()
