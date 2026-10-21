import unittest

from fraudscreen.records import Visit
from fraudscreen.signs import SIGNS, Context, Evidence, SignResult, evidence_from_visit, fmt_utc, sign_by_id


class RegistryTests(unittest.TestCase):
    def test_sign_ids_unique_and_ordered(self):
        ids = [s.id for s in SIGNS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids[:6], ["M1", "M2", "M3", "M4", "M5", "M6"])
        self.assertEqual(ids[6:], ["m%d" % i for i in range(1, 18)])
        self.assertTrue(all(s.tier == "major" for s in SIGNS[:6]))
        self.assertTrue(all(s.tier == "minor" for s in SIGNS[6:]))
        self.assertEqual(sign_by_id("m12").modes, "raw")
        self.assertEqual(sign_by_id("M1").modes, "both")

    def test_every_sign_has_one_sentence_innocent(self):
        for s in SIGNS:
            self.assertTrue(s.innocent.endswith("."), s.id)
            self.assertEqual(s.innocent.count(". "), 0, s.id)
            self.assertTrue(s.title and s.rule, s.id)

    def test_fmt_utc_and_evidence(self):
        self.assertEqual(fmt_utc(1789345395.5), "2026-09-14 00:23:15Z")
        v = Visit(1789345395500, "a.example", "/p", "x=1", "link", 1, 1, 1, True, "UTC", None, "f.json", "")
        self.assertEqual(evidence_from_visit(v), Evidence("2026-09-14 00:23:15Z", "https://a.example/p?x=1", "f.json"))
        r = SignResult("M1")
        self.assertEqual((r.fired, r.count, r.evidence, r.linked, r.notes, r.available), (False, 0, [], [], [], True))
        r.add(Evidence("t", "w", "f")); r.add(Evidence("t", "w2", "f"))
        self.assertEqual(r.count, 2)
        for i in range(10):
            r.add(Evidence("t", str(i), "f"))
        self.assertEqual((r.count, len(r.evidence)), (12, 5))
        ctx = Context(participants=[], fleet=None, raw_mode=True)
        self.assertEqual(ctx.by_key, {})


if __name__ == "__main__":
    unittest.main()
