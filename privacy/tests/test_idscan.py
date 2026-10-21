import hashlib
import time
import tracemalloc
import unittest

from privacy.idscan import IdScanner, candidate_ids
from privacy.tokens import Tokenizer

PID_A = "65f1c0de2b7a4e9f8c3d1a20"  # fake; ObjectId time 2024-03-13
PID_B = "6ac1f3a9e04b7d2c1a9f8e37"  # fake; ObjectId time 2026-10-04
IDENT_A = "WEIb_" + PID_A + "0015"


class IdScanTests(unittest.TestCase):
    def setUp(self):
        self.tok = Tokenizer(b"k" * 32)
        self.s = IdScanner(self.tok, known_hex={PID_A, PID_B},
                           prefix_counts={"WEIb_": 5}, threshold=5)
        self.pa = self.tok.token("pid", PID_A)

    def test_bare_hex24(self):
        self.assertEqual(self.s.scan(f"x {PID_A} y"), f"x {self.pa} y")

    def test_uppercase_hex_gets_the_same_token(self):
        self.assertEqual(self.s.scan(PID_A.upper()), self.pa)

    def test_percent_escape_before_the_id(self):
        self.assertEqual(self.s.scan(f"PROLIFIC_PID%3d{PID_A}&x"), f"PROLIFIC_PID%3d{self.pa}&x")

    def test_percent_escape_without_a_known_set(self):
        bare = IdScanner(self.tok)
        self.assertEqual(bare.scan(f"PROLIFIC_PID%3D{PID_A}"), f"PROLIFIC_PID%3D{self.pa}")

    def test_id_followed_by_a_digit_tail(self):
        self.assertEqual(self.s.scan(f"MITINTA_{PID_A}0015"), f"MITINTA_{self.pa}0015")

    def test_sha256_is_left_alone(self):
        h = hashlib.sha256(b"x").hexdigest()
        self.assertEqual(self.s.scan(h), h)

    def test_known_id_inside_a_long_run(self):
        run = "ff" * 10 + PID_B + "ee" * 10
        self.assertEqual(self.s.scan(run), "ff" * 10 + self.tok.token("pid", PID_B) + "ee" * 10)

    def test_identifier_with_a_shared_prefix_keeps_the_prefix(self):
        self.assertEqual(self.s.scan(IDENT_A), "WEIb_" + self.tok.token("ident", IDENT_A))

    def test_identifier_with_a_rare_prefix_is_fully_tokenized(self):
        ident = "AIMMSrareC_" + PID_B + "0042"
        self.assertEqual(self.s.scan(ident), self.tok.token("ident", ident))

    def test_identifier_after_an_encoded_equals_sign(self):
        self.assertEqual(self.s.scan(f"id%3D{IDENT_A}"),
                         "id%3DWEIb_" + self.tok.token("ident", IDENT_A))

    def test_identifier_info_records_pid_and_creation_month(self):
        tok = self.s.scan(IDENT_A)[len("WEIb_"):]
        self.assertEqual(self.s.ident_info[tok],
                         {"prefix": "WEIb_", "pid": self.pa, "pid_created": "2024-03",
                          "install": self.tok.token("ident", IDENT_A.lower())})

    def test_rescanning_output_changes_nothing(self):
        text = f"{IDENT_A} {PID_B} jane.roe@example.org {PID_A}0015"
        once = self.s.scan(text)
        self.assertEqual(self.s.scan(once), once)

    def test_plain_and_encoded_email_share_a_token(self):
        plain = self.s.scan("jane.roe@example.org")
        encoded = self.s.scan("email%3DJane.Roe%40example.org")
        self.assertRegex(plain, r"^email_[0-9a-f]{16}$")
        self.assertEqual(encoded, "email%3D" + plain)

    def test_found_collects_tokens_in_order(self):
        found = []
        self.s.scan(f"jane@x.org {PID_A}", found)
        self.assertEqual(found, [self.tok.token("email", "jane@x.org"), self.pa])

    def test_uuids_and_short_hex_are_left_alone(self):
        for text in ["c_8f2d3e4a5b6c7d8e", "123e4567-e89b-12d3-a456-426614174000", "deadbeef"]:
            self.assertEqual(self.s.scan(text), text)

    def test_a_long_run_without_an_at_sign_scans_in_linear_time(self):
        start = time.time()
        self.s.scan("z" * 50000)
        self.assertLess(time.time() - start, 0.5)

    def test_candidate_ids_does_not_copy_the_whole_input(self):
        data = ("x " * 1000 + '"https://a.example/?p=%25253d' + PID_A + '" ') * 200
        tracemalloc.start()
        found = candidate_ids(data)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertIn(PID_A, found)
        self.assertLess(peak, len(data) // 2)  # the old code held up to three decoded copies

    def test_candidate_ids_skip_escape_attached_runs(self):
        self.assertEqual(candidate_ids(f"a%3d{PID_A}"), {PID_A})
        self.assertEqual(candidate_ids(f"x_{PID_A}0015"), {PID_A})
        self.assertEqual(candidate_ids(hashlib.sha256(b"x").hexdigest()), set())


if __name__ == "__main__":
    unittest.main()
