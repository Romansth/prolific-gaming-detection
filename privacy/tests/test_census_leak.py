import hashlib
import io
import json
import os
import tempfile
import time
import tracemalloc
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from privacy import census, leakcheck, paths
from privacy.tokens import Tokenizer, load_or_create_key

PID_A = "65f1c0de2b7a4e9f8c3d1a20"
PID_B = "6ac1f3a9e04b7d2c1a9f8e37"
IDENT_A = "WEIb_" + PID_A + "0015"
IDENT_B = "WEIb_" + PID_B + "0042"


def visits(ident, *urls):
    return json.dumps([{"passive-data-metadata": {"source": ident, "generator-id": "rex-history-visit"},
                        "url": u, "domain": u.split("/")[2]} for u in urls])


class CensusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def put(self, name, text):
        p = self.tmp / name
        p.write_text(text)
        return p

    def test_owner_hosts_domains_and_known_ids(self):
        p = self.put(f"{IDENT_A}__rex-history-visit__2099-01-01.json",
                     visits(IDENT_A, f"https://common.example/a?PROLIFIC_PID%3d{PID_B}"))
        c = census.census_file(p)
        self.assertEqual(c["owners_hosts"], {IDENT_A.lower(): {"common.example"}})
        self.assertEqual(c["owners_domains"], {IDENT_A.lower(): {"common.example"}})
        self.assertIn(PID_B, c["known"])
        self.assertIn(PID_B.encode(), c["leak"])
        self.assertIn(IDENT_A, c["idents"])

    def test_zip_members_are_read(self):
        z = self.tmp / "nightly.zip"
        with zipfile.ZipFile(z, "w") as f:
            f.writestr(f"{IDENT_B}__rex-history-visit__2099-01-01.json", visits(IDENT_B, "https://common.example/b"))
        self.assertEqual(census.census_file(z)["owners_hosts"], {IDENT_B.lower(): {"common.example"}})

    def test_merge_counts_distinct_owners(self):
        a = census.census_file(self.put("a.json", visits(IDENT_A, "https://common.example/a", "https://rare.example/")))
        b = census.census_file(self.put("b.json", visits(IDENT_B, "https://common.example/b")))
        m = census.merge_census([a, b])
        self.assertEqual(m["host_counts"], {"common.example": 2, "rare.example": 1})
        self.assertEqual(m["prefix_counts"], {"weib_": 2})


class LeakTests(unittest.TestCase):
    def test_collect(self):
        self.assertEqual(leakcheck.collect(f"a%3d{PID_A}".encode()), {PID_A.encode()})
        self.assertEqual(leakcheck.collect(f"x_{PID_A}0015".encode()), {PID_A.encode()})
        self.assertEqual(leakcheck.collect(hashlib.sha256(b"x").hexdigest().encode()), set())

    def test_scan_finds_each_kind(self):
        known = {PID_A.encode()}
        self.assertEqual(leakcheck.scan(b"WEIb_ident_0123456789abcdef pid_0123456789abcdef0015", known), [])
        # IDENT_B, not IDENT_A: PID_A is known, so IDENT_A would add a second known-id hit.
        kinds = [k for k, _ in leakcheck.scan(
            f"{PID_B} ff{PID_A}ffffffffffffff {IDENT_B} jane@example.org jane%40example.org".encode(), known)]
        self.assertEqual(kinds, ["hex24", "known-id", "identifier", "email", "email"])

    def test_a_long_run_without_an_at_sign_scans_in_linear_time(self):
        start = time.time()
        leakcheck.scan(b"z" * 50000, set())
        self.assertLess(time.time() - start, 0.5)

    def test_collect_does_not_copy_the_whole_input(self):
        data = (b"x " * 1000 + b'"https://a.example/?p=%25253d' + PID_A.encode() + b'" ') * 200
        tracemalloc.start()
        found = leakcheck.collect(data)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertIn(PID_A.encode(), found)
        self.assertLess(peak, len(data) // 2)  # the old code held up to three decoded copies

    def test_email_pattern_costs_one_step_per_byte(self):
        start = time.time()
        sum(1 for _ in leakcheck.LK_EMAIL.finditer(b"z" * 20000000))  # 20 MB, no "@": ~7 s unanchored
        self.assertLess(time.time() - start, 1.0)

    def test_email_after_an_escape_is_still_found(self):
        kinds = [k for k, _ in leakcheck.scan(b"email%3DJane.Roe%40example.org x.y@z.example.com", set())]
        self.assertEqual(kinds, ["email", "email"])

    def test_collect_prefixes_takes_participant_ids_from_identifiers(self):
        data = f"{IDENT_A} https://x.example/?p={PID_B}".encode()
        self.assertEqual(leakcheck.collect_prefixes(data), {PID_A[:8].encode()})

    def test_scan_finds_id_shorthand(self):
        prefixes = {PID_A[:8].encode()}
        data = f"case weib_{PID_A[:8]} and aimeccplc_{PID_B[:8]} and bare {PID_A[:8]}.".encode()
        self.assertEqual(sorted(k for k, _ in leakcheck.scan(data, set(), prefixes)),
                         ["id-fragment", "id-fragment", "id-prefix", "id-prefix"])

    def test_scan_shorthand_ignores_tokens_uuids_and_other_hex(self):
        prefixes = {PID_A[:8].encode()}
        data = (f"WEIb_ident_0123456789abcdef weib_count {PID_A[:8]}-1111-2222-3333-444455556666 "
                "deadbeef pid_0123456789abcdef").encode()
        self.assertEqual(leakcheck.scan(data, set(), prefixes), [])

    def test_check_shares_no_code_with_the_redactor(self):
        source = Path(leakcheck.__file__).read_text()
        self.assertNotIn("idscan", source)
        self.assertNotIn("privacy.urls", source)

    def test_safe_text_hides_ids(self):
        self.assertNotIn(PID_A, leakcheck.safe_text(f"dir/{IDENT_A}__x.json {PID_A}".encode()))


class LeakCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.raw = self.tmp / "raw"
        red = self.raw / ".redaction"
        red.mkdir(parents=True)
        load_or_create_key(red / "key")
        (red / "leak_known.txt").write_text(PID_A + "\n")
        self.target = self.tmp / "repo"
        (self.target / "docs").mkdir(parents=True)
        (self.target / "docs" / f"{IDENT_A}.md").write_text(f"flagged {PID_A}\n")
        (self.target / "clean.md").write_text("nothing here\n")

    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = leakcheck.main(list(argv))
        return code, buf.getvalue()

    def test_hits_are_reported_without_values(self):
        code, out = self.run_cli("--raw", str(self.raw), str(self.target))
        self.assertEqual(code, 1)
        self.assertIn("hits: 3", out)  # name: identifier + known ID inside it; text: bare 24-hex
        self.assertNotIn(PID_A, out)
        self.assertNotIn(IDENT_A, out)

    def test_clean_target(self):
        code, out = self.run_cli("--raw", str(self.raw), str(self.target / "clean.md"))
        self.assertEqual((code, out.strip()), (0, "hits: 0"))

    def test_unreadable_target_is_reported_without_its_name(self):
        p = self.target / "docs" / f"{IDENT_B}.md"
        p.write_text("x")
        p.chmod(0)
        self.addCleanup(p.chmod, 0o600)
        code, out = self.run_cli("--raw", str(self.raw), str(self.target))
        self.assertEqual(code, 1)
        self.assertIn("unreadable", out)
        self.assertNotIn(PID_B, out)
        self.assertNotIn(IDENT_B, out)

    def test_refuses_inside_claude_on_the_real_folder(self):
        with mock.patch.object(paths, "DEFAULT_RAW", self.raw), mock.patch.dict(os.environ, {"CLAUDECODE": "1"}):
            self.assertEqual(self.run_cli(str(self.target))[0], 2)


if __name__ == "__main__":
    unittest.main()
