import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from privacy.files import FileRedactor
from privacy.idscan import IdScanner
from privacy.points import PointRedactor
from privacy.tokens import Tokenizer
from privacy.urls import Scrubber, UrlRule

PID_A = "65f1c0de2b7a4e9f8c3d1a20"
IDENT_A = "WEIb_" + PID_A + "0015"


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.raw, self.out = self.tmp / "raw", self.tmp / "out"
        self.raw.mkdir()
        tok = Tokenizer(b"k" * 32)
        scanner = IdScanner(tok, known_hex={PID_A}, prefix_counts={"WEIb_": 2}, threshold=2)
        urls = UrlRule(scanner, threshold=2)
        scrub = Scrubber(scanner, urls)
        self.parts = (scanner, PointRedactor(scanner, urls, scrub), scrub)
        self.f = FileRedactor(*self.parts, include_other=True)

    def put(self, rel, data):
        p = self.raw / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return p

    def run_one(self, rel):
        self.f.redact_file(self.raw / rel, Path(rel), self.out)

    def everything_written(self):
        if not self.out.exists():
            return b""
        paths = sorted(self.out.rglob("*"))
        names = " ".join(str(p.relative_to(self.out)) for p in paths).encode()
        return names + b"".join(p.read_bytes() for p in paths if p.is_file())

    def assert_no_ids(self):
        blob = self.everything_written()
        self.assertNotIn(PID_A.encode(), blob.lower())
        self.assertNotIn(IDENT_A.encode(), blob)

    @staticmethod
    def point(n=0):
        return {"passive-data-metadata": {"source": IDENT_A, "generator-id": "rex-history-visit"},
                "url": f"https://app.prolific.com/submissions/{PID_A}", "visit_id": str(n)}

    def test_by_default_only_pdk_exports_are_copied(self):
        f = FileRedactor(*self.parts)
        self.put("x.json", json.dumps([self.point(0)]))
        self.put("scores.json", json.dumps({IDENT_A: 1}))
        self.put("list.json", json.dumps([{"name": "Jane Roe"}]))
        self.put("REPORT.md", "case weib_65f1c0de")
        self.put("flags.csv", "a,b\n1,2\n")
        self.put("p.jsonl", json.dumps(self.point(0)) + "\n")
        for name in ["x.json", "scores.json", "list.json", "REPORT.md", "flags.csv", "p.jsonl"]:
            f.redact_file(self.raw / name, Path(name), self.out)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["x.json"])
        self.assertEqual((f.stats["skipped .json"], f.stats["skipped .md"], f.stats["skipped .csv"],
                          f.stats["skipped .jsonl"]), (2, 1, 1, 1))

    def test_pdk_array_one_point_per_line_and_name_scanned(self):
        name = f"{IDENT_A}__rex-history-visit__2099-01-01.json"
        self.put(name, json.dumps([self.point(0), self.point(1)]))
        self.run_one(name)
        [out] = list(self.out.iterdir())
        self.assertRegex(out.name, r"^WEIb_ident_[0-9a-f]{16}__rex-history-visit__2099-01-01\.json$")
        lines = out.read_text().splitlines()
        self.assertEqual((lines[0], lines[-1], len(lines)), ("[", "]", 4))
        self.assertEqual(len(json.loads(out.read_text())), 2)
        self.assert_no_ids()

    def test_large_array_streams_with_count_intact(self):
        self.put("big.json", json.dumps([self.point(i) for i in range(20000)]))
        self.run_one("big.json")
        self.assertEqual(len(json.loads((self.out / "big.json").read_text())), 20000)
        self.assertEqual(self.f.stats["files json"], 1)

    def test_truncated_export_keeps_whole_points_and_drops_the_rest(self):
        points = [dict(self.point(i), title="Jane Roe | blog") for i in range(2)]
        self.put("cut.json", json.dumps(points)[:-7])
        self.run_one("cut.json")
        out = (self.out / "cut.json").read_text()
        self.assertEqual(len(json.loads(out)), 1)
        self.assertNotIn("Jane Roe", out)
        self.assertEqual(self.f.stats["truncated json"], 1)
        self.assert_no_ids()

    def test_bom_prefixed_export_is_parsed(self):
        self.put("bom.json", b"\xef\xbb\xbf" + json.dumps([dict(self.point(0), title="Jane Roe")]).encode())
        self.run_one("bom.json")
        out = (self.out / "bom.json").read_text()
        self.assertEqual(len(json.loads(out)), 1)
        self.assertNotIn("Jane Roe", out)

    def test_unparseable_json_object_is_not_copied(self):
        self.put("obj.json", '{"passive-data-metadata": {"generator-id": "rex-history-visit"}, "title": "Jane Roe", ')
        self.run_one("obj.json")
        self.assertFalse((self.out / "obj.json").exists())
        self.assertEqual(self.f.stats["unparseable"], 1)

    def test_non_utf8_bytes_are_replaced_not_fatal(self):
        self.put("notes.txt", b"\xff\xfe " + PID_A.encode() + b"\n")
        self.put("t.csv", b"a,b\n\xff," + PID_A.encode() + b"\n")
        self.run_one("notes.txt")
        self.run_one("t.csv")
        self.assertIn("�", (self.out / "notes.txt").read_text())
        self.assert_no_ids()

    def test_generic_json_keys_and_values_are_scrubbed(self):
        self.put("audit/out.json", json.dumps({IDENT_A: {"u": f"https://x.example/?p={PID_A}"}}))
        self.run_one("audit/out.json")
        self.assert_no_ids()

    def test_jsonl_bad_line_is_dropped(self):
        self.put("p.jsonl", json.dumps(self.point(0)) + "\n{not json, title Jane Roe " + PID_A + "\n")
        self.run_one("p.jsonl")
        out = (self.out / "p.jsonl").read_text()
        self.assertEqual(len(out.splitlines()), 1)
        self.assertNotIn("Jane Roe", out)
        self.assertEqual(self.f.stats["bad jsonl lines"], 1)
        self.assert_no_ids()

    def test_prolific_export_csv_is_refused(self):
        self.put("p.csv", f"Participant id,Age\n{PID_A},30\n")
        self.run_one("p.csv")
        self.assertFalse((self.out / "p.csv").exists())
        self.assertEqual(self.f.stats["refused"], 1)

    def test_participant_export_variants_are_refused(self):
        for name, header in [("a.csv", "participant_id,ip_address"), ("b.csv", "workerId,AssignmentId")]:
            self.put(name, f"{header}\n{PID_A},1.2.3.4\n")
            self.run_one(name)
            self.assertFalse((self.out / name).exists(), name)
        self.assertEqual(self.f.stats["refused"], 2)

    def test_csv_that_cannot_be_parsed_is_not_copied(self):
        self.put("nul.csv", f"id,score\n{PID_A},3\x000\n")
        self.run_one("nul.csv")
        self.assertFalse((self.out / "nul.csv").exists())
        self.assertEqual(self.f.stats["unparseable"], 1)

    def test_csv_cells_are_scrubbed_and_header_kept(self):
        self.put("flags.csv", f"identifier,url\n{IDENT_A},https://app.prolific.com/x?pid={PID_A}\n")
        self.run_one("flags.csv")
        self.assertEqual((self.out / "flags.csv").read_text().splitlines()[0], "identifier,url")
        self.assert_no_ids()

    def test_binaries_are_not_copied(self):
        self.put("clip.mp4", b"\x00\x01")
        self.put("c.parquet", b"PAR1")
        self.run_one("clip.mp4")
        self.run_one("c.parquet")
        self.assertFalse(self.out.exists())
        self.assertEqual((self.f.stats["skipped .mp4"], self.f.stats["skipped .parquet"]), (1, 1))

    def test_zip_identical_to_its_folder_is_skipped(self):
        self.put("exp/a.json", json.dumps([self.point(0)]))
        with zipfile.ZipFile(self.raw / "exp.zip", "w") as z:
            z.write(self.raw / "exp/a.json", "a.json")
        self.run_one("exp.zip")
        self.assertEqual(self.f.stats["duplicate_zips"], 1)
        self.assertFalse(self.out.exists())

    def test_zip_members_are_processed_and_named_safely(self):
        with zipfile.ZipFile(self.raw / "other.zip", "w") as z:
            z.writestr(f"{IDENT_A}__x.md", f"flagged {PID_A}\n")
            z.writestr("../evil.txt", "x")
        self.run_one("other.zip")
        [member] = list((self.out / "other__zip").iterdir())
        self.assertRegex(member.name, r"^WEIb_ident_[0-9a-f]{16}__x\.md$")
        self.assertEqual(self.f.stats["unsafe_zip_members"], 1)
        self.assertFalse((self.tmp / "evil.txt").exists())
        self.assert_no_ids()


if __name__ == "__main__":
    unittest.main()
