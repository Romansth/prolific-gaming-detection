import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from fraudscreen.files import Input, list_inputs, parse_name, read_points

HEX = "a" * 24


class ParseNameTests(unittest.TestCase):
    def test_parse_name_three_variants(self):
        self.assertEqual(parse_name(f"WEIb_{HEX}1234__rex-history-visit__2026-09-14.json").variant, "plain")
        r = parse_name(f"weib_{HEX}1234__pdk-app-event__recorded_2026-10-01.json")
        self.assertEqual((r.ident, r.generator, r.day, r.variant),
                         (f"weib_{HEX}1234", "pdk-app-event", "2026-10-01", "recorded"))
        self.assertEqual(parse_name("x__y__created_2026-10-01.json").day, "2026-10-01")
        self.assertIsNone(parse_name("notes.txt"))
        self.assertIsNone(parse_name("WEIb_x__gen__2026-10-01.txt"))


class ListInputsTests(unittest.TestCase):
    def test_list_inputs_skips_duplicate_zip(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a__g__2026-01-01.json").write_text("[]")
            with zipfile.ZipFile(root / "a.zip", "w") as z:
                z.writestr("a__g__2026-01-01.json", "[]")
            (root / ".DS_Store").write_bytes(b"\x00")
            found = list_inputs(root)
            self.assertEqual([(i.path.name, i.member) for i in found], [("a__g__2026-01-01.json", None)])

    def test_list_inputs_reads_nested_and_zip_members(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sub").mkdir()
            (root / "sub" / "b__g__2026-01-01.json").write_text("[]")
            with zipfile.ZipFile(root / "c.zip", "w") as z:
                z.writestr("c1__g__2026-01-02.json", "[]")
                z.writestr("inner/c2__g__created_2026-01-03.json", "[]")
                z.writestr("readme.txt", "x")
            found = list_inputs(root)
            self.assertEqual(sorted((i.path.name, i.member) for i in found),
                             [("b__g__2026-01-01.json", None), ("c.zip", "c1__g__2026-01-02.json"),
                              ("c.zip", "inner/c2__g__created_2026-01-03.json")])
            self.assertEqual(found[0].name, found[0].member or found[0].path.name)

    def test_read_points_tolerates_garbage(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "t__g__2026-01-01.json").write_text('[{"a": 1}, {"b": 2')
            (root / "o__g__2026-01-01.json").write_text('{"a": 1}')
            (root / "ok__g__2026-01-01.json").write_text('[{"a": 1}, 5, {"b": 2}]')
            with zipfile.ZipFile(root / "z.zip", "w") as z:
                z.writestr("zz__g__2026-01-01.json", '[{"z": 1}]')
            self.assertEqual(read_points(Input(root / "t__g__2026-01-01.json", None)), [])
            self.assertEqual(read_points(Input(root / "o__g__2026-01-01.json", None)), [])
            self.assertEqual(read_points(Input(root / "ok__g__2026-01-01.json", None)), [{"a": 1}, {"b": 2}])
            self.assertEqual(read_points(Input(root / "z.zip", "zz__g__2026-01-01.json")), [{"z": 1}])
            self.assertEqual(read_points(Input(root / "missing.json", None)), [])


if __name__ == "__main__":
    unittest.main()
