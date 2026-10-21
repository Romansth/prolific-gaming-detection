import os
import stat
import tempfile
import unittest
from pathlib import Path

from privacy import paths, tokens


class PathTests(unittest.TestCase):
    def test_out_of_bounds_defaults_sit_next_to_the_repo(self):
        self.assertEqual(paths.DEFAULT_RAW.parent, paths.REPO.parent)
        self.assertEqual(paths.DEFAULT_PROCESSED.parent, paths.REPO.parent)
        self.assertEqual(paths.DEFAULT_SAFE.parent, paths.REPO)
        self.assertEqual(paths.DEFAULT_REPORTS.parent, paths.REPO)

    def test_inside_claude_reads_the_env(self):
        old = os.environ.pop("CLAUDECODE", None)
        try:
            self.assertFalse(paths.inside_claude())
            os.environ["CLAUDECODE"] = "1"
            self.assertTrue(paths.inside_claude())
        finally:
            os.environ.pop("CLAUDECODE", None)
            if old is not None:
                os.environ["CLAUDECODE"] = old


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.key = tokens.load_or_create_key(self.tmp / "k" / "key")

    def test_key_is_created_once_with_mode_600(self):
        self.assertEqual(self.key, tokens.load_or_create_key(self.tmp / "k" / "key"))
        self.assertEqual(len(self.key), 32)
        self.assertEqual(stat.S_IMODE(os.stat(self.tmp / "k" / "key").st_mode), 0o600)

    def test_token_shape_and_determinism(self):
        a = tokens.Tokenizer(self.key).token("pid", "65f1c0de2b7a4e9f8c3d1a20")
        self.assertRegex(a, r"^pid_[0-9a-f]{16}$")  # 64 bits: no collisions at study scale
        self.assertEqual(a, tokens.Tokenizer(self.key).token("pid", "65f1c0de2b7a4e9f8c3d1a20"))

    def test_kind_is_part_of_the_hash(self):
        t = tokens.Tokenizer(self.key)
        self.assertNotEqual(t.token("pid", "x")[4:], t.token("q", "x")[2:])

    def test_another_key_gives_another_token(self):
        self.assertNotEqual(tokens.Tokenizer(self.key).token("pid", "v"),
                            tokens.Tokenizer(b"\x00" * 32).token("pid", "v"))

    def test_collision_is_refused(self):
        tok = tokens.Tokenizer(self.key).token("pid", "a")
        seeded = tokens.Tokenizer(self.key, {tok: ("pid", "something else")})
        with self.assertRaises(tokens.TokenCollision):
            seeded.token("pid", "a")

    def test_unknown_kind_is_rejected(self):
        with self.assertRaises(ValueError):
            tokens.Tokenizer(self.key).token("name", "x")

    def test_added_tracks_only_new_entries(self):
        t = tokens.Tokenizer(self.key)
        tok = t.token("pid", "a")
        t2 = tokens.Tokenizer(self.key, dict(t.lookup))
        t2.token("pid", "a")
        self.assertEqual(t2.added, {})
        self.assertIn(tok, t.added)

    def test_lookup_round_trip_with_awkward_values(self):
        t = tokens.Tokenizer(self.key)
        for v in ["plain", "tab\there", "new\nline", 'quote"s', "x" * 200000]:
            t.token("q", v)
        path = self.tmp / "lookup.tsv"
        tokens.write_lookup(path, t.lookup)
        self.assertEqual(tokens.read_lookup(path), t.lookup)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_merge_detects_conflict(self):
        into = {"pid_0000000000000000": ("pid", "a")}
        tokens.merge_lookup(into, {"pid_0000000000000000": ("pid", "a")})
        with self.assertRaises(tokens.TokenCollision):
            tokens.merge_lookup(into, {"pid_0000000000000000": ("pid", "b")})


if __name__ == "__main__":
    unittest.main()
