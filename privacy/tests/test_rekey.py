import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from privacy import paths, redact, rekey_notes, tokens
from privacy.idscan import IdScanner
from privacy.tests import fixtures as fx


class RekeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.raw = fx.build_raw(self.tmp / "raw")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(redact.main(["--raw", str(self.raw), "--safe", str(self.tmp / "safe"),
                                          "--workers", "1", "--host-threshold", "2"]), 0)
        self.notes = self.tmp / "memory"
        self.notes.mkdir()
        self.note = self.notes / "gaming.md"
        self.original = (f"case {fx.IDENT_A}; fragment WEIb_{fx.PID_A[:8]}; bare {fx.PID_B[:8]}; "
                         f"session 84037730-4252; full {fx.PID_C}\n")
        self.note.write_text(self.original)
        self.t = tokens.Tokenizer(tokens.load_or_create_key(self.raw / ".redaction" / "key"))

    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = rekey_notes.main(["--notes", str(self.notes), "--raw", str(self.raw), *argv])
        return code, buf.getvalue()

    def test_ids_and_fragments_become_tokens(self):
        code, out = self.run_cli()
        self.assertEqual(code, 0, out)
        ident_a = self.t.token("ident", fx.IDENT_A)
        self.assertEqual(self.note.read_text(),
                         f"case {ident_a}; fragment {ident_a}; bare {self.t.token('pid', fx.PID_B)}; "
                         f"session 84037730-4252; full {self.t.token('pid', fx.PID_C)}\n")
        backups = list((self.raw / ".redaction").glob("notes-backup-*/gaming.md"))
        self.assertEqual([b.read_text() for b in backups], [self.original])
        for value in fx.PLANTED:
            self.assertNotIn(value, out)

    def test_dry_run_changes_nothing(self):
        code, out = self.run_cli("--dry-run")
        self.assertEqual(code, 0)
        self.assertEqual(self.note.read_text(), self.original)
        self.assertIn("gaming.md", out)

    def test_ambiguous_prefix_is_left_alone(self):
        scanner = IdScanner(tokens.Tokenizer(b"k" * 32), threshold=10 ** 9)
        pids = [("pid_aaaaaaaaaaaaaaaa", "65f1c0de" + "0" * 16), ("pid_bbbbbbbbbbbbbbbb", "65f1c0de" + "1" * 16)]
        text, counts = rekey_notes.rekey_text("see 65f1c0de here", scanner, [], pids, pids)
        self.assertEqual((text, counts["ambiguous"]), ("see 65f1c0de here", 1))

    def test_refuses_inside_claude_on_the_real_folder(self):
        with mock.patch.object(paths, "DEFAULT_RAW", self.raw), mock.patch.dict(os.environ, {"CLAUDECODE": "1"}):
            with redirect_stdout(io.StringIO()):
                code = rekey_notes.main(["--notes", str(self.notes)])
        self.assertEqual(code, 2)
        self.assertEqual(self.note.read_text(), self.original)


if __name__ == "__main__":
    unittest.main()
