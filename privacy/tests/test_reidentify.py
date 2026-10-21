import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from privacy import paths, redact, reidentify, tokens
from privacy.tests import fixtures as fx


class ReidentifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.raw = fx.build_raw(self.tmp / "raw")
        safe = self.tmp / "safe"
        with redirect_stdout(io.StringIO()):
            code = redact.main(["--raw", str(self.raw), "--safe", str(safe),
                                "--workers", "1", "--host-threshold", "2"])
        self.assertEqual(code, 0)
        self.reports, self.out = self.tmp / "report_claude", self.tmp / "processed"
        self.reports.mkdir()
        t = tokens.Tokenizer(tokens.load_or_create_key(self.raw / ".redaction" / "key"))
        self.ident_a, self.pid_b = t.token("ident", fx.IDENT_A), t.token("pid", fx.PID_B)
        self.q = t.token("q", "jane roe address")
        visits = json.loads((safe / "pdk-export_2099-01-01_1"
                             / f"WEIb_{self.ident_a}__rex-history-visit__2099-01-01.json").read_text())
        self.opaque = visits[5]["url"]  # the someone-personal.example visit, in opaque form

    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = reidentify.main(["--reports", str(self.reports), "--out", str(self.out),
                                    "--key-dir", str(self.raw / ".redaction"), *argv])
        return code, buf.getvalue()

    def test_tokens_become_real_values(self):
        (self.reports / "flags.md").write_text(
            f"WEIb_{self.ident_a} opened a link for {self.pid_b}; query {self.q}; site {self.opaque}\n")
        (self.reports / "flags.csv").write_text(f"ident,flag,other\n{self.ident_a},second_account,{self.pid_b}\n")
        code, out = self.run_cli()
        self.assertEqual(code, 0, out)
        md = (self.out / "flags.md").read_text()
        for value in [fx.IDENT_A, fx.PID_B, "jane roe address",
                      "https://someone-personal.example/blog?email=jane.roe%40example.org"]:
            self.assertIn(value, md)
        self.assertNotIn("ident_", md)
        self.assertNotIn("url_", md)
        self.assertIn(f"{fx.IDENT_A},second_account,{fx.PID_B}", (self.out / "flags.csv").read_text())
        for value in fx.PLANTED:
            self.assertNotIn(value, out)

    def test_binaries_are_copied_and_unknown_tokens_fail(self):
        (self.reports / "fig.png").write_bytes(b"\x89PNG\x00\x01")
        (self.reports / "notes.md").write_text("see pid_0000000000000000\n")
        code, out = self.run_cli()
        self.assertEqual(code, 1)
        self.assertEqual((self.out / "fig.png").read_bytes(), b"\x89PNG\x00\x01")
        self.assertIn("pid_0000000000000000", out)
        self.assertIn("pid_0000000000000000", (self.out / "notes.md").read_text())

    def test_nested_folders_are_mirrored(self):
        (self.reports / "sub" / "deeper").mkdir(parents=True)
        (self.reports / "sub" / "deeper" / "x.txt").write_text(self.pid_b)
        self.assertEqual(self.run_cli()[0], 0)
        self.assertEqual((self.out / "sub" / "deeper" / "x.txt").read_text(), fx.PID_B)

    def test_refuses_inside_claude_on_the_real_paths(self):
        with mock.patch.object(paths, "DEFAULT_RAW", self.raw), mock.patch.dict(os.environ, {"CLAUDECODE": "1"}):
            with redirect_stdout(io.StringIO()):
                code = reidentify.main(["--reports", str(self.reports), "--out", str(self.out)])
        self.assertEqual(code, 2)
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
