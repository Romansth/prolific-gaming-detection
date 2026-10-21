"""The repo flow: one command on raw-data/<pull> writes the team report (real ids) into
reports-team/, the redacted data into data-redacted/<pull>, and the scrubbed report into reports/;
lookup turns a real id into the token the scrubbed report uses."""
import io
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from fraudscreen.__main__ import main
from fraudscreen.lookup import main as lookup_main
from tests import synth as S

HEX24 = re.compile(r"\b[0-9a-f]{24}\b")


class FlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.repo = Path(cls.tmp.name, "prolific-gaming-detection")
        cls.pull = cls.repo / "raw-data" / "oct-10"
        cls.expected = S.build_folder(cls.pull)
        buf = io.StringIO()
        with mock.patch.dict(os.environ, {"CLAUDECODE": ""}), redirect_stdout(buf):
            cls.code = main(["--data", str(cls.pull), "--redact", "--workers", "2"])
        cls.stdout = buf.getvalue()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_three_outputs(self):
        self.assertEqual(self.code, 0, self.stdout)
        team = list((self.repo / "reports-team").glob("oct-10_screen_????-??-??.md"))
        pub = list((self.repo / "reports").glob("oct-10_screen_????-??-??.md"))
        self.assertEqual((len(team), len(pub)), (1, 1), self.stdout)
        self.assertTrue((self.repo / "data-redacted" / "oct-10" / "identifiers.csv").exists())
        self.assertTrue((self.repo / "raw-data" / ".redaction" / "key").exists())
        self.assertTrue(team[0].with_suffix(".csv").exists() and pub[0].with_suffix(".csv").exists())

    def test_team_report_has_real_ids_and_public_report_has_tokens(self):
        team = next((self.repo / "reports-team").glob("oct-10_screen_????-??-??.md")).read_text()
        pub = next((self.repo / "reports").glob("oct-10_screen_????-??-??.md")).read_text()
        m1_pid = next(pid for pid, exp in self.expected.items() if exp == {"M1"})
        self.assertIn(m1_pid, team)
        self.assertNotIn(m1_pid, pub)
        self.assertEqual(HEX24.findall(pub), [])
        self.assertIn("pid_", pub)
        self.assertIn("(WEIb)", pub)
        self.assertNotIn("shared-run-id", pub)        # M2 evidence names a storage id: a dev token in the data
        self.assertRegex(pub, r"id dev_[0-9a-f]{16}:")
        csv_pub = next((self.repo / "reports").glob("oct-10_screen_????-??-??.csv")).read_text()
        self.assertEqual(HEX24.findall(csv_pub), [])
        # same shape: both reports list the same number of participants
        self.assertEqual(team.count("\n### "), pub.count("\n### "))

    def test_lookup_maps_real_id_to_the_token_in_the_public_report(self):
        m1_pid = next(pid for pid, exp in self.expected.items() if exp == {"M1"})
        pub = next((self.repo / "reports").glob("oct-10_screen_????-??-??.md")).read_text()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = lookup_main([m1_pid, "--key-dir", str(self.repo / "raw-data" / ".redaction")])
        self.assertEqual(code, 0)
        token = buf.getvalue().strip().splitlines()[-1]
        self.assertRegex(token, r"^pid_[0-9a-f]{16}$")
        self.assertIn(token, pub)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = lookup_main(["WEIb_" + m1_pid + "1230", "--key-dir", str(self.repo / "raw-data" / ".redaction")])
        self.assertEqual(code, 0)
        self.assertIn("ident_", buf.getvalue())
        self.assertIn(token, buf.getvalue())

    def test_redacted_mode_screen_gets_its_own_file_name(self):
        pub = next((self.repo / "reports").glob("oct-10_screen_????-??-??.md"))
        before = pub.read_bytes()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["--data", str(self.repo / "data-redacted" / "oct-10"), "--workers", "2"])
        self.assertEqual(code, 0, buf.getvalue())
        self.assertEqual(pub.read_bytes(), before)
        extra = list((self.repo / "reports").glob("oct-10_screen_*_from-redacted.md"))
        self.assertEqual(len(extra), 1, buf.getvalue())
        md = extra[0].read_text()
        self.assertIn("Mode: redacted", md)
        self.assertIn("skipped: no_prolific_id 1", md.split("\n")[2])   # the internal id carries no pid token
        self.assertIn("Installs: 34.", md.split("\n")[2])                # case variants merged through the install column
        self.assertNotIn(" ()", md)

    def test_lookup_finds_key_dir_from_cwd(self):
        m1_pid = next(pid for pid, exp in self.expected.items() if exp == {"M1"})
        cwd = os.getcwd()
        try:
            os.chdir(self.repo / "reports")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = lookup_main([m1_pid])
        finally:
            os.chdir(cwd)
        self.assertEqual(code, 0, buf.getvalue())
        self.assertRegex(buf.getvalue().strip().splitlines()[-1], r"^pid_[0-9a-f]{16}$")


if __name__ == "__main__":
    unittest.main()
