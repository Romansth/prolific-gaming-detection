import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests import synth as S

HERE = Path(__file__).resolve().parent.parent
A, B = S.PID_A, S.PID_B


def run_cli(*args):
    env = dict(os.environ, PYTHONPATH=str(HERE))
    return subprocess.run([sys.executable, "-m", "fraudscreen", *args], cwd=str(HERE), env=env, capture_output=True, text=True)


def small_folder(d, launch=True):
    ident = "WEIb_" + A + "1230"
    vs = [S.visit(ident, "https://start.adspower.net/?id=k1&host=127.0.0.1:20725", 1, transition_type="auto_toplevel")] if launch else []
    vs += [S.visit(ident, "https://news.example/%d" % i, i + 2, ts=S.T0 + 60 + i) for i in range(5)]
    S.write_file(d, ident, "rex-history-visit", "2026-09-14", vs)
    S.write_file(d, ident, "pdk-system-status", "2026-09-14", [S.status(ident)])
    S.write_file(d, ident, "ai-market-add-identifier", "2026-09-14", [S.add_identifier(ident, ts=S.T0 - 5)])
    return ident


class CliTests(unittest.TestCase):
    def test_writes_report_and_csv(self):
        with tempfile.TemporaryDirectory() as d:
            data = Path(d, "pull_x"); data.mkdir()
            small_folder(data)
            r = run_cli("--data", str(data), "--workers", "1")
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            reports = list(Path(d).glob("pull_x_screen_*.md"))
            self.assertEqual(len(reports), 1)
            md = reports[0].read_text()
            self.assertIn(A + " (WEIb)", md)
            self.assertIn("M3", md)
            self.assertIn("Mode: raw", md)
            self.assertTrue(list(Path(d).glob("pull_x_screen_*.csv")))
            self.assertIn("1 participants carry", md)

    def test_exit_3_on_only_internal_ids(self):
        with tempfile.TemporaryDirectory() as d:
            ident = "WEIplaywrightCC_test07300000000000"
            S.write_file(d, ident, "pdk-system-status", "2026-09-14", [S.status(ident)])
            r = run_cli("--data", d, "--workers", "1")
            self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
            self.assertIn("internal", r.stdout + r.stderr)

    def test_exit_2_on_missing_folder(self):
        r = run_cli("--data", "/nonexistent/folder/x")
        self.assertEqual(r.returncode, 2)

    def test_redacted_mode_detected_and_out_option(self):
        with tempfile.TemporaryDirectory() as d:
            data = Path(d, "pull_r"); data.mkdir()
            ident = "WEIb_ident_0123456789abcdef"
            Path(data, "identifiers.csv").write_text("ident,prefix,pid,pid_created\nident_0123456789abcdef,WEIb_,pid_fedcba9876543210,2026-09\n")
            S.write_file(data, ident, "rex-history-visit", "2026-09-14",
                         [S.visit(ident, "https://accounts.google.co.ke/accounts/SetSID", 1),
                          S.visit(ident, "https://accounts.google.co.ke/accounts/SetSID", 2, ts=S.T0 + 10 * 86400)])
            S.write_file(data, ident, "pdk-system-status", "2026-09-14", [S.status(ident)])
            out = Path(d, "custom.md")
            r = run_cli("--data", str(data), "--workers", "1", "--out", str(out))
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            md = out.read_text()
            self.assertIn("Mode: redacted", md)
            self.assertIn("pid_fedcba9876543210", md)
            self.assertIn("n/a", md)   # m12 unavailable
            self.assertIn("M4", md)

    def test_arm_resolution(self):
        with tempfile.TemporaryDirectory() as d:
            data = Path(d, "pull_a"); data.mkdir()
            small_folder(data)
            Path(d, "arms.json").write_text(json.dumps({"4016cabf0000": "WebEatsItself_CC"}))
            r = run_cli("--data", str(data), "--workers", "1", "--arms", str(Path(d, "arms.json")))
            self.assertEqual(r.returncode, 0, r.stderr)
            md = list(Path(d).glob("pull_a_screen_*.md"))[0].read_text()
            self.assertIn("WebEatsItself_CC", md)


if __name__ == "__main__":
    unittest.main()
