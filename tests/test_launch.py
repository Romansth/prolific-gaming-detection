"""The zero-argument run: newest pull, redact, open the team page; and --open on an explicit run."""
import datetime as dt
import io
import os
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import fraudscreen.__main__ as M
from privacy.paths import AGENT_ENV_VARS, RAW_FOLDER_NAMES
from tests import synth as S


def small_pull(folder, pid=S.PID_A):
    ident = "WEIb_" + pid + "1230"
    S.write_file(folder, ident, "rex-history-visit", "2026-09-14", S.news(ident, 5))
    S.write_file(folder, ident, "pdk-system-status", "2026-09-14", [S.status(ident)])


class LaunchTests(unittest.TestCase):
    def test_open_flag_opens_the_team_report(self):
        with tempfile.TemporaryDirectory() as d:
            pull = Path(d, "pull"); small_pull(pull)
            with mock.patch("webbrowser.open") as opened, redirect_stdout(io.StringIO()):
                code = M.main(["--data", str(pull), "--out", str(Path(d, "r.html")), "--open", "--workers", "1"])
            self.assertEqual(code, 0)
            opened.assert_called_once_with(Path(d, "r.html").resolve().as_uri())

    def test_no_data_screens_the_newest_pull_redacts_and_opens(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d, "repo")
            old = repo / RAW_FOLDER_NAMES[-1] / "zz-sep-01"; small_pull(old)
            new = repo / RAW_FOLDER_NAMES[-1] / "aa-oct-10"; small_pull(new, pid=S.PID_B)   # first by name, newest by mtime
            (repo / RAW_FOLDER_NAMES[-1] / ".keys").mkdir()                                  # dot-folders are not pulls
            past = time.time() - 86400
            os.utime(old, (past, past))
            buf = io.StringIO()
            with mock.patch.object(M, "REPO_ROOT", repo), mock.patch("webbrowser.open") as opened, \
                    mock.patch.dict(os.environ, {v: "" for v in AGENT_ENV_VARS}), redirect_stdout(buf):
                code = M.main(["--workers", "1"])
            self.assertEqual(code, 0, buf.getvalue())
            self.assertIn("Screening the newest pull: aa-oct-10 (modified ", buf.getvalue())
            self.assertIn("also present: zz-sep-01", buf.getvalue())
            today = dt.date.today().isoformat()
            uri = opened.call_args[0][0]
            self.assertTrue(uri.endswith(f"aa-oct-10_screen_{today}.html"), uri)
            self.assertTrue(Path(uri[len("file://"):]).exists(), uri)
            self.assertTrue(list((repo / "reports").glob(f"aa-oct-10_screen_{today}.html")))   # redacted too

    def test_no_data_without_a_pull_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d, "repo"); (repo / RAW_FOLDER_NAMES[-1]).mkdir(parents=True)
            buf = io.StringIO()
            with mock.patch.object(M, "REPO_ROOT", repo), mock.patch.dict(os.environ, {v: "" for v in AGENT_ENV_VARS}), redirect_stdout(buf):
                code = M.main(["--workers", "1"])
            self.assertEqual(code, 2)
            self.assertIn("No pull found", buf.getvalue())

    def test_no_data_inside_agent_session_refused(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d, "repo"); small_pull(repo / RAW_FOLDER_NAMES[-1] / "oct-10")
            buf = io.StringIO()
            with mock.patch.object(M, "REPO_ROOT", repo), mock.patch("webbrowser.open") as opened, \
                    mock.patch.dict(os.environ, {"CLAUDECODE": "1"}), redirect_stdout(buf):
                code = M.main(["--workers", "1"])
            self.assertEqual(code, 2)
            self.assertIn("Refusing", buf.getvalue())
            self.assertNotIn("oct-10", buf.getvalue())   # the pull folder is never listed, not even its name
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
