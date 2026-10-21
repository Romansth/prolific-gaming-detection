"""Behaviours pinned by the whole-branch review: the data-boundary guard, scrub coverage, symlinked
pulls, redacted-mode gaps, link-sharing mutuality, Edge-imported duplicates, scoring speed, scan
tolerance, header counts, dead checks, missing US zones, e-mail masking."""
import datetime as dt
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from fraudscreen import hosts, participants as P, tz
from fraudscreen.__main__ import _counts_for_scrub, detect_mode, main, score_all
from fraudscreen.files import Input, read_points
from fraudscreen.fleet import Fleet, build_fleet
from fraudscreen.records import merge_install, new_install
from fraudscreen.report import participant_label, render_markdown
from fraudscreen.scan import scan_one
from fraudscreen.scrub import scrub_text
from fraudscreen.signs import SIGNS, Context, SignResult
from fraudscreen.signs.accounts import score_accounts
from fraudscreen.signs.behaviour import score_behaviour
from fraudscreen.signs.location import score_location
from fraudscreen.signs.machine import score_machine
from privacy.paths import AGENT_ENV_VARS, RAW_FOLDER_NAMES
from tests import synth as S

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / ".claude" / "hooks" / "guard.py"
A, B, C = S.PID_A, S.PID_B, S.PID_C
T = S.T0


def ctx(*ps, raw=True, fleet=None):
    return Context(participants=list(ps), fleet=fleet or Fleet(enrolled_ids={p["key"] for p in ps}), raw_mode=raw)


def guard(tool, tool_input, cwd=None):
    payload = {"tool_name": tool, "tool_input": tool_input, "cwd": cwd or str(ROOT)}
    r = subprocess.run([sys.executable, str(GUARD)], input=json.dumps(payload), capture_output=True, text=True, cwd=str(ROOT))
    return r.returncode, r.stderr


class GuardTests(unittest.TestCase):
    """C1: the hook must stop recursive reads from the repo root, not only calls naming the folders."""

    def test_named_folders_blocked_for_any_tool(self):
        self.assertEqual(guard("Read", {"file_path": "/x/raw-data/oct-10/a.json"})[0], 2)
        self.assertEqual(guard("Edit", {"file_path": "reports-team/x.md", "old_string": "a", "new_string": "b"})[0], 2)
        self.assertEqual(guard("Bash", {"command": "ls .redaction"})[0], 2)

    def test_recursive_commands_from_the_root_blocked(self):
        for cmd in ("find . -name '*.json'", "find", "grep -rn pid_ .", "grep -R x", "rg pid_", "ls -R",
                    "tree", "du -sh *", "cat */*/*.json", "head */*.md", "rg tok ..", "find / -name key",
                    "python3 -c \"import os; print(list(os.walk('.')))\"", "ls -la $CLAUDE_PROJECT_DIR"):
            self.assertEqual(guard("Bash", {"command": cmd})[0], 2, cmd)

    def test_scoped_commands_allowed(self):
        for cmd in ("grep -rn pid_ data-redacted/oct-10 reports/", "rg pid_ reports/", "ls", "ls -la fraudscreen",
                    "cat README.md", "python3 -m unittest discover -s tests -t .", "grep -n foo fraudscreen/scan.py",
                    "find fraudscreen -name '*.py'", "make test", "python3 -m fraudscreen --data data-redacted/oct-10",
                    "python3 -m fraudscreen.lookup 65f1c0de2b7a4e9f8c3d1a20", "git status", "cat tests/*.py | wc -l",
                    "python3 -c \"import os; print(os.walk('data-redacted/oct-10'))\""):
            rc, err = guard("Bash", {"command": cmd})
            self.assertEqual(rc, 0, f"{cmd}: {err}")

    def test_grep_and_glob_tools_must_be_scoped(self):
        self.assertEqual(guard("Grep", {"pattern": "pid_"})[0], 2)
        self.assertEqual(guard("Grep", {"pattern": "pid_", "path": "."})[0], 2)
        self.assertEqual(guard("Grep", {"pattern": "pid_", "path": "reports"})[0], 0)
        self.assertEqual(guard("Grep", {"pattern": "def main", "path": str(ROOT / "fraudscreen")})[0], 0)
        self.assertEqual(guard("Glob", {"pattern": "**/*.json"})[0], 2)
        self.assertEqual(guard("Glob", {"pattern": "**/*.json", "path": "data-redacted"})[0], 0)

    def test_codex_hook_runs_the_same_guard(self):
        """.codex/hooks.json finds guard.py from any folder of the repo (no git needed, the dist zip has
        none) and blocks the same calls, given the payload shape Codex sends."""
        (group,) = json.loads((ROOT / ".codex" / "hooks.json").read_text())["hooks"]["PreToolUse"]
        for tool in ("Bash", "apply_patch", "view_image"):
            self.assertRegex(tool, group["matcher"])
        command = group["hooks"][0]["command"]
        private = RAW_FOLDER_NAMES[-1]
        cases = (("Bash", "find . -name '*.json'", 2), ("Bash", "rg pid_ reports/", 0),
                 ("apply_patch", f"*** Begin Patch\n*** Add File: {private}/x.json\n+{{}}\n*** End Patch", 2),
                 ("apply_patch", "*** Begin Patch\n*** Add File: tests/x.py\n+pass\n*** End Patch", 0))
        for cwd in (ROOT, ROOT / "tests"):
            for tool, cmd, want in cases:
                payload = {"session_id": "s", "turn_id": "t", "transcript_path": None, "cwd": str(cwd),
                           "hook_event_name": "PreToolUse", "model": "m", "permission_mode": "default",
                           "tool_name": tool, "tool_use_id": "u", "tool_input": {"command": cmd}}
                r = subprocess.run(["sh", "-c", command], input=json.dumps(payload), capture_output=True, text=True, cwd=str(cwd))
                self.assertEqual(r.returncode, want, f"{cwd.name} {tool} {cmd!r}: {r.stderr}")

    def test_screen_refuses_raw_folder_inside_claude(self):
        self._screen_refuses_raw_folder({"CLAUDECODE": "1"})

    def test_screen_refuses_raw_folder_inside_codex(self):
        self._screen_refuses_raw_folder({"CODEX_THREAD_ID": "t"})

    def _screen_refuses_raw_folder(self, agent_env):
        with tempfile.TemporaryDirectory() as d:
            pull = Path(d, "raw-data", "oct-10")
            ident = "WEIb_" + A + "1230"
            S.write_file(pull, ident, "pdk-system-status", "2026-09-14", [S.status(ident)])
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {**{v: "" for v in AGENT_ENV_VARS}, **agent_env}), redirect_stdout(buf):
                code = main(["--data", str(pull), "--workers", "1"])
            self.assertEqual(code, 2)
            self.assertIn("Refusing", buf.getvalue())
            self.assertFalse(list(Path(d).rglob("*_screen_*")))


class ReportPlacementTests(unittest.TestCase):
    """A real-id report must never land in the shareable reports/ folder: the mode comes from the
    file names, a raw screen in the repo layout never writes under reports/, and --out with
    --redact outside the repo keeps the team report beside the scrubbed one."""

    def _raw_pull(self, pull):
        ident = "WEIb_" + A + "1230"
        S.write_file(pull, ident, "rex-history-visit", "2026-09-14", S.news(ident, 5))
        S.write_file(pull, ident, "pdk-system-status", "2026-09-14", [S.status(ident)])
        return ident

    def test_stray_identifiers_csv_does_not_make_a_raw_pull_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            pull = Path(d, "oct-10"); self._raw_pull(pull)
            Path(d, "identifiers.csv").write_text("ident,prefix,pid,pid_created,install\n")
            self.assertEqual(detect_mode(pull), "raw")
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {v: "" for v in AGENT_ENV_VARS}), redirect_stdout(buf):
                code = main(["--data", str(pull), "--redact", "--key-dir", str(Path(d, "key")), "--workers", "1"])
            self.assertEqual(code, 0, buf.getvalue())
            today = dt.date.today().isoformat()
            self.assertIn("Mode: raw", Path(d, f"oct-10_screen_{today}_team.md").read_text())
            self.assertNotIn(A, Path(d, f"oct-10_screen_{today}.md").read_text())

    def test_raw_files_under_data_redacted_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            pull = Path(d, "repo", "data-redacted", "oct-10"); self._raw_pull(pull)
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--data", str(pull), "--workers", "1"])
            self.assertEqual(code, 2)
            self.assertIn("Refusing", buf.getvalue())
            self.assertFalse(Path(d, "repo", "reports").exists())

    def test_out_under_reports_refused_for_raw_data(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d, "repo"); pull = repo / RAW_FOLDER_NAMES[-1] / "oct-10"; self._raw_pull(pull)
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {v: "" for v in AGENT_ENV_VARS}), redirect_stdout(buf):
                code = main(["--data", str(pull), "--out", str(repo / "reports" / "x.md"), "--workers", "1"])
            self.assertEqual(code, 2)
            self.assertFalse((repo / "reports" / "x.md").exists())

    def test_out_with_redact_outside_repo_keeps_both_reports(self):
        with tempfile.TemporaryDirectory() as d:
            pull = Path(d, "pull"); self._raw_pull(pull)
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {v: "" for v in AGENT_ENV_VARS}), redirect_stdout(buf):
                code = main(["--data", str(pull), "--redact", "--out", str(Path(d, "r.md")), "--key-dir", str(Path(d, "key")), "--workers", "1"])
            self.assertEqual(code, 0, buf.getvalue())
            self.assertIn(A, Path(d, "r_team.csv").read_text())   # the csv lists every participant
            self.assertNotIn(A, Path(d, "r.csv").read_text())
            self.assertIn("# Participant screen: pull\n", Path(d, "r.md").read_text())

    def test_csv_under_reports_refused_for_raw_data(self):
        """The CSV lists every participant with its real id; it is as sensitive as the report."""
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d, "repo"); pull = repo / RAW_FOLDER_NAMES[-1] / "oct-10"; self._raw_pull(pull)
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {v: "" for v in AGENT_ENV_VARS}), redirect_stdout(buf):
                code = main(["--data", str(pull), "--csv", str(repo / "reports" / "x.csv"), "--workers", "1"])
            self.assertEqual(code, 2)
            self.assertFalse((repo / "reports" / "x.csv").exists())

    def test_out_into_reports_refused_for_a_pull_outside_the_layout(self):
        """A pull in Downloads screened with --out into a repo's reports/: the folder is recognised by
        what sits beside it, not by where the data came from; with --redact the _team file would land there."""
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d, "repo"); (repo / RAW_FOLDER_NAMES[-1]).mkdir(parents=True)
            pull = Path(d, "Downloads", "oct-10"); self._raw_pull(pull)
            for extra in ([], ["--redact", "--key-dir", str(Path(d, "key"))]):
                buf = io.StringIO()
                with mock.patch.dict(os.environ, {v: "" for v in AGENT_ENV_VARS}), redirect_stdout(buf):
                    code = main(["--data", str(pull), "--out", str(repo / "reports" / "x.md"), "--workers", "1"] + extra)
                self.assertEqual(code, 2, extra)
                self.assertFalse((repo / "reports").exists() and list((repo / "reports").iterdir()), extra)

    def test_case_variant_of_reports_refused(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d, "repo"); pull = repo / RAW_FOLDER_NAMES[-1] / "oct-10"; self._raw_pull(pull)
            (repo / "reports").mkdir()
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {v: "" for v in AGENT_ENV_VARS}), redirect_stdout(buf):
                code = main(["--data", str(pull), "--out", str(repo / "Reports" / "x.md"), "--workers", "1"])
            self.assertEqual(code, 2)
            self.assertFalse(list((repo / "reports").iterdir()))

    def test_one_raw_file_among_many_token_files_makes_the_pull_raw(self):
        """detect_mode must look at every name, not the first 200."""
        with tempfile.TemporaryDirectory() as d:
            pull = Path(d, "oct-10"); pull.mkdir()
            for i in range(201):
                Path(pull, f"ident_{i:016x}__pdk-app-event__2026-09-14.json").write_text("[]")
            Path(pull, f"weib_{A}1230__pdk-app-event__2026-09-14.json").write_text("[]")   # sorts after the 201
            self.assertEqual(detect_mode(pull), "raw")

    def test_symlink_into_raw_folder_refused_inside_agent(self):
        with tempfile.TemporaryDirectory() as d:
            real = Path(d, RAW_FOLDER_NAMES[-1], "oct-10"); self._raw_pull(real)
            os.symlink(real, Path(d, "link"))
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {"CLAUDECODE": "1"}), redirect_stdout(buf):
                self.assertEqual(main(["--data", str(Path(d, "link")), "--workers", "1"]), 2)


class ScrubCoverageTests(unittest.TestCase):
    """I1: everything the redactor tokenizes in the data is tokenized in the scrubbed report."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key_dir = Path(self.tmp.name, ".redaction")

    def tearDown(self):
        self.tmp.cleanup()

    def test_device_ids_become_dev_tokens(self):
        out = scrub_text("id shared-run-id: this 2026 (3 pts); " + B + " 2026", self.key_dir, device_ids={"shared-run-id"})
        self.assertNotIn("shared-run-id", out)
        self.assertRegex(out, r"id dev_[0-9a-f]{16}:")

    def test_plain_text_rare_host_becomes_host_token(self):
        text = "hl=es on www.janes-family-blog.example · typed study link on blog.example"
        out = scrub_text(text, self.key_dir, host_counts={"www.janes-family-blog.example": 1, "blog.example": 7})
        self.assertNotIn("janes-family-blog", out)
        self.assertRegex(out, r"hl=es on host_[0-9a-f]{16} ")
        self.assertIn("on blog.example", out)

    def test_rare_prefix_reduced_to_study_stem(self):
        out = scrub_text(f"{A} (WEIb/WEIx)\n{B} (AIMECcplc)", self.key_dir, prefix_counts={"weib_": 9, "weix_": 1, "aimeccplc_": 2})
        self.assertNotIn("WEIx", out)
        self.assertNotIn("AIMECcplc", out)
        self.assertIn("(WEIb/WEI…)", out)
        self.assertIn("(AIMEC…)", out)

    def test_full_prefix_label_lets_the_rare_one_be_hidden(self):
        """'(AIMECcplc/eplc)' left 'eplc' readable: the rare-prefix rule needs the whole word."""
        p = S.mk_participant(A, prefixes=("AIMECcplc", "AIMECeplc"))
        self.assertEqual(participant_label(p), f"{A} (AIMECcplc/AIMECeplc)")
        out = scrub_text(participant_label(p), self.key_dir, prefix_counts={"aimeccplc_": 9, "aimeceplc_": 1})
        self.assertNotIn("eplc", out)
        self.assertIn("(AIMECcplc/AIMEC…)", out)

    def test_scrub_counts_digit_prefixes_like_the_redactor(self):
        """WEIb2_ is a cohort prefix to the redactor; the scrub must count it too or '(WEIb2)' stays readable."""
        installs = {"WEIb2_" + A + "1230": new_install("WEIb2_" + A + "1230"), "WEIb_" + B + "1230": new_install("WEIb_" + B + "1230")}
        _, prefixes, _ = _counts_for_scrub([], installs)
        self.assertEqual(prefixes, {"weib2_": 1, "weib_": 1})

    def test_scrub_leaves_ordinary_words_and_short_ids(self):
        """A prefix the redactor would not recognise, or a device id of '1', must not rewrite prose."""
        text = "**M1 Second Prolific id** Count: 1 None"
        out = scrub_text(text, self.key_dir, prefix_counts={"prolific_": 1}, device_ids={"1", "None", "long-device-id"})
        self.assertEqual(out, text)

    def test_typed_link_and_rlz_evidence_are_urls(self):
        links = [S.mk_visit(f"https://survey.example/s?PROLIFIC_PID={A}&SESSION_ID={i:024x}", ts=T + i * 100,
                            transition="typed", visit_id=i + 1) for i in range(8)]
        p = S.mk_participant(A, visits=links)
        r = score_behaviour(p, ctx(p))
        self.assertTrue(r["m11"].fired)
        self.assertTrue(any(e.what.startswith("typed study link: https://survey.example/s?") for e in r["m11"].evidence))
        p = S.mk_participant(A, visits=[S.mk_visit("https://www.google.com/search?q=weather&rlz=1C1ONGR_enVE1180VE1180", ts=T)])
        r = score_location(p, ctx(p))
        self.assertTrue(r["M6"].fired)
        self.assertIn("https://www.google.com/search?", r["M6"].evidence[0].what)


class SymlinkTests(unittest.TestCase):
    """I2: a pull symlinked under raw-data/ keeps the repo layout and the shared key."""

    def test_symlinked_pull_uses_repo_layout(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d, "repo")
            real = Path(d, "ext", "oct-10")
            ident = "WEIb_" + A + "1230"
            S.write_file(real, ident, "rex-history-visit", "2026-09-14",
                         [S.visit(ident, "https://start.adspower.net/?id=k1&host=127.0.0.1:20725", 1, transition_type="auto_toplevel")])
            S.write_file(real, ident, "pdk-system-status", "2026-09-14", [S.status(ident)])
            (repo / "raw-data").mkdir(parents=True)
            os.symlink(real, repo / "raw-data" / "oct-10")
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {v: "" for v in AGENT_ENV_VARS}), redirect_stdout(buf):
                code = main(["--data", str(repo / "raw-data" / "oct-10"), "--redact", "--workers", "1"])
            self.assertEqual(code, 0, buf.getvalue())
            self.assertTrue(list((repo / "reports-team").glob("oct-10_screen_*.md")), buf.getvalue())
            self.assertTrue(list((repo / "reports").glob("oct-10_screen_*.md")))
            self.assertTrue((repo / "raw-data" / ".redaction" / "key").exists())
            self.assertTrue((repo / "data-redacted" / "oct-10" / "identifiers.csv").exists())
            self.assertFalse((real / ".redaction").exists())
            self.assertFalse(list(Path(d, "ext").glob("*_screen_*")))


class RedactedModeTests(unittest.TestCase):
    """I3: internal ids skipped, raw-only signs n/a, case variants merged, distinct report name."""

    def test_token_without_pid_is_not_a_participant(self):
        idmap = {"ident_" + "a" * 16: ("", "", "", "ident_" + "a" * 16)}
        self.assertIsNone(P.parse_ident("ident_" + "a" * 16, idmap))

    def test_raw_only_signs_unavailable_in_redacted_mode(self):
        p = S.mk_participant("pid_" + "a" * 16, visits=[S.mk_visit("https://news.example/1")])
        res = score_all([p], build_fleet([p], 50), raw_mode=False)[p["key"]]
        self.assertFalse(res["M3"].available)
        self.assertFalse(res["M3"].fired)
        self.assertIn("not available in redacted mode", res["M3"].notes[0])
        res = score_all([p], build_fleet([p], 50), raw_mode=True)[p["key"]]
        self.assertTrue(res["M3"].available)

    def test_case_variants_merge_through_install_column(self):
        with tempfile.TemporaryDirectory() as d:
            up, lo, pid = "ident_" + "1" * 16, "ident_" + "2" * 16, "pid_" + "a" * 16
            Path(d, "identifiers.csv").write_text("ident,prefix,pid,pid_created,install\n"
                                                  f"{up},WEIb,{pid},2024-03,{lo}\n{lo},,{pid},2024-03,{lo}\n")
            installs = {}
            for ident in (up, lo):
                inst = new_install(ident)
                inst["visits"] = [S.mk_visit("https://host_x/url_y", ts=T, visit_id=1)]
                inst["status"] = [S.mk_status()]
                installs[ident] = inst
            parts, skipped = P.group(installs, Path(d, "identifiers.csv"), P.default_exclude())
            self.assertEqual(len(parts), 1)
            self.assertEqual(len(parts[0]["installs"]), 1)
            self.assertEqual(len(parts[0]["installs"][0]["visits"]), 1)
            self.assertEqual(parts[0]["prefixes"], {"WEIb"})


class LinkSharingTests(unittest.TestCase):
    """I5: the mutual clause of m3 needs both directions."""

    def test_one_way_carry_is_not_mutual(self):
        pa = S.mk_participant(A, visits=[S.mk_visit(f"https://x.qualtrics.com/jfe/form/SV_1?PROLIFIC_PID={C}", ts=T)])
        pc = S.mk_participant(C, visits=[S.mk_visit("https://news.example/1", ts=T)])
        fleet = Fleet(enrolled_ids={A, C}, foreign_id_owners={C: {A}})
        self.assertFalse(score_accounts(pa, ctx(pa, pc, fleet=fleet))["m3"].fired)
        self.assertFalse(score_accounts(pc, ctx(pa, pc, fleet=fleet))["m3"].fired)


class EdgeImportTests(unittest.TestCase):
    """I6: an Edge install's imported copy of a Chrome visit is not a second, local, visit."""

    def test_imported_copy_dropped_keeping_chrome_locality(self):
        url = f"https://app.prolific.com/submissions/complete?cc=X&PROLIFIC_PID={B}"
        ia = new_install("AIMECcplc_" + A + "1230")
        ia["visits"] = [S.mk_visit(url, ts=T, is_local=False, visit_id=40)]
        ia["status"] = [S.mk_status(browser="Chrome")]
        ib = new_install("AIMECeplc_" + A + "1231")
        ib["visits"] = [S.mk_visit(url, ts=T, is_local=True, visit_id=3), S.mk_visit("https://news.example/e", ts=T + 50, visit_id=4)]
        ib["status"] = [S.mk_status(browser="Edge")]
        parts, _ = P.group({ia["ident"]: ia, ib["ident"]: ib}, None, [])
        self.assertEqual(len(parts), 1)
        visits = [v for inst in parts[0]["installs"] for v in inst["visits"]]
        self.assertEqual(len(visits), 2)
        self.assertEqual([v.is_local for v in visits if v.host == "app.prolific.com"], [False])
        r = score_accounts(parts[0], ctx(parts[0]))
        self.assertFalse(r["M1"].fired)
        self.assertTrue(r["m2"].fired)


class SpeedTests(unittest.TestCase):
    """I7: scoring a heavy 30-day install must not take minutes."""

    def test_display_churn_window_is_linear(self):
        sizes = [(1366, 768), (1920, 1080), (1280, 720)]     # three sizes: the window never fires, so every point is scanned
        st = [S.mk_status(ts=T + i * 60, displays=(("d%d" % (i % 3), sizes[i % 3][0], sizes[i % 3][1], "Generic PnP Monitor"),))
              for i in range(8000)]
        p = S.mk_participant(A, status=st)
        t0 = time.perf_counter()
        r = score_machine(p, ctx(p))
        self.assertLess(time.perf_counter() - t0, 2.0)
        self.assertFalse(r["m5"].fired)

    def test_classify_is_cached(self):
        names = ["h%d.example" % i for i in range(1000)]
        for h in names:
            hosts.classify(h)
        t0 = time.perf_counter()
        for _ in range(200):
            for h in names:
                hosts.classify(h)
        self.assertLess(time.perf_counter() - t0, 0.5)


class ScanToleranceTests(unittest.TestCase):
    """I8: odd shapes inside a point never abort the run; unreadable files are counted and shown."""

    def _inp(self, d, name, obj):
        path = Path(d, name)
        path.write_text(json.dumps(obj))
        return Input(path, None)

    def test_non_dict_fields_do_not_raise(self):
        ident = "WEIb_" + A + "1230"
        with tempfile.TemporaryDirectory() as d:
            pts = [{"passive-data-metadata": "x", "url": "https://a.example/"},
                   dict(S.status(ident), **{"cpu-info": 5, "memory-info": [], "storage-info": 3, "display-info": "y"}),
                   dict(S.event(ident, "rex-history-collection-complete", count=3), event_details=[]),
                   dict(S.visit(ident, "https://b.example/", 2), _pdk_trace_context="t")]
            for p in pts:
                if isinstance(p.get("passive-data-metadata"), dict):
                    p["passive-data-metadata"]["configuration-hash"] = 7
            for gen in ("rex-history-visit", "pdk-system-status", "pdk-app-event"):
                inst = scan_one(self._inp(d, f"{ident}__{gen}__2026-09-14.json", pts), True)[1]
                self.assertEqual(inst["unreadable"], 0)

    def test_corrupt_zip_member_is_unreadable_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            z = Path(d, "x.zip")
            name = "WEIb_" + A + "1230__pdk-system-status__2026-09-14.json"
            with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(name, json.dumps([S.status("WEIb_" + A + "1230")]))
            raw = bytearray(z.read_bytes())
            raw[30 + len(name):30 + len(name) + 8] = b"\0" * 8     # corrupt the compressed stream
            z.write_bytes(bytes(raw))
            self.assertEqual(read_points(Input(z, name)), [])

    def test_header_and_exit_name_files_not_read(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "bad.zip").write_bytes(b"PK\x03\x04 truncated")
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(main(["--data", d, "--workers", "1"]), 3)
            self.assertIn("corrupt_zip 1", buf.getvalue())
            ident = "WEIb_" + A + "1230"
            S.write_file(d, ident, "pdk-system-status", "2026-09-14", [S.status(ident)])
            S.write_file(d, ident, "rex-history-visit", "2026-09-14", [S.visit(ident, "https://news.example/", 1)])
            with redirect_stdout(buf):
                self.assertEqual(main(["--data", d, "--workers", "1", "--out", str(Path(d, "r.md"))]), 0)
            self.assertIn("Files not read: corrupt_zip 1.", Path(d, "r.md").read_text())
            self.assertIn("Visits without a time: 0.", Path(d, "r.md").read_text())

    def test_header_reports_unreadable_files_and_merged_installs(self):
        with tempfile.TemporaryDirectory() as d:
            ident = "WEIb_" + A + "1230"
            S.write_file(d, ident, "rex-history-visit", "2026-09-14", [S.visit(ident, "https://whoer.net/", 1, transition_type="typed")])
            S.write_file(d, ident.lower(), "rex-history-visit", "2026-09-15", [S.visit(ident, "https://whoer.net/", 2, ts=T + 86400, transition_type="typed")])
            S.write_file(d, ident, "pdk-system-status", "2026-09-14", [S.status(ident)])
            Path(d, f"{ident}__pdk-app-event__2026-09-14.json").write_text("[{\"truncated\": ")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--data", d, "--workers", "1", "--out", str(Path(d, "r.md"))])
            self.assertEqual(code, 0, buf.getvalue())
            md = Path(d, "r.md").read_text()
            self.assertIn("Installs: 1.", md)
            self.assertIn("Unreadable files: 1", md)


class DeadCheckTests(unittest.TestCase):
    """I9: the headless flag survives merging; non-English Google titles are counted in raw mode."""

    def test_headless_flag_reaches_the_participant(self):
        ident = "WEIb_" + A + "1230"
        with tempfile.TemporaryDirectory() as d:
            pts = [S.visit(ident, "https://news.example/%d" % i, i + 1, ts=T + i * 10,
                           ua="Mozilla/5.0 (Windows NT 10.0) HeadlessChrome/152.0.0.0 Safari/537.36") for i in range(3)]
            path = Path(d, f"{ident}__rex-history-visit__2026-09-14.json")
            path.write_text(json.dumps(pts))
            part = scan_one(Input(path, None), True)[1]
            self.assertTrue(part.get("headless"))
            inst = new_install(ident)
            merge_install(inst, part)
            self.assertTrue(inst.get("headless"))
            parts, _ = P.group({ident: inst}, None, [])
            r = score_behaviour(parts[0], ctx(parts[0]))
            self.assertTrue(r["m14"].fired)
            self.assertIn("headless", r["m14"].evidence[0].what)

    def test_non_english_google_titles_counted_in_raw_mode_only(self):
        ident = "WEIb_" + A + "1230"
        with tempfile.TemporaryDirectory() as d:
            pts = [S.visit(ident, "https://www.google.com/search?q=clima", 1, title="clima - Buscar con Google"),
                   S.visit(ident, "https://www.google.com/search?q=rain", 2, ts=T + 5, title="rain - Google Search")]
            path = Path(d, f"{ident}__rex-history-visit__2026-09-14.json")
            path.write_text(json.dumps(pts))
            raw = scan_one(Input(path, None), True)[1]
            self.assertEqual(raw["nonen_titles"], {"Buscar con Google": 1})
            self.assertEqual(scan_one(Input(path, None), False)[1]["nonen_titles"], {})
            inst = new_install(ident)
            merge_install(inst, raw)
            parts, _ = P.group({ident: inst}, None, [])
            r = score_location(parts[0], ctx(parts[0]))
            self.assertTrue(r["m13"].fired)
            self.assertIn("Buscar con Google", r["m13"].evidence[0].what)


class ZoneTests(unittest.TestCase):
    """Missing US zones must not read as a non-US clock."""

    def test_remaining_us_zones(self):
        for z in ("America/Menominee", "America/North_Dakota/Center", "America/North_Dakota/New_Salem",
                  "America/North_Dakota/Beulah", "America/Nome", "America/Sitka", "America/Yakutat",
                  "America/Metlakatla", "Pacific/Guam", "Pacific/Saipan", "Pacific/Pago_Pago", "America/St_Thomas",
                  "America/Louisville", "America/Fort_Wayne", "America/Shiprock", "America/Atka", "US/Samoa"):
            self.assertTrue(tz.is_us_zone(z), z)
        with mock.patch.object(tz, "USE_ZONEINFO", False):
            self.assertEqual(tz.offset_hours("America/Kentucky/Louisville", 1789345395), -4)   # September: DST
            self.assertEqual(tz.offset_hours("America/Menominee", 1789345395), -5)
            self.assertEqual(tz.offset_hours("Pacific/Guam", 1789345395), 10)


class EmailMaskTests(unittest.TestCase):
    """The team report carries real ids but never an e-mail address."""

    def test_email_in_evidence_masked(self):
        p = S.mk_participant(A, visits=[S.mk_visit("https://accounts.google.co.ke/accounts/SetSID?login_hint=jane.doe%40example.com", ts=T),
                                        S.mk_visit("https://accounts.google.co.ke/accounts/SetSID?login_hint=jane.doe@example.com", ts=T + 8 * 86400, visit_id=2)])
        res = {A: score_location(p, ctx(p))}
        for s in SIGNS:
            res[A].setdefault(s.id, SignResult(s.id))
        md = render_markdown(res, [p], Fleet(), {"participants": 1})
        self.assertTrue(res[A]["M4"].fired)
        self.assertNotIn("jane.doe", md)
        self.assertIn("[email]", md)


if __name__ == "__main__":
    unittest.main()
