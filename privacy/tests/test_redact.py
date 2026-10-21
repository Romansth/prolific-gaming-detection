import csv
import io
import json
import os
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from privacy import paths, redact, tokens, urls
from privacy.tests import fixtures as fx


class RedactEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.raw = fx.build_raw(self.tmp / "raw")
        self.safe = self.tmp / "safe"

    def run_redact(self, *extra, threshold="2", workers="1"):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = redact.main(["--raw", str(self.raw), "--safe", str(self.safe),
                                "--workers", workers, "--host-threshold", threshold, *extra])
        return code, buf.getvalue()

    def snapshot(self):
        return {str(p.relative_to(self.safe)): p.read_bytes() for p in sorted(self.safe.rglob("*"))
                if p.is_file() and p.name != "_redaction_report.txt"}

    def blob(self):
        snap = self.snapshot()
        return (" ".join(snap) + "\n").encode() + b"".join(snap.values()) \
            + (self.safe / "_redaction_report.txt").read_bytes()

    def tok(self):
        return tokens.Tokenizer(tokens.load_or_create_key(self.raw / ".redaction" / "key"))

    def lookup(self):
        return tokens.read_lookup(self.raw / ".redaction" / "lookup.tsv")

    def test_clean_run_leaves_no_planted_value_anywhere(self):
        code, out = self.run_redact()
        self.assertEqual(code, 0, out)
        blob = self.blob().lower()
        for value in fx.PLANTED:
            self.assertNotIn(value.lower().encode(), blob, value)
            self.assertNotIn(value.lower(), out.lower(), value)

    def test_report_and_identifiers_csv(self):
        self.assertEqual(self.run_redact()[0], 0)
        report = (self.safe / "_redaction_report.txt").read_text()
        for line in ["rex-history-visit: mystery_field (1)", "brand-new-gen: payload.secret (1)",
                     ".mp4 1", ".parquet 1", ".csv 2", ".md 1", "duplicate_zips: 1",
                     "identifier prefixes shown: WEIb_", "leak check: clean"]:
            self.assertIn(line, report)
        with open(self.safe / "identifiers.csv", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual({r["pid_created"] for r in rows}, {"2024-03", "2026-10", "2023-09"})
        self.assertEqual(sorted(r["prefix"] for r in rows), ["", "WEIb_", "WEIb_"])

    def test_second_account_signal_survives(self):
        self.assertEqual(self.run_redact()[0], 0)
        t = self.tok()
        ident_a, ident_b = t.token("ident", fx.IDENT_A), t.token("ident", fx.IDENT_B)
        pid_b = t.token("pid", fx.PID_B)
        path = self.safe / "pdk-export_2099-01-01_1" / f"WEIb_{ident_a}__rex-history-visit__2099-01-01.json"
        visits = json.loads(path.read_text())
        self.assertEqual(visits[0]["passive-data-metadata"]["source"], "WEIb_" + ident_a)
        self.assertTrue(any(f"PROLIFIC_PID={pid_b}" in v["url"] for v in visits))
        with open(self.safe / "identifiers.csv", newline="") as f:
            pids = {r["ident"]: r["pid"] for r in csv.DictReader(f)}
        self.assertEqual(pids[ident_b], pid_b)

    def test_second_run_is_identical(self):
        self.assertEqual(self.run_redact()[0], 0)
        first, lookup = self.snapshot(), self.lookup()
        self.assertEqual(self.run_redact()[0], 0)
        self.assertEqual(self.snapshot(), first)
        self.assertEqual(self.lookup(), lookup)

    def test_new_data_keeps_old_tokens_and_lookup_values(self):
        self.assertEqual(self.run_redact(threshold="3")[0], 0)
        before = self.lookup()
        host_tok = self.tok().token("host", "common.example")
        self.assertIn(host_tok, before)  # two participants < 3: tokenized
        fx.add_participant_d(self.raw)
        self.assertEqual(self.run_redact(threshold="3")[0], 0)
        after = self.lookup()
        for tok, value in before.items():
            self.assertEqual(after.get(tok), value, tok)
        self.assertIn(b"https://common.example/", self.blob())  # three participants: now readable

    def test_leak_check_failure_publishes_nothing(self):
        self.assertEqual(self.run_redact()[0], 0)
        (self.safe / "sentinel.txt").write_text("previous copy")
        with mock.patch.object(urls.UrlRule, "apply", lambda self, url: url):
            code, out = self.run_redact()
        self.assertEqual(code, 1)
        self.assertIn("LEAK CHECK FAILED", out)
        self.assertTrue((self.safe / "sentinel.txt").exists())
        self.assertFalse((self.raw / ".staging").exists())
        for value in fx.PLANTED:
            self.assertNotIn(value.lower(), out.lower(), value)

    def test_leftover_staging_is_cleared(self):
        (self.raw / ".staging").mkdir()
        (self.raw / ".staging" / "junk.txt").write_text("half-written")
        self.assertEqual(self.run_redact()[0], 0)
        self.assertFalse((self.raw / ".staging").exists())
        self.assertFalse((self.safe / "junk.txt").exists())

    def test_refuses_inside_claude_on_the_real_folder(self):
        with mock.patch.object(paths, "RAW_FOLDER_NAME", self.raw.name), mock.patch.dict(os.environ, {"CLAUDECODE": "1"}):
            with redirect_stdout(io.StringIO()):
                code = redact.main(["--raw", str(self.raw), "--safe", str(self.safe), "--workers", "1"])
        self.assertEqual(code, 2)
        self.assertFalse(self.safe.exists())

    def test_refuses_inside_claude_on_a_subfolder_of_the_real_folder(self):
        with mock.patch.object(paths, "RAW_FOLDER_NAME", self.raw.name), mock.patch.dict(os.environ, {"CLAUDECODE": "1"}):
            with redirect_stdout(io.StringIO()):
                code = redact.main(["--raw", str(self.raw / "pdk-export_2099-01-01_1"),
                                    "--safe", str(self.safe), "--workers", "1"])
        self.assertEqual(code, 2)
        self.assertFalse(self.safe.exists())

    def test_token_collision_aborts(self):
        key = tokens.load_or_create_key(self.raw / ".redaction" / "key")
        tok = tokens.Tokenizer(key).token("pid", fx.PID_A)
        tokens.write_lookup(self.raw / ".redaction" / "lookup.tsv", {tok: ("pid", "not-the-same")})
        self.assertEqual(self.run_redact()[0], 3)
        self.assertFalse(self.safe.exists())

    def run_capturing_everything(self):
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(buf):
            code = redact.main(["--raw", str(self.raw), "--safe", str(self.safe),
                                "--workers", "1", "--host-threshold", "2"])
        return code, buf.getvalue()

    def assert_no_raw_values(self, out):
        for value in fx.PLANTED:
            self.assertNotIn(value.lower(), out.lower(), value)

    def test_corrupt_zip_member_is_counted_without_its_name(self):
        payload = b"CORRUPT-ME-PLEASE" * 4
        z = self.raw / "broken.zip"
        with zipfile.ZipFile(z, "w", compression=zipfile.ZIP_STORED) as f:
            f.writestr(f"{fx.IDENT_A}__rex-history-visit__2099-03-01.json", payload)
        data = z.read_bytes()
        self.assertEqual(data.count(payload), 1)  # premise: the stored bytes can be flipped
        z.write_bytes(data.replace(payload, payload[::-1]))
        code, out = self.run_capturing_everything()
        self.assertEqual(code, 0, out)
        self.assert_no_raw_values(out)
        self.assertIn("bad zip members: 1", (self.safe / "_redaction_report.txt").read_text())

    def test_unreadable_file_is_counted_without_its_name(self):
        p = self.raw / "pdk-export_2099-01-01_1" / f"{fx.IDENT_C}__extra__2099-01-01.json"
        p.write_text("[]")
        p.chmod(0)
        self.addCleanup(p.chmod, 0o600)
        code, out = self.run_capturing_everything()
        self.assertEqual(code, 0, out)
        self.assert_no_raw_values(out)
        self.assertIn("unreadable PermissionError: 1", (self.safe / "_redaction_report.txt").read_text())

    def test_unexpected_error_prints_no_values(self):
        with mock.patch.object(redact.census, "merge_census", side_effect=ValueError(f"boom {fx.IDENT_A}")):
            code, out = self.run_capturing_everything()
        self.assertEqual(code, 4)
        self.assert_no_raw_values(out)
        self.assertFalse((self.raw / ".staging").exists())

    def test_other_files_only_on_request_and_shorthand_fails_the_check(self):
        (self.raw / "audit" / "NOTES.md").write_text(f"case weib_{fx.PID_A[:8]} needs review\n")
        self.assertEqual(self.run_redact()[0], 0)
        self.assertFalse((self.safe / "audit").exists())
        code, out = self.run_redact("--include-other-files")
        self.assertEqual(code, 1)
        self.assertIn("LEAK CHECK FAILED", out)
        self.assertNotIn(fx.PID_A[:8], out)
        self.assertFalse((self.safe / "audit").exists())  # the failed run published nothing

    def test_parallel_workers_match_one_process(self):
        self.assertEqual(self.run_redact()[0], 0)
        single = self.snapshot()
        self.assertEqual(self.run_redact(workers="2")[0], 0)
        self.assertEqual(self.snapshot(), single)


if __name__ == "__main__":
    unittest.main()
