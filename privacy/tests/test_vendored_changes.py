"""The four additive changes the fraud-screen package makes to the vendored redactor."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from privacy import paths, redact, tokens
from privacy.idscan import IdScanner
from privacy.tests import fixtures as fx
from privacy.tokens import TOKEN_RE, Tokenizer
from privacy.urls import FRAUD_SIGNAL_HOSTS, UrlRule, is_signal_host
import re

PID_A = fx.PID_A
TOK = re.compile(TOKEN_RE)


class RuleChangeTests(unittest.TestCase):
    def setUp(self):
        self.tok = Tokenizer(b"k" * 32)
        self.scanner = IdScanner(self.tok, known_hex={PID_A}, prefix_counts={"weib_": 2, "aimeccplc_": 2}, threshold=2)
        self.rule = UrlRule(self.scanner, host_counts={}, domain_counts={}, threshold=2)

    def test_consent_gl_kept(self):
        out = self.rule.apply("https://consent.google.com/m?continue=https://chromewebstore.google.com/&gl=NG&hl=en-US&src=1")
        self.assertTrue(out.startswith("https://consent.google.com/m?"))
        self.assertIn("gl=NG", out)
        self.assertIn("hl=en-US", out)
        self.assertNotIn("src=1", out)

    def test_whoer_to_host_kept(self):
        self.assertEqual(self.rule.host_part("whoer.to"), "whoer.to")
        self.assertEqual(self.rule.host_part("ipfighter.com"), "ipfighter.com")
        self.assertIn("fakenamegenerator.com", FRAUD_SIGNAL_HOSTS)
        self.assertTrue(is_signal_host("dashboard.pawns.app"))

    def test_lowercase_ident_tokenized_same_pid(self):
        up = self.scanner.scan("WEIb_" + PID_A + "1230")
        lo = self.scanner.scan("weib_" + PID_A + "1230")
        self.assertRegex(up, r"^WEIb_ident_[0-9a-f]{16}$")
        self.assertRegex(lo, r"^weib_ident_[0-9a-f]{16}$")
        self.assertNotEqual(up, lo)
        infos = list(self.scanner.ident_info.values())
        self.assertEqual(len(infos), 2)
        self.assertEqual(infos[0]["pid"], infos[1]["pid"])
        self.assertEqual(infos[0]["pid_created"], "2024-03")
        self.assertEqual(self.scanner.scan("aimeccplc_" + PID_A + "1231")[:10], "aimeccplc_")


class RedactCliChangeTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.raw = fx.build_raw(self.tmp / "root" / "pull")
        lo = "weib_" + PID_A + "0015"
        exp = self.raw / "pdk-export_2099-01-01_1"
        (exp / f"{lo}__rex-history-visit__recorded_2099-01-02.json").write_text(
            '[{"passive-data-metadata": {"source": "%s", "generator-id": "rex-history-visit", "generator": "x", "timestamp": 1, "timezone": "UTC"},'
            ' "url": "https://common.example/page", "visit_id": "1", "visit_time": 1, "transition_type": "link"}]' % lo)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_raw_required(self):
        with self.assertRaises(SystemExit) as cm:
            redact.main(["--safe", str(self.tmp / "safe")])
        self.assertEqual(cm.exception.code, 2)

    def test_safe_default_sibling_and_lowercase_rows(self):
        with mock.patch.dict(os.environ, {"CLAUDECODE": ""}):
            code = redact.main(["--raw", str(self.raw), "--workers", "1"])
        self.assertEqual(code, 0)
        safe = self.raw.parent / "pull_redacted"
        self.assertTrue(safe.is_dir())
        rows = (safe / "identifiers.csv").read_text().splitlines()
        from collections import Counter
        pid_rows = Counter(r.split(",")[2] for r in rows[1:])
        self.assertEqual(max(pid_rows.values()), 2)   # the upper- and lower-case idents share one pid token
        names = [p.name for p in safe.rglob("*.json")]
        self.assertFalse(any(PID_A in n for n in names))
        self.assertTrue(any(n.startswith("ident_") for n in names), names)

    def test_key_dir_walk_up(self):
        keydir = self.tmp / "root" / ".redaction"
        keydir.mkdir()
        key = tokens.load_or_create_key(keydir / "key")
        with mock.patch.dict(os.environ, {"CLAUDECODE": ""}):
            code = redact.main(["--raw", str(self.raw), "--safe", str(self.tmp / "safe"), "--workers", "1"])
        self.assertEqual(code, 0)
        self.assertFalse((self.raw / ".redaction").exists())
        self.assertTrue((keydir / "lookup.tsv").exists())
        self.assertEqual(tokens.load_or_create_key(keydir / "key"), key)

    def test_guard_keys_on_raw_folder_name(self):
        guarded = self.tmp / paths.RAW_FOLDER_NAME / "pull"
        fx.build_raw(guarded)
        with mock.patch.dict(os.environ, {"CLAUDECODE": "1"}):
            code = redact.main(["--raw", str(guarded), "--safe", str(self.tmp / "safe2"), "--workers", "1"])
        self.assertEqual(code, 2)
        self.assertFalse((self.tmp / "safe2").exists())


if __name__ == "__main__":
    unittest.main()


class CensusCaseTests(unittest.TestCase):
    """Change 5: lower-case file names census cleanly, case variants share one owner, and
    identifiers.csv carries the install token (the lower-cased identifier's token)."""

    def test_lowercase_file_name_census_no_error_and_shared_owner(self):
        from privacy import census
        up = "WEIb_" + PID_A + "1230"
        with tempfile.TemporaryDirectory() as d:
            body = '[{"passive-data-metadata": {"source": "%s"}, "url": "https://rare.example/x"}]'
            fu = Path(d, f"{up}__rex-history-visit__2026-09-14.json")
            fl = Path(d, f"{up.lower()}__rex-history-visit__2026-09-15.json")
            fu.write_text(body % up)
            fl.write_text(body % up.lower())
            cu, cl = census.census_file(fu), census.census_file(fl)
            self.assertEqual(dict(cl["errors"]), {})
            self.assertEqual(set(cu["owners_hosts"]), {up.lower()})
            self.assertEqual(set(cl["owners_hosts"]), {up.lower()})
            merged = census.merge_census([cu, cl])
            self.assertEqual(merged["host_counts"]["rare.example"], 1)
            self.assertEqual(merged["prefix_counts"], {"weib_": 2})

    def test_ident_info_carries_install_token(self):
        tok = Tokenizer(b"k" * 32)
        scanner = IdScanner(tok, known_hex={PID_A}, prefix_counts={"weib_": 9}, threshold=5)
        up_tok = scanner.scan("WEIb_" + PID_A + "1230").replace("WEIb_", "")
        lo_tok = scanner.scan("weib_" + PID_A + "1230").replace("weib_", "")
        self.assertEqual(scanner.ident_info[up_tok]["install"], lo_tok)
        self.assertEqual(scanner.ident_info[lo_tok]["install"], lo_tok)
        with tempfile.TemporaryDirectory() as d:
            redact._write_identifiers(Path(d, "identifiers.csv"), scanner.ident_info)
            lines = Path(d, "identifiers.csv").read_text().splitlines()
            self.assertEqual(lines[0], "ident,prefix,pid,pid_created,install")
            self.assertTrue(any(line.endswith("," + lo_tok) for line in lines[1:]))
