"""The additive changes the fraud-screen package makes to the vendored redactor."""
import io
import os
import tempfile
from contextlib import redirect_stdout
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
NO_AGENT = {v: "" for v in paths.AGENT_ENV_VARS}   # so the suite passes when an agent runs it


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
        with mock.patch.dict(os.environ, NO_AGENT):
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
        with mock.patch.dict(os.environ, NO_AGENT):
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


class NulCsvTests(unittest.TestCase):
    """Python 3.11 lets the csv module read NUL bytes, which 3.9 refused. A NUL means a damaged or
    binary file, so the redactor refuses such a CSV on every version instead of copying it."""

    def test_csv_with_a_nul_byte_is_refused(self):
        from privacy.files import FileRedactor, Refused
        stub = mock.Mock(scrubber=mock.Mock(scrub=lambda c: c))
        with self.assertRaises(Refused) as cm:
            FileRedactor._csv(stub, f"id,score\n{PID_A},3\x000\n", ",", io.StringIO())
        self.assertIn("unparseable", str(cm.exception))


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
            self.assertEqual(set(cu["owners_hosts"]), {PID_A})   # owners are Prolific ids
            self.assertEqual(set(cl["owners_hosts"]), {PID_A})
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


class CensusPerParticipantTests(unittest.TestCase):
    """Change 7: hosts are counted per Prolific id, so a Chrome+Edge pair is one participant and a
    host three such pairs visited stays below a threshold of 5."""

    def test_two_identifiers_of_one_pid_count_once(self):
        from privacy import census
        with tempfile.TemporaryDirectory() as d:
            body = '[{"passive-data-metadata": {"source": "%s"}, "url": "https://rare.example/x"}]'
            parts = []
            for pre in ("AIMECcplc_", "AIMECeplc_"):
                p = Path(d, f"{pre}{PID_A}1231__rex-history-visit__2026-09-14.json")
                p.write_text(body % (pre + PID_A + "1231"))
                parts.append(census.census_file(p))
            self.assertEqual(census.merge_census(parts)["host_counts"], {"rare.example": 1})


class ShortDeviceIdTests(unittest.TestCase):
    """Change 8: a storage or display id under 6 characters identifies nothing and stays readable,
    so the screen's short-id filter for M2 applies to redacted data as it does to raw data."""

    def test_short_ids_are_not_tokenized(self):
        from privacy.points import PointRedactor
        from privacy.urls import Scrubber
        tok = Tokenizer(b"k" * 32)
        scanner = IdScanner(tok, known_hex=set(), prefix_counts={}, threshold=5)
        urls = UrlRule(scanner)
        r = PointRedactor(scanner, urls, Scrubber(scanner, urls))
        out = r.redact({"passive-data-metadata": {"generator-id": "pdk-system-status"},
                        "display-info": [{"id": "1"}, {"id": ""}, {"id": "2077749241"}]})
        self.assertEqual([x["id"][:4] for x in out["display-info"]], ["1", "", "dev_"])

    def test_short_storage_names_are_still_tokenized(self):
        """A volume label is a name, not an id: 'JANE' must not pass through because it is short."""
        from privacy.points import PointRedactor
        from privacy.urls import Scrubber
        tok = Tokenizer(b"k" * 32)
        scanner = IdScanner(tok, known_hex=set(), prefix_counts={}, threshold=5)
        urls = UrlRule(scanner)
        r = PointRedactor(scanner, urls, Scrubber(scanner, urls))
        out = r.redact({"passive-data-metadata": {"generator-id": "pdk-system-status"},
                        "storage-info": [{"id": "1", "name": "JANE"}]})
        self.assertEqual(out["storage-info"][0]["id"], "1")
        self.assertRegex(out["storage-info"][0]["name"], r"^dev_[0-9a-f]{16}$")


class CodexSessionTests(unittest.TestCase):
    """Change 6: a Codex shell (CODEX_THREAD_ID or CODEX_SESSION_ID set) is refused the raw folder
    exactly like a Claude Code shell."""

    def test_codex_env_counts_as_an_agent_session(self):
        for env in ({"CODEX_THREAD_ID": "t"}, {"CODEX_SESSION_ID": "s"}, {"CLAUDECODE": "1"}):
            with mock.patch.dict(os.environ, {**NO_AGENT, **env}):
                self.assertTrue(paths.inside_claude(), env)
        with mock.patch.dict(os.environ, NO_AGENT):
            self.assertFalse(paths.inside_claude())

    def test_redactor_refuses_raw_folder_inside_codex(self):
        with tempfile.TemporaryDirectory() as d:
            guarded = Path(d, paths.RAW_FOLDER_NAME, "pull")
            fx.build_raw(guarded)
            with mock.patch.dict(os.environ, {**NO_AGENT, "CODEX_THREAD_ID": "t"}), redirect_stdout(io.StringIO()):
                code = redact.main(["--raw", str(guarded), "--safe", str(Path(d, "safe")), "--workers", "1"])
            self.assertEqual(code, 2)
            self.assertFalse(Path(d, "safe").exists())
