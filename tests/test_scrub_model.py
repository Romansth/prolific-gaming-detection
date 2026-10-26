import json
import tempfile
import unittest
from pathlib import Path

from fraudscreen.scrub import leaks, scrub_model
from tests import synth as S

A, B = S.PID_A, S.PID_B


class ScrubModelTests(unittest.TestCase):
    """The token-only report is rendered from a scrubbed data model, so URLs reach the redactor's
    URL rule unescaped and every string leaf follows the same rules as the redacted data."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key_dir = Path(self.tmp.name, "key")

    def tearDown(self):
        self.tmp.cleanup()

    def test_scrub_model_tokenizes_strings_and_keeps_shape(self):
        model = {"a": [f"https://x.qualtrics.com/jfe/form/SV_1?PROLIFIC_PID={A}&STUDY_ID={B}", "id shared-run-id: this"],
                 "n": 3, "nested": {"k": A, "flag": True, "none": None}}
        out = scrub_model(model, self.key_dir, device_ids={"shared-run-id"})
        text = json.dumps(out)
        self.assertNotIn(A, text)
        self.assertNotIn(B, text)
        self.assertEqual(out["n"], 3)
        self.assertIs(out["nested"]["flag"], True)
        self.assertIsNone(out["nested"]["none"])
        self.assertRegex(out["nested"]["k"], r"^pid_[0-9a-f]{16}$")
        self.assertRegex(out["a"][1], r"^id dev_[0-9a-f]{16}: this$")
        self.assertIn("PROLIFIC_PID=pid_", out["a"][0])
        self.assertNotIn("&amp;", out["a"][0])
        self.assertEqual(model["nested"]["k"], A)   # the input is not modified

    def test_scrub_model_flattens_newlines(self):
        out = scrub_model({"x": ["a\nb", "c\r\nd", ""]}, self.key_dir)
        self.assertEqual(out["x"], ["a b", "c d", ""])



class LeakTests(unittest.TestCase):
    """Defence in depth: the one artefact that leaves the team is checked with the redactor's
    independent leak scanner before it is written."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key_dir = Path(self.tmp.name, "key")

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_scrubbed_model_has_no_leaks(self):
        model = {"a": [f"https://x.qualtrics.com/jfe/form/SV_1?PROLIFIC_PID={A}", f"WEIb_{A}1230__rex-history-visit__2026-09-14.json"],
                 "b": {"k": B, "mail": "Inbox - jane.doe@example.com - Gmail"}}
        self.assertEqual(leaks(scrub_model(model, self.key_dir), model), [])

    def test_leaks_names_the_kind_of_each_hit(self):
        bad = {"a": [f"https://x.qualtrics.com/jfe/form/SV_1?PROLIFIC_PID={A}", f"WEIb_{B}1230__x.json", "see jane.doe%40example.com"],
               "n": 1}
        kinds = sorted({k for k, _ in leaks(bad, bad)})
        self.assertEqual(kinds, ["email", "hex24", "identifier", "known-id"])   # the 28-hex run in the identifier is a known-id window too
        self.assertEqual(leaks({"a": "pid_" + "0" * 16, "b": "ident_" + "1" * 16}, {}), [])


if __name__ == "__main__":
    unittest.main()
