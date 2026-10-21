import re
import unittest

from privacy.idscan import IdScanner
from privacy.tokens import Tokenizer
from privacy.urls import Scrubber, UrlRule

PID_A = "65f1c0de2b7a4e9f8c3d1a20"
PID_B = "6ac1f3a9e04b7d2c1a9f8e37"
IDENT_A = "WEIb_" + PID_A + "0015"


class UrlRuleTests(unittest.TestCase):
    def setUp(self):
        self.tok = Tokenizer(b"k" * 32)
        self.scanner = IdScanner(self.tok, known_hex={PID_A, PID_B},
                                 prefix_counts={"WEIb_": 2}, threshold=2)
        self.rule = UrlRule(self.scanner, host_counts={"common.example": 2},
                            domain_counts={"common.example": 2}, threshold=2)
        self.pa = self.tok.token("pid", PID_A)
        self.pb = self.tok.token("pid", PID_B)

    def test_google_search_keeps_country_and_tokenizes_the_query(self):
        out = self.rule.apply("https://www.google.com.ng/search?q=cheap+flights&gl=ng&hl=en#frag")
        q = self.tok.token("q", "cheap flights")
        self.assertEqual(out, f"https://www.google.com.ng/search?q={q}&gl=ng&hl=en")

    def test_survey_link_keeps_id_tokens_readable(self):
        out = self.rule.apply(
            f"https://mit.co1.qualtrics.com/jfe/form/SV_x?PROLIFIC_PID={PID_A}&STUDY_ID={PID_B}")
        self.assertEqual(out, f"https://mit.co1.qualtrics.com/jfe/form/SV_x?PROLIFIC_PID={self.pa}&STUDY_ID={self.pb}")

    def test_google_redirect_target_goes_through_the_same_rule(self):
        out = self.rule.apply(
            "https://www.google.com/url?q=https%3A%2F%2Fmit.co1.qualtrics.com%2Fjfe%2Fform%2FSV_x"
            f"%3FPROLIFIC_PID%3d{PID_A}&sa=D")
        self.assertNotIn(PID_A, out.lower())
        self.assertIn(self.pa, out)
        self.assertIn("sa=" + self.tok.token("q", "D"), out)

    def test_prolific_path_ids_are_tokenized(self):
        out = self.rule.apply(f"https://app.prolific.com/submissions/{PID_A}/complete?cc=ABC123#x")
        self.assertEqual(out, f"https://app.prolific.com/submissions/{self.pa}/complete?cc="
                              + self.tok.token("q", "ABC123"))

    def test_id_with_a_tail_in_a_query_value_stays_readable(self):
        out = self.rule.apply(f"https://app.prolific.com/x?ref=MITINTA_{PID_A}0015")
        self.assertEqual(out, f"https://app.prolific.com/x?ref=MITINTA_{self.pa}0015")

    def test_rare_host_becomes_opaque_with_ids_listed(self):
        url = "https://someone-personal.example/blog?email=jane.roe%40example.org"
        out = self.rule.apply(url)
        self.assertRegex(out, r"^https://host_[0-9a-f]{16}/url_[0-9a-f]{16}\?ids=email_[0-9a-f]{16}$")
        url_tok = re.search(r"url_[0-9a-f]{16}", out).group(0)
        self.assertEqual(self.tok.lookup[url_tok], ("url", url))

    def test_common_host_is_kept_but_the_rest_is_opaque(self):
        self.assertRegex(self.rule.apply("https://common.example/page?x=1"),
                         r"^https://common\.example/url_[0-9a-f]{16}$")

    def test_credentials_in_the_url_never_survive(self):
        out = self.rule.apply("https://bob:secret@www.google.com/search?q=x")
        self.assertNotIn("bob", out)
        self.assertNotIn("secret", out)

    def test_chrome_pages_keep_the_page_name(self):
        self.assertEqual(self.rule.apply("chrome://newtab/"), "chrome://newtab/")
        self.assertRegex(self.rule.apply("chrome://settings/privacy"),
                         r"^chrome://settings/url_[0-9a-f]{16}$")

    def test_file_urls_are_fully_opaque(self):
        self.assertRegex(self.rule.apply("file:///Users/jane/Documents/x.pdf"), r"^file:url_[0-9a-f]{16}$")

    def test_unparseable_port_does_not_crash(self):
        self.assertRegex(self.rule.apply("http://x.example:99999/a"), r"^url_[0-9a-f]{16}$")

    def test_fraud_tool_hosts_stay_readable_when_rare(self):
        self.assertRegex(self.rule.apply("https://start.adspower.net/?id=7"),
                         r"^https://start\.adspower\.net/url_[0-9a-f]{16}$")
        self.assertEqual(self.rule.domain("whoer.net"), "whoer.net")
        self.assertRegex(self.rule.apply("https://whoer-net.example/"), r"^https://host_")  # suffix match only

    def test_google_install_and_account_params_stay_readable(self):
        out = self.rule.apply("https://www.google.com/search?q=x&rlz=1C1GCEU_enVE1050VE1050&authuser=1&cr=countryUS")
        self.assertIn("rlz=1C1GCEU_enVE1050VE1050", out)
        self.assertIn("authuser=1", out)
        self.assertIn("cr=countryUS", out)

    def test_domain_rule(self):
        self.assertRegex(self.rule.domain("someone-personal.example"), r"^host_[0-9a-f]{16}$")
        self.assertEqual(self.rule.domain("common.example"), "common.example")
        self.assertEqual(self.rule.domain("google.com"), "google.com")


class ScrubberTests(unittest.TestCase):
    def test_urls_and_ids_in_free_text(self):
        tok = Tokenizer(b"k" * 32)
        scanner = IdScanner(tok, prefix_counts={"WEIb_": 2}, threshold=2)
        scrub = Scrubber(scanner, UrlRule(scanner, threshold=2))
        out = scrub.scrub(f"see https://www.google.com/search?q=jane+roe. and {IDENT_A}")
        q = tok.token("q", "jane roe")
        self.assertEqual(out, f"see https://www.google.com/search?q={q}. and WEIb_"
                              + tok.token("ident", IDENT_A))


if __name__ == "__main__":
    unittest.main()
