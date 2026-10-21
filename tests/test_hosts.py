import unittest

from fraudscreen import hosts


class HostTests(unittest.TestCase):
    def test_subdomain_matches(self):
        self.assertEqual(hosts.classify("dashboard.honeygain.com"), "proxy")
        self.assertEqual(hosts.classify("start.adspower.net"), "antidetect")
        self.assertEqual(hosts.classify("whoer.to"), "ipcheck")

    def test_vpn_account_beats_marketing(self):
        self.assertEqual(hosts.classify("my.nordaccount.com"), "vpn_account")
        self.assertEqual(hosts.classify("account.protonvpn.com"), "vpn_account")
        self.assertEqual(hosts.classify("nordvpn.com"), "vpn_marketing")
        self.assertEqual(hosts.classify("www.expressvpn.com"), "vpn_marketing")

    def test_hola_com_is_not_vpn(self):
        self.assertIsNone(hosts.classify("hola.com"))
        self.assertEqual(hosts.classify("hola.org"), "vpn_marketing")
        self.assertIsNone(hosts.classify("theoluminati.example"))

    def test_gov_is_us_consumer(self):
        self.assertEqual(hosts.classify("www.dmv.ca.gov"), "us_consumer")
        self.assertEqual(hosts.classify("secure.chase.com"), "us_consumer")
        self.assertEqual(hosts.classify("www.skyscanner.com.mx"), "travel")
        self.assertEqual(hosts.classify("app.prolific.com"), "dashboard")
        self.assertEqual(hosts.classify("mit.co1.qualtrics.com"), "survey_infra")
        self.assertEqual(hosts.classify("chatgpt.com"), "chatbot")
        self.assertTrue(hosts.is_travel("www.google.com", "/travel/flights"))
        self.assertFalse(hosts.is_travel("www.google.com", "/search"))

    def test_fraud_signal_hosts_contains_whoer_to(self):
        self.assertIn("whoer.to", hosts.FRAUD_SIGNAL_HOSTS)
        self.assertIn("ipfighter.com", hosts.FRAUD_SIGNAL_HOSTS)
        self.assertIn("fakenamegenerator.com", hosts.FRAUD_SIGNAL_HOSTS)
        self.assertNotIn("chase.com", hosts.FRAUD_SIGNAL_HOSTS)
        self.assertTrue(hosts.is_signal_host("dashboard.honeygain.com"))


if __name__ == "__main__":
    unittest.main()
