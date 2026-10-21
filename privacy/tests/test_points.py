import unittest

from privacy import rules
from privacy.idscan import IdScanner
from privacy.points import PointRedactor
from privacy.tokens import Tokenizer
from privacy.urls import Scrubber, UrlRule

PID_A = "65f1c0de2b7a4e9f8c3d1a20"
IDENT_A = "WEIb_" + PID_A + "0015"


def meta(gen):
    return {"source": IDENT_A, "generator-id": gen, "generator": f"{gen}: Study/0.0.50 Mozilla/5.0",
            "timestamp": 1760000000, "timezone": "America/New_York"}


class PointTests(unittest.TestCase):
    def setUp(self):
        self.tok = Tokenizer(b"k" * 32)
        scanner = IdScanner(self.tok, known_hex={PID_A}, prefix_counts={"WEIb_": 2}, threshold=2)
        urls = UrlRule(scanner, threshold=2)
        self.r = PointRedactor(scanner, urls, Scrubber(scanner, urls))
        self.ident = "WEIb_" + self.tok.token("ident", IDENT_A)

    def test_history_visit(self):
        out = self.r.redact({
            "passive-data-metadata": meta("rex-history-visit"),
            "url": f"https://mit.co1.qualtrics.com/jfe/form/SV_x?PROLIFIC_PID={PID_A}",
            "domain": "someone-personal.example", "title": "Jane's page",
            "visit_time": 1760000000123.5, "categories": [], "mystery_field": "x"})
        self.assertEqual(out["passive-data-metadata"]["source"], self.ident)
        self.assertIn(self.tok.token("pid", PID_A), out["url"])
        self.assertRegex(out["domain"], r"^host_[0-9a-f]{16}$")
        self.assertEqual(out["visit_time"], 1760000000123.5)
        self.assertEqual(out["categories"], [])
        self.assertNotIn("title", out)
        self.assertNotIn("mystery_field", out)
        self.assertEqual(self.r.dropped["rex-history-visit"], {"mystery_field": 1})
        self.assertEqual(self.r.dropped_by_rule["rex-history-visit"], {"title": 1})

    def test_unknown_generator_keeps_only_common_metadata(self):
        out = self.r.redact({"passive-data-metadata": meta("brand-new-gen"),
                             "payload": {"secret": "x", "n": 3}, "date": 5})
        self.assertEqual(set(out), {"passive-data-metadata", "date"})
        self.assertEqual(self.r.dropped["brand-new-gen"], {"payload.secret": 1, "payload.n": 1})

    def test_conversation_drops_turns_and_keeps_skeleton(self):
        out = self.r.redact({
            "passive-data-metadata": meta("rex-conversation"), "platform": "chatgpt",
            "turns": [{"text": "hello"}],
            "metadata": {"mapping": {"8f2d3e4a-1111-2222-3333-444455556666": {
                "message": {"author": {"role": "user"}, "create_time": 1.5}}}}})
        self.assertNotIn("turns", out)
        node = out["metadata"]["mapping"]["8f2d3e4a-1111-2222-3333-444455556666"]
        self.assertEqual(node["message"]["author"]["role"], "user")

    def test_system_status_tokenizes_device_ids(self):
        out = self.r.redact({
            "passive-data-metadata": meta("pdk-system-status"),
            "display-info": [{"id": "2077749241", "name": "Built-in Retina Display", "dpiX": 144}],
            "storage-info": [{"id": "abc-storage", "name": "Jane's USB", "capacity": 64}],
            "cpu-info": {"modelName": "Apple M2"}})
        self.assertRegex(out["display-info"][0]["id"], r"^dev_[0-9a-f]{16}$")
        self.assertEqual(out["display-info"][0]["name"], "Built-in Retina Display")
        self.assertRegex(out["storage-info"][0]["name"], r"^dev_[0-9a-f]{16}$")
        self.assertEqual(out["cpu-info"]["modelName"], "Apple M2")

    def test_search_mirror_payload(self):
        out = self.r.redact({
            "passive-data-metadata": meta("search-mirror-result"),
            "payload": {"query": "jane roe address", "title": "t", "content": "<div>x</div>",
                        "link": "https://result.example/x", "engine": "bing", "index": 1}})
        p = out["payload"]
        self.assertEqual(p["query"], self.tok.token("q", "jane roe address"))
        self.assertNotIn("title", p)
        self.assertNotIn("content", p)
        self.assertRegex(p["link"], r"^https://host_[0-9a-f]{16}/url_[0-9a-f]{16}$")
        self.assertEqual(p["index"], 1)

    def test_dropped_paths_hide_id_shaped_keys(self):
        self.r.redact({"passive-data-metadata": meta("rex-history-visit"),
                       "mystery": {IDENT_A: 1, "8f2d3e4a-1111-2222-3333-444455556666": 2}})
        self.assertEqual(self.r.dropped["rex-history-visit"], {"mystery.*": 2})

    def test_history_visit_aggregate(self):
        out = self.r.redact({
            "passive-data-metadata": meta("rex-history-visit-aggregate"),
            "url": f"https://mit.co1.qualtrics.com/jfe/form/SV_x?PROLIFIC_PID={PID_A}",
            "recorded_url": "https://someone-personal.example/x", "domain": "someone-personal.example",
            "title": "Jane's page", "visit_count": 3, "typed_count": 0, "filtered": False,
            "history_item_id": "42", "last_visit_time": 1760001000000.5,
            "window_start": 1760000000000, "window_end": 1760003600000})
        self.assertIn(self.tok.token("pid", PID_A), out["url"])
        self.assertRegex(out["recorded_url"], r"^https://host_[0-9a-f]{16}/url_[0-9a-f]{16}$")
        self.assertRegex(out["domain"], r"^host_[0-9a-f]{16}$")
        self.assertNotIn("title", out)
        self.assertEqual((out["visit_count"], out["window_start"], out["window_end"]),
                         (3, 1760000000000, 1760003600000))
        self.assertNotIn("rex-history-visit-aggregate", self.r.dropped)

    def test_trace_context_and_conversation_user_agent_are_kept(self):
        out = self.r.redact({
            "passive-data-metadata": meta("rex-conversation"),
            "_pdk_trace_context": {"bundle_id": "8f2d3e4a-1111-2222-3333-444455556666", "bundle_trace_id": "t-77"},
            "user_agent": "Mozilla/5.0 (Macintosh)"})
        self.assertEqual(out["_pdk_trace_context"]["bundle_trace_id"], "t-77")
        self.assertEqual(out["user_agent"], "Mozilla/5.0 (Macintosh)")
        self.assertEqual(self.r.dropped, {})


class PatternTests(unittest.TestCase):
    def test_patterns(self):
        rs = rules.RuleSet([("a.b", "x"), ("c[].**", "y"), ("d.*.e", "z")])
        self.assertEqual(rs.lookup(("a", "b")), "x")
        self.assertIsNone(rs.lookup(("a", "b", "c")))
        self.assertEqual(rs.lookup(("c", "[]", "k", "[]")), "y")
        self.assertEqual(rs.lookup(("c", "[]")), "y")
        self.assertEqual(rs.lookup(("d", "*", "e")), "z")
        self.assertIsNone(rs.lookup(("d", "[]", "e")))

    def test_normalize_key(self):
        self.assertEqual(rules.normalize_key("passive-data-metadata"), "passive-data-metadata")
        self.assertEqual(rules.normalize_key("client-created-root"), "client-created-root")
        for k in ["8f2d3e4a-1111-2222-3333-444455556666", "c_8f2d3e4a5b6c", IDENT_A, "div[jsname='x']"]:
            self.assertEqual(rules.normalize_key(k), "*")


if __name__ == "__main__":
    unittest.main()
