import hashlib
import tempfile
import unittest
from pathlib import Path

from fraudscreen.files import Input
from fraudscreen.scan import scan_folder, scan_one
from tests import synth as S

HEX = "6a0e29aee7c2fddfc1bf8b06"
IDENT = "WEIb_" + HEX + "1234"


class ScanTests(unittest.TestCase):
    def test_visit_fields_extracted(self):
        with tempfile.TemporaryDirectory() as d:
            v = S.visit(IDENT, "https://App.Prolific.com/studies?x=1", 7, ts=S.T0 + 5, transition_type="typed",
                        visit_count=42, bundle=77)
            del v["is_local"]
            p = S.write_file(d, IDENT, "rex-history-visit", "2026-09-14", [v])
            ident, inst = scan_one(Input(p, None), raw_mode=True)
            self.assertEqual(ident, IDENT)
            vis = inst["visits"][0]
            self.assertEqual((vis.t_ms, vis.host, vis.path, vis.query), ((S.T0 + 5) * 1000, "app.prolific.com", "/studies", "x=1"))
            self.assertEqual((vis.transition, vis.visit_id, vis.hist_id, vis.visit_count), ("typed", 7, 7, 42))
            self.assertIsNone(vis.is_local)
            self.assertEqual((vis.tz, vis.bundle, vis.file), ("America/New_York", 77, p.name))

    def test_status_fields(self):
        with tempfile.TemporaryDirectory() as d:
            st = S.status(IDENT, disks=(("b", 1000202039296), ("a", 250057060352), ("usb", 1000)),
                          displays=(("d1", 1920, 1080, "Generic PnP Monitor"),), ua=S.EDGE_UA, ver="0.0.48")
            p = S.write_file(d, IDENT, "pdk-system-status", "2026-09-14", [st])
            _, inst = scan_one(Input(p, None), raw_mode=True)
            s = inst["status"][0]
            self.assertEqual(s.disks, (("a", 250057060352), ("b", 1000202039296), ("usb", 1000)))
            self.assertEqual(s.displays, (("d1", 1920, 1080, "Generic PnP Monitor"),))
            self.assertEqual((s.ver, s.browser, s.plat, s.nproc, s.mem), (48, "Edge", "Win", 4, 6311489536))
            self.assertEqual(s.cpu, "Intel(R) Core(TM) i5-5200U CPU @ 2.20GHz")

    def test_events_registration_conversations(self):
        with tempfile.TemporaryDirectory() as d:
            S.write_file(d, IDENT, "pdk-app-event", "2026-09-14",
                         [S.event(IDENT, "rex-history-collection-complete", count=22337),
                          S.event(IDENT, "rex-spider-gemini-complete", ts=S.T0 + 1)])
            S.write_file(d, IDENT, "ai-market-add-identifier", "2026-09-14", [S.add_identifier(IDENT, ts=S.T0 - 10)])
            S.write_file(d, IDENT, "rex-conversation", "2026-09-14", [S.conversation(IDENT, started=S.T0 + 99)])
            installs = scan_folder(Path(d), workers=1, raw_mode=True)
            inst = installs[IDENT]
            self.assertEqual([(e.name, e.count) for e in inst["events"]], [("rex-history-collection-complete", 22337)])
            self.assertEqual(inst["registered_at"], S.T0 - 10)
            self.assertEqual(inst["conversations"], [("chatgpt", S.T0 + 99)])

    def test_dedupe_across_variants(self):
        with tempfile.TemporaryDirectory() as d:
            pts = [S.visit(IDENT, "https://a.example/p", 1), S.visit(IDENT, "https://a.example/q", 2, ts=S.T0 + 1)]
            S.write_file(d, IDENT, "rex-history-visit", "2026-09-14", pts, "plain")
            S.write_file(d, IDENT, "rex-history-visit", "2026-09-14", pts, "recorded")
            S.write_file(d, IDENT, "pdk-system-status", "2026-09-14", [S.status(IDENT)], "plain")
            S.write_file(d, IDENT, "pdk-system-status", "2026-09-14", [S.status(IDENT)], "created")
            inst = scan_folder(Path(d), workers=2, raw_mode=True)[IDENT]
            self.assertEqual(len(inst["visits"]), 2)
            self.assertEqual(len(inst["status"]), 1)
            self.assertEqual(len(inst["files"]), 4)

    def test_unreadable_counted(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / f"{IDENT}__rex-history-visit__2026-09-15.json").write_text('[{"url": "https://a.example/"')
            S.write_file(d, IDENT, "rex-history-visit", "2026-09-14", [S.visit(IDENT, "https://a.example/p", 1)])
            inst = scan_folder(Path(d), workers=1, raw_mode=True)[IDENT]
            self.assertEqual(inst["unreadable"], 1)
            self.assertEqual(len(inst["visits"]), 1)

    def test_mail_identity_only_in_raw_mode(self):
        with tempfile.TemporaryDirectory() as d:
            v = S.visit(IDENT, "https://mail.google.com/mail/u/0/", 1, title="Inbox (3) - someone@example.org - Gmail")
            w = S.visit(IDENT, "https://outlook.live.com/mail/", 2, ts=S.T0 + 1, title="Inbox - Pat Example - Outlook")
            p = S.write_file(d, IDENT, "rex-history-visit", "2026-09-14", [v, w])
            _, raw = scan_one(Input(p, None), raw_mode=True)
            self.assertEqual(raw["mail_identities"],
                             [("email", hashlib.sha1(b"someone@example.org").hexdigest()),
                              ("name", hashlib.sha1(b"pat example").hexdigest())])
            _, red = scan_one(Input(p, None), raw_mode=False)
            self.assertEqual(red["mail_identities"], [])
            self.assertNotIn("title", str(raw["visits"]))


if __name__ == "__main__":
    unittest.main()
