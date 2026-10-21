import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fraudscreen.arms import arm_for, participant_arm

HERE = Path(__file__).resolve().parent.parent


class ArmTests(unittest.TestCase):
    def test_arm_for_prefix_match(self):
        arms = {"4016cabf0000": "WebEatsItself_CC@2026-09-16", "8e70a6eb1111": "WebEatsItself_RC"}
        self.assertEqual(arm_for("4016cabf", arms), "WebEatsItself_CC")
        self.assertEqual(arm_for("8e70a6eb1111ffff", arms), "WebEatsItself_RC")
        self.assertIsNone(arm_for("deadbeef", arms))
        self.assertIsNone(arm_for("", arms))
        p = {"installs": [{"chash": {"4016cabf": 10, "8e70a6eb": 3}}]}
        self.assertEqual(participant_arm(p, arms), "WebEatsItself_CC")
        self.assertEqual(participant_arm({"installs": [{"chash": {"deadbeef": 1}}]}, arms), "?deadbeef")

    def test_make_arm_map_on_temp_git_repo(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d, "repo"); (repo / "configs" / "X").mkdir(parents=True)
            cfg = repo / "configs" / "X" / "Study_Arm.json"
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x")
            subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
            cfg.write_text(json.dumps({"a": 1, "passive_data_kit": {"identifier": "drop-me", "endpoint": "e"}}))
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True, env=env)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "v1"], check=True, env=env)
            cfg.write_text(json.dumps({"a": 2, "passive_data_kit": {"endpoint": "e"}}))
            subprocess.run(["git", "-C", str(repo), "commit", "-qam", "v2"], check=True, env=env)
            out = Path(d, "arms.json")
            r = subprocess.run([sys.executable, str(HERE / "tools" / "make_arm_map.py"), "--repo", str(repo), "--out", str(out)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            arms = json.loads(out.read_text())
            self.assertEqual(len(arms), 2)
            self.assertTrue(all(len(k) == 12 for k in arms))
            self.assertTrue(all(v.startswith("Study_Arm@") for v in arms.values()))
            import hashlib
            h = hashlib.sha256(json.dumps({"a": 2, "passive_data_kit": {"endpoint": "e"}}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()[:12]
            self.assertIn(h, arms)

    def test_packaged_snapshot_exists(self):
        arms = json.loads((HERE / "fraudscreen" / "arms.json").read_text())
        self.assertGreater(len(arms), 50)
        self.assertTrue(any(v.startswith("WebEatsItself_CC") for v in arms.values()))


if __name__ == "__main__":
    unittest.main()
