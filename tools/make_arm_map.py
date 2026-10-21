#!/usr/bin/env python3
"""Refresh fraudscreen/arms.json: hash every committed version of configs/**/*.json in the
AI-extension-testing repo (and the config files on disk) the way the extension hashes a served
configuration, so a point's configuration-hash prefix resolves to an arm name.

usage: python3 tools/make_arm_map.py --repo <path to AI-extension-testing> --out fraudscreen/arms.json
"""
import argparse
import glob
import hashlib
import json
import os
import subprocess
import sys


def sh(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True).stdout


def config_hash(obj):
    if isinstance(obj.get("passive_data_kit"), dict):
        obj["passive_data_kit"].pop("identifier", None)
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()[:12]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    out, seen = {}, set()
    for line in sh(args.repo, "log", "--all", "--pretty=%H %cs", "--", "configs").splitlines():
        sha, date = line.split()
        for f in sh(args.repo, "ls-tree", "-r", "--name-only", sha, "--", "configs").splitlines():
            if not f.endswith(".json"):
                continue
            blob = sh(args.repo, "rev-parse", f"{sha}:{f}").strip()
            if blob in seen:
                continue
            seen.add(blob)
            try:
                obj = json.loads(sh(args.repo, "show", f"{sha}:{f}"))
            except ValueError:
                continue
            if not isinstance(obj, dict):
                continue
            out.setdefault(config_hash(obj), f"{os.path.basename(f)[:-5]}@{date}")
    for f in glob.glob(os.path.join(args.repo, "configs*", "**", "*.json"), recursive=True):
        try:
            obj = json.load(open(f, encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if isinstance(obj, dict):
            out.setdefault(config_hash(obj), os.path.basename(f)[:-5] + "@disk")
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(dict(sorted(out.items())), fh, indent=1)
    print(f"{len(out)} hashes -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
