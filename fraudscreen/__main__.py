"""python -m fraudscreen --data <folder> [--out report.md] [--csv file.csv] [--redact] ..."""
import argparse
import datetime as dt
import os
import sys
import time
from pathlib import Path

from fraudscreen import __version__
from fraudscreen.arms import load_arms, participant_arm
from fraudscreen.files import list_inputs, parse_name
from fraudscreen.fleet import build_fleet
from fraudscreen.participants import default_exclude, group
from fraudscreen.report import render_markdown, write_csv
from fraudscreen.scan import scan_folder
from fraudscreen.scrub import scrub_file
from fraudscreen.signs import SIGNS, Context
from fraudscreen.signs.accounts import score_accounts
from fraudscreen.signs.behaviour import score_behaviour
from fraudscreen.signs.location import score_location
from fraudscreen.signs.machine import score_machine
from fraudscreen.signs.tooling import score_tooling
import re


def detect_mode(folder):
    """'redacted' when identifiers.csv sits in the folder or identifiers carry tokens."""
    if (folder / "identifiers.csv").exists() or (folder.parent / "identifiers.csv").exists():
        return "redacted"
    for inp in list_inputs(folder)[:200]:
        fn = parse_name(inp.name)
        if fn and ("ident_" in fn.ident or "pid_" in fn.ident):
            return "redacted"
    return "raw"


def repo_layout(folder):
    """When the folder sits under raw-data/ or data-redacted/ inside a repo, report and redacted
    copy defaults follow that layout: <repo>/reports/ and <repo>/data-redacted/<name>."""
    for parent, kind in ((folder.parent, "raw"), (folder.parent, "redacted")):
        if parent.name == "raw-data" and kind == "raw":
            return parent.parent, "raw"
        if parent.name == "data-redacted" and kind == "redacted":
            return parent.parent, "redacted"
    return None, None


try:
    from privacy.paths import RAW_FOLDER_NAMES   # the folder names a Claude session must not read
except ImportError:  # pragma: no cover
    RAW_FOLDER_NAMES = ("raw-data",)


def score_all(participants, fleet, raw_mode):
    ctx = Context(participants=participants, fleet=fleet, raw_mode=raw_mode)
    raw_only = [s.id for s in SIGNS if s.modes == "raw"]
    results = {}
    for p in participants:
        res = {}
        for fn in (score_accounts, score_machine, score_tooling, score_location, score_behaviour):
            res.update(fn(p, ctx))
        if not raw_mode:
            for sid in raw_only:
                r = res[sid]
                r.fired, r.count, r.evidence, r.linked, r.available = False, 0, [], [], False
                r.notes = ["not available in redacted mode"]
        results[p["key"]] = res
    return results


def refuse_inside_claude(folder):
    """The raw folder is out of bounds for a Claude session; the person runs the screen on it."""
    if os.environ.get("CLAUDECODE") != "1":
        return False
    return any(part in RAW_FOLDER_NAMES for part in Path(folder).parts)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fraudscreen", description="Screen a folder of PDK exports for signs of participant gaming.")
    ap.add_argument("--data", required=True, help="folder of per-identifier export files (json, or zips of them)")
    ap.add_argument("--out", help="markdown report path (default: <folder>_screen_<date>.md, or reports/ in a repo layout)")
    ap.add_argument("--csv", help="csv path (default: next to the report)")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--redact", action="store_true", help="run the privacy redactor first and screen the redacted copy")
    ap.add_argument("--safe", help="where the redacted copy goes (default: <folder>_redacted, or data-redacted/<name> in a repo layout)")
    ap.add_argument("--key-dir", help="folder holding the redactor key and lookup (default: nearest .redaction/ above the data)")
    ap.add_argument("--arms", help="arms.json mapping configuration-hash prefixes to arm names")
    ap.add_argument("--min-visits", type=int, default=50, help="installs below this many visits do not set fleet percentiles")
    ap.add_argument("--exclude-pattern", action="append", default=None, help="regex for internal identifiers to skip (repeatable)")
    args = ap.parse_args(argv)
    t_start = time.time()
    # abspath, not resolve(): a pull symlinked under raw-data/ keeps the repo layout and the shared key
    folder = Path(os.path.abspath(os.path.expanduser(args.data)))
    if not folder.is_dir():
        print(f"Data folder not found: {args.data}")
        return 2
    if refuse_inside_claude(folder):
        print("Refusing to screen a raw-data folder inside a Claude session: run this command in your own "
              "terminal. Claude works from data-redacted/ and reports/.")
        return 2
    repo, kind = repo_layout(folder)
    today = dt.date.today().isoformat()
    mode = detect_mode(folder)
    raw_mode = mode == "raw"
    exclude = [re.compile(p, re.I) for p in args.exclude_pattern] if args.exclude_pattern else default_exclude()
    installs = scan_folder(folder, args.workers, raw_mode)
    ids_csv = folder / "identifiers.csv"
    if not ids_csv.exists():
        ids_csv = folder.parent / "identifiers.csv" if (folder.parent / "identifiers.csv").exists() else None
    participants, skipped = group(installs, ids_csv, exclude)
    n_visits = sum(len(i["visits"]) for p in participants for i in p["installs"])
    if not participants or n_visits == 0:
        print(f"Nothing screenable: {len(installs)} installs, skipped {dict(skipped)}, history points {n_visits}.")
        return 3
    arms = load_arms(args.arms)
    for p in participants:
        p["arm"] = participant_arm(p, arms)
    fleet = build_fleet(participants, args.min_visits)
    results = score_all(participants, fleet, raw_mode)
    days = sorted({parse_name(f).day for p in participants for i in p["installs"] for f in i["files"] if parse_name(f)})
    meta = dict(folder=str(folder), mode=mode, files=sum(len(i["files"]) for p in participants for i in p["installs"]),
                installs=sum(len(p["installs"]) for p in participants), participants=len(participants), skipped=dict(skipped),
                unreadable=sum(i["unreadable"] for i in installs.values()),
                date_range=f"{days[0]}..{days[-1]}" if days else "", version=__version__, seconds=time.time() - t_start,
                arms_available=bool(arms))
    # where the first (unscrubbed) report goes: a raw screen carries real ids and belongs with the team
    if args.out:
        out = Path(args.out)
    elif repo and raw_mode:
        out = repo / "reports-team" / f"{folder.name}_screen_{today}.md"
    elif repo:
        # a screen of the redacted copy must not replace the scrubbed report of the raw screen
        out = repo / "reports" / f"{folder.name}_screen_{today}_from-redacted.md"
    else:
        out = folder.parent / f"{folder.name}_screen_{today}{'_team' if args.redact else ''}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    csv_path = Path(args.csv) if args.csv else out.with_suffix(".csv")
    out.write_text(render_markdown(results, participants, fleet, meta), encoding="utf-8")
    write_csv(csv_path, results, participants)
    listed = sum(1 for p in participants if any(r.fired for r in results[p["key"]].values()))
    print(f"Report: {out}\nCSV: {csv_path}\nParticipants screened {len(participants)}, listed {listed}, mode {mode}, {meta['seconds']:.0f} s.")
    if not args.redact:
        return 0
    if not raw_mode:
        print("--redact ignored: the folder is already redacted.")
        return 0
    # redact the data with the shared key, then scrub the report and csv with the same key
    try:
        from privacy import redact as redactor
    except ImportError:
        print("The privacy redactor is not available next to fraudscreen; cannot --redact.")
        return 2
    if args.key_dir:
        key_dir = Path(args.key_dir)
    elif repo:
        key_dir = repo / "raw-data" / ".redaction"
    else:
        from privacy import paths as ppaths
        key_dir = ppaths.find_key_dir(folder)
    safe = Path(args.safe) if args.safe else (repo / "data-redacted" / folder.name if repo else folder.parent / (folder.name + "_redacted"))
    rc = redactor.main(["--raw", str(folder), "--safe", str(safe), "--key-dir", str(key_dir), "--workers", str(args.workers)])
    if rc != 0:
        print(f"Redactor exited {rc}; the team report stands, no scrubbed report written.")
        return 2
    host_counts, prefix_counts, device_ids = _counts_for_scrub(participants, installs)
    pub = (repo / "reports" / out.name) if repo else out.with_name(out.name.replace("_team", ""))
    kw = dict(host_counts=host_counts, prefix_counts=prefix_counts, device_ids=device_ids)
    scrub_file(out, pub, key_dir, **kw)
    scrub_file(csv_path, pub.with_suffix(".csv"), key_dir, **kw)
    print(f"Redacted data: {safe}\nScrubbed report: {pub}\nScrubbed CSV: {pub.with_suffix('.csv')}")
    return 0


def _counts_for_scrub(participants, installs):
    """Participants per host and identifiers per lower-cased prefix (the two census numbers the
    redactor's host and prefix rules use, so the scrubbed report follows the same decisions), and
    every storage or display id the report can quote (the redactor's dev tokens)."""
    from collections import Counter
    hosts = {}
    devices = set()
    for p in participants:
        for inst in p["installs"]:
            for v in inst["visits"]:
                hosts.setdefault(v.host, set()).add(p["key"])
            for st in inst["status"]:
                devices.update(d for d, _ in st.disks)
                devices.update(d for d, _, _, _ in st.displays)
    prefixes = Counter()
    for ident in installs:
        m = re.match(r"^([A-Za-z]+_)", ident)
        if m:
            prefixes[m.group(1).lower()] += 1
    return {h: len(s) for h, s in hosts.items()}, dict(prefixes), devices

if __name__ == "__main__":
    sys.exit(main())
