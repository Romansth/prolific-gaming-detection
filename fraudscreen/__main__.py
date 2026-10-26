"""python -m fraudscreen [--data <folder>] [--out report.html] [--csv file.csv] [--redact] [--open] ...
Without --data: the newest pull in this checkout, redacted, and the team page opened."""
import argparse
import datetime as dt
from collections import Counter
import os
import sys
import time
import webbrowser
from pathlib import Path

from fraudscreen import __version__
from fraudscreen.arms import load_arms, participant_arm
from fraudscreen.files import discover, list_inputs, parse_name
from fraudscreen.fleet import build_fleet
from fraudscreen.participants import _PIDTOKEN_RE, _RAW_RE, _TOKEN_RE, default_exclude, group
from fraudscreen.report import build_model, render_html, write_csv
from fraudscreen.scan import scan_folder
from fraudscreen.scrub import leaks, scrub_file, scrub_model
from fraudscreen.signs import SIGNS, Context
from fraudscreen.signs.accounts import score_accounts
from fraudscreen.signs.behaviour import score_behaviour
from fraudscreen.signs.location import score_location
from fraudscreen.signs.machine import score_machine
from fraudscreen.signs.tooling import score_tooling
import re


def detect_mode(folder):
    """'raw' when any file name carries a real 24-hex id, whatever sits beside it (a stray
    identifiers.csv must not send a real-id report to reports/); 'redacted' when the names carry
    tokens; the csv only decides for a folder whose names say nothing."""
    tokens = False
    for inp in list_inputs(folder):   # every name: one raw file among hundreds of token files still makes it raw
        fn = parse_name(inp.name)
        if fn and _RAW_RE.match(fn.ident):
            return "raw"
        if fn and (_PIDTOKEN_RE.match(fn.ident) or _TOKEN_RE.match(fn.ident)):
            tokens = True
    if tokens or (folder / "identifiers.csv").exists() or (folder.parent / "identifiers.csv").exists():
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


REPO_ROOT = Path(__file__).resolve().parents[1]   # this checkout; tests point it at a temporary repo
SHARE_DIR = REPO_ROOT / "reports"                  # this checkout's shareable folder


def newest_pulls(raw_dir):
    """Pull folders under the raw folder, oldest first by modification time, so the last one is the
    pull most recently copied in; dot-folders (the key folder) are not pulls."""
    if not raw_dir.is_dir():
        return []
    pulls = [d for d in raw_dir.glob("*") if d.is_dir() and not d.name.startswith(".")]
    return sorted(pulls, key=lambda d: d.stat().st_mtime)


def _in_shareable_folder(path, repo=None):
    """True when path, which need not exist yet, lies inside a folder real ids must never reach:
    a reports/ folder (any case) beside a raw or fraudscreen folder, i.e. the repo layout seen from
    wherever the pull lives; this checkout's reports/ and the detected repo's reports/ by inode,
    so a symlink target does not slip past either."""
    full = Path(os.path.abspath(path))
    for anc in full.parents:
        if anc.name.lower() == "reports" and any((anc.parent / x).is_dir() for x in (RAW_FOLDER_NAMES[-1], "fraudscreen")):
            return True
    existing = full
    while not existing.exists() and existing.parent != existing:
        existing = existing.parent
    targets = [SHARE_DIR] + ([repo / "reports"] if repo else [])
    for anc in [existing] + list(existing.parents):
        for t in targets:
            try:
                if t.exists() and os.path.samefile(anc, t):
                    return True
            except OSError:
                pass
    return False


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


def agent_session():
    """Claude Code sets CLAUDECODE=1 in its shells, Codex sets CODEX_THREAD_ID and CODEX_SESSION_ID."""
    return os.environ.get("CLAUDECODE") == "1" or bool(os.environ.get("CODEX_THREAD_ID")) or bool(os.environ.get("CODEX_SESSION_ID"))


def refuse_inside_claude(folder):
    """The raw folder is out of bounds for a Claude Code or Codex session; the person runs the screen
    on it."""
    if not agent_session():
        return False
    p = Path(folder)   # the path as given and where it really points, so a symlink is no way around
    return any(part in RAW_FOLDER_NAMES for part in p.parts + p.resolve().parts)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fraudscreen", description="Screen a folder of PDK exports for signs of participant gaming.")
    ap.add_argument("--data", help="folder of per-identifier export files (json, or zips of them); without it, the newest "
                    "pull folder in this checkout is screened with --redact and --open")
    ap.add_argument("--out", help="HTML report path (default: <folder>_screen_<date>.html, or reports/ in a repo layout)")
    ap.add_argument("--csv", help="csv path (default: next to the report)")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--redact", action="store_true", help="run the privacy redactor first and screen the redacted copy")
    ap.add_argument("--open", action="store_true", help="open the team report in the browser once written")
    ap.add_argument("--safe", help="where the redacted copy goes (default: <folder>_redacted, or data-redacted/<name> in a repo layout)")
    ap.add_argument("--key-dir", help="folder holding the redactor key and lookup (default: nearest .redaction/ above the data)")
    ap.add_argument("--arms", help="arms.json mapping configuration-hash prefixes to arm names")
    ap.add_argument("--min-visits", type=int, default=50, help="installs below this many visits do not set fleet percentiles")
    ap.add_argument("--exclude-pattern", action="append", default=None, help="regex for internal identifiers to skip (repeatable)")
    args = ap.parse_args(argv)
    if not args.data:
        if agent_session():   # before anything lists the raw folder: not even a pull's name may leave it
            print("Refusing: without --data the screen targets the newest raw pull, which is out of bounds in a Claude Code "
                  "or Codex session. Pass --data data-redacted/<pull>.")
            return 2
        pulls = newest_pulls(REPO_ROOT / RAW_FOLDER_NAMES[-1])
        if not pulls:
            print(f"No pull found under {RAW_FOLDER_NAMES[-1]}/: put a pull folder there, or pass --data.")
            return 2
        newest = pulls[-1]
        when = dt.datetime.fromtimestamp(newest.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        others = ", ".join(p.name for p in reversed(pulls[:-1])) or "none"
        print(f"Screening the newest pull: {newest.name} (modified {when}); also present: {others}. Pass --data to screen another.")
        args.data, args.redact, args.open = str(newest), True, True
    t_start = time.time()
    # abspath, not resolve(): a pull symlinked under raw-data/ keeps the repo layout and the shared key
    folder = Path(os.path.abspath(os.path.expanduser(args.data)))
    if not folder.is_dir():
        print(f"Data folder not found: {args.data}")
        return 2
    if refuse_inside_claude(folder):
        print("Refusing to screen a raw-data folder inside a Claude Code or Codex session: run this command in your own "
              "terminal. The agent works from data-redacted/ and reports/.")
        return 2
    repo, kind = repo_layout(folder)
    today = dt.date.today().isoformat()
    mode = detect_mode(folder)
    raw_mode = mode == "raw"
    if repo and raw_mode and kind == "redacted":
        print(f"Refusing: raw export files found under data-redacted/{folder.name}; move the pull to "
              f"{RAW_FOLDER_NAMES[-1]}/{folder.name} and run again.")
        return 2
    exclude = [re.compile(p, re.I) for p in args.exclude_pattern] if args.exclude_pattern else default_exclude()
    inputs, skipped_files = discover(folder)
    installs = scan_folder(folder, args.workers, raw_mode, inputs=inputs)
    ids_csv = folder / "identifiers.csv"
    if not ids_csv.exists():
        ids_csv = folder.parent / "identifiers.csv" if (folder.parent / "identifiers.csv").exists() else None
    participants, skipped = group(installs, ids_csv, exclude)
    n_visits = sum(len(i["visits"]) for p in participants for i in p["installs"])
    not_read = ", ".join(f"{k} {v}" for k, v in sorted(skipped_files.items())) or "none"
    if not participants or n_visits == 0:
        print(f"Nothing screenable: {len(installs)} installs, skipped {dict(skipped)}, history points {n_visits}, "
              f"files not read: {not_read}.")
        return 3
    arms = load_arms(args.arms)
    for p in participants:
        p["arm"] = participant_arm(p, arms)
    fleet = build_fleet(participants, args.min_visits, raw_mode)
    results = score_all(participants, fleet, raw_mode)
    days = sorted({parse_name(f).day for p in participants for i in p["installs"] for f in i["files"] if parse_name(f)})
    meta = dict(folder=folder.name, mode=mode, files=sum(len(i["files"]) for p in participants for i in p["installs"]),
                installs=sum(len(p["installs"]) for p in participants), participants=len(participants), skipped=dict(skipped),
                unreadable=sum(i["unreadable"] for i in installs.values()), skipped_files=dict(skipped_files),
                no_time=sum(i.get("no_time", 0) for i in installs.values()), visits=n_visits,
                no_status=sum(1 for p in participants if not any(i["status"] for i in p["installs"])),
                date_range=f"{days[0]}..{days[-1]}" if days else "", version=__version__, seconds=time.time() - t_start, run_date=today,
                arms_available=bool(arms))
    # where the first (unscrubbed) report goes: a raw screen carries real ids and belongs with the team
    pub = None
    if args.out:
        out = Path(args.out)
        if args.redact and raw_mode and not repo:
            # the name given is the shareable report; the real-id one goes beside it
            pub, out = out, out.with_name(out.stem + "_team" + out.suffix)
    elif repo and raw_mode:
        out = repo / "reports-team" / f"{folder.name}_screen_{today}.html"
    elif repo:
        # a screen of the redacted copy must not replace the scrubbed report of the raw screen
        out = repo / "reports" / f"{folder.name}_screen_{today}_from-redacted.html"
    else:
        out = folder.parent / f"{folder.name}_screen_{today}{'_team' if args.redact else ''}.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    csv_path = Path(args.csv) if args.csv else out.with_suffix(".csv")
    if raw_mode and any(_in_shareable_folder(x, repo) for x in (out, csv_path)):
        print("Refusing: a raw screen cannot write its report or CSV under reports/ (they carry real ids); "
              "drop --out/--csv or point them elsewhere.")
        return 2
    model = build_model(results, participants, fleet, meta)
    out.write_text(render_html(model), encoding="utf-8")
    write_csv(csv_path, results, participants)
    print(f"Report: {out}\nCSV: {csv_path}\nParticipants screened {len(participants)}, flagged {model['n_flagged']}, mode {mode}, {meta['seconds']:.0f} s.")
    if args.open and not webbrowser.open(out.resolve().as_uri()):
        print("No browser opened; the report path is above.")
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
    pub = pub or ((repo / "reports" / out.name) if repo else out.with_name(out.name.replace("_team", "")))
    kw = dict(host_counts=host_counts, prefix_counts=prefix_counts, device_ids=device_ids)
    # the token-only page is rendered from the scrubbed data model, not scrubbed as HTML
    try:
        pub_model = scrub_model(model, key_dir, **kw)
    except RuntimeError as exc:
        print(f"Scrub failed: {exc}. The team report stands.")
        return 2
    pub_model["ids"] = "tokens"
    hits = Counter(kind for kind, _ in leaks(pub_model, model))   # kinds only: the values would be the leak
    if hits:
        print("Refusing to write the token-only report: the leak check found "
              + ", ".join(f"{n} {kind}" for kind, n in sorted(hits.items())) + ". The team report stands.")
        return 2
    pub.parent.mkdir(parents=True, exist_ok=True)
    pub.write_text(render_html(pub_model), encoding="utf-8")
    scrub_file(csv_path, pub.with_suffix(".csv"), key_dir, **kw)
    print(f"Redacted data: {safe}\nScrubbed report: {pub}\nScrubbed CSV: {pub.with_suffix('.csv')}")
    return 0


def _counts_for_scrub(participants, installs):
    """Participants per host and identifiers per lower-cased prefix (the two census numbers the
    redactor's host and prefix rules use, so the scrubbed report follows the same decisions), and
    every storage or display id the report can quote (the redactor's dev tokens)."""
    hosts = {}
    devices = set()
    for p in participants:
        for inst in p["installs"]:
            for v in inst["visits"]:
                hosts.setdefault(v.host, set()).add(p["key"])
            for st in inst["status"]:
                devices.update(d for d, _ in st.disks if len(d) >= 6)
                devices.update(d for d, _, _, _ in st.displays if len(d) >= 6)
    # count prefixes exactly as the redactor's census does, so the scrub hides the same ones
    from privacy.idscan import IDENT_RE, ident_parts
    prefixes = Counter()
    for ident in installs:
        m = IDENT_RE.match(ident)
        if m:
            prefixes[ident_parts(m)[0].lower()] += 1
    return {h: len(s) for h, s in hosts.items()}, dict(prefixes), devices

if __name__ == "__main__":
    sys.exit(main())
