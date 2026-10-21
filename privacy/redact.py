"""python3 -m privacy.redact: write a tokenized copy of the raw participant data
(spec, "What redact does")."""
import argparse
import csv
import os
import shutil
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from privacy import census, leakcheck, paths, tokens
from privacy.files import FileRedactor
from privacy.idscan import IdScanner
from privacy.points import PointRedactor
from privacy.urls import Scrubber, UrlRule

SKIP_TOP_DIRS = {".redaction", ".staging", ".previous-safe"}
SKIP_TOP_FILES = ("MOVED_*.tsv",)  # move manifests hold raw paths and file names, not data
_W = {}


def list_inputs(raw):
    out = []
    for dirpath, dirnames, filenames in os.walk(raw):
        here = Path(dirpath)
        if here == raw:
            dirnames[:] = [d for d in dirnames if d not in SKIP_TOP_DIRS]
            filenames = [f for f in filenames if not any(Path(f).match(g) for g in SKIP_TOP_FILES)]
        dirnames.sort()
        out += [here / f for f in sorted(filenames)]
    return out


def _init(key, cen, threshold, include_other=False):
    tok = tokens.Tokenizer(key)
    scanner = IdScanner(tok, cen["known"], cen["prefix_counts"], threshold)
    urls = UrlRule(scanner, cen["host_counts"], cen["domain_counts"], threshold)
    scrub = Scrubber(scanner, urls)
    _W.update(tok=tok, scanner=scanner,
              files=FileRedactor(scanner, PointRedactor(scanner, urls, scrub), scrub,
                                 include_other=include_other))


def _census_one(src):
    try:
        return census.census_file(Path(src))
    except Exception as e:  # counted by type only: a message can carry a raw path
        return census.census_error(type(e).__name__)


def _redact_one(job):
    src, rel, staging = job
    tok, scanner, files = _W["tok"], _W["scanner"], _W["files"]
    pts = files.points
    try:
        files.redact_file(Path(src), Path(rel), Path(staging))
    except Exception as e:  # counted by type only: a message can carry a raw path
        files.stats["unreadable " + type(e).__name__] += 1
    out = {"added": dict(tok.added), "stats": Counter(files.stats), "points": dict(pts.points),
           "dropped": {g: dict(v) for g, v in pts.dropped.items()},
           "dropped_by_rule": {g: dict(v) for g, v in pts.dropped_by_rule.items()},
           "ident_info": dict(scanner.ident_info)}
    for d in (tok.added, tok.lookup, files.stats, pts.points, pts.dropped, pts.dropped_by_rule,
              scanner.ident_info):
        d.clear()
    return out


def _map(fn, items, workers, initargs=None):
    """Yield results in input order; one process when workers is 1 (tests rely
    on this so that mock patches apply)."""
    if workers <= 1:
        if initargs:
            _init(*initargs)
        for item in items:
            yield fn(item)
        return
    with ProcessPoolExecutor(max_workers=workers, initializer=_init if initargs else None,
                             initargs=initargs or ()) as ex:
        yield from ex.map(fn, items, chunksize=4)


def _combine(results, lookup):
    t = {"stats": Counter(), "points": Counter(), "dropped": {}, "dropped_by_rule": {}, "ident_info": {}}
    before = len(lookup)
    for r in results:
        tokens.merge_lookup(lookup, r["added"])
        t["stats"].update(r["stats"])
        t["points"].update(r["points"])
        for store in ("dropped", "dropped_by_rule"):
            for gen, per in r[store].items():
                t[store].setdefault(gen, Counter()).update(per)
        t["ident_info"].update(r["ident_info"])
    t["new_tokens"] = len(lookup) - before
    return t


def _write_identifiers(path, ident_info):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["ident", "prefix", "pid", "pid_created", "install"])
        for tok in sorted(ident_info):
            info = ident_info[tok]
            w.writerow([tok, info["prefix"], info["pid"], info["pid_created"], info.get("install", tok)])


def _report(t, cen, threshold, n_inputs, elapsed, lookup_size):
    s = t["stats"]
    written = ", ".join(f"{k[6:]} {v}" for k, v in sorted(s.items()) if k.startswith("files "))
    lines = [f"redact run {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
             f"input files: {n_inputs}", "written: " + (written or "nothing")]
    for key in sorted(k for k in s if not k.startswith(("files ", "skipped "))):
        lines.append(f"{key}: {s[key]}")
    for name, n in sorted(cen["errors"].items()):
        lines.append(f"census errors {name}: {n}")
    skipped = sorted((k[8:], v) for k, v in s.items() if k.startswith("skipped "))
    if skipped:
        lines.append("not copied: " + ", ".join(f"{ext} {n}" for ext, n in skipped))
    lines.append("points by generator:")
    lines += [f"  {g or '(none)'}: {n}" for g, n in sorted(t["points"].items())]
    for title, store in (("fields dropped, no rule:", "dropped"), ("fields dropped by rule:", "dropped_by_rule")):
        if t[store]:
            lines.append(title)
            lines += [f"  {gen}: {path} ({n})" for gen in sorted(t[store])
                      for path, n in sorted(t[store][gen].items())]
    hosts = cen["host_counts"]
    kept = sum(n >= threshold for n in hosts.values())
    lines.append(f"hosts kept readable (>= {threshold} participants): {kept} of {len(hosts)}")
    shown = sorted({i["prefix"] for i in t["ident_info"].values() if i.get("prefix")})
    lines.append("identifier prefixes shown: " + (", ".join(shown) or "none"))
    lines.append(f"tokens in lookup: {lookup_size} ({t['new_tokens']} new)")
    lines.append(f"elapsed: {elapsed:.0f} s")
    return lines


def _swap(staging, safe, previous):
    shutil.rmtree(previous, ignore_errors=True)
    if safe.exists():
        os.replace(safe, previous)
    try:
        os.replace(staging, safe)
    except OSError:  # staging and the published folder on different volumes
        shutil.move(str(staging), str(safe))
    shutil.rmtree(previous, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Write a tokenized copy of the raw participant data.")
    ap.add_argument("--raw", required=True, help="folder of raw exports")
    ap.add_argument("--safe", default=None, help="where the redacted copy goes (default: <raw>_redacted next to it)")
    ap.add_argument("--key-dir", default=None, help="folder holding key and lookup.tsv (default: nearest .redaction/ above --raw, else <raw>/.redaction)")
    ap.add_argument("--workers", type=int, default=max(1, min(4, (os.cpu_count() or 2) - 1)))
    ap.add_argument("--host-threshold", type=int, default=5)
    ap.add_argument("--include-other-files", action="store_true",
                    help="also copy reports, CSVs, logs and scripts (scrubbed); by default only "
                         "PDK exports are published")
    args = ap.parse_args(argv)
    raw = Path(args.raw)
    safe = Path(args.safe) if args.safe else raw.resolve().parent / (raw.resolve().name + "_redacted")
    key_dir = Path(args.key_dir) if args.key_dir else paths.find_key_dir(raw)
    if paths.inside_claude() and paths.in_raw_folder(raw):
        print("Refusing to run inside a Claude session: this reads the raw folder. "
              "Run python3 -m privacy.redact in your own terminal.")
        return 2
    if not raw.is_dir():
        print("Raw folder not found; pass --raw.")
        return 2
    try:
        return _run(args, raw, safe, key_dir)
    except Exception as e:
        shutil.rmtree(raw / ".staging", ignore_errors=True)
        print(f"redact stopped on an unexpected {type(e).__name__}. The message is withheld because it "
              "can contain raw paths. Nothing was published.")
        return 4


def _run(args, raw, safe, key_dir=None):
    started = time.time()
    red, staging = (Path(key_dir) if key_dir else raw / ".redaction"), raw / ".staging"
    red.mkdir(parents=True, exist_ok=True)
    key = tokens.load_or_create_key(red / "key")
    lookup = tokens.read_lookup(red / "lookup.tsv")
    inputs = list_inputs(raw)
    print(f"inputs: {len(inputs)} files, {args.workers} workers")
    cen = census.merge_census(_map(_census_one, [str(p) for p in inputs], args.workers))
    print("census done")
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    work = {k: cen[k] for k in ("known", "prefix_counts", "host_counts", "domain_counts")}
    jobs = [(str(p), str(p.relative_to(raw)), str(staging)) for p in inputs]
    try:
        t = _combine(_map(_redact_one, jobs, args.workers, (key, work, args.host_threshold, args.include_other_files)), lookup)
    except tokens.TokenCollision as e:
        shutil.rmtree(staging, ignore_errors=True)
        print(f"Token collision on {e}. Nothing was published; check lookup.tsv and the key.")
        return 3
    _write_identifiers(staging / "identifiers.csv", t["ident_info"])
    lines = _report(t, cen, args.host_threshold, len(inputs), time.time() - started, len(lookup))
    report = staging / "_redaction_report.txt"
    report.write_text("\n".join(lines) + "\n")
    hits = leakcheck.scan_tree(staging, cen["leak"], tokens.Tokenizer(key), cen["leak_prefixes"])
    if hits:
        shutil.rmtree(staging, ignore_errors=True)
        print(f"LEAK CHECK FAILED: {len(hits)} hits. Nothing was published; the previous copy is unchanged.")
        for kind, token, where in hits[:50]:
            print(f"  {kind:<10} {token}  {where}")
        if len(hits) > 50:
            print(f"  ... and {len(hits) - 50} more")
        return 1
    with report.open("a") as f:
        f.write("leak check: clean\n")
    tokens.write_lookup(red / "lookup.tsv", lookup)
    leak_file = red / "leak_known.txt"
    leak_file.write_text("".join(h.decode() + "\n" for h in sorted(cen["leak"])))
    os.chmod(leak_file, 0o600)
    prefix_file = red / "leak_prefixes.txt"
    prefix_file.write_text("".join(h.decode() + "\n" for h in sorted(cen["leak_prefixes"])))
    os.chmod(prefix_file, 0o600)
    _swap(staging, safe, raw / ".previous-safe")
    print("\n".join(lines))
    print("leak check: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
