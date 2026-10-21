"""One-off: replace participant IDs and ID fragments in Claude's memory notes
with tokens. The originals are copied into the raw folder first."""
import argparse
import os
import re
import shutil
import sys
import time
from pathlib import Path

from privacy import paths, tokens
from privacy.idscan import HEX24_RE, IdScanner

# Claude Code names a project's folder after its path, with "/" replaced by "-".
DEFAULT_NOTES = (Path.home() / ".claude" / "projects"
                 / ("-" + str(paths.REPO).strip("/").replace("/", "-")) / "memory")
FRAGMENT_RE = re.compile(r"((?:AIM(?:MS|EC)|WEI)[a-z]+[A-Z0-9]*_)([0-9a-f]{6,23})(?![0-9a-f])")
PREFIX8_RE = re.compile(r"(?<![0-9a-fA-F_])([0-9a-f]{8})(?![0-9a-f])")


def _unique(candidates, start):
    hits = [tok for tok, value in candidates if value.startswith(start)]
    return hits[0] if len(hits) == 1 else (None if not hits else "")


def rekey_text(text, scanner, idents, participant_pids, all_pids):
    """Fragments first: the full scan would otherwise give "WEIb_65f1c0de" a
    token of its own instead of the token of the identifier it abbreviates."""
    counts = {"full": 0, "fragment": 0, "prefix": 0, "ambiguous": 0}

    def fragment(m):
        hit = _unique(idents, m.group(1) + m.group(2))
        if hit:
            counts["fragment"] += 1
            return hit
        counts["ambiguous"] += hit == ""
        return m.group(0)

    def prefix(m):
        hit = _unique(participant_pids, m.group(1))
        if hit is None:
            hit = _unique(all_pids, m.group(1))
        if hit:
            counts["prefix"] += 1
            return hit
        counts["ambiguous"] += hit == ""
        return m.group(0)

    text = FRAGMENT_RE.sub(fragment, text)
    found = []
    text = scanner.scan(text, found)
    counts["full"] = len(found)
    return PREFIX8_RE.sub(prefix, text), counts


def main(argv=None):
    ap = argparse.ArgumentParser(description="Replace participant IDs in Claude's memory notes with tokens.")
    ap.add_argument("--notes", default=str(DEFAULT_NOTES))
    ap.add_argument("--raw", default=str(paths.DEFAULT_RAW))
    ap.add_argument("--dry-run", action="store_true", help="count, write nothing")
    args = ap.parse_args(argv)
    notes, raw = Path(args.notes), Path(args.raw)
    if paths.inside_claude() and paths.within(raw, paths.DEFAULT_RAW):
        print("Refusing to run inside a Claude session: this reads the lookup table. Run it in your own terminal.")
        return 2
    red = raw / ".redaction"
    lookup = tokens.read_lookup(red / "lookup.tsv")
    if not lookup or not (red / "key").exists():
        print("No lookup table yet. Run python3 -m privacy.redact first.")
        return 2
    tok = tokens.Tokenizer(bytes.fromhex((red / "key").read_text().strip()), lookup)
    idents = [(t, v) for t, (k, v) in lookup.items() if k == "ident"]
    all_pids = [(t, v) for t, (k, v) in lookup.items() if k == "pid"]
    inner = {m.group(0).lower() for _, v in idents for m in HEX24_RE.finditer(v)}
    participant_pids = [(t, v) for t, v in all_pids if v in inner]
    scanner = IdScanner(tok, known_hex={v for _, v in all_pids}, threshold=10 ** 9)  # no visible prefixes
    backup = red / ("notes-backup-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    for note in sorted(notes.glob("*.md")):
        original = note.read_text(encoding="utf-8")
        text, counts = rekey_text(original, scanner, idents, participant_pids, all_pids)
        print(f"{note.name}: full {counts['full']}, fragments {counts['fragment']}, "
              f"prefixes {counts['prefix']}, ambiguous {counts['ambiguous']}")
        if args.dry_run or text == original:
            continue
        backup.mkdir(parents=True, exist_ok=True)
        shutil.copy2(note, backup / note.name)
        tmp = note.with_name(note.name + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, note)
    if not args.dry_run and len(tok.lookup) > len(lookup):
        tokens.write_lookup(red / "lookup.tsv", tok.lookup)  # so reidentify can reverse the new tokens
    return 0


if __name__ == "__main__":
    sys.exit(main())
