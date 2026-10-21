"""Leak check (spec, "Leak check"). Written separately from the redactor and
importing none of its scanning code, so one bug cannot sit in both."""
import argparse
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, unquote_to_bytes

from privacy import paths, tokens

LK_RUN = re.compile(rb"[0-9a-fA-F]{24,}")
LK_IDENT = re.compile(rb"(?:AIM(?:MS|EC)|WEI)[a-z]+[A-Z0-9]*_"
                      rb"(?!(?:ident|pid|email|dev|host|url|q)_[0-9a-f]{16})[A-Za-z0-9]+"
                      rb"|(?:aim(?:ms|ec)|wei)[a-z]+_(?!(?:ident|pid|email|dev|host|url|q)_[0-9a-f]{16})[0-9a-f]{24}[0-9]*")
# A local part starts a run (or follows a %XX escape) and is at most 64 long,
# the RFC limit. Anchoring the start keeps the scan at one step per byte.
LK_EMAIL = re.compile(rb"(?:(?<![A-Za-z0-9._+-])|(?<=%[0-9A-Fa-f]{2}))[A-Za-z0-9._+-]{1,64}(?:@|%40)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# Identifier shorthand as analysts write it: any-case cohort prefix plus hex
# ("weib_" and 8 hex). A full, correctly cased identifier is LK_IDENT.
LK_FRAGMENT = re.compile(rb"(?:[Aa][Ii][Mm](?:[Mm][Ss]|[Ee][Cc])|[Ww][Ee][Ii])[A-Za-z]*_"
                         rb"(?!(?:ident|pid|email|dev|host|url|q)_[0-9a-f]{16})[0-9a-fA-F]{6,}")
# Exactly 8 hex on their own (a UUID group is excluded by the dash rule).
LK_HEX8 = re.compile(rb"(?<![0-9a-fA-F-])[0-9a-fA-F]{8}(?![0-9a-fA-F-])")
LK_HEX24 = re.compile(rb"[0-9a-fA-F]{24}")
_TOKEN_KIND = {"hex24": "pid", "known-id": "pid", "identifier": "ident", "email": "email",
               "id-fragment": "ident", "id-prefix": "pid"}
SKIP_DIRS = {".git", "node_modules"}


def _decodings(data):
    out = [data]
    for _ in range(3):
        nxt = unquote_to_bytes(out[-1])
        if nxt == out[-1]:
            break
        out.append(nxt)
    return out


_LK_SEPARATORS = frozenset(b" \t\r\n\f\v\"'<>")
_LK_SEPARATOR = re.compile(rb"[\s\"'<>]")


def _lk_windows(data):
    """Separator-bounded stretches of data holding a %, without copying it all."""
    pos, n = 0, len(data)
    while True:
        i = data.find(b"%", pos)
        if i == -1:
            return
        start = i
        while start > pos and data[start - 1] not in _LK_SEPARATORS:
            start -= 1
        m = _LK_SEPARATOR.search(data, i)
        end = m.start() if m else n
        yield data[start:end]
        pos = end


def _lk_runs(d, known):
    for m in LK_RUN.finditer(d):
        if m.start() and d[m.start() - 1] == 0x25:
            continue
        run = m.group(0).lower()
        if len(run) < 32:
            known.add(run[:24])


def collect(data):
    """24-hex IDs in raw bytes: exact runs and the first 24 of 25-31 runs, in
    the bytes and in up to three percent-decodings of each stretch holding a
    %. A run right after % is an escape plus hex; the decoded copy of its
    stretch shows the real boundary."""
    known = set()
    _lk_runs(data, known)
    for window in _lk_windows(data):
        for d in _decodings(window)[1:]:
            _lk_runs(d, known)
    return known


def collect_prefixes(data):
    """The first 8 hex of each Prolific ID inside a study identifier: the
    account-creation part that write-ups quote. Used to catch ID shorthand."""
    out = set()
    for m in LK_IDENT.finditer(data):
        inner = LK_HEX24.search(m.group(0))
        if inner:
            out.add(inner.group(0)[:8].lower())
    return out


def scan(data, known, prefixes=frozenset()):
    hits = []
    for m in LK_RUN.finditer(data):
        run = m.group(0).lower()
        if len(run) == 24:
            hits.append(("hex24", run))
            continue
        window = next((run[i:i + 24] for i in range(len(run) - 23) if run[i:i + 24] in known), None)
        if window is not None:
            hits.append(("known-id", window))
    ident_starts = set()
    for m in LK_IDENT.finditer(data):
        hits.append(("identifier", m.group(0)))
        ident_starts.add(m.start())
    hits += [("id-fragment", m.group(0)) for m in LK_FRAGMENT.finditer(data) if m.start() not in ident_starts]
    if prefixes:
        hits += [("id-prefix", m.group(0)) for m in LK_HEX8.finditer(data) if m.group(0).lower() in prefixes]
    hits += [("email", m.group(0)) for m in LK_EMAIL.finditer(data)]
    return hits


def display_token(tokenizer, kind, value):
    text = value.decode("utf-8", errors="replace")
    if kind == "email":
        text = unquote(text).lower()
    return tokenizer.token(_TOKEN_KIND[kind], text)


def safe_text(data):
    for pattern in (LK_IDENT, LK_FRAGMENT, LK_EMAIL, LK_RUN):
        data = pattern.sub(b"<redacted>", data)
    return data.decode("utf-8", errors="replace")


def scan_tree(root, known, tokenizer, prefixes=frozenset()):
    hits = []
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(dirnames) + sorted(filenames):
            p = Path(dirpath) / name
            rel = str(p.relative_to(root)).encode("utf-8", "surrogateescape")
            found = scan(rel, known, prefixes)
            unreadable = False
            if p.is_file():
                try:
                    found += scan(p.read_bytes(), known, prefixes)
                except OSError:
                    unreadable = True  # cannot be checked, so it counts against the check
            hits += [(k, display_token(tokenizer, k, v), safe_text(rel)) for k, v in found]
            if unreadable:
                hits.append(("unreadable", "-", safe_text(rel)))
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description="Search files for participant IDs that should be tokens.")
    ap.add_argument("targets", nargs="*", help="files or folders to scan")
    ap.add_argument("--raw", default=str(paths.DEFAULT_RAW), help="raw folder holding .redaction/")
    ap.add_argument("--stdin", action="store_true", help="also scan standard input (e.g. git log -p)")
    args = ap.parse_args(argv)
    raw = Path(args.raw)
    if paths.inside_claude() and paths.within(raw, paths.DEFAULT_RAW):
        print("Refusing to run inside a Claude session: this reads the raw folder. Run it in your own terminal.")
        return 2
    red = raw / ".redaction"
    if not (red / "leak_known.txt").exists() or not (red / "key").exists():
        print("No leak list yet. Run python3 -m privacy.redact first.")
        return 2
    known = {line.strip().encode() for line in (red / "leak_known.txt").read_text().splitlines() if line.strip()}
    tok = tokens.Tokenizer(bytes.fromhex((red / "key").read_text().strip()))
    pfile = red / "leak_prefixes.txt"
    prefixes = {line.strip().encode() for line in pfile.read_text().splitlines() if line.strip()} if pfile.exists() else set()
    hits = []
    try:
        if args.stdin:
            hits += [(k, display_token(tok, k, v), "<stdin>") for k, v in scan(sys.stdin.buffer.read(), known, prefixes)]
        for target in args.targets:
            p = Path(target)
            if p.is_dir():
                hits += scan_tree(p, known, tok, prefixes)
            elif p.is_file():
                name = str(p).encode()
                try:
                    found = scan(name + b"\n" + p.read_bytes(), known, prefixes)
                except OSError:
                    found = scan(name, known, prefixes)
                    hits.append(("unreadable", "-", safe_text(name)))
                hits += [(k, display_token(tok, k, v), safe_text(name)) for k, v in found]
    except Exception as e:
        print(f"leakcheck stopped on an unexpected {type(e).__name__}. The message is withheld because "
              "it can contain a path.")
        return 4
    print(f"hits: {len(hits)}")
    for kind, token, where in hits:
        print(f"  {kind:<10} {token}  {where}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
