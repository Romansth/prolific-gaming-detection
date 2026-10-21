"""python3 -m privacy.reidentify: copy report_claude/ into report_processed/ with every
token swapped back to the value it stands for (spec, "What reidentify does")."""
import argparse
import re
import shutil
import sys
from pathlib import Path

from privacy import paths, tokens

URL_FORM_RE = re.compile(r"(?<![A-Za-z0-9+.-])(?:[a-z][a-z0-9+.-]*:(?://[^/\s\"'<>]*/)?)?"
                         r"url_[0-9a-f]{16}(?:\?ids=[A-Za-z0-9_,]+)?")
IDENT_FORM_RE = re.compile(r"(?<![A-Za-z0-9])(?:(?:AIM(?:MS|EC)|WEI)[a-z]+[A-Z0-9]*_)?ident_[0-9a-f]{16}")
TOKEN_FIND_RE = re.compile(r"(?<![A-Za-z0-9])" + tokens.TOKEN_RE)
_URL_TOKEN_RE = re.compile(r"url_[0-9a-f]{16}")


def restore(text, lookup, unknown):
    def value(tok, fallback):
        hit = lookup.get(tok)
        if hit is None:
            unknown.add(tok)
            return fallback
        return hit[1]

    text = URL_FORM_RE.sub(lambda m: value(_URL_TOKEN_RE.search(m.group(0)).group(0), m.group(0)), text)
    text = IDENT_FORM_RE.sub(lambda m: value(m.group(0)[m.group(0).rindex("ident_"):], m.group(0)), text)
    return TOKEN_FIND_RE.sub(lambda m: value(m.group(0), m.group(0)), text)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Swap the tokens in Claude's reports back to real values.")
    ap.add_argument("--reports", default=str(paths.DEFAULT_REPORTS))
    ap.add_argument("--out", default=str(paths.DEFAULT_PROCESSED))
    ap.add_argument("--key-dir", default=None, help="folder holding key and lookup.tsv (default: nearest .redaction/ above --reports)")
    args = ap.parse_args(argv)
    reports, out = Path(args.reports), Path(args.out)
    key_dir = Path(args.key_dir) if args.key_dir else paths.find_key_dir(reports)
    raw = key_dir.parent
    if paths.inside_claude() and (paths.in_raw_folder(key_dir) or paths.in_raw_folder(out)
                                  or paths.within(out, paths.DEFAULT_PROCESSED)):
        print("Refusing to run inside a Claude session: this writes real IDs. "
              "Run python3 -m privacy.reidentify in your own terminal.")
        return 2
    lookup = tokens.read_lookup(key_dir / "lookup.tsv")
    if not lookup:
        print("No lookup table yet. Run python3 -m privacy.redact first.")
        return 2
    if not reports.is_dir():
        print("Reports folder not found; pass --reports.")
        return 2
    unknown, rewritten, binaries = set(), 0, []
    for src in sorted(p for p in reports.rglob("*") if p.is_file()):
        rel = src.relative_to(reports)
        dest = out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        try:
            if b"\x00" in data:
                raise UnicodeDecodeError("utf-8", data, 0, 1, "NUL byte")
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            shutil.copyfile(src, dest)
            binaries.append(str(rel))
            continue
        with open(dest, "w", encoding="utf-8", newline="") as f:
            f.write(restore(text, lookup, unknown))
        rewritten += 1
    print(f"files rewritten: {rewritten}")
    if binaries:
        print(f"copied unchanged (not text, tokens inside are not replaced): {len(binaries)}")
        for b in binaries:
            print("  " + b)
    if unknown:
        print(f"tokens not in the lookup (left as they are): {len(unknown)}")
        for tok in sorted(unknown):
            print("  " + tok)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
