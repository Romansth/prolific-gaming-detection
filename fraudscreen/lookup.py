"""python -m fraudscreen.lookup <prolific id | identifier | email> [--key-dir DIR]

Prints the token(s) the redacted data and the scrubbed reports use for a real value, and nothing
else. The key is read from --key-dir, else from the nearest raw-data/.redaction or .redaction
folder found walking up from the current directory."""
import argparse
import re
import sys
from pathlib import Path

from privacy import tokens
from privacy.idscan import IDENT_RE, IdScanner, ident_parts

HEX24 = re.compile(r"^[0-9a-fA-F]{24}$")


def find_key_dir(start=None):
    p = Path(start or Path.cwd()).resolve()
    for folder in [p] + list(p.parents):
        for cand in (folder / "raw-data" / ".redaction", folder / ".redaction"):
            if (cand / "key").exists():
                return cand
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fraudscreen.lookup", description="Real value -> redaction token.")
    ap.add_argument("value")
    ap.add_argument("--key-dir", default=None)
    args = ap.parse_args(argv)
    key_dir = Path(args.key_dir) if args.key_dir else find_key_dir()
    if key_dir is None or not (key_dir / "key").exists():
        print("No redaction key found; pass --key-dir <folder holding key>.")
        return 2
    tok = tokens.Tokenizer(tokens.load_or_create_key(key_dir / "key"))
    value = args.value.strip()
    if HEX24.match(value):
        print(tok.token("pid", value.lower()))
        return 0
    m = IDENT_RE.search(value)
    if m:
        prefix, suffix = ident_parts(m)
        print("ident: " + tok.token("ident", prefix + suffix))
        inner = re.search(r"[0-9a-fA-F]{24}", suffix)
        if inner:
            print(tok.token("pid", inner.group(0).lower()))
        return 0
    if "@" in value:
        print(tok.token("email", value.lower()))
        return 0
    scanner = IdScanner(tok, known_hex=set(), prefix_counts={}, threshold=1)
    print(scanner.scan(value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
