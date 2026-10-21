"""Keyed tokens. A token is <kind>_ plus the first 16 hex characters of
HMAC-SHA256(key, "kind:value"). The lookup maps each token back to its value."""
import csv
import hashlib
import hmac
import os
import secrets
from pathlib import Path

KINDS = ("ident", "pid", "email", "dev", "host", "url", "q")
TOKEN_RE = r"(?:ident|pid|email|dev|host|url|q)_[0-9a-f]{16}"

csv.field_size_limit(1 << 30)  # URLs and query values can exceed the 128 KB default


class TokenCollision(Exception):
    pass


def load_or_create_key(path):
    path = Path(path)
    if path.exists():
        return bytes.fromhex(path.read_text().strip())
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(key.hex() + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return key


class Tokenizer:
    def __init__(self, key, lookup=None):
        self.key = key
        self.lookup = dict(lookup or {})  # token -> (kind, value)
        self.added = {}

    def token(self, kind, value):
        if kind not in KINDS:
            raise ValueError(f"unknown token kind: {kind}")
        digest = hmac.new(self.key, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
        tok = f"{kind}_{digest[:16]}"
        seen = self.lookup.get(tok)
        if seen is None:
            self.lookup[tok] = (kind, value)
            self.added[tok] = (kind, value)
        elif seen != (kind, value):
            raise TokenCollision(tok)
        return tok


def merge_lookup(into, entries):
    for tok, kind_value in entries.items():
        seen = into.get(tok)
        if seen is None:
            into[tok] = kind_value
        elif seen != kind_value:
            raise TokenCollision(tok)


def read_lookup(path):
    path = Path(path)
    out = {}
    if not path.exists():
        return out
    with path.open(encoding="utf-8", newline="") as f:
        rows = csv.reader(f, delimiter="\t")
        next(rows, None)  # header
        for tok, kind, value in rows:
            out[tok] = (kind, value)
    return out


def write_lookup(path, lookup):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["token", "kind", "value"])
        for tok in sorted(lookup):
            kind, value = lookup[tok]
            w.writerow([tok, kind, value])
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
