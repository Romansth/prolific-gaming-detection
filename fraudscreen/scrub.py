"""Scrub a finished report (markdown or CSV text) with the redactor's key so it carries the same
tokens as the redacted data; new tokens are appended to the shared lookup for reidentify."""
import re
from pathlib import Path

from privacy import tokens
from privacy.idscan import IdScanner
from privacy.urls import Scrubber, UrlRule

HEX24 = re.compile(r"[0-9a-fA-F]{24}")
_STEM_RE = re.compile(r"^(aimms|aimec|wei)", re.I)


def _word_re(values, flags=0):
    """One pattern matching any of the values as whole words, longest first."""
    alts = sorted({v for v in values if v}, key=len, reverse=True)
    if not alts:
        return None
    return re.compile(r"(?<![A-Za-z0-9._-])(?:" + "|".join(re.escape(v) for v in alts) + r")(?![A-Za-z0-9-])", flags)


def scrub_text(text, key_dir, host_counts=None, prefix_counts=None, threshold=5, device_ids=None):
    """The redactor's rules applied to a report: identifiers, ids and e-mails in free text, URLs
    by the URL rule, then the values a report quotes outside a URL: storage and display ids
    (dev tokens), hosts below the participant threshold (host tokens) and cohort prefixes below the
    identifier threshold (reduced to the study stem)."""
    key_dir = Path(key_dir)
    key = tokens.load_or_create_key(key_dir / "key")
    lookup = tokens.read_lookup(key_dir / "lookup.tsv")
    tok = tokens.Tokenizer(key, lookup)
    known = {m.group(0).lower() for m in HEX24.finditer(text)}
    host_counts = host_counts or {}
    prefix_counts = prefix_counts or {}
    scanner = IdScanner(tok, known_hex=known, prefix_counts=prefix_counts, threshold=threshold)
    urls = UrlRule(scanner, host_counts=host_counts, domain_counts=host_counts, threshold=threshold)
    out = Scrubber(scanner, urls).scrub(text)
    # ids under 6 characters stay readable in the redacted data too (privacy/points.py), and a
    # whole-word match on "1" or "None" would rewrite ordinary report text
    dev = _word_re(d for d in (device_ids or ()) if len(d) >= 6)
    if dev:
        out = dev.sub(lambda m: tok.token("dev", m.group(0)), out)
    rare_hosts = _word_re(h for h, n in host_counts.items() if n < threshold and not urls.allowed_host(h))
    if rare_hosts:
        out = rare_hosts.sub(lambda m: urls.host_part(m.group(0).lower()), out)
    # only prefixes of the study grammar the redactor hides (AIMMS/AIMEC/WEI...); any other word
    # before an underscore in an identifier is not a cohort prefix and would hit prose ("Prolific")
    rare_prefixes = _word_re((pfx.rstrip("_") for pfx, n in prefix_counts.items() if n < threshold and _STEM_RE.match(pfx)), re.I)
    if rare_prefixes:
        out = rare_prefixes.sub(lambda m: _stem(m.group(0)), out)
    if tok.added:
        tokens.merge_lookup(lookup, tok.added)
        tokens.write_lookup(key_dir / "lookup.tsv", lookup)
    return out


def _stem(prefix):
    m = _STEM_RE.match(prefix)
    return (m.group(1).upper() if m else "") + "…"


def scrub_file(src, dest, key_dir, **kw):
    text = Path(src).read_text(encoding="utf-8")
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    Path(dest).write_text(scrub_text(text, key_dir, **kw), encoding="utf-8")
