"""Pass 1 over the raw tree: what redact must know before it writes anything
(spec, "What redact does", step 1). Participants are counted by identifier:
the file name's identifier, else the first "source" value in the file."""
import re
import zipfile
from collections import Counter
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from privacy import leakcheck
from privacy.files import kind_of, zip_is_duplicate
from privacy.idscan import HEX24_RE, IDENT_RE, candidate_ids, ident_parts
from privacy.urls import URL_IN_TEXT_RE

_DOMAIN_RE = re.compile(r'"domain"\s*:\s*"([^"\\]+)"')
_SOURCE_RE = re.compile(r'"source"\s*:\s*"([^"\\]+)"')


def _inputs(src, errors):
    """(name, bytes) for each readable input in src. Failures are counted by
    exception type, never with a path: names can hold identifiers."""
    kind = kind_of(src.name)
    if kind in ("junk", "skip"):
        return
    if kind != "zip":
        try:
            data = src.read_bytes()
        except OSError as e:
            errors[type(e).__name__] += 1
            return
        yield src.name, data
        return
    if zip_is_duplicate(src):
        return  # its extracted twin is censused instead
    try:
        z = zipfile.ZipFile(src)
    except (zipfile.BadZipFile, OSError) as e:
        errors[type(e).__name__] += 1
        return
    with z:
        for info in z.infolist():
            name = PurePosixPath(info.filename).name
            if info.is_dir() or kind_of(name) in ("junk", "skip", "zip"):
                continue
            try:
                data = z.read(info)
            except Exception as e:  # bad CRC, truncated archive, unsupported compression
                errors[type(e).__name__] += 1
                continue
            yield name, data


def _census_text(text, name):
    idents = {"".join(ident_parts(m)) for m in IDENT_RE.finditer(name + "\n" + text)}
    named = IDENT_RE.search(name)
    owner = "".join(ident_parts(named)) if named else None
    if owner is None:
        src = _SOURCE_RE.search(text)
        owner = src.group(1) if src else None
    if owner:
        # one participant per Prolific id: the Chrome and Edge identifiers of one person, and the
        # case variants of one identifier, must not count twice towards the host threshold
        inner = HEX24_RE.search(owner)
        owner = inner.group(0).lower() if inner else owner.lower()
    hosts = set()
    for m in URL_IN_TEXT_RE.finditer(text):
        try:
            host = urlsplit(m.group(0)).hostname
        except ValueError:
            continue
        if host:
            hosts.add(host.lower())
    domains = {d.lower() for d in _DOMAIN_RE.findall(text)}
    return idents, owner, hosts, domains


def census_file(src):
    out = {"idents": set(), "owners_hosts": {}, "owners_domains": {}, "known": set(), "leak": set(),
           "leak_prefixes": set(), "errors": Counter()}
    for name, data in _inputs(src, out["errors"]):
        text = data.decode("utf-8", errors="replace")
        idents, owner, hosts, domains = _census_text(text, name)
        out["idents"] |= idents
        out["known"] |= candidate_ids(text)
        out["leak"] |= leakcheck.collect(data)
        out["leak_prefixes"] |= leakcheck.collect_prefixes(data)
        if owner:
            out["owners_hosts"].setdefault(owner, set()).update(hosts)
            out["owners_domains"].setdefault(owner, set()).update(domains)
    return out


def census_error(name):
    """The census of an input that failed in an unexpected way."""
    return {"idents": set(), "owners_hosts": {}, "owners_domains": {}, "known": set(), "leak": set(),
            "leak_prefixes": set(), "errors": Counter({name: 1})}


def merge_census(results):
    prefixes, hosts, domains, known, leak, errors = {}, {}, {}, set(), set(), Counter()
    leak_prefixes = set()
    for r in results:
        for ident in r["idents"]:
            prefixes.setdefault(ident_parts(IDENT_RE.match(ident))[0].lower(), set()).add(ident)
        for owner, hs in r["owners_hosts"].items():
            for h in hs:
                hosts.setdefault(h, set()).add(owner)
        for owner, ds in r["owners_domains"].items():
            for d in ds:
                domains.setdefault(d, set()).add(owner)
        known |= r["known"]
        leak |= r["leak"]
        errors.update(r["errors"])
        leak_prefixes |= r["leak_prefixes"]
    return {"prefix_counts": {k: len(v) for k, v in prefixes.items()},
            "host_counts": {k: len(v) for k, v in hosts.items()},
            "domain_counts": {k: len(v) for k, v in domains.items()},
            "known": known, "leak": leak, "leak_prefixes": leak_prefixes, "errors": errors}
