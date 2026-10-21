"""Identifiers, installs and participants: one participant per Prolific id (or pid token)."""
import csv
import datetime as dt
import re
from collections import Counter, namedtuple

from fraudscreen.records import dedupe_install, merge_install, new_install

ParsedIdent = namedtuple("ParsedIdent", "prefix pid study browser_hint install")
# the same identifier shape the redactor accepts: a cohort prefix may carry digits, the id may be typed in capitals
_RAW_RE = re.compile(r"^([A-Za-z]+[A-Za-z0-9]*)_([0-9a-fA-F]{24})\d*$")
_TOKEN_RE = re.compile(r"^(?:([A-Za-z]+)_)?(ident_[0-9a-f]{16})$")
_PIDTOKEN_RE = re.compile(r"^([A-Za-z]+)_(pid_[0-9a-f]{16})\d*$")
DEFAULT_EXCLUDE = ("playwright", "test", "kevin", "camilo", "bwtest", "keystone", "mitinta", "stas",
                   "rnrl", "inta", "undefined", "unknown")


def default_exclude():
    return [re.compile(p, re.I) for p in DEFAULT_EXCLUDE]


def study_of(prefix):
    """The study a cohort prefix belongs to, by its stem (WEIb and WEIx are both WEI cohorts; the
    redactor reduces a rare prefix to the same stem)."""
    p = prefix.lower()
    if p.startswith("wei"):
        return "WEI"
    if p.startswith("aimec"):
        return "AIM-EC"
    if p.startswith("aimms"):
        return "AIM-MS"
    return "?"


def browser_hint(prefix):
    p = prefix.lower()
    return "Edge" if "epl" in p else "Chrome" if "cpl" in p else ""


def parse_ident(ident, identifiers_map=None):
    """ParsedIdent, or None when no Prolific id can be attached. `install` is the key case variants
    of one identifier share: the lower-cased identifier, or in redacted mode the token of it that
    identifiers.csv carries in its `install` column."""
    m = _RAW_RE.match(ident)
    if m:
        return ParsedIdent(m.group(1), m.group(2).lower(), study_of(m.group(1)), browser_hint(m.group(1)), ident.lower())
    m = _PIDTOKEN_RE.match(ident)
    if m:
        return ParsedIdent(m.group(1), m.group(2), study_of(m.group(1)), browser_hint(m.group(1)), ident.lower())
    m = _TOKEN_RE.match(ident)
    if m and identifiers_map and m.group(2) in identifiers_map:
        prefix, pid, _, install = identifiers_map[m.group(2)]
        if not pid.startswith("pid_"):
            return None   # no Prolific id inside the identifier (a test or internal install)
        prefix = (prefix or m.group(1) or "").rstrip("_")
        return ParsedIdent(prefix, pid, study_of(prefix), browser_hint(prefix), install or m.group(2))
    return None


def load_identifiers_csv(path):
    out = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out[row["ident"]] = (row.get("prefix") or "", row.get("pid") or "", row.get("pid_created") or "",
                                 row.get("install") or row["ident"])
    return out


def oid_date(hex24):
    return dt.datetime.fromtimestamp(int(hex24[:8], 16), dt.timezone.utc).date()


def _enrolment(inst):
    """When the install enrolled: the add-identifier record, else the first status point, else the
    first visit. History rows can be backfilled from months before the install, so the earliest
    visit is not the enrolment."""
    if inst["registered_at"] is not None:
        return inst["registered_at"]
    if inst["status"]:
        return min(s.ts for s in inst["status"])
    if inst["visits"]:
        return min(v.t_ms for v in inst["visits"]) / 1000
    return None


def group(installs, identifiers_csv, exclude):
    """(participants, skipped). Case variants of one identifier merge into one install; Chrome and
    Edge installs of one pid merge into one participant."""
    idmap = load_identifiers_csv(identifiers_csv) if identifiers_csv else None
    skipped = Counter()
    merged = {}
    parsed = {}
    for ident, inst in installs.items():
        if any(p.search(ident) for p in exclude):
            skipped["internal"] += 1
            continue
        pi = parse_ident(ident, idmap)
        if pi is None:
            skipped["no_prolific_id"] += 1
            continue
        key = pi.install
        if key not in merged:
            merged[key] = new_install(ident)
            parsed[key] = pi
        merge_install(merged[key], inst)
    by_pid = {}
    for key, inst in merged.items():
        dedupe_install(inst)
        pi = parsed[key]
        p = by_pid.setdefault(pi.pid, {"key": pi.pid, "study": pi.study, "installs": [], "prefixes": set(),
                                       "browsers": set(), "account_created": None, "account_resolution": None,
                                       "account_created_ts": None, "first_upload": None, "duplicate_enrolment": False,
                                       "prefix_hidden": False, "_lower_prefixes": set()})
        p["installs"].append(inst)
        p["prefixes"].add(pi.prefix)
        p["_lower_prefixes"].add(pi.prefix.lower())
        for s in inst["status"]:
            p["browsers"].add(s.browser)
        if not inst["status"] and pi.browser_hint:
            p["browsers"].add(pi.browser_hint)
        fu = _enrolment(inst)
        if fu is not None:
            p["first_upload"] = fu if p["first_upload"] is None else min(p["first_upload"], fu)
        if p["account_created"] is None:
            if re.fullmatch(r"[0-9a-f]{24}", pi.pid):
                p["account_created"], p["account_resolution"] = oid_date(pi.pid), "day"
                p["account_created_ts"] = int(pi.pid[:8], 16)
            elif idmap:
                month = next((v[2] for v in idmap.values() if v[1] == pi.pid and v[2]), "")
                if re.fullmatch(r"\d{4}-\d{2}", month):
                    p["account_created"] = dt.date(int(month[:4]), int(month[5:]), 1)
                    p["account_resolution"] = "month"
    out = []
    for p in by_pid.values():
        # a second enrolment is a second cohort label within one study; Chrome and Edge labels fold
        # together, and a label the redactor blanked cannot be compared at all
        by_study = {}
        for lp in p["_lower_prefixes"]:
            by_study.setdefault(study_of(lp), set()).add(re.sub(r"[ce]pl", "xpl", lp))
        p["prefix_hidden"] = "" in p["_lower_prefixes"]
        p["duplicate_enrolment"] = not p["prefix_hidden"] and any(len(v) > 1 for v in by_study.values())
        del p["_lower_prefixes"]
        _dedupe_across_installs(p)
        out.append(p)
    out.sort(key=lambda p: p["key"])
    return out, skipped


def _browser_of(inst):
    for s in inst["status"]:
        return s.browser
    return browser_hint(inst["ident"].split("_", 1)[0])


def _dedupe_across_installs(p):
    """One participant's installs can carry the same visit twice: a fresh Edge install imports the
    Chrome history as local rows, and two enrolments on one profile upload the same history. The
    copy in the earlier install (Chrome first) is kept; where copies disagree on locality the
    synced reading wins, so an imported copy never turns a synced page into a local one."""
    if len(p["installs"]) < 2:
        return
    p["installs"].sort(key=lambda i: (0 if _browser_of(i) == "Chrome" else 1, i["ident"]))
    kept = {}   # visit key -> (the list the kept copy sits in, its index); the list becomes inst["visits"]
    for inst in p["installs"]:
        out = []
        for v in inst["visits"]:
            k = (v.t_ms, v.host, v.path, v.query)
            if k in kept:
                lst, idx = kept[k]
                if v.is_local is False and lst[idx].is_local is not False:
                    lst[idx] = lst[idx]._replace(is_local=False)
                continue
            kept[k] = (out, len(out))
            out.append(v)
        inst["visits"] = out


def account_age_days(p):
    if p["account_resolution"] != "day" or p["first_upload"] is None:
        return None
    created = p.get("account_created_ts")   # the ObjectId's second, not its date: 29.1 days is not 30
    if created is None:
        created = dt.datetime.combine(p["account_created"], dt.time(), tzinfo=dt.timezone.utc).timestamp()
    return (p["first_upload"] - created) / 86400


def account_month_close(p):
    """Month resolution: created in the enrolment month or the month before."""
    if p["account_resolution"] != "month" or p["first_upload"] is None:
        return False
    enrol = dt.datetime.fromtimestamp(p["first_upload"], dt.timezone.utc).date()
    months = (enrol.year - p["account_created"].year) * 12 + enrol.month - p["account_created"].month
    return 0 <= months <= 1
