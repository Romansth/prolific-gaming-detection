"""Location signs: M4/m16 non-US Google sign-in route, M5/m17 non-US device clock, M6 install
locale, m8 activity hours, m9 zone switches, m13 foreign-language interface and searches."""
import re
from collections import Counter
from urllib.parse import parse_qsl, unquote

from fraudscreen import hosts, tz
from fraudscreen.fleet import local_visits, night_share, reported_zone
from fraudscreen.signs import Evidence, SignResult, evidence_from_visit, fmt_utc, visit_url

_CCTLD_RE = re.compile(r"^accounts\.google\.(?!com$)[a-z.]+$")
_RLZ_RE = re.compile(r"_[a-z]{2}([A-Z]{2})")
QUERY_PATTERNS = (
    ("zip code lookup", re.compile(r"\bzip ?code\b|\bzip\b.*\b(usa|us)\b|\bus zip\b", re.I)),
    ("my ip lookup", re.compile(r"what('|’)?s my ip|what is my ip|my ip address", re.I)),
    ("address generator", re.compile(r"address generator|fake (name|address)|us address", re.I)),
    ("ssn generator", re.compile(r"ssn generator", re.I)),
    ("prolific vpn", re.compile(r"prolific.*vpn|vpn.*prolific", re.I)),
    ("area code lookup", re.compile(r"area code", re.I)),
)
WEEK_S = 7 * 86400


def _params(v):
    try:
        return parse_qsl(v.query, keep_blank_values=True)
    except ValueError:
        return []


def context_notes(p, hit_times):
    vs = [v for inst in p["installs"] for v in inst["visits"]]
    us = sum(1 for v in vs if hosts.classify(v.host) == "us_consumer")
    travel = 0
    for v in vs:
        if hosts.is_travel(v.host, v.path) and any(abs(v.t_ms / 1000 - t) <= 3 * 86400 for t in hit_times):
            travel += 1
    return [f"US consumer sites visited: {us}", f"travel sites within 3 days of a location hit: {travel}"]


def _signin_hits(p):
    out = []
    for v in local_visits(p):
        if _CCTLD_RE.match(v.host):
            out.append(v)
        elif v.host.startswith("consent.google.") and v.path.startswith("/m"):
            gl = next((val for name, val in _params(v) if name.lower() == "gl"), None)
            if gl and gl.upper() != "US":
                out.append(v)
    return out


def score_location(p, ctx):
    r = {sid: SignResult(sid) for sid in ("M4", "M5", "M6", "m8", "m9", "m13", "m16", "m17")}
    # M4 / m16
    hits = _signin_hits(p)
    if hits:
        days = sorted({fmt_utc(v.t_ms / 1000)[:10] for v in hits})
        span = (max(v.t_ms for v in hits) - min(v.t_ms for v in hits)) / 1000
        target = r["M4"] if len(days) >= 2 and span >= WEEK_S else r["m16"]
        for v in hits:
            target.add(evidence_from_visit(v))
        target.notes.append(f"days: {', '.join(days)}")
        target.notes.extend(context_notes(p, [v.t_ms / 1000 for v in hits]))
    # M5 / m17
    points = [(s.ts, s.tz) for inst in p["installs"] for s in inst["status"]] + \
             [(v.t_ms / 1000, v.tz) for inst in p["installs"] for v in inst["visits"]]
    non_us = [(t, z) for t, z in points if z and not tz.is_us_zone(z)]
    if non_us:
        per_day = Counter((fmt_utc(t)[:10], z) for t, z in non_us)
        days = {d for d, _ in per_day}
        share = len(non_us) / len(points)
        target = r["M5"] if len(days) >= 7 or share >= 0.5 else r["m17"]
        zones = Counter(z for _, z in non_us)
        target.add(Evidence(fmt_utc(min(t for t, _ in non_us)), "zones: " + ", ".join(f"{z} ({n} pts)" for z, n in zones.most_common()), ""))
        target.count = len(non_us)
        target.notes.append(f"{len(days)} days, {share:.0%} of {len(points)} points")
        series = sorted(per_day.items())[:10]
        target.notes.append("per day: " + "; ".join(f"{d} {z.split('/')[-1]}={n}" for (d, z), n in series))
        target.notes.extend(context_notes(p, [t for t, _ in non_us]))
    # M6
    codes = Counter()
    first = {}
    for v in local_visits(p):
        if v.host.endswith("google.com") and v.path.startswith("/search") or (".google." in v.host and v.path.startswith("/search")):
            rlz = next((val for name, val in _params(v) if name.lower() == "rlz"), None)
            if rlz:
                m = _RLZ_RE.search(rlz)
                if m:
                    codes[m.group(1)] += 1
                    first.setdefault(m.group(1), v)
    for cc, n in codes.most_common():
        if cc != "US":
            r["M6"].add(evidence_from_visit(first[cc], f"rlz country {cc}: {visit_url(first[cc])}"))
            r["M6"].count = n
            r["M6"].notes.append("codes: " + ", ".join(f"{c}={k}" for c, k in codes.most_common()))
            r["M6"].notes.extend(context_notes(p, [first[cc].t_ms / 1000]))
    # m8
    zone = reported_zone(p)
    vs = local_visits(p)
    if zone and len(vs) >= 80:
        share = night_share(p, zone)
        threshold = max(ctx.fleet.night_p95 if ctx.fleet else 0.0, 0.20)
        if share > threshold:
            best = None
            for off in range(-12, 15):
                n = sum(1 for v in vs if 1 <= int(((v.t_ms / 1000 + off * 3600) % 86400) // 3600) < 5)
                sh = n / len(vs)
                if best is None or sh < best[1]:
                    best = (off, sh)
            if best[1] < 0.03:
                hist = Counter(tz.local_hour(v.t_ms / 1000, zone) for v in vs)
                r["m8"].add(Evidence("", f"{share:.0%} of {len(vs)} visits at 01:00-05:00 {zone} (fleet 95th pct {ctx.fleet.night_p95:.0%})", ""))
                r["m8"].notes.append("hours in reported zone: " + " ".join(f"{h:02d}:{hist.get(h, 0)}" for h in range(24)))
                r["m8"].notes.append(f"best-fitting offset UTC{best[0]:+d} gives {best[1]:.0%} at night")
                r["m8"].notes.extend(context_notes(p, []))
    # m9
    for inst in p["installs"]:
        st = sorted(inst["status"], key=lambda s: s.ts)
        for a, b in zip(st, st[1:]):
            if a.tz != b.tz and b.ts - a.ts <= 3 * 3600:
                r["m9"].add(Evidence(fmt_utc(b.ts), f"{a.tz} at {fmt_utc(a.ts)} -> {b.tz} at {fmt_utc(b.ts)}", b.file))
    # m13
    for v in local_visits(p):
        params = _params(v)
        hl = next((val for name, val in params if name.lower() == "hl"), None)
        if hl and hl.lower() not in ("en", "en-us", "en_us"):
            r["m13"].add(evidence_from_visit(v, f"hl={hl} on {v.host}"))
        if ctx.raw_mode and v.path.startswith("/search"):
            q = next((unquote(val) for name, val in params if name == "q"), "")
            for label, pat in QUERY_PATTERNS:
                if q and pat.search(q):
                    r["m13"].add(Evidence(fmt_utc(v.t_ms / 1000), f"search matching '{label}' on {v.host}", v.file))
                    r["m13"].notes.append(f"search pattern: {label}")
                    break
    if ctx.raw_mode:
        titles = Counter()
        for inst in p["installs"]:
            titles.update(inst.get("nonen_titles", {}))
        for t, n in titles.most_common():
            r["m13"].add(Evidence("", f"{n} Google result pages titled '... {t}'", ""))
            r["m13"].notes.append(f"interface title: {t} ({n})")
    return r
