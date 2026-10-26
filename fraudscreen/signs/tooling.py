"""Tooling signs: M3 antidetect launch page, m4 concealment-tool sites."""
from collections import defaultdict

from fraudscreen import hosts
from fraudscreen.signs import Evidence, SignResult, evidence_from_visit, fmt_utc, n_of

SESSION_GAP_S = 1200
M4_CATEGORIES = ("antidetect", "ipcheck", "vpn_account", "proxy", "remote", "sms", "tempmail", "generator")


def sessions(visits, gap_s=SESSION_GAP_S):
    """(start, end) index pairs over time-sorted visits, split at gaps over gap_s."""
    out = []
    if not visits:
        return out
    start = 0
    for i in range(1, len(visits) + 1):
        if i == len(visits) or (visits[i].t_ms - visits[i - 1].t_ms) / 1000 > gap_s:
            out.append((start, i))
            start = i
    return out


def is_launch_page(v):
    return any(v.host == h and v.path.startswith(p) for h, p in hosts.ANTIDETECT_LAUNCH) and hosts.ANTIDETECT_LAUNCH_QUERY in v.query


def score_tooling(p, ctx):
    r = {"M3": SignResult("M3"), "m4": SignResult("m4")}
    visits = sorted((v for inst in p["installs"] for v in inst["visits"] if v.is_local is not False), key=lambda v: v.t_ms)
    sess = sessions(visits)
    starts = {s for s, _ in sess}
    launch_sessions = 0
    for i, v in enumerate(visits):
        if is_launch_page(v) and (i in starts or v.transition == "auto_toplevel"):
            r["M3"].add(evidence_from_visit(v))
            if i in starts:
                launch_sessions += 1
    if r["M3"].fired:
        r["M3"].count = launch_sessions or r["M3"].count
        r["M3"].notes.append(f"{launch_sessions} of {len(sess)} sessions")
        host = next(v.host for v in visits if is_launch_page(v))
        if launch_sessions:
            r["M3"].headline = f"Antidetect browser: the {host} launch page opened {launch_sessions} of {n_of(len(sess), 'browsing session')}"
        else:
            r["M3"].headline = f"Antidetect browser: the {host} launch page loaded as a top-level page {n_of(r['M3'].count, 'time')}"
    cat = defaultdict(list)
    for i, v in enumerate(visits):
        c = hosts.classify(v.host)
        if c in M4_CATEGORIES or c == "vpn_marketing":
            cat[c].append((i, v))
    fired = False
    m4_cats, m4_hosts = [], []
    for c in M4_CATEGORIES + ("vpn_marketing",):
        rows = cat.get(c)
        if not rows:
            continue
        days = {fmt_utc(v.t_ms / 1000)[:10] for _, v in rows}
        typed = sum(1 for _, v in rows if v.transition == "typed")
        at_start = sum(1 for i, _ in rows if i in starts)
        hs = sorted({v.host for _, v in rows})
        if c == "vpn_marketing":
            r["m4"].notes.append(f"vpn_marketing: {len(rows)} visits (not counted): {', '.join(hs[:4])}")
            continue
        r["m4"].notes.append(f"{c}: {n_of(len(rows), 'visit')}, {n_of(len(days), 'day')}, typed {typed}, at session start {at_start}: {', '.join(hs[:4])}")
        m4_cats.append((c, len(rows)))
        m4_hosts.extend(h for h in hs if h not in m4_hosts)
        for _, v in rows[:2]:
            r["m4"].add(evidence_from_visit(v))
        r["m4"].count += max(0, len(rows) - 2)
        fired = True
    r["m4"].fired = fired
    if fired:
        r["m4"].headline = (f"{n_of(sum(n for _, n in m4_cats), 'visit')} to concealment-tool sites "
                            f"({', '.join(f'{c} {n}' for c, n in m4_cats)}): {', '.join(m4_hosts[:3])}")
    return r
