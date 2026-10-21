"""Behaviour signs: m11 survey-only / fresh profile / typed study links, m12 shared mail
identity (raw mode), m14 automated reloads, m15 chatbot during surveys. study_windows and
chat_share are also used by the fleet build."""
from collections import Counter
from urllib.parse import parse_qsl

from fraudscreen import hosts
from fraudscreen.fleet import infra_share, local_visits
from fraudscreen.signs import Evidence, SignResult, fmt_utc, visit_url

FRESH_ID_MAX = 200
TYPED_SHARE = 0.25
TYPED_MIN_LINKS = 8
MODAL_SHARE = 0.25
MODAL_MIN_GAPS = 50
WINDOW_CAP_S = 5400


def _params(v):
    try:
        return dict((k.lower(), val) for k, val in parse_qsl(v.query, keep_blank_values=True))
    except ValueError:
        return {}


def study_links(p):
    """First visit per study session id of a link carrying a Prolific id, outside prolific.com."""
    first = {}
    for v in sorted(local_visits(p), key=lambda v: v.t_ms):
        if v.host.endswith("prolific.com"):
            continue
        params = _params(v)
        sess = params.get("session_id") or params.get("prolific_sid")
        if sess and "prolific_pid" in params:
            first.setdefault(sess, v)
    return first


def study_windows(p, cap_s=WINDOW_CAP_S):
    """[(start_s, end_s)] from the first visit per study session id to its completion page."""
    starts = {sess: v.t_ms / 1000 for sess, v in study_links(p).items()}
    done = {}
    for v in sorted(local_visits(p), key=lambda v: v.t_ms):
        if v.host.endswith("prolific.com") and "submissions/complete" in v.path:
            sess = _params(v).get("session_id")
            if sess:
                done.setdefault(sess, v.t_ms / 1000)
    out = []
    for sess, t0 in starts.items():
        t1 = min(done.get(sess, t0 + cap_s), t0 + cap_s)
        if t1 > t0:
            out.append((t0, t1))
    return sorted(out)


def _chat_hits(p):
    wins = study_windows(p)
    chats = [v.t_ms / 1000 for v in local_visits(p) if hosts.classify(v.host) == "chatbot"]
    convs = [c.started_s for inst in p["installs"] for c in inst["conversations"]]
    hit = [(t0, t1) for t0, t1 in wins if any(t0 < t < t1 for t in chats) or any(t0 < t < t1 for t in convs)]
    return wins, hit


def chat_share(p):
    wins, hit = _chat_hits(p)
    return len(hit) / len(wins) if wins else 0.0


def score_behaviour(p, ctx):
    r = {sid: SignResult(sid) for sid in ("m11", "m12", "m14", "m15")}
    vs = sorted(local_visits(p), key=lambda v: v.t_ms)
    # m11a survey-only
    if len(vs) >= 50:
        share = infra_share(p)
        threshold = max(ctx.fleet.infra_p95 if ctx.fleet else 0.0, 0.80)
        if share > threshold:
            r["m11"].add(Evidence("", f"{share:.0%} of {len(vs)} visits on survey infrastructure (fleet 95th pct {threshold:.0%})", ""))
            r["m11"].notes.append(f"survey-only: {share:.0%}")
    # m11b fresh profile at install
    for inst in p["installs"]:
        t0 = inst["registered_at"]
        if t0 is None and inst["status"]:
            t0 = min(s.ts for s in inst["status"])
        if t0 is None:
            continue
        after = [v for v in inst["visits"] if v.is_local is not False and v.t_ms / 1000 >= t0 - 120]
        if after:
            f = min(after, key=lambda v: v.t_ms)
            if 0 <= f.visit_id < FRESH_ID_MAX and 0 <= f.hist_id < FRESH_ID_MAX:
                r["m11"].add(Evidence(fmt_utc(f.t_ms / 1000), f"first visit after install has visit id {f.visit_id}, history id {f.hist_id}", f.file))
                r["m11"].notes.append(f"fresh profile: history ids {f.visit_id}/{f.hist_id} at install")
    # m11c typed study links
    links = study_links(p)
    if len(links) >= TYPED_MIN_LINKS:
        typed = [v for v in links.values() if v.transition == "typed"]
        if len(typed) / len(links) > TYPED_SHARE:
            r["m11"].add(Evidence(fmt_utc(typed[0].t_ms / 1000), f"typed study link: {visit_url(typed[0])}", typed[0].file))
            r["m11"].notes.append(f"typed study links: {len(typed)} of {len(links)}")
    r["m11"].count = len(r["m11"].notes)
    # m12 shared mail identity (raw only)
    if not ctx.raw_mode:
        r["m12"].available = False
        r["m12"].notes.append("not available in redacted mode (titles dropped)")
    else:
        mine = {i for inst in p["installs"] for i in inst["mail_identities"]}
        owners = ctx.fleet.mail_identities if ctx.fleet else {}
        for ident in sorted(mine):
            for other in sorted(owners.get(ident, set()) - {p["key"]}):
                r["m12"].add(Evidence("", f"{ident[0]} identity #{ident[1][:8]} also under {other}", ""))
                r["m12"].link(other)
    # m14 automated reloads
    if any(inst.get("headless") for inst in p["installs"]):
        r["m14"].add(Evidence("", "headless user agent", ""))
    kept = []
    prev = None
    for v in vs:
        if prev is not None and hosts.classify(v.host) == "dashboard" and (v.host, v.path) == (prev.host, prev.path):
            continue
        kept.append(v)
        prev = v
    gaps = [round((b.t_ms - a.t_ms) / 1000) for a, b in zip(kept, kept[1:])]
    gaps = [g for g in gaps if 2 <= g <= 900]
    if len(gaps) >= MODAL_MIN_GAPS:
        modal, n = Counter(gaps).most_common(1)[0]
        if n / len(gaps) > MODAL_SHARE:
            r["m14"].add(Evidence("", f"{n} of {len(gaps)} inter-visit gaps equal {modal} s", ""))
            r["m14"].notes.append(f"modal gap {modal} s holds {n / len(gaps):.0%} of gaps")
    # m15 chatbot during surveys
    wins, hit = _chat_hits(p)
    if len(wins) >= 10:
        share = len(hit) / len(wins)
        threshold = max(ctx.fleet.chat_p95 if ctx.fleet else 0.0, 0.30)
        if share > threshold:
            r["m15"].add(Evidence(fmt_utc(hit[0][0]), f"study window {fmt_utc(hit[0][0])}..{fmt_utc(hit[0][1])} contained chatbot activity", ""))
            r["m15"].count = len(hit)
            r["m15"].notes.append(f"{len(hit)} of {len(wins)} study windows (fleet 95th pct {threshold:.0%})")
    return r
