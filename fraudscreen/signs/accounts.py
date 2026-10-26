"""Account signs: M1 second Prolific id (local), m2 synced in, m3 link-sharing, m6 account age,
m7 duplicate enrolment."""
import datetime as dt
import re
from collections import Counter
from urllib.parse import parse_qsl, unquote

from fraudscreen.participants import account_age_days, account_month_close
from fraudscreen.signs import SignResult, evidence_from_visit, fmt_utc, n_of

_HEX24 = re.compile(r"^[0-9a-f]{24}$")
_PIDTOK = re.compile(r"^pid_[0-9a-f]{16}$")
PID_PARAMS = ("prolific_pid", "prolific_id", "prolificpid")


def _decode(value, rounds=3):
    for _ in range(rounds):
        nv = unquote(value)
        if nv == value:
            break
        value = nv
    return value


def _pid_values(v, enrolled=()):
    """The participant ids a visit carries: the PROLIFIC_PID-style parameters of a Prolific-specific
    URL, and in redacted data the `ids=` list of an opaque URL (host/url_<tok>?ids=...), but from
    that list only enrolled participants' tokens: a study or session id is 24-hex too and gets a
    pid token of its own, so an unfiltered list would fire M1 on every study link."""
    if not v.query:
        return []
    try:
        pairs = parse_qsl(v.query, keep_blank_values=True)
    except ValueError:
        return []
    out = []
    for name, value in pairs:
        n = name.lower()
        if n in PID_PARAMS or (v.host == "conjointly.online" and n == "id"):
            value = _decode(value).strip().lower()
            if _HEX24.match(value) or _PIDTOK.match(value):
                out.append(value)
        elif n == "ids" and v.path.startswith("/url_"):
            out.extend(t for t in value.split(",") if _PIDTOK.match(t) and t in enrolled)
    return out


def _pid_value(v):
    """The first participant id carried by a Prolific-specific URL, or None."""
    vals = _pid_values(v)
    return vals[0] if vals else None


def foreign_id_visits(p, enrolled=(), raw_mode=False):
    """[(visit, foreign_id)] over all installs, any locality; in raw mode only ids whose account
    predates the visit by more than a day (a vendor's fresh session id is not an account)."""
    own = p["key"]
    out = []
    for inst in p["installs"]:
        for v in inst["visits"]:
            for pid in _pid_values(v, enrolled):
                if pid != own and (not raw_mode or _is_old_enough(pid, v)):
                    out.append((v, pid))
    return out


def _is_old_enough(pid, v):
    """Raw mode: the foreign id's account predates the visit by more than one day."""
    if not _HEX24.match(pid):
        return True
    return v.t_ms / 1000 - int(pid[:8], 16) > 86400


def score_accounts(p, ctx):
    r = {sid: SignResult(sid) for sid in ("M1", "m2", "m3", "m6", "m7")}
    own = p["key"]
    all_visits = [v for inst in p["installs"] for v in inst["visits"]]
    logins = [v.t_ms for v in all_visits if v.host == "auth.prolific.com" and v.path.startswith("/u/login")]
    days = {}
    foreign_ids = set()
    ids_of = {"M1": set(), "m2": set()}   # which ids each target saw, for its headline
    enrolled = set(ctx.by_key) | (set(ctx.fleet.enrolled_ids) if ctx.fleet else set())
    pairs = foreign_id_visits(p, enrolled=enrolled, raw_mode=ctx.raw_mode)
    completion = [(v, pid) for v, pid in pairs if v.host == "app.prolific.com" and "submissions/complete" in v.path]
    others = [(v, pid) for v, pid in pairs if not (v.host == "app.prolific.com" and "submissions/complete" in v.path)]
    for v, pid in completion + others:
        target = r["M1"] if v.is_local is not False else r["m2"]
        target.add(evidence_from_visit(v))
        foreign_ids.add(pid)
        ids_of[target.sign_id].add(pid)
        if pid in ctx.by_key:
            target.link(pid)
        d = fmt_utc(v.t_ms / 1000)[:10]
        days.setdefault(d, Counter())["foreign"] += 1
    if r["M1"].fired or r["m2"].fired:
        for v in all_visits:
            if _pid_value(v) == own:
                days.setdefault(fmt_utc(v.t_ms / 1000)[:10], Counter())["own"] += 1
        enrolled = any(pid in ctx.by_key or pid in ctx.fleet.enrolled_ids for pid in foreign_ids)
        for res in (r["M1"], r["m2"]):
            if res.fired:
                res.notes.append("foreign ids: " + ", ".join(sorted(foreign_ids)))
                res.notes.append("enrolled: " + ("yes" if enrolled else "no"))
                res.notes.append("per day: " + "; ".join(f"{d} own {c['own']} foreign {c['foreign']}" for d, c in sorted(days.items())))
                how = "opened locally" if res.sign_id == "M1" else "synced in from another device"
                own_enrolled = any(pid in ctx.by_key or pid in ctx.fleet.enrolled_ids for pid in ids_of[res.sign_id])
                res.headline = (f"{n_of(res.count, 'study page')} {how} under another Prolific id: " + ", ".join(sorted(ids_of[res.sign_id]))
                                + (" (also enrolled in this pull)" if own_enrolled else ""))
        if r["M1"].fired:
            near = sum(1 for t in logins if any(abs(t - v.t_ms) <= 3600 * 1000 for v, _ in pairs if v.is_local is not False))
            r["M1"].notes.append(f"logins within 60 min: {near} (auth.prolific.com/u/login)")
    # m3 link-sharing
    owners = ctx.fleet.foreign_id_owners if ctx.fleet else {}
    for pid in sorted(foreign_ids):
        others_with = owners.get(pid, set()) - {own}
        for k in sorted(others_with):
            r["m3"].add(_note_ev(f"foreign id {pid} also appears in {k}"))
            r["m3"].link(k)
    for other_key, carriers in owners.items():
        # mutual: this participant carries the other's id AND the other carries this one's
        if other_key in ctx.by_key and other_key in foreign_ids and other_key in owners.get(own, ()):
            r["m3"].add(_note_ev(f"{other_key} carries this participant's id and this participant carries theirs"))
            r["m3"].link(other_key)
    # m6 account age, measured from enrolment (participants._enrolment), never from backfilled history
    created = p.get("account_created")
    age = account_age_days(p) if created else None
    if age is not None and age < 30:
        r["m6"].add(_note_ev(f"account created {created.isoformat()}, {age:.0f} days before enrolment {fmt_utc(p['first_upload'])}"))
        r["m6"].notes.append(f"{age:.0f} days old at enrolment")
    elif created and account_month_close(p):
        enrol = dt.datetime.fromtimestamp(p["first_upload"], dt.timezone.utc).date()
        r["m6"].add(_note_ev(f"account created {created.strftime('%Y-%m')}, enrolment {enrol.isoformat()}"))
        r["m6"].notes.append("month resolution: created in the enrolment month or the month before")
    if _HEX24.match(own):
        mine = int(own[:8], 16)
        for k in ctx.by_key:
            if k != own and _HEX24.match(k) and abs(int(k[:8], 16) - mine) <= 600:
                r["m6"].add(_note_ev(f"enrolled id {k} created {abs(int(k[:8], 16) - mine)} s apart"))
                r["m6"].link(k)
    elif not ctx.raw_mode:
        r["m6"].notes.append("batch rule (two ids created within 10 min) needs raw ids")
    # m7 duplicate enrolment
    if p.get("prefix_hidden"):
        r["m7"].available = False
        r["m7"].notes.append("not evaluated: a cohort label is hidden in the redacted data")
    elif p.get("duplicate_enrolment"):
        r["m7"].add(_note_ev("prefixes: " + ", ".join(sorted(p["prefixes"]))))
    return r


def _note_ev(text):
    from fraudscreen.signs import Evidence
    return Evidence("", text, "")
