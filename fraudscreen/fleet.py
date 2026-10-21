"""Fleet-wide statistics computed once before scoring. The dataclass defaults let sign tests
run with a bare Fleet()."""
from dataclasses import dataclass, field

from fraudscreen import hosts, tz


@dataclass
class Fleet:
    night_p95: float = 0.0
    infra_p95: float = 0.0
    chat_p95: float = 0.0
    enrolled_ids: set = field(default_factory=set)
    foreign_id_owners: dict = field(default_factory=dict)
    hw_keys: dict = field(default_factory=dict)
    transient_ids: dict = field(default_factory=dict)
    mail_identities: dict = field(default_factory=dict)
    n_screened: int = 0
    n_in_percentiles: int = 0


def local_visits(p):
    return [v for inst in p["installs"] for v in inst["visits"] if v.is_local is not False]


def reported_zone(p):
    from collections import Counter
    c = Counter(s.tz for inst in p["installs"] for s in inst["status"] if s.tz)
    if not c:
        c = Counter(v.tz for inst in p["installs"] for v in inst["visits"] if v.tz)
    return c.most_common(1)[0][0] if c else ""


def night_share(p, zone):
    """Share of local visits whose local hour is 1, 2, 3 or 4 (01:00 to 05:00)."""
    vs = local_visits(p)
    if not vs or not zone:
        return 0.0
    n = sum(1 for v in vs if 1 <= tz.local_hour(v.t_ms / 1000, zone) < 5)
    return n / len(vs)


def infra_share(p):
    vs = local_visits(p)
    if not vs:
        return 0.0
    return sum(1 for v in vs if hosts.classify(v.host) in ("survey_infra", "dashboard")) / len(vs)


def _p95(values):
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]


def build_fleet(participants, min_visits):
    from fraudscreen.signs.accounts import foreign_id_visits
    from fraudscreen.signs.behaviour import chat_share
    from fraudscreen.signs.machine import hw_key
    f = Fleet(n_screened=len(participants))
    nights, infras, chats = [], [], []
    for p in participants:
        key = p["key"]
        f.enrolled_ids.add(key)
        for v, pid in foreign_id_visits(p):
            f.foreign_id_owners.setdefault(pid, set()).add(key)
        spans = {}
        for inst in p["installs"]:
            for s in inst["status"]:
                k = hw_key(s)
                if k:
                    f.hw_keys.setdefault(k, set()).add(key)
                for tid in [d for d, _ in s.disks] + [d for d, _, _, _ in s.displays]:
                    if len(tid) < 6:
                        continue
                    lo, hi, n = spans.get(tid, (s.ts, s.ts, 0))
                    spans[tid] = (min(lo, s.ts), max(hi, s.ts), n + 1)
            for ident in inst["mail_identities"]:
                f.mail_identities.setdefault(ident, set()).add(key)
        for tid, (lo, hi, n) in spans.items():
            f.transient_ids.setdefault(tid, []).append((key, lo, hi, n))
        if len(local_visits(p)) >= min_visits:
            f.n_in_percentiles += 1
            nights.append(night_share(p, reported_zone(p)))
            infras.append(infra_share(p))
            chats.append(chat_share(p))
    f.night_p95, f.infra_p95, f.chat_p95 = _p95(nights), _p95(infras), _p95(chats)
    return f
