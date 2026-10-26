"""Machine signs: M2 two participants in one running browser (shared transient ids), m1 shared
Windows/Linux hardware key, m5 virtual machine or remote session, m10 one identifier on two
machines."""
import re
from collections import Counter, defaultdict

from fraudscreen.signs import Evidence, SignResult, fmt_utc, join_and, n_of

_VM_RE = re.compile(r"QEMU|KVM|VMware|Virtual|Hyper-V|VirtualBox|Xen|Parallels", re.I)
FIXED_DISK_MIN = 2 ** 31
WINDOW_7D = 7 * 86400


def hw_key(s):
    """Machine key on platforms whose byte counts discriminate; None on Mac and ChromeOS, and None
    for a record with no cpu, memory or processor count (every such record would share one key).
    Removable media are left out: a USB stick is not the machine."""
    if s.plat not in ("Win", "Linux") or not s.cpu or s.mem <= 0 or s.nproc <= 0:
        return None
    disks = ";".join(str(c) for d, c in sorted(s.disks, key=lambda d: d[1]) if c >= FIXED_DISK_MIN and d not in s.removable)
    return f"{s.plat}|{s.cpu}|x{s.nproc}|{s.arch}|mem{s.mem}|disk{disks}"


def _times(p):
    """transient id (disk or display) -> sorted times of the status points that reported it."""
    out = defaultdict(list)
    for inst in p["installs"]:
        for s in inst["status"]:
            for tid in [d for d, _ in s.disks] + [d for d, _, _, _ in s.displays]:
                if len(tid) >= 6:
                    out[tid].append(s.ts)
    return {k: sorted(v) for k, v in out.items()}


def _same_minute(a, b):
    """The first (ta, tb) within 60 s between two sorted time lists, else None. Overall ranges are
    not enough: an id seen on day 0 and day 10 by one person and day 5 by another was never in
    one running browser."""
    i = j = 0
    while i < len(a) and j < len(b):
        if abs(a[i] - b[j]) <= 60:
            return a[i], b[j]
        if a[i] < b[j]:
            i += 1
        else:
            j += 1
    return None


def score_machine(p, ctx):
    r = {sid: SignResult(sid) for sid in ("M2", "m1", "m5", "m10")}
    status = [s for inst in p["installs"] for s in inst["status"]]
    if not status:
        for res in r.values():
            res.available = False
            res.notes.append("no status points")
        return r
    own = p["key"]
    # M2: a transient id reported by another participant within the same minute
    mine = _times(p)
    for tid, ts in sorted(mine.items()):
        for other, ots in ctx.fleet.transient_ids.get(tid, []):
            if other == own:
                continue
            pair = _same_minute(ts, ots)
            if pair:
                r["M2"].add(Evidence(fmt_utc(pair[0]), f"id {tid}: this {fmt_utc(pair[0])} and {other} {fmt_utc(pair[1])} within a minute ({len(ts)} vs {len(ots)} pts)", ""))
                r["M2"].link(other)
    if r["M2"].fired:
        r["M2"].headline = (f"In the same running browser as {join_and(r['M2'].linked)}: "
                            f"{n_of(r['M2'].count, 'browser id')} reported by both within a minute")
    # m1: shared hardware key
    keys = Counter()
    spans = {}
    for s in status:
        k = hw_key(s)
        if k:
            keys[k] += 1
            lo, hi = spans.get(k, (s.ts, s.ts))
            spans[k] = (min(lo, s.ts), max(hi, s.ts))
    m1_others, m1_overlap, m1_plat = [], False, ""
    for k, n in keys.most_common():
        others = ctx.fleet.hw_keys.get(k, set()) - {own}
        for other in sorted(others):
            lo, hi = spans[k]
            o = ctx.by_key.get(other)
            olo = ohi = None
            if o:
                ots = [s.ts for inst in o["installs"] for s in inst["status"] if hw_key(s) == k]
                if ots:
                    olo, ohi = min(ots), max(ots)
            overlap = olo is not None and olo <= hi and lo <= ohi
            r["m1"].add(Evidence(fmt_utc(lo), f"{k}: this {fmt_utc(lo)}..{fmt_utc(hi)} ({n} pts); {other} " + (f"{fmt_utc(olo)}..{fmt_utc(ohi)}" if olo else "n/a"), ""))
            r["m1"].link(other)
            r["m1"].notes.append(f"{other}: spans overlap: {'yes' if overlap else 'no'}")
            m1_others.append(other)
            m1_overlap = m1_overlap or overlap
            m1_plat = m1_plat or {"Win": "Windows"}.get(k.split("|")[0], k.split("|")[0])
    if r["m1"].fired:
        r["m1"].headline = (f"Identical {m1_plat} hardware as {join_and(sorted(set(m1_others)))}; "
                            f"status times {'overlap' if m1_overlap else 'do not overlap'}")
    # m5: VM strings, generic displays, display churn
    for s in status:
        if _VM_RE.search(s.cpu):
            r["m5"].add(Evidence(fmt_utc(s.ts), f"cpu model: {s.cpu}", s.file))
            break
    for s in status:
        names = [n for _, _, _, n in s.displays if "Non-PnP" in n]
        if names:
            r["m5"].add(Evidence(fmt_utc(s.ts), f"display: {names[0]} {';'.join(f'{w}x{h}' for _, w, h, _ in s.displays)}", s.file))
            break
    by_time = sorted(((s.ts, (w, h)) for s in status for _, w, h, _ in s.displays if w > 0 and h > 0), key=lambda x: x[0])
    window = Counter()   # sizes inside the sliding 7-day window, two pointers over the sorted points
    j = 0
    for i, (t0, _) in enumerate(by_time):
        while j < len(by_time) and by_time[j][0] - t0 <= WINDOW_7D:
            window[by_time[j][1]] += 1
            j += 1
        if len(window) > 4:
            r["m5"].add(Evidence(fmt_utc(t0), f"{len(window)} display sizes within 7 days: " + ", ".join(f"{w}x{h}" for w, h in sorted(window)), ""))
            break
        window[by_time[i][1]] -= 1
        if window[by_time[i][1]] == 0:
            del window[by_time[i][1]]
    # m10: two CPU models with local browsing on both within an hour
    for inst in p["installs"]:
        cpus = {s.cpu for s in inst["status"]}
        if len(cpus) < 2:
            continue
        by_bundle = {s.bundle: s for s in inst["status"] if s.bundle is not None}
        st_sorted = sorted(inst["status"], key=lambda s: s.ts)
        fallback = False

        def cpu_of(v):
            nonlocal fallback
            if v.bundle is not None and v.bundle in by_bundle:
                return by_bundle[v.bundle].cpu
            t = v.t_ms / 1000
            best = min(st_sorted, key=lambda s: abs(s.ts - t), default=None)
            if best is not None and abs(best.ts - t) <= 120:
                fallback = True
                return best.cpu
            return None
        tagged = [(v.t_ms / 1000, cpu_of(v), v) for v in inst["visits"] if v.is_local is not False]
        tagged = [(t, c, v) for t, c, v in tagged if c]
        found = False
        for i, (t, c, v) in enumerate(tagged):
            for t2, c2, v2 in tagged[i + 1:]:
                if t2 - t > 3600:
                    break
                if c2 != c:
                    r["m10"].add(Evidence(fmt_utc(t), f"{c} at {fmt_utc(t)} and {c2} at {fmt_utc(t2)}", v.file))
                    found = True
                    break
            if found:
                break
        if found:
            r["m10"].notes.append("cpu models: " + "; ".join(sorted(cpus)))
            if fallback:
                r["m10"].notes.append("attribution by nearest status point (no bundle id)")
    return r
