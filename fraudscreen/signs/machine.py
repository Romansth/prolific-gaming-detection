"""Machine signs: M2 two participants in one running browser (shared transient ids), m1 shared
Windows/Linux hardware key, m5 virtual machine or remote session, m10 one identifier on two
machines."""
import re
from collections import Counter, defaultdict

from fraudscreen.signs import Evidence, SignResult, fmt_utc

_VM_RE = re.compile(r"QEMU|KVM|VMware|Virtual|Hyper-V|VirtualBox|Xen|Parallels", re.I)
FIXED_DISK_MIN = 2 ** 31
WINDOW_7D = 7 * 86400


def hw_key(s):
    """Machine key on platforms whose byte counts discriminate; None on Mac and ChromeOS."""
    if s.plat not in ("Win", "Linux"):
        return None
    disks = ";".join(str(c) for _, c in sorted(s.disks, key=lambda d: d[1]) if c >= FIXED_DISK_MIN)
    return f"{s.plat}|{s.cpu}|x{s.nproc}|{s.arch}|mem{s.mem}|disk{disks}"


def _spans(p):
    """key -> [(start, end, n)] of status points per transient id (disk and display ids)."""
    out = defaultdict(lambda: [None, None, 0])
    for inst in p["installs"]:
        for s in inst["status"]:
            ids = [d for d, _ in s.disks] + [d for d, _, _, _ in s.displays]
            for tid in ids:
                if len(tid) < 6:
                    continue
                e = out[tid]
                e[0] = s.ts if e[0] is None else min(e[0], s.ts)
                e[1] = s.ts if e[1] is None else max(e[1], s.ts)
                e[2] += 1
    return out


def score_machine(p, ctx):
    r = {sid: SignResult(sid) for sid in ("M2", "m1", "m5", "m10")}
    status = [s for inst in p["installs"] for s in inst["status"]]
    if not status:
        for res in r.values():
            res.available = False
            res.notes.append("no status points")
        return r
    own = p["key"]
    # M2: a transient id shared with another participant over overlapping minutes
    mine = _spans(p)
    for tid, (a0, a1, n) in sorted(mine.items()):
        for other, b0, b1, m in ctx.fleet.transient_ids.get(tid, []):
            if other == own:
                continue
            if b0 <= a1 + 60 and a0 <= b1 + 60:
                r["M2"].add(Evidence(fmt_utc(a0), f"id {tid}: this {fmt_utc(a0)}..{fmt_utc(a1)} ({n} pts); {other} {fmt_utc(b0)}..{fmt_utc(b1)} ({m} pts)", ""))
                r["M2"].link(other)
    # m1: shared hardware key
    keys = Counter()
    spans = {}
    for s in status:
        k = hw_key(s)
        if k:
            keys[k] += 1
            lo, hi = spans.get(k, (s.ts, s.ts))
            spans[k] = (min(lo, s.ts), max(hi, s.ts))
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
    by_time = sorted(((s.ts, (w, h)) for s in status for _, w, h, _ in s.displays), key=lambda x: x[0])
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
