"""Synthetic export builders for tests. Every id here is invented."""
import json
from pathlib import Path

GEN_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
EDGE_UA = GEN_UA + " Edg/152.0.0.0"
T0 = 1789345395  # 2026-09-14 ~00:23 UTC, seconds


def point(gen, ident, ts=T0, tz="America/New_York", ua=GEN_UA, ver="0.0.48", bundle=1000, **fields):
    meta = {"source": ident, "generator-id": gen, "generator": f"{gen}: Web Usage Study Extension/{ver} {ua}",
            "timestamp": ts, "timezone": tz, "enqueued-at": ts + 30, "configuration-hash": "4016cabf" + "0" * 56,
            "encrypted_transmission": False}
    p = {"passive-data-metadata": meta, "name": gen, "generatorId": gen, "date": int(ts * 1000),
         "_pdk_trace_context": {"bundle_id": bundle, "bundle_trace_id": "t"}}
    p.update(fields)
    return p


def visit(ident, url, n, ts=T0, **extra):
    host = url.split("/")[2] if "://" in url else ""
    fields = dict(url=url, recorded_url=url, domain=host, visit_id=str(n), history_item_id=str(n),
                  visit_time=float(int(ts * 1000)), transition_type="link", visit_count=1, typed_count=0,
                  is_local=True, filtered=False)
    fields.update(extra)
    return point("rex-history-visit", ident, ts=ts, **fields)


def status(ident, ts=T0, cpu="Intel(R) Core(TM) i5-5200U CPU @ 2.20GHz", nproc=4, mem=6311489536,
           disks=(("d-1", 256005632000),), displays=(("disp-1", 1366, 768, "Generic PnP Monitor"),), **kw):
    return point("pdk-system-status", ident, ts=ts,
                 **{"cpu-info": {"modelName": cpu, "numOfProcessors": nproc, "archName": "x86_64"},
                    "memory-info": {"capacity": mem, "availableCapacity": 1},
                    "storage-info": [{"id": i, "name": "Windows", "type": "fixed", "capacity": c} for i, c in disks],
                    "display-info": [{"id": i, "name": n, "bounds": {"left": 0, "top": 0, "width": w, "height": h}}
                                     for i, w, h, n in displays],
                    "local-storage-bytes": 1, "pending-points": 0}, **kw)


def event(ident, name, ts=T0, count=None, **kw):
    details = {"date": ts}
    if count is not None:
        details["collected_count"] = count
    return point("pdk-app-event", ident, ts=ts, event_name=name, event_details=details, **kw)


def add_identifier(ident, ts=T0):
    return point("ai-market-add-identifier", ident, ts=ts, identifier=ident)


def conversation(ident, platform="chatgpt", started=T0, ts=T0):
    return point("rex-conversation", ident, ts=ts, platform=platform, identifier="c1",
                 started={"value": started * 1000}, ended={"value": started * 1000 + 1000})


def write_file(folder, ident, gen, day, points, variant="plain"):
    mid = {"plain": "", "recorded": "recorded_", "created": "created_"}[variant]
    path = Path(folder) / f"{ident}__{gen}__{mid}{day}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(points))
    return path


# ---- in-memory builders for sign tests (no files) ----
from fraudscreen.records import Status, Visit, new_install  # noqa: E402

PID_A = "65f1c0de2b7a4e9f8c3d1a20"   # 2024-03
PID_B = "6a0e29aee7c2fddfc1bf8b06"   # 2026-05-20
PID_C = "6512aa0b9c8d7e6f5a4b3c2d"   # 2023-09


def mk_visit(url, ts=T0, transition="link", is_local=True, visit_id=1, hist_id=None, visit_count=1, tz="America/New_York",
             bundle=None, file="f.json"):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    return Visit(int(ts * 1000), (parts.hostname or "").lower(), parts.path, parts.query, transition, visit_id,
                 visit_id if hist_id is None else hist_id, visit_count, is_local, tz, bundle, file, "")


def mk_status(ts=T0, tz="America/New_York", cpu="Intel(R) Core(TM) i5-5200U CPU @ 2.20GHz", nproc=4, mem=6311489536,
              disks=(("d-1", 256005632000),), displays=(("disp-1", 1366, 768, "Generic PnP Monitor"),), plat="Win",
              browser="Chrome", ver=48, bundle=None, file="s.json"):
    return Status(ts, tz, cpu, nproc, "x86_64", mem, tuple(sorted(disks)), tuple(displays), plat, browser, ver, bundle, file)


def mk_participant(pid, visits=(), status=(), study="WEI", registered_at=None, prefixes=("WEIb",), browsers=("Chrome",),
                   account_created=None, resolution="day", installs=None, duplicate=False, conversations=(), events=(),
                   mail_identities=()):
    import datetime as dt
    if installs is None:
        inst = new_install(prefixes[0] + "_" + pid)
        inst["visits"] = sorted(visits, key=lambda v: v.t_ms)
        inst["status"] = sorted(status, key=lambda s: s.ts)
        inst["registered_at"] = registered_at
        inst["conversations"] = list(conversations)
        inst["events"] = list(events)
        inst["mail_identities"] = list(mail_identities)
        installs = [inst]
    ts = [s.ts for i in installs for s in i["status"]] + [v.t_ms / 1000 for i in installs for v in i["visits"]]
    if account_created is None and len(pid) == 24 and all(c in "0123456789abcdef" for c in pid):
        account_created = dt.datetime.fromtimestamp(int(pid[:8], 16), dt.timezone.utc).date()
    return {"key": pid, "study": study, "installs": installs, "prefixes": set(prefixes), "browsers": set(browsers),
            "account_created": account_created, "account_resolution": resolution if account_created else None,
            "first_upload": min(ts) if ts else registered_at, "duplicate_enrolment": duplicate}


# ---- full synthetic folder: one planted case per sign, plus clean participants and file-shape cases ----
import zipfile  # noqa: E402

DAY = 86400
BASE_OID = int(__import__("datetime").datetime(2024, 1, 1, tzinfo=__import__("datetime").timezone.utc).timestamp())


def pid_for(idx, created=None):
    """A Prolific-shaped id whose ObjectId date is 2024-01-01 plus idx days (or `created` seconds)."""
    return "%08x" % (created if created else BASE_OID + idx * DAY) + "%016x" % (idx + 1)


def news(ident, n, start=None, ts0=None, host="news.example", gap=1.0, vid0=1000, **extra):
    """n ordinary daytime visits (15:00 UTC = 11:00 New York), one per day cycling over 10 days."""
    out = []
    for i in range(n):
        ts = (ts0 if ts0 is not None else T0 - (T0 % DAY) + 15 * 3600) + (i % 10) * DAY + (i // 10) * gap
        out.append(visit(ident, f"https://{host}/{i}", vid0 + i, ts=ts, **extra))
    return out


def build_folder(root, idents_out=None):
    """Writes the synthetic export folder; returns {participant_key: expected set of sign ids}."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    expected = {}
    counter = [0]

    def new_pid(created=None):
        counter[0] += 1
        return pid_for(counter[0], created)

    def hw(idx):
        return dict(mem=6311489536 + idx * 4096, disks=(("disk-%03d" % idx, 256005632000 + idx),),
                    displays=(("disp-%03d" % idx, 1366, 768, "Generic PnP Monitor"),))

    def emit(ident, visits, statuses, day="2026-09-14", extra_files=()):
        write_file(root, ident, "rex-history-visit", day, visits)
        write_file(root, ident, "pdk-system-status", day, statuses)
        write_file(root, ident, "ai-market-add-identifier", day, [add_identifier(ident, ts=T0 - 10)])
        for gen, pts in extra_files:
            write_file(root, ident, gen, day, pts)

    def statuses(idx, n=5, **kw):
        base = dict(hw(idx)); base.update(kw)
        return [status(ident_cur[0], ts=T0 + i * 60, **base) for i in range(n)]

    ident_cur = [None]

    def participant(prefix="WEIb", created=None, suffix="1230"):
        pid = new_pid(created)
        ident_cur[0] = f"{prefix}_{pid}{suffix}"
        return pid, ident_cur[0], counter[0]

    # M1: local completion page under a second id, plus login visits and own-id links
    pid, ident, idx = participant()
    foreign1 = new_pid()
    vs = news(ident, 50) + [
        visit(ident, f"https://app.prolific.com/submissions/complete?cc=X&PROLIFIC_PID={foreign1}&STUDY_ID={new_pid()}", 2000, ts=T0 + 100),
        visit(ident, f"https://mit.co1.qualtrics.com/jfe/form/SV_1?PROLIFIC_PID={foreign1}&STUDY_ID={new_pid()}&SESSION_ID={new_pid()}", 2001, ts=T0 - 300),
        visit(ident, f"https://x.qualtrics.com/jfe/form/SV_2?PROLIFIC_PID={pid}&STUDY_ID={new_pid()}&SESSION_ID={new_pid()}", 2002, ts=T0 - 3600),
        visit(ident, "https://auth.prolific.com/u/login?state=abc", 2003, ts=T0 - 1800)]
    emit(ident, vs, statuses(idx)); expected[pid] = {"M1"}
    # m2: same, synced in
    pid, ident, idx = participant(); foreign2 = new_pid()
    vs = news(ident, 50) + [visit(ident, f"https://app.prolific.com/submissions/complete?PROLIFIC_PID={foreign2}", 2000, ts=T0 + 100, is_local=False)]
    emit(ident, vs, statuses(idx)); expected[pid] = {"m2"}
    # M2: two participants sharing a storage id over the same hour
    pa, ia, ixa = participant(); pb, ib, ixb = participant()
    sa = [status(ia, ts=T0 + i * 60, mem=hw(ixa)["mem"], disks=(("shared-run-id", 1022317891584),), displays=hw(ixa)["displays"]) for i in range(10)]
    sb = [status(ib, ts=T0 + 120 + i * 60, mem=hw(ixb)["mem"], disks=(("shared-run-id", 1022317891584),), displays=hw(ixb)["displays"]) for i in range(10)]
    emit(ia, news(ia, 50), sa); emit(ib, news(ib, 50), sb); expected[pa] = {"M2"}; expected[pb] = {"M2"}
    # M3: AdsPower launch page opening a session (also m4 because the host is an antidetect host)
    pid, ident, idx = participant()
    vs = [visit(ident, "https://start.adspower.net/?id=k1edmect&host=127.0.0.1:20725", 999, ts=T0 - 7200, transition_type="auto_toplevel")] + news(ident, 50)
    emit(ident, vs, statuses(idx)); expected[pid] = {"M3", "m4"}
    # M4: Kenya sign-in on day 1 and day 9
    pid, ident, idx = participant()
    vs = news(ident, 50) + [visit(ident, "https://accounts.google.co.ke/accounts/SetSID?ssdc=1", 2000, ts=T0),
                            visit(ident, "https://accounts.google.co.ke/accounts/SetSID?ssdc=1", 2001, ts=T0 + 8 * DAY)]
    emit(ident, vs, statuses(idx)); expected[pid] = {"M4"}
    # m16: one day only
    pid, ident, idx = participant()
    vs = news(ident, 50) + [visit(ident, "https://accounts.google.com.ng/accounts/SetSID?ssdc=1", 2000, ts=T0)]
    emit(ident, vs, statuses(idx)); expected[pid] = {"m16"}
    # M5: Nairobi clock on 8 days
    pid, ident, idx = participant()
    st = [status(ident, ts=T0 + i * DAY, tz="Africa/Nairobi", **hw(idx)) for i in range(8)]
    emit(ident, news(ident, 50, tz="Africa/Nairobi"), st); expected[pid] = {"M5"}
    # m17: one London point among New York days
    pid, ident, idx = participant()
    st = [status(ident, ts=T0 + i * DAY, **hw(idx)) for i in range(10)] + [status(ident, ts=T0 + 3 * DAY + 12 * 3600, tz="Europe/London", **hw(idx))]
    emit(ident, news(ident, 50), st); expected[pid] = {"m17"}
    # M6: Venezuela install locale
    pid, ident, idx = participant()
    vs = news(ident, 50) + [visit(ident, "https://www.google.com/search?q=weather&rlz=1C1ONGR_enVE1180VE1180", 2000, ts=T0)]
    emit(ident, vs, statuses(idx)); expected[pid] = {"M6"}
    # m1: identical Windows bytes, disjoint spans
    pa, ia, ixa = participant(); pb, ib, ixb = participant()
    same = dict(mem=8299606016, disks=(("disk-a", 236063813632),))
    emit(ia, news(ia, 50), [status(ia, ts=T0 + i * 60, displays=hw(ixa)["displays"], **same) for i in range(5)])
    sameb = dict(mem=8299606016, disks=(("disk-b", 236063813632),))
    emit(ib, news(ib, 50, ts0=T0 + 10 * DAY), [status(ib, ts=T0 + 10 * DAY + i * 60, displays=hw(ixb)["displays"], **sameb) for i in range(5)])
    expected[pa] = {"m1"}; expected[pb] = {"m1"}
    # m3: one foreign id in two participants' study links (M1 fires too: a second id in a study link)
    shared_foreign = new_pid()
    for _ in range(2):
        pid, ident, idx = participant()
        vs = news(ident, 50) + [visit(ident, f"https://osu.az1.qualtrics.com/jfe/form/SV_3?PROLIFIC_PID={shared_foreign}&STUDY_ID={new_pid()}", 2000, ts=T0)]
        emit(ident, vs, statuses(idx)); expected[pid] = {"M1", "m3"}
    # m4: whoer.net typed three times
    pid, ident, idx = participant()
    vs = news(ident, 50) + [visit(ident, "https://whoer.net/", 2000 + i, ts=T0 + i * DAY + 5000, transition_type="typed") for i in range(3)]
    emit(ident, vs, statuses(idx)); expected[pid] = {"m4"}
    # m5: generic non-PnP display
    pid, ident, idx = participant()
    emit(ident, news(ident, 50), statuses(idx, displays=(("disp-vm", 854, 480, "Generic Non-PnP Monitor"),))); expected[pid] = {"m5"}
    # m6: account created 10 days before first upload
    pid, ident, idx = participant(created=int(T0 - 10 * DAY))
    emit(ident, news(ident, 50), statuses(idx)); expected[pid] = {"m6"}
    # m7: two prefixes, one pid
    pid, ident, idx = participant()
    emit(ident, news(ident, 50), statuses(idx))
    ident2 = f"WEIx_{pid}1231"
    write_file(root, ident2, "pdk-system-status", "2026-09-15", [status(ident2, ts=T0 + DAY + i * 60, **hw(idx)) for i in range(3)])
    expected[pid] = {"m7"}
    # m8: visits only at 02:00-04:00 New York (06:00-08:00 UTC), 100 of them
    pid, ident, idx = participant()
    vs = [visit(ident, f"https://news.example/n{i}", 1000 + i, ts=T0 - (T0 % DAY) + (i % 10) * DAY + 6 * 3600 + (i % 3) * 3600 + (i * i * 131) % 3400) for i in range(100)]
    emit(ident, vs, statuses(idx)); expected[pid] = {"m8"}
    # m9: zone switch within an hour
    pid, ident, idx = participant()
    st = [status(ident, ts=T0, tz="America/Chicago", **hw(idx)), status(ident, ts=T0 + 3600, tz="America/Los_Angeles", **hw(idx)), status(ident, ts=T0 + 7200, tz="America/Chicago", **hw(idx))]
    emit(ident, news(ident, 50), st); expected[pid] = {"m9"}
    # m10: two CPU models, browsing on both within an hour (bundle ids tie visits to status points)
    pid, ident, idx = participant()
    st = [status(ident, ts=T0, cpu="CPU One", bundle=11, **hw(idx)), status(ident, ts=T0 + 600, cpu="CPU Two", bundle=12, **hw(idx))]
    vs = news(ident, 50) + [visit(ident, "https://a.example/", 2000, ts=T0 + 5, bundle=11), visit(ident, "https://b.example/", 2001, ts=T0 + 605, bundle=12)]
    emit(ident, vs, st); expected[pid] = {"m10"}
    # m11: fresh profile (history ids 5 and 7 at the first visit after install)
    pid, ident, idx = participant()
    vs = [visit(ident, f"https://news.example/f{i}", 5 + i, ts=T0 + i, history_item_id=str(7 + i)) for i in range(60)]
    emit(ident, vs, statuses(idx)); expected[pid] = {"m11"}
    # m12: same Gmail title under two participants (raw mode)
    for _ in range(2):
        pid, ident, idx = participant()
        vs = news(ident, 50) + [visit(ident, "https://mail.google.com/mail/u/0/", 2000, ts=T0, title="Inbox (2) - shared.person@example.org - Gmail")]
        emit(ident, vs, statuses(idx)); expected[pid] = {"m12"}
    # m13: Spanish interface parameter
    pid, ident, idx = participant()
    vs = news(ident, 50) + [visit(ident, "https://www.google.com/search?q=weather&hl=es", 2000, ts=T0)]
    emit(ident, vs, statuses(idx)); expected[pid] = {"m13"}
    # m14: 61 visits exactly 10 s apart on a non-dashboard host
    pid, ident, idx = participant()
    vs = [visit(ident, "https://kalshi.com/markets", 1000 + i, ts=T0 + 10 * i) for i in range(61)]
    emit(ident, vs, statuses(idx)); expected[pid] = {"m14"}
    # m15: 12 study windows, 6 with a chatbot visit inside
    pid, ident, idx = participant()
    vs = news(ident, 50)
    for i in range(12):
        sess = new_pid(); t0 = T0 + 20 * DAY + i * 5000
        vs.append(visit(ident, f"https://x.qualtrics.com/jfe/form/SV_9?PROLIFIC_PID={pid}&STUDY_ID={new_pid()}&SESSION_ID={sess}", 3000 + 3 * i, ts=t0))
        if i < 6:
            vs.append(visit(ident, "https://chatgpt.com/c/abc", 3001 + 3 * i, ts=t0 + 60))
        vs.append(visit(ident, f"https://app.prolific.com/submissions/complete?cc=X&PROLIFIC_PID={pid}&SESSION_ID={sess}", 3002 + 3 * i, ts=t0 + 600))
    emit(ident, vs, statuses(idx)); expected[pid] = {"m15"}
    # clean participants: three plain, one Chrome+Edge pair, one with case variants and both file-name variants
    clean = []
    for k in range(3):
        pid, ident, idx = participant()
        emit(ident, news(ident, 60), statuses(idx)); clean.append(pid)
    pid = new_pid(); idx = counter[0]
    for pre, ua in (("AIMECcplc", GEN_UA), ("AIMECeplc", EDGE_UA)):
        ident = f"{pre}_{pid}1231"
        write_file(root, ident, "rex-history-visit", "2026-09-14", news(ident, 60, ua=ua))
        write_file(root, ident, "pdk-system-status", "2026-09-14", [status(ident, ts=T0 + i * 60, ua=ua, **hw(idx)) for i in range(5)])
        write_file(root, ident, "ai-market-add-identifier", "2026-09-14", [add_identifier(ident, ts=T0 - 10)])
    clean.append(pid)
    pid = new_pid(); idx = counter[0]
    up, lo = f"WEIb_{pid}1230", f"weib_{pid}1230"
    pts = news(up, 60)
    write_file(root, up, "rex-history-visit", "2026-09-14", pts, "plain")
    write_file(root, lo, "rex-history-visit", "2026-09-14", pts, "recorded")
    write_file(root, up, "pdk-system-status", "2026-09-14", [status(up, ts=T0 + i * 60, **hw(idx)) for i in range(5)], "plain")
    write_file(root, lo, "pdk-system-status", "2026-09-28", [status(lo, ts=T0 + 14 * DAY + i * 60, **hw(idx)) for i in range(5)], "created")
    write_file(root, up, "ai-market-add-identifier", "2026-09-14", [add_identifier(up, ts=T0 - 10)])
    clean.append(pid)
    for pid in clean:
        expected[pid] = set()
    # an internal install, a zip holding one file, and a truncated file
    internal = "WEIplaywrightCC_test07300000000000"
    write_file(root, internal, "pdk-system-status", "2026-09-14", [status(internal)])
    zpath = root / "extra.zip"
    member = f"{up}__pdk-app-event__2026-09-16.json"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr(member, json.dumps([event(up, "rex-history-collection-complete", ts=T0 + 2 * DAY, count=12)]))
    (root / f"{up}__rex-history-visit__2026-09-17.json").write_text('[{"url": "https://a.example/"')
    return expected


if __name__ == "__main__":
    import sys
    exp = build_folder(sys.argv[1])
    print(f"wrote synthetic folder {sys.argv[1]}: {len(exp)} participants")
