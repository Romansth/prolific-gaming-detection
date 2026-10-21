"""Compact per-install records produced by the scan and consumed by every sign."""
from collections import namedtuple

Visit = namedtuple("Visit", "t_ms host path query transition visit_id hist_id visit_count is_local tz bundle file ident_hint")
Status = namedtuple("Status", "ts tz cpu nproc arch mem disks displays plat browser ver bundle file")
Event = namedtuple("Event", "ts name count")
Conversation = namedtuple("Conversation", "platform started_s")


def new_install(ident):
    return {"ident": ident, "visits": [], "status": [], "events": [], "conversations": [],
            "registered_at": None, "files": set(), "mail_identities": [], "unreadable": 0,
            "chash": {}, "headless": False, "nonen_titles": {}}


def merge_install(into, part):
    """Fold a partial install (one file) into the accumulated one; de-duplicate later."""
    into["visits"].extend(part["visits"])
    into["status"].extend(part["status"])
    into["events"].extend(part["events"])
    into["conversations"].extend(part["conversations"])
    if part["registered_at"] is not None:
        into["registered_at"] = part["registered_at"] if into["registered_at"] is None else min(into["registered_at"], part["registered_at"])
    into["files"] |= part["files"]
    into["mail_identities"].extend(part["mail_identities"])
    into["unreadable"] += part["unreadable"]
    for k, n in part["chash"].items():
        into["chash"][k] = into["chash"].get(k, 0) + n
    into["headless"] = into.get("headless", False) or bool(part.get("headless"))
    for k, n in part.get("nonen_titles", {}).items():
        into["nonen_titles"][k] = into["nonen_titles"].get(k, 0) + n


def dedupe_install(inst):
    seen = set(); out = []
    for v in inst["visits"]:
        k = (v.visit_id, v.t_ms, v.host, v.path)
        if k not in seen:
            seen.add(k); out.append(v)
    inst["visits"] = sorted(out, key=lambda v: v.t_ms)
    seen = set(); out = []
    for s in inst["status"]:
        if s.ts not in seen:
            seen.add(s.ts); out.append(s)
    inst["status"] = sorted(out, key=lambda s: s.ts)
    inst["events"] = sorted(set(inst["events"]), key=lambda e: e.ts)
    inst["conversations"] = sorted(set(inst["conversations"]))
    inst["mail_identities"] = sorted(set(inst["mail_identities"]))
    return inst
