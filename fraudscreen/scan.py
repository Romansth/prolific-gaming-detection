"""Parallel scan of export files into compact per-install records."""
import hashlib
import re
from multiprocessing import Pool
from pathlib import Path
from urllib.parse import urlsplit

from fraudscreen.files import list_inputs, parse_name, read_points
from fraudscreen.records import Conversation, Event, Status, Visit, dedupe_install, merge_install, new_install

_VER_RE = re.compile(r"/0\.0\.(\d+) ")
_GMAIL_RE = re.compile(r"- ([^\s@]+@[^\s@]+) - Gmail$")
_OUTLOOK_RE = re.compile(r"^(?:Mail|Inbox(?: \(\d+\))?|Sent Items|Drafts|Junk Email|Deleted Items|Archive) - (.{2,60}?) - Outlook$")
HISTORY_EVENTS = ("rex-history-collection-complete", "rex-history-collection-progress")
NONEN_TITLES = ("Buscar con Google", "Recherche Google", "Google Suche", "Google-Suche", "Pesquisa Google",
                "Cerca con Google", "Google zoeken", "Google Поиск", "Google 搜索", "Google 検索")


def _dict(x):
    return x if isinstance(x, dict) else {}


def _list(x):
    return x if isinstance(x, list) else []


def title_language(title):
    """The non-English Google interface a result-page title shows, or None."""
    if isinstance(title, str):
        for t in NONEN_TITLES:
            if title.endswith(t):
                return t
    return None


def _int(x, default=-1):
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return default


def _ua_fields(gen_string):
    ua = gen_string.split("Mozilla/5.0 ", 1)[1] if "Mozilla/5.0 " in gen_string else gen_string
    m = _VER_RE.search(gen_string)
    plat = ("Win" if "Windows" in ua else "Mac" if "Mac OS" in ua else "CrOS" if "CrOS" in ua
            else "Linux" if "Linux" in ua else "?")
    return int(m.group(1)) if m else -1, plat, ("Edge" if "Edg/" in ua else "Chrome"), ("Headless" in ua)


def _bundle(p):
    return _int(_dict(p.get("_pdk_trace_context")).get("bundle_id"), None)


def _mail_identity(title):
    if not isinstance(title, str):
        return None
    m = _GMAIL_RE.search(title)
    if m:
        return ("email", hashlib.sha1(m.group(1).lower().encode("utf-8")).hexdigest())
    m = _OUTLOOK_RE.match(title)
    if m:
        kind = "email" if "@" in m.group(1) else "name"
        return (kind, hashlib.sha1(m.group(1).strip().lower().encode("utf-8")).hexdigest())
    return None


def scan_one(inp, raw_mode):
    """(ident, partial Install) for one file. Never raises on bad content."""
    fn = parse_name(inp.name)
    inst = new_install(fn.ident if fn else inp.name)
    inst["files"].add(inp.name)
    pts = read_points(inp)
    if not pts:
        inst["unreadable"] += 1
        return inst["ident"], inst
    gen = fn.generator if fn else ""
    for p in pts:
        md = _dict(p.get("passive-data-metadata"))
        gstr = md.get("generator")
        gstr = gstr if isinstance(gstr, str) else ""
        ver, plat, browser, headless = _ua_fields(gstr)
        tz = md.get("timezone")
        tz = tz if isinstance(tz, str) else ""
        ts = md.get("timestamp")
        ts = float(ts) if isinstance(ts, (int, float)) and not isinstance(ts, bool) else None
        ch = md.get("configuration-hash")
        ch = ch[:8] if isinstance(ch, str) else ""
        if ch:
            inst["chash"][ch] = inst["chash"].get(ch, 0) + 1
        if gen == "rex-history-visit":
            url = p.get("url")
            if not isinstance(url, str):
                continue
            try:
                parts = urlsplit(url)
            except ValueError:
                continue
            loc = p.get("is_local")
            inst["visits"].append(Visit(
                _int(p.get("visit_time")), (parts.hostname or "").lower(), parts.path, parts.query,
                str(p.get("transition_type") or ""), _int(p.get("visit_id")), _int(p.get("history_item_id")),
                _int(p.get("visit_count")), (loc if isinstance(loc, bool) else None), tz, _bundle(p), inp.name,
                str(md.get("source") or "")))
            if raw_mode:
                ident = _mail_identity(p.get("title"))
                if ident and ident not in inst["mail_identities"]:
                    inst["mail_identities"].append(ident)
                lang = title_language(p.get("title"))
                if lang:
                    inst["nonen_titles"][lang] = inst["nonen_titles"].get(lang, 0) + 1
            if headless:
                inst["headless"] = True
        elif gen == "pdk-system-status":
            if ts is None:
                continue
            cpu = _dict(p.get("cpu-info"))
            mem = _dict(p.get("memory-info"))
            disks = tuple(sorted((str(s.get("id")), _int(s.get("capacity")))
                                 for s in _list(p.get("storage-info")) if isinstance(s, dict)))
            displays = tuple((str(d.get("id")), _int(_dict(d.get("bounds")).get("width")),
                              _int(_dict(d.get("bounds")).get("height")), str(d.get("name") or ""))
                             for d in _list(p.get("display-info")) if isinstance(d, dict))
            inst["status"].append(Status(ts, tz, str(cpu.get("modelName") or "").strip(), _int(cpu.get("numOfProcessors")),
                                         str(cpu.get("archName") or ""), _int(mem.get("capacity")), disks, displays,
                                         plat, browser, ver, _bundle(p), inp.name))
        elif gen == "pdk-app-event":
            name = p.get("event_name")
            if ts is not None and name in HISTORY_EVENTS:
                inst["events"].append(Event(ts, name, _int(_dict(p.get("event_details")).get("collected_count"))))
        elif gen == "ai-market-add-identifier":
            if ts is not None and (inst["registered_at"] is None or ts < inst["registered_at"]):
                inst["registered_at"] = ts
        elif gen == "rex-conversation":
            st = p.get("started")
            st = st.get("value") if isinstance(st, dict) else st
            st = _int(st, None)
            if st is not None:
                inst["conversations"].append(Conversation(str(p.get("platform") or ""), st / 1000 if st > 1e11 else float(st)))
    return inst["ident"], inst


def _job(args):
    inp, raw_mode = args
    return scan_one(inp, raw_mode)


def scan_folder(root, workers, raw_mode):
    """dict ident -> Install, identifiers exactly as in the file names."""
    inputs = list_inputs(Path(root))
    inputs.sort(key=lambda i: -(i.path.stat().st_size if i.member is None else 0))
    installs = {}
    jobs = [(i, raw_mode) for i in inputs]
    if workers <= 1:
        results = map(_job, jobs)
    else:
        pool = Pool(workers)
        results = pool.imap_unordered(_job, jobs, chunksize=4)
    for ident, part in results:
        if ident not in installs:
            installs[ident] = new_install(ident)
        merge_install(installs[ident], part)
    if workers > 1:
        pool.close(); pool.join()
    for inst in installs.values():
        dedupe_install(inst)
    return installs
