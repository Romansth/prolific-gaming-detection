"""Field rules for PDK points (spec, "Rules for PDK exports"). Patterns use "."
between keys, "[]" for a list item, "*" for one key and "**" for any depth.
The first matching pattern wins; a field no pattern matches is dropped and
listed in the report."""
import re

KEEP, URL, DOMAIN, DEV, Q, DROP = "keep", "url", "domain", "dev", "q", "drop"

_META = ("source", "generator", "generator-id", "timestamp", "timezone", "enqueued-at",
         "configuration-hash", "encrypted_transmission")
COMMON = ([("passive-data-metadata." + k, KEEP) for k in _META]
          + [("date", KEEP), ("generatorId", KEEP), ("name", KEEP), ("source", KEEP),
             ("_pdk_trace_context.**", KEEP)])  # server-side upload-bundle ids

_VISIT_GRAPH = [("capture_rule", KEEP), ("referring_visit_id", KEEP), ("visit_id", KEEP),
                ("visit_time", KEEP), ("transition", KEEP), ("scheme", KEEP), ("tab_id", KEEP),
                ("url", URL)]
_MIRROR = [("type", KEEP), ("foreground", KEEP), ("engine", KEEP), ("index", KEEP),
           ("link", URL), ("search_url", URL), ("query", Q),
           ("title", DROP), ("citation", DROP), ("content", DROP)]
_MIRROR_BOTH = _MIRROR + [("payload." + p, t) for p, t in _MIRROR]

RULES = {
    "rex-history-visit": [
        ("url", URL), ("recorded_url", URL), ("domain", DOMAIN), ("title", DROP),
        ("categories[]", KEEP), ("filtered", KEEP), ("history_item_id", KEEP), ("is_local", KEEP),
        ("last_visit_time", KEEP), ("referring_visit_id", KEEP), ("transition_type", KEEP),
        ("typed_count", KEEP), ("visit_count", KEEP), ("visit_id", KEEP), ("visit_time", KEEP)],
    "rex-history-visit-aggregate": [
        ("url", URL), ("recorded_url", URL), ("domain", DOMAIN), ("title", DROP),
        ("filtered", KEEP), ("history_item_id", KEEP), ("last_visit_time", KEEP),
        ("typed_count", KEEP), ("visit_count", KEEP), ("window_start", KEEP), ("window_end", KEEP)],
    "rex-visit-graph-hop": _VISIT_GRAPH,
    "rex-visit-graph-navigation": _VISIT_GRAPH,
    "rex-visit-graph-opener": _VISIT_GRAPH,
    "rex-visit-graph-page": _VISIT_GRAPH,
    "page-blocked": [("url", URL)],
    "page-manipulation": [("url", URL), ("updates.**", KEEP)],
    "pdk-app-event": [("event_name", KEEP), ("event_details.**", KEEP)],
    "pdk-system-status": [
        ("display-info[].id", DEV), ("display-info[].mirroringSourceId", DEV),
        ("display-info[].mirroringDestinationIds[]", DEV),
        ("storage-info[].id", DEV), ("storage-info[].name", DEV),
        ("cpu-info.**", KEEP), ("display-info[].**", KEEP), ("storage-info[].**", KEEP),
        ("memory-info.**", KEEP), ("local-storage-bytes", KEEP), ("pending-points", KEEP)],
    "ai-market-add-identifier": [],
    "rex-conversation": [
        ("turns.**", DROP), ("identifier", KEEP), ("is_summary", KEEP), ("platform", KEEP),
        ("user_agent", KEEP),
        ("started.**", KEEP), ("ended.**", KEEP), ("metadata.**", KEEP)],
    "search-mirror-result": _MIRROR_BOTH,
    "search-mirror-result-ai": _MIRROR_BOTH,
}

_SEG_RE = re.compile(r"\[\]|[^.\[\]]+")
_PLAIN_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,40}")
_IDLIKE_RE = re.compile(r"\d{4,}|[0-9a-fA-F]{8,}|_[0-9a-f]{6,}")


def normalize_key(key):
    """A dict key that is a plain field name stays; one that looks like an ID,
    a UUID or a selector becomes "*", in rule matching and in the report."""
    if _PLAIN_KEY_RE.fullmatch(key) and not _IDLIKE_RE.search(key):
        return key
    return "*"


def path_string(path):
    out = ""
    for seg in path:
        out += seg if seg == "[]" else ("." + seg if out else seg)
    return out


def _match(pat, path):
    if not pat:
        return not path
    head = pat[0]
    if head == "**":
        return any(_match(pat[1:], path[i:]) for i in range(len(path) + 1))
    if not path:
        return False
    ok = path[0] != "[]" if head == "*" else head == path[0]
    return ok and _match(pat[1:], path[1:])


class RuleSet:
    def __init__(self, entries):
        self.entries = [(_SEG_RE.findall(p), t) for p, t in entries]
        self.cache = {}

    def lookup(self, path):
        if path not in self.cache:
            self.cache[path] = next((t for pat, t in self.entries if _match(pat, list(path))), None)
        return self.cache[path]


_SETS = {}


def ruleset_for(generator):
    if generator not in _SETS:
        _SETS[generator] = RuleSet(COMMON + RULES.get(generator, []))
    return _SETS[generator]
