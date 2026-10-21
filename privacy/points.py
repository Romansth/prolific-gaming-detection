"""Redact one PDK point with the field rules."""
from privacy import rules as R

_GONE = object()


def is_point(obj):
    return isinstance(obj, dict) and isinstance(obj.get("passive-data-metadata"), dict)


def generator_of(point):
    meta = point.get("passive-data-metadata") or {}
    gen = meta.get("generator-id") or point.get("generatorId") or ""
    return gen or str(meta.get("generator", "")).split(":")[0].strip()


class PointRedactor:
    def __init__(self, scanner, urls, scrubber):
        self.scanner = scanner
        self.urls = urls
        self.scrubber = scrubber
        self.points = {}
        self.dropped = {}
        self.dropped_by_rule = {}

    def redact(self, point):
        gen = generator_of(point)
        self.points[gen] = self.points.get(gen, 0) + 1
        out = self._node(point, (), R.ruleset_for(gen), gen)
        return {} if out is _GONE else out

    def _count(self, store, gen, path):
        per = store.setdefault(gen, {})
        key = R.path_string(path)
        per[key] = per.get(key, 0) + 1

    def _node(self, value, path, rs, gen):
        rule = rs.lookup(path) if path else None
        if rule == R.DROP:
            self._count(self.dropped_by_rule, gen, path)
            return _GONE
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                child = self._node(v, path + (R.normalize_key(str(k)),), rs, gen)
                if child is not _GONE:
                    out[self.scanner.scan(str(k))] = child
            return _GONE if (value and not out and rule is None) else out
        if isinstance(value, list):
            out = [c for c in (self._node(v, path + ("[]",), rs, gen) for v in value) if c is not _GONE]
            return _GONE if (value and not out and rule is None) else out
        if rule is None:
            self._count(self.dropped, gen, path)
            return _GONE
        return self._leaf(rule, value)

    def _leaf(self, rule, value):
        if not isinstance(value, str):
            return value  # numbers, booleans and null carry no identifiers
        if rule == R.KEEP:
            return self.scrubber.scrub(value)
        if rule == R.URL:
            return self.urls.apply(value)
        if rule == R.DOMAIN:
            return self.urls.domain(value)
        if rule == R.DEV:
            return self.scanner.tok.token("dev", value)
        if rule == R.Q:
            return self.scanner.tok.token("q", value) if value else value
        raise ValueError(f"unknown treatment: {rule}")
