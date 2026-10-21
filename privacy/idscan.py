"""ID scan: replace study identifiers, email addresses and 24-hex IDs inside
one string with tokens, leaving the rest of the string as it was."""
import re
from datetime import datetime, timezone
from urllib.parse import unquote

from privacy.tokens import TOKEN_RE

# Either lookbehind may hold: no letter or digit before, or a %XX escape before
# (so "id%3DWEIb_..." matches). The lookahead stops a shown prefix plus its
# token ("WEIb_ident_...") from being tokenized again on a second pass.
IDENT_RE = re.compile(
    r"(?:(?<![A-Za-z0-9])|(?<=%[0-9A-Fa-f]{2}))(?:"
    r"((?:AIM(?:MS|EC)|WEI)[a-z]+[A-Z0-9]*_)(?!" + TOKEN_RE + r")([A-Za-z0-9]+)"
    r"|((?:aim(?:ms|ec)|wei)[a-z]+_)(?!" + TOKEN_RE + r")([0-9a-f]{24}[0-9]*))")
# The second alternative is the lower-case prefix variant an install can carry; it needs a 24-hex
# core so that ordinary words ("weib_count") are not taken for identifiers.


def ident_parts(m):
    return (m.group(1) or m.group(3)), (m.group(2) or m.group(4))
# The lookbehinds stop a match from starting inside a %XX escape. The local part
# is capped at 64 (the RFC limit); unbounded, a long run without "@" scans in
# quadratic time.
EMAIL_RE = re.compile(
    r"(?<!%)(?<!%[0-9A-Fa-f])[A-Za-z0-9._+-]{1,64}(?:@|%40)"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
HEXRUN_RE = re.compile(r"[0-9a-fA-F]{24,}")
HEX24_RE = re.compile(r"[0-9a-fA-F]{24}")


def decodings(text, rounds=3):
    out = [text]
    for _ in range(rounds):
        nxt = unquote(out[-1])
        if nxt == out[-1]:
            break
        out.append(nxt)
    return out


_SEPARATORS = frozenset(" \t\r\n\f\v\"'<>")
_SEPARATOR_RE = re.compile(r"[\s\"'<>]")


def _encoded_windows(text):
    """Each separator-bounded stretch of text that holds a %. Found without
    copying the whole text: a census worker holds files of hundreds of MB."""
    pos, n = 0, len(text)
    while True:
        i = text.find("%", pos)
        if i == -1:
            return
        start = i
        while start > pos and text[start - 1] not in _SEPARATORS:
            start -= 1
        m = _SEPARATOR_RE.search(text, i)
        end = m.start() if m else n
        yield text[start:end]
        pos = end


def _add_runs(t, found):
    for m in HEXRUN_RE.finditer(t):
        if m.start() > 0 and t[m.start() - 1] == "%":
            continue
        run = m.group(0).lower()
        if len(run) < 32:
            found.add(run[:24])


def candidate_ids(text):
    """24-hex IDs in text: exact runs, and the first 24 of a 25-31 run (an ID
    with a digit tail). A run right after % is an escape plus hex, skipped
    here; the decoded copy of its stretch shows the real boundary."""
    found = set()
    _add_runs(text, found)
    for window in _encoded_windows(text):
        for t in decodings(window)[1:]:
            _add_runs(t, found)
    return found


def created_month(hex24):
    try:
        when = datetime.fromtimestamp(int(hex24[:8], 16), tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return ""
    return when.strftime("%Y-%m") if 2009 <= when.year <= 2100 else ""


class IdScanner:
    def __init__(self, tokenizer, known_hex=(), prefix_counts=None, threshold=5):
        self.tok = tokenizer
        self.known = set(known_hex)
        self.prefix_counts = {k.lower(): v for k, v in (prefix_counts or {}).items()}
        self.threshold = threshold
        self.ident_info = {}

    def scan(self, text, found=None):
        if not text:
            return text
        text = IDENT_RE.sub(lambda m: self._ident(m, found), text)
        text = EMAIL_RE.sub(lambda m: self._email(m, found), text)
        return HEXRUN_RE.sub(lambda m: self._hexrun(m, found), text)

    def _emit(self, tok, found):
        if found is not None:
            found.append(tok)
        return tok

    def _ident(self, m, found):
        prefix, suffix = ident_parts(m)
        tok = self._emit(self.tok.token("ident", prefix + suffix), found)
        shown = prefix if self.prefix_counts.get(prefix.lower(), 0) >= self.threshold else ""
        if tok not in self.ident_info:
            inner = HEX24_RE.search(suffix)
            pid = self.tok.token("pid", inner.group(0).lower()) if inner else ""
            self.ident_info[tok] = {"prefix": shown, "pid": pid,
                                    "pid_created": created_month(inner.group(0)) if inner else "",
                                    # the lower-cased identifier's token: case variants share it
                                    "install": self.tok.token("ident", (prefix + suffix).lower())}
        return shown + tok

    def _email(self, m, found):
        return self._emit(self.tok.token("email", unquote(m.group(0)).lower()), found)

    def _pid(self, hex24, found):
        return self._emit(self.tok.token("pid", hex24), found)

    def _hexrun(self, m, found):
        run, low = m.group(0), m.group(0).lower()
        escaped = m.start() > 0 and m.string[m.start() - 1] == "%"
        if len(run) < 32:
            w = next((i for i in range(len(low) - 23) if low[i:i + 24] in self.known), None)
            if w is None:
                w = 2 if escaped else 0
                if len(run) - w < 24:
                    return run
            return run[:w] + self._pid(low[w:w + 24], found) + run[w + 24:]
        # 32+ hex is a hash (MD5, SHA-1, SHA-256); only a known ID inside it is replaced.
        out, last, i = [], 0, 0
        while i + 24 <= len(low):
            if low[i:i + 24] in self.known:
                out += [run[last:i], self._pid(low[i:i + 24], found)]
                i = last = i + 24
            else:
                i += 1
        out.append(run[last:])
        return "".join(out)
