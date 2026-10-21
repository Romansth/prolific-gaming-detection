"""URL rule (spec, "URL rule"), the domain rule, and a scrubber for free text
that may contain URLs."""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from privacy.idscan import decodings
from privacy.tokens import TOKEN_RE

URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>\\]*[^\s\"'<>\\.,;:!?)\]}]")
NESTED_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
# rlz is Chrome's install code (brand, locale, date); authuser a signed-in slot
# or an email, which the ID scan tokenizes; cr and lr country and language filters.
KEEP_PARAMS = {"gl", "hl", "udm", "tbm", "rlz", "cr", "lr", "authuser"}
# Public services whose visit is itself a fraud-screen signal: anti-detect
# browsers, IP and fingerprint checkers, VPN and proxy providers, bandwidth-
# selling apps, remote access, SMS and temporary-mail services. Rarely visited,
# so the participant threshold would hide them, but none is a personal site.
_FALLBACK_SIGNAL_HOSTS = (
    "adspower.net", "adspower.com", "multilogin.com", "gologin.com", "dolphin-anty.com",
    "incogniton.com", "octobrowser.net", "kameleo.io", "undetectable.io", "vmlogin.us",
    "morelogin.com", "nstbrowser.io", "ixbrowser.com", "bitbrowser.net", "hidemyacc.com",
    "whoer.net", "ipinfo.io", "iplocation.net", "whatismyipaddress.com", "whatismyip.com",
    "ipleak.net", "browserleaks.com", "pixelscan.net", "iphey.com", "amiunique.org",
    "ipqualityscore.com", "scamalytics.com", "ip-api.com", "ipapi.co", "ipify.org",
    "myip.com", "dnsleaktest.com", "maxmind.com", "ip2location.com", "fingerprint.com",
    "deviceinfo.me", "nordvpn.com", "expressvpn.com", "surfshark.com", "protonvpn.com",
    "privateinternetaccess.com", "cyberghostvpn.com", "ipvanish.com", "hidemyass.com",
    "hide.me", "windscribe.com", "tunnelbear.com", "mullvad.net", "hola.org", "urban-vpn.com",
    "brightdata.com", "oxylabs.io", "smartproxy.com", "decodo.com", "iproyal.com", "soax.com",
    "webshare.io", "922proxy.com", "lunaproxy.com", "honeygain.com", "peer2profit.com",
    "earnapp.com", "repocket.com", "pawns.app", "traffmonetizer.com", "packetstream.io",
    "getgrass.io", "anydesk.com", "teamviewer.com", "remotedesktop.google.com", "parsec.app",
    "splashtop.com", "rustdesk.com", "ultraviewer.net", "sms-activate.org", "smspva.com",
    "5sim.net", "textverified.com", "quackr.io", "receive-smss.com", "temp-mail.org",
    "10minutemail.com", "guerrillamail.com", "mailinator.com",
)

try:  # one list, shared with the screen; the fallback keeps the redactor usable on its own
    from fraudscreen.hosts import FRAUD_SIGNAL_HOSTS
except ImportError:  # pragma: no cover
    FRAUD_SIGNAL_HOSTS = _FALLBACK_SIGNAL_HOSTS


def is_signal_host(host):
    return any(host == d or host.endswith("." + d) for d in FRAUD_SIGNAL_HOSTS)
_GOOGLE = r"google(?:\.[a-z]{2,3}){1,2}"
ALLOW = [
    (re.compile(r"(?:www\.)?" + _GOOGLE), "/search"),
    (re.compile(r"(?:www\.)?" + _GOOGLE), "/url"),
    (re.compile(r"accounts\." + _GOOGLE), "/"),
    (re.compile(r"consent\." + _GOOGLE), "/m"),   # server-issued gl= country on consent redirects
    (re.compile(r"(?:www\.)?bing\.com"), "/search"),
    (re.compile(r"(?:[a-z0-9-]+\.)*prolific\.(?:com|co)"), "/"),
    (re.compile(r"(?:[a-z0-9-]+\.)*qualtrics\.com"), "/jfe/form/"),
    (re.compile(r"(?:[a-z0-9-]+\.)*cloudresearch\.com"), "/"),
    (re.compile(r"chatgpt\.com"), "/c/"),
    (re.compile(r"gemini\.google\.com"), "/app"),
]
TOKEN_FIND_RE = re.compile(TOKEN_RE)
# What may surround ID tokens in a query value that stays readable, e.g.
# MITINTA_pid_..._0015. Anything longer or with spaces becomes a q token.
ID_GLUE_RE = re.compile(r"[A-Za-z0-9_.-]{0,40}")


class UrlRule:
    def __init__(self, scanner, host_counts=None, domain_counts=None, threshold=5):
        self.scanner = scanner
        self.tok = scanner.tok
        self.host_counts = host_counts or {}
        self.domain_counts = domain_counts or {}
        self.threshold = threshold

    @staticmethod
    def allowed_host(host):
        return any(h.fullmatch(host) for h, _ in ALLOW) or is_signal_host(host)

    @staticmethod
    def allowed(host, path):
        return any(h.fullmatch(host) and (path or "/").startswith(p) for h, p in ALLOW)

    def host_part(self, host):
        if self.allowed_host(host) or self.host_counts.get(host, 0) >= self.threshold:
            return host
        return self.tok.token("host", host)

    def domain(self, value):
        v = value.lower()
        if self.allowed_host(v) or self.domain_counts.get(v, 0) >= self.threshold:
            return self.scanner.scan(value)
        return self.tok.token("host", v)

    def apply(self, url):
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()  # hostname drops user:password@
            port = parts.port
        except ValueError:
            return self._opaque(url, "")
        scheme = parts.scheme.lower()
        port_s = f":{port}" if port else ""
        if scheme in ("http", "https") and host:
            if self.allowed(host, parts.path):
                return urlunsplit((scheme, host + port_s, self.scanner.scan(parts.path),
                                   self._query(parts.query), ""))
            return self._opaque(url, f"{scheme}://{self.host_part(host)}{port_s}/")
        if scheme in ("chrome", "edge") and host:
            if parts.path in ("", "/") and not parts.query and not parts.fragment:
                return f"{scheme}://{host}/"
            return self._opaque(url, f"{scheme}://{host}/")
        if scheme:
            return self._opaque(url, f"{scheme}:")
        return self.scanner.scan(url)

    def _opaque(self, url, head):
        found = []
        for text in decodings(url):
            self.scanner.scan(text, found)
        ids = list(dict.fromkeys(found))
        return head + self.tok.token("url", url) + ("?ids=" + ",".join(ids) if ids else "")

    def _query(self, query):
        if not query:
            return ""
        pairs = [(self.scanner.scan(name), self._value(name, value))
                 for name, value in parse_qsl(query, keep_blank_values=True)]
        return urlencode(pairs)

    def _value(self, name, value):
        if value == "":
            return ""
        if name.lower() in KEEP_PARAMS:
            return self.scanner.scan(value)
        if NESTED_URL_RE.match(value):
            return self.apply(value)
        scanned = self.scanner.scan(value)
        if TOKEN_FIND_RE.search(scanned) and ID_GLUE_RE.fullmatch(TOKEN_FIND_RE.sub("", scanned)):
            return scanned
        return self.tok.token("q", value)


class Scrubber:
    """Free text: each URL gets the URL rule, everything between gets the ID scan."""

    def __init__(self, scanner, urls):
        self.scanner = scanner
        self.urls = urls

    def scrub(self, text):
        if not text:
            return text
        out, last = [], 0
        for m in URL_IN_TEXT_RE.finditer(text):
            out.append(self.scanner.scan(text[last:m.start()]))
            out.append(self.urls.apply(m.group(0)))
            last = m.end()
        out.append(self.scanner.scan(text[last:]))
        return "".join(out)
