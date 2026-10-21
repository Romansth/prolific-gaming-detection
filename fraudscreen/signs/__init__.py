"""The sign catalogue: ids, tiers, rules, innocent readings, and the result structures every
sign module fills in."""
import datetime as dt
from collections import namedtuple
from dataclasses import dataclass, field
from typing import List

Evidence = namedtuple("Evidence", "when what file")
Sign = namedtuple("Sign", "id tier title rule innocent modes")
MAX_EVIDENCE = 5

SIGNS = [
    Sign("M1", "major", "Second Prolific id used in the monitored browser",
         "A local visit to a Prolific-specific URL (app.prolific.com with PROLIFIC_PID, any host with PROLIFIC_PID/prolific_pid, "
         "conjointly.online with id) carrying a participant id that is not this participant's own; in raw mode the id must be an "
         "account created more than one day before the visit. In redacted data also an enrolled participant's token in the id list "
         "of an opaque URL.",
         "A relative with their own Prolific account used this browser profile.", "both"),
    Sign("M2", "major", "Two enrolled participants in one running browser",
         "A storage or display id (transient per browser run, at least 6 characters) reported by installs of two different participants "
         "within the same minute.",
         "Two household members each keep a profile in the same Chrome window.", "both"),
    Sign("M3", "major", "Antidetect browser",
         "An antidetect launch page (start.adspower.net/?id=...&host=127.0.0.1:...) opening a browsing session or loaded as auto_toplevel.",
         "A legitimate multi-profile browser setup for work accounts.", "raw"),   # the launch query is tokenized away in redacted data
    Sign("M4", "major", "Google routed sign-ins outside the US, persistently",
         "accounts.google.<non-.com country domain> or consent.google.*/m?gl=<not US> on at least two calendar days at least 7 days "
         "apart (local visits; US territories count as US).",
         "A US resident on a foreign VPN exit, or travelling.", "both"),
    Sign("M5", "major", "Device clock outside the US, persistently",
         "A non-US timezone on at least 7 distinct local dates or on at least half of all observation minutes. One observation per "
         "minute and zone; a visit counts at the time its record was written, so a backfilled history collection counts once "
         "(Etc/GMT+4..+10 and US territories count as US).",
         "A US resident with a mis-set clock.", "both"),
    Sign("M6", "major", "Chrome installed with a non-US locale",
         "The rlz parameter on google.*/search carries an install country code other than the US or its territories "
         "(the two letters after the language, e.g. en-GBGB917 is GB).",
         "A US resident using a Chrome download from another country.", "both"),
    Sign("m1", "minor", "Same Windows or Linux hardware as another participant",
         "Identical platform, CPU model, logical processors, memory bytes and sorted fixed-disk bytes (over 2 GB, removable media "
         "excluded) on Windows or Linux; Mac, ChromeOS and records without hardware fields are ignored.",
         "Two household members share one PC.", "both"),
    Sign("m2", "minor", "Another participant's id synced into this profile",
         "The M1 pattern on visits marked is_local false (arrived through browser account sync).",
         "The Google account also signs in on a relative's device.", "both"),
    Sign("m3", "minor", "Link-sharing",
         "The same foreign Prolific id appears in two or more participants' browsers, or two participants carry each other's ids.",
         "A study link forwarded by another worker.", "both"),
    Sign("m4", "minor", "Concealment tool sites",
         "Visits to antidetect, IP or fingerprint checker, VPN account, proxy or bandwidth-selling, remote-control, SMS reseller, "
         "temp-mail or fake-identity generator hosts or their subdomains (VPN account pages host-exact); VPN marketing roots do not count.",
         "A VPN subscription, a curiosity visit, or remote-work tools.", "both"),
    Sign("m5", "minor", "Virtual machine or remote session",
         "CPU model naming a hypervisor, a display named Generic Non-PnP, or more than four distinct display sizes within seven days.",
         "A work laptop on a remote desktop, or a projector.", "both"),
    Sign("m6", "minor", "Prolific account younger than 30 days at enrolment",
         "Account creation (ObjectId time; month in redacted mode) less than 30 days before enrolment (the add-identifier record, "
         "else the first status point; never a backfilled history visit), or two enrolled ids created within 10 minutes of each "
         "other (raw mode only).",
         "A new but genuine Prolific account.", "both"),
    Sign("m7", "minor", "Same Prolific id enrolled twice",
         "Two identifiers with different cohort labels for one Prolific id in one study (Chrome and Edge pairs excluded; not "
         "evaluated when the redactor has hidden a label).",
         "Re-enrolment after a reinstall.", "both"),
    Sign("m8", "minor", "Activity hours disagree with the reported clock",
         "Share of at least 80 local visits at 01:00 to 05:00 in the reported zone above the fleet 95th percentile (floor 20 %; the "
         "floor alone when fewer than 20 participants set the percentile), while some other UTC offset gives under 3 %.",
         "A night-shift worker.", "both"),
    Sign("m9", "minor", "Timezone switches",
         "More than one zone on one install with a switch inside 3 hours between zones whose UTC offsets differ (a missing zone or "
         "an alias of the same zone is not a switch).",
         "Travel, or Windows automatic time-zone changes on a laptop.", "both"),
    Sign("m10", "minor", "One identifier on two machines",
         "Two different CPU models under one install with local visits attributed to both within one hour (by upload bundle, else nearest status point within 2 minutes).",
         "One person with a desktop and a laptop.", "both"),
    Sign("m11", "minor", "Survey-only browser, fresh profile, typed study links",
         "Survey-infrastructure share of at least 50 local visits above the fleet 95th percentile (floor 80 %; the floor alone below "
         "20 participants); or history ids under 200 at the first visit after install; or more than 25 % of at least 8 study links typed.",
         "A profile kept for survey work, or a new Chrome install.", "both"),
    Sign("m12", "minor", "Mail identity shared with another participant",
         "A Gmail or Outlook page title yielding the same address or display name under two Prolific ids.",
         "A shared family mailbox.", "raw"),
    Sign("m13", "minor", "Foreign-language interface and searches",
         "hl= with a language other than English (en-GB and en_CA are English); in raw mode also Google result pages titled in "
         "another language and searches matching a fixed pattern list (zip codes, my IP, address generators, prolific vpn).",
         "A bilingual household or a curiosity search.", "both"),
    Sign("m14", "minor", "Automated reloads",
         "More than 25 % of at least 50 inter-visit gaps of 2 to 900 s equal to one modal value after removing same-URL reloads on "
         "self-refreshing dashboards, or a headless user agent.",
         "A Prolific auto-refresh extension.", "both"),
    Sign("m15", "minor", "Chatbot during surveys",
         "Chatbot visits or new conversations inside more than the fleet 95th percentile (floor 30 %; the floor alone below 20 "
         "participants) of at least 10 Prolific study windows.",
         "Permitted chatbot use in the surveys taken.", "both"),
    Sign("m16", "minor", "Non-US sign-in route, one episode",
         "The M4 pattern on a single day or within one week.",
         "A US resident on a foreign VPN exit, or travelling.", "both"),
    Sign("m17", "minor", "Non-US device clock, briefly",
         "The M5 pattern on fewer than 7 days and under half of observation minutes.",
         "A laptop that changed zone for a day.", "both"),
]
_BY_ID = {s.id: s for s in SIGNS}


def sign_by_id(sid):
    return _BY_ID[sid]


def fmt_utc(ts_s):
    return dt.datetime.fromtimestamp(float(ts_s), dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def visit_url(v):
    return "https://" + v.host + v.path + ("?" + v.query if v.query else "")


def evidence_from_visit(v, what=None):
    return Evidence(fmt_utc(v.t_ms / 1000), what if what is not None else visit_url(v), v.file)


@dataclass
class SignResult:
    sign_id: str
    fired: bool = False
    count: int = 0
    evidence: List[Evidence] = field(default_factory=list)
    linked: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    available: bool = True

    def add(self, ev):
        self.count += 1
        if len(self.evidence) < MAX_EVIDENCE:
            self.evidence.append(ev)
        self.fired = True

    def link(self, key):
        if key not in self.linked:
            self.linked.append(key)


@dataclass
class Context:
    participants: list
    fleet: object
    raw_mode: bool
    by_key: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.by_key:
            self.by_key = {p["key"]: p for p in self.participants}
