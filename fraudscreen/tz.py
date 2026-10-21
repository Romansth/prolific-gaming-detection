"""Time zones without a database. Windows Python has no zone files, so the US zones carry the
US daylight-saving rule in code and other zones a standard offset (hour-level accuracy is all
the signs need). zoneinfo is used when the platform has it."""
import datetime as dt
import re

USE_ZONEINFO = True
try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # Python 3.9+
except ImportError:  # pragma: no cover
    ZoneInfo = None

# US zones: standard offset, observes US DST
_US = {
    "America/New_York": (-5, True), "America/Detroit": (-5, True), "America/Indianapolis": (-5, True),
    "America/Kentucky/Louisville": (-5, True), "America/Kentucky/Monticello": (-5, True),
    "America/Chicago": (-6, True), "America/Indiana/Knox": (-6, True), "America/Indiana/Tell_City": (-6, True),
    "America/Denver": (-7, True), "America/Boise": (-7, True), "America/Phoenix": (-7, False),
    "America/Los_Angeles": (-8, True), "America/Anchorage": (-9, True), "America/Juneau": (-9, True),
    "America/Adak": (-10, True), "Pacific/Honolulu": (-10, False), "America/Puerto_Rico": (-4, False),
    "US/Eastern": (-5, True), "US/Central": (-6, True), "US/Mountain": (-7, True), "US/Pacific": (-8, True),
    "US/Arizona": (-7, False), "US/Alaska": (-9, True), "US/Hawaii": (-10, False),
    "America/Menominee": (-6, True), "America/North_Dakota/Center": (-6, True),
    "America/North_Dakota/New_Salem": (-6, True), "America/North_Dakota/Beulah": (-6, True),
    "America/Nome": (-9, True), "America/Sitka": (-9, True), "America/Yakutat": (-9, True),
    "America/Metlakatla": (-9, True), "America/Atka": (-10, True), "America/Louisville": (-5, True),
    "America/Fort_Wayne": (-5, True), "America/Indiana/Indianapolis": (-5, True), "America/Shiprock": (-7, True),
    "America/St_Thomas": (-4, False), "America/Virgin": (-4, False), "Pacific/Guam": (10, False),
    "Pacific/Saipan": (10, False), "Pacific/Pago_Pago": (-11, False), "Pacific/Samoa": (-11, False),
    "US/Samoa": (-11, False), "US/East-Indiana": (-5, True), "US/Indiana-Starke": (-6, True),
    "US/Michigan": (-5, True), "US/Aleutian": (-10, True),
    # POSIX-style names a Linux TZ variable or an old Windows box reports, and legacy aliases
    "EST5EDT": (-5, True), "CST6CDT": (-6, True), "MST7MDT": (-7, True), "PST8PDT": (-8, True),
    "EST": (-5, False), "MST": (-7, False), "HST": (-10, False), "America/Knox_IN": (-6, True),
    "Navajo": (-7, True), "Pacific/Midway": (-11, False), "Pacific/Wake": (12, False), "Pacific/Johnston": (-10, False),
}
_US_PREFIXES = ("America/Indiana/", "America/Kentucky/", "America/North_Dakota/", "US/")
_US_PREFIXES_LOWER = tuple(p.lower() for p in _US_PREFIXES)
_ETC_RE = re.compile(r"^Etc/GMT([+-])(\d{1,2})$")
# Standard offsets for non-US zones seen in participant data (no DST handling).
_OTHER = {
    "Africa/Nairobi": 3, "Africa/Lagos": 1, "Africa/Accra": 0, "Africa/Johannesburg": 2, "Africa/Cairo": 2,
    "Asia/Kolkata": 5.5, "Asia/Calcutta": 5.5, "Asia/Manila": 8, "Asia/Karachi": 5, "Asia/Dhaka": 6,
    "Asia/Kathmandu": 5.75, "Asia/Shanghai": 8, "Asia/Hong_Kong": 8, "Asia/Tokyo": 9, "Asia/Jakarta": 7,
    "Asia/Ho_Chi_Minh": 7, "Asia/Dubai": 4, "Asia/Istanbul": 3, "Europe/London": 0, "Europe/Paris": 1,
    "Europe/Berlin": 1, "Europe/Madrid": 1, "Europe/Kiev": 2, "Europe/Kyiv": 2, "Europe/Moscow": 3,
    "America/Caracas": -4, "America/Bogota": -5, "America/Lima": -5, "America/Mexico_City": -6,
    "America/Sao_Paulo": -3, "America/Argentina/Buenos_Aires": -3, "America/Toronto": -5,
    "America/Vancouver": -8, "Australia/Sydney": 10, "UTC": 0, "Etc/UTC": 0, "GMT": 0,
}
# zone names are matched without regard to case: a lower-cased "america/new_york" is still US
_CANON = {k.lower(): k for k in list(_US) + list(_OTHER)}


def canonical(name):
    return _CANON.get((name or "").lower(), name or "")


def is_us_zone(name):
    if not name:
        return False
    name = canonical(name)
    if name in _US or name.lower().startswith(_US_PREFIXES_LOWER):
        return True
    m = _ETC_RE.match(name)
    return bool(m) and m.group(1) == "+" and 4 <= int(m.group(2)) <= 10


def is_unknown(name):
    return not (is_us_zone(name) or name in _OTHER or _ETC_RE.match(name or ""))


def _nth_sunday(year, month, n):
    first = dt.date(year, month, 1)
    offset = (6 - first.weekday()) % 7
    return first + dt.timedelta(days=offset + 7 * (n - 1))


def _us_dst_active(ts_s, std_offset):
    local_std = dt.datetime.fromtimestamp(ts_s, dt.timezone.utc) + dt.timedelta(hours=std_offset)
    y = local_std.year
    start = dt.datetime.combine(_nth_sunday(y, 3, 2), dt.time(2))      # second Sunday of March, 02:00 standard
    end = dt.datetime.combine(_nth_sunday(y, 11, 1), dt.time(1))       # first Sunday of November, 02:00 DST = 01:00 standard
    return start <= local_std.replace(tzinfo=None) < end


def offset_hours(zone, ts_s):
    """UTC offset of zone at the instant ts_s (seconds), in hours."""
    zone = canonical(zone)
    if USE_ZONEINFO and ZoneInfo is not None:
        try:
            z = ZoneInfo(zone)
            off = dt.datetime.fromtimestamp(ts_s, z).utcoffset()
            return off.total_seconds() / 3600
        except (ZoneInfoNotFoundError, ValueError, KeyError, OSError):
            pass
    if zone in _US:
        std, dst = _US[zone]
        return std + (1 if dst and _us_dst_active(ts_s, std) else 0)
    if zone.lower().startswith(_US_PREFIXES_LOWER):   # the Indiana and Kentucky counties not listed above are Eastern
        std = -6 if zone.lower().startswith("america/north_dakota/") else -5
        return std + (1 if _us_dst_active(ts_s, std) else 0)
    m = _ETC_RE.match(zone or "")
    if m:  # Etc/GMT+6 means UTC-6
        return -int(m.group(2)) if m.group(1) == "+" else int(m.group(2))
    return _OTHER.get(zone, 0)


def local_hour(ts_s, zone):
    return int(((ts_s + offset_hours(zone, ts_s) * 3600) % 86400) // 3600)
