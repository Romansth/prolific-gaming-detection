"""The report: a data model of flagged participants (strong signs with their headlines and
evidence, supporting signs as context), its self-contained HTML rendering, and the CSV that keeps
every participant and every sign. The token-only copy is rendered from a scrubbed model
(fraudscreen.scrub.scrub_model); finished HTML is never scrubbed, its escaped URLs would not
parse."""
import csv
import html
import re
from collections import Counter

from fraudscreen.signs import SIGNS, n_of

# both copies of the report mask e-mail addresses; the team copy keeps real ids and URLs
EMAIL_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}(?:@|%40)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")

STRONG = [s for s in SIGNS if s.tier == "major"]
SUPPORT = [s for s in SIGNS if s.tier == "minor"]

INTRO = ("A participant is flagged when at least one strong pattern was seen: a pattern where, in our judgment, gaming is "
         "more likely than not. Each flagged participant lists what was seen, the evidence behind it, and the ordinary "
         "explanation that would also produce it; someone has to look at the evidence and decide. Weaker, supporting patterns "
         "are shown under a flagged participant for context only. They never flag anyone on their own.")

EXCLUDED_SIGNALS = (
    ("Completion-code reuse", "every popular study hands out one code; 5,371 of 11,329 codes were shared in the audit pull"),
    ("Same-minute activity between participants", "two full-time workers overlap by nature; only pairs corroborated by other signs mean anything"),
    ("Number of Google accounts", "two thirds of installs have two or more"),
    ("Gift-card and cash-out sites", "how survey workers cash rewards"),
    ("Submissions per day", "fleet median 7 per active day, 99th percentile 33"),
    ("VPN marketing pages", "visiting a vendor site is not a subscription; account pages count under m4"),
    ("Resident-service hosts", "every foreign bank, telecom or government hit in the audit was a Google sign-in already counted, adware, or streaming"),
)
LIMITATIONS = (
    "No IP address exists in the data. Location rests on the device clock (a setting) and on Google's choice of a country-specific sign-in domain, which only occurs during Google sign-ins. A US clock plus a stable US VPN exit leaves no trace.",
    "A second Prolific account shows only when it is used in a browser profile the extension is installed in.",
    "Hardware keys discriminate on Windows and Linux (exact byte counts); stock Macs and Chromebooks collide and are not used for the shared-hardware sign.",
    "In redacted mode page titles are absent (mail-identity and interface-language title checks are off), account age is known to the month and the batch rule of m6 is off, the antidetect launch page (M3) and the search patterns of m13 are tokenized away, foreign ids (M1, m2, m3) are seen on allow-listed survey hosts (prolific, qualtrics, cloudresearch) and on any other host only when the id belongs to an enrolled participant, typed study links (m11) and study windows (m15) are seen only on the allow-listed hosts, and hosts visited by fewer than 5 participants appear as tokens.",
    "The fleet percentiles behind m8, m11 and m15 need at least 20 participants with enough visits; below that the fixed floors (20 %, 80 %, 30 %) alone apply.",
    "One folder is one run; nothing is remembered between runs.",
)


def participant_label(p):
    """'<pid> (<prefix>)': the id first, so a scrubbed report carries the same pid token as the
    redacted data; Chrome and Edge installs of one participant show as '(AIMECcplc/AIMECeplc)',
    each prefix in full so the scrub's whole-word rare-prefix rule can hide one of them."""
    prefixes = sorted(p["prefixes"])
    label = "/".join(prefixes) if prefixes else "?"
    return f"{p['key']} ({label})"


def _counts(results):
    major = sum(1 for s in SIGNS if s.tier == "major" and results[s.id].fired)
    minor = sum(1 for s in SIGNS if s.tier == "minor" and results[s.id].fired)
    return major, minor


def line_for(r, sign):
    """The one sentence a reader gets for a fired sign: the module's headline, else its first
    note, else its first evidence line, else the title."""
    if r.headline:
        return r.headline
    if r.notes:
        return r.notes[0]
    if r.evidence:
        return r.evidence[0].what
    return sign.title


def _mask(obj):
    if isinstance(obj, str):
        return EMAIL_RE.sub("[email]", obj)
    if isinstance(obj, list):
        return [_mask(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _mask(v) for k, v in obj.items()}
    return obj


def _skipped(sk):
    if not sk:
        return "none"
    return ", ".join(f"{k} {v}" for k, v in sorted(dict(sk).items()))


def run_line(meta):
    return (f"Mode: {meta.get('mode', '')}. Files: {meta.get('files', 0)}. Unreadable files: {meta.get('unreadable', 0)}. "
            f"Files not read: {_skipped(meta.get('skipped_files'))}. Visits without a time: {meta.get('no_time', 0)}. "
            f"Installs: {meta.get('installs', 0)}. "
            f"Participants screened: {meta.get('participants', 0)} (skipped: {_skipped(meta.get('skipped'))}). "
            f"Dates: {meta.get('date_range', '')}. Tool version {meta.get('version', '')}, run time {meta.get('seconds', 0):.0f} s.")


def _warnings(meta):
    """Lines for the banner when the pull looks half-read: any file not read or not parsed, more
    than 5 % of visits without a time, more than 10 % of participants without a device record."""
    out = []
    # junk entries (AppleDouble shadows, __MACOSX members) carry no data: a Mac-zipped pull is healthy
    sk = {k: v for k, v in (meta.get("skipped_files") or {}).items() if k != "junk"}
    if sk:
        out.append(f"{n_of(sum(sk.values()), 'file')} not read ({_skipped(sk)}): the screen never saw them; check what they are "
                   "and re-export the identifiers they belong to.")
    n_bad = meta.get("unreadable") or 0
    if n_bad:
        out.append(f"{n_of(n_bad, 'file')} truncated or not valid JSON: re-export {'it' if n_bad == 1 else 'them'}.")
    visits, no_time = meta.get("visits"), meta.get("no_time") or 0
    if visits is not None and visits + no_time and no_time / (visits + no_time) > 0.05:
        out.append(f"{no_time / (visits + no_time):.0%} of visits carry no time and were dropped; the timing checks ran on the rest.")
    n, no_status = meta.get("participants") or 0, meta.get("no_status") or 0
    if n and no_status / n > 0.10:
        out.append(f"{no_status} of {n} participants have no device records, so the hardware, clock and running-browser "
                   "checks could not run for them.")
    return out


def build_model(results_by_key, participants, fleet, meta):
    """Plain data (str, int, float, bool, None, list, dict) for render_html and scrub_model: the
    flagged participants (at least one strong sign) as cards, the support-only participants as a
    short table, the catalogue with counts, and the fixed appendix text. E-mail addresses are
    masked here so neither copy carries one."""
    flagged, support_only, n_clean = [], [], 0
    for p in participants:
        res = results_by_key.get(p["key"])
        if not res:
            continue
        major, minor = _counts(res)
        if major:
            flagged.append((p, res, major))
        elif minor:
            support_only.append((p, res, minor))
        else:
            n_clean += 1
    flagged_keys = {p["key"] for p, _, _ in flagged}
    cards = []
    for p, res, major in flagged:
        strong = [dict(id=s.id, title=s.title, headline=line_for(res[s.id], s), innocent=s.innocent, rule=s.rule,
                       evidence=[[e.when, e.what, e.file] for e in res[s.id].evidence], count=res[s.id].count, rows=res[s.id].rows,
                       notes=list(res[s.id].notes), linked=list(res[s.id].linked)) for s in STRONG if res[s.id].fired]
        support = [dict(id=s.id, title=s.title, line=line_for(res[s.id], s), linked=list(res[s.id].linked))
                   for s in SUPPORT if res[s.id].fired]
        linked = sorted({k for s in SIGNS for k in res[s.id].linked})
        # connected flagged participants sort next to each other: the group is the smallest key among them
        group = min([p["key"]] + [k for s in STRONG for k in res[s.id].linked if k in flagged_keys])
        cards.append((group, dict(key=p["key"], label=participant_label(p), study=p.get("study", ""), arm=p.get("arm", ""),
                                  browsers=sorted(p.get("browsers", ())), n_strong=major, strong=strong, support=support,
                                  linked=linked)))
    cards.sort(key=lambda g: (-g[1]["n_strong"], g[0], g[1]["key"]))
    support_only.sort(key=lambda t: (-t[2], t[0]["key"]))
    rows = [dict(key=p["key"], label=participant_label(p), study=p.get("study", ""), arm=p.get("arm", ""),
                 patterns=[s.title for s in SUPPORT if res[s.id].fired]) for p, res, _ in support_only]
    n_screened = meta.get("participants", len(participants))
    studies = Counter((c["study"] or "?") for _, c in cards)   # cards only: the chips sit under the flagged heading
    catalogue = []
    for s in SIGNS:
        fired = sum(1 for res in results_by_key.values() if res[s.id].fired)
        missing = sum(1 for res in results_by_key.values() if not res[s.id].available)
        catalogue.append(dict(id=s.id, tier="strong" if s.tier == "major" else "supporting", title=s.title, rule=s.rule,
                              innocent=s.innocent, fired=fired, screened=n_screened, missing=missing))
    model = dict(title=f"Participant screen: {meta.get('folder', '')}", folder=meta.get("folder", ""), mode=meta.get("mode", ""),
                 ids="tokens" if meta.get("mode") == "redacted" else "real",
                 run_line=run_line(meta), n_screened=n_screened, n_flagged=len(cards), n_support_only=len(rows), n_clean=n_clean,
                 intro=INTRO, flagged=[c for _, c in cards], support_only=rows, catalogue=catalogue,
                 excluded=[list(x) for x in EXCLUDED_SIGNALS], limitations=list(LIMITATIONS),
                 version=str(meta.get("version", "")), seconds=float(meta.get("seconds", 0) or 0),
                 run_date=str(meta.get("run_date", "")), warnings=_warnings(meta),
                 studies=[[k, n] for k, n in sorted(studies.items())])
    return _mask(model)


CSS = """
:root{--bg:#fff;--fg:#1c1e21;--muted:#5f6368;--line:#dadce0;--card:#f8f9fa;--code:#eef0f2;--link:#0b57d0;
--strong-bg:#fdecec;--strong-fg:#8a1c1c;--strong-line:#f1b8b8;--sup-bg:#eceff1;--sup-fg:#3c4043;--sup-line:#cfd4d9;--btn:#f1f3f4}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e8eaed;--muted:#9aa0a6;--line:#30353b;--card:#1a1d21;--code:#23272c;
--link:#8ab4f8;--strong-bg:#3a1c1c;--strong-fg:#ffb4b4;--strong-line:#6e2b2b;--sup-bg:#262a2f;--sup-fg:#c8ccd1;--sup-line:#3b4047;--btn:#2a2e33}}
*{box-sizing:border-box}
body{margin:0;padding:24px 16px 48px;background:var(--bg);color:var(--fg);font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header,section,article,footer,p.intro{max-width:1100px;margin-left:auto;margin-right:auto}
h1{font-size:26px;margin:0 0 6px}h2{font-size:20px;margin:28px 0 10px}h3{font-size:16px;margin:16px 0 6px}
code{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:1px 4px;border-radius:4px;word-break:break-all}
a{color:var(--link)}
.lead{font-size:17px;margin:0 0 6px}.meta{color:var(--muted);font-size:13px;margin:4px 0}.intro{margin:14px auto 6px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}
th{font-weight:600;color:var(--muted);font-size:13px}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:13px;border:1px solid;margin:1px 2px 1px 0}
.chip.strong{background:var(--strong-bg);color:var(--strong-fg);border-color:var(--strong-line)}
.chip.support{background:var(--sup-bg);color:var(--sup-fg);border-color:var(--sup-line)}
.code{color:var(--muted);font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:16px auto}
.card h2{margin:0 0 2px;font-size:18px}.cohort{color:var(--muted);font-weight:400;font-size:15px}
.finding{border-left:3px solid var(--strong-line);padding-left:12px;margin:14px 0}
.headline{font-weight:600;margin:4px 0 8px}
.evidence{font-size:13px}.evidence .when{white-space:nowrap}.evidence .what{word-break:break-all}.evidence .file{color:var(--muted);font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
.innocent{color:var(--muted);margin:8px 0 4px}.rule{color:var(--muted);font-size:13px}
details{margin:6px 0}summary{cursor:pointer;color:var(--muted);font-size:14px}details[open]>summary{margin-bottom:6px}
.support h3{color:var(--muted);font-weight:600}.hint{font-weight:400}.support ul{margin:4px 0;padding-left:20px}.support li{margin:3px 0;font-size:14px;color:var(--muted)}
.links{margin:10px 0 0}.tools{margin:6px 0 10px}button{font:13px inherit;padding:4px 10px;border:1px solid var(--line);border-radius:6px;background:var(--btn);color:var(--fg);cursor:pointer}
.none{padding:12px;border:1px dashed var(--line);border-radius:8px}
.banner{background:#fff4d6;border:1px solid #e6c77a;color:#5b4300;border-radius:8px;padding:10px 14px;margin:12px auto;max-width:1100px}
.banner ul{margin:6px 0 0;padding-left:20px}
@media (prefers-color-scheme:dark){.banner{background:#3a2f12;border-color:#7a6224;color:#f3dfa3}}
.summary{margin:0 0 8px}.summary .chip b{font-weight:700;margin-left:2px}
.chip.study{cursor:pointer;background:var(--btn);color:var(--fg);border-color:var(--line);font:inherit;font-size:13px}
.chip.study.on{background:var(--link);color:#fff;border-color:var(--link)}
.scroll{overflow-x:auto}
body:not(.files) .evidence .file{display:none}
.copy{margin-left:8px;font-size:12px;padding:2px 8px;vertical-align:middle}
.top{margin:10px 0 0;font-size:13px}
.tools label{margin-left:12px;font-size:14px;color:var(--muted)}
footer{margin-top:28px}
@media print{.tools{display:none}.card{break-inside:avoid}body{padding:0}}
"""
JS = """function toggleAll(o){document.querySelectorAll('details').forEach(function(d){d.open=o;});}
function filterStudy(b){var s=b.dataset.filter;document.querySelectorAll('[data-study]').forEach(function(x){x.hidden=!!s&&x.dataset.study!==s;});
document.querySelectorAll('.chip.study').forEach(function(c){c.classList.toggle('on',c.dataset.filter===s);});}
function copyId(b){var reset=function(ms){setTimeout(function(){b.textContent='Copy id';},ms);};
var done=function(){b.textContent='Copied';reset(1200);};var fail=function(){b.textContent='Select the id';reset(1600);};
if(!navigator.clipboard){fail();return;}navigator.clipboard.writeText(b.dataset.copy).then(done,fail);}
function showFiles(c){document.body.classList.toggle('files',c.checked);}"""


def _e(s):
    return html.escape(str(s), quote=True)


def render_html(model):
    """One self-contained page: no external resource, every string escaped."""
    e = _e
    out = []
    w = out.append
    flagged_keys = {c["key"] for c in model["flagged"]}

    def ref(k):   # a link when the participant has a card, plain text otherwise
        return f'<a href="#p-{e(k)}"><code>{e(k)}</code></a>' if k in flagged_keys else f"<code>{e(k)}</code>"

    def linkify(text):   # escaped text with every flagged id turned into a link to its card
        h = e(text)
        for k in flagged_keys:
            if e(k) in h:
                h = h.replace(e(k), ref(k))
        return h

    w("<!doctype html>")
    w('<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    w(f"<title>{e(model['title'])}</title><style>{CSS}</style></head><body>")
    ids_note = ("real Prolific ids: for the research team only" if model["ids"] == "real"
                else "tokens: safe to share and to discuss with an agent")
    w(f"<header><h1>{e(model['title'])}</h1>")
    run = f' Run on {e(model["run_date"])}.' if model.get("run_date") else ""
    w(f'<p class="lead">{model["n_screened"]} participants screened, <strong>{model["n_flagged"]} flagged</strong>. '
      f'Ids on this page are {ids_note}.{run}</p>')
    w(f'<p class="meta">{e(model["run_line"])}</p></header>')
    if model.get("warnings"):
        w('<div class="banner"><strong>Check this pull before trusting the page.</strong><ul>'
          + "".join(f"<li>{e(x)}</li>" for x in model["warnings"]) + "</ul></div>")
    w(f'<p class="intro">{e(model["intro"])}</p>')
    w(f'<section id="overview"><h2>Flagged participants ({model["n_flagged"]})</h2>')
    if model["flagged"]:
        counts = [(s["title"], s["fired"]) for s in model["catalogue"] if s["tier"] == "strong" and s["fired"]]
        w('<p class="summary">' + " ".join(f'<span class="chip strong">{e(t)} <b>{n}</b></span>' for t, n in counts) + "</p>")
        w('<p class="tools"><button type="button" onclick="toggleAll(true)">Expand all details</button> '
          '<button type="button" onclick="toggleAll(false)">Collapse all</button>'
          '<label><input type="checkbox" id="showfiles" onchange="showFiles(this)" autocomplete="off"> Show source files</label></p>')
        studies = model.get("studies") or []
        if len(studies) > 1:
            total = sum(n for _, n in studies)
            w('<p class="studies"><button type="button" class="chip study on" onclick="filterStudy(this)" data-filter="">'
              f'All ({total})</button> ' + " ".join(f'<button type="button" class="chip study" onclick="filterStudy(this)" '
                                                   f'data-filter="{e(k)}">{e(k)} ({n})</button>' for k, n in studies) + "</p>")
        w('<div class="scroll"><table class="overview"><thead><tr><th>Participant</th><th>Study</th><th>Arm</th>'
          '<th>Strong patterns seen</th><th>Connected to</th></tr></thead><tbody>')
        for c in model["flagged"]:
            chips = " ".join(f'<span class="chip strong">{e(s["title"])}</span>' for s in c["strong"])
            links = ", ".join(ref(k) for k in c["linked"])
            w(f'<tr data-study="{e(c["study"] or "?")}"><td><a href="#p-{e(c["key"])}"><code>{e(c["label"])}</code></a></td>'
              f'<td>{e(c["study"])}</td><td>{e(c["arm"])}</td><td>{chips}</td><td>{links}</td></tr>')
        w("</tbody></table></div>")
    else:
        w('<p class="none">No participant is flagged in this pull: no strong pattern was seen.</p>')
    w("</section>")
    for c in model["flagged"]:
        w(f'<article class="card" id="p-{e(c["key"])}" data-study="{e(c["study"] or "?")}">')
        cohort = c["label"][len(c["key"]):].strip()
        w(f'<h2><code>{e(c["key"])}</code> <span class="cohort">{e(cohort)}</span> '
          f'<button type="button" class="copy" data-copy="{e(c["key"])}" onclick="copyId(this)">Copy id</button></h2>')
        bits = [f"Study {c['study']}" if c["study"] else "", f"Arm {c['arm']}" if c["arm"] else "",
                ", ".join(c["browsers"]), n_of(c["n_strong"], "strong pattern")]
        w(f'<p class="meta">{e(" · ".join(b for b in bits if b))}</p>')
        for s in c["strong"]:
            w('<div class="finding">')
            w(f'<h3>{e(s["title"])} <span class="code">{e(s["id"])}</span></h3>')
            w(f'<p class="headline">{linkify(s["headline"])}</p>')
            if s["evidence"]:
                w('<div class="scroll"><table class="evidence"><thead><tr><th>When (UTC)</th><th>What was seen</th>'
                  '<th class="file">Source file</th></tr></thead><tbody>')
                for when, what, file in s["evidence"]:
                    w(f'<tr><td class="when">{e(when)}</td><td class="what">{e(what)}</td><td class="file">{e(file)}</td></tr>')
                w("</tbody></table></div>")
                if s["rows"] > len(s["evidence"]):   # rows, not count: M5 counts minutes, M3 sessions
                    w(f'<p class="meta">{s["rows"]} in total; the first {len(s["evidence"])} are shown.</p>')
            w(f'<p class="innocent">Also explained by: {e(s["innocent"])}</p>')
            w("<details><summary>Rule and notes</summary>")
            w(f'<p class="rule">{e(s["rule"])}</p>')
            if s["notes"]:
                w("<ul>" + "".join(f"<li>{e(n)}</li>" for n in s["notes"]) + "</ul>")
            w("</details></div>")
        if c["support"]:
            w('<div class="support"><h3>Supporting patterns <span class="hint">(context only; they do not flag on their own)</span></h3><ul>')
            for s in c["support"]:
                extra = (" · with " + ", ".join(ref(k) for k in s["linked"])) if s["linked"] else ""
                w(f'<li><span class="chip support">{e(s["title"])}</span> <span class="code">{e(s["id"])}</span> {e(s["line"])}{extra}</li>')
            w("</ul></div>")
        if c["linked"]:
            w('<p class="links">Connected to: ' + ", ".join(ref(k) for k in c["linked"]) + "</p>")
        w('<p class="top"><a href="#overview">Back to overview</a></p>')
        w("</article>")
    w('<section id="rest">')
    if model["support_only"]:
        n = model["n_support_only"]
        w(f'<details><summary>{n_of(n, "participant")} showed only supporting patterns and {"is" if n == 1 else "are"} not flagged</summary>')
        w('<p class="meta">Supporting patterns have an ordinary explanation more often than not. The CSV beside this report '
          'carries every participant and every pattern.</p>')
        w('<div class="scroll"><table class="rest"><thead><tr><th>Participant</th><th>Study</th><th>Arm</th><th>Supporting patterns</th></tr></thead><tbody>')
        for r in model["support_only"]:
            w(f'<tr data-study="{e(r["study"] or "?")}"><td><code>{e(r["label"])}</code></td><td>{e(r["study"])}</td><td>{e(r["arm"])}</td>'
              f'<td>{e("; ".join(r["patterns"]))}</td></tr>')
        w("</tbody></table></div></details>")
    w(f'<p class="meta">{n_of(model["n_clean"], "participant")} showed nothing.</p></section>')
    w('<section id="appendix"><details><summary>Appendix: every pattern checked, excluded signals, limitations</summary>')
    w('<div class="scroll"><table class="catalogue"><thead><tr><th>Code</th><th>Strength</th><th>Pattern</th><th>Rule</th><th>Fired / screened</th></tr></thead><tbody>')
    for s in model["catalogue"]:
        extra = f' (not available for {s["missing"]})' if s["missing"] else ""
        w(f'<tr><td><span class="code">{e(s["id"])}</span></td><td>{e(s["tier"])}</td>'
          f'<td>{e(s["title"])}<br><span class="innocent">Also explained by: {e(s["innocent"])}</span></td>'
          f'<td class="rule">{e(s["rule"])}</td><td>{s["fired"]} / {s["screened"]}{e(extra)}</td></tr>')
    w("</tbody></table></div>")
    w("<h3>Signals deliberately excluded</h3><ul>" + "".join(f"<li><strong>{e(n)}</strong>: {e(why)}.</li>" for n, why in model["excluded"]) + "</ul>")
    w("<h3>Limitations</h3><ul>" + "".join(f"<li>{e(x)}</li>" for x in model["limitations"]) + "</ul>")
    w("</details></section>")
    w(f'<footer class="meta">fraudscreen {e(model["version"])}, run time {model["seconds"]:.0f} s.</footer>')
    w(f"<script>{JS}</script></body></html>")
    return "\n".join(out)


def write_csv(path, results_by_key, participants):
    rows = []
    for p in participants:
        res = results_by_key.get(p["key"])
        if not res:
            continue
        major, minor = _counts(res)
        row = {"participant": participant_label(p), "study": p.get("study", ""), "arm": p.get("arm", ""),
               "flagged": int(major > 0), "major_count": major, "minor_count": minor}
        for s in SIGNS:
            row[f"{s.id}_fired"] = int(res[s.id].fired)
            row[f"{s.id}_count"] = res[s.id].count
        row["linked"] = ";".join(sorted({k for s in SIGNS for k in res[s.id].linked}))
        rows.append((major, minor, row))
    rows.sort(key=lambda r: (-r[0], -r[1], r[2]["participant"]))
    fields = ["participant", "study", "arm", "flagged", "major_count", "minor_count"] + [f"{s.id}_{k}" for s in SIGNS for k in ("fired", "count")] + ["linked"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for _, _, row in rows:
            w.writerow(row)
