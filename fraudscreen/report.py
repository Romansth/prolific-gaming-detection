"""The markdown report (participants by signs, evidence, appendices) and the CSV."""
import csv
import re

from fraudscreen.signs import SIGNS, sign_by_id

# the team report carries real ids but never an address (the plan's "never e-mail addresses")
EMAIL_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}(?:@|%40)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")

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
    "In redacted mode page titles are absent (mail-identity and interface-language title checks are off), account age is known to the month, the antidetect launch page (M3) and the search patterns of m13 are tokenized away, foreign ids (M1, m2, m3), typed study links (m11) and study windows (m15) are seen only on allow-listed survey hosts (prolific, qualtrics, cloudresearch), and hosts visited by fewer than 5 participants appear as tokens.",
    "One folder is one run; nothing is remembered between runs.",
)


def participant_label(p):
    """'<pid> (<prefix>)': the id first, so a scrubbed report carries the same pid token as the
    redacted data; Chrome and Edge installs of one participant show as '(AIMECcplc/eplc)'."""
    prefixes = sorted(p["prefixes"])
    if len(prefixes) > 1:
        split = [(re.search(r"[ce]pl", x), x) for x in prefixes]
        if all(m for m, _ in split) and len({x[:m.start()] for m, x in split}) == 1:
            stem = split[0][1][:split[0][0].start()]
            label = stem + "/".join(x[m.start():] for m, x in split)
        else:
            label = "/".join(prefixes)
    else:
        label = prefixes[0] if prefixes else "?"
    return f"{p['key']} ({label})"


def _counts(results):
    major = sum(1 for s in SIGNS if s.tier == "major" and results[s.id].fired)
    minor = sum(1 for s in SIGNS if s.tier == "minor" and results[s.id].fired)
    return major, minor


def _cell(r):
    if not r.available:
        return "n/a"
    if not r.fired:
        return ""
    return "✓" if r.count <= 1 else f"✓{r.count}"


def listed(results_by_key, participants):
    rows = []
    for p in participants:
        res = results_by_key.get(p["key"])
        if not res:
            continue
        major, minor = _counts(res)
        if major + minor == 0:
            continue
        rows.append((major, minor, p, res))
    rows.sort(key=lambda r: (-r[0], -r[1], r[2]["key"]))
    return rows


def render_markdown(results_by_key, participants, fleet, meta):
    rows = listed(results_by_key, participants)
    out = []
    out.append(f"# Participant screen: {meta.get('folder', '')}")
    out.append("")
    out.append(f"Mode: {meta.get('mode', '')}. Files: {meta.get('files', 0)}. Unreadable files: {meta.get('unreadable', 0)}. "
               f"Installs: {meta.get('installs', 0)}. "
               f"Participants screened: {meta.get('participants', 0)} (skipped: {_skipped(meta.get('skipped'))}). "
               f"Dates: {meta.get('date_range', '')}. Tool version {meta.get('version', '')}, run time {meta.get('seconds', 0):.0f} s.")
    out.append("")
    out.append(f"{len(rows)} participants carry at least one sign. A participant with no sign is not listed. "
               "Major signs are the proof bar; minor signs are support. Every tick has its evidence below; every sign has a fixed innocent reading.")
    out.append("")
    out.append("Legend: " + "; ".join(f"{s.id} {s.title}" for s in SIGNS))
    out.append("")
    head = ["Participant", "Study", "Arm", "Major"] + [s.id for s in SIGNS] + ["Linked to"]
    out.append("| " + " | ".join(head) + " |")
    out.append("|" + "|".join(["---"] * len(head)) + "|")
    for major, minor, p, res in rows:
        linked = sorted({k for s in SIGNS for k in res[s.id].linked})
        cells = [participant_label(p), p.get("study", ""), p.get("arm", ""), str(major)] + [_cell(res[s.id]) for s in SIGNS] + [", ".join(linked)]
        out.append("| " + " | ".join(cells) + " |")
    out.append("")
    out.append("## Evidence")
    for major, minor, p, res in rows:
        out.append("")
        out.append(f"### {participant_label(p)}")
        for s in SIGNS:
            r = res[s.id]
            if not r.fired:
                continue
            out.append("")
            out.append(f"**{s.id} {s.title}**")
            out.append(f"Rule: {s.rule}")
            for e in r.evidence:
                out.append(f"- {e.when} · {e.what} · {e.file}".replace(" ·  · ", " · ").rstrip(" ·"))
            out.append(f"Count: {r.count}")
            for n in r.notes:
                out.append(n)
            if r.linked:
                out.append("Linked to: " + ", ".join(r.linked))
            out.append(f"Innocent reading: {s.innocent}")
    out.append("")
    out.append("## Appendix A: signs and counts")
    out.append("")
    out.append("| Sign | Tier | Title | Rule | Participants fired / screened |")
    out.append("|---|---|---|---|---|")
    n_screened = meta.get("participants", len(participants))
    for s in SIGNS:
        fired = sum(1 for res in results_by_key.values() if res[s.id].fired)
        avail = sum(1 for res in results_by_key.values() if res[s.id].available)
        extra = "" if avail == len(results_by_key) else f" (not available for {len(results_by_key) - avail})"
        out.append(f"| {s.id} | {s.tier} | {s.title} | {s.rule} | {fired} / {n_screened}{extra} |")
    out.append("")
    out.append("## Appendix B: excluded signals")
    out.append("")
    for name, why in EXCLUDED_SIGNALS:
        out.append(f"- {name}: {why}.")
    out.append("")
    out.append("## Appendix C: limitations")
    out.append("")
    for line in LIMITATIONS:
        out.append(f"- {line}")
    out.append("")
    return EMAIL_RE.sub("[email]", "\n".join(out))


def _skipped(sk):
    if not sk:
        return "none"
    return ", ".join(f"{k} {v}" for k, v in sorted(dict(sk).items()))


def write_csv(path, results_by_key, participants):
    rows = []
    for p in participants:
        res = results_by_key.get(p["key"])
        if not res:
            continue
        major, minor = _counts(res)
        row = {"participant": participant_label(p), "study": p.get("study", ""), "arm": p.get("arm", ""),
               "major_count": major, "minor_count": minor}
        for s in SIGNS:
            row[f"{s.id}_fired"] = int(res[s.id].fired)
            row[f"{s.id}_count"] = res[s.id].count
        row["linked"] = ";".join(sorted({k for s in SIGNS for k in res[s.id].linked}))
        rows.append((major, minor, row))
    rows.sort(key=lambda r: (-r[0], -r[1], r[2]["participant"]))
    fields = ["participant", "study", "arm", "major_count", "minor_count"] + [f"{s.id}_{k}" for s in SIGNS for k in ("fired", "count")] + ["linked"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for _, _, row in rows:
            w.writerow(row)
