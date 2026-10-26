# HTML report for the participant screen

Design note, 2026-10-26. Replaces the markdown report. Written after the team said the
markdown version was unreadable: a 23-column grid of sign codes (`M1`, `m8`), a `✓n` count
whose unit differs from column to column, and a list that mixes strong findings with weak ones
nobody has time to review.

## What the report is for

Someone on the research team opens it, sees who is flagged, checks the evidence for each
flagged participant, and decides. Sixty seconds per participant. They have not read the sign
catalogue and will not.

## Decisions

1. **Flagged means at least one strong pattern.** The catalogue already splits the 23 signs into
   six major signs (the "proof bar") and seventeen minor ones (support). The major tier is the
   set where gaming is more likely than not: a second Prolific id used locally, two enrolled
   participants in one running browser, an antidetect launch page, sign-ins routed outside the
   US on two days a week apart, a non-US clock on seven days or half the observations, a
   non-US Chrome install locale. Minor signs never flag anyone. They appear only as supporting
   context under a flagged participant, and as a count (with a collapsed table) for the rest.
   Tiers are not changed by this work. Two minors sit close to the line and the team may want to
   promote them: `m12` (same mail identity under two ids, raw data only) and `m2` (a foreign
   Prolific id synced in from another device of the same Google account). A promotion is a
   one-word change in `fraudscreen/signs/__init__.py`.
2. **No sign codes as vocabulary.** Every pattern is named by its title ("Device clock outside
   the US, persistently"). The code appears once, small, after the title, so the appendix and
   the CSV columns can be cross-referenced.
3. **One sentence per finding, in the unit that fits.** Each strong pattern gets a headline
   written by the module that computed it: "Clock set to Africa/Nairobi on 8 days, 100% of 18
   observation minutes", "Google sign-ins routed through google.co.ke on 2 days (2026-09-14,
   2026-09-22)", "Chrome installed with a VE locale". The `✓n` grid is gone. The count stays in
   the CSV.
4. **Self-contained HTML.** One file, no network requests, system fonts, light and dark, works
   from a double-click. Collapsible sections (`<details>`) for the technical notes, the
   not-flagged list and the appendix; two buttons expand or collapse everything for printing.
5. **Scrub the data, not the HTML.** The token-only copy is produced by scrubbing the report's
   data model (every string, one per line) with the redactor's rules and rendering the HTML a
   second time. Scrubbing finished HTML would feed `&amp;`-escaped URLs to the URL rule. The
   CSV is still scrubbed as text.
6. **The CSV keeps every participant and every sign**, plus a `flagged` column, so anyone who
   wants the full grid has it.

## Page layout

1. Title "Participant screen: <pull>". One line: participants screened, flagged, whether the ids
   on the page are real or tokens, run date. One small line with the run details the tests check (mode, files,
   unreadable, not read, visits without a time, installs, skipped, dates, version, run time).
2. Three sentences on how to read the page (strong = more likely than not; evidence and the
   ordinary explanation are listed; supporting patterns never flag on their own).
3. Overview table of flagged participants: participant (id and cohort label, linking to the
   card), study, arm, patterns seen (one chip per strong pattern), connected to (links to other
   cards). Sorted by number of strong patterns, then so that connected participants sit together,
   then by id.
4. One card per flagged participant, anchored `p-<id>`. Header: id, cohort label, study, arm,
   browsers. Per strong pattern: title and code, headline, evidence table (time, detail, source
   file), "Also explained by: <innocent reading>", a collapsed "Rule and notes" with the rule and
   the technical notes. Then "Supporting patterns (do not flag on their own)": one muted line per
   fired minor sign (title, code, its headline or first note). Then "Connected to" links.
5. Collapsed: "N participants showed only supporting patterns and are not flagged", with a
   table (participant, study, patterns) and a pointer to the CSV. One line for the count with
   nothing seen.
6. Collapsed appendix: every pattern checked (code, strength, title, rule, fired / screened,
   not-available count), excluded signals, limitations.

## Pieces

- `SignResult.headline` (new field, default ""). Set by the modules for M1, M2, M3, M4, M5, M6
  and, because they share code paths, m2, m16, m17. m1, m4 and m8 get one too; other minors fall back to
  their first note or first evidence line (`report.line_for`).
- `fraudscreen/report.py`: `build_model(results, participants, fleet, meta) -> dict` (plain
  strings, ints, lists; e-mail addresses already masked), `render_html(model) -> str`,
  `write_csv` with the `flagged` column. `render_markdown` is removed.
- `fraudscreen/scrub.py`: `scrub_model(model, key_dir, **kw) -> dict`: joins every string leaf on
  its own line, runs `scrub_text`, splits, puts the strings back; refuses (raises) when the line
  count changed. `leaks(model, source_model)` runs the redactor's independent leak scanner over
  the scrubbed model; the CLI refuses to write the token-only page on any hit.
- `fraudscreen/__main__.py`: report paths end in `.html`; the token-only report is
  `render_html(scrub_model(model))`.
- Docs: README "Run" and "Reading the report", the two agent instruction files, `.gitignore`.
- Version 0.2.0 (round 1); 0.3.0 after round 2.

## Not in scope

No sign rule or threshold changes. No change to the redactor. No change to the CSV columns
other than adding `flagged`.

## Round 2 (2026-10-26, same day): ease of use

Calls made in chat, built under `docs/superpowers/plans/2026-10-26-report-usability.md`:

- `./screen.sh` alone picks the newest folder in the pull folder by modification time, runs with
  `--redact` and opens the team page; `--open` does the opening after an explicit run. Inside an
  agent session the zero-argument run resolves to the raw folder and is refused as before.
- A banner above the intro fires on any file not read or truncated, on more than 5 % of visits
  without a time, and on more than 10 % of participants without device records; each line says
  what to re-export.
- Study chips appear only when a pull has more than one study and filter the overview, the cards
  and the support-only table together.
- Reading aids: a per-pattern count line under the flagged heading, "Copy id" on each card, the
  other participant's id in a headline linked to their card, the source-file column behind a
  "Show source files" checkbox, "Back to overview" on each card, tables that scroll sideways on
  narrow screens.
