# Report design

The screen writes one HTML page per pull. A participant is flagged only when a strong pattern
fired; every weaker pattern is context. This note records why, what a reviewer sees, how the
token-only copy is made, and what the first real pull should settle.

## Who is flagged

A participant is flagged when at least one of the six major signs fired. The catalogue in
`fraudscreen/signs/__init__.py` splits the 23 signs into 6 major and 17 minor. The major six are
the ones where gaming is more likely than not:

| Code | Pattern |
|---|---|
| M1 | A second Prolific id used in the monitored browser |
| M2 | Two enrolled participants in one running browser |
| M3 | An antidetect browser launch page |
| M4 | Google sign-ins routed outside the US on two days at least a week apart |
| M5 | A non-US device clock on 7 or more days, or on half the observation minutes |
| M6 | Chrome installed with a non-US locale |

A minor sign never flags anyone on its own. Each one has a common ordinary reading (a shared
household PC, a night shift, a trip abroad), so seventeen kinds of weak support would cost review
time without changing many decisions. Minor signs appear under a flagged participant as context,
and participants with minor signs only are listed in a collapsed table. The CSV keeps every sign
for every participant.

On the synthetic test pull this lists 10 of 42 participants. Listing everyone with any sign gave 29.

Two minor signs sit close to the line and may deserve to flag:

- **m12**: the same mail address or display name under two Prolific ids (raw data only).
- **m2**: another participant's Prolific id synced into this browser profile from another device
  signed in to the same Google account.

Promoting either one means changing its tier from `minor` to `major` in the catalogue. The report
and the CSV follow without other changes.

## What a reviewer sees

The overview table lists the flagged participants with their study, arm, strong patterns and the
participants they are connected to. Rows are sorted by the number of strong patterns, with linked
participants next to each other.

Each flagged participant gets a card. For every strong pattern the card gives:

1. The pattern's name, with its code in small type for cross-reference with the CSV.
2. One sentence with the specifics, written by the check that found it, in the unit that fits:
   "Device clock set to Africa/Nairobi on 10 days, 100% of 18 observation minutes", or "In the
   same running browser as <id>: 1 browser id reported by both within a minute".
3. Up to five evidence rows: UTC time, what was seen, and (behind a checkbox) the source file.
4. The ordinary explanation that would produce the same evidence.
5. A collapsed block with the exact rule and the technical notes.

Supporting patterns that also fired follow as one line each. A yellow box at the top of the page
appears when the pull looks half-read: any archive that did not open or file name that did not
parse, any truncated file, more than 5% of visits without a time, or more than 10% of
participants without device records. When the flagged participants span several studies, chips
above the table narrow the page to one study.

## The token-only copy

The shareable copy is rendered from the report's data, not made by editing the finished HTML.
Every string in the data goes through the redactor's rules (`scrub_model` in
`fraudscreen/scrub.py`) with the same key and the same participant counts the redactor used for
the data, and the page is rendered a second time from the result. Editing HTML would hand the URL
rule `&amp;`-escaped links it cannot parse.

Before the copy is written, the redactor's independent leak scanner (`privacy/leakcheck.py`, which
shares no code with the scrub) checks the scrubbed data for 24-hex ids, study identifiers and
e-mail addresses. Any hit stops the run with exit 2 and a message that names the kind of hit,
never the value. The team copy is already written at that point and stays where it is. The CSV
is scrubbed as text.

## What the first real pull should check

1. **How often device records are written.** M2 links two participants only when the same browser
   id appears within one minute (`_same_minute` in `fraudscreen/signs/machine.py`). If the extension
   writes a status record every five minutes, that window is too narrow.
2. **Whether exports carry history from before the install.** M5 counts observation minutes at the
   time a record was written and m6 measures account age from enrolment, so both hold either way.
   The answer says how far back the other checks can see.
3. **Whether completion URLs carry a session id.** m15 closes a study window at the completion page
   for the same session. Without the id, every window runs to its 90-minute cap.
4. **How many participants have no device records.** If real exports routinely lack status files for
   some identifiers, the 10% line in the yellow box will fire every week and should be raised.

## Where the code lives

- `fraudscreen/signs/__init__.py`: the catalogue (tiers, rules, ordinary readings) and `SignResult`.
- `fraudscreen/signs/*.py`: the checks. Each strong check writes its one-sentence finding.
- `fraudscreen/report.py`: the report data (`build_model`), the page (`render_html`), the CSV.
- `fraudscreen/scrub.py`: the token-only copy (`scrub_model`) and the leak check (`leaks`).
- `fraudscreen/__main__.py`: the run, where files go, the refusals, and the zero-argument launcher.
