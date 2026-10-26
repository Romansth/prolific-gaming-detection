# Prolific gaming detection

Screens the browser-extension exports of a study pull for signs that a participant is gaming
the study: a second Prolific account in the monitored browser, two accounts in one running
browser, antidetect browsers, concealment tools, a non-US location behind a US clock, and
weaker supporting patterns. One command turns a pull into a report the research team can act
on and a token-only copy that can be discussed with Claude.

Pure Python 3.9 or newer, standard library only. Mac, Linux and Windows.

## Layout

```
raw-data/<pull>/      paste a pull here (the per-identifier JSON exports, zips allowed)   [never shared]
raw-data/.redaction/  the redaction key and lookup table, created on the first run        [never shared]
data-redacted/<pull>/ the tokenized copy of the pull                                      [safe to discuss]
reports-team/         reports with real Prolific ids, for the research team               [never shared]
reports/              the same reports with ids replaced by tokens                        [safe to discuss]
fraudscreen/          the screen;  privacy/  the team's redactor;  tests/  synthetic tests
```

## Install

Mac or Linux: `./setup.sh`. Windows (PowerShell): `.\setup.ps1`. Both create a private `.venv`
with the Python already on the machine; nothing is downloaded or installed.

## Run

1. Put a pull in `raw-data/<pull-name>/` (for example `raw-data/oct-10/`).
2. `./screen.sh --data raw-data/oct-10 --redact` (Windows: `.\screen.ps1 --data raw-data\oct-10 --redact`).

That one command:

- screens the raw data and writes `reports-team/oct-10_screen_<date>.html` and `.csv` (real ids);
- runs the redactor and writes `data-redacted/oct-10/` with `identifiers.csv`;
- scrubs the report and CSV with the same key and writes `reports/oct-10_screen_<date>.html` and `.csv` (tokens).

`./screen.sh` with no arguments screens the newest pull folder from step 1 (by modification time),
redacts, and opens the team page in the browser; `--open` opens the page after an explicit run.

Without `--redact` it screens whatever folder it is given (raw or already redacted) and writes
one report; a screen of `data-redacted/<pull>` goes to `reports/<pull>_screen_<date>_from-redacted.html`
so it never replaces the scrubbed report, and the two signs that need raw data (M3, m12) are marked not
available in its appendix (m13 runs without its search patterns). A symlink under `raw-data/` works like a copied folder.
Other options: `--out`, `--csv`, `--workers N`, `--arms arms.json`, `--min-visits 50`,
`--exclude-pattern REGEX`, `--key-dir`, `--safe`. Exit codes: 0 report written, 2 bad input or the
redactor refused, 3 nothing screenable.

Raw or redacted is decided from the file names (a real 24-hex id in a name means raw), never from
a stray `identifiers.csv`. Two things are refused with exit 2 so that no real id reaches the
shareable folder: a raw pull placed under `data-redacted/`, and `--out` pointing into `reports/`
on raw data. Outside the repo layout, `--out X --redact` writes the token-only report to X and the
real-id one to `X_team`. The report header counts the files that were not read (names that do not
parse, archives that do not open) and the visits without a time, so a half-read pull is visible.

To find a participant in the token-only report: `./screen.sh lookup <prolific id>` prints the
`pid_…` token (an identifier or an e-mail address works too). It prints nothing else.

The token-only report follows the redactor's own rules: Prolific ids, identifiers and e-mail
addresses become tokens, URLs keep only the allow-listed hosts and parameters, storage and display
ids become `dev_` tokens, hosts visited by fewer than 5 participants become `host_` tokens, and a
cohort prefix carried by fewer than 5 identifiers is reduced to its study stem (`WEI…`). The team
report keeps real ids and URLs but masks e-mail addresses as `[email]`.

Inside a Claude Code session the screen refuses a `raw-data/` folder, and the hook in
`.claude/settings.json` blocks any call that names `raw-data/`, `reports-team/` or `.redaction/`
or that reads recursively from the repo root (see `CLAUDE.md`).

Codex gets the same rules. `AGENTS.md` mirrors `CLAUDE.md`, `.codex/hooks.json` runs the same
guard, and the screen and redactor recognise a Codex shell by `CODEX_THREAD_ID`. Codex runs a
project hook only after you trust it: open Codex in this folder, run `/hooks` and approve the
guard (again after either file changes). The in-code refusal works without that step.

## Reading the report

The report is one HTML file; open it in a browser. It lists the participants that are flagged:
those with at least one strong pattern, a pattern where gaming is more likely than not. The top
table gives each flagged participant, the study and arm, the strong patterns seen, and the
participants it is connected to. One card per flagged participant follows. For each strong
pattern the card gives a one-sentence finding ("Device clock set to Africa/Nairobi on 10 days,
100% of 18 observation minutes"), the evidence rows (UTC time, what was seen, source file), the
ordinary explanation that would also produce it, and a collapsed "Rule and notes". Supporting
patterns that also fired are listed under the card for context; they never flag anyone on their
own. Below the cards, a collapsed table names the participants with supporting patterns only,
and a collapsed appendix gives every pattern checked (code, rule, how many participants tripped
it, how many it could not be evaluated for), the signals deliberately excluded, and the
limitations. The CSV beside the report carries every participant, a `flagged` column, and one
`_fired` / `_count` pair per pattern.

A yellow box at the top appears when the pull looks half-read (files that did not open or parse,
visits without a time, participants with no device record) and says what to re-export. With more
than one study in the pull, chips above the table narrow the page to one study. Each card has a
"Copy id" button and a "Back to overview" link; the source-file column of the evidence tables is
hidden until "Show source files" is ticked.

Strong patterns, the ones that flag: M1 second Prolific id used in the monitored browser; M2 two
enrolled participants in one running browser; M3 antidetect browser; M4 Google routed sign-ins
outside the US on two days a week apart; M5 device clock outside the US on 7+ days or half the
observation minutes; M6 Chrome installed with a non-US locale.

Supporting patterns, context only: m1 same Windows/Linux hardware as another participant; m2
another id synced into the profile; m3 link-sharing; m4 concealment tool sites; m5 virtual
machine or remote session; m6 account under 30 days old; m7 same id enrolled twice; m8 hours
disagree with the clock; m9 timezone switches; m10 one identifier on two machines; m11
survey-only browser, fresh profile, typed study links; m12 shared mail identity (raw data only);
m13 foreign-language interface and searches; m14 automated reloads; m15 chatbot during surveys;
m16 one non-US sign-in episode; m17 a non-US clock for a day.

## What it cannot see

No IP address is in the data: location rests on the device clock and on Google's choice of a
country-specific sign-in domain, so a US clock plus a stable US VPN exit leaves no trace. A second
account is visible only when used in the monitored browser profile. Stock Mac and Chromebook
hardware collides across unrelated people. Redacted data has no page titles and knows account
age only to the month.

## Maintenance

- `make test` runs the screen's tests and the redactor's tests on synthetic data; it fails when either does.
- `python3 -m tests.synth <folder>` writes a synthetic pull with one planted case per sign.
- `python3 tools/make_arm_map.py --repo <AI-extension-testing checkout> --out fraudscreen/arms.json`
  refreshes the configuration-hash to arm-name snapshot.
- `make dist` zips the package from an allow-list of folders and files; nothing a run wrote is included.
