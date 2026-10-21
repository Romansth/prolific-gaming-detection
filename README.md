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

- screens the raw data and writes `reports-team/oct-10_screen_<date>.md` and `.csv` (real ids);
- runs the redactor and writes `data-redacted/oct-10/` with `identifiers.csv`;
- scrubs the report and CSV with the same key and writes `reports/oct-10_screen_<date>.md` and `.csv` (tokens).

Without `--redact` it screens whatever folder it is given (raw or already redacted) and writes
one report; a screen of `data-redacted/<pull>` goes to `reports/<pull>_screen_<date>_from-redacted.md`
so it never replaces the scrubbed report, and the signs that need raw data (M3, m12, the search
patterns of m13) show as `n/a` there. A symlink under `raw-data/` works like a copied folder.
Other options: `--out`, `--csv`, `--workers N`, `--arms arms.json`, `--min-visits 50`,
`--exclude-pattern REGEX`, `--key-dir`, `--safe`. Exit codes: 0 report written, 2 bad input or the
redactor refused, 3 nothing screenable.

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

## Reading the report

The table lists every participant with at least one sign, rows sorted by the number of major
signs, one column per sign, `✓` (or `✓n` with a count) where it fired, `n/a` where the sign
cannot be evaluated on this data. Under the table, one section per participant gives, for each
fired sign, the rule, up to five evidence rows (UTC time, value as stored, source file), the
full count, notes, and a fixed innocent reading. Appendix A gives every sign's rule and how many
participants in this pull tripped it; Appendix B the signals deliberately excluded; Appendix C the
limitations.

Major signs (the proof bar): M1 second Prolific id used in the monitored browser; M2 two enrolled
participants in one running browser; M3 antidetect browser; M4 Google routed sign-ins outside the
US on two days a week apart; M5 device clock outside the US on 7+ days; M6 Chrome installed with a
non-US locale.

Minor signs (support): m1 same Windows/Linux hardware as another participant; m2 another id synced
into the profile; m3 link-sharing; m4 concealment tool sites; m5 virtual machine or remote
session; m6 account under 30 days old; m7 same id enrolled twice; m8 hours disagree with the
clock; m9 timezone switches; m10 one identifier on two machines; m11 survey-only browser, fresh
profile, typed study links; m12 shared mail identity (raw data only); m13 foreign-language
interface and searches; m14 automated reloads; m15 chatbot during surveys; m16 one non-US sign-in
episode; m17 a non-US clock for a day.

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
