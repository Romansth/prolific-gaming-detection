# Prolific gaming detection

Screens a Prolific study pull for participants who may be gaming the study: a second Prolific
account in the same browser, two participants sharing one browser, antidetect browsers, or a
non-US location behind a US clock. Each run gives the team a report with real ids, and a copy
with ids replaced by tokens that is safe to share.

It runs on Python 3.9 or newer, with nothing else to install.

## Screening a pull

1. Put a pull in `raw-data/<pull-name>/` (for example `raw-data/oct-10/`).
2. Run `./screen.sh` (Windows: `.\screen.ps1`).

The screen takes the newest pull, redacts it, and opens the team report in your browser. It writes:

- `reports-team/oct-10_screen_<date>.html`: the report with real Prolific ids, for the team only
- `reports/oct-10_screen_<date>.html`: the same report with tokens, safe to share
- `data-redacted/oct-10/`: the data with ids replaced by tokens

Each report has a CSV next to it with every participant and every check.

To screen a specific pull: `./screen.sh --data raw-data/oct-10 --redact`. To find a participant in
the shareable report, `./screen.sh lookup <prolific id>` prints their token. `./screen.sh --help`
lists the other options.

## Reading the report

Everyone in the top table is flagged: the screen found at least one strong sign of gaming. Each
flagged participant has a card with what was found, the evidence, and the innocent explanation to
rule out. Weaker signs appear on the card as context but never flag anyone on their own.

The strong signs are:

- a second Prolific id used in the monitored browser
- two enrolled participants in one running browser
- an antidetect browser
- Google sign-ins routed outside the US on two days a week apart
- a non-US device clock on 7 or more days, or half the time
- Chrome installed with a non-US locale

A yellow box at the top means part of the pull could not be read. Re-export the files it names
before relying on the page.

## What the screen cannot see

There are no IP addresses in the data. Location comes from the device clock and from Google's
sign-in domain, so a US clock behind a steady US VPN leaves no trace. A second Prolific account
shows up only if it was used in the browser profile the extension monitors.

## Folders

```
raw-data/<pull>/      paste a pull here (the per-identifier JSON exports, zips allowed)   [never shared]
raw-data/.redaction/  the redaction key and lookup table, created on the first run        [never shared]
data-redacted/<pull>/ the tokenized copy of the pull                                      [safe to discuss]
reports-team/         reports with real Prolific ids, for the research team               [never shared]
reports/              the same reports with ids replaced by tokens                        [safe to discuss]
```

Git ignores all four data folders, so nothing a run writes can be committed by accident.

## Claude Code and Codex

AI assistants may read only `data-redacted/` and `reports/`. A hook blocks them from the raw data,
the team reports and the redaction key. Claude Code picks the hook up from `.claude/settings.json`;
in Codex, run `/hooks` once in this folder and approve it. `CLAUDE.md` and `AGENTS.md` hold the
full rules.

## Maintenance

- `make test` runs all tests on synthetic data. GitHub runs them on every push.
- `python3 -m tests.synth <folder>` writes a synthetic pull with one planted case per sign.
- To change a sign, edit it in `fraudscreen/signs/`, add a planted case to `tests/synth.py` and the
  expected result to `tests/test_end_to_end.py`, then run `make test`.
- `python3 tools/make_arm_map.py --repo <AI-extension-testing checkout> --out fraudscreen/arms.json`
  refreshes the map from configuration hash to study arm.
- `fraudscreen/` is the screen; `privacy/` is a copy of the team's redactor.
- Design choices and open questions are in `docs/report-design.md`.
