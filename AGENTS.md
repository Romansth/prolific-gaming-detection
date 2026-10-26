# prolific-gaming-detection: instructions for Codex

This repo screens study pulls for participant gaming. Read `README.md` for the flow. Everything
happens inside this folder. These are the same rules Claude Code gets from `CLAUDE.md`; when one
file changes, change the other.

## Data boundary (team rule)

- `raw-data/`, `reports-team/` and any `.redaction/` folder hold real Prolific ids. Never read,
  list, grep, open, copy or run code on them.
- A PreToolUse hook (`.codex/hooks.json`, which runs the same `.claude/hooks/guard.py` Claude
  Code uses) refuses two kinds of call: anything that names one of those folders, including an
  `apply_patch` that touches them, and anything that reads recursively from the repo root or
  from an unnamed location (`find .`, `grep -r`, `rg <pattern>` with no path, `ls -R`, `du`,
  `tree`, a `**` glob, `os.walk('.')`). A "Blocked" message means the rule fired, not a bug to
  work around: name the folder you mean. Codex runs the hook only after the person has trusted
  it with `/hooks` (once per checkout, and again after the hook or guard changes); the rules
  here apply whether or not it is active.
- Work only from `data-redacted/<pull>/` (tokenized exports plus `identifiers.csv`) and
  `reports/` (token-only reports and CSVs). Scope every search to one of those, or to
  `fraudscreen/`, `privacy/`, `tests/`, `tools/` or `docs/`. Both data folders are git-ignored;
  `.ignore` whitelists them for ripgrep, and `grep -rn <token> data-redacted/<pull> reports/`
  always works.
- The user runs the screen on raw data in their own terminal:
  `./screen.sh --data raw-data/<pull> --redact`. The screen itself refuses a `raw-data/` folder
  inside an agent session (`CODEX_THREAD_ID` set, or `CLAUDECODE=1`). You may run it on a
  redacted folder
  (`python3 -m fraudscreen --data data-redacted/<pull>`, which writes
  `reports/<pull>_screen_<date>_from-redacted.html` and never touches the scrubbed report), the
  tests, and `python3 -m tests.synth`.
- When the user names a participant by a real Prolific id, identifier or e-mail in chat, run
  `python3 -m fraudscreen.lookup <value>` (it prints only the token), then search `reports/` and
  `data-redacted/<pull>` for that token. Refer to participants by token in everything you
  write; never write a real id into a file or a memory note.

## Conventions

- Python 3.9+, standard library only, no third-party packages anywhere.
- Tests: `make test` (synthetic data only; a failing suite fails make). Every sign rule change
  needs a planted case in `tests/synth.py` and an expectation in `tests/test_end_to_end.py`.
- The sign catalogue, thresholds and innocent readings live in `fraudscreen/signs/__init__.py`
  and the sign modules; the report wording is fixed there so two readers reach the same place.
- Reports state observations with evidence; they do not name causes that were not shown.
