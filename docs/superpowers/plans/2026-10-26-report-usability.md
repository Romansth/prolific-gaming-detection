# Report usability plan (round 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the weekly run and the review page frictionless: a zero-argument launcher that opens the page, a data-quality banner, a study filter, and small reading aids on the cards.

**Architecture:** All in `fraudscreen/__main__.py` (launcher, meta) and `fraudscreen/report.py` (model `warnings`/`studies`, renderer, inline CSS/JS). No new modules.

**Spec:** `docs/superpowers/specs/2026-10-26-html-report-design.md` (round 2 section) and the calls stated in chat on 2026-10-26.

## Global Constraints

- Standard library only, Python 3.9. No network access from the page.
- Private folder names never appear in tool input; code uses `RAW_FOLDER_NAMES[-1]`.
- Tests: `make test`.

## Review Focus

1. `./screen.sh` with no arguments inside an agent session must still refuse (it resolves to the raw folder).
2. The newest pull is chosen by folder mtime; a pull copied in later but named earlier wins.
3. The banner must not fire on a healthy pull (synthetic pull has one truncated file, so it fires there).
4. Study chips filter cards, overview rows and the support-only rows together; a single-study pull shows no chips.
5. Linkified ids in headlines must stay escaped and point only at participants with a card.

---

### Task 1: `--open` and the zero-argument run

**Files:** Modify `fraudscreen/__main__.py`. Test: `tests/test_launch.py` (new).

**Interfaces:** `REPO_ROOT` module constant (tests patch it); `--data` optional; `--open` flag.

- [ ] Step 1: failing tests `test_open_flag_opens_the_team_report`, `test_no_data_screens_the_newest_pull_redacts_and_opens`, `test_no_data_without_a_pull_exits_2`, `test_no_data_inside_agent_session_refused`.
- [ ] Step 2: run → fail (unrecognised `--open`, `--data` required).
- [ ] Step 3: implement: `REPO_ROOT`; newest folder under `REPO_ROOT / RAW_FOLDER_NAMES[-1]` by mtime (skip dot-folders); sets `redact` and `open`; prints "Screening the newest pull: <name>"; `webbrowser.open(out.resolve().as_uri())` right after the team report is written.
- [ ] Step 4: run → pass; whole suite.

### Task 2: data-quality banner

**Files:** Modify `fraudscreen/report.py` (`_warnings(meta)`, model key `warnings`, banner block), `fraudscreen/__main__.py` (meta `visits`, `no_status`). Test: `tests/test_report.py`, `tests/test_end_to_end.py`.

- [ ] Step 1: failing tests `test_warning_banner_names_what_was_not_read`, `test_no_banner_on_a_clean_pull`, e2e `test_banner_reports_the_truncated_file`.
- [ ] Step 2: run → fail. Step 3: implement (floors: any file not read or truncated; >5% visits without a time, share = no_time / (visits + no_time); >10% participants without status points). Step 4: run → pass.

### Task 3: study chips and reading aids

**Files:** Modify `fraudscreen/report.py`. Test: `tests/test_report.py`.

- [ ] Step 1: failing tests `test_study_chips_only_with_several_studies`, `test_pattern_summary_line`, `test_cards_carry_copy_button_and_back_link`, `test_headline_links_the_other_flagged_participant`, `test_source_file_column_behind_a_checkbox`, `test_tables_scroll_sideways`.
- [ ] Step 2: run → fail. Step 3: implement: `data-study` on cards and rows, chips (buttons) when >1 study with counts over flagged + support-only, `filterStudy(s)`; summary chips with counts under the flagged heading; `Copy id` button (`navigator.clipboard`); `Back to overview` link; linkified flagged ids in headlines; `Show source files` checkbox toggling `body.files`; `<div class="scroll">` around tables. Step 4: run → pass.

### Task 4: docs and version

- [ ] README Run (zero-argument run, `--open`) and Reading the report (banner, chips, copy, source files); spec round-2 section; version 0.3.0; `make test`.
