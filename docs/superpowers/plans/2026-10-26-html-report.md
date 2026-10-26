# HTML report implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the markdown report with a self-contained HTML page that lists only participants with a strong (major) sign, states each finding in one plain sentence, and is scrubbed through its data model.

**Architecture:** Sign modules write a `headline` on each strong result. `report.build_model` turns results into plain data, `report.render_html` renders it, `scrub.scrub_model` scrubs the data for the token-only copy. `__main__` renders twice.

**Tech Stack:** Python 3.9 stdlib (`html`, `json`), unittest.

**Spec:** `docs/superpowers/specs/2026-10-26-html-report-design.md`

## Global Constraints

- Standard library only. Python 3.9 syntax (no `match`, no `X | Y` types).
- No sign rule or threshold changes.
- Tests run with `python3 -m unittest discover -q -s tests -t .` and `make test`.
- Never write a real Prolific id anywhere; tests use `tests/synth.py` ids.
- Private folder names (the raw pull folder, the team report folder, the key folder) must not appear in any tool input; refer to them by role.

## Review Focus

1. An evidence URL with `&` must survive the round trip team HTML → scrubbed HTML with its parameters intact and tokenized (not `&amp;`-mangled).
2. A participant with a major sign in redacted mode (M3 n/a) must still render a card, and the catalogue row must show the not-available count.
3. A pull where nobody is flagged must render a page saying so, with the support-only section still present.
4. Two flagged participants linked by M2 must sit next to each other in the overview, whatever their ids.
5. A string leaf containing a newline must not desynchronise `scrub_model`.

---

### Task 1: Headlines on strong results

**Files:**
- Modify: `fraudscreen/signs/__init__.py` (SignResult gains `headline: str = ""`; add `def n_of(n, noun)` → `"1 page"` / `"3 pages"`)
- Modify: `fraudscreen/signs/accounts.py`, `machine.py`, `tooling.py`, `location.py`
- Test: `tests/test_signs_accounts.py`, `tests/test_signs_machine.py`, `tests/test_signs_tooling.py`, `tests/test_signs_location.py`

**Interfaces:**
- Produces: `SignResult.headline` (str). Set for M1, m2, M2, M3, M4, m16, M5, m17, M6. `n_of(n, noun)`.

- [ ] **Step 1: failing tests**

```python
# test_signs_accounts.py, class M1Tests
def test_m1_headline_counts_pages_and_names_the_id(self):
    p = S.mk_participant(A, visits=[
        S.mk_visit(f"https://app.prolific.com/submissions/complete?cc=X&PROLIFIC_PID={B}", ts=T, visit_id=1),
        S.mk_visit(f"https://x.qualtrics.com/jfe/form/SV_x?PROLIFIC_PID={B}", ts=T - 300, visit_id=2)])
    r = score_accounts(p, ctx(p))
    self.assertEqual(r["M1"].headline, f"2 study pages opened locally under another Prolific id: {B}")
    pb = S.mk_participant(B, visits=[])
    r = score_accounts(p, ctx(p, pb))
    self.assertEqual(r["M1"].headline, f"2 study pages opened locally under another Prolific id: {B} (also enrolled in this pull)")
    synced = S.mk_participant(A, visits=[S.mk_visit(f"https://app.prolific.com/submissions/complete?PROLIFIC_PID={B}", ts=T, is_local=False)])
    self.assertEqual(score_accounts(synced, ctx(synced))["m2"].headline, f"1 study page synced in from another device under another Prolific id: {B}")

# test_signs_machine.py
def test_m2_headline_names_the_other_participant(self):
    pa = S.mk_participant(A, status=[S.mk_status(ts=T + i * 60, disks=(("bf5b9a96", 1022317891584),)) for i in range(5)])
    pb = S.mk_participant(B, status=[S.mk_status(ts=T + 120 + i * 60, disks=(("bf5b9a96", 1022317891584),)) for i in range(5)])
    r = score_machine(pa, Context([pa, pb], fleet_for(pa, pb), True))
    self.assertEqual(r["M2"].headline, f"In the same running browser as {B}: 1 browser id reported by both within a minute")

# test_signs_tooling.py
def test_m3_headline_counts_sessions(self):
    vs = [S.mk_visit(LAUNCH, ts=T, transition="auto_toplevel"), S.mk_visit("https://app.prolific.com/studies", ts=T + 2, visit_id=2),
          S.mk_visit("https://b.example/", ts=T + 5000, visit_id=4)]
    r = run(S.mk_participant(A, visits=vs))
    self.assertEqual(r["M3"].headline, "Antidetect browser: the start.adspower.net launch page opened 1 of 2 browsing sessions")

# test_signs_location.py
def test_strong_location_headlines(self):
    vs = [S.mk_visit("https://accounts.google.co.ke/accounts/SetSID?ssdc=1", ts=T),
          S.mk_visit("https://accounts.google.co.ke/accounts/SetSID?ssdc=1", ts=T + 12 * DAY, visit_id=2)]
    r = run(S.mk_participant(A, visits=vs, status=[S.mk_status()]))
    self.assertEqual(r["M4"].headline, "Google sign-ins routed through google.co.ke on 2 days (2026-09-14 and 2026-09-26)")
    st = [S.mk_status(ts=T + i * DAY, tz="Africa/Nairobi") for i in range(8)]
    r = run(S.mk_participant(A, status=st))
    self.assertEqual(r["M5"].headline, "Device clock set to Africa/Nairobi on 8 days, 100% of 8 observation minutes")
    r = run(S.mk_participant(A, visits=[S.mk_visit("https://www.google.com/search?q=weather&rlz=1C1ONGR_enVE1180VE1180", ts=T)]))
    self.assertEqual(r["M6"].headline, "Chrome installed with a VE locale (1 search page carries the install code)")
    one = run(S.mk_participant(A, visits=[S.mk_visit("https://accounts.google.com.ng/accounts/SetSID?ssdc=1", ts=T)], status=[S.mk_status()]))
    self.assertEqual(one["m16"].headline, "Google sign-ins routed through google.com.ng on 1 day (2026-09-14)")
```

(The T0 date is 2026-09-14; check `S.T0` and adjust the dates in the M4 assertion if the fixture says otherwise.)

- [ ] **Step 2: run, expect AttributeError / AssertionError on `headline`**
- [ ] **Step 3: implement** — field, `n_of`, headline assignments in the four modules (M4 days: "2026-09-14 and 2026-09-26" for two days, "a, b, c" joined with ", " and " and " before the last; one day: just the date).
- [ ] **Step 4: run the four test files, expect PASS; run the whole suite.**

### Task 2: Report model, HTML renderer, CSV flag

**Files:**
- Modify: `fraudscreen/report.py` (remove `render_markdown`; add `build_model`, `render_html`, `headline_or_note`; `write_csv` gains `flagged`)
- Test: `tests/test_report.py` (rewrite)

**Interfaces:**
- Produces: `build_model(results_by_key, participants, fleet, meta) -> dict` with keys `title, mode, run_line, n_screened, n_flagged, n_support_only, n_clean, intro, flagged, support_only, catalogue, excluded, limitations, version, seconds`. Card keys: `key, label, study, arm, browsers, n_strong, strong, support, linked`. Strong item keys: `id, title, headline, innocent, rule, evidence (list of [when, what, file]), count, notes, linked`. Support item keys: `id, title, line, linked`.
- Produces: `render_html(model) -> str`; `write_csv(path, results_by_key, participants)` with column `flagged` after `arm`.

- [ ] **Step 1: failing tests** (replace the file; keep `res()` and `META` helpers)

```python
def test_model_flags_only_strong_patterns(self):
    m = build_model(self.results, [self.pa, self.pb, self.pc], self.fleet, META)
    self.assertEqual([c["key"] for c in m["flagged"]], [B])
    self.assertEqual([s["id"] for s in m["flagged"][0]["strong"]], ["M1", "M2"])
    self.assertEqual([s["id"] for s in m["flagged"][0]["support"]], ["m1"])
    self.assertEqual([r["key"] for r in m["support_only"]], [A])
    self.assertEqual((m["n_screened"], m["n_flagged"], m["n_support_only"], m["n_clean"]), (3, 1, 1, 1))
    self.assertEqual(m["flagged"][0]["linked"], [A])

def test_connected_participants_sit_together(self):
    y, x, z = "65000000000000000000000a", "65000000000000000000000b", "65000000000000000000000c"
    parts = [S.mk_participant(k, status=[S.mk_status()]) for k in (y, x, z)]
    results = {y: res(["M2"], linked={"M2": z}), x: res(["M4"]), z: res(["M2"], linked={"M2": y})}
    m = build_model(results, parts, self.fleet, META)
    self.assertEqual([c["key"] for c in m["flagged"]], [y, z, x])

def test_html_cards_sections_and_escaping(self):
    self.results[B]["M1"].evidence[0] = Evidence("2026-09-14 00:23:15Z", "https://x.example/p?a=1&b=2", "f.json")
    html = render_html(build_model(self.results, [self.pa, self.pb, self.pc], self.fleet, META))
    self.assertIn("<title>Participant screen: pull_x</title>", html)
    self.assertIn(f'id="p-{B}"', html)
    self.assertNotIn(f'id="p-{A}"', html)
    self.assertIn(A, html)                       # support-only table
    self.assertNotIn(C, html)
    self.assertIn("https://x.example/p?a=1&amp;b=2", html)
    self.assertIn("Mode: raw", html)
    self.assertIn("Two household members each keep a profile in the same Chrome window.", html)
    self.assertIn("Concealment tool sites", html)   # the support-only row names the pattern
    self.assertIn("1 / 3", html)                     # catalogue: M1 fired for 1 of 3

def test_catalogue_counts_unavailable(self):
    results = {A: res(["M1"], unavailable=["m12"])}
    html = render_html(build_model(results, [self.pa], self.fleet, dict(META, mode="redacted")))
    self.assertIn("not available for 1", html)
    self.assertIn("Mode: redacted", html)

def test_support_line_falls_back_to_first_note(self):
    m = build_model(self.results, [self.pa, self.pb, self.pc], self.fleet, META)
    self.assertEqual(m["flagged"][0]["support"][0]["line"], "note one")

def test_nobody_flagged_still_renders(self):
    html = render_html(build_model({A: res(["m4"])}, [self.pa], self.fleet, META))
    self.assertIn("No participant is flagged", html)
    self.assertIn(A, html)

def test_email_masked_in_model(self):
    r = res(["M4"]); r["M4"].evidence[0] = Evidence("2026-09-14 00:23:15Z", "https://accounts.google.co.ke/x?login_hint=jane.doe%40example.com", "")
    m = build_model({A: r}, [self.pa], self.fleet, META)
    self.assertNotIn("jane.doe", json.dumps(m))
    self.assertIn("[email]", json.dumps(m))

def test_csv_columns(self):  # extend the existing test
    self.assertEqual(rows[0]["flagged"], "1")
    self.assertEqual(rows[1]["flagged"], "0")
```

- [ ] **Step 2: run, expect ImportError on `build_model`**
- [ ] **Step 3: implement** `build_model`, `render_html` (inline CSS, `<details>`, expand/collapse buttons, `html.escape` on every string), `write_csv` flag. Sorting key for flagged: `(-n_strong, group_key, key)` where `group_key = min([key] + linked keys of strong signs that are themselves flagged)`.
- [ ] **Step 4: run tests/test_report.py, expect PASS**

### Task 3: scrub_model

**Files:**
- Modify: `fraudscreen/scrub.py`
- Test: `tests/test_scrub_model.py` (new)

**Interfaces:**
- Produces: `scrub_model(model, key_dir, **kw) -> dict` (same kwargs as `scrub_text`).

- [ ] **Step 1: failing tests**

```python
def test_scrub_model_tokenizes_strings_and_keeps_shape(self):
    model = {"a": [f"https://x.qualtrics.com/jfe/form/SV_1?PROLIFIC_PID={A}&STUDY_ID={B}", "id shared-run-id: this"],
             "n": 3, "nested": {"k": A, "flag": True}}
    out = scrub_model(model, self.key_dir, device_ids={"shared-run-id"})
    text = json.dumps(out)
    self.assertNotIn(A, text); self.assertNotIn(B, text)
    self.assertEqual(out["n"], 3); self.assertIs(out["nested"]["flag"], True)
    self.assertRegex(out["nested"]["k"], r"^pid_[0-9a-f]{16}$")
    self.assertRegex(out["a"][1], r"^id dev_[0-9a-f]{16}: this$")
    self.assertIn("PROLIFIC_PID=pid_", out["a"][0])
    self.assertNotIn("&amp;", out["a"][0])

def test_scrub_model_flattens_newlines(self):
    out = scrub_model({"x": ["a\nb", "c"]}, self.key_dir)
    self.assertEqual(out["x"], ["a b", "c"])
```

- [ ] **Step 2: run, expect ImportError**
- [ ] **Step 3: implement** — walk dict/list, collect str leaves, join with "\n" after replacing "\n"/"\r" with " ", `scrub_text`, split, assert same length (raise `RuntimeError("scrub changed the line count")`), rebuild.
- [ ] **Step 4: run, expect PASS**

### Task 4: CLI wiring and the flow tests

**Files:**
- Modify: `fraudscreen/__main__.py`
- Test: `tests/test_cli.py`, `tests/test_end_to_end.py`, `tests/test_flow.py`, `tests/test_review_fixes.py`

- [ ] **Step 1: update the tests** — every `_screen_*.md` glob and `r.md`/`report.md`/`custom.md` path becomes `.html`; `"# Participant screen: pull\n"` becomes `"<title>Participant screen: pull</title>"`; `"1 participants carry"` becomes `"1 flagged"`; `render_markdown(...)` becomes `render_html(build_model(...))`; test_flow `"\n### "` count becomes `'class="card"'` count and the dev assertion becomes `assertRegex(pub, r"dev_[0-9a-f]{16}")`; the `md.split("\n")[2]` checks become plain `assertIn` on the whole text. New e2e tests:

```python
def test_flagged_cards_are_exactly_the_strong_cases(self):
    strong = {s.id for s in SIGNS if s.tier == "major"}
    want = {pid for pid, exp in self.expected.items() if exp & strong}
    got = set(re.findall(r'id="p-([0-9a-f]{24})"', self.html))
    self.assertEqual(got, want)

def test_support_only_participants_have_no_card_but_are_listed(self):
    strong = {s.id for s in SIGNS if s.tier == "major"}
    for pid, exp in self.expected.items():
        if exp and not exp & strong:
            self.assertIn(pid, self.html); self.assertNotIn(f'id="p-{pid}"', self.html)
        if not exp:
            self.assertNotIn(pid, self.html)

def test_headlines_carry_specifics(self):
    for text in ("Device clock set to Africa/Nairobi on 8 days", "Google sign-ins routed through google.co.ke on 2 days",
                 "Chrome installed with a VE locale", "start.adspower.net launch page opened 1 of"):
        self.assertIn(text, self.html, text)
```

- [ ] **Step 2: run the four files, expect failures on `.html` paths / new assertions**
- [ ] **Step 3: implement** in `__main__`: `.html` defaults and help text; `model = build_model(...)`; `out.write_text(render_html(model))`; print `flagged N`; after the redactor: `pub.write_text(render_html(scrub_model(model, key_dir, **kw)))`; CSV scrub unchanged.
- [ ] **Step 4: run the whole suite (`make test`), expect both suites OK**

### Task 5: Docs, ignore file, version

**Files:**
- Modify: `README.md` (Run bullets, "Reading the report"), `CLAUDE.md`, `AGENTS.md` (the `_from-redacted` name), `.gitignore` (`*_screen_*.html`), `fraudscreen/__init__.py` (0.2.0)

- [ ] **Step 1: edit; `grep -n "_screen_" README.md CLAUDE.md AGENTS.md .gitignore` shows only `.html` (and the old `.md` ignore line).**
- [ ] **Step 2: `make test` green; render the synthetic pull to the scratchpad and read the HTML once.**
