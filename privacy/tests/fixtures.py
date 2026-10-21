"""A fake raw tree with fake IDs planted in every place real ones turn up.
Every value here is invented."""
import json
import zipfile
from pathlib import Path

PID_A = "65f1c0de2b7a4e9f8c3d1a20"  # ObjectId time 2024-03
PID_B = "6ac1f3a9e04b7d2c1a9f8e37"  # 2026-10, the "second account"
PID_C = "6512aa0b9c8d7e6f5a4b3c2d"  # 2023-09
PID_D = "6650bb00cc11dd22ee33ff44"
STUDY = "66aa11bb22cc33dd44ee55ff"
IDENT_A = "WEIb_" + PID_A + "0015"
IDENT_B = "WEIb_" + PID_B + "0042"
IDENT_C = "AIMMSrareC_" + PID_C + "0007"
IDENT_D = "WEIb_" + PID_D + "0003"
EMAIL = "jane.roe@example.org"
PLANTED = [PID_A, PID_B, PID_C, STUDY, IDENT_A, IDENT_B, IDENT_C, EMAIL,
           "jane.roe%40example.org", "Jane Roe"]


def _point(gen, ident, **fields):
    meta = {"source": ident, "generator-id": gen, "generator": f"{gen}: Study/0.0.50",
            "timestamp": 1760000000, "timezone": "America/New_York"}
    return {"passive-data-metadata": meta, **fields}


def _visit(ident, url, n, **extra):
    host = url.split("/")[2] if "://" in url else ""
    return _point("rex-history-visit", ident, url=url, recorded_url=url, domain=host,
                  visit_id=str(n), visit_time=1760000000000 + n, transition_type="link", **extra)


def _write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj))


def build_raw(root):
    root = Path(root)
    exp = root / "pdk-export_2099-01-01_1"
    a_urls = [
        f"https://mit.co1.qualtrics.com/jfe/form/SV_x?PROLIFIC_PID={PID_A}&STUDY_ID={STUDY}",
        f"https://mit.co1.qualtrics.com/jfe/form/SV_x?PROLIFIC_PID={PID_B}",
        "https://www.google.com/url?q=https%3A%2F%2Fmit.co1.qualtrics.com%2Fjfe%2Fform%2FSV_x"
        f"%3FPROLIFIC_PID%3d{PID_A}&sa=D",
        f"https://app.prolific.com/submissions/{PID_A}/complete#done",
        "https://www.google.com.ng/search?q=cheap+flights&gl=ng",
        "https://someone-personal.example/blog?email=jane.roe%40example.org",
        "https://common.example/page",
        "chrome://settings/privacy",
        "file:///Users/jane/Documents/notes.pdf",
    ]
    _write(exp / f"{IDENT_A}__rex-history-visit__2099-01-01.json",
           [_visit(IDENT_A, u, i, title="Jane Roe | page") for i, u in enumerate(a_urls)]
           + [_visit(IDENT_A, "https://common.example/x", 99, mystery_field="x")])
    _write(exp / f"{IDENT_B}__rex-history-visit__2099-01-01.json",
           [_visit(IDENT_B, "https://common.example/page", 1),
            _visit(IDENT_B, f"https://app.prolific.com/studies/{STUDY}", 2)])
    _write(exp / f"{IDENT_C}__rex-history-visit__2099-01-01.json",
           [_visit(IDENT_C, "https://www.google.com/search?q=weather", 1)])
    _write(exp / f"{IDENT_A}__pdk-system-status__2099-01-01.json", [_point(
        "pdk-system-status", IDENT_A,
        **{"display-info": [{"id": "2077749241", "name": "Built-in Retina Display"}],
           "storage-info": [{"id": "abc-storage", "name": "Jane Roe USB", "capacity": 64}],
           "cpu-info": {"modelName": "Apple M2"}})])
    _write(exp / f"{IDENT_A}__search-mirror-result__2099-01-01.json", [_point(
        "search-mirror-result", IDENT_A,
        payload={"query": "jane roe address", "title": "Jane Roe - Example", "content": "<div>Jane Roe</div>",
                 "link": "https://result.example/x", "search_url": "https://www.bing.com/search?q=jane+roe+address",
                 "engine": "bing", "index": 1})])
    _write(exp / f"{IDENT_A}__brand-new-gen__2099-01-01.json",
           [_point("brand-new-gen", IDENT_A, payload={"secret": EMAIL})])
    _write(exp / f"{IDENT_A}__ai-market-add-identifier__2099-01-01.json",
           [_point("ai-market-add-identifier", IDENT_A, source=IDENT_A, name=IDENT_A)])
    with zipfile.ZipFile(root / "pdk-export_2099-01-01_1.zip", "w") as z:  # byte-identical twin
        for p in sorted(exp.iterdir()):
            z.write(p, p.name)
    with zipfile.ZipFile(root / f"{IDENT_A}-{IDENT_B}_ai_market_2099-01-02__7_2099-01-03.zip", "w") as z:
        z.writestr(f"{IDENT_B}__rex-history-visit__recorded_2099-01-02.json",
                   json.dumps([_visit(IDENT_B, "https://common.example/z", 5)]))
    audit = root / "audit"
    audit.mkdir()
    (audit / "REPORT.md").write_text(
        f"Flagged {IDENT_A}: second account {PID_B}, contact {EMAIL}.\n"
        f"See https://app.prolific.com/submissions/{PID_A}\n")
    (audit / "flags.csv").write_text(
        "identifier,reason,url\n"
        f"{IDENT_A},second_account,https://mit.co1.qualtrics.com/jfe/form/SV_x?PROLIFIC_PID={PID_B}\n")
    (audit / "prolific_export.csv").write_text(f"Participant id,Age\n{PID_A},30\n")
    (audit / "cache.parquet").write_bytes(b"PAR1" + PID_A.encode())
    (audit / "scores.json").write_text(json.dumps({IDENT_A: {"score": 0.9}, IDENT_B: {"score": 0.1}}))
    (root / "recordings").mkdir()
    (root / "recordings" / "prolific recording Jane Roe.mp4").write_bytes(b"\x00\x00")
    (root / "MOVED_2099-01-01.tsv").write_text("original\tnew\n/Users/x/Downloads/Jane Roe.mp4\tsomewhere\n")
    (root / ".DS_Store").write_bytes(b"\x00")
    return root


def add_participant_d(raw):
    """A later export in which a fourth participant visits common.example."""
    _write(Path(raw) / "pdk-export_2099-02-01_2" / f"{IDENT_D}__rex-history-visit__2099-02-01.json",
           [_visit(IDENT_D, "https://common.example/page", 1)])
