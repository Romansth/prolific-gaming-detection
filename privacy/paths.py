"""Default locations. The raw and processed folders sit next to the repo, so
recursive searches from inside the repo never reach them."""
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_RAW = REPO.parent / "user_data_raw"
DEFAULT_PROCESSED = REPO.parent / "report_processed"
DEFAULT_SAFE = REPO / "user_data_safe"
DEFAULT_REPORTS = REPO / "report_claude"
RAW_FOLDER_NAME = DEFAULT_RAW.name   # the guard keys on this folder name, wherever it sits
RAW_FOLDER_NAMES = (RAW_FOLDER_NAME, "raw-data")   # ... and on the screening repo's raw folder


# Claude Code sets CLAUDECODE=1 for every shell it starts; Codex injects CODEX_THREAD_ID and
# CODEX_SESSION_ID, even under an include_only shell_environment_policy. A person's Terminal sets
# none of them, so these tell the two apart.
AGENT_ENV_VARS = ("CLAUDECODE", "CODEX_THREAD_ID", "CODEX_SESSION_ID")


def inside_claude():
    """True inside a Claude Code or Codex session (the name predates Codex support)."""
    return os.environ.get("CLAUDECODE") == "1" or any(os.environ.get(v) for v in AGENT_ENV_VARS[1:])


def in_raw_folder(path):
    """True when path is, or lies inside, a folder bearing the team's raw-folder name."""
    p = Path(os.path.abspath(path))
    names = set(RAW_FOLDER_NAMES) | {RAW_FOLDER_NAME}
    return any(part in names for part in p.parts)


def find_key_dir(start):
    """The nearest existing .redaction/ walking up from start, else <start>/.redaction."""
    p = Path(start).resolve()
    for folder in [p] + list(p.parents):
        if (folder / ".redaction").is_dir():
            return folder / ".redaction"
    return p / ".redaction"


def within(path, folder):
    """True when path is folder or anything inside it."""
    p, f = Path(path).resolve(), Path(folder).resolve()
    return p == f or f in p.parents
