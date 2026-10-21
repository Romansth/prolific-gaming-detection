"""Input discovery: export file names, plain files and zip members, tolerant JSON reading."""
import json
import os
import re
import zipfile
from collections import namedtuple
from pathlib import Path

FileName = namedtuple("FileName", "ident generator day variant")
_NAME_RE = re.compile(r"^(.+?)__(.+?)__(?:(recorded|created)_)?(\d{4}-\d{2}-\d{2})\.json$")
SKIP_DIRS = {".redaction", ".staging", ".previous-safe"}


class Input(namedtuple("Input", "path member")):
    """A plain file (member None) or one member of a zip archive."""
    __slots__ = ()

    @property
    def name(self):
        return self.member or self.path.name


def parse_name(name):
    base = name.rsplit("/", 1)[-1]
    m = _NAME_RE.match(base)
    if not m:
        return None
    return FileName(m.group(1), m.group(2), m.group(4), m.group(3) or "plain")


def _zip_members(path):
    try:
        with zipfile.ZipFile(path) as z:
            return [n for n in z.namelist() if not n.endswith("/") and parse_name(n)]
    except (zipfile.BadZipFile, OSError):
        return []


def list_inputs(root):
    """Every export file under root: plain .json files and .json members of .zip archives,
    skipping hidden entries and zips whose members all exist extracted next to the zip."""
    root = Path(root)
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in SKIP_DIRS)
        here = Path(dirpath)
        present = set(filenames)
        for f in sorted(filenames):
            if f.startswith("."):
                continue
            if f.endswith(".json") and parse_name(f):
                out.append(Input(here / f, None))
            elif f.endswith(".zip"):
                members = _zip_members(here / f)
                if members and all((here / m).exists() or m.rsplit("/", 1)[-1] in present for m in members):
                    continue
                out.extend(Input(here / f, m) for m in members)
    return out


def read_points(inp):
    """The JSON array in the file, dict items only; [] for anything unreadable."""
    try:
        if inp.member is None:
            with open(inp.path, "rb") as fh:
                data = fh.read()
        else:
            with zipfile.ZipFile(inp.path) as z:
                data = z.read(inp.member)
        obj = json.loads(data)
    except Exception:  # OSError, ValueError, BadZipFile, KeyError, zlib.error, EOFError, RuntimeError ...
        return []
    if not isinstance(obj, list):
        return []
    return [p for p in obj if isinstance(p, dict)]
