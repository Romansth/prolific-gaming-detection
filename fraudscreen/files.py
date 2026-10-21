"""Input discovery: export file names, plain files and zip members (one level of zip inside zip),
tolerant JSON reading, and a count of what was left unread so the report header can say so."""
import io
import json
import os
import re
import zipfile
from collections import Counter, namedtuple
from pathlib import Path

FileName = namedtuple("FileName", "ident generator day variant")
# a browser names a repeated download "X (1).json"; some tools upper-case the extension
_NAME_RE = re.compile(r"^(.+?)__(.+?)__(?:(recorded|created)_)?(\d{4}-\d{2}-\d{2})(?: \(\d+\))?\.json$", re.I)
_JUNK_DIRS = {"__MACOSX"}
SKIP_DIRS = {".redaction", ".staging", ".previous-safe"}


class Input(namedtuple("Input", "path member inner", defaults=(None, None))):
    """A plain file (member None), one member of a zip archive, or one member (inner) of a zip
    archive that is itself the member of the outer zip."""
    __slots__ = ()

    @property
    def name(self):
        return self.inner or self.member or self.path.name


def parse_name(name):
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    m = _NAME_RE.match(base)
    if not m:
        return None
    return FileName(m.group(1), m.group(2), m.group(4), m.group(3) or "plain")


def _junk(name):
    """AppleDouble shadows (._X.json) and __MACOSX folders: they carry a real file's name but no data."""
    parts = name.replace("\\", "/").split("/")
    return parts[-1].startswith("._") or any(p in _JUNK_DIRS for p in parts)


def _zip_members(path, skipped):
    """[(member, inner, size)] for the export files in an archive and in one level of zip inside it;
    None when the archive itself does not open (the caller counts it as corrupt_zip)."""
    out = []
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                if _junk(info.filename):
                    skipped["junk"] += 1
                elif parse_name(info.filename):
                    out.append((info.filename, None, info.file_size))
                elif info.filename.lower().endswith(".json"):
                    skipped["unparsed_name"] += 1
                elif info.filename.lower().endswith(".zip"):
                    try:
                        with zipfile.ZipFile(io.BytesIO(z.read(info))) as inner:
                            for ii in inner.infolist():
                                if ii.is_dir():
                                    continue
                                if _junk(ii.filename):
                                    skipped["junk"] += 1
                                elif parse_name(ii.filename):
                                    out.append((info.filename, ii.filename, ii.file_size))
                                elif ii.filename.lower().endswith(".json"):
                                    skipped["unparsed_name"] += 1
                                elif ii.filename.lower().endswith(".zip"):
                                    skipped["nested_zip"] += 1   # one level of nesting is read, not two
                    except Exception:  # bad CRC, truncated, encrypted ...
                        skipped["corrupt_zip"] += 1
    except (zipfile.BadZipFile, OSError):
        return None
    return out


def _extracted_twin(here, member, inner, size):
    """True when the member already sits extracted beside the zip with the member's size (a stale
    or truncated copy does not hide the zip)."""
    if inner is not None:
        return False
    for cand in (here / member, here / member.rsplit("/", 1)[-1]):
        try:
            if cand.is_file() and cand.stat().st_size == size:
                return True
        except OSError:
            pass
    return False


def discover(root):
    """(inputs, skipped): every export file under root, plain .json files and .json members of
    .zip archives, and a count of what was left unread: json names that do not parse, archives
    that do not open, junk entries. Hidden folders are read; only the redactor's own folders are
    skipped. A zip whose members all sit extracted beside it with the same sizes is skipped in
    favour of the extracted copies."""
    root = Path(root)
    out, skipped = [], Counter()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and d not in _JUNK_DIRS)
        here = Path(dirpath)
        for f in sorted(filenames):
            low = f.lower()
            if _junk(f):
                skipped["junk"] += 1
            elif f.startswith("."):
                continue   # .DS_Store and friends: not data, not worth a line in the header
            elif low.endswith(".json"):
                if parse_name(f):
                    out.append(Input(here / f, None))
                else:
                    skipped["unparsed_name"] += 1
            elif low.endswith(".zip"):
                members = _zip_members(here / f, skipped)
                if members is None:
                    skipped["corrupt_zip"] += 1
                elif members and all(_extracted_twin(here, m, inner, size) for m, inner, size in members):
                    continue
                else:
                    out.extend(Input(here / f, m, inner) for m, inner, _ in members)
    return out, skipped


def list_inputs(root):
    return discover(root)[0]


def read_points(inp):
    """The JSON array in the file, dict items only; [] for anything unreadable."""
    try:
        if inp.member is None:
            with open(inp.path, "rb") as fh:
                data = fh.read()
        else:
            with zipfile.ZipFile(inp.path) as z:
                data = z.read(inp.member)
            if inp.inner is not None:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    data = z.read(inp.inner)
        obj = json.loads(data)
    except Exception:  # OSError, ValueError, BadZipFile, KeyError, zlib.error, EOFError, RuntimeError ...
        return []
    if not isinstance(obj, list):
        return []
    return [p for p in obj if isinstance(p, dict)]
