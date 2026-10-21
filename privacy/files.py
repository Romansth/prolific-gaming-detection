"""Per-file-type redaction (spec, "Other files"). The output tree mirrors the
input, with every path component passed through the ID scan."""
import csv
import io
import json
import re
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

from privacy.points import is_point

TEXT_EXT = {".md", ".txt", ".log", ".err", ".out", ".py", ".sh", ".r", ".mjs", ".js", ".html",
            ".htm", ".tex", ".sql", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".xml"}
CSV_EXT = {".csv": ",", ".tsv": "\t"}
JUNK_NAMES = {".ds_store", "thumbs.db"}
# Header cells that mark a participant export (Prolific, Qualtrics, CloudResearch,
# MTurk), matched as substrings after lowercasing and removing non-alphanumerics.
REFUSED_MARKERS = ("participantid", "prolificpid", "submissionid", "responseid", "ipaddress",
                   "workerid", "assignmentid", "hitid", "latitude", "longitude", "recipientemail")
_SEP_RE = re.compile(r"[\s,]*")


class Refused(Exception):
    """A file that is not copied; args[0] names the report counter."""




def _is_participant_export(header):
    cells = {re.sub(r"[^a-z0-9]", "", c.lower()) for c in header}
    return any(marker in cell for cell in cells for marker in REFUSED_MARKERS)


def kind_of(name):
    low = name.lower()
    if low in JUNK_NAMES or low.startswith("._"):
        return "junk"
    ext = PurePosixPath(low).suffix
    if ext == ".json":
        return "json"
    if ext in (".jsonl", ".ndjson"):
        return "jsonl"
    if ext in CSV_EXT:
        return "csv"
    if ext in TEXT_EXT:
        return "text"
    if ext == ".zip":
        return "zip"
    return "skip"


def iter_json_array(text):
    """Yield a top-level JSON array's elements one at a time, so a large export
    never becomes one big object tree."""
    dec = json.JSONDecoder()
    i = text.index("[") + 1
    while True:
        i = _SEP_RE.match(text, i).end()
        if i >= len(text):
            raise json.JSONDecodeError("unterminated JSON array", text, i)
        if text[i] == "]":
            return
        obj, i = dec.raw_decode(text, i)
        yield obj


def _looks_like_export(text):
    """A PDK export is a JSON array of points; an empty or truncated array counts."""
    if not text.lstrip().startswith("["):
        return False
    try:
        first = next(iter_json_array(text), None)
    except json.JSONDecodeError:
        return True
    return first is None or is_point(first)


def _member_is_safe(member):
    return not member.is_absolute() and ".." not in member.parts


def zip_is_duplicate(src):
    """True when every member already exists, byte for byte, in the extracted
    folder of the same name (either with or without the top folder inside).
    A zip that cannot be read in full is never a duplicate."""
    try:
        return _zip_is_duplicate(src)
    except Exception:  # bad CRC, truncated archive, unreadable twin
        return False


def _zip_is_duplicate(src):
    folder = src.with_suffix("")
    if not folder.is_dir():
        return False
    try:
        z = zipfile.ZipFile(src)
    except zipfile.BadZipFile:
        return False
    with z:
        members = [i for i in z.infolist() if not i.is_dir()
                   and not i.filename.startswith("__MACOSX/")
                   and kind_of(PurePosixPath(i.filename).name) != "junk"]
        if not members:
            return False
        for info in members:
            if not _member_is_safe(PurePosixPath(info.filename)):
                return False
            twin = next((c for c in (folder / info.filename, folder.parent / info.filename)
                         if c.is_file() and c.stat().st_size == info.file_size), None)
            if twin is None or twin.read_bytes() != z.read(info):
                return False
    return True


class FileRedactor:
    def __init__(self, scanner, points, scrubber, include_other=False):
        # Off by default: reports, CSVs, logs and scripts derived from the raw data
        # can carry names and ID shorthand that no rule recognizes.
        self.include_other = include_other
        self.scanner = scanner
        self.points = points
        self.scrubber = scrubber
        self.stats = Counter()

    def scan_rel(self, rel):
        return Path(*[self.scanner.scan(part) for part in PurePosixPath(*Path(rel).parts).parts])

    def _skip(self, name):
        self.stats["skipped " + (PurePosixPath(name.lower()).suffix or "(no extension)")] += 1

    def redact_file(self, src, rel, dest_root):
        kind = kind_of(src.name)
        if kind == "junk":
            self.stats["junk"] += 1
        elif kind == "skip":
            self._skip(src.name)
        elif kind == "zip":
            self.redact_zip(src, Path(rel), dest_root)
        elif kind != "json" and not self.include_other:
            self._skip(src.name)
        else:
            self.write(kind, src.name, src.read_bytes(), dest_root / self.scan_rel(rel))

    def redact_zip(self, src, rel, dest_root):
        if zip_is_duplicate(src):
            self.stats["duplicate_zips"] += 1
            return
        try:
            z = zipfile.ZipFile(src)
        except (zipfile.BadZipFile, OSError):
            self.stats["bad_zips"] += 1
            return
        out_dir = dest_root / self.scan_rel(rel.parent) / (self.scanner.scan(src.stem) + "__zip")
        with z:
            self.stats["zips"] += 1
            for info in z.infolist():
                member = PurePosixPath(info.filename)
                if info.is_dir() or member.parts[:1] == ("__MACOSX",):
                    continue
                if not _member_is_safe(member):
                    self.stats["unsafe_zip_members"] += 1
                    continue
                kind = kind_of(member.name)
                if kind == "junk":
                    continue
                if kind in ("skip", "zip") or (kind != "json" and not self.include_other):
                    self._skip(member.name)
                    continue
                try:
                    data = z.read(info)
                except Exception:  # bad CRC, truncated archive, unsupported compression
                    self.stats["bad zip members"] += 1
                    continue
                self.write(kind, member.name, data, out_dir / self.scan_rel(member))

    def write(self, kind, name, data, dest):
        text = data.decode("utf-8-sig", errors="replace")  # json.loads rejects a BOM
        if kind == "json" and not self.include_other and not _looks_like_export(text):
            self._skip(name)  # decided before anything is created, so no empty folders
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(dest, "w", encoding="utf-8", newline="") as fh:
                if kind == "json":
                    self._json(text, fh)
                elif kind == "jsonl":
                    self._jsonl(text, fh)
                elif kind == "csv":
                    self._csv(text, CSV_EXT[PurePosixPath(name.lower()).suffix], fh)
                else:
                    self._text(text, fh)
        except Refused as r:
            dest.unlink()
            self.stats[r.args[0]] += 1
            return
        except Exception:
            dest.unlink(missing_ok=True)  # no half-written file in the staging copy
            raise
        self.stats["files " + kind] += 1

    def value(self, obj):
        if is_point(obj):
            return self.points.redact(obj)
        if isinstance(obj, dict):
            return {self.scrubber.scrub(str(k)): self.value(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.value(v) for v in obj]
        if isinstance(obj, str):
            return self.scrubber.scrub(obj)
        return obj

    @staticmethod
    def _dump(obj):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    def _json(self, text, fh):
        # A file that may hold points never falls back to text: text keeps every
        # field, so titles and search-mirror text would bypass the DROP rules.
        if text.lstrip().startswith("["):
            fh.write("[")
            sep = "\n"
            try:
                for obj in iter_json_array(text):
                    fh.write(sep + self._dump(self.value(obj)))
                    sep = ",\n"
            except json.JSONDecodeError:  # truncated download: keep the whole elements
                self.stats["truncated json"] += 1
            fh.write("\n]\n")
            return
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            raise Refused("unparseable")
        json.dump(self.value(obj), fh, ensure_ascii=False, indent=1)
        fh.write("\n")

    def _jsonl(self, text, fh):
        for line in text.splitlines():
            if not line.strip():
                fh.write("\n")
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:  # a partial point; as text it would skip the field rules
                self.stats["bad jsonl lines"] += 1
                continue
            fh.write(self._dump(self.value(obj)) + "\n")

    def _csv(self, text, delimiter, fh):
        try:
            rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
        except csv.Error:  # e.g. a NUL byte; unparsed, the header check cannot run
            raise Refused("unparseable")
        if rows and _is_participant_export(rows[0]):
            raise Refused("refused")
        w = csv.writer(fh, delimiter=delimiter, lineterminator="\n")
        for row in rows:
            w.writerow([self.scrubber.scrub(c) for c in row])

    def _text(self, text, fh):
        for line in text.splitlines(keepends=True):
            fh.write(self.scrubber.scrub(line))
