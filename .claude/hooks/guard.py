#!/usr/bin/env python3
"""PreToolUse guard for the data boundary.

The folders holding real participant ids sit inside this repo (raw-data/, reports-team/ and the
key folder raw-data/.redaction/), so two things are refused:

1. any tool call that names one of those folders;
2. any call that reads recursively from the repo root or from an unnamed location, since a
   `find .`, `grep -r`, `rg <pattern>`, `ls -R`, `**` glob or `os.walk('.')` would reach them.
   Recursive reads must be scoped to a folder: data-redacted/, reports/, fraudscreen/, privacy/,
   tests/, tools/, docs/ or .claude/.

Exit 2 blocks the call and the message on stderr tells the agent what to do instead; exit 0 lets it
through. Only accidental reach is in scope; obfuscated commands are a policy matter, not a hook's.
Claude Code runs it from .claude/settings.json, Codex from .codex/hooks.json; both send the same
payload fields (tool_name, tool_input, cwd), and Codex reports shell calls as tool_name "Bash".
"""
import json
import os
import re
import shlex
import sys

PRIVATE = re.compile(r"raw-data|reports-team|\.redaction|user_data_raw", re.I)
ALLOWED_ROOTS = ("data-redacted", "reports", "fraudscreen", "privacy", "tests", "tools", "docs", ".claude", ".codex",
                 ".superpowers", ".git", ".venv")
RECURSIVE = {"find", "rg", "tree", "du", "fd", "ag", "ack", "locate", "mdfind", "ugrep"}
READERS = {"cat", "head", "tail", "less", "more", "wc", "cp", "mv", "zip", "tar", "unzip", "sort", "uniq", "cut",
           "awk", "sed", "python", "python3", "jq", "diff", "md5", "md5sum", "shasum", "open", "file", "strings"}
GREP = {"grep", "egrep", "fgrep", "zgrep"}
# flags that take a value, per command family, so the value is not read as a path
_SEARCH_FLAGS = {"-e", "-f", "-g", "-t", "-T", "-m", "-A", "-B", "-C", "-j", "-d", "--type", "--glob", "--iglob",
                 "--max-depth", "--max-count", "--regexp", "--file", "--depth", "--include", "--exclude"}
VALUE_FLAGS = {"grep": _SEARCH_FLAGS, "egrep": _SEARCH_FLAGS, "fgrep": _SEARCH_FLAGS, "zgrep": _SEARCH_FLAGS,
               "rg": _SEARCH_FLAGS, "ag": _SEARCH_FLAGS, "ack": _SEARCH_FLAGS, "ugrep": _SEARCH_FLAGS,
               "python": {"-c", "-m", "-W", "-X"}, "python3": {"-c", "-m", "-W", "-X"},
               "head": {"-n", "-c"}, "tail": {"-n", "-c"}, "sed": {"-e", "-f"}, "awk": {"-f", "-v", "-F"},
               "tar": {"-f", "-C"}, "zip": {"-x", "-i"}, "cut": {"-d", "-f", "-c"}, "sort": {"-k", "-t"}}
WIDE_WORDS = {".", "./", "..", "../", "~", "/", "*", "./*", "$PWD", "${PWD}", "$HOME", "${HOME}",
              "$CLAUDE_PROJECT_DIR", "${CLAUDE_PROJECT_DIR}"}
WALK_RE = re.compile(r"os\.walk\(|\.rglob\(|glob\.glob\(|glob\.iglob\(|os\.listdir\(|os\.scandir\(|\.iterdir\(|Path\.cwd\(\)|Path\(\s*['\"]\.{1,2}/?['\"]\s*\)")
SEGMENT_RE = re.compile(r"\|\||&&|[|;\n]")

MESSAGE = ("Blocked: raw-data/, reports-team/ and .redaction/ hold real participant ids and are out of bounds. "
           "Work from data-redacted/ and reports/; use 'python3 -m fraudscreen.lookup <id>' to turn an id into its token.")
SCOPE_MESSAGE = ("Blocked: a recursive or wildcard read from the repo root would reach raw-data/ and reports-team/. "
                 "Name the folder: data-redacted/<pull>, reports/, fraudscreen/, privacy/, tests/, tools/ or docs/.")


def block(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)


def wide(arg, cwd):
    """True when a path argument reaches outside the allowed folders."""
    a = arg.strip("'\"")
    if not a or a in WIDE_WORDS or a.startswith(("$", "~/", "../", "./*")):
        return True
    if "**" in a:
        return True
    parts = a.replace("\\", "/").split("/")
    if a.startswith("/"):
        root = cwd.replace("\\", "/").rstrip("/")
        if not a.startswith(root + "/"):
            return True
        parts = a[len(root) + 1:].split("/")
    if any("*" in part or "?" in part for part in parts[:-1]):
        return True
    first = parts[0]
    if first in ALLOWED_ROOTS:
        return False
    if "*" in first or "?" in first:
        return len(parts) > 1
    if len(parts) == 1:
        return os.path.isdir(os.path.join(cwd, first))
    return True


def words(segment):
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def path_args(cmd, argv):
    """Arguments that name files or folders, skipping flags, flag values and the grep/rg pattern."""
    out, skip, pattern_taken = [], False, cmd not in GREP | {"rg", "ag", "ack", "ugrep"}
    value_flags = VALUE_FLAGS.get(cmd, set())
    for a in argv[1:]:
        if skip:
            skip = False
            continue
        if a.startswith("-") and a != "-":
            if a in value_flags:
                skip = True
                if a in ("-e", "--regexp", "-f", "--file") and not pattern_taken:
                    pattern_taken = True
            continue
        if cmd == "find" and a in ("(", "!"):
            break
        if not pattern_taken:
            pattern_taken = True
            continue
        out.append(a)
    return out


def check_segment(segment, cwd):
    argv = words(segment)
    while argv and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]) or argv[0] in ("sudo", "nice", "time", "command", "exec", "caffeinate")):
        argv = argv[1:]
    if not argv:
        return
    cmd = os.path.basename(argv[0])
    flags = [a for a in argv[1:] if a.startswith("-")]
    recursive = cmd in RECURSIVE
    if cmd in GREP and any(f in ("-r", "-R", "--recursive", "--dereference-recursive") or (f.startswith("-") and not f.startswith("--") and ("r" in f or "R" in f)) for f in flags):
        recursive = True
    if cmd == "ls" and any(f == "--recursive" or (f.startswith("-") and not f.startswith("--") and "R" in f) for f in flags):
        recursive = True
    paths = path_args(cmd, argv)
    if recursive:
        if cmd == "find":
            paths = []
            for a in argv[1:]:
                if a.startswith(("-", "(", "!")):
                    break
                paths.append(a)
        if not paths or any(wide(a, cwd) for a in paths):
            block(SCOPE_MESSAGE)
    elif cmd in READERS or cmd in GREP or cmd == "ls":
        if any(wide(a, cwd) for a in paths if "*" in a or a.startswith(("$", "~"))):
            block(SCOPE_MESSAGE)
    if WALK_RE.search(segment) and not re.search(r"data-redacted|reports/|fraudscreen|privacy|tests", segment):
        block(SCOPE_MESSAGE)


def main():
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return
    text = json.dumps(payload)
    if PRIVATE.search(text):
        block(MESSAGE)
    tool = payload.get("tool_name", "")
    inp = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()
    if tool == "Bash":
        for segment in SEGMENT_RE.split(inp.get("command", "") or ""):
            if segment.strip():
                check_segment(segment.strip(), cwd)
    elif tool in ("Grep", "Glob"):
        path = inp.get("path") or ""
        if not path or wide(path, cwd):
            block(SCOPE_MESSAGE)


if __name__ == "__main__":
    main()
