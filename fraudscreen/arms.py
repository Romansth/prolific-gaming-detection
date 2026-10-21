"""Configuration-hash prefix -> arm name, from a snapshot made in the AI-extension-testing repo."""
import json
from collections import Counter
from pathlib import Path

PACKAGED = Path(__file__).resolve().parent / "arms.json"


def load_arms(path=None):
    p = Path(path) if path else PACKAGED
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except ValueError:
        return {}


def arm_for(hash_prefix, arms):
    if not hash_prefix:
        return None
    for h, name in arms.items():
        if h.startswith(hash_prefix) or hash_prefix.startswith(h):
            return name.split("@")[0]
    return None


def participant_arm(p, arms):
    c = Counter()
    for inst in p["installs"]:
        for k, n in inst.get("chash", {}).items():
            c[k] += n
    if not c:
        return ""
    top = c.most_common(1)[0][0]
    return arm_for(top, arms) or ("?" + top)
