"""
Feed API keys — set once, kept out of git.

Two requirements pull against each other: the operator should enter a key
once rather than after every restart, and the key must never end up in a
commit. So keys live in a single gitignored file outside the tracked tree of
source, and the loader refuses to read a key file that git can see.

This is not encryption at rest. Anything that can read the file can read the
keys, and a key stored on disk is a key that can be stolen from disk. What it
does buy is the thing actually asked for: no re-entry, and no accidental
push. Revoking a leaked feed key is free and takes a minute, which is the
right threat model for a free-tier read-only API key.
"""
import json
import os
import stat
import subprocess
from pathlib import Path

KEY_FILE = Path(__file__).parent.parent / "config" / "intel_keys.json"

# Where an operator gets each one. All free; the abuse.ch key covers two.
SIGNUP = {
    "abusech": ("https://auth.abuse.ch/",
                "One key for URLhaus + ThreatFox. Best malware-distribution "
                "coverage. Start here."),
    "virustotal": ("https://www.virustotal.com/gui/join-us",
                   "70+ engines. 4 requests/min, 500/day."),
    "otx": ("https://otx.alienvault.com/api",
            "AlienVault OTX. Generous limits, good campaign context."),
    "urlscan": ("https://urlscan.io/user/signup",
                "URLScan.io. 100 searches/day free, rich page-level detail."),
    "safebrowsing": ("https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com",
                     "Google Safe Browsing. 10,000 requests/day free — the "
                     "most generous quota of the set."),
}


def _is_git_tracked(path: Path) -> bool:
    """True if git can see this file — in which case it must not hold keys.

    git check-ignore exit codes: 0 = ignored, 1 = NOT ignored, 128 = not a
    repository. Only 1 is dangerous. Treating every non-zero as dangerous
    means refusing to store keys anywhere outside a git repo, which is both
    wrong and the opposite of the point.
    """
    # Absolute, or a relative path gets resolved against cwd and silently
    # checks the wrong file — 'config/keys.json' from inside 'config/' asks
    # git about 'config/config/keys.json', which is ignored by nothing.
    target = path.resolve()
    try:
        proc = subprocess.run(
            ["git", "check-ignore", "-q", str(target)],
            cwd=str(target.parent), capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False        # no git available; nothing to leak into
    return proc.returncode == 1


def load(path: Path = None) -> dict:
    """Read stored keys. Returns {} when none are set."""
    path = Path(path or KEY_FILE)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {k: v for k, v in data.items() if isinstance(v, str) and v.strip()}
    except (ValueError, OSError):
        return {}


def save(keys: dict, path: Path = None) -> tuple:
    """Persist keys. Returns (ok, message).

    Refuses to write a file git is not ignoring, because a key written into a
    tracked path is a key that gets pushed.
    """
    path = Path(path or KEY_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)

    if _is_git_tracked(path):
        return False, (f"refusing to write keys to {path.name}: git is not "
                       f"ignoring it. Add 'config/intel_keys.json' to "
                       f".gitignore first.")

    existing = load(path)
    existing.update({k: v.strip() for k, v in keys.items() if v and v.strip()})
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    # Best effort on POSIX; Windows ACLs are not managed here.
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return True, f"{len(existing)} key(s) stored in {path.name}"


def remove(provider: str, path: Path = None) -> bool:
    path = Path(path or KEY_FILE)
    keys = load(path)
    if provider not in keys:
        return False
    del keys[provider]
    path.write_text(json.dumps(keys, indent=2), encoding="utf-8")
    return True


def status(path: Path = None) -> dict:
    """What is configured and what is still missing, with where to get it."""
    keys = load(path)
    out = {}
    for name, (url, note) in SIGNUP.items():
        out[name] = {"configured": bool(keys.get(name)), "url": url,
                     "note": note}
    return out


def expand(keys: dict) -> dict:
    """Map stored keys onto provider names.

    abuse.ch issues one key that authenticates both URLhaus and ThreatFox, so
    the operator enters it once rather than twice.
    """
    resolved = dict(keys)
    shared = keys.get("abusech")
    if shared:
        resolved.setdefault("urlhaus", shared)
        resolved.setdefault("threatfox", shared)
    return resolved
