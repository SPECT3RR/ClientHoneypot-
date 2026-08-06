"""
Rename the vendored service library so nothing on disk names it.

Runs once, inside the image build (docker/Dockerfile.honeypots).

WHY NOT SED
-----------
The obvious `sed -i "s/\\bhoneypots\\b/filesync/g"` misses more than it
catches, and each miss is a filename or identifier an attacker can grep for:

    HoneypotsManager        capitalised, so a lowercase pattern skips it
    _set_up_honeypots       underscore is a word character, so \\b never
    running_honeypots       matches at the start of the name
    HONEYPOT_MODE           case again

So the replacement is a plain ordered substring pass with no word boundaries
at all. Longest and most specific first, because "honeypots" contains
"honeypot" and replacing the singular first would leave a stray "s".

The singular becomes `filesvc` rather than something readable like `service`:
__main__.py already binds a local named `service`, and colliding with it
inside one scope would turn a cosmetic change into a real bug.

ONE REPLACEMENT MUST NOT BE MISSED
----------------------------------
The library looks up its own config section with a string literal, so that
key is renamed along with everything else. src/decoy_services.CONFIG_SECTION
has to match. When it did not, the section was simply not found: every
service fell back to a RANDOM high port, the listeners came up, the log said
"Everything looks good!", and nothing answered on 22 or 21. The Dockerfile
asserts the key afterwards so that failure can never be silent again.
"""
import sys
from pathlib import Path

# Ordered. Plural before singular; capitalised forms explicitly.
def replacements(pkg: str) -> list:
    svc = "filesvc"
    return [
        ("HONEYPOTS", pkg.upper()), ("Honeypots", pkg.capitalize()),
        ("honeypots", pkg),
        ("HONEYPOT", svc.upper()), ("Honeypot", svc.capitalize()),
        ("honeypot", svc),
        ("QEEQBOX", pkg.upper()), ("Qeeqbox", pkg.capitalize()),
        ("qeeqbox", pkg),
    ]


def rewrite(root: Path, pkg: str) -> tuple:
    pairs = replacements(pkg)
    files = changed = 0

    # Bytecode caches are deleted, not rewritten: a .pyc holds the constants
    # compiled from the original source. Python regenerates them from the
    # renamed sources on first import, so the copies it writes are clean.
    for cache in root.rglob("__pycache__"):
        for pyc in cache.glob("*.pyc"):
            pyc.unlink()
        cache.rmdir()

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue        # binary asset; nothing to rename in it
        files += 1
        new = text
        for old, replacement in pairs:
            new = new.replace(old, replacement)
        if new != text:
            path.write_text(new, encoding="utf-8")
            changed += 1

    # Paths can name it too.
    for path in sorted(root.rglob("*"), key=lambda p: -len(p.parts)):
        low = path.name.lower()
        if "honeypot" in low or "qeeqbox" in low:
            new_name = path.name
            for old, replacement in pairs:
                new_name = new_name.replace(old, replacement)
            path.rename(path.with_name(new_name))

    return files, changed


if __name__ == "__main__":
    root, pkg = Path(sys.argv[1]), sys.argv[2]
    files, changed = rewrite(root, pkg)
    print(f"vendor_rename: {changed}/{files} files rewritten under {root}")

    leftover = []
    for path in root.rglob("*"):
        if path.is_file():
            try:
                if ("honeypot" in path.read_text(encoding="utf-8").lower()
                        or "qeeqbox" in path.read_text(encoding="utf-8").lower()):
                    leftover.append(str(path))
            except (UnicodeDecodeError, OSError):
                continue
    if leftover:
        print("vendor_rename: STILL NAMED: " + ", ".join(leftover[:5]))
        raise SystemExit(1)
    print("vendor_rename: nothing under the package names the original")
