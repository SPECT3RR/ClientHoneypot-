"""
Covert sample capture — copy an attacker's payload without them knowing.

THE REQUIREMENT
---------------
When an exploit kit, dropper, webshell or plain executable lands on a decoy,
keep a copy: it is the attacker's own tool, in our hands, and it is the single
most valuable artefact the platform produces after a fired canary. The catch
is that the attacker must never learn the copy was taken -- no process they can
see in `ps`, no file appearing under them, no outbound connection, nothing
written into their container at all.

WHY THIS IS DONE ENTIRELY FROM THE HOST
---------------------------------------
The same boundary the telemetry collector uses (see decoy_telemetry). Docker's
control plane runs in the daemon, on the far side of the container's
namespaces:

    docker diff <container>       lists files written to the writable layer,
                                  computed on the host -- invisible inside
    docker cp <container>:<p> -   streams the file OUT as a tar to our stdout,
                                  no process spawned in the container

So the capture reads the container's filesystem and pulls bytes out without
ever entering it. From inside the decoy there is no watcher process, no inotify
hook, no mount, and nothing new on disk. An attacker who greps their whole
container finds no evidence a copy was taken, because the copy happened in a
namespace they cannot see. `docker exec` is never used -- that WOULD spawn a
visible process -- which is why everything here goes through diff and cp.

Covert means covert from the ATTACKER. The operator sees every capture on the
dashboard and in the SIEM; that is the whole point of keeping the sample.

STORED DEFANGED, NEVER RAW
--------------------------
The operator's rule is "do not get my system infected." A captured sample is
real malware, so it is never written to disk in runnable form. The bytes are
XOR-defanged on the way in: the copy on disk has no valid executable header,
matches no AV signature, and cannot be run by accident. `unpack()` reverses it
deliberately when an analyst wants the original inside a sandbox.

    ponytail: XOR is a defang, not encryption. The goal is "inert and
    un-runnable on disk", not confidentiality, and XOR is the standard tool
    for exactly that. If the sample store ever needs to be secret, wrap it.
"""
import hashlib
import io
import json
import subprocess
import tarfile
import threading
import time
from pathlib import Path

SAMPLE_DIR = Path(__file__).parent.parent / "telemetry" / "samples"
MANIFEST = SAMPLE_DIR / "manifest.jsonl"

# Do not pull these out to classify them -- they are the decoy's own churn and
# the kernel's virtual filesystems, never an attacker's payload. Everything
# else is pulled and classified by content, so a renamed executable is still
# caught. /tmp/tmp matches Python's tempfile names (qeeqbox's noise); a file an
# attacker names /tmp/evil does not match and is inspected.
NOISE_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/tmp/tmp",
                  "/var/log", "/var/lib/filesync", "/etc/filesyncd",
                  "/usr/sbin/filesyncd", "/.dockerenv")

# Never pull a file larger than this: a decoy sitting on a machine with ~1 GB
# free must not try to copy a 2 GB blob out. A payload that large is logged as
# skipped rather than captured.
MAX_SAMPLE_BYTES = 32 * 1024 * 1024

POLL_SECONDS = 5

# Defang key. Repeated over the payload. Not a secret; see the module note.
_DEFANG_KEY = b"CHP-QUARANTINE-DEFANG-v1"


# ── classification ───────────────────────────────────────────────────────────

# First bytes -> kind. Longest signatures first so a prefix cannot shadow a
# longer one.
_MAGIC = [
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),    # msi / legacy office
    (b"7z\xbc\xaf\x27\x1c",               "7z"),
    (b"\xcf\xfa\xed\xfe",                 "macho"),
    (b"\xca\xfe\xba\xbe",                 "macho"),   # fat binary
    (b"\x7fELF",                          "elf"),
    (b"PK\x03\x04",                       "zip"),     # jar / office / apk
    (b"%PDF",                             "pdf"),
    (b"Rar!",                             "rar"),
    (b"\x1f\x8b",                         "gzip"),
    (b"MZ",                               "pe"),      # exe / dll
    (b"#!",                               "script"),
]

# Text droppers and webshells often have no magic. A conservative token scan of
# the head catches the loud ones without flagging ordinary config text.
_SCRIPT_TOKENS = (b"powershell", b"invoke-expression", b"iex(", b"cmd.exe",
                  b"/bin/sh", b"/bin/bash", b"base64 -d", b"eval(",
                  b"<?php", b"system(", b"wscript.shell", b"frombase64string")


def classify(head: bytes) -> str:
    """Kind of payload from its leading bytes, or None if it is not one."""
    for sig, kind in _MAGIC:
        if head.startswith(sig):
            return kind
    low = head[:512].lower()
    if any(tok in low for tok in _SCRIPT_TOKENS):
        return "script"
    return None


# ── defanged store ───────────────────────────────────────────────────────────

def _xor(data: bytes) -> bytes:
    key = _DEFANG_KEY
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def docker_cp_file(container: str, path: str,
                   max_bytes: int = MAX_SAMPLE_BYTES) -> tuple:
    """Stream one file out of a container as a tar and return (bytes, error).

    `docker cp <c>:<path> -` writes a tar to stdout from the daemon; no process
    is created inside the container. When `path` is a directory the tar is the
    whole tree, so only the member whose name is the file we asked for is
    returned. Shared by the sample collector and the Cowrie ingest.
    """
    try:
        out = subprocess.run(["docker", "cp", f"{container}:{path}", "-"],
                             capture_output=True, timeout=60)
    except Exception as e:
        return None, f"cp {container}:{path}: {e}"
    if out.returncode != 0 or not out.stdout:
        return None, None
    base = path.rstrip("/").rsplit("/", 1)[-1]
    try:
        with tarfile.open(fileobj=io.BytesIO(out.stdout)) as tar:
            member = next((m for m in tar.getmembers()
                           if m.name == base and m.isfile()), None)
            if member is None:
                return None, None            # a directory or symlink, not a file
            if member.size > max_bytes:
                return None, f"{container}:{path} is {member.size} bytes, over cap"
            f = tar.extractfile(member)
            return (f.read() if f else None), None
    except tarfile.TarError as e:
        return None, f"untar {container}:{path}: {e}"


class SampleStore:
    """Where captured payloads live, defanged, on the host only."""

    def __init__(self, directory: Path = SAMPLE_DIR):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest = self.dir / "manifest.jsonl"
        self._seen = self._load_seen()

    def _load_seen(self) -> set:
        if not self.manifest.exists():
            return set()
        seen = set()
        for line in self.manifest.read_text(encoding="utf-8").splitlines():
            try:
                seen.add(json.loads(line)["sha256"])
            except (ValueError, KeyError):
                continue
        return seen

    def has(self, sha256: str) -> bool:
        return sha256 in self._seen

    def store(self, data: bytes, meta: dict) -> dict:
        """Defang and persist. Returns the manifest record."""
        sha = hashlib.sha256(data).hexdigest()
        record = {
            "sha256": sha,
            "size": len(data),
            "captured_ts": time.time(),
            **meta,
        }
        # .quar, not .exe: the bytes on disk are XOR'd, so nothing here is a
        # valid executable and nothing can run it.
        (self.dir / f"{sha}.quar").write_bytes(_xor(data))
        with open(self.manifest, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
        self._seen.add(sha)
        return record

    def unpack(self, sha256: str) -> bytes:
        """Reverse the defang for deliberate analysis in a sandbox."""
        return _xor((self.dir / f"{sha256}.quar").read_bytes())

    def records(self, limit: int = 100) -> list:
        if not self.manifest.exists():
            return []
        rows = [json.loads(l) for l in
                self.manifest.read_text(encoding="utf-8").splitlines() if l.strip()]
        return rows[-limit:][::-1]


# ── the collector ─────────────────────────────────────────────────────────────

class SampleCollector:
    """Watches container writable layers from the host and captures payloads.

    Runs on the host, never in a container, and never runs a process inside
    one. Giving a container the Docker socket so it could do this itself would
    hand any escape control of the daemon -- a far worse hole than the one this
    closes.
    """

    def __init__(self, exporter=None, store: SampleStore = None,
                 containers=None, poll=POLL_SECONDS):
        self.exporter = exporter
        self.store = store or SampleStore()
        self.containers = list(containers or ())
        self.poll = poll
        self.captured = 0
        self.skipped_large = 0
        self.errors = []
        # Per-container paths already inspected and found uninteresting, so the
        # same noise file is not pulled every poll.
        self._rejected = {}
        self._stop = threading.Event()
        self._thread = None

    # -- host-side primitives (diff + cp, never exec) ------------------------

    def _diff(self, container: str) -> list:
        try:
            out = subprocess.run(["docker", "diff", container],
                                 capture_output=True, text=True, timeout=30)
        except Exception as e:
            self.errors.append(f"diff {container}: {e}")
            return []
        paths = []
        for line in out.stdout.splitlines():
            if len(line) < 3 or line[0] not in ("A", "C"):
                continue          # A added, C changed; D deleted is uninteresting
            paths.append(line[2:])
        return paths

    def _pull(self, container: str, path: str) -> bytes:
        """Stream one file out as a tar and return its bytes, or None."""
        data, err = docker_cp_file(container, path)
        if err:
            if "over cap" in err:
                self.skipped_large += 1
            self.errors.append(err)
        return data

    # -- per-container pass --------------------------------------------------

    def _is_noise(self, path: str) -> bool:
        return path.startswith(NOISE_PREFIXES)

    def scan(self, container: str, session_id: str = None) -> list:
        """One pass over a container. Returns records for anything captured."""
        rejected = self._rejected.setdefault(container, set())
        captured = []
        for path in self._diff(container):
            if path in rejected or self._is_noise(path):
                continue
            data = self._pull(container, path)
            if not data:
                rejected.add(path)
                continue
            kind = classify(data[:1024])
            if kind is None:
                # Not a payload -- do not keep it, and do not pull it again.
                rejected.add(path)
                continue
            sha = hashlib.sha256(data).hexdigest()
            if self.store.has(sha):
                rejected.add(path)      # already have this exact file
                continue

            record = self.store.store(data, {
                "container": container,
                "path": path,
                "kind": kind,
                "session_id": session_id or container,
                "magic": data[:4].hex(),
            })
            captured.append(record)
            self.captured += 1
            self._ship(record)
        return captured

    def _ship(self, record: dict) -> None:
        if not self.exporter:
            return
        try:
            self.exporter.sample(
                record["sha256"], record["size"], record["kind"],
                record["container"], record["path"],
                session_id=record.get("session_id"), magic=record.get("magic"))
        except Exception as e:
            self.errors.append(f"ship {record['sha256'][:12]}: {e}")

    # -- lifecycle -----------------------------------------------------------

    def _loop(self):
        while not self._stop.is_set():
            for container in list(self.containers):
                if self._stop.is_set():
                    break
                self.scan(container)
            self._stop.wait(self.poll)

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="sample-capture")
        self._thread.start()
        return self._thread

    def stop(self):
        self._stop.set()

    def status(self) -> dict:
        return {"containers": self.containers, "captured": self.captured,
                "skipped_large": self.skipped_large, "errors": self.errors[-5:]}


def running_containers() -> list:
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                             capture_output=True, text=True, timeout=20)
        return [n for n in out.stdout.split() if n]
    except Exception:
        return []


def main(argv=None) -> int:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    import siem
    argv = list(argv if argv is not None else sys.argv[1:])
    names = [a for a in argv if not a.startswith("-")]

    live = running_containers()
    watching = [c for c in (names or live) if c in live]
    if not watching:
        print("[samples] nothing to watch")
        return 1

    collector = SampleCollector(exporter=siem.SiemExporter(mode="jsonl"),
                                containers=watching)
    print(f"[samples] watching {', '.join(watching)} from the host")
    print(f"[samples] captures -> {collector.store.dir} (defanged)")
    print("[samples] nothing runs inside the decoy; ctrl-c to stop")
    collector.start()
    try:
        while True:
            time.sleep(30)
            s = collector.status()
            print(f"[samples] captured={s['captured']} "
                  f"skipped_large={s['skipped_large']}")
    except KeyboardInterrupt:
        collector.stop()
        print(f"\n[samples] {json.dumps(collector.status(), default=str)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
