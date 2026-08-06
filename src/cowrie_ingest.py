"""
Covert ingest for the Cowrie shell decoy.

Cowrie gives the attacker a real emulated shell and, when they wget/curl/scp a
payload, SAVES the file by sha256 and logs a structured event tying it to the
command and the session. This turns those into the platform's own findings —
without the attacker learning anything is watching.

SAME HOST-SIDE BOUNDARY AS EVERYTHING ELSE
------------------------------------------
Cowrie writes JSON events to a file inside its container and saved payloads to
a downloads directory. Both are read from the HOST with `docker cp <c>:<p> -`
(a tar to our stdout, run in the daemon) — never `docker exec`, never a mount,
never a process inside the decoy. So from the attacker's emulated shell there
is no agent, no watcher, and no sign the session or the file they dropped was
copied. Cowrie already logs to its own file; we just read that file from
outside its namespace.

WHAT IS SHIPPED
---------------
  connect            -> decoy.connect              (reconnaissance)
  login.success      -> decoy.planted_cred if the password is bait we seeded,
                        else decoy.login_success    (exploitation)
  login.failed       -> decoy.login_failed          (exploitation)
  command.input      -> decoy.command               (exploitation)
  file_upload /      -> the saved payload is pulled out, defanged, stored, and
  file_download         shipped as a sample          (installation)

A wget whose fetch could not leave the internal network still arrives as a
command with the URL in it — the payload URL is intelligence even when the
file itself never lands.
"""
import hashlib
import json
import subprocess
import threading
import time
from pathlib import Path

from sample_capture import SampleStore, docker_cp_file, classify

CONTAINER = "decoy_shell"
LOG_PATH = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
DOWNLOADS = "/cowrie/cowrie-git/var/lib/cowrie/downloads"

# The log is small for a decoy, but cap the pull so a wildly rotated file
# cannot blow up memory.
LOG_MAX_BYTES = 64 * 1024 * 1024
POLL_SECONDS = 5


def match_planted(vault, password: str):
    """A login password that is character-for-character a credential we seeded
    can only have come from bait the attacker exfiltrated."""
    if vault is None or not password:
        return None
    for token in vault.all():
        if token.get("placement") == "decoy_services" and \
                token.get("value") == password:
            return token
    return None


class CowrieCollector:
    def __init__(self, exporter, store: SampleStore = None, vault=None,
                 container: str = CONTAINER, poll: int = POLL_SECONDS):
        self.exporter = exporter
        self.store = store or SampleStore()
        self.vault = vault
        self.container = container
        self.poll = poll
        self.events = 0
        self.captured = 0
        self.errors = []
        self._seen = set()          # line hashes already processed
        self._stop = threading.Event()
        self._thread = None

    # -- host-side read (cp only, never exec) --------------------------------

    def scan(self) -> int:
        data, err = docker_cp_file(self.container, LOG_PATH,
                                   max_bytes=LOG_MAX_BYTES)
        if err:
            self.errors.append(err)
        if not data:
            return 0
        handled = 0
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            h = hashlib.blake2b(line, digest_size=16).digest()
            if h in self._seen:
                continue            # already processed (poll re-reads the file)
            self._seen.add(h)
            try:
                event = json.loads(line)
            except ValueError:
                continue
            self._handle(event)
            handled += 1
        # The decoy log is small; still, do not let the dedup set grow forever.
        if len(self._seen) > 20000:
            self._seen = set(list(self._seen)[-10000:])
        return handled

    # -- event -> finding ----------------------------------------------------

    def _handle(self, e: dict) -> None:
        eid = e.get("eventid", "")
        session = e.get("session")
        src_ip = e.get("src_ip")
        self.events += 1

        if eid == "cowrie.session.connect":
            self.exporter.decoy_activity({"server": "shell", "action": "connection",
                                          "src_ip": src_ip})
        elif eid == "cowrie.login.success":
            planted = match_planted(self.vault, e.get("password"))
            if planted is not None:
                try:
                    self.vault.record_hit(
                        planted["token_id"], src_ip=src_ip,
                        user_agent="ssh shell login",
                        detail={"service": "ssh", "username": e.get("username"),
                                "collected": "out-of-band"})
                except Exception as ex:
                    self.errors.append(f"vault: {ex}")
                self.exporter.decoy_activity(
                    {"server": "shell", "action": "login", "src_ip": src_ip,
                     "username": e.get("username"), "password": e.get("password"),
                     "status": "success"}, planted=planted)
            else:
                self.exporter.decoy_activity(
                    {"server": "shell", "action": "login", "src_ip": src_ip,
                     "username": e.get("username"), "password": e.get("password"),
                     "status": "success"})
        elif eid == "cowrie.login.failed":
            self.exporter.decoy_activity(
                {"server": "shell", "action": "login", "src_ip": src_ip,
                 "username": e.get("username"), "password": e.get("password"),
                 "status": "failed"})
        elif eid == "cowrie.command.input":
            self.exporter.decoy_activity(
                {"server": "shell", "action": "command", "src_ip": src_ip,
                 "data": {"cmd": e.get("input", "")}})
        elif eid in ("cowrie.session.file_upload", "cowrie.session.file_download"):
            self._capture(e, session, src_ip)

    def _capture(self, e: dict, session, src_ip) -> None:
        shasum = e.get("shasum")
        if not shasum:
            return                   # a fetch that never landed; the URL is in
                                     # the command event already
        if self.store.has(shasum):
            return                   # already have this exact file
        data, err = docker_cp_file(self.container, f"{DOWNLOADS}/{shasum}")
        if err:
            self.errors.append(err)
        if not data:
            return
        kind = classify(data[:1024]) or "unknown"
        record = self.store.store(data, {
            "container": self.container,
            "path": e.get("outfile") or e.get("filename") or shasum,
            "kind": kind,
            "session_id": session,
            "src_ip": src_ip,
            "url": e.get("url"),
            "via": e.get("eventid", "").rsplit(".", 1)[-1],
            "magic": data[:4].hex(),
        })
        self.captured += 1
        try:
            self.exporter.sample(record["sha256"], record["size"], kind,
                                 self.container, record["path"],
                                 session_id=session, magic=record.get("magic"))
        except Exception as ex:
            self.errors.append(f"ship {shasum[:12]}: {ex}")

    # -- lifecycle -----------------------------------------------------------

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.scan()
            except Exception as e:
                self.errors.append(str(e))
            self._stop.wait(self.poll)

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="cowrie-ingest")
        self._thread.start()
        return self._thread

    def stop(self):
        self._stop.set()

    def status(self) -> dict:
        return {"container": self.container, "events": self.events,
                "captured": self.captured, "errors": self.errors[-5:]}


def is_running(container: str = CONTAINER) -> bool:
    try:
        out = subprocess.run(["docker", "inspect", container,
                              "--format", "{{.State.Running}}"],
                             capture_output=True, text=True, timeout=20)
        return out.stdout.strip().lower() == "true"
    except Exception:
        return False


def main(argv=None) -> int:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    import siem
    container = (argv or sys.argv[1:] or [CONTAINER])[0]
    if not is_running(container):
        print(f"[cowrie] {container} is not running")
        return 1
    vault = None
    try:
        from canary_vault import CanaryVault
        from verdict_db import VerdictDB
        vault = CanaryVault(VerdictDB())
    except Exception as e:
        print(f"[cowrie] no vault ({e}); planted-credential correlation off")
    col = CowrieCollector(siem.SiemExporter(mode="jsonl"), vault=vault,
                          container=container)
    print(f"[cowrie] reading {container}'s shell activity from the host")
    col.start()
    try:
        while True:
            time.sleep(30)
            s = col.status()
            print(f"[cowrie] events={s['events']} captured={s['captured']}")
    except KeyboardInterrupt:
        col.stop()
        print(f"\n[cowrie] {json.dumps(col.status(), default=str)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
