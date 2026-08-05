"""
Out-of-band decoy telemetry — shipping to Wazuh without the decoy knowing.

THE PROBLEM WITH AN AGENT
-------------------------
The obvious way to get decoy activity into Wazuh is to install wazuh-agent in
the decoy. Do that and an attacker who lands a shell runs three commands and
knows everything:

    ps aux              -> wazuh-agentd, wazuh-logcollector
    ls /var/ossec       -> the agent's whole install
    netstat -tunap      -> an ESTABLISHED session to 10.x.x.x:1514

They now know they are in a honeypot, who is watching, and where the manager
lives. They stop, or worse, they feed it lies. The agent is also a process
they can kill and a config they can read.

THE APPROACH HERE
-----------------
Nothing is installed in the decoy and nothing is mounted into it. The decoy
writes its records to stdout like any ordinary containerised service, and
Docker's json-file log driver captures them **in the daemon, on the host**.

That boundary is the entire trick. The log driver runs on the far side of the
container's namespaces, so from inside the decoy there is:

    no process           nothing appears in ps
    no listening socket  nothing appears in netstat, no port to find
    no outbound session  nothing to notice leaving, nothing to trace home
    no mount             /proc/mounts shows no collector path
    no file              nothing to tamper with, truncate, or feed false data
    no config            nothing that names a manager or an IP

An attacker can read every byte of that container and find no evidence that
anything is collecting, because inside the container there genuinely isn't.
It looks exactly like a normal service logging to stdout, which is what most
containerised software does anyway.

It is also tamper-proof in the direction that matters. Once a line is written
it is already on the host; the attacker cannot go back and edit what was
captured, because the captured copy was never in their namespace.

REACHING WAZUH
--------------
The decoy sits on an internal Docker network with no route off the host, so
it cannot reach the manager even knowing where it is. Traffic goes the other
way and is *pulled*: this collector runs on the host, reads the daemon's log
stream, and appends findings to the file a Wazuh agent tails. The decoy never
initiates anything, so there is no outbound path to follow and nothing for an
egress filter on the attacker's side to reveal.

    decoy container ──stdout──> docker daemon (host) ──> this collector
                                                              │
                                                    telemetry/siem.jsonl
                                                              │
                                                     wazuh-agent (host)
                                                              │
                                                       wazuh manager

Every arrow points away from the decoy. There is no arrow back.

A killed honeypot process is itself a finding: the stream stops, and silence
from a container that is still running ships as decoy.silent.
"""
import json
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from decoy_services import parse_log_line

# Containers whose stdout is decoy activity. Names, not IDs, so a rebuilt
# container is picked up without reconfiguration.
DEFAULT_CONTAINERS = ("decoy_svc", "decoy")

# Records qeeqbox emits about itself. Shipping these tells a SIEM operator
# nothing and buries the logins that matter.
NOISE_ACTIONS = {"process", "stats", "system", "listening", "starting"}


def is_activity(record: dict) -> bool:
    """True if this record describes something a visitor did.

    qeeqbox interleaves its own lifecycle and stats lines with real events on
    the same stream. Only visitor-caused records are findings.
    """
    if not record or not isinstance(record, dict):
        return False
    if str(record.get("action", "")).lower() in NOISE_ACTIONS:
        return False
    if str(record.get("server", "")).lower() in ("system", ""):
        return False
    # Something a remote party did always carries where it came from.
    return bool(record.get("src_ip"))


def match_planted(vault, record: dict):
    """Resolve a captured credential back to the canary that planted it.

    Matching on the password alone is deliberate: the attacker controls the
    username field and often mangles it, but a password that is character-for
    -character one of ours can only have come from bait we seeded.
    """
    if vault is None:
        return None
    password = str(record.get("password") or "")
    if not password:
        return None
    for token in vault.all():
        if token.get("placement") != "decoy_services":
            continue
        if token.get("value") and token["value"] == password:
            return token
    return None


class DecoyCollector:
    """Reads decoy stdout from the host side and ships findings.

    Runs on the host, never in a container. Giving a container the Docker
    socket to do this would hand any escape full control of the daemon, which
    is a far worse hole than the one it closes.
    """

    def __init__(self, exporter, vault=None, containers=None, db=None):
        self.exporter = exporter
        self.vault = vault
        self.containers = list(containers or DEFAULT_CONTAINERS)
        self.db = db          # Telemetry factory: db(session_id) -> Telemetry
        self.seen = 0
        self.shipped = 0
        self.errors = []
        self._threads = []
        self._stop = threading.Event()

    # ── the stream ─────────────────────────────────────────────────────────

    def _stream(self, container: str):
        """`docker logs --follow` for one container until told to stop."""
        proc = subprocess.Popen(
            ["docker", "logs", "--follow", "--tail", "0", container],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1)
        try:
            for line in proc.stdout:
                if self._stop.is_set():
                    break
                self.handle(line, container)
        finally:
            proc.kill()

        if self._stop.is_set():
            return
        # The stream ended while we still wanted it. Whether that is a finding
        # depends entirely on the container: if it is gone, something stopped
        # our decoy and a human should know. If it is still running we simply
        # lost the stream -- a docker hiccup, or our own process being killed
        # without the signal handler getting a turn, which is what happens on
        # Windows. Alerting on that ships a false level-6 every restart, and a
        # rule that cries wolf gets muted, taking the real alert with it.
        if is_running(container):
            self.errors.append(f"{container}: stream ended but container is up")
            return
        self.exporter.decoy_silent(container, "container is no longer running")

    def handle(self, line: str, container: str = None) -> dict:
        """One raw stdout line -> zero or one shipped finding."""
        record = parse_log_line(line)
        if not is_activity(record):
            return None
        self.seen += 1

        if record.get("server") == "web_decoy":
            return self._web(record)

        planted = match_planted(self.vault, record)
        if planted is not None and self.vault is not None:
            # Record the hit in the vault too, so the dashboard's canary view
            # and the SIEM agree on what fired.
            try:
                self.vault.record_hit(
                    planted["token_id"],
                    src_ip=record.get("src_ip"),
                    user_agent=f"{record.get('server', 'service')} login",
                    detail={"service": record.get("server"),
                            "username": record.get("username"),
                            "collected": "out-of-band"})
            except Exception as e:
                self.errors.append(f"vault: {e}")

        event = self.exporter.decoy_activity(record, planted=planted)
        if event is not None:
            self.shipped += 1
        return event

    def _web(self, record: dict) -> dict:
        """A record from the web decoy.

        Also re-recorded into the host telemetry database. The decoy's own
        write goes to its container layer, which is discarded, so without this
        the dashboard would lose the decoy view entirely -- the price of
        removing the mount, paid here rather than by keeping the mount.
        """
        detail = record.get("detail") or {}
        session_id = record.get("session_id")
        action = record.get("action")

        if self.db is not None:
            try:
                # Telemetry binds its session at construction, so one per
                # record, exactly as the decoy itself does.
                t = self.db(session_id or "unknown_session")
                t.log(action, detail)
                t.close()
            except Exception as e:
                self.errors.append(f"db: {e}")

        self.shipped += 1
        if action == "canary_hit":
            # The decoy reports the token id; the vault lives here, on the
            # host, and resolves it to what was planted and in which session.
            token_id = detail.get("token_id")
            hit = {}
            if self.vault is not None and token_id:
                try:
                    hit = self.vault.record_hit(
                        token_id, src_ip=record.get("src_ip"),
                        user_agent=record.get("user_agent"),
                        detail={"referer": detail.get("referer"),
                                "collected": "out-of-band"}) or {}
                except Exception as e:
                    self.errors.append(f"vault: {e}")
            # An unrecognised token id still ships. Someone fetching a canary
            # path we do not know is either scanning us or holding bait from a
            # run whose records are gone; both are worth a look.
            return self.exporter.canary(
                token_id, hit.get("kind") or "unknown",
                record.get("src_ip"),
                hit.get("origin_session") or session_id,
                placement=hit.get("placement"),
                user_agent=record.get("user_agent"))
        if action == "honeytoken_access":
            return self.exporter.honeytoken(
                detail.get("filename") or record.get("path"), session_id,
                src_ip=record.get("src_ip"))
        if action == "honeytoken_login_attempt":
            # No planted-credential correlation here, deliberately: the web
            # decoy records password_len and never the password itself, and
            # that is the right call for a form anyone on the internet can
            # post to. Bait used against the portal is correlated instead by
            # the /c/{token_id} callback above, which carries the token id in
            # the URL and ships at the same level.
            return self.exporter.decoy_activity(
                {"server": "web_decoy", "action": "login",
                 "src_ip": record.get("src_ip"),
                 "username": detail.get("username"),
                 "status": "success"})
        # Page views and tarpit hits are how the decoy is browsed, not a
        # finding on their own. They stay in the database for the dashboard's
        # session view and do not page anyone.
        self.shipped -= 1
        return None

    # ── lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        for container in self.containers:
            t = threading.Thread(target=self._stream, args=(container,),
                                 daemon=True, name=f"collect-{container}")
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()

    def status(self) -> dict:
        return {"containers": self.containers,
                "alive": [t.name for t in self._threads if t.is_alive()],
                "records_seen": self.seen, "findings_shipped": self.shipped,
                "errors": self.errors[-5:]}


def is_running(container: str) -> bool:
    """Ask Docker, on the host, whether the container is still up."""
    try:
        out = subprocess.run(
            ["docker", "inspect", container, "--format", "{{.State.Running}}"],
            capture_output=True, text=True, timeout=20)
        return out.stdout.strip().lower() == "true"
    except Exception:
        return False


def running_containers() -> list:
    """Names of currently running containers, for a pre-flight check."""
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                             capture_output=True, text=True, timeout=20)
        return [n for n in out.stdout.split() if n]
    except Exception:
        return []


def main(argv=None) -> int:
    sys.path.insert(0, str(Path(__file__).parent))
    import siem
    argv = list(argv if argv is not None else sys.argv[1:])

    containers = [a for a in argv if not a.startswith("-")] or list(DEFAULT_CONTAINERS)
    exporter = siem.SiemExporter(mode="jsonl")

    vault = None
    try:
        from canary_vault import CanaryVault
        from verdict_db import VerdictDB
        vault = CanaryVault(VerdictDB())
    except Exception as e:
        print(f"[collector] no canary vault ({e}); planted-credential "
              f"correlation is off")

    live = running_containers()
    missing = [c for c in containers if c not in live]
    if missing:
        print(f"[collector] not running: {', '.join(missing)}")
    watching = [c for c in containers if c in live]
    if not watching:
        print("[collector] nothing to watch")
        return 1

    try:
        from telemetry import Telemetry
    except Exception as e:
        Telemetry = None
        print(f"[collector] no telemetry db ({e}); dashboard decoy view is off")

    collector = DecoyCollector(exporter, vault=vault, containers=watching,
                               db=Telemetry)

    # Without this, stopping the collector kills its `docker logs` children,
    # the streams end, and every watched container ships a decoy.silent alert
    # on the way out. Shutting down cleanly must not page anyone.
    def _shutdown(_sig, _frame):
        collector.stop()
        raise KeyboardInterrupt
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):
            pass       # not the main thread, or unsupported on this platform

    collector.start()
    print(f"[collector] watching {', '.join(watching)} from the host")
    print(f"[collector] findings -> {exporter.path}")
    print("[collector] nothing was installed in the decoy; ctrl-c to stop")

    try:
        while True:
            time.sleep(30)
            s = collector.status()
            print(f"[collector] seen={s['records_seen']} "
                  f"shipped={s['findings_shipped']}")
    except KeyboardInterrupt:
        collector.stop()
        print(f"\n[collector] {json.dumps(collector.status(), default=str)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
