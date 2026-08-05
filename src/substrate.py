"""
Runtime substrate — where the browser is allowed to execute.

The honeyclient renders attacker-controlled content in a real Chromium. A
browser zero-day on a hunted page executes wherever that browser lives, so
"where" is a security decision, not a deployment detail.

Profiles, weakest to strongest:

  local   Windows host, no boundary. Development only. Refuses any target
          that is not loopback — this is the phase-7 gate, and it is the
          single most important line in this file.

  docker  Container inside the WSL2 utility VM. WSL2 runs a real Linux
          kernel in a lightweight VM, so a container escape lands in the VM
          rather than on Windows; reaching the host needs a hypervisor or
          virtio-interop exploit. Egress is restricted away from RFC1918 so
          a compromised session cannot reach the LAN.

  firecracker  Not implemented. Needs a Linux/KVM host, which Windows 11
          Home cannot provide (no Hyper-V, no Windows Sandbox). The seam is
          here so it drops in behind the same interface once such a host
          exists; nothing above this module changes.

Containment is layered, not absolute. WSL2 is a real VM boundary but it is
not a hardened microVM, and this is stated plainly rather than implied.
"""
import ipaddress
import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import yaml

CONFIG = Path(__file__).parent.parent / "config" / "runtime.yaml"

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class UnsafeTargetError(RuntimeError):
    """Raised when a profile is not permitted to visit a target."""


def _bare_host(netloc: str) -> str:
    """Strip the port without mangling IPv6.

    Splitting on ':' first turns '[::1]:8080' into '[' — so the bracket form
    has to be handled before any port split.
    """
    netloc = (netloc or "").strip().lower()
    if netloc.startswith("["):
        end = netloc.find("]")
        return netloc[1:end] if end > 0 else netloc[1:]
    return netloc.split(":")[0]


def _is_loopback(host: str) -> bool:
    host = _bare_host(host)
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_private(host: str) -> bool:
    try:
        return ipaddress.ip_address(_bare_host(host)).is_private
    except ValueError:
        return False


class Substrate:
    """Base interface. Subclasses decide where a session executes."""

    name = "base"
    isolated = False
    allows_live_targets = False

    def __init__(self, config: dict = None):
        self.config = config or {}

    # ── the gate ───────────────────────────────────────────────────────────

    def assert_target_allowed(self, url: str) -> None:
        """Refuse targets this substrate is not safe enough to visit.

        Called before every navigation. An unisolated profile pointed at a
        real malicious URL is the failure mode this whole module exists to
        prevent, so it fails loudly rather than warning.
        """
        host = urlparse(url).netloc
        if self.allows_live_targets:
            if _is_private(host) and not _is_loopback(host):
                raise UnsafeTargetError(
                    f"refusing to hunt {url!r}: RFC1918 address. Hunting must "
                    f"never touch your own network.")
            return

        if not _is_loopback(host):
            raise UnsafeTargetError(
                f"refusing to visit {url!r} under the {self.name!r} substrate: "
                f"no isolation boundary. Only loopback targets "
                f"(tests/mock_malicious_site.py) are permitted here. "
                f"Switch runtime.profile to 'docker' in config/runtime.yaml "
                f"for live hunting.")

    # ── lifecycle ──────────────────────────────────────────────────────────

    def available(self) -> tuple:
        """Return (ok, reason)."""
        return True, ""

    def prepare(self, session_id: str) -> dict:
        return {}

    def teardown(self, session_id: str) -> None:
        pass

    def describe(self) -> dict:
        return {"profile": self.name, "isolated": self.isolated,
                "allows_live_targets": self.allows_live_targets}


class LocalSubstrate(Substrate):
    """Windows host, no boundary. Development only."""

    name = "local"
    isolated = False
    allows_live_targets = False


class DockerSubstrate(Substrate):
    """Container inside the WSL2 utility VM, with restricted egress."""

    name = "docker"
    isolated = True
    allows_live_targets = True

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.image = self.config.get("image", "clienthoneypot/hunter:latest")
        self.network = self.config.get("network", "hunt_net")
        # The decoy is reached by container DNS on a shared internal network,
        # NOT through host.docker.internal. That route gave a hunted session a
        # path to every port listening on the host -- the dashboard included --
        # which is a hole the container hardening does nothing about.
        self.decoy_network = self.config.get("decoy_network", "decoy_net")
        self.decoy_base = self.config.get("decoy_base", "http://decoy:8001")
        # A compromised session must not be able to touch the verdict store or
        # the honeypot logs. It writes its result to its own drop directory and
        # the host ingests it.
        self.result_dir = self.config.get("result_dir", "telemetry/hunt_results")

    def available(self) -> tuple:
        if shutil.which("docker") is None:
            return False, "docker CLI not found on PATH"
        try:
            proc = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                                  capture_output=True, text=True, timeout=15)
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, f"docker not reachable: {e}"
        if proc.returncode != 0:
            return False, ("docker daemon is not running — start Docker Desktop "
                           "(its WSL2 backend is the isolation boundary)")
        return True, f"docker {proc.stdout.strip()}"

    def prepare(self, session_id: str) -> dict:
        ok, reason = self.available()
        if not ok:
            raise RuntimeError(f"cannot prepare isolated session: {reason}")
        self.ensure_network()
        return {"network": self.network, "image": self.image}

    def ingest_results(self, db) -> list:
        """Pull session results out of the drop directory into the verdict DB.

        The host reads; the container only ever writes. That asymmetry is the
        point — a compromised session can drop a malformed file but cannot
        corrupt the store, and anything unparseable is discarded rather than
        trusted.
        """
        root = Path(__file__).parent.parent
        drop = root / self.result_dir
        if not drop.exists():
            return []

        # Timelines first: the verdict is the headline, the timeline is the
        # third-party evidence behind it.
        reports = root / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        for tl in drop.glob("*_timeline.jsonl"):
            try:
                tl.replace(reports / tl.name)
            except OSError:
                pass

        ingested = []
        for path in sorted(drop.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                url = data["url"]
                db.record_verdict(
                    url=url,
                    score=int(data.get("score", 0)),
                    clusters=list(data.get("clusters") or []),
                    findings=list(data.get("findings") or []),
                    decision=str(data.get("decision", "unknown")),
                )
                ingested.append(url)
            except (ValueError, KeyError, TypeError, OSError):
                pass          # a bad drop is discarded, never trusted
            finally:
                try:
                    path.unlink()
                except OSError:
                    pass
        return ingested

    def ensure_network(self) -> None:
        """Create the hunt network if it is missing.

        Inter-container communication is disabled: two hunted sessions must
        not be able to reach each other, so a payload that compromises one
        worker cannot pivot into its neighbours.
        """
        # hunt_net: internet egress, inter-container talk off so one
        # compromised session cannot pivot into its neighbours.
        probe = subprocess.run(["docker", "network", "inspect", self.network],
                               capture_output=True, timeout=20)
        if probe.returncode != 0:
            subprocess.run(
                ["docker", "network", "create", "--driver", "bridge",
                 "--opt", "com.docker.network.bridge.enable_icc=false",
                 self.network],
                capture_output=True, timeout=30)

        # decoy_net: internal, so the decoy has no route off the host. A decoy
        # that can phone out is an attacker's relay.
        probe = subprocess.run(
            ["docker", "network", "inspect", self.decoy_network],
            capture_output=True, timeout=20)
        if probe.returncode != 0:
            subprocess.run(
                ["docker", "network", "create", "--driver", "bridge",
                 "--internal", self.decoy_network],
                capture_output=True, timeout=30)

    def run_session(self, url: str, session_id: str, timeout: int = 600) -> dict:
        """Run one hunting session inside a throwaway container.

        This is what makes the profile real rather than advisory: the browser
        that renders attacker-controlled content executes in the WSL2 VM, not
        on the Windows host.

        Two things a hunted page must not have, and no longer does:

        - a route to the host. host.docker.internal reached every port
          listening on Windows, the dashboard included, which the container
          hardening does nothing about. The decoy is now reached by container
          DNS on an internal network instead.
        - write access to the verdict store. The session drops its result in
          its own directory and the host ingests it, so a compromised
          container cannot touch verdicts.db or the honeypot logs.
        """
        self.assert_target_allowed(url)
        self.prepare(session_id)

        root = Path(__file__).parent.parent
        drop = root / self.result_dir
        drop.mkdir(parents=True, exist_ok=True)
        name = f"hunt_{session_id}"
        cmd = [
            "docker", "run", "--rm", "--name", name,
            "--network", self.network,          # egress
            "--network", self.decoy_network,    # decoy by DNS, internal only
            "--security-opt", "no-new-privileges:true",
            "--cap-drop", "ALL",
            "--shm-size", "1g",              # Chromium dies on the 64 MB default
            "--memory", "2g", "--pids-limit", "512",
            "-v", f"{drop}:/app/results",    # its own drop dir, nothing else
            "-e", "CH_SUBSTRATE=docker",     # the in-container run is already isolated
            "-e", "CH_RESULT_DIR=/app/results",
            "-e", f"CH_DECOY_BASE={self.decoy_base}",
            self.image, url,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout)
            return {"ok": proc.returncode == 0, "code": proc.returncode,
                    "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-2000:]}
        except subprocess.TimeoutExpired:
            self.teardown(session_id)
            return {"ok": False, "code": -1, "stdout": "",
                    "stderr": f"session exceeded {timeout}s and was destroyed"}

    def teardown(self, session_id: str) -> None:
        subprocess.run(["docker", "rm", "-f", f"hunt_{session_id}"],
                       capture_output=True, timeout=30)


PROFILES = {"local": LocalSubstrate, "docker": DockerSubstrate}


def load(config_path: Path = None) -> Substrate:
    """Build the substrate named in config/runtime.yaml.

    Defaults to 'local' — the safe-by-default direction. A missing or broken
    config must never silently grant live-hunting permission.
    """
    # A session already running inside the container is isolated by
    # definition; without this it would read the shipped 'local' config and
    # refuse its own target.
    if os.environ.get("CH_SUBSTRATE") == "docker":
        return DockerSubstrate()

    path = Path(config_path or CONFIG)
    data = {}
    if path.exists():
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {}

    runtime = data.get("runtime") or {}
    profile = runtime.get("profile", "local")
    cls = PROFILES.get(profile)
    if cls is None:
        raise ValueError(f"unknown runtime profile {profile!r}; "
                         f"expected one of {sorted(PROFILES)}")
    return cls(runtime.get(profile) or {})


def preflight(substrate: Substrate) -> list:
    """Human-readable readiness report for the dashboard and CLI."""
    ok, reason = substrate.available()
    lines = [
        f"profile          : {substrate.name}",
        f"isolated         : {'yes' if substrate.isolated else 'NO'}",
        f"live hunting     : {'permitted' if substrate.allows_live_targets else 'BLOCKED (loopback only)'}",
        f"substrate ready  : {'yes' if ok else 'no — ' + reason}",
    ]
    if not substrate.isolated:
        lines.append(
            "WARNING          : no containment. A browser exploit on a hunted "
            "page executes on this host.")
    return lines
