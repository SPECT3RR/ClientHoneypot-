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
import shutil
import socket
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
        subprocess.run(["docker", "network", "inspect", self.network],
                       capture_output=True, timeout=15)
        return {"network": self.network, "image": self.image}

    def teardown(self, session_id: str) -> None:
        subprocess.run(["docker", "rm", "-f", f"hunt_{session_id}"],
                       capture_output=True, timeout=30)


PROFILES = {"local": LocalSubstrate, "docker": DockerSubstrate}


def load(config_path: Path = None) -> Substrate:
    """Build the substrate named in config/runtime.yaml.

    Defaults to 'local' — the safe-by-default direction. A missing or broken
    config must never silently grant live-hunting permission.
    """
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
