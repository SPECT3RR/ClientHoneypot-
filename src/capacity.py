"""
Capacity governor — how many bots this machine can actually run.

Asking the operator to pick a bot count is a trap on a memory-constrained
box: exceed physical memory and Windows pages, Chromium instances stall, and
sessions get OOM-killed mid-hunt leaving half-written verdicts. A corrupt
verdict is worse than a slow hunt.

So the ceiling is measured, not chosen. The operator asks for 15 bots; the
governor runs what fits and queues the rest.

Measuring correctly matters. Win32_OperatingSystem.FreePhysicalMemory
excludes standby cache, which IS allocatable, and reports a number several
gigabytes too pessimistic. GlobalMemoryStatusEx.ullAvailPhys is the figure
Task Manager calls "Available", and it is the one to plan against.
"""
import ctypes
import os
import shutil
import subprocess
from pathlib import Path

# Measured on this project's Chromium sessions: a headed persistent context
# with the instrumentation and bait scripts settles around 450 MB; headless
# drops the compositor and window surface.
HEADED_MB = 450
HEADLESS_MB = 280

# Never consume the last of RAM: the dashboard, decoy, and Docker still need
# room, and swapping makes every session slower than running fewer would be.
RESERVE_MB = 700

MIN_BOTS = 1
MAX_BOTS = 50


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def available_mb() -> int:
    """Allocatable physical memory, in MB.

    Windows via GlobalMemoryStatusEx; Linux (and therefore the hunting
    container) via MemAvailable, which likewise accounts for reclaimable
    cache rather than only free pages.
    """
    if os.name == "nt":
        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(_MemoryStatusEx)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullAvailPhys / (1024 * 1024))
        return 0

    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(int(line.split()[1]) / 1024)
    return 0


def total_mb() -> int:
    if os.name == "nt":
        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(_MemoryStatusEx)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys / (1024 * 1024))
        return 0
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(int(line.split()[1]) / 1024)
    return 0


def bot_cost_mb(headless: bool) -> int:
    return HEADLESS_MB if headless else HEADED_MB


def max_bots(headless: bool = False, available: int = None) -> int:
    """How many concurrent sessions fit right now."""
    avail = available if available is not None else available_mb()
    usable = max(0, avail - RESERVE_MB)
    return max(0, min(MAX_BOTS, usable // bot_cost_mb(headless)))


def report(headless: bool = False) -> dict:
    """Everything the dashboard needs to explain the ceiling it is enforcing."""
    avail = available_mb()
    total = total_mb()
    fits = max_bots(headless, available=avail)
    return {
        "available_mb": avail,
        "total_mb": total,
        "reserve_mb": RESERVE_MB,
        "bot_cost_mb": bot_cost_mb(headless),
        "headless": headless,
        "max_bots": fits,
        "max_bots_headless": max_bots(True, available=avail),
        "constrained": fits <= 2,
    }


def clamp(requested: int, headless: bool = False) -> tuple:
    """Return (allowed, reason). Never silently changes the number."""
    requested = max(0, int(requested))
    ceiling = max_bots(headless)
    if requested == 0:
        return 0, ""
    if ceiling < MIN_BOTS:
        return 0, (f"only {available_mb()} MB available — not enough for a "
                   f"single {'headless' if headless else 'headed'} bot "
                   f"({bot_cost_mb(headless)} MB each plus a {RESERVE_MB} MB "
                   f"reserve). Close some windows or pause other containers.")
    if requested > ceiling:
        return ceiling, (f"capped at {ceiling}: {available_mb()} MB available, "
                         f"{bot_cost_mb(headless)} MB per "
                         f"{'headless' if headless else 'headed'} bot. "
                         f"The remaining {requested - ceiling} stay queued.")
    return requested, ""


# ── other containers competing for the same memory ─────────────────────────

def foreign_containers(exclude_prefixes=("hunt_", "decoy_", "clienthoneypot")) -> list:
    """Running containers that are not ours, so the operator can pause them.

    Offered, never automatic: they belong to the operator's other work.
    """
    if shutil.which("docker") is None:
        return []
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, OSError):
        return []
    if proc.returncode != 0:
        return []
    return [n for n in proc.stdout.split()
            if n and not any(n.startswith(p) for p in exclude_prefixes)]


def pause_containers(names: list) -> dict:
    """docker stop — containers and volumes are preserved, never removed."""
    if not names:
        return {"stopped": [], "failed": []}
    stopped, failed = [], []
    for name in names:
        try:
            proc = subprocess.run(["docker", "stop", name],
                                  capture_output=True, text=True, timeout=60)
            (stopped if proc.returncode == 0 else failed).append(name)
        except (subprocess.TimeoutExpired, OSError):
            failed.append(name)
    return {"stopped": stopped, "failed": failed}


def resume_containers(names: list) -> dict:
    started, failed = [], []
    for name in reversed(list(names)):
        try:
            proc = subprocess.run(["docker", "start", name],
                                  capture_output=True, text=True, timeout=60)
            (started if proc.returncode == 0 else failed).append(name)
        except (subprocess.TimeoutExpired, OSError):
            failed.append(name)
    return {"started": started, "failed": failed}
