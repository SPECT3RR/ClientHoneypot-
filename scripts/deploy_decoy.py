"""
Stand up the decoy contained and disguised, then prove both.

This exists because the compose file described containment the running system
did not have. `decoy_net` had been created by hand before compose declared it
`internal: true`, and Docker does not retrofit that onto an existing network,
so the flag sat in the file doing nothing while the decoy had full egress. The
service decoy was worse -- started with `docker run` during an earlier test, it
was still sitting on the default bridge, able to reach the internet, the host,
and every other container on that bridge.

A declaration is not containment. This script builds the topology and then
attacks it from the inside to check, and it is the check that matters.

WHAT IT ENFORCES

  Containment   decoy_net is genuinely internal. Verified by trying to reach
                the internet, the host, and a plausible SIEM from inside the
                decoy. All three must fail. A consequence worth knowing: an
                internal network cannot publish ports either, so the decoy is
                reachable only from decoy_net -- which is where hunted
                sessions live. There is no host-side door, for anyone.

  Disguise      no bind mounts, no agent, no collector process, and stdout
                logging. Mounts are the loudest tell: this project's mounts
                showed `D:\` over 9p, which tells an attacker the host is a
                Windows workstation running Docker Desktop with the operator's
                own drive attached. That is not a honeypot they will engage
                with. Config goes in with `docker cp`, which leaves no trace.

Telemetry is collected out of band by src/decoy_telemetry.py, running on the
host. Nothing in the decoy knows about it.

    python scripts/deploy_decoy.py              # deploy contained, then verify
    python scripts/deploy_decoy.py --verify     # check what is running now
    python scripts/deploy_decoy.py --expose-loopback   # testing only
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

NETWORK = "decoy_net"
SVC_CONTAINER = "decoy_svc"
SVC_IMAGE = "clienthoneypot/decoy-services:latest"

# A hostname is the first thing printed at an SSH prompt. "3f9a1c2b4e5d" says
# container; this says file server, and matches the company the web decoy
# invents so the two halves tell one story.
SVC_HOSTNAME = "asteria-fs01"

SERVICES = "ssh,ftp,mysql,postgres,smb,telnet,vnc,rdp,redis"

# `python -m honeypots --config /etc/honeypots/config.json` is the loudest
# tell in the whole container: the word is in every process line and every
# path, and one `cat /proc/self/status`-grade look ends the engagement.
#
# So the honeypot is started through a launcher with a mundane name and its
# config lives at a mundane path. The process reads as a Python daemon on a
# file server, which is what the host is pretending to be.
#
# This raises the bar; it does not clear it. pip leaves the package itself at
# site-packages/honeypots, and an attacker who goes looking there will find
# it. Hiding that means vendoring the library under another name -- a real
# piece of work, and worth doing before this is exposed to skilled targets.
PROC_NAME = "filesyncd"
LAUNCHER = f"/usr/sbin/{PROC_NAME}"
CONFIG_PATH = f"/etc/{PROC_NAME}/config.json"

LAUNCHER_SRC = f'''#!/usr/bin/env python3
"""Asteria file synchronisation daemon."""
import runpy
import sys

sys.argv = ["{PROC_NAME}", "--config", "{CONFIG_PATH}",
            "--termination-strategy", "signal", "--setup", "{SERVICES}"]
runpy.run_module("honeypots", run_name="__main__")
'''


def docker(*args, check=True, timeout=120):
    proc = subprocess.run(["docker", *args], capture_output=True, text=True,
                          timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)}\n{proc.stderr.strip()}")
    return proc.stdout.strip()


def network_is_internal(name: str):
    """None if absent, else True/False."""
    out = subprocess.run(["docker", "network", "inspect", name,
                          "--format", "{{.Internal}}"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return None
    return out.stdout.strip().lower() == "true"


def ensure_network(internal: bool = True) -> str:
    state = network_is_internal(NETWORK)
    if state == internal:
        return f"{NETWORK} already internal={internal}"

    if state is not None:
        # Every attached container has to come off before the network can go.
        attached = json.loads(docker("network", "inspect", NETWORK,
                                     "--format", "{{json .Containers}}") or "{}")
        for cid in attached:
            subprocess.run(["docker", "network", "disconnect", "-f",
                            NETWORK, cid], capture_output=True)
        docker("network", "rm", NETWORK)

    args = ["network", "create"]
    if internal:
        args.append("--internal")
    docker(*args, NETWORK)
    return (f"{NETWORK} recreated internal={internal}"
            + ("" if state is None else f" (was internal={state})"))


def build_service_config() -> dict:
    """Render qeeqbox config from the canary vault so planted creds work."""
    from decoy_services import build_config
    try:
        from canary_vault import CanaryVault
        from verdict_db import VerdictDB
        vault = CanaryVault(VerdictDB())
    except Exception as e:
        print(f"  ! no canary vault ({e}); using default credentials")
        vault = None
    return build_config(vault, services=SERVICES.split(","))


def deploy_services(internal: bool = True) -> list:
    steps = []
    subprocess.run(["docker", "rm", "-f", SVC_CONTAINER], capture_output=True)

    config = build_service_config()
    seeded = sum(1 for s in config["honeypots"].values()
                 if s.get("password") != "Asteria!2026")
    steps.append(f"config rendered: {len(config['honeypots'])} services, "
                 f"{seeded} seeded from the vault")
    assert config["logs"].startswith("terminal"), \
        "config must log to stdout or there is nothing to collect out of band"

    # No -v anywhere. Mounts are the tell we are removing.
    # /.dockerenv is deleted before the service starts: it is the first file
    # every container-detection script looks for. The old config directory
    # goes too, since its name gives the game away on its own.
    inner = (f"rm -f /.dockerenv; rm -rf /etc/honeypots /var/log/honeypots; "
             f"exec python3 {LAUNCHER}")
    docker("create", "--name", SVC_CONTAINER,
           "--network", NETWORK,
           "--hostname", SVC_HOSTNAME,
           "--restart", "unless-stopped",
           "--entrypoint", "sh",
           SVC_IMAGE, "-c", inner)
    steps.append(f"created on {NETWORK} as {SVC_HOSTNAME}, no bind mounts")

    # Copied in, not mounted, so /proc/mounts stays clean.
    with tempfile.TemporaryDirectory() as tmp:
        # Copy the directory, not the file: /etc/filesyncd does not exist in
        # the image, and `docker cp` will not create a missing parent.
        staged = Path(tmp) / PROC_NAME
        staged.mkdir()
        (staged / "config.json").write_text(json.dumps(config, indent=2),
                                            encoding="utf-8")
        docker("cp", str(staged), f"{SVC_CONTAINER}:/etc/")

        launcher = Path(tmp) / "launcher.py"
        launcher.write_text(LAUNCHER_SRC, encoding="utf-8")
        docker("cp", str(launcher), f"{SVC_CONTAINER}:{LAUNCHER}")
    steps.append(f"config and launcher copied in as {PROC_NAME} "
                 f"(docker cp leaves no mount)")

    docker("start", SVC_CONTAINER)
    steps.append("started")
    return steps


WEB_CONTAINER = "decoy"
WEB_IMAGE = "clienthoneypot/hunter:latest"
WEB_HOSTNAME = "asteria-portal"
WEB_PROC = "portald"

# The app decides which interface to bind by checking for /.dockerenv, and we
# delete that file. Without CH_SUBSTRATE it would decide it is on a host, bind
# 127.0.0.1 -- the container's own loopback -- and quietly become unreachable
# from decoy_net. The env var carries the decision the file used to.
WEB_LAUNCHER_SRC = '''#!/usr/bin/env python3
"""Asteria staff portal."""
import runpy
runpy.run_path("/app/decoy_app/app.py", run_name="__main__")
'''


def deploy_web() -> list:
    """The web decoy, with its host mount removed.

    It used to bind D:/ClientHoneypot/telemetry read-write. That put the
    operator's own drive one path traversal away from attacker-facing code,
    and put `D:\\` in /proc/mounts for anyone who got far enough to read it.
    It now logs to stdout and the collector writes the host copy.
    """
    steps = []
    subprocess.run(["docker", "rm", "-f", WEB_CONTAINER], capture_output=True)
    inner = f"rm -f /.dockerenv; exec python3 /usr/sbin/{WEB_PROC}"
    docker("create", "--name", WEB_CONTAINER,
           "--network", NETWORK,
           "--hostname", WEB_HOSTNAME,
           "--restart", "unless-stopped",
           "-e", "CH_SUBSTRATE=docker",
           "--entrypoint", "sh",
           WEB_IMAGE, "-c", inner)

    with tempfile.TemporaryDirectory() as tmp:
        launcher = Path(tmp) / "launcher.py"
        launcher.write_text(WEB_LAUNCHER_SRC, encoding="utf-8")
        docker("cp", str(launcher), f"{WEB_CONTAINER}:/usr/sbin/{WEB_PROC}")

    docker("start", WEB_CONTAINER)
    steps.append(f"web decoy on {NETWORK} as {WEB_HOSTNAME} "
                 f"running as {WEB_PROC}, no bind mounts")
    return steps


# ── verification ───────────────────────────────────────────────────────────

EGRESS_PROBES = {
    "the internet (1.1.1.1:53)": ("1.1.1.1", 53),
    "the host (host.docker.internal:8000)": ("host.docker.internal", 8000),
    "a Wazuh manager (192.168.65.254:1514)": ("192.168.65.254", 1514),
    "the LAN gateway (192.168.1.1:80)": ("192.168.1.1", 80),
}

PROBE_SRC = """
import socket, json
out = {}
for name, (h, p) in %s.items():
    try:
        socket.create_connection((h, p), timeout=3).close()
        out[name] = "REACHABLE"
    except Exception as e:
        out[name] = type(e).__name__
print(json.dumps(out))
"""


def verify_containment(container: str) -> tuple:
    """Attack the containment from inside. Reachable is a failure."""
    probes = {k: list(v) for k, v in EGRESS_PROBES.items()}
    out = subprocess.run(
        ["docker", "exec", container, "timeout", "25", "python", "-c",
         PROBE_SRC % json.dumps(probes)],
        capture_output=True, text=True, timeout=90)
    line = next((l for l in out.stdout.splitlines() if l.startswith("{")), None)
    if not line:
        return False, [f"probe did not run: {(out.stderr or out.stdout).strip()[:200]}"]

    results = json.loads(line)
    findings, ok = [], True
    for name, result in results.items():
        if result == "REACHABLE":
            ok = False
            findings.append(f"  FAIL  {name}: REACHABLE")
        else:
            findings.append(f"  ok    {name}: blocked ({result})")
    return ok, findings


# Paths that would tell an attacker they are being watched, and by what.
# These are the claim: find any of them and the disguise has failed.
MONITORING_TELLS = ["/var/ossec", "/etc/filebeat", "/opt/wazuh", "/etc/wazuh",
                    "/etc/rsyslog.d", "/etc/audit/auditd.conf",
                    "/etc/td-agent", "/usr/bin/wazuh-agentd"]

# Tells that this is a container. Reported, but not failures.
#
# The claim being made is "you cannot tell you are being monitored", which is
# not the same as "you cannot tell you are in a container" -- an enormous
# amount of ordinary production software runs in one, so learning that reveals
# nothing about our intent. /.dockerenv survives on the web decoy because that
# container runs as uid 10001 and cannot delete a root-owned file. Running
# attacker-facing code as root to hide one file would trade a real control for
# a cosmetic one.
CONTAINER_TELLS = ["/.dockerenv"]


def verify_disguise(container: str) -> tuple:
    """Look for what an attacker would look for."""
    findings, ok = [], True

    mounts = subprocess.run(["docker", "exec", container, "cat", "/proc/mounts"],
                            capture_output=True, text=True, timeout=30).stdout
    tells = [l for l in mounts.splitlines()
             if (" 9p " in l or "drvfs" in l or ":\\" in l)
             and "/etc/resolv.conf" not in l]
    if tells:
        ok = False
        findings.append(f"  FAIL  {len(tells)} host mount(s) visible in /proc/mounts:")
        for t in tells[:4]:
            findings.append(f"          {t.split(' type ')[0][:88]}")
    else:
        findings.append("  ok    no host mounts in /proc/mounts")

    def exists(paths):
        return [p for p in paths
                if subprocess.run(["docker", "exec", container, "test", "-e", p],
                                  capture_output=True, timeout=20).returncode == 0]

    agents = exists(MONITORING_TELLS)
    if agents:
        ok = False
        findings.append(f"  FAIL  monitoring agent present: {', '.join(agents)}")
    else:
        findings.append(f"  ok    none of {len(MONITORING_TELLS)} monitoring "
                        f"agents present")

    for path in exists(CONTAINER_TELLS):
        findings.append(f"  note  {path} present (says container, not honeypot)")

    # Anything the decoy has open to the outside world is something an
    # attacker can enumerate. Only the honeypot ports should answer.
    # The process list is read by anyone who lands a shell, and it is where
    # the word "honeypot" used to appear on every line.
    procs = subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         'for p in /proc/[0-9]*; do tr "\\0" " " < $p/cmdline 2>/dev/null; '
         'echo; done'],
        capture_output=True, text=True, timeout=30).stdout
    naming = [l.strip() for l in procs.splitlines()
              if "honeypot" in l.lower() or "decoy" in l.lower()]
    if naming:
        ok = False
        findings.append("  FAIL  process list names the software:")
        findings.append(f"          {naming[0][:88]}")
    else:
        findings.append("  ok    no process or path names the honeypot software")

    # Docker's default hostname is the short container id: 12 hex characters.
    # Testing the length alone is wrong -- a good fake hostname can be twelve
    # characters too, which is exactly what asteria-fs01 is.
    hostname = subprocess.run(["docker", "exec", container, "hostname"],
                              capture_output=True, text=True, timeout=20).stdout.strip()
    looks_generated = (len(hostname) == 12
                       and all(c in "0123456789abcdef" for c in hostname))
    if hostname and not looks_generated:
        findings.append(f"  ok    hostname reads as a real host: {hostname}")
    else:
        ok = False
        findings.append(f"  FAIL  hostname looks like a container id: {hostname}")

    return ok, findings


def verify(container: str = SVC_CONTAINER) -> bool:
    print(f"\nVerifying {container} the way an attacker inside it would.\n")
    print("Containment - can the decoy reach anything?")
    c_ok, c_out = verify_containment(container)
    print("\n".join(c_out))
    print("\nDisguise - can it tell it is being watched?")
    d_ok, d_out = verify_disguise(container)
    print("\n".join(d_out))

    print()
    if c_ok and d_ok:
        print("PASS  contained and disguised.")
        print("      Telemetry leaves via the docker log stream on the host;")
        print("      nothing inside the container participates.")
    else:
        print("FAIL  see above.")
    return c_ok and d_ok


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verify", action="store_true",
                    help="only check what is running now")
    ap.add_argument("--expose-loopback", action="store_true",
                    help="TESTING ONLY: non-internal network so you can reach "
                         "the decoy from the host. This also gives the decoy "
                         "egress.")
    args = ap.parse_args(argv)

    if args.verify:
        return 0 if (verify() and verify(WEB_CONTAINER)) else 1

    internal = not args.expose_loopback
    if not internal:
        print("!! --expose-loopback: the decoy will have egress and can reach")
        print("!! the host. Use for local testing only, never with live bait.\n")

    print(f"Network:  {ensure_network(internal=internal)}")
    for step in deploy_services(internal=internal):
        print(f"          {step}")
    for step in deploy_web():
        print(f"          {step}")

    import time
    time.sleep(6)
    ok = verify() and verify(WEB_CONTAINER)

    print("\nCollect telemetry with:")
    print("    python src/decoy_telemetry.py")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
