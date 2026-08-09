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

# `python -m honeypots --config /etc/honeypots/config.json` was the loudest
# tell in the container: the word appeared in every process line and every
# path. The process now reads as a Python daemon on a file server, which is
# what the host is pretending to be.
#
# The library itself is vendored as `filesync` at build time (see
# docker/Dockerfile.honeypots), so site-packages, the distribution metadata
# and `pip list` do not name it either.
PROC_NAME = "filesyncd"
PKG_NAME = "filesync"
LAUNCHER = f"/usr/sbin/{PROC_NAME}"
CONFIG_PATH = f"/etc/{PROC_NAME}/config.json"

LAUNCHER_SRC = f'''#!/usr/bin/env python3
"""Asteria file synchronisation daemon."""
import runpy
import sys

sys.argv = ["{PROC_NAME}", "--config", "{CONFIG_PATH}",
            "--termination-strategy", "signal", "--setup", "{SERVICES}"]
runpy.run_module("{PKG_NAME}", run_name="__main__")
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

    from decoy_services import CONFIG_SECTION
    config = build_service_config()
    services = config[CONFIG_SECTION]
    seeded = sum(1 for s in services.values()
                 if s.get("password") != "Asteria!2026")
    steps.append(f"config rendered: {len(services)} services, "
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
# Its own minimal image, not the hunter image. That one carries all 44 src
# modules, the dashboard and config/ -- i.e. the bot/human classifier, the
# canary design and the collection scheme -- into a container an attacker can
# stand in. See docker/Dockerfile.decoy.
WEB_IMAGE = "clienthoneypot/decoy-web:latest"
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


def _canary_env() -> dict:
    """Canary values from the host's config, for the decoy's environment."""
    path = ROOT / "config" / "canary_tokens.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {k: v for k, v in data.items()
            if k.startswith("AWS_") and isinstance(v, str) and v}


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

    args = ["create", "--name", WEB_CONTAINER,
            "--network", NETWORK,
            "--hostname", WEB_HOSTNAME,
            "--restart", "unless-stopped",
            "-e", "CH_SUBSTRATE=docker"]

    # The real canarytokens.org AWS key, handed over at deploy time rather
    # than baked in. Without this the decoy silently falls back to a random
    # key that fires nowhere, and the bait stops working with no error.
    for name, value in _canary_env().items():
        args += ["-e", f"{name}={value}"]

    args += ["--entrypoint", "sh", WEB_IMAGE, "-c", inner]
    docker(*args)

    with tempfile.TemporaryDirectory() as tmp:
        launcher = Path(tmp) / "launcher.py"
        launcher.write_text(WEB_LAUNCHER_SRC, encoding="utf-8")
        docker("cp", str(launcher), f"{WEB_CONTAINER}:/usr/sbin/{WEB_PROC}")

    docker("start", WEB_CONTAINER)
    steps.append(f"web decoy on {NETWORK} as {WEB_HOSTNAME} "
                 f"running as {WEB_PROC}, no bind mounts")
    return steps


SHELL_CONTAINER = "decoy_shell"
SHELL_IMAGE = "clienthoneypot/decoy-shell:latest"
SHELL_HOSTNAME = "asteria-app02"
SHELL_USERDB = "/cowrie/cowrie-git/etc/userdb.txt"


# Weak but PLAUSIBLE passwords the brute-force accounts accept.
#
# These used to be `root:x:*` and `admin:x:*`, meaning any password at all was
# accepted. That is the single most famous honeypot tell, and black-box testing
# confirmed it: one `ssh root@host` with eight random bytes as the password got
# a shell. No real server behaves that way, so an attacker learns what this is
# before they do anything worth recording.
#
# A fixed list keeps the engagement -- a real brute-force run still lands,
# because these are genuinely among the most-tried passwords -- while a random
# string now fails, exactly as it would on a badly-administered real host.
BRUTE_PASSWORDS = ["123456", "password", "admin", "root", "toor", "P@ssw0rd",
                   "12345678", "qwerty", "letmein", "changeme", "admin123",
                   "Passw0rd!", "1qaz2wsx", "welcome1"]


def build_userdb(vault) -> str:
    """Cowrie userdb.txt from the canary vault: a stolen ssh credential works.

    `user:x:pass` accepts that exact pair. Wildcards are deliberately NOT used
    -- see BRUTE_PASSWORDS. Every login, planted or brute-forced, is captured
    either way; the difference is whether the attacker can tell what they are
    standing in.
    """
    lines = []
    if vault:
        for t in vault.all():
            if (t.get("placement") == "decoy_services"
                    and t.get("kind") == "ssh_key" and t.get("value")):
                label = (t.get("label") or "svc").replace("-", "_")
                user = "".join(c for c in label if c.isalnum() or c == "_") or "svc"
                lines.append(f"{user}:x:{t['value']}")
    for account in ("root", "admin", "ubuntu", "deploy"):
        for password in BRUTE_PASSWORDS:
            lines.append(f"{account}:x:{password}")
    return "\n".join(lines) + "\n"


def deploy_shell() -> list:
    """The high-interaction shell decoy (Cowrie).

    A stolen ssh credential lands here in a real emulated shell, and any file
    the attacker uploads or writes is saved by sha256 -- which is exactly what
    qeeqbox could not do. Cowrie refuses to run as root, so it runs non-root
    with a sysctl that lets it bind port 22; presenting on 2222 would announce
    the honeypot. Config is baked into the image; the accepted credentials are
    copied in from the vault, no mount.
    """
    steps = []
    subprocess.run(["docker", "rm", "-f", SHELL_CONTAINER], capture_output=True)

    try:
        from canary_vault import CanaryVault
        from verdict_db import VerdictDB
        vault = CanaryVault(VerdictDB())
    except Exception as e:
        print(f"  ! no canary vault ({e}); shell accepts only brute-force creds")
        vault = None
    userdb = build_userdb(vault)
    seeded = sum(1 for ln in userdb.splitlines() if ln and not ln.endswith(":x:*"))

    docker("create", "--name", SHELL_CONTAINER,
           "--network", NETWORK,
           "--hostname", SHELL_HOSTNAME,
           # Cowrie is non-root; this lets uid 999 bind the real port 22.
           "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
           "--restart", "unless-stopped",
           SHELL_IMAGE)
    steps.append(f"shell decoy on {NETWORK} as {SHELL_HOSTNAME}")

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "userdb.txt"
        p.write_text(userdb, encoding="utf-8")
        docker("cp", str(p), f"{SHELL_CONTAINER}:{SHELL_USERDB}")
    steps.append(f"credentials copied in ({seeded} seeded from the vault)")

    docker("start", SHELL_CONTAINER)
    steps.append("started (Cowrie: emulated shell, saves dropped files)")
    return steps


# ── verification ───────────────────────────────────────────────────────────

EGRESS_PROBES = {
    "the internet (1.1.1.1:53)": ("1.1.1.1", 53),
    "the host (host.docker.internal:8000)": ("host.docker.internal", 8000),
    "a Wazuh manager (192.168.65.254:1514)": ("192.168.65.254", 1514),
    "the LAN gateway (192.168.1.1:80)": ("192.168.1.1", 80),
}

# `host.docker.internal` is a Docker Desktop convenience. On Docker Engine for
# Linux -- i.e. any real deployment -- the name does not resolve, so that probe
# fails with gaierror and reports "blocked" while telling us nothing: it never
# tried to reach the host at all. The host is at the network's GATEWAY there.
#
# So the probe reads its own default gateway from /proc/net/route and tests
# that too. This is the check that actually means "the decoy cannot reach the
# machine it runs on", and it is the same check on both platforms.
GATEWAY_PROBE = "the host via the default gateway"

PROBE_SRC = """
import socket, json, struct
out = {}


def default_gateway():
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                if f[1] == "00000000":          # destination 0.0.0.0
                    return socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
    except OSError:
        pass
    return None


gw = default_gateway()
out["_gateway"] = gw or "none (no default route at all)"
if gw:
    reached = []
    for port in (22, 80, 443, 8000, 8001):
        try:
            socket.create_connection((gw, port), timeout=2).close()
            reached.append(port)
        except Exception:
            pass
    out["%s"] = ("REACHABLE on " + str(reached)) if reached else "blocked"
else:
    # An internal Docker network gives the container no default route, which
    # is the strongest possible answer: there is nowhere for traffic to go.
    out["%s"] = "blocked"

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
        ["docker", "exec", container, "timeout", "30", "python", "-c",
         PROBE_SRC % (GATEWAY_PROBE, GATEWAY_PROBE, json.dumps(probes))],
        capture_output=True, text=True, timeout=120)
    line = next((l for l in out.stdout.splitlines() if l.startswith("{")), None)
    if not line:
        return False, [f"probe did not run: {(out.stderr or out.stdout).strip()[:200]}"]

    results = json.loads(line)
    gateway = results.pop("_gateway", "unknown")
    findings, ok = [], True
    for name, result in results.items():
        if str(result).startswith("REACHABLE"):
            ok = False
            findings.append(f"  FAIL  {name}: {result}")
        else:
            findings.append(f"  ok    {name}: blocked ({result})")
    # Printed either way: on Docker Desktop the name-based host probe fails to
    # resolve and proves nothing, so the gateway line is the one that carries
    # the real answer -- and on Linux it is the only one that does.
    findings.append(f"  info  default route from inside: {gateway}")
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

    # What is on disk. The process list can be clean while site-packages,
    # `pip list` and our own source all answer the same question.
    probe = (
        'python3 - <<"EOF"\n'
        'import glob, importlib.util, json, os\n'
        'out = {}\n'
        'out["pkg_importable"] = importlib.util.find_spec("honeypots") is not None\n'
        'hits = []\n'
        'for root in ("/usr/local/lib", "/usr/lib", "/app", "/etc", "/opt"):\n'
        '    for dirpath, dirnames, filenames in os.walk(root):\n'
        '        for n in list(dirnames) + list(filenames):\n'
        '            low = n.lower()\n'
        '            if "honeypot" in low or "qeeqbox" in low:\n'
        '                hits.append(os.path.join(dirpath, n))\n'
        '        # Names are not enough: the last hit in this container was a\n'
        '        # docstring inside a dependency, not a filename.\n'
        '        for n in filenames:\n'
        '            p = os.path.join(dirpath, n)\n'
        '            try:\n'
        '                with open(p, "rb") as fh:\n'
        '                    blob = fh.read(200000).lower()\n'
        '            except OSError:\n'
        '                continue\n'
        '            if b"honeypot" in blob or b"qeeqbox" in blob:\n'
        '                hits.append(p)\n'
        '        if len(hits) > 12: break\n'
        'out["named_paths"] = sorted(set(hits))[:6]\n'
        'secrets = [p for p in ("/app/config/intel_keys.json",\n'
        '                       "/app/config/canary_tokens.json")\n'
        '           if os.path.exists(p)]\n'
        'out["secrets"] = secrets\n'
        'playbook = [p for p in ("/app/src/canary_vault.py",\n'
        '                        "/app/src/decoy_telemetry.py",\n'
        '                        "/app/src/threat_scorer.py",\n'
        '                        "/app/src/threat_detection.py",\n'
        '                        "/app/src/compromise_detector.py",\n'
        '                        "/app/src/siem.py", "/app/src/intel_keys.py",\n'
        '                        "/app/dashboard", "/app/tests")\n'
        '            if os.path.exists(p)]\n'
        'out["playbook"] = playbook\n'
        'out["gate"] = os.path.exists("/app/src/operator_classifier.py")\n'
        'print(json.dumps(out))\n'
        'EOF\n')
    raw = subprocess.run(["docker", "exec", container, "sh", "-c", probe],
                         capture_output=True, text=True, timeout=120).stdout
    line = next((l for l in raw.splitlines() if l.startswith("{")), None)
    if line:
        disk = json.loads(line)
        if disk["pkg_importable"] or disk["named_paths"]:
            ok = False
            findings.append("  FAIL  the honeypot library is findable on disk:")
            for p in disk["named_paths"][:3]:
                findings.append(f"          {p}")
            if disk["pkg_importable"]:
                findings.append("          `import honeypots` succeeds")
        else:
            findings.append("  ok    nothing on disk names the honeypot library")

        if disk["secrets"]:
            ok = False
            findings.append(f"  FAIL  secrets in the image: "
                            f"{', '.join(disk['secrets'])}")
        else:
            findings.append("  ok    no threat-feed keys or bait list in the image")

        if disk["playbook"]:
            ok = False
            findings.append(f"  FAIL  our own detection logic is readable here: "
                            f"{', '.join(disk['playbook'][:3])}")
        else:
            findings.append("  ok    no scoring, canary, SIEM or console code "
                            "in the image")

        if disk.get("gate"):
            # Not a failure, and not something that can be fixed by moving it:
            # the decoy gates tier-2 access on a live bot/human decision, so
            # the test has to run here. The canary lookup could move to the
            # host because it is after-the-fact; this cannot.
            #
            # It is the one strategic disclosure left. Someone who reads it
            # learns which behaviours we score and can rehearse against them.
            # Worth knowing, and an argument for keeping the weights in config
            # rather than in code if this ever faces a determined adversary.
            findings.append("  note  operator_classifier.py present (the live "
                            "bot/human gate must run here)")
    else:
        findings.append("  ??    on-disk probe did not run")

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


def _grab_banner(host: str, port: int = 22) -> str:
    """Read a service banner from a throwaway container ON decoy_net.

    From the host there is no route in (the network is internal), so the probe
    has to run inside the network, the same place a hunted session lives."""
    src = (f"import socket\n"
           f"s=socket.create_connection(('{host}',{port}),timeout=6)\n"
           f"print(s.recv(80).decode('utf-8','replace').strip())")
    out = subprocess.run(
        ["docker", "run", "--rm", "--network", NETWORK,
         "python:3.11-slim", "python", "-c", src],
        capture_output=True, text=True, timeout=90)
    return out.stdout.strip()


def verify_shell(container: str = SHELL_CONTAINER) -> bool:
    """The shell decoy verifies differently: an attacker never reaches its real
    filesystem (the SSH shell is emulated), so the disguise is the SSH-visible
    surface, and the Cowrie image has no `sh` to exec a probe into anyway."""
    print(f"\nVerifying {container} (high-interaction shell).\n")
    ok = True

    print("Containment")
    nets = subprocess.run(
        ["docker", "inspect", container, "--format",
         "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}"],
        capture_output=True, text=True, timeout=20).stdout.split()
    if NETWORK in nets and network_is_internal(NETWORK):
        print(f"  ok    on {NETWORK}, which is internal — no egress "
              f"(proven by the other decoys' probes above)")
    else:
        ok = False
        print(f"  FAIL  not on an internal network: {nets}")

    print("\nDisguise — what a scanner sees")
    banner = _grab_banner(SHELL_HOSTNAME, 22)
    if banner and "OpenSSH_8" in banner and "cowrie" not in banner.lower():
        print(f"  ok    SSH banner reads as a patched server: {banner}")
    else:
        ok = False
        print(f"  FAIL  SSH banner: {banner!r}")
    print("  note  Cowrie's emulated shell has known behavioural tells a")
    print("        skilled adversary can fingerprint — true of every")
    print("        medium-interaction honeypot. The un-fingerprintable")
    print("        alternative is a real contained shell (real RCE).")

    print()
    print("PASS  contained; a stolen credential works and dropped files are saved."
          if ok else "FAIL  see above.")
    return ok


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
        return 0 if (verify() and verify(WEB_CONTAINER)
                     and verify_shell()) else 1

    internal = not args.expose_loopback
    if not internal:
        print("!! --expose-loopback: the decoy will have egress and can reach")
        print("!! the host. Use for local testing only, never with live bait.\n")

    print(f"Network:  {ensure_network(internal=internal)}")
    for step in deploy_services(internal=internal):
        print(f"          {step}")
    for step in deploy_web():
        print(f"          {step}")
    for step in deploy_shell():
        print(f"          {step}")

    import time
    time.sleep(8)
    ok = verify() and verify(WEB_CONTAINER) and verify_shell()

    print("\nCollect telemetry + capture with:")
    print("    python src/decoy_telemetry.py")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
