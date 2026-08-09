# Thug Deception Platform (MVP)

A research honeyclient platform: a browser that presents itself as a believable
enterprise employee workstation, browses candidate URLs, watches for malicious
behavior, and — when it detects something suspicious — diverts the interaction
into a fully synthetic decoy "enterprise" environment seeded with honeytokens,
while logging everything for analysis.

**This is a defensive security research tool.** It is meant to run against
known-malicious or suspicious URLs in an isolated lab, not on your normal
network. Read the "Isolation" section before pointing it at anything live.

## What is actually implemented in this drop

This is a working MVP, not the full architecture from the spec. Everything
listed below runs end-to-end on your machine with Python + Playwright:

| Component (spec name)         | Status | Notes |
|---|---|---|
| Fingerprint Manager            | ✅ implemented | Persona-consistent UA, viewport, locale, timezone, navigator/canvas/WebGL overrides injected via CDP |
| Persona Generator               | ✅ implemented | Generates synthetic employee persona + bookmarks/history/downloads |
| Human Behaviour Engine          | ✅ implemented | Randomized mouse movement, scroll, dwell time, click jitter |
| Browser Controller              | ✅ implemented | Playwright/Chromium, screenshots, console + network capture |
| Navigation Replay Engine        | ⚠️ partial | Supports a scripted referrer chain; no live ad-network replay |
| Browser Monitoring Engine       | ✅ implemented | Playwright hooks (requests/responses, console, downloads, dialogs, DOM snapshot) plus runtime DOM/JS instrumentation: dynamic script/iframe injection, popup spam, storage exfil, clipboard, service workers, credential form submits |
| Threat Detection Layer          | ⚠️ heuristic only | Correlated multi-signal scoring: 60+ raw signals grouped into 8 attack clusters, where a cluster must fire rather than a single pattern — **not** a real exploit/heap-spray detector |
| Decision Engine                 | ✅ implemented | Risk bands loaded from `config/decision_policy.yaml`; a CRITICAL payload detection overrides the bands and diverts immediately |
| Enterprise Deception Environment| ✅ implemented | Local FastAPI app: login, HR portal, finance portal, file server, wiki — entirely synthetic |
| Honey Assets / Honeytokens      | ✅ implemented | Fake AWS/SSH/DB creds, fake invoices/HR docs, each with a unique token ID |
| Honeytoken access logging       | ✅ implemented | Any GET/read of a honeytoken file logs an alert with timestamp + session ID |
| Telemetry Engine                | ✅ implemented | SQLite (`telemetry/session.db`) + per-session JSON |
| Session Recorder                | ✅ implemented | Per-session JSONL forensic timeline in `reports/` |
| Automated Cleanup               | ✅ implemented | Per-session profile directory, wiped on session end |
| **Bait seeder**                 | ✅ implemented | Arms the browser profile *before* navigation — Downloads, bookmarks, cookies, localStorage — where infostealers actually harvest |
| **Canary vault**                | ✅ implemented | Operator-supplied tokens plus self-minted URL tokens; every placement stamped with its session, so a callback days later names the visit that planted it |
| **Compromise detector**         | ✅ implemented | Nine typed action-of-compromise kinds. Behaviour-based, so it catches what a signature list cannot |
| **Verdict database**            | ✅ implemented | SQLite URL verdicts with evidence + confidence; `/api/verdict` is the reputation endpoint the RBI modules consume |
| **Decoy tiering**               | ✅ implemented | Tier 0 open, tier 1 behind a silent JS gate, tier 2 behind human classification; failures get a tarpit, never a 403 |
| **Operator classifier**         | ✅ implemented | Bot vs human on mouse-path entropy and typing cadence — *not* `isTrusted`, which is true for CDP automation |
| **Dashboard**                   | ✅ implemented | Live control plane: swarm target, intervention queue, canary vault, verdict browser, SSE alerts |
| **Intervention queue**          | ✅ implemented | Blocked bots park and raise a hand; the operator clears the challenge and hands control back mid-session |
| **Swarm manager**               | ✅ implemented | N concurrent workers converging on an operator-set target |
| **Ad / redirect crawler**       | ✅ implemented | Directed clicking of links, iframes, ad slots; captures popups and records a navigation graph |
| **Runtime substrate**           | ⚠️ partial | `local` (dev, refuses non-loopback targets) and `docker` (container inside the WSL2 VM). Firecracker seam present but needs a Linux/KVM host |
| MITRE ATT&CK mapping            | ⚠️ stub | Best-guess technique IDs from a small lookup table, not a real mapping engine |
| Elastic/TimescaleDB              | ❌ not implemented | SQLite only |
| Wazuh export                     | ❌ not implemented | Next module; events are already structured for it |
| Thug integration                | ❌ not implemented | Playwright replaces Thug's role directly |

## Why some things are stubbed

Real VM/container-per-session isolation, a genuine exploit/heap-spray detector,
and a production telemetry stack (Elastic/TimescaleDB) are each multi-week
efforts on their own — building fake versions of them wouldn't give you
anything you could trust in a real research setting. Instead this drop gives
you a real, working pipeline for everything that can be honestly delivered
in one pass, with the harder infrastructure pieces clearly marked so you know
what to build or bring in next (see "Roadmap").

## Requirements

- Python 3.10+
- `pip install -r requirements.txt`
- `playwright install chromium`
- Docker (Docker Desktop on Windows/macOS, Docker Engine on Linux) for the
  contained hunter and the decoy tiers

### Platform — Linux and Windows

The platform runs on both. Everything in `src/`, `dashboard/`, and
`decoy_app/` is pure Python + Docker: memory sensing branches on the OS
(`GlobalMemoryStatusEx` on Windows, `/proc/meminfo` on Linux), and every
Docker call goes through `subprocess`, so nothing is shell-specific.

The only OS-specific pieces are the helper scripts in `scripts/*.ps1`
(firewall rule, service stop/resume) — **Windows-only**, and not required to
run the system. On Linux the equivalent host-isolation is an `iptables`/`ufw`
rule blocking the Docker bridge from host services; the decoys are already
contained on an internal network regardless.

### Ubuntu — full setup from a clean clone

```bash
# 1. Docker Engine, and your user in the docker group (log out/in after)
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker "$USER"

# 2. Python side
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install --with-deps chromium      # --with-deps pulls the libs Ubuntu needs

# 3. Your own canary token (the committed file is only a template)
cp config/canary_tokens.json.example config/canary_tokens.json
$EDITOR config/canary_tokens.json            # paste a free token from canarytokens.org

# 4. Build the four images (they are not published; build once per machine)
docker build -f docker/Dockerfile.honeypots -t clienthoneypot/decoy-services:latest .
docker build -f docker/Dockerfile.decoy     -t clienthoneypot/decoy-web:latest .
docker build -f docker/Dockerfile.cowrie    -t clienthoneypot/decoy-shell:latest .
docker build -f docker/Dockerfile           -t clienthoneypot/hunter:latest .

# 5. Stand up the decoys — contained, disguised, and verified from the inside
python scripts/deploy_decoy.py

# 6. Covert telemetry + payload capture (host-side; nothing runs in the decoy)
python src/decoy_telemetry.py

# 7. Console -> http://127.0.0.1:8000
python dashboard/app.py
```

**The console now needs a token.** It is minted on first run and printed here:

```bash
cat config/dashboard_token
```

Paste it into the unlock page, or send it as `Authorization: Bearer <token>`
from the RBI modules and any script that calls `/api/verdict`.

**Wazuh** needs the manager-side rules, or every finding arrives at the
manager's default level instead of the one the code intends:

```bash
docker cp wazuh/rules/clienthoneypot_rules.xml <manager>:/var/ossec/etc/rules/
docker exec <manager> chown wazuh:wazuh /var/ossec/etc/rules/clienthoneypot_rules.xml
docker exec <manager> /var/ossec/bin/wazuh-control restart
# then confirm a real event matches rule 100101-100120:
docker exec -i <manager> /var/ossec/bin/wazuh-logtest < <(tail -1 telemetry/siem.jsonl)
```

Run the SIEM on a **separate host** from the decoys — a manager plus the decoy
stack did not fit in 7.7 GB during testing (see `docs/ASSESSMENT.md`).

### Kali (and other Debian-based distros)

Kali runs the same system — it is Debian-based, and everything here is Python
plus Docker. Three differences are worth knowing before you start:

```bash
# 1. Package names differ from Ubuntu. Kali ships docker.io; the compose
#    plugin is packaged as docker-compose (v1 CLI) unless you add Docker's
#    own repo. Nothing here requires compose: the decoys are deployed by
#    scripts/deploy_decoy.py, and compose only builds/tags images.
sudo apt update && sudo apt install -y docker.io
sudo systemctl enable --now docker

# 2. `playwright install --with-deps` frequently fails on Kali, because the
#    dependency list resolves to Ubuntu package names that Kali's rolling
#    repos do not match. Install the browser without --with-deps, and add the
#    libraries yourself if Chromium complains at launch.
playwright install chromium
sudo apt install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2t64 || \
sudo apt install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2
```

**3. Do not hunt as root.** Kali is often used as root, and Chromium will not
start as uid 0 with its sandbox on. The code detects this and sets
`--no-sandbox` so it runs at all, but that removes a real boundary. For
anything beyond loopback targets use the docker substrate (`config/runtime.yaml`),
which is the supported path anyway:

```bash
sudo useradd -m -G docker hunter && sudo -iu hunter   # then run from there
```

Everything else — the decoys, covert telemetry, sample capture, the Wazuh
rules — is identical to the Ubuntu instructions above. The container images
pin their own bases (`playwright/python:v1.45.0-jammy`, `python:3.11-slim`,
`cowrie/cowrie`), so what runs inside them does not depend on the host distro
at all; only the four host-side Python packages and Docker do.

See `OPERATING.md` for the decoy tiers, covert telemetry, sample capture and
the kill-chain map, and `docs/ASSESSMENT.md` for what black-box testing found,
what was fixed, and what is still open.

## Quick start

```bash
pip install -r requirements.txt
playwright install chromium

# Terminal 1: the synthetic enterprise the payload gets diverted into
python decoy_app/app.py

# Terminal 2: the control plane  ->  http://127.0.0.1:8000
python dashboard/app.py

# Terminal 3 (optional): the mock malicious page to hunt
python tests/mock_malicious_site.py
```

Then in the dashboard: paste `http://127.0.0.1:8080/` into **Target queue**,
set **bots** to 2, and watch the swarm detect, divert, and record a verdict.

Single session without the dashboard:

```bash
python src/v2_orchestrator.py http://127.0.0.1:8080
```

Test suite, including the end-to-end detection → decoy loop against a real browser:

```bash
python -m pytest tests/ -q
```

Output:
- `telemetry/verdicts.db` — URL verdicts, compromise actions, canaries, hits
- `telemetry/session.db` — raw event log
- `reports/<session_id>_timeline.jsonl` — forensic timeline
- `screenshots/<session_id>/` — PNGs per navigation step

## Isolation — read this before pointing it at real malicious URLs

**The platform now refuses to do this for you.** `config/runtime.yaml` selects a
runtime substrate, and the default (`local`) rejects any target that is not
loopback:

```
[!] REFUSED: refusing to visit 'https://evil.example/' under the 'local'
    substrate: no isolation boundary.
```

To hunt live targets, set `runtime.profile: docker`. Each session then runs in a
container inside the **WSL2 utility VM** — a real Linux kernel in a lightweight
VM, which is why it works on Windows 11 Home where Hyper-V and Windows Sandbox
do not:

```
Windows host
└── WSL2 utility VM              <- the security boundary
    ├── hunt_net    : internet-facing, RFC1918 refused
    └── decoy_net   : internal only, no route off the host
```

A browser exploit lands in the container; a container escape lands in the VM;
reaching Windows needs a hypervisor or virtio-interop exploit — a different
class of attacker than a drive-by kit. This is strong, **not absolute**. It is
not a hardened microVM. `src/substrate.py` has the seam for Firecracker/gVisor,
which need a Linux/KVM host this machine cannot provide.

The `docker` profile also refuses RFC1918 targets outright: hunting must never
touch your own network, however isolated the browser is.

### Exposing the decoy

For a real attacker to reach the decoy, something must be internet-reachable.
From a home or office network that exposes *your* network. Ports bind to
`127.0.0.1` only, and that is deliberate — use a tunnel that terminates outside
your perimeter when you are ready, never a port-forward.

## Roadmap (not built here)

1. Real VM-per-session orchestration (gVisor default / Firecracker for
   high-risk personas), matching the spec's risk-based placement idea.
2. Swap the heuristic threat detector for a real behavioral/ML classifier
   trained on labeled exploit-kit traffic.
3. Wire in actual Thug as a parallel low-interaction pass for pages the
   high-interaction browser doesn't need to fully render.
4. Elastic/TimescaleDB backend + a real live multi-session dashboard.
5. Navigation Replay Engine: real ad-network / malvertising chain replay
   instead of a scripted referrer chain.
6. Proper MITRE ATT&CK mapping (current lookup table is illustrative only).

## Legal / ethical note

Only point this at URLs you're authorized to research (e.g. your own
threat-intel feed, a CTF/lab range, or sources your institution has cleared).
Don't run it against production infrastructure or anything you don't have
permission to probe.
