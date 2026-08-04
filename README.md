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
