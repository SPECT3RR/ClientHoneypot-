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
| Browser Monitoring Engine       | ✅ implemented | Requests/responses, console, downloads, dialogs, DOM snapshot |
| Threat Detection Layer          | ⚠️ heuristic only | Regex/pattern based (obfuscated JS, exe/script downloads, redirect spam, known exploit-kit strings) — **not** a real exploit/heap-spray detector |
| Decision Engine                 | ✅ implemented | Threshold-based switch to decoy mode |
| Enterprise Deception Environment| ✅ implemented | Local FastAPI app: login, HR portal, finance portal, file server, wiki — entirely synthetic |
| Honey Assets / Honeytokens      | ✅ implemented | Fake AWS/SSH/DB creds, fake invoices/HR docs, each with a unique token ID |
| Honeytoken access logging       | ✅ implemented | Any GET/read of a honeytoken file logs an alert with timestamp + session ID |
| Telemetry Engine                | ✅ implemented | SQLite (`telemetry/session.db`) + per-session JSON |
| Session Recorder                | ✅ implemented | Produces `reports/<session_id>.json` and a simple HTML summary |
| Automated Cleanup               | ⚠️ partial | Closes browser context, wipes temp profile dir; **does not** manage VMs/containers — see below |
| Dashboard                       | ⚠️ minimal | Static HTML report per session, not a live multi-session dashboard |
| MITRE ATT&CK mapping            | ⚠️ stub | Threat detector tags findings with a best-guess ATT&CK technique ID from a small lookup table, not a real mapping engine |
| Elastic/TimescaleDB              | ❌ not implemented | SQLite only |
| VM/Docker sandbox isolation      | ❌ not implemented | A `docker/` folder is provided to run the *controller* in a container, but true untrusted-browser isolation (gVisor/Firecracker/disposable VM) is out of scope for this drop — see "Isolation" below |
| Thug integration                | ❌ not implemented | This MVP replaces Thug's role with Playwright directly; wiring in Thug as a secondary low-interaction pass is a documented next step |

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
cd thug-deception-platform
pip install -r requirements.txt
playwright install chromium

# Terminal 1: start the decoy enterprise environment
python decoy_app/app.py

# Terminal 2: run a session against one or more URLs
python src/orchestrator.py --urls https://example.com --persona finance_qatar
```

Output:
- `telemetry/session.db` — raw event log (SQLite)
- `screenshots/<session_id>/` — PNGs per navigation step
- `reports/<session_id>.json` — full structured report
- `reports/<session_id>.html` — human-readable summary

## Isolation — read this before pointing it at real malicious URLs

This MVP does **not** run the browser inside a disposable VM or gVisor/Firecracker
sandbox. For actual malicious-URL research you must supply that isolation
yourself, e.g.:
- Run the whole `thug-deception-platform` container (see `docker/Dockerfile`)
  inside a disposable VM snapshot you already control, with egress restricted
  to the target research range.
- Or run it in a cloud sandbox account with no route to any production network,
  no real credentials, no VPN.

The `docker/` folder isolates *process/filesystem* state per run (fresh
container, fresh profile dir, destroyed on exit) but is **not** a security
boundary against a browser exploit escaping to the host kernel. Treat it as
convenience/repeatability isolation, not a sandbox.

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
