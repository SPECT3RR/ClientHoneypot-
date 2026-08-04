# ClientHoneypot — Deception Loop Design

**Date:** 2026-08-04
**Status:** Approved
**Scope:** Module 3 of the 5-module platform, built standalone. Merges with RBI later.

## Context

ClientHoneypot is the hunting module of a five-module platform:

1. RBI — DOM-reconstruction based
2. RBI — VNC / pixel-streaming based
3. **ClientHoneypot** — this document
4. Wazuh — SIEM / correlation spine
5. LLM layer

Module 3 goes out on the web, finds malicious sites, gets compromised on purpose, and
turns that into intelligence: a scored URL database, attacker TTPs, and canary tokens
that fire from attacker infrastructure days later.

It is built and stabilised **independently**. RBI coupling happens after it works.

## Goal

Close a loop that does not exist today:

```
1. Honeyclient visits a suspicious URL with an armed persona
2. Payload lands → threat engine fires → session marked COMPROMISED
3. Bait is already in place: per-session canary credentials and a decoy portal
   URL seeded into localStorage, cookies, saved logins, autofill, Downloads,
   and bookmarks — where infostealers actually look
4. Payload exfiltrates the bait to attacker infrastructure
5. Attacker or their tooling uses the credentials against our decoy portal
6. Decoy classifies the visitor: bot → tarpit, human operator → open the vault
7. Tier-2 canaries fire from attacker infrastructure later
8. Everything lands in the URL verdict DB and the dashboard
```

Step 3 is the engine and it does not exist. Steps 5–7 exist only as an unreachable stub.

## Non-goals for this phase

Wazuh export, RBI coupling, ruflo orchestration, autonomous threat-feed ingestion,
ML-based classification, and Firecracker/gVisor microVMs. Each is deferred with a
named trigger in "Deferred work".

## Architecture

### Containment

Windows 11 Home has no Hyper-V and no Windows Sandbox, so per-session microVMs are not
available on the development machine. WSL2 is, and it is a genuine VM with its own Linux
kernel — not a container. That is the security boundary.

```
Windows 11 Home  (development, dashboard UI in browser)
└── WSL2 (Ubuntu)                        ← security boundary
    ├── dashboard + control plane        :8000
    ├── honeyclient workers              egress: internet only, RFC1918 blocked
    └── decoy portal                     separate docker network, no egress
```

A Chromium zero-day lands inside the WSL2 VM. Reaching Windows from there requires a
hypervisor or virtio-interop exploit — a materially different class of attacker than a
drive-by kit. `wsl --export` / `wsl --import` provides snapshot-restore, giving the
disposability the microVM design wanted.

Two runtime profiles, selected by config, with identical application code:

| Profile | Substrate | Use |
|---|---|---|
| `local` | Windows host, Playwright direct | Development only. Never point at live malicious URLs. |
| `wsl` | WSL2, egress-restricted | Live hunting. |

The VM lifecycle sits behind one interface (`runtime/substrate.py`) so Firecracker drops
in unchanged once a Linux/KVM host exists.

Headed browsing is required for human takeover. Under `wsl`, WSLg renders the browser to
the Windows desktop. Phase 1 runs workers directly in WSL2 rather than in containers —
the VM is already the boundary, and containerising blocks WSLg for no additional
guarantee. Containers are added in phase 2 as defence in depth.

### Component map

New components are marked NEW; everything else is an edit to existing code.

| Component | File | Responsibility |
|---|---|---|
| Threat scorer bridge | `src/threat_scorer.py` | Connect the bus to the existing detection engine |
| Runtime instrumentation | `src/browser_controller.py` | Inject `instrumentation.py`; per-session profile + wipe |
| Bait seeder | `src/bait_seeder.py` NEW | Arm the profile with canaries before navigation |
| Compromise detector | `src/compromise_detector.py` NEW | Classify actions of compromise from bus events |
| Ad / redirect crawler | `src/link_crawler.py` NEW | Click every ad and link, follow chains, record the graph |
| Operator classifier | `src/operator_classifier.py` NEW | Bot vs human, on the decoy side |
| Canary vault | `src/canary_vault.py` NEW | Store operator-supplied tokens, place them, track hits |
| Verdict DB | `src/verdict_db.py` NEW | URL verdicts, evidence, query API |
| Intervention queue | `src/interventions.py` NEW | Park blocked tabs, summon a human, hand back |
| Swarm manager | `src/swarm.py` NEW | N concurrent workers, lifecycle, scaling |
| Decoy portal v2 | `decoy_app/` | Tiering, JS entry gate, visitor scoring |
| Dashboard | `dashboard/` NEW | Control plane |

### Data flow

```
URL queue ──> Swarm manager ──> Worker (BrowserSession + bait-armed profile)
                                   │
                                   ├── bus events ──> threat scorer ──> decision policy
                                   │                  compromise detector       │
                                   │                  page classifier           │
                                   │                                           ▼
                                   ├── blocked? ──> intervention queue ──> dashboard ──> human
                                   │
                                   └── verdict ──> verdict DB ──> dashboard

Attacker ──> decoy portal ──> operator classifier ──> tier gate ──> canary placement
                                                                        │
Attacker infra ──> canary callback ──> canary vault ──> alert ──────────┘
```

## Component specifications

### 1. Threat scorer bridge

`src/threat_scorer.py` currently scores redirects at +5 and ignores
`src/threat_detection.py` entirely — 60+ signals and 8 correlation clusters are
disconnected. This makes the decoy unreachable.

Rewrite it to hold a `threat_detection.ThreatScorer` instance and feed it:

| Bus event | Call |
|---|---|
| `dom_snapshot` | `scan_dom(html, url)` |
| `script_evaluation` | `scan_script_text(text, url)` |
| `download` | `scan_download(filename)` |
| `redirect` | `scan_redirect_chain(chain_len)` |
| `visit_start` | `scan_url(url)` |

Publish `threat_score_updated` on every change, and `payload_detected` with
`confidence: CRITICAL` when `should_trigger_decoy()` returns true. That last event is
what `decision_policy.py` already listens for and never receives.

Also fix `_domain_allowlisted` in `threat_detection.py:51`: `.lstrip("www.")` strips a
character *set*, so `wow.com` becomes `ow.com`. Use `removeprefix("www.")`.

### 2. Runtime instrumentation

`src/instrumentation.py` is 173 lines of complete, working runtime hooks that nothing
injects. Wire it in `BrowserSession.start()`:

- `add_init_script(INSTRUMENTATION_JS)`
- `expose_binding("__reportRuntimeEvent", ...)` → publish as `EventCategory.DOM`

This surfaces dynamic script and iframe injection, popup spam, storage exfiltration,
clipboard access, permission prompts, service-worker persistence, and credential form
submits. All of it currently invisible.

Two further changes in the same file:

- **Per-session profile.** `browser_controller.py:41` resolves to
  `config/profiles/default` for every session, so malicious cookies, service workers,
  and CacheStorage accumulate across runs and contaminate later sessions. Use
  `profiles/{session_id}` and call the existing `cleanup.wipe_temp_profile()` in
  `stop()`.
- **Missing dependencies.** Add `playwright-stealth`, `pyyaml`, and `pyautogui` to
  `requirements.txt` — all are imported and none are declared.

### 3. Bait seeder — NEW

Runs before the first navigation. Writes per-session canary artifacts into the browser
profile in the places infostealers actually harvest:

| Location | Artifact |
|---|---|
| `localStorage` / `sessionStorage` | session tokens, API keys |
| Cookies | auth cookie for the decoy portal domain |
| Login Data (Chromium profile DB) | saved credentials for the decoy portal |
| Autofill | corporate email, employee ID |
| `Downloads/` | `vpn_config.ovpn`, `credentials.txt`, an AWS credentials file |
| Bookmarks | decoy portal, internal wiki |

Every artifact carries the session ID, so any later callback identifies the visit that
produced it. Tokens come from the canary vault (§7) — the seeder never invents them.

Bait is armed on every session regardless of verdict. A payload that steals credentials
does so before we score it.

### 4. Compromise detector — NEW

Consumes bus events and emits typed `compromise_action` events. Actions of compromise:

| Kind | Source |
|---|---|
| `file_download` | Playwright `download` event |
| `command_execution` | dropper patterns already in `JS_SIGNALS` |
| `dynamic_code_injection` | instrumentation: script / iframe injection |
| `persistence` | instrumentation: service-worker registration |
| `data_exfiltration` | instrumentation: storage writes, clipboard reads |
| `credential_harvest` | instrumentation: credential form submit |
| `outbound_beacon` | network request to a host outside the page origin, post-load |
| `popup_abuse` | instrumentation: popup count, plus `new_tab_opened` |
| `websocket_channel` | WebSocket or WebRTC data channel opened |

Every action is recorded with full evidence. A confirmed compromise action escalates
`payload_confidence` independently of the numeric score — a downloaded `.exe` should not
have to wait for a cluster to fire.

This is also the zero-day path: an unknown exploit still has to *do* something
observable. Behaviour-based detection catches what the signature list cannot.

### 5. Ad / redirect crawler — NEW

`behavior_engine.random_click()` clicks blindly at screen centre. Replace with directed
exploration:

- Enumerate links, iframes, and ad slots; click them in randomised order
- Capture popups and new tabs via the existing `_on_new_page` hook, and monitor them
- Follow redirect chains to a configurable depth (default 5)
- Record the full navigation graph — node per URL, edge per transition, tagged with
  the trigger (click, redirect, popup, meta-refresh)
- Cap per-page dwell and total session time; ad chains can loop indefinitely

The navigation graph is evidence: it is how you show a malvertising chain from a clean
publisher to a landing page.

### 6. Operator classifier — NEW

Distinguishes a scanner bot from a human operator on the decoy side. Reuses the
discriminator already built in `ownership_manager.py` and the init script in
`browser_controller.py:60`, which classify input by `e.isTrusted` and track activity and
idle transitions. Written to detect a human taking over our bot; here it detects a human
driving the attacker's session. Same mechanism, mirrored.

| Signal | Weight |
|---|---|
| Trusted input events present | +40 |
| Typing with variable inter-key delay | +20 |
| Mouse entropy above threshold | +20 |
| Time to first interaction in 1.5s–120s | +15 |
| Non-linear navigation (back, revisit, branch) | +15 |
| Known scanner user-agent | −25 |
| Sequential path enumeration | −30 |
| Requested `robots.txt`, `.env`, `.git`, `wp-admin` | −30 |
| No JS execution at all | −50 |

Threshold for tier 2: **60**, matching `DECOY_TRIGGER_THRESHOLD` on the client side.

### 7. Canary vault — NEW

The operator supplies tokens through the dashboard; the system decides placement and
tracks every hit back to its origin.

Stored per token: kind (AWS key, DNS callback, URL token, tracking pixel, document),
value, placement policy, and burn state.

| Placement | Lands in | Fires when |
|---|---|---|
| `browser_profile` | Bait seeder targets (§3) | an infostealer exfiltrates and someone uses the credential |
| `decoy_tier1` | Dashboard, HR and finance pages | anything gets past the JS gate |
| `decoy_tier2` | File server, crown jewels | a classified human reaches the vault |

Each placement is stamped with the session ID at placement time. `config/canary_tokens.json`
currently holds one hardcoded static pair used by every session — one burn kills them
all. It is replaced by per-session generation from the vault.

Callback receiver: a FastAPI route for URL, DNS, and pixel tokens. AWS-key callbacks use
canarytokens.org's free tier as the receiver, since we cannot observe AWS API usage
ourselves.

### 8. Verdict DB — NEW

SQLite, alongside the existing `telemetry/session.db`.

```sql
urls(url PK, host, tld, first_seen, last_seen, visit_count, max_score, verdict)
verdicts(id PK, url, session_id, ts, score, clusters JSON, findings JSON, decision)
compromise_actions(id PK, session_id, url, kind, detail JSON, ts)
nav_graph(id PK, session_id, from_url, to_url, trigger, ts)
canaries(token_id PK, kind, value, placement, session_id, placed_ts, burned)
canary_hits(id PK, token_id, ts, src_ip, user_agent, detail JSON)
decoy_sessions(id PK, ts, src_ip, ua, tier_reached, classification, score)
interventions(id PK, session_id, url, reason, screenshot_path, status, ts)
```

`verdict` is one of `clean | suspicious | malicious | blocked | unknown`. The query API
returns verdict **plus evidence and confidence** — a boolean is not actionable for a SOC,
and the consuming RBI needs to explain why it raised isolation.

### 9. Intervention queue — NEW

Today `orchestrator.py:191` writes a line to `needs_human_review.txt` and skips the URL.
The human is never summoned and the session is lost. Both entries in that file are sites
that blocked the bot with nobody told.

Replace with: park the tab, capture a screenshot, raise an intervention, and block that
worker on human resolution while the rest of the swarm continues. The human clears the
challenge; `notify_human_idle()` hands control back to the bot mid-session. The
`ownership_manager` state machine already supports this transition and nothing calls it.

Detection quality also improves: `_is_blocked` currently substring-matches `cloudflare`,
`blocked`, and `challenge` anywhere in host or path, which is how both existing entries
were flagged. Add page-content checks (challenge iframes, known interstitial markers)
alongside the status code.

Takeover under `local`/`wsl` focuses the browser window. Streamed takeover with input
forwarding is deliberately not built — that is what RBI modules 1 and 2 are, and they
fill this in at merge.

### 10. Swarm manager — NEW

Runs N concurrent workers against the URL queue. Per worker: own session ID, own persona,
own profile directory, own bait set. Enforces a global rate limit, per-host politeness,
and a hard session timeout.

Scaling is dashboard-driven: set a target count, and the manager converges by starting or
draining workers. Workers parked on interventions do not count toward the live target.

### 11. Decoy portal v2

The existing FastAPI app gains tiering and a gate.

| Tier | Gate | Contents |
|---|---|---|
| 0 | none | Login page, corporate shell |
| 1 | JS challenge solved **and** valid leaked credentials | Dashboard, HR and finance listings |
| 2 | operator score ≥ 60 | File server: AWS keys, SSH keys, VPN configs, DB credentials |

The entry is deliberately easy — leaked credentials simply work, no MFA, no CAPTCHA. The
filter is silent: submitting the login form requires a JS-computed value, which defeats
`curl`, `requests`, and most scanners without ever looking defensive. A CAPTCHA would
deter the human operator we want and advertise that the target is instrumented.

Bots that get past tier 0 but fail the behavioural gate receive a plausible, slow,
sparse tarpit. This preserves tier-2 tokens for real operators and avoids teaching
attacker tooling what our bait looks like.

The existing randomized walk in `decoy_navigator.py` is complete and unused; it is
repurposed as the decoy's own self-test fixture.

### 12. Dashboard — NEW

FastAPI + Jinja2 + Server-Sent Events. No new dependencies: FastAPI, uvicorn, and Jinja2
are already declared, and the event bus is already an event stream that SSE consumes
directly. No React, no build step.

| Screen | Contents |
|---|---|
| **Swarm control** | Target bot count, live / parked / blocked counts, per-bot current URL and threat score, start / stop / scale, kill switch |
| **Intervention queue** | Parked tabs with reason and screenshot, take-over and skip. The highest-value screen — this is what makes bot-blocking survivable |
| **Canary vault** | Paste tokens, tag by kind, set placement policy, view placements and hits |
| **Verdict DB** | Searchable URL table: score, clusters, ATT&CK tags, evidence, first and last seen |
| **Live alerts** | Canary fired, compromise action detected, bot blocked, decoy visitor classified human |

## Error handling

- **Worker crash** — the swarm manager restarts the worker on the next URL; the failed
  session is recorded with `verdict: unknown` and its partial timeline is preserved.
- **Bus subscriber exception** — `event_bus.py:87` currently dispatches with
  `create_task()` and never awaits, so exceptions in async subscribers vanish silently.
  For a forensic recorder that is a correctness bug. Replace with a bounded queue and
  awaited dispatch that logs failures.
- **Decoy unreachable** — bait seeding still proceeds; the session is recorded with a
  `decoy_unreachable` flag rather than aborted.
- **Canary vault empty** — sessions run with bait seeding disabled and a dashboard
  warning. Hunting must not be blocked on token supply.
- **Ownership state race** — `_set_state` calls `.set()` then immediately `.clear()`, so
  a waiter that has not yet reached `await` misses the edge and stalls a generation.
  Replace with a condition variable or per-generation event.

## Testing

Each non-trivial component ships one runnable check, per the project's existing style —
no framework, no fixtures.

- `tests/mock_malicious_site.py` already exists and exercises the detection heuristics.
  Extend it to trigger each correlation cluster and each compromise-action kind.
- **Loop integration test:** mock site → detection → bait exfiltration → decoy visit →
  canary fire, asserted end to end against the verdict DB.
- **Operator classifier:** replay two recorded sessions — one `curl` enumeration, one
  human — and assert opposite classifications.
- **Bait seeder:** assert every artifact is written and readable from a fresh Chromium
  profile.
- **Verdict DB:** assert idempotent upsert on repeat visits and correct score escalation.

## Build order

| Phase | Delivers | Why here |
|---|---|---|
| **1** | Threat scorer bridge, instrumentation wiring, per-session profiles, bus fix | Nothing else works until detection fires and events are trustworthy |
| **2** | Verdict DB, compromise detector | Turns sessions into a persistent asset |
| **3** | Canary vault, bait seeder | The intelligence engine |
| **4** | Decoy v2, operator classifier | Completes the loop |
| **5** | Dashboard, intervention queue | Makes it operable and unblocks bot-blocked sites |
| **6** | Swarm manager, ad/redirect crawler | Scale — only once the loop is correct |
| **7** | WSL2 substrate + egress rules | Before any live malicious URL |

Phase 7 gates live hunting. Phases 1–6 run under the `local` profile against
`tests/mock_malicious_site.py` only.

## Deferred work

| Deferred | Trigger to build |
|---|---|
| Wazuh export | Loop is stable; roughly a day once events are clean |
| RBI coupling | Modules 1 and 2 ready; `BrowserSession` is the seam |
| Streamed human takeover | Arrives free with RBI |
| ruflo orchestration | Swarm exceeds what the event bus coordinates well |
| Firecracker / gVisor | A Linux/KVM host exists; drops in behind `runtime/substrate.py` |
| Autonomous feed ingestion | Verdict DB proves useful on manual URL lists |
| v1 `orchestrator.py` | Dead — `TypeError` on launch from signature drift. Delete after phase 5 replaces it |

## Open risks

- **Internet exposure.** For a real attacker to reach the decoy, something must be
  reachable from outside. From a home or office network that exposes *your* network. Free
  path when ready is a Cloudflare Tunnel, which terminates outside the perimeter.
  Everything runs against localhost until then; the exposure point stays a config value.
- **Canary supply.** Tier-2 value depends on operator-supplied tokens. Empty vault means
  degraded intelligence, not a broken system.
- **WSL2 is not a microVM.** Strong, not absolute. Phase 7 must include egress
  restriction and a snapshot-restore routine, not just "run it in WSL".
- **Config drift.** Five YAML files in `config/` are currently read by no code. Any
  behaviour this spec describes as configurable must actually load from them, or the
  files should be deleted.
