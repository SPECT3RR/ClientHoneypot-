# Fan-out Swarm, Evidence Triage, and a Real Decoy — Design

**Date:** 2026-08-05
**Status:** Approved (concurrency + decoy decisions confirmed by operator)
**Builds on:** [2026-08-04 deception loop design](2026-08-04-client-honeypot-deception-loop-design.md)

## The hard constraint

```
cores      12
RAM        7.5 GB total
free       0.5 GB   (with the operator's 9-container RBI stack running)
```

A headed Chromium costs ~350–500 MB. The requested "3 bots fan out to 15" needs
5–7 GB of headroom this machine does not have while the RBI stack is up.

The fan-out design is still correct — it is the concurrency *ceiling* that must
be computed from live free memory rather than chosen. Asking for 15 bots runs
what fits and queues the rest. Nothing thrashes, and no session is OOM-killed
mid-hunt leaving a corrupt verdict.

**Operator decision:** auto-cap from live free RAM, and offer a one-click pause
of the RBI stack to free ~4 GB for a hunting run.

## Why qeeqbox, and why not T-Pot

The bait credentials currently have nowhere to land. We plant a fake SSH key, DB
password and VPN config in the browser profile; a stealer exfiltrates them; the
attacker tries them and gets connection refused. Only the HTTP URL token can
fire. The attacker learns nothing happened and does not come back.

**T-Pot** was rejected on two grounds: it needs 8–16 GB RAM on a 7.5 GB machine,
and it targets the wrong surface — Cowrie and Dionaea never see a JavaScript
stealer.

**qeeqbox/honeypots** answers the actual gap: 30 services (SSH, FTP, MySQL,
Postgres, Redis, SMB, VNC, RDP, LDAP, SMTP, MSSQL, Telnet, …), pure Python with
no ELK or JVM, pip- or Docker-installable, selectable per service
(`--setup ssh,mysql:3306`), capturing username/password plus optional command
capture, logging to JSON/SQLite. Light enough to run here, and it makes the
planted credentials *work*.

## Decoy architecture

```
decoy_net  (internal: true — no route to the host or the LAN)
├── decoy-web       Asteria portal        human with leaked portal credentials
└── decoy-services  qeeqbox honeypots     attacker using leaked SSH / DB / FTP creds
```

A canary registered in the dashboard is placed in three locations, all stamped
with the session that planted it:

| Placement | Lands in | Fires when |
|---|---|---|
| `browser_profile` | localStorage, cookies, Downloads, bookmarks | a stealer exfiltrates it |
| `decoy_web` | tier-1/tier-2 portal files | someone gets past the JS gate |
| `decoy_services` | a **working credential** on the matching qeeqbox service | the attacker actually tries it |

The third is the new one and the reason the loop closes.

## Build order

### Phase 8 — Intake and capacity

- **File upload.** `.txt` / `.csv` / `.json` of URLs, deduplicated against the
  queue and against already-visited URLs, chunked for processing.
- **Capacity governor.** Reads live free memory, computes
  `max_bots = free_mb / BOT_COST_MB`, exposes it to the dashboard, and hard-caps
  the swarm target. Headed and headless have different costs.
- **RBI pause.** Detects the operator's other containers and offers a one-click
  stop/restart to free memory for a run. Never automatic.

### Phase 9 — Fan-out swarm

The current crawler navigates in place and goes back. The requirement is
different: discoveries must **spawn new bots**.

- **Anchor bot** holds the URL the operator supplied and never leaves it.
- **Discovery queue.** Every redirect, popup, new tab, and ad click on any bot
  emits a discovery carrying its parent session id and depth.
- **Child bots** are spawned from discoveries, do the same aggressive work, and
  emit their own discoveries — so 3 bots become 10 or 15 as the ad chain opens
  up, bounded by depth, total-bot cap, and the capacity governor.
- **Provenance.** Every bot records its parent, so the dashboard can show the
  chain from the publisher the operator gave to the landing page that dropped
  the payload. That chain is the malvertising evidence.
- **Full permissiveness.** Chrome blocks popups and mixed content by default,
  which hides exactly what we are hunting. Popup blocking, safe browsing,
  mixed-content blocking and download protection are all disabled in the hunting
  profile. This is only safe under the isolated substrate, so the permissive
  flags are gated on it.

### Phase 10 — Evidence and triage

- **Evidence view.** For every verdict, the exact signals that produced it: the
  matched pattern, the snippet, the URL, the timestamp, the cluster that fired,
  and every observed action of compromise. Not a score — the actual reasoning.
- **Negative evidence.** When a URL is judged clean, say what was checked and
  what did not fire. "Nothing matched" is a finding the operator needs too.
- **Confidence floor.** Only findings above a confidence threshold surface for
  review. A page with one weak signal is logged, not escalated — false positives
  are the thing that destroys trust in a detection system.
- **Human triage.** Each surfaced finding is confirmed or rejected by the
  operator. Confirmed goes to the malicious URL database. Rejected goes to a
  visited-clean list, is excluded from future queues, and is recorded as a
  labelled false positive so the thresholds can be tuned against real data.

### Phase 11 — Real decoy containers

- Move the Asteria portal into its own container on `decoy_net`.
- Add the qeeqbox honeypots container, services selected by config.
- Extend the canary vault with the `decoy_services` placement, injecting the
  planted credential into qeeqbox at container start.
- Correlate a qeeqbox credential hit back to the session that planted it, the
  same way URL tokens already resolve.

### Phase 12 — Layout

Reorder the dashboard to the operator's working sequence, without redesigning it:

1. **Control** — bot count, URL paste, file upload, capacity readout
2. **Results** — findings awaiting triage, with their evidence, confirm/reject
3. **Live** — telemetry and logs streaming underneath

## Open risks

- **Memory.** Even with the RBI stack paused, this machine supports roughly 8–12
  headless or 4–6 headed bots. Deep fan-out will queue rather than run wide.
- **Permissive Chrome.** Disabling popup blocking and safe browsing removes
  guardrails the browser normally provides. Gated on the isolated substrate for
  that reason, and refused under `local`.
- **qeeqbox interaction depth.** Low-to-medium, not a real shell. It captures
  credentials and commands, which is what the canary flow needs; it will not
  hold a skilled operator's attention for long.
- **Fan-out explosion.** Ad networks loop by design. Depth, total-bot and
  per-domain caps are mandatory, not optional.
