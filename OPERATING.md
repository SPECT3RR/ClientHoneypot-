# Operating ClientHoneypot

Everything the dashboard does, what each control actually means, and the
mistakes that produce a wrong answer.

---

## 1. Start the stack

Three processes plus two containers. Nothing works if the decoy is down.

```bash
powershell -File scripts/stop_services.ps1     # clean slate
```

```bash
python decoy_app/app.py                        # terminal 1 — the decoy
```

```bash
python dashboard/app.py                        # terminal 2 — the control plane
```

```bash
python tests/mock_ad_chain.py                  # terminal 3 — a target to practise on
```

Then open **http://127.0.0.1:8000**.

Check the state bar before doing anything. It tells you three things:

| Shows | Means |
|---|---|
| `IDLE / HUNTING / NEEDS OPERATOR / ATTACKER ENGAGED / CANARY FIRED` | worst thing currently true |
| `CONTAINED · docker` or `NOT CONTAINED · local` | where the browser executes |
| `loopback only` | live URLs will be **refused** |

---

## 2. The single most important number: capacity

This machine has 7.7 GB total. A **headed** Chromium costs ~450 MB, **headless**
~280 MB, and 300 MB is reserved for everything else.

The Capacity panel shows what actually fits *right now*. **Believe it.**

Asking for more bots than fit does not give more throughput. Before this was
enforced at spawn time, three headed bots launched into 640 MB, were starved,
clicked nothing, discovered nothing — and that nothing was recorded as a
**clean** verdict on a page that is definitely malicious. That is the single
most likely way to get a wrong answer out of this tool.

**If capacity says 0–1, run 1 bot.** Close Chrome windows to buy more; Chrome
routinely holds 2 GB across its processes. The **Pause other containers**
button frees whatever Docker is holding.

---

## 3. Headed vs headless

| Mode | Cost | Can you take over a blocked bot? |
|---|---|---|
| **headed** (default) | 450 MB | **Yes** — a real window opens |
| headless | 280 MB | **No** — there is no window to click in |

Headless fits more bots and is right for unattended bulk hunting. But an
intervention raised by a headless bot can be acknowledged and never actually
solved, which makes the whole human-in-the-loop design pointless.

**Working the intervention queue → headed, 1–2 bots. Bulk scanning → headless.**

---

## 4. Queue targets

**Paste** one URL per line, or **upload** a `.txt` / `.csv` / `.json` file.
Comments (`#`) and duplicates are dropped, and URLs already judged are skipped.

Two things that will bite you:

- **Typos are not caught.** `http://127.0.0.1/8001` (missing colon) is a valid
  URL pointing at a path. It now reports **`unreachable`**, not `clean` — but
  check what you pasted.
- **`loopback only` means loopback only.** Under the `local` profile anything
  that is not `127.0.0.1` / `localhost` is refused before a browser launches.
  For live targets, see §8.

---

## 5. Reading a verdict

| Verdict | Means |
|---|---|
| `malicious` | a CRITICAL action was observed, or the score cleared 60 |
| `suspicious` | a HIGH action, or score ≥ 30 |
| `clean` | examined, nothing fired |
| `unreachable` | **never examined** — navigation failed |

`clean` and `unreachable` are not the same claim. One says we looked, the other
says we could not.

**A clean verdict on the page does not mean the page is safe.** Expand the
finding: the contact block shows which third-party hosts it loaded and which
your threat feeds flag. `ww8.123moviesfree.net` scores 4 on its own behaviour
and contacts ten hosts VirusTotal calls malicious. That case surfaces for review
tagged *third-party infrastructure*.

Every finding carries **the exact signals that decided it** — the matched
pattern, its weight, its ATT&CK tag, and what it means in English. Open
*the exact signals that decided this* to see the reasoning rather than the score.

---

## 6. Why a "clean" result can be correct and still feel wrong

The mock ad chain is the clearest example, and it is worth understanding
because real malvertising is built the same way.

```
/                 the publisher    — ZERO malicious signals. Genuinely clean.
  /ad/rotator     ad broker        — redirects onward
  /ad/interstitial popup opener
    /land/kit     the exploit kit  — scores 79, classic_exploit_kit
    /land/phish   credential theft
```

Visiting `/` and scoring it gives **0, correctly**. The payload is two hops away.

This is what fan-out is for: the anchor bot holds `/`, and every popup and
redirect it uncovers **spawns its own bot**. A correct run looks like:

```
#1 [anchor] score 79 malicious  http://localhost:8081/
#2 [child ] score 79 malicious  http://localhost:8081/land/kit   <- via popup
```

**If you see the anchor alone with score 0 and `spawned: 0`, fan-out did not
run** — almost always because there was no memory for the child bot. Check the
Capacity panel.

---

## 7. Interventions — the human in the loop

When a bot hits a CAPTCHA or challenge wall it **parks** and raises its hand.
The rest of the swarm keeps hunting.

1. **Blocked bots** panel shows the target, the reason, and a screenshot
2. Find the browser window that bot opened (headed only)
3. Solve the challenge yourself
4. Click **Solved → resume** — the bot continues *in that same session*

`python /tmp/blocked_site.py` serves a Cloudflare-style wall on 8090 to practise.

---

## 8. Hunting live targets

**Default is loopback-only, deliberately.** To hunt the real internet:

```yaml
# config/runtime.yaml
runtime:
  profile: docker
```

Sessions then run inside a container in the WSL2 VM — not on Windows. Requires
Docker Desktop running and the image built:

```bash
docker build -f docker/Dockerfile -t clienthoneypot/hunter:latest .
```

What the container gives you: `cap-drop ALL`, non-root, no-new-privileges,
memory and pid limits, one writable directory, downloads cancelled, profile
wiped. What it does **not** give you: Docker Desktop injects
`host.docker.internal` into every container, so host ports remain reachable from
a compromised session. Closing that needs a Windows Firewall rule.

RFC1918 targets are refused even under `docker`. Hunting never touches your LAN.

---

## 9. The decoy — testing attacker engagement

The decoy is a real thing you can drive yourself.

**As a human operator:** open http://127.0.0.1:8001/portal/login, log in with
anything, click into the file server. Move the mouse naturally and type at an
uneven rhythm. You should classify as **`human_operator`** and reach tier 2 —
the real AWS keys, SSH keys and DB credentials.

**As a scanner:** `curl http://127.0.0.1:8001/portal/files/aws_keys.txt`
You get an "archived — contact IT" tarpit and classify as **`bot`**. No 403,
because an error tells a scanner it was detected.

Both appear live in **Decoy visitors**.

The classifier does **not** trust `isTrusted` — that flag is true for
Playwright, Puppeteer and Selenium. It weights mouse-path entropy and typing
cadence, which automation does not reproduce.

---

## 10. Canary tokens

Paste tokens in **Canary vault**, or mint self-hosted ones. Each gets a
placement:

| Placement | Lands in | Fires when |
|---|---|---|
| `browser_profile` | localStorage, cookies, Downloads, bookmarks | an infostealer exfiltrates it and someone uses it |
| `decoy_tier1` | portal pages | anything gets past the JS gate |
| `decoy_tier2` | file server | a classified **human** reaches the vault |
| `decoy_services` | a **working login** on qeeqbox SSH/FTP/MySQL | the attacker tries the credential they stole |

`decoy_services` is the one that closes the loop: without a service that
answers, a stolen SSH key hits connection-refused and the attacker learns
nothing landed.

Start both decoys — contained, disguised, and verified:

```bash
python scripts/deploy_decoy.py
```

Never start them with a bare `docker run`. The command that used to be printed
here mounted `config/honeypots` and `telemetry/honeypots` into the container,
and those mounts were visible to anyone who landed a shell:

```
D:\134 /var/log/honeypots 9p rw,...,aname=drvfs;path=D:\
```

That single line tells an attacker the host is a Windows workstation running
Docker Desktop with the operator's own drive attached, and it gave them a
writable path onto that drive. The decoys take their config by `docker cp` now
and log to stdout instead.

### Telemetry to Wazuh

Nothing is installed in the decoy. It logs to stdout, Docker's log driver
captures that in the daemon **on the host**, and a collector on the host reads
the stream and writes findings for a Wazuh agent to tail:

```bash
python src/decoy_telemetry.py
```

From inside the decoy there is no process, no port, no outbound connection, no
mount and no config revealing that it is watched — collection happens on the
far side of the container's namespaces. See `src/decoy_telemetry.py` for why
putting an agent in the decoy is the wrong answer.

Check containment and disguise at any time:

```bash
python scripts/deploy_decoy.py --verify
```

### Covert sample capture

The same collector process also captures any payload an attacker drops — an
exploit kit, a dropper, a webshell, a plain executable. It watches each
container's writable layer with `docker diff` and pulls new payloads out with
`docker cp <c>:<path> -` (a tar to stdout), both of which run in the daemon
**on the host**. Nothing runs inside the decoy, nothing is written into it, and
`docker exec` is never used — so from the attacker's side there is no watcher
process, no new file, and no sign a copy was taken.

Captures land in `telemetry/samples/`, **XOR-defanged** (`.quar`): the bytes on
disk are not a valid executable and cannot run, so a captured sample can never
infect the machine analysing it. The dashboard's *Captured payloads* panel
lists them; the download hands you the defanged `.quar`, which you un-defang
deliberately inside a sandbox:

```python
from sample_capture import SampleStore
open("sample.bin", "wb").write(SampleStore().unpack("<sha256>"))
```

Every download is audited as sensitive. The store is git- and docker-ignored —
malware never reaches a repo or an image.

### The Cyber Kill Chain map

Every finding is stamped with its Lockheed Martin kill-chain stage, in the SIEM
and on the dashboard's *Cyber Kill Chain* panel, which shows how far each
attacker got: a captured executable puts them at **Installation**, a fired
canary proves **Command & Control**, a honeytoken read is **Actions on
Objectives**. "Furthest stage reached" is the one number that ranks one
attacker against another.

### What is deliberately kept out of the decoy images

`.gitignore` protects the repository; it has no effect on `docker build`,
which sends the whole directory as build context regardless. `.dockerignore`
is the only thing keeping these out of an attacker-facing image, and before it
existed the decoy shipped with live threat-feed API keys and the canary bait
list inside it:

| Excluded | Why |
|---|---|
| `config/intel_keys.json` | working VirusTotal / Safe Browsing / abuse.ch keys |
| `config/canary_tokens.json` | the bait list — reading it tells them what to avoid |
| `config/honeypots/` | the logins the decoy accepts |
| `telemetry/`, `reports/` | prior sessions and collected intelligence |
| `tests/` | describes every detection rule and threshold |

The web decoy also has its **own** minimal image (`docker/Dockerfile.decoy`)
rather than the hunter image, which carries all 44 modules. It gets the four
it imports, with comments and docstrings stripped — the code is unremarkable,
but the commentary explained the bot/human strategy in plain English.

The service library is vendored as `filesync` at build time, so
`site-packages`, `pip list` and the startup banner do not name it either.

**Consequences to remember**

- The decoys build from images now, so **code changes need a rebuild** — there
  is no mount to pick them up:
  ```bash
  docker build -f docker/Dockerfile.decoy -t clienthoneypot/decoy-web:latest .
  ```
- `src/decoy_services.CONFIG_SECTION` must match `ARG PKG` in
  `docker/Dockerfile.honeypots`. If they drift, the config section is not
  found, **every service silently binds a random high port**, and the log
  still reports that everything is fine. The build and a test both assert it.

---

## 11. Threat feeds

Keys are entered **once** and stored in `config/intel_keys.json` (gitignored —
the writer refuses if git can see the path).

| Provider | Free at | Quota |
|---|---|---|
| **abuse.ch** | auth.abuse.ch | one key covers URLhaus **and** ThreatFox — start here |
| Google Safe Browsing | console.cloud.google.com | 10,000/day — the deepest fallback |
| VirusTotal | virustotal.com | 4/min, 500/day |
| OTX | otx.alienvault.com/api | generous |
| URLScan | urlscan.io | 100/day |

Every scan enriches its own contacts automatically. **Look up against feeds**
works through the backlog. When one provider hits its quota it stands down and
the others carry on.

---

## 12. Triage — your ruling

Only findings above the confidence floor surface. Weak single signals are logged
and never shown; surfacing them is how a detector learns to cry wolf.

- **Confirm malicious** → the malicious URL database, with its evidence attached
- **False positive** → verdict cleared so a consuming RBI stops isolating it,
  excluded from future queues, and kept as a labelled false positive

The false-positive rate is computed from your rulings. It is the only honest
way to tune the thresholds.

---

## Quick checklist when a result looks wrong

1. **Is the target actually up?** `curl` it.
2. **Does Capacity allow the bots you set?** If it says 0, nothing useful ran.
3. **Did fan-out spawn?** `spawned: 0` on an ad-heavy page means no child bots.
4. **Is the verdict `unreachable`?** Then it was never examined — check the URL.
5. **Is the page clean but the contacts flagged?** That is a real finding, not a
   miss.
6. **Under `local` with a live URL?** It was refused before a browser launched.
