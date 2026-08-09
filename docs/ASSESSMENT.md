# Industry-viability assessment

Adversarial (black-box / grey-box) testing of the running system, 2026-08-06.
Every finding below was produced by attacking the platform, not by reading it.
Where something could not be tested, that is stated rather than assumed.

**Method.** A separate attacker container (`openssh-client`, `sshpass`) on
`decoy_net`, driving real SSH and SCP against the decoys exactly as an intruder
would; a real `wazuh/wazuh-manager:4.9.0` container for the SIEM side; the
FastAPI test client against the console with no credentials.

---

## Verdict

**Not ready for an unsupervised production launch. Ready for lab and
supervised-pilot use once the two open items below are closed.**

The core is genuinely strong and does something most honeypot stacks do not:
containment is *enforced and re-proven on every deploy*, telemetry collection
is invisible from inside the decoy, and dropped payloads are captured and
stored inert. The gaps are at the edges — an emulated shell that a skilled
operator can fingerprint, and a SIEM path validated on paper but not yet fired
end-to-end through a manager.

---

## What was verified working

| Capability | Evidence |
|---|---|
| Containment of all three decoys | 4/4 egress probes blocked from inside each container (internet, host, a plausible SIEM, LAN gateway) on every deploy |
| Covert telemetry | From inside the decoy: no monitoring agent, 0 established outbound connections, 0 host mounts, no process or on-disk path naming the software |
| Stolen-credential engagement | A canary-vault SSH credential opened a real shell; shipped as `decoy.planted_cred` at severity 13 with token attribution |
| Payload capture | A PE, an ELF and a PowerShell dropper written into a decoy were captured host-side, stored XOR-defanged (`.quar`, no runnable header), and shipped at `installation` |
| SCP file drop | An uploaded ELF implant saved by Cowrie, pulled out with `docker cp`, defanged, attributed to its session |
| Kill-chain mapping | Sessions correctly ranked to their furthest stage; a captured executable places an attacker at Installation |
| Console authentication | 7/7 sensitive routes answer 401 to an unauthenticated caller; bearer and cookie paths both work |
| Test suite | 319 passing |

---

## Findings

### P0-1 — The shell decoy announced itself in one command *(FIXED)*

`build_userdb()` emitted `root:x:*` and `admin:x:*`, meaning **any** password
was accepted:

```
ssh root@asteria-app02   with 8 random bytes as the password   ->  shell
```

No real server behaves that way. This was our own configuration choice, made to
attract brute force, and it defeated the whole disguise. Replaced with a fixed
list of genuinely common passwords: a real brute-force run still succeeds, a
random string no longer does.

### P0-2 — The console had no authentication *(FIXED)*

24 routes, 16 mutating, no auth of any kind. Anyone reaching `:8000` could list
every canary token (learning the complete bait set, and therefore what to
avoid), download captured malware, clear verdicts, change containment, and read
or store threat-feed keys.

Fixed with a single operator token, enforced as **middleware** so a route added
later is protected by default. Bearer header for the RBI modules, cookie for
the browser, `hmac.compare_digest` for the comparison.

### P0-3 — Wazuh received events no rule could match *(FIXED, partially validated)*

The code assigned each finding a severity on Wazuh's 0–15 scale and the module
claimed thresholds would work untuned. **That was wrong.** Wazuh's JSON decoder
parses our fields into `data.*`, but the alert level comes from whichever
*rule* matches — and no rule matched our events at all, so everything would
have arrived at the manager's default level. The severity we were careful about
meant nothing on the receiving end.

Added `wazuh/rules/clienthoneypot_rules.xml` — a parent rule plus one child per
event carrying the intended level, MITRE technique, and kill-chain stage.
Generated from `siem.py` by `scripts/gen_wazuh_rules.py`, so the two cannot
drift, with tests asserting coverage, level parity, ID range, and staleness.

Generating it caught a bug hand-review missed: **a double hyphen is illegal
inside an XML comment**, and the first version's header had one. Wazuh would
have rejected the entire rules file.

**Validated:** well-formed XML; every event has a rule; levels match
`siem.EVENTS`; IDs in the site-local range; a real manager starts and runs
`wazuh-analysisd`.
**Not yet validated:** the rules firing at their intended level under
`wazuh-logtest` — see P1-5.

### P1-4 — Cowrie's emulated shell is fingerprintable *(NOT FIXED — architectural)*

Measured from a real SSH session:

| Probe | Result |
|---|---|
| `id` vs `/etc/passwd` | reports `svc_deploy(4605)`, but no such entry in `/etc/passwd` |
| `uname -a` vs `gcc --version` | kernel Debian 6.1.90 (2024) alongside gcc 4.7.2 (2012) |
| `head -5 file` | `head: invalid option -- '5'` (real coreutils accepts it; `head -n 5` works) |
| write, reconnect, read | file does not persist across sessions |
| `python3 -c ...`, `mount` | `cannot execute binary file: Exec format error` |

These are inherent to medium-interaction emulation. In this Cowrie build the
fake filesystem is **pickle-backed**, so even `/etc/passwd` cannot be corrected
without forking Cowrie's data — a fix that re-breaks on every upstream update,
and which the next tell defeats anyway.

**The real remedy is available:** this Cowrie build ships `cowrie.ssh_proxy`,
i.e. **proxy mode**, which MITMs SSH to a genuine backend OS. The attacker
interacts with a real system (nothing to fingerprint) while Cowrie logs
everything and still captures files. That is the industry answer and the
recommended next step before facing skilled adversaries.

### P1-5 — The platform and a Wazuh manager do not fit on this host *(hardware)*

Running `wazuh/wazuh-manager` alongside the three decoys exhausted memory: the
WSL2 VM collapsed (`vmmemWSL` fell to 8 MB), the Docker daemon stopped
answering, and it did not recover across several clean restarts. Free RAM was
~500 MB before the attempt on a 7.7 GB machine.

This is why the live `wazuh-logtest` run is outstanding, and it is a genuine
deployment constraint, not a code defect: **run the SIEM on a different host**,
which is normal practice anyway. On the Ubuntu machine, validate with:

```bash
docker cp wazuh/rules/clienthoneypot_rules.xml <mgr>:/var/ossec/etc/rules/
docker exec <mgr> chown wazuh:wazuh /var/ossec/etc/rules/clienthoneypot_rules.xml
docker exec <mgr> /var/ossec/bin/wazuh-control restart
docker exec -i <mgr> /var/ossec/bin/wazuh-logtest < a-line-from-telemetry/siem.jsonl
```

Expect the matching rule id (100101–100120) and its level in the output.

---

## Remaining gaps for a production launch

| Gap | Impact | Effort |
|---|---|---|
| `wazuh-logtest` not yet run against the rules | Rule firing unproven end-to-end | 1 hour on adequate hardware |
| Cowrie fingerprintable | A skilled attacker disengages | Proxy mode: ~1 day |
| Single shared console token, no TLS | Fine for one operator on loopback; insufficient for a team or remote access | ~1 day (per-user auth + TLS) |
| No log rotation for `siem.jsonl` / sample store | Unbounded growth on a long-running deployment | ~2 hours |
| Single host, no HA, no backup of the verdict DB | Losing the box loses the canary vault and all attribution | ~1 day |
| No external exposure path | Decoys are reachable only from `decoy_net`; a real attacker cannot arrive without a deliberate tunnel | Design decision, not a defect |

## What is genuinely strong

- **Containment is proven, not declared.** The deploy script attacks its own
  network from inside and refuses to report success until every egress probe
  fails. This caught a real gap once already, where a compose declaration was
  doing nothing.
- **Nothing in the decoy participates in its own monitoring.** No agent, no
  port, no mount, no outbound session — collection happens on the far side of
  the container's namespaces, and captured lines are on the host before the
  attacker could know capture exists.
- **Captured malware is inert by construction**, never stored runnable, never
  in git, never in an image.
- **The generated Wazuh rules cannot drift from the code**, and the generator
  found a defect that review had not.
