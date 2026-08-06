"""
Cyber Kill Chain mapping — turn the platform's findings into an attack story.

The platform already emits typed findings: a connect, a login, a captured
sample, a fired canary. On their own they are a flat list. The kill chain is
the frame that says which of these is early-stage noise and which means an
adversary is deep in, so an operator reading the dashboard sees "they reached
Actions on Objectives" rather than scrolling twelve rows.

Lockheed Martin's seven stages, in order. The index matters: "furthest stage
reached" is the single number that ranks one attacker against another.

  1 reconnaissance        looking: scans, connects, page enumeration
  2 weaponization         building the payload — happens on their side, so we
                          almost never see it directly; inferred from delivery
  3 delivery              the payload arrives: a malicious page served to a
                          hunt, a file transferred in
  4 exploitation          the payload runs or a stolen credential is tried
  5 installation          it writes itself to our disk — a captured executable
  6 command_and_control   a channel back to them proves out: a canary fires
                          from their infrastructure, a beacon leaves
  7 actions_on_objectives the goal: reading honeytokens, pulling files,
                          moving laterally

The mapping is deliberately a plain dict, not a classifier. Every arrow is a
decision someone can read and argue with, which is what you want in the thing
that decides whether to wake a human at 3am.
"""

# (key, human label). Order is the kill-chain order and is load-bearing.
STAGES = [
    ("reconnaissance",        "Reconnaissance"),
    ("weaponization",         "Weaponization"),
    ("delivery",              "Delivery"),
    ("exploitation",          "Exploitation"),
    ("installation",          "Installation"),
    ("command_and_control",   "Command & Control"),
    ("actions_on_objectives", "Actions on Objectives"),
]
STAGE_INDEX = {key: i for i, (key, _) in enumerate(STAGES)}
STAGE_LABEL = dict(STAGES)

# Finding action -> stage. A finding not listed here carries no kill-chain
# meaning (a clean verdict, an operator intervention) and is skipped.
EVENT_STAGE = {
    # Looking around.
    "decoy.connect":          "reconnaissance",
    "decoy_page_view":        "reconnaissance",
    "session.refused":        "reconnaissance",
    "intel.flagged":          "reconnaissance",   # profiling third-party infra

    # A payload reaches us.
    "verdict.suspicious":     "delivery",
    "verdict.malicious":      "delivery",         # a weaponised page served
    "sample.captured":        "delivery",         # a non-executable file arrived

    # Something runs, or a stolen key is tried.
    "decoy.login_failed":     "exploitation",     # credential attempts
    "decoy.login_success":    "exploitation",
    "decoy.planted_cred":     "exploitation",     # our bait, used = valid-account abuse
    "decoy.command":          "exploitation",     # hands on keyboard
    "compromise.high":        "exploitation",
    "compromise.critical":    "exploitation",

    # It writes itself to our disk.
    "sample.executable":      "installation",

    # A channel back to them proves out.
    "canary.fired":           "command_and_control",  # bait beacons from their infra

    # The goal.
    "decoy.honeytoken_read":  "actions_on_objectives",
    "decoy.human_operator":   "actions_on_objectives",
}

# ATT&CK technique per stage, for a SIEM that pivots on the framework. These
# are stage-level defaults; a specific finding may carry its own in siem.py.
STAGE_TECHNIQUE = {
    "reconnaissance":        "T1595",  # Active Scanning
    "weaponization":         "T1587",  # Develop Capabilities
    "delivery":              "T1189",  # Drive-by Compromise
    "exploitation":          "T1203",  # Exploitation for Client Execution
    "installation":          "T1105",  # Ingress Tool Transfer
    "command_and_control":   "T1071",  # Application Layer Protocol
    "actions_on_objectives": "T1005",  # Data from Local System
}


def stage_for(event_type: str) -> str:
    """The kill-chain stage a finding belongs to, or None if it carries none."""
    return EVENT_STAGE.get(event_type)


class KillChain:
    """Assemble findings into a per-session kill chain.

    Feed it finding dicts (siem.build output, or a stored siem.jsonl line).
    It groups by session and remembers, for each stage, the evidence that
    reached it and how far the attacker got.
    """

    def __init__(self):
        # session_id -> stage_key -> list of evidence dicts
        self._chains: dict = {}

    def add(self, finding: dict) -> str:
        action = (finding.get("event") or {}).get("action") or finding.get("action")
        stage = stage_for(action)
        if stage is None:
            return None
        session = (finding.get("session_id") or finding.get("visitor")
                   or "unattributed")
        evidence = {
            "action": action,
            "stage": stage,
            "ts": finding.get("timestamp"),
            "src_ip": finding.get("src_ip"),
            "detail": (finding.get("command") or finding.get("username")
                       or finding.get("sample_type") or finding.get("url")
                       or finding.get("token_kind")),
            "severity": (finding.get("event") or {}).get("severity"),
        }
        self._chains.setdefault(session, {}).setdefault(stage, []).append(evidence)
        return stage

    def sessions(self) -> list:
        return sorted(self._chains, key=lambda s: -self.furthest_index(s))

    def furthest_index(self, session: str) -> int:
        stages = self._chains.get(session, {})
        return max((STAGE_INDEX[s] for s in stages), default=-1)

    def summary(self, session: str) -> dict:
        """Which stages this session reached, in order, with their evidence."""
        reached = self._chains.get(session, {})
        furthest = self.furthest_index(session)
        return {
            "session": session,
            "furthest_stage": (STAGES[furthest][0] if furthest >= 0 else None),
            "furthest_label": (STAGE_LABEL[STAGES[furthest][0]]
                               if furthest >= 0 else None),
            "furthest_index": furthest,
            "stages": [
                {
                    "key": key, "label": label,
                    "index": i,
                    "reached": key in reached,
                    "count": len(reached.get(key, [])),
                    "evidence": reached.get(key, []),
                }
                for i, (key, label) in enumerate(STAGES)
            ],
        }

    def all_summaries(self) -> list:
        return [self.summary(s) for s in self.sessions()]

    def render(self, session: str) -> str:
        """One-line ASCII kill chain for the CLI. Reached stages in caps."""
        s = self.summary(session)
        cells = []
        for stage in s["stages"]:
            mark = stage["label"].upper() if stage["reached"] else stage["label"].lower()
            if stage["reached"] and stage["count"] > 1:
                mark += f"(x{stage['count']})"
            cells.append(mark)
        return f"{session}: " + " -> ".join(cells)


def from_findings(findings) -> KillChain:
    kc = KillChain()
    for f in findings:
        kc.add(f)
    return kc


def from_siem_file(path) -> KillChain:
    """Build a kill chain from a stored siem.jsonl."""
    import json
    from pathlib import Path
    kc = KillChain()
    p = Path(path)
    if not p.exists():
        return kc
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            kc.add(json.loads(line))
        except ValueError:
            continue
    return kc


if __name__ == "__main__":
    # Self-check: a full chain from recon to objectives orders correctly.
    kc = KillChain()
    for action in ["decoy.connect", "decoy.login_success", "sample.executable",
                   "canary.fired", "decoy.honeytoken_read"]:
        kc.add({"event": {"action": action, "severity": 10}, "session_id": "s1"})
    s = kc.summary("s1")
    assert s["furthest_stage"] == "actions_on_objectives", s["furthest_stage"]
    assert [x["reached"] for x in s["stages"]] == \
        [True, False, False, True, True, True, True]
    assert stage_for("verdict.clean") is None
    print(kc.render("s1"))
    print("killchain self-check ok")
