"""
Evidence and triage — showing the reasoning, not the score.

"Malicious, 79" is not a finding an analyst can act on. The operator asked
the right question: if you say it is malicious, which exact logs decided
that? And when you say it is clean, what did you check?

So a verdict here carries the signals that fired, what each one means, the
cluster that correlated them, and every observed action of compromise --
plus, when nothing fired, an explicit statement of what was examined and
came back empty. Silence and "not looked at" must never look the same.

Triage is the other half. False positives destroy trust in a detector faster
than misses do, so only findings above a confidence floor are surfaced for
review. The operator confirms or rejects; confirmed goes to the malicious
database, rejected goes to a visited-clean list, is excluded from future
queues, and is kept as a labelled false positive so thresholds can be tuned
against real decisions rather than guesses.
"""
import json
import time

from threat_detection import (ATTACK_CLUSTERS, BASE_WEIGHTS, MITRE_LABELS,
                              DECOY_TRIGGER_THRESHOLD)

# Plain-English meaning for each raw signal. A label like "obf_unescape" tells
# an analyst nothing on its own.
SIGNAL_MEANING = {
    "obf_unescape": "calls unescape() — classic payload de-obfuscation",
    "obf_eval": "calls eval() on constructed input",
    "obf_charcode": "builds strings from character codes to evade scanners",
    "obf_hex_sequence": "long hex-escaped byte run, typical of packed payloads",
    "obf_b64_decode": "base64-decodes at runtime",
    "obf_double_decode": "double-decodes (base64 then URI) — deliberate obfuscation",
    "ek_docwrite_unescape": "document.write(unescape(...)) — exploit-kit signature",
    "ek_shellcode": "references shellcode directly",
    "ek_heap_gc": "forces garbage collection, a heap-spray precursor",
    "ek_large_array": "allocates a huge array — heap-spray setup",
    "ek_ie_useragent_check": "branches on Internet Explorer, targeting old bugs",
    "ek_trident_check": "detects the Trident engine to pick an exploit",
    "activex_instantiate": "instantiates ActiveX — Windows-only attack vector",
    "activex_shell": "reaches for WScript.Shell / Shell.Application",
    "activex_fso": "reaches for the filesystem object",
    "activex_http": "uses XMLHTTP/WinHttpRequest to fetch a second stage",
    "steal_clipboard": "reads or writes the clipboard",
    "cookie_write": "writes a cookie without httponly",
    "cred_hardcoded": "contains a hardcoded credential",
    "cryptominer": "loads a cryptominer",
    "webrtc_leak": "opens an RTCPeerConnection — used to leak the real IP",
    "evade_selenium": "probes for Selenium",
    "evade_webdriver": "probes navigator.webdriver — checking for automation",
    "evade_noplugins": "checks for an empty plugin list, a sandbox tell",
    "evade_smallscreen": "checks for a tiny screen, a sandbox tell",
    "evade_outerwidth": "checks window.outerWidth === 0, a headless tell",
    "dropper_ps1": "contains an encoded PowerShell command line",
    "dropper_cmd": "contains a cmd.exe invocation",
    "dropper_mshta": "contains an mshta invocation",
    "dropper_wscript": "contains a wscript/cscript invocation",
    "dom_hidden_iframe": "hides an iframe at zero size or display:none",
    "dom_meta_refresh": "meta-refreshes to another domain",
    "dom_offsite_form": "posts a form to a different domain",
    "dom_password_field": "contains a password input",
    "fp_canvas": "fingerprints via canvas",
    "fp_audio": "fingerprints via AudioContext",
    "fp_webgl_ext": "reads the WebGL debug renderer",
    "suspicious_download": "served a file with an executable extension",
    "excessive_redirects": "bounced through four or more redirects",
    "suspicious_tld": "sits on a TLD heavily abused for throwaway domains",
}

ACTION_MEANING = {
    "file_download": "downloaded a file",
    "command_execution": "carried an OS command line",
    "dynamic_code_injection": "injected script or iframe elements at runtime",
    "persistence": "registered a service worker to survive navigation",
    "data_exfiltration": "wrote bulk data to storage or read the clipboard",
    "credential_harvest": "submitted a form containing credentials",
    "outbound_beacon": "called a third-party host after load",
    "popup_abuse": "opened pop-unders or extra tabs",
    "websocket_channel": "opened a WebSocket channel",
    "permission_abuse": "requested sensitive browser permissions",
}

# What a clean verdict means we actually checked, so "nothing found" is
# distinguishable from "nothing looked at".
CHECKS_PERFORMED = [
    "page source scanned against 60+ obfuscation, exploit-kit, dropper and "
    "evasion patterns",
    "DOM scanned for hidden iframes, off-site forms and credential fields",
    "8 correlation clusters evaluated for co-occurring signals",
    "downloads inspected for executable extensions",
    "redirect chain length measured",
    "runtime hooks watched for dynamic script injection, service workers, "
    "storage exfiltration, clipboard access and credential submits",
]

# A finding must clear this to be worth an operator's attention. Below it the
# session is recorded but never surfaced: one weak signal on one page is the
# raw material of false positives, and false positives are what stop people
# trusting a detector.
REVIEW_FLOOR = DECOY_TRIGGER_THRESHOLD

TRIAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS triage (
    url          TEXT PRIMARY KEY,
    verdict      TEXT NOT NULL,
    score        INTEGER NOT NULL,
    decision     TEXT NOT NULL,       -- confirmed | rejected
    decided_by   TEXT,
    decided_ts   REAL NOT NULL,
    note         TEXT,
    evidence     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_triage_decision ON triage(decision);
"""


def _cluster_by_name(name: str) -> dict:
    for cluster in ATTACK_CLUSTERS:
        if cluster["name"] == name:
            return cluster
    return {}


def explain(row: dict) -> dict:
    """Turn a stored verdict into the reasoning behind it.

    Every signal is reported with its weight, its ATT&CK tag and what it
    actually means, so the operator can judge the decision rather than trust
    the number.
    """
    if not row:
        return {}

    findings = row.get("findings") or []
    signals, clusters = [], []

    for label in findings:
        if label.startswith("[CLUSTER]"):
            name = label.replace("[CLUSTER]", "").strip()
            cluster = _cluster_by_name(name)
            clusters.append({
                "name": name,
                "bonus": cluster.get("bonus", 0),
                "mitre": cluster.get("mitre", ""),
                "why": cluster.get("description", ""),
                "required": sorted(cluster.get("required", set())),
            })
            continue
        signals.append({
            "label": label,
            "weight": BASE_WEIGHTS.get(label, 0),
            "mitre": MITRE_LABELS.get(label, ""),
            "means": SIGNAL_MEANING.get(label, "matched a detection pattern"),
        })

    actions = []
    for action in row.get("compromise_actions") or []:
        kind = action.get("kind", "")
        actions.append({
            "kind": kind,
            "severity": action.get("severity", "LOW"),
            "means": ACTION_MEANING.get(kind, "observed during the session"),
        })

    signals.sort(key=lambda s: s["weight"], reverse=True)

    return {
        "url": row.get("url"),
        "verdict": row.get("verdict"),
        "score": row.get("score", 0),
        "confidence": row.get("confidence", "low"),
        "threshold": DECOY_TRIGGER_THRESHOLD,
        "signals": signals,
        "clusters": clusters,
        "actions": actions,
        "summary": _summarise(row, signals, clusters, actions),
        "checks_performed": CHECKS_PERFORMED,
        "reviewable": is_reviewable(row),
    }


def _summarise(row, signals, clusters, actions) -> str:
    """One sentence an analyst can paste into a ticket."""
    verdict = row.get("verdict")
    score = row.get("score", 0)

    if verdict == "clean":
        return (f"No detection fired. {len(CHECKS_PERFORMED)} check groups ran "
                f"and the page scored {score}, below the suspicious threshold. "
                f"This is an observed negative, not an unexamined page.")

    parts = []
    if clusters:
        names = ", ".join(c["name"].replace("_", " ") for c in clusters)
        parts.append(f"correlated attack pattern: {names}")
    if actions:
        worst = [a for a in actions if a["severity"] in ("CRITICAL", "HIGH")]
        if worst:
            parts.append("observed " + ", ".join(a["means"] for a in worst[:3]))
    if signals and not parts:
        parts.append(f"{len(signals)} independent signals, strongest: "
                     f"{signals[0]['means']}")

    reason = "; ".join(parts) if parts else "score accumulated from weak signals"
    return (f"Scored {score} against a threshold of {DECOY_TRIGGER_THRESHOLD} — "
            f"{reason}.")


def is_reviewable(row: dict) -> bool:
    """Worth an operator's time?

    A confirmed action of compromise always is: the page DID something.
    Otherwise it must clear the score floor. Weak single signals are logged
    and left alone, because surfacing them is how a detector earns a
    reputation for crying wolf.
    """
    if not row:
        return False
    if row.get("compromise_actions"):
        return True
    return row.get("score", 0) >= REVIEW_FLOOR


class TriageStore:
    """Operator decisions on surfaced findings."""

    def __init__(self, db):
        self.db = db
        self.db.conn.executescript(TRIAGE_SCHEMA)
        self.db.conn.commit()

    def pending(self, limit: int = 50) -> list:
        """Findings above the floor that nobody has ruled on yet."""
        rows = self.db.conn.execute(
            """SELECT url FROM urls
               WHERE verdict IN ('malicious', 'suspicious')
                 AND url NOT IN (SELECT url FROM triage)
               ORDER BY max_score DESC, last_seen DESC LIMIT ?""",
            (limit,)).fetchall()

        out = []
        for row in rows:
            full = self.db.lookup(row["url"])
            if full and is_reviewable(full):
                out.append(explain(full))
        return out

    def decide(self, url: str, decision: str, note: str = None,
               decided_by: str = "operator") -> bool:
        """Record the operator's ruling.

        Rejections are kept, not deleted: a labelled false positive is the
        only honest way to tune the thresholds later.
        """
        if decision not in ("confirmed", "rejected"):
            raise ValueError(f"decision must be confirmed or rejected, "
                             f"got {decision!r}")
        row = self.db.lookup(url)
        if row is None:
            return False

        self.db.conn.execute(
            """INSERT OR REPLACE INTO triage
               (url, verdict, score, decision, decided_by, decided_ts,
                note, evidence)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (url, row["verdict"], row["score"], decision, decided_by,
             time.time(), note, json.dumps(explain(row), default=str)))

        if decision == "rejected":
            # Excluded from future queues, and the stored verdict corrected so
            # a consuming RBI stops raising isolation on an operator-cleared URL.
            self.db.conn.execute(
                "UPDATE urls SET verdict = 'clean' WHERE url = ?", (url,))
        self.db.conn.commit()
        return True

    def confirmed(self, limit: int = 200) -> list:
        return [dict(r) for r in self.db.conn.execute(
            """SELECT * FROM triage WHERE decision = 'confirmed'
               ORDER BY decided_ts DESC LIMIT ?""", (limit,))]

    def false_positives(self, limit: int = 200) -> list:
        return [dict(r) for r in self.db.conn.execute(
            """SELECT * FROM triage WHERE decision = 'rejected'
               ORDER BY decided_ts DESC LIMIT ?""", (limit,))]

    def is_cleared(self, url: str) -> bool:
        """True when the operator rejected this URL — skip it in future runs."""
        row = self.db.conn.execute(
            "SELECT 1 FROM triage WHERE url = ? AND decision = 'rejected'",
            (url,)).fetchone()
        return row is not None

    def stats(self) -> dict:
        rows = self.db.conn.execute(
            "SELECT decision, COUNT(*) c FROM triage GROUP BY decision").fetchall()
        counts = {r["decision"]: r["c"] for r in rows}
        confirmed = counts.get("confirmed", 0)
        rejected = counts.get("rejected", 0)
        total = confirmed + rejected
        return {
            "confirmed": confirmed,
            "rejected": rejected,
            "reviewed": total,
            # The number that matters: how often the detector was wrong when
            # it was confident enough to ask.
            "false_positive_rate": round(rejected / total, 3) if total else None,
        }
