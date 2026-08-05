"""
SIEM export — shipping findings to Wazuh (module 4) and generic SIEMs.

Three sinks, because the right one depends on where the SIEM is:

  jsonl    newline-delimited JSON to a file a Wazuh agent tails. The most
           robust option: no network dependency, survives the manager being
           down, and Wazuh parses the fields natively with
           `<log_format>json</log_format>`. This is the default.
  syslog   RFC 5424 over UDP/TCP straight to a Wazuh manager or any syslog
           collector. Use when there is no agent on this host.
  cef      ArcSight Common Event Format, for SIEMs that speak CEF rather than
           JSON. Same events, different envelope.

What gets shipped is deliberately narrow. A honeyclient generates tens of
thousands of raw browser events per session; forwarding those to a SIEM buries
the three that matter. Only findings go: a verdict, an observed action of
compromise, a canary that fired, a human operator inside the decoy, a bot that
needs a person. Raw telemetry stays in the forensic timeline where it belongs.

Severity follows Wazuh's 0-15 rule levels so alerting thresholds work without
per-event tuning.
"""
import json
import socket
import time
from pathlib import Path

SIEM_LOG = Path(__file__).parent.parent / "telemetry" / "siem.jsonl"

VENDOR = "ClientHoneypot"
PRODUCT = "honeyclient"
VERSION = "1.0"

# Wazuh rule levels. 12+ pages someone; 7-11 is a real finding; below that is
# context. A canary firing outranks everything else the platform can observe,
# because it proves bait travelled to attacker infrastructure and came back.
EVENTS = {
    "canary.fired":          (13, "Canary token used from attacker infrastructure"),
    "decoy.planted_cred":    (13, "Planted credential used against a decoy service"),
    "decoy.human_operator":  (12, "Human operator classified inside the decoy"),
    "compromise.critical":   (11, "Critical action of compromise observed"),
    "decoy.command":         (11, "Command executed inside a decoy service"),
    "verdict.malicious":     (10, "URL judged malicious"),
    "decoy.honeytoken_read": (10, "Honeytoken accessed in the decoy"),
    "decoy.login_success":   (11, "Login succeeded against a decoy service"),
    "decoy.login_failed":     (8, "Login attempted against a decoy service"),
    "compromise.high":        (8, "Action of compromise observed"),
    "verdict.suspicious":     (7, "URL judged suspicious"),
    "intel.flagged":          (7, "Third-party host flagged by threat feeds"),
    "decoy.silent":           (6, "Decoy stopped reporting while running"),
    "intervention.raised":    (5, "Bot blocked, operator needed"),
    "session.refused":        (5, "Target refused by the containment gate"),
    "decoy.connect":          (4, "Connection to a decoy service"),
    "verdict.clean":          (3, "URL judged clean"),
    "verdict.unreachable":    (3, "Target could not be reached"),
}

# ATT&CK mapping, so a Wazuh rule can pivot on technique rather than our
# internal vocabulary.
TECHNIQUE = {
    "canary.fired": "T1078",             # Valid Accounts
    "decoy.planted_cred": "T1078",       # Valid Accounts
    "compromise.critical": "T1203",      # Exploitation for Client Execution
    "compromise.high": "T1189",          # Drive-by Compromise
    "verdict.malicious": "T1189",
    "decoy.honeytoken_read": "T1005",    # Data from Local System
    "decoy.command": "T1059",            # Command and Scripting Interpreter
    "decoy.login_failed": "T1110",       # Brute Force
    "decoy.connect": "T1046",            # Network Service Discovery
}


# Verbs a client library emits on its own to set up a session. They carry no
# intent -- an ordinary ftplib login produces TYPE and PASV without the person
# driving it ever asking for them, and USER/PASS are the login handshake that
# the login record already reports in full. Shipping these as decoy.command
# pages someone at level 11 for a protocol negotiation, which is precisely how
# a SIEM rule earns itself a mute. The raw lines stay in the docker log for
# forensics; only the commands a person chose to run are findings.
#
# Free-form shell input from the SSH and telnet decoys never matches this set,
# so an attacker typing `cat /etc/shadow` is always a finding.
PROTOCOL_CHATTER = {
    "USER", "PASS", "TYPE", "PASV", "EPSV", "PORT", "EPRT", "SYST", "FEAT",
    "OPTS", "NOOP", "QUIT", "ABOR", "STAT", "REST", "MODE", "STRU", "ACCT",
    "AUTH", "PBSZ", "PROT", "CCC", "HELP", "PWD", "XPWD",
}


def _severity(event_type: str) -> tuple:
    level, description = EVENTS.get(event_type, (3, event_type))
    return level, description


def build(event_type: str, **fields) -> dict:
    """One normalised finding. Field names follow ECS where they exist, so a
    SIEM that already knows ECS does not need a custom decoder."""
    level, description = _severity(event_type)
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "vendor": VENDOR,
        "product": PRODUCT,
        "version": VERSION,
        "event": {
            "kind": "alert" if level >= 7 else "event",
            "category": event_type.split(".")[0],
            "action": event_type,
            "severity": level,
            "reason": description,
        },
        "host": {"name": socket.gethostname()},
    }
    if event_type in TECHNIQUE:
        event["threat"] = {"technique": {"id": TECHNIQUE[event_type]}}
    event.update({k: v for k, v in fields.items() if v is not None})
    return event


# ── formatters ─────────────────────────────────────────────────────────────

def to_cef(event: dict) -> str:
    """CEF:0|vendor|product|version|signature|name|severity|extensions"""
    ev = event.get("event", {})
    sig = ev.get("action", "event")
    name = ev.get("reason", sig)
    # CEF severity is 0-10; Wazuh levels run 0-15.
    sev = min(10, int(ev.get("severity", 3) * 10 / 15))

    def esc(v):
        return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")

    ext = []
    for key in ("url", "verdict", "score", "host", "session_id", "src_ip",
                "provider", "token", "actor", "reason"):
        value = event.get(key)
        if isinstance(value, dict):
            value = value.get("name") or json.dumps(value)
        if value not in (None, ""):
            ext.append(f"{key}={esc(value)}")
    return (f"CEF:0|{VENDOR}|{PRODUCT}|{VERSION}|{sig}|{esc(name)}|{sev}|"
            + " ".join(ext))


def to_syslog(event: dict, facility: int = 13) -> str:
    """RFC 5424. Priority = facility*8 + severity, mapped from the rule level."""
    level = int(event.get("event", {}).get("severity", 3))
    # Wazuh 0-15 -> syslog 0-7, inverted (syslog 0 is most severe).
    sev = max(0, min(7, 7 - int(level * 7 / 15)))
    pri = facility * 8 + sev
    host = event.get("host", {}).get("name", "-")
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    return (f"<{pri}>1 {ts} {host} {PRODUCT} - - - "
            + json.dumps(event, default=str))


# ── sinks ──────────────────────────────────────────────────────────────────

class SiemExporter:
    """Ships findings. Never raises into the hunting path.

    A SIEM being down must not stop a hunt or lose a verdict — the finding is
    already in the verdict database. Delivery failures are counted and
    surfaced, not thrown.
    """

    def __init__(self, mode: str = "jsonl", path: Path = None,
                 host: str = None, port: int = 514, protocol: str = "udp",
                 enabled: bool = True):
        self.mode = mode
        self.path = Path(path or SIEM_LOG)
        self.host = host
        self.port = int(port)
        self.protocol = protocol
        self.enabled = enabled
        self.sent = 0
        self.failed = 0
        self.last_error = None
        if self.mode == "jsonl":
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event_type: str, **fields) -> dict:
        event = build(event_type, **fields)
        if not self.enabled:
            return event
        try:
            if self.mode == "jsonl":
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, default=str) + "\n")
            elif self.mode == "cef":
                with open(self.path.with_suffix(".cef"), "a",
                          encoding="utf-8") as f:
                    f.write(to_cef(event) + "\n")
            elif self.mode == "syslog":
                self._syslog(to_syslog(event))
            else:
                raise ValueError(f"unknown sink mode {self.mode!r}")
            self.sent += 1
            self.last_error = None
        except Exception as e:
            self.failed += 1
            self.last_error = f"{type(e).__name__}: {e}"
            print(f"[siem] delivery failed ({self.mode}): {self.last_error}")
        return event

    def _syslog(self, line: str) -> None:
        if not self.host:
            raise ValueError("syslog mode needs a manager host")
        data = line.encode("utf-8", errors="replace")
        if self.protocol == "tcp":
            with socket.create_connection((self.host, self.port), timeout=5) as s:
                s.sendall(data + b"\n")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5)
                s.sendto(data, (self.host, self.port))

    # ── the events worth shipping ──────────────────────────────────────────

    def verdict(self, url, verdict, score, clusters=None, findings=None,
                session_id=None):
        return self.emit(f"verdict.{verdict}", url=url, verdict=verdict,
                         score=score, clusters=clusters or [],
                         findings=(findings or [])[:20], session_id=session_id)

    def compromise(self, kind, severity, url=None, session_id=None, detail=None):
        tier = "critical" if severity == "CRITICAL" else "high"
        if severity == "LOW":
            return None       # context, not a finding — do not page anyone
        return self.emit(f"compromise.{tier}", action_kind=kind,
                         severity=severity, url=url, session_id=session_id,
                         detail=detail or {})

    def canary(self, token, kind, src_ip, origin_session, placement=None,
               user_agent=None):
        """The highest-value event the platform produces: bait we planted has
        been used, from somewhere that is not us."""
        return self.emit("canary.fired", token=token, token_kind=kind,
                         src_ip=src_ip, session_id=origin_session,
                         placement=placement, user_agent=user_agent)

    def decoy_operator(self, visitor_id, src_ip, score, signals=None,
                       tier_reached=None):
        return self.emit("decoy.human_operator", visitor=visitor_id,
                         src_ip=src_ip, score=score,
                         signals=signals or [], tier=tier_reached)

    def honeytoken(self, filename, session_id, src_ip=None, actor=None):
        return self.emit("decoy.honeytoken_read", filename=filename,
                         session_id=session_id, src_ip=src_ip, actor=actor)

    def decoy_activity(self, record: dict, planted: dict = None):
        """One observation from a decoy service, collected out of band.

        `planted` is set when the credential used is one we seeded ourselves,
        which upgrades a brute-force attempt into proof that our bait was
        exfiltrated and tried. That is the whole point of the decoy, so it
        ships at the same level as a fired canary.
        """
        common = {
            "service": record.get("server"),
            "src_ip": record.get("src_ip"),
            "src_port": record.get("src_port"),
            "dest_port": record.get("dest_port"),
            "action": record.get("action"),
        }
        action = str(record.get("action") or "").lower()

        if planted:
            return self.emit("decoy.planted_cred", username=record.get("username"),
                             token=planted.get("token_id"),
                             token_kind=planted.get("kind"),
                             session_id=planted.get("session_id"), **common)

        if action == "login" or record.get("password"):
            # The password itself is evidence: an attacker's reused password is
            # intelligence and it is ours to keep. Success matters far more
            # than an attempt — it means they are now inside and acting.
            succeeded = str(record.get("status") or "").lower() == "success"
            return self.emit(
                "decoy.login_success" if succeeded else "decoy.login_failed",
                username=record.get("username"),
                password=record.get("password"), **common)

        if action in ("command", "query"):
            data = record.get("data")
            if isinstance(data, dict):
                cmd = str(data.get("cmd") or "")
                if cmd.upper() in PROTOCOL_CHATTER:
                    return None
                text = f"{cmd} {data.get('args') or ''}".strip()
            else:
                text = str(data or "")
            return self.emit("decoy.command", command=text[:500], **common)

        return self.emit("decoy.connect", **common)

    def decoy_silent(self, container, reason):
        """The log stream stopped while the container was meant to be running.

        Worth an alert on its own: an attacker who kills the honeypot process
        to stop being watched produces exactly this and nothing else.
        """
        return self.emit("decoy.silent", container=container, reason=reason)

    def intel_flagged(self, host, verdict, providers, parent_url=None):
        return self.emit("intel.flagged", host=host, verdict=verdict,
                         provider=",".join(providers), url=parent_url)

    def intervention(self, url, reason, session_id=None):
        return self.emit("intervention.raised", url=url, reason=reason,
                         session_id=session_id)

    def refused(self, url, reason):
        return self.emit("session.refused", url=url, reason=reason)

    def status(self) -> dict:
        return {"mode": self.mode, "enabled": self.enabled,
                "destination": (f"{self.host}:{self.port}" if self.mode == "syslog"
                                else str(self.path)),
                "sent": self.sent, "failed": self.failed,
                "last_error": self.last_error}


def wazuh_agent_config(path: Path = None) -> str:
    """The block to paste into ossec.conf so a Wazuh agent picks this up."""
    log = Path(path or SIEM_LOG)
    return f"""<!-- ClientHoneypot findings -->
<localfile>
  <log_format>json</log_format>
  <location>{log}</location>
</localfile>"""
