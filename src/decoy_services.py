"""
Decoy services — the other half of the trap.

Until now the bait had a dead end. We plant a fake SSH key, DB password, VPN
config and FTP login in the browser profile; a stealer exfiltrates them; the
attacker tries them and gets connection refused. Nothing answers, nothing is
logged, and they conclude the credentials are stale and never come back.

qeeqbox/honeypots closes that: real listeners on SSH, FTP, MySQL, Postgres,
SMB, VNC, RDP, Telnet and more, configured with *our planted credentials* so
the attacker's login actually succeeds, and logging username, password and
source IP on every attempt.

Two functions matter here:

  build_config()  turns the canary vault's decoy_services placements into the
                  qeeqbox config.json, so a token pasted into the dashboard
                  becomes a credential that works.

  ingest_logs()   reads qeeqbox's JSON log and correlates each captured
                  credential back to the session that planted it — the same
                  attribution the URL tokens already have.
"""
import ast
import json
from pathlib import Path

# Which honeypot a planted credential belongs on. A stolen SSH key is only
# interesting if something answers on 22.
KIND_SERVICES = {
    "ssh_key":       ["ssh"],
    "db_credential": ["mysql", "postgres", "mssql"],
    "document":      ["ftp", "smb"],
    "url_token":     ["http", "https"],
    "dns_callback":  ["dns"],
    "aws_key":       [],   # fires through canarytokens.org, not a local port
    "tracking_pixel": ["http"],
}

# Ports match the real services, because an attacker who finds SSH on 2222
# knows they are in a honeypot.
DEFAULT_PORTS = {
    "ssh": 22, "ftp": 21, "telnet": 23, "smtp": 25, "dns": 53,
    "http": 80, "https": 443, "smb": 445, "mssql": 1433, "mysql": 3306,
    "rdp": 3389, "postgres": 5432, "vnc": 5900, "redis": 6379,
    "elastic": 9200, "memcache": 11211, "ldap": 389, "imap": 143,
    "pop3": 110, "vpn": 1194,
}

DEFAULT_SERVICES = ["ssh", "ftp", "mysql", "postgres", "smb", "telnet",
                    "vnc", "rdp", "redis"]

LOG_DIR = "/var/log/honeypots"


def build_config(vault, services: list = None,
                 log_dir: str = LOG_DIR) -> dict:
    """Render a qeeqbox config.json from the vault's decoy_services tokens.

    Each service is seeded with a planted credential where one exists, so the
    attacker's stolen login succeeds rather than bouncing. Services with no
    matching token still run with plausible defaults — a port that answers is
    better than a port that does not, and silence is itself a signal.
    """
    services = services or list(DEFAULT_SERVICES)

    # Every decoy_services token, INCLUDING burned ones. for_placement()
    # filters burned tokens out, which is right for a single-use URL beacon
    # and wrong here: burning happens the moment the attacker first uses the
    # credential, so filtering means the login that just worked is refused
    # the next time they come back. That teaches them the credential was
    # revoked -- they were detected -- which is the exact conclusion this
    # module exists to prevent. A service credential must keep working. The
    # repeat logins are the best telemetry we get: they show persistence,
    # tooling, and which hours the operator keeps.
    tokens = ([t for t in vault.all() if t.get("placement") == "decoy_services"]
              if vault else [])

    # Map service -> the token whose kind belongs on it.
    by_service = {}
    for token in tokens:
        for svc in KIND_SERVICES.get(token["kind"], []):
            by_service.setdefault(svc, token)

    honeypots = {}
    for svc in services:
        entry = {
            "port": DEFAULT_PORTS.get(svc, 0),
            "ip": "0.0.0.0",
            "options": ["capture_commands"],
        }
        token = by_service.get(svc)
        if token:
            # The planted credential IS the accepted credential.
            entry["username"] = _username_for(token)
            entry["password"] = token["value"]
        else:
            entry["username"] = "svc_backup"
            entry["password"] = "Asteria!2026"
        honeypots[svc] = entry

    # "terminal" means stdout, which Docker's log driver captures in the
    # daemon on the host. That is deliberate and it is the whole disguise:
    # writing to a file needs a mount, and a mount is visible in
    # /proc/mounts to anyone who lands a shell here. See decoy_telemetry.
    return {
        "logs": "terminal,json",
        "logs_location": log_dir,
        "honeypots": honeypots,
    }


def _username_for(token: dict) -> str:
    label = (token.get("label") or "").strip()
    if label and label.replace("-", "").replace("_", "").isalnum():
        return label.replace("-", "_")
    return "svc_reporting"


def write_config(vault, path: Path, services: list = None) -> dict:
    config = build_config(vault, services=services)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config


# ── log ingestion ──────────────────────────────────────────────────────────

def parse_log_line(line: str) -> dict:
    """One qeeqbox log record, or None if the line is not one.

    qeeqbox writes Python dict repr, not JSON -- single-quoted keys, and
    True/False/None rather than true/false/null:

        {'action': 'connection', 'src_ip': '172.17.0.1', 'server': 'ssh_server'}

    json.loads rejects every one of those, so a JSON-only parser silently
    attributes nothing. Both forms are accepted here because the project
    documents JSON output and emits repr.

    Fields: server, action, status, src_ip, src_port, dest_ip, dest_port,
    username, password, timestamp.
    """
    line = line.strip()
    if not line or not line.startswith("{"):
        return None

    record = None
    try:
        record = json.loads(line)
    except ValueError:
        try:
            record = ast.literal_eval(line)
        except (ValueError, SyntaxError):
            return None

    if not isinstance(record, dict):
        return None

    # "data" is overloaded. Some records wrap the whole payload in it; but a
    # captured command puts the command ITSELF there, alongside the fields
    # that say who ran it:
    #
    #   {"action": "command", "src_ip": "...", "data": {"cmd": "LIST"}}
    #
    # Unwrapping that unconditionally threw away src_ip and server and left a
    # bare {"cmd": ...}, which then failed every "is this real activity?"
    # check for want of a source address -- so captured commands, including
    # everything an attacker typed at the SSH decoy, were silently dropped.
    # Only unwrap when there is no record around the payload.
    inner = record.get("data")
    if isinstance(inner, dict) and not (record.get("action") or record.get("server")):
        return inner
    return record


def is_credential_attempt(record: dict) -> bool:
    """Only login attempts carry intelligence; connection noise does not."""
    if not record:
        return False
    return bool(record.get("username") or record.get("password"))


def ingest_logs(vault, log_path: Path, since_offset: int = 0) -> tuple:
    """Read new qeeqbox log lines and record any that used planted bait.

    Returns (hits, new_offset). A credential we planted appearing here means
    the attacker exfiltrated it and tried it — the strongest signal the
    platform produces, because it proves the bait travelled.
    """
    log_path = Path(log_path)
    if not log_path.exists():
        return [], since_offset

    hits = []
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(since_offset)
        for line in f:
            record = parse_log_line(line)
            if not is_credential_attempt(record):
                continue
            hit = _match_token(vault, record)
            if hit:
                hits.append(hit)
        offset = f.tell()

    return hits, offset


def _match_token(vault, record: dict):
    """Resolve a captured credential back to the canary that planted it."""
    password = str(record.get("password") or "")
    username = str(record.get("username") or "")
    if not password and not username:
        return None

    for token in vault.all():
        if token["placement"] != "decoy_services":
            continue
        if token["value"] and token["value"] == password:
            return vault.record_hit(
                token["token_id"],
                src_ip=record.get("src_ip"),
                user_agent=f"{record.get('server', 'service')} login",
                detail={"service": record.get("server"),
                        "username": username,
                        "action": record.get("action"),
                        "dest_port": record.get("dest_port")},
            )
    return None
