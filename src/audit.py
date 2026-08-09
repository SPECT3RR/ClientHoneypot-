"""
Audit log — who did what, and when.

A security tool that anyone other than its author operates needs to answer
three questions after the fact: who queued that target, who ruled that finding
a false positive, and who changed the isolation profile. Without it, a wrong
verdict in the database has no provenance and a disputed decision has no
record.

Append-only by construction. There is no update or delete path, and the file
sink is opened in append mode — a log an operator can quietly edit is not an
audit log. The database copy is what the dashboard reads; the file copy is
what survives the database being replaced.

Actor is whoever the dashboard says it is. The console is single-operator and
gated by one shared token (see console_auth), so an entry proves the caller
held that token — it does not distinguish between two people who both have it.
The source address is still the distinguishing detail, and saying so is better
than implying an identity the system does not have.
"""
import json
import time
from pathlib import Path

AUDIT_LOG = Path(__file__).parent.parent / "telemetry" / "audit.jsonl"

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    actor   TEXT NOT NULL,
    source  TEXT,
    action  TEXT NOT NULL,
    target  TEXT,
    detail  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit(target);
"""

# Every action worth answering "who did this?" about. Anything that changes
# what gets hunted, what a verdict says, or how contained the hunt is.
ACTIONS = {
    # what gets hunted
    "queue.add":            "queued URLs",
    "queue.upload":         "uploaded a URL file",
    "swarm.target":         "changed the bot target",
    "swarm.headless":       "changed browser mode",
    "swarm.kill":           "engaged the kill switch",
    # what a verdict says — the ones that alter recorded truth
    "triage.confirm":       "confirmed a finding malicious",
    "triage.reject":        "ruled a finding a false positive",
    # deception assets
    "canary.add":           "registered a canary token",
    "canary.mint":          "minted a canary token",
    "canary.remove":        "removed a canary token",
    # secrets and posture
    "intel.key.set":        "stored a threat-feed key",
    "intel.key.remove":     "removed a threat-feed key",
    "intel.scan":           "ran a feed lookup",
    # operational
    "intervention.resolve": "resolved a blocked bot",
    "container.pause":      "paused other containers",
    "container.resume":     "resumed paused containers",
    # a captured attacker payload leaving the store
    "sample.retrieve":      "downloaded a captured malware sample",
    # console access
    "console.login":        "unlocked the console",
    "console.login_failed": "failed a console unlock",
}

# Actions that change recorded truth or reduce isolation. Called out so a
# reviewer can find them without reading the whole log.
SENSITIVE = {"triage.confirm", "triage.reject", "swarm.kill",
             "intel.key.set", "intel.key.remove", "container.pause",
             "sample.retrieve", "console.login_failed"}


class AuditLog:
    def __init__(self, db, path: Path = None):
        self.db = db
        self.path = Path(path or AUDIT_LOG)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db.conn.executescript(SCHEMA)
        self.db.conn.commit()

    def record(self, action: str, actor: str = "operator", target: str = None,
               source: str = None, **detail) -> dict:
        """Append one entry. Never raises into the caller's path.

        An audit failure must not break the operation being audited — but it
        must not silently succeed either, so the failure is printed.
        """
        entry = {
            "ts": time.time(),
            "actor": actor or "operator",
            "source": source,
            "action": action,
            "target": target,
            "detail": detail or {},
            "sensitive": action in SENSITIVE,
        }
        try:
            self.db.conn.execute(
                "INSERT INTO audit (ts, actor, source, action, target, detail) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (entry["ts"], entry["actor"], entry["source"], action, target,
                 json.dumps(entry["detail"], default=str)))
            self.db.conn.commit()
        except Exception as e:
            print(f"[audit] DB write failed for {action}: {e}")

        try:
            # Append-only file sink: survives the database being replaced.
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError as e:
            print(f"[audit] file write failed for {action}: {e}")

        return entry

    def recent(self, limit: int = 100, action: str = None,
               sensitive_only: bool = False) -> list:
        sql = "SELECT * FROM audit"
        where, args = [], []
        if action:
            where.append("action = ?")
            args.append(action)
        if sensitive_only:
            where.append("action IN (%s)" % ",".join("?" * len(SENSITIVE)))
            args.extend(sorted(SENSITIVE))
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)

        out = []
        for row in self.db.conn.execute(sql, args):
            out.append({
                "id": row["id"], "ts": row["ts"], "actor": row["actor"],
                "source": row["source"], "action": row["action"],
                "target": row["target"],
                "detail": json.loads(row["detail"]),
                "described": ACTIONS.get(row["action"], row["action"]),
                "sensitive": row["action"] in SENSITIVE,
            })
        return out

    def for_target(self, target: str, limit: int = 50) -> list:
        """Everything anyone did to one URL — the provenance of its verdict."""
        return [dict(r) for r in self.db.conn.execute(
            "SELECT ts, actor, action, detail FROM audit "
            "WHERE target = ? ORDER BY ts DESC LIMIT ?", (target, limit))]

    def stats(self) -> dict:
        total = self.db.conn.execute(
            "SELECT COUNT(*) c FROM audit").fetchone()["c"]
        sensitive = self.db.conn.execute(
            "SELECT COUNT(*) c FROM audit WHERE action IN (%s)"
            % ",".join("?" * len(SENSITIVE)), sorted(SENSITIVE)).fetchone()["c"]
        actors = self.db.conn.execute(
            "SELECT COUNT(DISTINCT actor) c FROM audit").fetchone()["c"]
        return {"entries": total, "sensitive": sensitive, "actors": actors,
                "file": str(self.path)}
