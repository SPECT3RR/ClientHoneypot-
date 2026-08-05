"""
Verdict database — the durable product of every hunting session.

A session is ephemeral; what survives it is a scored, evidenced judgement
about a URL. That judgement is what the RBI modules and Wazuh consume, so
the store keeps evidence and confidence alongside the verdict. A bare
boolean is not actionable for an analyst and gives a consuming RBI nothing
to explain when it raises isolation.

Schema covers every phase up front — one migration point rather than seven —
but each phase only writes the tables it owns.
"""
import json
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from event_bus import EventBus, Event, EventCategory

DB_PATH = Path(__file__).parent.parent / "telemetry" / "verdicts.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    url         TEXT PRIMARY KEY,
    host        TEXT,
    tld         TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    visit_count INTEGER NOT NULL DEFAULT 0,
    max_score   INTEGER NOT NULL DEFAULT 0,
    verdict     TEXT NOT NULL DEFAULT 'unknown'
);
CREATE INDEX IF NOT EXISTS idx_urls_verdict ON urls(verdict);
CREATE INDEX IF NOT EXISTS idx_urls_host    ON urls(host);

CREATE TABLE IF NOT EXISTS verdicts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ts         REAL NOT NULL,
    score      INTEGER NOT NULL,
    clusters   TEXT NOT NULL,
    findings   TEXT NOT NULL,
    decision   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_url ON verdicts(url);

CREATE TABLE IF NOT EXISTS compromise_actions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    url        TEXT,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    detail     TEXT NOT NULL,
    ts         REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_session ON compromise_actions(session_id);

CREATE TABLE IF NOT EXISTS nav_graph (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    from_url   TEXT,
    to_url     TEXT NOT NULL,
    trigger    TEXT NOT NULL,
    ts         REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nav_session ON nav_graph(session_id);

CREATE TABLE IF NOT EXISTS canaries (
    token_id   TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    label      TEXT,
    placement  TEXT NOT NULL,
    session_id TEXT,
    placed_ts  REAL,
    burned     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS canary_hits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id   TEXT NOT NULL,
    ts         REAL NOT NULL,
    src_ip     TEXT,
    user_agent TEXT,
    detail     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decoy_sessions (
    id             TEXT PRIMARY KEY,
    ts             REAL NOT NULL,
    src_ip         TEXT,
    user_agent     TEXT,
    tier_reached   INTEGER NOT NULL DEFAULT 0,
    classification TEXT NOT NULL DEFAULT 'unknown',
    score          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS interventions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    url             TEXT NOT NULL,
    reason          TEXT NOT NULL,
    screenshot_path TEXT,
    status          TEXT NOT NULL DEFAULT 'open',
    ts              REAL NOT NULL
);
"""

# Score bands for the stored verdict. Deliberately mirrors
# threat_detection.DECOY_TRIGGER_THRESHOLD so a diversion always means malicious.
MALICIOUS_SCORE = 60
SUSPICIOUS_SCORE = 30


def classify(score: int, had_compromise: bool = False) -> str:
    """Map a session score into a stored verdict.

    An observed action of compromise outranks the score outright: a page that
    dropped an executable is malicious whether or not a signature cluster
    happened to fire.
    """
    if had_compromise or score >= MALICIOUS_SCORE:
        return "malicious"
    if score >= SUSPICIOUS_SCORE:
        return "suspicious"
    return "clean"



def _locked(fn):
    """Serialise a write. Two threads committing at once is how you get
    'database is locked' mid-hunt and a half-written verdict."""
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


class VerdictDB:
    def __init__(self, db_path: Path = None, session_id: str = "unknown_session"):
        self.path = Path(db_path or DB_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False because the dashboard reads this connection
        # from FastAPI handlers while background work touches it from the
        # executor; sqlite3's default guard raises ProgrammingError across
        # threads. The lock below is what actually makes that safe.
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.session_id = session_id
        self._had_compromise = False
        self._current_url = None

    # ── bus wiring ─────────────────────────────────────────────────────────

    def name(self) -> str:
        return "VerdictDB"

    def initialize(self, bus: EventBus) -> None:
        bus.subscribe(EventCategory.PAYLOAD, self._on_payload)
        bus.subscribe(EventCategory.NAVIGATION, self._on_navigation)

    async def _on_navigation(self, event: Event) -> None:
        url = event.payload.get("url", "")
        if event.type == "visit_start":
            self._current_url = url
            self.record_nav(event.payload.get("referrer"), url, "visit")
        elif event.type == "framenavigated" and url:
            if url != self._current_url:
                self.record_nav(self._current_url, url, "framenavigated")
                self._current_url = url
        elif event.type == "new_tab_opened" and url:
            self.record_nav(self._current_url, url, "popup")

    async def _on_payload(self, event: Event) -> None:
        if event.type == "compromise_action":
            self._had_compromise = True
            self.record_compromise(
                url=event.payload.get("url") or self._current_url,
                kind=event.payload.get("kind", "unknown"),
                severity=event.payload.get("severity", "LOW"),
                detail=event.payload.get("detail", {}),
            )

    # ── writes ─────────────────────────────────────────────────────────────

    @_locked
    def record_verdict(self, url: str, score: int, clusters: list,
                       findings: list, decision: str) -> str:
        """Upsert the URL row and append an immutable verdict record."""
        now = time.time()
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        tld = "." + host.split(".")[-1].split(":")[0] if "." in host else ""
        verdict = classify(score, self._had_compromise)

        self.conn.execute(
            """INSERT INTO urls (url, host, tld, first_seen, last_seen,
                                 visit_count, max_score, verdict)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?)
               ON CONFLICT(url) DO UPDATE SET
                   last_seen   = excluded.last_seen,
                   visit_count = urls.visit_count + 1,
                   max_score   = MAX(urls.max_score, excluded.max_score),
                   verdict     = CASE
                       WHEN excluded.max_score >= urls.max_score
                       THEN excluded.verdict ELSE urls.verdict END""",
            (url, host, tld, now, now, score, verdict))
        self.conn.execute(
            """INSERT INTO verdicts (url, session_id, ts, score, clusters,
                                     findings, decision)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (url, self.session_id, now, score, json.dumps(clusters),
             json.dumps(findings), decision))
        self.conn.commit()
        return verdict

    @_locked
    def record_compromise(self, url: str, kind: str, severity: str,
                          detail: dict) -> None:
        self.conn.execute(
            """INSERT INTO compromise_actions
               (session_id, url, kind, severity, detail, ts)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (self.session_id, url, kind, severity,
             json.dumps(detail, default=str), time.time()))
        self.conn.commit()

    @_locked
    def record_nav(self, from_url: str, to_url: str, trigger: str) -> None:
        self.conn.execute(
            """INSERT INTO nav_graph (session_id, from_url, to_url, trigger, ts)
               VALUES (?, ?, ?, ?, ?)""",
            (self.session_id, from_url, to_url, trigger, time.time()))
        self.conn.commit()

    # ── reads: this is the reputation API other modules consume ────────────

    def lookup(self, url: str) -> dict:
        """Verdict plus the evidence behind it, or None if never seen.

        Evidence is not optional. 'Malicious' with nothing attached tells an
        analyst nothing and gives a consuming RBI no basis to explain why it
        raised the isolation level.
        """
        row = self.conn.execute("SELECT * FROM urls WHERE url = ?", (url,)).fetchone()
        if row is None:
            return None

        latest = self.conn.execute(
            """SELECT clusters, findings, decision, session_id, ts FROM verdicts
               WHERE url = ? ORDER BY score DESC, ts DESC LIMIT 1""",
            (url,)).fetchone()
        actions = self.conn.execute(
            """SELECT DISTINCT kind, severity FROM compromise_actions
               WHERE session_id IN (SELECT session_id FROM verdicts WHERE url = ?)""",
            (url,)).fetchall()

        return {
            "url": row["url"],
            "host": row["host"],
            "verdict": row["verdict"],
            "score": row["max_score"],
            "confidence": self._confidence(row["max_score"], len(actions)),
            "visit_count": row["visit_count"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "clusters": json.loads(latest["clusters"]) if latest else [],
            "findings": json.loads(latest["findings"]) if latest else [],
            "compromise_actions": [dict(a) for a in actions],
        }

    @staticmethod
    def _confidence(score: int, action_count: int) -> str:
        if action_count > 0 or score >= 120:
            return "high"
        if score >= MALICIOUS_SCORE:
            return "medium"
        return "low"

    def recent(self, limit: int = 50, verdict: str = None) -> list:
        sql = "SELECT * FROM urls"
        args = []
        if verdict:
            sql += " WHERE verdict = ?"
            args.append(verdict)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def stats(self) -> dict:
        rows = self.conn.execute(
            "SELECT verdict, COUNT(*) c FROM urls GROUP BY verdict").fetchall()
        out = {r["verdict"]: r["c"] for r in rows}
        out["total"] = sum(out.values())
        out["compromise_actions"] = self.conn.execute(
            "SELECT COUNT(*) c FROM compromise_actions").fetchone()["c"]
        return out

    def close(self):
        self.conn.close()
