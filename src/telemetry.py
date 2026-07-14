"""
Telemetry Engine (spec Component 12) — SQLite-backed.

Every event the monitoring engine, threat detector, and decoy environment
produce funnels through here so a session can be fully reconstructed later.
"""
import json
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "telemetry" / "session.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ts REAL NOT NULL,
    event_type TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session ON events(session_id);
"""


class Telemetry:
    def __init__(self, session_id: str, db_path: Path = DB_PATH):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def log(self, event_type: str, data: dict):
        self.conn.execute(
            "INSERT INTO events (session_id, ts, event_type, data) VALUES (?, ?, ?, ?)",
            (self.session_id, time.time(), event_type, json.dumps(data, default=str)),
        )
        self.conn.commit()

    def all_events(self):
        cur = self.conn.execute(
            "SELECT ts, event_type, data FROM events WHERE session_id = ? ORDER BY ts ASC",
            (self.session_id,),
        )
        return [
            {"ts": row[0], "event_type": row[1], "data": json.loads(row[2])}
            for row in cur.fetchall()
        ]

    def close(self):
        self.conn.close()
