"""
Third-party host inventory — everything a hunted page reached out to.

A hunted page is rarely alone. It pulls scripts from ad brokers, beacons to
trackers, and redirects through infrastructure that is often the actually
interesting part: the publisher may be innocent while the broker two hops
down is serving the kit.

Every request, redirect, popup and navigation the sessions observed is
already in the forensic timelines. This pulls those hosts out, records where
each was seen and in what role, and keeps them so they can be enriched
against threat feeds — retroactively for hunts already done, and
continuously for new ones.

Roles matter more than counts. A host seen only as a script source is
ordinary; the same host seen as a redirect target or a popup destination is
the shape of a malvertising chain.
"""
import json
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

REPORTS_DIR = Path(__file__).parent.parent / "reports"

SCHEMA = """
CREATE TABLE IF NOT EXISTS third_party_hosts (
    host        TEXT PRIMARY KEY,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    hit_count   INTEGER NOT NULL DEFAULT 0,
    roles       TEXT NOT NULL DEFAULT '[]',
    sessions    TEXT NOT NULL DEFAULT '[]',
    sample_url  TEXT,
    parent_urls TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_tp_last ON third_party_hosts(last_seen);

CREATE TABLE IF NOT EXISTS intel_lookups (
    host       TEXT NOT NULL,
    provider   TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    score      INTEGER NOT NULL DEFAULT 0,
    detail     TEXT NOT NULL DEFAULT '{}',
    checked_ts REAL NOT NULL,
    PRIMARY KEY (host, provider)
);
CREATE INDEX IF NOT EXISTS idx_intel_verdict ON intel_lookups(verdict);
"""

# Event types that tell us *how* a host was reached. The role is the signal.
ROLE_BY_EVENT = {
    "request": "resource",
    "response": "resource",
    "redirect": "redirect",
    "framenavigated": "navigation",
    "new_tab_opened": "popup",
    "visit_start": "visit",
    "download": "download",
    "websocket": "websocket",
    "dynamic_script_injection": "injected_script",
    "dynamic_iframe_injection": "injected_iframe",
}

# Roles that make a host worth looking at even with a low hit count.
INTERESTING_ROLES = {"redirect", "popup", "download", "injected_script",
                     "injected_iframe", "websocket", "navigation"}

# Hosts that are never the finding. Kept deliberately short — an allowlist
# that grows becomes the place attackers hide.
BORING_SUFFIXES = (
    "googleapis.com", "gstatic.com", "google-analytics.com",
    "googletagmanager.com", "cloudflare.com", "jsdelivr.net",
    "unpkg.com", "bootstrapcdn.com", "jquery.com", "fontawesome.com",
    "w3.org", "schema.org",
)


def host_of(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower()
        return host.split("@")[-1]        # strip any userinfo
    except Exception:
        return ""


def is_boring(host: str) -> bool:
    return any(host == b or host.endswith("." + b) for b in BORING_SUFFIXES)


def harvest_timelines(reports_dir: Path = None, skip_local: bool = True) -> dict:
    """Read every forensic timeline and inventory the hosts they touched.

    Returns {host: {roles, count, sessions, sample_url, parents}}.
    """
    reports_dir = Path(reports_dir or REPORTS_DIR)
    found = defaultdict(lambda: {"roles": set(), "count": 0, "sessions": set(),
                                 "sample_url": None, "parents": set()})

    for path in sorted(reports_dir.glob("*.jsonl")):
        session = path.stem.replace("_timeline", "")
        current_page = None

        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue

            payload = event.get("payload") or {}
            url = payload.get("url") or ""
            if not url.startswith("http"):
                continue

            etype = event.get("type", "")
            if etype in ("visit_start", "framenavigated"):
                current_page = url

            host = host_of(url)
            if not host:
                continue
            if skip_local and ("127.0.0.1" in host or "localhost" in host
                               or "host.docker.internal" in host):
                continue

            rec = found[host]
            rec["count"] += 1
            rec["roles"].add(ROLE_BY_EVENT.get(etype, etype))
            rec["sessions"].add(session)
            if rec["sample_url"] is None:
                rec["sample_url"] = url
            if current_page and host_of(current_page) != host:
                rec["parents"].add(current_page)

    return found


def store(db, harvested: dict) -> int:
    """Upsert the inventory, merging roles and sessions across runs."""
    import time
    now = time.time()
    db.conn.executescript(SCHEMA)

    written = 0
    for host, rec in harvested.items():
        row = db.conn.execute(
            "SELECT roles, sessions, parent_urls, hit_count, first_seen "
            "FROM third_party_hosts WHERE host = ?", (host,)).fetchone()

        roles = set(rec["roles"])
        sessions = set(rec["sessions"])
        parents = set(list(rec["parents"])[:20])
        count = rec["count"]
        first = now

        if row:
            roles |= set(json.loads(row["roles"]))
            sessions |= set(json.loads(row["sessions"]))
            parents |= set(json.loads(row["parent_urls"]))
            count = max(count, row["hit_count"])
            first = row["first_seen"]

        db.conn.execute(
            """INSERT OR REPLACE INTO third_party_hosts
               (host, first_seen, last_seen, hit_count, roles, sessions,
                sample_url, parent_urls)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (host, first, now, count, json.dumps(sorted(roles)),
             json.dumps(sorted(sessions)), rec["sample_url"],
             json.dumps(sorted(parents)[:20])))
        written += 1

    db.conn.commit()
    return written


def priority_hosts(db, limit: int = 200, include_boring: bool = False) -> list:
    """Hosts worth spending a rate-limited lookup on, most interesting first.

    A free threat-feed quota is small, so ordering matters: a host seen once
    as a redirect target beats a CDN seen five thousand times.
    """
    rows = db.conn.execute(
        "SELECT * FROM third_party_hosts ORDER BY hit_count DESC").fetchall()

    scored = []
    for row in rows:
        host = row["host"]
        if not include_boring and is_boring(host):
            continue
        roles = set(json.loads(row["roles"]))
        weight = len(roles & INTERESTING_ROLES) * 100
        weight += min(row["hit_count"], 50)
        scored.append((weight, {
            "host": host,
            "roles": sorted(roles),
            "hit_count": row["hit_count"],
            "sessions": json.loads(row["sessions"])[:5],
            "sample_url": row["sample_url"],
            "parents": json.loads(row["parent_urls"])[:3],
            "interesting": bool(roles & INTERESTING_ROLES),
        }))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [item for _, item in scored[:limit]]


def stats(db) -> dict:
    db.conn.executescript(SCHEMA)
    total = db.conn.execute(
        "SELECT COUNT(*) c FROM third_party_hosts").fetchone()["c"]
    checked = db.conn.execute(
        "SELECT COUNT(DISTINCT host) c FROM intel_lookups").fetchone()["c"]
    flagged = db.conn.execute(
        "SELECT COUNT(DISTINCT host) c FROM intel_lookups "
        "WHERE verdict IN ('malicious','suspicious')").fetchone()["c"]
    return {"hosts": total, "checked": checked, "unchecked": total - checked,
            "flagged": flagged}
