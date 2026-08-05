"""
Canary vault — the operator supplies tokens, the system decides placement
and tracks every hit back to the session that produced it.

The vault holds two kinds of token:

  operator-supplied  real canaries minted elsewhere (canarytokens.org AWS
                     keys, DNS callbacks, tracking pixels). We cannot observe
                     AWS API usage ourselves, so those fire through their own
                     provider and the operator pastes them in here.

  self-minted        unique URL tokens served by our own callback route, for
                     everything we *can* observe.

Placement policy decides where each lands:

  browser_profile  bait seeded into the profile before navigation, where an
                   infostealer will find it. Fires when someone later USES
                   the credential -- typically days later, from attacker
                   infrastructure. This is the real intelligence.
  decoy_tier1      dashboard and department pages. Fires when anything gets
                   past the JS entry gate.
  decoy_tier2      the file server. Fires only when a classified human
                   operator reaches the vault, so real tokens are not burned
                   on automated scanners.
  decoy_services   a WORKING credential on the matching qeeqbox honeypot --
                   an SSH key that opens 22, a DB password that opens 3306.
                   Fires when the attacker actually tries the bait they stole,
                   which is the strongest signal the platform produces because
                   it proves the credential travelled.

Every placement is stamped with the session id, so a callback months later
still identifies the visit that planted it.
"""
import json
import secrets
import time
import uuid
from pathlib import Path

from verdict_db import VerdictDB

PLACEMENTS = ("browser_profile", "decoy_tier1", "decoy_tier2", "decoy_services")
KINDS = ("aws_key", "dns_callback", "url_token", "tracking_pixel", "document",
         "ssh_key", "db_credential")


class CanaryVault:
    def __init__(self, db: VerdictDB):
        self.db = db

    # ── operator-facing ────────────────────────────────────────────────────

    def add(self, kind: str, value: str, placement: str,
            label: str = None, token_id: str = None) -> str:
        """Register an operator-supplied token. Returns its token id."""
        if placement not in PLACEMENTS:
            raise ValueError(f"unknown placement {placement!r}; "
                             f"expected one of {PLACEMENTS}")
        if kind not in KINDS:
            raise ValueError(f"unknown kind {kind!r}; expected one of {KINDS}")

        token_id = token_id or uuid.uuid4().hex[:12]
        self.db.conn.execute(
            """INSERT OR REPLACE INTO canaries
               (token_id, kind, value, label, placement, session_id,
                placed_ts, burned)
               VALUES (?, ?, ?, ?, ?, NULL, NULL, 0)""",
            (token_id, kind, value, label, placement))
        self.db.conn.commit()
        return token_id

    def mint_url_token(self, placement: str, label: str = None,
                       base: str = "http://127.0.0.1:8001") -> tuple:
        """Create a self-hosted token we can observe ourselves.

        Returns (token_id, url). Any GET of that url is a confirmed hit.
        """
        token_id = secrets.token_hex(8)
        url = f"{base}/c/{token_id}"
        self.add("url_token", url, placement, label=label, token_id=token_id)
        return token_id, url

    def remove(self, token_id: str) -> None:
        self.db.conn.execute("DELETE FROM canaries WHERE token_id = ?", (token_id,))
        self.db.conn.commit()

    def all(self) -> list:
        return [dict(r) for r in self.db.conn.execute(
            "SELECT * FROM canaries ORDER BY placed_ts IS NULL DESC, placed_ts DESC")]

    # ── placement ──────────────────────────────────────────────────────────

    def for_placement(self, placement: str) -> list:
        """Unburned tokens registered for a placement."""
        return [dict(r) for r in self.db.conn.execute(
            "SELECT * FROM canaries WHERE placement = ? AND burned = 0",
            (placement,))]

    def stamp(self, token_id: str, session_id: str) -> None:
        """Record that this token was planted during this session."""
        self.db.conn.execute(
            "UPDATE canaries SET session_id = ?, placed_ts = ? WHERE token_id = ?",
            (session_id, time.time(), token_id))
        self.db.conn.commit()

    # ── callbacks ──────────────────────────────────────────────────────────

    def record_hit(self, token_id: str, src_ip: str = None,
                   user_agent: str = None, detail: dict = None) -> dict:
        """A canary fired. Returns the origin session, or None if unknown.

        The hit usually arrives long after the session ended and from
        attacker infrastructure rather than the site we visited -- which is
        exactly why the stamp matters.
        """
        row = self.db.conn.execute(
            "SELECT * FROM canaries WHERE token_id = ?", (token_id,)).fetchone()
        if row is None:
            return None

        self.db.conn.execute(
            """INSERT INTO canary_hits (token_id, ts, src_ip, user_agent, detail)
               VALUES (?, ?, ?, ?, ?)""",
            (token_id, time.time(), src_ip, user_agent,
             json.dumps(detail or {}, default=str)))
        self.db.conn.execute(
            "UPDATE canaries SET burned = 1 WHERE token_id = ?", (token_id,))
        self.db.conn.commit()

        return {"token_id": token_id, "kind": row["kind"],
                "label": row["label"], "placement": row["placement"],
                "origin_session": row["session_id"],
                "placed_ts": row["placed_ts"], "src_ip": src_ip}

    def hits(self, limit: int = 50) -> list:
        return [dict(r) for r in self.db.conn.execute(
            """SELECT h.*, c.kind, c.label, c.placement, c.session_id
               FROM canary_hits h JOIN canaries c ON c.token_id = h.token_id
               ORDER BY h.ts DESC LIMIT ?""", (limit,))]

    def stats(self) -> dict:
        total = self.db.conn.execute(
            "SELECT COUNT(*) c FROM canaries").fetchone()["c"]
        burned = self.db.conn.execute(
            "SELECT COUNT(*) c FROM canaries WHERE burned = 1").fetchone()["c"]
        by_placement = {r["placement"]: r["c"] for r in self.db.conn.execute(
            "SELECT placement, COUNT(*) c FROM canaries GROUP BY placement")}
        return {"total": total, "burned": burned,
                "hits": self.db.conn.execute(
                    "SELECT COUNT(*) c FROM canary_hits").fetchone()["c"],
                "by_placement": by_placement}


def default_seed_tokens(vault: CanaryVault) -> list:
    """Mint a minimal self-hosted bait set so hunting is never blocked on
    the operator having pasted real canaries in yet. Degraded, not broken.
    """
    minted = []
    if not vault.for_placement("browser_profile"):
        for label in ("corp-vpn", "aws-prod", "internal-wiki"):
            token_id, url = vault.mint_url_token("browser_profile", label=label)
            minted.append(token_id)
    return minted
