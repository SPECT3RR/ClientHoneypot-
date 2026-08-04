"""
Bait seeder — arms the browser profile before the first navigation.

This is the engine of the whole platform, and it inverts the usual honeypot
direction. We do not wait for a payload to come exploring our decoy: most
payloads never explore anything. An infostealer grabs what is in front of it
and exfiltrates. So we put the bait in front of it.

Everything written here is synthetic and non-functional. The credentials
point at our own decoy portal or at canary tokens that fire when used. When
the attacker later tries them -- from their own infrastructure, days later --
the callback identifies the session that planted them.

Seeding happens on EVERY session regardless of verdict, because a payload
steals credentials before we have finished deciding it is a payload.

Locations were chosen to match what commodity infostealers actually harvest:
localStorage, cookies, the Chromium Login Data store, autofill, the Downloads
folder, and bookmarks.
"""
import json
import sqlite3
import time
from pathlib import Path

DECOY_BASE = "http://127.0.0.1:8001"


def _download_files(persona: dict, tokens: dict) -> dict:
    """Files a real employee plausibly has sitting in Downloads."""
    name = persona.get("employee_name", "A. Employee")
    company = "Asteria Holdings"
    return {
        "credentials.txt": (
            f"# {company} - saved logins ({name})\n"
            f"portal   {DECOY_BASE}/portal/login\n"
            f"user     {tokens['username']}\n"
            f"pass     {tokens['password']}\n"),
        "vpn_config.ovpn": (
            f"# {company} VPN\nremote vpn.asteriaholdings.example 1194\n"
            f"proto udp\ndev tun\nauth-user-pass\n"
            f"# {tokens['username']} / {tokens['password']}\n"),
        "aws_credentials": (
            f"[default]\naws_access_key_id = {tokens['aws_key']}\n"
            f"aws_secret_access_key = {tokens['aws_secret']}\n"
            f"region = us-east-1\n"),
    }


class BaitSeeder:
    """Writes per-session bait into a Chromium profile directory."""

    def __init__(self, profile_dir: Path, session_id: str, persona: dict,
                 vault=None):
        self.profile_dir = Path(profile_dir)
        self.session_id = session_id
        self.persona = persona
        self.vault = vault
        self.planted: list = []

    # ── token assembly ─────────────────────────────────────────────────────

    def _tokens(self) -> dict:
        """Build the bait credential set, preferring operator-supplied
        canaries and falling back to self-hosted URL tokens.
        """
        tokens = {
            "username": (self.persona.get("employee_name", "user")
                         .split()[0].lower() + ".asteria"),
            "password": f"Asteria!{self.session_id[:8]}",
            "aws_key": f"AKIA{self.session_id[:16].upper()}",
            "aws_secret": f"seed{self.session_id}00000000000000",
            "callback_urls": [],
        }
        if self.vault is None:
            return tokens

        for row in self.vault.for_placement("browser_profile"):
            self.vault.stamp(row["token_id"], self.session_id)
            self.planted.append(row["token_id"])
            if row["kind"] == "aws_key":
                # Operator-supplied real canary beats our synthetic one.
                tokens["aws_key"] = row["value"]
                tokens["aws_secret"] = row.get("label") or tokens["aws_secret"]
            elif row["kind"] in ("url_token", "dns_callback", "tracking_pixel"):
                tokens["callback_urls"].append(row["value"])
        return tokens

    # ── profile writers ────────────────────────────────────────────────────

    def _write_downloads(self, tokens: dict) -> None:
        downloads = self.profile_dir.parent / "Downloads" / self.session_id
        downloads.mkdir(parents=True, exist_ok=True)
        for filename, content in _download_files(self.persona, tokens).items():
            (downloads / filename).write_text(content, encoding="utf-8")
        self.downloads_dir = downloads

    def _write_bookmarks(self, tokens: dict) -> None:
        """Chromium Bookmarks is plain JSON, so this needs no browser running."""
        urls = [
            (f"{DECOY_BASE}/portal/login", "Asteria Employee Portal"),
            (f"{DECOY_BASE}/portal/finance", "Finance Portal"),
            (f"{DECOY_BASE}/portal/files", "File Server"),
        ] + [(u, "Internal") for u in tokens["callback_urls"]]

        children = [{
            "date_added": str(int(time.time() * 1_000_000)),
            "id": str(100 + i), "name": name, "type": "url", "url": url,
        } for i, (url, name) in enumerate(urls)]

        default = self.profile_dir / "Default"
        default.mkdir(parents=True, exist_ok=True)
        (default / "Bookmarks").write_text(json.dumps({
            "checksum": "", "version": 1,
            "roots": {
                "bookmark_bar": {"children": children, "date_added": "0",
                                 "id": "1", "name": "Bookmarks bar",
                                 "type": "folder"},
                "other": {"children": [], "date_added": "0", "id": "2",
                          "name": "Other bookmarks", "type": "folder"},
                "synced": {"children": [], "date_added": "0", "id": "3",
                           "name": "Mobile bookmarks", "type": "folder"},
            }}, indent=2), encoding="utf-8")

    def init_script(self, tokens: dict) -> str:
        """JS injected before any page script, seeding web storage.

        Chromium keeps localStorage in a LevelDB the browser holds open, so
        writing it from disk is not practical. Injecting at document_start
        gets the same result and runs before any payload can read it.
        """
        payload = {
            "asteria_session": f"sess_{self.session_id}",
            "asteria_user": tokens["username"],
            "asteria_api_key": tokens["aws_key"],
            "asteria_portal": f"{DECOY_BASE}/portal/login",
        }
        if tokens["callback_urls"]:
            payload["asteria_sync_url"] = tokens["callback_urls"][0]

        return f"""
        (() => {{
          const bait = {json.dumps(payload)};
          try {{
            for (const [k, v] of Object.entries(bait)) {{
              localStorage.setItem(k, v);
            }}
            sessionStorage.setItem('asteria_token', bait.asteria_session);
          }} catch (e) {{}}
        }})();
        """

    def cookies(self, tokens: dict) -> list:
        """Playwright cookie objects for the decoy domain."""
        expires = time.time() + 30 * 24 * 3600
        return [
            {"name": "sid", "value": self.session_id, "domain": "127.0.0.1",
             "path": "/", "expires": expires},
            {"name": "asteria_auth", "value": f"tok_{tokens['aws_key'][:16]}",
             "domain": "127.0.0.1", "path": "/", "expires": expires},
        ]

    # ── entrypoint ─────────────────────────────────────────────────────────

    def seed(self) -> dict:
        """Write everything that can be written before the browser starts."""
        tokens = self._tokens()
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        self._write_downloads(tokens)
        self._write_bookmarks(tokens)
        self.tokens = tokens
        return {
            "session_id": self.session_id,
            "planted_tokens": self.planted,
            "callback_urls": tokens["callback_urls"],
            "downloads": str(self.downloads_dir),
            "username": tokens["username"],
        }
