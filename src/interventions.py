"""
Intervention queue — the human-in-the-loop surface.

Bot blockers are the reason the weave engine exists. When a bot hits a
CAPTCHA or challenge wall, the old behaviour was to append a line to
needs_human_review.txt and skip the URL entirely: the human was never
summoned and the session was thrown away.

Here the tab is parked instead. The worker blocks, the rest of the swarm
keeps hunting, and an operator picks the tab up, clears the challenge, and
hands it back mid-session — ownership_manager already models exactly that
transition and nothing was calling it.

This scales the way an operator actually works: with twenty bots running you
do not watch twenty browsers, you work a queue of raised hands.
"""
import asyncio
import re
import time

# Substring matching on the URL alone produced both entries currently sitting
# in needs_human_review.txt — "challenge" appears in plenty of benign paths.
# URL evidence is now a hint that must be corroborated by page content.
URL_HINTS = re.compile(
    r"(captcha|challenge|bot-?check|are-?you-?human|ddos-guard|cloudflare"
    r"|recaptcha|hcaptcha|please-verify|access-denied|blocked)", re.IGNORECASE)

CONTENT_MARKERS = re.compile(
    r"(g-recaptcha|h-captcha|hcaptcha\.com|recaptcha/api|cf-challenge"
    r"|challenge-platform|__cf_chl|turnstile|checking your browser"
    r"|verify you are human|enable javascript and cookies|ray id)",
    re.IGNORECASE)

BLOCKING_STATUS = {401, 403, 429, 503}


def detect_block(status: int, url: str, content: str = "") -> tuple:
    """Return (blocked, reason).

    Content evidence is authoritative; a URL hint alone is not enough.
    """
    if content and CONTENT_MARKERS.search(content):
        marker = CONTENT_MARKERS.search(content).group(0)
        return True, f"challenge page detected (marker: {marker!r})"

    if status in BLOCKING_STATUS:
        hint = URL_HINTS.search(url or "")
        detail = f", url hint {hint.group(0)!r}" if hint else ""
        return True, f"HTTP {status}{detail}"

    return False, ""


class Intervention:
    __slots__ = ("id", "session_id", "url", "reason", "screenshot",
                 "status", "ts", "resolved_ts", "_event")

    def __init__(self, iid, session_id, url, reason, screenshot=None):
        self.id = iid
        self.session_id = session_id
        self.url = url
        self.reason = reason
        self.screenshot = screenshot
        self.status = "open"
        self.ts = time.time()
        self.resolved_ts = None
        self._event = asyncio.Event()

    def as_dict(self) -> dict:
        return {"id": self.id, "session_id": self.session_id, "url": self.url,
                "reason": self.reason, "screenshot": self.screenshot,
                "status": self.status, "ts": self.ts,
                "age_seconds": round(time.time() - self.ts, 1),
                "resolved_ts": self.resolved_ts}


class InterventionQueue:
    def __init__(self, db=None):
        self._items: dict = {}
        self._next_id = 1
        self.db = db
        self._listeners: list = []

    def open(self) -> list:
        return [i.as_dict() for i in self._items.values() if i.status == "open"]

    def all(self) -> list:
        return [i.as_dict() for i in self._items.values()]

    def get(self, iid: int):
        return self._items.get(iid)

    def subscribe(self, callback) -> None:
        """Dashboard hook so a raised hand appears without polling."""
        self._listeners.append(callback)

    def _notify(self, item: Intervention) -> None:
        for cb in list(self._listeners):
            try:
                cb(item.as_dict())
            except Exception:
                pass

    async def raise_for(self, session_id: str, url: str, reason: str,
                        screenshot: str = None, timeout: float = 900) -> str:
        """Park this tab and block until an operator resolves it.

        Returns "resolved", "skipped", or "timeout". Only this worker waits;
        the rest of the swarm keeps hunting.
        """
        item = Intervention(self._next_id, session_id, url, reason, screenshot)
        self._items[item.id] = item
        self._next_id += 1

        if self.db is not None:
            self.db.conn.execute(
                """INSERT INTO interventions
                   (session_id, url, reason, screenshot_path, status, ts)
                   VALUES (?, ?, ?, ?, 'open', ?)""",
                (session_id, url, reason, screenshot, item.ts))
            self.db.conn.commit()

        self._notify(item)
        print(f"[INTERVENTION #{item.id}] {url}\n"
              f"    reason: {reason}\n"
              f"    waiting for an operator (dashboard -> Interventions)")

        try:
            await asyncio.wait_for(item._event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            item.status = "timeout"
            item.resolved_ts = time.time()
            self._notify(item)
            return "timeout"
        return item.status

    def resolve(self, iid: int, status: str = "resolved") -> bool:
        """Operator cleared the challenge (or chose to skip)."""
        item = self._items.get(iid)
        if item is None or item.status != "open":
            return False
        item.status = status
        item.resolved_ts = time.time()
        if self.db is not None:
            self.db.conn.execute(
                "UPDATE interventions SET status = ? WHERE session_id = ? AND url = ?",
                (status, item.session_id, item.url))
            self.db.conn.commit()
        item._event.set()
        self._notify(item)
        return True

    def stats(self) -> dict:
        counts = {}
        for i in self._items.values():
            counts[i.status] = counts.get(i.status, 0) + 1
        return {"open": counts.get("open", 0), "total": len(self._items),
                "by_status": counts}
