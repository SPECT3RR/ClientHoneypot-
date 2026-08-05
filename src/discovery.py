"""
Discovery queue — how three bots become fifteen.

The crawler navigates in place and comes back. That is the wrong shape for
malvertising: the payload usually sits two or three hops past the publisher,
behind an ad slot, an interstitial or a pop-under, and a single bot walking
that chain serially misses everything the other branches opened.

So a discovery does not get followed by the bot that found it. It gets
queued, and the swarm spawns a *new* bot for it. The anchor bot stays on the
URL the operator gave and keeps working it; children chase what it kicked up,
and their own discoveries spawn grandchildren. Three bots on a busy ad page
become ten or fifteen as the chain opens.

Every discovery carries its parent session and depth, so the finished
navigation graph shows the path from the clean publisher the operator typed
to the landing page that dropped the payload. That path is the evidence.

Bounded on every axis, because ad networks loop forever by design and this
machine has 900 MB to play with.
"""
import time
from urllib.parse import urlparse


class Discovery:
    __slots__ = ("url", "parent_session", "parent_worker", "depth",
                 "trigger", "ts")

    def __init__(self, url, parent_session=None, parent_worker=None,
                 depth=1, trigger="redirect"):
        self.url = url
        self.parent_session = parent_session
        self.parent_worker = parent_worker
        self.depth = depth
        self.trigger = trigger
        self.ts = time.time()

    def as_dict(self):
        return {"url": self.url, "parent_session": self.parent_session,
                "parent_worker": self.parent_worker, "depth": self.depth,
                "trigger": self.trigger, "ts": self.ts}


def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


class DiscoveryQueue:
    """Redirects, popups and ad clicks waiting for a bot of their own.

    The caps are the whole design. Without them one ad rotator produces
    unbounded bots and the machine dies before the hunt finishes.
    """

    def __init__(self, max_depth: int = 3, max_total: int = 60,
                 max_per_host: int = 6):
        self.max_depth = max_depth
        self.max_total = max_total
        self.max_per_host = max_per_host

        self._pending: list = []
        self._seen: set = set()
        self._per_host: dict = {}
        self.spawned = 0
        self.rejected: dict = {"depth": 0, "total": 0, "per_host": 0,
                               "duplicate": 0}

    def __len__(self):
        return len(self._pending)

    def offer(self, discovery: Discovery) -> bool:
        """Accept a discovery, or say why not.

        Rejections are counted rather than silently dropped: "we stopped at
        depth 3" is a finding, and an operator looking at a shallow graph
        needs to know whether the chain ended or we did.
        """
        url = (discovery.url or "").strip()
        if not url or not url.lower().startswith(("http://", "https://")):
            return False

        if url in self._seen:
            self.rejected["duplicate"] += 1
            return False
        if discovery.depth > self.max_depth:
            self.rejected["depth"] += 1
            return False
        if self.spawned + len(self._pending) >= self.max_total:
            self.rejected["total"] += 1
            return False

        host = host_of(url)
        if self._per_host.get(host, 0) >= self.max_per_host:
            # One ad rotator serving a hundred variants is one finding, not a
            # hundred bots.
            self.rejected["per_host"] += 1
            return False

        self._seen.add(url)
        self._per_host[host] = self._per_host.get(host, 0) + 1
        self._pending.append(discovery)
        return True

    def next(self):
        if not self._pending:
            return None
        # Shallowest first: the operator cares more about what the page they
        # typed does than about depth-3 tail of an ad chain.
        self._pending.sort(key=lambda d: (d.depth, d.ts))
        item = self._pending.pop(0)
        self.spawned += 1
        return item

    def stats(self) -> dict:
        return {"pending": len(self._pending), "spawned": self.spawned,
                "seen": len(self._seen), "rejected": dict(self.rejected),
                "max_depth": self.max_depth, "max_total": self.max_total}


# ── Chrome permissiveness ──────────────────────────────────────────────────
#
# Chrome blocks popups, mixed content and downloads it dislikes. Those
# defaults hide exactly what we are hunting: a blocked pop-under is a
# redirect chain we never see, and a blocked mixed-content script is a
# payload that never runs.
#
# Only safe under an isolated substrate, which is why the swarm gates it.
PERMISSIVE_ARGS = [
    "--disable-popup-blocking",
    "--disable-features=BlockInsecurePrivateNetworkRequests,"
    "AutoupgradeMixedContent,HttpsUpgrades",
    "--allow-running-insecure-content",
    "--disable-web-security",          # cross-origin frames stay readable
    "--safebrowsing-disable-download-protection",
    "--disable-client-side-phishing-detection",
    "--no-default-browser-check",
    "--disable-notifications",         # prompts, not blocks: stops modal stalls
    "--autoplay-policy=no-user-gesture-required",
]


def permissive_args(isolated: bool) -> list:
    """Unblock everything, but only when the browser is contained.

    Disabling web security and safe browsing on the host would be handing a
    hunted page the run of the machine.
    """
    return list(PERMISSIVE_ARGS) if isolated else []
