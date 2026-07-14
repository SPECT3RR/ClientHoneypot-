"""
URL Queue + Traffic Scheduler (spec — URL Queue / Traffic Scheduler nodes).

Reads URLs from a file or list, deduplicates, applies a configurable rate
limit, and feeds them to the orchestrator in batches.  Each URL entry can
carry optional metadata (source, priority, referrer_chain) so the Navigation
Replay Engine can reconstruct a realistic browsing journey around it.
"""
import asyncio
import csv
import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass(order=True)
class QueuedURL:
    priority: int              # lower = higher priority (0 = critical)
    url: str = field(compare=False)
    source: str = field(default="manual", compare=False)
    referrer_chain: list = field(default_factory=list, compare=False)
    added_ts: float = field(default_factory=time.time, compare=False)


class URLQueue:
    def __init__(self, rate_per_minute: int = 10):
        self._queue: deque[QueuedURL] = deque()
        self._seen: set = set()
        self._rate = rate_per_minute
        self._interval = 60.0 / rate_per_minute
        self._last_dispatch = 0.0

    def add(self, url: str, priority: int = 5, source: str = "manual",
            referrer_chain: list = None):
        if url in self._seen:
            return
        self._seen.add(url)
        entry = QueuedURL(
            priority=priority,
            url=url,
            source=source,
            referrer_chain=referrer_chain or [],
        )
        self._queue.append(entry)
        # Sort by priority after each insert (small queues, fine for MVP)
        sorted_q = sorted(self._queue)
        self._queue = deque(sorted_q)

    def add_from_file(self, path: str):
        """Load URLs from a plain text file (one per line) or JSON/CSV."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(path)
        text = p.read_text()
        if path.endswith(".json"):
            items = json.loads(text)
            for item in items:
                if isinstance(item, str):
                    self.add(item)
                elif isinstance(item, dict):
                    self.add(
                        item["url"],
                        priority=item.get("priority", 5),
                        source=item.get("source", "file"),
                        referrer_chain=item.get("referrer_chain", []),
                    )
        elif path.endswith(".csv"):
            reader = csv.DictReader(text.splitlines())
            for row in reader:
                self.add(row["url"], source=row.get("source", "csv"))
        else:
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self.add(line)

    async def next(self) -> Optional[QueuedURL]:
        if not self._queue:
            return None
        now = time.time()
        wait = self._interval - (now - self._last_dispatch)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_dispatch = time.time()
        return self._queue.popleft()

    def __len__(self):
        return len(self._queue)
