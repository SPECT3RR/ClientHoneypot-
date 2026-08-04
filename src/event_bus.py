"""
Central Event Bus for the Adaptive Weave Engine.
Implements an asyncio.PriorityQueue-based Publisher/Subscriber model.
"""
import asyncio
import itertools
from typing import Callable, Dict, List, Any, Set  # noqa: F401
from enum import Enum
from dataclasses import dataclass, field
import datetime
import traceback

class EventCategory(Enum):
    NAVIGATION = "navigation"
    BEHAVIORAL = "behavioral"
    NETWORK = "network"
    DOM = "dom"
    BROWSER = "browser"
    PAYLOAD = "payload"
    ANALYST = "analyst"
    SYSTEM = "system"

_seq_counter = itertools.count()


@dataclass(order=True)
class Event:
    priority: int
    category: EventCategory = field(compare=False)
    type: str = field(compare=False)
    payload: Dict[str, Any] = field(compare=False)
    source: str = field(compare=False)
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat(), compare=False)
    # PriorityQueue is a heap, and a heap is not stable. Without a tiebreaker,
    # events sharing a priority — which is nearly all of them — dispatch in
    # arbitrary order and the forensic timeline no longer reflects what
    # actually happened. Ordering is therefore (priority, seq): dataclass
    # order compares compare=True fields in declaration order.
    seq: int = field(default_factory=lambda: next(_seq_counter), compare=True)

class EventBus:
    def __init__(self, maxsize: int = 10000):
        self._subscribers: Dict[EventCategory, Set[Callable[[Event], Any]]] = {
            cat: set() for cat in EventCategory
        }
        self._all_subscribers: Set[Callable[[Event], Any]] = set()
        self._queue = asyncio.PriorityQueue(maxsize=maxsize)
        self._worker_task = None
        self.errors: List[tuple] = []
        self.dropped: int = 0

    def start(self):
        """Start the background worker task to process events."""
        if self._worker_task is None:
            self._worker_task = asyncio.create_task(self._worker_loop())

    async def stop(self):
        """Stop the background worker."""
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None

    def subscribe(self, category: EventCategory, callback: Callable[[Event], Any]):
        """Subscribe to a specific event category."""
        self._subscribers[category].add(callback)

    def unsubscribe(self, category: EventCategory, callback: Callable[[Event], Any]):
        """Remove a subscription to prevent memory leaks."""
        if callback in self._subscribers[category]:
            self._subscribers[category].remove(callback)

    def subscribe_all(self, callback: Callable[[Event], Any]):
        """Subscribe to all events (useful for Timeline Recorders)."""
        self._all_subscribers.add(callback)

    def unsubscribe_all(self, callback: Callable[[Event], Any]):
        """Remove a global subscription."""
        if callback in self._all_subscribers:
            self._all_subscribers.remove(callback)

    async def publish(self, event: Event):
        """Enqueue an event. Never blocks: subscribers publish from inside
        dispatch, so a blocking put would deadlock the worker against itself.
        A full queue drops the event and increments `dropped`.
        """
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

    async def drain(self):
        """Return once every queued event has been dispatched."""
        await self._queue.join()

    async def _worker_loop(self):
        """Dedicated worker pulling events and dispatching safely."""
        while True:
            try:
                event = await self._queue.get()
                try:
                    await self._dispatch(event)
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[EventBus] Worker error: {e}")
                traceback.print_exc()

    async def _dispatch(self, event: Event):
        """Await every subscriber so failures surface instead of vanishing.

        ponytail: serial dispatch — one slow subscriber stalls the timeline.
        Move to per-subscriber queues if a subscriber ever does real I/O.
        """
        callbacks = list(self._subscribers.get(event.category, set())) + \
                    list(self._all_subscribers)
        if not callbacks:
            return

        loop = asyncio.get_running_loop()
        awaitables = []
        for cb in callbacks:
            if asyncio.iscoroutinefunction(cb):
                awaitables.append(cb(event))
            else:
                awaitables.append(loop.run_in_executor(None, cb, event))

        results = await asyncio.gather(*awaitables, return_exceptions=True)
        for cb, result in zip(callbacks, results):
            if isinstance(result, BaseException):
                name = getattr(cb, "__qualname__", repr(cb))
                self.errors.append((name, result))
                print(f"[EventBus] subscriber {name} failed: {result!r}")
