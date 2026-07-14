"""
Central Event Bus for the Adaptive Weave Engine.
Implements an asyncio.PriorityQueue-based Publisher/Subscriber model.
"""
import asyncio
from typing import Callable, Dict, List, Any, Set
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

@dataclass(order=True)
class Event:
    priority: int
    category: EventCategory = field(compare=False)
    type: str = field(compare=False)
    payload: Dict[str, Any] = field(compare=False)
    source: str = field(compare=False)
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat(), compare=False)

class EventBus:
    def __init__(self):
        self._subscribers: Dict[EventCategory, Set[Callable[[Event], Any]]] = {
            cat: set() for cat in EventCategory
        }
        self._all_subscribers: Set[Callable[[Event], Any]] = set()
        self._queue = asyncio.PriorityQueue()
        self._worker_task = None

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
        """Publish an event by pushing it onto the PriorityQueue."""
        await self._queue.put(event)

    async def _worker_loop(self):
        """Dedicated worker pulling events and dispatching safely."""
        while True:
            try:
                event = await self._queue.get()
                callbacks = list(self._subscribers.get(event.category, set())) + list(self._all_subscribers)
                
                for callback in callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            asyncio.create_task(callback(event))
                        else:
                            asyncio.get_running_loop().run_in_executor(None, callback, event)
                    except Exception as e:
                        print(f"[EventBus] Error dispatching to {callback}: {e}")
                        traceback.print_exc()
                        
                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[EventBus] Worker error: {e}")
                traceback.print_exc()
