"""
Decoy Controller — drives the browser into the synthetic enterprise
environment once the decision policy calls for it.

Subscribes to state_transition. On DECOY it takes ownership, then hands the
browser to decoy_navigator.explore_decoy, which performs a randomised walk
(login, form fill, 2-4 portal pages, file server, honeytoken) so successive
sessions do not look scripted.
"""
import asyncio

from event_bus import EventBus, Event, EventCategory
from decoy_navigator import explore_decoy, check_decoy_reachable


class DecoyController:
    def __init__(self, bus: EventBus, ownership_mgr=None, browser=None):
        self.bus = bus
        self.ownership = ownership_mgr
        self.browser = browser
        self.engaged = False
        # Set once the walk is over, however it ended. The orchestrator waits
        # on this before teardown: engage() runs from a bus subscriber, so
        # without it the weave loop sees DECOY, breaks, and closes the browser
        # out from under the walk still using it.
        self.finished = asyncio.Event()
        bus.subscribe(EventCategory.SYSTEM, self._on_system_event)

    async def _on_system_event(self, event: Event) -> None:
        if event.type == "state_transition" and \
                event.payload.get("new_state") == "DECOY":
            await self.engage()

    async def engage(self, browser=None) -> bool:
        if self.engaged:
            return False
        try:
            return await self._engage(browser)
        finally:
            self.finished.set()

    async def _engage(self, browser=None) -> bool:
        browser = browser or self.browser
        if browser is None:
            return False

        if not check_decoy_reachable():
            print("[DecoyController] decoy unreachable on 127.0.0.1:8001 - "
                  "start it with: python decoy_app/app.py")
            await self.bus.publish(Event(
                priority=5, category=EventCategory.SYSTEM,
                type="decoy_engage_failed",
                payload={"reason": "decoy app not reachable on 127.0.0.1:8001"},
                source="DecoyController"))
            return False

        self.engaged = True
        if self.ownership is not None:
            self.ownership.set_decoy()

        session_id = getattr(browser, "session_id", "unknown_session")
        print("[DecoyController] engaging decoy environment...")
        summary = await explore_decoy(browser, session_id)

        await self.bus.publish(Event(
            priority=5, category=EventCategory.SYSTEM,
            type="decoy_engaged",
            payload={"status": "success", **summary},
            source="DecoyController"))
        return True
