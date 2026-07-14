from weave_controller import AdaptiveWeaveController
from user_context import UserContextModel
from event_bus import EventBus, Event, EventCategory
import asyncio

class InteractionScheduler:
    """
    Translates the current Weave state into Playwright commands and Micro-Weaves.
    Event-driven design replaces static sleep().
    """
    def __init__(self, bus: EventBus, weave_controller: AdaptiveWeaveController, user_context: UserContextModel):
        self.bus = bus
        self.weave_controller = weave_controller
        self.context = user_context
        
        # State event queue for non-blocking reactive waits
        self._action_events = asyncio.Queue()
        self.bus.subscribe(EventCategory.DOM, self._on_dom_event)
        
    async def _on_dom_event(self, event: Event):
        if event.type in ("page_ready", "interaction_complete"):
            await self._action_events.put(event)
        
    async def tick(self, page) -> None:
        """Main non-blocking execution loop."""
        state = self.weave_controller.active_state
        
        if state == "BOT_ACTIVE":
            await self._run_bot_primitives(page)
        elif state == "SHARED_CONTROL":
            await self._run_micro_weaves(page)
        elif state == "HUMAN_ACTIVE":
            pass # Wait for state change, no automated actions
        
        # Wait for next logical tick or DOM event before cycling
        try:
            await asyncio.wait_for(self._action_events.get(), timeout=1.0)
        except asyncio.TimeoutError:
            pass
            
    async def _run_bot_primitives(self, page) -> None:
        # Publish interaction events rather than blocking
        pass
        
    async def _run_micro_weaves(self, page) -> None:
        # Event-driven micro-weave
        pass
