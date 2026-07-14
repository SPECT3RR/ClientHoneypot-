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
        
    async def tick(self, root_page) -> None:
        """Main non-blocking execution loop."""
        import time
        state = self.weave_controller.active_state
        
        # Iterate over all tabs in the context
        pages = root_page.context.pages
        for page in pages:
            if page.is_closed():
                continue
                
            # 1. Idle Detection (Check if Human is active on this tab)
            try:
                last_move = await page.evaluate("window.__lastHumanMove || 0")
                idle_time_ms = (time.time() * 1000) - last_move
            except Exception:
                idle_time_ms = 0
                last_move = 0
                
            # If human hasn't moved in 5 seconds or never moved
            human_idle = (idle_time_ms > 5000) or (last_move == 0)
            
            if state == "BOT_ACTIVE":
                if human_idle:
                    await self._run_bot_primitives(page)
                else:
                    pass # Human is actively driving this tab
            elif state == "SHARED_CONTROL":
                if human_idle:
                    await self._run_micro_weaves(page)
            elif state == "HUMAN_ACTIVE":
                pass # Wait for state change, no automated actions
        
        
        # Wait for next logical tick or DOM event before cycling
        try:
            await asyncio.wait_for(self._action_events.get(), timeout=1.0)
        except asyncio.TimeoutError:
            pass
            
    async def _run_bot_primitives(self, page) -> None:
        from behavior_engine import act_human
        print("[InteractionScheduler] BOT_ACTIVE: Simulating human reading and navigation...")
        try:
            await act_human(page)
        except Exception:
            pass
        
    async def _run_micro_weaves(self, page) -> None:
        from behavior_engine import random_scroll, random_mouse_wander
        print("[InteractionScheduler] SHARED_CONTROL: Executing micro-weave jitter...")
        try:
            await random_mouse_wander(page, moves=2)
            await random_scroll(page, iterations=1)
        except Exception:
            pass
