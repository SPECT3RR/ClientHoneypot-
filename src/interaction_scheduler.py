import asyncio
from event_bus import EventBus, Event, EventCategory
from ownership_manager import OwnershipManager, OwnerState, bot_action_boundary
from user_context import UserContextModel
import behavior_engine
import random

class InteractionScheduler:
    """
    Manages continuous, interrupt-driven Bot loops for all open tabs.
    Complies entirely with OwnershipManager.
    """
    def __init__(self, bus: EventBus, ownership_mgr: OwnershipManager, user_context: UserContextModel):
        self.bus = bus
        self.ownership = ownership_mgr
        self.context = user_context
        self._active_tasks = {}

    async def tick(self, root_page) -> None:
        """Called periodically by orchestrator to ensure all tabs have bot tasks."""
        pages = root_page.context.pages
        for page in pages:
            if page.is_closed():
                continue
                
            page_id = id(page)
            if page_id not in self._active_tasks or self._active_tasks[page_id].done():
                print(f"[SwarmBot] Launching continuous weave task for tab: {page.url[:40]}")
                self._active_tasks[page_id] = asyncio.create_task(self._continuous_bot_loop(page))
                
        await asyncio.sleep(1.0) # Prevent tight CPU loop in orchestrator
        
    async def _continuous_bot_loop(self, page) -> None:
        """
        The continuous asynchronous behavior loop required by the architecture.
        It waits for BOT_ACTIVE, then executes primitives while checking ownership.
        """
        while not page.is_closed():
            # 1. Wait until bot owns the browser
            await self.ownership.wait_until(OwnerState.BOT_ACTIVE)
            generation = self.ownership.generation
            
            # If page closed while waiting, break
            if page.is_closed():
                break
                
            # 2. Execute primitive: Wander
            if not self.ownership.is_valid(generation): continue
            async with bot_action_boundary(self.ownership, generation):
                try:
                    await behavior_engine.random_mouse_wander(page)
                except Exception:
                    pass

            # 3. Execute primitive: Scroll
            if not self.ownership.is_valid(generation): continue
            async with bot_action_boundary(self.ownership, generation):
                try:
                    await behavior_engine.random_scroll(page)
                except Exception:
                    pass

            # 4. Execute primitive: Click
            if not self.ownership.is_valid(generation): continue
            if random.random() < 0.8:
                async with bot_action_boundary(self.ownership, generation):
                    try:
                        await behavior_engine.random_click(page)
                    except Exception:
                        pass

            # 5. Execute primitive: Read
            if not self.ownership.is_valid(generation): continue
            async with bot_action_boundary(self.ownership, generation):
                try:
                    await behavior_engine.simulate_reading(page)
                except Exception:
                    pass

            # 6. Execute primitive: Idle
            if not self.ownership.is_valid(generation): continue
            async with bot_action_boundary(self.ownership, generation):
                try:
                    await behavior_engine.occasional_idle()
                except Exception:
                    pass
