import asyncio
from enum import Enum

class OwnerState(Enum):
    BOT_ACTIVE = "BOT_ACTIVE"
    HUMAN_OVERRIDE = "HUMAN_OVERRIDE"
    TRANSITION_TO_BOT = "TRANSITION_TO_BOT"
    PAUSED = "PAUSED"
    DECOY = "DECOY"

class OwnershipManager:
    """
    Authoritative source of truth for browser session ownership.
    """
    def __init__(self, idle_threshold_ms=5000):
        self._state = OwnerState.BOT_ACTIVE
        self.generation = 1
        self.idle_threshold_ms = idle_threshold_ms
        self._state_changed_event = asyncio.Event()
        
        # Explicit bot-action boundary flag
        self.bot_action_active = False

    @property
    def current_owner(self) -> OwnerState:
        return self._state

    def is_valid(self, generation: int) -> bool:
        """Scheduler checks this to ensure its actions aren't stale."""
        return self._state == OwnerState.BOT_ACTIVE and self.generation == generation

    async def wait_until(self, target_state: OwnerState):
        """Block until the requested state is reached."""
        while self._state != target_state:
            await self._state_changed_event.wait()

    def _set_state(self, new_state: OwnerState):
        if self._state != new_state:
            print(f"[WEAVE] {self._state.name} -> {new_state.name}")
            self._state = new_state
            
            if hasattr(self, "_browser") and self._browser:
                import asyncio
                asyncio.create_task(self._browser.broadcast_owner_state(new_state.name))
            
            # Unblock any waiters
            self._state_changed_event.set()
            self._state_changed_event.clear()

    def notify_human_activity(self, event_type: str = "unknown"):
        """Called by browser bridge when candidate input is detected."""
        if self.bot_action_active:
            # We are actively executing a Playwright command. Ignore!
            return
            
        if self._state in (OwnerState.BOT_ACTIVE, OwnerState.TRANSITION_TO_BOT):
            print(f"[WEAVE] HUMAN_ACTIVITY {event_type}")
            self.generation += 1 # Immediately invalidate in-flight bot routines
            self._set_state(OwnerState.HUMAN_OVERRIDE)

    def notify_human_idle(self):
        """Called by browser bridge when inactivity reaches threshold."""
        if self._state == OwnerState.HUMAN_OVERRIDE:
            print(f"[WEAVE] HUMAN_IDLE {self.idle_threshold_ms}ms")
            self._set_state(OwnerState.TRANSITION_TO_BOT)
            
            # Instantly transition back to bot (scheduler will pick it up)
            print("[WEAVE] Scheduler resuming current page")
            self._set_state(OwnerState.BOT_ACTIVE)

    def set_decoy(self):
        """Enter DECOY: the session has been diverted into the synthetic
        environment. Bumps generation so any in-flight bot routine on the
        real page is invalidated before the walk starts.
        """
        self.generation += 1
        self._set_state(OwnerState.DECOY)


class bot_action_boundary:
    """
    Async context manager that marks the active bot boundary.
    Any browser events arriving during this window are classified as BOT_ACTIVITY.
    """
    def __init__(self, ownership_mgr: OwnershipManager, generation: int):
        self.mgr = ownership_mgr
        self.gen = generation
        
    async def __aenter__(self):
        self.mgr.bot_action_active = True
        return self
        
    async def __aexit__(self, exc_type, exc, tb):
        self.mgr.bot_action_active = False
