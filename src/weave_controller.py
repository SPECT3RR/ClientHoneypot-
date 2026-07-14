from event_bus import EventBus, Event, EventCategory

class AdaptiveWeaveController:
    """
    Maintains the active interaction state of the browser.
    """
    def __init__(self, bus: EventBus):
        self.bus = bus
        self.active_state = "BOT_ACTIVE"
        bus.subscribe(EventCategory.SYSTEM, self._on_system_event)
        
    async def _on_system_event(self, event: Event) -> None:
        if event.type == "state_transition":
            self.active_state = event.payload.get("new_state", "BOT_ACTIVE")
            print(f"[WeaveController] Active state changed to {self.active_state}")
