from typing import Protocol
from event_bus import EventBus

class AnalyticsPlugin(Protocol):
    """Base interface for all analytics engines in the Adaptive Weave Engine."""
    
    def name(self) -> str:
        """Return the name of the analytics plugin."""
        ...
        
    def initialize(self, bus: EventBus) -> None:
        """Register subscriptions to the central event bus."""
        ...
