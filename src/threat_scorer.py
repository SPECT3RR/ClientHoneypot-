from plugins.analytics_interface import AnalyticsPlugin
from event_bus import EventBus, Event, EventCategory

class ThreatScorer(AnalyticsPlugin):
    """
    Evaluates raw bus events to flag malicious intent and emits categorized Threat events.
    Replaces the legacy ThreatScorer.
    """
    def name(self) -> str:
        return "ThreatScorer"
        
    def initialize(self, bus: EventBus) -> None:
        self.bus = bus
        self.score = 0
        bus.subscribe(EventCategory.NETWORK, self._on_network)
        bus.subscribe(EventCategory.DOM, self._on_dom)
        
    async def _on_network(self, event: Event) -> None:
        # Example network evaluation logic
        if event.type == "redirect":
            self.score += 5
            await self.bus.publish(Event(
                priority=10,
                category=EventCategory.PAYLOAD,
                type="threat_score_updated",
                payload={"score": self.score, "reason": "excessive_redirect"},
                source=self.name()
            ))
        
    async def _on_dom(self, event: Event) -> None:
        # Example DOM evaluation logic
        pass
