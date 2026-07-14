from plugins.analytics_interface import AnalyticsPlugin
from event_bus import EventBus, Event, EventCategory

class BehavioralChallengeDetector(AnalyticsPlugin):
    """
    Detects malware actively checking for automation via sophisticated browser queries.
    """
    def name(self) -> str:
        return "BehavioralChallengeDetector"
        
    def initialize(self, bus: EventBus) -> None:
        self.bus = bus
        bus.subscribe(EventCategory.BROWSER, self._on_browser_event)
        bus.subscribe(EventCategory.DOM, self._on_dom_event)
        
    async def _on_browser_event(self, event: Event) -> None:
        if event.type == "api_access":
            api = event.payload.get("api_name", "")
            if api in ["navigator.webdriver", "HTMLCanvasElement.toDataURL", "WebGLRenderingContext"]:
                await self.bus.publish(Event(
                    priority=10,
                    category=EventCategory.BEHAVIORAL,
                    type="behavioral_challenge_detected",
                    payload={"challenge_type": "fingerprinting", "api": api},
                    source=self.name()
                ))

    async def _on_dom_event(self, event: Event) -> None:
        if event.type == "script_evaluation":
            script = event.payload.get("script", "")
            if "mousemove" in script and "entropy" in script:
                await self.bus.publish(Event(
                    priority=10,
                    category=EventCategory.BEHAVIORAL,
                    type="behavioral_challenge_detected",
                    payload={"challenge_type": "mouse_entropy_check"},
                    source=self.name()
                ))
