from plugins.analytics_interface import AnalyticsPlugin
from event_bus import EventBus, Event, EventCategory

class PageClassifier(AnalyticsPlugin):
    """
    Categorizes the active page (PAGE_LOGIN, PAGE_ARTICLE, PAGE_CHECKOUT, etc.)
    to inform the Decision Policy.
    """
    def name(self) -> str:
        return "PageClassifier"
        
    def initialize(self, bus: EventBus) -> None:
        self.bus = bus
        bus.subscribe(EventCategory.DOM, self._on_dom_event)
        
    async def _on_dom_event(self, event: Event) -> None:
        # Evaluate DOM snapshots for page signatures
        if event.type != "dom_snapshot":
            return
            
        html = event.payload.get("html", "").lower()
        classification = "PAGE_UNKNOWN"
        
        if "type=\"password\"" in html or "login" in html:
            classification = "PAGE_LOGIN"
        elif "checkout" in html or "add to cart" in html:
            classification = "PAGE_CHECKOUT"
        elif "article" in html or "blog" in html:
            classification = "PAGE_ARTICLE"
            
        # Emit a higher-order analytics event
        await self.bus.publish(Event(
            priority=10,
            category=EventCategory.BEHAVIORAL,
            type="page_classified",
            payload={"classification": classification, "url": event.payload.get("url", "")},
            source=self.name()
        ))
