import re

from plugins.analytics_interface import AnalyticsPlugin
from event_bus import EventBus, Event, EventCategory


class PageClassifier(AnalyticsPlugin):
    """
    Categorizes the active page (PAGE_LOGIN, PAGE_ARTICLE, PAGE_CHECKOUT, etc.)
    to inform the Decision Policy.
    """

    LOGIN_RE = re.compile(
        r'<form[^>]*>.*?<input[^>]+type\s*=\s*["\']password["\']',
        re.IGNORECASE | re.DOTALL)

    def name(self) -> str:
        return "PageClassifier"

    def initialize(self, bus: EventBus) -> None:
        self.bus = bus
        bus.subscribe(EventCategory.DOM, self._on_dom_event)

    def _classify(self, html: str) -> str:
        """Classify a page from its HTML.

        A password input inside a form — not the bare word "login", which
        appears in the footer of most sites on the internet and previously
        classified nearly every page as a credential boundary.
        """
        if self.LOGIN_RE.search(html):
            return "PAGE_LOGIN"
        lowered = html.lower()
        if "add to cart" in lowered or "checkout" in lowered:
            return "PAGE_CHECKOUT"
        if "<article" in lowered:
            return "PAGE_ARTICLE"
        return "PAGE_UNKNOWN"

    async def _on_dom_event(self, event: Event) -> None:
        if event.type != "dom_snapshot":
            return
        classification = self._classify(event.payload.get("html", ""))
        await self.bus.publish(Event(
            priority=10,
            category=EventCategory.BEHAVIORAL,
            type="page_classified",
            payload={"classification": classification,
                     "url": event.payload.get("url", "")},
            source=self.name(),
        ))
