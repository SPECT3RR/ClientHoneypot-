"""
Bridge between the event bus and the correlated detection engine.

The engine itself lives in threat_detection.py — 60+ raw signals grouped into
8 attack clusters, where only co-occurring signals produce a real score. This
module's only job is to route bus events into the right scan function and
republish the result as higher-order analytics events.

Publishes on EventCategory.PAYLOAD:
  threat_score_updated  — every time the score changes
  payload_detected      — once, when the score first crosses the decoy threshold
"""
from plugins.analytics_interface import AnalyticsPlugin
from event_bus import EventBus, Event, EventCategory
import threat_detection as td


class ThreatScorer(AnalyticsPlugin):
    def __init__(self):
        self._engine = td.ThreatScorer()
        self._redirect_chain = 0
        self._detected = False
        self._muted = False
        self.bus = None

    def name(self) -> str:
        return "ThreatScorer"

    @property
    def score(self) -> int:
        return self._engine.score

    @property
    def clusters(self) -> list:
        return list(self._engine.clusters)

    def summary(self) -> dict:
        return self._engine.summary()

    def initialize(self, bus: EventBus) -> None:
        self.bus = bus
        bus.subscribe(EventCategory.NETWORK, self._on_network)
        bus.subscribe(EventCategory.DOM, self._on_dom)
        bus.subscribe(EventCategory.NAVIGATION, self._on_navigation)
        bus.subscribe(EventCategory.SYSTEM, self._on_system)

    async def _on_system(self, event: Event) -> None:
        """Stop scoring once diverted.

        Past DECOY the browser is walking our own synthetic portal, which has
        login forms and password fields of its own. Scoring those attributes
        our decoy's behaviour to the attacker and inflates the verdict for the
        real target.
        """
        if event.type == "state_transition" and \
                event.payload.get("new_state") == "DECOY":
            self._muted = True

    # ── routing ────────────────────────────────────────────────────────────

    async def _on_navigation(self, event: Event) -> None:
        if self._muted:
            return
        if event.type == "visit_start":
            self._redirect_chain = 0
            url = event.payload.get("url", "")
            await self._record(td.scan_url(url), url)

    async def _on_network(self, event: Event) -> None:
        if self._muted:
            return
        if event.type == "redirect":
            self._redirect_chain += 1
            await self._record(td.scan_redirect_chain(self._redirect_chain),
                               event.payload.get("url", ""))
        elif event.type == "download":
            filename = event.payload.get("filename", "")
            await self._record(td.scan_download(filename), filename)

    async def _on_dom(self, event: Event) -> None:
        if self._muted:
            return
        url = event.payload.get("url", "")
        if event.type == "dom_snapshot":
            await self._record(td.scan_dom(event.payload.get("html", ""), url), url)
        elif event.type == "script_evaluation":
            await self._record(
                td.scan_script_text(event.payload.get("script", ""), url), url)

    # ── scoring ────────────────────────────────────────────────────────────

    async def _record(self, labels: list, detail: str) -> None:
        if not labels:
            return

        before = self._engine.score
        self._engine.add(labels, detail)
        if self._engine.score == before:
            return  # all labels were duplicates

        await self.bus.publish(Event(
            priority=10,
            category=EventCategory.PAYLOAD,
            type="threat_score_updated",
            payload={
                "score": self._engine.score,
                "clusters": list(self._engine.clusters),
                "findings": [f["label"] for f in self._engine.findings],
            },
            source=self.name(),
        ))

        if self._engine.should_trigger_decoy() and not self._detected:
            self._detected = True
            await self.bus.publish(Event(
                priority=1,  # jumps the queue — this drives a state transition
                category=EventCategory.PAYLOAD,
                type="payload_detected",
                payload={
                    "confidence": "CRITICAL",
                    "score": self._engine.score,
                    "clusters": list(self._engine.clusters),
                    "summary": self._engine.summary(),
                },
                source=self.name(),
            ))
