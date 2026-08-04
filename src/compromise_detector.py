"""
Compromise Detector — turns raw observations into typed actions of compromise.

The threat scorer answers "does this page look malicious". This answers the
harder and more useful question: "did something actually happen". A page that
drops an executable, registers a service worker, or posts a credential form
off-site has *done* something, and that is true whether or not any signature
matched.

That distinction is the zero-day path. An unknown exploit still has to act,
and acting is observable. Behaviour-based detection catches what a pattern
list cannot.

A confirmed action escalates payload confidence directly rather than waiting
for the numeric score to accumulate — a dropped .exe should not need a
correlation cluster to also fire before the decoy engages.
"""
from urllib.parse import urlparse

from plugins.analytics_interface import AnalyticsPlugin
from event_bus import EventBus, Event, EventCategory
from threat_detection import SUSPICIOUS_EXTENSIONS

# Runtime instrumentation event type -> (action kind, severity).
# CRITICAL escalates payload confidence and therefore triggers diversion.
RUNTIME_ACTIONS = {
    "dynamic_script_injection":     ("dynamic_code_injection", "HIGH"),
    "dynamic_iframe_injection":     ("dynamic_code_injection", "HIGH"),
    "service_worker_registration":  ("persistence",            "CRITICAL"),
    "storage_exfil_write":          ("data_exfiltration",      "HIGH"),
    "clipboard_read_runtime":       ("data_exfiltration",      "HIGH"),
    "clipboard_write_runtime":      ("data_exfiltration",      "LOW"),
    "form_submit_credentials":      ("credential_harvest",     "CRITICAL"),
    "popup_spam":                   ("popup_abuse",            "HIGH"),
    "new_tab_abuse":                ("popup_abuse",            "LOW"),
    "indexeddb_write":              ("data_exfiltration",      "LOW"),
    "permission_request_suspicious": ("permission_abuse",      "LOW"),
}

# Threat-scorer signal labels that mean a dropper string is present in the page.
DROPPER_LABELS = {"dropper_ps1", "dropper_cmd", "dropper_mshta", "dropper_wscript"}

ESCALATING = {"CRITICAL", "HIGH"}


class CompromiseDetector(AnalyticsPlugin):
    def __init__(self):
        self.bus = None
        self.actions: list = []
        self._page_host = None
        self._page_loaded = False
        self._seen = set()
        self._escalated = False
        self._muted = False

    def name(self) -> str:
        return "CompromiseDetector"

    def initialize(self, bus: EventBus) -> None:
        self.bus = bus
        bus.subscribe(EventCategory.NETWORK, self._on_network)
        bus.subscribe(EventCategory.DOM, self._on_dom)
        bus.subscribe(EventCategory.NAVIGATION, self._on_navigation)
        bus.subscribe(EventCategory.PAYLOAD, self._on_payload)
        bus.subscribe(EventCategory.SYSTEM, self._on_system)

    async def _on_system(self, event: Event) -> None:
        """Stop recording once diverted.

        The decoy walk logs into our own portal, which fires
        form_submit_credentials. Recording that would attribute our own
        deception activity to the attacker as a credential_harvest TTP.
        """
        if event.type == "state_transition" and \
                event.payload.get("new_state") == "DECOY":
            self._muted = True

    # ── sources ────────────────────────────────────────────────────────────

    async def _on_navigation(self, event: Event) -> None:
        if event.type in ("visit_start", "framenavigated"):
            url = event.payload.get("url", "")
            host = urlparse(url).netloc.lower()
            if host and host != self._page_host:
                self._page_host = host
                self._page_loaded = True
        elif event.type == "new_tab_opened":
            await self._report("popup_abuse", "LOW",
                               {"url": event.payload.get("url", "")})

    async def _on_network(self, event: Event) -> None:
        if event.type == "download":
            filename = event.payload.get("filename", "")
            suspicious = any(filename.lower().endswith(ext)
                             for ext in SUSPICIOUS_EXTENSIONS)
            await self._report(
                "file_download", "CRITICAL" if suspicious else "LOW",
                {"filename": filename, "url": event.payload.get("url", ""),
                 "suspicious_extension": suspicious})

        elif event.type == "request":
            await self._check_beacon(event)

        elif event.type == "websocket":
            await self._report("websocket_channel", "HIGH",
                               {"url": event.payload.get("url", "")})

    async def _check_beacon(self, event: Event) -> None:
        """A request to a third-party host after the page has loaded.

        Third-party requests are utterly normal on the open web, so this is
        LOW on its own and exists to be correlated, not to fire alone.
        """
        if not self._page_loaded or not self._page_host:
            return
        url = event.payload.get("url", "")
        host = urlparse(url).netloc.lower()
        if not host or host == self._page_host:
            return
        if event.payload.get("resource_type") not in ("xhr", "fetch", "websocket"):
            return
        await self._report("outbound_beacon", "LOW",
                           {"url": url, "host": host,
                            "page_host": self._page_host})

    async def _on_dom(self, event: Event) -> None:
        mapped = RUNTIME_ACTIONS.get(event.type)
        if mapped is None:
            return
        kind, severity = mapped
        detail = {k: v for k, v in event.payload.items() if k != "url"}
        detail["url"] = event.payload.get("url", "")
        await self._report(kind, severity, detail)

    async def _on_payload(self, event: Event) -> None:
        """Dropper strings come from the threat scorer's signal labels."""
        if event.type != "threat_score_updated":
            return
        hits = DROPPER_LABELS.intersection(event.payload.get("findings", []))
        if hits:
            await self._report("command_execution", "CRITICAL",
                               {"signals": sorted(hits)})

    # ── emit ───────────────────────────────────────────────────────────────

    async def _report(self, kind: str, severity: str, detail: dict) -> None:
        if self._muted:
            return
        # Deduplicate on (kind, severity): a page injecting forty scripts is
        # one finding, not forty, and forty identical rows bury the timeline.
        key = (kind, severity)
        if key in self._seen:
            return
        self._seen.add(key)

        record = {"kind": kind, "severity": severity, "detail": detail,
                  "url": detail.get("url", "")}
        self.actions.append(record)

        await self.bus.publish(Event(
            priority=5, category=EventCategory.PAYLOAD,
            type="compromise_action", payload=record, source=self.name()))

        if severity in ESCALATING and not self._escalated:
            self._escalated = True
            await self.bus.publish(Event(
                priority=1, category=EventCategory.PAYLOAD,
                type="payload_detected",
                payload={
                    "confidence": "CRITICAL" if severity == "CRITICAL" else "HIGH",
                    "reason": f"observed action of compromise: {kind}",
                    "kind": kind,
                    "detail": detail,
                },
                source=self.name()))

    def summary(self) -> dict:
        by_severity = {}
        for a in self.actions:
            by_severity.setdefault(a["severity"], []).append(a["kind"])
        return {"count": len(self.actions), "by_severity": by_severity,
                "kinds": sorted({a["kind"] for a in self.actions})}
