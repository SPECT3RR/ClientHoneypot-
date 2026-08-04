"""
Decision Policy Engine — maps analytics into ownership-state transitions.

Risk bands are loaded from config/decision_policy.yaml so thresholds can be
tuned without a code change. A CRITICAL payload detection overrides the bands
entirely: a confirmed exploit-kit cluster diverts to the decoy immediately,
whatever the numeric score says.
"""
from pathlib import Path

import yaml

from event_bus import EventBus, Event, EventCategory

DEFAULT_CONFIG = Path(__file__).parent.parent / "config" / "decision_policy.yaml"


class DecisionPolicyEngine:
    def __init__(self, bus: EventBus, config_path: Path = None):
        self.bus = bus
        self.current_state = "BOT_ACTIVE"
        self.context = {
            "threat_score": 0,
            "page_classification": "PAGE_UNKNOWN",
            "payload_confidence": "LOW",
        }
        self.bands = self._load_bands(config_path or DEFAULT_CONFIG)

        if bus is not None:
            bus.subscribe(EventCategory.PAYLOAD, self._on_analytics_event)
            bus.subscribe(EventCategory.BEHAVIORAL, self._on_analytics_event)

    @staticmethod
    def _load_bands(path: Path) -> list:
        """Return risk bands sorted ascending by min_score."""
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        bands = list((config.get("thresholds") or {}).values())
        if not bands:
            raise ValueError(f"no thresholds defined in {path}")
        return sorted(bands, key=lambda b: b["min_score"])

    def _state_for_score(self, score: int) -> str:
        """Highest band whose min_score the value reaches.

        Deliberately ignores each band's max_score: real scores routinely
        exceed the YAML's top bound (the mock page alone reaches 79, a full
        exploit kit 164) and must stay in the top band rather than falling
        through to the default.
        """
        state = self.bands[0]["state"]
        for band in self.bands:
            if score >= band["min_score"]:
                state = band["state"]
        return state

    async def _on_analytics_event(self, event: Event) -> None:
        dirty = False
        if event.type == "threat_score_updated":
            self.context["threat_score"] = event.payload.get("score", 0)
            dirty = True
        elif event.type == "page_classified":
            self.context["page_classification"] = event.payload.get(
                "classification", "PAGE_UNKNOWN")
            dirty = True
        elif event.type == "payload_detected":
            self.context["payload_confidence"] = event.payload.get(
                "confidence", "LOW")
            dirty = True

        if dirty:
            await self._evaluate()

    async def _evaluate(self) -> None:
        if self.context["payload_confidence"] == "CRITICAL":
            new_state, reason = "DECOY", "critical payload detected"
        elif self.context["payload_confidence"] == "HIGH":
            new_state, reason = "HUMAN_ACTIVE", "high-confidence payload"
        else:
            score = self.context["threat_score"]
            new_state = self._state_for_score(score)
            reason = f"threat score {score}"
            if (new_state == "BOT_ACTIVE"
                    and self.context["page_classification"] == "PAGE_LOGIN"):
                new_state, reason = "HUMAN_ACTIVE", "credential boundary"

        if new_state == self.current_state:
            return

        self.current_state = new_state
        await self.bus.publish(Event(
            priority=1,
            category=EventCategory.SYSTEM,
            type="state_transition",
            payload={"new_state": new_state, "reason": reason},
            source="DecisionPolicyEngine",
        ))
