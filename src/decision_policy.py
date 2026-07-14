from event_bus import EventBus, Event, EventCategory

class DecisionPolicyEngine:
    """
    Evaluates Analytics -> State Transitions using a Decision Matrix.
    """
    def __init__(self, bus: EventBus):
        self.bus = bus
        self.current_state = "BOT_ACTIVE"
        
        # State Matrix context variables
        self.context = {
            "threat_score": 0,
            "page_classification": "PAGE_UNKNOWN",
            "payload_confidence": "LOW"
        }
        
        bus.subscribe(EventCategory.PAYLOAD, self._on_analytics_event)
        bus.subscribe(EventCategory.BEHAVIORAL, self._on_analytics_event)
        
    async def _on_analytics_event(self, event: Event) -> None:
        dirty = False
        
        if event.type == "threat_score_updated":
            self.context["threat_score"] = event.payload.get("score", 0)
            dirty = True
        elif event.type == "page_classified":
            self.context["page_classification"] = event.payload.get("classification", "PAGE_UNKNOWN")
            dirty = True
        elif event.type == "payload_detected":
            self.context["payload_confidence"] = event.payload.get("confidence", "LOW")
            dirty = True
            
        if dirty:
            await self._evaluate_matrix()
            
    async def _evaluate_matrix(self):
        new_state = "BOT_ACTIVE"
        
        # Matrix rules evaluation
        if self.context["payload_confidence"] == "CRITICAL":
            new_state = "DECOY"
        elif self.context["payload_confidence"] == "HIGH":
            new_state = "HUMAN_ACTIVE"
        elif self.context["page_classification"] == "PAGE_LOGIN":
            # Always hand off to human on credential boundaries
            new_state = "HUMAN_ACTIVE"
        elif self.context["threat_score"] > 50:
            new_state = "SHARED_CONTROL"
            
        if new_state != self.current_state:
            self.current_state = new_state
            await self.bus.publish(Event(
                priority=1, # High priority transition
                category=EventCategory.SYSTEM,
                type="state_transition",
                payload={"new_state": self.current_state},
                source="DecisionPolicyEngine"
            ))
