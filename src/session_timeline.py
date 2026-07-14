from plugins.analytics_interface import AnalyticsPlugin
from event_bus import EventBus, Event, EventCategory
import json
import datetime
from pathlib import Path

class SessionTimelineRecorder(AnalyticsPlugin):
    """
    Subscribes to all bus events to construct a perfect forensic timeline.
    """
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.timeline = []
        
    def name(self) -> str:
        return "SessionTimelineRecorder"
        
    def initialize(self, bus: EventBus) -> None:
        bus.subscribe_all(self._on_any_event)
        
    async def _on_any_event(self, event: Event) -> None:
        self.timeline.append({
            "timestamp": event.timestamp,
            "priority": event.priority,
            "category": event.category.value,
            "type": event.type,
            "source": event.source,
            "payload": event.payload
        })
        
    def export(self, output_dir: str = "reports/"):
        path = Path(output_dir) / f"{self.session_id}_timeline.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.timeline, f, indent=2)
        print(f"[TimelineRecorder] Exported forensic timeline with {len(self.timeline)} events to {path}")
