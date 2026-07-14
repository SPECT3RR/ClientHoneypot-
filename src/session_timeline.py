from plugins.analytics_interface import AnalyticsPlugin
from event_bus import EventBus, Event, EventCategory
import json
import datetime
from pathlib import Path

class SessionTimelineRecorder(AnalyticsPlugin):
    """
    Subscribes to all bus events to construct a perfect forensic timeline.
    """
    def __init__(self, session_id: str, output_dir: str = "reports/"):
        self.session_id = session_id
        self.event_count = 0
        path = Path(output_dir) / f"{self.session_id}_timeline.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(path, "w", encoding="utf-8")
        
    def name(self) -> str:
        return "SessionTimelineRecorder"
        
    def initialize(self, bus: EventBus) -> None:
        bus.subscribe_all(self._on_any_event)
        
    async def _on_any_event(self, event: Event) -> None:
        record = {
            "timestamp": event.timestamp,
            "priority": event.priority,
            "category": event.category.value,
            "type": event.type,
            "source": event.source,
            "payload": event.payload
        }
        try:
            self.file.write(json.dumps(record) + "\n")
            self.file.flush()
            self.event_count += 1
        except ValueError:
            pass # File closed
        
    def export(self, output_dir: str = "reports/"):
        self.file.close()
        print(f"[TimelineRecorder] Streamed forensic timeline with {self.event_count} events finalized.")
