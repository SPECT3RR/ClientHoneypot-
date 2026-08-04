import asyncio
import json
import pytest
from event_bus import EventBus, EventCategory
from browser_controller import BrowserSession
from ownership_manager import OwnershipManager
from instrumentation import INSTRUMENTATION_JS


class Collector:
    def __init__(self):
        self.events = []

    async def __call__(self, event):
        self.events.append(event)


def _session(bus):
    return BrowserSession(bus=bus, persona={"persona_id": "test"},
                          session_id="test_session",
                          ownership_mgr=OwnershipManager(), headless=True)


def test_instrumentation_js_is_non_empty_and_guarded():
    assert "__deceptionInstrumented" in INSTRUMENTATION_JS
    assert "__reportRuntimeEvent" in INSTRUMENTATION_JS


@pytest.mark.asyncio
async def test_runtime_event_is_republished_on_the_bus():
    bus = EventBus()
    bus.start()
    collector = Collector()
    bus.subscribe(EventCategory.DOM, collector)

    session = _session(bus)
    session._on_runtime_event(None, json.dumps({
        "type": "service_worker_registration",
        "detail": {"script": "https://evil.example/sw.js"},
        "url": "https://evil.example/",
        "ts": 1,
    }))
    # The binding schedules the publish rather than awaiting it, so the page
    # is never stalled by the bus. Yield once to let that task run.
    await asyncio.sleep(0)
    await bus.drain()
    await bus.stop()

    types = [e.type for e in collector.events]
    assert "service_worker_registration" in types
    event = [e for e in collector.events if e.type == "service_worker_registration"][0]
    assert event.payload["script"] == "https://evil.example/sw.js"
    assert event.payload["url"] == "https://evil.example/"


@pytest.mark.asyncio
async def test_malformed_runtime_payload_is_ignored():
    bus = EventBus()
    bus.start()
    session = _session(bus)
    session._on_runtime_event(None, "not json{{{")  # must not raise
    await asyncio.sleep(0)
    await bus.drain()
    await bus.stop()
    assert bus.errors == []
