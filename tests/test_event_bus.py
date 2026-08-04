import asyncio
import pytest
from event_bus import EventBus, Event, EventCategory


def _evt(n: int) -> Event:
    return Event(priority=10, category=EventCategory.SYSTEM, type="t",
                 payload={"n": n}, source="test")


@pytest.mark.asyncio
async def test_subscriber_exceptions_are_recorded_not_swallowed():
    bus = EventBus()
    bus.start()

    async def boom(event):
        raise ValueError("subscriber failed")

    bus.subscribe(EventCategory.SYSTEM, boom)
    await bus.publish(_evt(1))
    await bus.drain()
    await bus.stop()

    assert len(bus.errors) == 1
    name, exc = bus.errors[0]
    assert isinstance(exc, ValueError)
    assert "boom" in name


@pytest.mark.asyncio
async def test_events_dispatch_in_priority_then_publish_order():
    bus = EventBus()
    bus.start()
    seen = []

    async def record(event):
        seen.append(event.payload["n"])

    bus.subscribe(EventCategory.SYSTEM, record)
    for n in range(10):
        await bus.publish(_evt(n))
    await bus.drain()
    await bus.stop()

    assert seen == list(range(10))


@pytest.mark.asyncio
async def test_publish_never_blocks_when_queue_is_full():
    # A subscriber that publishes must not deadlock the bus.
    bus = EventBus(maxsize=4)
    for n in range(20):
        await bus.publish(_evt(n))
    assert bus.dropped == 16
