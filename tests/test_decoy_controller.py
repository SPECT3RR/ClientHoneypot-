import pytest
from event_bus import EventBus, Event, EventCategory
from ownership_manager import OwnershipManager, OwnerState
from decoy_controller import DecoyController


class FakeBrowser:
    """Stands in for BrowserSession — records the walk without a real browser."""
    def __init__(self):
        self.visited = []
        self.shots = []
        self.persona = {"employee_name": "Layla Haddad"}
        self.session_id = "fake_session"
        self._page = None
        self.bus = None

    async def visit(self, url, referrer=None):
        self.visited.append(url)
        return True

    async def screenshot(self, label):
        self.shots.append(label)

    async def current_url(self):
        return self.visited[-1] if self.visited else ""


def test_ownership_manager_exposes_a_decoy_transition():
    mgr = OwnershipManager()
    before = mgr.generation
    mgr.set_decoy()
    assert mgr.current_owner == OwnerState.DECOY
    assert mgr.generation > before


@pytest.mark.asyncio
async def test_state_transition_to_decoy_engages_the_controller(monkeypatch):
    import decoy_controller as dc

    calls = {}

    async def fake_explore(browser, session_id, telemetry=None, num_pages=None):
        calls["ran"] = True
        return {"steps": ["login", "files"], "honeytokens_accessed": ["aws_keys.txt"]}

    monkeypatch.setattr(dc, "explore_decoy", fake_explore)
    monkeypatch.setattr(dc, "check_decoy_reachable", lambda *a, **k: True)

    bus = EventBus()
    bus.start()
    mgr = OwnershipManager()
    browser = FakeBrowser()
    DecoyController(bus, ownership_mgr=mgr, browser=browser)

    await bus.publish(Event(priority=1, category=EventCategory.SYSTEM,
                            type="state_transition",
                            payload={"new_state": "DECOY", "reason": "test"},
                            source="test"))
    await bus.drain()
    await bus.stop()

    assert calls.get("ran"), "explore_decoy was never called"
    assert mgr.current_owner == OwnerState.DECOY


@pytest.mark.asyncio
async def test_unreachable_decoy_reports_failure_without_raising(monkeypatch):
    import decoy_controller as dc
    monkeypatch.setattr(dc, "check_decoy_reachable", lambda *a, **k: False)

    bus = EventBus()
    bus.start()
    ctrl = DecoyController(bus, ownership_mgr=OwnershipManager(), browser=FakeBrowser())
    engaged = await ctrl.engage()
    await bus.stop()

    assert engaged is False


@pytest.mark.asyncio
async def test_controller_engages_only_once(monkeypatch):
    import decoy_controller as dc
    calls = []

    async def fake_explore(browser, session_id, telemetry=None, num_pages=None):
        calls.append(1)
        return {"steps": [], "honeytokens_accessed": []}

    monkeypatch.setattr(dc, "explore_decoy", fake_explore)
    monkeypatch.setattr(dc, "check_decoy_reachable", lambda *a, **k: True)

    bus = EventBus()
    bus.start()
    ctrl = DecoyController(bus, ownership_mgr=OwnershipManager(), browser=FakeBrowser())
    await ctrl.engage()
    await ctrl.engage()
    await bus.stop()

    assert len(calls) == 1
