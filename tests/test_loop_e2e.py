"""End-to-end: mock malicious page in, decoy honeytoken access out.

Requires Playwright Chromium: playwright install chromium
Runs entirely against 127.0.0.1. Never point this at a real URL.
"""
import asyncio
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
MOCK_URL = "http://127.0.0.1:8080"


def _wait_for_port(port, timeout=25):
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


@pytest.fixture(scope="module")
def servers():
    mock = subprocess.Popen([sys.executable, str(ROOT / "tests" / "mock_malicious_site.py")])
    decoy = subprocess.Popen([sys.executable, str(ROOT / "decoy_app" / "app.py")])
    try:
        assert _wait_for_port(8080), "mock malicious site did not start on 8080"
        assert _wait_for_port(8001), "decoy app did not start on 8001"
        yield
    finally:
        mock.terminate()
        decoy.terminate()
        mock.wait(timeout=10)
        decoy.wait(timeout=10)


@pytest.mark.asyncio
async def test_malicious_page_diverts_into_the_decoy(servers):
    from event_bus import EventBus
    from ownership_manager import OwnershipManager, OwnerState
    from persona import load_persona
    from threat_scorer import ThreatScorer
    from page_classifier import PageClassifier
    from decision_policy import DecisionPolicyEngine
    from decoy_controller import DecoyController
    from browser_controller import BrowserSession

    seen = []

    async def record(event):
        seen.append(event.type)

    bus = EventBus()
    bus.start()
    bus.subscribe_all(record)

    scorer = ThreatScorer()
    scorer.initialize(bus)
    PageClassifier().initialize(bus)
    DecisionPolicyEngine(bus)

    ownership = OwnershipManager()
    persona = load_persona("finance_qatar")
    browser = BrowserSession(bus=bus, persona=persona,
                             session_id="e2e_test", ownership_mgr=ownership,
                             headless=True)
    DecoyController(bus, ownership_mgr=ownership, browser=browser)

    await browser.start()
    try:
        assert await browser.visit(MOCK_URL), "navigation to mock site failed"
        # Let detection, the state transition, and the decoy walk complete.
        for _ in range(60):
            await bus.drain()
            if ownership.current_owner == OwnerState.DECOY:
                break
            await asyncio.sleep(0.5)
        await bus.drain()
        # The decoy walk runs after the transition; give it time to finish.
        for _ in range(60):
            if "decoy_engaged" in seen:
                break
            await asyncio.sleep(0.5)
            await bus.drain()
    finally:
        await browser.stop()
        await bus.stop()

    assert scorer.score >= 60, f"detection did not fire: score {scorer.score}"
    assert "classic_exploit_kit" in scorer.clusters
    assert "payload_detected" in seen
    assert "state_transition" in seen
    assert ownership.current_owner == OwnerState.DECOY
    assert "decoy_engaged" in seen
    assert bus.errors == [], f"subscriber failures: {bus.errors}"

    # The honeytoken read is the evidence the decoy exists to produce, and it
    # is worthless unless attributed to this session. The walk clicks links
    # rather than building URLs, so attribution rides on the session cookie.
    import sqlite3
    conn = sqlite3.connect(ROOT / "telemetry" / "session.db")
    hits = conn.execute(
        "SELECT data FROM events WHERE session_id = ? AND event_type = ?",
        ("e2e_test", "honeytoken_access")).fetchall()
    conn.close()
    assert hits, "decoy walk logged no honeytoken_access for this session"
