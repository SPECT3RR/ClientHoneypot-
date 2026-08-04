import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "decoy_app"))

from operator_classifier import VisitorProfile, OperatorRegistry, OPERATOR_THRESHOLD
import gate


# ── entry gate ─────────────────────────────────────────────────────────────

def test_gate_accepts_a_correctly_computed_token():
    assert gate.verify(gate.expected_answer())


def test_gate_rejects_junk_and_empty():
    assert not gate.verify("")
    assert not gate.verify(None)
    assert not gate.verify("deadbeefdeadbeef")


def test_gate_accepts_the_previous_window():
    # A slow human must not be locked out mid-login by the hour rolling over.
    prev = int(time.time() // gate.WINDOW_SECONDS) - 1
    assert gate.verify(gate.expected_answer(prev))


def test_gate_rejects_a_stale_token():
    old = int(time.time() // gate.WINDOW_SECONDS) - 5
    assert not gate.verify(gate.expected_answer(old))


def test_challenge_uses_subtlecrypto_not_a_captcha():
    js = gate.challenge_script()
    # SubtleCrypto exists in every real browser and in no HTTP client.
    assert "crypto.subtle.digest" in js
    # A CAPTCHA would deter the human we want and advertise instrumentation.
    assert "captcha" not in js.lower()


# ── classifier ─────────────────────────────────────────────────────────────

def test_plain_scanner_is_classified_bot():
    v = VisitorProfile("v1", user_agent="python-requests/2.31")
    for p in ("/robots.txt", "/.env", "/wp-admin", "/portal/files"):
        v.note_path(p)
    assert v.classification == "bot"
    assert v.score == 0


def test_scanner_never_reaches_any_gated_tier():
    v = VisitorProfile("v2", user_agent="curl/8.4")
    assert v.may_reach_tier(0) is True    # the door is open by design
    assert v.may_reach_tier(1) is False
    assert v.may_reach_tier(2) is False


def test_human_operator_clears_tier_two():
    v = VisitorProfile("v3", user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/126")
    v.note_js_solved()
    time.sleep(0.01)
    v.first_seen -= 5  # simulate 5s of dwell before touching anything
    v.note_interaction("mousemove", trusted=True, mouse_entropy=0.6)
    v.note_interaction("keydown", trusted=True,
                       key_intervals=[110, 240, 90, 300, 150, 205])
    v.note_path("/portal/files")
    v.note_path("/portal/hr")
    v.note_path("/portal/files")

    assert v.score >= OPERATOR_THRESHOLD, v.summary()
    assert v.classification == "human_operator"
    assert v.may_reach_tier(2) is True


def test_synthetic_events_prove_nothing():
    v = VisitorProfile("v4", user_agent="Mozilla/5.0 Chrome/126")
    v.note_js_solved()
    v.note_interaction("mousemove", trusted=False, mouse_entropy=0.9)
    assert "trusted_input" not in v.signals
    assert v.may_reach_tier(2) is False


def test_cdp_automation_does_not_pass_as_human():
    """isTrusted is true for Playwright/Puppeteer/Selenium: they dispatch
    through the browser's real input pipeline. The flag only filters
    dispatchEvent fakes, so it cannot carry the classification on its own.
    What gives a driver away is the SHAPE of the input -- interpolated mouse
    paths are straight lines."""
    v = VisitorProfile("cdp", user_agent="Mozilla/5.0 Chrome/126")
    v.note_js_solved()
    v.first_seen -= 5
    v.note_interaction("mousemove", trusted=True, mouse_entropy=0.0)
    v.note_path("/portal/hr")
    v.note_path("/portal/files")
    v.note_path("/portal/hr")

    assert "trusted_input" in v.signals
    assert "linear_mouse" in v.signals
    assert v.score < OPERATOR_THRESHOLD, v.summary()
    assert v.may_reach_tier(2) is False


def test_headless_and_automation_agents_are_penalised():
    v = VisitorProfile("v5", user_agent="Mozilla/5.0 HeadlessChrome/126")
    assert "scanner_agent" in v.signals


def test_constant_typing_cadence_reads_as_scripted():
    v = VisitorProfile("v6", user_agent="Mozilla/5.0 Chrome/126")
    v.note_js_solved()
    v.first_seen -= 5
    # A script pastes at a metronome rate; a human never does.
    v.note_interaction("keydown", trusted=True,
                       key_intervals=[100, 100, 100, 100, 100, 100])
    assert "typing_cadence" not in v.signals


def test_variable_typing_cadence_reads_as_human():
    v = VisitorProfile("v7", user_agent="Mozilla/5.0 Chrome/126")
    v.note_js_solved()
    v.first_seen -= 5
    v.note_interaction("keydown", trusted=True,
                       key_intervals=[90, 310, 140, 260, 70, 400])
    assert "typing_cadence" in v.signals


def test_rapid_wordlist_enumeration_is_penalised():
    v = VisitorProfile("v8", user_agent="Mozilla/5.0 Chrome/126")
    for p in ("/a", "/b", "/c", "/d", "/e"):
        v.note_path(p)
    assert "sequential_paths" in v.signals


def test_revisiting_pages_reads_as_human_browsing():
    v = VisitorProfile("v9", user_agent="Mozilla/5.0 Chrome/126")
    v.note_path("/portal/hr")
    v.note_path("/portal/finance")
    v.note_path("/portal/hr")
    assert "nonlinear_navigation" in v.signals


def test_registry_tracks_and_filters_humans():
    reg = OperatorRegistry()
    bot = reg.get("b1", user_agent="curl/8")
    bot.note_path("/.env")

    human = reg.get("h1", user_agent="Mozilla/5.0 Chrome/126")
    human.note_js_solved()
    human.first_seen -= 5
    human.note_interaction("mousemove", trusted=True, mouse_entropy=0.6)
    human.note_interaction("keydown", trusted=True,
                           key_intervals=[90, 310, 140, 260, 70, 400])

    assert len(reg.all()) == 2
    assert [h["visitor_id"] for h in reg.humans()] == ["h1"]
    # Same id returns the same accumulating profile, not a fresh one.
    assert reg.get("h1") is human
