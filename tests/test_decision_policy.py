import pytest
from event_bus import EventBus, Event, EventCategory
from decision_policy import DecisionPolicyEngine
from page_classifier import PageClassifier


class Collector:
    def __init__(self):
        self.events = []

    async def __call__(self, event):
        self.events.append(event)


def test_score_bands_come_from_yaml():
    engine = DecisionPolicyEngine(bus=None)
    assert engine._state_for_score(0) == "BOT_ACTIVE"
    assert engine._state_for_score(29) == "BOT_ACTIVE"
    assert engine._state_for_score(30) == "SHARED_CONTROL"
    assert engine._state_for_score(60) == "HUMAN_ACTIVE"
    assert engine._state_for_score(90) == "DECOY"


def test_scores_above_the_top_band_stay_in_the_top_band():
    # The mock page scores 79; a real exploit kit reaches 164. The YAML's
    # highest band declares max_score 100 — anything above must not fall through.
    engine = DecisionPolicyEngine(bus=None)
    assert engine._state_for_score(164) == "DECOY"
    assert engine._state_for_score(10000) == "DECOY"


@pytest.mark.asyncio
async def test_critical_payload_forces_decoy_regardless_of_score():
    bus = EventBus()
    bus.start()
    collector = Collector()
    bus.subscribe(EventCategory.SYSTEM, collector)
    DecisionPolicyEngine(bus)

    await bus.publish(Event(priority=1, category=EventCategory.PAYLOAD,
                            type="payload_detected",
                            payload={"confidence": "CRITICAL", "score": 61},
                            source="test"))
    await bus.drain()
    await bus.stop()

    transitions = [e for e in collector.events if e.type == "state_transition"]
    assert transitions, "no state_transition published"
    assert transitions[-1].payload["new_state"] == "DECOY"


def test_page_classifier_requires_a_real_password_input():
    clf = PageClassifier()
    footer_link = '<html><body><a href="/login">Login</a><p>News</p></body></html>'
    real_form = ('<html><body><form action="/auth">'
                 '<input type="text" name="user">'
                 '<input type="password" name="pass"></form></body></html>')
    assert clf._classify(footer_link) != "PAGE_LOGIN"
    assert clf._classify(real_form) == "PAGE_LOGIN"
