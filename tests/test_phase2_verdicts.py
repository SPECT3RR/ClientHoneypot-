import pytest
from event_bus import EventBus, Event, EventCategory
from compromise_detector import CompromiseDetector
from verdict_db import VerdictDB, classify


# ── compromise detector ────────────────────────────────────────────────────

class Collector:
    def __init__(self):
        self.events = []

    async def __call__(self, event):
        self.events.append(event)

    def of(self, t):
        return [e for e in self.events if e.type == t]


async def _detect(events):
    bus = EventBus()
    bus.start()
    collector = Collector()
    bus.subscribe(EventCategory.PAYLOAD, collector)
    det = CompromiseDetector()
    det.initialize(bus)
    for e in events:
        await bus.publish(e)
    await bus.drain()
    await bus.stop()
    return det, collector


def _dom(t, payload):
    return Event(priority=10, category=EventCategory.DOM, type=t,
                 payload=payload, source="test")


@pytest.mark.asyncio
async def test_executable_download_is_critical_and_escalates():
    dl = Event(priority=10, category=EventCategory.NETWORK, type="download",
               payload={"filename": "invoice.exe", "url": "http://x/invoice.exe"},
               source="test")
    det, collector = await _detect([dl])

    assert det.summary()["kinds"] == ["file_download"]
    assert det.actions[0]["severity"] == "CRITICAL"
    # A dropped executable must not wait for a signature cluster to also fire.
    detected = collector.of("payload_detected")
    assert detected and detected[0].payload["confidence"] == "CRITICAL"


@pytest.mark.asyncio
async def test_harmless_download_does_not_escalate():
    dl = Event(priority=10, category=EventCategory.NETWORK, type="download",
               payload={"filename": "report.pdf", "url": "http://x/report.pdf"},
               source="test")
    det, collector = await _detect([dl])
    assert det.actions[0]["severity"] == "LOW"
    assert collector.of("payload_detected") == []


@pytest.mark.asyncio
async def test_service_worker_registration_is_persistence():
    det, collector = await _detect([
        _dom("service_worker_registration",
             {"script": "https://evil/sw.js", "url": "https://evil/"})])
    assert "persistence" in det.summary()["kinds"]
    assert collector.of("payload_detected")


@pytest.mark.asyncio
async def test_credential_form_submit_is_critical():
    det, _ = await _detect([
        _dom("form_submit_credentials",
             {"fields": ["user", "password"], "url": "https://evil/login"})])
    assert "credential_harvest" in det.summary()["kinds"]


@pytest.mark.asyncio
async def test_dropper_signals_become_command_execution():
    score = Event(priority=10, category=EventCategory.PAYLOAD,
                  type="threat_score_updated",
                  payload={"score": 30, "clusters": [],
                           "findings": ["obf_eval", "dropper_ps1"]},
                  source="test")
    det, _ = await _detect([score])
    assert "command_execution" in det.summary()["kinds"]


@pytest.mark.asyncio
async def test_repeated_injections_collapse_to_one_finding():
    events = [_dom("dynamic_script_injection", {"via": "mutation", "url": "http://x/"})
              for _ in range(40)]
    det, _ = await _detect(events)
    assert det.summary()["count"] == 1


@pytest.mark.asyncio
async def test_benign_traffic_produces_no_actions():
    req = Event(priority=10, category=EventCategory.NETWORK, type="request",
                payload={"url": "http://cdn.example/app.js", "method": "GET",
                         "resource_type": "script"}, source="test")
    det, collector = await _detect([req])
    assert det.summary()["count"] == 0
    assert collector.of("payload_detected") == []


# ── verdict db ─────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path):
    d = VerdictDB(db_path=tmp_path / "v.db", session_id="s1")
    yield d
    d.close()


def test_classify_bands():
    assert classify(0) == "clean"
    assert classify(29) == "clean"
    assert classify(30) == "suspicious"
    assert classify(60) == "malicious"
    assert classify(200) == "malicious"


def test_a_critical_action_outranks_a_low_score():
    # A page that dropped an executable is malicious even if nothing matched.
    assert classify(5, had_compromise=True, worst_action="CRITICAL") == "malicious"


def test_low_severity_actions_alone_are_not_malicious():
    """Live testing caught this: a runtime script injection and a third-party
    CDN call are how the entire modern web works. Treating any action as
    malicious made a site scoring ZERO come back malicious."""
    assert classify(0, had_compromise=True, worst_action="LOW") == "clean"


def test_a_high_action_raises_suspicion_not_a_conviction():
    assert classify(10, had_compromise=True, worst_action="HIGH") == "suspicious"


def test_lookup_returns_verdict_with_evidence(db):
    db.record_compromise("http://evil.test/x", "file_download", "CRITICAL",
                         {"filename": "a.exe"})
    db._had_compromise = True
    db.record_verdict("http://evil.test/x", 79, ["classic_exploit_kit"],
                      ["obf_eval", "ek_docwrite_unescape"], "divert_to_decoy")

    row = db.lookup("http://evil.test/x")
    assert row["verdict"] == "malicious"
    assert row["score"] == 79
    assert row["confidence"] == "high"
    # Evidence is mandatory: a bare boolean gives an RBI nothing to explain.
    assert "classic_exploit_kit" in row["clusters"]
    assert "obf_eval" in row["findings"]
    assert row["compromise_actions"][0]["kind"] == "file_download"


def test_unseen_url_returns_none(db):
    assert db.lookup("http://never.seen/") is None


def test_revisit_increments_and_keeps_the_worst_score(db):
    db.record_verdict("http://x.test/", 70, [], [], "divert_to_decoy")
    db.record_verdict("http://x.test/", 10, [], [], "continue")
    row = db.lookup("http://x.test/")
    assert row["visit_count"] == 2
    assert row["score"] == 70, "a later clean visit must not erase a malicious verdict"
    assert row["verdict"] == "malicious"


def test_stats_and_recent(db):
    db.record_verdict("http://a.test/", 70, [], [], "divert_to_decoy")
    db.record_verdict("http://b.test/", 5, [], [], "continue")
    stats = db.stats()
    assert stats["total"] == 2
    assert stats["malicious"] == 1
    assert len(db.recent(verdict="malicious")) == 1


@pytest.mark.asyncio
async def test_db_records_compromise_actions_off_the_bus(tmp_path):
    bus = EventBus()
    bus.start()
    db = VerdictDB(db_path=tmp_path / "v.db", session_id="s2")
    db.initialize(bus)
    CompromiseDetector().initialize(bus)

    await bus.publish(Event(priority=10, category=EventCategory.NETWORK,
                            type="download",
                            payload={"filename": "x.exe", "url": "http://e/x.exe"},
                            source="test"))
    await bus.drain()
    await bus.stop()

    db.record_verdict("http://e/", 0, [], [], "continue")
    # An executable download is CRITICAL, so it convicts on its own.
    assert db.lookup("http://e/")["verdict"] == "malicious"
    db.close()


# ── decoy must not pollute the target's intelligence ───────────────────────

def _transition(state):
    return Event(priority=1, category=EventCategory.SYSTEM,
                 type="state_transition", payload={"new_state": state},
                 source="test")


@pytest.mark.asyncio
async def test_decoy_activity_is_not_recorded_as_attacker_compromise():
    # Our own decoy walk submits a login form, firing form_submit_credentials.
    # Recording it would attribute our deception to the attacker.
    det, _ = await _detect([
        _transition("DECOY"),
        _dom("form_submit_credentials",
             {"fields": ["username", "password"],
              "url": "http://127.0.0.1:8001/portal/login"}),
    ])
    assert det.summary()["count"] == 0


@pytest.mark.asyncio
async def test_threat_scorer_stops_scoring_after_diversion():
    from threat_scorer import ThreatScorer as Bridge
    bus = EventBus()
    bus.start()
    scorer = Bridge()
    scorer.initialize(bus)

    await bus.publish(_transition("DECOY"))
    await bus.drain()
    # The decoy portal's own login page has a password field worth 5 points.
    await bus.publish(_dom("dom_snapshot",
                           {"html": '<form><input type="password"></form>',
                            "url": "http://127.0.0.1:8001/portal/login"}))
    await bus.drain()
    await bus.stop()

    assert scorer.score == 0, "decoy pages must not inflate the target's score"


def test_an_unreachable_page_is_not_clean():
    """A typo'd URL and a dead C2 both came back 'clean' — which says the
    page was examined and found safe. It was never examined at all."""
    assert classify(0, False, None, reachable=False) == "unreachable"
    assert classify(0, False, None, reachable=True) == "clean"


def test_navigation_failure_records_unreachable(db):
    db.record_verdict("http://127.0.0.1/8001", 0, [], [], "navigation_failed")
    assert db.lookup("http://127.0.0.1/8001")["verdict"] == "unreachable"
