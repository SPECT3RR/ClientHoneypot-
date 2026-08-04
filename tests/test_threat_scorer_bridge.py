import pytest
from event_bus import EventBus, Event, EventCategory
from threat_scorer import ThreatScorer

MOCK_PAGE = """<html><body>
<script>
console.log(eval("'hello'"));
console.log(String.fromCharCode(104,105));
document.write(unescape('%68%69'));
</script></body></html>"""


class Collector:
    def __init__(self):
        self.events = []

    async def __call__(self, event):
        self.events.append(event)

    def types(self):
        return [e.type for e in self.events]


async def _run(events):
    bus = EventBus()
    bus.start()
    collector = Collector()
    bus.subscribe(EventCategory.PAYLOAD, collector)
    scorer = ThreatScorer()
    scorer.initialize(bus)
    for e in events:
        await bus.publish(e)
    await bus.drain()
    await bus.stop()
    return scorer, collector


def _dom(html, url="http://127.0.0.1:8080"):
    return Event(priority=10, category=EventCategory.DOM, type="script_evaluation",
                 payload={"script": html, "url": url}, source="test")


@pytest.mark.asyncio
async def test_malicious_page_crosses_threshold_and_fires_payload_detected():
    scorer, collector = await _run([_dom(MOCK_PAGE)])

    assert scorer.score >= 60, f"score was {scorer.score}"
    assert "threat_score_updated" in collector.types()
    assert "payload_detected" in collector.types()

    detected = [e for e in collector.events if e.type == "payload_detected"][0]
    assert detected.payload["confidence"] == "CRITICAL"
    assert "classic_exploit_kit" in detected.payload["clusters"]


@pytest.mark.asyncio
async def test_benign_page_does_not_fire():
    benign = "<html><body><h1>Quarterly report</h1><p>Revenue up.</p></body></html>"
    scorer, collector = await _run([_dom(benign)])

    assert scorer.score == 0
    assert "payload_detected" not in collector.types()


@pytest.mark.asyncio
async def test_payload_detected_fires_only_once():
    scorer, collector = await _run([_dom(MOCK_PAGE), _dom(MOCK_PAGE), _dom(MOCK_PAGE)])
    fired = [e for e in collector.events if e.type == "payload_detected"]
    assert len(fired) == 1


@pytest.mark.asyncio
async def test_suspicious_download_is_scored():
    dl = Event(priority=10, category=EventCategory.NETWORK, type="download",
               payload={"filename": "setup_invoice_viewer.exe",
                        "url": "http://127.0.0.1:8080/setup_invoice_viewer.exe"},
               source="test")
    scorer, collector = await _run([dl])
    assert scorer.score >= 35
    assert "threat_score_updated" in collector.types()
