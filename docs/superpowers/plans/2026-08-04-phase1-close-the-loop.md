# Phase 1: Close the Detection → Decoy Loop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the honeyclient actually detect a malicious page and divert into the decoy environment — the one thing the platform claims and currently cannot do.

**Architecture:** Everything needed already exists but is disconnected. `threat_detection.py` holds a complete 60-signal, 8-cluster correlation engine that nothing calls. `instrumentation.py` holds complete runtime DOM/JS hooks that nothing injects. `decoy_navigator.py` holds a complete decoy walk that nothing invokes. This phase wires those three into the v2 event-bus pipeline, repairs the four cut links between detection and diversion, and makes event dispatch trustworthy enough to be forensic evidence. Net new logic is small; most tasks are reconnection.

**Tech Stack:** Python 3.10+, Playwright 1.45, asyncio, FastAPI + Jinja2 (decoy), SQLite, pytest + pytest-asyncio.

## Global Constraints

- Python 3.10+ (`dict | dict` merge syntax and `str.removeprefix` are used).
- No new runtime dependencies beyond `playwright-stealth` and `pyyaml`, both already imported by existing code but undeclared. Test-only: `pytest`, `pytest-asyncio`.
- All work runs under the `local` runtime profile against `tests/mock_malicious_site.py`. **Do not point any task's test at a real URL.** Live hunting is gated on phase 7 (WSL2 containment).
- `src/` is a flat module directory added to `sys.path` by each entrypoint. Imports inside `src/` are bare (`from event_bus import ...`), not package-qualified. Follow that pattern.
- Never commit anything under `config/profiles/`. It is gitignored as of commit `b11699a`.
- The existing decoy trigger threshold is `DECOY_TRIGGER_THRESHOLD = 60` in `src/threat_detection.py:247`. Do not change it.

## Reference: why the loop is currently broken

Five cut links, all repaired in this plan:

1. `src/threat_scorer.py` scores redirects at +5 and never calls `threat_detection.py`. Max realistic score ≈ 15. **Task 3.**
2. Nothing publishes `payload_detected`, so `payload_confidence` is permanently `"LOW"` and the `DECOY` branch at `src/decision_policy.py:41` is unreachable. **Task 3.**
3. `DecisionPolicyEngine` publishes `state_transition`; its only subscriber `AdaptiveWeaveController` is never instantiated. **Task 5.**
4. `DecoyController.engage()` is never called, and would only print if it were. **Task 5.**
5. `OwnerState.DECOY` is never set, so the break condition at `src/v2_orchestrator.py:91` cannot fire. **Task 5.**

---

### Task 1: Test harness and domain-allowlist bug fix

Establishes the pytest harness every later task needs, and fixes a real matching bug in the allowlist while proving the harness works.

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/test_threat_detection.py`
- Modify: `src/threat_detection.py:51`
- Modify: `requirements.txt`

**Interfaces:**
- Consumes: nothing.
- Produces: pytest importable `src/` modules via `conftest.py` path injection. All later tasks rely on this.

- [ ] **Step 1: Add test dependencies**

Append to `requirements.txt`:

```
playwright-stealth==2.0.0
pyyaml==6.0.1
pytest==8.2.0
pytest-asyncio==0.23.7
```

`playwright-stealth` is imported by `src/browser_controller.py:10` and `pyyaml` by `src/browser_persona.py:1`; neither was declared, so a fresh clone fails on import.

- [ ] **Step 2: Create the pytest path shim**

Create `tests/conftest.py`:

```python
"""Makes the flat src/ module directory importable from tests."""
import sys
from pathlib import Path

SRC = Path(__file__).parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
```

- [ ] **Step 3: Write the failing test**

Create `tests/test_threat_detection.py`:

```python
import threat_detection as td


def test_allowlisted_domain_matches_exactly():
    assert td._domain_allowlisted("https://bloomberg.com/markets")
    assert td._domain_allowlisted("https://www.bloomberg.com/markets")
    assert td._domain_allowlisted("https://sub.bloomberg.com/x")


def test_typosquat_cannot_bypass_the_allowlist():
    # str.lstrip takes a CHARACTER SET, so lstrip("www.") strips any leading
    # run of 'w' and '.' characters. That makes "wwwbloomberg.com" — a real,
    # registrable typosquat with no dot — strip to "bloomberg.com" and match
    # the allowlist, so every script served from it is skipped by the scanner.
    # A $10 domain registration disables detection. This is the bug.
    assert not td._domain_allowlisted("https://wwwbloomberg.com/x")
    assert not td._domain_allowlisted("https://wwwreuters.com/x")


def test_mock_site_content_fires_classic_exploit_kit_cluster():
    # Exactly the script block served by tests/mock_malicious_site.py.
    page = """
    var s = "aGVsbG8=";
    console.log(eval("'hello'"));
    console.log(String.fromCharCode(104,105));
    document.write(unescape('%68%69'));
    """
    labels = td.scan_script_text(page, "http://127.0.0.1:8080")
    assert "obf_eval" in labels
    assert "obf_unescape" in labels
    assert "obf_charcode" in labels
    assert "ek_docwrite_unescape" in labels

    scorer = td.ThreatScorer()
    scorer.add(labels, "mock page")
    assert "classic_exploit_kit" in scorer.clusters
    assert scorer.should_trigger_decoy(), f"score {scorer.score} below threshold 60"
```

- [ ] **Step 4: Run the tests and verify the typosquat test fails**

Run: `python -m pytest tests/test_threat_detection.py -v`

Expected: `test_typosquat_cannot_bypass_the_allowlist` FAILS on the first assertion — `"wwwbloomberg.com".lstrip("www.")` returns `"bloomberg.com"`, which matches the allowlist, so `_domain_allowlisted` wrongly returns `True`. The other two tests PASS.

- [ ] **Step 5: Fix the allowlist matcher**

In `src/threat_detection.py`, replace line 51:

```python
        host = urlparse(url).netloc.lower().lstrip("www.")
```

with:

```python
        host = urlparse(url).netloc.lower().removeprefix("www.")
```

- [ ] **Step 6: Run the tests and verify all pass**

Run: `python -m pytest tests/test_threat_detection.py -v`
Expected: 3 passed.

- [ ] **Step 7: Commit**

```bash
git add requirements.txt tests/conftest.py tests/test_threat_detection.py src/threat_detection.py
git commit -m "fix: correct domain allowlist prefix matching, add pytest harness"
```

---

### Task 2: Make event dispatch trustworthy

`src/event_bus.py:87` dispatches with `asyncio.create_task(callback(event))` and never awaits the task. Every exception raised inside an async subscriber is swallowed silently, and event ordering is not guaranteed. For a component whose output is forensic evidence, that is a correctness bug, not a style preference.

**Files:**
- Modify: `src/event_bus.py`
- Create: `tests/test_event_bus.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `EventBus.errors` — a `list[tuple[str, BaseException]]` of `(callback_name, exception)` for every subscriber that raised. `EventBus.dropped` — an `int` count of events rejected because the queue was full. `EventBus.drain()` — an `async` method that returns once the queue is empty, used by tests to await dispatch deterministically.

- [ ] **Step 1: Write the failing test**

Create `tests/test_event_bus.py`:

```python
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
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `python -m pytest tests/test_event_bus.py -v`
Expected: FAIL — `AttributeError: 'EventBus' object has no attribute 'errors'`.

- [ ] **Step 3: Rewrite the bus internals**

In `src/event_bus.py`, replace the `EventBus.__init__`, `publish`, and `_worker_loop` methods, and add `drain`:

```python
    def __init__(self, maxsize: int = 10000):
        self._subscribers: Dict[EventCategory, Set[Callable[[Event], Any]]] = {
            cat: set() for cat in EventCategory
        }
        self._all_subscribers: Set[Callable[[Event], Any]] = set()
        self._queue = asyncio.PriorityQueue(maxsize=maxsize)
        self._worker_task = None
        self.errors: List[tuple] = []
        self.dropped: int = 0

    async def publish(self, event: Event):
        """Enqueue an event. Never blocks: subscribers publish from inside
        dispatch, so a blocking put would deadlock the worker against itself.
        A full queue drops the event and increments `dropped`.
        """
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1

    async def drain(self):
        """Return once every queued event has been dispatched."""
        await self._queue.join()

    async def _worker_loop(self):
        while True:
            try:
                event = await self._queue.get()
                try:
                    await self._dispatch(event)
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[EventBus] Worker error: {e}")
                traceback.print_exc()

    async def _dispatch(self, event: Event):
        """Await every subscriber so failures surface instead of vanishing.

        ponytail: serial dispatch — one slow subscriber stalls the timeline.
        Move to per-subscriber queues if a subscriber ever does real I/O.
        """
        callbacks = list(self._subscribers.get(event.category, set())) + \
                    list(self._all_subscribers)
        if not callbacks:
            return

        loop = asyncio.get_running_loop()
        awaitables = []
        for cb in callbacks:
            if asyncio.iscoroutinefunction(cb):
                awaitables.append(cb(event))
            else:
                awaitables.append(loop.run_in_executor(None, cb, event))

        results = await asyncio.gather(*awaitables, return_exceptions=True)
        for cb, result in zip(callbacks, results):
            if isinstance(result, BaseException):
                name = getattr(cb, "__qualname__", repr(cb))
                self.errors.append((name, result))
                print(f"[EventBus] subscriber {name} failed: {result!r}")
```

Add `List` to the `typing` import on line 6 if not already present.

- [ ] **Step 4: Run the test and verify it passes**

Run: `python -m pytest tests/test_event_bus.py -v`
Expected: 3 passed.

- [ ] **Step 5: Run the full suite to confirm no regression**

Run: `python -m pytest tests/ -v`
Expected: 6 passed.

- [ ] **Step 6: Commit**

```bash
git add src/event_bus.py tests/test_event_bus.py
git commit -m "fix: await event dispatch so subscriber failures surface"
```

---

### Task 3: Connect the bus to the real detection engine

This is the task that turns 317 lines of dormant detection logic on.

**Files:**
- Rewrite: `src/threat_scorer.py`
- Create: `tests/test_threat_scorer_bridge.py`

**Interfaces:**
- Consumes: `EventBus`, `Event`, `EventCategory` from Task 2. `threat_detection` module functions `scan_dom(html, url)`, `scan_script_text(text, url)`, `scan_download(filename)`, `scan_redirect_chain(int)`, `scan_url(url)`, and class `ThreatScorer` with `.add(labels, detail)`, `.score`, `.clusters`, `.summary()`, `.should_trigger_decoy()`.
- Produces: class `ThreatScorer` with `name() -> str`, `initialize(bus) -> None`, and property `score -> int`. Publishes two event types on `EventCategory.PAYLOAD`:
  - `threat_score_updated`, payload `{"score": int, "clusters": list[str], "findings": list[str]}`
  - `payload_detected`, payload `{"confidence": "CRITICAL", "score": int, "clusters": list[str], "summary": dict}` — published **once** per session.

- [ ] **Step 1: Write the failing test**

Create `tests/test_threat_scorer_bridge.py`:

```python
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
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `python -m pytest tests/test_threat_scorer_bridge.py -v`
Expected: FAIL — the current `ThreatScorer` has no `score` attribute before `initialize`, and never publishes `payload_detected`.

- [ ] **Step 3: Rewrite the bridge**

Replace the entire contents of `src/threat_scorer.py`:

```python
"""
Bridge between the event bus and the correlated detection engine.

The engine itself lives in threat_detection.py — 60+ raw signals grouped into
8 attack clusters, where only co-occurring signals produce a real score. This
module's only job is to route bus events into the right scan function and
republish the result as higher-order analytics events.

Publishes on EventCategory.PAYLOAD:
  threat_score_updated  — every time the score changes
  payload_detected      — once, when the score first crosses the decoy threshold
"""
from plugins.analytics_interface import AnalyticsPlugin
from event_bus import EventBus, Event, EventCategory
import threat_detection as td


class ThreatScorer(AnalyticsPlugin):
    def __init__(self):
        self._engine = td.ThreatScorer()
        self._redirect_chain = 0
        self._detected = False
        self.bus = None

    def name(self) -> str:
        return "ThreatScorer"

    @property
    def score(self) -> int:
        return self._engine.score

    @property
    def clusters(self) -> list:
        return list(self._engine.clusters)

    def summary(self) -> dict:
        return self._engine.summary()

    def initialize(self, bus: EventBus) -> None:
        self.bus = bus
        bus.subscribe(EventCategory.NETWORK, self._on_network)
        bus.subscribe(EventCategory.DOM, self._on_dom)
        bus.subscribe(EventCategory.NAVIGATION, self._on_navigation)

    # ── routing ────────────────────────────────────────────────────────────

    async def _on_navigation(self, event: Event) -> None:
        if event.type == "visit_start":
            self._redirect_chain = 0
            url = event.payload.get("url", "")
            await self._record(td.scan_url(url), url)

    async def _on_network(self, event: Event) -> None:
        if event.type == "redirect":
            self._redirect_chain += 1
            await self._record(td.scan_redirect_chain(self._redirect_chain),
                               event.payload.get("url", ""))
        elif event.type == "download":
            filename = event.payload.get("filename", "")
            await self._record(td.scan_download(filename), filename)

    async def _on_dom(self, event: Event) -> None:
        url = event.payload.get("url", "")
        if event.type == "dom_snapshot":
            await self._record(td.scan_dom(event.payload.get("html", ""), url), url)
        elif event.type == "script_evaluation":
            await self._record(
                td.scan_script_text(event.payload.get("script", ""), url), url)

    # ── scoring ────────────────────────────────────────────────────────────

    async def _record(self, labels: list, detail: str) -> None:
        if not labels:
            return

        before = self._engine.score
        self._engine.add(labels, detail)
        if self._engine.score == before:
            return  # all labels were duplicates

        await self.bus.publish(Event(
            priority=10,
            category=EventCategory.PAYLOAD,
            type="threat_score_updated",
            payload={
                "score": self._engine.score,
                "clusters": list(self._engine.clusters),
                "findings": [f["label"] for f in self._engine.findings],
            },
            source=self.name(),
        ))

        if self._engine.should_trigger_decoy() and not self._detected:
            self._detected = True
            await self.bus.publish(Event(
                priority=1,  # jumps the queue — this drives a state transition
                category=EventCategory.PAYLOAD,
                type="payload_detected",
                payload={
                    "confidence": "CRITICAL",
                    "score": self._engine.score,
                    "clusters": list(self._engine.clusters),
                    "summary": self._engine.summary(),
                },
                source=self.name(),
            ))
```

- [ ] **Step 4: Run the test and verify it passes**

Run: `python -m pytest tests/test_threat_scorer_bridge.py -v`
Expected: 4 passed.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest tests/ -v`
Expected: 10 passed.

- [ ] **Step 6: Commit**

```bash
git add src/threat_scorer.py tests/test_threat_scorer_bridge.py
git commit -m "feat: route bus events into the correlated detection engine"
```

---

### Task 4: Drive state transitions from configuration

`src/decision_policy.py:48` hardcodes `threat_score > 50` while `config/decision_policy.yaml` defines four risk bands that nothing reads. The YAML's top band caps at `max_score: 100`, but real scores exceed that — the mock page alone reaches 79 — so naive band matching would fall through and return the wrong state.

The page classifier is fixed in the same task because its bug directly corrupts this state machine: `src/page_classifier.py:24` matches the bare string `"login"` in any HTML, which is true of most pages on the internet, forcing `HUMAN_ACTIVE` constantly.

**Files:**
- Modify: `src/decision_policy.py`
- Modify: `src/page_classifier.py:20-29`
- Create: `tests/test_decision_policy.py`

**Interfaces:**
- Consumes: `threat_score_updated` and `payload_detected` events from Task 3.
- Produces: `DecisionPolicyEngine(bus, config_path=None)`. Publishes `state_transition` on `EventCategory.SYSTEM` with payload `{"new_state": str, "reason": str}` where `new_state` is one of `BOT_ACTIVE | SHARED_CONTROL | HUMAN_ACTIVE | DECOY`. Exposes `_state_for_score(score: int) -> str` for direct testing.

- [ ] **Step 1: Write the failing test**

Create `tests/test_decision_policy.py`:

```python
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
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `python -m pytest tests/test_decision_policy.py -v`
Expected: FAIL — `DecisionPolicyEngine` has no `_state_for_score`, and `PageClassifier` has no `_classify`.

- [ ] **Step 3: Rewrite the decision policy engine**

Replace the entire contents of `src/decision_policy.py`:

```python
"""
Decision Policy Engine — maps analytics into ownership-state transitions.

Risk bands are loaded from config/decision_policy.yaml so thresholds can be
tuned without a code change. A CRITICAL payload detection overrides the bands
entirely: a confirmed exploit-kit cluster diverts to the decoy immediately,
whatever the numeric score says.
"""
from pathlib import Path

import yaml

from event_bus import EventBus, Event, EventCategory

DEFAULT_CONFIG = Path(__file__).parent.parent / "config" / "decision_policy.yaml"


class DecisionPolicyEngine:
    def __init__(self, bus: EventBus, config_path: Path = None):
        self.bus = bus
        self.current_state = "BOT_ACTIVE"
        self.context = {
            "threat_score": 0,
            "page_classification": "PAGE_UNKNOWN",
            "payload_confidence": "LOW",
        }
        self.bands = self._load_bands(config_path or DEFAULT_CONFIG)

        if bus is not None:
            bus.subscribe(EventCategory.PAYLOAD, self._on_analytics_event)
            bus.subscribe(EventCategory.BEHAVIORAL, self._on_analytics_event)

    @staticmethod
    def _load_bands(path: Path) -> list:
        """Return risk bands sorted ascending by min_score."""
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        bands = list((config.get("thresholds") or {}).values())
        if not bands:
            raise ValueError(f"no thresholds defined in {path}")
        return sorted(bands, key=lambda b: b["min_score"])

    def _state_for_score(self, score: int) -> str:
        """Highest band whose min_score the value reaches.

        Deliberately ignores each band's max_score: real scores routinely
        exceed the YAML's top bound (the mock page alone reaches 79, a full
        exploit kit 164) and must stay in the top band rather than falling
        through to the default.
        """
        state = self.bands[0]["state"]
        for band in self.bands:
            if score >= band["min_score"]:
                state = band["state"]
        return state

    async def _on_analytics_event(self, event: Event) -> None:
        dirty = False
        if event.type == "threat_score_updated":
            self.context["threat_score"] = event.payload.get("score", 0)
            dirty = True
        elif event.type == "page_classified":
            self.context["page_classification"] = event.payload.get(
                "classification", "PAGE_UNKNOWN")
            dirty = True
        elif event.type == "payload_detected":
            self.context["payload_confidence"] = event.payload.get(
                "confidence", "LOW")
            dirty = True

        if dirty:
            await self._evaluate()

    async def _evaluate(self) -> None:
        if self.context["payload_confidence"] == "CRITICAL":
            new_state, reason = "DECOY", "critical payload detected"
        elif self.context["payload_confidence"] == "HIGH":
            new_state, reason = "HUMAN_ACTIVE", "high-confidence payload"
        else:
            score = self.context["threat_score"]
            new_state = self._state_for_score(score)
            reason = f"threat score {score}"
            if (new_state == "BOT_ACTIVE"
                    and self.context["page_classification"] == "PAGE_LOGIN"):
                new_state, reason = "HUMAN_ACTIVE", "credential boundary"

        if new_state == self.current_state:
            return

        self.current_state = new_state
        await self.bus.publish(Event(
            priority=1,
            category=EventCategory.SYSTEM,
            type="state_transition",
            payload={"new_state": new_state, "reason": reason},
            source="DecisionPolicyEngine",
        ))
```

- [ ] **Step 4: Tighten the page classifier**

In `src/page_classifier.py`, replace lines 20-29 (the body of `_on_dom_event` from `html = ...` through the `PAGE_ARTICLE` branch) with a call to a new testable method, and add that method to the class:

```python
    LOGIN_RE = re.compile(
        r'<form[^>]*>.*?<input[^>]+type\s*=\s*["\']password["\']',
        re.IGNORECASE | re.DOTALL)

    def _classify(self, html: str) -> str:
        """Classify a page from its HTML.

        A password input inside a form — not the bare word "login", which
        appears in the footer of most sites on the internet and previously
        classified nearly every page as a credential boundary.
        """
        if self.LOGIN_RE.search(html):
            return "PAGE_LOGIN"
        lowered = html.lower()
        if "add to cart" in lowered or "checkout" in lowered:
            return "PAGE_CHECKOUT"
        if "<article" in lowered:
            return "PAGE_ARTICLE"
        return "PAGE_UNKNOWN"

    async def _on_dom_event(self, event: Event) -> None:
        if event.type != "dom_snapshot":
            return
        classification = self._classify(event.payload.get("html", ""))
        await self.bus.publish(Event(
            priority=10,
            category=EventCategory.BEHAVIORAL,
            type="page_classified",
            payload={"classification": classification,
                     "url": event.payload.get("url", "")},
            source=self.name(),
        ))
```

Add `import re` at the top of the file.

- [ ] **Step 5: Run the test and verify it passes**

Run: `python -m pytest tests/test_decision_policy.py -v`
Expected: 4 passed.

- [ ] **Step 6: Run the full suite**

Run: `python -m pytest tests/ -v`
Expected: 14 passed.

- [ ] **Step 7: Commit**

```bash
git add src/decision_policy.py src/page_classifier.py tests/test_decision_policy.py
git commit -m "feat: load risk bands from yaml, require real password field for login class"
```

---

### Task 5: Make the decoy diversion actually happen

Three cut links repaired at once, because none of them is independently testable: the state transition must reach the `DecoyController`, the controller must set `OwnerState.DECOY`, and it must navigate the browser through the decoy. `src/decoy_navigator.py` already contains a complete randomised walk — login, form fill, 2-4 portal pages, file server, honeytoken — that nothing has ever called.

**Files:**
- Modify: `src/ownership_manager.py`
- Rewrite: `src/decoy_controller.py`
- Modify: `src/decoy_navigator.py:26-27,163`
- Modify: `src/v2_orchestrator.py:72`
- Create: `tests/test_decoy_controller.py`

**Interfaces:**
- Consumes: `state_transition` events from Task 4. `decoy_navigator.explore_decoy(browser, session_id, telemetry=None, num_pages=None)` and `decoy_navigator.check_decoy_reachable(host, port) -> bool`.
- Produces: `OwnershipManager.set_decoy() -> None` which sets state to `OwnerState.DECOY` and bumps `generation`. `DecoyController(bus, ownership_mgr=None, browser=None)` with `async engage(browser=None) -> bool`, returning `True` when the walk ran and `False` when the decoy was unreachable.

- [ ] **Step 1: Write the failing test**

Create `tests/test_decoy_controller.py`:

```python
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
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `python -m pytest tests/test_decoy_controller.py -v`
Expected: FAIL — `OwnershipManager` has no `set_decoy`, and `DecoyController.__init__` takes only `bus`.

- [ ] **Step 3: Add the DECOY transition to the ownership manager**

In `src/ownership_manager.py`, add this method to `OwnershipManager` after `notify_human_idle`:

```python
    def set_decoy(self):
        """Enter DECOY: the session has been diverted into the synthetic
        environment. Bumps generation so any in-flight bot routine on the
        real page is invalidated before the walk starts.
        """
        self.generation += 1
        self._set_state(OwnerState.DECOY)
```

- [ ] **Step 4: Make the decoy navigator work without a v1 telemetry object**

`explore_decoy` currently requires a v1 `Telemetry` instance, which the v2 pipeline does not have. Make it optional.

In `src/decoy_navigator.py`, change the signature on line 26-27:

```python
async def explore_decoy(browser, session_id: str, telemetry=None,
                        num_pages: int = None) -> dict:
```

and replace line 163:

```python
    telemetry.log("decoy_exploration_complete", summary)
```

with:

```python
    if telemetry is not None:
        telemetry.log("decoy_exploration_complete", summary)
```

- [ ] **Step 5: Rewrite the decoy controller**

Replace the entire contents of `src/decoy_controller.py`:

```python
"""
Decoy Controller — drives the browser into the synthetic enterprise
environment once the decision policy calls for it.

Subscribes to state_transition. On DECOY it takes ownership, then hands the
browser to decoy_navigator.explore_decoy, which performs a randomised walk
(login, form fill, 2-4 portal pages, file server, honeytoken) so successive
sessions do not look scripted.
"""
from event_bus import EventBus, Event, EventCategory
from decoy_navigator import explore_decoy, check_decoy_reachable


class DecoyController:
    def __init__(self, bus: EventBus, ownership_mgr=None, browser=None):
        self.bus = bus
        self.ownership = ownership_mgr
        self.browser = browser
        self.engaged = False
        bus.subscribe(EventCategory.SYSTEM, self._on_system_event)

    async def _on_system_event(self, event: Event) -> None:
        if event.type == "state_transition" and \
                event.payload.get("new_state") == "DECOY":
            await self.engage()

    async def engage(self, browser=None) -> bool:
        if self.engaged:
            return False
        browser = browser or self.browser
        if browser is None:
            return False

        if not check_decoy_reachable():
            print("[DecoyController] decoy unreachable on 127.0.0.1:8001 — "
                  "start it with: python decoy_app/app.py")
            await self.bus.publish(Event(
                priority=5, category=EventCategory.SYSTEM,
                type="decoy_engage_failed",
                payload={"reason": "decoy app not reachable on 127.0.0.1:8001"},
                source="DecoyController"))
            return False

        self.engaged = True
        if self.ownership is not None:
            self.ownership.set_decoy()

        session_id = getattr(browser, "session_id", "unknown_session")
        print("[DecoyController] engaging decoy environment...")
        summary = await explore_decoy(browser, session_id)

        await self.bus.publish(Event(
            priority=5, category=EventCategory.SYSTEM,
            type="decoy_engaged",
            payload={"status": "success", **summary},
            source="DecoyController"))
        return True
```

- [ ] **Step 6: Wire the controller in the orchestrator**

In `src/v2_orchestrator.py`, the browser is constructed on line 75, after the controller on line 72. Move the `DecoyController` construction to after the `BrowserSession` line and pass the dependencies. Replace line 72:

```python
    decoy_controller = DecoyController(session_bus)
```

with nothing, and insert immediately after the `browser = BrowserSession(...)` line:

```python
    decoy_controller = DecoyController(session_bus,
                                       ownership_mgr=ownership_mgr,
                                       browser=browser)
```

- [ ] **Step 7: Run the test and verify it passes**

Run: `python -m pytest tests/test_decoy_controller.py -v`
Expected: 4 passed.

- [ ] **Step 8: Run the full suite**

Run: `python -m pytest tests/ -v`
Expected: 18 passed.

- [ ] **Step 9: Commit**

```bash
git add src/ownership_manager.py src/decoy_controller.py src/decoy_navigator.py src/v2_orchestrator.py tests/test_decoy_controller.py
git commit -m "feat: divert the browser into the decoy on critical detection"
```

---

### Task 6: Inject the runtime instrumentation

`src/instrumentation.py` is 173 lines of complete, working page hooks that nothing injects. It surfaces dynamic script and iframe injection, popup spam, storage exfiltration, clipboard access, permission prompts, service-worker persistence, and credential form submits — none of which the Playwright-level hooks can see.

**Files:**
- Modify: `src/browser_controller.py`
- Create: `tests/test_instrumentation_bridge.py`

**Interfaces:**
- Consumes: `INSTRUMENTATION_JS` from `src/instrumentation.py`.
- Produces: `BrowserSession._on_runtime_event(source, payload_json) -> None`, the binding target. Publishes on `EventCategory.DOM` with `type` taken from the JS report (`dynamic_script_injection`, `popup_spam`, `storage_exfil_write`, `service_worker_registration`, `form_submit_credentials`, and the others defined in `instrumentation.py`), payload merging the JS `detail` object with `{"url": ...}`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_instrumentation_bridge.py`:

```python
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
    await bus.drain()
    await bus.stop()
    assert bus.errors == []
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `python -m pytest tests/test_instrumentation_bridge.py -v`
Expected: FAIL — `BrowserSession` has no `_on_runtime_event`.

- [ ] **Step 3: Add the binding target**

In `src/browser_controller.py`, add `import json` at the top, add the import `from instrumentation import INSTRUMENTATION_JS` next to the existing `from persona import fingerprint_init_script`, and add this method to `BrowserSession` immediately before `_wire_monitoring`:

```python
    def _on_runtime_event(self, source, payload_json: str) -> None:
        """Binding target for instrumentation.js. Runs on the event loop
        thread; publishing is scheduled rather than awaited so a slow bus
        never stalls the page.
        """
        try:
            data = json.loads(payload_json)
        except (ValueError, TypeError):
            return

        detail = data.get("detail") or {}
        if not isinstance(detail, dict):
            detail = {"value": detail}

        asyncio.create_task(self.bus.publish(Event(
            priority=10,
            category=EventCategory.DOM,
            type=data.get("type", "runtime_event"),
            payload={**detail, "url": data.get("url", "")},
            source="RuntimeInstrumentation",
        )))
```

- [ ] **Step 4: Inject the script at context start**

In `src/browser_controller.py`, immediately after the existing line 54
(`await self._context.add_init_script(fingerprint_init_script(self.persona))`), add:

```python
        await self._context.add_init_script(INSTRUMENTATION_JS)
```

and add the binding next to the two existing `expose_binding` calls around line 141:

```python
        await self._context.expose_binding("__reportRuntimeEvent", self._on_runtime_event)
```

- [ ] **Step 5: Run the test and verify it passes**

Run: `python -m pytest tests/test_instrumentation_bridge.py -v`
Expected: 3 passed.

- [ ] **Step 6: Run the full suite**

Run: `python -m pytest tests/ -v`
Expected: 21 passed.

- [ ] **Step 7: Commit**

```bash
git add src/browser_controller.py tests/test_instrumentation_bridge.py
git commit -m "feat: inject runtime DOM/JS instrumentation and bridge it to the bus"
```

---

### Task 7: Isolate browser profiles per session

`src/browser_controller.py:41` resolves the profile directory from `persona["persona_id"]`, which the v2 persona does not define — so every session shares `config/profiles/default`. Cookies, service workers, and CacheStorage fetched from malicious sites accumulate there and contaminate later sessions. `cleanup.wipe_temp_profile()` exists and is called by nothing.

**Files:**
- Modify: `src/browser_controller.py`
- Create: `tests/test_profile_isolation.py`

**Interfaces:**
- Consumes: `cleanup.wipe_temp_profile(Path) -> None`.
- Produces: `BrowserSession.profile_dir` — a `Path` attribute set in `__init__`, unique per `session_id`, wiped by `stop()`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_profile_isolation.py`:

```python
from pathlib import Path
from event_bus import EventBus
from browser_controller import BrowserSession
from ownership_manager import OwnershipManager


def _session(session_id):
    return BrowserSession(bus=EventBus(), persona={"persona_id": "shared"},
                          session_id=session_id,
                          ownership_mgr=OwnershipManager(), headless=True)


def test_each_session_gets_its_own_profile_directory():
    a = _session("session_aaa")
    b = _session("session_bbb")
    assert a.profile_dir != b.profile_dir
    assert "session_aaa" in str(a.profile_dir)
    assert "session_bbb" in str(b.profile_dir)


def test_profile_directory_is_not_the_shared_default():
    s = _session("session_ccc")
    assert s.profile_dir.name != "default"
    assert s.profile_dir.parent.name == "profiles"


def test_profile_directory_is_under_config_profiles():
    s = _session("session_ddd")
    expected_root = Path(__file__).parent.parent / "config" / "profiles"
    assert expected_root.resolve() in s.profile_dir.resolve().parents
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `python -m pytest tests/test_profile_isolation.py -v`
Expected: FAIL — `BrowserSession` has no `profile_dir` attribute.

- [ ] **Step 3: Set the profile directory per session**

In `src/browser_controller.py`, add the import `from cleanup import wipe_temp_profile` alongside the other `src/` imports, and add to `__init__` after `self._shot_dir` is set:

```python
        # One profile per session: cookies, service workers, and CacheStorage
        # fetched from a malicious site must never reach the next session.
        self.profile_dir = (Path(__file__).parent.parent / "config"
                            / "profiles" / session_id)
```

- [ ] **Step 4: Use it at launch and wipe it at teardown**

In `start()`, replace lines 41-42:

```python
        user_data_dir = Path(__file__).parent.parent / "config" / "profiles" / self.persona.get("persona_id", "default")
        user_data_dir.mkdir(parents=True, exist_ok=True)
```

with:

```python
        user_data_dir = self.profile_dir
        user_data_dir.mkdir(parents=True, exist_ok=True)
```

In `stop()`, add the wipe after the context and playwright are closed, before the `session_end` publish:

```python
            wipe_temp_profile(self.profile_dir)
```

- [ ] **Step 5: Run the test and verify it passes**

Run: `python -m pytest tests/test_profile_isolation.py -v`
Expected: 3 passed.

- [ ] **Step 6: Run the full suite**

Run: `python -m pytest tests/ -v`
Expected: 24 passed.

- [ ] **Step 7: Commit**

```bash
git add src/browser_controller.py tests/test_profile_isolation.py
git commit -m "fix: isolate and wipe browser profiles per session"
```

---

### Task 8: End-to-end loop verification

Proves the whole chain against a real browser: mock malicious page → detection → cluster fires → state transition → decoy walk → honeytoken read. This is the test that would have caught every one of the five cut links.

**Files:**
- Create: `tests/test_loop_e2e.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything from Tasks 1-7.
- Produces: nothing consumed by later code.

- [ ] **Step 1: Write the failing test**

Create `tests/test_loop_e2e.py`:

```python
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


def _wait_for_port(port, timeout=15):
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
    sys.path.insert(0, str(ROOT / "src"))
    from event_bus import EventBus, EventCategory
    from ownership_manager import OwnershipManager, OwnerState
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
    browser = BrowserSession(bus=bus, persona={"persona_id": "e2e"},
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
```

- [ ] **Step 2: Run the test and observe the result**

Run: `python -m pytest tests/test_loop_e2e.py -v -s`

Expected on a correct implementation: PASS. If it fails, the assertion that fails names the broken link — `payload_detected` missing means Task 3, `state_transition` missing means Task 4, `DECOY` state missing means Task 5.

- [ ] **Step 3: Verify the decoy actually logged a honeytoken read**

Run:

The decoy app logs through `src/telemetry.py`, whose schema is
`events(id, session_id, ts, event_type, data)`.

```bash
python -c "import sqlite3; c=sqlite3.connect('telemetry/session.db'); print(c.execute(\"select event_type, count(*) from events where session_id='e2e_test' group by event_type\").fetchall())"
```

Expected: rows including `honeytoken_access` and `decoy_page_view`.

- [ ] **Step 4: Correct the README status table**

`README.md` currently claims Automated Cleanup "wipes temp profile dir" and describes v1 `orchestrator.py` as the entrypoint. Both are wrong. In the component table, update these rows:

```markdown
| Threat Detection Layer          | ✅ implemented | Correlated multi-signal scoring: 60+ raw signals grouped into 8 attack clusters; a cluster must fire, not a single pattern |
| Decision Engine                 | ✅ implemented | Risk bands loaded from `config/decision_policy.yaml`; a CRITICAL payload detection overrides the bands |
| Browser Monitoring Engine       | ✅ implemented | Playwright hooks plus runtime DOM/JS instrumentation: dynamic script/iframe injection, popup spam, storage exfil, clipboard, service workers, credential form submits |
| Automated Cleanup               | ⚠️ partial | Per-session profile directory, wiped on session end; **does not** manage VMs/containers — see "Isolation" |
```

Replace the Quick start command block with the v2 entrypoint:

````markdown
```bash
pip install -r requirements.txt
playwright install chromium

# Terminal 1: start the decoy enterprise environment
python decoy_app/app.py

# Terminal 2: run a session
python src/v2_orchestrator.py http://127.0.0.1:8080 --headed
```
````

Add a line under Quick start:

```markdown
> `src/orchestrator.py` (v1) does not run — its `BrowserSession` call predates the
> v2 signature change. Use `src/v2_orchestrator.py`. v1 is removed in a later phase.
```

- [ ] **Step 5: Run the complete suite one final time**

Run: `python -m pytest tests/ -v`
Expected: 25 passed.

- [ ] **Step 6: Commit**

```bash
git add tests/test_loop_e2e.py README.md
git commit -m "test: end-to-end detection to decoy diversion, correct README status"
```

---

## Phase 1 exit criteria

- [ ] `python -m pytest tests/ -v` — 25 passed.
- [ ] A run of `python src/v2_orchestrator.py http://127.0.0.1:8080 --headed` visibly ends in the decoy portal.
- [ ] `telemetry/session.db` contains `honeytoken_access` rows for that session.
- [ ] `config/profiles/` contains no leftover directory after a clean session exit.
- [ ] `bus.errors` is empty across the e2e run.

## What Phase 1 deliberately does not do

Bait seeding, canary vault, verdict DB, compromise detector, operator classifier, decoy tiering, dashboard, swarm, ad/redirect crawling, WSL2 containment, and Wazuh export. Each gets its own plan. Phase 2 (verdict DB and compromise detector) is next.

The v1 `src/orchestrator.py` is left in place and broken. It is deleted in phase 5, once the dashboard replaces its CLI role. Deleting it now would remove the only working reference implementation of the decoy walk while phases 2-4 are still being written against it.
