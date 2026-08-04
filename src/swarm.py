"""
Swarm manager — N concurrent hunting workers over the URL queue.

Each worker owns a session id, a persona, a profile directory, and its own
bait set; nothing is shared but the queue and the verdict store. Scaling is
convergent rather than imperative: the dashboard sets a target count and the
manager starts or drains workers until live == target.

Workers parked on an intervention do not count toward the live target, so a
bot waiting on a human never starves the swarm of capacity.
"""
import asyncio
import datetime
import random
import traceback

from event_bus import EventBus, EventCategory
from ownership_manager import OwnershipManager, OwnerState
from persona import load_persona, PERSONA_LIBRARY
from threat_scorer import ThreatScorer
from page_classifier import PageClassifier
from compromise_detector import CompromiseDetector
from decision_policy import DecisionPolicyEngine
from decoy_controller import DecoyController
from browser_controller import BrowserSession
from session_timeline import SessionTimelineRecorder
from interventions import detect_block
from link_crawler import LinkCrawler
from nav_replay import build_journey
from canary_vault import default_seed_tokens
import substrate as substrate_mod


class WorkerState:
    __slots__ = ("worker_id", "session_id", "url", "status", "score",
                 "verdict", "started", "persona")

    def __init__(self, worker_id):
        self.worker_id = worker_id
        self.session_id = None
        self.url = None
        self.status = "idle"
        self.score = 0
        self.verdict = None
        self.started = None
        self.persona = None

    def as_dict(self):
        return {"worker_id": self.worker_id, "session_id": self.session_id,
                "url": self.url, "status": self.status, "score": self.score,
                "verdict": self.verdict, "persona": self.persona,
                "started": self.started}


class SwarmManager:
    def __init__(self, queue, verdict_db, vault, interventions,
                 headless: bool = True, target: int = 0,
                 crawl_depth: int = 2, substrate=None):
        self.queue = queue
        self.db = verdict_db
        self.vault = vault
        self.interventions = interventions
        self.headless = headless
        self.crawl_depth = crawl_depth
        # Decides where a session may execute, and refuses targets this
        # machine has no boundary for. Never None: a missing substrate would
        # silently mean "no gate".
        self.substrate = substrate or substrate_mod.load()

        # Self-seed the vault so swarm sessions plant *tracked* bait. Without
        # this the seeder still writes synthetic credentials, but nothing is
        # stamped with a session id — so a callback later could not be traced
        # back to the visit that planted it, which is the whole point.
        # Idempotent: a vault the operator has already filled is left alone.
        minted = default_seed_tokens(self.vault)
        if minted:
            print(f"[swarm] minted {len(minted)} self-hosted bait tokens "
                  f"(vault was empty)")

        self._target = target
        self._workers: dict = {}
        self._tasks: dict = {}
        self._next_id = 1
        self._stop = False
        self.completed = 0

    # ── control plane ──────────────────────────────────────────────────────

    @property
    def target(self) -> int:
        return self._target

    def set_target(self, n: int) -> int:
        self._target = max(0, int(n))
        return self._target

    def live(self) -> int:
        return sum(1 for w in self._workers.values()
                   if w.status not in ("idle", "done"))

    def status(self) -> dict:
        states = [w.as_dict() for w in self._workers.values()]
        counts = {}
        for s in states:
            counts[s["status"]] = counts.get(s["status"], 0) + 1
        return {
            "target": self._target,
            "live": self.live(),
            "parked": counts.get("parked", 0),
            "completed": self.completed,
            "queued": len(self.queue),
            "by_status": counts,
            "workers": states,
        }

    def kill(self) -> None:
        """Stop everything. Existing sessions tear down at their next check."""
        self._stop = True
        self._target = 0
        for task in self._tasks.values():
            task.cancel()

    # ── convergence loop ───────────────────────────────────────────────────

    async def run(self, poll: float = 1.0, exit_when_drained: bool = False) -> None:
        """Converge live workers toward the target.

        exit_when_drained suits a batch CLI run: finish the queue and return.
        The dashboard leaves it False, because at startup the manager sits at
        target=0 with an empty queue — the exact condition that would look
        like "drained" — and must stay alive waiting for the operator.
        """
        while not self._stop:
            for wid, task in list(self._tasks.items()):
                if task.done():
                    self._tasks.pop(wid, None)

            # Parked workers are waiting on a human, not consuming capacity.
            active = sum(1 for w in self._workers.values()
                         if w.status not in ("idle", "done", "parked"))

            if active < self._target and len(self.queue) > 0:
                wid = self._next_id
                self._next_id += 1
                state = WorkerState(wid)
                self._workers[wid] = state
                self._tasks[wid] = asyncio.create_task(self._worker(state))

            if (exit_when_drained and not self._tasks
                    and len(self.queue) == 0):
                break
            await asyncio.sleep(poll)

        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)

    # ── one hunting session ────────────────────────────────────────────────

    async def _worker(self, state: WorkerState) -> None:
        entry = await self.queue.next()
        if entry is None:
            state.status = "done"
            return

        state.url = entry.url
        state.status = "starting"

        # Gate before anything is launched. An unisolated profile pointed at a
        # live malicious URL is the failure this refuses to allow.
        try:
            self.substrate.assert_target_allowed(entry.url)
        except substrate_mod.UnsafeTargetError as e:
            state.status = "refused"
            state.verdict = "refused"
            self.completed += 1
            print(f"[worker {state.worker_id}] REFUSED {entry.url}\n    {e}")
            return

        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        state.session_id = f"w{state.worker_id}_{stamp}_{random.randrange(16**4):04x}"
        state.persona = random.choice(list(PERSONA_LIBRARY))
        state.started = stamp

        bus = EventBus()
        bus.start()
        browser = None
        timeline = SessionTimelineRecorder(state.session_id)
        timeline.initialize(bus)

        scorer = ThreatScorer()
        scorer.initialize(bus)
        PageClassifier().initialize(bus)
        compromise = CompromiseDetector()
        compromise.initialize(bus)
        policy = DecisionPolicyEngine(bus)

        db = type(self.db)(session_id=state.session_id)
        db.initialize(bus)

        # Mirror progress onto the worker row so the dashboard shows what is
        # happening now, not a summary once the session is already over.
        async def _live(event):
            if event.type == "threat_score_updated":
                state.score = event.payload.get("score", state.score)
            elif event.type == "compromise_action":
                state.status = "compromised"

        async def _live_state(event):
            if (event.type == "state_transition"
                    and event.payload.get("new_state") == "DECOY"):
                state.status = "decoy"

        bus.subscribe(EventCategory.PAYLOAD, _live)
        bus.subscribe(EventCategory.SYSTEM, _live_state)

        ownership = OwnershipManager()
        try:
            persona = load_persona(state.persona)
            browser = BrowserSession(bus=bus, persona=persona,
                                     session_id=state.session_id,
                                     ownership_mgr=ownership,
                                     headless=self.headless,
                                     vault=self.vault)
            decoy = DecoyController(bus, ownership_mgr=ownership, browser=browser)

            await browser.start()
            state.status = "hunting"

            # Never arrive cold. A visit with no referrer, no cookies, and no
            # prior history is itself a bot signal — walking a plausible
            # journey first is cheaper than defeating a block afterwards.
            # Only under an isolated substrate: the hops are real sites, and
            # the local profile is loopback-only by design.
            if self.substrate.allows_live_targets:
                journey = build_journey(entry.url, state.persona,
                                        custom_chain=entry.referrer_chain or None)
                previous = None
                for hop in journey.hops:
                    if await browser.visit(hop, referrer=previous):
                        previous = hop
                    await asyncio.sleep(random.uniform(0.8, 2.5))
                ok = await browser.visit(entry.url, referrer=previous)
            else:
                ok = await browser.visit(entry.url)
            await bus.drain()

            if ok:
                blocked, reason = await self._check_blocked(browser)
                if blocked:
                    state.status = "parked"
                    shot = await self._park_screenshot(browser)
                    outcome = await self.interventions.raise_for(
                        state.session_id, entry.url, reason, screenshot=shot)
                    state.status = "hunting" if outcome == "resolved" else "skipping"
                    if outcome == "resolved":
                        await browser.scan_page_source()
                        await bus.drain()

                if state.status == "hunting":
                    crawler = LinkCrawler(browser, bus, max_depth=self.crawl_depth)
                    await crawler.explore()
                    await bus.drain()

                if ownership.current_owner == OwnerState.DECOY:
                    state.status = "decoy"
                    try:  # noqa: SIM105
                        await asyncio.wait_for(decoy.finished.wait(), timeout=180)
                    except asyncio.TimeoutError:
                        pass

            state.score = scorer.score
        except asyncio.CancelledError:
            state.status = "cancelled"
            raise
        except Exception:
            state.status = "error"
            traceback.print_exc()
        finally:
            if browser is not None:
                try:
                    await browser.stop()
                except Exception:
                    pass
            try:
                state.verdict = db.record_verdict(
                    url=entry.url, score=scorer.score, clusters=scorer.clusters,
                    findings=[f["label"] for f in scorer.summary()["findings"]],
                    decision=policy.current_state)
            except Exception:
                state.verdict = "unknown"
            db.close()
            timeline.export()
            await bus.stop()
            if state.status not in ("cancelled", "error"):
                state.status = "done"
            self.completed += 1
            print(f"[worker {state.worker_id}] {entry.url} -> "
                  f"{state.verdict} (score {state.score})")

    async def _check_blocked(self, browser) -> tuple:
        try:
            content = await browser._page.content()
        except Exception:
            content = ""
        return detect_block(browser.last_response_status,
                            await browser.current_url(), content)

    async def _park_screenshot(self, browser):
        try:
            await browser.screenshot("blocked")
            shots = sorted(browser._shot_dir.glob("*_blocked.png"))
            return str(shots[-1]) if shots else None
        except Exception:
            return None
