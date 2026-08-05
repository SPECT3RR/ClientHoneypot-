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
from discovery import Discovery, DiscoveryQueue, permissive_args
import capacity
import substrate as substrate_mod
import third_party
import threatintel
import intel_keys


class WorkerState:
    __slots__ = ("worker_id", "session_id", "url", "status", "score",
                 "verdict", "started", "persona", "kind", "depth",
                 "parent_worker", "trigger", "spawned")

    def __init__(self, worker_id, kind="anchor", depth=0,
                 parent_worker=None, trigger=None):
        self.worker_id = worker_id
        self.session_id = None
        self.url = None
        self.status = "idle"
        self.score = 0
        self.verdict = None
        self.started = None
        self.persona = None
        # anchor = a URL the operator supplied; child = something a bot found.
        self.kind = kind
        self.depth = depth
        self.parent_worker = parent_worker
        self.trigger = trigger
        self.spawned = 0

    def as_dict(self):
        return {"worker_id": self.worker_id, "session_id": self.session_id,
                "url": self.url, "status": self.status, "score": self.score,
                "verdict": self.verdict, "persona": self.persona,
                "started": self.started, "kind": self.kind,
                "depth": self.depth, "parent_worker": self.parent_worker,
                "trigger": self.trigger, "spawned": self.spawned}


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
        # Feeds are consulted automatically after every session, so a hunt
        # answers "what did this contact, and is any of it known bad?" without
        # the operator remembering to press anything.
        self.intel_keys = intel_keys.expand(intel_keys.load())
        self.auto_enrich = bool(self.intel_keys)
        self.enrich_budget = 8      # per session; free quotas are small

        # Self-seed the vault so swarm sessions plant *tracked* bait. Without
        # this the seeder still writes synthetic credentials, but nothing is
        # stamped with a session id — so a callback later could not be traced
        # back to the visit that planted it, which is the whole point.
        # Idempotent: a vault the operator has already filled is left alone.
        # Discoveries spawn their own bots rather than being chased inline.
        self.discoveries = DiscoveryQueue()

        minted = default_seed_tokens(self.vault)
        if minted:
            print(f"[swarm] minted {len(minted)} self-hosted bait tokens "
                  f"(vault was empty)")

        self._target = target
        self.requested_target = target
        self.capacity_reason = ""
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
        """Set the target, clamped to what this machine can actually run.

        Exceeding physical memory does not give you more throughput; it gives
        you paging, stalled Chromium instances, and sessions OOM-killed
        mid-hunt leaving half-written verdicts. The excess stays queued.
        """
        allowed, reason = capacity.clamp(n, headless=self.headless)
        self.requested_target = max(0, int(n))
        self._target = allowed
        self.capacity_reason = reason
        return self._target

    def set_headless(self, headless: bool) -> bool:
        """Headed or headless, chosen by the operator.

        This is not cosmetic. A human cannot take over a headless browser —
        there is no window to click in — so an intervention raised by a
        headless worker can be acknowledged but never actually solved. Run
        headed whenever you intend to work the intervention queue.

        Applies to workers started from now on; sessions already running keep
        the mode they launched with.
        """
        self.headless = bool(headless)
        return self.headless

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
            "requested_target": self.requested_target,
            "capacity_reason": self.capacity_reason,
            "capacity": capacity.report(self.headless),
            "headless": self.headless,
            "live": self.live(),
            "parked": counts.get("parked", 0),
            "completed": self.completed,
            "queued": len(self.queue),
            "by_status": counts,
            "workers": states,
            "discoveries": self.discoveries.stats(),
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

            if active < self._target:
                # Discoveries first: a redirect the swarm just uncovered is
                # hotter than the next URL on a static list, and the chain
                # goes cold if the tab that spawned it is long gone.
                found = self.discoveries.next()
                if found is not None:
                    wid = self._next_id
                    self._next_id += 1
                    state = WorkerState(wid, kind="child", depth=found.depth,
                                        parent_worker=found.parent_worker,
                                        trigger=found.trigger)
                    parent = self._workers.get(found.parent_worker)
                    if parent:
                        parent.spawned += 1
                    self._workers[wid] = state
                    self._tasks[wid] = asyncio.create_task(
                        self._worker(state, discovery=found))
                elif len(self.queue) > 0:
                    wid = self._next_id
                    self._next_id += 1
                    state = WorkerState(wid, kind="anchor", depth=0)
                    self._workers[wid] = state
                    self._tasks[wid] = asyncio.create_task(self._worker(state))

            if (exit_when_drained and not self._tasks
                    and len(self.queue) == 0 and len(self.discoveries) == 0):
                break
            await asyncio.sleep(poll)

        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)

    # ── one hunting session ────────────────────────────────────────────────

    async def _worker(self, state: WorkerState, discovery=None) -> None:
        if discovery is not None:
            entry = type("Entry", (), {"url": discovery.url,
                                       "referrer_chain": []})()
        else:
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

        # Under an isolated substrate the whole session runs inside a
        # throwaway container: the browser rendering attacker-controlled
        # content must not execute on this host. Results come back through
        # the shared verdict database, so the control plane never reaches in.
        if getattr(self.substrate, "isolated", False):
            await self._containerised_session(state, entry)
            return

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
                    def report(url, trigger, _s=state):
                        """Hand a redirect or popup to the swarm as its own bot.

                        The anchor bot stays on the operator's URL and keeps
                        working it; the destination gets a fresh bot with its
                        own persona, profile and bait, and its discoveries
                        spawn again. That is how three bots become fifteen.
                        """
                        self.discoveries.offer(Discovery(
                            url, parent_session=_s.session_id,
                            parent_worker=_s.worker_id,
                            depth=_s.depth + 1, trigger=trigger))

                    crawler = LinkCrawler(browser, bus,
                                          max_depth=self.crawl_depth,
                                          on_discovery=report,
                                          anchor=True)
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
            self._post_session(state, entry.url)
            self.completed += 1
            tag = (f"{state.kind}" if state.kind == "anchor"
                   else f"child d{state.depth} via {state.trigger} "
                        f"of #{state.parent_worker}")
            print(f"[worker {state.worker_id}] ({tag}) {entry.url} -> "
                  f"{state.verdict} (score {state.score})"
                  + (f" spawned {state.spawned}" if state.spawned else ""))

    def _post_session(self, state, url: str) -> None:
        """Harvest this session's third-party contacts and check the new ones.

        Runs for every completed hunt, not on a button. Bounded per session
        because the free quotas are small and a busy ad page can contact
        dozens of hosts.
        """
        try:
            third_party.harvest_session(self.db, state.session_id)
        except Exception:
            return
        if not self.auto_enrich:
            return
        try:
            enricher = threatintel.Enricher(self.db, self.intel_keys)
            contacts = third_party.contacts_for(self.db, url)
            for entry in contacts["unchecked"][:self.enrich_budget]:
                verdict = threatintel.consensus(enricher.lookup(entry["host"]))
                if verdict["verdict"] in ("malicious", "suspicious"):
                    print(f"    [intel] {entry['host']} -> "
                          f"{verdict['verdict'].upper()} per "
                          f"{', '.join(verdict['flagged_by'])}")
        except Exception:
            pass

    async def _containerised_session(self, state: WorkerState, entry) -> None:
        """Delegate one session to a disposable container in the WSL2 VM.

        Per-worker telemetry is coarser than the in-process path — the bus
        lives inside the container — so status comes from the process and the
        verdict is read back from the shared database afterwards. That is the
        honest trade for not rendering hostile content on this host.
        """
        state.status = "hunting (isolated)"
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(
                None, self.substrate.run_session, entry.url, state.session_id)
            state.status = "done" if result["ok"] else "error"
            if not result["ok"] and result["stderr"]:
                print(f"[worker {state.worker_id}] container error: "
                      f"{result['stderr'][:400]}")
        except Exception:
            state.status = "error"
            traceback.print_exc()
        finally:
            try:
                self.substrate.ingest_results(self.db)
            except Exception:
                pass
            self._post_session(state, entry.url)
            row = None
            try:
                row = self.db.lookup(entry.url)
            except Exception:
                pass
            if row:
                state.verdict = row["verdict"]
                state.score = row["score"]
            self.completed += 1
            print(f"[worker {state.worker_id}] {entry.url} -> "
                  f"{state.verdict} (score {state.score}) [containerised]")

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
