import asyncio
import sys
from pathlib import Path
import argparse

sys.path.insert(0, str(Path(__file__).parent))

from event_bus import EventBus, Event, EventCategory
from browser_persona import BrowserPersonaManager
from user_context import UserContextModel
from threat_scorer import ThreatScorer
from page_classifier import PageClassifier
from behavioral_detector import BehavioralChallengeDetector
from compromise_detector import CompromiseDetector
from verdict_db import VerdictDB
from canary_vault import CanaryVault, default_seed_tokens
import substrate
from decision_policy import DecisionPolicyEngine
from ownership_manager import OwnershipManager
from interaction_scheduler import InteractionScheduler
from decoy_controller import DecoyController
from reliability_layer import ReliabilityLayer
from session_timeline import SessionTimelineRecorder
from browser_controller import BrowserSession

async def run_v2_session(target_url: str, headless: bool = True):
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    session_id = f"v2_live_session_{timestamp}"
    print(f"\n[+] Starting Live v2 Session for: {target_url} (Headless: {headless})")

    runtime = substrate.load()
    for line in substrate.preflight(runtime):
        print(f"    {line}")
    try:
        runtime.assert_target_allowed(target_url)
    except substrate.UnsafeTargetError as e:
        print(f"\n[!] REFUSED: {e}")
        return
    
    # 1. Initialize Event-Driven Backbone
    session_bus = EventBus()
    session_bus.start()
    
    # 2. Initialize Context & Persona
    persona_mgr = BrowserPersonaManager()
    persona = persona_mgr.static_persona
    if not persona:
        persona = {
            "persona_id": "default",
            "employee_name": "Test User",
            "department": "IT",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "screen": {"width": 1920, "height": 1080},
            "locale": "en-US",
            "timezone_id": "America/New_York",
            "cpu_count": 8,
            "device_memory_gb": 16,
            "webgl_vendor": "Google Inc. (Intel)",
            "webgl_renderer": "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0)",
            "fonts": ["Arial", "Calibri", "Segoe UI", "Tahoma"]
        }
        
    user_context = UserContextModel()
    
    # 3. Initialize Analytics Plugins & Timeline Recorder
    timeline_recorder = SessionTimelineRecorder(session_id)
    timeline_recorder.initialize(session_bus)
    
    threat_scorer = ThreatScorer()
    threat_scorer.initialize(session_bus)
    
    page_classifier = PageClassifier()
    page_classifier.initialize(session_bus)
    
    behavioral_detector = BehavioralChallengeDetector()
    behavioral_detector.initialize(session_bus)

    compromise_detector = CompromiseDetector()
    compromise_detector.initialize(session_bus)

    verdict_db = VerdictDB(session_id=session_id)
    verdict_db.initialize(session_bus)

    vault = CanaryVault(verdict_db)
    minted = default_seed_tokens(vault)
    if minted:
        print(f"[+] Canaries  : minted {len(minted)} self-hosted bait tokens "
              f"(vault was empty)")
    
    # 4. Initialize Control & Interaction Engines
    decision_policy = DecisionPolicyEngine(session_bus)
    ownership_mgr = OwnershipManager()
    interaction_scheduler = InteractionScheduler(session_bus, ownership_mgr, user_context)
    
    # 5. Initialize Playwright Browser
    browser = BrowserSession(bus=session_bus, persona=persona, session_id=session_id, ownership_mgr=ownership_mgr, headless=headless, vault=vault)

    # 6. Initialize Subsystems — needs the browser it will drive into the decoy
    decoy_controller = DecoyController(session_bus,
                                       ownership_mgr=ownership_mgr,
                                       browser=browser)

    print("[+] Components wired. Launching Playwright browser...")
    await browser.start()
    
    print(f"[+] Navigating to {target_url}...")
    success = await browser.visit(target_url)
    
    if success:
        print("[+] Navigation successful. Handing control to Adaptive Weave Engine...")
        
        # Start the scheduler tick loop which will weave until the browser closes or hits DECOY
        try:
            # Weave indefinitely until page closes
            while not browser._page.is_closed():
                await interaction_scheduler.tick(browser._page)
                if ownership_mgr.current_owner.name == "DECOY":
                    print("[!] DECOY state detected. Waiting for the decoy walk "
                          "to finish before teardown...")
                    # engage() runs from a bus subscriber, concurrently with
                    # this loop. Tearing the browser down now would kill the
                    # walk mid-step and lose the honeytoken evidence.
                    try:
                        await asyncio.wait_for(
                            decoy_controller.finished.wait(), timeout=180)
                        print("[+] Decoy walk complete.")
                    except asyncio.TimeoutError:
                        print("[!] Decoy walk timed out after 180s.")
                    break
        except (Exception, KeyboardInterrupt, asyncio.CancelledError) as e:
            print(f"\n[!] Session interrupted by user (or error): {type(e).__name__}")
            
        finally:
            print("\n[+] Tearing down session...")
            try:
                await browser.stop()
            except Exception:
                pass # Ignore Playwright connection drop on forced interrupt

            verdict = verdict_db.record_verdict(
                url=target_url,
                score=threat_scorer.score,
                clusters=threat_scorer.clusters,
                findings=[f["label"] for f in threat_scorer.summary()["findings"]],
                decision=decision_policy.current_state,
            )
            actions = compromise_detector.summary()
            print(f"[+] Verdict   : {verdict.upper()} (score {threat_scorer.score})")
            print(f"[+] Clusters  : {threat_scorer.clusters or 'none'}")
            print(f"[+] Compromise: {actions['count']} action(s) {actions['kinds']}")
            verdict_db.close()

            timeline_recorder.export()
            await session_bus.stop()
            print("[+] Live session complete.")

    else:
        print("[-] Navigation failed.")
        await browser.stop()
        verdict_db.record_verdict(target_url, threat_scorer.score,
                                  threat_scorer.clusters, [], "navigation_failed")
        verdict_db.close()
        timeline_recorder.export()
        await session_bus.stop()

if __name__ == "__main__":
    # The Windows console defaults to cp1252, which cannot encode the box
    # drawing and arrow characters used in status output. Without this, the
    # first state transition kills the run with UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

    parser = argparse.ArgumentParser(description="Run the v2 Adaptive Weave Engine")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--headed", action="store_true", help="Run with visible browser window")
    args = parser.parse_args()
    
    asyncio.run(ReliabilityLayer.safe_execute(run_v2_session(args.url, headless=not args.headed)))
