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
from decision_policy import DecisionPolicyEngine
from weave_controller import AdaptiveWeaveController
from interaction_scheduler import InteractionScheduler
from decoy_controller import DecoyController
from reliability_layer import ReliabilityLayer
from session_timeline import SessionTimelineRecorder
from browser_controller import BrowserSession

async def run_v2_session(target_url: str, headless: bool = True):
    session_id = "v2_live_session"
    print(f"\n[+] Starting Live v2 Session for: {target_url} (Headless: {headless})")
    
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
    
    # 4. Initialize Control & Interaction Engines
    decision_policy = DecisionPolicyEngine(session_bus)
    weave_controller = AdaptiveWeaveController(session_bus)
    interaction_scheduler = InteractionScheduler(session_bus, weave_controller, user_context)
    
    # 5. Initialize Subsystems
    decoy_controller = DecoyController(session_bus)
    
    # 6. Initialize Playwright Browser
    browser = BrowserSession(bus=session_bus, persona=persona, session_id=session_id, headless=headless)
    
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
                if weave_controller.active_state == "DECOY":
                    print("[!] DECOY State detected! Breaking weave loop.")
                    break
        except (Exception, KeyboardInterrupt, asyncio.CancelledError) as e:
            print(f"\n[!] Session interrupted by user (or error): {type(e).__name__}")
            
        finally:
            print("\n[+] Tearing down session...")
            try:
                await browser.stop()
            except Exception:
                pass # Ignore Playwright connection drop on forced interrupt
                
            timeline_recorder.export()
            await session_bus.stop()
            print("[+] Live session complete.")
            
    else:
        print("[-] Navigation failed.")
        await browser.stop()
        timeline_recorder.export()
        await session_bus.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the v2 Adaptive Weave Engine")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--headed", action="store_true", help="Run with visible browser window")
    args = parser.parse_args()
    
    asyncio.run(ReliabilityLayer.safe_execute(run_v2_session(args.url, headless=not args.headed)))
