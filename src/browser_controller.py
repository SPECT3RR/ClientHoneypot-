"""
Modern Chromium Controller + Browser Monitoring Engine (v2)
Launches real Chromium via Playwright, drives interaction,
and acts as a pure Telemetry Collector, forwarding all observables to the Event Bus.
"""
import asyncio
import json
from pathlib import Path

from playwright.async_api import async_playwright
from playwright_stealth import Stealth

from persona import fingerprint_init_script
from instrumentation import INSTRUMENTATION_JS
from event_bus import EventBus, Event, EventCategory

SCREENSHOT_DIR = Path(__file__).parent.parent / "screenshots"

from ownership_manager import OwnershipManager

class BrowserSession:
    def __init__(self, bus: EventBus, persona: dict, session_id: str, ownership_mgr: OwnershipManager, headless: bool = True):
        self.bus = bus
        self.persona = persona
        self.session_id = session_id
        self.headless = headless
        self.ownership = ownership_mgr
        self.ownership._browser = self
        
        self.last_response_status = 200
        self._pw = None
        self._context = None
        self._page = None
        self._shot_dir = SCREENSHOT_DIR / session_id
        self._shot_dir.mkdir(parents=True, exist_ok=True)
        self._shot_index = 0

    # ── lifecycle ──────────────────────────────────────────────────────────────

    async def start(self):
        self._pw = await async_playwright().start()
        
        user_data_dir = Path(__file__).parent.parent / "config" / "profiles" / self.persona.get("persona_id", "default")
        user_data_dir.mkdir(parents=True, exist_ok=True)
        
        self._context = await self._pw.chromium.launch_persistent_context(
            user_data_dir=str(user_data_dir),
            headless=self.headless,
            args=["--disable-blink-features=AutomationControlled", "--test-type", "--disable-infobars", "--disable-popup-blocking"],
            ignore_default_args=["--enable-automation", "--no-sandbox"],
            user_agent=self.persona.get("user_agent", "Mozilla/5.0"),
            viewport=self.persona.get("screen", {"width": 1920, "height": 1080}),
            locale=self.persona.get("locale", "en-US"),
            timezone_id=self.persona.get("timezone_id", "America/New_York"),
        )
        await self._context.add_init_script(fingerprint_init_script(self.persona))
        await self._context.add_init_script(INSTRUMENTATION_JS)
        await self._context.add_init_script("""
            window.__weave = {
                owner: "BOT_ACTIVE"
            };
            
            function handleInput(e) {
                // If it's a Playwright-injected event during a bot action, ignore completely.
                if (!e.isTrusted) return; 
                
                // If it's trusted, it's a candidate for human activity.
                // We forward it to Python which will classify it against the Bot-Action Boundary.
                if (window.notify_human_activity) {
                    window.notify_human_activity(e.type);
                }
            }
            
            // Listen to all physical input events
            ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart'].forEach(t => 
                document.addEventListener(t, handleInput, {capture: true, passive: true})
            );
            
            let lastActivity = performance.now();
            let isIdle = false;
            
            // Override handleInput to also track local idle state
            function handleInputWrapper(e) {
                if (e.isTrusted) {
                    lastActivity = performance.now();
                    isIdle = false;
                    handleInput(e);
                }
            }
            ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart'].forEach(t => 
                document.removeEventListener(t, handleInput, {capture: true, passive: true})
            );
            ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart'].forEach(t => 
                document.addEventListener(t, handleInputWrapper, {capture: true, passive: true})
            );

            setInterval(() => {
                if (!isIdle && (performance.now() - lastActivity > 5000)) {
                    isIdle = true;
                    if (window.notify_human_idle) {
                        window.notify_human_idle();
                    }
                }
            }, 500);
            
            // Persistent Red Dot Injector (survives navigations)
            setInterval(() => {
                if (!window.__virtualCursor && document.body) {
                    const cursor = document.createElement('div');
                    cursor.style.width = '20px';
                    cursor.style.height = '20px';
                    cursor.style.background = 'rgba(255, 0, 0, 0.8)';
                    cursor.style.position = 'absolute';
                    cursor.style.pointerEvents = 'none';
                    cursor.style.zIndex = '2147483647';
                    cursor.style.borderRadius = '50%';
                    cursor.style.border = '2px solid white';
                    cursor.style.transition = 'top 0.05s linear, left 0.05s linear';
                    cursor.style.opacity = '0'; // Hide by default
                    document.body.appendChild(cursor);
                    window.__virtualCursor = cursor;
                    
                    document.addEventListener('mousemove', e => {
                        // Move the dot when bot is moving the mouse
                        if (!e.isTrusted) {
                            window.__virtualCursor.style.left = e.pageX + 'px';
                            window.__virtualCursor.style.top = e.pageY + 'px';
                        }
                    }, {capture: true});
                }
                
                // The visibility is STRICTLY tied to the Authoritative Ownership State!
                if (window.__virtualCursor) {
                    if (window.__weave.owner === "BOT_ACTIVE") {
                        window.__virtualCursor.style.opacity = '1';
                    } else {
                        window.__virtualCursor.style.opacity = '0';
                    }
                }
            }, 100);
        """)
        
        # Bind Python callbacks so JS can push interrupts directly to Python
        await self._context.expose_binding("notify_human_activity", lambda source, event_type: self.ownership.notify_human_activity(event_type))
        await self._context.expose_binding("notify_human_idle", lambda source: self.ownership.notify_human_idle())
        await self._context.expose_binding("__reportRuntimeEvent", self._on_runtime_event)

        
        if self._context.pages:
            self._page = self._context.pages[0]
        else:
            self._page = await self._context.new_page()
            
        stealth = Stealth()
        await stealth.apply_stealth_async(self._page)
        self._wire_monitoring(self._page)
        self._context.on("page", self._on_new_page)
        
        await self.bus.publish(Event(
            priority=10,
            category=EventCategory.SYSTEM,
            type="session_start",
            payload={"persona_id": self.persona.get("persona_id", "unknown")},
            source="BrowserController"
        ))

    async def broadcast_owner_state(self, state_name: str):
        """Pushes the authoritative ownership state to all active tabs to update the Red Dot."""
        if not self._context: return
        for p in self._context.pages:
            if not p.is_closed():
                try:
                    await p.evaluate(f"window.__weave = window.__weave || {{}}; window.__weave.owner = '{state_name}';")
                except Exception:
                    pass

    # ── monitoring hooks (Telemetry Collectors) ────────────────────────────────

    def _on_new_page(self, page):
        """Called whenever a new tab or pop-under opens."""
        asyncio.create_task(self.bus.publish(Event(
            priority=5,
            category=EventCategory.NAVIGATION,
            type="new_tab_opened",
            payload={"url": page.url},
            source="BrowserController"
        )))
        self._wire_monitoring(page)

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

    def _wire_monitoring(self, page):
        page.on("console",        self._on_console)
        page.on("request",        self._on_request)
        page.on("response",       self._on_response)
        page.on("download",       lambda dl: asyncio.create_task(self._on_download(dl)))
        page.on("dialog",         lambda d:  asyncio.create_task(self._on_dialog(d)))
        page.on("framenavigated", self._on_navigation)

    def _on_console(self, msg):
        asyncio.create_task(self.bus.publish(Event(
            priority=10,
            category=EventCategory.DOM,
            type="console_message",
            payload={"type": msg.type, "text": msg.text, "url": self._page.url if self._page else ""},
            source="TelemetryCollector"
        )))

    def _on_request(self, req):
        asyncio.create_task(self.bus.publish(Event(
            priority=10,
            category=EventCategory.NETWORK,
            type="request",
            payload={"url": req.url, "method": req.method, "resource_type": req.resource_type},
            source="TelemetryCollector"
        )))

    def _on_response(self, resp):
        status = resp.status
        if resp.request.resource_type == "document":
            self.last_response_status = status
            
        asyncio.create_task(self.bus.publish(Event(
            priority=10,
            category=EventCategory.NETWORK,
            type="response",
            payload={"url": resp.url, "status": status},
            source="TelemetryCollector"
        )))
        
        if status in (301, 302, 303, 307, 308):
            asyncio.create_task(self.bus.publish(Event(
                priority=10,
                category=EventCategory.NETWORK,
                type="redirect",
                payload={"url": resp.url, "status": status},
                source="TelemetryCollector"
            )))

    async def _on_download(self, download):
        await self.bus.publish(Event(
            priority=10,
            category=EventCategory.NETWORK,
            type="download",
            payload={"filename": download.suggested_filename, "url": download.url},
            source="TelemetryCollector"
        ))
        try:
            await download.cancel()
        except Exception:
            pass

    async def _on_dialog(self, dialog):
        await self.bus.publish(Event(
            priority=10,
            category=EventCategory.BROWSER,
            type="dialog",
            payload={"type": dialog.type, "message": dialog.message},
            source="TelemetryCollector"
        ))
        await dialog.dismiss()

    def _on_navigation(self, frame):
        if frame.parent_frame is None:
            asyncio.create_task(self.bus.publish(Event(
                priority=10,
                category=EventCategory.NAVIGATION,
                type="framenavigated",
                payload={"url": frame.url},
                source="TelemetryCollector"
            )))

    # ── page-source scan ───────────────────────────────────────────────────────

    async def scan_page_source(self):
        """Take a DOM snapshot and publish it for the PageClassifier."""
        try:
            content  = await self._page.content()
            page_url = self._page.url
            
            await self.bus.publish(Event(
                priority=10,
                category=EventCategory.DOM,
                type="dom_snapshot",
                payload={"html": content, "url": page_url},
                source="TelemetryCollector"
            ))
            
            # Publish script evaluation equivalent for behavioral detector
            await self.bus.publish(Event(
                priority=10,
                category=EventCategory.DOM,
                type="script_evaluation",
                payload={"script": content, "url": page_url},
                source="TelemetryCollector"
            ))
        except Exception:
            pass

    # ── navigation & interaction ───────────────────────────────────────────────

    async def visit(self, url: str, referrer: str = None) -> bool:
        """Navigate to url. Returns True on success, False on timeout/error."""
        await self.bus.publish(Event(
            priority=10,
            category=EventCategory.NAVIGATION,
            type="visit_start",
            payload={"url": url, "referrer": referrer},
            source="BrowserController"
        ))
        
        try:
            await self._page.goto(url, referer=referrer or "",
                                  timeout=25000, wait_until="domcontentloaded")
            await self.screenshot("landing")
            await self.scan_page_source()
            return True
        except Exception as e:
            await self.bus.publish(Event(
                priority=10,
                category=EventCategory.SYSTEM,
                type="visit_error",
                payload={"url": url, "error": str(e)},
                source="BrowserController"
            ))
            return False

    async def screenshot(self, label: str):
        self._shot_index += 1
        path = self._shot_dir / f"{self._shot_index:03d}_{label}.png"
        try:
            await self._page.screenshot(path=str(path))
            await self.bus.publish(Event(
                priority=10,
                category=EventCategory.SYSTEM,
                type="screenshot",
                payload={"path": str(path), "label": label},
                source="BrowserController"
            ))
        except Exception:
            pass

    async def current_url(self) -> str:
        return self._page.url if self._page else ""

    # ── teardown ───────────────────────────────────────────────────────────────

    async def stop(self):
        try:
            if self._context:
                await self._context.close()
            if self._pw:
                await self._pw.stop()
        finally:
            await self.bus.publish(Event(
                priority=10,
                category=EventCategory.SYSTEM,
                type="session_end",
                payload={},
                source="BrowserController"
            ))
