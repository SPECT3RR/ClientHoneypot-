"""
Modern Chromium Controller + Browser Monitoring Engine (v2)
Launches real Chromium via Playwright, drives interaction,
and acts as a pure Telemetry Collector, forwarding all observables to the Event Bus.
"""
import asyncio
from pathlib import Path

from playwright.async_api import async_playwright
from playwright_stealth import Stealth

from persona import fingerprint_init_script
from event_bus import EventBus, Event, EventCategory

SCREENSHOT_DIR = Path(__file__).parent.parent / "screenshots"

class BrowserSession:
    def __init__(self, bus: EventBus, persona: dict, session_id: str, headless: bool = True):
        self.bus = bus
        self.persona = persona
        self.session_id = session_id
        self.headless = headless
        
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
        await self._context.add_init_script("""
            window.__lastHumanMove = Date.now();
            document.addEventListener('mousemove', e => {
                if (e.isTrusted) { window.__lastHumanMove = Date.now(); }
            }, {capture: true});
            document.addEventListener('keydown', e => {
                if (e.isTrusted) { window.__lastHumanMove = Date.now(); }
            }, {capture: true});
        """)
        
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
