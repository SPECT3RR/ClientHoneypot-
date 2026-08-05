"""
Link and ad crawler — directed exploration instead of a blind click.

behavior_engine.random_click() clicked at screen centre and hoped. Malicious
ad chains do not reward hope: the payload usually sits two or three hops
past the publisher, behind an ad slot, an interstitial, or a pop-under.

This walks links, iframes, and ad slots deliberately, captures the tabs they
spawn, follows the chain to a bounded depth, and records the full navigation
graph. That graph is the evidence — it is how you show a malvertising path
from a clean publisher to a landing page.

Bounded on every axis, because ad chains loop forever by design.
"""
import asyncio
import random
import time
from urllib.parse import urlparse

# Selectors that carry ad and redirect traffic, ordered most to least likely.
AD_SELECTORS = [
    "iframe[src*='ad']", "iframe[id*='google_ads']", "iframe[src*='doubleclick']",
    "div[id*='banner'] a", "div[class*='ad'] a", "a[target='_blank']",
    "a[href*='redirect']", "a[href*='click']", "a[href*='goto']",
    "[onclick]", "a[href^='http']",
]

SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "blob:", "#")


class LinkCrawler:
    def __init__(self, browser, bus, max_depth: int = 2, max_clicks: int = 12,
                 max_seconds: float = 90.0, max_tabs: int = 6,
                 on_discovery=None, anchor: bool = False):
        self.browser = browser
        self.bus = bus
        self.max_depth = max_depth
        self.max_clicks = max_clicks
        self.max_seconds = max_seconds
        self.max_tabs = max_tabs

        # When set, a redirect or popup is HANDED OFF to spawn its own bot
        # instead of being chased here. An anchor bot then never leaves the
        # URL the operator gave it — it keeps working that page while
        # children pursue everything it kicks up.
        self.on_discovery = on_discovery
        self.anchor = anchor

        self.visited: set = set()
        self.edges: list = []
        self.discoveries: list = []
        self.clicks = 0
        self._deadline = None

    def _hand_off(self, url: str, trigger: str) -> bool:
        """Report a discovery for the swarm to spawn a bot against."""
        if not self.on_discovery or not url:
            return False
        self.discoveries.append({"url": url, "trigger": trigger})
        self.on_discovery(url, trigger)
        return True

    def _expired(self) -> bool:
        return (self.clicks >= self.max_clicks
                or time.time() > self._deadline)

    async def explore(self) -> dict:
        """Walk the page's links and ad slots, following what they open."""
        self._deadline = time.time() + self.max_seconds
        page = self.browser._page
        origin = page.url
        self.visited.add(origin)

        try:
            await self._walk(page, origin, depth=0)
        except Exception:
            pass  # exploration is best-effort; never fail a session on it

        return {"clicks": self.clicks, "urls": len(self.visited),
                "edges": self.edges}

    async def _walk(self, page, origin: str, depth: int) -> None:
        if depth > self.max_depth or self._expired() or page.is_closed():
            return

        targets = await self._candidates(page)
        random.shuffle(targets)

        for selector, index in targets:
            if self._expired() or page.is_closed():
                return

            before = set(p.url for p in page.context.pages)
            opened = await self._click(page, selector, index)
            if not opened:
                continue
            self.clicks += 1

            # A click either navigates this tab or spawns a new one.
            await asyncio.sleep(random.uniform(0.8, 2.0))
            current = page.url
            if current != origin and current not in self.visited:
                self.visited.add(current)
                self._record(origin, current, "click")
                await self._snapshot(page)
                # An anchor bot hands the destination off and returns to its
                # own page; a plain crawler follows it inline as before.
                if self.anchor and self._hand_off(current, "redirect"):
                    pass
                else:
                    await self._walk(page, current, depth + 1)
                try:
                    await page.go_back(timeout=8000)
                except Exception:
                    return

            for popup in page.context.pages:
                if popup is page or popup.is_closed():
                    continue
                if popup.url in before or popup.url in self.visited:
                    continue
                self.visited.add(popup.url)
                self._record(origin, popup.url, "popup")
                await self._snapshot(popup)
                # A pop-under is the classic malvertising hop. Give it a bot.
                self._hand_off(popup.url, "popup")
                if len(page.context.pages) > self.max_tabs:
                    try:
                        await popup.close()
                    except Exception:
                        pass

    async def _candidates(self, page) -> list:
        out = []
        for selector in AD_SELECTORS:
            try:
                count = await page.locator(selector).count()
            except Exception:
                continue
            for i in range(min(count, 3)):
                out.append((selector, i))
            if len(out) >= self.max_clicks * 2:
                break
        return out

    async def _click(self, page, selector: str, index: int) -> bool:
        try:
            element = page.locator(selector).nth(index)
            if not await element.is_visible(timeout=1000):
                return False
            href = await element.get_attribute("href")
            if href and href.lower().startswith(SKIP_SCHEMES):
                return False
            # no_wait_after: an ad click often opens a tab rather than
            # navigating, and Playwright would otherwise block on navigation.
            await element.click(timeout=3000, no_wait_after=True)
            return True
        except Exception:
            return False

    async def _snapshot(self, page) -> None:
        """Feed the new page to the detection engine."""
        try:
            content = await page.content()
        except Exception:
            return
        from event_bus import Event, EventCategory
        for etype, key in (("dom_snapshot", "html"), ("script_evaluation", "script")):
            await self.bus.publish(Event(
                priority=10, category=EventCategory.DOM, type=etype,
                payload={key: content, "url": page.url},
                source="LinkCrawler"))

    def _record(self, from_url: str, to_url: str, trigger: str) -> None:
        self.edges.append({"from": from_url, "to": to_url, "trigger": trigger,
                           "cross_domain": _host(from_url) != _host(to_url)})


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""
