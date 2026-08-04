import time

import pytest

from link_crawler import LinkCrawler, AD_SELECTORS, SKIP_SCHEMES, _host


class FakePage:
    def __init__(self, url="http://pub.example/"):
        self.url = url
        self._closed = False
        self.context = type("Ctx", (), {"pages": [self]})()

    def is_closed(self):
        return self._closed

    async def content(self):
        return "<html></html>"


class FakeBus:
    def __init__(self):
        self.published = []

    async def publish(self, event):
        self.published.append(event)


class FakeBrowser:
    def __init__(self, page):
        self._page = page


def _crawler(**kw):
    page = FakePage()
    return LinkCrawler(FakeBrowser(page), FakeBus(), **kw), page


def test_ad_and_redirect_selectors_are_targeted():
    joined = " ".join(AD_SELECTORS)
    # The payload usually sits past an ad slot, not on the publisher page.
    assert "doubleclick" in joined
    assert "google_ads" in joined
    assert "target='_blank'" in joined
    assert "a[href*='redirect']" in joined


def test_non_navigating_schemes_are_skipped():
    assert "javascript:" in SKIP_SCHEMES
    assert "mailto:" in SKIP_SCHEMES
    assert "data:" in SKIP_SCHEMES


def test_cross_domain_hops_are_flagged_as_evidence():
    """A malvertising chain is proved by hops from a clean publisher to a
    landing page, so each edge records whether it crossed a domain."""
    c, _ = _crawler()
    c._record("http://publisher.example/news", "http://adnet.example/x", "click")
    c._record("http://adnet.example/x", "http://adnet.example/y", "click")

    assert c.edges[0]["cross_domain"] is True
    assert c.edges[1]["cross_domain"] is False
    assert c.edges[0]["trigger"] == "click"


def test_click_budget_bounds_the_walk():
    c, _ = _crawler(max_clicks=3)
    c._deadline = time.time() + 999
    c.clicks = 3
    assert c._expired() is True


def test_wall_clock_budget_bounds_the_walk():
    # Ad chains loop by design; without a deadline a worker never returns.
    c, _ = _crawler(max_seconds=0.01)
    c._deadline = time.time() - 1
    assert c._expired() is True


@pytest.mark.asyncio
async def test_explore_returns_a_graph_and_never_raises(monkeypatch):
    c, page = _crawler()

    async def no_candidates(_page):
        return []

    monkeypatch.setattr(c, "_candidates", no_candidates)
    result = await c.explore()
    assert result["clicks"] == 0
    assert result["urls"] == 1
    assert result["edges"] == []


@pytest.mark.asyncio
async def test_a_broken_page_does_not_fail_the_session(monkeypatch):
    c, page = _crawler()

    async def boom(_page):
        raise RuntimeError("page detached")

    monkeypatch.setattr(c, "_candidates", boom)
    # Exploration is best-effort: a hunting session must survive it.
    assert await c.explore() is not None


@pytest.mark.asyncio
async def test_new_pages_are_fed_to_the_detection_engine():
    c, page = _crawler()
    await c._snapshot(page)
    types = [e.type for e in c.bus.published]
    # Both, because the scorer routes DOM and script scans separately.
    assert "dom_snapshot" in types
    assert "script_evaluation" in types


def test_host_extraction_is_defensive():
    assert _host("http://a.example/x") == "a.example"
    assert _host("not a url") == ""
