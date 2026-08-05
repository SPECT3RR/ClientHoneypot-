import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "dashboard"))

import capacity
from app import parse_url_file  # noqa: E402


# ── measurement ────────────────────────────────────────────────────────────

def test_available_memory_is_measured_not_guessed():
    avail = capacity.available_mb()
    total = capacity.total_mb()
    assert avail > 0, "no memory reading — the governor would divide by nothing"
    assert total >= avail


def test_headless_costs_less_than_headed():
    assert capacity.bot_cost_mb(True) < capacity.bot_cost_mb(False)


def test_ceiling_reserves_headroom_for_everything_else():
    """The dashboard, decoy and Docker still need room; consuming the last of
    RAM makes every session slower than running fewer would be."""
    fits = capacity.max_bots(headless=False, available=capacity.RESERVE_MB + 900)
    assert fits == 2, f"expected 2 from 900 MB usable at 450 MB each, got {fits}"


def test_no_bots_when_memory_is_exhausted():
    assert capacity.max_bots(headless=False, available=capacity.RESERVE_MB) == 0
    assert capacity.max_bots(headless=False, available=100) == 0


def test_ceiling_is_bounded_even_on_a_huge_machine():
    assert capacity.max_bots(headless=True, available=1_000_000) == capacity.MAX_BOTS


# ── clamping ───────────────────────────────────────────────────────────────

def test_request_within_capacity_is_untouched(monkeypatch):
    monkeypatch.setattr(capacity, "available_mb", lambda: capacity.RESERVE_MB + 2000)
    allowed, reason = capacity.clamp(3, headless=False)
    assert allowed == 3 and reason == ""


def test_excess_is_capped_and_explained(monkeypatch):
    monkeypatch.setattr(capacity, "available_mb", lambda: capacity.RESERVE_MB + 900)
    allowed, reason = capacity.clamp(15, headless=False)
    assert allowed == 2
    # The operator must know why, and that the rest is queued not discarded.
    assert "capped at 2" in reason and "queued" in reason


def test_zero_is_always_allowed(monkeypatch):
    monkeypatch.setattr(capacity, "available_mb", lambda: 50)
    assert capacity.clamp(0) == (0, "")


def test_exhausted_machine_refuses_with_a_fixable_reason(monkeypatch):
    monkeypatch.setattr(capacity, "available_mb", lambda: 200)
    allowed, reason = capacity.clamp(4, headless=False)
    assert allowed == 0
    assert "not enough" in reason and ("Close" in reason or "pause" in reason)


def test_report_exposes_what_the_ceiling_is_based_on():
    r = capacity.report(headless=False)
    for key in ("available_mb", "total_mb", "reserve_mb", "bot_cost_mb",
                "max_bots", "max_bots_headless", "constrained"):
        assert key in r


# ── URL file parsing ───────────────────────────────────────────────────────

def test_plain_text_one_per_line():
    urls = parse_url_file("http://a.test/\nhttp://b.test/\n", "list.txt")
    assert urls == ["http://a.test/", "http://b.test/"]


def test_comments_and_blank_lines_ignored():
    urls = parse_url_file("# feed export\n\nhttp://a.test/\n\n# end\n", "f.txt")
    assert urls == ["http://a.test/"]


def test_duplicates_removed_but_order_kept():
    urls = parse_url_file("http://b.test/\nhttp://a.test/\nhttp://b.test/\n", "f.txt")
    assert urls == ["http://b.test/", "http://a.test/"]


def test_json_array_of_strings():
    urls = parse_url_file('["http://a.test/", "http://b.test/"]', "f.json")
    assert urls == ["http://a.test/", "http://b.test/"]


def test_json_array_of_objects():
    raw = '[{"url": "http://a.test/", "tag": "ek"}, {"url": "http://b.test/"}]'
    assert parse_url_file(raw, "f.json") == ["http://a.test/", "http://b.test/"]


def test_csv_with_a_url_column():
    raw = "first_seen,url,threat\n2026-01-01,http://a.test/,ek\n2026-01-02,http://b.test/,phish\n"
    assert parse_url_file(raw, "feed.csv") == ["http://a.test/", "http://b.test/"]


def test_malformed_file_still_yields_its_urls():
    """A threat feed arrives however it arrives. Rejecting the whole file over
    one bad row is useless — sweep for URLs rather than return nothing."""
    raw = 'garbage {{{ http://a.test/payload broken,,,\nnoise http://b.test/x junk'
    urls = parse_url_file(raw, "weird.dat")
    assert "http://a.test/payload" in urls
    assert "http://b.test/x" in urls


def test_non_url_lines_are_dropped():
    assert parse_url_file("just some text\nnot-a-url\n", "f.txt") == []


def test_broken_json_falls_back_to_line_scan():
    raw = '[{"url": "http://a.test/",,,, BROKEN\nhttp://b.test/\n'
    assert "http://b.test/" in parse_url_file(raw, "f.json")
