import pytest

from discovery import (Discovery, DiscoveryQueue, permissive_args,
                       PERMISSIVE_ARGS, host_of)


def _d(url, depth=1, parent=1, trigger="popup"):
    return Discovery(url, parent_session=f"s{parent}", parent_worker=parent,
                     depth=depth, trigger=trigger)


# ── the fan-out itself ─────────────────────────────────────────────────────

def test_a_discovery_is_queued_for_its_own_bot():
    q = DiscoveryQueue()
    assert q.offer(_d("http://adnet.example/x")) is True
    assert len(q) == 1
    item = q.next()
    assert item.url == "http://adnet.example/x"
    assert q.spawned == 1


def test_provenance_survives_so_the_chain_can_be_shown():
    """The finished graph must show the path from the publisher the operator
    typed to the page that dropped the payload."""
    q = DiscoveryQueue()
    q.offer(_d("http://land.example/", depth=2, parent=7, trigger="redirect"))
    item = q.next()
    assert item.parent_worker == 7
    assert item.parent_session == "s7"
    assert item.depth == 2
    assert item.trigger == "redirect"


def test_shallow_discoveries_are_served_first():
    # What the operator's own page does matters more than the tail of an ad chain.
    q = DiscoveryQueue()
    q.offer(_d("http://deep.example/", depth=3))
    q.offer(_d("http://near.example/", depth=1))
    assert q.next().url == "http://near.example/"


# ── the caps, which are the whole design ───────────────────────────────────

def test_depth_is_bounded():
    q = DiscoveryQueue(max_depth=2)
    assert q.offer(_d("http://a.example/", depth=2)) is True
    assert q.offer(_d("http://b.example/", depth=3)) is False
    assert q.stats()["rejected"]["depth"] == 1


def test_total_bots_are_bounded():
    q = DiscoveryQueue(max_total=3)
    for i in range(10):
        q.offer(_d(f"http://h{i}.example/"))
    assert len(q) == 3
    assert q.stats()["rejected"]["total"] == 7


def test_one_ad_rotator_cannot_own_the_swarm():
    """A hundred variants from one host is one finding, not a hundred bots."""
    q = DiscoveryQueue(max_per_host=3)
    for i in range(10):
        q.offer(_d(f"http://rotator.example/ad{i}"))
    assert len(q) == 3
    assert q.stats()["rejected"]["per_host"] == 7


def test_other_hosts_are_unaffected_by_a_noisy_one():
    q = DiscoveryQueue(max_per_host=2)
    for i in range(5):
        q.offer(_d(f"http://noisy.example/{i}"))
    assert q.offer(_d("http://quiet.example/")) is True


def test_the_same_url_is_not_hunted_twice():
    q = DiscoveryQueue()
    assert q.offer(_d("http://a.example/x")) is True
    assert q.offer(_d("http://a.example/x")) is False
    assert q.stats()["rejected"]["duplicate"] == 1


def test_rejections_are_counted_not_silently_dropped():
    """A shallow graph means either the chain ended or we stopped; the
    operator has to be able to tell which."""
    q = DiscoveryQueue(max_depth=1)
    q.offer(_d("http://a.example/", depth=5))
    assert q.stats()["rejected"]["depth"] == 1


def test_non_http_schemes_are_ignored():
    q = DiscoveryQueue()
    for bad in ("javascript:void(0)", "mailto:a@b.c", "data:text/html,x", ""):
        assert q.offer(_d(bad)) is False


def test_empty_queue_returns_none():
    assert DiscoveryQueue().next() is None


def test_host_extraction_is_defensive():
    assert host_of("http://a.example/x") == "a.example"
    assert host_of("nonsense") == ""


# ── permissiveness ─────────────────────────────────────────────────────────

def test_blocking_is_disabled_when_contained():
    args = permissive_args(isolated=True)
    joined = " ".join(args)
    # A blocked pop-under is a redirect chain we never observe.
    assert "--disable-popup-blocking" in joined
    assert "--allow-running-insecure-content" in joined
    assert "safebrowsing-disable-download-protection" in joined


def test_nothing_is_unblocked_on_an_unisolated_host():
    """Disabling web security and safe browsing on the host would hand a
    hunted page the run of the machine."""
    assert permissive_args(isolated=False) == []


def test_permissive_set_is_not_empty():
    assert len(PERMISSIVE_ARGS) >= 5
