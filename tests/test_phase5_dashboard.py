import asyncio
import pytest

from interventions import InterventionQueue, detect_block
from verdict_db import VerdictDB


# ── block detection ────────────────────────────────────────────────────────

def test_url_hint_alone_is_not_enough():
    """Both entries currently in needs_human_review.txt were flagged purely
    because 'challenge' appeared in the URL. That is not evidence."""
    blocked, _ = detect_block(200, "https://shop.example/challenge-coin", "")
    assert blocked is False
    blocked, _ = detect_block(200, "https://fidel-itjy.cyou/yh88msj", "")
    assert blocked is False


def test_content_marker_is_authoritative():
    blocked, reason = detect_block(
        200, "https://any.example/",
        '<div class="g-recaptcha" data-sitekey="x"></div>')
    assert blocked
    assert "g-recaptcha" in reason


def test_cloudflare_interstitial_detected():
    blocked, reason = detect_block(
        503, "https://x.example/", "<h1>Checking your browser before accessing")
    assert blocked


def test_blocking_status_counts_even_without_content():
    blocked, reason = detect_block(403, "https://x.example/", "<html>nope</html>")
    assert blocked and "403" in reason


def test_ordinary_page_is_not_blocked():
    blocked, _ = detect_block(200, "https://x.example/",
                              "<html><body><h1>Welcome</h1></body></html>")
    assert blocked is False


# ── intervention queue ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_worker_parks_until_an_operator_resolves_it():
    q = InterventionQueue()
    task = asyncio.create_task(
        q.raise_for("sess1", "http://blocked.example/", "captcha", timeout=5))
    await asyncio.sleep(0.05)

    assert len(q.open()) == 1
    assert q.stats()["open"] == 1

    assert q.resolve(q.open()[0]["id"], "resolved") is True
    assert await task == "resolved"
    assert q.open() == []


@pytest.mark.asyncio
async def test_operator_can_skip_instead_of_taking_over():
    q = InterventionQueue()
    task = asyncio.create_task(
        q.raise_for("s", "http://x/", "403", timeout=5))
    await asyncio.sleep(0.05)
    q.resolve(1, "skipped")
    assert await task == "skipped"


@pytest.mark.asyncio
async def test_unattended_intervention_times_out_rather_than_hanging():
    q = InterventionQueue()
    assert await q.raise_for("s", "http://x/", "captcha", timeout=0.2) == "timeout"


@pytest.mark.asyncio
async def test_resolving_twice_is_a_no_op():
    q = InterventionQueue()
    task = asyncio.create_task(q.raise_for("s", "http://x/", "r", timeout=5))
    await asyncio.sleep(0.05)
    assert q.resolve(1) is True
    assert q.resolve(1) is False
    await task


@pytest.mark.asyncio
async def test_dashboard_is_notified_the_moment_a_hand_goes_up():
    q = InterventionQueue()
    seen = []
    q.subscribe(seen.append)
    task = asyncio.create_task(q.raise_for("s", "http://x/", "captcha", timeout=5))
    await asyncio.sleep(0.05)
    assert seen and seen[0]["status"] == "open"
    q.resolve(1)
    await task


@pytest.mark.asyncio
async def test_interventions_persist_for_the_record(tmp_path):
    db = VerdictDB(db_path=tmp_path / "v.db", session_id="s")
    q = InterventionQueue(db=db)
    task = asyncio.create_task(q.raise_for("s", "http://x/", "captcha", timeout=5))
    await asyncio.sleep(0.05)
    rows = db.conn.execute("SELECT url, status FROM interventions").fetchall()
    assert rows[0]["url"] == "http://x/" and rows[0]["status"] == "open"
    q.resolve(1)
    await task
    db.close()


# ── swarm control plane ────────────────────────────────────────────────────

def _swarm(tmp_path, target=0):
    from url_queue import URLQueue
    from canary_vault import CanaryVault
    from swarm import SwarmManager
    db = VerdictDB(db_path=tmp_path / "v.db", session_id="dash")
    return SwarmManager(URLQueue(rate_per_minute=600), db, CanaryVault(db),
                        InterventionQueue(), headless=True, target=target), db


def test_target_is_clamped_to_what_the_machine_can_run(tmp_path, monkeypatch):
    """Asking for more bots than fit does not give more throughput; it gives
    paging and OOM-killed sessions with half-written verdicts."""
    import capacity
    swarm, db = _swarm(tmp_path)

    monkeypatch.setattr(capacity, "available_mb",
                        lambda: capacity.RESERVE_MB + 2000)
    assert swarm.set_target(3) == 3
    assert swarm.capacity_reason == ""

    monkeypatch.setattr(capacity, "available_mb",
                        lambda: capacity.RESERVE_MB + 900)
    # This manager is headless (280 MB/bot), so 900 MB usable fits 3.
    assert swarm.set_target(15) == 3
    assert "queued" in swarm.capacity_reason
    assert swarm.requested_target == 15   # the ask is remembered, not lost

    # Headed costs more, so the same memory fits fewer. Switching mode must
    # re-clamp, or a headed swarm silently runs over budget.
    swarm.set_headless(False)
    assert swarm.set_target(15) == 2

    assert swarm.set_target(-3) == 0
    db.close()


def test_status_reports_the_shape_of_the_swarm(tmp_path):
    swarm, db = _swarm(tmp_path, target=3)
    s = swarm.status()
    assert s["target"] == 3 and s["live"] == 0 and s["workers"] == []
    db.close()


def test_kill_switch_zeroes_the_target(tmp_path):
    swarm, db = _swarm(tmp_path, target=4)
    swarm.kill()
    assert swarm.target == 0
    db.close()


@pytest.mark.asyncio
async def test_batch_mode_drains_and_exits(tmp_path):
    swarm, db = _swarm(tmp_path, target=0)
    await asyncio.wait_for(swarm.run(poll=0.05, exit_when_drained=True),
                           timeout=5)
    db.close()


@pytest.mark.asyncio
async def test_control_plane_mode_stays_alive_while_idle(tmp_path):
    """At dashboard startup the manager sits at target=0 with an empty
    queue — which must NOT be mistaken for 'drained', or the operator sets a
    target and nothing ever starts."""
    swarm, db = _swarm(tmp_path, target=0)
    task = asyncio.create_task(swarm.run(poll=0.05))
    await asyncio.sleep(0.3)
    assert not task.done(), "control-plane swarm exited while idle"
    swarm.kill()
    await asyncio.wait_for(task, timeout=5)
    db.close()


def test_swarm_self_seeds_the_canary_vault(tmp_path):
    """Bait that is not tracked is worthless: a callback months later must
    still name the visit that planted it, which needs a stamped token."""
    swarm, db = _swarm(tmp_path)
    assert len(swarm.vault.for_placement("browser_profile")) == 3
    db.close()


def test_swarm_leaves_an_operator_filled_vault_alone(tmp_path):
    from url_queue import URLQueue
    from canary_vault import CanaryVault
    from swarm import SwarmManager
    db = VerdictDB(db_path=tmp_path / "v.db", session_id="dash")
    vault = CanaryVault(db)
    vault.add("aws_key", "AKIAREALCANARY", "browser_profile", label="real")

    SwarmManager(URLQueue(rate_per_minute=600), db, vault,
                 InterventionQueue(), headless=True)
    rows = vault.for_placement("browser_profile")
    assert len(rows) == 1 and rows[0]["value"] == "AKIAREALCANARY"
    db.close()


@pytest.mark.asyncio
async def test_capacity_is_rechecked_before_each_spawn(tmp_path, monkeypatch):
    """The target is set once; free memory moves constantly. Three headed
    bots were allowed to start into 640 MB, were starved, produced nothing,
    and that nothing was recorded as a clean verdict."""
    import capacity
    from url_queue import URLQueue
    from canary_vault import CanaryVault
    from swarm import SwarmManager

    db = VerdictDB(db_path=tmp_path / "v.db", session_id="s")
    q = URLQueue(rate_per_minute=600)
    for i in range(5):
        q.add(f"http://127.0.0.1:8080/{i}")

    # Plenty of room when the target is set...
    monkeypatch.setattr(capacity, "available_mb",
                        lambda: capacity.RESERVE_MB + 4000)
    swarm = SwarmManager(q, db, CanaryVault(db), InterventionQueue(),
                         headless=True, substrate=None)
    assert swarm.set_target(5) == 5

    # ...and none by the time workers would spawn.
    monkeypatch.setattr(capacity, "available_mb", lambda: capacity.RESERVE_MB)
    assert capacity.max_bots(headless=True) == 0

    task = asyncio.create_task(swarm.run(poll=0.05))
    await asyncio.sleep(0.4)
    swarm.kill()
    await asyncio.wait_for(task, timeout=10)

    started = [w for w in swarm.status()["workers"]]
    assert len(started) <= 1, f"spawned {len(started)} with no memory available"
    db.close()
