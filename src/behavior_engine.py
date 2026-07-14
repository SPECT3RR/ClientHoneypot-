"""
Human Behaviour Engine (spec Component 4).

Adds jitter/randomness to browsing actions so timing doesn't look like a
scripted crawler: randomized mouse movement, scroll, dwell/reading pauses,
click hesitation, and occasional idle periods.
"""
import asyncio
import random


async def human_pause(min_s=0.4, max_s=1.8):
    await asyncio.sleep(random.uniform(min_s, max_s))


async def simulate_reading(page, min_s=1.5, max_s=4.5):
    await asyncio.sleep(random.uniform(min_s, max_s))


async def random_mouse_wander(page, moves=None):
    moves = moves or random.randint(3, 7)
    viewport = page.viewport_size or {"width": 1280, "height": 800}
    for _ in range(moves):
        x = random.randint(0, max(1, viewport["width"] - 1))
        y = random.randint(0, max(1, viewport["height"] - 1))
        steps = random.randint(5, 20)
        await page.mouse.move(x, y, steps=steps)
        await asyncio.sleep(random.uniform(0.05, 0.35))


async def random_scroll(page, iterations=None):
    iterations = iterations or random.randint(2, 5)
    for _ in range(iterations):
        delta = random.randint(150, 700)
        await page.mouse.wheel(0, delta)
        await asyncio.sleep(random.uniform(0.3, 1.1))


async def hesitant_click(page, selector: str, timeout_ms=3000):
    """Move toward an element, pause (hesitation), then click."""
    try:
        el = await page.wait_for_selector(selector, timeout=timeout_ms)
        if not el:
            return False
        box = await el.bounding_box()
        if not box:
            return False
        target_x = box["x"] + box["width"] / 2
        target_y = box["y"] + box["height"] / 2
        await page.mouse.move(target_x - random.randint(20, 60), target_y - random.randint(10, 30), steps=10)
        await human_pause(0.2, 0.7)
        await page.mouse.move(target_x, target_y, steps=8)
        await human_pause(0.15, 0.5)
        await el.click()
        return True
    except Exception:
        return False


async def occasional_idle(probability=0.2, min_s=2.0, max_s=6.0):
    if random.random() < probability:
        await asyncio.sleep(random.uniform(min_s, max_s))


async def random_click(page):
    """Finds a random element or screen location and clicks it to trigger popunders/interactions."""
    try:
        # 123movies and similar sites use invisible overlays, a center-screen click often triggers it
        viewport = page.viewport_size or {"width": 1280, "height": 800}
        x = viewport["width"] / 2 + random.randint(-100, 100)
        y = viewport["height"] / 2 + random.randint(-100, 100)
        
        await page.mouse.move(x, y, steps=10)
        await asyncio.sleep(0.3)
        await page.mouse.click(x, y)
        print("[BehaviorEngine] Executed random page click (hunting for popunders/links).")
    except Exception:
        pass

async def act_human(page):
    """Composite behavior pass used after each navigation."""
    try:
        await page.evaluate("""
            if (!window.__virtualCursor) {
                const cursor = document.createElement('div');
                cursor.style.width = '20px';
                cursor.style.height = '20px';
                cursor.style.background = 'rgba(255, 0, 0, 0.8)';
                cursor.style.position = 'absolute';
                cursor.style.pointerEvents = 'none';
                cursor.style.zIndex = '2147483647'; // Max z-index
                cursor.style.borderRadius = '50%';
                cursor.style.border = '2px solid white';
                cursor.style.transition = 'top 0.05s linear, left 0.05s linear';
                document.body.appendChild(cursor);
                window.__virtualCursor = cursor;
                
                document.addEventListener('mousemove', e => {
                    window.__virtualCursor.style.left = e.pageX + 'px';
                    window.__virtualCursor.style.top = e.pageY + 'px';
                });
            }
        """)
    except Exception:
        pass

    await random_mouse_wander(page)
    await random_scroll(page)
    if random.random() < 0.8:
        await random_click(page)
    await simulate_reading(page)
    await occasional_idle()
