"""
Decoy Navigator — controls how the browser explores the synthetic
enterprise environment after a threat threshold triggers diversion.

Extracts the hardcoded decoy-walk logic from orchestrator.py into a
reusable, randomized, testable module.  Each run explores a different
subset of the decoy portal so demonstrations look organic, not scripted.
"""
import random
import asyncio

DECOY_BASE = "http://127.0.0.1:8001"

# Pool of decoy pages the browser can visit.  Each entry has a path
# and optional CSS selectors for interactive elements on that page.
DECOY_PAGES = [
    {"path": "/portal/hr",        "name": "HR Portal",         "click_selectors": ["table tr td"]},
    {"path": "/portal/finance",   "name": "Finance Portal",    "click_selectors": ["table tr td"]},
    {"path": "/portal/wiki",      "name": "Internal Wiki",     "click_selectors": ["a[href*='wiki/']"]},
    {"path": "/portal/helpdesk",  "name": "IT Help Desk",      "click_selectors": []},
    {"path": "/portal/directory", "name": "Employee Directory", "click_selectors": ["table tr td"]},
    {"path": "/portal/files",     "name": "File Server",       "click_selectors": ["a[href*='files/']"]},
]


async def explore_decoy(browser, session_id: str, telemetry,
                        num_pages: int = None) -> dict:
    """
    Walk the browser through the decoy enterprise portal.
    
    1. Visit the login page
    2. Fill and submit the login form with fake credentials
    3. Visit the dashboard
    4. Randomly visit 2-4 portal pages (unless num_pages is specified)
    5. Always visit the file server last and open a random honeytoken
    
    Returns a dict summarizing the decoy exploration steps taken.
    """
    from behavior_engine import act_human, hesitant_click
    
    steps = []
    decoy_login = f"{DECOY_BASE}/portal/login?sid={session_id}"
    decoy_dashboard = f"{DECOY_BASE}/portal/dashboard?sid={session_id}"
    
    # ── Step 1: Login page ──
    print(f"  [decoy] visiting login portal...")
    ok = await browser.visit(decoy_login)
    await browser.screenshot("decoy_login")
    steps.append("login_page")
    
    if ok:
        # ── Step 2: Fill and submit login form ──
        try:
            page = browser._page
            # Type credentials with human-like delays
            username_field = await page.wait_for_selector(
                'input[name="username"]', timeout=3000)
            if username_field:
                await username_field.click()
                fake_user = browser.persona.get("employee_name", "admin").split()[0].lower()
                await page.keyboard.type(fake_user, delay=random.randint(50, 150))
            
            password_field = await page.wait_for_selector(
                'input[name="password"]', timeout=3000)
            if password_field:
                await password_field.click()
                await page.keyboard.type("AsteriaPass2026!", delay=random.randint(40, 120))
            
            # Click submit with hesitation
            await hesitant_click(page, 'button[type="submit"]')
            await asyncio.sleep(random.uniform(1.0, 2.0))
            await browser.screenshot("decoy_login_submit")
            steps.append("login_submit")
            print(f"  [decoy] submitted login credentials")
        except Exception as e:
            print(f"  [decoy] login form interaction failed: {e}")
            # Fall back to direct navigation
            await browser.visit(decoy_dashboard)
    
    # ── Step 3: Dashboard ──
    current = await browser.current_url()
    if "dashboard" not in current:
        await browser.visit(decoy_dashboard)
    await browser.screenshot("decoy_dashboard")
    await act_human(browser._page)
    steps.append("dashboard")
    print(f"  [decoy] viewing dashboard")
    
    # ── Step 4: Random exploration ──
    if num_pages is None:
        num_pages = random.randint(2, 4)
    
    # Shuffle and pick pages, always reserving file server for last
    non_file_pages = [p for p in DECOY_PAGES if p["path"] != "/portal/files"]
    random.shuffle(non_file_pages)
    pages_to_visit = non_file_pages[:num_pages]
    
    for page_info in pages_to_visit:
        page_url = f"{DECOY_BASE}{page_info['path']}?sid={session_id}"
        print(f"  [decoy] exploring {page_info['name']}...")
        await browser.visit(page_url)
        await browser.screenshot(f"decoy_{page_info['name'].lower().replace(' ', '_')}")
        
        # Try clicking an interactive element on the page
        if page_info["click_selectors"]:
            selector = random.choice(page_info["click_selectors"])
            try:
                clicked = await hesitant_click(browser._page, selector, timeout_ms=2000)
                if clicked:
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    await browser.screenshot(f"decoy_{page_info['name'].lower().replace(' ', '_')}_click")
            except Exception:
                pass
        
        await act_human(browser._page)
        steps.append(page_info["path"])
    
    # ── Step 5: File server + honeytoken ──
    file_url = f"{DECOY_BASE}/portal/files?sid={session_id}"
    print(f"  [decoy] navigating to file server...")
    await browser.visit(file_url)
    await browser.screenshot("decoy_files")
    steps.append("files")
    
    # Open a random honeytoken file
    honeytoken_files = [
        "aws_keys.txt", "id_rsa_backup.txt", "db_credentials.txt",
        "vpn_config.ovpn", "invoice_04178.pdf.txt", "employee_records_export.csv",
    ]
    chosen_token = random.choice(honeytoken_files)
    token_url = f"{DECOY_BASE}/portal/files/{chosen_token}?sid={session_id}"
    print(f"  [decoy] opening honeytoken ({chosen_token})...")
    
    # Try to click the link on the page first (more realistic)
    try:
        clicked = await hesitant_click(
            browser._page, f"a[href*='{chosen_token}']", timeout_ms=3000)
        if not clicked:
            await browser.visit(token_url)
    except Exception:
        await browser.visit(token_url)
    
    await browser.screenshot("decoy_honeytoken_access")
    steps.append(f"honeytoken:{chosen_token}")
    print(f"  [decoy] honeytoken access logged to telemetry")
    
    # Maybe open a second honeytoken (30% chance)
    if random.random() < 0.3:
        remaining = [f for f in honeytoken_files if f != chosen_token]
        second_token = random.choice(remaining)
        second_url = f"{DECOY_BASE}/portal/files/{second_token}?sid={session_id}"
        print(f"  [decoy] opening second honeytoken ({second_token})...")
        await browser.visit(second_url)
        await browser.screenshot("decoy_honeytoken_access_2")
        steps.append(f"honeytoken:{second_token}")
    
    summary = {
        "steps": steps,
        "pages_explored": len(pages_to_visit) + 2,  # +dashboard +files
        "honeytokens_accessed": [s.split(":")[1] for s in steps if s.startswith("honeytoken:")],
    }
    
    telemetry.log("decoy_exploration_complete", summary)
    return summary


def check_decoy_reachable(host: str = "127.0.0.1", port: int = 8001) -> bool:
    """Check if the decoy app is running before attempting navigation."""
    import socket
    try:
        s = socket.create_connection((host, port), timeout=2)
        s.close()
        return True
    except OSError:
        return False
