"""
Orchestrator — main entrypoint tying all components together.

Flow per session:
  1. Load persona + fingerprint profile
  2. Start browser
  3. Build realistic referrer journey (hop chain → target URL)
  4. Visit each URL; monitor + score continuously
  5. If bot-blocked (403 / captcha wall) → save to needs_human_review.txt
  6. If threat threshold crossed → divert browser to decoy enterprise env
  7. Record full session (timeline, screenshots, threat summary, MITRE tags)
  8. Write per-URL log to logs/<sanitised_domain>_<ts>.log
  9. Cleanup

Usage examples
──────────────
  # One or more URLs directly on the command line
  python src/orchestrator.py --urls https://suspicious.example --persona finance_qatar

  # Large list from a text file (one URL per line)
  python src/orchestrator.py --url-file targets.txt --persona hr_generic

  # Show the browser window (useful for demos / debugging)
  python src/orchestrator.py --urls https://example.com --headed

Output locations
────────────────
  reports/<session_id>.html   — human-readable HTML session report
  reports/<session_id>.json   — full structured timeline
  screenshots/<session_id>/   — PNG screenshots per navigation step
  telemetry/session.db        — raw SQLite event log (all sessions)
  logs/<domain>_<ts>.log      — per-URL plain-text log
  needs_human_review.txt      — URLs blocked by captcha/403 for manual review
"""
import argparse
import asyncio
import datetime
import re
import socket
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))

from persona import load_persona, save_persona_snapshot
from telemetry import Telemetry
from browser_controller import BrowserSession
from nav_replay import build_journey
from decision_engine import decide
from session_recorder import build_report
from cleanup import cleanup_session
from url_queue import URLQueue

# ── output directories ────────────────────────────────────────────────────────
ROOT                 = Path(__file__).parent.parent
PERSONA_SNAPSHOT_DIR = ROOT / "config" / "persona_snapshots"
LOGS_DIR             = ROOT / "logs"
HUMAN_REVIEW_FILE    = ROOT / "needs_human_review.txt"

LOGS_DIR.mkdir(parents=True, exist_ok=True)


# ── helpers ───────────────────────────────────────────────────────────────────

def _sanitise_for_filename(url: str) -> str:
    """Turn a URL into a safe filename component."""
    url = re.sub(r"https?://", "", url)
    url = re.sub(r"[^\w\-.]", "_", url)
    return url[:60]


def _write_url_log(url: str, lines: list):
    """Write a plain-text per-URL log file to logs/."""
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"{_sanitise_for_filename(url)}_{ts}.log"
    path = LOGS_DIR / name
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _flag_for_human_review(url: str, reason: str):
    """Append a blocked URL + reason to needs_human_review.txt."""
    ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}]  {url}  |  {reason}\n"
    with open(HUMAN_REVIEW_FILE, "a", encoding="utf-8") as f:
        f.write(line)
    print(f"  [human-review] {url} saved to needs_human_review.txt  ({reason})")


def _decoy_reachable() -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", 8001), timeout=2)
        s.close()
        return True
    except OSError:
        return False


def _is_blocked(status: int, url_after_nav: str) -> tuple:
    """
    Returns (blocked: bool, reason: str).
    Detects 403 responses and common captcha/challenge page patterns
    by examining the final URL the browser landed on after navigation.
    """
    captcha_patterns = [
        "captcha", "challenge", "bot-check", "are-you-human",
        "ddos-guard", "cloudflare", "recaptcha", "hcaptcha",
        "please-verify", "access-denied", "blocked",
    ]
    if status == 403:
        return True, f"HTTP 403 Forbidden"
    if status == 401:
        return True, f"HTTP 401 Unauthorized"
        
    parsed = urlparse(url_after_nav.lower())
    path_and_host = parsed.netloc + parsed.path
    
    for pat in captcha_patterns:
        if pat in path_and_host:
            return True, f"captcha/challenge wall detected ({pat} in URL)"
    return False, ""


# ── core session runner ───────────────────────────────────────────────────────

async def run_session(urls: list, persona_name: str,
                      headless: bool = True, referrer_chain: list = None):
    session_id = uuid.uuid4().hex[:16]
    persona    = load_persona(persona_name)
    save_persona_snapshot(persona, PERSONA_SNAPSHOT_DIR)

    telemetry = Telemetry(session_id)
    browser   = BrowserSession(persona, session_id, telemetry, headless=headless)

    # Per-URL log buffer (one entry per URL processed in this session)
    url_log_lines = [
        f"Session  : {session_id}",
        f"Persona  : {persona['employee_name']} ({persona['department']})",
        f"Started  : {datetime.datetime.now().isoformat()}",
        f"URLs     : {urls}",
        "─" * 60,
    ]

    print(f"\n[+] Session   : {session_id}")
    print(f"[+] Persona   : {persona['employee_name']} ({persona['department']})")
    print(f"[+] UA        : {persona['user_agent'][:70]}...")
    print(f"[+] URLs      : {urls}\n")

    await browser.start()

    decision        = {"action": "continue", "reason": {}}
    last_url        = None
    decoy_triggered = False

    for target_url in urls:
        url_log_lines.append(f"\n[target] {target_url}")

        # ── referrer hop chain ────────────────────────────────────────────────
        journey = build_journey(target_url, persona_name,
                                custom_chain=referrer_chain)
        for hop in journey.hops:
            print(f"  [hop]   {hop}")
            url_log_lines.append(f"  [hop]   {hop}")
            ok = await browser.visit(hop, referrer=last_url, is_hop=True)
            if ok:
                last_url = hop
            if browser.scorer.should_trigger_decoy():
                break

        if browser.scorer.should_trigger_decoy():
            decision = decide(browser.scorer)

        # ── visit target URL ──────────────────────────────────────────────────
        if not browser.scorer.should_trigger_decoy():
            print(f"  [visit] {target_url}")
            ok = await browser.visit(target_url, referrer=last_url)

            # ── human-in-the-loop: bot wall detection ─────────────────────────
            # After navigation, check the HTTP status code from telemetry
            # and the final URL for captcha/challenge patterns.
            final_url    = await browser.current_url()
            last_status  = browser.last_response_status  # set by monitoring hook
            blocked, reason = _is_blocked(last_status, final_url)

            if blocked:
                msg = f"BLOCKED — {reason}  (status={last_status}, landed={final_url})"
                print(f"  [!] {msg}")
                url_log_lines.append(f"  [!] {msg}")
                _flag_for_human_review(target_url, reason)
                telemetry.log("blocked", {
                    "url": target_url, "reason": reason,
                    "status": last_status, "final_url": final_url,
                })
                # Skip to next URL — do not score or divert for blocked pages
                continue

            if ok:
                last_url = target_url

            decision = decide(browser.scorer)

        # ── decoy diversion ───────────────────────────────────────────────────
        if decision["action"] == "divert_to_decoy" and not decoy_triggered:
            decoy_triggered = True
            score = browser.scorer.score
            print(f"\n[!] THREAT THRESHOLD HIT (score={score})")
            print(f"    Findings : {[f['label'] for f in browser.scorer.findings]}")
            print(f"    Action   : diverting browser to decoy enterprise portal\n")

            url_log_lines.append(f"\n[!] THREAT HIT score={score}")
            url_log_lines.append(
                f"    Findings: {[f['label'] for f in browser.scorer.findings]}")

            telemetry.log("decoy_diversion", decision["reason"])

            # ── HOW THE DECOY WORKS ───────────────────────────────────────────
            #
            # The decoy is our own fake company "Asteria Holdings", running as
            # a local FastAPI server on port 8001.  It has:
            #   /portal/login    — fake employee login page
            #   /portal/hr       — fake HR portal
            #   /portal/finance  — fake finance portal
            #   /portal/files    — fake file server listing
            #   /portal/files/<name> — honeytoken files (fake AWS keys, SSH
            #                          keys, DB passwords, VPN configs, invoices)
            #
            # When the browser is diverted here, whatever malicious script was
            # running on the original page continues executing — but now it only
            # ever interacts with synthetic data.  Any credential it harvests,
            # any file it reads, any API key it copies is entirely fake.
            #
            # Every access to a honeytoken file is logged immediately to SQLite
            # with an alert flag so the session report shows exactly what the
            # attacker touched and when.
            # ─────────────────────────────────────────────────────────────────

            if not _decoy_reachable():
                msg = "DECOY APP NOT RUNNING on port 8001 — start: python decoy_app/app.py"
                print(f"  [!] {msg}")
                url_log_lines.append(f"  [!] {msg}")
                telemetry.log("decoy_diversion_failed",
                              {"reason": "decoy app not reachable on 127.0.0.1:8001"})
                break

            decoy_base  = "http://127.0.0.1:8001"
            sid_param   = f"sid={session_id}"
            login_url   = f"{decoy_base}/portal/login?{sid_param}"
            files_url   = f"{decoy_base}/portal/files?{sid_param}"
            token_url   = f"{decoy_base}/portal/files/aws_keys.txt?{sid_param}"

            steps = [
                (login_url,  "decoy_login",             "visiting fake login portal"),
                (files_url,  "decoy_file_server",       "browsing fake file server"),
                (token_url,  "decoy_honeytoken_aws",    "opening honeytoken aws_keys.txt"),
            ]

            for step_url, screenshot_label, desc in steps:
                print(f"  [decoy] {desc} ...")
                url_log_lines.append(f"  [decoy] {desc}  →  {step_url}")
                await browser.visit(step_url, referrer=last_url)
                await browser.screenshot(screenshot_label)
                last_url = step_url

            print(f"  [decoy] complete — honeytoken access logged\n")
            url_log_lines.append("  [decoy] complete")
            telemetry.log("decoy_diversion_complete", {
                "steps": ["login", "files", "honeytoken_aws_keys"],
            })
            break

    # ── teardown + report ─────────────────────────────────────────────────────
    threat_summary = browser.scorer.summary()
    await cleanup_session(browser, telemetry)

    t2 = Telemetry(session_id)
    target_sanitized = _sanitise_for_filename(urls[0]) if urls else "session"
    json_path, html_path = build_report(session_id, t2, threat_summary, decision, report_prefix=target_sanitized)
    t2.close()

    url_log_lines += [
        "─" * 60,
        f"Score    : {threat_summary['score']}",
        f"Decision : {decision['action']}",
        f"Report   : {html_path}",
        f"Ended    : {datetime.datetime.now().isoformat()}",
    ]

    # Write per-URL log (uses first URL as filename basis)
    log_path = _write_url_log(urls[0] if urls else "session", url_log_lines)

    print(f"\n[+] Score     : {threat_summary['score']}")
    print(f"[+] Decision  : {decision['action']}")
    print(f"[+] Report    : {html_path}")
    print(f"[+] Log       : {log_path}")

    return session_id, json_path, html_path


# ── queue runner ──────────────────────────────────────────────────────────────

async def run_queue(queue: URLQueue, persona_name: str, headless: bool = True):
    """Process a URLQueue one entry at a time, rate-limited by the queue."""
    processed = 0
    while len(queue) > 0:
        entry = await queue.next()
        if entry is None:
            break
        print(f"\n{'='*60}")
        print(f"[queue] {processed+1}/{len(queue)+processed+1}  {entry.url}")
        await run_session(
            urls=[entry.url],
            persona_name=persona_name,
            headless=headless,
            referrer_chain=entry.referrer_chain or None,
        )
        processed += 1
    print(f"\n[+] Queue complete — {processed} URL(s) processed.")
    if HUMAN_REVIEW_FILE.exists():
        blocked = [l for l in HUMAN_REVIEW_FILE.read_text(
            encoding="utf-8").splitlines() if l.strip()]
        if blocked:
            print(f"[!] {len(blocked)} URL(s) need human review → {HUMAN_REVIEW_FILE}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Thug Deception Platform — honeyclient research orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Visit one URL
  python src/orchestrator.py --urls https://suspicious.example

  # Visit several URLs inline
  python src/orchestrator.py --urls https://a.example https://b.example https://c.example

  # Process a large list from a text file (one URL per line, # = comment)
  python src/orchestrator.py --url-file targets.txt

  # Use the HR persona with a visible browser window
  python src/orchestrator.py --url-file targets.txt --persona hr_generic --headed

targets.txt format:
  # Lines starting with # are ignored
  https://suspicious-site-1.example
  https://suspicious-site-2.example
  https://another-site.example

Output:
  reports/          — HTML + JSON session reports (one per session)
  screenshots/      — PNGs per navigation step
  logs/             — per-URL plain-text logs
  needs_human_review.txt — URLs blocked by captcha/403 for manual visit
        """)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--urls", nargs="+", metavar="URL",
        help="One or more target URLs to visit")
    group.add_argument(
        "--url-file", metavar="FILE",
        help="Path to a .txt / .json / .csv file of target URLs")

    parser.add_argument(
        "--persona", default="finance_qatar",
        choices=["finance_qatar", "hr_generic"],
        help="Which employee persona to use (default: finance_qatar)")
    parser.add_argument(
        "--headed", action="store_true",
        help="Show the browser window instead of running headless")
    parser.add_argument(
        "--rate", type=int, default=10, metavar="N",
        help="Max URLs per minute when using --url-file (default: 10)")

    args = parser.parse_args()

    if args.urls:
        asyncio.run(run_session(
            urls=args.urls,
            persona_name=args.persona,
            headless=not args.headed,
        ))
    else:
        q = URLQueue(rate_per_minute=args.rate)
        q.add_from_file(args.url_file)
        total = len(q)
        if total == 0:
            print(f"[!] No URLs found in {args.url_file}")
            return
        print(f"[+] Loaded {total} URL(s) from {args.url_file}")
        print(f"[+] Rate limit: {args.rate} URLs/min")
        print(f"[+] Persona: {args.persona}\n")
        asyncio.run(run_queue(q, args.persona, headless=not args.headed))


if __name__ == "__main__":
    main()
