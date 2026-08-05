"""
Control plane — swarm, interventions, canaries, verdicts, alerts.

FastAPI + Jinja2 + Server-Sent Events. No React, no build step, no new
dependencies: the event bus is already an event stream and SSE is just a
sink for it.

Run:
    python dashboard/app.py
Then open http://127.0.0.1:8000
"""
import asyncio
import json
import sys
from pathlib import Path

import csv
import io
import re

from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verdict_db import VerdictDB              # noqa: E402
from canary_vault import CanaryVault, PLACEMENTS, KINDS  # noqa: E402
from interventions import InterventionQueue    # noqa: E402
from url_queue import URLQueue                 # noqa: E402
from swarm import SwarmManager                 # noqa: E402
import capacity                                # noqa: E402
import substrate as substrate_mod              # noqa: E402
from evidence import TriageStore, explain      # noqa: E402
import third_party                             # noqa: E402
import threatintel                             # noqa: E402
import urllib.request                          # noqa: E402

DECOY_BASE = "http://127.0.0.1:8001"

APP_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
app = FastAPI(title="ClientHoneypot Control")

# ── shared state ───────────────────────────────────────────────────────────
DB = VerdictDB(session_id="dashboard")
VAULT = CanaryVault(DB)
QUEUE = URLQueue(rate_per_minute=30)
INTERVENTIONS = InterventionQueue(db=DB)
TRIAGE = TriageStore(DB)
SUBSTRATE = substrate_mod.load()
# Headed by default: a human cannot take over a headless browser, so running
# headless silently makes the intervention queue unable to do its job.
SWARM = SwarmManager(QUEUE, DB, VAULT, INTERVENTIONS, headless=False, target=0,
                     substrate=SUBSTRATE)


def decoy_visitors() -> dict:
    """Who is currently touching the decoy, and how they were classified.

    This is the attacker-engagement view. It lived only on the decoy app and
    was never surfaced, so the operator had no way to see the one thing the
    platform exists to observe.
    """
    try:
        with urllib.request.urlopen(f"{DECOY_BASE}/_visitors", timeout=2) as r:
            return json.loads(r.read())
    except Exception:
        return {"visitors": [], "humans": [], "offline": True}


def containment() -> dict:
    ok, reason = SUBSTRATE.available()
    return {"profile": SUBSTRATE.name, "isolated": SUBSTRATE.isolated,
            "live_allowed": SUBSTRATE.allows_live_targets,
            "ready": ok, "reason": reason}


def system_state(interventions: list, visitors: dict, hits: list) -> str:
    """One word for the top of the screen, worst-first.

    An operator should never have to read five panels to learn that someone
    is inside the decoy right now.
    """
    if hits:
        return "CANARY FIRED"
    if visitors.get("humans"):
        return "ATTACKER ENGAGED"
    if interventions:
        return "NEEDS OPERATOR"
    if SWARM.live() > 0:
        return "HUNTING"
    return "IDLE"

ALERTS: list = []
PAUSED: list = []          # containers the dashboard stopped, so it can restore them
# Feed keys live in memory only: a key pasted into a dashboard should not end
# up in a file the operator forgets about.
INTEL_KEYS: dict = {}
_subscribers: list = []

URL_RE = re.compile(r"https?://[^\s\"'<>,;]+", re.IGNORECASE)


def parse_url_file(raw: str, filename: str = "") -> list:
    """Pull URLs out of .txt, .csv or .json, preserving order and deduping.

    Deliberately forgiving: a threat feed arrives however it arrives, and a
    strict parser that rejects the whole file over one bad row is useless.
    Falls back to a regex sweep so a wrapped or malformed file still yields
    its URLs rather than nothing.
    """
    name = (filename or "").lower()
    found: list = []

    if name.endswith(".json"):
        try:
            data = json.loads(raw)
            items = data if isinstance(data, list) else data.get("urls", [])
            for item in items:
                if isinstance(item, str):
                    found.append(item)
                elif isinstance(item, dict) and item.get("url"):
                    found.append(item["url"])
        except (ValueError, AttributeError):
            found = []

    elif name.endswith(".csv") or name.endswith(".tsv"):
        delim = "\t" if name.endswith(".tsv") else ","
        try:
            reader = csv.DictReader(io.StringIO(raw), delimiter=delim)
            key = next((f for f in (reader.fieldnames or [])
                        if f and f.strip().lower() in ("url", "uri", "link",
                                                       "indicator")), None)
            if key:
                found = [r[key] for r in reader if r.get(key)]
        except (csv.Error, ValueError):
            found = []

    if not found:
        # .txt, or any of the above that did not parse cleanly.
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            found.append(line)

    cleaned, seen = [], set()
    for candidate in found:
        candidate = (candidate or "").strip().strip('"\'')
        if not candidate:
            continue
        if not candidate.lower().startswith(("http://", "https://")):
            match = URL_RE.search(candidate)
            candidate = match.group(0) if match else None
            if not candidate:
                continue
        if candidate not in seen:
            seen.add(candidate)
            cleaned.append(candidate)
    return cleaned


def alert(kind: str, message: str, detail: dict = None) -> None:
    item = {"kind": kind, "message": message, "detail": detail or {},
            "ts": asyncio.get_event_loop().time()}
    ALERTS.insert(0, item)
    del ALERTS[200:]
    for q in list(_subscribers):
        try:
            q.put_nowait(item)
        except Exception:
            pass


INTERVENTIONS.subscribe(lambda i: alert(
    "intervention",
    f"Bot blocked on {i['url']} — {i['reason']}" if i["status"] == "open"
    else f"Intervention #{i['id']} {i['status']}", i))


def _third_party_view(limit: int = 20) -> list:
    """Shortlist plus whatever the feeds have said about each host."""
    enricher = threatintel.Enricher(DB, INTEL_KEYS)
    out = []
    for entry in third_party.priority_hosts(DB, limit=limit):
        cached = enricher.cached(entry["host"])
        entry["intel"] = threatintel.consensus(cached) if cached else None
        entry["providers"] = cached
        out.append(entry)
    # Anything a feed flagged floats to the top; it outranks hit count.
    rank = {"malicious": 0, "suspicious": 1}
    out.sort(key=lambda e: rank.get((e["intel"] or {}).get("verdict"), 9))
    return out


@app.on_event("startup")
async def _start_swarm():
    asyncio.create_task(SWARM.run())


# ── pages ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    interventions = INTERVENTIONS.open()
    visitors = decoy_visitors()
    hits = VAULT.hits(20)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "state": system_state(interventions, visitors, hits),
        "containment": containment(),
        "headless": SWARM.headless,
        "capacity": capacity.report(SWARM.headless),
        "foreign": capacity.foreign_containers(),
        "paused": list(PAUSED),
        "swarm": SWARM.status(),
        "interventions": interventions,
        "visitors": visitors,
        "canaries": VAULT.all(),
        "canary_hits": hits,
        "canary_stats": VAULT.stats(),
        "verdicts": DB.recent(40),
        "db_stats": DB.stats(),
        "pending_review": TRIAGE.pending(12),
        "triage_stats": TRIAGE.stats(),
        "intel_stats": third_party.stats(DB),
        "intel_active": threatintel.Enricher(DB, INTEL_KEYS).active(),
        "intel_missing": threatintel.Enricher(DB, INTEL_KEYS).missing_keys(),
        "intel_providers": sorted(threatintel.PROVIDERS),
        "third_party": _third_party_view(20),
        "alerts": ALERTS[:40],
        "placements": PLACEMENTS,
        "kinds": KINDS,
    })


# ── swarm control ──────────────────────────────────────────────────────────

@app.post("/swarm/target")
async def set_target(bots: int = Form(...)):
    SWARM.set_target(bots)
    if SWARM.capacity_reason:
        alert("capacity", SWARM.capacity_reason)
    else:
        alert("swarm", f"Target bot count set to {SWARM.target}")
    return RedirectResponse("/", status_code=303)


@app.post("/swarm/headless")
async def set_headless(mode: str = Form(...)):
    headless = (mode == "headless")
    SWARM.set_headless(headless)
    alert("swarm", "Browser mode: " + (
        "headless — faster, but you CANNOT take over a blocked bot"
        if headless else
        "headed — windows open so you can solve challenges yourself"))
    return RedirectResponse("/", status_code=303)


@app.post("/swarm/kill")
async def kill_swarm():
    SWARM.kill()
    alert("swarm", "Kill switch engaged — all workers stopping")
    return RedirectResponse("/", status_code=303)


@app.post("/queue/add")
async def add_urls(urls: str = Form(...)):
    added = 0
    for line in urls.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            before = len(QUEUE)
            QUEUE.add(line, source="dashboard")
            added += len(QUEUE) - before
    alert("queue", f"{added} URL(s) queued ({len(QUEUE)} pending)")
    return RedirectResponse("/", status_code=303)


@app.post("/queue/upload")
async def upload_urls(file: UploadFile = File(...)):
    """Take a URL list off a file rather than the clipboard.

    Accepts .txt (one per line), .csv (a url column or first field), and
    .json (array of strings or objects with a url key). Anything already
    queued, already visited, or already judged is skipped — re-hunting a URL
    you have a verdict for wastes the one resource this machine is short of.
    """
    raw = (await file.read()).decode("utf-8", errors="replace")
    found = parse_url_file(raw, file.filename or "")

    known = {r["url"] for r in DB.recent(limit=100000)}
    added = skipped = 0
    for url in found:
        if url in known:
            skipped += 1
            continue
        before = len(QUEUE)
        QUEUE.add(url, source=f"upload:{file.filename}")
        if len(QUEUE) > before:
            added += 1
        else:
            skipped += 1

    alert("queue", f"{file.filename}: {added} queued, {skipped} skipped "
                   f"(already seen or duplicate) — {len(QUEUE)} pending")
    return RedirectResponse("/", status_code=303)


# ── triage ─────────────────────────────────────────────────────────────────

@app.post("/triage/{decision}")
async def triage(decision: str, url: str = Form(...), note: str = Form(None)):
    """The operator's ruling on a surfaced finding.

    Confirmed goes to the malicious database. Rejected clears the verdict so
    a consuming RBI stops isolating it, excludes it from future queues, and
    is kept as a labelled false positive — the only honest way to tune the
    thresholds later.
    """
    if decision not in ("confirmed", "rejected"):
        return RedirectResponse("/", status_code=303)
    if TRIAGE.decide(url, decision, note=note):
        verb = ("confirmed malicious" if decision == "confirmed"
                else "marked false positive and cleared")
        alert("triage", f"{url} — {verb}")
    return RedirectResponse("/", status_code=303)


@app.get("/api/evidence")
async def api_evidence(url: str):
    """Full reasoning behind one verdict, for the RBI modules and Wazuh."""
    row = DB.lookup(url)
    return explain(row) if row else {"url": url, "verdict": "unknown"}


# ── threat intel ───────────────────────────────────────────────────────────

@app.post("/intel/key")
async def set_intel_key(provider: str = Form(...), key: str = Form(...)):
    """Store a feed API key for this session.

    Kept in memory only — a key pasted into a dashboard should not end up in
    a file the operator forgets about. Re-enter after a restart.
    """
    key = (key or "").strip()
    if provider not in threatintel.PROVIDERS or not key:
        alert("error", f"unknown provider or empty key: {provider!r}")
        return RedirectResponse("/", status_code=303)
    INTEL_KEYS[provider] = key
    # abuse.ch issues one key that covers both of its services.
    if provider in ("urlhaus", "threatfox"):
        INTEL_KEYS.setdefault("urlhaus", key)
        INTEL_KEYS.setdefault("threatfox", key)
    alert("intel", f"{provider} key set — "
                   f"{len(threatintel.Enricher(DB, INTEL_KEYS).active())} provider(s) active")
    return RedirectResponse("/", status_code=303)


@app.post("/intel/harvest")
async def harvest_hosts():
    """Inventory every third-party host the past hunts touched."""
    found = third_party.harvest_timelines()
    n = third_party.store(DB, found)
    alert("intel", f"harvested {n} third-party hosts from the forensic timelines")
    return RedirectResponse("/", status_code=303)


@app.post("/intel/scan")
async def scan_hosts(limit: int = Form(20)):
    """Look up the shortlist against every provider that has a key.

    Bounded per click because free quotas are small — VirusTotal allows four
    requests a minute — and the shortlist is ordered so the quota is spent on
    redirect targets and popup destinations rather than CDNs.
    """
    enricher = threatintel.Enricher(DB, INTEL_KEYS)
    if not enricher.active():
        alert("error", "no provider has a key yet — add one above. "
                       "auth.abuse.ch is free and covers URLhaus + ThreatFox.")
        return RedirectResponse("/", status_code=303)

    hosts = third_party.priority_hosts(DB, limit=int(limit))
    flagged = 0
    for entry in hosts:
        verdict = threatintel.consensus(enricher.lookup(entry["host"]))
        if verdict["verdict"] in ("malicious", "suspicious"):
            flagged += 1
            alert("intel", f"{entry['host']} — {verdict['verdict'].upper()} "
                           f"per {', '.join(verdict['flagged_by'])}")
    alert("intel", f"checked {len(hosts)} host(s) via "
                   f"{', '.join(enricher.active())}: {flagged} flagged")
    return RedirectResponse("/", status_code=303)


@app.get("/api/intel")
async def api_intel(host: str):
    """Everything known about one third-party host."""
    enricher = threatintel.Enricher(DB, INTEL_KEYS)
    results = enricher.cached(host)
    return {"host": host, "results": results,
            "consensus": threatintel.consensus(results)}


# ── capacity ───────────────────────────────────────────────────────────────

@app.post("/capacity/pause")
async def pause_foreign():
    """Stop other containers to free memory. Preserved, never removed."""
    names = capacity.foreign_containers()
    if not names:
        alert("capacity", "no other containers are running")
        return RedirectResponse("/", status_code=303)
    PAUSED.clear()
    PAUSED.extend(names)
    result = capacity.pause_containers(names)
    alert("capacity", f"paused {len(result['stopped'])} container(s) — "
                      f"{capacity.available_mb()} MB now available")
    return RedirectResponse("/", status_code=303)


@app.post("/capacity/resume")
async def resume_foreign():
    if not PAUSED:
        alert("capacity", "nothing was paused by the dashboard")
        return RedirectResponse("/", status_code=303)
    result = capacity.resume_containers(PAUSED)
    alert("capacity", f"resumed {len(result['started'])} container(s)")
    PAUSED.clear()
    return RedirectResponse("/", status_code=303)


# ── interventions ──────────────────────────────────────────────────────────

@app.post("/intervention/{iid}/{action}")
async def resolve_intervention(iid: int, action: str):
    status = "resolved" if action == "resolve" else "skipped"
    INTERVENTIONS.resolve(iid, status)
    return RedirectResponse("/", status_code=303)


# ── canary vault ───────────────────────────────────────────────────────────

@app.post("/canary/add")
async def add_canary(kind: str = Form(...), value: str = Form(...),
                     placement: str = Form(...), label: str = Form(None)):
    try:
        VAULT.add(kind, value.strip(), placement, label=label)
        alert("canary", f"Token '{label or kind}' registered for {placement}")
    except ValueError as e:
        alert("error", str(e))
    return RedirectResponse("/", status_code=303)


@app.post("/canary/mint")
async def mint_canary(placement: str = Form(...), label: str = Form(None)):
    _, url = VAULT.mint_url_token(placement, label=label)
    alert("canary", f"Minted self-hosted token for {placement}: {url}")
    return RedirectResponse("/", status_code=303)


@app.post("/canary/{token_id}/delete")
async def delete_canary(token_id: str):
    VAULT.remove(token_id)
    return RedirectResponse("/", status_code=303)


# ── live data ──────────────────────────────────────────────────────────────

@app.get("/api/status")
async def api_status():
    interventions = INTERVENTIONS.open()
    visitors = decoy_visitors()
    hits = VAULT.hits(20)
    return {"state": system_state(interventions, visitors, hits),
            "containment": containment(),
            "swarm": SWARM.status(), "interventions": interventions,
            "visitors": visitors, "canary_hits": hits,
            "canaries": VAULT.stats(), "verdicts": DB.stats(),
            "queued": len(QUEUE)}


@app.get("/api/verdict")
async def api_verdict(url: str):
    """The reputation API the RBI modules consume.

    Returns verdict plus evidence, never a bare boolean — a consuming RBI
    has to be able to explain why it raised the isolation level.
    """
    row = DB.lookup(url)
    return row or {"url": url, "verdict": "unknown", "confidence": "none"}


@app.get("/events")
async def events():
    """SSE stream. The bus is already an event stream; this is its sink."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    _subscribers.append(queue)

    async def stream():
        try:
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=5.0)
                    yield f"data: {json.dumps(item, default=str)}\n\n"
                except asyncio.TimeoutError:
                    interventions = INTERVENTIONS.open()
                    visitors = decoy_visitors()
                    hits = VAULT.hits(20)
                    payload = {
                        "kind": "status",
                        "state": system_state(interventions, visitors, hits),
                        "interventions": len(interventions),
                        "humans": len(visitors.get("humans", [])),
                        "visitors": visitors.get("visitors", []),
                        "hits": len(hits),
                        **SWARM.status(),
                    }
                    yield f"data: {json.dumps(payload, default=str)}\n\n"
        finally:
            if queue in _subscribers:
                _subscribers.remove(queue)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    import uvicorn
    print("Control plane: http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)
