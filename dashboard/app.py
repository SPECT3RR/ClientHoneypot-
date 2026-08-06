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
import interventions as _interventions         # noqa: E402
from url_queue import URLQueue                 # noqa: E402
from swarm import SwarmManager                 # noqa: E402
import capacity                                # noqa: E402
import substrate as substrate_mod              # noqa: E402
from evidence import TriageStore, explain      # noqa: E402
import third_party                             # noqa: E402
import threatintel                             # noqa: E402
import intel_keys                              # noqa: E402
from audit import AuditLog                     # noqa: E402
import siem                                    # noqa: E402
import killchain                               # noqa: E402
from sample_capture import SampleStore         # noqa: E402
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
AUDIT = AuditLog(DB)
# Findings ship to a file a Wazuh agent tails. No network
# dependency, so a manager being down cannot lose a verdict.
SIEM = siem.SiemExporter(mode='jsonl')
# Captured attacker payloads (defanged on disk) and the kill-chain map, both
# read-only here — the capture itself runs in the collector process.
SAMPLES = SampleStore()
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
# Feed keys: entered once, persisted to a gitignored file, loaded at startup.
# intel_keys.save() refuses to write if git is not ignoring the path.
INTEL_KEYS: dict = intel_keys.expand(intel_keys.load())
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


INTERVENTIONS.subscribe(lambda i: _interventions.ship_to_siem(SIEM, i))
INTERVENTIONS.subscribe(lambda i: alert(
    "intervention",
    f"Bot blocked on {i['url']} — {i['reason']}" if i["status"] == "open"
    else f"Intervention #{i['id']} {i['status']}", i))


def _pending_with_contacts(limit: int = 12) -> list:
    """Each finding, plus the third parties that target contacted.

    A per-page score cannot see that an innocent-looking publisher loads
    infrastructure the feeds already know. This puts both on the same card.
    """
    out, seen = [], set()

    for finding in TRIAGE.pending(limit):
        finding["contacts"] = third_party.contacts_for(DB, finding["url"])
        seen.add(finding["url"])
        out.append(finding)

    # A page can score clean on its own behaviour and still load
    # infrastructure the feeds already know. That is the case a per-page score
    # structurally cannot reach, and it is exactly what the enrichment exists
    # to catch — so it belongs in the review queue too.
    decided = {r["url"] for r in DB.conn.execute("SELECT url FROM triage")}
    for row in DB.recent(limit=200):
        url = row["url"]
        if url in seen or url in decided:
            continue
        contacts = third_party.contacts_for(DB, url)
        if not contacts["flagged"]:
            continue
        full = DB.lookup(url)
        if not full:
            continue
        finding = explain(full)
        finding["contacts"] = contacts
        finding["surfaced_by"] = "third-party infrastructure"
        finding["summary"] = (
            f"Page behaviour scored {finding['score']}, below the threshold — "
            f"but it contacted {len(contacts['flagged'])} host(s) that threat "
            f"feeds flag. The publisher may be innocent; the infrastructure "
            f"it loads is not.")
        out.append(finding)
        if len(out) >= limit:
            break
    return out


def _client(request) -> str:
    """Caller address for the audit trail. Without auth this is all the
    identity there is, and saying so is better than pretending otherwise."""
    try:
        return request.client.host if request and request.client else None
    except Exception:
        return None


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
        "pending_review": _pending_with_contacts(12),
        "triage_stats": TRIAGE.stats(),
        "intel_stats": third_party.stats(DB),
        "intel_active": threatintel.Enricher(DB, INTEL_KEYS).active(),
        "intel_missing": threatintel.Enricher(DB, INTEL_KEYS).missing_keys(),
        "intel_providers": sorted(threatintel.PROVIDERS),
        "intel_keys": intel_keys.status(),
        "intel_status": threatintel.Enricher(DB, INTEL_KEYS).status(),
        "audit": AUDIT.recent(25),
        "audit_stats": AUDIT.stats(),
        "siem_status": SIEM.status(),
        "wazuh_config": siem.wazuh_agent_config(),
        "samples": SAMPLES.records(25),
        "killchain": killchain.from_siem_file(SIEM.path).all_summaries()[:12],
        "killchain_stages": killchain.STAGES,
        "third_party": _third_party_view(20),
        "alerts": ALERTS[:40],
        "placements": PLACEMENTS,
        "kinds": KINDS,
    })


# ── swarm control ──────────────────────────────────────────────────────────

@app.post("/swarm/target")
async def set_target(request: Request, bots: int = Form(...)):
    SWARM.set_target(bots)
    AUDIT.record("swarm.target", source=_client(request),
                 requested=bots, allowed=SWARM.target)
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
async def kill_swarm(request: Request):
    SWARM.kill()
    AUDIT.record("swarm.kill", source=_client(request))
    alert("swarm", "Kill switch engaged — all workers stopping")
    return RedirectResponse("/", status_code=303)


@app.get("/samples/{sha}")
async def download_sample(request: Request, sha: str):
    """Hand the operator a captured payload — DEFANGED.

    What downloads is the XOR'd `.quar`, not a runnable binary: serving live
    malware over the dashboard is how you infect the machine analysing it. The
    operator un-defangs it deliberately inside a sandbox with the one-liner in
    sample_capture (`SampleStore.unpack`). The retrieval is audited as
    sensitive, since it is the point at which a real sample leaves the store.
    """
    import io
    if not (len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)):
        return RedirectResponse("/", status_code=303)
    path = SAMPLES.dir / f"{sha}.quar"
    if not path.exists():
        return RedirectResponse("/", status_code=303)
    AUDIT.record("sample.retrieve", source=_client(request), target=sha)
    data = path.read_bytes()
    return StreamingResponse(
        io.BytesIO(data), media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{sha}.quar"'})


@app.post("/queue/add")
async def add_urls(request: Request, urls: str = Form(...)):
    added = 0
    for line in urls.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            before = len(QUEUE)
            QUEUE.add(line, source="dashboard")
            added += len(QUEUE) - before
    alert("queue", f"{added} URL(s) queued ({len(QUEUE)} pending)")
    AUDIT.record("queue.add", source=_client(request), added=added, pending=len(QUEUE))
    return RedirectResponse("/", status_code=303)


@app.post("/queue/upload")
async def upload_urls(request: Request, file: UploadFile = File(...)):
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
async def triage(request: Request, decision: str, url: str = Form(...),
                 note: str = Form(None)):
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
        # This ruling changes recorded truth, so it is the single most
        # important thing in the audit log.
        AUDIT.record(f"triage.{'confirm' if decision == 'confirmed' else 'reject'}",
                     target=url, source=_client(request), note=note)
        row = DB.lookup(url)
        if decision == "confirmed" and row:
            SIEM.verdict(url, row["verdict"], row["score"],
                         clusters=row.get("clusters"),
                         findings=row.get("findings"))
    return RedirectResponse("/", status_code=303)


@app.get("/api/evidence")
async def api_evidence(url: str):
    """Full reasoning behind one verdict, for the RBI modules and Wazuh."""
    row = DB.lookup(url)
    return explain(row) if row else {"url": url, "verdict": "unknown"}


# ── threat intel ───────────────────────────────────────────────────────────

@app.post("/intel/key")
async def set_intel_key(request: Request, provider: str = Form(...), key: str = Form(...)):
    """Store a feed API key for this session.

    Kept in memory only — a key pasted into a dashboard should not end up in
    a file the operator forgets about. Re-enter after a restart.
    """
    key = (key or "").strip()
    if provider not in intel_keys.SIGNUP or not key:
        alert("error", f"unknown provider or empty key: {provider!r}")
        return RedirectResponse("/", status_code=303)

    ok, message = intel_keys.save({provider: key})
    if not ok:
        alert("error", message)      # refuses to write a git-visible path
        return RedirectResponse("/", status_code=303)

    INTEL_KEYS.clear()
    INTEL_KEYS.update(intel_keys.expand(intel_keys.load()))
    active = threatintel.Enricher(DB, INTEL_KEYS).active()
    # The provider is recorded; the key never is.
    AUDIT.record("intel.key.set", target=provider, source=_client(request))
    alert("intel", f"{provider} key stored (one-time) — active: "
                   f"{', '.join(active) or 'none'}")
    return RedirectResponse("/", status_code=303)


@app.post("/intel/key/{provider}/forget")
async def forget_intel_key(provider: str):
    intel_keys.remove(provider)
    INTEL_KEYS.clear()
    INTEL_KEYS.update(intel_keys.expand(intel_keys.load()))
    alert("intel", f"{provider} key removed")
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

    # Say plainly when a provider dropped out mid-scan, so a thin result is
    # not mistaken for a clean sweep.
    for st in enricher.status():
        if st["last_error"]:
            alert("intel", f"{st['provider']} stood down ({st['last_error']}) — "
                           f"the remaining providers carried the scan")
    alert("intel", f"checked {len(hosts)} host(s): {flagged} flagged")
    return RedirectResponse("/", status_code=303)


@app.get("/api/contacts")
async def api_contacts(url: str):
    """Which third parties this target contacted, and what the feeds say."""
    return third_party.contacts_for(DB, url)


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
async def add_canary(request: Request, kind: str = Form(...), value: str = Form(...),
                     placement: str = Form(...), label: str = Form(None)):
    try:
        VAULT.add(kind, value.strip(), placement, label=label)
        AUDIT.record("canary.add", target=label, source=_client(request), kind=kind, placement=placement, label=label)
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
