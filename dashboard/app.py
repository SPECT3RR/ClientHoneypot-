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

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verdict_db import VerdictDB              # noqa: E402
from canary_vault import CanaryVault, PLACEMENTS, KINDS  # noqa: E402
from interventions import InterventionQueue    # noqa: E402
from url_queue import URLQueue                 # noqa: E402
from swarm import SwarmManager                 # noqa: E402

APP_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
app = FastAPI(title="ClientHoneypot Control")

# ── shared state ───────────────────────────────────────────────────────────
DB = VerdictDB(session_id="dashboard")
VAULT = CanaryVault(DB)
QUEUE = URLQueue(rate_per_minute=30)
INTERVENTIONS = InterventionQueue(db=DB)
SWARM = SwarmManager(QUEUE, DB, VAULT, INTERVENTIONS, headless=True, target=0)

ALERTS: list = []
_subscribers: list = []


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


@app.on_event("startup")
async def _start_swarm():
    asyncio.create_task(SWARM.run())


# ── pages ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "swarm": SWARM.status(),
        "interventions": INTERVENTIONS.open(),
        "canaries": VAULT.all(),
        "canary_hits": VAULT.hits(20),
        "canary_stats": VAULT.stats(),
        "verdicts": DB.recent(40),
        "db_stats": DB.stats(),
        "alerts": ALERTS[:30],
        "placements": PLACEMENTS,
        "kinds": KINDS,
    })


# ── swarm control ──────────────────────────────────────────────────────────

@app.post("/swarm/target")
async def set_target(bots: int = Form(...)):
    SWARM.set_target(bots)
    alert("swarm", f"Target bot count set to {SWARM.target}")
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
    return {"swarm": SWARM.status(), "interventions": INTERVENTIONS.open(),
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
                    payload = {"kind": "status", **SWARM.status()}
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
