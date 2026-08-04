"""
Enterprise Deception Environment (spec Component 9), served with FastAPI.

A fully synthetic company ("Asteria Holdings") with a login page, HR portal,
finance portal, file server (honeytoken downloads), wiki, and help desk.
Every honeytoken access is logged to the same SQLite telemetry DB the
browser controller uses, tagged with the session_id passed in as a query
param or cookie, so a report can show "attacker opened decoy file X at
time Y" alongside the rest of the session timeline.

Run standalone: python decoy_app/app.py
"""
import sys
import time
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

sys.path.append(str(Path(__file__).parent.parent / "src"))
from telemetry import Telemetry  # noqa: E402
from honeytokens_gen import generate_honeytokens, HONEYTOKEN_DIR  # noqa: E402

APP_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

app = FastAPI(title="Asteria Holdings Decoy Portal")

_FILES = generate_honeytokens()


@app.middleware("http")
async def _bind_session_cookie(request: Request, call_next):
    """Pin the session id to a cookie the first time it arrives as ?sid=.

    Without this, attribution only survives while every URL is constructed by
    us. The moment the visitor *clicks* a link — which is what a real attacker
    does — the query param is gone and the honeytoken read is logged against
    "unknown_session", orphaning the single most important piece of evidence
    the decoy produces.
    """
    sid = request.query_params.get("sid")
    response = await call_next(request)
    if sid:
        response.set_cookie("sid", sid, httponly=True, samesite="lax")
    return response


def _log_access(request: Request, event_type: str, data: dict):
    session_id = request.query_params.get("sid") or request.cookies.get("sid") or "unknown_session"
    t = Telemetry(session_id)
    t.log(event_type, data)
    t.close()


@app.get("/c/{token_id}")
async def canary_callback(request: Request, token_id: str):
    """Self-hosted canary endpoint.

    A GET here means bait we planted has been used. It usually arrives long
    after the session ended and from attacker infrastructure rather than the
    site we visited — which is exactly why the token carries its origin
    session. Responds innocuously so the caller learns nothing.
    """
    from canary_vault import CanaryVault  # noqa: E402
    from verdict_db import VerdictDB      # noqa: E402

    db = VerdictDB()
    hit = CanaryVault(db).record_hit(
        token_id,
        src_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        detail={"path": str(request.url.path),
                "referer": request.headers.get("referer")},
    )
    db.close()

    if hit:
        origin = hit.get("origin_session") or "unattributed"
        print(f"[CANARY] {hit['kind']} '{hit['label']}' fired from "
              f"{hit['src_ip']} -- planted in session {origin}")
        _log_access(request, "canary_hit", hit)

    return PlainTextResponse("", status_code=204)


@app.get("/portal/login", response_class=HTMLResponse)
async def login_page(request: Request):
    _log_access(request, "decoy_page_view", {"page": "login"})
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/portal/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    # Never validates — every login "succeeds" into the decoy environment,
    # and the attempted creds themselves are valuable telemetry.
    _log_access(request, "honeytoken_login_attempt", {"username": username, "password_len": len(password)})
    resp = RedirectResponse(url=f"/portal/hr?sid={request.query_params.get('sid','unknown_session')}", status_code=303)
    return resp


@app.get("/portal/hr", response_class=HTMLResponse)
async def hr_portal(request: Request):
    _log_access(request, "decoy_page_view", {"page": "hr"})
    return templates.TemplateResponse("page.html", {
        "request": request,
        "heading": "Human Resources",
        "body": "Employee records, onboarding docs, and policy library.",
        "items": ["Onboarding Checklist.pdf", "Benefits Summary 2026.pdf", "PTO Policy.docx"],
    })


@app.get("/portal/finance", response_class=HTMLResponse)
async def finance_portal(request: Request):
    _log_access(request, "decoy_page_view", {"page": "finance"})
    return templates.TemplateResponse("page.html", {
        "request": request,
        "heading": "Finance",
        "body": "Budgets, invoices, and vendor payment records.",
        "items": ["Q2_budget_review.pdf", "vendor_invoice_0417.pdf", "AP_ledger_export.csv"],
    })


@app.get("/portal/wiki", response_class=HTMLResponse)
async def wiki(request: Request):
    _log_access(request, "decoy_page_view", {"page": "wiki"})
    return templates.TemplateResponse("page.html", {
        "request": request,
        "heading": "Internal Wiki",
        "body": "How-to guides, IT policies, and department directories.",
        "items": ["VPN Setup Guide", "New Hire FAQ", "Expense Reporting Guide"],
    })


@app.get("/portal/helpdesk", response_class=HTMLResponse)
async def helpdesk(request: Request):
    _log_access(request, "decoy_page_view", {"page": "helpdesk"})
    return templates.TemplateResponse("page.html", {
        "request": request,
        "heading": "IT Help Desk",
        "body": "Open a ticket or browse existing tickets below.",
        "items": ["TICKET-1021: VPN drops on Monday mornings", "TICKET-1044: Need SSH access to reporting box"],
    })


@app.get("/portal/webmail", response_class=HTMLResponse)
async def webmail(request: Request):
    _log_access(request, "decoy_page_view", {"page": "webmail"})
    return templates.TemplateResponse("page.html", {
        "request": request,
        "heading": "Enterprise Webmail",
        "body": "Inbox, Sent Items, and Drafts.",
        "items": ["Fwd: Q3 Planning", "Action Required: Security Update", "Welcome to Asteria"],
    })


@app.get("/portal/files", response_class=HTMLResponse)
async def file_list(request: Request):
    _log_access(request, "decoy_page_view", {"page": "files"})
    return templates.TemplateResponse("files.html", {"request": request, "files": _FILES})


@app.get("/portal/files/{filename}", response_class=PlainTextResponse)
async def file_download(request: Request, filename: str):
    path = HONEYTOKEN_DIR / filename
    if not path.exists() or path.parent != HONEYTOKEN_DIR:
        return PlainTextResponse("Not found", status_code=404)
    content = path.read_text()
    _log_access(request, "honeytoken_access", {
        "filename": filename,
        "alert": True,
        "message": f"Honeytoken '{filename}' was accessed at {time.time()}",
    })
    return PlainTextResponse(content)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
