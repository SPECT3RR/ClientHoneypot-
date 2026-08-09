"""
Console authentication.

WHY
---
The dashboard had none. It binds loopback, which stops the LAN but not:

  * any other process or user on this machine,
  * a hunted session that escapes its container -- reaching the host dashboard
    on :8000 is exactly the threat scripts/harden_firewall.ps1 exists to block,
    which means we already treat it as reachable,
  * any future deployment that publishes the port or puts it behind a tunnel.

And what it protects is not ordinary: the console lists every canary token (so
a reader learns the whole bait set and can avoid it), serves captured malware
samples, clears verdicts, changes containment, and stores threat-feed keys.

FAIL CLOSED, BY DEFAULT
-----------------------
Enforced as middleware rather than a per-route dependency. A dependency has to
be remembered on every new route and this codebase has 24 of them; middleware
means a route added tomorrow is protected without anyone thinking about it.
The public set is a short explicit allowlist.

The token is generated once into config/dashboard_token (gitignored) and
compared with hmac.compare_digest, so a wrong guess leaks no timing signal.
This is a single-operator console, so a bearer token is the right weight --
not user accounts, and not a password anyone would reuse.
"""
import hmac
import secrets
from pathlib import Path

TOKEN_FILE = Path(__file__).parent.parent / "config" / "dashboard_token"

COOKIE = "ch_console"

# Paths reachable without a token. Deliberately tiny.
PUBLIC_PATHS = {"/login", "/favicon.ico"}


def load_or_create_token(path: Path = None) -> str:
    """The console token, minted on first run."""
    path = Path(path or TOKEN_FILE)
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = secrets.token_hex(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token, encoding="utf-8")
    try:
        path.chmod(0o600)      # best effort; a no-op on Windows
    except OSError:
        pass
    return token


def presented(request) -> str:
    """Whatever credential the caller offered, in preference order."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return (request.headers.get("x-auth-token")
            or request.cookies.get(COOKIE) or "")


def is_authenticated(request, token: str) -> bool:
    offered = presented(request)
    if not offered or not token:
        return False
    return hmac.compare_digest(offered, token)


def is_public(path: str) -> bool:
    return path in PUBLIC_PATHS


LOGIN_HTML = """<!doctype html><meta charset=utf-8>
<title>ClientHoneypot console</title>
<style>
 body{{background:#0d1117;color:#c9d1d9;font:14px/1.5 system-ui,sans-serif;
      display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
 form{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:28px;
      min-width:340px}}
 h1{{font-size:15px;margin:0 0 4px}} p{{color:#8b949e;font-size:12px;margin:0 0 16px}}
 input{{width:100%;padding:9px;background:#0d1117;border:1px solid #30363d;
        border-radius:5px;color:#c9d1d9;font-family:monospace;box-sizing:border-box}}
 button{{margin-top:12px;width:100%;padding:9px;background:#238636;border:0;
         border-radius:5px;color:#fff;font-weight:600;cursor:pointer}}
 .err{{color:#f85149;font-size:12px;margin-top:10px}}
 code{{color:#8b949e;font-size:11px}}
</style>
<form method="post" action="/login">
  <h1>ClientHoneypot console</h1>
  <p>This console reads the canary vault and serves captured malware. It needs
     the operator token.</p>
  <input name="token" type="password" placeholder="console token" autofocus>
  <button>Unlock</button>
  {error}
  <p style="margin-top:16px"><code>token: config/dashboard_token</code></p>
</form>"""
