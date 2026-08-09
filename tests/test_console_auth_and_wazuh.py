"""Console authentication, and the Wazuh rule set staying in sync with siem.py.

Both cover gaps that black-box testing found: the console had no auth at all,
and the Wazuh "integration" shipped events no rule ever matched.
"""
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest

import console_auth
import siem

ROOT = Path(__file__).parent.parent
RULES = ROOT / "wazuh" / "rules" / "clienthoneypot_rules.xml"


# ── console auth ────────────────────────────────────────────────────────────

class _Req:
    """Minimal stand-in for a Starlette request."""
    def __init__(self, headers=None, cookies=None, path="/"):
        self.headers = headers or {}
        self.cookies = cookies or {}


def test_a_token_is_minted_and_reused(tmp_path):
    path = tmp_path / "tok"
    first = console_auth.load_or_create_token(path)
    assert len(first) == 64
    assert console_auth.load_or_create_token(path) == first, "token must persist"


def test_no_credential_means_no_access():
    assert not console_auth.is_authenticated(_Req(), "sekret")


def test_a_wrong_token_is_rejected():
    assert not console_auth.is_authenticated(
        _Req(headers={"authorization": "Bearer wrong"}), "sekret")


def test_bearer_header_cookie_and_x_auth_all_work():
    """The browser uses a cookie; the RBI modules and scripts use a header."""
    for req in (_Req(headers={"authorization": "Bearer sekret"}),
                _Req(headers={"x-auth-token": "sekret"}),
                _Req(cookies={console_auth.COOKIE: "sekret"})):
        assert console_auth.is_authenticated(req, "sekret")


def test_an_empty_configured_token_never_authenticates():
    """A missing/blank token file must not turn into a wildcard."""
    assert not console_auth.is_authenticated(
        _Req(headers={"authorization": "Bearer "}), "")
    assert not console_auth.is_authenticated(_Req(cookies={}), "")


def test_only_the_login_page_is_public():
    """The public set is what an unauthenticated caller can reach. It must stay
    tiny — everything else fails closed."""
    assert console_auth.is_public("/login")
    for guarded in ("/", "/api/verdict", "/swarm/kill", "/samples/abc",
                    "/intel/key", "/canary/add"):
        assert not console_auth.is_public(guarded), f"{guarded} is public"


# ── the dashboard actually enforces it ──────────────────────────────────────

@pytest.fixture
def client():
    sys.path.insert(0, str(ROOT / "dashboard"))
    from fastapi.testclient import TestClient
    import app as dashboard_app
    return TestClient(dashboard_app.app), dashboard_app


def test_every_sensitive_route_is_closed_to_strangers(client):
    """The console lists every canary token, serves captured malware, and can
    clear verdicts. None of that may answer an unauthenticated caller."""
    c, _ = client
    probes = [("GET", "/", None),
              ("GET", "/api/verdict?url=http://x/", None),
              ("GET", "/samples/" + "a" * 64, None),
              ("POST", "/swarm/kill", {}),
              ("POST", "/queue/add", {"urls": "http://x/"}),
              ("POST", "/intel/key", {"provider": "virustotal", "key": "X"})]
    for method, path, data in probes:
        r = c.request(method, path, data=data, follow_redirects=False)
        assert r.status_code == 401, f"{method} {path} answered {r.status_code}"


def test_the_right_token_unlocks_the_console(client):
    c, dash = client
    r = c.post("/login", data={"token": dash.CONSOLE_TOKEN},
               follow_redirects=False)
    assert r.status_code == 303
    assert c.get("/").status_code == 200


def test_a_failed_unlock_is_audited(client):
    c, dash = client
    before = len(dash.AUDIT.recent(200))
    c.post("/login", data={"token": "not-the-token"}, follow_redirects=False)
    after = dash.AUDIT.recent(200)
    assert len(after) > before
    assert any(e["action"] == "console.login_failed" for e in after)


# ── wazuh rules ─────────────────────────────────────────────────────────────

def test_the_rule_file_is_wellformed_xml():
    ElementTree.parse(RULES)


def test_every_shipped_event_has_a_rule():
    """siem.py assigns a severity, but Wazuh's alert level comes from the RULE.
    An event with no rule arrives at the manager's default level, so adding one
    to EVENTS without regenerating silently downgrades it."""
    root = ElementTree.parse(RULES).getroot()
    covered = {f.text.strip("^$") for rule in root.findall("rule")
               for f in rule.findall("field")
               if f.get("name") == "event.action"}
    missing = set(siem.EVENTS) - covered
    assert not missing, f"no Wazuh rule for: {sorted(missing)}"


def test_rule_levels_match_the_severities_in_siem():
    root = ElementTree.parse(RULES).getroot()
    for rule in root.findall("rule"):
        action = next((f.text.strip("^$") for f in rule.findall("field")
                       if f.get("name") == "event.action"), None)
        if action is None or action not in siem.EVENTS:
            continue
        assert int(rule.get("level")) == siem.EVENTS[action][0], \
            f"{action}: rule level {rule.get('level')} != siem severity"


def test_rule_ids_are_in_the_site_local_range():
    """Wazuh reserves everything below 100000 for its own rule set."""
    root = ElementTree.parse(RULES).getroot()
    for rule in root.findall("rule"):
        assert int(rule.get("id")) >= 100000


def test_the_checked_in_rules_are_not_stale():
    """Regenerating must be a no-op; if it is not, code and SIEM have drifted."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_wazuh_rules.py"), "--check"],
        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
