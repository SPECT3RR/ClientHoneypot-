import json

import pytest

from verdict_db import VerdictDB
from audit import AuditLog, ACTIONS, SENSITIVE
import siem


@pytest.fixture
def db(tmp_path):
    d = VerdictDB(db_path=tmp_path / "v.db", session_id="s1")
    yield d
    d.close()


# ── audit ──────────────────────────────────────────────────────────────────

def test_an_entry_lands_in_both_sinks(db, tmp_path):
    """The file copy survives the database being replaced."""
    log = AuditLog(db, tmp_path / "audit.jsonl")
    log.record("queue.add", target="http://x.test/", count=3)

    assert len(log.recent()) == 1
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["action"] == "queue.add"


def test_the_log_is_append_only(db, tmp_path):
    """A log an operator can quietly edit is not an audit log — there is no
    update or delete path on the class at all."""
    log = AuditLog(db, tmp_path / "a.jsonl")
    assert not hasattr(log, "delete")
    assert not hasattr(log, "update")
    assert not hasattr(log, "clear")


def test_verdict_rulings_are_recorded_with_who_and_what(db, tmp_path):
    log = AuditLog(db, tmp_path / "a.jsonl")
    log.record("triage.reject", actor="analyst-1", target="http://evil.test/",
               source="10.0.0.5", note="internal test page")
    entry = log.recent()[0]
    assert entry["actor"] == "analyst-1"
    assert entry["target"] == "http://evil.test/"
    assert entry["source"] == "10.0.0.5"
    assert entry["detail"]["note"] == "internal test page"


def test_truth_changing_actions_are_marked_sensitive(db, tmp_path):
    """A reviewer must be able to find the decisions that altered recorded
    truth without reading the whole log."""
    log = AuditLog(db, tmp_path / "a.jsonl")
    log.record("queue.add", target="http://x/")
    log.record("triage.reject", target="http://y/")
    log.record("swarm.kill")

    sensitive = log.recent(sensitive_only=True)
    actions = {e["action"] for e in sensitive}
    assert "triage.reject" in actions and "swarm.kill" in actions
    assert "queue.add" not in actions


def test_provenance_of_a_single_url_is_retrievable(db, tmp_path):
    log = AuditLog(db, tmp_path / "a.jsonl")
    log.record("queue.add", target="http://x.test/")
    log.record("triage.confirm", target="http://x.test/")
    log.record("queue.add", target="http://other.test/")
    assert len(log.for_target("http://x.test/")) == 2


def test_every_action_has_a_human_description():
    for action in SENSITIVE:
        assert action in ACTIONS, f"{action} is sensitive but undescribed"
    assert all(v for v in ACTIONS.values())


def test_an_audit_failure_does_not_break_the_operation(db, tmp_path):
    """Auditing must not be able to take down the thing it audits."""
    log = AuditLog(db, tmp_path / "nonexistent-dir" / "a.jsonl")
    log.path = tmp_path / "no" / "such" / "dir" / "a.jsonl"
    entry = log.record("queue.add", target="http://x/")   # must not raise
    assert entry["action"] == "queue.add"


# ── siem ───────────────────────────────────────────────────────────────────

def test_only_findings_are_shipped_not_raw_telemetry():
    """A session produces tens of thousands of browser events; forwarding them
    buries the three that matter."""
    assert "verdict.malicious" in siem.EVENTS
    assert "canary.fired" in siem.EVENTS
    for noisy in ("request", "response", "console_message", "dom_snapshot"):
        assert noisy not in siem.EVENTS


def test_a_fired_canary_outranks_everything_else():
    """It proves bait travelled to attacker infrastructure and came back."""
    canary = siem.EVENTS["canary.fired"][0]
    for other in ("verdict.malicious", "compromise.critical",
                  "decoy.honeytoken_read", "intervention.raised"):
        assert canary >= siem.EVENTS[other][0]


def test_severity_uses_wazuh_rule_levels():
    for level, _ in siem.EVENTS.values():
        assert 0 <= level <= 15
    assert siem.EVENTS["verdict.clean"][0] < 7      # context, not an alert
    assert siem.EVENTS["verdict.malicious"][0] >= 7  # an alert


def test_findings_carry_an_attack_technique():
    event = siem.build("verdict.malicious", url="http://x/")
    assert event["threat"]["technique"]["id"] == "T1189"


def test_alerts_and_events_are_distinguished():
    assert siem.build("canary.fired")["event"]["kind"] == "alert"
    assert siem.build("verdict.clean")["event"]["kind"] == "event"


def test_jsonl_sink_writes_one_object_per_line(tmp_path):
    ex = siem.SiemExporter(mode="jsonl", path=tmp_path / "s.jsonl")
    ex.verdict("http://evil.test/", "malicious", 79,
               clusters=["classic_exploit_kit"])
    ex.canary("tok1", "ssh_key", "203.0.113.9", "sess42")

    lines = (tmp_path / "s.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["url"] == "http://evil.test/"
    assert first["event"]["severity"] == 10
    assert ex.status()["sent"] == 2 and ex.status()["failed"] == 0


def test_cef_is_well_formed(tmp_path):
    line = siem.to_cef(siem.build("verdict.malicious", url="http://a=b/",
                                  verdict="malicious", score=79))
    assert line.startswith("CEF:0|ClientHoneypot|honeypot") or \
           line.startswith("CEF:0|ClientHoneypot|honeyclient")
    parts = line.split("|")
    assert len(parts) >= 8
    assert 0 <= int(parts[6]) <= 10          # CEF severity range
    assert "\\=" in line                      # the '=' in the URL is escaped


def test_syslog_priority_inverts_correctly():
    """Wazuh 0-15 ascending, syslog 0-7 descending — a canary must not come
    out as 'debug'."""
    high = siem.to_syslog(siem.build("canary.fired"))
    low = siem.to_syslog(siem.build("verdict.clean"))
    pri_high = int(high[1:high.index(">")])
    pri_low = int(low[1:low.index(">")])
    assert pri_high < pri_low


def test_a_low_severity_action_is_not_shipped(tmp_path):
    """LOW actions are context. Paging on a third-party CDN call is how a SIEM
    integration gets muted."""
    ex = siem.SiemExporter(mode="jsonl", path=tmp_path / "s.jsonl")
    assert ex.compromise("outbound_beacon", "LOW") is None
    assert ex.sent == 0


def test_a_dead_siem_never_breaks_a_hunt(tmp_path):
    """The finding is already in the verdict DB; delivery failure is counted,
    not thrown."""
    ex = siem.SiemExporter(mode="syslog", host=None)
    ex.verdict("http://x/", "malicious", 79)     # must not raise
    assert ex.failed == 1
    assert ex.last_error


def test_disabled_exporter_still_builds_but_sends_nothing(tmp_path):
    ex = siem.SiemExporter(mode="jsonl", path=tmp_path / "s.jsonl",
                           enabled=False)
    event = ex.verdict("http://x/", "malicious", 79)
    assert event["url"] == "http://x/"
    assert ex.sent == 0
    assert not (tmp_path / "s.jsonl").exists()


def test_wazuh_agent_config_is_pasteable():
    cfg = siem.wazuh_agent_config()
    assert "<log_format>json</log_format>" in cfg
    assert "<localfile>" in cfg and "</localfile>" in cfg


# ── integration: the endpoints themselves ──────────────────────────────────
#
# Unit tests on AuditLog and SiemExporter all passed while /queue/add raised
# NameError at runtime, because none of them touched a real handler. These do.

@pytest.fixture
def client():
    """An AUTHENTICATED console client.

    The console now requires a token on every route, so these tests carry one:
    what they are checking is operator behaviour, not the door. The door has
    its own tests in test_console_auth_and_wazuh.py, which assert that the same
    endpoints refuse a caller without it.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "dashboard"))
    from fastapi.testclient import TestClient
    import app as dashboard_app
    client = TestClient(
        dashboard_app.app,
        headers={"Authorization": f"Bearer {dashboard_app.CONSOLE_TOKEN}"})
    return client, dashboard_app


def test_every_audited_endpoint_actually_responds(client):
    """A handler that records an audit entry must have Request in scope. This
    is the test that would have caught the NameError."""
    c, _ = client
    calls = [
        ("/queue/add",     {"urls": "http://127.0.0.1:8081/"}),
        ("/swarm/target",  {"bots": "0"}),
        ("/swarm/headless", {"mode": "headless"}),
        ("/swarm/kill",    {}),
        ("/canary/add",    {"kind": "url_token", "value": "http://x/c/t",
                            "placement": "browser_profile", "label": "t"}),
    ]
    for path, data in calls:
        r = c.post(path, data=data, follow_redirects=False)
        assert r.status_code in (200, 303), f"{path} -> {r.status_code}"


def test_operator_actions_reach_the_audit_log(client):
    c, dash = client
    before = len(dash.AUDIT.recent(500))
    c.post("/queue/add", data={"urls": "http://127.0.0.1:8081/audit-probe"},
           follow_redirects=False)
    after = dash.AUDIT.recent(500)
    assert len(after) > before
    assert any(e["action"] == "queue.add" for e in after)


def test_the_source_address_is_captured(client):
    c, dash = client
    c.post("/swarm/target", data={"bots": "0"}, follow_redirects=False)
    entry = next(e for e in dash.AUDIT.recent(20) if e["action"] == "swarm.target")
    assert entry["source"], "no source address recorded"


def test_a_key_is_audited_but_never_logged(client):
    """The provider is worth recording; the secret never is."""
    c, dash = client
    c.post("/intel/key", data={"provider": "virustotal", "key": "SECRET-XYZ"},
           follow_redirects=False)
    for entry in dash.AUDIT.recent(20):
        assert "SECRET-XYZ" not in json.dumps(entry)
