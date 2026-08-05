"""Out-of-band decoy telemetry.

The disguise is a property of what is ABSENT from the decoy, so most of these
assert on absence: no mount, no agent, no egress, no config naming a manager.
"""
import json
from pathlib import Path

import pytest

import siem
from decoy_telemetry import DecoyCollector, is_activity, match_planted
from decoy_services import build_config
from verdict_db import VerdictDB
from canary_vault import CanaryVault


@pytest.fixture
def vault(tmp_path):
    db = VerdictDB(db_path=tmp_path / "v.db", session_id="s1")
    yield CanaryVault(db)
    db.close()


@pytest.fixture
def exporter(tmp_path):
    return siem.SiemExporter(mode="jsonl", path=tmp_path / "siem.jsonl")


def shipped(exporter):
    p = Path(exporter.path)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]


# Real records, copied verbatim from decoy_svc stdout.
CONNECT = ('{"action": "connection", "dest_ip": "0.0.0.0", "dest_port": "21", '
           '"server": "ftp_server", "src_ip": "172.22.0.3", "src_port": "52484"}')
LOGIN_OK = ('{"action": "login", "dest_port": "21", "password": "Fs01-Drop-9xK2!", '
            '"server": "ftp_server", "src_ip": "172.22.0.3", "status": "success", '
            '"username": "file_drop"}')
LOGIN_BAD = ('{"action": "login", "dest_port": "21", "password": "hunter2", '
             '"server": "ftp_server", "src_ip": "172.22.0.3", "status": "failed", '
             '"username": "admin"}')
CMD_PASS = ('{"action": "command", "data": {"args": "(\'Fs01-Drop-9xK2!\',)", '
            '"cmd": "PASS"}, "server": "ftp_server", "src_ip": "172.22.0.3"}')
CMD_REAL = ('{"action": "command", "data": {"args": "()", "cmd": "LIST"}, '
            '"server": "ftp_server", "src_ip": "172.22.0.3"}')
NOISE = '{"action": "process", "server": "system", "data": "listening on 21"}'


# ── the disguise ───────────────────────────────────────────────────────────

def test_decoy_config_logs_to_stdout_not_a_file(vault):
    """A file needs a mount, and a mount is visible in /proc/mounts to anyone
    who lands a shell. stdout is captured by the daemon on the host instead."""
    config = build_config(vault)
    assert "terminal" in config["logs"]
    assert "file" not in config["logs"]


def test_a_used_credential_keeps_working(vault):
    """Burning is right for a single-use URL beacon and wrong for a service
    login. The credential burns the instant the attacker first uses it; if
    that removed it from the config, their second visit would be refused and
    they would know they had been caught."""
    vault.add("document", "Fs01-Drop-9xK2!", "decoy_services", label="file_drop")
    token = vault.for_placement("decoy_services")[0]
    vault.record_hit(token["token_id"], src_ip="1.2.3.4")
    assert vault.for_placement("decoy_services") == [], "should now be burned"

    ftp = build_config(vault)["honeypots"]["ftp"]
    assert ftp["password"] == "Fs01-Drop-9xK2!", \
        "a used credential was revoked; the attacker's next login would fail"


def test_nothing_in_the_config_names_a_siem(vault):
    """An attacker reading the decoy's own config must not learn where the
    telemetry goes, because it does not go anywhere from here."""
    blob = json.dumps(build_config(vault)).lower()
    for tell in ("wazuh", "ossec", "siem", "1514", "syslog", "logstash"):
        assert tell not in blob


def test_the_collector_never_touches_the_decoy(exporter, vault):
    """It reads the daemon's log stream on the host. If it ever connected TO
    the decoy, that connection would be visible from inside it."""
    import inspect
    import decoy_telemetry
    src = inspect.getsource(decoy_telemetry)
    assert "docker" in src and "logs" in src
    # No inbound path into the container: no exec, no cp, no socket to it.
    assert "docker exec" not in src
    assert "create_connection" not in src


# ── classification ─────────────────────────────────────────────────────────

def test_a_planted_credential_outranks_everything(exporter, vault):
    """It proves the bait was exfiltrated and tried — the point of the decoy."""
    tid = vault.add("document", "Fs01-Drop-9xK2!", "decoy_services",
                    label="file_drop")
    c = DecoyCollector(exporter, vault=vault)
    c.handle(LOGIN_OK)

    events = shipped(exporter)
    assert len(events) == 1
    assert events[0]["event"]["action"] == "decoy.planted_cred"
    assert events[0]["event"]["severity"] == 13
    assert events[0]["token"] == tid


def test_an_unrelated_password_is_not_a_planted_credential(exporter, vault):
    vault.add("document", "Fs01-Drop-9xK2!", "decoy_services")
    c = DecoyCollector(exporter, vault=vault)
    c.handle(LOGIN_BAD)
    assert shipped(exporter)[0]["event"]["action"] == "decoy.login_failed"


def test_success_outranks_an_attempt(exporter, vault):
    c = DecoyCollector(exporter, vault=vault)
    c.handle(LOGIN_OK)      # no matching token: still a successful login
    c.handle(LOGIN_BAD)
    levels = {e["event"]["action"]: e["event"]["severity"]
              for e in shipped(exporter)}
    assert levels["decoy.login_success"] > levels["decoy.login_failed"]


def test_the_login_handshake_is_not_shipped_twice(exporter, vault):
    """FTP reports USER and PASS as commands AND as a login record. Shipping
    both pages someone three times for one login."""
    c = DecoyCollector(exporter, vault=vault)
    assert c.handle(CMD_PASS) is None
    assert shipped(exporter) == []


def test_protocol_negotiation_is_not_an_alert(exporter, vault):
    """An ordinary ftplib login emits TYPE and PASV on its own. At level 11
    those page someone for something no human chose to do."""
    c = DecoyCollector(exporter, vault=vault)
    for verb in ("TYPE", "PASV", "SYST", "QUIT"):
        line = ('{"action": "command", "server": "ftp_server", '
                '"src_ip": "1.2.3.4", "data": {"cmd": "%s", "args": "()"}}' % verb)
        assert c.handle(line) is None, f"{verb} should not be a finding"
    assert shipped(exporter) == []


def test_shell_input_is_always_a_finding(exporter, vault):
    """Whatever an attacker types at the SSH decoy is intent, and must never
    be filtered by the protocol-chatter list."""
    c = DecoyCollector(exporter, vault=vault)
    c.handle('{"action": "command", "server": "ssh_server", "src_ip": "1.2.3.4",'
             ' "data": {"cmd": "cat /etc/shadow"}}')
    event = shipped(exporter)[0]
    assert event["event"]["action"] == "decoy.command"
    assert event["event"]["severity"] >= 10
    assert "/etc/shadow" in event["command"]


def test_a_real_command_is_shipped(exporter, vault):
    c = DecoyCollector(exporter, vault=vault)
    c.handle(CMD_REAL)
    event = shipped(exporter)[0]
    assert event["event"]["action"] == "decoy.command"
    assert "LIST" in event["command"]


def test_housekeeping_lines_are_not_findings():
    """qeeqbox interleaves its own stats with real events on one stream."""
    assert not is_activity({"action": "process", "server": "system"})
    assert not is_activity({"action": "connection", "server": "ftp_server"})  # no src
    assert is_activity({"action": "connection", "server": "ftp_server",
                        "src_ip": "1.2.3.4"})


def test_the_password_is_kept(exporter, vault):
    """An attacker's reused password is intelligence and it is ours."""
    DecoyCollector(exporter, vault=vault).handle(LOGIN_BAD)
    assert shipped(exporter)[0]["password"] == "hunter2"


def test_a_planted_match_is_on_the_password_not_the_username(vault):
    """The attacker controls the username and often mangles it; a password
    that is character-for-character ours could only have come from bait."""
    vault.add("document", "Fs01-Drop-9xK2!", "decoy_services", label="file_drop")
    assert match_planted(vault, {"username": "nonsense",
                                 "password": "Fs01-Drop-9xK2!"})
    assert not match_planted(vault, {"username": "file_drop",
                                     "password": "wrong"})


def test_a_broken_line_never_stops_collection(exporter, vault):
    c = DecoyCollector(exporter, vault=vault)
    for junk in ("", "not json", "{unclosed", NOISE):
        assert c.handle(junk) is None
    c.handle(LOGIN_BAD)
    assert len(shipped(exporter)) == 1


# ── the web decoy ──────────────────────────────────────────────────────────

WEB_CANARY = ('{"server": "web_decoy", "action": "canary_hit", '
              '"src_ip": "203.0.113.9", "session_id": "unknown_session", '
              '"user_agent": "curl/8", "detail": {"token_id": "%s"}}')
WEB_VIEW = ('{"server": "web_decoy", "action": "decoy_page_view", '
            '"src_ip": "203.0.113.9", "detail": {"page": "hr"}}')


def test_a_canary_is_resolved_on_the_host_not_in_the_decoy(exporter, vault):
    """The decoy holds no vault, so it cannot enumerate our bait even if it is
    compromised. It reports the token id and the host resolves it."""
    tid = vault.add("ssh_key", "id_rsa_leak", "browser_profile", label="vpn")
    vault.stamp(tid, "sess-hunt-7")

    DecoyCollector(exporter, vault=vault).handle(WEB_CANARY % tid)
    event = shipped(exporter)[0]
    assert event["event"]["action"] == "canary.fired"
    assert event["event"]["severity"] == 13
    assert event["token_kind"] == "ssh_key"
    assert event["session_id"] == "sess-hunt-7"


def test_an_unknown_canary_token_still_ships(exporter, vault):
    """Only logging recognised tokens meant a fired canary vanished whenever
    the decoy could not reach the database — the most valuable event we have,
    dropped in silence."""
    DecoyCollector(exporter, vault=vault).handle(WEB_CANARY % "deadbeefcafe")
    event = shipped(exporter)[0]
    assert event["event"]["action"] == "canary.fired"
    assert event["token_kind"] == "unknown"


def test_browsing_the_decoy_is_not_an_alert(exporter, vault):
    """Page views are how the decoy is read. They belong in the session view,
    not in someone's pager."""
    c = DecoyCollector(exporter, vault=vault)
    assert c.handle(WEB_VIEW) is None
    assert shipped(exporter) == []


def test_web_events_are_recorded_for_the_dashboard(exporter, vault):
    """The decoy's own database write goes to a container layer that is
    discarded, so the host copy has to be made here or the dashboard loses the
    decoy view entirely."""
    logged = []

    class FakeTelemetry:
        def __init__(self, session_id):
            self.session_id = session_id
        def log(self, event_type, data):
            logged.append((self.session_id, event_type, data))
        def close(self):
            pass

    c = DecoyCollector(exporter, vault=vault, db=FakeTelemetry)
    c.handle(WEB_VIEW)
    assert logged and logged[0][1] == "decoy_page_view"


def test_silence_is_only_a_finding_if_the_container_stopped(exporter, monkeypatch):
    """Alerting whenever the stream ends ships a false level-6 on every
    collector restart, and a rule that cries wolf gets muted."""
    import decoy_telemetry
    c = DecoyCollector(exporter, containers=["decoy_svc"])

    monkeypatch.setattr(decoy_telemetry, "is_running", lambda _c: True)
    monkeypatch.setattr(decoy_telemetry.subprocess, "Popen", _fake_popen)
    c._stream("decoy_svc")
    assert shipped(exporter) == [], "alerted while the container was still up"

    monkeypatch.setattr(decoy_telemetry, "is_running", lambda _c: False)
    c._stream("decoy_svc")
    assert shipped(exporter)[0]["event"]["action"] == "decoy.silent"


class _FakeProc:
    stdout = iter(())
    def kill(self): pass


def _fake_popen(*_a, **_k):
    return _FakeProc()
