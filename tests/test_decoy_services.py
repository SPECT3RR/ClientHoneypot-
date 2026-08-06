import json

import pytest

from verdict_db import VerdictDB
from canary_vault import CanaryVault
import decoy_services as ds


@pytest.fixture
def vault(tmp_path):
    db = VerdictDB(db_path=tmp_path / "v.db", session_id="s1")
    yield CanaryVault(db)
    db.close()


# ── config generation ──────────────────────────────────────────────────────

def test_planted_credential_becomes_the_accepted_credential(vault):
    """The whole point: the stolen login must actually work, or the attacker
    concludes the credentials are stale and never returns."""
    vault.add("ssh_key", "Sup3rSecret-ssh", "decoy_services", label="corp-ssh")
    cfg = ds.build_config(vault)

    assert cfg[ds.CONFIG_SECTION]["ssh"]["password"] == "Sup3rSecret-ssh"
    assert cfg[ds.CONFIG_SECTION]["ssh"]["username"] == "corp_ssh"


def test_db_credentials_seed_every_matching_engine(vault):
    vault.add("db_credential", "Fake!dbPassw0rd", "decoy_services", label="reporting")
    cfg = ds.build_config(vault)
    for engine in ("mysql", "postgres"):
        assert cfg[ds.CONFIG_SECTION][engine]["password"] == "Fake!dbPassw0rd"


def test_services_without_a_token_still_answer(vault):
    """A port that answers beats a port that refuses; silence is a signal to
    the attacker that nothing is there."""
    cfg = ds.build_config(vault)
    for svc in ds.DEFAULT_SERVICES:
        assert cfg[ds.CONFIG_SECTION][svc]["password"]
        assert cfg[ds.CONFIG_SECTION][svc]["port"] == ds.DEFAULT_PORTS[svc]


def test_real_ports_are_used_not_high_ports(vault):
    # SSH on 2222 tells the attacker they are in a honeypot.
    cfg = ds.build_config(vault)
    assert cfg[ds.CONFIG_SECTION]["ssh"]["port"] == 22
    assert cfg[ds.CONFIG_SECTION]["mysql"]["port"] == 3306
    assert cfg[ds.CONFIG_SECTION]["smb"]["port"] == 445


def test_command_capture_is_enabled(vault):
    cfg = ds.build_config(vault)
    assert "capture_commands" in cfg[ds.CONFIG_SECTION]["ssh"]["options"]


def test_aws_keys_are_not_given_a_local_port(vault):
    # An AWS canary fires through canarytokens.org; there is no local service.
    vault.add("aws_key", "AKIAFAKE", "decoy_services", label="aws")
    cfg = ds.build_config(vault)
    assert all(h["password"] != "AKIAFAKE" for h in cfg[ds.CONFIG_SECTION].values())


def test_config_writes_valid_json(vault, tmp_path):
    path = tmp_path / "config.json"
    ds.write_config(vault, path)
    loaded = json.loads(path.read_text())
    # stdout, not a file: a log file needs a mount, and a mount is visible in
    # /proc/mounts to an attacker who lands a shell in the decoy.
    assert loaded["logs"] == "terminal,json"
    assert "ssh" in loaded[ds.CONFIG_SECTION]


def test_a_captured_command_keeps_who_ran_it():
    """qeeqbox puts the command in "data" alongside the fields identifying the
    source. Unwrapping "data" as an envelope dropped src_ip and server, and
    everything an attacker typed at the SSH decoy was discarded for want of a
    source address."""
    rec = ds.parse_log_line(
        '{"action": "command", "server": "ssh_server", "src_ip": "1.2.3.4", '
        '"data": {"cmd": "cat /etc/shadow"}}')
    assert rec["src_ip"] == "1.2.3.4"
    assert rec["server"] == "ssh_server"
    assert rec["data"]["cmd"] == "cat /etc/shadow"


# ── log ingestion ──────────────────────────────────────────────────────────

def test_credential_attempt_is_recognised():
    rec = {"server": "ssh", "username": "root", "password": "x", "src_ip": "1.2.3.4"}
    assert ds.is_credential_attempt(rec)
    assert not ds.is_credential_attempt({"server": "ssh", "action": "connection"})
    assert not ds.is_credential_attempt(None)


def test_non_json_lines_are_skipped():
    assert ds.parse_log_line("not json") is None
    assert ds.parse_log_line("") is None


def test_nested_data_field_is_unwrapped():
    line = json.dumps({"id": 1, "date": "x",
                       "data": {"server": "ssh", "username": "u", "password": "p"}})
    assert ds.parse_log_line(line)["server"] == "ssh"


def test_a_used_credential_resolves_to_the_session_that_planted_it(vault, tmp_path):
    """Attribution is the product: a hit weeks later must still name the visit
    whose browser profile the credential was stolen from."""
    tid = vault.add("ssh_key", "Sup3rSecret-ssh", "decoy_services", label="corp-ssh")
    vault.stamp(tid, "session_hunt_042")

    log = tmp_path / "honeypots.jsonl"
    log.write_text(json.dumps({
        "server": "ssh", "action": "login", "status": "success",
        "src_ip": "203.0.113.77", "dest_port": 22,
        "username": "corp_ssh", "password": "Sup3rSecret-ssh",
    }) + "\n", encoding="utf-8")

    hits, offset = ds.ingest_logs(vault, log)
    assert len(hits) == 1
    assert hits[0]["origin_session"] == "session_hunt_042"
    assert hits[0]["src_ip"] == "203.0.113.77"
    assert offset > 0


def test_unrelated_logins_are_not_attributed(vault, tmp_path):
    vault.add("ssh_key", "our-planted-key", "decoy_services")
    log = tmp_path / "h.jsonl"
    log.write_text(json.dumps({
        "server": "ssh", "username": "admin", "password": "admin123",
        "src_ip": "10.0.0.1"}) + "\n", encoding="utf-8")

    hits, _ = ds.ingest_logs(vault, log)
    assert hits == []


def test_offset_prevents_double_counting(vault, tmp_path):
    tid = vault.add("db_credential", "dbpass-xyz", "decoy_services")
    vault.stamp(tid, "s9")
    log = tmp_path / "h.jsonl"
    log.write_text(json.dumps({"server": "mysql", "username": "u",
                               "password": "dbpass-xyz", "src_ip": "1.1.1.1"}) + "\n",
                   encoding="utf-8")

    hits, offset = ds.ingest_logs(vault, log)
    assert len(hits) == 1
    # Re-reading from the recorded offset must not re-report the same hit.
    hits2, _ = ds.ingest_logs(vault, log, since_offset=offset)
    assert hits2 == []


def test_missing_log_file_is_not_an_error(vault, tmp_path):
    hits, offset = ds.ingest_logs(vault, tmp_path / "nope.jsonl")
    assert hits == [] and offset == 0


def test_qeeqbox_dict_repr_is_parsed_not_just_json():
    """qeeqbox writes Python dict repr with single quotes, not JSON. A
    json.loads-only parser silently attributes nothing -- every real log line
    is dropped."""
    line = ("{'action': 'connection', 'src_ip': '172.17.0.1', "
            "'src_port': 43708, 'server': 'ssh_server', 'dest_port': 22}")
    rec = ds.parse_log_line(line)
    assert rec is not None, "real qeeqbox output must parse"
    assert rec["server"] == "ssh_server"
    assert rec["src_ip"] == "172.17.0.1"


def test_python_literals_in_repr_are_handled():
    rec = ds.parse_log_line("{'server': 'ssh', 'status': None, 'ok': True}")
    assert rec["status"] is None and rec["ok"] is True


def test_json_form_still_parses():
    rec = ds.parse_log_line('{"server": "ssh", "username": "u"}')
    assert rec["server"] == "ssh"


def test_a_repr_credential_attempt_is_attributed(vault, tmp_path):
    tid = vault.add("ssh_key", "Asteria-ssh-K3y!", "decoy_services", label="corp-ssh")
    vault.stamp(tid, "hunt_session_7")

    log = tmp_path / "honeypotslogger_QSSHServer_abc"
    log.write_text(
        "{'action': 'connection', 'src_ip': '203.0.113.9', 'server': 'ssh_server'}\n"
        "{'action': 'login', 'username': 'corp_ssh', 'password': 'Asteria-ssh-K3y!', "
        "'src_ip': '203.0.113.9', 'server': 'ssh_server', 'dest_port': 22}\n",
        encoding="utf-8")

    hits, _ = ds.ingest_logs(vault, log)
    assert len(hits) == 1
    assert hits[0]["origin_session"] == "hunt_session_7"
    assert hits[0]["src_ip"] == "203.0.113.9"
