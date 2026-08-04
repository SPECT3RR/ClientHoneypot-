import pytest

import substrate as sub


# ── the gate: the single most important behaviour in this module ───────────

def test_local_profile_refuses_live_targets():
    """An unisolated profile pointed at a real malicious URL is the exact
    failure this module exists to prevent."""
    s = sub.LocalSubstrate()
    with pytest.raises(sub.UnsafeTargetError):
        s.assert_target_allowed("https://malware.example/drive-by")
    with pytest.raises(sub.UnsafeTargetError):
        s.assert_target_allowed("http://198.51.100.7/payload")


def test_local_profile_permits_the_mock_site():
    s = sub.LocalSubstrate()
    for url in ("http://127.0.0.1:8080/", "http://localhost:8080/a",
                "http://[::1]:8080/"):
        s.assert_target_allowed(url)


def test_refusal_names_the_fix():
    s = sub.LocalSubstrate()
    with pytest.raises(sub.UnsafeTargetError) as e:
        s.assert_target_allowed("https://evil.example/")
    msg = str(e.value)
    assert "docker" in msg and "runtime.yaml" in msg


def test_isolated_profile_permits_live_targets():
    s = sub.DockerSubstrate()
    s.assert_target_allowed("https://malware.example/drive-by")


def test_isolated_profile_still_refuses_your_own_network():
    """Hunting must never touch the LAN, however isolated the browser is."""
    s = sub.DockerSubstrate()
    for url in ("http://192.168.1.10/", "http://10.0.0.5/x",
                "http://172.16.4.4/y"):
        with pytest.raises(sub.UnsafeTargetError):
            s.assert_target_allowed(url)


def test_loopback_is_allowed_even_on_the_isolated_profile():
    # The decoy and the mock site are loopback and must stay reachable.
    sub.DockerSubstrate().assert_target_allowed("http://127.0.0.1:8001/portal/login")


# ── profile loading: safe by default ───────────────────────────────────────

def test_default_profile_is_the_safe_one(tmp_path):
    missing = tmp_path / "nope.yaml"
    assert isinstance(sub.load(missing), sub.LocalSubstrate)


def test_broken_config_does_not_silently_grant_permission(tmp_path):
    """A malformed config must never fail open into live hunting."""
    bad = tmp_path / "runtime.yaml"
    bad.write_text("runtime: [this is not a mapping", encoding="utf-8")
    s = sub.load(bad)
    assert s.allows_live_targets is False


def test_docker_profile_loads_from_config(tmp_path):
    cfg = tmp_path / "runtime.yaml"
    cfg.write_text(
        "runtime:\n  profile: docker\n  docker:\n    network: custom_net\n",
        encoding="utf-8")
    s = sub.load(cfg)
    assert isinstance(s, sub.DockerSubstrate)
    assert s.network == "custom_net"
    assert s.isolated is True


def test_unknown_profile_is_rejected_loudly(tmp_path):
    cfg = tmp_path / "runtime.yaml"
    cfg.write_text("runtime:\n  profile: firecracker\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown runtime profile"):
        sub.load(cfg)


def test_repo_config_ships_safe(tmp_path):
    # The committed default must not be the one that permits live hunting.
    assert sub.load().allows_live_targets is False


# ── reporting ──────────────────────────────────────────────────────────────

def test_preflight_warns_loudly_when_unisolated():
    lines = "\n".join(sub.preflight(sub.LocalSubstrate()))
    assert "isolated         : NO" in lines
    assert "BLOCKED" in lines
    assert "WARNING" in lines


def test_docker_availability_is_reported_not_assumed():
    ok, reason = sub.DockerSubstrate().available()
    assert isinstance(ok, bool)
    if not ok:
        assert reason  # must say why, so the operator can fix it


def test_describe_is_machine_readable():
    d = sub.DockerSubstrate().describe()
    assert d == {"profile": "docker", "isolated": True,
                 "allows_live_targets": True}


# ── the docker profile must actually relocate execution ────────────────────

def test_isolated_profile_exposes_a_session_runner():
    """A profile that permits live hunting but still runs the browser on the
    host would be a lie. The runner is what makes it true."""
    s = sub.DockerSubstrate()
    assert callable(getattr(s, "run_session", None))


def test_run_session_refuses_a_target_the_profile_disallows():
    s = sub.DockerSubstrate()
    with pytest.raises(sub.UnsafeTargetError):
        s.run_session("http://192.168.1.50/", "sess1")


def test_container_run_inherits_isolation_from_the_environment(monkeypatch):
    """Inside the container the shipped config still says 'local'. Without
    the env override the session would refuse its own target."""
    monkeypatch.setenv("CH_SUBSTRATE", "docker")
    s = sub.load()
    assert isinstance(s, sub.DockerSubstrate)
    assert s.allows_live_targets is True


def test_env_override_does_not_leak_when_unset(monkeypatch):
    monkeypatch.delenv("CH_SUBSTRATE", raising=False)
    assert sub.load().allows_live_targets is False


def test_decoy_base_is_reachable_from_inside_a_container():
    # Loopback inside the container is the container, not the host.
    s = sub.DockerSubstrate()
    assert "host.docker.internal" in s.decoy_base


def test_container_run_command_carries_the_hardening(monkeypatch):
    """Assert the flags that actually constrain a hostile session, so a
    silent drop of one is caught here rather than after a breach."""
    captured = {}

    class FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "run"]:
            captured["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(sub.subprocess, "run", fake_run)
    s = sub.DockerSubstrate()
    s.run_session("https://evil.example/x", "sess42")

    cmd = " ".join(captured["cmd"])
    assert "--rm" in cmd                              # disposable
    assert "no-new-privileges:true" in cmd            # no privilege gain
    assert "--cap-drop ALL" in cmd
    assert "--network hunt_net" in cmd                # not the host network
    assert "--shm-size 1g" in cmd                     # Chromium OOMs on 64 MB
    assert "--pids-limit" in cmd and "--memory" in cmd
    assert "CH_SUBSTRATE=docker" in cmd
    assert "host.docker.internal:host-gateway" in cmd
    assert cmd.rstrip().endswith("https://evil.example/x")


def test_container_timeout_destroys_the_session(monkeypatch):
    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "run"]:
            raise sub.subprocess.TimeoutExpired(cmd, 600)
        class P: returncode = 0; stdout = ""; stderr = ""
        return P()

    monkeypatch.setattr(sub.subprocess, "run", fake_run)
    result = sub.DockerSubstrate().run_session("https://evil.example/", "s1")
    # A hung hostile session must not linger; it is killed and reported.
    assert result["ok"] is False
    assert "destroyed" in result["stderr"]
