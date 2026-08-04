from pathlib import Path
from event_bus import EventBus
from browser_controller import BrowserSession
from ownership_manager import OwnershipManager


def _session(session_id):
    return BrowserSession(bus=EventBus(), persona={"persona_id": "shared"},
                          session_id=session_id,
                          ownership_mgr=OwnershipManager(), headless=True)


def test_each_session_gets_its_own_profile_directory():
    a = _session("session_aaa")
    b = _session("session_bbb")
    assert a.profile_dir != b.profile_dir
    assert "session_aaa" in str(a.profile_dir)
    assert "session_bbb" in str(b.profile_dir)


def test_profile_directory_is_not_the_shared_default():
    s = _session("session_ccc")
    assert s.profile_dir.name != "default"
    assert s.profile_dir.parent.name == "profiles"


def test_profile_directory_is_under_config_profiles():
    s = _session("session_ddd")
    expected_root = Path(__file__).parent.parent / "config" / "profiles"
    assert expected_root.resolve() in s.profile_dir.resolve().parents
