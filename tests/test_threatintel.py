import json

import pytest

from verdict_db import VerdictDB
import third_party as tp
import threatintel as ti


@pytest.fixture
def db(tmp_path):
    d = VerdictDB(db_path=tmp_path / "v.db", session_id="s1")
    d.conn.executescript(tp.SCHEMA)
    yield d
    d.close()


def _timeline(dirpath, name, events):
    p = dirpath / f"{name}_timeline.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return p


def _evt(etype, url):
    return {"type": etype, "category": "network", "source": "t",
            "payload": {"url": url}}


# ── harvesting ─────────────────────────────────────────────────────────────

def test_hosts_are_pulled_from_the_forensic_timelines(tmp_path):
    _timeline(tmp_path, "s1", [
        _evt("visit_start", "http://publisher.test/"),
        _evt("request", "https://adnet.test/tag.js"),
        _evt("redirect", "https://broker.test/go"),
    ])
    found = tp.harvest_timelines(tmp_path)
    assert set(found) == {"publisher.test", "adnet.test", "broker.test"}


def test_the_role_is_recorded_not_just_the_count():
    """A host seen as a script source is ordinary. The same host as a
    redirect target is the shape of a malvertising chain."""
    assert tp.ROLE_BY_EVENT["redirect"] == "redirect"
    assert tp.ROLE_BY_EVENT["new_tab_opened"] == "popup"
    assert "redirect" in tp.INTERESTING_ROLES
    assert "resource" not in tp.INTERESTING_ROLES


def test_loopback_is_excluded(tmp_path):
    _timeline(tmp_path, "s1", [
        _evt("request", "http://127.0.0.1:8001/portal/login"),
        _evt("request", "https://real.test/x"),
    ])
    assert set(tp.harvest_timelines(tmp_path)) == {"real.test"}


def test_a_redirect_target_outranks_a_busy_cdn(db, tmp_path):
    """Free quota is small, so ordering decides what it gets spent on."""
    _timeline(tmp_path, "s1",
              [_evt("request", "https://cdn.test/a.js")] * 400
              + [_evt("redirect", "https://broker.test/go")])
    tp.store(db, tp.harvest_timelines(tmp_path))
    shortlist = tp.priority_hosts(db)
    assert shortlist[0]["host"] == "broker.test"
    assert shortlist[0]["interesting"] is True


def test_known_infrastructure_is_skipped(db, tmp_path):
    _timeline(tmp_path, "s1", [
        _evt("request", "https://ajax.googleapis.com/x.js"),
        _evt("request", "https://evil.test/x.js"),
    ])
    tp.store(db, tp.harvest_timelines(tmp_path))
    assert [h["host"] for h in tp.priority_hosts(db)] == ["evil.test"]


def test_the_allowlist_stays_short():
    """An allowlist that grows becomes the place attackers hide."""
    assert len(tp.BORING_SUFFIXES) <= 15


def test_repeat_runs_merge_rather_than_overwrite(db, tmp_path):
    _timeline(tmp_path, "s1", [_evt("request", "https://x.test/a")])
    tp.store(db, tp.harvest_timelines(tmp_path))
    _timeline(tmp_path, "s2", [_evt("redirect", "https://x.test/b")])
    tp.store(db, tp.harvest_timelines(tmp_path))

    row = db.conn.execute(
        "SELECT roles, sessions FROM third_party_hosts WHERE host='x.test'").fetchone()
    assert set(json.loads(row["roles"])) >= {"resource", "redirect"}
    assert len(json.loads(row["sessions"])) == 2


# ── providers ──────────────────────────────────────────────────────────────

def test_every_provider_now_needs_a_key():
    """abuse.ch returns 401 without an Auth-Key -- URLhaus is no longer the
    keyless option it used to be."""
    assert ti.PROVIDERS["urlhaus"].needs_key is True
    assert all(c.needs_key for c in ti.PROVIDERS.values())


def test_virustotal_is_rate_limited_hardest():
    # 4 requests a minute on the free tier.
    assert ti.PROVIDERS["virustotal"].per_minute == 4


def test_a_single_engine_is_not_a_conviction():
    assert ti.VT_MALICIOUS > ti.VT_SUSPICIOUS


def test_enricher_reports_what_it_cannot_do(db):
    e = ti.Enricher(db, {})
    assert e.active() == []
    assert set(e.missing_keys()) == set(ti.PROVIDERS)


def test_a_key_activates_its_provider(db):
    e = ti.Enricher(db, {"urlhaus": "abc"})
    assert e.active() == ["urlhaus"]


# ── consensus ──────────────────────────────────────────────────────────────

def test_the_worst_substantiated_verdict_wins():
    results = [{"provider": "urlhaus", "verdict": "clean", "score": 0},
               {"provider": "virustotal", "verdict": "malicious", "score": 7}]
    c = ti.consensus(results)
    assert c["verdict"] == "malicious"
    assert c["by"] == "virustotal"
    assert c["flagged_by"] == ["virustotal"]


def test_errors_never_become_a_verdict():
    """A quota exhaustion must not read as 'clean'."""
    c = ti.consensus([{"provider": "vt", "verdict": "error", "score": 0}])
    assert c["verdict"] == "unknown"


def test_which_provider_said_it_is_always_carried():
    """'VirusTotal 3/70' and 'URLhaus: known distribution point' are very
    different claims; the analyst has to see which one they have."""
    c = ti.consensus([{"provider": "urlhaus", "verdict": "malicious", "score": 2},
                      {"provider": "otx", "verdict": "clean", "score": 0}])
    assert c["checked_by"] == ["urlhaus", "otx"]
    assert c["flagged_by"] == ["urlhaus"]


def test_answers_are_cached_so_quota_is_spent_once(db, monkeypatch):
    calls = []

    class Fake(ti.Provider):
        name = "fake"
        needs_key = False
        per_minute = 0

        def lookup(self, host):
            calls.append(host)
            return {"verdict": "clean", "score": 0, "detail": {}}

    monkeypatch.setitem(ti.PROVIDERS, "fake", Fake)
    e = ti.Enricher(db, {})
    e.providers = [Fake()]

    e.lookup("x.test")
    e.lookup("x.test")
    assert calls == ["x.test"], "a cached answer must not re-spend quota"


# ── persistent keys ────────────────────────────────────────────────────────

def test_keys_survive_a_restart(tmp_path):
    """One-time setup: re-entering a key after every restart is the thing
    that was explicitly not wanted."""
    import intel_keys as ik
    f = tmp_path / "keys.json"
    ok, _ = ik.save({"abusech": "SECRET123"}, f)
    assert ok
    assert ik.load(f) == {"abusech": "SECRET123"}


def test_one_abusech_key_covers_both_of_its_services():
    import intel_keys as ik
    resolved = ik.expand({"abusech": "K"})
    assert resolved["urlhaus"] == "K" and resolved["threatfox"] == "K"


def test_writing_keys_to_a_git_visible_path_is_refused(tmp_path, monkeypatch):
    """A key written into a tracked path is a key that gets pushed."""
    import intel_keys as ik
    monkeypatch.setattr(ik, "_is_git_tracked", lambda p: True)
    ok, msg = ik.save({"virustotal": "K"}, tmp_path / "keys.json")
    assert ok is False and "gitignore" in msg


def test_the_real_key_file_is_gitignored():
    import subprocess
    from pathlib import Path
    root = Path(__file__).parent.parent
    proc = subprocess.run(["git", "check-ignore", "-q",
                           "config/intel_keys.json"],
                          cwd=str(root), capture_output=True)
    assert proc.returncode == 0, "config/intel_keys.json must be gitignored"


def test_every_provider_has_a_signup_route():
    """The operator has to be able to go and get each key."""
    import intel_keys as ik
    for name, (url, note) in ik.SIGNUP.items():
        assert url.startswith("https://") and note


# ── failover ───────────────────────────────────────────────────────────────

def test_a_quota_wall_stands_the_provider_down_not_the_scan():
    p = ti.PROVIDERS["virustotal"]("k")
    assert p.available() is True
    p.mark_exhausted(600, "HTTP 429 quota")
    assert p.available() is False
    assert p.status()["cooldown_seconds"] > 0


def test_a_daily_cap_retires_a_provider():
    p = ti.PROVIDERS["urlscan"]("k")
    p.used_today = p.per_day
    assert p.available() is False


def test_an_exhausted_provider_is_skipped_and_others_carry_on(db):
    calls = []

    class Dead(ti.Provider):
        name = "dead"; needs_key = False; per_minute = 0
        def lookup(self, host):
            calls.append("dead"); return {"verdict": "clean", "score": 0, "detail": {}}

    class Alive(ti.Provider):
        name = "alive"; needs_key = False; per_minute = 0
        def lookup(self, host):
            calls.append("alive")
            return {"verdict": "malicious", "score": 4, "detail": {}}

    e = ti.Enricher(db, {})
    dead, alive = Dead(), Alive()
    dead.mark_exhausted(600, "quota")
    e.providers = [dead, alive]

    results = e.lookup("x.test")
    assert calls == ["alive"], "the exhausted provider must be skipped"
    assert ti.consensus(results)["verdict"] == "malicious"


def test_safebrowsing_is_the_deepest_fallback():
    """When VirusTotal's 500/day runs dry, something has to carry on."""
    assert ti.PROVIDERS["safebrowsing"].per_day > ti.PROVIDERS["virustotal"].per_day


def test_six_providers_are_available_to_fall_back_through():
    assert len(ti.PROVIDERS) == 6


def test_threatfox_requires_an_exact_host_match():
    """search_ioc is a substring search: it returns every IOC that merely
    MENTIONS the term. Unfiltered it called google.com malicious on 33 IOCs
    that only referenced it."""
    tf = ti.ThreatFox("k")
    assert tf._is_exact({"ioc": "evil.test", "ioc_type": "domain"}, "evil.test")
    assert tf._is_exact({"ioc": "http://evil.test/x", "ioc_type": "url"}, "evil.test")
    # merely mentioning the host is not the host
    assert not tf._is_exact({"ioc": "http://other.test/?r=google.com",
                             "ioc_type": "url"}, "google.com")
    assert not tf._is_exact({"ioc": "1.2.3.4:80", "ioc_type": "ip:port"}, "google.com")
    assert not tf._is_exact({"ioc": "", "ioc_type": "domain"}, "google.com")


def test_an_unexpected_provider_status_is_unknown_not_clean():
    """A malformed request reading as 'nothing found' is how a feed stops
    contributing without anyone noticing — ThreatFox returned no_json for
    every host until the body format was fixed."""
    import inspect
    src = inspect.getsource(ti.ThreatFox.lookup)
    assert '"verdict": "unknown"' in src


# ── per-target contacts ────────────────────────────────────────────────────

def test_contacts_are_attributed_to_the_target_that_loaded_them(db, tmp_path):
    """The question a per-page score cannot answer: what did this page reach
    out to, and is any of it known bad?"""
    _timeline(tmp_path, "sess1", [
        _evt("visit_start", "http://publisher.test/"),
        _evt("redirect", "https://broker.test/go"),
        _evt("request", "https://tracker.test/px"),
    ])
    tp.store(db, tp.harvest_timelines(tmp_path))
    db.record_verdict("http://publisher.test/", 5, [], [], "continue")
    db.conn.execute("UPDATE verdicts SET session_id='sess1' WHERE url=?",
                    ("http://publisher.test/",))
    db.conn.commit()

    c = tp.contacts_for(db, "http://publisher.test/")
    hosts = {e["host"] for e in c["unchecked"]}
    assert "broker.test" in hosts and "tracker.test" in hosts


def test_a_flagged_contact_is_separated_from_a_clean_one(db, tmp_path):
    _timeline(tmp_path, "s1", [
        _evt("visit_start", "http://pub.test/"),
        _evt("redirect", "https://bad.test/x"),
        _evt("request", "https://ok.test/y"),
    ])
    tp.store(db, tp.harvest_timelines(tmp_path))
    db.record_verdict("http://pub.test/", 0, [], [], "continue")
    db.conn.execute("UPDATE verdicts SET session_id='s1'")
    import time
    for host, verdict in (("bad.test", "malicious"), ("ok.test", "clean")):
        db.conn.execute(
            "INSERT OR REPLACE INTO intel_lookups "
            "(host, provider, verdict, score, detail, checked_ts) "
            "VALUES (?,?,?,?,'{}',?)", (host, "virustotal", verdict, 5, time.time()))
    db.conn.commit()

    c = tp.contacts_for(db, "http://pub.test/")
    assert [e["host"] for e in c["flagged"]] == ["bad.test"]
    assert [e["host"] for e in c["clean"]] == ["ok.test"]
    assert c["flagged"][0]["flagged_by"] == ["virustotal"]


def test_the_join_survives_a_session_id_mismatch(db, tmp_path):
    """Timeline names and verdict session ids diverge whenever a hunt runs
    somewhere else — a contact must not vanish because of that."""
    _timeline(tmp_path, "other_session", [
        _evt("visit_start", "http://pub.test/"),
        _evt("redirect", "https://broker.test/go"),
    ])
    tp.store(db, tp.harvest_timelines(tmp_path))
    db.record_verdict("http://pub.test/", 0, [], [], "continue")   # different id
    c = tp.contacts_for(db, "http://pub.test/")
    assert any(e["host"] == "broker.test"
               for e in c["unchecked"] + c["flagged"] + c["clean"])


def test_harvest_session_scopes_to_one_timeline(db, tmp_path):
    _timeline(tmp_path, "a", [_evt("request", "https://one.test/x")])
    _timeline(tmp_path, "b", [_evt("request", "https://two.test/x")])
    tp.harvest_session(db, "a", tmp_path)
    hosts = {r["host"] for r in db.conn.execute("SELECT host FROM third_party_hosts")}
    assert hosts == {"one.test"}
