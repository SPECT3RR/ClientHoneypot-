import pytest

from verdict_db import VerdictDB
from evidence import (explain, is_reviewable, TriageStore, REVIEW_FLOOR,
                      CHECKS_PERFORMED)


@pytest.fixture
def db(tmp_path):
    d = VerdictDB(db_path=tmp_path / "v.db", session_id="s1")
    yield d
    d.close()


def _malicious(db, url="http://evil.test/"):
    db.record_verdict(url, 79, ["classic_exploit_kit"],
                      ["obf_unescape", "obf_eval", "obf_charcode",
                       "ek_docwrite_unescape", "[CLUSTER] classic_exploit_kit"],
                      "divert_to_decoy")
    return db.lookup(url)


# ── the reasoning, not the score ───────────────────────────────────────────

def test_every_signal_is_explained_in_english(db):
    """'obf_unescape' tells an analyst nothing. The operator asked which exact
    logs decided it was malicious."""
    ev = explain(_malicious(db))
    labels = {s["label"]: s for s in ev["signals"]}
    assert "unescape()" in labels["obf_unescape"]["means"]
    assert "exploit-kit signature" in labels["ek_docwrite_unescape"]["means"]
    assert all(s["means"] for s in ev["signals"])


def test_signals_carry_weight_and_attack_tag(db):
    ev = explain(_malicious(db))
    strongest = ev["signals"][0]
    assert strongest["weight"] > 0
    assert strongest["mitre"]


def test_signals_are_ordered_by_what_mattered_most(db):
    ev = explain(_malicious(db))
    weights = [s["weight"] for s in ev["signals"]]
    assert weights == sorted(weights, reverse=True)


def test_the_cluster_explains_why_the_signals_correlate(db):
    ev = explain(_malicious(db))
    assert ev["clusters"]
    cluster = ev["clusters"][0]
    assert cluster["name"] == "classic_exploit_kit"
    assert cluster["why"]
    assert cluster["bonus"] > 0
    assert "obf_unescape" in cluster["required"]


def test_summary_is_paste_into_a_ticket_short(db):
    ev = explain(_malicious(db))
    assert "79" in ev["summary"]
    assert "classic exploit kit" in ev["summary"]


def test_observed_actions_are_explained_too(db):
    db.record_compromise("http://e.test/", "file_download", "CRITICAL",
                         {"filename": "x.exe"})
    db._had_compromise = True
    db.record_verdict("http://e.test/", 20, [], [], "continue")
    ev = explain(db.lookup("http://e.test/"))
    assert ev["actions"][0]["kind"] == "file_download"
    assert "downloaded a file" in ev["actions"][0]["means"]


# ── why NOT malicious ──────────────────────────────────────────────────────

def test_a_clean_verdict_says_what_was_checked(db):
    """'Nothing found' and 'nothing looked at' must never look the same."""
    db.record_verdict("http://ok.test/", 0, [], [], "continue")
    ev = explain(db.lookup("http://ok.test/"))
    assert ev["verdict"] == "clean"
    assert len(ev["checks_performed"]) == len(CHECKS_PERFORMED)
    assert "observed negative" in ev["summary"]
    assert "No detection fired" in ev["summary"]


# ── the confidence floor ───────────────────────────────────────────────────

def test_weak_findings_are_not_surfaced(db):
    """One weak signal is the raw material of false positives, and false
    positives are how a detector earns a reputation for crying wolf."""
    db.record_verdict("http://weak.test/", 8, [], ["fp_canvas"], "continue")
    assert is_reviewable(db.lookup("http://weak.test/")) is False


def test_findings_above_the_floor_are_surfaced(db):
    assert is_reviewable(_malicious(db)) is True


def test_an_observed_action_always_surfaces_regardless_of_score(db):
    """The page DID something. That outranks any score."""
    db.record_compromise("http://act.test/", "persistence", "CRITICAL", {})
    db._had_compromise = True
    db.record_verdict("http://act.test/", 5, [], [], "continue")
    assert is_reviewable(db.lookup("http://act.test/")) is True


def test_floor_matches_the_diversion_threshold(db):
    from threat_detection import DECOY_TRIGGER_THRESHOLD
    assert REVIEW_FLOOR == DECOY_TRIGGER_THRESHOLD


# ── triage ─────────────────────────────────────────────────────────────────

def test_only_undecided_findings_are_pending(db):
    _malicious(db)
    t = TriageStore(db)
    assert len(t.pending()) == 1
    t.decide("http://evil.test/", "confirmed")
    assert t.pending() == []


def test_confirming_records_the_evidence_behind_the_decision(db):
    _malicious(db)
    t = TriageStore(db)
    t.decide("http://evil.test/", "confirmed", note="matches known EK")
    row = t.confirmed()[0]
    assert row["url"] == "http://evil.test/"
    assert row["note"] == "matches known EK"
    assert "classic_exploit_kit" in row["evidence"]


def test_rejecting_clears_the_verdict_so_rbi_stops_isolating(db):
    _malicious(db)
    t = TriageStore(db)
    t.decide("http://evil.test/", "rejected", note="internal test page")
    assert db.lookup("http://evil.test/")["verdict"] == "clean"
    assert t.is_cleared("http://evil.test/") is True


def test_rejections_are_kept_as_labelled_false_positives(db):
    """The only honest way to tune a threshold is against real decisions."""
    _malicious(db)
    t = TriageStore(db)
    t.decide("http://evil.test/", "rejected")
    assert len(t.false_positives()) == 1


def test_false_positive_rate_is_measured(db):
    for i in range(4):
        db.record_verdict(f"http://x{i}.test/", 79, ["classic_exploit_kit"],
                          ["obf_eval"], "divert_to_decoy")
    t = TriageStore(db)
    t.decide("http://x0.test/", "confirmed")
    t.decide("http://x1.test/", "confirmed")
    t.decide("http://x2.test/", "confirmed")
    t.decide("http://x3.test/", "rejected")
    assert t.stats() == {"confirmed": 3, "rejected": 1, "reviewed": 4,
                         "false_positive_rate": 0.25}


def test_rate_is_none_before_any_review(db):
    assert TriageStore(db).stats()["false_positive_rate"] is None


def test_an_invalid_decision_is_refused(db):
    _malicious(db)
    t = TriageStore(db)
    with pytest.raises(ValueError):
        t.decide("http://evil.test/", "maybe")


def test_deciding_on_an_unknown_url_is_a_no_op(db):
    assert TriageStore(db).decide("http://never.seen/", "confirmed") is False
