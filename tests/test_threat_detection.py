import threat_detection as td


def test_allowlisted_domain_matches_exactly():
    assert td._domain_allowlisted("https://bloomberg.com/markets")
    assert td._domain_allowlisted("https://www.bloomberg.com/markets")
    assert td._domain_allowlisted("https://sub.bloomberg.com/x")


def test_typosquat_cannot_bypass_the_allowlist():
    # str.lstrip takes a CHARACTER SET, so lstrip("www.") strips any leading
    # run of 'w' and '.' characters. That makes "wwwbloomberg.com" — a real,
    # registrable typosquat with no dot — strip to "bloomberg.com" and match
    # the allowlist, so every script served from it is skipped by the scanner.
    # A $10 domain registration disables detection. This is the bug.
    assert not td._domain_allowlisted("https://wwwbloomberg.com/x")
    assert not td._domain_allowlisted("https://wwwreuters.com/x")


def test_mock_site_content_fires_classic_exploit_kit_cluster():
    # Exactly the script block served by tests/mock_malicious_site.py.
    page = """
    var s = "aGVsbG8=";
    console.log(eval("'hello'"));
    console.log(String.fromCharCode(104,105));
    document.write(unescape('%68%69'));
    """
    labels = td.scan_script_text(page, "http://127.0.0.1:8080")
    assert "obf_eval" in labels
    assert "obf_unescape" in labels
    assert "obf_charcode" in labels
    assert "ek_docwrite_unescape" in labels

    scorer = td.ThreatScorer()
    scorer.add(labels, "mock page")
    assert "classic_exploit_kit" in scorer.clusters
    assert scorer.should_trigger_decoy(), f"score {scorer.score} below threshold 60"
