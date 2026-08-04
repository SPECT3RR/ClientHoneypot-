from nav_replay import build_journey, REFERRER_CHAINS, PERSONA_CHAIN_MAP


def test_journey_ends_at_the_real_target():
    j = build_journey("http://evil.example/payload", "finance_qatar")
    assert j.target == "http://evil.example/payload"
    assert j.hops, "arriving with no referrer at all is itself a bot signal"


def test_persona_selects_a_plausible_entry_path():
    j = build_journey("http://x/", "hr_generic")
    valid = set()
    for key in PERSONA_CHAIN_MAP["hr_generic"]:
        valid.update(REFERRER_CHAINS[key])
    assert set(j.hops) <= valid


def test_unknown_persona_falls_back_rather_than_raising():
    j = build_journey("http://x/", "not_a_persona")
    assert j.hops


def test_custom_chain_is_honoured():
    chain = ["https://a.example/", "https://b.example/"]
    assert build_journey("http://x/", "finance_qatar", custom_chain=chain).hops == chain


def test_journeys_vary_between_sessions():
    # Identical hop sequences every run are their own fingerprint.
    seen = {tuple(build_journey("http://x/", "hr_generic").hops) for _ in range(40)}
    assert len(seen) > 1
