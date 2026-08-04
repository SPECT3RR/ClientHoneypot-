import json
import pytest

from verdict_db import VerdictDB
from canary_vault import CanaryVault, default_seed_tokens
from bait_seeder import BaitSeeder

PERSONA = {"employee_name": "Layla Haddad", "department": "Finance"}


@pytest.fixture
def vault(tmp_path):
    db = VerdictDB(db_path=tmp_path / "v.db", session_id="s1")
    yield CanaryVault(db)
    db.close()


# ── vault ──────────────────────────────────────────────────────────────────

def test_operator_can_register_a_real_canary(vault):
    tid = vault.add("aws_key", "AKIAREALCANARY123", "browser_profile",
                    label="canarytokens.org prod")
    rows = vault.for_placement("browser_profile")
    assert len(rows) == 1 and rows[0]["token_id"] == tid


def test_unknown_placement_is_rejected(vault):
    with pytest.raises(ValueError):
        vault.add("aws_key", "x", "somewhere_else")


def test_minted_url_token_is_self_hosted(vault):
    tid, url = vault.mint_url_token("decoy_tier2", label="crown-jewels")
    assert url.endswith(f"/c/{tid}")


def test_hit_identifies_the_session_that_planted_it(vault):
    tid = vault.add("url_token", "http://x/c/abc", "browser_profile", label="vpn")
    vault.stamp(tid, "session_042")

    hit = vault.record_hit(tid, src_ip="203.0.113.9", user_agent="curl/8")
    # The whole point: a callback days later still names the origin visit.
    assert hit["origin_session"] == "session_042"
    assert hit["src_ip"] == "203.0.113.9"
    assert vault.stats()["burned"] == 1


def test_hit_on_an_unknown_token_is_ignored(vault):
    assert vault.record_hit("not-a-real-token") is None


def test_burned_tokens_are_not_placed_again(vault):
    tid = vault.add("url_token", "http://x/c/a", "browser_profile")
    vault.record_hit(tid)
    assert vault.for_placement("browser_profile") == []


def test_empty_vault_is_seeded_rather_than_blocking_the_hunt(vault):
    # Degraded intelligence beats a hunt that refuses to run.
    minted = default_seed_tokens(vault)
    assert len(minted) == 3
    assert len(vault.for_placement("browser_profile")) == 3
    # Idempotent: a second call must not keep minting.
    assert default_seed_tokens(vault) == []


# ── seeder ─────────────────────────────────────────────────────────────────

def test_seed_writes_bait_where_infostealers_look(tmp_path, vault):
    default_seed_tokens(vault)
    profile = tmp_path / "profile"
    seeder = BaitSeeder(profile, "abc123session", PERSONA, vault=vault)
    result = seeder.seed()

    downloads = profile.parent / "Downloads" / "abc123session"
    names = {p.name for p in downloads.iterdir()}
    assert {"credentials.txt", "vpn_config.ovpn", "aws_credentials"} <= names

    bookmarks = json.loads((profile / "Default" / "Bookmarks").read_text())
    urls = [c["url"] for c in bookmarks["roots"]["bookmark_bar"]["children"]]
    assert any("portal/login" in u for u in urls)

    assert len(result["planted_tokens"]) == 3
    assert result["callback_urls"]


def test_planted_tokens_are_stamped_with_this_session(vault, tmp_path):
    default_seed_tokens(vault)
    BaitSeeder(tmp_path / "p", "sess_xyz", PERSONA, vault=vault).seed()
    assert all(r["session_id"] == "sess_xyz" for r in vault.all())


def test_init_script_seeds_web_storage(tmp_path, vault):
    seeder = BaitSeeder(tmp_path / "p", "sess1", PERSONA, vault=vault)
    seeder.seed()
    js = seeder.init_script(seeder.tokens)
    assert "localStorage.setItem" in js
    assert "asteria_api_key" in js
    assert "sess_sess1" in js


def test_cookies_target_the_decoy_domain(tmp_path, vault):
    seeder = BaitSeeder(tmp_path / "p", "sess1", PERSONA, vault=vault)
    seeder.seed()
    cookies = seeder.cookies(seeder.tokens)
    assert {c["name"] for c in cookies} == {"sid", "asteria_auth"}
    assert all(c["domain"] == "127.0.0.1" for c in cookies)


def test_operator_aws_canary_overrides_the_synthetic_one(tmp_path, vault):
    vault.add("aws_key", "AKIATHEREALCANARY", "browser_profile", label="secret")
    seeder = BaitSeeder(tmp_path / "p", "sess1", PERSONA, vault=vault)
    seeder.seed()
    assert seeder.tokens["aws_key"] == "AKIATHEREALCANARY"
    creds = (tmp_path / "Downloads" / "sess1" / "aws_credentials").read_text()
    assert "AKIATHEREALCANARY" in creds


def test_seeding_works_with_no_vault_at_all(tmp_path):
    # Bait must still be planted when the operator has supplied nothing.
    seeder = BaitSeeder(tmp_path / "p", "sess1", PERSONA, vault=None)
    result = seeder.seed()
    assert result["planted_tokens"] == []
    assert (tmp_path / "Downloads" / "sess1" / "credentials.txt").exists()
