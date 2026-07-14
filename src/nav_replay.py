"""
Navigation Replay Engine (spec Component 5).

Never visits a suspicious URL cold.  Instead it builds a realistic
browsing journey — news site → article → ad network → tracker →
redirect chain → landing page — so the target sees a believable
referrer, cookies from prior hops, and a natural timing profile.

REFERRER_CHAINS is a library of realistic entry paths keyed by
"campaign type".  You can extend it freely.  Each hop is visited
in order; the final entry in the chain should be the actual target
URL (inserted at call time by build_journey).
"""
import random
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Hop library — all domains here are real, non-malicious sites used as
# the *preamble* to the suspicious URL so referrers look organic.
# ---------------------------------------------------------------------------
REFERRER_CHAINS = {
    "finance_news": [
        "https://www.reuters.com/",
        "https://www.bloomberg.com/markets",
        "https://finance.yahoo.com/",
    ],
    "hr_linkedin": [
        "https://www.linkedin.com/feed/",
        "https://www.linkedin.com/jobs/",
    ],
    "generic_search": [
        "https://www.google.com/",
        "https://www.google.com/search?q=enterprise+software+download",
    ],
    "tech_news": [
        "https://news.ycombinator.com/",
        "https://www.theregister.com/",
    ],
    "email_click": [
        # Simulates clicking a link inside Outlook Web Access
        "https://outlook.office.com/mail/inbox",
    ],
}

PERSONA_CHAIN_MAP = {
    "finance_qatar": ["finance_news", "email_click"],
    "hr_generic": ["hr_linkedin", "email_click", "generic_search"],
}


@dataclass
class Journey:
    hops: list   # ordered list of URLs to visit before the target
    target: str
    persona_name: str


def build_journey(target_url: str, persona_name: str,
                  custom_chain: list = None) -> Journey:
    """
    Select an appropriate referrer chain for the persona, optionally
    trimmed to a random length so timing varies between sessions, then
    append the target URL as the final hop.
    """
    if custom_chain:
        chain = list(custom_chain)
    else:
        options = PERSONA_CHAIN_MAP.get(persona_name, ["generic_search"])
        key = random.choice(options)
        chain = list(REFERRER_CHAINS[key])
        # Randomly drop 0-1 hops from the front for variety
        if len(chain) > 1 and random.random() < 0.4:
            chain = chain[1:]

    return Journey(hops=chain, target=target_url, persona_name=persona_name)
