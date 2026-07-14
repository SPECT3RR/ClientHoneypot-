"""
Decision Engine (spec Component 8).

Given the running ThreatScorer, decide whether to keep browsing normally
or divert into the decoy enterprise environment.
"""

DECOY_BASE_URL = "http://127.0.0.1:8001"


def decide(scorer) -> dict:
    if scorer.should_trigger_decoy():
        return {
            "action": "divert_to_decoy",
            "target": f"{DECOY_BASE_URL}/portal/login",
            "reason": scorer.summary(),
        }
    return {"action": "continue", "reason": scorer.summary()}
