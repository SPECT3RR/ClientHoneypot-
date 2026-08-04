"""
Operator classifier — scanner bot or human operator?

The discriminator itself is not new. ownership_manager.py and the init script
in browser_controller.py already classify input by `e.isTrusted` and track
activity/idle transitions; they were written to detect a human taking over
our bot. Pointed at the decoy's visitors, the same mechanism detects a human
driving the attacker's session. Same signal, mirrored.

Why it matters: tier-2 tokens are finite and expensive. Burning a real
canarytoken on an automated scanner teaches attacker tooling what our bait
looks like and wastes the token. A human operator poking around a file
server is the visitor worth spending on.

Threshold is 60, matching threat_detection.DECOY_TRIGGER_THRESHOLD so both
sides of the platform speak the same scale.
"""
import re
import time

OPERATOR_THRESHOLD = 60

# Paths only automated tooling asks for. A human clicking a portal never
# requests .env or wp-admin.
SCANNER_PATHS = re.compile(
    r"/(robots\.txt|\.env|\.git|wp-admin|wp-login|phpmyadmin|admin\.php"
    r"|\.aws/|config\.json|backup\.zip|\.ds_store)", re.IGNORECASE)

SCANNER_AGENTS = re.compile(
    r"(curl|wget|python-requests|python-urllib|go-http|java/|libwww|scrapy"
    r"|nikto|sqlmap|nmap|masscan|zgrab|httpx|feroxbuster|gobuster|dirb"
    r"|postman|insomnia|axios|node-fetch|okhttp|headlesschrome|phantomjs)",
    re.IGNORECASE)

# Weighting note — isTrusted is NOT the discriminator.
#
# CDP-driven automation (Playwright, Puppeteer, Selenium) dispatches through
# the browser's real input pipeline, so its events carry isTrusted=true.
# The flag only filters dispatchEvent-style fakes. Weighting it heavily would
# hand tier 2 to any attacker driving a headless browser — which is most of
# them. ownership_manager.py never relied on it alone either; it pairs the
# flag with an explicit bot-action boundary.
#
# What automation does NOT reproduce cheaply is the *shape* of human input:
# interpolated mouse paths are straight and evenly spaced, and scripted
# typing is metronomic. Those carry the weight here.
SIGNALS = {
    "mouse_entropy":        30,   # direction reversals — real hands wander
    "typing_cadence":       25,   # variable inter-key delay
    "nonlinear_navigation": 15,   # back, revisit, branch
    "trusted_input":        15,   # necessary, nowhere near sufficient
    "human_dwell":          10,   # first interaction in 1.5s..120s
    "linear_mouse":        -25,   # movement with near-zero entropy: scripted
    "scanner_agent":       -25,
    "sequential_paths":    -30,
    "scanner_path":        -30,
    "no_js":               -50,   # never solved the entry gate
}

# Below this, reported pointer movement is an interpolated straight line
# rather than a hand. Playwright's mouse.move(steps=n) sits at ~0.
LINEAR_MOUSE_ENTROPY = 0.12


class VisitorProfile:
    """Accumulates evidence about one decoy visitor."""

    def __init__(self, visitor_id: str, user_agent: str = "", src_ip: str = ""):
        self.visitor_id = visitor_id
        self.user_agent = user_agent or ""
        self.src_ip = src_ip or ""
        self.first_seen = time.time()
        self.paths: list = []
        self.signals: set = set()
        self.js_solved = False
        self.tier_reached = 0

        if SCANNER_AGENTS.search(self.user_agent):
            self.signals.add("scanner_agent")

    # ── evidence ───────────────────────────────────────────────────────────

    def note_path(self, path: str) -> None:
        self.paths.append(path)
        if SCANNER_PATHS.search(path):
            self.signals.add("scanner_path")
        if len(self.paths) >= 4 and self._looks_enumerated():
            self.signals.add("sequential_paths")
        if self._revisited():
            self.signals.add("nonlinear_navigation")

    def _looks_enumerated(self) -> bool:
        """Bots walk a wordlist: many distinct paths, none revisited, fast."""
        if len(set(self.paths)) != len(self.paths):
            return False
        elapsed = time.time() - self.first_seen
        return len(self.paths) >= 4 and elapsed < len(self.paths) * 1.0

    def _revisited(self) -> bool:
        return len(self.paths) >= 3 and len(set(self.paths)) < len(self.paths)

    def note_js_solved(self) -> None:
        self.js_solved = True

    def note_interaction(self, kind: str, trusted: bool,
                         mouse_entropy: float = 0.0,
                         key_intervals: list = None) -> None:
        """Report an input event observed on the decoy page."""
        if not trusted:
            return  # synthetic events prove nothing
        self.signals.add("trusted_input")

        elapsed = time.time() - self.first_seen
        if 1.5 <= elapsed <= 120:
            self.signals.add("human_dwell")

        if kind == "mousemove":
            if mouse_entropy >= 0.35:
                self.signals.add("mouse_entropy")
            elif mouse_entropy < LINEAR_MOUSE_ENTROPY:
                # Moved, but in a straight interpolated line. That is a
                # driver, not a hand.
                self.signals.add("linear_mouse")

        if key_intervals and self._variable_cadence(key_intervals):
            self.signals.add("typing_cadence")

    @staticmethod
    def _variable_cadence(intervals: list) -> bool:
        """Humans type unevenly; a script pastes at a constant rate."""
        vals = [i for i in intervals if i is not None]
        if len(vals) < 4:
            return False
        mean = sum(vals) / len(vals)
        if mean <= 0:
            return False
        variance = sum((v - mean) ** 2 for v in vals) / len(vals)
        return (variance ** 0.5) / mean > 0.25

    # ── verdict ────────────────────────────────────────────────────────────

    @property
    def score(self) -> int:
        signals = set(self.signals)
        if not self.js_solved:
            signals.add("no_js")
        return max(0, sum(SIGNALS.get(s, 0) for s in signals))

    @property
    def classification(self) -> str:
        if self.score >= OPERATOR_THRESHOLD:
            return "human_operator"
        if "trusted_input" in self.signals or self.js_solved:
            return "unclear"
        return "bot"

    def may_reach_tier(self, tier: int) -> bool:
        """Tier 0 open, tier 1 needs the JS gate, tier 2 needs a human."""
        if tier <= 0:
            return True
        if tier == 1:
            return self.js_solved
        return self.js_solved and self.score >= OPERATOR_THRESHOLD

    def summary(self) -> dict:
        return {
            "visitor_id": self.visitor_id,
            "src_ip": self.src_ip,
            "user_agent": self.user_agent[:200],
            "score": self.score,
            "classification": self.classification,
            "js_solved": self.js_solved,
            "signals": sorted(self.signals),
            "paths": self.paths[-25:],
            "tier_reached": self.tier_reached,
        }


class OperatorRegistry:
    """Tracks every visitor to the decoy for the life of the process."""

    def __init__(self):
        self._visitors: dict = {}

    def get(self, visitor_id: str, user_agent: str = "",
            src_ip: str = "") -> VisitorProfile:
        profile = self._visitors.get(visitor_id)
        if profile is None:
            profile = VisitorProfile(visitor_id, user_agent, src_ip)
            self._visitors[visitor_id] = profile
        return profile

    def all(self) -> list:
        return [v.summary() for v in self._visitors.values()]

    def humans(self) -> list:
        return [v.summary() for v in self._visitors.values()
                if v.classification == "human_operator"]
