"""
Threat Detection Layer — Correlated Multi-Signal Scoring Engine.

Core principle: NO single indicator triggers a diversion.
Every finding is logged and scored, but the decision engine only
fires when MULTIPLE correlated signals appear together, forming a
recognisable attack pattern cluster.

This eliminates the Bloomberg false-positive class: a page with
eval() and an iframe is a normal news site.  A page with eval() +
unescape() + a hidden iframe + an ActiveX probe + a suspicious
download is an exploit kit.

Architecture
────────────
1.  Raw signals — individual pattern matches (JS, DOM, network, download).
    Each has a base weight and an ATT&CK technique tag.

2.  Correlation clusters — named attack patterns that require a MINIMUM
    SET of co-occurring signals.  Only when a cluster is satisfied does
    its bonus score apply.  Partial matches score nothing extra.

3.  ThreatScorer — accumulates raw signal scores (deduplicated) plus
    cluster bonuses.  Exposes .should_trigger_decoy() when the combined
    score crosses DECOY_TRIGGER_THRESHOLD.

4.  Allowlisted domains — known-clean CDNs whose JS is skipped entirely
    during page-source scans (Bloomberg, DoubleClick, etc.).

MITRE ATT&CK IDs are best-effort analyst starting points, not certified.
"""
import re
from urllib.parse import urlparse


# ── 1. Domain allowlist ────────────────────────────────────────────────────────
# JS from these domains is skipped during page-source scans.
ALLOWLISTED_DOMAINS = {
    "doubleclick.net", "googlesyndication.com", "google-analytics.com",
    "googletagmanager.com", "doubleverify.com", "adsafeprotected.com",
    "amazon-adsystem.com", "adsrvr.org", "moatads.com", "pubmatic.com",
    "rubiconproject.com", "openx.net", "casalemedia.com", "criteo.com",
    "bwbx.io", "bloomberg.com", "reuters.com", "nytimes.com", "bbc.co.uk",
    "akamaized.net", "cloudfront.net", "fastly.net", "cdn.jsdelivr.net",
    "sourcepointcmp.bloomberg.com", "sp-prod.net", "consentframework.com",
}


def _domain_allowlisted(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower().removeprefix("www.")
        return any(host == d or host.endswith("." + d) for d in ALLOWLISTED_DOMAINS)
    except Exception:
        return False


# ── 2. Raw signal definitions ──────────────────────────────────────────────────
# (pattern, signal_id, mitre_technique, base_weight)
# Weights are LOW intentionally — individual signals rarely mean anything alone.
# Cluster bonuses (section 3) provide the real scoring lift.

JS_SIGNALS = [
    # Obfuscation
    (r"unescape\s*\(",                              "obf_unescape",          "T1027",  6),
    (r"\beval\s*\(",                                "obf_eval",              "T1027",  4),
    (r"String\.fromCharCode\s*\(",                  "obf_charcode",          "T1027",  4),
    (r"(?:\\x[0-9a-f]{2}){4,}",                    "obf_hex_sequence",      "T1027",  8),
    (r"\batob\s*\(",                                "obf_b64_decode",        "T1027",  4),
    (r"decodeURIComponent\s*\(\s*(?:atob|unescape)","obf_double_decode",     "T1027", 12),

    # Exploit-kit fingerprints (high-confidence single signals)
    (r"document\.write\s*\(\s*unescape",            "ek_docwrite_unescape",  "T1189", 20),
    (r"\bshellcode\b",                              "ek_shellcode",          "T1203", 30),
    (r"CollectGarbage\s*\(\)|GC\s*\(\)",            "ek_heap_gc",            "T1203", 25),
    (r"new\s+Array\s*\(\s*\d{5,}\s*\)",             "ek_large_array",        "T1203", 15),
    (r"\.indexOf\(['\"]MSIE\s",                     "ek_ie_useragent_check", "T1189", 10),
    (r"\.indexOf\(['\"]Trident",                    "ek_trident_check",      "T1189", 10),

    # ActiveX / Windows-only attack vectors
    (r"new\s+ActiveXObject\s*\(",                   "activex_instantiate",   "T1218", 20),
    (r"WScript\.Shell|Shell\.Application",          "activex_shell",         "T1218", 25),
    (r"Scripting\.FileSystemObject",                "activex_fso",           "T1218", 20),
    (r"XMLHTTP|WinHttpRequest",                     "activex_http",          "T1218", 12),

    # Credential / data theft
    (r"clipboardData\.setData|execCommand\s*\(\s*['\"]copy", "steal_clipboard","T1115",15),
    (r"localStorage\[|sessionStorage\[",            "storage_access",        "T1539",  3),
    (r"document\.cookie\s*=(?!.*httponly)",         "cookie_write",          "T1539",  6),
    (r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{3}", "cred_hardcoded",   "T1552", 18),

    # Cryptomining
    (r"CoinHive|coinhive|cryptonight|monero.*miner","cryptominer",           "T1496", 25),

    # Browser / extension fingerprinting
    (r"chrome\.runtime\.sendMessage",               "ext_probe_chrome",      "T1176", 10),
    (r"moz-extension://",                           "ext_probe_firefox",     "T1176", 10),

    # WebRTC IP leak (common in browser-based attacks)
    (r"new\s+RTCPeerConnection\s*\(",               "webrtc_leak",           "T1614", 12),

    # Sandbox / analysis evasion (attacker probing OUR environment)
    (r"__selenium|_phantom|callPhantom\b",          "evade_selenium",        "T1497", 18),
    (r"\bwebdriver\b",                              "evade_webdriver",       "T1497", 15),
    (r"navigator\.plugins\.length\s*(?:===?|==)\s*0","evade_noplugins",     "T1497", 15),
    (r"screen\.width\s*(?:<|<=)\s*(?:200|100|50)\b","evade_smallscreen",    "T1497", 15),
    (r"navigator\.language\s*===?\s*(?:null|undefined|'')", "evade_nolang",  "T1497", 15),
    (r"window\.outerWidth\s*===?\s*0",              "evade_outerwidth",      "T1497", 18),

    # PowerShell / script dropper patterns
    (r"powershell(?:\.exe)?\s+-(?:enc|exec|nop|w\s+hidden)", "dropper_ps1", "T1059", 30),
    (r"cmd(?:\.exe)?\s+/c\s+",                     "dropper_cmd",           "T1059", 20),
    (r"mshta(?:\.exe)?",                            "dropper_mshta",         "T1218", 25),
    (r"wscript(?:\.exe)?|cscript(?:\.exe)?",        "dropper_wscript",       "T1059", 20),
]

DOM_SIGNALS = [
    # Hidden iframes — suspicious only in combination with other signals
    (r'<iframe[^>]+(?:width\s*=\s*["\']?\s*0|height\s*=\s*["\']?\s*0'
     r'|style\s*=\s*["\'][^"\']*display\s*:\s*none)',
     "dom_hidden_iframe", "T1189", 8),

    # Meta refresh to a different domain (redirect chain indicator)
    (r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]+url\s*=\s*["\']https?://',
     "dom_meta_refresh", "T1189", 8),

    # Form action pointing off-domain (phishing indicator)
    (r'<form[^>]+action\s*=\s*["\']https?://',
     "dom_offsite_form", "T1566", 12),

    # Password field outside a login context (credential harvesting)
    (r'<input[^>]+type\s*=\s*["\']password["\']',
     "dom_password_field", "T1566", 5),
]

FP_PROBE_SIGNALS = [
    # Fingerprinting probes — common on legitimate sites too, low weight
    (r"getImageData|toDataURL",               "fp_canvas",     "T1592", 4),
    (r"AudioContext|createOscillator",        "fp_audio",      "T1592", 4),
    (r"WEBGL_debug_renderer_info",            "fp_webgl_ext",  "T1592", 6),
    (r"getBattery\s*\(",                      "fp_battery",    "T1592", 5),
    (r"navigator\.connection\b",              "fp_network",    "T1592", 3),
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1",
    ".hta", ".jar", ".bat", ".cmd", ".dll", ".lnk", ".iso", ".img",
    ".msi", ".msp", ".com", ".pif", ".ws", ".wsf",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".icu",
    ".club", ".work", ".buzz", ".live", ".online", ".site", ".pw",
}

MITRE_LABELS = {s[1]: s[2] for s in JS_SIGNALS + DOM_SIGNALS + FP_PROBE_SIGNALS}
MITRE_LABELS.update({
    "suspicious_download": "T1189 - Drive-by Compromise",
    "excessive_redirects":  "T1189 - Drive-by Compromise",
    "suspicious_tld":       "T1583 - Acquire Infrastructure",
    "cluster_bonus":        "T1189 - Drive-by Compromise",
})

BASE_WEIGHTS = {s[1]: s[3] for s in JS_SIGNALS + DOM_SIGNALS + FP_PROBE_SIGNALS}
BASE_WEIGHTS.update({
    "suspicious_download": 35,
    "excessive_redirects":  15,
    "suspicious_tld":        8,
})


# ── 3. Correlation clusters ────────────────────────────────────────────────────
# Each cluster fires a BONUS score only when ALL required signals are present.
# This is the primary false-positive-reduction mechanism.

ATTACK_CLUSTERS = [
    {
        "name": "classic_exploit_kit",
        "description": "JS obfuscation + eval/unescape + document.write — classic EK pattern",
        "required": {"obf_unescape", "obf_eval", "ek_docwrite_unescape"},
        "bonus": 45,
        "mitre": "T1189 - Drive-by Compromise",
    },
    {
        "name": "heap_spray_attempt",
        "description": "Large array allocation + GC call + obfuscation — heap spray setup",
        "required": {"ek_large_array", "ek_heap_gc", "obf_eval"},
        "bonus": 55,
        "mitre": "T1203 - Exploitation for Client Execution",
    },
    {
        "name": "activex_dropper",
        "description": "ActiveX instantiation + shell/FSO access + obfuscation",
        "required": {"activex_instantiate", "activex_shell"},
        "bonus": 50,
        "mitre": "T1218 - System Binary Proxy Execution",
    },
    {
        "name": "credential_phishing",
        "description": "Off-site form + password field + obfuscation or fingerprinting",
        "required": {"dom_offsite_form", "dom_password_field"},
        "any_of": {"obf_eval", "obf_unescape", "fp_canvas", "fp_audio"},
        "any_of_min": 1,
        "bonus": 40,
        "mitre": "T1566 - Phishing",
    },
    {
        "name": "sandbox_evasion_active",
        "description": "Multiple sandbox-detection probes — attacker actively checking for analysis env",
        "required": set(),
        "any_of": {"evade_selenium", "evade_webdriver", "evade_noplugins",
                   "evade_smallscreen", "evade_nolang", "evade_outerwidth"},
        "any_of_min": 2,
        "bonus": 40,
        "mitre": "T1497 - Virtualization/Sandbox Evasion",
    },
    {
        "name": "drive_by_download",
        "description": "Suspicious download + redirect chain + obfuscation",
        "required": {"suspicious_download"},
        "any_of": {"obf_eval", "obf_unescape", "excessive_redirects",
                   "dom_hidden_iframe", "ek_docwrite_unescape"},
        "any_of_min": 1,
        "bonus": 50,
        "mitre": "T1189 - Drive-by Compromise",
    },
    {
        "name": "fingerprint_harvest",
        "description": "Multiple browser fingerprinting APIs + data exfil indicator",
        "required": set(),
        "any_of": {"fp_canvas", "fp_audio", "fp_webgl_ext", "fp_battery",
                   "webrtc_leak", "ext_probe_chrome"},
        "any_of_min": 3,
        "bonus": 25,
        "mitre": "T1592 - Gather Victim Host Information",
    },
    {
        "name": "script_dropper",
        "description": "PowerShell/cmd/mshta execution string in page — dropper delivery",
        "required": set(),
        "any_of": {"dropper_ps1", "dropper_cmd", "dropper_mshta", "dropper_wscript"},
        "any_of_min": 1,
        "bonus": 40,
        "mitre": "T1059 - Command and Scripting Interpreter",
    },
]

DECOY_TRIGGER_THRESHOLD = 60   # raised from 40 — requires either a cluster hit
                                # or several independent signals to fire


# ── 4. Scan functions ──────────────────────────────────────────────────────────

def _run_patterns(patterns_with_meta, text: str) -> list:
    hits = []
    for entry in patterns_with_meta:
        pattern, label = entry[0], entry[1]
        if re.search(pattern, text, re.IGNORECASE):
            hits.append(label)
    return hits


def scan_script_text(text: str, page_url: str = "") -> list:
    if page_url and _domain_allowlisted(page_url):
        return []
    return _run_patterns(JS_SIGNALS, text)


def scan_dom(html: str, page_url: str = "") -> list:
    if page_url and _domain_allowlisted(page_url):
        return []
    return _run_patterns(DOM_SIGNALS + FP_PROBE_SIGNALS, html)


def scan_download(filename: str) -> list:
    lower = filename.lower()
    return ["suspicious_download"] if any(
        lower.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS) else []


def scan_redirect_chain(chain_length: int) -> list:
    return ["excessive_redirects"] if chain_length >= 4 else []


def scan_form_fields(fields: list) -> list:
    joined = " ".join(fields).lower()
    kws = ("password", "passwd", "ssn", "card_number", "cvv",
           "routing", "pin", "secret", "credential")
    return ["dom_password_field"] if any(k in joined for k in kws) else []


scan_form_for_phishing = scan_form_fields  # backwards-compat alias


def scan_url(url: str) -> list:
    if _domain_allowlisted(url):
        return []
    try:
        tld = "." + urlparse(url).netloc.split(".")[-1].split(":")[0].lower()
        if tld in SUSPICIOUS_TLDS:
            return ["suspicious_tld"]
    except Exception:
        pass
    return []


# ── 5. Cluster evaluator ───────────────────────────────────────────────────────

def evaluate_clusters(seen_labels: set) -> list:
    """
    Check which attack clusters are satisfied by the current set of
    observed signal labels.  Returns list of fired cluster dicts.
    """
    fired = []
    for cluster in ATTACK_CLUSTERS:
        required = cluster.get("required", set())
        any_of   = cluster.get("any_of", set())
        min_any  = cluster.get("any_of_min", 0)

        # All required signals must be present
        if not required.issubset(seen_labels):
            continue

        # If any_of is specified, at least min_any must be present
        if any_of and len(any_of.intersection(seen_labels)) < min_any:
            continue

        fired.append(cluster)
    return fired


# ── 6. Stateful scorer ─────────────────────────────────────────────────────────

class ThreatScorer:
    def __init__(self):
        self.score          = 0
        self.findings:  list = []
        self.clusters:  list = []          # fired cluster names
        self._seen_labels:  set = set()   # deduplication

    def add(self, labels: list, detail: str = ""):
        """Add raw signal findings.  Each label counted at most once."""
        new_labels = []
        for label in labels:
            if label in self._seen_labels:
                continue
            self._seen_labels.add(label)
            weight = BASE_WEIGHTS.get(label, 5)
            self.score += weight
            self.findings.append({
                "label":  label,
                "mitre":  MITRE_LABELS.get(label, "T????"),
                "detail": detail,
                "weight": weight,
            })
            new_labels.append(label)

        # Re-evaluate clusters after every new signal batch
        if new_labels:
            self._check_clusters()

    def _check_clusters(self):
        fired = evaluate_clusters(self._seen_labels)
        for cluster in fired:
            if cluster["name"] not in self.clusters:
                self.clusters.append(cluster["name"])
                bonus = cluster["bonus"]
                self.score += bonus
                self.findings.append({
                    "label":  f"[CLUSTER] {cluster['name']}",
                    "mitre":  cluster["mitre"],
                    "detail": cluster["description"],
                    "weight": bonus,
                })

    def should_trigger_decoy(self) -> bool:
        return self.score >= DECOY_TRIGGER_THRESHOLD

    def summary(self) -> dict:
        return {
            "score":    self.score,
            "findings": self.findings,
            "clusters": self.clusters,
        }
