"""
Persona Generator + Fingerprint Manager (spec Components 2 & 3, merged).

Generates a synthetic "employee" identity that stays internally consistent
for the whole session (same OS/browser/fonts/timezone/etc. for the life of
a persona) plus a bit of synthetic browsing furniture (bookmarks, fake
recent downloads) used to make the profile look lived-in.

Every field is fictional. No real person, company, or credential is ever
referenced.
"""
import json
import random
import uuid
from pathlib import Path

CONFIG_DIR = Path(__file__).parent.parent / "config"

PERSONA_LIBRARY = {
    "finance_qatar": {
        "employee_name": "Layla Haddad",  # synthetic
        "department": "Finance",
        "os": "Windows 11 Enterprise",
        "os_ua_token": "Windows NT 10.0; Win64; x64",
        "browser_version": "126.0.6478.127",
        "timezone_id": "Asia/Qatar",
        "locale": "en-US",
        "secondary_language": "ar",
        "screen": {"width": 1920, "height": 1080},
        "work_hours": {"start": 8, "end": 17},
        "cpu_count": 8,
        "device_memory_gb": 8,
        "webgl_vendor": "Google Inc. (Intel)",
        "webgl_renderer": "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0)",
        "fonts": ["Arial", "Calibri", "Segoe UI", "Tahoma", "Times New Roman"],
        "bookmarks": [
            "https://outlook.office.com/mail/",
            "https://www.investing.com/",
            "https://portal.asteriaholdings.example/finance",
        ],
        "recent_downloads": ["Q2_budget_review.pdf", "vendor_invoice_0417.pdf"],
        "search_habits": ["exchange rate USD QAR", "excel vlookup tutorial", "sap gui login"],
    },
    "hr_generic": {
        "employee_name": "Marcus Whitfield",  # synthetic
        "department": "Human Resources",
        "os": "Windows 11 Pro",
        "os_ua_token": "Windows NT 10.0; Win64; x64",
        "browser_version": "126.0.6478.127",
        "timezone_id": "America/New_York",
        "locale": "en-US",
        "secondary_language": None,
        "screen": {"width": 1536, "height": 864},
        "work_hours": {"start": 9, "end": 18},
        "cpu_count": 4,
        "device_memory_gb": 8,
        "webgl_vendor": "Google Inc. (NVIDIA)",
        "webgl_renderer": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0)",
        "fonts": ["Arial", "Calibri", "Segoe UI", "Verdana"],
        "bookmarks": [
            "https://portal.asteriaholdings.example/hr",
            "https://www.linkedin.com/",
            "https://www.indeed.com/",
        ],
        "recent_downloads": ["onboarding_checklist.pdf", "benefits_summary_2026.pdf"],
        "search_habits": ["employee handbook template", "PTO policy sample", "background check vendors"],
    },
}


def load_persona(name: str) -> dict:
    if name not in PERSONA_LIBRARY:
        raise ValueError(f"Unknown persona '{name}'. Options: {list(PERSONA_LIBRARY)}")
    persona = dict(PERSONA_LIBRARY[name])
    persona["persona_id"] = str(uuid.uuid4())
    persona["user_agent"] = (
        f"Mozilla/5.0 ({persona['os_ua_token']}) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{persona['browser_version']} Safari/537.36"
    )
    return persona


def save_persona_snapshot(persona: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"persona_{persona['persona_id']}.json"
    path.write_text(json.dumps(persona, indent=2), encoding="utf-8")
    return path


def fingerprint_init_script(persona: dict) -> str:
    """
    JS injected via add_init_script BEFORE any page script runs, so
    navigator/canvas/webgl overrides are consistent from the first paint.
    This is a fingerprint-consistency layer, not an anti-analysis exploit:
    its only job is to make a real headless Chromium report properties
    consistent with the declared persona (e.g. not "HeadlessChrome"),
    the same way any privacy-respecting browser fingerprint-randomization
    extension does.
    """
    fonts_js = json.dumps(persona["fonts"])
    return f"""
    Object.defineProperty(navigator, 'webdriver', {{ get: () => undefined }});
    Object.defineProperty(navigator, 'hardwareConcurrency', {{ get: () => {persona['cpu_count']} }});
    Object.defineProperty(navigator, 'deviceMemory', {{ get: () => {persona['device_memory_gb']} }});
    Object.defineProperty(navigator, 'languages', {{ get: () => ['{persona['locale']}'] }});
    Object.defineProperty(navigator, 'platform', {{ get: () => 'Win32' }});

    const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(parameter) {{
        if (parameter === 37445) return '{persona['webgl_vendor']}';
        if (parameter === 37446) return '{persona['webgl_renderer']}';
        return originalGetParameter.call(this, parameter);
    }};

    window.__personaFonts = {fonts_js};
    """
