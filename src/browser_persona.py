import yaml
from pathlib import Path
from typing import Dict, Any

class BrowserPersonaManager:
    """
    Initializes and maintains a consistent browser environment (e.g., locale, display characteristics,
    browsing state, and session artifacts) to support realistic user simulation.
    """
    def __init__(self, config_path: str = "config/persona.yaml"):
        self.config_path = Path(config_path)
        self.static_persona: Dict[str, Any] = {}
        self.dynamic_persona: Dict[str, Any] = {}
        self.load_config()

    def load_config(self) -> None:
        if self.config_path.exists():
            with open(self.config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
                if config:
                    self.static_persona = config.get("static_persona", {})
                    self.dynamic_persona = config.get("dynamic_persona", {})
                
    def get_playwright_context_args(self) -> Dict[str, Any]:
        """Return the arguments needed for Playwright's browser.new_context()."""
        args = {}
        if "locale" in self.static_persona:
            args["locale"] = self.static_persona["locale"]
        if "timezone" in self.static_persona:
            args["timezone_id"] = self.static_persona["timezone"]
        if "screen_resolution" in self.static_persona:
            args["viewport"] = {
                "width": self.static_persona["screen_resolution"].get("width", 1920),
                "height": self.static_persona["screen_resolution"].get("height", 1080)
            }
        return args
