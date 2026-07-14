from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class UserContextModel:
    """
    Maintains a rich, evolving session context to inform the Interaction Scheduler.
    Replaces basic session memory with structured historical intelligence.
    """
    current_page: str = ""
    navigation_history: List[str] = field(default_factory=list)
    visited_forms: List[str] = field(default_factory=list)
    open_tabs: int = 1
    read_duration_seconds: float = 0.0
    previous_login_attempts: int = 0
    
    # Evolving behavioral profile from Analyst Mode learning
    mouse_profile: Dict[str, Any] = field(default_factory=lambda: {"entropy": 0.8})
    typing_profile: Dict[str, Any] = field(default_factory=lambda: {"wpm": 60})
    active_intent: str = "unknown"
    
    def update_page(self, url: str) -> None:
        """Update current page and append to navigation history."""
        self.current_page = url
        self.navigation_history.append(url)
        
    def add_read_duration(self, seconds: float) -> None:
        """Accumulate total reading time."""
        self.read_duration_seconds += seconds
        
    def record_login_attempt(self) -> None:
        """Record a login attempt."""
        self.previous_login_attempts += 1

    def record_visited_form(self, form_id: str) -> None:
        """Record that a specific form was interacted with."""
        if form_id not in self.visited_forms:
            self.visited_forms.append(form_id)
