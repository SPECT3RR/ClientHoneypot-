from typing import Protocol, List, Dict, Any

class IntentPlugin(Protocol):
    """Base interface for behavioral intent profiles."""
    
    def profile_name(self) -> str:
        """Return the name of the intent profile (e.g., 'professional', 'consumer')."""
        ...
        
    def get_supported_domains(self) -> List[str]:
        """Return a list of domains this profile covers."""
        ...
        
    def generate_sequence(self, context: Dict[str, Any]) -> List[str]:
        """Generate a sequence of interaction primitives based on the current context."""
        ...
