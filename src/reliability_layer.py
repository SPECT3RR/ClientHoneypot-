import traceback
import asyncio
from typing import Callable, Coroutine, Any

class ReliabilityLayer:
    """
    Provides fault tolerance and session recovery capabilities.
    """
    @staticmethod
    async def safe_execute(coro: Coroutine[Any, Any, Any], fallback: Any = None) -> Any:
        try:
            return await coro
        except asyncio.TimeoutError:
            print("[ReliabilityLayer] Recovered from TimeoutError")
            return fallback
        except Exception as e:
            print(f"[ReliabilityLayer] Recovered from unexpected fault: {e}")
            traceback.print_exc()
            return fallback
