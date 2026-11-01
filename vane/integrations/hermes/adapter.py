"""Hermes host bridge contract; default implementation performs no runtime calls."""
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

@dataclass(frozen=True, slots=True)
class HermesContext:
    session_id: str
    profile_name: str
    tool_names: tuple[str, ...] = ()
class HermesHost(Protocol):
    def current_context(self) -> HermesContext: ...
    def request_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any: ...
class HermesAdapter:
    def __init__(self, host: HermesHost | None = None) -> None:
        self._host = host
    def describe(self) -> dict[str, Any]:
        return {"runtime": "Hermes Agent", "connected": self._host is not None,
                "execution_enabled": False, "note": "Default adapter makes no runtime calls."}
    @staticmethod
    def profile_source_path() -> Path:
        return Path(__file__).resolve().parents[3]
