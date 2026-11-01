"""Explicit allowlist for MCP capabilities."""
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class ToolCapability:
    server: str
    name: str
    risk_tier: str
    methods: tuple[str, ...]
    approval_required: bool = True
    enabled: bool = False

class CapabilityRegistry:
    def __init__(self, capabilities: tuple[ToolCapability, ...] = ()) -> None:
        self._items = {(c.server, c.name): c for c in capabilities}
    def resolve(self, server: str, name: str) -> ToolCapability:
        try:
            capability = self._items[(server, name)]
        except KeyError as exc:
            raise PermissionError(f"MCP capability is not registered: {server}/{name}") from exc
        if not capability.enabled:
            raise PermissionError(f"MCP capability is registered but disabled: {server}/{name}")
        return capability
