import pytest
from vane.mcp.registry import CapabilityRegistry, ToolCapability

def test_unenabled_tool_cannot_be_resolved():
    registry = CapabilityRegistry((ToolCapability("server", "tool", "high", ("read",)),))
    with pytest.raises(PermissionError):
        registry.resolve("server", "tool")
