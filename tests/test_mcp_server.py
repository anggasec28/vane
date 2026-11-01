def test_local_mcp_server_imports():
    from vane.mcp.server import server
    assert server is not None

def test_profile_tool_allowlist_matches_server_definitions():
    import re
    from pathlib import Path
    source = Path("vane/mcp/server.py").read_text(encoding="utf-8")
    profile = Path("config.yaml").read_text(encoding="utf-8")
    defined = set(re.findall(r"def (vane_[a-z0-9_]+)\\(", source))
    allowed = set(re.findall(r"^\\s+- (vane_[a-z0-9_]+)\\s*$", profile, re.MULTILINE))
    assert defined == allowed
