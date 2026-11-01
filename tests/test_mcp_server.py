def test_local_mcp_server_imports():
    from vane.mcp.server import server
    assert server is not None
