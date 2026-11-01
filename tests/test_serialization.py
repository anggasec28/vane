from vane.security.serialization import authorization_from_dict

def test_authorization_deserialization_requires_timezone():
    data = {"envelope_id":"a1","principal":"master","project_id":"p1",
            "rules":[{"kind":"hostname","value":"example.com"}],
            "allowed_methods":["http_metadata"],"expires_at":"2026-12-01T00:00:00"}
    try:
        authorization_from_dict(data)
    except ValueError as exc:
        assert "timezone" in str(exc)
    else:
        raise AssertionError("naive timestamp must be rejected")
