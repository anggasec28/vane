from vane.evidence.provenance import chain_digest
from vane.evidence.chain import verify_event_chain

def test_event_chain_detects_payload_tampering():
    payload = {"event_id":"e1","project_id":"p1","event_type":"created",
               "actor":"master","occurred_at":"2026-01-01T00:00:00Z","payload":{"x":1}}
    digest = chain_digest(None, payload)
    event = {**payload, "payload": {"x": 2}, "previous_digest": None, "digest": digest}
    result = verify_event_chain([event])
    assert not result.valid
