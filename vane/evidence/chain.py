"""Verification for exported hash-linked event sequences."""
from dataclasses import dataclass
from typing import Any
from vane.evidence.provenance import chain_digest

@dataclass(frozen=True, slots=True)
class ChainVerification:
    valid: bool
    checked: int
    failed_sequence: int | None = None
    reason: str = ""

def verify_event_chain(events: list[dict[str, Any]]) -> ChainVerification:
    previous: str | None = None
    for index, event in enumerate(events, start=1):
        payload = {key: event[key] for key in
                   ("event_id", "project_id", "event_type", "actor", "occurred_at", "payload")}
        expected = chain_digest(previous, payload)
        if event.get("previous_digest") != previous or event.get("digest") != expected:
            return ChainVerification(False, index, index, "Previous digest or event digest mismatch.")
        previous = expected
    return ChainVerification(True, len(events))
