"""Evidence validation and evidence sufficiency helpers."""
from vane.errors import EvidenceError
from vane.models import EvidenceRecord

def validate_evidence(record: EvidenceRecord) -> None:
    required = (record.evidence_id, record.project_id, record.mission_id, record.kind,
                record.source, record.content_digest, record.authorization_id)
    if any(not value for value in required):
        raise EvidenceError("Evidence is missing a required identity, source, digest, or authorization link.")
    if len(record.content_digest) != 64:
        raise EvidenceError("content_digest must be a SHA-256 hex digest.")
    try:
        int(record.content_digest, 16)
    except ValueError as exc:
        raise EvidenceError("content_digest is not hexadecimal.") from exc

def evidence_sufficiency(required: set[str], collected: set[str]) -> tuple[bool, set[str]]:
    missing = required - collected
    return not missing, missing
