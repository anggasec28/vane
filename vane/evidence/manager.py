"""Evidence validation and evidence sufficiency helpers."""
from datetime import timedelta
from vane.errors import EvidenceError
from vane.models import EvidenceRecord, utc_now

def validate_evidence(record: EvidenceRecord) -> None:
    required = (record.evidence_id, record.project_id, record.mission_id, record.kind,
                record.source, record.content_digest, record.authorization_id,
                record.collection_method)
    if any(not value for value in required):
        raise EvidenceError("Evidence is missing a required identity, source, method, digest, or authorization link.")
    if record.observed_at.tzinfo is None or record.observed_at.utcoffset() is None:
        raise EvidenceError("observed_at must be timezone-aware.")
    if record.observed_at > utc_now() + timedelta(minutes=5):
        raise EvidenceError("observed_at is unexpectedly in the future.")
    if len(record.content_digest) != 64:
        raise EvidenceError("content_digest must be a SHA-256 hex digest.")
    try:
        int(record.content_digest, 16)
    except ValueError as exc:
        raise EvidenceError("content_digest is not hexadecimal.") from exc
    if record.evidence_id in record.parent_evidence_ids:
        raise EvidenceError("Evidence cannot be its own parent.")
    if len(record.parent_evidence_ids) != len(set(record.parent_evidence_ids)):
        raise EvidenceError("parent_evidence_ids must be unique.")
    satisfies = record.metadata.get("satisfies")
    if satisfies is not None and (not isinstance(satisfies, list)
            or not all(isinstance(item, str) and item for item in satisfies)):
        raise EvidenceError("metadata.satisfies must be a list of non-empty strings.")

def evidence_sufficiency(required: set[str], collected: set[str]) -> tuple[bool, set[str]]:
    missing = required - collected
    return not missing, missing
