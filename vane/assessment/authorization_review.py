"""Authorization-envelope structural review before activation."""
from dataclasses import dataclass
from vane.models import AuthorizationEnvelope

@dataclass(frozen=True, slots=True)
class EnvelopeReview:
    valid: bool
    issues: tuple[str, ...]

def review_envelope(envelope: AuthorizationEnvelope) -> EnvelopeReview:
    issues: list[str] = []
    if not envelope.envelope_id.strip(): issues.append("missing_envelope_id")
    if not envelope.principal.strip(): issues.append("missing_principal")
    if not envelope.project_id.strip(): issues.append("missing_project_id")
    if not envelope.rules: issues.append("empty_scope")
    if not envelope.allowed_methods: issues.append("empty_method_allowlist")
    if not envelope.approval_id: issues.append("missing_approval_reference")
    if envelope.starts_at is None or envelope.expires_at is None:
        issues.append("missing_finite_validity_window")
    elif envelope.starts_at >= envelope.expires_at:
        issues.append("invalid_validity_window")
    return EnvelopeReview(not issues, tuple(issues))
