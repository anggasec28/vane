"""Normalized, time-bounded threat intelligence records from supplied sources."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum

from vane.errors import PolicyViolation


class IntelConfidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True, slots=True)
class ThreatIntelRecord:
    intel_id: str
    source_id: str
    source_uri: str
    title: str
    summary: str
    published_at: datetime
    observed_at: datetime
    expires_at: datetime | None
    indicators: tuple[str, ...]
    affected_products: tuple[str, ...]
    affected_versions: tuple[str, ...]
    confidence: IntelConfidence
    tags: tuple[str, ...] = ()


def validate_intel(record: ThreatIntelRecord, *, now: datetime | None = None) -> None:
    if not all((record.intel_id, record.source_id, record.source_uri,
                record.title.strip(), record.summary.strip())):
        raise PolicyViolation("Threat intelligence requires stable identity, source, title, and summary.")
    for value in (record.published_at, record.observed_at):
        if value.tzinfo is None or value.utcoffset() is None:
            raise PolicyViolation("Threat intelligence timestamps must be timezone-aware.")
    if record.expires_at is not None:
        if record.expires_at.tzinfo is None or record.expires_at.utcoffset() is None:
            raise PolicyViolation("Threat intelligence expiry must be timezone-aware.")
        if record.expires_at <= record.published_at:
            raise PolicyViolation("Threat intelligence expiry must follow publication.")
    current = now or datetime.now(timezone.utc)
    if record.published_at > current or record.observed_at > current:
        raise PolicyViolation("Future-dated threat intelligence cannot be activated.")
    if record.observed_at < record.published_at:
        raise PolicyViolation("Threat intelligence cannot be observed before publication.")
    if not record.indicators and not record.affected_products and not record.tags:
        raise PolicyViolation("Threat intelligence requires at least one matching dimension.")


def is_current(record: ThreatIntelRecord, *, now: datetime | None = None) -> bool:
    current = now or datetime.now(timezone.utc)
    validate_intel(record, now=current)
    return record.expires_at is None or current < record.expires_at


def relevance_score(record: ThreatIntelRecord, *, indicators: set[str],
                    products: set[str], versions: set[str], tags: set[str],
                    now: datetime | None = None) -> float:
    """Return a transparent lexical relevance score, not a claim of exploitability."""
    if not is_current(record, now=now):
        return 0.0
    matched = 0.0
    total = 0.0
    for expected, supplied, weight in (
        (set(record.indicators), indicators, 4.0),
        (set(record.affected_products), products, 3.0),
        (set(record.affected_versions), versions, 2.0),
        (set(record.tags), tags, 1.0),
    ):
        if expected:
            total += weight
            if expected & supplied:
                matched += weight
    if total == 0:
        return 0.0
    confidence_weight = {
        IntelConfidence.LOW: 0.5,
        IntelConfidence.MEDIUM: 0.75,
        IntelConfidence.HIGH: 1.0,
    }[record.confidence]
    return round((matched / total) * confidence_weight, 4)
