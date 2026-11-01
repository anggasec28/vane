"""JSON Schema validation and typed record-to-schema mapping."""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from vane.errors import PolicyViolation


SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"

SCHEMA_BY_RECORD_TYPE = {
    "project": "project.schema.json",
    "authorization": "authorization-envelope.schema.json",
    "approval": "approval.schema.json",
    "mission": "mission.schema.json",
    "asset": "asset.schema.json",
    "evidence": "evidence-record.schema.json",
    "finding": "finding-record.schema.json",
    "worker_task": "worker-task.schema.json",
    "worker_assignment": "worker-assignment.schema.json",
    "case_work_item": "case-work-item.schema.json",
    "case_timeline_event": "case-timeline-event.schema.json",
    "threat_intel": "threat-intel-record.schema.json",
    "remediation_action": "remediation-action.schema.json",
    "report_bundle": "report-bundle.schema.json",
    "lifecycle_review": "lifecycle-review.schema.json",
}


def load_schema(schema_name: str) -> dict[str, Any]:
    if not schema_name.endswith(".schema.json") or "/" in schema_name or "\\" in schema_name:
        raise ValueError("schema_name must be a plain *.schema.json filename.")
    path = SCHEMA_DIR / schema_name
    if not path.is_file():
        raise FileNotFoundError(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyViolation(f"Schema {schema_name} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PolicyViolation(f"Schema {schema_name} must contain a JSON object.")
    return value


def validate_document(document: Any, schema_name: str) -> None:
    """Validate a JSON-compatible document using the Draft 2020-12 schema."""
    schema = load_schema(schema_name)
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise RuntimeError("Install the VANE package dependencies to enable JSON Schema validation.") from exc
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(document),
                    key=lambda error: (list(map(str, error.path)), error.message))
    if errors:
        first = errors[0]
        location = ".".join(map(str, first.path)) or "<root>"
        raise PolicyViolation(f"{schema_name} validation failed at {location}: {first.message}")


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set)):
        return [_json_value(item) for item in value]
    return value


def validate_domain_record(record_type: str, record: dict[str, Any]) -> None:
    """Validate a typed repository record against its canonical JSON Schema."""
    schema_name = SCHEMA_BY_RECORD_TYPE.get(record_type)
    if schema_name is None:
        return
    document = _json_value(record)
    if record_type == "mission":
        document.pop("history", None)
    elif record_type == "evidence":
        document.pop("status", None)
    validate_document(document, schema_name)


def validate_all_schemas() -> tuple[str, ...]:
    """Parse and meta-validate every repository schema without loading target data."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise RuntimeError("Install the VANE package dependencies to validate schemas.") from exc
    names = tuple(sorted(path.name for path in SCHEMA_DIR.glob("*.schema.json")))
    for name in names:
        Draft202012Validator.check_schema(load_schema(name))
    return names
