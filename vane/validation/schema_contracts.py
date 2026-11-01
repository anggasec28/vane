"""Optional JSON Schema validation for repository record contracts."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vane.errors import PolicyViolation


SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"


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
    """Validate a JSON-compatible document; jsonschema is a declared dev dependency."""
    schema = load_schema(schema_name)
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise RuntimeError("Install VANE development dependencies to enable JSON Schema validation.") from exc
    errors = sorted(Draft202012Validator(schema).iter_errors(document),
                    key=lambda error: (list(map(str, error.path)), error.message))
    if errors:
        first = errors[0]
        location = ".".join(map(str, first.path)) or "<root>"
        raise PolicyViolation(f"{schema_name} validation failed at {location}: {first.message}")


def validate_all_schemas() -> tuple[str, ...]:
    """Parse and meta-validate every repository schema without loading target data."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise RuntimeError("Install VANE development dependencies to validate schemas.") from exc
    names = tuple(sorted(path.name for path in SCHEMA_DIR.glob("*.schema.json")))
    for name in names:
        Draft202012Validator.check_schema(load_schema(name))
    return names
