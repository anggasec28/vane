import json
from pathlib import Path
from jsonschema import Draft202012Validator

def test_all_json_schemas_are_well_formed():
    root = Path(__file__).parents[1] / "schemas"
    schema_files = sorted(root.glob("*.schema.json"))
    assert len(schema_files) == 9
    for path in schema_files:
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
