import base64
import json
import pytest
from vane.crypto.keyring import load_public_keyring

def test_public_keyring_loads_only_32_byte_public_keys(tmp_path):
    path = tmp_path / "keys.json"
    encoded = base64.b64encode(b"x" * 32).decode()
    path.write_text(json.dumps({"keys": {"master-key-1": encoded}}), encoding="utf-8")
    assert load_public_keyring(path)["master-key-1"] == b"x" * 32

def test_public_keyring_rejects_invalid_length(tmp_path):
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"keys": {"bad": base64.b64encode(b"x").decode()}}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_public_keyring(path)
