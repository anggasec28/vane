import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vane.bootstrap import create_engine


def test_bootstrap_fails_closed_when_master_emergency_identity_is_unconfigured(tmp_path, monkeypatch):
    monkeypatch.delenv("VANE_MASTER_PRINCIPAL", raising=False)
    monkeypatch.delenv("VANE_MASTER_KEY_IDS", raising=False)
    monkeypatch.setenv("VANE_REQUIRE_EMERGENCY_CONTROL", "true")
    engine = create_engine(
        public_keyring_path=str(tmp_path / "missing-keyring.json"),
        database_path=str(tmp_path / "vane.sqlite3"),
    )
    decision = engine.enforcer.authorize_action(None, "asset.example", "passive_scan")
    assert decision.allowed is False
    assert decision.code == "EMERGENCY_CONTROL_UNAVAILABLE"


def test_bootstrap_wires_configured_master_emergency_identity(tmp_path, monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    keyring = tmp_path / "keys.json"
    keyring.write_text(json.dumps({"keys": {"master-key": base64.b64encode(public_key).decode()}}))
    monkeypatch.setenv("VANE_MASTER_PRINCIPAL", "master-telegram-principal")
    monkeypatch.setenv("VANE_MASTER_KEY_IDS", "master-key")
    monkeypatch.setenv("VANE_REQUIRE_EMERGENCY_CONTROL", "true")
    engine = create_engine(
        public_keyring_path=str(keyring),
        database_path=str(tmp_path / "vane-configured.sqlite3"),
    )
    decision = engine.enforcer.authorize_action(None, "asset.example", "passive_scan")
    assert decision.code == "AUTHORIZATION_DENIED"
