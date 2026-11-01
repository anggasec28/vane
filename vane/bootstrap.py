"""Explicit engine composition from profile-local public-key and database configuration."""
import os
from pathlib import Path

from vane.crypto.approval_verifier import Ed25519ApprovalVerifier
from vane.crypto.keyring import load_public_keyring
from vane.engine import VaneEngine
from vane.security.enforcement import SecurityEnforcer
from vane.security.emergency_suspension import MasterEmergencySuspension
from vane.security.policy_engine import PolicyEngine
from vane.storage.repository import SQLiteRepository
from vane.storage.sqlite_store import SQLiteStore

def create_engine(public_keyring_path: str | None = None,
                  database_path: str | None = None) -> VaneEngine:
    hermes_home = Path(os.environ.get("HERMES_HOME", "."))
    keyring_path = public_keyring_path or os.environ.get(
        "VANE_APPROVAL_KEYRING", str(hermes_home / "config" / "approval-public-keys.json"))
    db_path = database_path or os.environ.get(
        "VANE_DB_PATH", str(hermes_home / "data" / "vane.sqlite3"))
    public_keys = load_public_keyring(keyring_path) if Path(keyring_path).is_file() else {}
    verifier = Ed25519ApprovalVerifier(public_keys)
    store = SQLiteStore(db_path)
    repository = SQLiteRepository(store)
    require_control = os.environ.get("VANE_REQUIRE_EMERGENCY_CONTROL", "true").strip().lower() not in {
        "0", "false", "no",
    }
    master_principal = os.environ.get("VANE_MASTER_PRINCIPAL", "").strip()
    master_key_ids = {
        item.strip() for item in os.environ.get("VANE_MASTER_KEY_IDS", "").split(",")
        if item.strip()
    }
    suspension = None
    if master_principal and master_key_ids:
        suspension = MasterEmergencySuspension(
            store, master_principal=master_principal,
            master_key_ids=master_key_ids, verifier=verifier,
        )
    policy = PolicyEngine(
        verifier, emergency_suspension=suspension,
        require_emergency_control=require_control,
    )
    return VaneEngine(enforcer=SecurityEnforcer(policy), repository=repository)
