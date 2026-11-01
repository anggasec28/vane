"""Explicit engine composition from local public-key and database configuration."""
from vane.crypto.approval_verifier import Ed25519ApprovalVerifier
from vane.crypto.keyring import load_public_keyring
from vane.engine import VaneEngine
from vane.security.enforcement import SecurityEnforcer
from vane.security.policy_engine import PolicyEngine
from vane.storage.repository import SQLiteRepository
from vane.storage.sqlite_store import SQLiteStore

def create_engine(public_keyring_path: str,
                  database_path: str = "data/vane.sqlite3") -> VaneEngine:
    public_keys = load_public_keyring(public_keyring_path)
    verifier = Ed25519ApprovalVerifier(public_keys)
    repository = SQLiteRepository(SQLiteStore(database_path))
    return VaneEngine(enforcer=SecurityEnforcer(PolicyEngine(verifier)),
                      repository=repository)
