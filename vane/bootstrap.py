"""Explicit engine composition from local public-key configuration."""
from vane.crypto.approval_verifier import Ed25519ApprovalVerifier
from vane.crypto.keyring import load_public_keyring
from vane.engine import VaneEngine
from vane.security.enforcement import SecurityEnforcer
from vane.security.policy_engine import PolicyEngine

def create_engine(public_keyring_path: str) -> VaneEngine:
    public_keys = load_public_keyring(public_keyring_path)
    verifier = Ed25519ApprovalVerifier(public_keys)
    return VaneEngine(enforcer=SecurityEnforcer(PolicyEngine(verifier)))
