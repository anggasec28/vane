import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from vane.security.approval import Approval
from vane.security.digests import approval_signing_payload
from vane.crypto.approval_verifier import Ed25519ApprovalVerifier

def test_ed25519_verifier_accepts_only_valid_signature():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    unsigned = Approval("ap1", "master", "a" * 64, "APPROVE",
        datetime.now(timezone.utc), "master-key-1", "placeholder",
        datetime.now(timezone.utc) + timedelta(hours=1), "approved test")
    signature = base64.b64encode(private_key.sign(approval_signing_payload(unsigned))).decode()
    signed = replace(unsigned, signature=signature)
    verifier = Ed25519ApprovalVerifier({"master-key-1": public_key})
    assert verifier.verify(signed)
    assert not verifier.verify(replace(signed, rationale="tampered"))
