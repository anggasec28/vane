"""Ed25519 approval verifier. Only public keys are loaded by this component."""
import base64
from vane.security.approval import Approval
from vane.security.digests import approval_signing_payload

class Ed25519ApprovalVerifier:
    def __init__(self, public_keys: dict[str, bytes]) -> None:
        self._public_keys = dict(public_keys)

    def verify(self, approval: Approval) -> bool:
        public_key = self._public_keys.get(approval.key_id)
        if public_key is None:
            return False
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            return False
        try:
            signature = base64.b64decode(approval.signature, validate=True)
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature, approval_signing_payload(approval))
            return True
        except (ValueError, InvalidSignature):
            return False
