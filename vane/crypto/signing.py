"""Ed25519 signer/verifier separation contracts; no private keys are stored here."""
from typing import Protocol

class Signer(Protocol):
    def sign(self, payload: bytes, *, key_id: str) -> bytes: ...
class Verifier(Protocol):
    def verify(self, payload: bytes, signature: bytes, *, public_key: bytes) -> bool: ...
class ExternalSignerRequired(RuntimeError):
    pass
class SigningGateway:
    def __init__(self, signer: Signer | None = None) -> None:
        self._signer = signer
    def sign(self, payload: bytes, *, key_id: str) -> bytes:
        if self._signer is None:
            raise ExternalSignerRequired("Configure the isolated Ed25519 signing service.")
        return self._signer.sign(payload, key_id=key_id)
