# Ed25519 Approval Signing Format

VANE verifies approval records; it does not hold or operate the private signing key. The external signing service signs the exact canonical approval payload using Ed25519. The engine receives only the signed record and a public key.

## Record fields
- `approval_id`: unique approval identifier.
- `approver`: authenticated Master/principal identifier.
- `subject_digest`: SHA-256 digest of the authorization envelope or exact capability action.
- `decision`: `APPROVE` or `REJECT`.
- `decided_at`: timezone-aware ISO 8601 timestamp.
- `key_id`: identifier of the public key used for verification.
- `signature`: base64-encoded Ed25519 signature.
- `expires_at`: required timezone-aware ISO 8601 expiry.
- `rationale`: signed approval rationale.

## Canonical payload
The signature covers all record fields except `signature`, serialized as UTF-8 JSON with:
- keys sorted lexicographically;
- separators `,` and `:` with no added whitespace;
- Unicode preserved (no ASCII escaping);
- datetimes serialized using `datetime.isoformat()`.

The signature payload is the canonical JSON bytes. The verifier loads the public key selected by `key_id`, decodes the base64 signature, and verifies Ed25519 over those bytes.

## Subject digest
- Mission approval: SHA-256 of the canonical authorization-envelope object.
- Action approval: SHA-256 of canonical JSON containing `authorization_digest`, exact `locator`, and lowercased `method`.

An approval for one envelope or action cannot be reused for a different one. Mission approval ID is tied to the envelope's `approval_id`; action approvals have their own IDs and bind to their action digest.

## Key custody
The profile-local keyring contains only base64-encoded 32-byte Ed25519 public keys. Private keys remain in the separate signing service. An absent keyring, unknown key ID, malformed signature, invalid signature, expired approval, or mismatched digest is a denial.
