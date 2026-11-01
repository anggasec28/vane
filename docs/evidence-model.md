# Evidence Management Model

Hybrid model: structured metadata and immutable content references, with controlled project-level organization and explicit preservation status.

Each record binds evidence_id, case/mission, source/collector, tool/version, target, authorization, method, observed/collected timestamps, digest, provenance, transformations, data class, confidence, limitations, and validation state.

States: PROPOSED, COLLECTED, QUARANTINED, VERIFIED, DISPUTED, SUPERSEDED, PRESERVED, DISPOSED. Transitions require policy checks and audit events.

Hash at acquisition; preserve originals where permitted; record transformations separately; never overwrite original evidence. Ed25519 private key remains in signing service; verifier receives public key only.

Evidence sufficiency is claim-specific, not file-existence-based. Blocked, partial, stale, or indirect observations retain their limitations.
