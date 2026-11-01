# Cryptographic Trust Policy

Use asymmetric Ed25519 signing. Private signing key material is confined to the signing service. Verifier profiles hold public keys only. HMAC does not satisfy independent signer/verifier separation.

## Recorded custody and anchoring constraints
- Q1-B: PKCS#11 host-separated custody.
- Q2-C: published head hash / OTS.
- Q3-A: 2-of-3; same-person shares are not truly independent.
- R2 O3: countersigned origin envelope.
- L2 signer separation; L3 external anchor.
- Anchor C: CAS/conditional write through hybrid single-writer service.
- Prepared B: no prepared state.
- Lost response is indeterminate; resolve by GET using deterministic cp_id.
- Burn A: allowance 1 plus durable anchored burn.
- Reset outage A: refuse reset until anchor available and checkpoint committed.
- MAX_UNANCHORED=8; off-host heartbeat observer; daily OTS of latest checkpoint head hash.

## Open proof obligations
UQ-5 atomic CAS over state/dedupe/head_receipt requires linearizability proof. Anchor regression fails closed using trusted evidence outside the anchor failure domain. These are design constraints, not claims of implementation.
