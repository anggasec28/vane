# Master Decision Register

## Consolidated architecture decisions
| ID | Selection | Model |
|---|---|---|
| 56 | C | Hybrid Finding Governance |
| 57 | C | Hybrid Evidence Management |
| 58 | C | Hybrid Project & Case Operations |
| 59 | A | Central Security Enforcement |
| 60 | C | Independent Hybrid Validation |

## Build implementation architecture
- Hybrid modular Python engine + VANE profile + Hermes runtime boundary is the implementation default adopted to proceed with the requested full build. This is an engineering architecture choice, not a change to Master authority or Hermes runtime.

## Other confirmed choices
- Data Lifecycle Governance: C, hybrid policy-driven by data class, project context, information status, and preservation need. Exceptions require reason, authority, and record. Unclear ownership/status is never auto-deleted.
- Workflow: C, adaptive hybrid; deep root-cause and relevant dependency tracing within approved scope.
- Observation Failure & Recovery: C, adaptive evidence-driven.
- Q-1: B (retain selected choice; consult source package for exact implementation semantics).
- Q-3: C, follow symlink only when resolved target is within approved boundary; otherwise record NOT_INSPECTED.
- MK-2: A (retain selected choice; do not infer details beyond source decision).
- MK-4: A, Ed25519 asymmetric signing; private key only in signing service, verifier holds public key; signing and verification authority separated.

## Custody / L3 design constraints
Q1-B PKCS#11 host-separated custody; Q2-C published head hash/OTS; Q3-A 2-of-3 (same-person shares are not truly independent); R2 O3 countersigned origin envelope; L2 signer separation; L3 external anchor; anchor C CAS/conditional write via hybrid single-writer service; prepared B no prepared state; lost response indeterminate and resolved by GET using deterministic cp_id; burn A allowance 1 plus durable anchored burn; reset outage A refuses reset until anchor is available and checkpoint committed; MAX_UNANCHORED=8; heartbeat B off-host operator cron; daily OTS of latest checkpoint head hash.

UQ-1 A checkpoint binds verified pre-reset marks; UQ-2 A gap ≤ 1 + burns; UQ-3 A cadence floor inside same reservation lock; UQ-4 A dedupe after index eviction via canonical claim refusal; UQ-5 A atomic CAS over state/dedupe/head_receipt, with linearizability proof still required; UQ-7 A reset and reserve_seq share counter lock; UQ-8 A dead-man switch for off-host heartbeat observer; UQ-9 A OTS tuple (anchor_seq, digest); UQ-10 A fail closed on anchor regression using trusted evidence outside anchor failure domain.

Burn policy 1-S: provable burn requires zero operator attestation; operator-initiated burn requires two operator attestations. QA-O6 definition 2: proof criterion only; sig_state and closure_state remain separate.

## Open / not approved
Operational Intelligence architecture selection is unresolved. R-12 OPEN; Gate 0b NOT PASSED; Phase 1 LOCKED. AUD-3 closure mechanism and append barrier OPEN. O-7/O-8/R-QA-11 OPEN. B-10 OPEN. SD-2 PROPOSED and NOT READY; no immediate erratum authorization. Do not infer approval for unrecorded decisions.

If this register conflicts with a source decision package, stop and reconcile with the Master rather than silently choosing.
