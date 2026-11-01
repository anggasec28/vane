# VANE Architecture Conflict and Adjudication Register

This register preserves explicit conflicts identified in **05 — VANE Final Architecture Blueprint** and source decisions. It does not silently revise Master selections. Each item remains unresolved until the designated authority records an adjudication or the independent evaluator demonstrates a precise reconciliation.

| ID | Recorded choice / issue | Interacting principle | Required resolution | Status |
|---|---|---|---|---|
| CF-01 | CR-01 A: automatic inspection of all technically connected components without an internal expansion limit | Effective authority, mission scope, third-party boundaries, technically connected assets | Define technical connectivity for internal architecture mapping separately from permission to interact. Every target-facing action remains gated by explicit scope and methods. | OPEN |
| CF-02 | CR-02 A: immediate resume from last saved progress without routine rechecking | Revocation, changed mission conditions, emergency suspension, current approval | Separate restoration of a checkpoint from permission to resume actions. Define mandatory revalidation triggers and deny action when authority cannot be established. | OPEN |
| CF-03 | CR-06 A: automatic repair directly on original data | Original evidence preservation, provenance, version history, rollback, nearest-data recovery | Classify mutable operational data versus immutable evidence/originals. Define copy-on-write, version retention, integrity checks, rollback, and proof before replacing an active version. | OPEN |
| CF-04 | CR-08 B: immediate security fix followed by recording | Critical-action approval, auditability, security precedence | Define narrowly bounded emergency remediation classes, preconditions, authority basis, contemporaneous or tamper-evident recording, and post-action review. | OPEN |
| CF-05 | Central Data Management responsibility | One accountable owner per material dependency and domain operational accountability | Separate central policy/registry ownership from provider accountability for service contract, integrity, and reliability, and consumer accountability for use/failure handling. | OPEN |
| CF-06 | Estimates and nearest-data repair | Evidence quality and prohibition on false certainty | Label estimates exactly as PERKIRAAN, preserve source and confidence, never promote to verified fact without evidence. Treat nearest data as a recovery candidate, not automatically authoritative truth. | OPEN |
| CF-07 | Cached authority/decision continuity | Central authoritative Decision Ledger, revocation, integrity and consistency | Define signed/verified cache provenance, freshness and revocation checks, bounded continuity actions, and exact BLOCKED/SUSPENDED conditions. | OPEN |

## Additional architecture gaps to preserve

- Operational Intelligence architecture selection remains unresolved; do not infer a selected architecture.
- Decision Ledger arbitration, appeals/reversals, hybrid projections, relationship index, and causal reconciliation remain incomplete.
- Emergency Suspension Authority is Master-only. Central Security Enforcement is not a substitute and cannot release a Master suspension.
- Master authentication/identity binding from the Hermes Telegram channel has not been verified in the repository.
- L3/R-12 remains OPEN; Gate 0b NOT PASSED; Phase 1 LOCKED; Production NOT AUTHORIZED.
- AUD-3 closure mechanism and append barrier remain OPEN; O-7/O-8/R-QA-11 and B-10 remain OPEN; SD-2 remains PROPOSED and NOT READY.

## Adjudication rules

1. Preserve the original selection and its lineage.
2. Record the conflicting principles, concrete failure modes, and affected domains.
3. Distinguish semantic reconciliation from a change to the recorded Master choice.
4. Require a new traceable decision for any changed choice.
5. Do not implement an unresolved conflict by guessing its intended meaning.
6. Keep all related capabilities NOT_PROVEN until objective acceptance evidence exists.
