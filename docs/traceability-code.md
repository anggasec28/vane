# Master Decision to Code Traceability

This is the initial code-level traceability map. A mapping means the requirement has a source implementation or contract; it does not imply runtime integration or complete verification.

| Decision / requirement | Code or artifact | Current coverage |
|---|---|---|
| VANE hosted by Hermes, not replacement runtime | `SOUL.md`, `vane/integrations/hermes/adapter.py` | Boundary contract; Hermes compatibility unverified |
| Autonomous with approval | `vane/security/approval.py`, `vane/security/policy_engine.py`, `vane/crypto/approval_verifier.py` | Ed25519 signed approval, action digest binding, public-only verification |
| Central enforcement (Decision 59 A) | `vane/security/enforcement.py`, `policy_engine.py` | Central decision facade |
| Hybrid finding governance (Decision 56 C) | `vane/findings/governance.py` | Evidence-linked validation; workflow incomplete |
| Hybrid evidence management (Decision 57 C) | `vane/evidence/`, `vane/storage/sqlite_store.py` | Integrity, provenance, persistence foundation |
| Hybrid project/case operations (Decision 58 C) | `vane/projects/registry.py`, `vane/engine.py` | In-memory project/mission composition |
| Independent hybrid validation (Decision 60 C) | `vane/validation/independent.py` | Deterministic closure checks |
| Adaptive hybrid workflow | `vane/core/state_machine.py`, `vane/core/orchestrator.py` | Mission lifecycle foundation |
| Deep root-cause within approved scope | `vane/assessment/root_cause.py` | In-scope graph traversal |
| Discovered assets do not become authorized | `vane/assessment/asset_mapping.py`, `vane/security/authorization.py` | Out-of-scope classification and deny |
| Adaptive evidence-driven recovery | `vane/recovery/planner.py` | Bounded recovery recommendations |
| Hybrid policy-driven data lifecycle | `vane/lifecycle/policy.py` | Preservation and approval decisions |
| Ed25519 signer/verifier separation | `vane/crypto/signing.py` | External signer contract; no key provisioning |
| MCP capability governance | `vane/mcp/registry.py` | Explicit registration, disabled by default |
| Worker authority is subordinate | `vane/workers/contracts.py` | Delegation contract; runtime scheduler absent |
| L3/R-12 external anchor and reset ledger | `docs/master-decisions.md`, `policies/cryptographic-trust.md` | OPEN / NOT IMPLEMENTED |

## Gaps requiring implementation
- Durable project/mission/evidence/finding repositories and migrations.
- A complete transactional event writer integrating canonical hash-chain computation.
- All historical L3/R-12 requirements and AUD findings translated into executable tests.
- Full worker scheduler and verifier separation.
- Hermes-native profile format and tool adapter compatibility verification.
- End-to-end integration tests and a signed release process.
