---
name: independent-validation
description: Independently validate evidence and closure criteria.
version: 0.2.0
metadata:
  hermes:
    tags: [security, validation, assurance]
    category: security
---
# Independent Validation

## When to Use
Use before a mission is marked completed or closed, and when a finding is promoted to validated.

## Procedure
1. Review the authorization envelope and scope coverage independently of the execution worker.
2. Reconcile required evidence objectives against collected evidence.
3. Check evidence references, integrity, provenance, and limitations.
4. Confirm there are no unresolved blockers or uninspected assets misrepresented as covered.
5. Review finding claims and evidence links independently.
6. Return PASS, FAIL, or INDETERMINATE per check. Do not collapse unknown into pass.
7. After PASS, submit the completed mission snapshot for Master closure approval and verify it with `vane_verify_closure_approval`.
8. Keep validator identity and rationale in the validation record.

## Engine Tool

Use `vane_validate_mission_closure` with mission, evidence, and finding records. Treat every failed or indeterminate check as unresolved.

## Mission Lifecycle Tools
After the review checks pass, use `vane_complete_mission` to record COMPLETED. Then verify the signed Master closure approval with `vane_verify_closure_approval` and call `vane_close_mission` with the exact completed snapshot. Do not mark CLOSED on a worker's assertion.

## Pitfalls
- The worker who performed an observation is not automatically an independent verifier.
- Task success is not assessment closure.
- A hash chain without an independently trusted head is not externally anchored evidence.

## Verification
Return a check-by-check report with evidence references, failures, and explicit indeterminate items.
