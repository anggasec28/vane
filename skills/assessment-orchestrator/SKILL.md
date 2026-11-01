---
name: assessment-orchestrator
description: Plan and govern evidence-led security assessments.
version: 0.2.0
metadata:
  hermes:
    tags: [security, orchestration, assessment]
    category: security
---
# Assessment Orchestrator

## When to Use
Use for a new assessment, a changed objective, a recovery decision, or a mission closure review.

## Procedure
1. Identify the project, objective, and current mission state.
2. Obtain the exact, current authorization envelope and approval reference from the Master.
3. Use `vane_status` to confirm the local engine is available.
4. Verify the signed mission approval with `vane_verify_mission_approval`.
5. Use `vane_scope_check` for every proposed asset and method before planning.
6. Use `vane_plan_web2` for passive Web2 work planning. It does not make network requests.
7. Keep Web2 and Web3 work items, tasks, evidence objectives, blockers, and findings separate.
8. Adapt the plan when evidence is incomplete. Never treat a task result as mission closure.
9. Request independent validation before recommending closure.

## Project and Mission Tools
- Use `vane_create_project` and `vane_create_mission` to create durable draft records.
- Use `vane_submit_mission` to place a mission into the approval queue.
- Use `vane_authorize_mission` only with the exact signed envelope and Ed25519 approval.
- Use `vane_start_mission` only after authorization is verified.
- Use `vane_request_evidence_review`, `vane_complete_mission`, and `vane_close_mission` for the independent review and signed closure gates.

## Pitfalls
- Discovery is not authorization.
- A redirect, related hostname, dependency, wallet, contract, or repository does not enter scope automatically.
- Blocked or missing observations are not passes.
- The current MCP server plans and validates; it does not perform live scans.

## Verification
Return the authorization reference, scoped assets, approved methods, evidence gaps, blockers, and validation result. State clearly whether the mission is open, blocked, completed, or closed.
