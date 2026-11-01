---
name: project-case-operations
description: Organize projects, missions, tasks, and case handoffs.
version: 0.2.0
metadata:
  hermes:
    tags: [security, projects, workflow]
    category: security
---
# Project and Case Operations

## When to Use
Use when creating or updating an assessment project, mission, task, handoff, or case record.

## Procedure
1. Give each project and mission a stable identifier and named owner.
2. Keep project, mission, task, evidence, and finding lifecycles distinct.
3. Attach the current authorization envelope to each mission.
4. Preserve task dependencies, worker assignments, blockers, and decision history.
5. Delegate only bounded tasks with explicit asset/method allowlists and deadlines.
6. Keep durable records in an approved persistence adapter. The baseline in-memory registry is not durable storage.
7. Handoff with current state, evidence references, blockers, and next authorized actions.

## Hermes MCP Workflow
Use `vane_list_projects`, `vane_create_project`, `vane_create_mission`, `vane_get_mission`, and `vane_list_missions` for durable records. Use `vane_submit_mission`, `vane_start_mission`, `vane_add_blocker`, `vane_clear_blocker`, and `vane_request_evidence_review` to move the explicit mission lifecycle. Start/resume operations revalidate the stored signed authorization. The tools do not spawn worker sessions.

## Pitfalls
- A project record does not authorize a mission.
- A completed task does not close the mission.
- Never represent in-memory state as durable or independently recoverable.

## Verification
A handoff must be reconstructable from IDs, authorization references, event history, evidence, and unresolved blockers.
