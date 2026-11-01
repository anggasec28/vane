---
name: data-lifecycle
description: Apply policy-driven retention and preservation decisions.
version: 0.2.0
metadata:
  hermes:
    tags: [security, data, retention]
    category: security
---
# Data Lifecycle Governance

## When to Use
Use when retaining, archiving, reviewing, or proposing disposal of project data and evidence.

## Procedure
1. Classify data by sensitivity and evidentiary role.
2. Consider project activity, ownership, dispute status, preservation holds, and retention expiry.
3. Preserve records when ownership or status is unknown.
4. Require an authorized, reasoned, recorded exception for policy deviation.
5. Treat disposal as a proposed action requiring approval, not an automatic timer event.
6. Preserve audit metadata and chain-of-custody references.

## Engine Tool

Use `mcp__vane_engine__vane_lifecycle_decision` to obtain a retention decision. The tool never deletes data; any disposal remains a separately approved action.

## Pitfalls
- Unknown ownership is not permission to delete.
- Expired retention does not override legal, contractual, or evidentiary holds.
- A backup is not proof that the authoritative record can be discarded.

## Verification
Record the data class, context, decision, authority, rationale, and any required approval.
