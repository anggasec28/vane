# Project and Case Operations

Hybrid model: central governance defines identifiers, states, access, audit, and cross-case constraints; project context controls objectives, schedules, stakeholder workflow, and evidence organization.

Hierarchy: workspace → project → case/engagement → mission → task → evidence/finding.

A project may contain multiple cases; a case may contain multiple missions. Task completion does not imply mission closure; mission closure does not imply project closure.

Every handoff includes objective, scope reference, completed work, evidence references, unresolved questions, risks, next action, and expiry/approval context. Workers receive minimum necessary context and capability.


## Implemented case operations

Case work items and timeline events are stored in the project event chain. Work-item dependencies are validated for missing references and cycles. The read-only SLA evaluator classifies items as ON_TRACK, DUE_SOON, OVERDUE, BLOCKED, or COMPLETE and may recommend an escalation level. It does not schedule jobs, change item status, or notify stakeholders automatically.
