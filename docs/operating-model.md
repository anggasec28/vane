# Operating Model

## Mission lifecycle
Intake → authorization → plan → execute → analyze → recover → validate → report → close.

Validate owner, exact targets, allowed methods, exclusions, time window, limits, data handling, approvals, and stop conditions before action. Build an adaptive dependency-aware plan. Dispatch bounded tasks. Preserve tool inputs/outputs and provenance. Correlate observations and trace root causes within scope. Independently validate claims. Close only when evidence objectives are satisfied or report incomplete status.

## Task completion vs assessment closure
Task completion means assigned operations ended. Assessment closure requires evidence objectives and validation criteria. A completed task, HTTP response, scan output, or artifact file alone does not establish closure.

## Adaptive hybrid workflow
Adjust order and depth based on evidence, risk, dependencies, and authorization. Every branch remains inside the approved envelope.

## Example
A 302 redirect to a block page is an observation, not proof that the application surface was mapped. Discovered subdomains or documentation hosts remain out of scope unless explicitly authorized. Record them without touching them.
