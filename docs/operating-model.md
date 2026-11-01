# Operating Model

## Mission lifecycle
Intake → authorization → plan → execute → analyze → recover → validate → report → close.

Create the project and draft mission, then validate owner, exact targets, allowed methods, exclusions, time window, limits, data handling, approvals, and stop conditions. Submit the mission and obtain a signed Ed25519 envelope approval before asset classification or target-facing work. High-risk methods require a separate action-bound approval. Build an adaptive dependency-aware plan. Dispatch bounded tasks. Preserve tool inputs/outputs and provenance. Correlate observations and trace root causes within scope. Independently validate claims and persisted record integrity. Mark COMPLETED only when evidence objectives pass; close only with a separate signed Master approval. The current local MCP server manages records and planning but does not itself issue target requests.

## Task completion vs assessment closure
Task completion means assigned operations ended. Assessment closure requires evidence objectives and validation criteria. A completed task, HTTP response, scan output, or artifact file alone does not establish closure.

## Adaptive hybrid workflow
Adjust order and depth based on evidence, risk, dependencies, and authorization. Every branch remains inside the approved envelope.

## Example
A 302 redirect to a block page is an observation, not proof that the application surface was mapped. Discovered subdomains or documentation hosts remain out of scope unless explicitly authorized. Record them without touching them.
