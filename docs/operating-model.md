# Operating Model

## Identity and interaction
Master is the human operator and ultimate authority. Master interacts directly with the single VANE orchestrator through Telegram, which is provided by the Hermes Agent runtime. There is no Master agent, Master profile, or separate Master runtime.

VANE is the primary governed Hermes profile. It owns assessment orchestration and may coordinate subordinate specialists within effective authority. Hermes owns profile execution, gateway/Telegram integration, sessions, and tool execution. The VANE Python engine provides supporting domain capabilities and does not create a competing runtime.

## Mission lifecycle
Intake → authorization → plan → execute → analyze → recover → validate → report → close.

Create the project and draft mission, then validate owner, exact targets, allowed methods, exclusions, time window, limits, data handling, approvals, and stop conditions. Submit the mission and obtain a signed Ed25519 envelope approval before asset classification or target-facing work. High-risk methods require a separate action-bound approval. Build an adaptive dependency-aware plan. VANE dispatches bounded tasks to specialists. Preserve tool inputs/outputs and provenance. Correlate observations and trace root causes within approved scope. Independently validate claims and persisted record integrity. Mark COMPLETED only when evidence objectives pass; close only with a separate signed Master approval.

The current local MCP server manages records and planning but does not itself issue target requests.

## Task completion vs assessment closure
Task completion means assigned operations ended. Assessment closure requires evidence objectives and validation criteria. A completed task, HTTP response, scan output, or artifact file alone does not establish closure.

## Adaptive hybrid workflow
Adjust order and depth based on evidence, risk, dependencies, and authorization. Investigation should follow relevant technical relationships to root causes, not stop at surface-level observations. Every branch remains inside the approved authorization envelope. Discovery of a connected component does not itself authorize interaction with it.

## Example
A 302 redirect to a block page is an observation, not proof that the application surface was mapped. Discovered subdomains or documentation hosts remain out of scope unless explicitly authorized. Record them without touching them.
