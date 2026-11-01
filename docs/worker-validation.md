# Worker Delegation and Independent Validation

Workers are subordinate execution contexts. Every delegated task must include a parent mission, named worker profile, explicit objective, finite asset allowlist, explicit method allowlist, deadline, and approval reference. Workers cannot expand their asset or method set. Results are rejected if identity, task, or asset references do not match the delegation.

Independent validation is separate from task execution. It checks evidence completeness, unresolved blockers, finding-to-evidence references, and mission state. A successful worker result is not a closure decision. Validation results are recorded as checks, not silently converted into approval.

The repository implementation provides bounded delegation, specialist-profile allowlisting, strict result validation, durable task and assignment records, restore-on-demand after engine restart, and persisted completion/revocation history. Initial task and assignment persistence is atomic. Completion or revocation persistence failures roll back the in-memory assignment. Hermes session spawning, tool execution, host scheduling, and runtime compatibility remain with the operator's Hermes agent.
