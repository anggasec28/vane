# Worker Delegation and Independent Validation

Workers are subordinate execution contexts. Every delegated task must include a parent mission, named worker profile, explicit objective, finite asset allowlist, explicit method allowlist, deadline, and approval reference. Workers cannot expand their asset or method set. Results are rejected if identity, task, or asset references do not match the delegation.

Independent validation is separate from task execution. It checks evidence completeness, unresolved blockers, finding-to-evidence references, and mission state. A successful worker result is not a closure decision. Validation results are recorded as checks, not silently converted into approval.

The current implementation provides bounded delegation, result validation, and deterministic validators. It persists delegated task contracts when a repository is configured; assignment/completion state remains in memory. High-risk worker methods are denied by default. It does not spawn Hermes worker sessions or invoke tools; high-risk worker methods are denied until a separately approved delegation path exists.
