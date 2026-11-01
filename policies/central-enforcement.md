# Central Security Enforcement

A single logical policy decision point governs all enforcement points. Every tool, worker, workflow transition, evidence mutation, and lifecycle action is evaluated.

Decision outputs: ALLOW, DENY, REQUIRE_APPROVAL, NOT_APPLICABLE. Include policy version and machine-readable reason.

Deny when authorization is missing/invalid, target is out of scope, method is unapproved, approval expired, data handling prohibited, worker privilege mismatched, integrity fails, policy is uncertain, or stop condition is active.

Workers, MCP tools, fallback tools, retries, and recovery routines cannot bypass enforcement. Policy service unavailability fails closed for consequential actions.
