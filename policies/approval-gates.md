# Approval Gates

Routine in-scope read/observe actions may run autonomously only when explicitly permitted by the active envelope. Elevated actions require the approval specified by that envelope.

Destructive, state-changing, credential-sensitive, signing, reset, deployment, and scope-changing actions require explicit Master approval unless a separately approved policy defines narrower delegated authority.

Approval binds action, target, parameters/bounds, purpose, expiry, and authority. Generic approval cannot be stretched to materially different actions. Missing, expired, mismatched, or changed approval means DENY and request a new decision.

Protected identity/authority edits require explicit Master confirmation after explanation of exact changes, rationale, impact, risks, and rollback.
