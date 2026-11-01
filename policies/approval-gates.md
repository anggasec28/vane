# Approval Gates

Every mission requires a finite, signed Ed25519 approval bound to the exact authorization envelope. The envelope must identify the project, principal, assets, allowed methods, start time, expiry, and approval reference.

Routine read/observe actions may proceed autonomously only when the mission approval is valid and the exact asset/method is covered by the envelope.

High-risk methods require a second, separately signed Ed25519 approval bound to the exact locator and method. The baseline high-risk set includes active scanning, exploit validation, credential testing, transaction submission, state changes, data export, and destructive actions. The additional approval cannot outlive the authorization envelope.

Missing public keys, unknown key IDs, malformed or invalid signatures, expired approvals, mismatched digests, or missing authorization references mean DENY.

Protected identity/authority edits, deployment, reset, signing-key operations, and scope changes require explicit Master approval under their separate policies. Approval for one action cannot be stretched to materially different actions.
