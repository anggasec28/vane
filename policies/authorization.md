# Authorization and Scope Policy

Every engagement defines owner/authority, exact targets, allowed actions, exclusions, methods, time window, rate/concurrency limits, data handling, approvals, and stop conditions.

DNS relationships, redirects, certificates, links, shared infrastructure, adjacent subdomains, repositories, wallets, and discovered contracts do not automatically extend scope.

Follow a symlink only when its resolved target is within the approved inspection boundary. Otherwise record NOT_INSPECTED and the reason; do not silently skip or inspect it.

Authorization expires at its stated time or on material scope/ownership/context change. Revalidate before continuing. Ambiguity is deny-by-default.

Bind each action to authorization_id, scope version, principal, tool, target, method, timestamp, and approval reference.
