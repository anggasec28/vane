---
name: web2-assessment
description: Plan bounded Web2 security reviews with evidence goals.
version: 0.2.0
metadata:
  hermes:
    tags: [security, web2, assessment]
    category: security
---
# Web2 Assessment

## When to Use
Use for authorized web application, API, hostname, and service assessments.

## Procedure
1. Confirm the authorization envelope and method allowlist.
2. Use the VANE planning MCP tool to prepare passive review work items for in-scope assets.
3. Separate passive metadata review from active testing. The baseline MCP planner performs no network requests.
4. Define evidence objectives for identity, routing, application behavior, access control, input handling, session boundaries, and relevant dependencies.
5. Trace root causes only through evidence-backed, in-scope dependencies.
6. Record blocked observations and missing evidence explicitly.
7. Propose active testing only when the exact method is authorized and the relevant adapter has separately passed review.

## Pitfalls
- HTTP status alone does not prove application visibility or vulnerability.
- A redirect to a block page is a blocked observation, not proof that the origin is absent.
- Never follow discovered links or hosts beyond the authorization envelope.

## Verification
Produce an evidence-linked surface map, method coverage, limitations, and unresolved evidence gaps.
