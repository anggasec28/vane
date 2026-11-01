---
name: mcp-tool-governance
description: Govern MCP tools by capability, scope, and side effect.
version: 0.2.0
metadata:
  hermes:
    tags: [security, mcp, tools]
    category: security
---
# MCP Tool Governance

## When to Use
Use before invoking any MCP server or newly discovered tool.

## Procedure
1. Resolve the server, tool name, schema, version, side effects, and data sensitivity.
2. Confirm the capability is registered in the VANE allowlist and enabled for the current task.
3. Apply exact asset and method authorization before invocation.
4. Use per-server tool allowlists in Hermes config. Keep resources and prompts disabled unless required.
5. Validate arguments and bound result size, time, and asset set.
6. Record the tool identity, arguments digest, result digest, authorization, and limitations.
7. Deny unknown, changed, or newly introduced tools until reviewed.

## Pitfalls
- Tool availability is not authorization.
- A server connection does not imply every advertised tool is approved.
- Never pass secrets in tool arguments or logs.

## Verification
Confirm the exact tool and schema are approved, the action is in scope, and the result is linked to an evidence record.
