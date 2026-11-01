# MCP and Skill Integration

MCP servers expose tools; skills describe when and how VANE uses capabilities. Neither tool discovery nor successful connection grants authorization.

For each tool register stable id, provider/server, operations, input/output schema, side effects, data sensitivity, approval requirements, scope semantics, timeout/retry behavior, audit fields, and failure modes.

Invocation: resolve capability → evaluate authorization/policy → validate arguments and scope → obtain required approval → invoke bounded parameters → capture output/provenance → evaluate evidence value.

Use least privilege. General tools and verifier profiles never receive private signing keys. Read-only audit profiles remain allowlisted. Unknown or materially changed tools are denied pending review.
