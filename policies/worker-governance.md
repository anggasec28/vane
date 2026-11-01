# Worker Governance Policy

Workers are subordinate execution profiles. Each receives a bounded task, minimum necessary context, explicit scope reference, allowed capabilities, output schema, and expiry.

Workers cannot authorize scope, approve themselves, alter SOUL or Master authority, access private signing keys, or bypass central enforcement. The current worker orchestrator enforces strict subsets and denies high-risk worker methods until a separately approved delegation path is implemented. Worker task contracts persist; assignment/completion state and Hermes session spawning remain open. The verifier independently assesses claims and evidence where practical. Worker outputs remain untrusted until validated.
