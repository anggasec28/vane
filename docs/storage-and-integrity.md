# Storage and Event Integrity

The SQLite store provides typed project/authorization/mission/asset/evidence/finding/approval/worker-task persistence and a transactionally appended, per-project hash-linked event sequence. Domain-record revisions and their audit events are committed atomically. An append takes SQLite's write reservation before reading the current project head, computes the canonical event digest, and commits the event in the same transaction. This serializes concurrent writers within the database.

The event chain detects modification, reordering, and deletion within the retained sequence when verified against a trusted head. Current domain-record rows are also compared with their latest recorded record digests, so row tampering or deletion is detected against the retained event history. A local hash chain alone does not prevent an attacker with write access from rewriting the entire database or truncating the unanchored tail. Independent tamper evidence requires an external anchor and trusted head publication. Those L3/R-12 controls remain open and are not claimed as implemented.

The event store is a persistence foundation, not a complete domain repository layer. Project, mission, finding, and evidence repository migrations remain future implementation work.
