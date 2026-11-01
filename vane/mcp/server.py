"""Local VANE MCP server exposing policy and evidence utilities only.

No network scanning, exploitation, transaction submission, key operations, or target mutation
is exposed by this server. Hermes connects over stdio after the Python extra is installed.
"""
from __future__ import annotations
import json
from datetime import datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from vane import __version__
from vane.assessment.web2 import plan_web2_surface_review
from vane.evidence.chain import verify_event_chain
from vane.evidence.manager import validate_evidence
from vane.models import Asset, EvidenceRecord, EvidenceStatus
from vane.security.authorization import require_authorized
from vane.security.serialization import authorization_from_dict

server = FastMCP("vane-engine")

@server.tool()
def vane_status() -> dict[str, Any]:
    """Return VANE engine version and safe capability status."""
    return {"name": "VANE", "version": __version__, "runtime": "Hermes Agent",
            "default_policy": "deny", "live_scanning_enabled": False,
            "transaction_submission_enabled": False, "signing_keys_in_engine": False}

@server.tool()
def vane_scope_check(envelope_json: str, locator: str, method: str) -> dict[str, Any]:
    """Check whether an exact asset and method are covered by an authorization envelope."""
    try:
        envelope = authorization_from_dict(json.loads(envelope_json))
        require_authorized(envelope, locator, method)
        return {"allowed": True, "decision": "ALLOW", "envelope_id": envelope.envelope_id,
                "locator": locator, "method": method}
    except Exception as exc:
        return {"allowed": False, "decision": "DENY", "reason": str(exc),
                "locator": locator, "method": method}

@server.tool()
def vane_plan_web2(envelope_json: str, assets_json: str) -> dict[str, Any]:
    """Create passive Web2 review work items for explicitly in-scope assets; performs no requests."""
    envelope = authorization_from_dict(json.loads(envelope_json))
    raw_assets = json.loads(assets_json)
    assets = [Asset(asset_id=str(item["asset_id"]), locator=str(item["locator"]),
                    asset_type=str(item.get("asset_type", "hostname")))
              for item in raw_assets]
    from vane.assessment.asset_mapping import classify_discovered_asset
    classified = [classify_discovered_asset(asset, envelope) for asset in assets]
    work = plan_web2_surface_review(classified, envelope)
    return {"work_items": [{"locator": item.locator, "activity": item.activity,
                            "rationale": item.rationale} for item in work],
            "assets": [{"asset_id": a.asset_id, "locator": a.locator,
                        "disposition": a.disposition.value} for a in classified],
            "execution_performed": False}

@server.tool()
def vane_validate_evidence(evidence_json: str) -> dict[str, Any]:
    """Validate required evidence identity, provenance, authorization link, and SHA-256 digest shape."""
    item = json.loads(evidence_json)
    record = EvidenceRecord(
        evidence_id=str(item["evidence_id"]), project_id=str(item["project_id"]),
        mission_id=str(item["mission_id"]), kind=str(item["kind"]),
        source=str(item["source"]), observed_at=datetime.fromisoformat(
            str(item["observed_at"]).replace("Z", "+00:00")),
        content_digest=str(item["content_digest"]),
        status=EvidenceStatus(item.get("status", "OBSERVED")),
        authorization_id=item.get("authorization_id"),
        collection_method=str(item.get("collection_method", "manual")),
        limitations=list(item.get("limitations", [])),
        parent_evidence_ids=list(item.get("parent_evidence_ids", [])),
        metadata=dict(item.get("metadata", {})),
    )
    validate_evidence(record)
    return {"valid": True, "evidence_id": record.evidence_id,
            "content_digest": record.content_digest}

@server.tool()
def vane_verify_event_chain(events_json: str) -> dict[str, Any]:
    """Verify a supplied hash-linked event sequence; does not anchor or mutate it."""
    result = verify_event_chain(json.loads(events_json))
    return {"valid": result.valid, "checked": result.checked,
            "failed_sequence": result.failed_sequence, "reason": result.reason}

def main() -> None:
    server.run(transport="stdio")

if __name__ == "__main__":
    main()
