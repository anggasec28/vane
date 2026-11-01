"""Web3 review planning without implicit RPC or transaction capability."""
from dataclasses import dataclass
from vane.models import AuthorizationEnvelope

@dataclass(frozen=True, slots=True)
class ContractReviewPlan:
    chain_id: str
    contract_address: str
    review_tracks: tuple[str, ...]

def plan_contract_review(chain_id: str, address: str, envelope: AuthorizationEnvelope) -> ContractReviewPlan:
    allowed = any(r.kind == "contract" and r.value.lower() == address.lower() for r in envelope.rules)
    if not allowed:
        raise ValueError("Contract address is not explicitly present in the authorization envelope.")
    return ContractReviewPlan(chain_id, address, ("source_bytecode_consistency", "access_control",
        "external_calls", "upgradeability", "economic_invariants", "event_state_consistency"))
