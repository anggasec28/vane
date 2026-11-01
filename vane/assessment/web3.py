"""Web3 review planning without implicit RPC or transaction capability."""
from dataclasses import dataclass
from vane.errors import AuthorizationError
from vane.models import AuthorizationEnvelope

@dataclass(frozen=True, slots=True)
class ContractReviewPlan:
    chain_id: str
    contract_address: str
    review_tracks: tuple[str, ...]

def plan_contract_review(chain_id: str, address: str, envelope: AuthorizationEnvelope) -> ContractReviewPlan:
    if not envelope.is_time_valid():
        raise AuthorizationError("Web3 planning requires an active, approved, time-bounded envelope.")
    if "contract_read" not in {method.lower() for method in envelope.allowed_methods}:
        raise AuthorizationError("The envelope does not allow the contract_read method.")
    allowed = any(rule.kind == "contract" and rule.value.lower() == address.lower()
                  for rule in envelope.rules)
    if not allowed:
        raise AuthorizationError("Contract address is not explicitly present in the authorization envelope.")
    return ContractReviewPlan(chain_id, address, ("source_bytecode_consistency", "access_control",
        "external_calls", "upgradeability", "economic_invariants", "event_state_consistency"))
