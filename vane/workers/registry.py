"""Typed specialist registry independent of Hermes session management."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from vane.errors import PolicyViolation


@dataclass(frozen=True, slots=True)
class SpecialistContract:
    profile_id: str
    title: str
    responsibilities: tuple[str, ...]
    required_inputs: tuple[str, ...]
    allowed_activities: tuple[str, ...]
    prohibited_activities: tuple[str, ...]
    output_type: str
    required_output_fields: tuple[str, ...]


class SpecialistRegistry:
    def __init__(self, contracts: Iterable[SpecialistContract]) -> None:
        self._contracts: dict[str, SpecialistContract] = {}
        for contract in contracts:
            if not contract.profile_id or contract.profile_id in self._contracts:
                raise ValueError("Specialist profile IDs must be non-empty and unique.")
            if not contract.output_type or not contract.required_output_fields:
                raise ValueError(f"Specialist {contract.profile_id} has no output contract.")
            self._contracts[contract.profile_id] = contract

    def get(self, profile_id: str) -> SpecialistContract:
        try:
            return self._contracts[profile_id]
        except KeyError as exc:
            raise PolicyViolation(f"Unknown specialist profile: {profile_id}") from exc

    def validate_dispatch(self, profile_id: str, *, supplied_inputs: set[str],
                          requested_activities: set[str]) -> SpecialistContract:
        contract = self.get(profile_id)
        missing = set(contract.required_inputs) - supplied_inputs
        if missing:
            raise PolicyViolation("Specialist dispatch is missing inputs: " + ", ".join(sorted(missing)))
        prohibited = requested_activities & set(contract.prohibited_activities)
        if prohibited:
            raise PolicyViolation("Specialist dispatch requests prohibited activities: " +
                                  ", ".join(sorted(prohibited)))
        unknown = requested_activities - set(contract.allowed_activities)
        if unknown:
            raise PolicyViolation("Specialist dispatch requests undeclared activities: " +
                                  ", ".join(sorted(unknown)))
        return contract

    def validate_output(self, profile_id: str, output: dict) -> None:
        contract = self.get(profile_id)
        if output.get("type") != contract.output_type:
            raise PolicyViolation("Specialist output type does not match its registered contract.")
        missing = set(contract.required_output_fields) - output.keys()
        if missing:
            raise PolicyViolation("Specialist output is missing fields: " + ", ".join(sorted(missing)))

    @property
    def profile_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._contracts))
