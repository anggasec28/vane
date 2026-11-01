"""Readiness checks distinguish code presence from operational authorization."""
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class ReadinessItem:
    name: str
    passed: bool
    detail: str

@dataclass(frozen=True, slots=True)
class ReadinessReport:
    items: tuple[ReadinessItem, ...]
    @property
    def ready(self) -> bool:
        return all(item.passed for item in self.items)

def evaluate_release_readiness(*, tests_passed: bool, manifest_verified: bool,
                               decision_traceability_complete: bool,
                               runtime_approval: bool = False,
                               production_approval: bool = False) -> ReadinessReport:
    items = (
        ReadinessItem("tests", tests_passed, "Automated test suite result."),
        ReadinessItem("manifest", manifest_verified, "Repository inventory matches manifest."),
        ReadinessItem("traceability", decision_traceability_complete, "Requirements map to implementation."),
        ReadinessItem("runtime_approval", runtime_approval, "Explicit approval for Hermes runtime integration."),
        ReadinessItem("production_approval", production_approval, "Explicit production authorization."),
    )
    return ReadinessReport(items)
