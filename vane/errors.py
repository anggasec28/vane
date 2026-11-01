"""Domain exceptions. Callers should handle these without weakening policy."""
class VaneError(Exception):
    """Base class for expected VANE domain failures."""

class AuthorizationError(VaneError):
    """An action is not covered by the active authorization envelope."""

class PolicyViolation(VaneError):
    """A requested transition violates a mandatory policy."""

class InvalidTransition(VaneError):
    """A mission or artifact transition is not permitted."""

class EvidenceError(VaneError):
    """Evidence is incomplete, invalid, or lacks required provenance."""
