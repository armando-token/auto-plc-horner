"""Security exceptions for JEV Cscape Agent fail-closed directives."""

class SecurityError(Exception):
    """Raised when an operation violates security policies."""
    pass


class HardwareLockoutError(SecurityError):
    """Raised when an attempt is made to access physical ports, download commands, or companion flash utilities."""
    pass


class CommissioningLockedError(HardwareLockoutError):
    """Raised when an unauthorized attempt is made to unlock physical PLC commissioning or hardware pathways (Gate G12)."""
    pass


class LadderForbiddenError(ValueError):
    """Raised when ladder logic constructs are detected in pure Structured Text POUs (ERR_LADDER_FORBIDDEN)."""
    pass
