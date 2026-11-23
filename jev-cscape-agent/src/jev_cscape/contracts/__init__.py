"""Engineering Contract Specification for JEV Cscape Agent.

Every tool, subagent, and test assertion must strictly adhere to:
    status: success | partial | failed | blocked | inconclusive
Prohibiting subjective or invented pseudo-statuses (e.g. 'VERIFIED', '100%').
"""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class AgentStatus(str, Enum):
    """The canonical states of the JEV engineering contract."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


class ExecutionResult(BaseModel):
    """Standardized result envelope conforming to the engineering contract."""
    status: AgentStatus
    error_code: Optional[str] = None
    details: str = Field(..., description="Factual description of outcome")
    data: Dict[str, Any] = Field(default_factory=dict, description="Structured execution payload")

    @property
    def output(self) -> Dict[str, Any]:
        return self.data

    @classmethod
    def success(cls, details: str, data: Optional[Dict[str, Any]] = None) -> "ExecutionResult":
        return cls(status=AgentStatus.SUCCESS, details=details, data=data or {})

    @classmethod
    def partial(cls, details: str, data: Optional[Dict[str, Any]] = None) -> "ExecutionResult":
        return cls(status=AgentStatus.PARTIAL, details=details, data=data or {})

    @classmethod
    def failed(cls, error_code: str, details: str, data: Optional[Dict[str, Any]] = None) -> "ExecutionResult":
        return cls(status=AgentStatus.FAILED, error_code=error_code, details=details, data=data or {})

    @classmethod
    def blocked(cls, error_code: str, details: str, data: Optional[Dict[str, Any]] = None) -> "ExecutionResult":
        return cls(status=AgentStatus.BLOCKED, error_code=error_code, details=details, data=data or {})

    @classmethod
    def inconclusive(cls, details: str, error_code: Optional[str] = None, data: Optional[Dict[str, Any]] = None) -> "ExecutionResult":
        return cls(status=AgentStatus.INCONCLUSIVE, error_code=error_code, details=details, data=data or {})


from .contract_validator import (
    ContractValidator,
    FalseSuccessPattern,
    FalseSuccessViolation,
    ValidationReport,
)

__all__ = [
    "AgentStatus",
    "ExecutionResult",
    "ContractValidator",
    "FalseSuccessPattern",
    "FalseSuccessViolation",
    "ValidationReport",
]
