"""Multi-Agent Hierarchy, JevPolicy & FastMCP Tool Registry.

Work Package: W025 / Megaplan 12.3 & 12.4
Classification: PRODUCTION_READY

Provides:
- JevPolicy: TypeSafe SystemOne decision engine (state + typed choice/noul questions)
- FastMCPToolRegistry: 16-tool FastMCP registry and JSON-RPC 2.0 protocol server
"""

from .policy import (
    JevPolicy,
    JevDecision,
    ChoiceQuestion,
    NoulQuestion,
    ScoreQuestion,
    ChoiceAnswer,
)
from .registry import (
    ToolParameter,
    ToolDefinition,
    FastMCPToolRegistry,
)
from .server import (
    FastMCPServer,
)

__all__ = [
    "JevPolicy",
    "JevDecision",
    "ChoiceQuestion",
    "NoulQuestion",
    "ScoreQuestion",
    "ChoiceAnswer",
    "ToolParameter",
    "ToolDefinition",
    "FastMCPToolRegistry",
    "FastMCPServer",
]
