"""Cscape Launcher for JEV Cscape Agent.

Provides dedicated CscapeLauncher interface for starting, managing, and inspecting
Cscape 10.2 application instances on winsta0\\Default.
"""

from typing import Optional
from jev_cscape.automation.lifecycle import CscapeLifecycleController
from jev_cscape.contracts import ExecutionResult


class CscapeLauncher(CscapeLifecycleController):
    """Launcher and process manager for Cscape 10.2 on interactive desktop winsta0\\Default."""

    def __init__(self, cscape_exe: Optional[str] = None):
        if cscape_exe:
            super().__init__(cscape_exe=cscape_exe)
        else:
            super().__init__()
