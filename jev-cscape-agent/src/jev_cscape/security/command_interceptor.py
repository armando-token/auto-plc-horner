"""Fail-Closed Win32 Command Interceptor for Cscape 10.2.

Intercepts Win32 WM_COMMAND messages dispatched to Cscape main frame.
Enforces permanent lockout of physical controller download commands:
- ID_PROGRAM_DOWNLOAD = 32827
- ID_CONTROLLER_DOWNLOAD = 33149

Permits safe diagnostic commands such as:
- ID_PROGRAM_ERRORCHECK = 32826 (Ctrl+F7)
- ID_VIEW_PROJECT_NAVIGATOR = 32800
- ID_VIEW_OUTPUT_WINDOW = 32801
"""

import logging
from typing import Any, Dict, Optional, Set
import win32con
import win32gui

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.security.exceptions import HardwareLockoutError

logger = logging.getLogger(__name__)


class Win32CommandInterceptor:
    """Security interceptor guarding Win32 WM_COMMAND dispatches to Cscape."""

    BLOCKED_COMMAND_MAP: Dict[int, str] = {
        32827: "ID_PROGRAM_DOWNLOAD",
        33149: "ID_CONTROLLER_DOWNLOAD",
    }

    PERMITTED_COMMAND_MAP: Dict[int, str] = {
        32826: "ID_PROGRAM_ERRORCHECK",
        32800: "ID_VIEW_PROJECT_NAVIGATOR",
        32801: "ID_VIEW_OUTPUT_WINDOW",
        57600: "ID_FILE_NEW",
        57601: "ID_FILE_OPEN",
        57602: "ID_FILE_CLOSE",
        57603: "ID_FILE_SAVE",
        57604: "ID_FILE_SAVE_AS",
        57665: "ID_APP_EXIT",
    }

    @classmethod
    def assert_command_safe(cls, cmd_id: int) -> None:
        """Assert command ID is not blocked by fail-closed hardware lockout.
        
        Raises:
            HardwareLockoutError if command is a prohibited physical download.
        """
        if cmd_id in cls.BLOCKED_COMMAND_MAP:
            cmd_name = cls.BLOCKED_COMMAND_MAP[cmd_id]
            raise HardwareLockoutError(
                f"FAIL_CLOSED_HARDWARE_LOCKOUT: Command ID {cmd_id} ({cmd_name}) is permanently "
                f"blocked by safety policy. Direct PLC physical download is prohibited."
            )

    @classmethod
    def dispatch_safe_command(
        cls,
        hwnd: int,
        cmd_id: int,
        lparam: int = 0,
        use_post: bool = True,
    ) -> ExecutionResult:
        """Validate command safety and dispatch WM_COMMAND to target HWND."""
        # 1. Fail-closed security intercept
        try:
            cls.assert_command_safe(cmd_id)
        except HardwareLockoutError as e:
            logger.critical(f"Security interceptor blocked command {cmd_id}: {e}")
            return ExecutionResult.blocked(
                error_code="FAIL_CLOSED_WIN32_LOCKOUT",
                details=str(e),
                data={"command_id": cmd_id, "command_name": cls.BLOCKED_COMMAND_MAP.get(cmd_id)},
            )

        # 2. Window validation
        if not win32gui.IsWindow(hwnd):
            return ExecutionResult.failed(
                error_code="INVALID_HWND",
                details=f"Target window handle {hwnd} ({hex(hwnd)}) is not a valid Win32 window.",
            )

        cmd_name = cls.PERMITTED_COMMAND_MAP.get(cmd_id, f"CUSTOM_COMMAND_{cmd_id}")

        # 3. Message dispatch
        try:
            if use_post:
                win32gui.PostMessage(hwnd, win32con.WM_COMMAND, cmd_id, lparam)
            else:
                win32gui.SendMessage(hwnd, win32con.WM_COMMAND, cmd_id, lparam)

            return ExecutionResult.success(
                details=f"Dispatched WM_COMMAND {cmd_id} ({cmd_name}) to HWND {hex(hwnd)} successfully.",
                data={"command_id": cmd_id, "command_name": cmd_name, "hwnd": hwnd, "use_post": use_post},
            )
        except Exception as e:
            return ExecutionResult.failed(
                error_code="DISPATCH_ERROR",
                details=f"Failed to dispatch WM_COMMAND {cmd_id} to HWND {hex(hwnd)}: {e}",
            )
