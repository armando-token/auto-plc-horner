"""Field Commissioning Lockout Guardian (Gate G12, Work Package W031).

Enforces permanent fail-closed zero-trust boundary against physical PLC hardware
access, controller downloads, port activation, and companion flashing utilities
unless explicit multi-party physical commissioning authorization is granted.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Set, Union
from uuid import uuid4

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.security.exceptions import CommissioningLockedError, HardwareLockoutError
from jev_cscape.security.guard import SecurityGuard

logger = logging.getLogger(__name__)


class _ClassOrInstanceProperty:
    """Descriptor supporting property access on both classes and instances."""

    def __init__(self, fget: Callable[[Any], Any]) -> None:
        self.fget = fget

    def __get__(self, instance: Any, owner: Any) -> Any:
        target = owner if instance is None else instance
        return self.fget(target)


class _DualMethod:
    """Descriptor allowing a method to be invoked as both classmethod and instancemethod."""

    def __init__(self, func: Callable[..., Any]) -> None:
        self.func = func

    def __get__(self, instance: Any, owner: Any) -> Callable[..., Any]:
        target = owner if instance is None else instance

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return self.func(target, *args, **kwargs)

        return wrapper


class CommissioningGuard:
    """Gate G12 fail-closed guardian blocking physical PLC commissioning attempts."""

    # Inherit and reference physical hardware protection constants
    BLOCKED_PORTS = SecurityGuard.BLOCKED_PORTS
    BLOCKED_FLASH_BINARIES: Set[str] = SecurityGuard.BLOCKED_FLASH_BINARIES
    BLOCKED_COMMAND_IDS: Set[int] = SecurityGuard.BLOCKED_COMMAND_IDS
    BLOCKED_CLI_SWITCHES: Set[str] = SecurityGuard.BLOCKED_CLI_SWITCHES

    # Default state is strictly fail-closed / unauthorized
    is_authorized: bool = False
    _audit_log: List[Dict[str, Any]] = []

    def __init__(self, authorized: bool = False) -> None:
        """Initialize CommissioningGuard instance with fail-closed default."""
        self.is_authorized: bool = bool(authorized)
        self._audit_log: List[Dict[str, Any]] = []

    @_ClassOrInstanceProperty
    def audit_log(self_or_cls: Any) -> List[Dict[str, Any]]:
        """Return a copy of the audit log of blocked commissioning attempts."""
        return list(self_or_cls._audit_log)

    @_DualMethod
    def is_commissioning_authorized(self_or_cls: Any) -> bool:
        """Check if physical PLC commissioning is explicitly authorized (default: False)."""
        return bool(self_or_cls.is_authorized)

    @_DualMethod
    def get_audit_log(self_or_cls: Any) -> List[Dict[str, Any]]:
        """Retrieve all recorded blocked physical commissioning audit log entries."""
        return list(self_or_cls._audit_log)

    @_DualMethod
    def clear_audit_log(self_or_cls: Any) -> None:
        """Clear audit log entries."""
        self_or_cls._audit_log.clear()

    @_DualMethod
    def _record_blocked_attempt(
        self_or_cls: Any,
        action: str,
        target: Any,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a blocked commissioning attempt into the audit log."""
        entry: Dict[str, Any] = {
            "id": f"AUDIT-{uuid4().hex[:8].upper()}",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "gate": "G12",
            "work_package": "W031",
            "action": action,
            "target": str(target) if target is not None else None,
            "status": "blocked",
            "error_code": "ERR_COMMISSIONING_LOCKED",
            "details": reason,
            "metadata": metadata or {},
        }

        self_or_cls._audit_log.append(entry)
        # If recording on an instance, also record on the class ledger for global auditing
        if not isinstance(self_or_cls, type):
            CommissioningGuard._audit_log.append(entry)

        logger.warning(
            "COMMISSIONING_LOCKOUT: Gate G12 blocked action '%s' for target '%s': %s",
            action,
            target,
            reason,
        )
        return entry

    @_DualMethod
    def assert_commissioning_authorized(
        self_or_cls: Any,
        action: str = "general_access",
        target: Any = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Assert that physical PLC commissioning is explicitly authorized.
        
        Raises:
            CommissioningLockedError: If commissioning is not explicitly authorized.
        """
        if not self_or_cls.is_commissioning_authorized():
            reason = (
                f"FAIL_CLOSED_COMMISSIONING_LOCKOUT: Gate G12 prohibits physical PLC commissioning. "
                f"Action '{action}' on target '{target}' blocked without explicit authorization."
            )
            self_or_cls._record_blocked_attempt(action, target, reason, metadata)
            exc = CommissioningLockedError(reason)
            exc.action = action  # type: ignore[attr-defined]
            exc.target = target  # type: ignore[attr-defined]
            exc.error_code = "ERR_COMMISSIONING_LOCKED"  # type: ignore[attr-defined]
            raise exc

    @_DualMethod
    def attempt_unlock(
        self_or_cls: Any,
        action: str,
        target: Any = None,
        details: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Generic attempt to unlock physical commissioning pathways."""
        meta = dict(metadata or {})
        if details:
            meta["details"] = details
        self_or_cls.assert_commissioning_authorized(action=action, target=target, metadata=meta)

    @_DualMethod
    def request_port_unlock(self_or_cls: Any, port_name: str) -> None:
        """Attempt to unlock a physical serial, CAN, USB, or JTAG port.
        
        Raises:
            CommissioningLockedError: If physical commissioning is unauthorized.
        """
        port_clean = str(port_name).strip()
        self_or_cls.assert_commissioning_authorized(
            action="unlock_port",
            target=port_clean,
            metadata={"port": port_clean},
        )

    @_DualMethod
    def request_flash_tool_unlock(self_or_cls: Any, binary_name: str) -> None:
        """Attempt to unlock companion flashing binary execution.
        
        Raises:
            CommissioningLockedError: If physical commissioning is unauthorized.
        """
        binary_clean = str(binary_name).strip()
        self_or_cls.assert_commissioning_authorized(
            action="unlock_flash_tool",
            target=binary_clean,
            metadata={"binary": binary_clean},
        )

    @_DualMethod
    def request_win32_download_unlock(self_or_cls: Any, command_id: Union[int, str]) -> None:
        """Attempt to unlock Win32 controller download command IDs (32827, 33149).
        
        Raises:
            CommissioningLockedError: If physical commissioning is unauthorized.
        """
        cmd_str = str(command_id).strip()
        self_or_cls.assert_commissioning_authorized(
            action="unlock_win32_download",
            target=cmd_str,
            metadata={"command_id": command_id},
        )

    @_DualMethod
    def assert_port_safe(self_or_cls: Any, port_name: str) -> None:
        """Validate port safety against fail-closed hardware lockout policy.
        
        Raises:
            CommissioningLockedError: If unauthorized attempt to access physical port occurs.
        """
        normalized = port_name.strip()
        for pattern in self_or_cls.BLOCKED_PORTS:
            if pattern.match(normalized):
                if not self_or_cls.is_commissioning_authorized():
                    reason = (
                        f"FAIL_CLOSED_HARDWARE_LOCKOUT: Access to physical hardware port '{port_name}' "
                        f"is strictly prohibited by Gate G12 commissioning lockout directive."
                    )
                    self_or_cls._record_blocked_attempt("access_port", port_name, reason)
                    raise CommissioningLockedError(reason)
                return

    @_DualMethod
    def assert_binary_execution_safe(self_or_cls: Any, binary_path_or_name: str) -> None:
        """Validate companion flash binary execution against fail-closed lockout policy.
        
        Raises:
            CommissioningLockedError: If unauthorized attempt to launch flash utility occurs.
        """
        normalized = binary_path_or_name.lower().replace("\\", "/").split("/")[-1]
        if normalized in self_or_cls.BLOCKED_FLASH_BINARIES:
            if not self_or_cls.is_commissioning_authorized():
                reason = (
                    f"FAIL_CLOSED_FLASH_LOCKOUT: Execution of companion flashing utility '{normalized}' "
                    f"is strictly prohibited by Gate G12 commissioning lockout directive."
                )
                self_or_cls._record_blocked_attempt("execute_flash_binary", normalized, reason)
                raise CommissioningLockedError(reason)

    @_DualMethod
    def assert_win32_command_safe(self_or_cls: Any, command_id: int) -> None:
        """Validate Win32 WM_COMMAND ID against fail-closed download lockout policy.
        
        Raises:
            CommissioningLockedError: If unauthorized attempt to dispatch download command occurs.
        """
        if command_id in self_or_cls.BLOCKED_COMMAND_IDS:
            if not self_or_cls.is_commissioning_authorized():
                reason = (
                    f"FAIL_CLOSED_WIN32_LOCKOUT: Win32 download command ID {command_id} "
                    f"is strictly intercepted and blocked by Gate G12 commissioning lockout directive."
                )
                self_or_cls._record_blocked_attempt("dispatch_win32_download", command_id, reason)
                raise CommissioningLockedError(reason)

    @_DualMethod
    def assert_cli_switches_safe(self_or_cls: Any, args: List[str]) -> None:
        """Validate CLI flags against fail-closed flashing switches.
        
        Raises:
            CommissioningLockedError: If unauthorized download/flash switch is provided.
        """
        for arg in args:
            if arg.lower() in self_or_cls.BLOCKED_CLI_SWITCHES:
                if not self_or_cls.is_commissioning_authorized():
                    reason = (
                        f"FAIL_CLOSED_SWITCH_LOCKOUT: Download/flash CLI switch '{arg}' "
                        f"is strictly prohibited by Gate G12 commissioning lockout directive."
                    )
                    self_or_cls._record_blocked_attempt("cli_download_switch", arg, reason)
                    raise CommissioningLockedError(reason)

    @_DualMethod
    def export_audit_log(
        self_or_cls: Any,
        output_path: Optional[Union[str, Path]] = None,
    ) -> str:
        """Serialize audit log to JSON string and optionally write to file."""
        payload = {
            "gate": "G12",
            "work_package": "W031",
            "export_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "is_authorized": self_or_cls.is_commissioning_authorized(),
            "total_blocked_attempts": len(self_or_cls._audit_log),
            "audit_records": self_or_cls._audit_log,
        }
        json_str = json.dumps(payload, indent=2)
        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json_str, encoding="utf-8")
        return json_str
