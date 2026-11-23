"""Tests for Win32CommandInterceptor fail-closed security and safe dispatch."""

import pytest
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.exceptions import HardwareLockoutError
from jev_cscape.contracts import AgentStatus


def test_interceptor_blocks_program_download():
    # ID_PROGRAM_DOWNLOAD = 32827
    with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_HARDWARE_LOCKOUT"):
        Win32CommandInterceptor.assert_command_safe(32827)


def test_interceptor_blocks_controller_download():
    # ID_CONTROLLER_DOWNLOAD = 33149
    with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_HARDWARE_LOCKOUT"):
        Win32CommandInterceptor.assert_command_safe(33149)


def test_interceptor_permits_error_check():
    # ID_PROGRAM_ERRORCHECK = 32826
    Win32CommandInterceptor.assert_command_safe(32826)


def test_dispatch_safe_command_intercepts_download():
    # Attempting to dispatch a blocked download command must return BLOCKED result
    res = Win32CommandInterceptor.dispatch_safe_command(hwnd=12345, cmd_id=32827)
    assert res.status == AgentStatus.BLOCKED
    assert res.error_code == "FAIL_CLOSED_WIN32_LOCKOUT"


def test_dispatch_safe_command_invalid_hwnd():
    # Safe command with non-existent HWND must return FAILED
    res = Win32CommandInterceptor.dispatch_safe_command(hwnd=99999999, cmd_id=32826)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "INVALID_HWND"
