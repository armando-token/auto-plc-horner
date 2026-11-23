"""Tests for Gate G12 Field Commissioning Fail-Closed Hardware Lockout (Work Package W031)."""

import json
from pathlib import Path
import pytest

from jev_cscape.security.commissioning import CommissioningGuard
from jev_cscape.security.exceptions import (
    CommissioningLockedError,
    HardwareLockoutError,
    SecurityError,
)
from jev_cscape.security.guard import SecurityGuard


@pytest.fixture(autouse=True)
def reset_guard_state():
    """Ensure clean class-level state for each test."""
    CommissioningGuard.is_authorized = False
    CommissioningGuard.clear_audit_log()
    yield
    CommissioningGuard.is_authorized = False
    CommissioningGuard.clear_audit_log()


def test_default_state_is_locked_unauthorized():
    """Verify that physical PLC commissioning defaults to unauthorized (fail-closed)."""
    assert CommissioningGuard.is_authorized is False
    assert CommissioningGuard.is_commissioning_authorized() is False

    guard = CommissioningGuard()
    assert guard.is_authorized is False
    assert guard.is_commissioning_authorized() is False
    assert len(guard.audit_log) == 0


def test_exception_hierarchy():
    """Verify CommissioningLockedError inherits from HardwareLockoutError and SecurityError."""
    assert issubclass(CommissioningLockedError, HardwareLockoutError)
    assert issubclass(CommissioningLockedError, SecurityError)
    assert issubclass(CommissioningLockedError, Exception)

    err = CommissioningLockedError("test failure")
    assert isinstance(err, HardwareLockoutError)
    assert isinstance(err, SecurityError)


def test_unauthorized_port_unlock_requests_blocked():
    """Verify unauthorized attempts to unlock physical ports raise CommissioningLockedError."""
    guard = CommissioningGuard()
    test_ports = [
        "COM1", "COM2", "COM10", "com256",
        r"\\.\COM1", r"\\.\COM10",
        "/dev/ttyUSB0", "/dev/ttyS0",
        "CAN0", "CAN1",
        "USB0", "USB1",
        "JTAG", "JTAG_INTERFACE",
    ]
    for port in test_ports:
        with pytest.raises(CommissioningLockedError, match="FAIL_CLOSED_COMMISSIONING_LOCKOUT"):
            guard.request_port_unlock(port)


def test_unauthorized_flash_tool_unlock_requests_blocked():
    """Verify unauthorized attempts to unlock companion flash tools raise CommissioningLockedError."""
    guard = CommissioningGuard()
    test_binaries = [
        "PGMUpdateUtility.exe",
        "pgmupdateutility.exe",
        "DfuSeCommand.exe",
        "dfusecommand.exe",
        "STMFlashLoader.exe",
        "stmflashloader.exe",
        "WinJTAG.exe",
        "winjtag.exe",
    ]
    for b in test_binaries:
        with pytest.raises(CommissioningLockedError, match="FAIL_CLOSED_COMMISSIONING_LOCKOUT"):
            guard.request_flash_tool_unlock(b)


def test_unauthorized_win32_download_unlock_requests_blocked():
    """Verify unauthorized attempts to unlock Win32 download commands raise CommissioningLockedError."""
    guard = CommissioningGuard()
    blocked_commands = [
        32827,  # ID_PROGRAM_DOWNLOAD
        33149,  # ID_CONTROLLER_DOWNLOAD
        "32827",
        "33149",
        "ID_PROGRAM_DOWNLOAD",
        "ID_CONTROLLER_DOWNLOAD",
    ]
    for cmd in blocked_commands:
        with pytest.raises(CommissioningLockedError, match="FAIL_CLOSED_COMMISSIONING_LOCKOUT"):
            guard.request_win32_download_unlock(cmd)


def test_generic_attempt_unlock_and_assertion_blocked():
    """Verify generic attempt_unlock and assert_commissioning_authorized fail closed."""
    guard = CommissioningGuard()
    with pytest.raises(CommissioningLockedError, match="FAIL_CLOSED_COMMISSIONING_LOCKOUT"):
        guard.attempt_unlock(action="unlock_all_hardware", target="global", details="Emergency bypass attempt")

    with pytest.raises(CommissioningLockedError, match="FAIL_CLOSED_COMMISSIONING_LOCKOUT"):
        guard.assert_commissioning_authorized(action="general_access")


def test_audit_log_records_blocked_attempts():
    """Verify blocked commissioning attempts are recorded accurately in the audit log."""
    guard = CommissioningGuard()
    guard.clear_audit_log()

    # Trigger 3 blocked events
    with pytest.raises(CommissioningLockedError):
        guard.request_port_unlock("COM1")

    with pytest.raises(CommissioningLockedError):
        guard.request_flash_tool_unlock("PGMUpdateUtility.exe")

    with pytest.raises(CommissioningLockedError):
        guard.request_win32_download_unlock(32827)

    log = guard.get_audit_log()
    assert len(log) == 3
    assert len(guard.audit_log) == 3

    # Validate first entry (COM1)
    entry0 = log[0]
    assert entry0["gate"] == "G12"
    assert entry0["work_package"] == "W031"
    assert entry0["action"] == "unlock_port"
    assert entry0["target"] == "COM1"
    assert entry0["status"] == "blocked"
    assert entry0["error_code"] == "ERR_COMMISSIONING_LOCKED"
    assert "COM1" in entry0["details"]
    assert "timestamp_utc" in entry0
    assert entry0["id"].startswith("AUDIT-")

    # Validate second entry (flash tool)
    entry1 = log[1]
    assert entry1["action"] == "unlock_flash_tool"
    assert entry1["target"] == "PGMUpdateUtility.exe"
    assert entry1["status"] == "blocked"

    # Validate third entry (download command)
    entry2 = log[2]
    assert entry2["action"] == "unlock_win32_download"
    assert entry2["target"] == "32827"
    assert entry2["status"] == "blocked"


def test_class_level_direct_invocation():
    """Verify CommissioningGuard works at class level without instantiation."""
    CommissioningGuard.clear_audit_log()
    assert CommissioningGuard.is_commissioning_authorized() is False

    with pytest.raises(CommissioningLockedError):
        CommissioningGuard.request_port_unlock("COM99")

    with pytest.raises(CommissioningLockedError):
        CommissioningGuard.request_flash_tool_unlock("DfuSeCommand.exe")

    with pytest.raises(CommissioningLockedError):
        CommissioningGuard.request_win32_download_unlock(33149)

    class_log = CommissioningGuard.get_audit_log()
    assert len(class_log) == 3
    assert class_log[0]["target"] == "COM99"
    assert class_log[1]["target"] == "DfuSeCommand.exe"
    assert class_log[2]["target"] == "33149"


def test_assert_port_safe_enforcement():
    """Verify assert_port_safe catches all physical ports and raises CommissioningLockedError."""
    guard = CommissioningGuard()
    for port in ["COM1", "COM256", r"\\.\COM1", "CAN0", "USB1", "/dev/ttyUSB0"]:
        with pytest.raises(CommissioningLockedError, match="FAIL_CLOSED_HARDWARE_LOCKOUT"):
            guard.assert_port_safe(port)

    # Safe pseudo-ports or non-matching strings do not raise
    guard.assert_port_safe("VIRTUAL_NULL_LOOPBACK")


def test_assert_binary_execution_safe_enforcement():
    """Verify assert_binary_execution_safe catches flashing utilities and raises CommissioningLockedError."""
    guard = CommissioningGuard()
    for b in ["pgmupdateutility.exe", r"C:\Horner\bin\DfuSeCommand.exe", "stmflashloader.exe", "winjtag.exe"]:
        with pytest.raises(CommissioningLockedError, match="FAIL_CLOSED_FLASH_LOCKOUT"):
            guard.assert_binary_execution_safe(b)

    # Benign binaries do not raise
    guard.assert_binary_execution_safe("Cscape.exe")
    guard.assert_binary_execution_safe("notepad.exe")


def test_assert_win32_command_safe_enforcement():
    """Verify assert_win32_command_safe catches download commands and raises CommissioningLockedError."""
    guard = CommissioningGuard()
    for cmd_id in [32827, 33149]:
        with pytest.raises(CommissioningLockedError, match="FAIL_CLOSED_WIN32_LOCKOUT"):
            guard.assert_win32_command_safe(cmd_id)

    # Safe error check (compile) does not raise
    guard.assert_win32_command_safe(32826)


def test_assert_cli_switches_safe_enforcement():
    """Verify assert_cli_switches_safe catches flash/download CLI arguments."""
    guard = CommissioningGuard()
    for sw in [["/d"], ["/download"], ["/flash"], ["/burn"], ["/write-flash"]]:
        with pytest.raises(CommissioningLockedError, match="FAIL_CLOSED_SWITCH_LOCKOUT"):
            guard.assert_cli_switches_safe(sw)

    # Benign CLI switches pass
    guard.assert_cli_switches_safe(["/open", "project.csp"])


def test_export_audit_log_functionality(tmp_path: Path):
    """Verify export_audit_log writes formatted JSON output."""
    guard = CommissioningGuard()
    with pytest.raises(CommissioningLockedError):
        guard.request_port_unlock("COM12")

    export_file = tmp_path / "commissioning_audit.json"
    json_str = guard.export_audit_log(output_path=export_file)

    data = json.loads(json_str)
    assert data["gate"] == "G12"
    assert data["work_package"] == "W031"
    assert data["total_blocked_attempts"] >= 1
    assert data["is_authorized"] is False
    assert export_file.exists()
    assert json.loads(export_file.read_text(encoding="utf-8")) == data


def test_explicit_authorization_lifecycle():
    """Verify that when authorized is explicitly enabled, operations succeed, but re-locking re-enforces fail-closed."""
    guard = CommissioningGuard(authorized=True)
    assert guard.is_commissioning_authorized() is True

    # Should not raise when explicitly authorized
    guard.assert_commissioning_authorized(action="licensed_field_service")
    guard.request_port_unlock("COM1")
    guard.request_flash_tool_unlock("pgmupdateutility.exe")
    guard.request_win32_download_unlock(32827)
    guard.assert_port_safe("COM1")
    guard.assert_binary_execution_safe("pgmupdateutility.exe")
    guard.assert_win32_command_safe(32827)

    # Re-lock
    guard.is_authorized = False
    assert guard.is_commissioning_authorized() is False

    with pytest.raises(CommissioningLockedError):
        guard.request_port_unlock("COM1")


def test_ops_commissioning_lockout_json_conformance():
    """Verify ops/commissioning_lockout.json adheres strictly to Gate G12 specifications."""
    repo_root = Path(__file__).parent.parent
    policy_path = repo_root / "ops" / "commissioning_lockout.json"

    assert policy_path.exists(), "ops/commissioning_lockout.json must exist"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))

    # Metadata assertions
    assert policy["policy_metadata"]["gate"] == "G12"
    assert policy["policy_metadata"]["work_package"] == "W031"
    assert policy["policy_metadata"]["status"] == "ACTIVE_FAIL_CLOSED"
    assert policy["policy_metadata"]["blocker_id"] == "BLK-COMMISSIONING-LOCKOUT"

    # Zero trust boundary assertions
    ztb = policy["zero_trust_boundary"]
    assert "COM1 through COM256" in ztb["locked_communication_ports"]["serial_ports"]
    assert "pgmupdateutility.exe" in ztb["locked_companion_binaries"]
    assert "32827" in ztb["locked_win32_command_ids"]
    assert "33149" in ztb["locked_win32_command_ids"]
    assert "/download" in ztb["locked_cli_switches"]
    assert ztb["network_and_vcs_lockout"]["git_remotes_allowed"] == 0

    # Hardware protection invariants assertions (INV-G12-001 through INV-G12-006)
    invariants = {inv["id"]: inv for inv in policy["hardware_protection_invariants"]}
    for expected_id in [
        "INV-G12-001",
        "INV-G12-002",
        "INV-G12-003",
        "INV-G12-004",
        "INV-G12-005",
        "INV-G12-006",
    ]:
        assert expected_id in invariants, f"Invariant {expected_id} missing from policy"

    # Exception contracts
    assert policy["exception_contracts"]["primary_exception"] == "CommissioningLockedError"
    assert policy["exception_contracts"]["base_exception"] == "HardwareLockoutError"
