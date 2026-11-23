"""Tests asserting Gate G11 Pre-Commissioning Safety Lockout & Interceptor Audit invariants."""

import subprocess
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.exceptions import HardwareLockoutError
from jev_cscape.security.guard import SecurityGuard


def test_g11_all_com_ports_1_to_256_blocked():
    """Verify COM1 through COM256 are permanently blocked."""
    for i in range(1, 257):
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_HARDWARE_LOCKOUT"):
            SecurityGuard.assert_port_safe(f"COM{i}")
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_HARDWARE_LOCKOUT"):
            SecurityGuard.assert_port_safe(f"com{i}")


def test_g11_special_device_interfaces_blocked():
    """Verify \\\\.\\COM*, CAN, USB, JTAG, and /dev/tty are permanently blocked."""
    interfaces = [
        r"\\.\COM1", r"\\.\COM10", r"\\.\COM256",
        "/dev/ttyUSB0", "/dev/ttyS0", "/dev/ttyACM0",
        "CAN0", "CAN1", "can99",
        "USB0", "USB1", "usb_hub",
        "JTAG", "JTAG_INTERFACE", "jtag_probe"
    ]
    for iface in interfaces:
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_HARDWARE_LOCKOUT"):
            SecurityGuard.assert_port_safe(iface)


def test_g11_flashing_companion_binaries_blocked():
    """Verify companion flashing utilities are permanently blocked from execution."""
    banned = [
        "PGMUpdateUtility.exe", "pgmupdateutility.exe",
        "DfuSeCommand.exe", "dfusecommand.exe",
        "STMFlashLoader.exe", "stmflashloader.exe",
        "WinJTAG.exe", "winjtag.exe",
    ]
    for b in banned:
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_FLASH_LOCKOUT"):
            SecurityGuard.assert_binary_execution_safe(b)


def test_g11_win32_download_commands_intercepted():
    """Verify Win32 commands 32827 and 33149 are actively intercepted and hard-blocked."""
    for cmd_id in [32827, 33149]:
        # Direct check raises HardwareLockoutError
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_HARDWARE_LOCKOUT"):
            Win32CommandInterceptor.assert_command_safe(cmd_id)

        # Dispatch check returns BLOCKED result
        res = Win32CommandInterceptor.dispatch_safe_command(hwnd=12345, cmd_id=cmd_id)
        assert res.status == AgentStatus.BLOCKED
        assert res.error_code == "FAIL_CLOSED_WIN32_LOCKOUT"


def test_g11_security_guard_assert_win32_command_safe():
    """Verify SecurityGuard.assert_win32_command_safe fails closed with HardwareLockoutError."""
    for cmd in [32827, 33149, "32827", "33149", "ID_PROGRAM_DOWNLOAD", "ID_CONTROLLER_DOWNLOAD"]:
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_WIN32_LOCKOUT"):
            SecurityGuard.assert_win32_command_safe(cmd)

    # Safe error check (compile) does not raise
    SecurityGuard.assert_win32_command_safe(32826)


def test_g11_cli_switches_blocked():
    """Verify download and flash CLI switches are permanently blocked with HardwareLockoutError."""
    blocked_switches = [
        "/d", "/D", "-d", "--d",
        "/download", "/DOWNLOAD", "-download", "--download",
        "/flash", "/FLASH", "-flash", "--flash",
        "/burn", "/BURN", "-burn", "--burn",
        "/write-flash", "/WRITE-FLASH", "-write-flash", "--write-flash",
        "/download:firmware.bin", "/d=COM1",
    ]
    for sw in blocked_switches:
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_SWITCH_LOCKOUT"):
            SecurityGuard.assert_cli_switches_safe([sw])

    # Benign CLI switches pass cleanly
    SecurityGuard.assert_cli_switches_safe(["/open", "project.csp", "--verbose", "-v"])


def test_g11_git_remotes_zero_configured():
    """Verify that zero git remotes are configured (local-only git)."""
    repo_root = Path(__file__).parent.parent
    result = subprocess.run(
        ["git", "remote"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=True
    )
    remotes = [r.strip() for r in result.stdout.strip().splitlines() if r.strip()]
    assert len(remotes) == 0, f"Expected 0 remotes, found: {remotes}"


def test_g11_no_horner_cscape_mcp_in_src():
    """Verify horner-cscape-mcp is NEVER imported or referenced anywhere in src/jev_cscape/."""
    src_dir = Path(__file__).parent.parent / "src" / "jev_cscape"
    violations = []
    for p in src_dir.rglob("*.py"):
        content = p.read_text(encoding="utf-8")
        if "horner-cscape-mcp" in content.lower():
            violations.append(str(p))
    assert len(violations) == 0, f"Found horner-cscape-mcp references in: {violations}"


def test_g11_network_target_blocked_plc_ports():
    """Verify physical PLC ports (20502, 502, 44818, 4840) are blocked across hosts."""
    blocked_ports = [
        (20502, "Horner CsCAN / PComm"),
        (502, "Modbus TCP"),
        (44818, "EtherNet/IP CIP"),
        (4840, "OPC UA"),
    ]
    test_hosts = ["10.0.0.1", "172.16.0.5", "127.0.0.1", "localhost"]

    for port, label in blocked_ports:
        for host in test_hosts:
            with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_NETWORK_LOCKOUT") as exc_info:
                SecurityGuard.assert_network_target_safe(host, port)
            assert "FAIL_CLOSED_NETWORK_LOCKOUT: Network connections to physical PLC targets are forbidden in offline/mock mode." in str(exc_info.value)


def test_g11_network_target_blocked_plc_ips():
    """Verify physical PLC IPs (192.168.1.0/24, 192.168.1.100, 192.168.1.1) are blocked."""
    blocked_ips = [
        "192.168.1.1",        # Factory default gateway
        "192.168.1.100",      # Horner OCS default IP
        "192.168.1.50",       # Subnet IP
        "192.168.1.254",      # Subnet IP
        "192.168.1.0/24",     # Entire subnet CIDR
    ]
    non_plc_ports = [80, 443, 8080, 9000]

    for host in blocked_ips:
        for port in non_plc_ports:
            with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_NETWORK_LOCKOUT") as exc_info:
                SecurityGuard.assert_network_target_safe(host, port)
            assert "FAIL_CLOSED_NETWORK_LOCKOUT: Network connections to physical PLC targets are forbidden in offline/mock mode." in str(exc_info.value)


def test_g11_network_target_permits_local_mock_loops():
    """Verify local mock loopbacks with non-PLC ports are permitted cleanly."""
    permitted_targets = [
        ("127.0.0.1", 8080),
        ("127.0.0.1", 1502),
        ("127.0.0.1", 50201),
        ("localhost", 8000),
        ("localhost", 9999),
        ("::1", 8080),
    ]
    for host, port in permitted_targets:
        # Must not raise HardwareLockoutError or any other exception
        SecurityGuard.assert_network_target_safe(host, port)
