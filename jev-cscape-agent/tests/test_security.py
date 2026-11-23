"""Tests for SecurityGuard fail-closed invariants and boundary enforcements."""

import pytest
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError


def test_physical_ports_blocked():
    blocked_ports = ["COM1", "COM3", "com256", "\\\\.\\COM1", "/dev/ttyUSB0", "CAN0", "USB1", "JTAG_INTERFACE"]
    for port in blocked_ports:
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_HARDWARE_LOCKOUT"):
            SecurityGuard.assert_port_safe(port)


def test_companion_flash_binaries_blocked():
    binaries = [
        "PGMUpdateUtility.exe",
        r"C:\Tools\DfuSeCommand.exe",
        "stmflashloader.exe",
        "winjtag.exe"
    ]
    for b in binaries:
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_FLASH_LOCKOUT"):
            SecurityGuard.assert_binary_execution_safe(b)


def test_download_cli_switches_blocked():
    switches = [["/d"], ["/DOWNLOAD"], ["/flash"], ["/burn"], ["/write-flash"]]
    for sw in switches:
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_SWITCH_LOCKOUT"):
            SecurityGuard.assert_cli_switches_safe(sw)


def test_win32_download_commands_blocked():
    blocked_cmds = [32827, 33149]
    for cmd in blocked_cmds:
        with pytest.raises(HardwareLockoutError, match="FAIL_CLOSED_WIN32_LOCKOUT"):
            SecurityGuard.assert_win32_command_safe(cmd)


def test_safe_win32_commands_allowed():
    # 32826 is Error Check (compile)
    SecurityGuard.assert_win32_command_safe(32826)


def test_pure_st_allowed():
    valid_st = """
    PROGRAM TankControl
    VAR
        Level : REAL;
        PumpCmd : BOOL;
    END_VAR
    IF Level < 20.0 THEN
        PumpCmd := TRUE;
    ELSIF Level > 80.0 THEN
        PumpCmd := FALSE;
    END_IF;
    END_PROGRAM
    """
    # Should not raise
    SecurityGuard.assert_pure_st_content(valid_st)


@pytest.mark.parametrize("bad_snippet", [
    "---[ ]---",
    "---[/]---",
    "---( )---",
    "---(S)---",
    "---(R)---",
    "RUNG 1",
    "NETWORK 2",
    "XIC Valve_Open",
    "OTE Pump_Run",
])
def test_ladder_constructs_rejected_in_st(bad_snippet: str):
    code = f"""
    PROGRAM Test
    VAR x : BOOL; END_VAR
    {bad_snippet}
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError, match="ERR_LADDER_FORBIDDEN"):
        SecurityGuard.assert_pure_st_content(code)
