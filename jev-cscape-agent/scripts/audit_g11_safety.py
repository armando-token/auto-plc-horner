"""Gate G11 Pre-Commissioning Safety Lockout & Interceptor Audit Script.

Executes deterministic verification of:
1. Physical communication ports lockout (COM1-COM256, \\\\.\\COM*, CAN, USB, JTAG).
2. Companion flashing binaries execution lockout (PGMUpdateUtility, DfuSeCommand, STMFlashLoader, WinJTAG).
3. Win32 download command interception (32827 and 33149) with HardwareLockoutError.
4. Zero git remotes configuration check.
5. horner-cscape-mcp isolation across src/jev_cscape/.

Produces artifacts/G11/safety_lockout_audit_evidence.json with strict 4-state engineering contract.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# Add src to python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.exceptions import HardwareLockoutError
from jev_cscape.security.guard import SecurityGuard


def audit_physical_ports() -> dict:
    """Audit lockout for all COM ports (1-256), device paths, CAN, USB, JTAG."""
    tested_com_ports = 0
    blocked_com_ports = 0

    # 1. Test COM1 through COM256 exhaustive
    for i in range(1, 257):
        port_name = f"COM{i}"
        tested_com_ports += 1
        try:
            SecurityGuard.assert_port_safe(port_name)
            raise AssertionError(f"Port {port_name} was NOT blocked!")
        except HardwareLockoutError:
            blocked_com_ports += 1

    # 2. Test lowercase and device paths
    special_ports = [
        "com1", "com256",
        r"\\.\COM1", r"\\.\COM10", r"\\.\COM256",
        "/dev/ttyUSB0", "/dev/ttyS0", "/dev/ttyACM0",
        "CAN0", "CAN1", "can99",
        "USB0", "USB1", "usb_hub",
        "JTAG", "JTAG_INTERFACE", "jtag_probe"
    ]
    blocked_special = 0
    for p in special_ports:
        try:
            SecurityGuard.assert_port_safe(p)
            raise AssertionError(f"Port/interface {p} was NOT blocked!")
        except HardwareLockoutError:
            blocked_special += 1

    # 3. Assert non-hardware ports are not blocked
    safe_ports = ["ETH0", "MODBUS_TCP", "127.0.0.1:502"]
    for sp in safe_ports:
        SecurityGuard.assert_port_safe(sp)

    return {
        "status": "passed",
        "com_ports_1_to_256_tested": tested_com_ports,
        "com_ports_1_to_256_blocked": blocked_com_ports,
        "special_interfaces_tested": len(special_ports),
        "special_interfaces_blocked": blocked_special,
        "all_ports_locked_out": (tested_com_ports == blocked_com_ports == 256) and (blocked_special == len(special_ports))
    }


def audit_companion_flash_binaries() -> dict:
    """Audit lockout for companion flashing utilities."""
    target_binaries = [
        "PGMUpdateUtility.exe",
        "pgmupdateutility.exe",
        r"C:\Cscape\PGMUpdateUtility.exe",
        "DfuSeCommand.exe",
        "dfusecommand.exe",
        r"C:\Tools\DfuSeCommand.exe",
        "STMFlashLoader.exe",
        "stmflashloader.exe",
        r"C:\ST\STMFlashLoader.exe",
        "WinJTAG.exe",
        "winjtag.exe",
        r"C:\Hardware\WinJTAG.exe"
    ]
    blocked_count = 0
    for binary in target_binaries:
        try:
            SecurityGuard.assert_binary_execution_safe(binary)
            raise AssertionError(f"Flashing binary {binary} was NOT blocked!")
        except HardwareLockoutError:
            blocked_count += 1

    return {
        "status": "passed",
        "binaries_tested": len(target_binaries),
        "binaries_blocked": blocked_count,
        "all_binaries_locked_out": blocked_count == len(target_binaries)
    }


def audit_win32_command_interceptor() -> dict:
    """Audit Win32 download command interception (32827 & 33149)."""
    download_cmds = [
        (32827, "ID_PROGRAM_DOWNLOAD"),
        (33149, "ID_CONTROLLER_DOWNLOAD")
    ]
    interceptor_checks = []

    for cmd_id, name in download_cmds:
        # Check 1: SecurityGuard assertion raises HardwareLockoutError
        guard_raised = False
        try:
            SecurityGuard.assert_win32_command_safe(cmd_id)
        except HardwareLockoutError:
            guard_raised = True

        # Check 2: Win32CommandInterceptor.assert_command_safe raises HardwareLockoutError
        interceptor_raised = False
        try:
            Win32CommandInterceptor.assert_command_safe(cmd_id)
        except HardwareLockoutError:
            interceptor_raised = True

        # Check 3: Win32CommandInterceptor.dispatch_safe_command returns BLOCKED
        dispatch_result = Win32CommandInterceptor.dispatch_safe_command(hwnd=99999, cmd_id=cmd_id)
        dispatch_blocked = (
            dispatch_result.status == AgentStatus.BLOCKED
            and dispatch_result.error_code == "FAIL_CLOSED_WIN32_LOCKOUT"
        )

        interceptor_checks.append({
            "command_id": cmd_id,
            "command_name": name,
            "security_guard_raised": guard_raised,
            "interceptor_raised": interceptor_raised,
            "dispatch_blocked": dispatch_blocked,
        })

    # Verify safe compile command is NOT blocked
    safe_raised = False
    try:
        Win32CommandInterceptor.assert_command_safe(32826)
    except HardwareLockoutError:
        safe_raised = True

    return {
        "status": "passed",
        "download_commands_audited": interceptor_checks,
        "error_check_allowed": not safe_raised,
        "all_download_commands_hard_blocked": all(
            c["security_guard_raised"] and c["interceptor_raised"] and c["dispatch_blocked"]
            for c in interceptor_checks
        )
    }


def audit_cli_switches() -> dict:
    """Audit lockout for prohibited download/flash command-line switches."""
    target_switches = [
        "/d", "/D", "-d", "--d",
        "/download", "/DOWNLOAD", "-download", "--download",
        "/flash", "/FLASH", "-flash", "--flash",
        "/burn", "/BURN", "-burn", "--burn",
        "/write-flash", "/WRITE-FLASH", "-write-flash", "--write-flash",
        "/download:firmware.bin", "/d=COM1",
    ]
    blocked_count = 0
    for sw in target_switches:
        try:
            SecurityGuard.assert_cli_switches_safe([sw])
            raise AssertionError(f"Switch {sw} was NOT blocked!")
        except HardwareLockoutError:
            blocked_count += 1

    # Verify benign switches pass cleanly
    safe_switches = ["/open", "project.csp", "--verbose", "-v"]
    SecurityGuard.assert_cli_switches_safe(safe_switches)

    return {
        "status": "passed",
        "switches_tested": len(target_switches),
        "switches_blocked": blocked_count,
        "all_switches_locked_out": blocked_count == len(target_switches)
    }


def audit_git_remotes(repo_root: Path) -> dict:
    """Audit that zero git remotes are configured."""
    result = subprocess.run(
        ["git", "remote"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=True
    )
    remotes = [r.strip() for r in result.stdout.strip().splitlines() if r.strip()]

    # Also inspect .git/config
    git_config_path = repo_root / ".git" / "config"
    has_remote_in_config = False
    if git_config_path.exists():
        content = git_config_path.read_text(encoding="utf-8")
        has_remote_in_config = "[remote" in content

    return {
        "status": "passed" if len(remotes) == 0 and not has_remote_in_config else "failed",
        "configured_remotes": remotes,
        "remote_count": len(remotes),
        "git_config_contains_remote": has_remote_in_config,
        "local_only_enforced": len(remotes) == 0 and not has_remote_in_config
    }


def audit_no_horner_cscape_mcp(repo_root: Path) -> dict:
    """Verify horner-cscape-mcp is NEVER imported or referenced anywhere in src/jev_cscape/."""
    src_dir = repo_root / "src" / "jev_cscape"
    violations = []
    scanned_files = 0

    for p in src_dir.rglob("*"):
        if p.is_file() and p.suffix in [".py", ".json", ".yaml", ".yml", ".md", ".toml"]:
            scanned_files += 1
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                if "horner-cscape-mcp" in content.lower():
                    violations.append(str(p.relative_to(repo_root)))
            except Exception as e:
                violations.append(f"{p}: error reading ({e})")

    return {
        "status": "passed" if len(violations) == 0 else "failed",
        "scanned_files_count": scanned_files,
        "forbidden_references_found": len(violations),
        "violations": violations,
        "isolation_verified": len(violations) == 0
    }


def run_full_g11_audit() -> dict:
    """Execute complete Gate G11 pre-commissioning safety lockout audit."""
    repo_root = Path(__file__).parent.parent.resolve()

    ports_res = audit_physical_ports()
    flashers_res = audit_companion_flash_binaries()
    interceptor_res = audit_win32_command_interceptor()
    cli_switches_res = audit_cli_switches()
    git_res = audit_git_remotes(repo_root)
    mcp_res = audit_no_horner_cscape_mcp(repo_root)

    all_passed = (
        ports_res["all_ports_locked_out"]
        and flashers_res["all_binaries_locked_out"]
        and interceptor_res["all_download_commands_hard_blocked"]
        and cli_switches_res["all_switches_locked_out"]
        and git_res["local_only_enforced"]
        and mcp_res["isolation_verified"]
    )

    audit_evidence = {
        "gate": "G11",
        "title": "Pre-Commissioning Safety Lockout & Interceptor Audit",
        "verdict": "success" if all_passed else "failed",
        "error_code": None if all_passed else "SAFETY_AUDIT_FAILURE",
        "details": (
            "Exhaustive pre-commissioning safety audit passed: 256 COM ports locked out, "
            "17 device/bus interfaces locked out, 4 companion flasher utilities blocked, "
            "Win32 download commands (32827, 33149) intercepted with HardwareLockoutError, "
            "prohibited CLI download switches blocked, zero git remotes configured (local-only git), "
            "and zero horner-cscape-mcp references in src/jev_cscape/."
            if all_passed else
            "Pre-commissioning safety audit detected policy violations."
        ),
        "data": {
            "physical_ports_audit": ports_res,
            "flasher_binaries_audit": flashers_res,
            "win32_interceptor_audit": interceptor_res,
            "cli_switches_audit": cli_switches_res,
            "git_remotes_audit": git_res,
            "mcp_isolation_audit": mcp_res,
        }
    }

    # Save artifact
    artifacts_dir = repo_root / "artifacts" / "G11"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = artifacts_dir / "safety_lockout_audit_evidence.json"
    evidence_file.write_text(json.dumps(audit_evidence, indent=2), encoding="utf-8")

    return audit_evidence


if __name__ == "__main__":
    report = run_full_g11_audit()
    print(json.dumps(report, indent=2))
    if report["verdict"] != "success":
        sys.exit(1)
    sys.exit(0)
