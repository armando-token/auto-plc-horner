"""Fail-Closed SecurityGuard enforcing hardware port lockout, flasher binary ban,
Win32 download command ban, and pure-ST boundary verification.
"""

import ipaddress
import re
from typing import List, Set
from .exceptions import HardwareLockoutError, LadderForbiddenError


class SecurityGuard:
    """Enforces absolute fail-closed safety invariants across all agent operations."""

    # Physical port patterns strictly prohibited
    BLOCKED_PORTS = [
        re.compile(r"^COM([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-6]):?$", re.I),
        re.compile(r"^\\\\\.\\COM\d+:?", re.I),
        re.compile(r"^/dev/tty.*", re.I),
        re.compile(r"^CAN\d*", re.I),
        re.compile(r"^USB\d*", re.I),
        re.compile(r"^JTAG.*", re.I),
    ]

    # Companion flash and programming binaries strictly blocked
    BLOCKED_FLASH_BINARIES: Set[str] = {
        "pgmupdateutility.exe",
        "pgmupdateutility",
        "dfusecommand.exe",
        "dfusecommand",
        "stmflashloader.exe",
        "stmflashloader",
        "winjtag.exe",
        "winjtag",
    }

    # Prohibited command-line switches
    BLOCKED_CLI_SWITCHES: Set[str] = {
        "/d",
        "-d",
        "--d",
        "/download",
        "-download",
        "--download",
        "/flash",
        "-flash",
        "--flash",
        "/burn",
        "-burn",
        "--burn",
        "/write-flash",
        "-write-flash",
        "--write-flash",
    }

    # Win32 download command IDs intercepted and blocked
    ID_PROGRAM_DOWNLOAD = 32827
    ID_CONTROLLER_DOWNLOAD = 33149
    BLOCKED_COMMAND_IDS: Set[int] = {ID_PROGRAM_DOWNLOAD, ID_CONTROLLER_DOWNLOAD}

    # Physical PLC network ports strictly prohibited in offline/mock mode
    PORT_MODBUS_TCP: int = 502
    PORT_OPC_UA: int = 4840
    PORT_CSCAN_PCOMM: int = 20502
    PORT_ETHERNET_IP_CIP: int = 44818

    BLOCKED_PLC_PORTS: Set[int] = {
        PORT_MODBUS_TCP,       # 502 Modbus TCP
        PORT_OPC_UA,           # 4840 OPC UA
        PORT_CSCAN_PCOMM,      # 20502 Horner CsCAN / PComm
        PORT_ETHERNET_IP_CIP,  # 44818 EtherNet/IP CIP
    }

    # Physical PLC IP subnets and standard factory default IPs strictly prohibited in offline/mock mode
    BLOCKED_PLC_SUBNETS = [
        ipaddress.ip_network("192.168.1.0/24"),
    ]
    BLOCKED_PLC_IPS: Set[str] = {
        "192.168.1.1",
        "192.168.1.100",
    }

    # Prohibited Ladder logic regexes in ST POUs
    LADDER_PATTERNS = [
        re.compile(r"-{2,}\[\s*[ /]?\s*\]-{2,}"),          # ASCII contacts --[ ]-- or --[/]-- or ---[ ]---
        re.compile(r"-{2,}\(\s*[SRLU/?]?\s*\)-{2,}"),         # ASCII coils --( )--, --(/)--, --(S)--, --(R)--, --(L)--, --(U)--
        re.compile(r"\b(RUNG|END_RUNG|NETWORK|END_NETWORK)\b", re.I), # Ladder network/rung delimiters
        re.compile(r"\b(XIC|XIO|OTE|OTL|OTU)\b", re.I),   # Allen-Bradley / Ladder mnemonics
    ]

    @classmethod
    def assert_port_safe(cls, port_name: str) -> None:
        """Validate that a port is not a physical serial/CAN/USB/JTAG interface."""
        normalized = str(port_name).strip()
        for pattern in cls.BLOCKED_PORTS:
            if pattern.match(normalized):
                raise HardwareLockoutError(
                    f"FAIL_CLOSED_HARDWARE_LOCKOUT: Access to physical hardware port '{port_name}' "
                    f"is strictly prohibited by safety directive."
                )

    @classmethod
    def assert_network_target_safe(cls, host: str, port: int) -> None:
        """Validate that target network host and port do not target physical PLC interfaces in offline/mock mode.

        Blocks:
        - Physical PLC network ports:
          * 20502 (Horner CsCAN / PComm)
          * 502 (Modbus TCP)
          * 44818 (EtherNet/IP CIP)
          * 4840 (OPC UA)
        - Physical PLC IPs / subnets:
          * 192.168.1.0/24
          * Standard Horner factory default IPs (192.168.1.100, 192.168.1.1)

        Raises:
            HardwareLockoutError: FAIL_CLOSED_NETWORK_LOCKOUT when targeting physical PLC interfaces.
        """
        try:
            int_port = int(port)
        except (ValueError, TypeError):
            int_port = None

        if int_port in cls.BLOCKED_PLC_PORTS:
            raise HardwareLockoutError(
                "FAIL_CLOSED_NETWORK_LOCKOUT: Network connections to physical PLC targets are forbidden in offline/mock mode."
            )

        normalized_host = str(host).strip()
        if normalized_host in cls.BLOCKED_PLC_IPS:
            raise HardwareLockoutError(
                "FAIL_CLOSED_NETWORK_LOCKOUT: Network connections to physical PLC targets are forbidden in offline/mock mode."
            )

        # Check IP address against blocked subnets
        try:
            target_ip = ipaddress.ip_address(normalized_host)
            for subnet in cls.BLOCKED_PLC_SUBNETS:
                if target_ip.version == subnet.version and target_ip in subnet:
                    raise HardwareLockoutError(
                        "FAIL_CLOSED_NETWORK_LOCKOUT: Network connections to physical PLC targets are forbidden in offline/mock mode."
                    )
        except ValueError:
            # Check if host was specified as CIDR notation
            try:
                target_net = ipaddress.ip_network(normalized_host, strict=False)
                for subnet in cls.BLOCKED_PLC_SUBNETS:
                    if target_net.version == subnet.version and target_net.overlaps(subnet):
                        raise HardwareLockoutError(
                            "FAIL_CLOSED_NETWORK_LOCKOUT: Network connections to physical PLC targets are forbidden in offline/mock mode."
                        )
            except ValueError:
                pass

    @classmethod
    def assert_binary_execution_safe(cls, binary_path_or_name: str) -> None:
        """Ensure no companion flashing utility is launched."""
        normalized = str(binary_path_or_name).lower().replace("\\", "/").split("/")[-1].strip()
        base_name = normalized[:-4] if normalized.endswith(".exe") else normalized
        if (
            normalized in cls.BLOCKED_FLASH_BINARIES
            or base_name in cls.BLOCKED_FLASH_BINARIES
            or f"{base_name}.exe" in cls.BLOCKED_FLASH_BINARIES
        ):
            raise HardwareLockoutError(
                f"FAIL_CLOSED_FLASH_LOCKOUT: Execution of companion flashing utility '{normalized}' "
                f"is strictly forbidden."
            )

    @classmethod
    def assert_cli_switches_safe(cls, args: List[str]) -> None:
        """Ensure no download or flashing CLI switch is supplied."""
        for arg in args:
            norm = str(arg).strip().lower()
            token = norm.split("=")[0].split(":")[0].strip()
            if norm in cls.BLOCKED_CLI_SWITCHES or token in cls.BLOCKED_CLI_SWITCHES:
                raise HardwareLockoutError(
                    f"FAIL_CLOSED_SWITCH_LOCKOUT: Download/flash CLI switch '{arg}' "
                    f"is strictly forbidden."
                )

    @classmethod
    def assert_win32_command_safe(cls, command_id: int) -> None:
        """Ensure no Win32 download command is dispatched to Cscape."""
        try:
            cid = int(command_id)
        except (ValueError, TypeError):
            cid = None
        if (
            cid in cls.BLOCKED_COMMAND_IDS
            or str(command_id).strip() in {"32827", "33149", "ID_PROGRAM_DOWNLOAD", "ID_CONTROLLER_DOWNLOAD"}
        ):
            raise HardwareLockoutError(
                f"FAIL_CLOSED_WIN32_LOCKOUT: Win32 download command ID {command_id} "
                f"is strictly intercepted and blocked."
            )

    @classmethod
    def assert_pure_st_content(cls, st_code: str) -> None:
        """Enforce zero ladder constructs in IEC 61131-3 Structured Text source."""
        for pattern in cls.LADDER_PATTERNS:
            match = pattern.search(st_code)
            if match:
                raise LadderForbiddenError(
                    f"ERR_LADDER_FORBIDDEN: Forbidden ladder construct '{match.group()}' "
                    f"detected in Structured Text source at index {match.start()}."
                )

    @classmethod
    def validate_pure_st(cls, st_code: str):
        """Validate that Structured Text contains zero ladder constructs and return ExecutionResult."""
        from jev_cscape.contracts import ExecutionResult
        try:
            cls.assert_pure_st_content(st_code)
            return ExecutionResult.success(
                details="Structured Text passes pure ST validation without ladder constructs."
            )
        except LadderForbiddenError as exc:
            return ExecutionResult.failed(
                error_code="ERR_LADDER_FORBIDDEN",
                details=str(exc),
            )
