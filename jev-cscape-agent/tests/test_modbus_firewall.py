"""Unit tests for Industrial Modbus TCP Security Guard & Packet Firewall (W067).

Tests:
1. Valid Modbus TCP frame allowed cleanly with DroppedReason.NO_DROP.
2. CIDR subnet allowlist verification (192.168.1.0/24 allowed, 172.16.0.0/16 rejected).
3. Explicit IP blocklist enforcement (blacklisted IP dropped).
4. MBAP header DPI: protocol ID != 0 rejection.
5. MBAP header DPI: truncated frame < 8 bytes.
6. MBAP header DPI: length mismatch between MBAP length and payload bytes.
7. Unit ID allowlist filtering.
8. Function code policy: legal FCs (1, 2, 3, 4, 5, 6, 15, 16) vs illegal (8, 90).
9. Semantic register range access: operational zone write allowed, safety zone write blocked.
10. ENFORCE_READ_ONLY mode hard-blocks all write function codes.
11. FAIL_CLOSED_ISOLATE mode hard-blocks all traffic.
12. Sliding-window token bucket rate limiter exhaustion.
13. Horner OCS register space synchronization (%R290..%R295, %M65..%M66).
14. Reset handshake coil %M66 clears counters and self-resets.
15. Pure ST boundary enforcement: rejection of forbidden ladder logic constructs.
16. End-to-end canonical verification runner and evidence export.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.modbus_firewall import (
    DroppedReason,
    FirewallMode,
    FirewallStatusFlag,
    ModbusTcpFirewall,
    verify_modbus_firewall_and_export_evidence,
)


def _make_mbap_frame(trans_id: int, proto_id: int, unit_id: int, fc: int, pdu_body: bytes) -> bytes:
    mbap_len = len(pdu_body) + 2  # 1 byte unit_id + 1 byte fc + pdu_body
    return struct.pack(">HHHBB", trans_id, proto_id, mbap_len, unit_id, fc) + pdu_body


def test_valid_read_holding_registers_frame_allowed() -> None:
    """Verify standard read holding registers frame is approved."""
    fw = ModbusTcpFirewall(mode=FirewallMode.ENFORCE_STANDARD, allowed_cidrs=["192.168.1.0/24"], allowed_unit_ids={1})
    pdu = struct.pack(">HH", 50, 10)  # Read %R51..%R60
    frame = _make_mbap_frame(1, 0, 1, 3, pdu)
    v = fw.inspect_frame(frame, client_ip="192.168.1.10")
    assert v.allowed is True
    assert v.reason_code == DroppedReason.NO_DROP


def test_cidr_subnet_filtering() -> None:
    """Verify client IPs outside authorized CIDR subnets are dropped."""
    fw = ModbusTcpFirewall(mode=FirewallMode.ENFORCE_STANDARD, allowed_cidrs=["10.0.0.0/8"])
    frame = _make_mbap_frame(1, 0, 1, 3, struct.pack(">HH", 10, 5))

    v_ok = fw.inspect_frame(frame, client_ip="10.20.30.40")
    assert v_ok.allowed is True

    v_blocked = fw.inspect_frame(frame, client_ip="192.168.1.1")
    assert v_blocked.allowed is False
    assert v_blocked.reason_code == DroppedReason.IP_NOT_IN_ALLOWLIST


def test_explicit_ip_blocklist() -> None:
    """Verify explicitly blocked IP is denied even within allowed CIDR."""
    fw = ModbusTcpFirewall(mode=FirewallMode.ENFORCE_STANDARD, allowed_cidrs=["192.168.1.0/24"])
    fw.block_ip("192.168.1.99")
    frame = _make_mbap_frame(1, 0, 1, 3, struct.pack(">HH", 10, 5))

    v = fw.inspect_frame(frame, client_ip="192.168.1.99")
    assert v.allowed is False
    assert v.reason_code == DroppedReason.IP_NOT_IN_ALLOWLIST

    fw.unblock_ip("192.168.1.99")
    v_unblocked = fw.inspect_frame(frame, client_ip="192.168.1.99")
    assert v_unblocked.allowed is True


def test_mbap_protocol_id_dpi() -> None:
    """Verify non-zero protocol ID is rejected as non-Modbus payload."""
    fw = ModbusTcpFirewall(mode=FirewallMode.ENFORCE_STANDARD)
    frame = _make_mbap_frame(1, 0x0001, 1, 3, struct.pack(">HH", 10, 5))
    v = fw.inspect_frame(frame, client_ip="127.0.0.1")
    assert v.allowed is False
    assert v.reason_code == DroppedReason.INVALID_PROTOCOL_ID


def test_mbap_truncated_frame() -> None:
    """Verify truncated frame smaller than 8 bytes is dropped."""
    fw = ModbusTcpFirewall(mode=FirewallMode.ENFORCE_STANDARD)
    v = fw.inspect_frame(b"\x00\x01\x00\x00\x00", client_ip="127.0.0.1")
    assert v.allowed is False
    assert v.reason_code == DroppedReason.MALFORMED_MBAP_HEADER


def test_mbap_length_mismatch() -> None:
    """Verify mismatch between MBAP length header and actual frame size is dropped."""
    fw = ModbusTcpFirewall(mode=FirewallMode.ENFORCE_STANDARD)
    # Header claims length is 10, but total remaining is only 6
    frame = struct.pack(">HHHBBHH", 1, 0, 10, 1, 3, 10, 5)
    v = fw.inspect_frame(frame, client_ip="127.0.0.1")
    assert v.allowed is False
    assert v.reason_code == DroppedReason.MALFORMED_MBAP_HEADER


def test_unit_id_filtering() -> None:
    """Verify unmapped slave Unit ID is dropped."""
    fw = ModbusTcpFirewall(mode=FirewallMode.ENFORCE_STANDARD, allowed_unit_ids={1, 2})
    frame = _make_mbap_frame(1, 0, 99, 3, struct.pack(">HH", 10, 5))
    v = fw.inspect_frame(frame, client_ip="127.0.0.1")
    assert v.allowed is False
    assert v.reason_code == DroppedReason.IP_NOT_IN_ALLOWLIST


def test_function_code_policy() -> None:
    """Verify illegal or diagnostic function codes are blocked."""
    fw = ModbusTcpFirewall(mode=FirewallMode.ENFORCE_STANDARD)
    # FC 08 (Diagnostics)
    frame_fc8 = _make_mbap_frame(1, 0, 1, 8, struct.pack(">HH", 0, 0))
    v = fw.inspect_frame(frame_fc8, client_ip="127.0.0.1")
    assert v.allowed is False
    assert v.reason_code == DroppedReason.ILLEGAL_FUNCTION_CODE

    # Unknown FC 99
    frame_fc99 = _make_mbap_frame(1, 0, 1, 99, b"\x01\x02\x03\x04")
    v99 = fw.inspect_frame(frame_fc99, client_ip="127.0.0.1")
    assert v99.allowed is False
    assert v99.reason_code == DroppedReason.ILLEGAL_FUNCTION_CODE


def test_register_zone_boundary_security() -> None:
    """Verify write to protected safety register zone (%R9000+) is blocked."""
    fw = ModbusTcpFirewall(mode=FirewallMode.ENFORCE_STANDARD)
    # Write single register to %R9500 (0-based 9499)
    frame_safety = _make_mbap_frame(1, 0, 1, 6, struct.pack(">HH", 9499, 12345))
    v_safety = fw.inspect_frame(frame_safety, client_ip="127.0.0.1")
    assert v_safety.allowed is False
    assert v_safety.reason_code == DroppedReason.UNAUTHORIZED_REGISTER_WRITE

    # Write single register to %R100 (0-based 99 in operational zone)
    frame_op = _make_mbap_frame(2, 0, 1, 6, struct.pack(">HH", 99, 12345))
    v_op = fw.inspect_frame(frame_op, client_ip="127.0.0.1")
    assert v_op.allowed is True


def test_enforce_read_only_mode() -> None:
    """Verify ENFORCE_READ_ONLY mode blocks writes while permitting reads."""
    fw = ModbusTcpFirewall(mode=FirewallMode.ENFORCE_READ_ONLY)
    read_frame = _make_mbap_frame(1, 0, 1, 3, struct.pack(">HH", 10, 5))
    write_frame = _make_mbap_frame(2, 0, 1, 6, struct.pack(">HH", 10, 50))

    assert fw.inspect_frame(read_frame, client_ip="127.0.0.1").allowed is True
    v_write = fw.inspect_frame(write_frame, client_ip="127.0.0.1")
    assert v_write.allowed is False
    assert v_write.reason_code == DroppedReason.READ_ONLY_LOCKDOWN


def test_fail_closed_isolate_mode() -> None:
    """Verify FAIL_CLOSED_ISOLATE mode drops all ingress packets."""
    fw = ModbusTcpFirewall(mode=FirewallMode.FAIL_CLOSED_ISOLATE)
    frame = _make_mbap_frame(1, 0, 1, 3, struct.pack(">HH", 10, 5))
    v = fw.inspect_frame(frame, client_ip="127.0.0.1")
    assert v.allowed is False
    assert v.reason_code == DroppedReason.ISOLATION_ACTIVE


def test_sliding_window_rate_limiting() -> None:
    """Verify token bucket rate limiter exhausts under rapid packet bursts."""
    fw = ModbusTcpFirewall(
        mode=FirewallMode.ENFORCE_STANDARD,
        global_burst_capacity=10.0,
        global_refill_rate=1.0,
    )
    frame = _make_mbap_frame(1, 0, 1, 3, struct.pack(">HH", 10, 5))
    allowed_count = 0
    blocked_count = 0
    for _ in range(15):
        v = fw.inspect_frame(frame, client_ip="192.168.1.200")
        if v.allowed:
            allowed_count += 1
        else:
            blocked_count += 1
    assert allowed_count == 10
    assert blocked_count == 5


def test_horner_register_sync() -> None:
    """Verify %R290..%R295 and %M65..%M66 synchronization."""
    regs = RegisterTable()
    fw = ModbusTcpFirewall()

    # Pre-configure %M65 = True (Enable)
    regs.write_bit("%M65", True, privilege=PrivilegeMode.SYSTEM)
    regs.write_word("%R295", 1, privilege=PrivilegeMode.SYSTEM)
    fw.solve(regs)

    assert regs.read_word("%R290") & FirewallStatusFlag.ACTIVE
    assert regs.read_word("%R295") == 1
    assert regs.read_bit("%M65") is True


def test_reset_handshake_coil() -> None:
    """Verify %M66 reset handshake coil clears counters and self-clears."""
    regs = RegisterTable()
    fw = ModbusTcpFirewall()
    fw.packets_inspected = 500
    fw.packets_dropped = 42

    regs.write_bit("%M65", True, privilege=PrivilegeMode.SYSTEM)
    regs.write_bit("%M66", True, privilege=PrivilegeMode.SYSTEM)
    fw.solve(regs)

    assert regs.read_bit("%M66") is False  # Self-cleared
    assert fw.packets_inspected == 0
    assert fw.packets_dropped == 0
    assert regs.read_word("%R291") == 0
    assert regs.read_word("%R292") == 0


def test_pure_st_boundary_enforcement() -> None:
    """Verify IEC 61131-3 Pure ST boundary rejects ladder constructs."""
    valid_st = (
        "PROGRAM ModbusTcpFirewall\n"
        "VAR\n"
        "    StatusWord AT %R290 : INT;\n"
        "    PacketsInspected AT %R291 : INT;\n"
        "    PacketsDropped AT %R292 : INT;\n"
        "    ActiveIPBlockCount AT %R293 : INT;\n"
        "    LastDroppedReason AT %R294 : INT;\n"
        "    FirewallConfigMode AT %R295 : INT;\n"
        "    FirewallEnable AT %M65 : BOOL;\n"
        "    FirewallReset AT %M66 : BOOL;\n"
        "END_VAR\n"
        "IF FirewallEnable THEN\n"
        "    StatusWord := %R290;\n"
        "END_IF;\n"
        "END_PROGRAM"
    )
    SecurityGuard.assert_pure_st_content(valid_st)
    ast = STParser.parse_pou(valid_st)
    assert ast.name == "ModbusTcpFirewall"
    assert ast.pou_type == POUType.PROGRAM
    assert set(ast.bound_registers) == {"%R290", "%R291", "%R292", "%R293", "%R294", "%R295", "%M65", "%M66"}

    ladder_samples = [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 10",
        "XIC FirewallEnable",
        "OTE PacketBlocked",
    ]
    for sample in ladder_samples:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(f"{valid_st}\n{sample}")


def test_verification_runner_and_artifact(tmp_path: Path) -> None:
    """Verify canonical verification runner and artifact generation."""
    evidence_file = tmp_path / "modbus_firewall_evidence.json"
    result = verify_modbus_firewall_and_export_evidence(output_evidence_path=str(evidence_file))

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["tests_run"] == result["data"]["tests_passed"]
    assert evidence_file.exists()

    with open(evidence_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["status"] == "success"
    assert "firewall_modes" in loaded["data"]
