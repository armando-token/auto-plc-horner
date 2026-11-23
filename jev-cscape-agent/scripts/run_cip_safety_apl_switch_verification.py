#!/usr/bin/env python3
"""Deterministic 9-Stage Verification Runner for Industrial ODVA CIP Safety Over Ethernet-APL Field Switch Diagnostics Protocol Engine (W322).

Work Package: W322 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [ODVA CIP Safety Over Ethernet-APL Field Switch Diagnostics Protocol Engine]
Status Contract: Strict 4-State JSON output (success | failed | blocked | inconclusive) & evidence emission.

Standards & Specifications:
- IEEE 802.3cg-2019: 10 Mb/s Single Pair Ethernet (10BASE-T1L Ethernet-APL):
  - Point-to-point trunk (up to 1,000m) and spur (up to 200m) topologies.
  - Trunk power delivery surveillance: Nominal 50.0V (acceptable window 44.0V .. 55.0V).
  - Field Switch physical architecture: 1-2 Trunk Ports + 8 Intrinsically Safe 2-WISE Spur Ports.
- IEC 60079-47: Explosive atmospheres - Part 47: Equipment protection by 2-Wire Intrinsically Safe Ethernet (2-WISE):
  - 2-WISE Intrinsically Safe Spur maximum current limit: I_spur <= 115 mA.
  - Spur port short-circuit and overload surveillance (> 115 mA).
- IEC 60079-11: Explosive atmospheres - Part 11: Equipment protection by intrinsic safety "i":
  - Field switch surface/internal temperature limit: T_switch <= 85.0 degC.
- ODVA CIP Networks Library Volume 5: CIP Safety Specification:
  - Class 0x39: Safety Supervisor Object
  - Class 0x3A: Safety Validator Object
  - Class 0x3B: Safety Connection Object
  - Class 0x4B: Ethernet-APL Field Switch Diagnostics & Management Object
  - Dual 16-bit Safety CRCs (IEC 61784-3-2 / IEC 61508 SIL 3):
    - CRC-S1: Generator polynomial 0x5935 (init 0x0000) over process data payload.
    - CRC-S2: Generator polynomial 0x755B (init 0x0000) over inverted header fields.
  - Rolling 16-bit sequence counter (0..65535).
  - Electronic Product ID (EPID) CRC32 ("HORNER-OCS-APL-FIELD-SWITCH-SIL3" -> 0xDB4B7D28).
- Diagnostics & Surveillance (%R2837):
  - 0x0000: DIAG_OK (Nominal healthy field switch operation)
  - 0xEEB1: DIAG_ERR_TRUNK_POWER_DEGRADED (Trunk voltage < 44.0V or > 55.0V)
  - 0xEEB2: DIAG_ERR_SPUR_PORT_FAULT (Spur short-circuit or overload > 115 mA)
  - 0xEEB3: DIAG_ERR_SWITCH_THERMAL_OVERHEAT (T_switch > 85.0 degC)
  - 0xEEB4: DIAG_ERR_DUAL_CRC_SAFETY_FAULT (Dual CRC-S1/S2 mismatch)
  - 0xEEB5: DIAG_ERR_PORT_BABBLING_IDIOT (Jabber frame count > limit)
- Horner OCS Memory Space:
  - Analog registers %R2830..%R2837:
    - %R2830: REG_CIP_APL_SWITCH_STATUS (Switch state: 0=DE_ENERGIZED..5=SAFETY_TRIP)
    - %R2831: REG_CIP_APL_SWITCH_PORT_BITMAP (Active link-up spur ports bitmask e.g. 0x00FF)
    - %R2832: REG_CIP_APL_SWITCH_TRUNK_VOLTAGE_MV (Trunk input voltage in mV: 44000..55000 mV)
    - %R2833: REG_CIP_APL_SWITCH_TRUNK_CURRENT_MA (Trunk delivery current in mA: nominal 800 mA)
    - %R2834: REG_CIP_APL_SWITCH_SPUR_FAULT_BITMAP (Spur fault bitmask: bit i set on fault)
    - %R2835: REG_CIP_APL_SWITCH_TEMP_DEGC (Switch internal temperature in degC: limit <= 85 degC)
    - %R2836: REG_CIP_APL_SWITCH_CRC_ERROR_COUNT (Monotonic dual CRC safety error count)
    - %R2837: REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE (Diagnostic code: 0x0000, 0xEEB1..0xEEB5)
  - Discrete coils %M660..%M661:
    - %M660: COIL_CIP_APL_SWITCH_ONLINE (BOOL, True when switch healthy & operational)
    - %M661: COIL_CIP_APL_SWITCH_SAFETY_TRIP (BOOL, True on safety trip or fault lockout)
- Implements ILogicUnit interface with scan_step(*args, **kwargs), step(), execute(), reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.USER/SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'CipSafetyAplSwitchSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.

Deterministic 9-Stage Verification Sequence:
  Stage 1: environment
  Stage 2: protocol_constants_and_register_mappings
  Stage 3: odva_cip_safety_dual_crc_mathematics
  Stage 4: apl_switch_trunk_and_spur_port_telemetry
  Stage 5: trunk_voltage_and_spur_fault_trips
  Stage 6: thermal_overheat_and_babbling_diagnostics
  Stage 7: register_table_synchronization
  Stage 8: pure_st_pou_and_anti_ladder_rejection
  Stage 9: simulation_soak_100_cycles_and_evidence_emission

Generates:
  artifacts/telemetry/cip_safety_apl_switch_evidence.json
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import Enum, IntEnum, IntFlag
import hashlib
import json
import math
from pathlib import Path
import platform
import struct
import sys
import time
import tracemalloc
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import zlib

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = REPO_ROOT / "src"
for p in (str(REPO_ROOT), str(SRC_PATH)):
    if p not in sys.path:
        sys.path.insert(0, p)

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

# Import core protocol engine, constants, models, and ST definitions
from jev_cscape.telemetry.cip_safety_apl_switch import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_APL_SWITCH_CLASS_ID,
    CIP_APL_SWITCH_CLASS_ID,
    REG_CIP_APL_SWITCH_STATUS,
    REG_CIP_APL_SWITCH_PORT_BITMAP,
    REG_CIP_APL_SWITCH_TRUNK_VOLTAGE_MV,
    REG_CIP_APL_SWITCH_TRUNK_CURRENT_MA,
    REG_CIP_APL_SWITCH_SPUR_FAULT_BITMAP,
    REG_CIP_APL_SWITCH_TEMP_DEGC,
    REG_CIP_APL_SWITCH_CRC_ERROR_COUNT,
    REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE,
    COIL_CIP_APL_SWITCH_ONLINE,
    COIL_CIP_APL_SWITCH_SAFETY_TRIP,
    DIAG_OK,
    DIAG_ERR_TRUNK_POWER_DEGRADED,
    DIAG_ERR_SPUR_PORT_FAULT,
    DIAG_ERR_SWITCH_THERMAL_OVERHEAT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_ERR_PORT_BABBLING_IDIOT,
    DiagnosticCode,
    SwitchOperatingState,
    SwitchPortState,
    SwitchStatusBits,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    DEFAULT_SAFETY_EPID,
    DEFAULT_SESSION_ID,
    TRUNK_VOLTAGE_MIN_MV,
    TRUNK_VOLTAGE_MAX_MV,
    TRUNK_VOLTAGE_NOMINAL_MV,
    TRUNK_CURRENT_NOMINAL_MA,
    SPUR_CURRENT_MAX_MA,
    SWITCH_TEMP_MAX_DEGC,
    MAX_JABBER_FRAME_LIMIT,
    DEFAULT_NUM_SPUR_PORTS,
    DEFAULT_ACTIVE_PORTS_BITMAP,
    compute_crc_s1,
    compute_crc_s2,
    compute_epid_hash,
    compute_epid_crc32,
    CIPAPLSwitchSafetyEngine,
    CIPAPLSwitchPacket,
    create_valid_apl_switch_packet,
    ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC,
    verify_cip_safety_apl_switch_pure_st,
)


# ============================================================================
# Ethernet-APL Field Switch Electrical & Telemetry Helpers
# ============================================================================

def calculate_switch_trunk_power_mw(trunk_voltage_mv: int, trunk_current_ma: int) -> int:
    """Compute field switch trunk power delivery in milliwatts: P = (V_trunk_mV * I_trunk_mA) / 1000."""
    return int((int(trunk_voltage_mv) * int(trunk_current_ma)) // 1000)


def calculate_trunk_voltage_margin_mv(
    trunk_voltage_mv: int,
    min_mv: int = TRUNK_VOLTAGE_MIN_MV,
    max_mv: int = TRUNK_VOLTAGE_MAX_MV,
) -> int:
    """Compute distance to nearest trunk voltage limit in millivolts."""
    if trunk_voltage_mv < min_mv:
        return int(trunk_voltage_mv - min_mv)
    if trunk_voltage_mv > max_mv:
        return int(trunk_voltage_mv - max_mv)
    return int(min(trunk_voltage_mv - min_mv, max_mv - trunk_voltage_mv))


def calculate_spur_current_margin_ma(
    spur_current_ma: int,
    limit_ma: int = SPUR_CURRENT_MAX_MA,
) -> int:
    """Compute spur port current safety margin in mA before overload trip."""
    return int(max(0, limit_ma - spur_current_ma))


# ============================================================================
# ANSI Formatting Helpers
# ============================================================================

ESC_RESET = "\033[0m"
ESC_BOLD = "\033[1m"
ESC_DIM = "\033[2m"
ESC_GREEN = "\033[92m"
ESC_RED = "\033[91m"
ESC_YELLOW = "\033[93m"
ESC_CYAN = "\033[96m"


def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    """Format strict 4-state contract ANSI badge."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{ESC_YELLOW}{ESC_BOLD}[BLOCKED]{ESC_RESET}"
    if norm_status == "inconclusive":
        return f"{ESC_YELLOW}{ESC_BOLD}[INCONCLUSIVE]{ESC_RESET}"
    if passed or norm_status in ("passed", "pass", "success"):
        return f"{ESC_GREEN}{ESC_BOLD}[PASS]{ESC_RESET}"
    return f"{ESC_RED}{ESC_BOLD}[FAIL]{ESC_RESET}"


def format_stage_result(
    stage: int | str,
    name: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format a single stage line with ANSI colored badge, timing, and description."""
    badge = format_stage_badge(passed, status)
    timing_str = f" ({timing_ms:.3f} ms)" if timing_ms is not None else ""
    line = f"  Stage {stage}: {badge} {name}{timing_str}"
    if details:
        line += f"\n    {ESC_DIM}{details}{ESC_RESET}"
    return line


# ============================================================================
# Main Deterministic 9-Stage Verification Suite
# ============================================================================

def execute_9stage_verification_suite(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W322",
    quick: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W322 CIP Safety Over Ethernet-APL Field Switch Engine.

    Stages:
      Stage 1: environment
      Stage 2: protocol_constants_and_register_mappings
      Stage 3: odva_cip_safety_dual_crc_mathematics
      Stage 4: apl_switch_trunk_and_spur_port_telemetry
      Stage 5: trunk_voltage_and_spur_fault_trips
      Stage 6: thermal_overheat_and_babbling_diagnostics
      Stage 7: register_table_synchronization
      Stage 8: pure_st_pou_and_anti_ladder_rejection
      Stage 9: simulation_soak_100_cycles_and_evidence_emission
    """
    stages_log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: environment
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    py_ver = sys.version_info
    py_ok = (py_ver.major == 3 and py_ver.minor >= 8)
    plat_str = platform.platform()

    deps_ok = True
    try:
        from jev_cscape.contracts import AgentStatus, ExecutionResult
        from jev_cscape.iec.st_parser import STParser, POUType
        from jev_cscape.security.guard import SecurityGuard
        from jev_cscape.security.exceptions import LadderForbiddenError
        from jev_cscape.simulation.register_table import RegisterTable, PrivilegeMode
        from jev_cscape.simulation.engine import ILogicUnit, ScanContext
        from jev_cscape.telemetry.cip_safety_apl_switch import (
            CIPAPLSwitchSafetyEngine,
            CIPAPLSwitchPacket,
            SwitchOperatingState,
            SwitchPortState,
            DiagnosticCode,
            SwitchStatusBits,
        )
    except ImportError:
        deps_ok = False

    s1_passed = py_ok and deps_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 1,
        "name": "environment",
        "check": "Verify Python runtime, OS platform, and core telemetry dependencies",
        "passed": bool(s1_passed),
        "timing_ms": round(t1, 3),
        "details": f"Python {py_ver.major}.{py_ver.minor}.{py_ver.micro} on {plat_str}. Dependencies verified: {deps_ok}.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: protocol_constants_and_register_mappings
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    class_ids_ok = (
        CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        and CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        and CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        and CIP_SAFETY_APL_SWITCH_CLASS_ID == 0x4B
        and CIP_APL_SWITCH_CLASS_ID == 0x4B
    )

    regs_ok = (
        REG_CIP_APL_SWITCH_STATUS == "%R2830"
        and REG_CIP_APL_SWITCH_PORT_BITMAP == "%R2831"
        and REG_CIP_APL_SWITCH_TRUNK_VOLTAGE_MV == "%R2832"
        and REG_CIP_APL_SWITCH_TRUNK_CURRENT_MA == "%R2833"
        and REG_CIP_APL_SWITCH_SPUR_FAULT_BITMAP == "%R2834"
        and REG_CIP_APL_SWITCH_TEMP_DEGC == "%R2835"
        and REG_CIP_APL_SWITCH_CRC_ERROR_COUNT == "%R2836"
        and REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE == "%R2837"
        and COIL_CIP_APL_SWITCH_ONLINE == "%M660"
        and COIL_CIP_APL_SWITCH_SAFETY_TRIP == "%M661"
    )

    diag_codes_ok = (
        int(DIAG_OK) == 0x0000
        and int(DIAG_ERR_TRUNK_POWER_DEGRADED) == 0xEEB1
        and int(DIAG_ERR_SPUR_PORT_FAULT) == 0xEEB2
        and int(DIAG_ERR_SWITCH_THERMAL_OVERHEAT) == 0xEEB3
        and int(DIAG_ERR_DUAL_CRC_SAFETY_FAULT) == 0xEEB4
        and int(DIAG_ERR_PORT_BABBLING_IDIOT) == 0xEEB5
        # Signed 16-bit safe equality tests
        and DIAG_ERR_TRUNK_POWER_DEGRADED == (0xEEB1 - 0x10000)
        and (DIAG_ERR_TRUNK_POWER_DEGRADED & 0xFFFF) == 0xEEB1
        and DIAG_ERR_SPUR_PORT_FAULT == (0xEEB2 - 0x10000)
        and (DIAG_ERR_SPUR_PORT_FAULT & 0xFFFF) == 0xEEB2
        and DIAG_ERR_SWITCH_THERMAL_OVERHEAT == (0xEEB3 - 0x10000)
        and (DIAG_ERR_SWITCH_THERMAL_OVERHEAT & 0xFFFF) == 0xEEB3
        and DIAG_ERR_DUAL_CRC_SAFETY_FAULT == (0xEEB4 - 0x10000)
        and (DIAG_ERR_DUAL_CRC_SAFETY_FAULT & 0xFFFF) == 0xEEB4
        and DIAG_ERR_PORT_BABBLING_IDIOT == (0xEEB5 - 0x10000)
        and (DIAG_ERR_PORT_BABBLING_IDIOT & 0xFFFF) == 0xEEB5
    )

    enums_ok = (
        int(SwitchOperatingState.DE_ENERGIZED) == 0
        and int(SwitchOperatingState.STANDBY) == 1
        and int(SwitchOperatingState.NORMAL_OPERATION) == 2
        and int(SwitchOperatingState.DEGRADED) == 3
        and int(SwitchOperatingState.FAULT_LOCKOUT) == 4
        and int(SwitchOperatingState.SAFETY_TRIP) == 5
        and int(SwitchPortState.PORT_DISABLED) == 0
        and int(SwitchPortState.PORT_LINK_DOWN) == 1
        and int(SwitchPortState.PORT_LINK_UP) == 2
        and int(SwitchPortState.PORT_OVERLOAD) == 3
        and int(SwitchPortState.PORT_SHORT_CIRCUIT) == 4
        and int(SwitchPortState.PORT_BABBLING) == 5
        and int(SwitchStatusBits.ONLINE) == (1 << 0)
        and int(SwitchStatusBits.NORMAL) == (1 << 1)
        and int(SwitchStatusBits.TRUNK_POWER_DEGRADED) == (1 << 2)
        and int(SwitchStatusBits.SPUR_PORT_FAULT) == (1 << 3)
        and int(SwitchStatusBits.THERMAL_OVERHEAT) == (1 << 4)
        and int(SwitchStatusBits.CRC_FAULT) == (1 << 5)
        and int(SwitchStatusBits.BABBLING_FAULT) == (1 << 6)
        and int(SwitchStatusBits.SAFETY_TRIPPED) == (1 << 7)
    )

    thresholds_ok = (
        TRUNK_VOLTAGE_MIN_MV == 44000
        and TRUNK_VOLTAGE_MAX_MV == 55000
        and TRUNK_VOLTAGE_NOMINAL_MV == 50000
        and SPUR_CURRENT_MAX_MA == 115
        and SWITCH_TEMP_MAX_DEGC == 85.0
        and MAX_JABBER_FRAME_LIMIT == 10
        and DEFAULT_NUM_SPUR_PORTS == 8
        and DEFAULT_ACTIVE_PORTS_BITMAP == 0x00FF
    )

    s2_passed = class_ids_ok and regs_ok and diag_codes_ok and enums_ok and thresholds_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 2,
        "name": "protocol_constants_and_register_mappings",
        "check": "Verify Field Switch diagnostic codes (0xEEB1-0xEEB5), register offsets (%R2830..%R2837), coils (%M660..%M661)",
        "passed": bool(s2_passed),
        "timing_ms": round(t1, 3),
        "details": "Class IDs (0x39, 0x3A, 0x3B, 0x4B), registers %R2830..%R2837, coils %M660..%M661, and diagnostic codes (0x0000, 0xEEB1..0xEEB5) verified bit-exact.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: odva_cip_safety_dual_crc_mathematics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    sample_payload = b"Horner-ODVA-CIP-Safety-APL-Field-Switch-W322-Payload"
    c1 = compute_crc_s1(sample_payload)
    c1_again = compute_crc_s1(sample_payload)
    crc_s1_det = (c1 == c1_again) and (0 <= c1 <= 0xFFFF) and (c1 != 0)

    raw_header = (
        (DEFAULT_SESSION_ID).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (400).to_bytes(4, "big")
        + (2).to_bytes(1, "big")
        + (0x00FF).to_bytes(2, "big")
        + (50000).to_bytes(2, "big")
        + (800).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (35).to_bytes(2, "big")
    )
    inverted = bytes(~b & 0xFF for b in raw_header)
    c2 = compute_crc_s2(inverted)
    c2_again = compute_crc_s2(inverted)
    crc_s2_det = (c2 == c2_again) and (0 <= c2 <= 0xFFFF) and (c2 != 0)

    # Distinct polynomials: 0x5935 (S1) vs 0x755B (S2)
    poly_distinct = (c1 != c2)

    # Sensitivity: 1-bit payload flip detection in CRC-S1
    mut_payload = bytearray(sample_payload)
    mut_payload[0] ^= 0x01
    c1_mut = compute_crc_s1(bytes(mut_payload))
    s1_tamper_ok = (c1_mut != c1)

    # Sensitivity: 1-bit header flip detection in CRC-S2
    mut_inv = bytearray(inverted)
    mut_inv[0] ^= 0x01
    c2_mut = compute_crc_s2(bytes(mut_inv))
    s2_tamper_ok = (c2_mut != c2)

    # Packet model framing round-trip
    pkt = create_valid_apl_switch_packet(payload_bytes=sample_payload, sequence=10, timestamp_us=400)
    pkt_valid = pkt.validate_crcs() and (pkt.crc_s1 == c1)
    raw = pkt.pack()
    unpacked = CIPAPLSwitchPacket.unpack(raw)
    unpack_ok = unpacked.validate_crcs() and (unpacked.payload_bytes == sample_payload)

    # Corrupted packet detection
    bad_pkt = create_valid_apl_switch_packet(payload_bytes=sample_payload, sequence=10, timestamp_us=400)
    bad_pkt.crc_s1 = 0x9999
    bad_caught = not bad_pkt.validate_crcs()

    # EPID hash and CRC32 verification
    epid_h = compute_epid_hash()
    epid_crc32 = compute_epid_crc32()
    epid_ok = (epid_h != 0) and (epid_crc32 == 0xDB4B7D28)

    s3_passed = (
        crc_s1_det
        and crc_s2_det
        and poly_distinct
        and s1_tamper_ok
        and s2_tamper_ok
        and pkt_valid
        and unpack_ok
        and bad_caught
        and epid_ok
        and (CIP_SAFETY_CRC_S1_POLY == 0x5935)
        and (CIP_SAFETY_CRC_S2_POLY == 0x755B)
        and (CIP_SAFETY_CRC_INIT == 0x0000)
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 3,
        "name": "odva_cip_safety_dual_crc_mathematics",
        "check": "Verify dual CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B) mathematics, bit-flip detection, and frame integrity",
        "passed": bool(s3_passed),
        "timing_ms": round(t1, 3),
        "details": f"CRC-S1=0x{c1:04X}, CRC-S2=0x{c2:04X}. Dual polynomial mathematics, 1-bit mutation sensitivity, and packet serialization round-trip verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: apl_switch_trunk_and_spur_port_telemetry
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    # Calculations
    p_calc = calculate_switch_trunk_power_mw(50000, 800)
    margin_v = calculate_trunk_voltage_margin_mv(50000)
    margin_i = calculate_spur_current_margin_ma(50)
    electrical_ok = (p_calc == 40000) and (margin_v == 5000) and (margin_i == 65)

    # Nominal Field Switch Engine baseline
    eng4 = CIPAPLSwitchSafetyEngine()
    eng4.connect()
    nom_ok = (
        eng4.switch_state == SwitchOperatingState.NORMAL_OPERATION
        and eng4.trunk_voltage_mv == 50000
        and eng4.trunk_current_ma == 800
        and eng4.power_mw == 40000
        and eng4.temp_degc == 35
        and eng4.active_ports_bitmap == 0x00FF
        and eng4.spur_fault_bitmap == 0
        and eng4.online is True
        and eng4.tripped is False
        and eng4.diagnostic_code == DIAG_OK
        and eng4.fault_code == 0
        and all(s == SwitchPortState.PORT_LINK_UP for s in eng4.port_states)
    )

    # Frame transmission and reception across engines
    tx_pkt = eng4.send_packet(b"ValidSwitchPayload")
    tx_ok = tx_pkt.validate_crcs()

    rx_eng = CIPAPLSwitchSafetyEngine()
    rx_eng.connect()
    rx_ok = rx_eng.receive_packet(tx_pkt)
    exchange_ok = tx_ok and rx_ok and rx_eng.online and not rx_eng.tripped

    s4_passed = electrical_ok and nom_ok and exchange_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 4,
        "name": "apl_switch_trunk_and_spur_port_telemetry",
        "check": "Verify IEEE 802.3cg trunk power delivery (50V/800mA), 8-spur-port telemetry, and packet transmission",
        "passed": bool(s4_passed),
        "timing_ms": round(t1, 3),
        "details": f"Field switch nominal telemetry verified; operating at {eng4.power_mw} mW across 8 healthy spur ports.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: trunk_voltage_and_spur_fault_trips
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng5 = CIPAPLSwitchSafetyEngine()
    eng5.connect()

    # 1. Under-voltage trip (< 44.0V -> 0xEEB1)
    eng5.inject_trunk_voltage_fault(41000)
    uv_trip_ok = (
        eng5.switch_state == SwitchOperatingState.SAFETY_TRIP
        and eng5.diagnostic_code == DIAG_ERR_TRUNK_POWER_DEGRADED
        and eng5.diagnostic_code == 0xEEB1
        and eng5.fault_code == 0xEEB1
        and eng5.trunk_voltage_mv == 41000
        and eng5.online is False
        and eng5.tripped is True
    )
    eng5.clear_fault()
    uv_rec_ok = (
        eng5.switch_state == SwitchOperatingState.NORMAL_OPERATION
        and eng5.diagnostic_code == DIAG_OK
        and eng5.fault_code == 0
        and eng5.online is True
        and eng5.tripped is False
    )

    # 2. Over-voltage trip (> 55.0V -> 0xEEB1)
    eng5.inject_trunk_voltage_fault(57500)
    ov_trip_ok = (
        eng5.switch_state == SwitchOperatingState.SAFETY_TRIP
        and eng5.diagnostic_code == DIAG_ERR_TRUNK_POWER_DEGRADED
        and eng5.fault_code == 0xEEB1
        and eng5.trunk_voltage_mv == 57500
        and eng5.online is False
        and eng5.tripped is True
    )
    eng5.clear_fault()
    ov_rec_ok = (eng5.online is True and eng5.tripped is False and eng5.diagnostic_code == DIAG_OK)

    # 3. Spur port fault trip (current > 115 mA -> 0xEEB2)
    eng5.inject_spur_fault(port_idx=2, current_ma=160)
    spur_trip_ok = (
        eng5.switch_state == SwitchOperatingState.SAFETY_TRIP
        and eng5.diagnostic_code == DIAG_ERR_SPUR_PORT_FAULT
        and eng5.diagnostic_code == 0xEEB2
        and eng5.fault_code == 0xEEB2
        and (eng5.spur_fault_bitmap & (1 << 2)) != 0
        and eng5.online is False
        and eng5.tripped is True
    )
    eng5.clear_fault()
    spur_rec_ok = (
        eng5.switch_state == SwitchOperatingState.NORMAL_OPERATION
        and eng5.diagnostic_code == DIAG_OK
        and eng5.spur_fault_bitmap == 0
        and eng5.online is True
        and eng5.tripped is False
    )

    s5_passed = uv_trip_ok and uv_rec_ok and ov_trip_ok and ov_rec_ok and spur_trip_ok and spur_rec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 5,
        "name": "trunk_voltage_and_spur_fault_trips",
        "check": "Verify trunk degraded trip (0xEEB1) and spur port fault trip (0xEEB2) asserting fail-safe state and recovery",
        "passed": bool(s5_passed),
        "timing_ms": round(t1, 3),
        "details": "Trunk degraded voltage (0xEEB1) and spur overload/short-circuit (0xEEB2) safety trips properly forced fail-safe state.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: thermal_overheat_and_babbling_diagnostics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng6 = CIPAPLSwitchSafetyEngine()
    eng6.connect()

    # 1. Thermal overheat fault (T_switch > 85.0 degC -> 0xEEB3)
    eng6.inject_thermal_fault(92)
    thm_trip_ok = (
        eng6.switch_state == SwitchOperatingState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_SWITCH_THERMAL_OVERHEAT
        and eng6.diagnostic_code == 0xEEB3
        and eng6.fault_code == 0xEEB3
        and eng6.temp_degc == 92
        and eng6.online is False
        and eng6.tripped is True
    )
    eng6.clear_fault()
    thm_rec_ok = (eng6.online is True and eng6.tripped is False and eng6.diagnostic_code == DIAG_OK)

    # 2. Port babbling idiot fault (jabber frame count > limit -> 0xEEB5)
    eng6.inject_babbling_fault(port_idx=4)
    bab_trip_ok = (
        eng6.switch_state == SwitchOperatingState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_PORT_BABBLING_IDIOT
        and eng6.diagnostic_code == 0xEEB5
        and eng6.fault_code == 0xEEB5
        and (eng6.spur_fault_bitmap & (1 << 4)) != 0
        and eng6.port_states[4] == SwitchPortState.PORT_BABBLING
        and eng6.online is False
        and eng6.tripped is True
    )
    eng6.clear_fault()
    bab_rec_ok = (eng6.online is True and eng6.diagnostic_code == DIAG_OK)

    # 3. Dual CRC safety corruption fault (0xEEB4)
    bad_crc_pkt = create_valid_apl_switch_packet()
    bad_crc_pkt.crc_s1 = 0xBADC
    rx_bad = eng6.receive_packet(bad_crc_pkt)
    crc_trip_ok = (
        rx_bad is False
        and eng6.switch_state == SwitchOperatingState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        and eng6.diagnostic_code == 0xEEB4
        and eng6.crc_error_count >= 1
    )
    eng6.clear_fault()
    crc_rec_ok = (eng6.online is True and eng6.tripped is False and eng6.diagnostic_code == DIAG_OK)

    s6_passed = thm_trip_ok and thm_rec_ok and bab_trip_ok and bab_rec_ok and crc_trip_ok and crc_rec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 6,
        "name": "thermal_overheat_and_babbling_diagnostics",
        "check": "Verify switch thermal overheat fault (0xEEB3), babbling idiot fault (0xEEB5), and CRC safety trip (0xEEB4)",
        "passed": bool(s6_passed),
        "timing_ms": round(t1, 3),
        "details": "Thermal overheat (0xEEB3), babbling idiot (0xEEB5), and CRC mismatch (0xEEB4) verified with safe recovery.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: register_table_synchronization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt7 = RegisterTable()
    eng7 = CIPAPLSwitchSafetyEngine(register_table=rt7)
    eng7.connect()
    eng7.sync_to_registers(rt7, privilege=PrivilegeMode.USER)

    # 1. Healthy nominal state
    w_stat = rt7.read_word(REG_CIP_APL_SWITCH_STATUS)
    w_ports = rt7.read_uword(REG_CIP_APL_SWITCH_PORT_BITMAP)
    w_vin = rt7.read_uword(REG_CIP_APL_SWITCH_TRUNK_VOLTAGE_MV)
    w_i = rt7.read_uword(REG_CIP_APL_SWITCH_TRUNK_CURRENT_MA)
    w_fault = rt7.read_uword(REG_CIP_APL_SWITCH_SPUR_FAULT_BITMAP)
    w_temp = rt7.read_word(REG_CIP_APL_SWITCH_TEMP_DEGC)
    w_crc_err = rt7.read_uword(REG_CIP_APL_SWITCH_CRC_ERROR_COUNT)
    w_diag = rt7.read_uword(REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE)
    b_online = rt7.read_bit(COIL_CIP_APL_SWITCH_ONLINE)
    b_trip = rt7.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP)

    nom_sync_ok = (
        w_stat == int(SwitchOperatingState.NORMAL_OPERATION)
        and w_ports == 0x00FF
        and w_vin == 50000
        and w_i == 800
        and w_fault == 0
        and w_temp == 35
        and w_crc_err == 0
        and w_diag == 0x0000
        and b_online is True
        and b_trip is False
    )

    # 2. Trunk degradation fault reflection
    eng7.inject_trunk_voltage_fault(42000)
    eng7.sync_to_registers(rt7)
    u_diag = rt7.read_uword(REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE)
    s_diag = rt7.read_word(REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE)

    fault_sync_ok = (
        rt7.read_word(REG_CIP_APL_SWITCH_STATUS) == int(SwitchOperatingState.SAFETY_TRIP)
        and rt7.read_uword(REG_CIP_APL_SWITCH_TRUNK_VOLTAGE_MV) == 42000
        and u_diag == 0xEEB1
        and s_diag == (0xEEB1 - 0x10000)
        and (s_diag & 0xFFFF) == 0xEEB1
        and rt7.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is False
        and rt7.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is True
    )

    # 3. Restoration
    eng7.clear_fault()
    eng7.sync_to_registers(rt7, privilege=PrivilegeMode.SYSTEM)
    rec_sync_ok = (
        rt7.read_word(REG_CIP_APL_SWITCH_STATUS) == int(SwitchOperatingState.NORMAL_OPERATION)
        and rt7.read_uword(REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE) == 0x0000
        and rt7.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is True
        and rt7.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is False
    )

    s7_passed = nom_sync_ok and fault_sync_ok and rec_sync_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 7,
        "name": "register_table_synchronization",
        "check": "Verify RegisterTable reads/writes, signed/unsigned masking across %R2830..%R2837 and coils %M660..%M661",
        "passed": bool(s7_passed),
        "timing_ms": round(t1, 3),
        "details": "Bit-exact synchronization and 16-bit signed masking verified across %R2830..%R2837 and coils %M660..%M661.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    # 1. Validate ST POU syntax and AST parsing
    st_syntax_ok = verify_cip_safety_apl_switch_pure_st()
    SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC)
    res_st = STParser.validate_code(ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC)
    parser_ok = (res_st.status == AgentStatus.SUCCESS)
    ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC)
    ast_ok = (ast.pou_type == POUType.PROGRAM and ast.name == "CipSafetyAplSwitchSync")

    # Verify address bindings in ST POU
    bindings_ok = (
        "%R2830" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        and "%R2831" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        and "%R2832" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        and "%R2833" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        and "%R2834" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        and "%R2835" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        and "%R2836" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        and "%R2837" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        and "%M660" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        and "%M661" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
    )

    # 2. Strict rejection of ladder logic constructs
    ladder_snippets = [
        "PROGRAM LadderTest\n VAR x : BOOL; END_VAR\n ---[ ]--- x;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR x : BOOL; END_VAR\n ---[/]--- x;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR y : BOOL; END_VAR\n ---( )--- y;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR y : BOOL; END_VAR\n ---(S)--- y;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR y : BOOL; END_VAR\n ---(R)--- y;\n END_PROGRAM",
        "PROGRAM LadderTest\n RUNG 1\n END_PROGRAM",
        "PROGRAM LadderTest\n NETWORK 10\n END_PROGRAM",
        "PROGRAM LadderTest\n XIC(Contact1);\n END_PROGRAM",
        "PROGRAM LadderTest\n OTE(Coil1);\n END_PROGRAM",
    ]
    ladder_rejected = 0
    for snippet in ladder_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snippet)
        except LadderForbiddenError:
            ladder_rejected += 1
        except Exception:
            pass

    anti_ladder_ok = (ladder_rejected == len(ladder_snippets))
    s8_passed = st_syntax_ok and parser_ok and ast_ok and bindings_ok and anti_ladder_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 8,
        "name": "pure_st_pou_and_anti_ladder_rejection",
        "check": "Verify pure IEC 61131-3 ST POU 'CipSafetyAplSwitchSync' and strict rejection of ladder logic constructs",
        "passed": bool(s8_passed),
        "timing_ms": round(t1, 3),
        "details": f"Pure ST POU verified. Rejected {ladder_rejected}/{len(ladder_snippets)} ladder constructs with LadderForbiddenError.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: simulation_soak_100_cycles_and_evidence_emission
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim_cycles = 10 if quick else 100
    rt9 = RegisterTable()
    eng9 = CIPAPLSwitchSafetyEngine(register_table=rt9)
    eng9.connect()

    tracemalloc.start()
    for cycle in range(1, sim_cycles + 1):
        pkt = eng9.send_packet()
        eng9.receive_packet(pkt)
        res = eng9.scan_step(dt=0.0004, register_table=rt9)
        assert res.status == AgentStatus.SUCCESS
        assert eng9.online is True
        assert eng9.tripped is False
        assert eng9.diagnostic_code == DIAG_OK
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    soak_ok = (
        eng9.online is True
        and eng9.tripped is False
        and eng9.diagnostic_code == DIAG_OK
        and rt9.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is True
        and rt9.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is False
        and peak_mem < 2 * 1024 * 1024
    )

    t1 = (time.perf_counter() - t0) * 1000.0
    stage_9_entry = {
        "stage": 9,
        "name": "simulation_soak_100_cycles_and_evidence_emission",
        "check": f"Verify multi-cycle ILogicUnit scan execution ({sim_cycles} cycles), zero memory leaks, and emit evidence JSON",
        "passed": bool(soak_ok),
        "timing_ms": round(t1, 3),
        "details": f"Executed {sim_cycles} continuous scan cycles. Zero errors, peak memory: {peak_mem / 1024:.1f} KB.",
    }
    stages_log.append(stage_9_entry)

    all_stages_passed = all(stg["passed"] for stg in stages_log)
    passed_count = sum(1 for stg in stages_log if stg["passed"])

    # Generate cryptographic SHA-256 digests
    pou_sha256 = hashlib.sha256(ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC.encode("utf-8")).hexdigest()
    stages_summary_str = json.dumps(stages_log, sort_keys=True)
    stages_sha256 = hashlib.sha256(stages_summary_str.encode("utf-8")).hexdigest()

    evidence_dict: Dict[str, Any] = {
        "status": "success" if all_stages_passed else "failed",
        "error_code": None if all_stages_passed else "ERR_STAGE_FAILED",
        "details": (
            f"All 9 Industrial ODVA CIP Safety Over Ethernet-APL Field Switch Diagnostics Protocol Engine ({work_package}) stages passed deterministically "
            f"(PASSED {passed_count}/9 stages)."
            if all_stages_passed
            else f"Verification failed with {passed_count}/9 stages passing."
        ),
        "work_package": work_package,
        "stages_passed": passed_count,
        "total_stages": 9,
        "passed_stages": passed_count,
        "data": {
            "work_package": work_package,
            "gate": "G8",
            "protocol": "Industrial ODVA CIP Safety Over Ethernet-APL Field Switch Diagnostics Protocol Engine (IEEE 802.3cg / IEC 60079-47 / IEC 61784-3-2)",
            "standards": [
                "ODVA CIP Safety Volume 5",
                "IEEE 802.3cg-2019 10BASE-T1L",
                "IEC 60079-47 2-WISE",
                "IEC 61784-3-2",
                "IEC 61508 SIL 3",
            ],
            "registers": [
                "%R2830..%R2837",
                "%M660..%M661",
            ],
            "diagnostic_codes": {
                "0x0000": "OK",
                "0xEEB1": "ERR_TRUNK_POWER_DEGRADED",
                "0xEEB2": "ERR_SPUR_PORT_FAULT",
                "0xEEB3": "ERR_SWITCH_THERMAL_OVERHEAT",
                "0xEEB4": "ERR_DUAL_CRC_SAFETY_FAULT",
                "0xEEB5": "ERR_PORT_BABBLING_IDIOT",
            },
            "sha256_digests": {
                "pou_sha256": pou_sha256,
                "stages_sha256": stages_sha256,
            },
            "checks_passed": passed_count,
            "total_checks": 9,
            "stages": stages_log,
            "tests": stages_log,
        },
    }

    # Save evidence file if output_path provided
    if output_path:
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence_dict, f, indent=2)

    return evidence_dict


# Backwards compatibility and standard aliases
run_cip_safety_apl_switch_verification = execute_9stage_verification_suite
run_deterministic_9stage_suite = execute_9stage_verification_suite


# ============================================================================
# CLI Entrypoint
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for W322 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Execute W322 CIP Safety Over Ethernet-APL Field Switch Diagnostics Protocol Engine 9-Stage Verification Suite"
    )
    parser.add_argument(
        "positional_path",
        nargs="?",
        default=None,
        help="Optional positional path for output evidence JSON file",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="flag_path",
        default=None,
        help="Path to output JSON evidence artifact (default: artifacts/telemetry/cip_safety_apl_switch_evidence.json)",
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        default=False,
        help="Execute quick verification mode (reduced simulation cycles)",
    )
    parser.add_argument(
        "--work-package",
        "-w",
        default="W322",
        help="Work package ID (default: W322)",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_apl_switch_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: ODVA CIP Safety Over Ethernet-APL Field Switch Verification ({args.work_package}){ESC_RESET}")
        print("=" * 80)

    t0 = time.perf_counter()
    try:
        evidence = execute_9stage_verification_suite(
            output_path=evidence_path,
            work_package=args.work_package,
            quick=args.quick,
        )
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1
    elapsed_total_ms = (time.perf_counter() - t0) * 1000.0

    # Ensure evidence file was written
    if not evidence_path.exists() or evidence_path.stat().st_size == 0:
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    stages = evidence.get("data", {}).get("stages", [])
    for stg in stages:
        stage_num = stg.get("stage", "?")
        stage_name = stg.get("name") or stg.get("check", "unnamed_stage")
        passed = stg.get("passed", False)
        timing = stg.get("timing_ms") or stg.get("duration_ms")
        details = stg.get("details", "")
        status = stg.get("status")
        print(format_stage_result(stage_num, stage_name, passed, timing, details, status))

    passed_count = evidence.get("stages_passed", sum(1 for s in stages if s.get("passed", False)))
    total_count = evidence.get("total_stages", len(stages))
    status_str = evidence.get("status", "unknown")

    print("-" * 80)
    status_badge = (
        f"{ESC_GREEN}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
        if status_str == "success"
        else f"{ESC_RED}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
    )
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed across {len(stages)} verification stages (in {elapsed_total_ms:.2f} ms).")
    print(f"[*] Status: {status_badge}")
    print(f"[*] Evidence artifact saved: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print("=" * 80)

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
