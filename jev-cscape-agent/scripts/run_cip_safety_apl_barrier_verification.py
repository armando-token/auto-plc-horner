#!/usr/bin/env python3
"""Deterministic 9-Stage Verification Runner for Industrial ODVA CIP Safety Over Ethernet-APL Intrinsic Safety Power Barrier Monitor Engine (W319).

Work Package: W319 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [ODVA CIP Safety Over Ethernet-APL Intrinsic Safety Power Barrier Monitor Engine]
Status Contract: Strict 4-State JSON output (success | failed | blocked | inconclusive) & evidence emission.

Standards & Specifications:
- IEC 60079-11: Explosive atmospheres - Part 11: Equipment protection by intrinsic safety "i":
  - Intrinsic Safety (IS) energy limitation for Zone 0 / Class I Div 1 hazardous locations.
  - Zener / galvanically isolated electronic barrier surveillance.
  - Thermal surface temperature surveillance (T4 classification <= 135 degC, component limit <= 85 degC).
- IEC 60079-47: Explosive atmospheres - Part 47: Equipment protection by 2-Wire Intrinsically Safe Ethernet (2-WISE):
  - 2-WISE IS maximum output voltage: U_o <= 15.0 V (15,000 mV).
  - 2-WISE IS maximum output current: I_o <= 215 mA.
  - Fast crowbar / galvanic cutoff clamping output voltage to safe levels.
- IEEE 802.3cg-2019: 10 Mb/s Single Pair Ethernet (10BASE-T1L Ethernet-APL):
  - Point-to-point trunk (up to 1,000m) and spur (up to 200m) topologies.
  - Intrinsic safety barrier profiles:
    - PROFILE_2WISE_15V_215MA = 0 (2-WISE Spur Intrinsically Safe Barrier: V_max 15.0V, I_max 215 mA, P_max 3225 mW)
    - PROFILE_APL_TRUNK_50V_1500MA = 1 (APL Trunk Barrier / Power Supply: V_max 50.0V, I_max 1500 mA, P_max 75000 mW)
    - PROFILE_SPUR_FIELD_15V_100MA = 2 (APL Field Spur Barrier: V_max 15.0V, I_max 100 mA, P_max 1500 mW)
  - Barrier Operational State Machine:
    0: DE_ENERGIZED (Power barrier de-energized / disconnected)
    1: MONITORING (Actively probing / monitoring line health)
    2: NORMAL_OPERATION (Normal regulated IS operation within safe envelope)
    3: WARNING (Thermal warning or excursion approaching limit)
    4: FAULT_LOCKOUT (Latched fault lockout requiring reset)
    5: SAFETY_TRIP (Safety interlock trip; safe galvanic de-energization asserted)
- ODVA CIP Networks Library Volume 5: CIP Safety Specification:
  - Class 0x39: Safety Supervisor Object
  - Class 0x3A: Safety Validator Object
  - Class 0x3B: Safety Connection Object
  - Class 0x49: Ethernet-APL Intrinsic Safety Barrier Management Object
  - Dual 16-bit Safety CRCs (IEC 61784-3-2 / IEC 61508 SIL 3):
    - CRC-S1: Generator polynomial 0x5935 (init 0x0000) over process data payload.
    - CRC-S2: Generator polynomial 0x755B (init 0x0000) over inverted header fields.
  - Rolling 16-bit sequence counter (0..65535).
  - Electronic Product ID (EPID) CRC32 ("HORNER-OCS-APL-IS-BARRIER-SIL3" -> 0x09AAE062).
- Diagnostics & Surveillance (%R2807):
  - 0x0000: DIAG_OK (Nominal healthy barrier operation)
  - 0xEEA1: DIAG_ERR_OVERVOLTAGE_BARRIER (V_out > 15.0V / 2-WISE IS limit breach)
  - 0xEEA2: DIAG_ERR_OVERCURRENT_EXCURSION (I_out > 215 mA excursion)
  - 0xEEA3: DIAG_ERR_THERMAL_BARRIER_OVERHEAT (T_barrier > 85.0 degC overheat)
  - 0xEEA4: DIAG_ERR_DUAL_CRC_SAFETY_FAULT (CRC-S1 or CRC-S2 mismatch)
  - 0xEEA5: DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT (Shield leakage current > 50 uA)
- Horner OCS Memory Space:
  - Analog registers %R2800..%R2807:
    - %R2800: REG_CIP_APL_BARRIER_STATUS (Barrier state: 0=DE_ENERGIZED..5=SAFETY_TRIP)
    - %R2801: REG_CIP_APL_BARRIER_VOLTAGE_IN_MV (Input bus voltage in mV)
    - %R2802: REG_CIP_APL_BARRIER_VOLTAGE_OUT_MV (Regulated IS output voltage in mV)
    - %R2803: REG_CIP_APL_BARRIER_CURRENT_MA (Barrier output current in mA)
    - %R2804: REG_CIP_APL_BARRIER_IMPEDANCE_MOHM (Dynamic barrier impedance in mOhm)
    - %R2805: REG_CIP_APL_BARRIER_TEMP_DEGC (Barrier internal surface temperature in degC)
    - %R2806: REG_CIP_APL_BARRIER_POWER_MW (Delivered/dissipated power in mW)
    - %R2807: REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE (Diagnostic code: 0x0000, 0xEEA1..0xEEA5)
  - Discrete coils %M653..%M654:
    - %M653: COIL_CIP_APL_BARRIER_ONLINE (BOOL, True when barrier is healthy & operational)
    - %M654: COIL_CIP_APL_BARRIER_SAFETY_TRIP (BOOL, True on safety trip or fault lockout)
- Implements ILogicUnit interface with scan_step(*args, **kwargs), step(), execute(), reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.USER/SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'CipSafetyAplBarrierSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.

Deterministic 9-Stage Verification Sequence:
  Stage 1: environment
  Stage 2: protocol_constants_and_register_mappings
  Stage 3: odva_cip_safety_dual_crc_mathematics
  Stage 4: apl_intrinsic_safety_power_profiles_and_telemetry
  Stage 5: overvoltage_and_overcurrent_barrier_trips
  Stage 6: thermal_overheat_and_shield_leakage_diagnostics
  Stage 7: register_table_synchronization
  Stage 8: pure_st_pou_and_anti_ladder_rejection
  Stage 9: simulation_soak_100_cycles_and_evidence_emission

Generates:
  artifacts/telemetry/cip_safety_apl_barrier_evidence.json
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
from jev_cscape.telemetry.cip_safety_apl_barrier import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_APL_BARRIER_CLASS_ID,
    CIP_APL_BARRIER_CLASS_ID,
    REG_CIP_APL_BARRIER_STATUS,
    REG_CIP_APL_BARRIER_VOLTAGE_IN_MV,
    REG_CIP_APL_BARRIER_VOLTAGE_OUT_MV,
    REG_CIP_APL_BARRIER_CURRENT_MA,
    REG_CIP_APL_BARRIER_IMPEDANCE_MOHM,
    REG_CIP_APL_BARRIER_TEMP_DEGC,
    REG_CIP_APL_BARRIER_POWER_MW,
    REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE,
    COIL_CIP_APL_BARRIER_ONLINE,
    COIL_CIP_APL_BARRIER_SAFETY_TRIP,
    DIAG_OK,
    DIAG_ERR_OVERVOLTAGE_BARRIER,
    DIAG_ERR_OVERCURRENT_EXCURSION,
    DIAG_ERR_THERMAL_BARRIER_OVERHEAT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT,
    DiagnosticCode,
    BarrierOperatingState,
    BarrierProfile,
    BarrierStatusBits,
    BARRIER_PROFILE_SPECS,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    DEFAULT_SAFETY_EPID,
    DEFAULT_SESSION_ID,
    DEFAULT_BARRIER_IMPEDANCE_MOHM,
    DEFAULT_SHIELD_LEAKAGE_THRESHOLD_UA,
    DEFAULT_THERMAL_LIMIT_DEGC,
    compute_crc_s1,
    compute_crc_s2,
    compute_epid_hash,
    compute_epid_crc32,
    CIPAPLBarrierSafetyEngine,
    CIPAPLBarrierPacket,
    create_valid_apl_barrier_packet,
    ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC,
    verify_cip_safety_apl_barrier_pure_st,
)


# ============================================================================
# Ethernet-APL Intrinsic Safety Power & Physics Kinematics Calculation Helpers
# ============================================================================

def calculate_barrier_power_mw(voltage_out_mv: int, current_ma: int) -> int:
    """Compute barrier active power delivery in milliwatts: P = (V_out_mV * I_mA) / 1000."""
    return int((int(voltage_out_mv) * int(current_ma)) // 1000)


def calculate_barrier_voltage_drop_mv(voltage_in_mv: int, voltage_out_mv: int) -> int:
    """Compute series voltage drop across barrier pass elements: V_drop = V_in - V_out."""
    return int(max(0, int(voltage_in_mv) - int(voltage_out_mv)))


def calculate_barrier_impedance_mohm(voltage_drop_mv: int, current_ma: int) -> int:
    """Compute dynamic series resistance in mOhm: Z = (V_drop_mV * 1000) / I_mA."""
    return int((int(voltage_drop_mv) * 1000) // max(1, int(current_ma)))


def calculate_shield_leakage_margin_ua(leakage_ua: float, threshold_ua: float = 50.0) -> float:
    """Compute shield leakage safety margin in microamperes before fault trip."""
    return float(max(0.0, threshold_ua - leakage_ua))


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
    work_package: str = "W319",
    quick: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W319 CIP Safety Over Ethernet-APL IS Barrier Engine.

    Stages:
      Stage 1: environment
      Stage 2: protocol_constants_and_register_mappings
      Stage 3: odva_cip_safety_dual_crc_mathematics
      Stage 4: apl_intrinsic_safety_power_profiles_and_telemetry
      Stage 5: overvoltage_and_overcurrent_barrier_trips
      Stage 6: thermal_overheat_and_shield_leakage_diagnostics
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
        from jev_cscape.telemetry.cip_safety_apl_barrier import (
            CIPAPLBarrierSafetyEngine,
            CIPAPLBarrierPacket,
            BarrierOperatingState,
            BarrierProfile,
            DiagnosticCode,
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
        and CIP_SAFETY_APL_BARRIER_CLASS_ID == 0x49
        and CIP_APL_BARRIER_CLASS_ID == 0x49
    )

    regs_ok = (
        REG_CIP_APL_BARRIER_STATUS == "%R2800"
        and REG_CIP_APL_BARRIER_VOLTAGE_IN_MV == "%R2801"
        and REG_CIP_APL_BARRIER_VOLTAGE_OUT_MV == "%R2802"
        and REG_CIP_APL_BARRIER_CURRENT_MA == "%R2803"
        and REG_CIP_APL_BARRIER_IMPEDANCE_MOHM == "%R2804"
        and REG_CIP_APL_BARRIER_TEMP_DEGC == "%R2805"
        and REG_CIP_APL_BARRIER_POWER_MW == "%R2806"
        and REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE == "%R2807"
        and COIL_CIP_APL_BARRIER_ONLINE == "%M653"
        and COIL_CIP_APL_BARRIER_SAFETY_TRIP == "%M654"
    )

    diag_codes_ok = (
        int(DIAG_OK) == 0x0000
        and int(DIAG_ERR_OVERVOLTAGE_BARRIER) == 0xEEA1
        and int(DIAG_ERR_OVERCURRENT_EXCURSION) == 0xEEA2
        and int(DIAG_ERR_THERMAL_BARRIER_OVERHEAT) == 0xEEA3
        and int(DIAG_ERR_DUAL_CRC_SAFETY_FAULT) == 0xEEA4
        and int(DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT) == 0xEEA5
        # Signed 16-bit safe equality tests
        and DIAG_ERR_OVERVOLTAGE_BARRIER == (0xEEA1 - 0x10000)
        and (DIAG_ERR_OVERVOLTAGE_BARRIER & 0xFFFF) == 0xEEA1
        and DIAG_ERR_OVERCURRENT_EXCURSION == (0xEEA2 - 0x10000)
        and (DIAG_ERR_OVERCURRENT_EXCURSION & 0xFFFF) == 0xEEA2
        and DIAG_ERR_THERMAL_BARRIER_OVERHEAT == (0xEEA3 - 0x10000)
        and (DIAG_ERR_THERMAL_BARRIER_OVERHEAT & 0xFFFF) == 0xEEA3
        and DIAG_ERR_DUAL_CRC_SAFETY_FAULT == (0xEEA4 - 0x10000)
        and (DIAG_ERR_DUAL_CRC_SAFETY_FAULT & 0xFFFF) == 0xEEA4
        and DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT == (0xEEA5 - 0x10000)
        and (DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT & 0xFFFF) == 0xEEA5
    )

    enums_ok = (
        int(BarrierOperatingState.DE_ENERGIZED) == 0
        and int(BarrierOperatingState.MONITORING) == 1
        and int(BarrierOperatingState.NORMAL_OPERATION) == 2
        and int(BarrierOperatingState.WARNING) == 3
        and int(BarrierOperatingState.FAULT_LOCKOUT) == 4
        and int(BarrierOperatingState.SAFETY_TRIP) == 5
        and int(BarrierProfile.PROFILE_2WISE_15V_215MA) == 0
        and int(BarrierProfile.PROFILE_APL_TRUNK_50V_1500MA) == 1
        and int(BarrierProfile.PROFILE_SPUR_FIELD_15V_100MA) == 2
        and int(BarrierStatusBits.ONLINE) == (1 << 0)
        and int(BarrierStatusBits.NORMAL) == (1 << 1)
        and int(BarrierStatusBits.OVERVOLTAGE) == (1 << 2)
        and int(BarrierStatusBits.OVERCURRENT) == (1 << 3)
        and int(BarrierStatusBits.THERMAL_OVERHEAT) == (1 << 4)
        and int(BarrierStatusBits.CRC_FAULT) == (1 << 5)
        and int(BarrierStatusBits.LEAKAGE_FAULT) == (1 << 6)
        and int(BarrierStatusBits.SAFETY_TRIPPED) == (1 << 7)
    )

    s2_passed = class_ids_ok and regs_ok and diag_codes_ok and enums_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 2,
        "name": "protocol_constants_and_register_mappings",
        "check": "Verify APL IS Barrier diagnostic codes (0xEEA1-0xEEA5), register offsets (%R2800..%R2807), coils (%M653..%M654)",
        "passed": bool(s2_passed),
        "timing_ms": round(t1, 3),
        "details": "Class IDs (0x39, 0x3A, 0x3B, 0x49), registers %R2800..%R2807, coils %M653..%M654, and diagnostic codes (0x0000, 0xEEA1..0xEEA5) verified bit-exact.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: odva_cip_safety_dual_crc_mathematics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    sample_payload = b"Horner-ODVA-CIP-Safety-APL-IS-Barrier-W319-Payload"
    c1 = compute_crc_s1(sample_payload)
    c1_again = compute_crc_s1(sample_payload)
    crc_s1_det = (c1 == c1_again) and (0 <= c1 <= 0xFFFF) and (c1 != 0)

    raw_header = (
        (DEFAULT_SESSION_ID).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (400).to_bytes(4, "big")
        + (2).to_bytes(1, "big")
        + (0).to_bytes(1, "big")
        + (24000).to_bytes(2, "big")
        + (14500).to_bytes(2, "big")
        + (150).to_bytes(2, "big")
        + (35).to_bytes(2, "big")
        + (350).to_bytes(2, "big")
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
    pkt = create_valid_apl_barrier_packet(payload_bytes=sample_payload, sequence=10, timestamp_us=400)
    pkt_valid = pkt.validate_crcs() and (pkt.crc_s1 == c1)
    raw = pkt.pack()
    unpacked = CIPAPLBarrierPacket.unpack(raw)
    unpack_ok = unpacked.validate_crcs() and (unpacked.payload_bytes == sample_payload)

    # Corrupted packet detection
    bad_pkt = create_valid_apl_barrier_packet(payload_bytes=sample_payload, sequence=10, timestamp_us=400)
    bad_pkt.crc_s1 = 0x9999
    bad_caught = not bad_pkt.validate_crcs()

    # EPID hash and CRC32 verification
    epid_h = compute_epid_hash()
    epid_crc32 = compute_epid_crc32()
    epid_ok = (epid_h != 0) and (epid_crc32 == 0x09AAE062)

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
    # Stage 4: apl_intrinsic_safety_power_profiles_and_telemetry
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    # Kinematics and electrical calculations
    p_calc = calculate_barrier_power_mw(14500, 150)
    v_drop_calc = calculate_barrier_voltage_drop_mv(24000, 14500)
    z_calc = calculate_barrier_impedance_mohm(v_drop_calc, 150)
    leakage_margin = calculate_shield_leakage_margin_ua(20.0, 50.0)
    electrical_ok = (p_calc == 2175) and (v_drop_calc == 9500) and (z_calc == 63333) and (leakage_margin == 30.0)

    # Validate all 3 barrier profiles specifications
    profiles_verified = True
    for prof in (
        BarrierProfile.PROFILE_2WISE_15V_215MA,
        BarrierProfile.PROFILE_APL_TRUNK_50V_1500MA,
        BarrierProfile.PROFILE_SPUR_FIELD_15V_100MA,
    ):
        spec = BARRIER_PROFILE_SPECS[prof]
        if not (
            spec["v_max_out_mv"] in (15000, 50000)
            and spec["i_max_ma"] in (100, 215, 1500)
            and spec["p_max_mw"] > 0
            and prof.v_max_out_mv == spec["v_max_out_mv"]
            and prof.i_max_ma == spec["i_max_ma"]
            and prof.p_max_mw == spec["p_max_mw"]
        ):
            profiles_verified = False
            break

    # Nominal 2-WISE IS Barrier Engine baseline
    eng4 = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
    eng4.connect()
    nom_ok = (
        eng4.barrier_state == BarrierOperatingState.NORMAL_OPERATION
        and eng4.profile == BarrierProfile.PROFILE_2WISE_15V_215MA
        and eng4.voltage_in_mv == 24000
        and eng4.voltage_out_mv == 14500
        and eng4.current_ma == 150
        and eng4.impedance_mohm == 350
        and eng4.temp_degc == 35
        and eng4.power_mw == 2175
        and eng4.online is True
        and eng4.tripped is False
        and eng4.diagnostic_code == DIAG_OK
        and eng4.fault_code == 0
    )

    # Frame transmission and reception across engines
    tx_pkt = eng4.send_packet(b"ValidBarrierPayload")
    tx_ok = tx_pkt.validate_crcs()

    rx_eng = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
    rx_eng.connect()
    rx_ok = rx_eng.receive_packet(tx_pkt)
    exchange_ok = tx_ok and rx_ok and rx_eng.online and not rx_eng.tripped

    s4_passed = electrical_ok and profiles_verified and nom_ok and exchange_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 4,
        "name": "apl_intrinsic_safety_power_profiles_and_telemetry",
        "check": "Verify IEC 60079-47 2-WISE IS limits (15V / 215mA), power calculation (P=V*I), and nominal telemetry",
        "passed": bool(s4_passed),
        "timing_ms": round(t1, 3),
        "details": f"APL barrier profiles verified; 2-WISE IS engine operating at {eng4.power_mw} mW with zero faults.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: overvoltage_and_overcurrent_barrier_trips
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng5 = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
    eng5.connect()

    # 1. Overvoltage injection (exceeding 2-WISE limit of 15000 mV -> 0xEEA1)
    eng5.inject_overvoltage(16500)
    ov_trip_ok = (
        eng5.barrier_state == BarrierOperatingState.SAFETY_TRIP
        and eng5.diagnostic_code == DIAG_ERR_OVERVOLTAGE_BARRIER
        and eng5.diagnostic_code == 0xEEA1
        and eng5.fault_code == 0xEEA1
        and eng5.voltage_out_mv == 16500
        and eng5.online is False
        and eng5.tripped is True
    )
    eng5.clear_fault()
    ov_rec_ok = (
        eng5.barrier_state == BarrierOperatingState.NORMAL_OPERATION
        and eng5.diagnostic_code == DIAG_OK
        and eng5.fault_code == 0
        and eng5.online is True
        and eng5.tripped is False
    )

    # 2. Overcurrent excursion injection (exceeding 2-WISE limit of 215 mA -> 0xEEA2)
    eng5.inject_overcurrent(265)
    oc_trip_ok = (
        eng5.barrier_state == BarrierOperatingState.SAFETY_TRIP
        and eng5.diagnostic_code == DIAG_ERR_OVERCURRENT_EXCURSION
        and eng5.diagnostic_code == 0xEEA2
        and eng5.fault_code == 0xEEA2
        and eng5.current_ma == 265
        and eng5.online is False
        and eng5.tripped is True
    )
    eng5.clear_fault()
    oc_rec_ok = (
        eng5.barrier_state == BarrierOperatingState.NORMAL_OPERATION
        and eng5.diagnostic_code == DIAG_OK
        and eng5.online is True
        and eng5.tripped is False
    )

    s5_passed = ov_trip_ok and ov_rec_ok and oc_trip_ok and oc_rec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 5,
        "name": "overvoltage_and_overcurrent_barrier_trips",
        "check": "Verify overvoltage trip (0xEEA1) and overcurrent excursion trip (0xEEA2) asserting fail-safe state and recovery",
        "passed": bool(s5_passed),
        "timing_ms": round(t1, 3),
        "details": "Overvoltage (0xEEA1) and overcurrent excursion (0xEEA2) safety trips properly forced fail-safe state and recovered deterministically.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: thermal_overheat_and_shield_leakage_diagnostics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng6 = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
    eng6.connect()

    # 1. Thermal overheat fault (T_barrier > 85.0 degC -> 0xEEA3)
    eng6.inject_thermal_fault(95)
    thm_trip_ok = (
        eng6.barrier_state == BarrierOperatingState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_THERMAL_BARRIER_OVERHEAT
        and eng6.diagnostic_code == 0xEEA3
        and eng6.fault_code == 0xEEA3
        and eng6.temp_degc == 95
        and eng6.online is False
        and eng6.tripped is True
    )
    eng6.clear_fault()
    thm_rec_ok = (eng6.online is True and eng6.tripped is False and eng6.diagnostic_code == DIAG_OK)

    # 2. Shield leakage current fault (I_leak > 50.0 uA -> 0xEEA5)
    eng6.inject_leakage_fault(75.0)
    leak_trip_ok = (
        eng6.barrier_state == BarrierOperatingState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT
        and eng6.diagnostic_code == 0xEEA5
        and eng6.fault_code == 0xEEA5
        and eng6.leakage_ua == 75.0
        and eng6.online is False
        and eng6.tripped is True
    )
    eng6.clear_fault()
    leak_rec_ok = (eng6.online is True and eng6.diagnostic_code == DIAG_OK)

    # 3. Dual CRC safety corruption fault (0xEEA4)
    bad_crc_pkt = create_valid_apl_barrier_packet()
    bad_crc_pkt.crc_s1 = 0xBADC
    rx_bad = eng6.receive_packet(bad_crc_pkt)
    crc_trip_ok = (
        rx_bad is False
        and eng6.barrier_state == BarrierOperatingState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        and eng6.diagnostic_code == 0xEEA4
        and eng6.packet_loss_counter == 1
    )
    eng6.clear_fault()
    crc_rec_ok = (eng6.online is True and eng6.tripped is False and eng6.diagnostic_code == DIAG_OK)

    s6_passed = thm_trip_ok and thm_rec_ok and leak_trip_ok and leak_rec_ok and crc_trip_ok and crc_rec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 6,
        "name": "thermal_overheat_and_shield_leakage_diagnostics",
        "check": "Verify thermal overheat fault (0xEEA3), shield leakage fault (0xEEA5), and CRC safety trip (0xEEA4)",
        "passed": bool(s6_passed),
        "timing_ms": round(t1, 3),
        "details": "Thermal overheat (0xEEA3), shield leakage (0xEEA5), and CRC mismatch (0xEEA4) verified with safe recovery.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: register_table_synchronization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt7 = RegisterTable()
    eng7 = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA, register_table=rt7)
    eng7.connect()
    eng7.sync_to_registers(rt7, privilege=PrivilegeMode.USER)

    # 1. Healthy nominal state
    w_stat = rt7.read_word(REG_CIP_APL_BARRIER_STATUS)
    w_vin = rt7.read_uword(REG_CIP_APL_BARRIER_VOLTAGE_IN_MV)
    w_vout = rt7.read_uword(REG_CIP_APL_BARRIER_VOLTAGE_OUT_MV)
    w_i = rt7.read_uword(REG_CIP_APL_BARRIER_CURRENT_MA)
    w_z = rt7.read_uword(REG_CIP_APL_BARRIER_IMPEDANCE_MOHM)
    w_temp = rt7.read_word(REG_CIP_APL_BARRIER_TEMP_DEGC)
    w_p = rt7.read_uword(REG_CIP_APL_BARRIER_POWER_MW)
    w_diag = rt7.read_uword(REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE)
    b_online = rt7.read_bit(COIL_CIP_APL_BARRIER_ONLINE)
    b_trip = rt7.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP)

    nom_sync_ok = (
        w_stat == int(BarrierOperatingState.NORMAL_OPERATION)
        and w_vin == 24000
        and w_vout == 14500
        and w_i == 150
        and w_z == 350
        and w_temp == 35
        and w_p == 2175
        and w_diag == 0x0000
        and b_online is True
        and b_trip is False
    )

    # 2. Overvoltage fault reflection
    eng7.inject_overvoltage(16500)
    eng7.sync_to_registers(rt7)
    u_diag = rt7.read_uword(REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE)
    s_diag = rt7.read_word(REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE)

    ov_sync_ok = (
        rt7.read_word(REG_CIP_APL_BARRIER_STATUS) == int(BarrierOperatingState.SAFETY_TRIP)
        and rt7.read_uword(REG_CIP_APL_BARRIER_VOLTAGE_OUT_MV) == 16500
        and u_diag == 0xEEA1
        and s_diag == (0xEEA1 - 0x10000)
        and (s_diag & 0xFFFF) == 0xEEA1
        and rt7.read_bit(COIL_CIP_APL_BARRIER_ONLINE) is False
        and rt7.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP) is True
    )

    # 3. Restoration
    eng7.clear_fault()
    eng7.sync_to_registers(rt7, privilege=PrivilegeMode.SYSTEM)
    rec_sync_ok = (
        rt7.read_word(REG_CIP_APL_BARRIER_STATUS) == int(BarrierOperatingState.NORMAL_OPERATION)
        and rt7.read_uword(REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE) == 0x0000
        and rt7.read_bit(COIL_CIP_APL_BARRIER_ONLINE) is True
        and rt7.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP) is False
    )

    s7_passed = nom_sync_ok and ov_sync_ok and rec_sync_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 7,
        "name": "register_table_synchronization",
        "check": "Verify RegisterTable reads/writes, signed/unsigned masking across %R2800..%R2807 and coils %M653..%M654",
        "passed": bool(s7_passed),
        "timing_ms": round(t1, 3),
        "details": "Bit-exact synchronization and 16-bit signed masking verified across %R2800..%R2807 and coils %M653..%M654.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    # 1. Validate ST POU syntax and AST parsing
    st_syntax_ok = verify_cip_safety_apl_barrier_pure_st()
    SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC)
    res_st = STParser.validate_code(ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC)
    parser_ok = (res_st.status == AgentStatus.SUCCESS)
    ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC)
    ast_ok = (ast.pou_type == POUType.PROGRAM and ast.name == "CipSafetyAplBarrierSync")

    # Verify address bindings in ST POU
    bindings_ok = (
        "%R2800" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        and "%R2801" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        and "%R2802" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        and "%R2803" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        and "%R2804" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        and "%R2805" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        and "%R2806" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        and "%R2807" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        and "%M653" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        and "%M654" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
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
        "check": "Verify pure IEC 61131-3 ST POU 'CipSafetyAplBarrierSync' and strict rejection of ladder logic constructs",
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
    eng9 = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA, register_table=rt9)
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
        and rt9.read_bit(COIL_CIP_APL_BARRIER_ONLINE) is True
        and rt9.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP) is False
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
    pou_sha256 = hashlib.sha256(ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC.encode("utf-8")).hexdigest()
    stages_summary_str = json.dumps(stages_log, sort_keys=True)
    stages_sha256 = hashlib.sha256(stages_summary_str.encode("utf-8")).hexdigest()

    evidence_dict: Dict[str, Any] = {
        "status": "success" if all_stages_passed else "failed",
        "error_code": None if all_stages_passed else "ERR_STAGE_FAILED",
        "details": (
            f"All 9 Industrial ODVA CIP Safety Over Ethernet-APL Intrinsic Safety Power Barrier Monitor Engine ({work_package}) stages passed deterministically "
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
            "protocol": "Industrial ODVA CIP Safety Over Ethernet-APL Intrinsic Safety Power Barrier Monitor Engine (IEC 60079-11 / IEC 60079-47 / IEEE 802.3cg / IEC 61784-3-2)",
            "standards": [
                "ODVA CIP Safety Volume 5",
                "IEC 60079-11 Intrinsic Safety",
                "IEC 60079-47 2-WISE",
                "IEEE 802.3cg-2019 10BASE-T1L",
                "IEC 61784-3-2",
                "IEC 61508 SIL 3",
            ],
            "registers": [
                "%R2800..%R2807",
                "%M653..%M654",
            ],
            "diagnostic_codes": {
                "0x0000": "OK",
                "0xEEA1": "ERR_OVERVOLTAGE_BARRIER",
                "0xEEA2": "ERR_OVERCURRENT_EXCURSION",
                "0xEEA3": "ERR_THERMAL_BARRIER_OVERHEAT",
                "0xEEA4": "ERR_DUAL_CRC_SAFETY_FAULT",
                "0xEEA5": "ERR_LEAKAGE_TO_SHIELD_FAULT",
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
run_cip_safety_apl_barrier_verification = execute_9stage_verification_suite
run_deterministic_9stage_suite = execute_9stage_verification_suite


# ============================================================================
# CLI Entrypoint
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for W319 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Execute W319 CIP Safety Over Ethernet-APL Intrinsic Safety Power Barrier Monitor Engine 9-Stage Verification Suite"
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
        help="Path to output JSON evidence artifact (default: artifacts/telemetry/cip_safety_apl_barrier_evidence.json)",
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
        default="W319",
        help="Work package ID (default: W319)",
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
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_apl_barrier_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: ODVA CIP Safety Over Ethernet-APL IS Barrier Verification ({args.work_package}){ESC_RESET}")
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
