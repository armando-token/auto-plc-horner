#!/usr/bin/env python3
"""Deterministic 9-Stage Verification Runner for Industrial ODVA CIP Safety Over SPE Power-over-Data-Line (PoDL) Fault Engine (W316).

Work Package: W316 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [ODVA CIP Safety Over SPE Single-Pair Ethernet PoDL Fault Engine]
Status Contract: Strict 4-State JSON output (success | failed | blocked | inconclusive) & evidence emission.

Standards & Specifications:
- IEEE 802.3cg-2019 / IEEE 802.3bu-2016 Single Pair Ethernet (10BASE-T1L / 10BASE-T1S):
  - Point-to-point reach up to 1,000 meters (1 km) over single balanced twisted-pair cabling.
  - Clause 104 Power over Data Lines (PoDL / SPoE) PSE Power Classes (Classes 10 to 15):
    - CLASS_10: 12V / 0.46A (max 460 mA, nominal 5.52W, V_min 10000 mV)
    - CLASS_11: 12V / 0.83A (max 830 mA, nominal 9.96W, V_min 10000 mV)
    - CLASS_12: 24V / 0.46A (max 460 mA, nominal 11.04W, V_min 20000 mV)
    - CLASS_13: 24V / 0.92A (max 920 mA, nominal 22.08W, V_min 20000 mV)
    - CLASS_14: 48V / 0.63A (max 630 mA, nominal 30.24W, V_min 40000 mV)
    - CLASS_15: 48V / 1.36A (max 1360 mA, nominal 65.28W, V_min 40000 mV)
  - PoDL Operational State Machine:
    0: SLEEP (Unpowered / sleep mode)
    1: DETECTION (Probing signature resistance)
    2: CLASSIFICATION (SCCP power class negotiation)
    3: POWERED_NORMAL (Normal powered delivery & active CIP Safety data)
    4: FAULT_LOCKOUT (Latched fault lockout)
    5: SAFETY_TRIP (Safety trip state; safe de-energization asserted)
  - Serial Communication Classification Protocol (SCCP):
    - Heartbeat interval: 400 us nominal.
    - Frame loss watchdog timeout: 1000 us (DIAG_ERR_PSE_COMMUNICATION_TIMEOUT 0xEE95).
- ODVA CIP Networks Library Volume 5: CIP Safety Specification:
  - Class 0x39: Safety Supervisor Object
  - Class 0x3A: Safety Validator Object
  - Class 0x3B: Safety Connection Object
  - Class 0x48: Single-Pair Ethernet PoDL Safety Extension Object
  - Dual 16-bit Safety CRCs (IEC 61784-3-2 / IEC 61508 SIL 3):
    - CRC-S1: Generator polynomial 0x5935 (init 0x0000) over process data payload.
    - CRC-S2: Generator polynomial 0x755B (init 0x0000) over inverted header fields.
  - Rolling 16-bit sequence counter (0..65535).
  - Electronic Product ID (EPID) CRC32 ("HORNER-OCS-SPE-PODL-SIL3").
- Diagnostics & Watchdogs (%R2775, %R2777):
  - 0x0000: DIAG_OK (Nominal healthy operation)
  - 0xEE91: DIAG_ERR_OVERCURRENT_FAULT (I > I_max_mA for PSE Class)
  - 0xEE92: DIAG_ERR_UNDERVOLTAGE_FAULT (V < V_min_mV)
  - 0xEE93: DIAG_ERR_GROUND_LOOP_FAULT (R_loop > limit or leakage detected)
  - 0xEE94: DIAG_ERR_DUAL_CRC_SAFETY_FAULT (CRC-S1 or CRC-S2 mismatch)
  - 0xEE95: DIAG_ERR_PSE_COMMUNICATION_TIMEOUT (Serial SCCP frame loss > 1000 us)
- Horner OCS Memory Space:
  - Analog registers %R2770..%R2777:
    - %R2770: REG_CIP_PODL_STATUS (PoDL state: 0=SLEEP, 1=DETECTION, 2=CLASS, 3=POWERED, 4=LOCKOUT, 5=TRIP)
    - %R2771: REG_CIP_PODL_VOLTAGE_MV (Bus voltage in mV)
    - %R2772: REG_CIP_PODL_CURRENT_MA (Delivery current in mA)
    - %R2773: REG_CIP_PODL_LOOP_RESISTANCE_MOHM (Loop resistance in mOhm)
    - %R2774: REG_CIP_PODL_POWER_MW (Power in mW)
    - %R2775: REG_CIP_PODL_FAULT_CODE (PoDL fault code)
    - %R2776: REG_CIP_PODL_PSE_CLASS (PSE class: 10..15)
    - %R2777: REG_CIP_PODL_DIAGNOSTIC_CODE (Diagnostic code: 0x0000, 0xEE91..0xEE95)
  - Discrete coils %M646..%M647:
    - %M646: COIL_CIP_PODL_ONLINE (BOOL, True when PoDL is healthy and operational)
    - %M647: COIL_CIP_PODL_SAFETY_TRIP (BOOL, True on safety trip or fault lockout)
- Implements ILogicUnit interface with scan_step(dt, context), step(), execute(), reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.USER/SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'CipSafetyPodlFaultSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.

Deterministic 9-Stage Verification Sequence:
  Stage 1: environment
  Stage 2: protocol_constants_and_register_mappings
  Stage 3: odva_cip_safety_dual_crc_mathematics
  Stage 4: spe_podl_power_classification_and_telemetry
  Stage 5: overcurrent_and_undervoltage_fault_trips
  Stage 6: ground_loop_and_sccp_timeout_diagnostics
  Stage 7: register_table_synchronization
  Stage 8: pure_st_pou_and_anti_ladder_rejection
  Stage 9: simulation_soak_100_cycles_and_evidence_emission

Generates:
  artifacts/telemetry/cip_safety_podl_fault_evidence.json
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
from jev_cscape.telemetry.cip_safety_podl_fault import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_PODL_CLASS_ID,
    REG_CIP_PODL_STATUS,
    REG_CIP_PODL_VOLTAGE_MV,
    REG_CIP_PODL_CURRENT_MA,
    REG_CIP_PODL_LOOP_RESISTANCE_MOHM,
    REG_CIP_PODL_POWER_MW,
    REG_CIP_PODL_FAULT_CODE,
    REG_CIP_PODL_PSE_CLASS,
    REG_CIP_PODL_DIAGNOSTIC_CODE,
    COIL_CIP_PODL_ONLINE,
    COIL_CIP_PODL_SAFETY_TRIP,
    DIAG_OK,
    DIAG_ERR_OVERCURRENT_FAULT,
    DIAG_ERR_UNDERVOLTAGE_FAULT,
    DIAG_ERR_GROUND_LOOP_FAULT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_ERR_PSE_COMMUNICATION_TIMEOUT,
    DiagnosticCode,
    PoDLPSEClass,
    PoDLState,
    PoDLStatusBits,
    PSE_CLASS_SPECS,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    DEFAULT_SAFETY_EPID,
    DEFAULT_SESSION_ID,
    compute_crc_s1,
    compute_crc_s2,
    compute_epid_hash,
    compute_epid_crc32,
    CIPPoDLSafetyEngine,
    CIPPoDLPacket,
    create_valid_podl_packet,
    ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC,
    verify_cip_safety_podl_fault_pure_st,
)


# ============================================================================
# SPE PoDL Electrical Kinematics & Physics Calculation Helpers
# ============================================================================

def calculate_podl_power_mw(voltage_mv: int, current_ma: int) -> int:
    """Compute PoDL active power delivery in milliwatts: P = (V_mV * I_mA) / 1000."""
    return int((int(voltage_mv) * int(current_ma)) // 1000)


def calculate_loop_voltage_drop_mv(current_ma: int, loop_mohm: int) -> int:
    """Compute DC resistive voltage drop across twisted pair loop: V_drop = (I_mA * R_mOhm) / 1000."""
    return int((int(current_ma) * int(loop_mohm)) // 1000)


def calculate_sccp_frame_loss_margin_us(
    sccp_interval_us: float = 400.0,
    timeout_threshold_us: float = 1000.0,
) -> float:
    """Compute SCCP watchdog safety margin in microseconds before fault trip."""
    return float(timeout_threshold_us - sccp_interval_us)


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
    work_package: str = "W316",
    quick: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W316 CIP Safety Over SPE PoDL Fault Engine.

    Stages:
      Stage 1: environment
      Stage 2: protocol_constants_and_register_mappings
      Stage 3: odva_cip_safety_dual_crc_mathematics
      Stage 4: spe_podl_power_classification_and_telemetry
      Stage 5: overcurrent_and_undervoltage_fault_trips
      Stage 6: ground_loop_and_sccp_timeout_diagnostics
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
        from jev_cscape.telemetry.cip_safety_podl_fault import (
            CIPPoDLSafetyEngine,
            CIPPoDLPacket,
            PoDLState,
            PoDLPSEClass,
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
        and CIP_SAFETY_PODL_CLASS_ID == 0x48
    )

    regs_ok = (
        REG_CIP_PODL_STATUS == "%R2770"
        and REG_CIP_PODL_VOLTAGE_MV == "%R2771"
        and REG_CIP_PODL_CURRENT_MA == "%R2772"
        and REG_CIP_PODL_LOOP_RESISTANCE_MOHM == "%R2773"
        and REG_CIP_PODL_POWER_MW == "%R2774"
        and REG_CIP_PODL_FAULT_CODE == "%R2775"
        and REG_CIP_PODL_PSE_CLASS == "%R2776"
        and REG_CIP_PODL_DIAGNOSTIC_CODE == "%R2777"
        and COIL_CIP_PODL_ONLINE == "%M646"
        and COIL_CIP_PODL_SAFETY_TRIP == "%M647"
    )

    diag_codes_ok = (
        int(DIAG_OK) == 0x0000
        and int(DIAG_ERR_OVERCURRENT_FAULT) == 0xEE91
        and int(DIAG_ERR_UNDERVOLTAGE_FAULT) == 0xEE92
        and int(DIAG_ERR_GROUND_LOOP_FAULT) == 0xEE93
        and int(DIAG_ERR_DUAL_CRC_SAFETY_FAULT) == 0xEE94
        and int(DIAG_ERR_PSE_COMMUNICATION_TIMEOUT) == 0xEE95
        # Signed 16-bit equality tests
        and DIAG_ERR_OVERCURRENT_FAULT == (0xEE91 - 0x10000)
        and (DIAG_ERR_OVERCURRENT_FAULT & 0xFFFF) == 0xEE91
        and DIAG_ERR_UNDERVOLTAGE_FAULT == (0xEE92 - 0x10000)
        and (DIAG_ERR_UNDERVOLTAGE_FAULT & 0xFFFF) == 0xEE92
        and DIAG_ERR_GROUND_LOOP_FAULT == (0xEE93 - 0x10000)
        and (DIAG_ERR_GROUND_LOOP_FAULT & 0xFFFF) == 0xEE93
        and DIAG_ERR_DUAL_CRC_SAFETY_FAULT == (0xEE94 - 0x10000)
        and (DIAG_ERR_DUAL_CRC_SAFETY_FAULT & 0xFFFF) == 0xEE94
        and DIAG_ERR_PSE_COMMUNICATION_TIMEOUT == (0xEE95 - 0x10000)
        and (DIAG_ERR_PSE_COMMUNICATION_TIMEOUT & 0xFFFF) == 0xEE95
    )

    enums_ok = (
        int(PoDLPSEClass.CLASS_10) == 10
        and int(PoDLPSEClass.CLASS_11) == 11
        and int(PoDLPSEClass.CLASS_12) == 12
        and int(PoDLPSEClass.CLASS_13) == 13
        and int(PoDLPSEClass.CLASS_14) == 14
        and int(PoDLPSEClass.CLASS_15) == 15
        and int(PoDLState.SLEEP) == 0
        and int(PoDLState.DETECTION) == 1
        and int(PoDLState.CLASSIFICATION) == 2
        and int(PoDLState.POWERED_NORMAL) == 3
        and int(PoDLState.FAULT_LOCKOUT) == 4
        and int(PoDLState.SAFETY_TRIP) == 5
        and int(PoDLStatusBits.ONLINE) == (1 << 0)
        and int(PoDLStatusBits.POWERED) == (1 << 1)
        and int(PoDLStatusBits.OVERCURRENT) == (1 << 2)
        and int(PoDLStatusBits.UNDERVOLTAGE) == (1 << 3)
        and int(PoDLStatusBits.GROUND_FAULT) == (1 << 4)
        and int(PoDLStatusBits.CRC_FAULT) == (1 << 5)
        and int(PoDLStatusBits.TIMEOUT) == (1 << 6)
        and int(PoDLStatusBits.SAFETY_TRIPPED) == (1 << 7)
    )

    s2_passed = class_ids_ok and regs_ok and diag_codes_ok and enums_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 2,
        "name": "protocol_constants_and_register_mappings",
        "check": "Verify PoDL diagnostic codes (0xEE91-0xEE95), register offsets (%R2770..%R2777), coils (%M646..%M647)",
        "passed": bool(s2_passed),
        "timing_ms": round(t1, 3),
        "details": "Class IDs (0x39, 0x3A, 0x3B, 0x48), registers %R2770..%R2777, coils %M646..%M647, and diagnostic codes (0x0000, 0xEE91..0xEE95) verified bit-exact.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: odva_cip_safety_dual_crc_mathematics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    sample_payload = b"Horner-ODVA-CIP-Safety-SPE-PoDL-Fault-W316-Payload"
    c1 = compute_crc_s1(sample_payload)
    c1_again = compute_crc_s1(sample_payload)
    crc_s1_det = (c1 == c1_again) and (0 <= c1 <= 0xFFFF) and (c1 != 0)

    raw_header = (
        (DEFAULT_SESSION_ID).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (400).to_bytes(4, "big")
        + (3).to_bytes(1, "big")
        + (12).to_bytes(1, "big")
        + (24000).to_bytes(2, "big")
        + (350).to_bytes(2, "big")
        + (1850).to_bytes(2, "big")
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
    pkt = create_valid_podl_packet(payload_bytes=sample_payload, sequence=10, timestamp_us=400)
    pkt_valid = pkt.validate_crcs() and (pkt.crc_s1 == c1)
    raw = pkt.pack()
    unpacked = CIPPoDLPacket.unpack(raw)
    unpack_ok = unpacked.validate_crcs() and (unpacked.payload_bytes == sample_payload)

    # Corrupted packet detection
    bad_pkt = create_valid_podl_packet(payload_bytes=sample_payload, sequence=10, timestamp_us=400)
    bad_pkt.crc_s1 = 0x9999
    bad_caught = not bad_pkt.validate_crcs()

    # EPID hash and CRC32 verification
    epid_h = compute_epid_hash()
    epid_crc32 = compute_epid_crc32()
    epid_ok = (epid_h != 0) and (epid_crc32 == 0x0E7CC1A9)

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
    # Stage 4: spe_podl_power_classification_and_telemetry
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    # Kinematics and electrical calculations
    p_calc = calculate_podl_power_mw(24000, 350)
    v_drop_calc = calculate_loop_voltage_drop_mv(350, 1850)
    sccp_margin_us = calculate_sccp_frame_loss_margin_us(400.0, 1000.0)
    electrical_ok = (p_calc == 8400) and (v_drop_calc == 647) and (sccp_margin_us == 600.0)

    # Validate all 6 PSE power classes specifications
    classes_verified = True
    for pse_cls in (
        PoDLPSEClass.CLASS_10,
        PoDLPSEClass.CLASS_11,
        PoDLPSEClass.CLASS_12,
        PoDLPSEClass.CLASS_13,
        PoDLPSEClass.CLASS_14,
        PoDLPSEClass.CLASS_15,
    ):
        spec = PSE_CLASS_SPECS[pse_cls]
        if not (
            spec["v_nominal_mv"] in (12000, 24000, 48000)
            and spec["i_max_ma"] in (460, 630, 830, 920, 1360)
            and spec["p_max_mw"] > 0
            and pse_cls.v_nominal_mv == spec["v_nominal_mv"]
            and pse_cls.i_max_ma == spec["i_max_ma"]
            and pse_cls.p_max_mw == spec["p_max_mw"]
        ):
            classes_verified = False
            break

    # Nominal PoDL Powered Normal Engine baseline
    eng4 = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12)
    eng4.connect()
    nom_ok = (
        eng4.podl_state == PoDLState.POWERED_NORMAL
        and eng4.pse_class == PoDLPSEClass.CLASS_12
        and eng4.voltage_mv == 24000
        and eng4.current_ma == 350
        and eng4.loop_mohm == 1850
        and eng4.power_mw == 8400
        and eng4.online is True
        and eng4.tripped is False
        and eng4.diagnostic_code == DIAG_OK
        and eng4.fault_code == 0
    )

    # Frame transmission and reception across engines
    tx_pkt = eng4.send_packet(b"ValidPoDLPayload")
    tx_ok = tx_pkt.validate_crcs()

    rx_eng = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12)
    rx_eng.connect()
    rx_ok = rx_eng.receive_packet(tx_pkt)
    exchange_ok = tx_ok and rx_ok and rx_eng.online and (rx_eng.sccp_timer_us == 0.0)

    s4_passed = electrical_ok and classes_verified and nom_ok and exchange_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 4,
        "name": "spe_podl_power_classification_and_telemetry",
        "check": "Verify IEEE 802.3cg/bu PoDL PSE Classes 10-15, power calculation (P=V*I), and nominal telemetry",
        "passed": bool(s4_passed),
        "timing_ms": round(t1, 3),
        "details": f"PoDL power classes 10-15 verified; Class 12 (24V/0.46A) nominal engine operating at {eng4.power_mw} mW with zero faults.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: overcurrent_and_undervoltage_fault_trips
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng5 = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12)
    eng5.connect()

    # 1. Overcurrent injection (exceeding Class 12 limit of 460 mA -> 0xEE91)
    eng5.inject_overcurrent(560)
    oc_trip_ok = (
        eng5.podl_state == PoDLState.SAFETY_TRIP
        and eng5.diagnostic_code == DIAG_ERR_OVERCURRENT_FAULT
        and eng5.diagnostic_code == 0xEE91
        and eng5.fault_code == 0xEE91
        and eng5.current_ma == 560
        and eng5.online is False
        and eng5.tripped is True
    )
    eng5.clear_fault()
    oc_rec_ok = (
        eng5.podl_state == PoDLState.POWERED_NORMAL
        and eng5.diagnostic_code == DIAG_OK
        and eng5.fault_code == 0
        and eng5.online is True
        and eng5.tripped is False
    )

    # 2. Undervoltage injection (collapsing below Class 12 min of 20000 mV -> 0xEE92)
    eng5.inject_undervoltage(18000)
    uv_trip_ok = (
        eng5.podl_state == PoDLState.SAFETY_TRIP
        and eng5.diagnostic_code == DIAG_ERR_UNDERVOLTAGE_FAULT
        and eng5.diagnostic_code == 0xEE92
        and eng5.fault_code == 0xEE92
        and eng5.voltage_mv == 18000
        and eng5.online is False
        and eng5.tripped is True
    )
    eng5.clear_fault()
    uv_rec_ok = (
        eng5.podl_state == PoDLState.POWERED_NORMAL
        and eng5.diagnostic_code == DIAG_OK
        and eng5.online is True
        and eng5.tripped is False
    )

    s5_passed = oc_trip_ok and oc_rec_ok and uv_trip_ok and uv_rec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 5,
        "name": "overcurrent_and_undervoltage_fault_trips",
        "check": "Verify overcurrent trip (0xEE91) and undervoltage trip (0xEE92) asserting fail-safe state and recovery",
        "passed": bool(s5_passed),
        "timing_ms": round(t1, 3),
        "details": "Overcurrent (0xEE91) and undervoltage (0xEE92) safety trips properly forced fail-safe state and recovered deterministically.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: ground_loop_and_sccp_timeout_diagnostics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng6 = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12)
    eng6.connect()

    # 1. Ground loop resistance fault (R_loop > 65000 mOhm -> 0xEE93)
    eng6.inject_ground_fault(75000)
    gnd_trip_ok = (
        eng6.podl_state == PoDLState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_GROUND_LOOP_FAULT
        and eng6.diagnostic_code == 0xEE93
        and eng6.fault_code == 0xEE93
        and eng6.loop_mohm == 75000
        and eng6.online is False
        and eng6.tripped is True
    )
    eng6.clear_fault()
    gnd_rec_ok = (eng6.online is True and eng6.tripped is False and eng6.diagnostic_code == DIAG_OK)

    # 2. SCCP frame loss communication timeout (> 1000 us -> 0xEE95)
    eng6.inject_sccp_timeout()
    sccp_trip_ok = (
        eng6.podl_state == PoDLState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_PSE_COMMUNICATION_TIMEOUT
        and eng6.diagnostic_code == 0xEE95
        and eng6.online is False
        and eng6.tripped is True
    )
    eng6.clear_fault()
    sccp_rec_ok = (eng6.online is True and eng6.diagnostic_code == DIAG_OK)

    # 3. Dual CRC safety corruption fault (0xEE94)
    bad_crc_pkt = create_valid_podl_packet()
    bad_crc_pkt.crc_s1 = 0xBADC
    rx_bad = eng6.receive_packet(bad_crc_pkt)
    crc_trip_ok = (
        rx_bad is False
        and eng6.podl_state == PoDLState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        and eng6.diagnostic_code == 0xEE94
        and eng6.packet_loss_counter == 1
    )
    eng6.clear_fault()
    crc_rec_ok = (eng6.online is True and eng6.tripped is False and eng6.diagnostic_code == DIAG_OK)

    s6_passed = gnd_trip_ok and gnd_rec_ok and sccp_trip_ok and sccp_rec_ok and crc_trip_ok and crc_rec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 6,
        "name": "ground_loop_and_sccp_timeout_diagnostics",
        "check": "Verify ground loop fault (0xEE93), SCCP frame loss timeout (0xEE95), and CRC safety trip (0xEE94)",
        "passed": bool(s6_passed),
        "timing_ms": round(t1, 3),
        "details": "Ground loop fault (0xEE93), SCCP timeout (0xEE95), and CRC mismatch (0xEE94) verified with safe recovery.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: register_table_synchronization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt7 = RegisterTable()
    eng7 = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12, register_table=rt7)
    eng7.connect()
    eng7.sync_to_registers(rt7, privilege=PrivilegeMode.USER)

    # 1. Healthy nominal state
    w_stat = rt7.read_word(REG_CIP_PODL_STATUS)
    w_v = rt7.read_uword(REG_CIP_PODL_VOLTAGE_MV)
    w_i = rt7.read_uword(REG_CIP_PODL_CURRENT_MA)
    w_loop = rt7.read_uword(REG_CIP_PODL_LOOP_RESISTANCE_MOHM)
    w_p = rt7.read_uword(REG_CIP_PODL_POWER_MW)
    w_flt = rt7.read_uword(REG_CIP_PODL_FAULT_CODE)
    w_cls = rt7.read_uword(REG_CIP_PODL_PSE_CLASS)
    w_diag = rt7.read_uword(REG_CIP_PODL_DIAGNOSTIC_CODE)
    b_online = rt7.read_bit(COIL_CIP_PODL_ONLINE)
    b_trip = rt7.read_bit(COIL_CIP_PODL_SAFETY_TRIP)

    nom_sync_ok = (
        w_stat == int(PoDLState.POWERED_NORMAL)
        and w_v == 24000
        and w_i == 350
        and w_loop == 1850
        and w_p == 8400
        and w_flt == 0
        and w_cls == 12
        and w_diag == 0x0000
        and b_online is True
        and b_trip is False
    )

    # 2. Overcurrent fault reflection
    eng7.inject_overcurrent(600)
    eng7.sync_to_registers(rt7)
    u_diag = rt7.read_uword(REG_CIP_PODL_DIAGNOSTIC_CODE)
    s_diag = rt7.read_word(REG_CIP_PODL_DIAGNOSTIC_CODE)

    oc_sync_ok = (
        rt7.read_word(REG_CIP_PODL_STATUS) == int(PoDLState.SAFETY_TRIP)
        and rt7.read_uword(REG_CIP_PODL_CURRENT_MA) == 600
        and rt7.read_uword(REG_CIP_PODL_FAULT_CODE) == 0xEE91
        and u_diag == 0xEE91
        and s_diag == (0xEE91 - 0x10000)
        and (s_diag & 0xFFFF) == 0xEE91
        and rt7.read_bit(COIL_CIP_PODL_ONLINE) is False
        and rt7.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is True
    )

    # 3. Restoration
    eng7.clear_fault()
    eng7.sync_to_registers(rt7, privilege=PrivilegeMode.SYSTEM)
    rec_sync_ok = (
        rt7.read_word(REG_CIP_PODL_STATUS) == int(PoDLState.POWERED_NORMAL)
        and rt7.read_uword(REG_CIP_PODL_DIAGNOSTIC_CODE) == 0x0000
        and rt7.read_bit(COIL_CIP_PODL_ONLINE) is True
        and rt7.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is False
    )

    s7_passed = nom_sync_ok and oc_sync_ok and rec_sync_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 7,
        "name": "register_table_synchronization",
        "check": "Verify RegisterTable reads/writes, signed/unsigned masking across %R2770..%R2777 and coils %M646..%M647",
        "passed": bool(s7_passed),
        "timing_ms": round(t1, 3),
        "details": "Bit-exact synchronization and 16-bit signed masking verified across %R2770..%R2777 and coils %M646..%M647.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    # 1. Validate ST POU syntax and AST parsing
    st_syntax_ok = verify_cip_safety_podl_fault_pure_st()
    SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC)
    res_st = STParser.validate_code(ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC)
    parser_ok = (res_st.status == AgentStatus.SUCCESS)
    ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC)
    ast_ok = (ast.pou_type == POUType.PROGRAM and ast.name == "CipSafetyPodlFaultSync")

    # Verify address bindings in ST POU
    bindings_ok = (
        "%R2770" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        and "%R2771" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        and "%R2772" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        and "%R2773" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        and "%R2774" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        and "%R2775" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        and "%R2776" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        and "%R2777" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        and "%M646" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        and "%M647" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
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
        "check": "Verify pure IEC 61131-3 ST POU 'CipSafetyPodlFaultSync' and strict rejection of ladder logic constructs",
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
    eng9 = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12, register_table=rt9)
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
        and rt9.read_bit(COIL_CIP_PODL_ONLINE) is True
        and rt9.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is False
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
    pou_sha256 = hashlib.sha256(ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC.encode("utf-8")).hexdigest()
    stages_summary_str = json.dumps(stages_log, sort_keys=True)
    stages_sha256 = hashlib.sha256(stages_summary_str.encode("utf-8")).hexdigest()

    evidence_dict: Dict[str, Any] = {
        "status": "success" if all_stages_passed else "failed",
        "error_code": None if all_stages_passed else "ERR_STAGE_FAILED",
        "details": (
            f"All 9 Industrial ODVA CIP Safety Over SPE Single-Pair Ethernet PoDL Fault Engine ({work_package}) stages passed deterministically "
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
            "protocol": "Industrial ODVA CIP Safety Over SPE Single-Pair Ethernet Power-over-Data-Line (PoDL) Fault Engine (IEEE 802.3cg / IEEE 802.3bu / IEC 61784-3-2)",
            "standards": [
                "ODVA CIP Safety Volume 5",
                "IEEE 802.3cg-2019 10BASE-T1L",
                "IEEE 802.3bu PoDL / Clause 104 SPoE",
                "IEC 61784-3-2",
                "IEC 61508 SIL 3",
            ],
            "registers": [
                "%R2770..%R2777",
                "%M646..%M647",
            ],
            "diagnostic_codes": {
                "0x0000": "OK",
                "0xEE91": "ERR_OVERCURRENT_FAULT",
                "0xEE92": "ERR_UNDERVOLTAGE_FAULT",
                "0xEE93": "ERR_GROUND_LOOP_FAULT",
                "0xEE94": "ERR_DUAL_CRC_SAFETY_FAULT",
                "0xEE95": "ERR_PSE_COMMUNICATION_TIMEOUT",
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
run_cip_safety_podl_fault_verification = execute_9stage_verification_suite
run_deterministic_9stage_suite = execute_9stage_verification_suite


# ============================================================================
# CLI Entrypoint
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for W316 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Execute W316 CIP Safety Over SPE Single-Pair Ethernet PoDL Fault Engine 9-Stage Verification Suite"
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
        help="Path to output JSON evidence artifact (default: artifacts/telemetry/cip_safety_podl_fault_evidence.json)",
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
        default="W316",
        help="Work package ID (default: W316)",
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
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_podl_fault_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: ODVA CIP Safety Over SPE PoDL Fault Verification ({args.work_package}){ESC_RESET}")
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
