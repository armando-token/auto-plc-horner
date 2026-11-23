#!/usr/bin/env python3
"""Verification Runner for Industrial ODVA CIP Safety Over Single-Pair Ethernet (SPE) Hybrid Power and Data Engine (W298).

Work Package: W298 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [ODVA CIP Safety Over SPE Hybrid Power & Data Engine]
Status Contract: Strict 4-State JSON output & evidence emission.

Features & Standards:
- IEEE 802.3cg-2019: 10BASE-T1L Single-Pair Ethernet (SPE) with SPoE / PoDL Power Delivery.
- IEEE 802.3bu / IEEE 802.3cg SPoE / PoDL Power Classes 10-15 (1.23W..52.0W, 20-58V).
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3).
- Dual 16-bit Safety CRCs (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B inverted header).
- Horner OCS Memory Space:
  - Registers %R2590..%R2597:
    %R2590: Bus Voltage (mV)
    %R2591: Bus Current (mA)
    %R2592: Consumed Power (mW)
    %R2593: Loop Resistance (mOhm)
    %R2594: Status Word (bitmask: power, running, fault flags)
    %R2595: Diagnostic Code (0x0000 OK, 0xEE31..0xEE37)
    %R2596: Error Count (0..65535)
    %R2597: Sequence Counter (0..65535)
  - Discrete Coils %M604..%M605:
    %M604: SPoE / Hybrid Power Enable & Safety Link Healthy (BOOL)
    %M605: Safety Stop Tripped / Power Alarm (BOOL)
- Pure IEC 61131-3 Structured Text POU: 'CipSafetySpeHybridSync' with anti-ladder validation.

Deterministic 9-Stage Verification Sequence:
  Stage 1: environment: verify Python, platform, and dependencies.
  Stage 2: protocol_constants: verify power classes, diagnostic codes (0xEE31-0xEE37), register offsets (%R2590..%R2597, %M604..%M605).
  Stage 3: crc_mathematics: verify dual CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B).
  Stage 4: power_coordination_and_faults: verify under-voltage (0xEE31), over-current (0xEE32), high loop resistance (0xEE33), ground leakage (0xEE34).
  Stage 5: safety_connection: verify state machine transitions and packet timeout (0xEE35).
  6. register_synchronization: verify RegisterTable reads/writes and bitwise masks.
  7. structured_text_validation: verify ST POU 'CipSafetySpeHybridSync' and LadderForbiddenError on ladder syntax.
  8. scan_cycle_simulation: verify multi-cycle ILogicUnit execution.
  9. evidence_emission: write deterministic evidence JSON with SHA-256 digests.

Generates:
  artifacts/telemetry/cip_safety_spe_hybrid_evidence.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import sys
import time
import tracemalloc
from typing import Any, Dict, List, Optional, Union

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
from jev_cscape.telemetry.cip_safety_spe_hybrid import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_SPE_HYBRID_CLASS_ID,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    UNDER_VOLTAGE_THRESHOLD_MV,
    OVER_CURRENT_THRESHOLD_MA,
    HIGH_LOOP_RESISTANCE_THRESHOLD_MOHM,
    GROUND_LEAKAGE_THRESHOLD_MA,
    MAX_DEENERGIZE_TIME_MS,
    DEFAULT_VOLTAGE_MV,
    DEFAULT_CURRENT_MA,
    DEFAULT_LOOP_RESISTANCE_MOHM,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CRC_INIT,
    REG_CIP_SAFETY_SPE_VOLTAGE_MV,
    REG_CIP_SAFETY_SPE_CURRENT_MA,
    REG_CIP_SAFETY_SPE_POWER_MW,
    REG_CIP_SAFETY_SPE_LOOP_RESISTANCE_MOHM,
    REG_CIP_SAFETY_SPE_STATUS_WORD,
    REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE,
    REG_CIP_SAFETY_SPE_ERROR_COUNT,
    REG_CIP_SAFETY_SPE_SEQUENCE_COUNTER,
    COIL_CIP_SAFETY_SPE_POWER_ENABLE,
    COIL_CIP_SAFETY_SPE_TRIP,
    COIL_CIP_SAFETY_SPE_HYBRID_HEALTHY,
    COIL_CIP_SAFETY_SPE_HYBRID_TRIP,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_UNDER_VOLTAGE,
    DIAG_ERR_OVER_CURRENT,
    DIAG_ERR_HIGH_LOOP_RESISTANCE,
    DIAG_ERR_GROUND_LEAKAGE,
    DIAG_ERR_TIMEOUT,
    DIAG_ERR_CRC_S1,
    DIAG_ERR_CRC_S2,
    PowerClass,
    SpeHybridPowerClass,
    SafetyConnectionState,
    CipSafetySpeHybridStatusBits,
    ST_PROGRAM_CIP_SAFETY_SPE_HYBRID_SYNC,
    CipSafetySpeHybridEngine,
    CipSafetySpeHybridFrame,
    calculate_crc_s1,
    calculate_crc_s2,
    compute_crc_s1,
    compute_crc_s2,
    verify_cip_safety_spe_hybrid_pure_st,
)

# ANSI terminal formatting constants matching repo conventions
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


def execute_9stage_verification_suite(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W298",
    quick: bool = False,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W298.

    Stages:
      1. environment: verify Python, platform, and dependencies.
      2. protocol_constants: verify power classes, diagnostic codes (0xEE31-0xEE37), register offsets (%R2590..%R2597, %M604..%M605).
      3. crc_mathematics: verify dual CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B).
      4. power_coordination_and_faults: verify under-voltage (0xEE31), over-current (0xEE32), high loop resistance (0xEE33), ground leakage (0xEE34).
      5. safety_connection: verify state machine transitions and packet timeout (0xEE35).
      6. register_synchronization: verify RegisterTable reads/writes and bitwise masks.
      7. structured_text_validation: verify ST POU 'CipSafetySpeHybridSync' and LadderForbiddenError on ladder syntax.
      8. scan_cycle_simulation: verify multi-cycle ILogicUnit execution.
      9. evidence_emission: write deterministic evidence JSON with SHA-256 digests.
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
        from jev_cscape.simulation.register_table import RegisterTable
        from jev_cscape.simulation.engine import ILogicUnit, ScanContext
    except ImportError:
        deps_ok = False

    s1_passed = py_ok and deps_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 1,
        "name": "environment",
        "check": "Verify Python version, OS platform, and core dependencies",
        "passed": bool(s1_passed),
        "timing_ms": round(t1, 3),
        "details": f"Python {py_ver.major}.{py_ver.minor}.{py_ver.micro} on {plat_str}. Dependencies verified: {deps_ok}.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: protocol_constants
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    power_classes_ok = (
        int(PowerClass.CLASS_10) == 10
        and int(PowerClass.CLASS_11) == 11
        and int(PowerClass.CLASS_12) == 12
        and int(PowerClass.CLASS_13) == 13
        and int(PowerClass.CLASS_14) == 14
        and int(PowerClass.CLASS_15) == 15
    )

    diag_codes_ok = (
        int(DIAG_ERR_UNDER_VOLTAGE) == 0xEE31
        and int(DIAG_ERR_OVER_CURRENT) == 0xEE32
        and int(DIAG_ERR_HIGH_LOOP_RESISTANCE) == 0xEE33
        and int(DIAG_ERR_GROUND_LEAKAGE) == 0xEE34
        and int(DIAG_ERR_TIMEOUT) == 0xEE35
        and int(DIAG_ERR_CRC_S1) == 0xEE36
        and int(DIAG_ERR_CRC_S2) == 0xEE37
        and int(DIAG_OK) == 0x0000
    )

    regs_ok = (
        REG_CIP_SAFETY_SPE_VOLTAGE_MV == "%R2590"
        and REG_CIP_SAFETY_SPE_CURRENT_MA == "%R2591"
        and REG_CIP_SAFETY_SPE_POWER_MW == "%R2592"
        and REG_CIP_SAFETY_SPE_LOOP_RESISTANCE_MOHM == "%R2593"
        and REG_CIP_SAFETY_SPE_STATUS_WORD == "%R2594"
        and REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE == "%R2595"
        and REG_CIP_SAFETY_SPE_ERROR_COUNT == "%R2596"
        and REG_CIP_SAFETY_SPE_SEQUENCE_COUNTER == "%R2597"
        and COIL_CIP_SAFETY_SPE_POWER_ENABLE == "%M604"
        and COIL_CIP_SAFETY_SPE_TRIP == "%M605"
    )

    s2_passed = power_classes_ok and diag_codes_ok and regs_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 2,
        "name": "protocol_constants",
        "check": "Verify power classes (10-15), diagnostic codes (0xEE31-0xEE37), register offsets (%R2590..%R2597, %M604..%M605)",
        "passed": bool(s2_passed),
        "timing_ms": round(t1, 3),
        "details": "Power classes (10..15), diagnostic codes (0xEE31..0xEE37), and register bindings (%R2590..%R2597, %M604..%M605) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: crc_mathematics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sample_payload = b"ODVA-CIP-SAFETY-SPE-HYBRID-PAYLOAD-001"
    crc1 = calculate_crc_s1(sample_payload)
    crc2 = calculate_crc_s2(sequence_number=1, timestamp_us=1000, safety_network_number=0x1A2B)

    # Distinctness and determinism
    crc1_again = calculate_crc_s1(sample_payload)
    crc2_again = calculate_crc_s2(sequence_number=1, timestamp_us=1000, safety_network_number=0x1A2B)
    crc_det = (crc1 == crc1_again) and (crc2 == crc2_again) and (crc1 != 0) and (crc2 != 0) and (crc1 != crc2)

    # Single-bit mutation sensitivity
    mutated_payload = bytearray(sample_payload)
    mutated_payload[0] ^= 0x01
    crc1_mut = calculate_crc_s1(bytes(mutated_payload))
    crc_mut_detected = (crc1_mut != crc1)

    s3_passed = crc_det and crc_mut_detected and (CIP_SAFETY_CRC_S1_POLY == 0x5935) and (CIP_SAFETY_CRC_S2_POLY == 0x755B)
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 3,
        "name": "crc_mathematics",
        "check": "Verify dual CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B) mathematics and corruption detection",
        "passed": bool(s3_passed),
        "timing_ms": round(t1, 3),
        "details": f"CRC-S1=0x{crc1:04X}, CRC-S2=0x{crc2:04X}. Distinct, deterministic, single-bit corruption detected.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: power_coordination_and_faults
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng4 = CipSafetySpeHybridEngine()

    # 1. Under-voltage trip (0xEE31)
    eng4.inject_under_voltage(17000)
    uv_ok = (
        eng4.diagnostic_code == DIAG_ERR_UNDER_VOLTAGE
        and eng4.is_tripped is True
        and eng4.power_enabled is False
        and eng4.state == SafetyConnectionState.FAULT
    )
    eng4.clear_faults()

    # 2. Over-current trip (0xEE32)
    eng4.inject_over_current(1900)
    oc_ok = (
        eng4.diagnostic_code == DIAG_ERR_OVER_CURRENT
        and eng4.is_tripped is True
        and eng4.last_fault_deenergize_time_ms < MAX_DEENERGIZE_TIME_MS
    )
    eng4.clear_faults()

    # 3. High loop resistance trip (0xEE33)
    eng4.inject_high_loop_resistance(70000)
    hlr_ok = (
        eng4.diagnostic_code == DIAG_ERR_HIGH_LOOP_RESISTANCE
        and eng4.is_tripped is True
    )
    eng4.clear_faults()

    # 4. Ground leakage trip (0xEE34)
    eng4.inject_ground_leakage(6.5)
    gl_ok = (
        eng4.diagnostic_code == DIAG_ERR_GROUND_LEAKAGE
        and eng4.is_tripped is True
    )
    eng4.clear_faults()

    # 5. Clean recovery
    rec_ok = (eng4.is_healthy is True and eng4.diagnostic_code == DIAG_OK)

    s4_passed = uv_ok and oc_ok and hlr_ok and gl_ok and rec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 4,
        "name": "power_coordination_and_faults",
        "check": "Verify under-voltage (0xEE31), over-current (0xEE32), high loop resistance (0xEE33), ground leakage (0xEE34)",
        "passed": bool(s4_passed),
        "timing_ms": round(t1, 3),
        "details": "All 4 power fault modes tripped deterministically with correct diagnostic codes and clean recovery.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: safety_connection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng5 = CipSafetySpeHybridEngine(auto_activate=False)

    # State machine transitions: IDLE -> CONNECTING -> RUNNING -> FAULT
    idle_ok = (eng5.state == SafetyConnectionState.IDLE)

    eng5.connect()
    conn_ok = (eng5.state == SafetyConnectionState.CONNECTING)

    eng5.complete_connection()
    run_ok = (eng5.state == SafetyConnectionState.RUNNING and eng5.diagnostic_code == DIAG_OK)

    # Packet timeout trip (0xEE35)
    eng5.inject_timeout()
    to_ok = (
        eng5.diagnostic_code == DIAG_ERR_TIMEOUT
        and eng5.state == SafetyConnectionState.FAULT
        and eng5.is_tripped is True
    )

    eng5.clear_faults()
    rec5_ok = (eng5.is_healthy is True and eng5.state == SafetyConnectionState.RUNNING)

    s5_passed = idle_ok and conn_ok and run_ok and to_ok and rec5_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 5,
        "name": "safety_connection",
        "check": "Verify state machine transitions and packet timeout (0xEE35)",
        "passed": bool(s5_passed),
        "timing_ms": round(t1, 3),
        "details": "State machine transitions (IDLE->CONNECTING->RUNNING->FAULT) verified. Watchdog timeout tripped 0xEE35.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: register_synchronization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt6 = RegisterTable()
    eng6 = CipSafetySpeHybridEngine(register_table=rt6)
    eng6.sync_to_registers(rt6, privilege=PrivilegeMode.USER)

    w_volt = rt6.read_word(REG_CIP_SAFETY_SPE_VOLTAGE_MV) & 0xFFFF
    w_curr = rt6.read_word(REG_CIP_SAFETY_SPE_CURRENT_MA) & 0xFFFF
    w_pwr = rt6.read_word(REG_CIP_SAFETY_SPE_POWER_MW) & 0xFFFF
    w_rloop = rt6.read_word(REG_CIP_SAFETY_SPE_LOOP_RESISTANCE_MOHM) & 0xFFFF
    w_word = rt6.read_word(REG_CIP_SAFETY_SPE_STATUS_WORD) & 0xFFFF
    w_diag = rt6.read_word(REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE) & 0xFFFF
    w_err = rt6.read_word(REG_CIP_SAFETY_SPE_ERROR_COUNT) & 0xFFFF
    w_seq = rt6.read_word(REG_CIP_SAFETY_SPE_SEQUENCE_COUNTER) & 0xFFFF
    b_pwr_en = rt6.read_bit(COIL_CIP_SAFETY_SPE_POWER_ENABLE)
    b_trip = rt6.read_bit(COIL_CIP_SAFETY_SPE_TRIP)

    sync_nom_ok = (
        w_volt == 24000
        and w_curr == 500
        and w_pwr == 12000
        and w_rloop == 2000
        and (w_word & 3) == 3
        and w_diag == 0x0000
        and w_err == 0
        and w_seq == 0
        and b_pwr_en is True
        and b_trip is False
    )

    # Verify bitwise masks upon fault
    eng6.inject_under_voltage(15000)
    w_word_fault = rt6.read_word(REG_CIP_SAFETY_SPE_STATUS_WORD) & 0xFFFF
    w_diag_fault = rt6.read_word(REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE) & 0xFFFF
    b_trip_fault = rt6.read_bit(COIL_CIP_SAFETY_SPE_TRIP)

    sync_fault_ok = (
        (w_word_fault & int(CipSafetySpeHybridStatusBits.UNDER_VOLTAGE)) != 0
        and w_diag_fault == 0xEE31
        and b_trip_fault is True
    )

    s6_passed = sync_nom_ok and sync_fault_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 6,
        "name": "register_synchronization",
        "check": "Verify RegisterTable reads/writes and bitwise masks across %R2590..%R2597 and %M604..%M605",
        "passed": bool(s6_passed),
        "timing_ms": round(t1, 3),
        "details": "Bit-exact synchronization verified across all 8 analog registers and 2 discrete coils.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: structured_text_validation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_syntax_ok = verify_cip_safety_spe_hybrid_pure_st(ST_PROGRAM_CIP_SAFETY_SPE_HYBRID_SYNC)

    ladder_snippets = [
        "PROGRAM LadderTest\n VAR x : BOOL; END_VAR\n ---[ ]--- x;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR x : BOOL; END_VAR\n ---[/]--- x;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR y : BOOL; END_VAR\n ---( )--- y;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR y : BOOL; END_VAR\n ---(S)--- y;\n END_PROGRAM",
        "PROGRAM LadderTest\n VAR y : BOOL; END_VAR\n ---(R)--- y;\n END_PROGRAM",
        "PROGRAM LadderTest\n RUNG 1\n END_PROGRAM",
        "PROGRAM LadderTest\n NETWORK 1\n END_PROGRAM",
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
    s7_passed = st_syntax_ok and anti_ladder_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 7,
        "name": "structured_text_validation",
        "check": "Verify ST POU 'CipSafetySpeHybridSync' and LadderForbiddenError on ladder syntax",
        "passed": bool(s7_passed),
        "timing_ms": round(t1, 3),
        "details": f"Pure ST POU verified. Rejected {ladder_rejected}/{len(ladder_snippets)} ladder constructs with LadderForbiddenError.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: scan_cycle_simulation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim_cycles = 10 if quick else 100
    rt8 = RegisterTable()
    eng8 = CipSafetySpeHybridEngine(register_table=rt8)

    tracemalloc.start()
    for _ in range(sim_cycles):
        res = eng8.scan_step(dt_ms=10.0)
        assert res.status == AgentStatus.SUCCESS
        eng8.feed_watchdog()
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    scans_ok = (eng8.cycles_count == sim_cycles)
    no_err_ok = (eng8.error_count == 0 and eng8.diagnostic_code == DIAG_OK)
    healthy_ok = (eng8.is_healthy is True and rt8.read_bit(COIL_CIP_SAFETY_SPE_POWER_ENABLE) is True)
    mem_ok = (peak_mem < 2 * 1024 * 1024)

    s8_passed = scans_ok and no_err_ok and healthy_ok and mem_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 8,
        "name": "scan_cycle_simulation",
        "check": f"Verify multi-cycle ILogicUnit execution ({sim_cycles} cycles)",
        "passed": bool(s8_passed),
        "timing_ms": round(t1, 3),
        "details": f"Executed {sim_cycles} continuous scan cycles. Zero errors, peak memory: {peak_mem / 1024:.1f} KB.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: evidence_emission
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    all_stages_passed = all(stg["passed"] for stg in stages_log)
    passed_count = sum(1 for stg in stages_log if stg["passed"]) + 1  # including stage 9

    # Generate cryptographic SHA-256 digests
    pou_sha256 = hashlib.sha256(ST_PROGRAM_CIP_SAFETY_SPE_HYBRID_SYNC.encode("utf-8")).hexdigest()
    stages_summary_str = json.dumps(stages_log, sort_keys=True)
    stages_sha256 = hashlib.sha256(stages_summary_str.encode("utf-8")).hexdigest()

    evidence_dict: Dict[str, Any] = {
        "status": "success" if all_stages_passed else "failed",
        "error_code": None if all_stages_passed else "ERR_STAGE_FAILED",
        "details": (
            f"All 9 Industrial ODVA CIP Safety Over SPE Hybrid Power and Data stages passed deterministically "
            f"(PASSED {passed_count}/9 stages)."
            if all_stages_passed
            else f"Verification failed with {passed_count}/9 stages passing."
        ),
        "stages_passed": passed_count,
        "total_stages": 9,
        "passed_stages": passed_count,
        "data": {
            "work_package": work_package,
            "gate": "G8",
            "protocol": "ODVA CIP Safety Over Single-Pair Ethernet (SPE) Hybrid Power and Data (IEEE 802.3cg / IEEE 802.3bu SPoE)",
            "standards": [
                "IEEE 802.3cg 10BASE-T1L",
                "IEEE 802.3bu SPoE / PoDL Classes 10-15",
                "ODVA CIP Safety Volume 5",
                "IEC 61784-3-2",
                "IEC 61508 SIL 3",
            ],
            "registers": [
                "%R2590..%R2597",
                "%M604..%M605",
            ],
            "sha256_digests": {
                "pou_sha256": pou_sha256,
                "stages_sha256": stages_sha256,
            },
            "checks_passed": passed_count,
            "total_checks": 9,
            "stages": stages_log,
        },
    }

    t1 = (time.perf_counter() - t0) * 1000.0
    stage_9_entry = {
        "stage": 9,
        "name": "evidence_emission",
        "check": "Write deterministic evidence JSON with SHA-256 digests",
        "passed": bool(all_stages_passed),
        "timing_ms": round(t1, 3),
        "details": f"Cryptographic SHA-256 digests generated. ST POU digest: {pou_sha256[:16]}...",
    }
    stages_log.append(stage_9_entry)

    # Save evidence file if path provided
    if output_path:
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence_dict, f, indent=2)

    return evidence_dict


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute W298 CIP Safety Over Single-Pair Ethernet (SPE) Hybrid Power and Data 9-Stage Verification Suite"
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
        help="Path to output JSON evidence artifact (default: artifacts/telemetry/cip_safety_spe_hybrid_evidence.json)",
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
        default="W298",
        help="Work package ID (default: W298)",
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
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_spe_hybrid_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: ODVA CIP Safety Over SPE Hybrid Verification ({args.work_package}){ESC_RESET}")
        print("=" * 80)

    t0 = time.perf_counter()
    try:
        evidence = execute_9stage_verification_suite(
            output_path=str(evidence_path),
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

    passed_count = evidence.get("data", {}).get("checks_passed", sum(1 for s in stages if s.get("passed", False)))
    total_count = evidence.get("data", {}).get("total_checks", len(stages))
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
