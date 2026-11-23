#!/usr/bin/env python3
"""Verification Script for Industrial ODVA CIP Safety Over TSN (Time-Sensitive Networking) Protocol Engine (Wave W259).

Work Package: W259 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Follows the deterministic 9-stage verification pattern:
  Stage 1: IEEE 802.1Qbv Gate Control List (GCL) & 802.1Qbu Preemption Framing
  Stage 2: Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard
  Stage 3: Anti-Ladder Security Guard Interception
  Stage 4: Nominal TSN Safety Telemetry (Cycle 1000us, Offset 250us, Jitter 45ns, 0x0000)
  Stage 5: Schedule Mismatch Safe Stop Trip (0xEE31, %M514)
  Stage 6: Jitter Overrun & Clock Skew Trip (0xEE32, %M514)
  Stage 7: Guard Band Encroachment Trip (0xEE33, %M514)
  Stage 8: Horner OCS Register Table Synchronization (%R2200..%R2207, %M513..%M514)
  Stage 9: Simulation Soak 100 Cycles & Zero Drift

Generates:
  artifacts/telemetry/cip_safety_tsn_evidence.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
import tracemalloc
from typing import Any, Dict, List, Optional, Union

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_tsn import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_TSN_CLASS_ID,
    NOMINAL_TSN_CYCLE_TIME_US,
    NOMINAL_TSN_SCHEDULE_OFFSET_US,
    NOMINAL_TSN_MAX_JITTER_NS,
    NOMINAL_TSN_SAFETY_FLOW_PRIORITY,
    REG_TSN_SAFETY_GATE_STATE,
    REG_TSN_CYCLE_TIME_US,
    REG_TSN_SCHEDULE_OFFSET_US,
    REG_TSN_MAX_JITTER_NS,
    REG_TSN_PREEMPTION_COUNT,
    REG_TSN_EXPRESS_PACKET_COUNT,
    REG_TSN_SAFETY_FLOW_PRIORITY,
    REG_TSN_SAFETY_DIAGNOSTIC_CODE,
    COIL_TSN_SCHEDULE_SYNCED,
    COIL_TSN_SAFETY_INTERLOCK_TRIPPED,
    CIP_SAFETY_TSN_SYNC_POU,
    DiagnosticCode,
    TSNGateState,
    CIPSafetyTSNEngine,
    CIPSafetyTSNPacket,
    compute_crc_s1,
    compute_crc_s2,
    verify_cip_safety_tsn_pure_st,
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
    check: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format a single stage line with ANSI colored badge, timing, and description."""
    badge = format_stage_badge(passed, status)
    timing_str = f" ({timing_ms:.2f} ms)" if timing_ms is not None else ""
    line = f"  Stage {stage}: {badge} {check}{timing_str}"
    if details:
        line += f"\n    {ESC_DIM}{details}{ESC_RESET}"
    return line


def run_deterministic_9stage_suite(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W259",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W259.

    Returns strict 4-state contract JSON evidence.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: IEEE 802.1Qbv Gate Control List (GCL) & 802.1Qbu Preemption Framing
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    # 1. Verify Class IDs
    class_ids_ok = (
        CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        and CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        and CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        and CIP_SAFETY_TSN_CLASS_ID == 0x39
    )

    # 2. IEEE 802.1Qbv GCL Cyclic Windowing Progression
    engine_gcl = CIPSafetyTSNEngine(auto_activate=True)
    g_pre1 = engine_gcl.evaluate_gate_state_at_time(100.0)   # 100 us -> PREEMPTABLE_OPEN
    g_gb = engine_gcl.evaluate_gate_state_at_time(220.0)     # 220 us -> GUARD_BAND_ACTIVE
    g_exp = engine_gcl.evaluate_gate_state_at_time(300.0)    # 300 us -> EXPRESS_SCHEDULED_OPEN
    g_pre2 = engine_gcl.evaluate_gate_state_at_time(600.0)   # 600 us -> PREEMPTABLE_OPEN

    gcl_ok = (
        g_pre1 == TSNGateState.PREEMPTABLE_OPEN
        and g_gb == TSNGateState.GUARD_BAND_ACTIVE
        and g_exp == TSNGateState.EXPRESS_SCHEDULED_OPEN
        and g_pre2 == TSNGateState.PREEMPTABLE_OPEN
    )

    # 3. Dual CRC-S Calculation (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B)
    sample_payload = b"HornerOCS-TSN-SafePayload"
    c1 = compute_crc_s1(sample_payload)
    c2 = compute_crc_s2(sample_payload)
    crcs_distinct = (c1 != c2) and (c1 != 0) and (c2 != 0)

    # 4. Single-bit corruption detection
    corrupted_payload = bytearray(sample_payload)
    corrupted_payload[0] ^= 0x01
    c1_mut = compute_crc_s1(bytes(corrupted_payload))
    c2_mut = compute_crc_s2(bytes(corrupted_payload))
    mutation_ok = (c1_mut != c1) and (c2_mut != c2)

    # 5. IEEE 802.1Qbu Preemption Framing: packet creation, sequence diversification, and CRC check
    pkt = engine_gcl.create_packet(seq=42)
    seq_ok = pkt.verify_sequence()
    crc_ok = pkt.verify_crcs()

    # Mutate packet payload and verify corruption caught
    pkt_corrupted = engine_gcl.create_packet(seq=42)
    pkt_corrupted.mutate_bit(0, 0)
    corrupt_caught = not pkt_corrupted.verify_crcs()

    # Invert sequence diversification and verify failure
    pkt_bad_seq = engine_gcl.create_packet(seq=42)
    pkt_bad_seq.sequence_diversified = 42
    bad_seq_caught = not pkt_bad_seq.verify_sequence()

    # Frame Preemption Fragmentation (802.1Qbu / 802.3br)
    large_frame = b"X" * 128
    frag1, frag2 = engine_gcl.preempt_frame(large_frame, fragment_size=64)
    preempt_ok = (len(frag1) == 64 and len(frag2) == 64 and engine_gcl.preemption_count == 1)

    s1_pass = (
        class_ids_ok
        and gcl_ok
        and crcs_distinct
        and mutation_ok
        and seq_ok
        and crc_ok
        and corrupt_caught
        and bad_seq_caught
        and preempt_ok
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 1,
        "name": "IEEE_802_1Qbv_GCL_And_802_1Qbu_Preemption_Framing",
        "check": "IEEE 802.1Qbv Gate Control List (GCL) & 802.1Qbu Preemption Framing",
        "passed": bool(s1_pass),
        "timing_ms": round(t1, 3),
        "details": "802.1Qbv TAS GCL (1000 us cycle, 250 us offset), 802.1Qbu frame preemption, and Dual CRC-S1 (0x5935)/S2 (0x755B) framing verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s2_pass = verify_cip_safety_tsn_pure_st(CIP_SAFETY_TSN_SYNC_POU)
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 2,
        "name": "Pure_IEC_61131_3_ST_POU_Validation",
        "check": "Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard",
        "passed": bool(s2_pass),
        "timing_ms": round(t1, 3),
        "details": "POU 'CipSafetyTsnSync' validated with STParser and SecurityGuard, binding %R2200..%R2207 and %M513..%M514.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Anti-Ladder Security Guard Interception
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
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
    rejected_count = 0
    for snip in ladder_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snip)
        except LadderForbiddenError:
            rejected_count += 1
        except Exception:
            pass
    s3_pass = (rejected_count == len(ladder_snippets))
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 3,
        "name": "Anti_Ladder_Security_Guard_Interception",
        "check": "Anti-Ladder Security Guard Interception",
        "passed": bool(s3_pass),
        "timing_ms": round(t1, 3),
        "details": f"Rejected {rejected_count}/{len(ladder_snippets)} ladder logic constructs with LadderForbiddenError.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Nominal TSN Safety Telemetry (Cycle 1000us, Offset 250us, Jitter 45ns, 0x0000)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s4 = RegisterTable()
    engine_s4 = CIPSafetyTSNEngine(register_table=rt_s4, auto_activate=True)

    # Process nominal express packet during scheduled express window
    nom_pkt = engine_s4.create_packet()
    proc_ok = engine_s4.process_express_packet(nom_pkt)

    s4_pass = (
        proc_ok is True
        and engine_s4.gate_state == TSNGateState.EXPRESS_SCHEDULED_OPEN
        and engine_s4.cycle_time_us == 1000
        and engine_s4.schedule_offset_us == 250
        and engine_s4.max_jitter_ns == 45
        and engine_s4.diagnostic_code == DiagnosticCode.OK
        and engine_s4.schedule_synced is True
        and engine_s4.interlock_tripped is False
        and rt_s4.read_word("%R2200") == 2
        and rt_s4.read_word("%R2201") == 1000
        and rt_s4.read_word("%R2202") == 250
        and rt_s4.read_word("%R2203") == 45
        and rt_s4.read_word("%R2204") == 0
        and rt_s4.read_word("%R2205") == 101  # Initial 100 + 1 processed
        and rt_s4.read_uword("%R2206") == 0x0739
        and rt_s4.read_uword("%R2207") == 0x0000
        and rt_s4.read_bit("%M513") is True
        and rt_s4.read_bit("%M514") is False
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 4,
        "name": "Nominal_TSN_Safety_Telemetry",
        "check": "Nominal TSN Safety Telemetry (Cycle 1000us, Offset 250us, Jitter 45ns, 0x0000)",
        "passed": bool(s4_pass),
        "timing_ms": round(t1, 3),
        "details": "Nominal Cycle 1000 us, Offset 250 us, Jitter 45 ns, Diagnostic 0x0000, %M513=True, and %M514=False confirmed.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Schedule Mismatch Safe Stop Trip (0xEE31, %M514)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s5 = RegisterTable()
    engine_s5 = CIPSafetyTSNEngine(register_table=rt_s5, auto_activate=True)

    # Force gate state to PREEMPTABLE_OPEN (outside scheduled express window) and transmit express packet
    engine_s5.gate_state = TSNGateState.PREEMPTABLE_OPEN
    pkt_s5 = engine_s5.create_packet()
    res_mismatch = engine_s5.process_express_packet(pkt_s5)

    s5_tripped = (
        res_mismatch is False
        and engine_s5.diagnostic_code == DiagnosticCode.SCHEDULE_MISMATCH_TRIP
        and engine_s5.diagnostic_code == 0xEE31
        and engine_s5.gate_state == TSNGateState.FAILSAFE_CLOSED
        and engine_s5.interlock_tripped is True
        and engine_s5.schedule_synced is False
        and rt_s5.read_word("%R2200") == 4
        and rt_s5.read_uword("%R2207") == 0xEE31
        and rt_s5.read_bit("%M513") is False
        and rt_s5.read_bit("%M514") is True
    )

    # Operator recovery reset
    engine_s5.reset()
    s5_recovered = (
        engine_s5.interlock_tripped is False
        and engine_s5.schedule_synced is True
        and engine_s5.diagnostic_code == DiagnosticCode.OK
        and rt_s5.read_word("%R2200") == 2
        and rt_s5.read_uword("%R2207") == 0x0000
        and rt_s5.read_bit("%M513") is True
        and rt_s5.read_bit("%M514") is False
    )

    s5_pass = s5_tripped and s5_recovered
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 5,
        "name": "Schedule_Mismatch_Safe_Stop_Trip",
        "check": "Schedule Mismatch Safe Stop Trip (0xEE31, %M514)",
        "passed": bool(s5_pass),
        "timing_ms": round(t1, 3),
        "details": "802.1Qbv schedule mismatch (packet outside express window) tripped 0xEE31, asserted %M514, de-asserted %M513, recovery verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Jitter Overrun & Clock Skew Trip (0xEE32, %M514)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s6 = RegisterTable()
    engine_s6 = CIPSafetyTSNEngine(register_table=rt_s6, auto_activate=True)

    # Inject jitter overrun: 105 ns (>= 100 ns watchdog limit)
    engine_s6.update_jitter(105)

    s6_tripped = (
        engine_s6.diagnostic_code == DiagnosticCode.JITTER_EXCEEDED_TRIP
        and engine_s6.diagnostic_code == 0xEE32
        and engine_s6.gate_state == TSNGateState.FAILSAFE_CLOSED
        and engine_s6.interlock_tripped is True
        and engine_s6.schedule_synced is False
        and rt_s6.read_word("%R2200") == 4
        and rt_s6.read_word("%R2203") == 105
        and rt_s6.read_uword("%R2207") == 0xEE32
        and rt_s6.read_bit("%M513") is False
        and rt_s6.read_bit("%M514") is True
    )

    # Operator recovery reset
    engine_s6.reset()
    s6_recovered = (
        engine_s6.interlock_tripped is False
        and engine_s6.schedule_synced is True
        and engine_s6.diagnostic_code == DiagnosticCode.OK
        and rt_s6.read_word("%R2200") == 2
        and rt_s6.read_uword("%R2207") == 0x0000
        and rt_s6.read_bit("%M513") is True
        and rt_s6.read_bit("%M514") is False
    )

    s6_pass = s6_tripped and s6_recovered
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 6,
        "name": "Jitter_Overrun_And_Clock_Skew_Trip",
        "check": "Jitter Overrun & Clock Skew Trip (0xEE32, %M514)",
        "passed": bool(s6_pass),
        "timing_ms": round(t1, 3),
        "details": "TSN jitter overrun (105 ns >= 100 ns limit) tripped 0xEE32, asserted %M514, de-asserted %M513, recovery verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Guard Band Encroachment Trip (0xEE33, %M514)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s7 = RegisterTable()
    engine_s7 = CIPSafetyTSNEngine(register_table=rt_s7, auto_activate=True)

    # Force gate state to GUARD_BAND_ACTIVE and attempt to transmit preemptable frame
    engine_s7.gate_state = TSNGateState.GUARD_BAND_ACTIVE
    res_gb = engine_s7.transmit_preemptable_frame(b"preemptable_data_frame", duration_us=20)

    s7_tripped = (
        res_gb is False
        and engine_s7.diagnostic_code == DiagnosticCode.GUARD_BAND_VIOLATION
        and engine_s7.diagnostic_code == 0xEE33
        and engine_s7.gate_state == TSNGateState.FAILSAFE_CLOSED
        and engine_s7.interlock_tripped is True
        and engine_s7.schedule_synced is False
        and rt_s7.read_word("%R2200") == 4
        and rt_s7.read_uword("%R2207") == 0xEE33
        and rt_s7.read_bit("%M513") is False
        and rt_s7.read_bit("%M514") is True
    )

    # Operator recovery reset
    engine_s7.reset()
    s7_recovered = (
        engine_s7.interlock_tripped is False
        and engine_s7.schedule_synced is True
        and engine_s7.diagnostic_code == DiagnosticCode.OK
        and rt_s7.read_word("%R2200") == 2
        and rt_s7.read_uword("%R2207") == 0x0000
        and rt_s7.read_bit("%M513") is True
        and rt_s7.read_bit("%M514") is False
    )

    s7_pass = s7_tripped and s7_recovered
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 7,
        "name": "Guard_Band_Encroachment_Trip",
        "check": "Guard Band Encroachment Trip (0xEE33, %M514)",
        "passed": bool(s7_pass),
        "timing_ms": round(t1, 3),
        "details": "Guard band encroachment (preemptable traffic during guard band) tripped 0xEE33, asserted %M514, de-asserted %M513, recovery verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Horner OCS Register Table Synchronization (%R2200..%R2207, %M513..%M514)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s8 = RegisterTable()
    engine_s8 = CIPSafetyTSNEngine(register_table=rt_s8, auto_activate=True)

    # Initial nominal synchronization check
    s8_init = (
        rt_s8.read_word("%R2200") == 2
        and rt_s8.read_word("%R2201") == 1000
        and rt_s8.read_word("%R2202") == 250
        and rt_s8.read_word("%R2203") == 45
        and rt_s8.read_word("%R2204") == 0
        and rt_s8.read_word("%R2205") == 100
        and rt_s8.read_uword("%R2206") == 0x0739
        and rt_s8.read_uword("%R2207") == 0x0000
        and rt_s8.read_bit("%M513") is True
        and rt_s8.read_bit("%M514") is False
    )

    # Sequential fault trips bit-exact verification
    engine_s8.trip_fault(DiagnosticCode.SCHEDULE_MISMATCH_TRIP)
    s8_trip1 = (
        rt_s8.read_word("%R2200") == 4
        and rt_s8.read_uword("%R2207") == 0xEE31
        and rt_s8.read_bit("%M513") is False
        and rt_s8.read_bit("%M514") is True
    )

    engine_s8.trip_fault(DiagnosticCode.JITTER_EXCEEDED_TRIP)
    s8_trip2 = (
        rt_s8.read_word("%R2200") == 4
        and rt_s8.read_uword("%R2207") == 0xEE32
        and rt_s8.read_bit("%M513") is False
        and rt_s8.read_bit("%M514") is True
    )

    engine_s8.trip_fault(DiagnosticCode.GUARD_BAND_VIOLATION)
    s8_trip3 = (
        rt_s8.read_word("%R2200") == 4
        and rt_s8.read_uword("%R2207") == 0xEE33
        and rt_s8.read_bit("%M513") is False
        and rt_s8.read_bit("%M514") is True
    )

    # Reset under SYSTEM privilege
    engine_s8.reset()
    s8_reset = (
        rt_s8.read_word("%R2200") == 2
        and rt_s8.read_word("%R2201") == 1000
        and rt_s8.read_word("%R2202") == 250
        and rt_s8.read_word("%R2203") == 45
        and rt_s8.read_uword("%R2207") == 0x0000
        and rt_s8.read_bit("%M513") is True
        and rt_s8.read_bit("%M514") is False
    )

    s8_pass = s8_init and s8_trip1 and s8_trip2 and s8_trip3 and s8_reset
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 8,
        "name": "Horner_OCS_Register_Table_Synchronization",
        "check": "Horner OCS Register Table Synchronization (%R2200..%R2207, %M513..%M514)",
        "passed": bool(s8_pass),
        "timing_ms": round(t1, 3),
        "details": "Bit-exact %R2200..%R2207 and %M513..%M514 synchronization verified under SYSTEM privilege across trips and reset.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Simulation Soak 100 Cycles & Zero Drift
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s9 = RegisterTable()
    engine_s9 = CIPSafetyTSNEngine(register_table=rt_s9, auto_activate=True)

    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()
    soak_stable = True

    for cycle_i in range(1, 101):
        try:
            # Advance 1 ms per cycle (1 full TSN cycle)
            engine_s9.scan_step(0.001)
        except Exception:
            soak_stable = False
            break

    snapshot_after = tracemalloc.take_snapshot()
    stats = snapshot_after.compare_to(snapshot_before, "lineno")
    heap_growth_kb = sum(st.size_diff for st in stats if st.size_diff > 0) / 1024.0
    tracemalloc.stop()

    s9_pass = (
        soak_stable
        and engine_s9.cycles_count >= 100
        and heap_growth_kb < 100.0
        and rt_s9.read_word("%R2201") == 1000
        and rt_s9.read_word("%R2202") == 250
        and rt_s9.read_word("%R2203") == 45
        and rt_s9.read_uword("%R2207") == 0x0000
        and rt_s9.read_bit("%M513") is True
        and rt_s9.read_bit("%M514") is False
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 9,
        "name": "Simulation_Soak_100_Cycles_And_Zero_Drift",
        "check": "Simulation Soak 100 Cycles & Zero Drift",
        "passed": bool(s9_pass),
        "timing_ms": round(t1, 3),
        "details": f"100 scan cycles executed without fault or drift, heap growth {heap_growth_kb:.2f} KB (< 100 KB).",
    })

    # ------------------------------------------------------------------------
    # Aggregate Verification Result
    # ------------------------------------------------------------------------
    stages_passed = sum(1 for r in test_results if r["passed"])
    total_stages = len(test_results)
    all_passed = (stages_passed == total_stages)

    status = "success" if all_passed else "failed"
    error_code = None if all_passed else "ERR_STAGE_VERIFICATION_FAILED"
    details = (
        f"Wave {work_package} CIP Safety Over TSN Protocol Engine Verification PASSED ({stages_passed}/{total_stages} stages)."
        if all_passed
        else f"Wave {work_package} Verification FAILED ({stages_passed}/{total_stages} stages passed)."
    )

    evidence_payload: Dict[str, Any] = {
        "status": status,
        "error_code": error_code,
        "details": details,
        "work_package": work_package,
        "total_stages": total_stages,
        "stages_passed": stages_passed,
        "data": {
            "protocol": "ODVA CIP Safety Over TSN (IEEE 802.1Qbv / IEEE 802.1Qbu)",
            "work_package": work_package,
            "classes": {
                "0x39": "Safety Supervisor Object",
                "0x3A": "Safety Validator Object",
                "0x3B": "Safety Connection Object",
            },
            "parameters": {
                "cycle_time_us": 1000,
                "schedule_offset_us": 250,
                "nominal_jitter_ns": 45,
                "guard_band_duration_us": 50,
            },
            "register_map": {
                "%R2200": "TSN Gate State (0..4)",
                "%R2201": "TSN Cycle Time (us)",
                "%R2202": "Schedule Offset (us)",
                "%R2203": "Max Time-Sync Jitter (ns)",
                "%R2204": "Cumulative Preemption Count",
                "%R2205": "Express Packet Count",
                "%R2206": "Safety Flow Priority (PCP=7, Safe Class 0x39)",
                "%R2207": "Safety Diagnostic Code",
                "%M513": "TSN Schedule Synced Coil",
                "%M514": "Safety Interlock Tripped Coil",
            },
            "stages": test_results,
            "tests": test_results,
            "checks_passed": stages_passed,
            "total_checks": total_stages,
        },
    }

    if output_path is not None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(evidence_payload, f, indent=2)

    return evidence_payload


def main(argv: Optional[List[str]] = None) -> int:
    """Main verification CLI entry point."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="JEV Cscape Agent: Industrial ODVA CIP Safety Over TSN Verification (W259)"
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
        help="Specified evidence JSON output path",
    )
    parser.add_argument(
        "--work-package",
        dest="work_package",
        default="W259",
        help="Work package identifier (default: W259)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw strict 4-state contract JSON to stdout",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_tsn_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: Industrial ODVA CIP Safety Over TSN Verification ({args.work_package}){ESC_RESET}")
        print("=" * 80)

    t_start = time.perf_counter()
    try:
        evidence = run_deterministic_9stage_suite(
            output_path=evidence_path,
            work_package=args.work_package,
        )
    except Exception as exc:
        elapsed_fail = (time.perf_counter() - t_start) * 1000.0
        fail_payload: Dict[str, Any] = {
            "status": "failed",
            "error_code": "VERIFICATION_EXCEPTION",
            "details": f"Verification suite crashed with unhandled exception: {exc}",
            "stages_passed": 0,
            "total_stages": 9,
            "passed_stages": 0,
            "data": {
                "work_package": args.work_package,
                "duration_ms": elapsed_fail,
                "stages": [],
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(fail_payload, f, indent=2)

        if args.json:
            print(json.dumps(fail_payload, indent=2))
        else:
            print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
            print(f"  {type(exc).__name__}: {exc}")
            print("=" * 80)
        return 1

    total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    # Ensure evidence dictionary has tests alias and total_checks
    if isinstance(evidence, dict) and "data" in evidence:
        stages_list = evidence["data"].get("stages", [])
        if "tests" not in evidence["data"]:
            evidence["data"]["tests"] = stages_list
        if "checks_passed" not in evidence["data"]:
            evidence["data"]["checks_passed"] = sum(1 for s in stages_list if s.get("passed"))
        if "total_checks" not in evidence["data"]:
            evidence["data"]["total_checks"] = len(stages_list)
        # Re-save with complete data
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    valid_states = {"success", "failed", "blocked", "inconclusive"}
    overall_status = evidence.get("status") if isinstance(evidence, dict) else None
    error_code = evidence.get("error_code") if isinstance(evidence, dict) else "INVALID_PAYLOAD"
    details_str = evidence.get("details", "") if isinstance(evidence, dict) else "Evidence is not a dictionary"

    if overall_status not in valid_states:
        print(f"\n[{ESC_RED}{ESC_BOLD}CONTRACT VIOLATION{ESC_RESET}] Invalid status '{overall_status}'. Must be one of {valid_states}.")
        print("=" * 80)
        return 1

    stages_data: List[Dict[str, Any]] = []
    if isinstance(evidence, dict):
        data_dict = evidence.get("data")
        if isinstance(data_dict, dict):
            stages_data = data_dict.get("stages") or data_dict.get("tests") or []

    print("\nDeterministic 9-Stage Protocol Verification Results:")
    for s in stages_data:
        st_num = s.get("stage", "?")
        chk_name = s.get("check") or s.get("name") or s.get("stage_name") or f"Stage_{st_num}"
        passed = bool(s.get("passed"))
        details = s.get("details", "")
        timing = s.get("timing_ms")
        st_stat = s.get("status")
        print(format_stage_result(st_num, chk_name, passed, timing, details, st_stat))

    print("-" * 80)
    print(f"Total Execution Time: {total_elapsed_ms:.2f} ms")
    stages_passed = evidence.get("stages_passed", sum(1 for s in stages_data if s.get("passed")))
    total_stages = evidence.get("total_stages", len(stages_data))
    print(f"Stages Passed: {stages_passed}/{total_stages}")
    print(f"Evidence Artifact: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print(f"Engineering Contract Status: {overall_status.upper()}")

    if overall_status == "blocked":
        print(f"\n{ESC_YELLOW}{ESC_BOLD}[BLOCKED] Action prevented by safety policy or platform limitation: {error_code}{ESC_RESET}")
        return 2
    elif overall_status == "inconclusive":
        print(f"\n{ESC_YELLOW}{ESC_BOLD}[INCONCLUSIVE] Outcome unverified: {error_code}{ESC_RESET}")
        return 3
    elif overall_status == "success":
        print(f"\n{ESC_GREEN}{ESC_BOLD}[SUCCESS] All 9 CIP Safety Over TSN protocol stages PASSED deterministically.{ESC_RESET}")
        print("=" * 80)
        return 0
    else:
        print(f"\n{ESC_RED}{ESC_BOLD}[FAILED] Verification failed with status '{overall_status}' (error_code: {error_code}).{ESC_RESET}")
        print(f"Details: {details_str}")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
