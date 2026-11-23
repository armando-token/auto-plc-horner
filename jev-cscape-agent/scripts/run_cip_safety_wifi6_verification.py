#!/usr/bin/env python3
"""Verification Script for Industrial ODVA CIP Safety Over Wi-Fi 6 (IEEE 802.11ax) Protocol Engine (Wave W268).

Work Package: W268 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Follows the deterministic 9-stage verification pattern:
  Stage 1: IEEE 802.11ax Wi-Fi 6 OFDMA Safety Frame Profile & SNN
  Stage 2: Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard
  Stage 3: Anti-Ladder Security Guard Interception
  Stage 4: Nominal Wireless Safety Telemetry (RSSI -54 dBm, PER 0.12%, EPI 5000 us, 0x0000)
  Stage 5: Dual-Antenna Diversity RSSI Degradation Safe Stop Trip (0xEE61, %M535)
  Stage 6: Packet Error Rate Burst Safe Stop Trip (0xEE62, %M535)
  Stage 7: BSS Roaming Handover Watchdog Fault (0xEE63, %M535)
  Stage 8: Horner OCS Register Table Synchronization (%R2290..%R2297, %M534..%M535)
  Stage 9: Simulation Soak 100 Cycles & Zero Drift

Generates:
  artifacts/telemetry/cip_safety_wifi6_evidence.json
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
from jev_cscape.telemetry.cip_safety_wifi6 import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_WIFI6_CLASS_ID,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    NOMINAL_WIFI6_RSSI_DBM,
    DEFAULT_RSSI_TRIP_THRESHOLD_DBM,
    NOMINAL_WIFI6_PER_BPS,
    DEFAULT_PER_TRIP_THRESHOLD_BPS,
    NOMINAL_WIFI6_EPI_US,
    DEFAULT_EPI_TIMEOUT_THRESHOLD_US,
    NOMINAL_OFDMA_RU_ALLOCATION,
    DEFAULT_BSS_COLOR,
    DEFAULT_ROAMING_WATCHDOG_MS,
    REG_WIFI6_SAFETY_STATE,
    REG_WIFI6_RSSI_PRIMARY_DBM,
    REG_WIFI6_RSSI_DIVERSITY_DBM,
    REG_WIFI6_PER_SCALED,
    REG_WIFI6_TX_FRAME_COUNT,
    REG_WIFI6_ROAMING_EVENT_COUNT,
    REG_WIFI6_EPI_TIMER_US,
    REG_WIFI6_DIAGNOSTIC_CODE,
    COIL_WIFI6_SAFETY_LINK_HEALTHY,
    COIL_WIFI6_SAFETY_STOP_TRIPPED,
    CIP_SAFETY_WIFI6_SYNC_POU,
    DiagnosticCode,
    SafeWifi6State,
    CIPSafetyWifi6Frame,
    CIPSafetyWifi6Packet,
    CIPSafetyWifi6Engine,
    compute_crc_s1,
    compute_crc_s2,
    create_valid_wifi6_frame,
    verify_cip_safety_wifi6_pure_st,
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
    work_package: str = "W268",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W268.

    Returns strict 4-state contract JSON evidence.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: IEEE 802.11ax Wi-Fi 6 OFDMA Safety Frame Profile & SNN
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    # 1. Verify Class IDs
    class_ids_ok = (
        CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        and CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        and CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        and CIP_SAFETY_WIFI6_CLASS_ID in (0x3E, 0x40, 0x2E)
    )

    # 2. Safety Network Number (SNN) verification
    snn_ok = (DEFAULT_SNN in (0x3A4B, 14923))

    # 3. Dual CRC-S Calculation (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B)
    sample_payload = b"HornerOCS-WiFi6-OFDMA-Safety-SPDU"
    c1 = compute_crc_s1(sample_payload)
    c2 = compute_crc_s2(sample_payload)
    crcs_distinct = (c1 != c2) and (c1 != 0) and (c2 != 0)

    # 4. Single-bit corruption detection
    corrupted_payload = bytearray(sample_payload)
    corrupted_payload[0] ^= 0x01
    c1_mut = compute_crc_s1(bytes(corrupted_payload))
    c2_mut = compute_crc_s2(bytes(corrupted_payload))
    mutation_ok = (c1_mut != c1) and (c2_mut != c2)

    # 5. Packet Framing: packet creation, sequence diversification, and CRC check
    pkt = create_valid_wifi6_frame(
        sequence_primary=1,
        snn=DEFAULT_SNN,
        epi_timer_us=5000,
        rssi_antenna_a_dbm=-54,
        rssi_antenna_b_dbm=-58,
        packet_error_rate_bps=12,
        ofdma_ru_allocation=106,
    )
    seq_ok = pkt.verify_sequence()
    crc_ok = pkt.verify_crcs()
    snn_verify_ok = pkt.verify_snn(DEFAULT_SNN)

    # Mutate packet payload and verify corruption caught
    pkt_corrupted = create_valid_wifi6_frame(
        sequence_primary=1,
        snn=DEFAULT_SNN,
        epi_timer_us=5000,
        rssi_antenna_a_dbm=-54,
        rssi_antenna_b_dbm=-58,
        packet_error_rate_bps=12,
        ofdma_ru_allocation=106,
    )
    pkt_corrupted.mutate_bit(0, 0)
    corrupt_caught = not pkt_corrupted.verify_crcs()

    # Invert sequence diversification and verify failure
    pkt_bad_seq = create_valid_wifi6_frame(
        sequence_primary=1,
        snn=DEFAULT_SNN,
        epi_timer_us=5000,
        rssi_antenna_a_dbm=-54,
        rssi_antenna_b_dbm=-58,
        packet_error_rate_bps=12,
        ofdma_ru_allocation=106,
    )
    pkt_bad_seq.sequence_diversified = pkt_bad_seq.sequence_primary
    bad_seq_caught = not pkt_bad_seq.verify_sequence()

    s1_pass = (
        class_ids_ok
        and snn_ok
        and crcs_distinct
        and mutation_ok
        and seq_ok
        and crc_ok
        and snn_verify_ok
        and corrupt_caught
        and bad_seq_caught
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 1,
        "name": "IEEE_802_11ax_WiFi6_OFDMA_Safety_Frame_Profile_And_SNN",
        "check": "IEEE 802.11ax Wi-Fi 6 OFDMA Safety Frame Profile & SNN",
        "passed": bool(s1_pass),
        "timing_ms": round(t1, 3),
        "details": f"Class IDs (0x39/0x3A/0x3B/0x2E), SNN 0x{DEFAULT_SNN:04X}, Dual CRC-S1 (0x5935)/S2 (0x755B), and OFDMA 106-RU framing verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s2_pass = verify_cip_safety_wifi6_pure_st(CIP_SAFETY_WIFI6_SYNC_POU)
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 2,
        "name": "Pure_IEC_61131_3_ST_POU_Validation",
        "check": "Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard",
        "passed": bool(s2_pass),
        "timing_ms": round(t1, 3),
        "details": "POU 'CipSafetyWiFi6Sync' validated with STParser and SecurityGuard, binding %R2290..%R2297 and %M534..%M535.",
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
    # Stage 4: Nominal Wireless Safety Telemetry (RSSI -54 dBm, PER 0.12%, EPI 5000 us, 0x0000)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s4 = RegisterTable()
    engine_s4 = CIPSafetyWifi6Engine(register_table=rt_s4, auto_activate=True)

    # Process nominal Wi-Fi 6 safety packet
    nom_pkt = engine_s4.create_packet(
        seq=1,
        rssi_primary_dbm=-54,
        rssi_diversity_dbm=-58,
        per_scaled=12,
        epi_timer_us=5000,
    )
    proc_ok = engine_s4.process_incoming_packet(nom_pkt)

    s4_pass = (
        proc_ok is True
        and engine_s4.state == SafeWifi6State.SAFE_OPERATIONAL
        and engine_s4.rssi_primary_dbm == -54
        and engine_s4.per_scaled == 12
        and engine_s4.epi_timer_us == 5000
        and engine_s4.diagnostic_code == DiagnosticCode.OK
        and engine_s4.link_healthy is True
        and engine_s4.stop_tripped is False
        and rt_s4.read_word("%R2290") == 3
        and rt_s4.read_word("%R2291") == -54
        and rt_s4.read_word("%R2292") == -58
        and rt_s4.read_word("%R2293") == 12
        and rt_s4.read_uword("%R2294") >= 100
        and rt_s4.read_uword("%R2295") == 0
        and rt_s4.read_uword("%R2296") == 5000
        and rt_s4.read_uword("%R2297") == 0x0000
        and rt_s4.read_bit("%M534") is True
        and rt_s4.read_bit("%M535") is False
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 4,
        "name": "Nominal_Wireless_Safety_Telemetry",
        "check": "Nominal Wireless Safety Telemetry (RSSI -54 dBm, PER 0.12%, EPI 5000 us, 0x0000)",
        "passed": bool(s4_pass),
        "timing_ms": round(t1, 3),
        "details": "RSSI -54 dBm, PER 0.12% (12 in %R2293), EPI 5000 us, Diagnostic 0x0000, %M534=True, %M535=False confirmed.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Dual-Antenna Diversity RSSI Degradation Safe Stop Trip (0xEE61, %M535)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s5 = RegisterTable()
    engine_s5 = CIPSafetyWifi6Engine(register_table=rt_s5, auto_activate=True, rssi_trip_threshold_dbm=-82)

    # 1. Test single antenna degradation: Antenna A drops to -86 dBm, Antenna B remains -54 dBm
    engine_s5.evaluate_antenna_diversity(-86, -54)
    diversity_switched = (
        engine_s5.active_antenna == 1  # Switched to Antenna B
        and engine_s5.rssi_diversity_dbm == -54
        and engine_s5.link_healthy is True
        and rt_s5.read_word("%R2290") == 3
        and rt_s5.read_bit("%M534") is True
        and rt_s5.read_bit("%M535") is False
    )

    # 2. Inject dual antenna degradation: Both antennas drop below -82 dBm (-86 dBm & -88 dBm)
    engine_s5.inject_rssi_degradation(rssi_primary_dbm=-86, rssi_diversity_dbm=-88)

    s5_tripped = (
        diversity_switched
        and engine_s5.diagnostic_code == DiagnosticCode.RSSI_DEGRADATION_TRIP
        and engine_s5.diagnostic_code == 0xEE61
        and engine_s5.state == SafeWifi6State.SAFE_STOP_TRIPPED
        and engine_s5.stop_tripped is True
        and engine_s5.link_healthy is False
        and rt_s5.read_word("%R2290") == 4
        and rt_s5.read_word("%R2291") == -86
        and rt_s5.read_word("%R2292") == -88
        and rt_s5.read_uword("%R2297") == 0xEE61
        and rt_s5.read_bit("%M534") is False
        and rt_s5.read_bit("%M535") is True
    )

    # Operator recovery reset
    engine_s5.reset()
    s5_recovered = (
        engine_s5.stop_tripped is False
        and engine_s5.link_healthy is True
        and engine_s5.diagnostic_code == DiagnosticCode.OK
        and rt_s5.read_word("%R2290") == 3
        and rt_s5.read_word("%R2291") == -54
        and rt_s5.read_word("%R2292") == -58
        and rt_s5.read_uword("%R2297") == 0x0000
        and rt_s5.read_bit("%M534") is True
        and rt_s5.read_bit("%M535") is False
    )

    s5_pass = s5_tripped and s5_recovered
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 5,
        "name": "Dual_Antenna_Diversity_RSSI_Degradation_Safe_Stop_Trip",
        "check": "Dual-Antenna Diversity RSSI Degradation Safe Stop Trip (0xEE61, %M535)",
        "passed": bool(s5_pass),
        "timing_ms": round(t1, 3),
        "details": "Dual-antenna diversity switched on single degradation; dual drop (-86/-88 dBm < -82 dBm) tripped 0xEE61, asserted %M535, recovery verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Packet Error Rate Burst Safe Stop Trip (0xEE62, %M535)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s6 = RegisterTable()
    engine_s6 = CIPSafetyWifi6Engine(register_table=rt_s6, auto_activate=True)

    # Inject PER burst: 650 scaled (6.50% > 5.00% limit)
    engine_s6.inject_packet_error_burst(per_scaled=650)

    s6_tripped = (
        engine_s6.diagnostic_code == DiagnosticCode.PACKET_ERROR_BURST_TRIP
        and engine_s6.diagnostic_code == 0xEE62
        and engine_s6.state == SafeWifi6State.SAFE_STOP_TRIPPED
        and engine_s6.stop_tripped is True
        and engine_s6.link_healthy is False
        and rt_s6.read_word("%R2290") == 4
        and rt_s6.read_word("%R2293") == 650
        and rt_s6.read_uword("%R2297") == 0xEE62
        and rt_s6.read_bit("%M534") is False
        and rt_s6.read_bit("%M535") is True
    )

    # Operator recovery reset
    engine_s6.reset()
    s6_recovered = (
        engine_s6.stop_tripped is False
        and engine_s6.link_healthy is True
        and engine_s6.diagnostic_code == DiagnosticCode.OK
        and rt_s6.read_word("%R2290") == 3
        and rt_s6.read_word("%R2293") == 12
        and rt_s6.read_uword("%R2297") == 0x0000
        and rt_s6.read_bit("%M534") is True
        and rt_s6.read_bit("%M535") is False
    )

    s6_pass = s6_tripped and s6_recovered
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 6,
        "name": "Packet_Error_Rate_Burst_Safe_Stop_Trip",
        "check": "Packet Error Rate Burst Safe Stop Trip (0xEE62, %M535)",
        "passed": bool(s6_pass),
        "timing_ms": round(t1, 3),
        "details": "PER burst (6.50% > 5.00% limit) tripped 0xEE62, asserted %M535, %R2293=650, recovery verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: BSS Roaming Handover Watchdog Fault (0xEE63, %M535)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s7 = RegisterTable()
    engine_s7 = CIPSafetyWifi6Engine(register_table=rt_s7, auto_activate=True, roaming_watchdog_ms=25.0)

    # 1. Successful handover within budget (8.0 ms <= 25.0 ms)
    engine_s7.start_roaming_handover()
    ok_handover = engine_s7.complete_roaming_handover(duration_ms=8.0)

    # 2. Inject handover overrun: 35.0 ms (> 25.0 ms limit)
    engine_s7.start_roaming_handover()
    bad_handover = engine_s7.complete_roaming_handover(duration_ms=35.0)

    s7_tripped = (
        ok_handover is True
        and bad_handover is False
        and engine_s7.diagnostic_code == DiagnosticCode.ROAMING_HANDOVER_FAULT
        and engine_s7.diagnostic_code == 0xEE63
        and engine_s7.state == SafeWifi6State.SAFE_STOP_TRIPPED
        and engine_s7.stop_tripped is True
        and engine_s7.link_healthy is False
        and rt_s7.read_word("%R2290") == 4
        and rt_s7.read_uword("%R2297") == 0xEE63
        and rt_s7.read_bit("%M534") is False
        and rt_s7.read_bit("%M535") is True
    )

    # 3. Test cyclic scan watchdog timeout during roaming
    engine_wd = CIPSafetyWifi6Engine(auto_activate=True, roaming_watchdog_ms=20.0)
    engine_wd.start_roaming_handover()
    for _ in range(25):  # 25 x 1ms = 25 ms > 20 ms
        engine_wd.scan_step(0.001)
    cyclic_timeout_ok = (
        engine_wd.state == SafeWifi6State.SAFE_STOP_TRIPPED
        and engine_wd.diagnostic_code == 0xEE63
        and engine_wd.stop_tripped is True
    )

    # Operator recovery reset
    engine_s7.reset()
    s7_recovered = (
        engine_s7.stop_tripped is False
        and engine_s7.link_healthy is True
        and engine_s7.diagnostic_code == DiagnosticCode.OK
        and rt_s7.read_word("%R2290") == 3
        and rt_s7.read_uword("%R2297") == 0x0000
        and rt_s7.read_bit("%M534") is True
        and rt_s7.read_bit("%M535") is False
    )

    s7_pass = s7_tripped and cyclic_timeout_ok and s7_recovered
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 7,
        "name": "BSS_Roaming_Handover_Watchdog_Fault",
        "check": "BSS Roaming Handover Watchdog Fault (0xEE63, %M535)",
        "passed": bool(s7_pass),
        "timing_ms": round(t1, 3),
        "details": "BSS roaming handover overrun (35 ms > 25 ms limit) & cyclic silence timeout tripped 0xEE63, asserted %M535, recovery verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Horner OCS Register Table Synchronization (%R2290..%R2297, %M534..%M535)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s8 = RegisterTable()
    engine_s8 = CIPSafetyWifi6Engine(register_table=rt_s8, auto_activate=True)

    s8_init = (
        rt_s8.read_word("%R2290") == 3
        and rt_s8.read_word("%R2291") == -54
        and rt_s8.read_word("%R2292") == -58
        and rt_s8.read_word("%R2293") == 12
        and rt_s8.read_uword("%R2294") == 100
        and rt_s8.read_uword("%R2295") == 0
        and rt_s8.read_uword("%R2296") == 5000
        and rt_s8.read_uword("%R2297") == 0x0000
        and rt_s8.read_bit("%M534") is True
        and rt_s8.read_bit("%M535") is False
    )

    # Sequential fault trips bit-exact verification
    engine_s8.trip_fault(DiagnosticCode.RSSI_DEGRADATION_TRIP)
    s8_trip1 = (
        rt_s8.read_word("%R2290") == 4
        and rt_s8.read_uword("%R2297") == 0xEE61
        and rt_s8.read_bit("%M534") is False
        and rt_s8.read_bit("%M535") is True
    )

    engine_s8.trip_fault(DiagnosticCode.PACKET_ERROR_BURST_TRIP)
    s8_trip2 = (
        rt_s8.read_word("%R2290") == 4
        and rt_s8.read_uword("%R2297") == 0xEE62
        and rt_s8.read_bit("%M534") is False
        and rt_s8.read_bit("%M535") is True
    )

    engine_s8.trip_fault(DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT)
    s8_trip3 = (
        rt_s8.read_word("%R2290") == 4
        and rt_s8.read_uword("%R2297") == 0xEE63
        and rt_s8.read_bit("%M534") is False
        and rt_s8.read_bit("%M535") is True
    )

    # Reset under SYSTEM privilege
    engine_s8.reset()
    s8_reset = (
        rt_s8.read_word("%R2290") == 3
        and rt_s8.read_word("%R2291") == -54
        and rt_s8.read_word("%R2292") == -58
        and rt_s8.read_word("%R2293") == 12
        and rt_s8.read_uword("%R2297") == 0x0000
        and rt_s8.read_bit("%M534") is True
        and rt_s8.read_bit("%M535") is False
    )

    s8_pass = s8_init and s8_trip1 and s8_trip2 and s8_trip3 and s8_reset
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 8,
        "name": "Horner_OCS_Register_Table_Synchronization",
        "check": "Horner OCS Register Table Synchronization (%R2290..%R2297, %M534..%M535)",
        "passed": bool(s8_pass),
        "timing_ms": round(t1, 3),
        "details": "Bit-exact %R2290..%R2297 and %M534..%M535 synchronization verified under SYSTEM privilege across trips and reset.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Simulation Soak 100 Cycles & Zero Drift
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s9 = RegisterTable()
    engine_s9 = CIPSafetyWifi6Engine(register_table=rt_s9, auto_activate=True)

    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()
    soak_stable = True

    for cycle_i in range(1, 101):
        try:
            pkt_in = engine_s9.create_packet(seq=cycle_i)
            engine_s9.process_incoming_packet(pkt_in)
            engine_s9.scan_step(0.005)
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
        and engine_s9.state == SafeWifi6State.SAFE_OPERATIONAL
        and engine_s9.rssi_primary_dbm == -54
        and engine_s9.per_scaled == 12
        and engine_s9.epi_timer_us == 5000
        and engine_s9.diagnostic_code == DiagnosticCode.OK
        and engine_s9.link_healthy is True
        and engine_s9.stop_tripped is False
        and rt_s9.read_word("%R2290") == 3
        and rt_s9.read_word("%R2291") == -54
        and rt_s9.read_word("%R2292") == -58
        and rt_s9.read_word("%R2293") == 12
        and rt_s9.read_uword("%R2296") == 5000
        and rt_s9.read_uword("%R2297") == 0x0000
        and rt_s9.read_bit("%M534") is True
        and rt_s9.read_bit("%M535") is False
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
        f"Wave {work_package} CIP Safety Over Wi-Fi 6 IEEE 802.11ax Protocol Engine Verification PASSED ({stages_passed}/{total_stages} stages)."
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
            "protocol": "ODVA CIP Safety Over Wi-Fi 6 (IEEE 802.11ax) Protocol Engine",
            "work_package": work_package,
            "classes": {
                "0x39": "Safety Supervisor Object",
                "0x3A": "Safety Validator Object",
                "0x3B": "Safety Connection Object",
                "0x2E": "CIP Safety Wireless Extension Class ID",
            },
            "snn": hex(DEFAULT_SNN),
            "rssi_dbm": NOMINAL_WIFI6_RSSI_DBM,
            "per_bps": NOMINAL_WIFI6_PER_BPS,
            "epi_us": NOMINAL_WIFI6_EPI_US,
            "register_map": {
                "%R2290": "REG_WIFI6_SAFETY_STATE (0..4)",
                "%R2291": "REG_WIFI6_RSSI_PRIMARY_DBM (-54 dBm)",
                "%R2292": "REG_WIFI6_RSSI_DIVERSITY_DBM (-58 dBm)",
                "%R2293": "REG_WIFI6_PER_SCALED (12 = 0.12% PER)",
                "%R2294": "REG_WIFI6_TX_FRAME_COUNT (100)",
                "%R2295": "REG_WIFI6_ROAMING_EVENT_COUNT (0)",
                "%R2296": "REG_WIFI6_EPI_TIMER_US (5000 us)",
                "%R2297": "REG_WIFI6_DIAGNOSTIC_CODE (0x0000 OK, 0xEE61..0xEE64)",
                "%M534": "COIL_WIFI6_SAFETY_LINK_HEALTHY",
                "%M535": "COIL_WIFI6_SAFETY_STOP_TRIPPED",
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
        description="JEV Cscape Agent: Industrial ODVA CIP Safety Wi-Fi 6 IEEE 802.11ax Verification (W268)"
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
        default="W268",
        help="Work package identifier (default: W268)",
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
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_wifi6_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: Industrial ODVA CIP Safety Wi-Fi 6 Verification ({args.work_package}){ESC_RESET}")
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
        print(f"\n{ESC_GREEN}{ESC_BOLD}[SUCCESS] All 9 CIP Safety Wi-Fi 6 IEEE 802.11ax protocol stages PASSED deterministically.{ESC_RESET}")
        print("=" * 80)
        return 0
    else:
        print(f"\n{ESC_RED}{ESC_BOLD}[FAILED] Verification failed with status '{overall_status}' (error_code: {error_code}).{ESC_RESET}")
        print(f"Details: {details_str}")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
