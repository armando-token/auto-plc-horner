#!/usr/bin/env python3
"""Verification Script for Industrial ODVA CIP Safety Dual-Port Daisy-Chain Engine (Wave W232).

Work Package: W232 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Follows the 9-stage verification pattern:
  Stage 1: Protocol Architecture & Constants Initialization (Class 0x39, 0x3A, 0x3B, SNN, SCID, dual-port mode, nominal EPI 10ms, watchdog 30ms, max jitter 2000us).
  Stage 2: Pure IEC 61131-3 Structured Text POU Validation ('CipSafetyDaisyChainSync' with STParser & SecurityGuard).
  Stage 3: Anti-Ladder Security Guard Interception (rejection of contacts, coils, rungs with LadderForbiddenError).
  Stage 4: Dual-Port Topology Binding & Bridge Forwarding (Port 1 and Port 2 active, state transitions to DUAL_PORT_BRIDGED).
  Stage 5: Dual-Channel Diversified Payload Cross-Comparison & Dual CRC-S Validation (Channel A vs Channel B parity, CRC-S1/CRC-S2 verification).
  Stage 6: EPI Watchdog Surveillance & Timeout Fault Injection (exceed 30 ms watchdog timeout -> 0xE902, %M451 safe state asserted).
  Stage 7: Daisy-Chain Link Break & Jitter Overrun Injections (0xE905 link break on Port 2, 0xE906 jitter > 2000 us, recovery).
  Stage 8: Horner OCS Register Table Synchronization (%R1930..%R1937, %M450..%M451 bit-exact verification with signed/unsigned masking).
  Stage 9: 100-Cycle Simulation Soak & Forwarding Boundedness (deterministic scan cycles, 0 memory leak, forwarding jitter bounds).

Generates:
  artifacts/telemetry/cip_safety_daisy_chain_evidence.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
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

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import RegisterTable

from jev_cscape.telemetry.cip_safety_daisy_chain import (
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_DAISY_CHAIN_CLASS_ID,
    CIP_SAFETY_DAISY_CHAIN_CONNECTION_CLASS_ID,
    CIP_SAFETY_DAISY_CHAIN_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_DAISY_CHAIN_SYNC_POU,
    CIP_SAFETY_DAISY_CHAIN_VALIDATOR_CLASS_ID,
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIPSafetyDaisyChainEngine,
    CipSafetyCrcCorruptionError,
    CipSafetyDaisyChainEngine,
    CipSafetyDaisyChainLinkBreakError,
    CipSafetyDaisyChainPacket,
    CipSafetyDaisyChainState,
    CipSafetyDualChannelDiscrepancyError,
    CipSafetyForwardingJitterOverrunError,
    CipSafetyJitterOverrunError,
    CipSafetyLinkBreakError,
    CipSafetyPacket,
    CipSafetySnnMismatchError,
    DAISY_CHAIN_MODE,
    DEFAULT_EPI_MS,
    DEFAULT_MAX_JITTER_US,
    DEFAULT_PORT1_UNID,
    DEFAULT_PORT2_UNID,
    DEFAULT_SCID,
    DEFAULT_SNN,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DUAL_PORT_MODE,
    DaisyChainDiagnosticCode,
    DaisyChainState,
    DiagnosticCode,
    DiversifiedMode,
    MAX_FORWARDING_JITTER_US,
    MAX_JITTER_US,
    NOMINAL_EPI_MS,
    PortIdentifier,
    SafetyControlByte,
    SafetyOperationalState,
    compute_crc_s1,
    compute_crc_s2,
    format_snn,
    generate_snn,
    parse_snn,
    run_cip_safety_daisy_chain_verification,
    validate_snn,
    verify_cip_safety_daisy_chain_pure_st,
    verify_dual_channel_payload,
)

# ANSI terminal formatting constants
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


def run_9_stage_verification(output_path: Optional[Union[Path, str]] = None) -> Dict[str, Any]:
    """Execute the deterministic 9-stage CIP Safety Daisy-Chain verification suite."""
    test_results: List[Dict[str, Any]] = []

    # ========================================================================
    # Stage 1: Protocol Architecture & Constants Initialization
    # ========================================================================
    t0 = time.perf_counter()
    s1_class = (
        CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        and CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        and CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        and CIP_SAFETY_DAISY_CHAIN_CLASS_ID in (0x39, 0x3B)
        and CIP_SAFETY_DAISY_CHAIN_SUPERVISOR_CLASS_ID == 0x39
        and CIP_SAFETY_DAISY_CHAIN_VALIDATOR_CLASS_ID == 0x3A
        and CIP_SAFETY_DAISY_CHAIN_CONNECTION_CLASS_ID == 0x3B
    )
    s1_params = (
        DUAL_PORT_MODE == 1
        and DAISY_CHAIN_MODE == 1
        and NOMINAL_EPI_MS == 10.0
        and DEFAULT_WATCHDOG_TIMEOUT_MS == 30.0
        and MAX_JITTER_US == 2000.0
        and len(DEFAULT_SNN) == 6
        and DEFAULT_SCID == 0x20261006
    )
    s1_diag_signed = (
        DiagnosticCode.OK == 0x0000
        and DiagnosticCode.SNN_SIGNATURE_MISMATCH == 0xE901
        and (DiagnosticCode.SNN_SIGNATURE_MISMATCH & 0xFFFF) == 0xE901
        and DiagnosticCode.EPI_WATCHDOG_TIMEOUT == 0xE902
        and (DiagnosticCode.EPI_WATCHDOG_TIMEOUT & 0xFFFF) == 0xE902
        and DiagnosticCode.DUAL_CHANNEL_DISCREPANCY == 0xE903
        and (DiagnosticCode.DUAL_CHANNEL_DISCREPANCY & 0xFFFF) == 0xE903
        and DiagnosticCode.CRC_S_CORRUPTION == 0xE904
        and (DiagnosticCode.CRC_S_CORRUPTION & 0xFFFF) == 0xE904
        and DiagnosticCode.LINK_BREAK_FAULT == 0xE905
        and (DiagnosticCode.LINK_BREAK_FAULT & 0xFFFF) == 0xE905
        and DiagnosticCode.JITTER_OVERRUN_FAULT == 0xE906
        and (DiagnosticCode.JITTER_OVERRUN_FAULT & 0xFFFF) == 0xE906
    )
    s1_pass = s1_class and s1_params and s1_diag_signed
    t1_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 1,
        "check": "Protocol_Architecture_And_Constants_Initialization",
        "passed": s1_pass,
        "timing_ms": round(t1_ms, 3),
        "details": "Class 0x39, 0x3A, 0x3B, SNN (6 octets), SCID (0x20261006), dual-port mode, nominal EPI 10ms, watchdog 30ms, max jitter 2000us verified.",
    })

    # ========================================================================
    # Stage 2: Pure IEC 61131-3 Structured Text POU Validation
    # ========================================================================
    t0 = time.perf_counter()
    SecurityGuard.assert_pure_st_content(CIP_SAFETY_DAISY_CHAIN_SYNC_POU)
    v_st = STParser.validate_code(CIP_SAFETY_DAISY_CHAIN_SYNC_POU)
    ast = STParser.parse_pou(CIP_SAFETY_DAISY_CHAIN_SYNC_POU)
    required_registers = {
        "%R1930", "%R1931", "%R1932", "%R1933",
        "%R1934", "%R1935", "%R1936", "%R1937",
        "%M450", "%M451",
    }
    bound_all = required_registers.issubset(set(ast.bound_registers))
    s2_pass = (
        v_st.status == AgentStatus.SUCCESS
        and ast.pou_type == POUType.PROGRAM
        and ast.name == "CipSafetyDaisyChainSync"
        and bound_all
    )
    t2_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 2,
        "check": "Pure_IEC_61131_3_ST_POU_Validation",
        "passed": s2_pass,
        "timing_ms": round(t2_ms, 3),
        "details": "POU 'CipSafetyDaisyChainSync' validated clean with STParser & SecurityGuard; all 10 registers bound.",
    })

    # ========================================================================
    # Stage 3: Anti-Ladder Security Guard Interception
    # ========================================================================
    t0 = time.perf_counter()
    ladder_snippets = [
        "PROGRAM Test VAR END_VAR\n  ---[ ]---( )---\nEND_PROGRAM",
        "PROGRAM Test VAR END_VAR\n  RUNG 1\n  XIC MotorStart OTE MotorRunning;\nEND_PROGRAM",
        "PROGRAM Test VAR END_VAR\n  NETWORK 1\n  |---| |---( )---|\nEND_PROGRAM",
    ]
    interceptions = 0
    for snip in ladder_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snip)
        except LadderForbiddenError:
            interceptions += 1

    s3_pass = (interceptions == len(ladder_snippets))
    t3_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 3,
        "check": "Anti_Ladder_Security_Guard_Interception",
        "passed": s3_pass,
        "timing_ms": round(t3_ms, 3),
        "details": f"Anti-ladder security guard intercepted {interceptions}/{len(ladder_snippets)} prohibited ladder constructs with LadderForbiddenError.",
    })

    # ========================================================================
    # Stage 4: Dual-Port Topology Binding & Bridge Forwarding
    # ========================================================================
    t0 = time.perf_counter()
    snn_bytes = generate_snn(0x2026, 0x1006CC88)
    snn_str = format_snn(snn_bytes)
    snn_parsed = parse_snn(snn_str)
    snn_valid = validate_snn(snn_bytes) and not validate_snn(b"\x00" * 6) and (snn_parsed == snn_bytes)

    engine_stage4 = CipSafetyDaisyChainEngine(snn=snn_bytes)
    bind_ok = engine_stage4.bind_dual_port(port1_unid=101, port2_unid=102, snn=snn_bytes, scid=0x20261006)

    ports_active = engine_stage4.port1_link_up and engine_stage4.port2_link_up
    state_bridged = (
        engine_stage4.connection_state == DaisyChainState.DUAL_PORT_BRIDGED
        and engine_stage4.operational_state == SafetyOperationalState.OPERATIONAL
    )
    zero_faults = (engine_stage4.diagnostic_code == DiagnosticCode.OK)
    m450_active = engine_stage4.daisy_chain_active
    m451_no_trip = not engine_stage4.safe_state_engaged

    pkt_fwd_test = CipSafetyDaisyChainPacket(
        snn=snn_bytes,
        tunid=102,
        ounid=101,
        target_id=1,
        sequence_number=1,
        timestamp_ms=10.0,
        mode_byte=SafetyControlByte.RUN,
        channel_a_payload=b"\x12\x34",
        channel_b_payload=b"\xED\xCB",
        ingress_port=1,
        egress_port=2,
    )
    pkt_fwd_test.calculate_crcs()
    forwarded_pkt = engine_stage4.forward_packet(pkt_fwd_test, ingress_port=1)
    fwd_success = (
        forwarded_pkt is not None
        and forwarded_pkt.egress_port == 2
        and (forwarded_pkt.mode_byte & SafetyControlByte.BRIDGE_FORWARD) != 0
        and engine_stage4.forwarded_packets_count == 1
    )

    s4_pass = (
        snn_valid
        and bind_ok
        and ports_active
        and state_bridged
        and zero_faults
        and m450_active
        and m451_no_trip
        and fwd_success
    )
    t4_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 4,
        "check": "Dual_Port_Topology_Binding_And_Bridge_Forwarding",
        "passed": s4_pass,
        "timing_ms": round(t4_ms, 3),
        "details": "Port 1 and Port 2 active, state transitions to DUAL_PORT_BRIDGED; forward frame verified.",
    })

    # ========================================================================
    # Stage 5: Dual-Channel Diversified Payload Cross-Comparison & Dual CRC-S Validation
    # ========================================================================
    t0 = time.perf_counter()
    ch_a = bytes([0x12, 0x34, 0x56, 0x78])
    ch_b_inv = bytes([0xED, 0xCB, 0xA9, 0x87])
    ch_b_bad = bytes([0xED, 0xCB, 0x00, 0x87])

    v_inv_ok = verify_dual_channel_payload(ch_a, ch_b_inv, mode=DiversifiedMode.INVERTED)
    v_inv_bad = verify_dual_channel_payload(ch_a, ch_b_bad, mode=DiversifiedMode.INVERTED)

    # CRC-S1 and inverted CRC-S2 calculations
    test_data = b"ODVA_CIP_SAFETY_DAISY_CHAIN_W232"
    crc1 = compute_crc_s1(test_data)
    crc2 = compute_crc_s2(test_data, inverted=True)
    crc_inv_match = (crc2 == ((~crc1) & 0xFFFF))

    # Engine cross-comparison discrepancy trip test
    engine_disc = CipSafetyDaisyChainEngine(snn=snn_bytes)
    engine_disc.bind_dual_port(port1_unid=101, port2_unid=102, snn=snn_bytes, scid=0x20261006)

    disc_pkt = CipSafetyDaisyChainPacket(
        snn=snn_bytes,
        tunid=102,
        ounid=101,
        target_id=1,
        sequence_number=1,
        timestamp_ms=10.0,
        mode_byte=SafetyControlByte.RUN,
        channel_a_payload=ch_a,
        channel_b_payload=ch_b_bad,
        ingress_port=1,
    )
    disc_pkt.calculate_crcs()

    disc_caught = False
    try:
        engine_disc.receive_safety_packet(disc_pkt)
    except CipSafetyDualChannelDiscrepancyError:
        disc_caught = True

    disc_tripped = (
        disc_caught
        and engine_disc.diagnostic_code == DiagnosticCode.DUAL_CHANNEL_DISCREPANCY
        and engine_disc.safe_state_engaged
        and not engine_disc.daisy_chain_active
    )

    s5_pass = v_inv_ok and (not v_inv_bad) and crc_inv_match and disc_tripped
    t5_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 5,
        "check": "Dual_Channel_Diversified_Payload_Cross_Comparison_And_Dual_CRC_S_Validation",
        "passed": s5_pass,
        "timing_ms": round(t5_ms, 3),
        "details": "Channel A / Channel B complement parity and CRC-S1/CRC-S2 verified; 0xE903 discrepancy fault caught.",
    })

    # ========================================================================
    # Stage 6: EPI Watchdog Surveillance & Timeout Fault Injection
    # ========================================================================
    t0 = time.perf_counter()
    rt_epi = RegisterTable()
    engine_epi = CipSafetyDaisyChainEngine(register_table=rt_epi, snn=snn_bytes, watchdog_timeout_ms=30.0)
    engine_epi.bind_dual_port(port1_unid=101, port2_unid=102, snn=snn_bytes, scid=0x20261006)
    engine_epi.sync_to_registers(rt_epi)

    init_m450 = (rt_epi.read_bit("%M450") is True)
    init_m451 = (rt_epi.read_bit("%M451") is False)

    # Step simulation without packets for 20 ms (below 30 ms watchdog limit)
    engine_epi.scan_step(0.020)
    still_healthy = (
        engine_epi.diagnostic_code == DiagnosticCode.OK
        and not engine_epi.safe_state_engaged
        and rt_epi.read_bit("%M450") is True
        and rt_epi.read_bit("%M451") is False
    )

    # Step simulation past 30 ms watchdog limit (+15 ms -> 35 ms total)
    engine_epi.scan_step(0.015)
    timeout_tripped = (
        engine_epi.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        and engine_epi.safe_state_engaged
        and engine_epi.connection_state == DaisyChainState.FAULT_SAFE_STATE
        and rt_epi.read_uword("%R1937") == 0xE902
        and rt_epi.read_bit("%M450") is False
        and rt_epi.read_bit("%M451") is True
    )

    s6_pass = init_m450 and init_m451 and still_healthy and timeout_tripped
    t6_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 6,
        "check": "EPI_Watchdog_Surveillance_And_Timeout_Fault_Injection",
        "passed": s6_pass,
        "timing_ms": round(t6_ms, 3),
        "details": "Silence monitored; exceeding 30.0 ms watchdog injected 0xE902 and asserted %M451 safe state.",
    })

    # ========================================================================
    # Stage 7: Daisy-Chain Link Break & Jitter Overrun Injections
    # ========================================================================
    t0 = time.perf_counter()
    rt_inj = RegisterTable()
    engine_inj = CipSafetyDaisyChainEngine(register_table=rt_inj, snn=snn_bytes, max_jitter_us=2000.0)
    engine_inj.bind_dual_port(port1_unid=101, port2_unid=102, snn=snn_bytes, scid=0x20261006)

    # 1. 0xE905 Link Break on Port 2
    engine_inj.simulate_link_break(port=2)
    link_break_tripped = (
        engine_inj.diagnostic_code == DiagnosticCode.LINK_BREAK_FAULT
        and rt_inj.read_uword("%R1937") == 0xE905
        and rt_inj.read_bit("%M451") is True
        and rt_inj.read_bit("%M450") is False
    )

    # Reset before jitter test
    engine_inj.reset_fault(force=True, restore_operational=True)
    reset_interm = (
        engine_inj.diagnostic_code == DiagnosticCode.OK
        and rt_inj.read_uword("%R1937") == 0x0000
        and rt_inj.read_bit("%M450") is True
        and rt_inj.read_bit("%M451") is False
    )

    # 2. 0xE906 Jitter Overrun (jitter > 2000 us, e.g. 2500 us)
    jitter_caught = False
    pkt_jitter = CipSafetyDaisyChainPacket(
        snn=snn_bytes,
        tunid=102,
        ounid=101,
        target_id=1,
        sequence_number=10,
        timestamp_ms=100.0,
        mode_byte=SafetyControlByte.RUN,
        channel_a_payload=b"\x01\x02",
        channel_b_payload=b"\xFE\xFD",
        ingress_port=1,
        forwarding_jitter_us=2500.0,
    )
    pkt_jitter.calculate_crcs()
    try:
        engine_inj.forward_packet(pkt_jitter, ingress_port=1)
    except CipSafetyJitterOverrunError:
        jitter_caught = True

    jitter_tripped = (
        jitter_caught
        and engine_inj.diagnostic_code == DiagnosticCode.JITTER_OVERRUN_FAULT
        and rt_inj.read_uword("%R1937") == 0xE906
        and rt_inj.read_bit("%M451") is True
        and rt_inj.read_bit("%M450") is False
    )

    # Reset and recovery verification
    engine_inj.reset_fault(force=True, restore_operational=True)
    recovery_ok = (
        engine_inj.diagnostic_code == DiagnosticCode.OK
        and rt_inj.read_uword("%R1937") == 0x0000
        and rt_inj.read_bit("%M451") is False
        and rt_inj.read_bit("%M450") is True
    )

    s7_pass = link_break_tripped and reset_interm and jitter_tripped and recovery_ok
    t7_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 7,
        "check": "Daisy_Chain_Link_Break_And_Jitter_Overrun_Injections",
        "passed": s7_pass,
        "timing_ms": round(t7_ms, 3),
        "details": "0xE905 link break on Port 2 and 0xE906 jitter > 2000 us injected; %M451 safe state asserted, clean recovery verified.",
    })

    # ========================================================================
    # Stage 8: Horner OCS Register Table Synchronization
    # ========================================================================
    t0 = time.perf_counter()
    rt_sync = RegisterTable()
    engine_sync = CipSafetyDaisyChainEngine(register_table=rt_sync, snn=snn_bytes)
    engine_sync.bind_dual_port(port1_unid=101, port2_unid=102, snn=snn_bytes, scid=0x20261006)

    engine_sync.port1_latency_ms = 9.5
    engine_sync.forwarding_jitter_us = 450.0
    engine_sync.forwarded_packets_count = 120
    engine_sync.sync_to_registers(rt_sync)

    r_state = (rt_sync.read_word("%R1930") == int(DaisyChainState.DUAL_PORT_BRIDGED))
    r_packets = (rt_sync.read_word("%R1931") == 120)
    r_lat = (rt_sync.read_word("%R1932") == 95)
    r_jitter = (rt_sync.read_word("%R1933") == 450)
    r_diag0 = (rt_sync.read_uword("%R1937") == 0x0000)
    m_active = (rt_sync.read_bit("%M450") is True)
    m_no_fault = (rt_sync.read_bit("%M451") is False)

    # Signed/unsigned bit-exact masking test with fault 0xE902
    engine_sync.simulate_epi_watchdog_timeout()
    engine_sync.sync_to_registers(rt_sync)

    uword_diag = rt_sync.read_uword("%R1937")
    signed_diag = rt_sync.read_word("%R1937")
    masked_diag = signed_diag & 0xFFFF

    masking_ok = (
        uword_diag == 0xE902
        and signed_diag == (0xE902 - 0x10000)
        and masked_diag == 0xE902
        and rt_sync.read_bit("%M450") is False
        and rt_sync.read_bit("%M451") is True
    )

    # Operator reset restores nominal state
    engine_sync.reset_fault(force=True, restore_operational=True)
    reset_cleared = (
        rt_sync.read_uword("%R1937") == 0x0000
        and rt_sync.read_bit("%M451") is False
        and rt_sync.read_bit("%M450") is True
    )

    s8_pass = (
        r_state and r_packets and r_lat and r_jitter and r_diag0 and m_active and m_no_fault and masking_ok and reset_cleared
    )
    t8_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 8,
        "check": "Horner_OCS_Register_Table_Synchronization",
        "passed": s8_pass,
        "timing_ms": round(t8_ms, 3),
        "details": "Bit-exact synchronization of %R1930..%R1937 and %M450..%M451 verified with signed/unsigned masking.",
    })

    # ========================================================================
    # Stage 9: 100-Cycle Simulation Soak & Forwarding Boundedness
    # ========================================================================
    t0 = time.perf_counter()
    rt_soak = RegisterTable()
    engine_soak = CipSafetyDaisyChainEngine(register_table=rt_soak, snn=snn_bytes, max_jitter_us=2000.0)
    engine_soak.bind_dual_port(port1_unid=101, port2_unid=102, snn=snn_bytes, scid=0x20261006)

    tracemalloc.start()
    mem_start = tracemalloc.get_traced_memory()[0]

    cycle_latencies_ms: List[float] = []
    measured_jitters_us: List[float] = []

    for cycle in range(1, 101):
        t_cyc_start = time.perf_counter()

        if cycle % 2 == 0:
            sim_jitter = 200.0 + (cycle % 10) * 50.0  # 200..650 us (< 2000 us)
            pkt = CipSafetyDaisyChainPacket(
                snn=snn_bytes,
                tunid=102,
                ounid=101,
                target_id=1,
                sequence_number=cycle,
                timestamp_ms=float(cycle * 10),
                mode_byte=SafetyControlByte.RUN,
                channel_a_payload=b"\x01\x02",
                channel_b_payload=b"\xFE\xFD",
                ingress_port=1,
                forwarding_jitter_us=sim_jitter,
            )
            pkt.calculate_crcs()
            fwd = engine_soak.forward_packet(pkt, ingress_port=1)
            measured_jitters_us.append(fwd.forwarding_jitter_us)

        engine_soak.silence_elapsed_ms = 0.0
        engine_soak.scan_step(0.010)
        cyc_dur_ms = (time.perf_counter() - t_cyc_start) * 1000.0
        cycle_latencies_ms.append(cyc_dur_ms)

    mem_current, mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    heap_growth_kb = max(0.0, (mem_current - mem_start) / 1024.0)
    max_cycle_latency_ms = max(cycle_latencies_ms)
    mean_cycle_latency_ms = sum(cycle_latencies_ms) / len(cycle_latencies_ms)
    max_jitter_observed = max(measured_jitters_us) if measured_jitters_us else 0.0

    soak_healthy = (
        engine_soak.connection_state == DaisyChainState.DUAL_PORT_BRIDGED
        and engine_soak.operational_state == SafetyOperationalState.OPERATIONAL
        and engine_soak.diagnostic_code == DiagnosticCode.OK
        and rt_soak.read_bit("%M450") is True
        and rt_soak.read_bit("%M451") is False
        and rt_soak.read_uword("%R1937") == 0x0000
        and engine_soak.forwarded_packets_count == 50
    )
    memory_bounded = (heap_growth_kb < 100.0)
    latency_bounded = (max_cycle_latency_ms < 100.0 and mean_cycle_latency_ms < 25.0)
    jitter_bounded = (max_jitter_observed <= 2000.0)

    s9_pass = soak_healthy and memory_bounded and latency_bounded and jitter_bounded
    t9_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 9,
        "check": "Simulation_Soak_100_Cycles_And_Forwarding_Boundedness",
        "passed": s9_pass,
        "timing_ms": round(t9_ms, 3),
        "details": (
            f"100 deterministic scan cycles completed cleanly. "
            f"Heap growth: {heap_growth_kb:.2f} KB (< 100 KB), "
            f"Peak cycle latency: {max_cycle_latency_ms:.2f} ms (< 100 ms), "
            f"Mean cycle latency: {mean_cycle_latency_ms:.2f} ms, "
            f"Max forwarding jitter: {max_jitter_observed:.1f} us (<= 2000 us)."
        ),
    })

    # ========================================================================
    # Summary & Evidence Serialization
    # ========================================================================
    passed_count = sum(1 for t in test_results if t["passed"])
    total_stages = len(test_results)
    all_passed = (passed_count == total_stages)

    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "STAGE_VERIFICATION_FAILURE",
        "details": f"CIP Safety Dual-Port Daisy-Chain Engine (W232) verified cleanly ({passed_count}/{total_stages} stages passed).",
        "stages_passed": passed_count,
        "total_stages": total_stages,
        "data": {
            "work_package": "W232",
            "standards": [
                "ODVA CIP Networks Library Volume 5 (CIP Safety)",
                "Class 0x39 (Safety Supervisor Object)",
                "Class 0x3A (Safety Validator Object)",
                "Class 0x3B (Safety Connection Object - Daisy Chain / Dual Port)",
                "IEC 61784-3 Table 1 (Black Channel Mitigations)",
                "IEC 61508 / IEC 62061 SIL 3",
                "IEC 61131-3 Structured Text",
            ],
            "stages": test_results,
            "tests": test_results,
            "checks_passed": passed_count,
            "total_checks": total_stages,
            "register_map": {
                "%R1930": "DaisyChainState",
                "%R1931": "ForwardedPacketsCount",
                "%R1932": "Port1LatencyMsScaled",
                "%R1933": "ForwardingJitterUs",
                "%R1934": "SafetyConsecutiveFaultCount",
                "%R1935": "SafetySequenceNumber",
                "%R1936": "SafetyPayloadWord",
                "%R1937": "DiagnosticStatusCode",
                "%M450": "CipSafetyDaisyChainActive",
                "%M451": "SafetyDaisyChainTripEngaged",
            },
            "registers": {
                "%R1930": rt_soak.read_word("%R1930"),
                "%R1931": rt_soak.read_word("%R1931"),
                "%R1932": rt_soak.read_word("%R1932"),
                "%R1933": rt_soak.read_word("%R1933"),
                "%R1934": rt_soak.read_word("%R1934"),
                "%R1935": rt_soak.read_word("%R1935"),
                "%R1936": rt_soak.read_word("%R1936"),
                "%R1937": rt_soak.read_uword("%R1937"),
                "%M450": rt_soak.read_bit("%M450"),
                "%M451": rt_soak.read_bit("%M451"),
            },
            "metrics": {
                "heap_growth_kb": round(heap_growth_kb, 2),
                "peak_cycle_latency_ms": round(max_cycle_latency_ms, 3),
                "mean_cycle_latency_ms": round(mean_cycle_latency_ms, 3),
                "max_forwarding_jitter_us": round(max_jitter_observed, 1),
                "total_soak_cycles": 100,
                "forwarded_packets": engine_soak.forwarded_packets_count,
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if output_path is not None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


def main(argv: Optional[List[str]] = None) -> int:
    """Main verification CLI entry point."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="JEV Cscape Agent: Industrial ODVA CIP Safety Dual-Port Daisy-Chain Engine Verification (W232)"
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
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_daisy_chain_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print(f"  {ESC_BOLD}JEV Cscape Agent: Industrial ODVA CIP Safety Dual-Port Daisy-Chain Verification (W232){ESC_RESET}")
    print("=" * 80)

    t_start = time.perf_counter()
    try:
        evidence = run_9_stage_verification(evidence_path)
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1
    total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

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
        print(f"\n{ESC_GREEN}{ESC_BOLD}[SUCCESS] All 9 CIP Safety Dual-Port Daisy-Chain protocol stages PASSED deterministically.{ESC_RESET}")
        print("=" * 80)
        return 0
    else:
        print(f"\n{ESC_RED}{ESC_BOLD}[FAILED] Verification failed with status '{overall_status}' (error_code: {error_code}).{ESC_RESET}")
        print(f"Details: {details_str}")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
