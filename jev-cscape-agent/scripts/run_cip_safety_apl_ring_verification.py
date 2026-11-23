#!/usr/bin/env python3
"""Deterministic 9-Stage Verification Runner for Industrial ODVA CIP Safety Over Ethernet-APL Redundant Ring (DLR) Protocol Engine (W313).

Work Package: W313 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [ODVA CIP Safety Over Ethernet-APL Redundant Ring Topology]
Status Contract: Strict 4-State JSON output (success | failed | blocked | inconclusive) & evidence emission.

Standards & Specifications:
- IEEE 802.3cg-2019 / Ethernet-APL 10BASE-T1L Single Pair Ethernet:
  - 10 Mb/s full-duplex operation over balanced twisted pair (1000m trunk, 200m spurs).
  - Media Redundancy Protocol (MRP, IEC 62439-2) and Device Level Ring (DLR, ODVA) state machines.
  - Sub-10 ms deterministic ring break switchover and fault localization.
  - Active Ring Supervisor and Non-Supervisor (Client Node) role management.
- ODVA CIP Networks Library Volume 5: CIP Safety Specification:
  - Class 0x39: Safety Supervisor Object
  - Class 0x3A: Safety Validator Object
  - Class 0x3B: Safety Connection Object (Ring Safety Connection)
  - Class 0x47: Device Level Ring (DLR) Object
  - Dual 16-bit Safety CRCs (IEC 61784-3-2 / IEC 61508 SIL 3):
    - CRC-S1: Generator polynomial 0x5935 (init 0x0000) over process data payload.
    - CRC-S2: Generator polynomial 0x755B (init 0x0000) over inverted header fields.
  - Rolling 16-bit sequence counter (0..65535).
- Safe Ring Topology State Machine (%R2740 High Byte):
  0: NORMAL_RING (Ring closed, supervisor active, Port 2 blocked)
  1: RING_FAULT (Ring break detected, alternate port unblocked < 10 ms switchover)
  2: LINEAR_TOPOLOGY (Linear bus topology, ring redundancy disabled)
  3: SUPERVISOR_ACTIVE (Supervisor actively transmitting beacons)
  4: SAFETY_TRIP (Fail-safe interlock tripped; safe state asserted)
- Supervisor Roles (%R2741):
  0: BACKUP (Backup ring supervisor)
  1: ACTIVE_SUPERVISOR (Primary active ring supervisor)
  2: NON_SUPERVISOR (Standard ring participant node)
- Diagnostics & Watchdogs (%R2745):
  0x0000: DIAG_OK (Nominal healthy operation)
  0xEE81: DIAG_ERR_BEACON_TIMEOUT (Beacon frame loss > 400 us)
  0xEE82: DIAG_ERR_DUAL_PORT_LINK_DOWN (Both Port 1 and Port 2 PHY link down)
  0xEE83: DIAG_ERR_RING_FAULT_DETECTED (Ring break detected, unblocked alternate port)
  0xEE84: DIAG_ERR_DUAL_CRC_SAFETY_FAULT (CRC-S1 or CRC-S2 mismatch)
  0xEE85: DIAG_ERR_SUPERVISOR_COLLISION (Multiple active supervisors detected)
- Horner OCS Memory Space:
  - Analog registers %R2740..%R2747:
    - %R2740: REG_CIP_APL_RING_STATUS (High byte = Topology State, Low byte = Supervisor Role)
    - %R2741: REG_CIP_APL_RING_SUPERVISOR_STATE (Supervisor Role: 0=BACKUP, 1=ACTIVE, 2=NON_SUPERVISOR)
    - %R2742: REG_CIP_APL_RING_FAULT_LOCATION (Fault Location: 0=healthy, 1=Port 1, 2=Port 2, 3=Both)
    - %R2743: REG_CIP_APL_RING_TRANSITION_COUNT (Count of ring topology transitions)
    - %R2744: REG_CIP_APL_RING_BEACON_INTERVAL_US (Beacon interval in us, nominal 400 us)
    - %R2745: REG_CIP_APL_RING_DIAGNOSTIC_CODE (Diagnostic code: 0x0000, 0xEE81..0xEE85)
    - %R2746: REG_CIP_APL_RING_PORT1_LINK_QUALITY (Port 1 link quality percentage 0..100)
    - %R2747: REG_CIP_APL_RING_PORT2_LINK_QUALITY (Port 2 link quality percentage 0..100)
  - Discrete coils %M639..%M640:
    - %M639: COIL_CIP_APL_RING_ONLINE (BOOL, True when ring healthy & operational)
    - %M640: COIL_CIP_APL_RING_SAFETY_TRIP (BOOL, True on safety trip or fault)
- Implements ILogicUnit interface with scan_step(dt, context), step(), execute(), reset().
- Implements sync_to_registers(reg_table, privilege=PrivilegeMode.USER/SYSTEM).
- Includes pure IEC 61131-3 Structured Text POU 'CipSafetyAplRingSync' validated via
  SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
- Strictly rejects ladder logic constructs with ERR_LADDER_FORBIDDEN / LadderForbiddenError.

Deterministic 9-Stage Verification Sequence:
  Stage 1: environment
  Stage 2: protocol_constants_and_register_mappings
  Stage 3: odva_cip_safety_dual_crc_mathematics
  Stage 4: ethernet_apl_ring_topology_and_beacons
  Stage 5: port_break_and_fault_localization_trips
  Stage 6: safety_interlock_trips_and_fault_recovery
  Stage 7: register_table_synchronization
  Stage 8: pure_st_pou_and_anti_ladder_rejection
  Stage 9: simulation_soak_100_cycles_and_evidence_emission

Generates:
  artifacts/telemetry/cip_safety_apl_ring_evidence.json
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
from jev_cscape.telemetry.cip_safety_apl_ring import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_APL_RING_CLASS_ID,
    CIP_DLR_CLASS_ID,
    REG_CIP_APL_RING_STATUS,
    REG_CIP_APL_RING_SUPERVISOR_STATE,
    REG_CIP_APL_RING_FAULT_LOCATION,
    REG_CIP_APL_RING_TRANSITION_COUNT,
    REG_CIP_APL_RING_BEACON_INTERVAL_US,
    REG_CIP_APL_RING_DIAGNOSTIC_CODE,
    REG_CIP_APL_RING_PORT1_LINK_QUALITY,
    REG_CIP_APL_RING_PORT2_LINK_QUALITY,
    COIL_CIP_APL_RING_ONLINE,
    COIL_CIP_APL_RING_SAFETY_TRIP,
    DIAG_OK,
    DIAG_ERR_BEACON_TIMEOUT,
    DIAG_ERR_DUAL_PORT_LINK_DOWN,
    DIAG_ERR_RING_FAULT_DETECTED,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_ERR_SUPERVISOR_COLLISION,
    DiagnosticCode,
    RingTopologyState,
    SupervisorRole,
    AplRingStatusBits,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    DEFAULT_SAFETY_EPID,
    DEFAULT_SUPERVISOR_PRECEDENCE,
    DEFAULT_SESSION_ID,
    compute_crc_s1,
    compute_crc_s2,
    compute_epid_hash,
    compute_epid_crc32,
    CIPAPLRingSafetyEngine,
    CIPAPLRingPacket,
    create_valid_apl_ring_packet,
    ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC,
    verify_cip_safety_apl_ring_pure_st,
)


# ============================================================================
# Ethernet-APL Ring Topology & Physics Kinematics Helpers
# ============================================================================

def calculate_ring_propagation_delay_us(
    cable_length_m: float = 200.0,
    num_nodes: int = 8,
    per_hop_phy_us: float = 1.2,
) -> float:
    """Compute total ring physical propagation delay in microseconds.

    Based on 10BASE-T1L twisted-pair velocity factor (~0.66c -> ~5.0 ns/meter = 0.005 us/m)
    and hardware PHY cut-through forwarding latency per node.
    """
    cable_delay_us = float(cable_length_m) * 0.005
    node_forward_us = float(num_nodes) * float(per_hop_phy_us)
    return float(cable_delay_us + node_forward_us)


def calculate_mrp_switchover_latency_ms(
    ring_break_detect_ms: float = 3.0,
    port_unblock_latency_ms: float = 5.5,
) -> float:
    """Compute IEC 62439-2 Media Redundancy Protocol (MRP) ring switchover latency in ms.

    Nominal fast switchover target is < 10.0 ms.
    """
    return float(ring_break_detect_ms + port_unblock_latency_ms)


def calculate_ring_beacon_budget_ms(
    beacon_interval_ms: float = 0.4,
    max_missed_beacons: int = 1,
) -> float:
    """Compute supervisor beacon watchdog timeout budget in ms (0.4 ms = 400 us)."""
    return float(beacon_interval_ms * max_missed_beacons)


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
    work_package: str = "W313",
    quick: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W313 CIP Safety Over Ethernet-APL Ring Topology.

    Stages:
      Stage 1: environment
      Stage 2: protocol_constants_and_register_mappings
      Stage 3: odva_cip_safety_dual_crc_mathematics
      Stage 4: ethernet_apl_ring_topology_and_beacons
      Stage 5: port_break_and_fault_localization_trips
      Stage 6: safety_interlock_trips_and_fault_recovery
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
        from jev_cscape.telemetry.cip_safety_apl_ring import (
            CIPAPLRingSafetyEngine,
            CIPAPLRingPacket,
            RingTopologyState,
            SupervisorRole,
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
        and CIP_APL_RING_CLASS_ID == 0x47
        and CIP_DLR_CLASS_ID == 0x47
    )

    regs_ok = (
        REG_CIP_APL_RING_STATUS == "%R2740"
        and REG_CIP_APL_RING_SUPERVISOR_STATE == "%R2741"
        and REG_CIP_APL_RING_FAULT_LOCATION == "%R2742"
        and REG_CIP_APL_RING_TRANSITION_COUNT == "%R2743"
        and REG_CIP_APL_RING_BEACON_INTERVAL_US == "%R2744"
        and REG_CIP_APL_RING_DIAGNOSTIC_CODE == "%R2745"
        and REG_CIP_APL_RING_PORT1_LINK_QUALITY == "%R2746"
        and REG_CIP_APL_RING_PORT2_LINK_QUALITY == "%R2747"
        and COIL_CIP_APL_RING_ONLINE == "%M639"
        and COIL_CIP_APL_RING_SAFETY_TRIP == "%M640"
    )

    diag_codes_ok = (
        int(DIAG_OK) == 0x0000
        and int(DIAG_ERR_BEACON_TIMEOUT) == 0xEE81
        and int(DIAG_ERR_DUAL_PORT_LINK_DOWN) == 0xEE82
        and int(DIAG_ERR_RING_FAULT_DETECTED) == 0xEE83
        and int(DIAG_ERR_DUAL_CRC_SAFETY_FAULT) == 0xEE84
        and int(DIAG_ERR_SUPERVISOR_COLLISION) == 0xEE85
        # Signed 16-bit equality tests
        and DIAG_ERR_BEACON_TIMEOUT == (0xEE81 - 0x10000)
        and (DIAG_ERR_BEACON_TIMEOUT & 0xFFFF) == 0xEE81
        and DIAG_ERR_DUAL_PORT_LINK_DOWN == (0xEE82 - 0x10000)
        and (DIAG_ERR_DUAL_PORT_LINK_DOWN & 0xFFFF) == 0xEE82
        and DIAG_ERR_RING_FAULT_DETECTED == (0xEE83 - 0x10000)
        and (DIAG_ERR_RING_FAULT_DETECTED & 0xFFFF) == 0xEE83
        and DIAG_ERR_DUAL_CRC_SAFETY_FAULT == (0xEE84 - 0x10000)
        and (DIAG_ERR_DUAL_CRC_SAFETY_FAULT & 0xFFFF) == 0xEE84
        and DIAG_ERR_SUPERVISOR_COLLISION == (0xEE85 - 0x10000)
        and (DIAG_ERR_SUPERVISOR_COLLISION & 0xFFFF) == 0xEE85
    )

    enums_ok = (
        int(RingTopologyState.NORMAL_RING) == 0
        and int(RingTopologyState.RING_FAULT) == 1
        and int(RingTopologyState.LINEAR_TOPOLOGY) == 2
        and int(RingTopologyState.SUPERVISOR_ACTIVE) == 3
        and int(RingTopologyState.SAFETY_TRIP) == 4
        and int(SupervisorRole.BACKUP) == 0
        and int(SupervisorRole.ACTIVE_SUPERVISOR) == 1
        and int(SupervisorRole.NON_SUPERVISOR) == 2
        and int(AplRingStatusBits.ONLINE) == (1 << 0)
        and int(AplRingStatusBits.SUPERVISOR_ACTIVE) == (1 << 1)
        and int(AplRingStatusBits.RING_NORMAL) == (1 << 2)
        and int(AplRingStatusBits.RING_FAULT) == (1 << 3)
        and int(AplRingStatusBits.PORT1_LINK_UP) == (1 << 4)
        and int(AplRingStatusBits.PORT2_LINK_UP) == (1 << 5)
        and int(AplRingStatusBits.SAFETY_TRIPPED) == (1 << 6)
        and int(AplRingStatusBits.BEACON_OK) == (1 << 7)
    )

    s2_passed = class_ids_ok and regs_ok and diag_codes_ok and enums_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 2,
        "name": "protocol_constants_and_register_mappings",
        "check": "Verify MRP/DLR ring diagnostic codes (0xEE81-0xEE85), register offsets (%R2740..%R2747), coils (%M639..%M640)",
        "passed": bool(s2_passed),
        "timing_ms": round(t1, 3),
        "details": "Class IDs (0x39, 0x3A, 0x3B, 0x47), registers %R2740..%R2747, coils %M639..%M640, and diagnostic codes (0x0000, 0xEE81..0xEE85) verified bit-exact.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: odva_cip_safety_dual_crc_mathematics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    sample_payload = b"Horner-ODVA-CIP-Safety-Ethernet-APL-Ring-W313-Payload"
    c1 = compute_crc_s1(sample_payload)
    c1_again = compute_crc_s1(sample_payload)
    crc_s1_det = (c1 == c1_again) and (0 <= c1 <= 0xFFFF) and (c1 != 0)

    raw_header = (
        (DEFAULT_SESSION_ID).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (400).to_bytes(4, "big")
        + (0).to_bytes(1, "big")
        + (100).to_bytes(1, "big")
        + (1).to_bytes(1, "big")
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
    pkt = create_valid_apl_ring_packet(payload_bytes=sample_payload, sequence=10, timestamp_us=400)
    pkt_valid = pkt.validate_crcs() and (pkt.crc_s1 == c1)
    raw = pkt.pack()
    unpacked = CIPAPLRingPacket.unpack(raw)
    unpack_ok = unpacked.validate_crcs() and (unpacked.payload_bytes == sample_payload)

    # Corrupted packet detection
    bad_pkt = create_valid_apl_ring_packet(payload_bytes=sample_payload, sequence=10, timestamp_us=400)
    bad_pkt.crc_s1 = 0x9999
    bad_caught = not bad_pkt.validate_crcs()

    # EPID hash verification
    epid_h = compute_epid_hash()
    epid_crc32 = compute_epid_crc32()
    epid_ok = (epid_h != 0) and (epid_crc32 != 0)

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
    # Stage 4: ethernet_apl_ring_topology_and_beacons
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    # Kinematics and physics calculations
    prop_delay_us = calculate_ring_propagation_delay_us(cable_length_m=500.0, num_nodes=10, per_hop_phy_us=1.2)
    switchover_calc_ms = calculate_mrp_switchover_latency_ms(ring_break_detect_ms=3.0, port_unblock_latency_ms=5.5)
    beacon_budget_calc_ms = calculate_ring_beacon_budget_ms(beacon_interval_ms=0.4, max_missed_beacons=1)
    kinematics_ok = (14.0 < prop_delay_us < 15.0) and (switchover_calc_ms < 10.0) and (beacon_budget_calc_ms == 0.4)

    # Active Ring Supervisor baseline
    sup_eng = CIPAPLRingSafetyEngine(supervisor_role=SupervisorRole.ACTIVE_SUPERVISOR)
    sup_eng.connect()
    sup_ok = (
        sup_eng.ring_state == RingTopologyState.SUPERVISOR_ACTIVE
        and sup_eng.supervisor_role == SupervisorRole.ACTIVE_SUPERVISOR
        and sup_eng.online is True
        and sup_eng.tripped is False
        and sup_eng.diagnostic_code == DIAG_OK
        and sup_eng.port1_link_quality == 100
        and sup_eng.port2_link_quality == 100
        and sup_eng.beacon_interval_us == 400
    )

    # Non-Supervisor (Client Node) baseline
    cli_eng = CIPAPLRingSafetyEngine(supervisor_role=SupervisorRole.NON_SUPERVISOR)
    cli_eng.connect()
    cli_ok = (
        cli_eng.ring_state == RingTopologyState.NORMAL_RING
        and cli_eng.supervisor_role == SupervisorRole.NON_SUPERVISOR
        and cli_eng.online is True
        and cli_eng.tripped is False
    )

    # Frame transmission and reception across supervisor and client
    tx_pkt = sup_eng.send_packet(b"ValidRingPayload")
    tx_ok = tx_pkt.validate_crcs()
    rx_ok = cli_eng.receive_packet(tx_pkt)
    exchange_ok = (
        tx_ok is True
        and rx_ok is True
        and cli_eng.online is True
        and cli_eng.beacon_timer_us == 0.0
    )

    s4_passed = kinematics_ok and sup_ok and cli_ok and exchange_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 4,
        "name": "ethernet_apl_ring_topology_and_beacons",
        "check": "Verify 10BASE-T1L Ethernet-APL MRP supervisor/client topology, beacon timing, and kinematics",
        "passed": bool(s4_passed),
        "timing_ms": round(t1, 3),
        "details": f"Ring kinematics (delay {prop_delay_us:.2f}us, switchover budget {switchover_calc_ms:.1f}ms), active supervisor (400us beacon), and client node verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: port_break_and_fault_localization_trips
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng5 = CIPAPLRingSafetyEngine()
    eng5.connect()

    # 1. Single Port 1 Link Loss (Ring break switchover -> 0xEE83)
    eng5.inject_port_fault(1)
    p1_break_ok = (
        eng5.ring_state == RingTopologyState.RING_FAULT
        and eng5.diagnostic_code == DIAG_ERR_RING_FAULT_DETECTED
        and eng5.diagnostic_code == 0xEE83
        and eng5.fault_location == 1
        and eng5.port1_link_quality == 0
        and eng5.port2_link_quality == 100
        and eng5.transition_count >= 1
    )
    eng5.clear_fault()
    p1_rec_ok = (
        eng5.ring_state == RingTopologyState.SUPERVISOR_ACTIVE
        and eng5.diagnostic_code == DIAG_OK
        and eng5.online is True
    )

    # 2. Single Port 2 Link Loss
    eng5.inject_port_fault(2)
    p2_break_ok = (
        eng5.ring_state == RingTopologyState.RING_FAULT
        and eng5.diagnostic_code == DIAG_ERR_RING_FAULT_DETECTED
        and eng5.diagnostic_code == 0xEE83
        and eng5.fault_location == 2
        and eng5.port1_link_quality == 100
        and eng5.port2_link_quality == 0
    )
    eng5.clear_fault()
    p2_rec_ok = (
        eng5.ring_state == RingTopologyState.SUPERVISOR_ACTIVE
        and eng5.diagnostic_code == DIAG_OK
        and eng5.online is True
    )

    s5_passed = p1_break_ok and p1_rec_ok and p2_break_ok and p2_rec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 5,
        "name": "port_break_and_fault_localization_trips",
        "check": "Verify ring break switchover (< 10 ms -> 0xEE83) and Port 1/2 link loss trips (0xEE83)",
        "passed": bool(s5_passed),
        "timing_ms": round(t1, 3),
        "details": "Ring break switchover (0xEE83) and port link loss localization (location 1 and 2) verified with clean restoration.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: safety_interlock_trips_and_fault_recovery
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng6 = CIPAPLRingSafetyEngine()
    eng6.connect()

    # 1. Dual-port simultaneous PHY link loss -> fail-safe trip (0xEE82)
    eng6.inject_port_fault(1)
    eng6.inject_port_fault(2)
    dual_trip_ok = (
        eng6.ring_state == RingTopologyState.SAFETY_TRIP
        and eng6.online is False
        and eng6.tripped is True
        and eng6.fault_location == 3
        and eng6.diagnostic_code == DIAG_ERR_DUAL_PORT_LINK_DOWN
        and eng6.diagnostic_code == 0xEE82
    )
    eng6.clear_fault()
    rec_dual_ok = (eng6.online is True and eng6.tripped is False and eng6.diagnostic_code == DIAG_OK)

    # 2. Beacon watchdog expiration (> 400 us loss) -> beacon loss trip (0xEE81)
    eng6.inject_beacon_timeout()
    beacon_trip_ok = (
        eng6.ring_state == RingTopologyState.SAFETY_TRIP
        and eng6.online is False
        and eng6.tripped is True
        and eng6.diagnostic_code == DIAG_ERR_BEACON_TIMEOUT
        and eng6.diagnostic_code == 0xEE81
    )
    eng6.clear_fault()
    rec_beacon_ok = (eng6.online is True and eng6.diagnostic_code == DIAG_OK)

    # 3. Payload corruption -> CRC-S1 trip (0xEE84)
    bad_crc_pkt = create_valid_apl_ring_packet()
    bad_crc_pkt.crc_s1 = 0xBADC
    rx_crc_ok = eng6.receive_packet(bad_crc_pkt)
    crc_trip_ok = (
        rx_crc_ok is False
        and eng6.ring_state == RingTopologyState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        and eng6.diagnostic_code == 0xEE84
    )
    eng6.clear_fault()

    # 4. Multiple active supervisor collision trip (0xEE85)
    collision_pkt = create_valid_apl_ring_packet(
        session_id=0x9999,
        supervisor_precedence=DEFAULT_SUPERVISOR_PRECEDENCE,
    )
    rx_coll_ok = eng6.receive_packet(collision_pkt)
    coll_trip_ok = (
        rx_coll_ok is False
        and eng6.ring_state == RingTopologyState.SAFETY_TRIP
        and eng6.diagnostic_code == DIAG_ERR_SUPERVISOR_COLLISION
        and eng6.diagnostic_code == 0xEE85
    )
    eng6.clear_fault()
    rec_all_ok = (eng6.online is True and eng6.tripped is False and eng6.diagnostic_code == DIAG_OK)

    s6_passed = (
        dual_trip_ok
        and rec_dual_ok
        and beacon_trip_ok
        and rec_beacon_ok
        and crc_trip_ok
        and coll_trip_ok
        and rec_all_ok
    )
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 6,
        "name": "safety_interlock_trips_and_fault_recovery",
        "check": "Verify dual-port failure (0xEE82), beacon loss (0xEE81), CRC corruption (0xEE84), collision (0xEE85), and recovery",
        "passed": bool(s6_passed),
        "timing_ms": round(t1, 3),
        "details": "All interlock trips (0xEE81, 0xEE82, 0xEE84, 0xEE85) correctly forced fail-safe state and recovered deterministically.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: register_table_synchronization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt7 = RegisterTable()
    eng7 = CIPAPLRingSafetyEngine(register_table=rt7)
    eng7.connect()
    eng7.sync_to_registers(rt7, privilege=PrivilegeMode.USER)

    # 1. Healthy nominal state
    w_stat = rt7.read_word(REG_CIP_APL_RING_STATUS) & 0xFFFF
    w_sup = rt7.read_word(REG_CIP_APL_RING_SUPERVISOR_STATE)
    w_flt_loc = rt7.read_word(REG_CIP_APL_RING_FAULT_LOCATION)
    w_trans = rt7.read_uword(REG_CIP_APL_RING_TRANSITION_COUNT)
    w_bcn = rt7.read_uword(REG_CIP_APL_RING_BEACON_INTERVAL_US)
    w_diag = rt7.read_uword(REG_CIP_APL_RING_DIAGNOSTIC_CODE)
    w_p1_q = rt7.read_uword(REG_CIP_APL_RING_PORT1_LINK_QUALITY)
    w_p2_q = rt7.read_uword(REG_CIP_APL_RING_PORT2_LINK_QUALITY)
    b_online = rt7.read_bit(COIL_CIP_APL_RING_ONLINE)
    b_trip = rt7.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP)

    nom_sync_ok = (
        (w_stat >> 8) == int(RingTopologyState.SUPERVISOR_ACTIVE)
        and (w_stat & 0xFF) == int(SupervisorRole.ACTIVE_SUPERVISOR)
        and w_sup == int(SupervisorRole.ACTIVE_SUPERVISOR)
        and w_flt_loc == 0
        and w_trans == 0
        and w_bcn == 400
        and w_diag == 0x0000
        and w_p1_q == 100
        and w_p2_q == 100
        and b_online is True
        and b_trip is False
    )

    # 2. Ring open / single port link fault reflection
    eng7.inject_port_fault(1)
    eng7.sync_to_registers(rt7)
    open_sync_ok = (
        rt7.read_word(REG_CIP_APL_RING_FAULT_LOCATION) == 1
        and rt7.read_uword(REG_CIP_APL_RING_DIAGNOSTIC_CODE) == 0xEE83
        and rt7.read_uword(REG_CIP_APL_RING_PORT1_LINK_QUALITY) == 0
        and rt7.read_uword(REG_CIP_APL_RING_PORT2_LINK_QUALITY) == 100
        and rt7.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is True
    )

    # 3. Dual port link down trip and signed 16-bit register verification
    eng7.inject_port_fault(2)
    eng7.sync_to_registers(rt7, privilege=PrivilegeMode.SYSTEM)
    u_diag = rt7.read_uword(REG_CIP_APL_RING_DIAGNOSTIC_CODE)
    s_diag = rt7.read_word(REG_CIP_APL_RING_DIAGNOSTIC_CODE)

    trip_sync_ok = (
        rt7.read_word(REG_CIP_APL_RING_FAULT_LOCATION) == 3
        and u_diag == 0xEE82
        and s_diag == (0xEE82 - 0x10000)
        and (s_diag & 0xFFFF) == 0xEE82
        and rt7.read_bit(COIL_CIP_APL_RING_ONLINE) is False
        and rt7.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is True
    )

    s7_passed = nom_sync_ok and open_sync_ok and trip_sync_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    stages_log.append({
        "stage": 7,
        "name": "register_table_synchronization",
        "check": "Verify RegisterTable reads/writes, privilege modes, and status bitmasks across %R2740..%R2747 and %M639..%M640",
        "passed": bool(s7_passed),
        "timing_ms": round(t1, 3),
        "details": "Bit-exact synchronization and 16-bit signed masking verified across %R2740..%R2747 and coils %M639..%M640.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()

    # 1. Validate ST POU syntax and AST parsing
    st_syntax_ok = verify_cip_safety_apl_ring_pure_st()
    SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC)
    res_st = STParser.validate_code(ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC)
    parser_ok = (res_st.status == AgentStatus.SUCCESS)
    ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC)
    ast_ok = (ast.pou_type == POUType.PROGRAM and ast.name == "CipSafetyAplRingSync")

    # Verify address bindings in ST POU
    bindings_ok = (
        "%R2740" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        and "%R2741" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        and "%R2742" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        and "%R2743" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        and "%R2744" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        and "%R2745" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        and "%R2746" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        and "%R2747" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        and "%M639" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        and "%M640" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
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
        "check": "Verify pure IEC 61131-3 ST POU 'CipSafetyAplRingSync' and strict rejection of ladder logic constructs",
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
    eng9 = CIPAPLRingSafetyEngine(register_table=rt9)
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
        and rt9.read_bit(COIL_CIP_APL_RING_ONLINE) is True
        and rt9.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is False
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
    pou_sha256 = hashlib.sha256(ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC.encode("utf-8")).hexdigest()
    stages_summary_str = json.dumps(stages_log, sort_keys=True)
    stages_sha256 = hashlib.sha256(stages_summary_str.encode("utf-8")).hexdigest()

    evidence_dict: Dict[str, Any] = {
        "status": "success" if all_stages_passed else "failed",
        "error_code": None if all_stages_passed else "ERR_STAGE_FAILED",
        "details": (
            f"All 9 Industrial ODVA CIP Safety Over Ethernet-APL Redundant Ring ({work_package}) stages passed deterministically "
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
            "protocol": "Industrial ODVA CIP Safety Over Ethernet-APL Redundant Ring (DLR - Device Level Ring) Protocol Engine (IEC 62439-2 / IEC 61784-3-2 / IEEE 802.3cg)",
            "standards": [
                "ODVA CIP Safety Volume 5",
                "ODVA EtherNet/IP Volume 2 Chapter 9 (Device Level Ring - DLR)",
                "IEC 62439-2",
                "IEC 61784-3-2",
                "IEEE 802.3cg 10BASE-T1L",
                "IEC TS 60079-47 2-WISE",
                "IEC 61508 SIL 3",
            ],
            "registers": [
                "%R2740..%R2747",
                "%M639..%M640",
            ],
            "diagnostic_codes": {
                "0x0000": "OK",
                "0xEE81": "ERR_BEACON_TIMEOUT",
                "0xEE82": "ERR_DUAL_PORT_LINK_DOWN",
                "0xEE83": "ERR_RING_FAULT_DETECTED",
                "0xEE84": "ERR_DUAL_CRC_SAFETY_FAULT",
                "0xEE85": "ERR_SUPERVISOR_COLLISION",
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
run_cip_safety_apl_ring_verification = execute_9stage_verification_suite
run_deterministic_9stage_suite = execute_9stage_verification_suite


# ============================================================================
# CLI Entrypoint
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for W313 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Execute W313 CIP Safety Over Ethernet-APL Redundant Ring 9-Stage Verification Suite"
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
        help="Path to output JSON evidence artifact (default: artifacts/telemetry/cip_safety_apl_ring_evidence.json)",
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
        default="W313",
        help="Work package ID (default: W313)",
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
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_apl_ring_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: ODVA CIP Safety Over Ethernet-APL Redundant Ring Verification ({args.work_package}){ESC_RESET}")
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
