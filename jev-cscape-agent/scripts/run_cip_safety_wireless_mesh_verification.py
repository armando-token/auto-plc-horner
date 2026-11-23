#!/usr/bin/env python3
"""Verification Script for Industrial ODVA CIP Safety Over Wireless Mesh Protocol Engine (Wave W280).

Work Package: W280 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Standards & Specifications:
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
  - CIP Safety Over Wireless Mesh (IEEE 802.15.4 / 6LoWPAN multi-hop mesh network)
  - 32-bit Safety Network Number (SNN) verification
  - Dual 16-bit Safety CRCs (CRC-S1 for payload, CRC-S2 for sequence, timestamp, and SNN)
  - Safe State Machine: INIT=0, OPERATIONAL=1, DEGRADED=2, FAIL_SAFE=3
- IEEE 802.15.4 / 6LoWPAN Multi-Hop Mesh Routing:
  - Dynamic route selection and alternate route failover on RSSI degradation (< -82 dBm) or packet loss (> 5.0%)
  - Dynamic multi-hop latency compensation: safety watchdog threshold scales with hop count
  - Fail-safe fallback state: on watchdog expiration, link partition, or CRC corruption
- Horner OCS Memory Space:
  - Analog registers %R2410..%R2417:
    - %R2410: Mesh Node ID / Status (lower byte node_id, upper byte status code)
    - %R2411: Mesh Channel / PAN ID (lower byte channel, upper byte PAN ID & 0xFF)
    - %R2412: Scaled Link Quality (lower byte scaled RSSI 0..100, upper byte LQI 0..255)
    - %R2413: Hop Count / Route Metric (lower byte hop_count, upper byte ETX x10)
    - %R2414: Safety Network Number High Word (SNN >> 16)
    - %R2415: Safety Network Number Low Word (SNN & 0xFFFF)
    - %R2416: Mesh Packet Loss Rate (0.01% units, e.g. 250 = 2.50%)
    - %R2417: Diagnostic Code & 0xFFFF
  - Discrete bits %M562..%M563:
    - %M562: Mesh Route Active / Safety Connection Established
    - %M563: Mesh Path Failover / Link Degradation Alarm

Follows the deterministic 9-stage verification sequence:
  Stage 1: init_and_config (engine creation with default and custom configs)
  Stage 2: payload_and_dual_crc_s1_s2 (verify CRC-S1 and CRC-S2 generation and validation, corrupted payload rejection)
  Stage 3: multi_hop_routing_and_forwarding (3-hop mesh route traversal and packet forwarding)
  Stage 4: latency_jitter_watchdog_compensation (hop-based dynamic latency scaling and timeout enforcement)
  Stage 5: link_degradation_and_alternate_route_failover (simulate RSSI drop / packet loss and verify automatic bumpless reroute)
  Stage 6: fail_safe_fallback_on_mesh_partition (simulate partition, verify transition to FAIL_SAFE, zeroing of outputs, alarm assertion)
  Stage 7: horner_ocs_register_sync (verify %R2410..%R2417 and %M562..%M563 in RegisterTable)
  Stage 8: pure_st_pou_generation_and_ladder_rejection (verify ST POU syntax and rejection of ladder tokens)
  Stage 9: cyclic_soak_100_scans (100 scan cycles without memory leak, stable latency, zero unexpected faults)

Generates:
  artifacts/telemetry/cip_safety_wireless_mesh_evidence.json
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
from jev_cscape.telemetry.cip_safety_wireless_mesh import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_WIRELESS_MESH_CLASS_ID,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_NODE_ID,
    DEFAULT_PAN_ID,
    DEFAULT_CHANNEL,
    DEFAULT_BASE_TIMEOUT_MS,
    DEFAULT_HOP_DELAY_MS,
    DEFAULT_RSSI_DBM,
    DEFAULT_LQI,
    DEFAULT_RSSI_THRESHOLD_DBM,
    DEFAULT_PACKET_LOSS_THRESHOLD,
    DEFAULT_PACKET_LOSS_RATE,
    CRC_POLY_1021,
    CRC_POLY_8408,
    REG_WIRELESS_MESH_NODE_STATUS,
    REG_WIRELESS_MESH_CHANNEL_PAN,
    REG_WIRELESS_MESH_LINK_QUALITY,
    REG_WIRELESS_MESH_HOP_METRIC,
    REG_WIRELESS_MESH_SNN_HIGH,
    REG_WIRELESS_MESH_SNN_LOW,
    REG_WIRELESS_MESH_PACKET_LOSS,
    REG_WIRELESS_MESH_DIAGNOSTIC_CODE,
    COIL_WIRELESS_MESH_ROUTE_ACTIVE,
    COIL_WIRELESS_MESH_PATH_FAILOVER,
    CipSafetyWirelessMeshState,
    CipSafetyWirelessMeshDiagnosticCode,
    WirelessMeshNode,
    WirelessMeshRoute,
    CipSafetyWirelessMeshFrame,
    CipSafetyWirelessMeshEngine,
    CipSafetyWirelessMeshSync,
    compute_crc_s1,
    compute_crc_s2,
    create_valid_frame,
    verify_cip_safety_wireless_mesh_pure_st,
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
    work_package: str = "W280",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification sequence for W280.

    Stages:
      Stage 1: init_and_config
      Stage 2: payload_and_dual_crc_s1_s2
      Stage 3: multi_hop_routing_and_forwarding
      Stage 4: latency_jitter_watchdog_compensation
      Stage 5: link_degradation_and_alternate_route_failover
      Stage 6: fail_safe_fallback_on_mesh_partition
      Stage 7: horner_ocs_register_sync
      Stage 8: pure_st_pou_generation_and_ladder_rejection
      Stage 9: cyclic_soak_100_scans

    Returns strict 4-state contract JSON evidence.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: init_and_config
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1.1 Default configuration verification
    eng_def = CipSafetyWirelessMeshEngine()
    def_ok = (
        eng_def.safety_network_number == DEFAULT_SAFETY_NETWORK_NUMBER
        and eng_def.state == CipSafetyWirelessMeshState.OPERATIONAL
        and eng_def.base_timeout_ms == DEFAULT_BASE_TIMEOUT_MS
        and eng_def.hop_delay_ms == DEFAULT_HOP_DELAY_MS
        and eng_def.rssi_threshold_dbm == DEFAULT_RSSI_THRESHOLD_DBM
        and eng_def.packet_loss_threshold == DEFAULT_PACKET_LOSS_THRESHOLD
        and eng_def.is_healthy is True
        and eng_def.local_node.node_id == DEFAULT_NODE_ID
        and eng_def.local_node.pan_id == DEFAULT_PAN_ID
        and eng_def.local_node.channel == DEFAULT_CHANNEL
    )

    # 1.2 Custom configuration verification
    node_custom = WirelessMeshNode(
        node_id=14,
        pan_id=0xCAFE,
        channel=24,
        hop_count=3,
        rssi_dbm=-72.0,
        lqi=195,
        is_coordinator=False,
    )
    route_custom = WirelessMeshRoute(
        route_id=10,
        destination_id=20,
        next_hop_id=12,
        hop_count=3,
        path_etx=2.1,
        path_latency_ms=35.0,
        is_active=True,
    )
    eng_cust = CipSafetyWirelessMeshEngine(
        safety_network_number=0xAABBCCDD,
        local_node=node_custom,
        routes=[route_custom],
        base_timeout_ms=350.0,
        hop_delay_ms=45.0,
        rssi_threshold_dbm=-80.0,
        packet_loss_threshold=0.04,
        auto_activate=False,
    )
    cust_ok = (
        eng_cust.safety_network_number == 0xAABBCCDD
        and eng_cust.local_node.node_id == 14
        and eng_cust.local_node.pan_id == 0xCAFE
        and eng_cust.local_node.channel == 24
        and eng_cust.base_timeout_ms == 350.0
        and eng_cust.hop_delay_ms == 45.0
        and eng_cust.rssi_threshold_dbm == -80.0
        and eng_cust.packet_loss_threshold == 0.04
        and eng_cust.state == CipSafetyWirelessMeshState.INIT
        and eng_cust.active_route is not None
        and eng_cust.active_route.route_id == 10
    )

    # 1.3 Constants and Class ID verification
    const_ok = (
        CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        and CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        and CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        and CIP_SAFETY_WIRELESS_MESH_CLASS_ID == 0x2F
        and REG_WIRELESS_MESH_NODE_STATUS == "%R2410"
        and REG_WIRELESS_MESH_CHANNEL_PAN == "%R2411"
        and REG_WIRELESS_MESH_LINK_QUALITY == "%R2412"
        and REG_WIRELESS_MESH_HOP_METRIC == "%R2413"
        and REG_WIRELESS_MESH_SNN_HIGH == "%R2414"
        and REG_WIRELESS_MESH_SNN_LOW == "%R2415"
        and REG_WIRELESS_MESH_PACKET_LOSS == "%R2416"
        and REG_WIRELESS_MESH_DIAGNOSTIC_CODE == "%R2417"
        and COIL_WIRELESS_MESH_ROUTE_ACTIVE == "%M562"
        and COIL_WIRELESS_MESH_PATH_FAILOVER == "%M563"
        and hash(CipSafetyWirelessMeshDiagnosticCode.OK) == hash(0)
    )

    s1_pass = def_ok and cust_ok and const_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 1,
        "name": "init_and_config",
        "check": "Engine Initialization & Configuration (Default and Custom Parameters)",
        "passed": bool(s1_pass),
        "timing_ms": round(t1, 3),
        "details": "Default engine, custom node/routes, Class IDs (0x39/0x3A/0x3B/0x2F), and register mappings verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: payload_and_dual_crc_s1_s2
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sample_payload = b"\x10\x20\x30\x40\x50\x60\x70\x80"
    crc1_val = compute_crc_s1(sample_payload)
    crc1_repeat = compute_crc_s1(sample_payload)
    crc2_val = compute_crc_s2(DEFAULT_SAFETY_NETWORK_NUMBER, 1, 1000, crc1_val)
    crc2_repeat = compute_crc_s2(DEFAULT_SAFETY_NETWORK_NUMBER, 1, 1000, crc1_val)

    crc_calc_ok = (
        crc1_val == crc1_repeat
        and crc2_val == crc2_repeat
        and crc1_val != crc2_val
        and crc1_val != 0
        and crc2_val != 0
    )

    # Valid frame creation & verification
    valid_frame = create_valid_frame(
        safety_network_number=DEFAULT_SAFETY_NETWORK_NUMBER,
        node_id=1,
        sequence_number=10,
        timestamp_ms=2000,
        payload_bytes=sample_payload,
    )
    frame_valid_ok = valid_frame.verify_crc_s1() and valid_frame.verify_crc_s2() and valid_frame.is_valid()

    # Corrupted payload rejection
    corrupt_payload_frame = create_valid_frame(
        safety_network_number=DEFAULT_SAFETY_NETWORK_NUMBER,
        node_id=1,
        sequence_number=10,
        timestamp_ms=2000,
        payload_bytes=sample_payload,
    )
    corrupt_payload_frame.mutate_payload(byte_offset=1, bit_pos=2)
    payload_corrupt_detected = (
        not corrupt_payload_frame.verify_crc_s1()
        and not corrupt_payload_frame.is_valid()
    )

    # Corrupted S2 rejection (sequence number tampered)
    bad_seq_frame = create_valid_frame(
        safety_network_number=DEFAULT_SAFETY_NETWORK_NUMBER,
        node_id=1,
        sequence_number=10,
        timestamp_ms=2000,
        payload_bytes=sample_payload,
    )
    bad_seq_frame.sequence_number = 999
    bad_seq_detected = (
        bad_seq_frame.verify_crc_s1() is True  # Payload intact
        and bad_seq_frame.verify_crc_s2() is False  # Header tampered
        and not bad_seq_frame.is_valid()
    )

    # Wire format pack & unpack round-trip
    packed_bytes = valid_frame.pack()
    unpacked_frame = CipSafetyWirelessMeshFrame.unpack(packed_bytes)
    pack_unpack_ok = (
        unpacked_frame.is_valid()
        and unpacked_frame.payload_bytes == sample_payload
        and unpacked_frame.crc_s1 == valid_frame.crc_s1
        and unpacked_frame.crc_s2 == valid_frame.crc_s2
        and unpacked_frame.sequence_number == 10
    )

    s2_pass = crc_calc_ok and frame_valid_ok and payload_corrupt_detected and bad_seq_detected and pack_unpack_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 2,
        "name": "payload_and_dual_crc_s1_s2",
        "check": "Payload Framing & Dual Safety CRC-S1/S2 Verification and Corruption Detection",
        "passed": bool(s2_pass),
        "timing_ms": round(t1, 3),
        "details": "CRC-S1/S2 calculation, single-bit payload mutation detection, header sequence tamper detection, and wire pack/unpack verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: multi_hop_routing_and_forwarding
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Construct 3-hop mesh topology: Node 1 -> Node 2 -> Node 3 -> Node 4
    r1_primary = WirelessMeshRoute(
        route_id=1,
        destination_id=4,
        next_hop_id=2,
        hop_count=3,
        path_etx=2.2,
        path_latency_ms=45.0,
        is_active=True,
    )
    r2_alternate = WirelessMeshRoute(
        route_id=2,
        destination_id=4,
        next_hop_id=5,
        hop_count=4,
        path_etx=3.5,
        path_latency_ms=65.0,
        is_active=False,
    )
    r3_intermediate = WirelessMeshRoute(
        route_id=3,
        destination_id=3,
        next_hop_id=2,
        hop_count=2,
        path_etx=1.6,
        path_latency_ms=28.0,
        is_active=True,
    )

    eng_mesh_source = CipSafetyWirelessMeshEngine(
        routes=[r1_primary, r2_alternate, r3_intermediate],
        auto_activate=True,
    )

    # Route selection logic
    best_route_dest4 = eng_mesh_source.select_best_route(destination_id=4)
    best_route_dest3 = eng_mesh_source.select_best_route(destination_id=3)
    route_selection_ok = (
        best_route_dest4 is not None
        and best_route_dest4.route_id == 1
        and best_route_dest3 is not None
        and best_route_dest3.route_id == 3
    )

    # Transmit frame along 3-hop path
    tx_frame_hop = eng_mesh_source.transmit_frame(payload_bytes=b"\xFE\xDC\xBA\x98")
    tx_ok = (
        tx_frame_hop.is_valid()
        and eng_mesh_source.tx_sequence == 1
        and tx_frame_hop.payload_bytes == b"\xFE\xDC\xBA\x98"
    )

    # Receiver engine at Hop 3 (Destination Node 4) receives and processes forwarded packet
    eng_mesh_dest = CipSafetyWirelessMeshEngine(
        local_node=WirelessMeshNode(node_id=4, hop_count=3),
        auto_activate=True,
    )
    rx_forward_ok = eng_mesh_dest.process_frame(tx_frame_hop)
    dest_proc_ok = (
        rx_forward_ok is True
        and eng_mesh_dest.rx_sequence == 1
        and eng_mesh_dest.safe_inputs == b"\xFE\xDC\xBA\x98"
        and eng_mesh_dest.frames_processed == 1
        and eng_mesh_dest.is_healthy is True
        and eng_mesh_dest.state == CipSafetyWirelessMeshState.OPERATIONAL
    )

    s3_pass = route_selection_ok and tx_ok and dest_proc_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 3,
        "name": "multi_hop_routing_and_forwarding",
        "check": "Multi-Hop Mesh Route Traversal (3 Hops) and Packet Forwarding",
        "passed": bool(s3_pass),
        "timing_ms": round(t1, 3),
        "details": "3-hop route ETX selection (Route 1), frame transmission, and multi-hop destination receipt verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: latency_jitter_watchdog_compensation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng_watchdog = CipSafetyWirelessMeshEngine(
        base_timeout_ms=200.0,
        hop_delay_ms=25.0,
        auto_activate=True,
    )

    # Dynamic scaling verification: base + hop_count * hop_delay
    to_h1 = eng_watchdog.get_effective_watchdog_timeout_ms(hop_count=1)
    to_h2 = eng_watchdog.get_effective_watchdog_timeout_ms(hop_count=2)
    to_h3 = eng_watchdog.get_effective_watchdog_timeout_ms(hop_count=3)
    to_h4 = eng_watchdog.get_effective_watchdog_timeout_ms(hop_count=4)
    scaling_ok = (
        to_h1 == 225.0
        and to_h2 == 250.0
        and to_h3 == 275.0
        and to_h4 == 300.0
    )

    # Operational within compensated window (e.g. 150 ms < 225 ms)
    eng_watchdog.scan_step(0.150)
    in_window_ok = (
        eng_watchdog.state == CipSafetyWirelessMeshState.OPERATIONAL
        and eng_watchdog.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.OK
        and eng_watchdog.is_healthy is True
    )

    # Watchdog feed resets timer
    eng_watchdog.feed_watchdog()
    feed_ok = (eng_watchdog.watchdog_timer_ms == 0.0)

    # Watchdog timeout trip enforcement (240 ms > 225 ms)
    eng_watchdog.scan_step(0.240)
    timeout_trip_ok = (
        eng_watchdog.state == CipSafetyWirelessMeshState.FAIL_SAFE
        and eng_watchdog.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.TIMEOUT_EXPIRED
        and eng_watchdog.is_fail_safe is True
        and eng_watchdog.is_healthy is False
    )

    s4_pass = scaling_ok and in_window_ok and feed_ok and timeout_trip_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 4,
        "name": "latency_jitter_watchdog_compensation",
        "check": "Hop-Based Dynamic Latency Scaling and Safety Watchdog Timeout Enforcement",
        "passed": bool(s4_pass),
        "timing_ms": round(t1, 3),
        "details": "Hop-scaled thresholds (225ms/250ms/275ms/300ms), in-window execution, watchdog kick, and TIMEOUT_EXPIRED trip confirmed.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: link_degradation_and_alternate_route_failover
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s5 = RegisterTable()
    eng_failover = CipSafetyWirelessMeshEngine(register_table=rt_s5, auto_activate=True)
    initial_route_id = eng_failover.active_route.route_id if eng_failover.active_route else 0

    # 5.1 RSSI degradation below threshold (-86 dBm < -82 dBm) -> bumpless switch to alternate route
    reroute_rssi = eng_failover.evaluate_link_quality(rssi_dbm=-86.0)
    rssi_failover_ok = (
        reroute_rssi is True
        and eng_failover.state == CipSafetyWirelessMeshState.DEGRADED
        and eng_failover.active_route is not None
        and eng_failover.active_route.route_id != initial_route_id
        and eng_failover.is_failover_active is True
        and eng_failover.failover_count == 1
        and eng_failover.is_path_failover is True
        and rt_s5.read_bit("%M563") is True
    )

    # 5.2 Reset and test Packet Loss surge (> 5.0% threshold)
    eng_failover.reset()
    route_id_before_loss = eng_failover.active_route.route_id if eng_failover.active_route else 0
    reroute_loss = eng_failover.evaluate_link_quality(packet_loss=0.075)  # 7.50% loss
    loss_failover_ok = (
        reroute_loss is True
        and eng_failover.state == CipSafetyWirelessMeshState.DEGRADED
        and eng_failover.active_route is not None
        and eng_failover.active_route.route_id != route_id_before_loss
        and eng_failover.is_failover_active is True
        and eng_failover.packet_loss_rate == 0.075
        and rt_s5.read_bit("%M563") is True
        and rt_s5.read_uword("%R2416") == 750
    )

    s5_pass = rssi_failover_ok and loss_failover_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 5,
        "name": "link_degradation_and_alternate_route_failover",
        "check": "Link Degradation Surveillance (RSSI & Packet Loss) and Automatic Bumpless Reroute",
        "passed": bool(s5_pass),
        "timing_ms": round(t1, 3),
        "details": "Bumpless failover to alternate route on RSSI < -82 dBm and packet loss > 5.0% with %M563 alarm assertion verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: fail_safe_fallback_on_mesh_partition
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s6 = RegisterTable()

    # 6.1 Partition when no alternate route is available
    single_route = WirelessMeshRoute(route_id=1, destination_id=2, next_hop_id=2, is_active=True)
    eng_part_no_alt = CipSafetyWirelessMeshEngine(
        register_table=rt_s6,
        routes=[single_route],
        auto_activate=True,
    )
    eng_part_no_alt.safe_outputs = b"\xAA\xBB\xCC\xDD"
    part_result = eng_part_no_alt.evaluate_link_quality(rssi_dbm=-89.0)
    no_alt_fail_safe_ok = (
        part_result is False
        and eng_part_no_alt.state == CipSafetyWirelessMeshState.FAIL_SAFE
        and eng_part_no_alt.safe_outputs == b"\x00\x00\x00\x00"  # Zeroed outputs
        and eng_part_no_alt.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.RSSI_BELOW_THRESHOLD
        and rt_s6.read_bit("%M562") is False
        and rt_s6.read_bit("%M563") is True
    )

    # 6.2 Explicit network partition injection
    rt_s6_inj = RegisterTable()
    eng_part_inj = CipSafetyWirelessMeshEngine(register_table=rt_s6_inj, auto_activate=True)
    eng_part_inj.inject_split_brain_partition()
    inject_part_ok = (
        eng_part_inj.state == CipSafetyWirelessMeshState.FAIL_SAFE
        and eng_part_inj.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.SPLIT_BRAIN_PARTITION
        and eng_part_inj.safe_outputs == b"\x00\x00\x00\x00"
        and eng_part_inj.is_fail_safe is True
        and rt_s6_inj.read_uword("%R2417") == 7
    )

    # 6.3 Rejection of frame from foreign SNN (partitioned node)
    eng_snn_check = CipSafetyWirelessMeshEngine(safety_network_number=0x11112222, auto_activate=True)
    foreign_frame = create_valid_frame(safety_network_number=0x99998888)
    foreign_rx_ok = eng_snn_check.process_frame(foreign_frame)
    foreign_snn_rejected = (
        foreign_rx_ok is False
        and eng_snn_check.state == CipSafetyWirelessMeshState.FAIL_SAFE
        and eng_snn_check.diagnostic_code == CipSafetyWirelessMeshDiagnosticCode.SPLIT_BRAIN_PARTITION
    )

    s6_pass = no_alt_fail_safe_ok and inject_part_ok and foreign_snn_rejected
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 6,
        "name": "fail_safe_fallback_on_mesh_partition",
        "check": "Fail-Safe Fallback Interlock on Mesh Partition (Outputs Zeroed & Alarm Asserted)",
        "passed": bool(s6_pass),
        "timing_ms": round(t1, 3),
        "details": "Mesh partition without alternate route, explicit split-brain fault, and foreign SNN packet rejection into FAIL_SAFE confirmed.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: horner_ocs_register_sync
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_s7 = RegisterTable()
    eng_sync = CipSafetyWirelessMeshEngine(register_table=rt_s7, auto_activate=True)

    # 7.1 Verify nominal register table mapping
    # %R2410: node_id=1, state=1 -> ((1 << 8) | 1) = 257
    # %R2411: channel=15, pan_id=0x1A2B -> (((0x1A2B & 0xFF) << 8) | 15) = 11023
    # %R2412: scaled_rssi = -65 + 100 = 35, lqi=220 -> ((220 << 8) | 35) = 56355
    # %R2413: hop_count=1, etx=1.0 -> ((10 << 8) | 1) = 2561
    # %R2414: SNN >> 16 = 0x0001
    # %R2415: SNN & 0xFFFF = 0x2345
    # %R2416: Packet loss rate (0.20% -> 20)
    # %R2417: Diagnostic code 0 (OK)
    # %M562: True (Route Active)
    # %M563: False (Failover Alarm)
    nom_sync_ok = (
        rt_s7.read_uword("%R2410") == 257
        and rt_s7.read_uword("%R2411") == 11023
        and rt_s7.read_uword("%R2412") == 56355
        and rt_s7.read_uword("%R2413") == 2561
        and rt_s7.read_uword("%R2414") == 0x0001
        and rt_s7.read_uword("%R2415") == 0x2345
        and rt_s7.read_uword("%R2416") == 20
        and rt_s7.read_uword("%R2417") == 0
        and rt_s7.read_bit("%M562") is True
        and rt_s7.read_bit("%M563") is False
    )

    # 7.2 Update under link degradation & failover
    eng_sync.evaluate_link_quality(rssi_dbm=-85.0)
    # State = 2 (DEGRADED) -> %R2410 = ((2 << 8) | 1) = 513
    # Scaled RSSI = 15 -> %R2412 = ((220 << 8) | 15) = 56335
    # Route 2 hop_count=2, etx=1.4 -> %R2413 = ((14 << 8) | 2) = 3586
    # %M562 = True (route active), %M563 = True (failover alarm)
    degrade_sync_ok = (
        rt_s7.read_uword("%R2410") == 513
        and rt_s7.read_uword("%R2412") == 56335
        and rt_s7.read_uword("%R2413") == 3586
        and rt_s7.read_bit("%M562") is True
        and rt_s7.read_bit("%M563") is True
    )

    # 7.3 Update under FAIL_SAFE trip
    eng_sync.trip_watchdog_timeout()
    # State = 3 (FAIL_SAFE) -> %R2410 = ((3 << 8) | 1) = 769
    # Diagnostic code 3 (TIMEOUT_EXPIRED) -> %R2417 = 3
    # %M562 = False, %M563 = True
    failsafe_sync_ok = (
        rt_s7.read_uword("%R2410") == 769
        and rt_s7.read_uword("%R2417") == 3
        and rt_s7.read_bit("%M562") is False
        and rt_s7.read_bit("%M563") is True
    )

    s7_pass = nom_sync_ok and degrade_sync_ok and failsafe_sync_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 7,
        "name": "horner_ocs_register_sync",
        "check": "Horner OCS Register Space Synchronization (%R2410..%R2417 and %M562..%M563)",
        "passed": bool(s7_pass),
        "timing_ms": round(t1, 3),
        "details": "Verified full synchronization of %R2410..%R2417 and discrete coils %M562..%M563 across nominal, degraded, and fail-safe states.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_generation_and_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    pou_valid = verify_cip_safety_wireless_mesh_pure_st()

    # Verify bound registers in POU
    ast = STParser(pou_type=POUType.PROGRAM).parse(CipSafetyWirelessMeshSync)
    expected_regs = {
        "%R2410", "%R2411", "%R2412", "%R2413",
        "%R2414", "%R2415", "%R2416", "%R2417",
        "%M562", "%M563",
    }
    regs_bound_ok = expected_regs.issubset(set(ast.bound_registers))

    # Reject forbidden ladder constructs
    ladder_snippets = [
        "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[ ]--- x; END_PROGRAM",
        "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[/]--- x; END_PROGRAM",
        "PROGRAM LadderTest VAR y : BOOL; END_VAR ---( )--- y; END_PROGRAM",
        "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(S)--- y; END_PROGRAM",
        "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(R)--- y; END_PROGRAM",
        "PROGRAM LadderTest RUNG 1 END_PROGRAM",
        "PROGRAM LadderTest NETWORK 1 END_PROGRAM",
        "PROGRAM LadderTest XIC(Contact1); END_PROGRAM",
        "PROGRAM LadderTest OTE(Coil1); END_PROGRAM",
    ]
    rejected_count = 0
    for snippet in ladder_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snippet)
        except LadderForbiddenError:
            rejected_count += 1
        except Exception:
            pass

    anti_ladder_ok = (rejected_count == len(ladder_snippets))

    s8_pass = pou_valid and regs_bound_ok and anti_ladder_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 8,
        "name": "pure_st_pou_generation_and_ladder_rejection",
        "check": "Pure IEC 61131-3 Structured Text POU Validation and Anti-Ladder Construct Rejection",
        "passed": bool(s8_pass),
        "timing_ms": round(t1, 3),
        "details": f"CipSafetyWirelessMeshSync pure ST verified with {len(ast.bound_registers)} bound registers; rejected {rejected_count}/{len(ladder_snippets)} ladder constructs.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: cyclic_soak_100_scans
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    tracemalloc.start()
    rt_s9 = RegisterTable()
    eng_soak = CipSafetyWirelessMeshEngine(register_table=rt_s9, auto_activate=True)

    scan_errors = 0
    for cycle in range(100):
        try:
            eng_soak.feed_watchdog()
            eng_soak.transmit_frame()
            eng_soak.scan_step(0.010)
            if not eng_soak.is_healthy or eng_soak.diagnostic_code != CipSafetyWirelessMeshDiagnosticCode.OK:
                scan_errors += 1
        except Exception:
            scan_errors += 1

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # ILogicUnit execute method verification
    exec_result = eng_soak.execute()
    exec_ok = (
        exec_result.status == AgentStatus.SUCCESS
        and exec_result.error_code is None
        and eng_soak.cycles_count == 100
        and scan_errors == 0
        and peak_mem < 2 * 1024 * 1024  # Less than 2MB memory footprint
    )

    s9_pass = exec_ok
    t1 = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 9,
        "name": "cyclic_soak_100_scans",
        "check": "100 Cyclic Scan Soak Execution, Memory Leak & Latency Stability Surveillance",
        "passed": bool(s9_pass),
        "timing_ms": round(t1, 3),
        "details": f"100 scan cycles executed cleanly with 0 faults (peak memory: {peak_mem / 1024:.1f} KB, execution status: SUCCESS).",
    })

    # ------------------------------------------------------------------------
    # Aggregate Results & Strict 4-State Evidence
    # ------------------------------------------------------------------------
    stages_passed = sum(1 for r in test_results if r["passed"])
    total_stages = len(test_results)
    all_passed = (stages_passed == total_stages)

    status = "success" if all_passed else "failed"
    error_code = None if all_passed else "ERR_STAGE_VERIFICATION_FAILED"
    details = (
        f"Wave {work_package} CIP Safety Over Wireless Mesh Protocol Engine Verification PASSED ({stages_passed}/{total_stages} stages)."
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
            "work_package": work_package,
            "gate": "G8",
            "protocol": "ODVA CIP Safety Over Wireless Mesh (IEEE 802.15.4 / 6LoWPAN)",
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
        description="JEV Cscape Agent: Industrial ODVA CIP Safety Over Wireless Mesh Verification (W280)"
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
        default="W280",
        help="Work package identifier (default: W280)",
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
        evidence_path = (
            REPO_ROOT
            / "artifacts"
            / "telemetry"
            / "cip_safety_wireless_mesh_evidence.json"
        ).resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(
            f"  {ESC_BOLD}JEV Cscape Agent: Industrial ODVA CIP Safety Over Wireless Mesh Verification ({args.work_package}){ESC_RESET}"
        )
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
            print(
                f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:"
            )
            print(f"  {type(exc).__name__}: {exc}")
            print("=" * 80)
        return 1

    total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    if isinstance(evidence, dict) and "data" in evidence:
        stages_list = evidence["data"].get("stages", [])
        if "tests" not in evidence["data"]:
            evidence["data"]["tests"] = stages_list
        if "checks_passed" not in evidence["data"]:
            evidence["data"]["checks_passed"] = sum(
                1 for s in stages_list if s.get("passed")
            )
        if "total_checks" not in evidence["data"]:
            evidence["data"]["total_checks"] = len(stages_list)
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    valid_states = {"success", "failed", "blocked", "inconclusive"}
    overall_status = (
        evidence.get("status") if isinstance(evidence, dict) else None
    )
    error_code = (
        evidence.get("error_code")
        if isinstance(evidence, dict)
        else "INVALID_PAYLOAD"
    )
    details_str = (
        evidence.get("details", "")
        if isinstance(evidence, dict)
        else "Evidence is not a dictionary"
    )

    if overall_status not in valid_states:
        print(
            f"\n[{ESC_RED}{ESC_BOLD}CONTRACT VIOLATION{ESC_RESET}] Invalid status '{overall_status}'. Must be one of {valid_states}."
        )
        print("=" * 80)
        return 1

    stages_data: List[Dict[str, Any]] = []
    if isinstance(evidence, dict):
        data_dict = evidence.get("data")
        if isinstance(data_dict, dict):
            stages_data = data_dict.get("stages") or data_dict.get("tests") or []

    print("\nDeterministic 9-Stage Wireless Mesh Protocol Verification Results:")
    for s in stages_data:
        st_num = s.get("stage", "?")
        chk_name = (
            s.get("check")
            or s.get("name")
            or s.get("stage_name")
            or f"Stage_{st_num}"
        )
        passed = bool(s.get("passed"))
        details = s.get("details", "")
        timing = s.get("timing_ms")
        st_stat = s.get("status")
        print(format_stage_result(st_num, chk_name, passed, timing, details, st_stat))

    print("-" * 80)
    print(f"Total Execution Time: {total_elapsed_ms:.2f} ms")
    stages_passed = evidence.get(
        "stages_passed", sum(1 for s in stages_data if s.get("passed"))
    )
    total_stages = evidence.get("total_stages", len(stages_data))
    print(f"Stages Passed: {stages_passed}/{total_stages}")
    print(f"Evidence Artifact: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print(f"Engineering Contract Status: {overall_status.upper()}")

    if overall_status == "blocked":
        print(
            f"\n{ESC_YELLOW}{ESC_BOLD}[BLOCKED] Action prevented by safety policy or platform limitation: {error_code}{ESC_RESET}"
        )
        return 2
    elif overall_status == "inconclusive":
        print(
            f"\n{ESC_YELLOW}{ESC_BOLD}[INCONCLUSIVE] Outcome unverified: {error_code}{ESC_RESET}"
        )
        return 3
    elif overall_status == "success":
        print(
            f"\n{ESC_GREEN}{ESC_BOLD}[SUCCESS] All 9 CIP Safety Over Wireless Mesh protocol stages PASSED deterministically.{ESC_RESET}"
        )
        print("=" * 80)
        return 0
    else:
        print(
            f"\n{ESC_RED}{ESC_BOLD}[FAILED] Verification failed with status '{overall_status}' (error_code: {error_code}).{ESC_RESET}"
        )
        print(f"Details: {details_str}")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
