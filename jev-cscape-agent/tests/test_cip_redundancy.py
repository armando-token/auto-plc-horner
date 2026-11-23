"""Comprehensive Unit and Integration Test Suite for Industrial EtherNet/IP CIP Redundancy Engine.

Work Package: W196 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Test Coverage (75+ Unit Tests across 13 Sections):
1. Section 1: Constants, Enums & Protocol Defaults (CipRedundancyState, NodeStatus, ActiveNodeSelection, etc.).
2. Section 2: Node Configuration, Dual-IP & Data Models (NodeNetworkConfig, HeartbeatPacket, GratuitousArpFrame).
3. Section 3: ODVA CIP Redundancy Object (Class 0x3E attribute resolution and read-only protections).
4. Section 4: Primary and Secondary Node Pairing & Link States (Healthy, Link 1 Down, Link 2 Active, Collapse).
5. Section 5: High-Frequency Heartbeat Tracking & Sequence Rollover (Ping/Pong, 15-bit counter rollover 32767 -> 0).
6. Section 6: Heartbeat Loss Detection & Watchdog (< 100ms timeout threshold, 0xD401 trip).
7. Section 7: Automated Failover Switchover & Gratuitous ARP (Bumpless takeover, 3 GARP burst dispatch).
8. Section 8: Split-Brain Detection, Conflict Handling & Resolution (0xD403 detection, fault latch, recovery).
9. Section 9: Packet Loss Calculation & Health Scoring (0..100 bounded health score calculation).
10. Section 10: Horner OCS Register Table Synchronization (%R1570..%R1577, %M366..%M367 with PrivilegeMode.SYSTEM).
11. Section 11: ILogicUnit Scan Cycle Simulation (100-cycle scan simulation, execute, reset, timing).
12. Section 12: Pure ST POU AST Validation & Anti-Ladder Interception (SecurityGuard, STParser, LadderForbiddenError).
13. Section 13: Deterministic 9-Stage Verification Runner (run_cip_redundancy_verification execution and JSON export).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_redundancy import (
    ActiveNodeSelection,
    CIP_REDUNDANCY_CLASS_ID,
    CIP_REDUNDANCY_PORT,
    CIP_REDUNDANCY_POU,
    CIP_REDUNDANCY_SYNC_POU,
    CIP_REDUNDANCY_TCP_PORT,
    CIPRedundancyDiagnosticCode,
    CIPRedundancyEngine,
    CipNodeStatus,
    CipRedundancyDiagnosticCode,
    CipRedundancyEngine,
    CipRedundancyObject,
    CipRedundancyRole,
    CipRedundancyState,
    CipRedundancySyncPOU,
    DEFAULT_HEARTBEAT_INTERVAL_MS,
    DEFAULT_HEARTBEAT_TIMEOUT_MS,
    DEFAULT_PRIMARY_IP_A,
    DEFAULT_PRIMARY_IP_B,
    DEFAULT_SECONDARY_IP_A,
    DEFAULT_SECONDARY_IP_B,
    DEFAULT_VIRTUAL_IP,
    DualIpConfig,
    GARP_BURST_COUNT,
    GratuitousArpFrame,
    HeartbeatFrame,
    HeartbeatMessageType,
    HeartbeatPacket,
    HeartbeatTracker,
    MAX_PERMISSIBLE_SWITCHOVER_MS,
    NOMINAL_SWITCHOVER_LATENCY_MS,
    NodeNetworkConfig,
    NodeStatus,
    RedundancyLinkState,
    RedundancyNodeConfig,
    RedundancyState,
    RedundancySwitchoverReason,
    ROLLING_WINDOW_SIZE,
    decode_dint_words,
    encode_dint_words,
    run_cip_redundancy_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
)


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def empty_reg_table() -> RegisterTable:
    """Fixture providing clean RegisterTable."""
    return RegisterTable()


@pytest.fixture
def paired_engine(empty_reg_table: RegisterTable) -> CipRedundancyEngine:
    """Fixture providing initialized and paired CIP Redundancy Engine."""
    engine = CipRedundancyEngine(
        node_id=1,
        reg_table=empty_reg_table,
        heartbeat_interval_ms=20.0,
        heartbeat_timeout_ms=60.0,
    )
    engine.initiate_pairing()
    return engine


# ============================================================================
# Section 1: Constants, Enums & Protocol Defaults
# ============================================================================

class TestCipRedundancyConstantsAndEnums:
    """Tests for protocol constants, enums, diagnostic codes, and configuration defaults."""

    def test_protocol_constants_values(self) -> None:
        assert CIP_REDUNDANCY_CLASS_ID == 0x3E
        assert CIP_REDUNDANCY_PORT == 2224
        assert CIP_REDUNDANCY_TCP_PORT == 44818
        assert DEFAULT_HEARTBEAT_INTERVAL_MS == 20.0
        assert DEFAULT_HEARTBEAT_TIMEOUT_MS == 60.0
        assert MAX_PERMISSIBLE_SWITCHOVER_MS == 100.0
        assert NOMINAL_SWITCHOVER_LATENCY_MS == 15.0
        assert DEFAULT_PRIMARY_IP_A == "192.168.1.10"
        assert DEFAULT_PRIMARY_IP_B == "192.168.2.10"
        assert DEFAULT_SECONDARY_IP_A == "192.168.1.11"
        assert DEFAULT_SECONDARY_IP_B == "192.168.2.11"
        assert DEFAULT_VIRTUAL_IP == "192.168.1.100"
        assert GARP_BURST_COUNT == 3
        assert ROLLING_WINDOW_SIZE == 1000

    def test_cip_redundancy_state_enum_and_aliases(self) -> None:
        assert CipRedundancyState.DISCONNECTED == 0
        assert CipRedundancyState.STANDBY == 1
        assert CipRedundancyState.SYNCHRONIZING == 2
        assert CipRedundancyState.ACTIVE_PRIMARY == 3
        assert CipRedundancyState.ACTIVE_SECONDARY == 4
        assert CipRedundancyState.FAULTED == 5

        # Compatibility aliases
        assert CipRedundancyState.Disconnected == 0
        assert CipRedundancyState.Standby == 1
        assert CipRedundancyState.Synchronizing == 2
        assert CipRedundancyState.ActivePrimary == 3
        assert CipRedundancyState.ActiveSecondary == 4
        assert CipRedundancyState.Faulted == 5
        assert RedundancyState is CipRedundancyState

    def test_node_status_enum_and_aliases(self) -> None:
        assert NodeStatus.DOWN == 0
        assert NodeStatus.STANDBY == 1
        assert NodeStatus.ACTIVE == 2
        assert NodeStatus.FAULT == 3

        # Compatibility aliases
        assert NodeStatus.Down == 0
        assert NodeStatus.Standby == 1
        assert NodeStatus.Active == 2
        assert NodeStatus.Fault == 3
        assert CipNodeStatus is NodeStatus

    def test_active_node_selection_enum(self) -> None:
        assert ActiveNodeSelection.NONE == 0
        assert ActiveNodeSelection.PRIMARY == 1
        assert ActiveNodeSelection.SECONDARY == 2

        # Compatibility aliases
        assert ActiveNodeSelection.NoneSelected == 0
        assert ActiveNodeSelection.Primary == 1
        assert ActiveNodeSelection.Secondary == 2

    def test_diagnostic_codes_and_aliases(self) -> None:
        assert CipRedundancyDiagnosticCode.OK == 0x0000
        assert CipRedundancyDiagnosticCode.HEARTBEAT_TIMEOUT == 0xD401
        assert CipRedundancyDiagnosticCode.DUAL_IP_CONFLICT == 0xD402
        assert CipRedundancyDiagnosticCode.SPLIT_BRAIN_DETECTED == 0xD403
        assert CipRedundancyDiagnosticCode.SYNC_DEGRADED == 0xD404

        # Convenience aliases
        assert CipRedundancyDiagnosticCode.ERR_HEARTBEAT_TIMEOUT == 0xD401
        assert CipRedundancyDiagnosticCode.ERR_DUAL_IP_CONFLICT == 0xD402
        assert CipRedundancyDiagnosticCode.ERR_SPLIT_BRAIN == 0xD403
        assert CipRedundancyDiagnosticCode.ERR_SYNC_DEGRADED == 0xD404
        assert CIPRedundancyDiagnosticCode is CipRedundancyDiagnosticCode

    def test_heartbeat_message_type_enum(self) -> None:
        assert HeartbeatMessageType.PING == 1
        assert HeartbeatMessageType.PONG == 2
        assert HeartbeatMessageType.STATE_SYNC == 3
        assert HeartbeatMessageType.SWITCHOVER_CMD == 4
        assert HeartbeatMessageType.GARP_NOTIFY == 5

    def test_compatibility_enums_present(self) -> None:
        assert hasattr(CipRedundancyRole, "PRIMARY")
        assert hasattr(RedundancyLinkState, "HEALTHY")
        assert hasattr(RedundancySwitchoverReason, "HEARTBEAT_LOSS")
        assert CIPRedundancyEngine is CipRedundancyEngine


# ============================================================================
# Section 2: Node Configuration, Dual-IP & Data Models
# ============================================================================

class TestNodeConfigAndDataModels:
    """Tests for NodeNetworkConfig, DualIpConfig, HeartbeatPacket, and GratuitousArpFrame."""

    def test_node_network_config_defaults(self) -> None:
        cfg = NodeNetworkConfig(node_id=1, name="PriNode")
        assert cfg.node_id == 1
        assert cfg.name == "PriNode"
        assert cfg.primary_ip == DEFAULT_PRIMARY_IP_A
        assert cfg.secondary_ip == DEFAULT_PRIMARY_IP_B
        assert cfg.virtual_ip == DEFAULT_VIRTUAL_IP
        assert cfg.mac_address == "00:1D:9C:C0:01:01"
        assert cfg.link1_up is True
        assert cfg.link2_up is True
        assert DualIpConfig is NodeNetworkConfig
        assert RedundancyNodeConfig is NodeNetworkConfig

    def test_node_network_config_to_dict(self) -> None:
        cfg = NodeNetworkConfig(node_id=2, name="SecNode")
        d = cfg.to_dict()
        assert d["node_id"] == 2
        assert d["name"] == "SecNode"
        assert d["primary_ip"] == DEFAULT_PRIMARY_IP_A
        assert d["virtual_ip"] == DEFAULT_VIRTUAL_IP
        assert d["link1_up"] is True

    def test_heartbeat_packet_creation_and_to_dict(self) -> None:
        pkt = HeartbeatPacket(
            msg_type=HeartbeatMessageType.PING,
            sequence_id=42,
            source_node=1,
            target_node=2,
            node_status=NodeStatus.ACTIVE,
            redundancy_state=CipRedundancyState.ACTIVE_PRIMARY,
            health_score=95,
            timestamp_ms=1000.0,
        )
        assert pkt.sequence_id == 42
        assert pkt.msg_type == HeartbeatMessageType.PING
        assert HeartbeatFrame is HeartbeatPacket
        d = pkt.to_dict()
        assert d["sequence_id"] == 42
        assert d["msg_type_name"] == "PING"
        assert d["health_score"] == 95

    def test_gratuitous_arp_frame_creation_and_to_dict(self) -> None:
        garp = GratuitousArpFrame(
            virtual_ip="192.168.1.100",
            sender_mac="00:1D:9C:C0:01:02",
            sender_ip="192.168.1.100",
            broadcast_seq=1,
        )
        assert garp.virtual_ip == "192.168.1.100"
        assert garp.target_mac == "FF:FF:FF:FF:FF:FF"
        d = garp.to_dict()
        assert d["virtual_ip"] == "192.168.1.100"
        assert d["sender_mac"] == "00:1D:9C:C0:01:02"

    def test_heartbeat_tracker_model(self) -> None:
        tracker = HeartbeatTracker()
        tracker.record(True)
        tracker.record(True)
        tracker.record(False)
        assert tracker.packets_sent == 3
        assert tracker.packets_received == 2
        assert tracker.packets_dropped == 1
        assert round(tracker.packet_loss_pct(), 1) == 33.3


# ============================================================================
# Section 3: ODVA CIP Redundancy Object (Class 0x3E)
# ============================================================================

class TestCipRedundancyObject:
    """Tests for ODVA CIP Redundancy Object (Class 0x3E) attribute resolution and modification."""

    def test_cip_redundancy_object_attributes_resolution(self) -> None:
        obj = CipRedundancyObject()
        assert obj.class_id == 0x3E
        assert obj.get_attribute(1) == int(CipRedundancyState.DISCONNECTED)
        assert obj.get_attribute(2) == int(NodeStatus.DOWN)
        assert obj.get_attribute(3) == int(NodeStatus.DOWN)
        assert obj.get_attribute(4) == int(ActiveNodeSelection.NONE)
        assert obj.get_attribute(5) == 0
        assert obj.get_attribute(6) == 0
        assert obj.get_attribute(7) == 0
        assert obj.get_attribute(8) == 0
        assert obj.get_attribute(9) == 0
        assert obj.get_attribute(10) == DEFAULT_VIRTUAL_IP
        assert obj.get_attribute(11) == 0
        assert obj.get_attribute(12) == 0

    def test_cip_redundancy_object_writable_attribute(self) -> None:
        obj = CipRedundancyObject()
        assert obj.set_attribute(10, "10.0.0.100") is True
        assert obj.virtual_ip == "10.0.0.100"
        assert obj.get_attribute(10) == "10.0.0.100"

    def test_cip_redundancy_object_read_only_attribute(self) -> None:
        obj = CipRedundancyObject()
        assert obj.set_attribute(1, 3) is False
        assert obj.set_attribute(5, 100) is False

    def test_cip_redundancy_object_invalid_attribute_error(self) -> None:
        obj = CipRedundancyObject()
        with pytest.raises(KeyError):
            obj.get_attribute(99)


# ============================================================================
# Section 4: Primary and Secondary Node Pairing & Link States
# ============================================================================

class TestNodePairingAndLinkStates:
    """Tests for node pairing, dual-IP Ethernet port monitoring, link transitions, and IP collision check."""

    def test_engine_initialization_defaults(self, empty_reg_table: RegisterTable) -> None:
        engine = CipRedundancyEngine(reg_table=empty_reg_table)
        assert engine.node_id == 1
        assert engine.redundancy_state == CipRedundancyState.DISCONNECTED
        assert engine.primary_status == NodeStatus.DOWN
        assert engine.secondary_status == NodeStatus.DOWN
        assert engine.active_node_selection == ActiveNodeSelection.NONE
        assert engine.redundancy_healthy is False

    def test_initiate_pairing_success(self, empty_reg_table: RegisterTable) -> None:
        engine = CipRedundancyEngine(reg_table=empty_reg_table)
        success = engine.initiate_pairing()
        assert success is True
        assert engine.primary_status == NodeStatus.ACTIVE
        assert engine.secondary_status == NodeStatus.STANDBY
        assert engine.active_node_selection == ActiveNodeSelection.PRIMARY
        assert engine.redundancy_state == CipRedundancyState.ACTIVE_PRIMARY
        assert engine.redundancy_healthy is True
        assert engine.health_score >= 80

    def test_initiate_pairing_ip_conflict_detection(self, empty_reg_table: RegisterTable) -> None:
        # Same primary IP configured for both primary and secondary nodes
        engine = CipRedundancyEngine(
            primary_ip="192.168.1.10",
            secondary_ip="192.168.1.10",
            reg_table=empty_reg_table,
        )
        success = engine.initiate_pairing()
        assert success is False
        assert engine.diagnostic_code == CipRedundancyDiagnosticCode.DUAL_IP_CONFLICT
        assert engine.redundancy_healthy is False
        assert engine.redundancy_state == CipRedundancyState.FAULTED

    def test_initiate_pairing_link_down_failure(self, empty_reg_table: RegisterTable) -> None:
        engine = CipRedundancyEngine(reg_table=empty_reg_table)
        engine.primary_config.link1_up = False
        engine.primary_config.link2_up = False
        success = engine.initiate_pairing()
        assert success is False
        assert engine.redundancy_state == CipRedundancyState.DISCONNECTED
        assert engine.primary_status == NodeStatus.DOWN

    def test_dual_link_status_redundancy(self, paired_engine: CipRedundancyEngine) -> None:
        # Sever Link 1; Link 2 remains active
        paired_engine.primary_config.link1_up = False
        assert paired_engine.primary_config.link2_up is True
        paired_engine.calculate_health_score()
        # Path redundancy preserved, health score degraded slightly but still operational
        assert paired_engine.health_score > 0
        assert paired_engine.redundancy_state == CipRedundancyState.ACTIVE_PRIMARY

    def test_dual_link_collapse(self, paired_engine: CipRedundancyEngine) -> None:
        init_score = paired_engine.calculate_health_score()
        # Sever all redundant links
        paired_engine.primary_config.link1_up = False
        paired_engine.primary_config.link2_up = False
        paired_engine.secondary_config.link1_up = False
        paired_engine.secondary_config.link2_up = False
        new_score = paired_engine.calculate_health_score()
        assert new_score < init_score
        assert new_score == 80


# ============================================================================
# Section 5: High-Frequency Heartbeat Tracking & Sequence Rollover
# ============================================================================

class TestHeartbeatTrackingAndRollover:
    """Tests for cyclic heartbeat ping/pong protocol, sequence tracking, and INT16 rollover (32767 -> 0)."""

    def test_send_heartbeat_ping(self, paired_engine: CipRedundancyEngine) -> None:
        assert paired_engine.heartbeat_seq_counter == 0
        ping = paired_engine.send_heartbeat_ping()
        assert ping.msg_type == HeartbeatMessageType.PING
        assert ping.sequence_id == 1
        assert paired_engine.heartbeat_seq_counter == 1
        assert paired_engine.packets_transmitted == 1

    def test_process_heartbeat_ping_generates_pong(self, paired_engine: CipRedundancyEngine) -> None:
        ping = paired_engine.send_heartbeat_ping()
        pong = paired_engine.process_heartbeat_ping(ping)
        assert pong.msg_type == HeartbeatMessageType.PONG
        assert pong.sequence_id == ping.sequence_id
        assert pong.source_node == ping.target_node
        assert pong.target_node == ping.source_node
        assert paired_engine.packets_received == 1

    def test_process_heartbeat_pong_updates_timing(self, paired_engine: CipRedundancyEngine) -> None:
        ping = paired_engine.send_heartbeat_ping()
        pong = paired_engine.process_heartbeat_ping(ping)
        # Advance simulation time by 5 ms
        paired_engine.elapsed_simulation_ms += 5.0
        rtt_ms = paired_engine.process_heartbeat_pong(pong)
        assert rtt_ms >= 5.0
        assert paired_engine.last_heartbeat_time_ms == paired_engine.elapsed_simulation_ms

    def test_heartbeat_sequence_15bit_rollover(self, paired_engine: CipRedundancyEngine) -> None:
        # Pre-set sequence counter to INT16 boundary 32767 (0x7FFF)
        paired_engine.heartbeat_seq_counter = 32767
        ping = paired_engine.send_heartbeat_ping()
        # Next sequence should wrap cleanly to 0
        assert ping.sequence_id == 0
        assert paired_engine.heartbeat_seq_counter == 0

    def test_multiple_heartbeat_exchanges(self, paired_engine: CipRedundancyEngine) -> None:
        for i in range(1, 11):
            ping = paired_engine.send_heartbeat_ping()
            pong = paired_engine.process_heartbeat_ping(ping)
            paired_engine.process_heartbeat_pong(pong)
            assert ping.sequence_id == i


# ============================================================================
# Section 6: Heartbeat Loss Detection & Watchdog (< 100ms Timeout)
# ============================================================================

class TestHeartbeatLossWatchdog:
    """Tests for heartbeat age tracking, watchdog timeout (< 100ms threshold), and 0xD401 trip."""

    def test_heartbeat_loss_timeout_configured(self, paired_engine: CipRedundancyEngine) -> None:
        assert paired_engine.heartbeat_timeout_ms <= 100.0
        assert paired_engine.heartbeat_timeout_ms == 60.0

    def test_heartbeat_silence_below_timeout_no_failover(self, paired_engine: CipRedundancyEngine) -> None:
        # 30 ms silence < 60 ms timeout
        paired_engine.scan_step(dt=0.030)
        assert paired_engine.diagnostic_code == CipRedundancyDiagnosticCode.OK
        assert paired_engine.failover_triggered is False
        assert paired_engine.active_node_selection == ActiveNodeSelection.PRIMARY

    def test_heartbeat_silence_exceeding_timeout_triggers_failover(self, paired_engine: CipRedundancyEngine) -> None:
        # Establish baseline active heartbeat timestamp > 0
        paired_engine.last_heartbeat_time_ms = 10.0
        paired_engine.elapsed_simulation_ms = 10.0
        # 80 ms silence > 60 ms timeout threshold
        paired_engine.scan_step(dt=0.080)
        assert paired_engine.diagnostic_code == CipRedundancyDiagnosticCode.HEARTBEAT_TIMEOUT
        assert paired_engine.failover_triggered is True
        assert paired_engine.secondary_status == NodeStatus.ACTIVE
        assert paired_engine.active_node_selection == ActiveNodeSelection.SECONDARY
        assert paired_engine.redundancy_state == CipRedundancyState.ACTIVE_SECONDARY

    def test_simulate_heartbeat_timeout_helper(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.simulate_heartbeat_timeout(latency_ms=18.5)
        assert paired_engine.diagnostic_code == CipRedundancyDiagnosticCode.HEARTBEAT_TIMEOUT
        assert paired_engine.failover_triggered is True
        assert paired_engine.switchover_latency_ms == 18.5
        assert paired_engine.secondary_status == NodeStatus.ACTIVE
        assert paired_engine.active_node_selection == ActiveNodeSelection.SECONDARY


# ============================================================================
# Section 7: Automated Failover Switchover & Gratuitous ARP
# ============================================================================

class TestAutomatedFailoverAndGarp:
    """Tests for bumpless failover switchover, switchover latency, and Gratuitous ARP burst dispatch."""

    def test_automated_failover_node_status_transition(self, paired_engine: CipRedundancyEngine) -> None:
        assert paired_engine.primary_status == NodeStatus.ACTIVE
        assert paired_engine.secondary_status == NodeStatus.STANDBY
        paired_engine.execute_failover(reason="Test failover")
        assert paired_engine.primary_status == NodeStatus.DOWN
        assert paired_engine.secondary_status == NodeStatus.ACTIVE

    def test_automated_failover_active_selection_updates(self, paired_engine: CipRedundancyEngine) -> None:
        assert paired_engine.active_node_selection == ActiveNodeSelection.PRIMARY
        paired_engine.execute_failover()
        assert paired_engine.active_node_selection == ActiveNodeSelection.SECONDARY

    def test_automated_failover_redundancy_state_updates(self, paired_engine: CipRedundancyEngine) -> None:
        assert paired_engine.redundancy_state == CipRedundancyState.ACTIVE_PRIMARY
        paired_engine.execute_failover()
        assert paired_engine.redundancy_state == CipRedundancyState.ACTIVE_SECONDARY

    def test_automated_failover_switchover_latency_recorded(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.execute_failover(measured_latency_ms=22.5)
        assert paired_engine.switchover_latency_ms == 22.5
        assert paired_engine.switchover_latency_ms < 100.0

    def test_automated_failover_latches_failover_event(self, paired_engine: CipRedundancyEngine) -> None:
        assert paired_engine.failover_triggered is False
        paired_engine.execute_failover()
        assert paired_engine.failover_triggered is True

    def test_automated_failover_dispatches_garp_burst(self, paired_engine: CipRedundancyEngine) -> None:
        assert len(paired_engine.gratuitous_arp_history) == 0
        paired_engine.execute_failover()
        assert len(paired_engine.gratuitous_arp_history) == 3
        assert paired_engine.gratuitous_arp_count == 3
        assert paired_engine.redundancy_object.garp_count == 3

    def test_garp_frame_attributes_correct(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.execute_failover()
        frames = paired_engine.broadcast_gratuitous_arp(count=3)
        assert len(frames) == 3
        for f in frames:
            assert f.virtual_ip == paired_engine.virtual_ip
            assert f.target_mac == "FF:FF:FF:FF:FF:FF"
            assert f.sender_mac == paired_engine.secondary_config.mac_address


# ============================================================================
# Section 8: Split-Brain Detection, Conflict Handling & Resolution
# ============================================================================

class TestSplitBrainDetectionAndResolution:
    """Tests for Split-Brain condition detection (0xD403), state tripping, and fault recovery."""

    def test_split_brain_detection_0xd403(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.simulate_split_brain()
        assert paired_engine.diagnostic_code == CipRedundancyDiagnosticCode.SPLIT_BRAIN_DETECTED
        assert paired_engine.diagnostic_code == 0xD403

    def test_split_brain_sets_state_to_faulted(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.simulate_split_brain()
        assert paired_engine.redundancy_state == CipRedundancyState.FAULTED
        assert paired_engine.active_node_selection == ActiveNodeSelection.NONE

    def test_split_brain_sets_node_statuses_to_fault(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.simulate_split_brain()
        assert paired_engine.primary_status == NodeStatus.FAULT
        assert paired_engine.secondary_status == NodeStatus.FAULT

    def test_split_brain_clears_redundancy_healthy(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.simulate_split_brain()
        assert paired_engine.redundancy_healthy is False
        assert paired_engine.health_score == 0

    def test_split_brain_resolution_via_reset_fault(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.simulate_split_brain()
        assert paired_engine.diagnostic_code == 0xD403

        res = paired_engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert paired_engine.diagnostic_code == CipRedundancyDiagnosticCode.OK
        assert paired_engine.redundancy_state == CipRedundancyState.STANDBY
        assert paired_engine.primary_status == NodeStatus.STANDBY
        assert paired_engine.secondary_status == NodeStatus.STANDBY


# ============================================================================
# Section 9: Packet Loss Calculation & Health Scoring (0..100)
# ============================================================================

class TestPacketLossAndHealthScoring:
    """Tests for packet loss calculation, degradation tracking, and health score bounds [0..100]."""

    def test_packet_loss_calculation_zero_loss(self, paired_engine: CipRedundancyEngine) -> None:
        for _ in range(10):
            paired_engine.record_packet_transmission(success=True)
        assert paired_engine.calculate_packet_loss() == 0.0
        assert paired_engine.packet_loss_rate_pct == 0.0

    def test_packet_loss_calculation_with_drops(self, paired_engine: CipRedundancyEngine) -> None:
        for _ in range(990):
            paired_engine.record_packet_transmission(success=True)
        for _ in range(10):
            paired_engine.record_packet_transmission(success=False)
        # 10 dropped out of 1000 = 1.0% loss
        assert paired_engine.calculate_packet_loss() == 1.0

    def test_simulate_packet_loss_helper(self, paired_engine: CipRedundancyEngine) -> None:
        loss = paired_engine.simulate_packet_loss(dropped_count=15, total_count=10000)
        assert abs(loss - 0.15) < 1e-4
        assert abs(paired_engine.packet_loss_rate_pct - 0.15) < 1e-4

    def test_health_score_nominal_pairing_ge_80(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.calculate_health_score()
        assert paired_engine.health_score >= 80
        assert paired_engine.redundancy_healthy is True

    def test_health_score_single_link_loss_penalty(self, paired_engine: CipRedundancyEngine) -> None:
        init_score = paired_engine.calculate_health_score()
        paired_engine.primary_config.link1_up = False
        new_score = paired_engine.calculate_health_score()
        assert new_score < init_score

    def test_health_score_packet_loss_penalty(self, paired_engine: CipRedundancyEngine) -> None:
        init_score = paired_engine.calculate_health_score()
        paired_engine.simulate_packet_loss(dropped_count=50, total_count=100)
        new_score = paired_engine.calculate_health_score()
        assert new_score < init_score

    def test_health_score_heartbeat_timeout_penalty(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.diagnostic_code = CipRedundancyDiagnosticCode.HEARTBEAT_TIMEOUT
        paired_engine.calculate_health_score()
        assert paired_engine.health_score == 30
        assert paired_engine.redundancy_healthy is False

    def test_health_score_sync_degraded_penalty(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.simulate_sync_degraded(packet_loss_pct=5.0)
        assert paired_engine.diagnostic_code == CipRedundancyDiagnosticCode.SYNC_DEGRADED
        assert paired_engine.health_score == 50
        assert paired_engine.redundancy_healthy is False

    def test_health_score_bounded_between_0_and_100(self, paired_engine: CipRedundancyEngine) -> None:
        score = paired_engine.calculate_health_score()
        assert 0 <= score <= 100


# ============================================================================
# Section 10: Horner OCS Register Table Synchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Tests for Horner OCS memory map bindings (%R1570..%R1577, %M366..%M367) with PrivilegeMode.SYSTEM."""

    def test_register_sync_all_fields(self, empty_reg_table: RegisterTable) -> None:
        engine = CipRedundancyEngine(reg_table=empty_reg_table)
        engine.primary_status = NodeStatus.ACTIVE
        engine.secondary_status = NodeStatus.STANDBY
        engine.switchover_latency_ms = 18.5
        engine.active_node_selection = ActiveNodeSelection.PRIMARY
        engine.packet_loss_rate_pct = 0.25
        engine.heartbeat_seq_counter = 500
        engine.health_score = 90
        engine.diagnostic_code = CipRedundancyDiagnosticCode.OK
        engine.redundancy_healthy = True
        engine.failover_triggered = False

        engine.sync_to_registers(empty_reg_table, privilege=PrivilegeMode.SYSTEM)

        assert empty_reg_table.read_word("%R1570") == int(NodeStatus.ACTIVE)
        assert empty_reg_table.read_word("%R1571") == int(NodeStatus.STANDBY)
        assert empty_reg_table.read_word("%R1572") == 185  # 18.5 * 10
        assert empty_reg_table.read_word("%R1573") == int(ActiveNodeSelection.PRIMARY)
        assert empty_reg_table.read_word("%R1574") == 25   # 0.25 * 100
        assert empty_reg_table.read_word("%R1575") == 500
        assert empty_reg_table.read_word("%R1576") == 90
        assert empty_reg_table.read_uword("%R1577") == 0x0000
        assert empty_reg_table.read_bit("%M366") is True
        assert empty_reg_table.read_bit("%M367") is False

    def test_register_sync_diagnostic_fault_codes(self, empty_reg_table: RegisterTable) -> None:
        engine = CipRedundancyEngine(reg_table=empty_reg_table)
        for code in [0xD401, 0xD402, 0xD403, 0xD404]:
            engine.diagnostic_code = CipRedundancyDiagnosticCode(code)
            engine.sync_to_registers(empty_reg_table, privilege=PrivilegeMode.SYSTEM)
            assert empty_reg_table.read_uword("%R1577") == code

    def test_register_sync_failover_coil_m367(self, empty_reg_table: RegisterTable) -> None:
        engine = CipRedundancyEngine(reg_table=empty_reg_table)
        engine.failover_triggered = True
        engine.sync_to_registers(empty_reg_table, privilege=PrivilegeMode.SYSTEM)
        assert empty_reg_table.read_bit("%M367") is True

    def test_word_encoding_helpers(self, empty_reg_table: RegisterTable) -> None:
        safe_write_word(empty_reg_table, "%R1570", 2)
        assert empty_reg_table.read_word("%R1570") == 2

        safe_write_uword(empty_reg_table, "%R1577", 0xD401)
        assert empty_reg_table.read_uword("%R1577") == 0xD401

        safe_write_bit(empty_reg_table, "%M366", True)
        assert empty_reg_table.read_bit("%M366") is True
        safe_write_bit(empty_reg_table, "%M366", False)
        assert empty_reg_table.read_bit("%M366") is False

    def test_encode_decode_dint_words_roundtrip(self) -> None:
        v = 98765432
        hi, lo = encode_dint_words(v)
        rec = decode_dint_words(hi, lo)
        assert rec == v


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Simulation
# ============================================================================

class TestILogicUnitScanSimulation:
    """Tests for ILogicUnit interface, scan_step, execute, and engine reset."""

    def test_ilogicunit_properties(self, paired_engine: CipRedundancyEngine) -> None:
        assert paired_engine.name == "cip_redundancy"
        assert paired_engine.priority == 94
        assert paired_engine.is_enabled is True
        assert paired_engine.total_scan_cycles == 0
        assert paired_engine.elapsed_simulation_ms == 0.0

    def test_scan_step_clock_advancement(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.scan_step(dt=0.010)
        assert paired_engine.total_scan_cycles == 1
        assert round(paired_engine.elapsed_simulation_ms) == 10

    def test_execute_via_scan_context(self, paired_engine: CipRedundancyEngine, empty_reg_table: RegisterTable) -> None:
        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=empty_reg_table.read_register,
            set_register=lambda a, v: empty_reg_table.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: d,
            set_variable=lambda k, v: None,
            record_fault=lambda f: None,
        )
        paired_engine.execute(ctx)
        assert paired_engine.total_scan_cycles == 1
        assert round(paired_engine.elapsed_simulation_ms) == 10

    def test_100_scan_cycles_simulation(self, paired_engine: CipRedundancyEngine, empty_reg_table: RegisterTable) -> None:
        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=empty_reg_table.read_register,
            set_register=lambda a, v: empty_reg_table.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: d,
            set_variable=lambda k, v: None,
            record_fault=lambda f: None,
        )
        for c in range(1, 101):
            ctx.cycle = c
            ctx.elapsed_time_ms = c * 10.0
            paired_engine.execute(ctx)

        assert paired_engine.total_scan_cycles == 100
        assert round(paired_engine.elapsed_simulation_ms) == 1000

    def test_engine_reset(self, paired_engine: CipRedundancyEngine) -> None:
        paired_engine.simulate_split_brain()
        assert paired_engine.diagnostic_code == 0xD403
        paired_engine.reset()
        assert paired_engine.diagnostic_code == CipRedundancyDiagnosticCode.OK

    def test_get_snapshot_dictionary(self, paired_engine: CipRedundancyEngine) -> None:
        snap = paired_engine.get_snapshot()
        assert isinstance(snap, dict)
        assert "redundancy_state" in snap
        assert "health_score" in snap
        assert "switchover_latency_ms" in snap


# ============================================================================
# Section 12: Pure ST POU AST Validation & Anti-Ladder Interception
# ============================================================================

class TestPureStPouAndSecurityGuard:
    """Tests for Pure IEC 61131-3 Structured Text validation and anti-ladder rejection."""

    def test_st_pou_ast_structure_and_name(self) -> None:
        ast = STParser.parse_pou(CIP_REDUNDANCY_SYNC_POU)
        assert ast.name == "CipRedundancySync"
        assert ast.pou_type == POUType.PROGRAM
        assert CIP_REDUNDANCY_POU == CIP_REDUNDANCY_SYNC_POU
        assert CipRedundancySyncPOU == CIP_REDUNDANCY_SYNC_POU

    def test_st_pou_bound_registers(self) -> None:
        ast = STParser.parse_pou(CIP_REDUNDANCY_SYNC_POU)
        expected_registers = {
            "%R1570", "%R1571", "%R1572", "%R1573",
            "%R1574", "%R1575", "%R1576", "%R1577",
            "%M366", "%M367",
        }
        bound = set(ast.bound_registers)
        assert expected_registers.issubset(bound)

    def test_st_pou_syntax_validation(self) -> None:
        val = STParser.validate_code(CIP_REDUNDANCY_SYNC_POU)
        assert val.status == AgentStatus.SUCCESS

    def test_pure_st_security_guard_passes(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_REDUNDANCY_SYNC_POU)

    def test_anti_ladder_contacts_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---[ ]---")

    def test_anti_ladder_coils_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("---( )---")

    def test_anti_ladder_rung_network_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("RUNG 1")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("NETWORK 1")

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("XIC Primary_Active")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("OTE Failover_Trig")


# ============================================================================
# Section 13: Deterministic 9-Stage Verification Runner
# ============================================================================

class TestDeterministicVerificationRunner:
    """Tests for run_cip_redundancy_verification runner execution and evidence artifact generation."""

    def test_verification_runner_execution_success(self) -> None:
        res = run_cip_redundancy_verification()
        assert res["status"] == "success"
        assert res["stages_passed"] == 9
        assert res["total_stages"] == 9
        assert res["error_code"] is None
        assert "9/9 stages passed" in res["details"]

    def test_verification_runner_all_9_stages_pass(self) -> None:
        res = run_cip_redundancy_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9
        for st in stages:
            assert st["passed"] is True, f"Stage {st['stage']} ({st['check']}) failed!"

    def test_verification_runner_exports_json_evidence(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_redundancy_evidence.json"
        res = run_cip_redundancy_verification(output_path=out_file)
        assert res["status"] == "success"
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            evidence = json.load(f)
        assert evidence["status"] == "success"
        assert evidence["stages_passed"] == 9
        assert evidence["data"]["work_package"] == "W196"

    def test_verification_runner_evidence_registers_and_metadata(self) -> None:
        res = run_cip_redundancy_verification()
        data = res["data"]
        assert data["work_package"] == "W196"
        assert "standards" in data
        assert "register_map" in data
        assert "registers" in data
        assert "%R1570" in data["registers"]
        assert "%R1577" in data["registers"]
        assert "%M366" in data["registers"]
        assert "%M367" in data["registers"]
