"""Comprehensive Unit and Integration Test Suite for ODVA Device Level Ring (DLR) Engine.

Work Package: W202 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Test Coverage (75+ Unit Tests across 13 Sections):
1. Section 1: Constants, Enums & Protocol Defaults (DlrTopologyState, DlrSupervisorRole, etc.).
2. Section 2: DLR Protocol Frame Models & Wire Serialization (Beacon, Neighbor Check, Link Status, Flush Table, Sign On).
3. Section 3: ODVA CIP DLR Object (Class 0x47 attribute resolution and writable attribute controls).
4. Section 4: Active Ring Supervisor Initialization & Topology Management (Ring Start, Port 2 Blocking).
5. Section 5: High-Frequency Beacon Generation & Loss Tracking (400 μs interval, 200..1000 μs bounds, 0xDA01).
6. Section 6: Supervisor Precedence Election & Multi-Supervisor Conflict (Precedence yield, 0xDA02 conflict).
7. Section 7: Sub-3ms Fast Fault Detection & Port 2 Unblocking (< 3 ms recovery, Ring_Fault to Linear).
8. Section 8: Ring Restoration & MAC Flush Table Broadcast (Re-blocking Port 2, Learning update dispatch).
9. Section 9: Rapid Ring Flapping Detection & Safety Interlock Trip (> 3 transitions in 1 s, 0xDA03).
10. Section 10: Neighbor Check Protocol Handshake & Timeout Detection (0xDA04 trip).
11. Section 11: Horner OCS Register Table Synchronization (%R1630..%R1637, %M380..%M381 with PrivilegeMode.SYSTEM).
12. Section 12: ILogicUnit Scan Cycle Simulation (100-cycle scan simulation, execute, reset, timing).
13. Section 13: Pure ST POU AST Validation & Anti-Ladder Security Guard Interception (SecurityGuard, STParser).
14. Section 14: Deterministic 9-Stage Verification Runner (run_cip_dlr_verification execution and JSON export).
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
from jev_cscape.telemetry.cip_dlr import (
    BeaconFrame,
    CIP_DLR_CLASS_ID,
    CIP_DLR_ENGINE,
    CIP_DLR_POU,
    CIP_DLR_SYNC_POU,
    CIPDLRDiagnosticCode,
    CIPDLREngine,
    CIPDlrEngine,
    CipDlrDiagnosticCode,
    CipDlrEngine,
    CipDlrObject,
    CipDlrRole,
    CipDlrState,
    CipDlrSyncPOU,
    DEFAULT_BEACON_INTERVAL_US,
    DEFAULT_BEACON_TIMEOUT_US,
    DEFAULT_NEIGHBOR_CHECK_INTERVAL_MS,
    DEFAULT_NEIGHBOR_CHECK_TIMEOUT_MS,
    DEFAULT_RING_NODE_COUNT,
    DEFAULT_SUPERVISOR_IP,
    DEFAULT_SUPERVISOR_MAC,
    DEFAULT_SUPERVISOR_PRECEDENCE,
    DiagnosticStatusCode,
    DLR_ETHERTYPE,
    DLR_MULTICAST_NODE,
    DLR_MULTICAST_SUPERVISOR,
    DLR_VLAN_PCP,
    DlrAnnounceFrame,
    DlrBeaconFrame,
    DlrConfig,
    DlrDiagnosticCode,
    DlrEngine,
    DlrFlushTableFrame,
    DlrFrameType,
    DlrLinkStatusFrame,
    DlrLocateFaultFrame,
    DlrNeighborCheckRequestFrame,
    DlrNeighborCheckResponseFrame,
    DlrPortLinkState,
    DlrPortTrafficState,
    DlrRingNodeDescriptor,
    DlrSignOnFrame,
    DlrSupervisorRole,
    DlrSupervisorStatus,
    DlrTopologyState,
    FlushTableFrame,
    LinkStatusFrame,
    MAX_BEACON_INTERVAL_US,
    MAX_FAULT_RECOVERY_TIME_US,
    MIN_BEACON_INTERVAL_US,
    NeighborCheckRequestFrame,
    NeighborCheckResponseFrame,
    NOMINAL_FAULT_RECOVERY_TIME_US,
    SignOnFrame,
    SupervisorRole,
    SupervisorStatus,
    bytes_to_ip,
    bytes_to_mac,
    decode_dint_words,
    encode_dint_words,
    ip_to_bytes,
    mac_to_bytes,
    run_cip_dlr_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    verify_cip_dlr_pure_st,
)


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def empty_reg_table() -> RegisterTable:
    """Fixture providing clean RegisterTable."""
    return RegisterTable()


@pytest.fixture
def default_dlr_engine(empty_reg_table: RegisterTable) -> CipDlrEngine:
    """Fixture providing initialized Active Ring Supervisor engine."""
    return CipDlrEngine(reg_table=empty_reg_table)


# ============================================================================
# Section 1: Constants, Enums & Protocol Defaults
# ============================================================================

class TestCipDlrConstantsAndEnums:
    def test_protocol_constants(self) -> None:
        assert CIP_DLR_CLASS_ID == 0x47
        assert DLR_ETHERTYPE == 0x80E1
        assert DLR_VLAN_PCP == 7
        assert DLR_MULTICAST_SUPERVISOR == "01:21:6C:00:00:01"
        assert DLR_MULTICAST_NODE == "01:21:6C:00:00:02"
        assert DEFAULT_BEACON_INTERVAL_US == 400
        assert MIN_BEACON_INTERVAL_US == 200
        assert MAX_BEACON_INTERVAL_US == 1000
        assert MAX_FAULT_RECOVERY_TIME_US == 3000.0
        assert NOMINAL_FAULT_RECOVERY_TIME_US == 2450.0

    def test_dlr_topology_state_enum(self) -> None:
        assert DlrTopologyState.LINEAR_DISRUPTED == 0
        assert DlrTopologyState.RING_NORMAL == 1
        assert DlrTopologyState.RING_FAULT == 2
        assert DlrTopologyState.BACKUP_SUPERVISOR_ACTIVE == 3
        # Compatibility aliases
        assert CipDlrState == DlrTopologyState

    def test_dlr_supervisor_role_enum(self) -> None:
        assert DlrSupervisorRole.NON_SUPERVISOR == 0
        assert DlrSupervisorRole.BACKUP_SUPERVISOR == 1
        assert DlrSupervisorRole.ACTIVE_SUPERVISOR == 2
        assert CipDlrRole == DlrSupervisorRole

    def test_dlr_frame_type_enum(self) -> None:
        assert DlrFrameType.BEACON == 0x01
        assert DlrFrameType.NEIGHBOR_CHECK_REQUEST == 0x02
        assert DlrFrameType.NEIGHBOR_CHECK_RESPONSE == 0x03
        assert DlrFrameType.LINK_STATUS == 0x04
        assert DlrFrameType.LOCATE_FAULT == 0x05
        assert DlrFrameType.ANNOUNCE == 0x06
        assert DlrFrameType.SIGN_ON == 0x07
        assert DlrFrameType.FLUSH_TABLE == 0x08

    def test_dlr_diagnostic_codes_enum(self) -> None:
        assert DlrDiagnosticCode.OK == 0x0000
        assert DlrDiagnosticCode.BEACON_TIMEOUT == 0xDA01
        assert DlrDiagnosticCode.MULTIPLE_SUPERVISOR_CONFLICT == 0xDA02
        assert DlrDiagnosticCode.RAPID_RING_FLAPPING == 0xDA03
        assert DlrDiagnosticCode.NEIGHBOR_CHECK_TIMEOUT == 0xDA04
        assert CipDlrDiagnosticCode == DlrDiagnosticCode
        assert CIPDLRDiagnosticCode == DlrDiagnosticCode


# ============================================================================
# Section 2: DLR Protocol Frame Models & Wire Serialization
# ============================================================================

class TestDlrProtocolFramesAndSerialization:
    def test_mac_and_ip_helpers(self) -> None:
        mac_str = "00:1D:9C:C0:02:01"
        b_mac = mac_to_bytes(mac_str)
        assert len(b_mac) == 6
        assert bytes_to_mac(b_mac) == mac_str

        ip_str = "192.168.1.1"
        b_ip = ip_to_bytes(ip_str)
        assert len(b_ip) == 4
        assert bytes_to_ip(b_ip) == ip_str

    def test_beacon_frame_serialization(self) -> None:
        frame = DlrBeaconFrame(
            sequence_id=100,
            ring_state=DlrTopologyState.RING_NORMAL,
            supervisor_precedence=128,
            beacon_interval_us=400,
            beacon_timeout_us=1940,
            ring_node_count=16,
        )
        raw = frame.encode_bytes()
        decoded = DlrBeaconFrame.decode_bytes(raw)
        assert decoded is not None
        assert decoded.sequence_id == 100
        assert decoded.ring_state == DlrTopologyState.RING_NORMAL
        assert decoded.supervisor_precedence == 128
        assert decoded.beacon_interval_us == 400
        assert decoded.beacon_timeout_us == 1940
        assert decoded.ring_node_count == 16
        d = frame.to_dict()
        assert d["frame_type"] == "BEACON"
        assert d["supervisor_precedence"] == 128

    def test_neighbor_check_request_frame_serialization(self) -> None:
        req = DlrNeighborCheckRequestFrame(
            source_mac="00:1D:9C:C0:02:05",
            source_port=2,
            sequence_id=45,
        )
        raw = req.encode_bytes()
        dec = DlrNeighborCheckRequestFrame.decode_bytes(raw)
        assert dec is not None
        assert dec.source_mac == "00:1D:9C:C0:02:05"
        assert dec.source_port == 2
        assert dec.sequence_id == 45

    def test_neighbor_check_response_frame_serialization(self) -> None:
        resp = DlrNeighborCheckResponseFrame(
            source_mac="00:1D:9C:C0:02:06",
            target_mac="00:1D:9C:C0:02:05",
            target_port=2,
            sequence_id=45,
        )
        raw = resp.encode_bytes()
        dec = DlrNeighborCheckResponseFrame.decode_bytes(raw)
        assert dec is not None
        assert dec.source_mac == "00:1D:9C:C0:02:06"
        assert dec.target_mac == "00:1D:9C:C0:02:05"
        assert dec.target_port == 2
        assert dec.sequence_id == 45

    def test_link_status_frame_serialization(self) -> None:
        frame = DlrLinkStatusFrame(
            source_mac="00:1D:9C:C0:02:07",
            port1_status=DlrPortLinkState.LINK_UP,
            port2_status=DlrPortLinkState.LINK_DOWN,
            sequence_id=12,
        )
        raw = frame.encode_bytes()
        dec = DlrLinkStatusFrame.decode_bytes(raw)
        assert dec is not None
        assert dec.source_mac == "00:1D:9C:C0:02:07"
        assert dec.port1_status == DlrPortLinkState.LINK_UP
        assert dec.port2_status == DlrPortLinkState.LINK_DOWN
        assert dec.sequence_id == 12

    def test_sign_on_frame_serialization(self) -> None:
        frame = DlrSignOnFrame(
            node_mac="00:1D:9C:C0:02:08",
            node_ip="192.168.1.8",
            is_supervisor_capable=True,
            sequence_id=3,
        )
        raw = frame.encode_bytes()
        dec = DlrSignOnFrame.decode_bytes(raw)
        assert dec is not None
        assert dec.node_mac == "00:1D:9C:C0:02:08"
        assert dec.node_ip == "192.168.1.8"
        assert dec.is_supervisor_capable is True

    def test_flush_table_frame_serialization(self) -> None:
        frame = DlrFlushTableFrame(
            supervisor_mac="00:1D:9C:C0:02:01",
            learning_update_seq=99,
            sequence_id=101,
        )
        raw = frame.encode_bytes()
        dec = DlrFlushTableFrame.decode_bytes(raw)
        assert dec is not None
        assert dec.supervisor_mac == "00:1D:9C:C0:02:01"
        assert dec.learning_update_seq == 99
        assert dec.sequence_id == 101


# ============================================================================
# Section 3: ODVA CIP DLR Object (Class 0x47)
# ============================================================================

class TestCipDlrObject:
    def test_cip_dlr_object_attributes_resolution(self) -> None:
        obj = CipDlrObject(
            active_supervisor_precedence=120,
            beacon_interval_us=400,
            beacon_timeout_us=1940,
            ring_node_count=16,
        )
        assert obj.class_id == 0x47
        assert obj.get_attribute(1) == 2   # Ring topology
        assert obj.get_attribute(2) == 0   # Normal status
        assert obj.get_attribute(3) == 1   # Active supervisor
        assert obj.get_attribute(4) == 120 # Precedence
        assert obj.get_attribute(5) == 400 # Beacon interval
        assert obj.get_attribute(6) == 1940 # Timeout
        assert obj.get_attribute(7) == 16  # Node count
        assert obj.get_attribute(10) == 0x0003 # Capabilities

    def test_cip_dlr_object_set_attributes(self) -> None:
        obj = CipDlrObject()
        assert obj.set_attribute(4, 200) is True
        assert obj.active_supervisor_precedence == 200

        # Writable beacon interval within 200..1000
        assert obj.set_attribute(5, 500) is True
        assert obj.beacon_interval_us == 500
        assert obj.set_attribute(5, 100) is False # Out of range

    def test_cip_dlr_object_invalid_attribute(self) -> None:
        obj = CipDlrObject()
        with pytest.raises(KeyError):
            obj.get_attribute(99)


# ============================================================================
# Section 4: Active Ring Supervisor Initialization & Topology Management
# ============================================================================

class TestSupervisorInitializationAndTopology:
    def test_engine_initialization_defaults(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        assert engine.role == DlrSupervisorRole.ACTIVE_SUPERVISOR
        assert engine.topology_state == DlrTopologyState.RING_NORMAL
        assert engine.port1_link == DlrPortLinkState.LINK_UP
        assert engine.port2_link == DlrPortLinkState.LINK_UP
        assert engine.port1_traffic == DlrPortTrafficState.UNBLOCKED
        assert engine.port2_traffic == DlrPortTrafficState.BLOCKED
        assert engine.beacon_interval_us == 400
        assert engine.fault_recovery_time_us == 2450.0
        assert engine.ring_node_count == 16
        assert engine.network_health_score == 100
        assert engine.diagnostic_code == DlrDiagnosticCode.OK

    def test_start_ring_resets_and_broadcasts_flush_table(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.topology_state = DlrTopologyState.LINEAR_DISRUPTED
        assert engine.start_ring() is True
        assert engine.topology_state == DlrTopologyState.RING_NORMAL
        assert engine.port2_traffic == DlrPortTrafficState.BLOCKED
        assert engine.flush_tables_sent >= 1


# ============================================================================
# Section 5: High-Frequency Beacon Generation & Loss Tracking
# ============================================================================

class TestBeaconGenerationAndLossTracking:
    def test_beacon_generation(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        b1 = engine.generate_beacon()
        b2 = engine.generate_beacon()
        assert b1.sequence_id == 1
        assert b2.sequence_id == 2
        assert engine.beacons_sent == 2
        assert b1.ring_state == DlrTopologyState.RING_NORMAL
        assert b1.supervisor_precedence == DEFAULT_SUPERVISOR_PRECEDENCE

    def test_beacon_loopback_processing(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        b = engine.generate_beacon()
        assert engine.process_beacon(b, ingress_port=2) is True
        assert engine.beacon_loss_counter == 0
        assert engine.beacons_received_port2 >= 1

    def test_beacon_loss_simulation_trips_0xda01(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.simulate_beacon_loss(count=3)
        assert engine.beacon_loss_counter == 3
        assert engine.diagnostic_code == DlrDiagnosticCode.BEACON_TIMEOUT
        assert engine.topology_state == DlrTopologyState.RING_FAULT


# ============================================================================
# Section 6: Supervisor Precedence Election & Multi-Supervisor Conflict
# ============================================================================

class TestSupervisorPrecedenceAndConflict:
    def test_higher_precedence_yields_to_backup_supervisor(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.active_precedence = 100
        high_beacon = DlrBeaconFrame(
            source_mac="00:1D:9C:C0:02:99",
            sequence_id=1,
            supervisor_precedence=150,
        )
        assert engine.process_beacon(high_beacon, ingress_port=1) is True
        assert engine.role == DlrSupervisorRole.BACKUP_SUPERVISOR
        assert engine.topology_state == DlrTopologyState.BACKUP_SUPERVISOR_ACTIVE
        assert engine.active_precedence == 150
        assert engine.port2_traffic == DlrPortTrafficState.UNBLOCKED

    def test_equal_precedence_higher_mac_yields(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.supervisor_mac = "00:1D:9C:C0:02:01"
        engine.active_precedence = 100
        high_mac_beacon = DlrBeaconFrame(
            source_mac="00:1D:9C:C0:02:FF", # Higher MAC
            sequence_id=1,
            supervisor_precedence=100,       # Equal precedence
        )
        assert engine.process_beacon(high_mac_beacon, ingress_port=1) is True
        assert engine.role == DlrSupervisorRole.BACKUP_SUPERVISOR

    def test_lower_precedence_rogue_supervisor_trips_0xda02(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.simulate_multiple_supervisor_conflict(
            other_mac="00:1D:9C:C0:09:99",
            other_precedence=80,
        )
        assert engine.diagnostic_code == DlrDiagnosticCode.MULTIPLE_SUPERVISOR_CONFLICT


# ============================================================================
# Section 7: Sub-3ms Fast Fault Detection & Port 2 Unblocking
# ============================================================================

class TestSub3msFastFaultDetection:
    def test_trigger_link_fault_transitions_to_ring_fault(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        recovery_time = engine.trigger_link_fault(port=1)
        assert recovery_time == 2450.0
        assert recovery_time < MAX_FAULT_RECOVERY_TIME_US # Strictly < 3000 μs
        assert engine.topology_state == DlrTopologyState.RING_FAULT
        assert engine.port1_link == DlrPortLinkState.LINK_DOWN
        assert engine.port2_traffic == DlrPortTrafficState.UNBLOCKED # Unblocked for linear mode
        assert engine.flush_tables_sent >= 1

    def test_link_status_frame_triggers_fault(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        frame = DlrLinkStatusFrame(
            source_mac="00:1D:9C:C0:02:02",
            port1_status=DlrPortLinkState.LINK_DOWN,
            port2_status=DlrPortLinkState.LINK_UP,
        )
        engine.process_link_status(frame)
        assert engine.topology_state == DlrTopologyState.RING_FAULT


# ============================================================================
# Section 8: Ring Restoration & MAC Flush Table Broadcast
# ============================================================================

class TestRingRestorationAndFlushTable:
    def test_restore_link_reblocks_port2(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.trigger_link_fault(port=1)
        flushes_before = engine.flush_tables_sent

        assert engine.restore_link(port=1) is True
        assert engine.topology_state == DlrTopologyState.RING_NORMAL
        assert engine.port1_link == DlrPortLinkState.LINK_UP
        assert engine.port2_link == DlrPortLinkState.LINK_UP
        assert engine.port2_traffic == DlrPortTrafficState.BLOCKED
        assert engine.flush_tables_sent > flushes_before

    def test_link_status_frame_restores_ring(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.trigger_link_fault(port=1)
        frame = DlrLinkStatusFrame(
            source_mac="00:1D:9C:C0:02:02",
            port1_status=DlrPortLinkState.LINK_UP,
            port2_status=DlrPortLinkState.LINK_UP,
        )
        engine.process_link_status(frame)
        assert engine.topology_state == DlrTopologyState.RING_NORMAL


# ============================================================================
# Section 9: Rapid Ring Flapping Detection & Safety Interlock Trip
# ============================================================================

class TestRapidRingFlapping:
    def test_rapid_flapping_trips_0xda03(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.simulate_rapid_flapping(transition_count=4)
        assert engine.diagnostic_code == DlrDiagnosticCode.RAPID_RING_FLAPPING
        assert engine.network_health_score < 80

    def test_reset_diagnostic_clears_flapping(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.simulate_rapid_flapping(transition_count=4)
        engine.reset_diagnostic()
        assert engine.diagnostic_code == DlrDiagnosticCode.OK
        assert engine.network_health_score == 100


# ============================================================================
# Section 10: Neighbor Check Protocol Handshake & Timeout Detection
# ============================================================================

class TestNeighborCheckHandshakeAndTimeout:
    def test_neighbor_check_request_and_response(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        req = engine.send_neighbor_check_request("00:1D:9C:C0:02:03", port=1)
        assert req.source_port == 1
        resp = engine.process_neighbor_check_request(req)
        assert resp.target_mac == "00:1D:9C:C0:02:03"
        assert engine.process_neighbor_check_response(resp) is True

    def test_neighbor_check_timeout_trips_0xda04(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.simulate_neighbor_check_timeout("00:1D:9C:C0:02:04")
        assert engine.diagnostic_code == DlrDiagnosticCode.NEIGHBOR_CHECK_TIMEOUT


# ============================================================================
# Section 11: Horner OCS Register Table Synchronization
# ============================================================================

class TestHornerRegisterSynchronization:
    def test_register_sync_nominal(self, default_dlr_engine: CipDlrEngine, empty_reg_table: RegisterTable) -> None:
        engine = default_dlr_engine
        rt = empty_reg_table
        engine.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)

        assert rt.read_word("%R1630") == int(DlrTopologyState.RING_NORMAL)
        assert rt.read_word("%R1631") == 2450
        assert rt.read_word("%R1632") == DEFAULT_SUPERVISOR_PRECEDENCE
        assert rt.read_word("%R1633") == 16
        assert rt.read_word("%R1634") == 400
        assert rt.read_word("%R1635") == 0
        assert rt.read_word("%R1636") == 100
        assert rt.read_uword("%R1637") == int(DlrDiagnosticCode.OK)
        assert rt.read_bit("%M380") is True
        assert rt.read_bit("%M381") is False

    def test_register_sync_on_ring_fault(self, default_dlr_engine: CipDlrEngine, empty_reg_table: RegisterTable) -> None:
        engine = default_dlr_engine
        rt = empty_reg_table
        engine.trigger_link_fault(port=1)
        engine.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)

        assert rt.read_word("%R1630") == int(DlrTopologyState.RING_FAULT)
        assert rt.read_bit("%M380") is False
        assert rt.read_bit("%M381") is True

    def test_dint_words_encoding_roundtrip(self) -> None:
        high, low = encode_dint_words(123456789)
        val = decode_dint_words(high, low)
        assert val == 123456789


# ============================================================================
# Section 12: ILogicUnit Scan Cycle Simulation
# ============================================================================

class TestILogicUnitScanSimulation:
    def test_ilogicunit_properties(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        assert engine.name == "cip_dlr"
        assert engine.priority == 96
        assert engine.is_enabled is True

    def test_scan_step_clock_advancement(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.scan_step(dt=0.010) # 10 ms
        assert engine.elapsed_simulation_us == 10000.0
        assert engine.total_scan_cycles == 1

    def test_100_scan_cycles_simulation(self, default_dlr_engine: CipDlrEngine, empty_reg_table: RegisterTable) -> None:
        engine = default_dlr_engine
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
        for i in range(1, 101):
            ctx.cycle = i
            ctx.elapsed_time_ms = i * 10.0
            engine.execute(ctx)
        assert engine.total_scan_cycles == 100
        assert engine.elapsed_simulation_us == 1000000.0
        assert engine.beacons_sent > 0

    def test_engine_reset(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.trigger_link_fault(port=1)
        engine.reset()
        assert engine.topology_state == DlrTopologyState.RING_NORMAL
        assert engine.port2_traffic == DlrPortTrafficState.BLOCKED
        assert engine.diagnostic_code == DlrDiagnosticCode.OK

    def test_snapshot_dictionary(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        snap = engine.get_snapshot()
        assert snap["topology_state"] == "RING_NORMAL"
        assert snap["fault_recovery_time_us"] == 2450.0
        assert snap["beacon_interval_us"] == 400


# ============================================================================
# Section 13: Pure ST POU AST Validation & Anti-Ladder Security Guard Interception
# ============================================================================

class TestPureStPouAndSecurityGuard:
    def test_pure_st_pou_syntax_and_ast(self) -> None:
        assert verify_cip_dlr_pure_st() is True
        parser = STParser()
        pou = parser.parse_pou(CIP_DLR_SYNC_POU)
        assert pou is not None
        assert pou.name == "CipDlrSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_pure_st_bound_registers(self) -> None:
        parser = STParser()
        pou = parser.parse_pou(CIP_DLR_SYNC_POU)
        assert pou is not None
        bound = {v.name: v.address_binding for v in pou.variables if v.address_binding}
        assert bound["DlrTopologyState"] == "%R1630"
        assert bound["FaultRecoveryTimeUs"] == "%R1631"
        assert bound["ActiveSupervisorPrecedence"] == "%R1632"
        assert bound["RingNodeCount"] == "%R1633"
        assert bound["BeaconIntervalUs"] == "%R1634"
        assert bound["BeaconLossCounter"] == "%R1635"
        assert bound["NetworkHealthScore"] == "%R1636"
        assert bound["DiagnosticStatusCode"] == "%R1637"
        assert bound["DlrRingHealthy"] == "%M380"
        assert bound["RingFaultDetected"] == "%M381"

    def test_anti_ladder_contacts_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("""
            PROGRAM BadLadderContacts
            VAR bit : BOOL; END_VAR
            ---[ ]---
            END_PROGRAM
            """)

    def test_anti_ladder_coils_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("""
            PROGRAM BadLadderCoils
            VAR bit : BOOL; END_VAR
            ---( )---
            END_PROGRAM
            """)

    def test_anti_ladder_rung_delimiters_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("""
            PROGRAM BadLadderRung
            RUNG 1
            END_PROGRAM
            """)

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("""
            PROGRAM BadLadderMnemonics
            XIC InputBit
            OTE OutputBit
            END_PROGRAM
            """)


# ============================================================================
# Section 13B: Edge Cases, Malformed Frames & Boundary Conditions
# ============================================================================

class TestEdgeCasesAndBoundaryConditions:
    def test_engine_constructor_boundaries(self) -> None:
        # Interval clamped to [200, 1000]
        e_low = CipDlrEngine(beacon_interval_us=50)
        assert e_low.beacon_interval_us == MIN_BEACON_INTERVAL_US

        e_high = CipDlrEngine(beacon_interval_us=5000)
        assert e_high.beacon_interval_us == MAX_BEACON_INTERVAL_US

        # Precedence clamped to [0, 255]
        e_prec_high = CipDlrEngine(supervisor_precedence=300)
        assert e_prec_high.supervisor_precedence == 255

        e_prec_low = CipDlrEngine(supervisor_precedence=-50)
        assert e_prec_low.supervisor_precedence == 0

        # Ring node count min 2
        e_nodes = CipDlrEngine(ring_node_count=1)
        assert e_nodes.ring_node_count >= 2

    def test_malformed_beacon_frame_decode(self) -> None:
        assert DlrBeaconFrame.decode_bytes(b"short") is None
        assert DlrBeaconFrame.decode_bytes(b"\x00" * 30) is None # Bad ethertype

    def test_malformed_neighbor_check_frames_decode(self) -> None:
        assert DlrNeighborCheckRequestFrame.decode_bytes(b"short") is None
        assert DlrNeighborCheckResponseFrame.decode_bytes(b"short") is None

    def test_malformed_link_status_and_flush_table_decode(self) -> None:
        assert DlrLinkStatusFrame.decode_bytes(b"short") is None
        assert DlrFlushTableFrame.decode_bytes(b"short") is None
        assert DlrSignOnFrame.decode_bytes(b"short") is None

    def test_sign_on_registration_expands_node_directory(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        initial_count = len(engine.ring_nodes)
        sign_on_frame = DlrSignOnFrame(
            node_mac="00:1D:9C:C0:02:AA",
            node_ip="192.168.1.170",
            is_supervisor_capable=True,
        )
        engine.process_sign_on(sign_on_frame)
        assert len(engine.ring_nodes) == initial_count + 1
        assert "00:1D:9C:C0:02:AA" in engine.ring_nodes
        assert engine.ring_node_count == len(engine.ring_nodes)

    def test_health_score_accumulated_penalties(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.topology_state = DlrTopologyState.RING_FAULT # -30
        engine.beacon_loss_counter = 5                      # -10
        engine.diagnostic_code = DlrDiagnosticCode.BEACON_TIMEOUT # -25
        score = engine.calculate_health_score()
        assert score == (100 - 30 - 10 - 25) # 35
        assert score == engine.network_health_score

    def test_health_score_linear_disrupted_clamp(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.topology_state = DlrTopologyState.LINEAR_DISRUPTED # -50
        engine.beacon_loss_counter = 20                           # -20 (max cap)
        engine.diagnostic_code = DlrDiagnosticCode.RAPID_RING_FLAPPING # -25
        score = engine.calculate_health_score()
        assert score == (100 - 50 - 20 - 25) # 5
        assert 0 <= score <= 100

    def test_safe_write_word_overflow_handling(self, empty_reg_table: RegisterTable) -> None:
        rt = empty_reg_table
        safe_write_word(rt, "%R1630", 40000, privilege=PrivilegeMode.SYSTEM)
        val = rt.read_word("%R1630")
        assert val < 0 # Signed wrap

    def test_safe_write_uword_and_bit(self, empty_reg_table: RegisterTable) -> None:
        rt = empty_reg_table
        safe_write_uword(rt, "%R1637", 0xDA01, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_uword("%R1637") == 0xDA01
        safe_write_bit(rt, "%M380", True, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_bit("%M380") is True
        safe_write_bit(rt, "%M380", False, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_bit("%M380") is False

    def test_tie_breaking_equal_precedence_lower_mac_rejected(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.supervisor_mac = "00:1D:9C:C0:02:80"
        engine.active_precedence = 100
        # Remote has equal precedence but lower MAC -> rejected as conflict
        lower_mac_beacon = DlrBeaconFrame(
            source_mac="00:1D:9C:C0:02:10",
            sequence_id=5,
            supervisor_precedence=100,
        )
        assert engine.process_beacon(lower_mac_beacon, ingress_port=1) is False
        assert engine.diagnostic_code == DlrDiagnosticCode.MULTIPLE_SUPERVISOR_CONFLICT

    def test_beacon_transmitted_during_ring_fault(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.trigger_link_fault(port=1)
        assert engine.topology_state == DlrTopologyState.RING_FAULT
        sent_before = engine.beacons_sent
        engine.scan_step(dt=0.005) # 5 ms > 400 us
        assert engine.beacons_sent > sent_before

    def test_neighbor_check_request_port2(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        req = engine.send_neighbor_check_request("00:1D:9C:C0:02:04", port=2)
        assert req.source_port == 2

    def test_sign_on_duplicate_mac_does_not_increment_count(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        count_before = engine.ring_node_count
        first_mac = next(iter(engine.ring_nodes.keys()))
        frame = DlrSignOnFrame(node_mac=first_mac, node_ip="192.168.1.100")
        engine.process_sign_on(frame)
        assert engine.ring_node_count == count_before

    def test_cip_dlr_object_fault_count_and_recovery_time_attributes(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.trigger_link_fault(port=1)
        engine.trigger_link_fault(port=2)
        assert engine.dlr_object.get_attribute(11) == 2
        assert engine.dlr_object.get_attribute(12) == int(engine.fault_recovery_time_us)

    def test_cip_dlr_object_set_timeout_attribute(self) -> None:
        obj = CipDlrObject()
        assert obj.set_attribute(6, 2500) is True
        assert obj.beacon_timeout_us == 2500
        assert obj.set_attribute(6, 100) is True # clamped to min 400
        assert obj.beacon_timeout_us >= 400
        assert obj.set_attribute(99, 123) is False # non-writable attr

    def test_dint_words_negative_roundtrip(self) -> None:
        h, l = encode_dint_words(-987654)
        val = decode_dint_words(h, l)
        assert val == -987654

    def test_ring_node_descriptor_to_dict(self) -> None:
        node = DlrRingNodeDescriptor(
            node_id=3,
            mac_address="00:1D:9C:C0:02:03",
            ip_address="192.168.1.3",
            is_supervisor_capable=False,
            precedence=20,
        )
        d = node.to_dict()
        assert d["node_id"] == 3
        assert d["mac_address"] == "00:1D:9C:C0:02:03"
        assert d["port1_link"] == "LINK_UP"

    def test_all_frames_to_dict_structure(self) -> None:
        nc_req = DlrNeighborCheckRequestFrame().to_dict()
        assert nc_req["frame_type"] == "NEIGHBOR_CHECK_REQUEST"
        nc_resp = DlrNeighborCheckResponseFrame().to_dict()
        assert nc_resp["frame_type"] == "NEIGHBOR_CHECK_RESPONSE"
        ls = DlrLinkStatusFrame().to_dict()
        assert ls["frame_type"] == "LINK_STATUS"
        so = DlrSignOnFrame().to_dict()
        assert so["frame_type"] == "SIGN_ON"
        ft = DlrFlushTableFrame().to_dict()
        assert ft["frame_type"] == "FLUSH_TABLE"

    def test_reset_diagnostic_with_force_parameter(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        engine.diagnostic_code = DlrDiagnosticCode.BEACON_TIMEOUT
        engine.reset_diagnostic(force=True)
        assert engine.diagnostic_code == DlrDiagnosticCode.OK

    def test_st_pou_aliases_identity(self) -> None:
        assert CIP_DLR_POU == CIP_DLR_SYNC_POU
        assert CipDlrSyncPOU == CIP_DLR_SYNC_POU
        assert verify_cip_dlr_pure_st() is True

    def test_dlr_config_defaults_and_to_dict(self) -> None:
        cfg = DlrConfig()
        assert cfg.supervisor_enabled is True
        assert cfg.supervisor_precedence == DEFAULT_SUPERVISOR_PRECEDENCE
        assert cfg.beacon_interval_us == DEFAULT_BEACON_INTERVAL_US
        assert cfg.beacon_timeout_us == DEFAULT_BEACON_TIMEOUT_US
        assert cfg.supervisor_mac == DEFAULT_SUPERVISOR_MAC
        assert cfg.supervisor_ip == DEFAULT_SUPERVISOR_IP
        d = cfg.to_dict()
        assert isinstance(d, dict)
        assert d["supervisor_enabled"] is True
        assert d["beacon_interval_us"] == 400

    def test_engine_initialized_from_dlr_config(self, empty_reg_table: RegisterTable) -> None:
        cfg = DlrConfig(
            supervisor_precedence=175,
            beacon_interval_us=500,
            beacon_timeout_us=2500,
            ring_node_count=8,
        )
        engine = CipDlrEngine(config=cfg, reg_table=empty_reg_table)
        assert engine.config == cfg
        assert engine.active_precedence == 175
        assert engine.beacon_interval_us == 500
        assert engine.beacon_timeout_us == 2500
        assert engine.ring_node_count == 8

    def test_engine_method_aliases(self, default_dlr_engine: CipDlrEngine) -> None:
        engine = default_dlr_engine
        b = engine.transmit_beacon()
        assert isinstance(b, DlrBeaconFrame)
        res = engine.receive_beacon(b, ingress_port=2)
        assert res is True

        recovery_us = engine.trigger_ring_fault(port=1)
        assert recovery_us < MAX_FAULT_RECOVERY_TIME_US
        assert engine.topology_state == DlrTopologyState.RING_FAULT

        healed = engine.heal_ring(port=1)
        assert healed is True
        assert engine.topology_state == DlrTopologyState.RING_NORMAL

        ft = engine.dispatch_flush_table()
        assert isinstance(ft, DlrFlushTableFrame)

    def test_scan_step_with_scan_context_object(self, default_dlr_engine: CipDlrEngine, empty_reg_table: RegisterTable) -> None:
        engine = default_dlr_engine
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
        engine.scan_step(ctx)
        assert engine.total_scan_cycles == 1
        assert engine.elapsed_simulation_us == 10000.0

    def test_linear_topology_alias(self) -> None:
        assert DlrTopologyState.LINEAR == 0
        assert DlrTopologyState.Linear == 0
        assert DlrTopologyState.LINEAR == DlrTopologyState.LINEAR_DISRUPTED

    def test_supervisor_status_role_aliases(self) -> None:
        assert DlrSupervisorStatus == DlrSupervisorRole
        assert SupervisorRole == DlrSupervisorRole
        assert SupervisorStatus == DlrSupervisorRole
        assert DlrSupervisorStatus.ACTIVE_SUPERVISOR == 2

    def test_frame_alias_identity(self) -> None:
        assert BeaconFrame == DlrBeaconFrame
        assert FlushTableFrame == DlrFlushTableFrame
        assert NeighborCheckRequestFrame == DlrNeighborCheckRequestFrame
        assert NeighborCheckResponseFrame == DlrNeighborCheckResponseFrame
        assert LinkStatusFrame == DlrLinkStatusFrame
        assert SignOnFrame == DlrSignOnFrame

    def test_engine_class_aliases(self) -> None:
        assert CIPDlrEngine == CipDlrEngine
        assert CIP_DLR_ENGINE == CipDlrEngine

    def test_neighbor_check_failed_diagnostic_code(self) -> None:
        assert DlrDiagnosticCode.NEIGHBOR_CHECK_FAILED == 0xDA04
        assert DlrDiagnosticCode.ERR_NEIGHBOR_CHECK_FAILED == 0xDA04


# ============================================================================
# Section 14: Deterministic 9-Stage Verification Runner
# ============================================================================

class TestDeterministicVerificationRunner:
    def test_verification_runner_execution_success(self) -> None:
        result = run_cip_dlr_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["stages_passed"] == 9
        assert result["data"]["total_stages"] == 9

    def test_verification_runner_all_9_stages_pass(self) -> None:
        result = run_cip_dlr_verification()
        stages = result["data"]["stages"]
        assert len(stages) == 9
        for stage in stages:
            assert stage["passed"] is True, f"Stage {stage['stage']} ({stage['name']}) failed"

    def test_verification_runner_exports_json_evidence(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_dlr_verification.json"
        result = run_cip_dlr_verification(output_path=out_file)
        assert out_file.exists()
        with open(out_file, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["status"] == "success"
        assert loaded["data"]["work_package"] == "W202"
        assert loaded["data"]["stages_passed"] == 9
