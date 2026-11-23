"""Unit Test Suite for Industrial DeviceNet Master Protocol Engine.

Work Package: W106 (Gate G8 / G4 - Industrial Protocols / Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Pure ST POU AST validation and anti-ladder check (verify_devicenet_pure_st).
2. CAN ID encoding: Group 1 poll response (make_group1_poll_response_can_id) and Group 2 IDs (make_group2_can_id).
3. Multi-frame fragmentation and reassembly (FragmentationEngine): normal reassembly, timeout, sequence gap, orphan.
4. Duplicate MAC ID check with collision detection asserting %M157 and diagnostic code 0x8302.
5. Master state machine transitions (OFFLINE -> RUNNING -> FAULT_LOCKED).
6. Cyclic polled I/O data produce and consume exchange.
7. Bus fault diagnostics: 3 consecutive timeouts triggering slave drop and SCANLIST_MISMATCH, and CAN Bus-Off condition asserting %M157 and code 0x8304.
8. Horner OCS register space synchronization (%R670..%R677, %M156..%M157).
9. Anti-ladder security guard rejection (LadderForbiddenError on contacts/coils).
10. End-to-end 9-stage verification suite (run_devicenet_verification).
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.devicenet import (
    DEVICENET_DEFAULT_EPR_MS,
    DEVICENET_FRAG_TIMEOUT_S,
    DEVICENET_MAX_SLAVES,
    DEVICENET_PURE_ST_POU,
    DeviceNetDiagnosticCode,
    DeviceNetMasterEngine,
    DeviceNetMasterState,
    DeviceNetMasterStatusBits,
    DeviceNetSlaveDescriptor,
    FRAG_SEQ_MASK,
    FRAG_TYPE_END,
    FRAG_TYPE_FIRST,
    FRAG_TYPE_MIDDLE,
    FragmentationEngine,
    GRP2_MSG_DUP_MAC_CHECK,
    GRP2_MSG_EXPLICIT_FRAG,
    GRP2_MSG_EXPLICIT_NON_FRAG,
    GRP2_MSG_MASTER_POLL_REQ,
    SlavePollState,
    make_group1_poll_response_can_id,
    make_group2_can_id,
    run_devicenet_verification,
    verify_devicenet_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def master_engine(register_table: RegisterTable) -> DeviceNetMasterEngine:
    """Provide a DeviceNetMasterEngine initialized with MAC ID 0."""
    return DeviceNetMasterEngine(master_mac_id=0, register_table=register_table)


@pytest.fixture
def frag_engine() -> FragmentationEngine:
    """Provide a standard FragmentationEngine instance."""
    return FragmentationEngine(timeout_s=1.0)


# ============================================================================
# Section 1: Pure ST POU AST Validation & Anti-Ladder Guard
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for Pure Structured Text POU validation and anti-ladder compliance."""

    def test_verify_devicenet_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_devicenet_pure_st() is True

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Parse DEVICENET_PURE_ST_POU using STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(DEVICENET_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "DeviceNetMasterSync"
        assert pou.pou_type == POUType.PROGRAM

        # Check declared variable names and direct address bindings
        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "MasterStatusWord",
            "ConfiguredSlaveCount",
            "ActiveSlaveMaskLow",
            "ActiveSlaveMaskMid",
            "ActiveSlaveMaskHigh",
            "TotalTelegramXfers",
            "FragmentationErrCnt",
            "DiagnosticEventCode",
            "MasterBusNormalActive",
            "DeviceNetBusFaultTrip",
        }
        assert expected_vars.issubset(var_names)

        # Verify address mappings
        var_map = {v.name: v for v in pou.variables}
        assert var_map["MasterStatusWord"].address_binding == "%R670"
        assert var_map["ConfiguredSlaveCount"].address_binding == "%R671"
        assert var_map["ActiveSlaveMaskLow"].address_binding == "%R672"
        assert var_map["ActiveSlaveMaskMid"].address_binding == "%R673"
        assert var_map["ActiveSlaveMaskHigh"].address_binding == "%R674"
        assert var_map["TotalTelegramXfers"].address_binding == "%R675"
        assert var_map["FragmentationErrCnt"].address_binding == "%R676"
        assert var_map["DiagnosticEventCode"].address_binding == "%R677"
        assert var_map["MasterBusNormalActive"].address_binding == "%M156"
        assert var_map["DeviceNetBusFaultTrip"].address_binding == "%M157"

        # Verify bound registers extracted by parser
        assert "%R670" in pou.bound_registers
        assert "%M156" in pou.bound_registers
        assert "%M157" in pou.bound_registers

    def test_security_guard_assert_pure_st_content_accepts_pou(self) -> None:
        """Assert SecurityGuard accepts the authentic pure ST POU."""
        SecurityGuard.assert_pure_st_content(DEVICENET_PURE_ST_POU)


# ============================================================================
# Section 2: CAN ID Encoding (Group 1 & Group 2)
# ============================================================================

class TestSection2CANIDEncoding:
    """Tests for 11-bit CAN ID encoding across DeviceNet Predefined Master/Slave sets."""

    def test_group1_poll_response_can_id_encoding(self) -> None:
        """Verify Group 1 Slave Poll Response CAN ID generation (0x3C0 | MAC_ID)."""
        # MAC ID 0
        cid_0 = make_group1_poll_response_can_id(0)
        assert cid_0 == 0x3C0

        # MAC ID 3
        cid_3 = make_group1_poll_response_can_id(3)
        assert cid_3 == 0x3C3

        # MAC ID 63 (maximum standard MAC)
        cid_63 = make_group1_poll_response_can_id(63)
        assert cid_63 == 0x3FF

        # All Group 1 IDs must be within 0x000..0x3FF range
        for mac in range(64):
            cid = make_group1_poll_response_can_id(mac)
            assert 0x3C0 <= cid <= 0x3FF
            assert cid <= 0x7FF

    def test_group1_poll_response_masking(self) -> None:
        """Verify Group 1 MAC ID parameter is masked to 6 bits (0..63)."""
        cid_wrapped = make_group1_poll_response_can_id(64)  # 64 & 0x3F = 0
        assert cid_wrapped == 0x3C0

        cid_wrapped_65 = make_group1_poll_response_can_id(65)  # 65 & 0x3F = 1
        assert cid_wrapped_65 == 0x3C1

    def test_group2_can_id_encoding(self) -> None:
        """Verify Group 2 CAN ID encoding (0x400 | (MAC_ID << 3) | MsgType)."""
        # Master Poll Request (msg_type = 5)
        cid_poll_0 = make_group2_can_id(0, GRP2_MSG_MASTER_POLL_REQ)
        assert cid_poll_0 == 0x400 | (0 << 3) | 5  # 0x405

        cid_poll_3 = make_group2_can_id(3, GRP2_MSG_MASTER_POLL_REQ)
        assert cid_poll_3 == 0x400 | (3 << 3) | 5  # 0x41D = 1053

        cid_poll_63 = make_group2_can_id(63, GRP2_MSG_MASTER_POLL_REQ)
        assert cid_poll_63 == 0x400 | (63 << 3) | 5  # 0x5FD

        # Duplicate MAC Check (msg_type = 6)
        cid_dup_0 = make_group2_can_id(0, GRP2_MSG_DUP_MAC_CHECK)
        assert cid_dup_0 == 0x406

        cid_dup_3 = make_group2_can_id(3, GRP2_MSG_DUP_MAC_CHECK)
        assert cid_dup_3 == 0x41E

        # Explicit non-fragmented (msg_type = 4) & fragmented (msg_type = 7)
        cid_exp_nonfrag = make_group2_can_id(10, GRP2_MSG_EXPLICIT_NON_FRAG)
        assert cid_exp_nonfrag == 0x400 | (10 << 3) | 4

        cid_exp_frag = make_group2_can_id(10, GRP2_MSG_EXPLICIT_FRAG)
        assert cid_exp_frag == 0x400 | (10 << 3) | 7

        # Range checks: Group 2 IDs must stay within 0x400..0x5FF
        for mac in range(64):
            for msg_t in range(8):
                cid = make_group2_can_id(mac, msg_t)
                assert 0x400 <= cid <= 0x5FF
                assert cid <= 0x7FF


# ============================================================================
# Section 3: Multi-Frame Fragmentation & Reassembly Engine
# ============================================================================

class TestSection3FragmentationEngine:
    """Tests for ODVA CIP Volume 3 Section 3-5 Fragmentation Protocol Engine."""

    def test_short_payload_not_fragmented(self, frag_engine: FragmentationEngine) -> None:
        """Verify payloads <= 8 bytes are not fragmented by fragment_payload."""
        payload_short = b"\x01\x02\x03\x04"
        frames = frag_engine.fragment_payload(payload_short)
        assert len(frames) == 1
        assert frames[0] == payload_short

    def test_unfragmented_frame_reception(self, frag_engine: FragmentationEngine) -> None:
        """Verify frame with unfragmented marker (bits 7..6 = 0b11) returns UNFRAGMENTED_COMPLETE."""
        unfrag_frame = b"\xC0\x11\x22\x33"  # 0xC0 & 0xC0 == 0xC0 (not FIRST, MIDDLE, or END)
        done, reassembled, status = frag_engine.process_incoming_frame(mac_id=1, frame_data=unfrag_frame)
        assert done is True
        assert reassembled == unfrag_frame
        assert status == "UNFRAGMENTED_COMPLETE"

    def test_fragmentation_header_encoding_and_reassembly(self, frag_engine: FragmentationEngine) -> None:
        """Verify fragmentation splitting and bit-for-bit reassembly for >8 bytes."""
        payload = b"Horner_APG_DeviceNet_Explicit_Parameter_Transfer_Test_Data_12345678"
        frames = frag_engine.fragment_payload(payload)
        assert len(frames) > 1

        # Check first frame header: Bits 7..6 = 0b00 (FRAG_TYPE_FIRST), seq = 0
        first_hdr = frames[0][0]
        assert (first_hdr & 0xC0) == FRAG_TYPE_FIRST
        assert (first_hdr & FRAG_SEQ_MASK) == 0
        assert len(frames[0]) == 8  # 1 byte hdr + 7 bytes payload

        # Check middle frames
        for frame in frames[1:-1]:
            hdr = frame[0]
            assert (hdr & 0xC0) == FRAG_TYPE_MIDDLE
            assert len(frame) == 8

        # Check end frame: Bits 7..6 = 0b10 (FRAG_TYPE_END)
        end_hdr = frames[-1][0]
        assert (end_hdr & 0xC0) == FRAG_TYPE_END

        # Reassemble frame by frame
        reconstructed = None
        for i, frame in enumerate(frames):
            done, data, status = frag_engine.process_incoming_frame(mac_id=2, frame_data=frame)
            if i == 0:
                assert done is False
                assert status == "FIRST_FRAGMENT_RECEIVED"
            elif i < len(frames) - 1:
                assert done is False
                assert status == "MIDDLE_FRAGMENT_RECEIVED"
            else:
                assert done is True
                assert status == "REASSEMBLY_COMPLETE"
                reconstructed = data

        assert reconstructed == payload
        assert frag_engine.error_count == 0

    def test_fragmentation_timeout_handling(self, frag_engine: FragmentationEngine) -> None:
        """Verify inter-fragment timeout deletes active assembly and increments error_count."""
        payload = b"01234567890123456789"
        frames = frag_engine.fragment_payload(payload)

        t0 = 1000.0
        done, _, status = frag_engine.process_incoming_frame(mac_id=5, frame_data=frames[0], current_time=t0)
        assert done is False
        assert status == "FIRST_FRAGMENT_RECEIVED"
        assert 5 in frag_engine.active_assemblies

        # Advance time past 1.0s timeout (e.g. 1000.0 + 1.5s)
        t1 = t0 + 1.5
        done, result, status = frag_engine.process_incoming_frame(mac_id=5, frame_data=frames[1], current_time=t1)
        assert done is False
        assert result is None
        assert status == "ERR_FRAG_TIMEOUT"
        assert 5 not in frag_engine.active_assemblies
        assert frag_engine.error_count == 1

    def test_fragmentation_sequence_gap_detection(self, frag_engine: FragmentationEngine) -> None:
        """Verify non-consecutive fragment sequence numbers abort assembly with ERR_FRAG_SEQ_GAP."""
        payload = b"Sequence_Gap_Detection_Payload_12345678901234567890"
        frames = frag_engine.fragment_payload(payload)
        assert len(frames) >= 3

        # Feed frame 0 (seq 0)
        frag_engine.process_incoming_frame(mac_id=7, frame_data=frames[0])

        # Skip frame 1 and feed frame 2 directly
        done, result, status = frag_engine.process_incoming_frame(mac_id=7, frame_data=frames[2])
        assert done is False
        assert result is None
        assert status == "ERR_FRAG_SEQ_GAP"
        assert 7 not in frag_engine.active_assemblies
        assert frag_engine.error_count == 1

    def test_orphan_fragment_rejection(self, frag_engine: FragmentationEngine) -> None:
        """Verify middle or end fragment received without prior first fragment returns ERR_ORPHAN_FRAGMENT."""
        orphan_frame = bytes([FRAG_TYPE_MIDDLE | 0x01, 0x11, 0x22, 0x33])
        done, result, status = frag_engine.process_incoming_frame(mac_id=9, frame_data=orphan_frame)
        assert done is False
        assert result is None
        assert status == "ERR_ORPHAN_FRAGMENT"
        assert frag_engine.error_count == 1


# ============================================================================
# Section 4: Duplicate MAC ID Detection & Collision Handling
# ============================================================================

class TestSection4DuplicateMACCheck:
    """Tests for Duplicate MAC ID Check startup algorithm and fault assertions."""

    def test_duplicate_mac_collision_asserts_fault_and_registers(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Assert duplicate MAC collision locks master, asserts %M157=TRUE and code 0x8302."""
        master_engine.master_mac_id = 5
        existing_nodes = {1, 2, 5, 10}

        success = master_engine.perform_duplicate_mac_check(existing_nodes)
        assert success is False
        assert master_engine.has_duplicate_mac is True
        assert master_engine.state == DeviceNetMasterState.FAULT_LOCKED
        assert master_engine.diagnostic_code == DeviceNetDiagnosticCode.DUPLICATE_MAC_ID
        assert (
            master_engine.status_bits & DeviceNetMasterStatusBits.DUPLICATE_MAC_FAULT
        ) != 0

        # Check Horner OCS registers
        assert master_engine.reg_table.read_uword("%R677") == int(DeviceNetDiagnosticCode.DUPLICATE_MAC_ID)
        assert master_engine.reg_table.read_bit("%M157") is True
        assert master_engine.reg_table.read_bit("%M156") is False

    def test_unique_mac_passes_and_transitions_to_running(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Assert unique MAC ID passes check, transitions to RUNNING, and clears %M157."""
        master_engine.master_mac_id = 7
        existing_nodes = {0, 1, 2, 5}

        success = master_engine.perform_duplicate_mac_check(existing_nodes)
        assert success is True
        assert master_engine.has_duplicate_mac is False
        assert master_engine.state == DeviceNetMasterState.RUNNING
        assert master_engine.diagnostic_code == DeviceNetDiagnosticCode.OK
        assert (
            master_engine.status_bits & DeviceNetMasterStatusBits.DUPLICATE_MAC_FAULT
        ) == 0

        assert master_engine.reg_table.read_uword("%R677") == int(DeviceNetDiagnosticCode.OK)
        assert master_engine.reg_table.read_bit("%M157") is False


# ============================================================================
# Section 5: Master State Machine Transitions
# ============================================================================

class TestSection5MasterStateMachine:
    """Tests for master operational lifecycle state transitions."""

    def test_initial_state_and_progression_to_running(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify initial state is INITIALIZING and advances to RUNNING on successful startup."""
        assert master_engine.state == DeviceNetMasterState.INITIALIZING
        assert (master_engine.status_bits & DeviceNetMasterStatusBits.MASTER_ACTIVE) != 0

        # Pass duplicate MAC check
        ok = master_engine.perform_duplicate_mac_check(set())
        assert ok is True
        assert master_engine.state == DeviceNetMasterState.RUNNING

    def test_offline_to_running_transition(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify explicit master transition from OFFLINE through DUP_MAC_CHECK to RUNNING."""
        master_engine.state = DeviceNetMasterState.OFFLINE
        assert master_engine.state == DeviceNetMasterState.OFFLINE

        ok = master_engine.perform_duplicate_mac_check(existing_macs={1, 2, 3})
        assert ok is True
        assert master_engine.state == DeviceNetMasterState.RUNNING
        assert (master_engine.status_bits & DeviceNetMasterStatusBits.MASTER_ACTIVE) != 0

    def test_state_machine_with_configured_slaves(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify scan list registration and cyclic scan state progression."""
        master_engine.perform_duplicate_mac_check(set())

        slave1 = DeviceNetSlaveDescriptor(mac_id=1, poll_state=SlavePollState.OPERATIONAL)
        slave2 = DeviceNetSlaveDescriptor(mac_id=2, poll_state=SlavePollState.OPERATIONAL)
        master_engine.add_slave(slave1)
        master_engine.add_slave(slave2)

        res = master_engine.execute_scan_cycle()
        assert res["state"] == "RUNNING"
        assert res["configured_slaves"] == 2
        assert res["successful_polls"] == 2

        # BUS_NORMAL_ACTIVE is set and %M156 is TRUE
        assert (
            master_engine.status_bits & DeviceNetMasterStatusBits.BUS_NORMAL_ACTIVE
        ) != 0
        assert master_engine.reg_table.read_bit("%M156") is True

    def test_fault_locked_transition_and_recovery(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify transition to FAULT_LOCKED upon CAN Bus-Off and recovery to RUNNING."""
        master_engine.perform_duplicate_mac_check(set())
        assert master_engine.state == DeviceNetMasterState.RUNNING

        master_engine.set_bus_off(True)
        assert master_engine.state == DeviceNetMasterState.FAULT_LOCKED
        assert master_engine.reg_table.read_bit("%M157") is True

        # Clear bus off
        master_engine.set_bus_off(False)
        assert master_engine.state == DeviceNetMasterState.RUNNING
        assert master_engine.reg_table.read_bit("%M157") is False


# ============================================================================
# Section 6: Cyclic Polled I/O Data Produce and Consume Exchange
# ============================================================================

class TestSection6CyclicPolledIO:
    """Tests for DeviceNet cyclic polled I/O exchange."""

    def test_slave_produce_consume_data_exchange(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify slave poll response updates input buffer and transfer metrics."""
        slave = DeviceNetSlaveDescriptor(mac_id=4, poll_produce_len=4, poll_consume_len=4)
        master_engine.add_slave(slave)

        # Exchange 4 bytes of input data
        test_data = b"\x11\x22\x33\x44"
        success, rx_data = master_engine.poll_slave(mac_id=4, slave_response_data=test_data)
        assert success is True
        assert rx_data == test_data
        assert bytes(slave.input_data) == test_data
        assert master_engine.total_transfers == 1

        # Additional poll with new data
        test_data_2 = b"\xAA\xBB\xCC\xDD"
        success, rx_data_2 = master_engine.poll_slave(mac_id=4, slave_response_data=test_data_2)
        assert success is True
        assert rx_data_2 == test_data_2
        assert bytes(slave.input_data) == test_data_2
        assert master_engine.total_transfers == 2

    def test_poll_unconfigured_slave_returns_false(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Assert polling an unconfigured slave MAC returns (False, None)."""
        success, rx_data = master_engine.poll_slave(mac_id=60)
        assert success is False
        assert rx_data is None

    def test_execute_scan_cycle_statistics(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify execute_scan_cycle aggregates transfer counts across multiple slaves."""
        s1 = DeviceNetSlaveDescriptor(mac_id=1)
        s2 = DeviceNetSlaveDescriptor(mac_id=2)
        s3 = DeviceNetSlaveDescriptor(mac_id=3)
        master_engine.add_slave(s1)
        master_engine.add_slave(s2)
        master_engine.add_slave(s3)

        initial_transfers = master_engine.total_transfers
        metrics = master_engine.execute_scan_cycle()

        assert metrics["configured_slaves"] == 3
        assert metrics["successful_polls"] == 3
        assert master_engine.total_transfers == initial_transfers + 3
        assert (master_engine.status_bits & DeviceNetMasterStatusBits.CYCLIC_IO_EXCHANGE_ACTIVE) != 0


# ============================================================================
# Section 7: Bus Fault Diagnostics (Timeouts, Drop, SCANLIST_MISMATCH, Bus-Off)
# ============================================================================

class TestSection7BusFaultDiagnostics:
    """Tests for DeviceNet bus fault diagnostics, slave drop, and transceiver fault conditions."""

    def test_three_consecutive_timeouts_triggers_slave_drop_and_mismatch(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify 3 consecutive missed polls transitions slave to OFFLINE, asserts SCANLIST_MISMATCH and 0x8301."""
        slave = DeviceNetSlaveDescriptor(mac_id=10)
        master_engine.add_slave(slave)

        # Timeout 1
        ok1, _ = master_engine.poll_slave(mac_id=10, force_timeout=True)
        assert ok1 is False
        assert slave.consecutive_timeouts == 1
        assert slave.poll_state == SlavePollState.TIMEOUT

        # Timeout 2
        ok2, _ = master_engine.poll_slave(mac_id=10, force_timeout=True)
        assert ok2 is False
        assert slave.consecutive_timeouts == 2
        assert slave.poll_state == SlavePollState.TIMEOUT

        # Timeout 3 -> slave dropped to OFFLINE
        ok3, _ = master_engine.poll_slave(mac_id=10, force_timeout=True)
        assert ok3 is False
        assert slave.consecutive_timeouts == 3
        assert slave.poll_state == SlavePollState.OFFLINE

        # Master status word should indicate SCANLIST_MISMATCH and SLAVE_OFFLINE code
        assert (
            master_engine.status_bits & DeviceNetMasterStatusBits.SCANLIST_MISMATCH
        ) != 0
        assert master_engine.diagnostic_code == DeviceNetDiagnosticCode.SLAVE_OFFLINE
        assert master_engine.reg_table.read_uword("%R677") == int(DeviceNetDiagnosticCode.SLAVE_OFFLINE)

    def test_slave_recovery_after_timeout(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify successful poll recovers slave from OFFLINE and clears mismatch status."""
        slave = DeviceNetSlaveDescriptor(mac_id=12)
        master_engine.add_slave(slave)

        # Drop slave
        for _ in range(3):
            master_engine.poll_slave(mac_id=12, force_timeout=True)
        assert slave.poll_state == SlavePollState.OFFLINE
        assert master_engine.diagnostic_code == DeviceNetDiagnosticCode.SLAVE_OFFLINE

        # Recovery poll
        ok, _ = master_engine.poll_slave(mac_id=12, slave_response_data=b"\x01\x02\x03\x04")
        assert ok is True
        assert slave.poll_state == SlavePollState.OPERATIONAL
        assert slave.consecutive_timeouts == 0
        assert master_engine.diagnostic_code == DeviceNetDiagnosticCode.OK
        assert (
            master_engine.status_bits & DeviceNetMasterStatusBits.SCANLIST_MISMATCH
        ) == 0

    def test_can_bus_off_asserts_trip_coil_and_code(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify CAN Bus-Off condition asserts %M157=TRUE and diagnostic code 0x8304."""
        master_engine.set_bus_off(True)

        assert master_engine.is_bus_off is True
        assert master_engine.state == DeviceNetMasterState.FAULT_LOCKED
        assert (master_engine.status_bits & DeviceNetMasterStatusBits.CAN_BUS_OFF) != 0
        assert master_engine.diagnostic_code == DeviceNetDiagnosticCode.CAN_BUS_OFF

        assert master_engine.reg_table.read_uword("%R677") == 0x8304
        assert master_engine.reg_table.read_bit("%M157") is True
        assert master_engine.reg_table.read_bit("%M156") is False

        # Polling during Bus-Off fails immediately
        slave = DeviceNetSlaveDescriptor(mac_id=15)
        master_engine.add_slave(slave)
        ok, _ = master_engine.poll_slave(mac_id=15)
        assert ok is False


# ============================================================================
# Section 8: Horner OCS Register Space Synchronization
# ============================================================================

class TestSection8RegisterSynchronization:
    """Tests for Horner OCS memory mapping (%R670..%R677, %M156..%M157)."""

    def test_configured_slave_count_and_masks(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify %R671 slave count and %R672..%R674 active slave bitmasks across 3 bands."""
        # Add slaves across low (0..15), mid (16..31), high (32..47)
        s_low = DeviceNetSlaveDescriptor(mac_id=2)
        s_low2 = DeviceNetSlaveDescriptor(mac_id=5)
        s_mid = DeviceNetSlaveDescriptor(mac_id=18)  # bit 18-16 = 2
        s_high = DeviceNetSlaveDescriptor(mac_id=35)  # bit 35-32 = 3

        master_engine.add_slave(s_low)
        master_engine.add_slave(s_low2)
        master_engine.add_slave(s_mid)
        master_engine.add_slave(s_high)

        # Check %R671: 4 configured slaves
        assert master_engine.reg_table.read_word("%R671") == 4

        # Check %R672: (1 << 2) | (1 << 5) = 4 | 32 = 36
        expected_mask_low = (1 << 2) | (1 << 5)
        assert master_engine.reg_table.read_uword("%R672") == expected_mask_low

        # Check %R673: (1 << (18 - 16)) = 1 << 2 = 4
        expected_mask_mid = (1 << 2)
        assert master_engine.reg_table.read_uword("%R673") == expected_mask_mid

        # Check %R674: (1 << (35 - 32)) = 1 << 3 = 8
        expected_mask_high = (1 << 3)
        assert master_engine.reg_table.read_uword("%R674") == expected_mask_high

    def test_total_transfers_counter_register(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify %R675 reflects master.total_transfers masked to 15-bit INT."""
        s = DeviceNetSlaveDescriptor(mac_id=1)
        master_engine.add_slave(s)

        for _ in range(10):
            master_engine.poll_slave(mac_id=1)

        assert master_engine.total_transfers == 10
        assert master_engine.reg_table.read_word("%R675") == 10

    def test_fragmentation_error_counter_register(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify %R676 tracks fragmentation errors."""
        # Cause an orphan fragmentation error
        master_engine.fragmentation.process_incoming_frame(
            mac_id=8, frame_data=bytes([FRAG_TYPE_MIDDLE | 1, 0x01, 0x02])
        )
        assert master_engine.fragmentation.error_count == 1
        master_engine._sync_registers()
        assert master_engine.reg_table.read_word("%R676") == 1
        assert (
            master_engine.status_bits & DeviceNetMasterStatusBits.FRAGMENTATION_ERROR
        ) != 0

    def test_master_status_word_and_discrete_coils(
        self, master_engine: DeviceNetMasterEngine
    ) -> None:
        """Verify %R670 status bitmask, %M156 normal coil, and %M157 trip coil."""
        s = DeviceNetSlaveDescriptor(mac_id=1)
        master_engine.add_slave(s)
        master_engine.perform_duplicate_mac_check(set())

        # Healthy operational state
        r670 = master_engine.reg_table.read_uword("%R670")
        assert (r670 & DeviceNetMasterStatusBits.MASTER_ACTIVE) != 0
        assert (r670 & DeviceNetMasterStatusBits.BUS_NORMAL_ACTIVE) != 0
        assert master_engine.reg_table.read_bit("%M156") is True
        assert master_engine.reg_table.read_bit("%M157") is False


# ============================================================================
# Section 9: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection9AntiLadderGuard:
    """Tests for SecurityGuard strict rejection of forbidden ladder logic artifacts."""

    def test_reject_ladder_contact_and_coil(self) -> None:
        """Verify SecurityGuard rejects contacts and coils with LadderForbiddenError."""
        ladder_code = """
        PROGRAM LadderViolation
        VAR In : BOOL; Out : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(ladder_code)

    def test_reject_ladder_rung_delimiters(self) -> None:
        """Verify SecurityGuard rejects RUNG / NETWORK keywords."""
        ladder_code = """
        PROGRAM RungViolation
        RUNG 1
        A := B;
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(ladder_code)

    def test_reject_ladder_mnemonics(self) -> None:
        """Verify SecurityGuard rejects XIC and OTE instructions."""
        ladder_code = """
        PROGRAM MnemonicViolation
        XIC Contact1 OTE Coil1;
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(ladder_code)


# ============================================================================
# Section 10: End-to-End Verification Runner
# ============================================================================

class TestSection10EndToEndVerificationSuite:
    """Tests for run_devicenet_verification executing the complete 9-stage verification suite."""

    def test_run_devicenet_verification_all_stages_pass(self, tmp_path: Path) -> None:
        """Execute run_devicenet_verification and verify JSON evidence artifact generation."""
        evidence_file = tmp_path / "devicenet_verification_evidence.json"
        res = run_devicenet_verification(evidence_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W106"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

        # Check all 9 stage results
        for test_stage in res["data"]["tests"]:
            assert test_stage["passed"] is True, f"Stage {test_stage['stage']} failed: {test_stage['check']}"

        # Check evidence file written
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            loaded_data = json.load(f)
        assert loaded_data["status"] == "success"
        assert loaded_data["data"]["checks_passed"] == 9


# ============================================================================
# Section 11: Architectural Safety Audit (Strict 4-Check Verification)
# ============================================================================

class TestSection11ArchitecturalSafetyAudit:
    """Rigorous audit against Horner register table conventions and safety invariants."""

    def test_audit_horner_register_assignments_match_conventions(
        self, register_table: RegisterTable
    ) -> None:
        """Audit 1: Verify %R670..%R677 and %M156..%M157 strictly match register_table.py conventions."""
        expected_r = [f"%R{i}" for i in range(670, 678)]
        expected_m = ["%M156", "%M157"]

        # 1. Analog Holding Registers %R670..%R677
        for r_addr in expected_r:
            parsed = register_table.parse_address(r_addr)
            assert parsed.prefix == "%R"
            assert parsed.channel_type.element_type == "INT"
            assert parsed.channel_type.bit_width == 16
            assert parsed.channel_type.range_min <= parsed.index <= parsed.channel_type.range_max
            # Test read/write with SYSTEM privilege
            register_table.write_word(r_addr, 1234, privilege=PrivilegeMode.SYSTEM)
            assert register_table.read_word(r_addr) == 1234

        # Verify contiguous allocation
        consec = register_table.get_consecutive_addresses("%R670", 8)
        assert consec == expected_r

        # 2. Discrete Internal Coils %M156..%M157
        for m_addr in expected_m:
            parsed = register_table.parse_address(m_addr)
            assert parsed.prefix == "%M"
            assert parsed.channel_type.element_type == "BOOL"
            assert parsed.channel_type.bit_width == 1
            assert parsed.channel_type.range_min <= parsed.index <= parsed.channel_type.range_max
            # Test read/write with SYSTEM privilege
            register_table.write_bit(m_addr, True, privilege=PrivilegeMode.SYSTEM)
            assert register_table.read_bit(m_addr) is True
            register_table.write_bit(m_addr, False, privilege=PrivilegeMode.SYSTEM)
            assert register_table.read_bit(m_addr) is False

    def test_audit_status_bits_cleanly_aligned(self) -> None:
        """Audit 2: Verify DeviceNetMasterStatusBits are cleanly aligned powers of 2 without sign collisions."""
        seen_values = set()
        for bit_flag in DeviceNetMasterStatusBits:
            val = bit_flag.value
            # Must be positive
            assert val > 0
            # Must be a pure power of 2
            assert (val & (val - 1)) == 0, f"Bit {bit_flag.name} ({val}) is not a power of 2"
            # Must not duplicate any other bit
            assert val not in seen_values, f"Bit {bit_flag.name} ({val}) collides with another bit"
            seen_values.add(val)
            # Must fit in 16-bit word
            assert val < 0x10000, f"Bit {bit_flag.name} ({val}) exceeds 16-bit width"
            # Must avoid signed 16-bit INT sign bit (bit 15 = 0x8000)
            assert val < 0x8000, f"Bit {bit_flag.name} ({val}) collides with INT16 sign bit"

        # Verify exact alignment with pure ST POU literals
        assert int(DeviceNetMasterStatusBits.BUS_NORMAL_ACTIVE) == 2
        fault_bits = int(
            DeviceNetMasterStatusBits.DUPLICATE_MAC_FAULT
            | DeviceNetMasterStatusBits.CAN_BUS_OFF
        )
        assert fault_bits == 40

    def test_audit_pure_iec_st_pou_parses_cleanly_with_st_parser(self) -> None:
        """Audit 3: Verify DeviceNetMasterSync parses cleanly with STParser and binds all registers."""
        val_res = STParser.validate_code(DEVICENET_PURE_ST_POU)
        assert val_res.status == AgentStatus.SUCCESS
        assert val_res.data["pou_name"] == "DeviceNetMasterSync"
        assert val_res.data["pou_type"] == "PROGRAM"

        ast_res = STParser.parse_pou(DEVICENET_PURE_ST_POU)
        assert ast_res.name == "DeviceNetMasterSync"
        assert ast_res.pou_type == POUType.PROGRAM

        expected_bound = {f"%R{i}" for i in range(670, 678)} | {"%M156", "%M157"}
        assert set(ast_res.bound_registers) == expected_bound
        assert all(var.binding_valid for var in ast_res.variables)

        # Anti-ladder verification
        SecurityGuard.assert_pure_st_content(DEVICENET_PURE_ST_POU)

    def test_audit_no_forbidden_hardware_imports(self) -> None:
        """Audit 4: Verify devicenet.py has zero forbidden hardware imports, ports, or flash utilities."""
        target_file = Path("src/jev_cscape/telemetry/devicenet.py")
        assert target_file.exists()

        tree = ast.parse(target_file.read_text(encoding="utf-8"))
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_modules.add(node.module.split(".")[0])

        forbidden = {
            "serial",
            "pyserial",
            "can",
            "python-can",
            "socketcan",
            "pcan",
            "kvaser",
            "vector",
            "ixxat",
            "win32gui",
            "win32con",
            "win32process",
            "win32api",
            "win32file",
            "win32pipe",
            "win32comm",
            "pywin32",
        }
        forbidden_hits = imported_modules.intersection(forbidden)
        assert not forbidden_hits, f"Forbidden hardware imports detected: {forbidden_hits}"

        # Check source text for forbidden hardware patterns
        source = target_file.read_text(encoding="utf-8")
        for blocked_port in SecurityGuard.BLOCKED_PORTS:
            assert not blocked_port.search(source), f"Blocked port pattern found: {blocked_port.pattern}"

        for blocked_bin in SecurityGuard.BLOCKED_FLASH_BINARIES:
            assert blocked_bin not in source.lower(), f"Blocked flash binary found: {blocked_bin}"

        for blocked_cmd in SecurityGuard.BLOCKED_COMMAND_IDS:
            assert str(blocked_cmd) not in source, f"Blocked Win32 command ID found: {blocked_cmd}"

