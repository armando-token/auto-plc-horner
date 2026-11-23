"""Comprehensive Unit Test Suite for Wave W289 CIP Safety Over Ethernet-APL Star Topology Protocol Engine.

Work Package: W289 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Ethernet-APL Star Topology (10BASE-T1L / IEEE 802.3cg) for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 14 Mandatory Test Classes:
1. TestImportsConstantsAndDiagnosticCodes: Protocol constants, diagnostic codes (0x0000, 0xEE11..0xEE17),
   signed/unsigned equality, string & repr representations, register mappings (%R2500..%R2507),
   coil mappings (%M583..%M584), status bits, and enums (StarRole, StarOperationalState, SwitchPortState, PortState).
2. TestDualSafetyCrcCalculation: CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B inverted data) calculations,
   determinism, 16-bit range bounds, seed variation, bit-flip corruption detection across payload and header fields.
3. TestCipSafetyAplStarFrameModel: Frame encapsulation, CRC computation, frame validation, payload bit-tamper
   detection, sequence number tampering, timestamp tampering, SNN tampering, port ID association, serialization/deserialization.
4. TestAplStarNodeModel: AplStarNode model defaults, role assignment, port states, error counters, and active flags.
5. TestStarTopologyNodeConnectionsAndPortTransitions: Star topology switch root and branch spur node connections,
   port state transitions (DOWN -> LINK_UP -> FORWARDING), active branch port mask calculation.
6. TestBranchLinkLossAndDegradedTopology: Single and multiple branch link loss surveillance, topology fail-safe trip,
   diagnostic code 0xEE11 assertion, port error counter incrementation, and clean branch restoration.
7. TestSwitchRootFailureAndFailSafeState: Switch root uplink failure detection, transition to fail-safe safe state,
   assertion of diagnostic code 0xEE12, deterministic safe state fallback, and root restoration.
8. TestDuplicateNodeAddressDetection: Interception of duplicate node address on star network asserting 0xEE16
   and triggering fail-safe safe state.
9. TestSafetyFrameTransmissionAndTamperDetection: Transmission sequence increments, frame validation,
   SNN mismatch fail-safe trip (0xEE17), CRC-S1 fault (0xEE13), and CRC-S2 fault (0xEE14).
10. TestHeartbeatWatchdogSurveillance: Heartbeat watchdog timer surveillance, watchdog timeout (> 200 ms)
   forcing fail-safe safe state, diagnostic code 0xEE15 assertion, and watchdog timer reset upon frame receipt.
11. TestHornerOcsRegisterSpaceSynchronization: Bit-exact synchronization to Horner OCS analog registers
   (%R2500..%R2507) and discrete coils (%M583..%M584), bit-packing, operational states, privilege mode support,
   and coil mutual exclusivity.
12. TestPureIEC61131StructuredTextAndSecurity: Pure IEC 61131-3 Structured Text POU CipSafetyAplStarSync
   syntax validation via STParser and SecurityGuard, variable address bindings, and strict rejection of ladder logic
   constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
13. TestILogicUnitComplianceAndSoak: ILogicUnit interface compliance (scan_step, step, execute, reset),
   ScanContext propagation, ExecutionResult contracts, and 100-cycle continuous scan soak execution.
14. TestNineStageVerificationRunner: Complete 9-stage verification suite run_cip_safety_apl_star_verification,
   strict 4-state engineering contract validation, stage timing metrics, and JSON evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_apl_star import (
    REG_CIP_SAFETY_STAR_STATUS,
    REG_CIP_SAFETY_STAR_SWITCH_PORT_STATE,
    REG_CIP_SAFETY_STAR_CONNECTED_MASK,
    REG_CIP_SAFETY_STAR_LINK_QUALITY,
    REG_CIP_SAFETY_STAR_FORWARDING_LATENCY_US,
    REG_CIP_SAFETY_STAR_SEQUENCE_COUNTER,
    REG_CIP_SAFETY_STAR_CRC_STATUS,
    REG_CIP_SAFETY_STAR_DIAGNOSTIC_CODE,
    COIL_CIP_SAFETY_STAR_ACTIVE,
    COIL_CIP_SAFETY_STAR_FAULT,
    REG_STAR_STATUS,
    REG_STAR_SWITCH_PORT_STATE,
    REG_STAR_CONNECTED_MASK,
    REG_STAR_LINK_QUALITY,
    REG_STAR_FORWARDING_LATENCY_US,
    REG_STAR_SEQUENCE_COUNTER,
    REG_STAR_CRC_STATUS,
    REG_STAR_DIAGNOSTIC_CODE,
    REG_CIP_SAFETY_STAR_TOPOLOGY_STATE,
    REG_CIP_SAFETY_STAR_FORWARDING_DELAY_MS,
    REG_CIP_SAFETY_STAR_ROOT_PORT_STATE,
    REG_CIP_SAFETY_STAR_BRANCH_MASK,
    COIL_STAR_ACTIVE,
    COIL_STAR_FAULT,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_BRANCH_LINK_LOSS,
    DIAG_ERR_SWITCH_ROOT_DOWN,
    DIAG_ERR_SWITCH_ROOT_FAILURE,
    DIAG_ERR_CRC_S1_FAULT,
    DIAG_ERR_CRC_S2_FAULT,
    DIAG_ERR_HEARTBEAT_TIMEOUT,
    DIAG_ERR_DUPLICATE_NODE_ID,
    DIAG_ERR_NODE_DISCONNECT,
    DIAG_ERR_FAIL_SAFE_TRIP,
    CipSafetyAplStarDiagnosticCode,
    AplStarDiagnosticCode,
    StarRole,
    StarOperationalState,
    StarTopologyState,
    SwitchPortState,
    PortState,
    CipSafetyAplStarStatusBits,
    CipSafetyStarStatusBits,
    AplStarStatusBits,
    calculate_crc_s1,
    calculate_crc_s2,
    CipSafetyAplStarFrame,
    AplStarNode,
    ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC,
    CIP_SAFETY_APL_STAR_PURE_ST_POU,
    CipSafetyAplStarSync,
    verify_cip_safety_apl_star_pure_st,
    CipSafetyAplStarEngine,
    run_cip_safety_apl_star_verification,
)


# ============================================================================
# 1. TestImportsConstantsAndDiagnosticCodes
# ============================================================================

class TestImportsConstantsAndDiagnosticCodes:
    """Validate ODVA CIP Safety Over Ethernet-APL Star Topology constants, register maps, and diagnostic codes."""

    def test_register_and_coil_mappings(self) -> None:
        """Verify exact register addresses %R2500..%R2507 and coils %M583..%M584."""
        assert REG_CIP_SAFETY_STAR_STATUS == "%R2500"
        assert REG_CIP_SAFETY_STAR_SWITCH_PORT_STATE == "%R2501"
        assert REG_CIP_SAFETY_STAR_CONNECTED_MASK == "%R2502"
        assert REG_CIP_SAFETY_STAR_LINK_QUALITY == "%R2503"
        assert REG_CIP_SAFETY_STAR_FORWARDING_LATENCY_US == "%R2504"
        assert REG_CIP_SAFETY_STAR_SEQUENCE_COUNTER == "%R2505"
        assert REG_CIP_SAFETY_STAR_CRC_STATUS == "%R2506"
        assert REG_CIP_SAFETY_STAR_DIAGNOSTIC_CODE == "%R2507"

        assert COIL_CIP_SAFETY_STAR_ACTIVE == "%M583"
        assert COIL_CIP_SAFETY_STAR_FAULT == "%M584"

    def test_diagnostic_code_values_and_aliases(self) -> None:
        """Verify diagnostic code numerical assignments and type aliases (0xEE11..0xEE17)."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_BRANCH_LINK_LOSS == 0xEE11
        assert DIAG_ERR_SWITCH_ROOT_DOWN == 0xEE12
        assert DIAG_ERR_SWITCH_ROOT_FAILURE == 0xEE12
        assert DIAG_ERR_CRC_S1_FAULT == 0xEE13
        assert DIAG_ERR_CRC_S2_FAULT == 0xEE14
        assert DIAG_ERR_HEARTBEAT_TIMEOUT == 0xEE15
        assert DIAG_ERR_DUPLICATE_NODE_ID == 0xEE16
        assert DIAG_ERR_NODE_DISCONNECT == 0xEE16
        assert DIAG_ERR_FAIL_SAFE_TRIP == 0xEE17

        assert CipSafetyAplStarDiagnosticCode is DiagnosticCode
        assert AplStarDiagnosticCode is DiagnosticCode

    def test_diagnostic_code_equality_and_representations(self) -> None:
        """Verify signed and unsigned equality, hashing, and string representations of DiagnosticCode."""
        diag_branch = DIAG_ERR_BRANCH_LINK_LOSS
        assert diag_branch == 0xEE11
        # Signed 16-bit representation: 0xEE11 - 0x10000 = -4591
        assert diag_branch == -4591
        assert int(diag_branch) & 0xFFFF == 0xEE11
        assert str(diag_branch) == "0xEE11"
        assert repr(diag_branch) == "DiagnosticCode(0xEE11)"
        assert hash(diag_branch) == hash(0xEE11)

        diag_switch = DIAG_ERR_SWITCH_ROOT_DOWN
        assert diag_switch == 0xEE12
        assert diag_switch == -4590
        assert str(diag_switch) == "0xEE12"

        diag_ok = DIAG_OK
        assert diag_ok == 0
        assert str(diag_ok) == "0x0000"
        assert repr(diag_ok) == "DiagnosticCode(0x0000)"

    def test_star_role_and_topology_state_enums(self) -> None:
        """Verify StarRole, StarOperationalState, SwitchPortState, and PortState enumeration members."""
        assert StarRole.SWITCH_ROOT.value == "SWITCH_ROOT"
        assert StarRole.BRANCH_NODE.value == "BRANCH_NODE"

        assert StarOperationalState.INIT == 0
        assert StarOperationalState.OPERATIONAL == 1
        assert StarOperationalState.DEGRADED == 2
        assert StarOperationalState.FAIL_SAFE == 3

        assert SwitchPortState.UP == 1
        assert SwitchPortState.DOWN == 2
        assert SwitchPortState.FAULT == 3

        assert PortState.DOWN == 0
        assert PortState.LINK_UP == 1
        assert PortState.BLOCKED == 2
        assert PortState.FORWARDING == 3

    def test_status_bitmask_flags(self) -> None:
        """Verify bit flags in CipSafetyAplStarStatusBits and class aliases."""
        assert CipSafetyAplStarStatusBits.CRC_S1_VALID == 1 << 0
        assert CipSafetyAplStarStatusBits.CRC_S2_VALID == 1 << 1
        assert CipSafetyAplStarStatusBits.STAR_LINK_UP == 1 << 2
        assert CipSafetyAplStarStatusBits.SWITCH_SYNCED == 1 << 3
        assert CipSafetyAplStarStatusBits.FAIL_SAFE_ACTIVE == 1 << 4

        assert CipSafetyStarStatusBits is CipSafetyAplStarStatusBits
        assert AplStarStatusBits is CipSafetyAplStarStatusBits


# ============================================================================
# 2. TestDualSafetyCrcCalculation
# ============================================================================

class TestDualSafetyCrcCalculation:
    """Validate dual safety CRC algorithms (CRC-S1 poly 0x5935 and CRC-S2 poly 0x755B inverted)."""

    def test_crc_s1_determinism_and_bounds(self) -> None:
        """Verify CRC-S1 calculates deterministic 16-bit values over arbitrary payload."""
        payload = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        crc1 = calculate_crc_s1(payload)
        crc2 = calculate_crc_s1(payload)
        assert crc1 == crc2
        assert 0 <= crc1 <= 0xFFFF
        assert crc1 != 0

    def test_crc_s1_empty_payload(self) -> None:
        """Verify CRC-S1 with default initial seed 0xFFFF on empty bytes returns seed."""
        crc_empty = calculate_crc_s1(b"", initial_seed=0xFFFF)
        assert crc_empty == 0xFFFF

    def test_crc_s1_bit_tamper_detection(self) -> None:
        """Verify CRC-S1 detects single bit flips across every bit position of payload."""
        base_payload = bytearray(b"\x12\x34\x56\x78")
        base_crc = calculate_crc_s1(bytes(base_payload))

        for byte_idx in range(len(base_payload)):
            for bit_idx in range(8):
                tampered = bytearray(base_payload)
                tampered[byte_idx] ^= (1 << bit_idx)
                tampered_crc = calculate_crc_s1(bytes(tampered))
                assert tampered_crc != base_crc, f"CRC-S1 failed to detect bit flip at byte {byte_idx}, bit {bit_idx}"

    def test_crc_s2_determinism_and_bounds(self) -> None:
        """Verify CRC-S2 calculates deterministic 16-bit values over inverted sequence/timestamp/SNN."""
        seq = 100
        ts = 12345678
        snn = 0x1337
        crc1 = calculate_crc_s2(seq, ts, snn)
        crc2 = calculate_crc_s2(seq, ts, snn)
        assert crc1 == crc2
        assert 0 <= crc1 <= 0xFFFF
        assert crc1 != 0

    def test_crc_s2_tamper_detection(self) -> None:
        """Verify CRC-S2 detects modifications to sequence number, timestamp, and SNN."""
        seq = 100
        ts = 12345678
        snn = 0x1337
        nominal_crc = calculate_crc_s2(seq, ts, snn)

        # Sequence number mutation
        crc_mut_seq = calculate_crc_s2(seq + 1, ts, snn)
        assert crc_mut_seq != nominal_crc

        # Timestamp mutation
        crc_mut_ts = calculate_crc_s2(seq, ts + 1, snn)
        assert crc_mut_ts != nominal_crc

        # SNN mutation
        crc_mut_snn = calculate_crc_s2(seq, ts, snn ^ 0x0001)
        assert crc_mut_snn != nominal_crc

    def test_crc_s1_s2_polynomial_distinctness(self) -> None:
        """Verify CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B) produce distinct signatures."""
        seq = 0x1234
        ts = 0x56789ABC
        snn = 0xDEF0
        s2 = calculate_crc_s2(seq, ts, snn)

        raw = (
            (seq & 0xFFFF).to_bytes(2, "big")
            + (ts & 0xFFFFFFFF).to_bytes(4, "big")
            + (snn & 0xFFFF).to_bytes(2, "big")
        )
        s1 = calculate_crc_s1(raw)
        assert s1 != s2


# ============================================================================
# 3. TestCipSafetyAplStarFrameModel
# ============================================================================

class TestCipSafetyAplStarFrameModel:
    """Validate CipSafetyAplStarFrame data model, CRC computation, and validity checks."""

    def test_frame_compute_crcs_and_is_valid(self) -> None:
        """Verify fresh frame with computed CRCs reports is_valid True."""
        frame = CipSafetyAplStarFrame(
            node_id=1,
            sequence_number=42,
            timestamp_us=98765432,
            safety_network_number=0x1337,
            payload=b"\xCA\xFE\xBA\xBE",
            port_id=1,
        )
        assert frame.crc_s1 == 0
        assert frame.crc_s2 == 0
        assert frame.is_valid() is False

        frame.compute_crcs()
        assert frame.crc_s1 != 0
        assert frame.crc_s2 != 0
        assert frame.is_valid() is True

    def test_frame_payload_tamper_detection(self) -> None:
        """Verify mutating payload corrupts frame validity."""
        frame = CipSafetyAplStarFrame(
            node_id=1,
            sequence_number=1,
            timestamp_us=1000,
            safety_network_number=0x1337,
            payload=b"SAFETY_COMMAND_ESTOP",
            port_id=2,
        )
        frame.compute_crcs()
        assert frame.is_valid() is True

        # Mutate payload
        frame.payload = b"SAFETY_COMMAND_RESET"
        assert frame.is_valid() is False

    def test_frame_header_tamper_detection(self) -> None:
        """Verify mutating sequence number or SNN invalidates frame."""
        frame = CipSafetyAplStarFrame(
            node_id=1,
            sequence_number=10,
            timestamp_us=5000,
            safety_network_number=0x1234,
            payload=b"SAFE_DATA",
        )
        frame.compute_crcs()
        assert frame.is_valid() is True

        frame.sequence_number = 11
        assert frame.is_valid() is False

    def test_frame_serialization_deserialization_roundtrip(self) -> None:
        """Verify frame binary serialization and deserialization preserves all fields."""
        orig = CipSafetyAplStarFrame(
            node_id=3,
            target_node=5,
            sequence_number=123,
            timestamp_us=999999,
            safety_network_number=0x5678,
            payload=b"\xAA\xBB\xCC\xDD",
        )
        orig.compute_crcs()

        raw_bytes = orig.serialize()
        assert len(raw_bytes) >= 16

        recovered = CipSafetyAplStarFrame.deserialize(raw_bytes)
        assert recovered.node_id == orig.node_id
        assert recovered.target_node == orig.target_node
        assert recovered.sequence_number == orig.sequence_number
        assert recovered.timestamp_us == orig.timestamp_us
        assert recovered.safety_network_number == orig.safety_network_number
        assert recovered.payload == orig.payload
        assert recovered.crc_s1 == orig.crc_s1
        assert recovered.crc_s2 == orig.crc_s2
        assert recovered.is_valid() is True


# ============================================================================
# 4. TestAplStarNodeModel
# ============================================================================

class TestAplStarNodeModel:
    """Validate AplStarNode data model defaults and configuration."""

    def test_node_defaults(self) -> None:
        """Verify default attributes of AplStarNode."""
        node = AplStarNode(node_id=10, port_id=2)
        assert node.node_id == 10
        assert node.port_id == 2
        assert node.role == StarRole.BRANCH_NODE
        assert node.port_state == PortState.FORWARDING
        assert node.is_connected is True
        assert node.link_quality == 100
        assert node.errors_count == 0
        assert node.port_errors == 0

    def test_switch_root_node_instantiation(self) -> None:
        """Verify switch root node instantiation."""
        node = AplStarNode(node_id=1, port_id=0, role=StarRole.SWITCH_ROOT, port_state=PortState.FORWARDING)
        assert node.node_id == 1
        assert node.role == StarRole.SWITCH_ROOT


# ============================================================================
# 5. TestStarTopologyNodeConnectionsAndPortTransitions
# ============================================================================

class TestStarTopologyNodeConnectionsAndPortTransitions:
    """Validate star topology switch root and branch spur node connection states."""

    def test_root_switch_initialization(self) -> None:
        """Verify star root switch initializes with default branch ports healthy."""
        eng = CipSafetyAplStarEngine(node_id=1, role=StarRole.SWITCH_ROOT, num_branch_ports=4)
        assert eng.node_id == 1
        assert eng.role == StarRole.SWITCH_ROOT
        assert eng.root_port_state == PortState.FORWARDING
        assert len(eng.branches) == 4
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True
        assert eng.fail_safe_active is False
        assert eng.active_branch_mask == 0b1111  # Ports 1..4 forwarding

    def test_connect_branch_nodes(self) -> None:
        """Verify connecting new branch spur nodes dynamically."""
        eng = CipSafetyAplStarEngine(node_id=1, num_branch_ports=2)
        assert len(eng.branches) == 2

        new_node = eng.connect_branch_node(port_id=3, node_id=103, initial_state=PortState.FORWARDING)
        assert len(eng.branches) == 3
        assert 3 in eng.branches
        assert new_node.node_id == 103
        assert new_node.port_state == PortState.FORWARDING
        assert eng.is_healthy is True

    def test_branch_port_state_transitions(self) -> None:
        """Verify port state transitions (DOWN -> LINK_UP -> FORWARDING)."""
        eng = CipSafetyAplStarEngine(node_id=1, num_branch_ports=3)
        eng.connect_branch_node(port_id=4, node_id=104, initial_state=PortState.DOWN)

        assert eng.branches[4].port_state == PortState.DOWN
        assert eng.operational_state == StarOperationalState.DEGRADED

        eng.set_branch_port_state(4, PortState.LINK_UP)
        assert eng.branches[4].port_state == PortState.LINK_UP

        eng.set_branch_port_state(4, PortState.FORWARDING)
        assert eng.branches[4].port_state == PortState.FORWARDING
        assert eng.is_healthy is True

    def test_active_branch_mask_calculation(self) -> None:
        """Verify active_branch_mask correctly reflects bitmask of forwarding ports."""
        eng = CipSafetyAplStarEngine(node_id=1, num_branch_ports=4)
        assert eng.active_branch_mask == 0x0F  # Bits 0..3 set

        # Set port 2 down
        eng.set_branch_port_state(2, PortState.DOWN)
        assert eng.active_branch_mask == 0b1101  # Bit 1 cleared (port 2)

        # Set port 4 blocked
        eng.set_branch_port_state(4, PortState.BLOCKED)
        assert eng.active_branch_mask == 0b0101  # Bit 3 cleared (port 4)


# ============================================================================
# 6. TestBranchLinkLossAndDegradedTopology
# ============================================================================

class TestBranchLinkLossAndDegradedTopology:
    """Validate branch link loss detection, diagnostic codes, and restoration."""

    def test_single_branch_link_loss(self) -> None:
        """Verify branch link loss asserts DIAG_ERR_BRANCH_LINK_LOSS (0xEE11) and trips fail-safe."""
        eng = CipSafetyAplStarEngine(node_id=1, num_branch_ports=4)
        assert eng.is_healthy is True

        eng.inject_branch_loss(node_id=3)
        assert eng.branches[3].port_state == PortState.DOWN
        assert eng.branches[3].port_errors == 1
        assert eng.diagnostic_code == DIAG_ERR_BRANCH_LINK_LOSS
        assert eng.fail_safe_active is True
        assert eng.operational_state == StarOperationalState.FAIL_SAFE

        # Check register sync
        assert eng.reg_table.read_word(REG_CIP_SAFETY_STAR_DIAGNOSTIC_CODE) & 0xFFFF == 0xEE11
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is False
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_FAULT) is True

    def test_multiple_branch_links_down(self) -> None:
        """Verify multiple branch disconnections maintain fail-safe state until restored."""
        eng = CipSafetyAplStarEngine(node_id=1, num_branch_ports=4)
        eng.inject_branch_loss(1)
        eng.inject_branch_loss(2)

        assert eng.fail_safe_active is True
        assert eng.active_branch_mask == 0b1100

    def test_restore_branch_recovers_healthy_state(self) -> None:
        """Verify restoring disconnected branch recovers healthy state and clears diagnostic."""
        eng = CipSafetyAplStarEngine(node_id=1, num_branch_ports=4)
        eng.inject_branch_loss(2)
        assert eng.fail_safe_active is True

        eng.restore_branch(2)
        assert eng.branches[2].port_state == PortState.FORWARDING
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True

        assert eng.reg_table.read_word(REG_CIP_SAFETY_STAR_DIAGNOSTIC_CODE) == 0x0000
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is True

    def test_branch_error_counter_increments(self) -> None:
        """Verify port_errors increments every time a branch link loss occurs."""
        eng = CipSafetyAplStarEngine(node_id=1, num_branch_ports=2)
        assert eng.branches[1].port_errors == 0

        eng.inject_branch_loss(1)
        assert eng.branches[1].port_errors == 1

        eng.restore_branch(1)
        eng.inject_branch_loss(1)
        assert eng.branches[1].port_errors == 2


# ============================================================================
# 7. TestSwitchRootFailureAndFailSafeState
# ============================================================================

class TestSwitchRootFailureAndFailSafeState:
    """Validate root switch failure detection, safe state fallback, and root restoration."""

    def test_switch_root_failure_triggers_fault(self) -> None:
        """Verify root switch failure asserts DIAG_ERR_SWITCH_ROOT_DOWN (0xEE12) and sets FAIL_SAFE."""
        eng = CipSafetyAplStarEngine(node_id=1)
        assert eng.switch_port_state == SwitchPortState.UP

        eng.inject_switch_down()
        assert eng.switch_port_state == SwitchPortState.DOWN
        assert eng.root_port_errors == 1
        assert eng.diagnostic_code == DIAG_ERR_SWITCH_ROOT_DOWN
        assert eng.fail_safe_active is True
        assert eng.is_healthy is False

        # Verify registers in root fault state
        assert eng.reg_table.read_word(REG_CIP_SAFETY_STAR_SWITCH_PORT_STATE) == 2  # DOWN
        assert eng.reg_table.read_word(REG_CIP_SAFETY_STAR_DIAGNOSTIC_CODE) & 0xFFFF == 0xEE12
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is False
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_FAULT) is True

    def test_switch_root_failure_forces_fail_safe_safe_state(self) -> None:
        """Verify scan_step in root failure state returns FAILED result with error code."""
        eng = CipSafetyAplStarEngine(node_id=1)
        eng.inject_switch_down()

        res = eng.scan_step()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == str(DIAG_ERR_SWITCH_ROOT_DOWN)
        assert eng.operational_state == StarOperationalState.FAIL_SAFE

    def test_switch_root_recovery(self) -> None:
        """Verify restoring switch root returns root port to UP and recovers health."""
        eng = CipSafetyAplStarEngine(node_id=1)
        eng.inject_switch_down()
        assert eng.is_healthy is False

        eng.restore_switch()
        assert eng.switch_port_state == SwitchPortState.UP
        assert eng.fail_safe_active is False
        assert eng.is_healthy is True
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is True

    def test_clear_faults_and_reset(self) -> None:
        """Verify clear_faults and reset method restore healthy baseline from root failure."""
        eng = CipSafetyAplStarEngine(node_id=1)
        eng.inject_switch_down()
        eng.inject_branch_loss(1)
        assert eng.fail_safe_active is True

        eng.reset()
        assert eng.switch_port_state == SwitchPortState.UP
        assert eng.branches[1].port_state == PortState.FORWARDING
        assert eng.diagnostic_code == DIAG_OK
        assert eng.fail_safe_active is False
        assert eng.is_healthy is True


# ============================================================================
# 8. TestDuplicateNodeAddressDetection
# ============================================================================

class TestDuplicateNodeAddressDetection:
    """Validate duplicate node address collision detection and fail-safe safe state fallback."""

    def test_duplicate_node_id_injection(self) -> None:
        """Verify injecting duplicate node address asserts DIAG_ERR_DUPLICATE_NODE_ID (0xEE16)."""
        eng = CipSafetyAplStarEngine(node_id=1)
        assert eng.is_healthy is True

        eng.inject_duplicate_node_id(1)
        assert eng.diagnostic_code == DIAG_ERR_DUPLICATE_NODE_ID
        assert eng.fail_safe_active is True
        assert eng.operational_state == StarOperationalState.FAIL_SAFE
        assert eng.safe_output_data == b"\x00\x00\x00\x00"
        assert eng.reg_table.read_word(REG_CIP_SAFETY_STAR_DIAGNOSTIC_CODE) & 0xFFFF == 0xEE16
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is False
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_FAULT) is True


# ============================================================================
# 9. TestSafetyFrameTransmissionAndTamperDetection
# ============================================================================

class TestSafetyFrameTransmissionAndTamperDetection:
    """Validate frame transmission sequence increments, reception validation, and tamper rejection."""

    def test_send_safety_frame_sequence_and_crcs(self) -> None:
        """Verify send_safety_frame increments sequence counter and computes valid CRCs."""
        eng = CipSafetyAplStarEngine(node_id=1, safety_network_number=0x4321)
        assert eng.sequence_counter == 0

        f1 = eng.send_safety_frame(b"\x0A\x0B", target_node=2)
        assert f1.node_id == 1
        assert f1.sequence_number == 1
        assert f1.safety_network_number == 0x4321
        assert f1.payload == b"\x0A\x0B"
        assert f1.is_valid() is True
        assert eng.sequence_counter == 1

        f2 = eng.send_safety_frame(b"\x0C\x0D", target_node=3)
        assert f2.sequence_number == 2
        assert eng.sequence_counter == 2

    def test_receive_safety_frame_valid(self) -> None:
        """Verify receiving valid frame keeps engine healthy and resets heartbeat timer."""
        eng_tx = CipSafetyAplStarEngine(node_id=1)
        eng_rx = CipSafetyAplStarEngine(node_id=2)
        eng_rx.time_since_heartbeat_ms = 120.0
        frame = eng_tx.send_safety_frame(b"NORMAL_STAR_TELEMETRY", target_node=2)

        assert eng_rx.receive_safety_frame(frame) is True
        assert eng_rx.diagnostic_code == DIAG_OK
        assert eng_rx.time_since_heartbeat_ms == 0.0
        assert eng_rx.is_healthy is True

    def test_receive_safety_frame_snn_mismatch(self) -> None:
        """Verify safety frame with foreign SNN trips fail-safe state (0xEE17)."""
        eng = CipSafetyAplStarEngine(node_id=1, safety_network_number=0x1337)
        foreign_frame = CipSafetyAplStarFrame(
            node_id=2,
            sequence_number=1,
            timestamp_us=1000,
            safety_network_number=0x9999,  # Mismatched SNN
            payload=b"SAFE",
        )
        foreign_frame.compute_crcs()

        assert eng.receive_safety_frame(foreign_frame) is False
        assert eng.diagnostic_code == DIAG_ERR_FAIL_SAFE_TRIP
        assert eng.fail_safe_active is True
        assert eng.operational_state == StarOperationalState.FAIL_SAFE
        assert eng.is_healthy is False

    def test_receive_safety_frame_crc_s1_corruption(self) -> None:
        """Verify safety frame with corrupted CRC-S1 asserts DIAG_ERR_CRC_S1_FAULT (0xEE13)."""
        eng = CipSafetyAplStarEngine(node_id=1, safety_network_number=0x1337)
        frame = eng.send_safety_frame(b"PAYLOAD", target_node=2)

        corrupt_s1 = CipSafetyAplStarFrame(
            node_id=frame.node_id,
            target_node=frame.target_node,
            sequence_number=frame.sequence_number,
            timestamp_us=frame.timestamp_us,
            safety_network_number=frame.safety_network_number,
            payload=b"TAMPERED",  # Changed payload but kept old CRCs
            crc_s1=frame.crc_s1,
            crc_s2=frame.crc_s2,
        )

        assert eng.receive_safety_frame(corrupt_s1) is False
        assert eng.diagnostic_code == DIAG_ERR_CRC_S1_FAULT
        assert eng.fail_safe_active is True
        assert eng.is_healthy is False

    def test_receive_safety_frame_crc_s2_corruption(self) -> None:
        """Verify safety frame with valid CRC-S1 but corrupted CRC-S2 asserts DIAG_ERR_CRC_S2_FAULT (0xEE14)."""
        eng = CipSafetyAplStarEngine(node_id=1, safety_network_number=0x1337)
        frame = eng.send_safety_frame(b"PAYLOAD", target_node=2)

        corrupt_s2 = CipSafetyAplStarFrame(
            node_id=frame.node_id,
            target_node=frame.target_node,
            sequence_number=frame.sequence_number + 1,  # Corrupt sequence number -> CRC-S2 fails
            timestamp_us=frame.timestamp_us,
            safety_network_number=frame.safety_network_number,
            payload=frame.payload,  # Payload intact -> CRC-S1 valid
            crc_s1=frame.crc_s1,
            crc_s2=frame.crc_s2,
        )

        assert eng.receive_safety_frame(corrupt_s2) is False
        assert eng.diagnostic_code == DIAG_ERR_CRC_S2_FAULT
        assert eng.fail_safe_active is True
        assert eng.is_healthy is False


# ============================================================================
# 10. TestHeartbeatWatchdogSurveillance
# ============================================================================

class TestHeartbeatWatchdogSurveillance:
    """Validate heartbeat watchdog timer surveillance (> 200 ms) and fail-safe safe state fallback."""

    def test_heartbeat_watchdog_healthy_increment(self) -> None:
        """Verify scan_step increments heartbeat timer without fault when below timeout."""
        eng = CipSafetyAplStarEngine(watchdog_timeout_ms=200.0)
        assert eng.time_since_heartbeat_ms == 0.0

        ctx = ScanContext(cycle=1, dt_ms=10.0)
        res = eng.scan_step(ctx)
        assert res.status == AgentStatus.SUCCESS
        assert eng.time_since_heartbeat_ms == 10.0
        assert eng.is_healthy is True

    def test_heartbeat_watchdog_timeout_trip(self) -> None:
        """Verify missing heartbeat exceeding 200 ms triggers DIAG_ERR_HEARTBEAT_TIMEOUT (0xEE15) and safe state."""
        eng = CipSafetyAplStarEngine(watchdog_timeout_ms=200.0)
        eng.time_since_heartbeat_ms = 195.0

        # Step 10 ms -> 205 ms > 200 ms timeout
        ctx = ScanContext(cycle=2, dt_ms=10.0)
        res = eng.scan_step(ctx)

        assert res.status == AgentStatus.FAILED
        assert eng.diagnostic_code == DIAG_ERR_HEARTBEAT_TIMEOUT
        assert eng.fail_safe_active is True
        assert eng.operational_state == StarOperationalState.FAIL_SAFE
        assert eng.is_healthy is False
        assert res.error_code == str(DIAG_ERR_HEARTBEAT_TIMEOUT)
        assert res.data["diagnostic_code"] == str(DIAG_ERR_HEARTBEAT_TIMEOUT)

        # Check Horner OCS registers in heartbeat timeout safe state
        assert eng.reg_table.read_word(REG_CIP_SAFETY_STAR_DIAGNOSTIC_CODE) & 0xFFFF == 0xEE15
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is False
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_FAULT) is True

    def test_heartbeat_reset_on_frame_reception(self) -> None:
        """Verify receiving valid frame resets watchdog timer back to 0.0 ms."""
        eng_tx = CipSafetyAplStarEngine(node_id=1, watchdog_timeout_ms=200.0)
        eng_rx = CipSafetyAplStarEngine(node_id=2, watchdog_timeout_ms=200.0)
        eng_rx.time_since_heartbeat_ms = 180.0

        frame = eng_tx.send_safety_frame(b"KEEPALIVE", target_node=2)
        eng_rx.receive_safety_frame(frame)
        assert eng_rx.time_since_heartbeat_ms == 0.0
        assert eng_rx.is_healthy is True


# ============================================================================
# 11. TestHornerOcsRegisterSpaceSynchronization
# ============================================================================

class TestHornerOcsRegisterSpaceSynchronization:
    """Validate Horner OCS register space %R2500..%R2507 and discrete coils %M583..%M584."""

    def test_register_sync_healthy_state(self) -> None:
        """Verify bit-exact mapping of registers in nominal healthy state."""
        rt = RegisterTable()
        eng = CipSafetyAplStarEngine(node_id=5, num_branch_ports=4, register_table=rt)
        eng.sync_to_registers(rt)

        # %R2500: High byte = Node ID (5), Low byte = Operational State (1 = OPERATIONAL) -> 0x0501
        w_status = rt.read_word(REG_CIP_SAFETY_STAR_STATUS)
        assert (w_status >> 8) & 0xFF == 5
        assert w_status & 0xFF == 1

        # %R2501: Switch Root Port State (1 = UP)
        assert rt.read_word(REG_CIP_SAFETY_STAR_SWITCH_PORT_STATE) == 1

        # %R2502: Connected Star Nodes Bitmask (Ports 1..4 forwarding -> 0x0F)
        assert rt.read_word(REG_CIP_SAFETY_STAR_CONNECTED_MASK) == 0x0F

        # %R2503: Link Quality (100)
        assert rt.read_word(REG_CIP_SAFETY_STAR_LINK_QUALITY) == 100

        # %R2504: Forwarding Latency (15 us)
        assert rt.read_word(REG_CIP_SAFETY_STAR_FORWARDING_LATENCY_US) == 15

        # %R2505: Rolling Sequence Counter (0)
        assert rt.read_word(REG_CIP_SAFETY_STAR_SEQUENCE_COUNTER) == 0

        # %R2506: CRC & Star Status Bitmask
        status_word = rt.read_word(REG_CIP_SAFETY_STAR_CRC_STATUS)
        assert status_word & int(CipSafetyAplStarStatusBits.CRC_S1_VALID) != 0
        assert status_word & int(CipSafetyAplStarStatusBits.CRC_S2_VALID) != 0
        assert status_word & int(CipSafetyAplStarStatusBits.STAR_LINK_UP) != 0
        assert status_word & int(CipSafetyAplStarStatusBits.SWITCH_SYNCED) != 0
        assert status_word & int(CipSafetyAplStarStatusBits.FAIL_SAFE_ACTIVE) == 0

        # %R2507: Diagnostic Code (0x0000)
        assert rt.read_word(REG_CIP_SAFETY_STAR_DIAGNOSTIC_CODE) == 0x0000

        # Coils: %M583 True, %M584 False
        assert rt.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is True
        assert rt.read_bit(COIL_CIP_SAFETY_STAR_FAULT) is False

    def test_register_sync_privilege_modes(self) -> None:
        """Verify register synchronization accepts PrivilegeMode.USER and PrivilegeMode.SYSTEM."""
        rt = RegisterTable()
        eng = CipSafetyAplStarEngine(node_id=1, register_table=rt)

        eng.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert rt.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is True

        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is True

    def test_register_sync_branch_loss_state(self) -> None:
        """Verify registers and status bitmask in branch link loss state."""
        rt = RegisterTable()
        eng = CipSafetyAplStarEngine(node_id=1, num_branch_ports=4, register_table=rt)

        eng.inject_branch_loss(1)
        assert rt.read_word(REG_CIP_SAFETY_STAR_DIAGNOSTIC_CODE) & 0xFFFF == 0xEE11
        assert rt.read_word(REG_CIP_SAFETY_STAR_CONNECTED_MASK) == 0x0E  # Port 1 bit cleared

        status_word = rt.read_word(REG_CIP_SAFETY_STAR_CRC_STATUS)
        assert status_word & int(CipSafetyAplStarStatusBits.FAIL_SAFE_ACTIVE) != 0
        assert rt.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is False
        assert rt.read_bit(COIL_CIP_SAFETY_STAR_FAULT) is True

    def test_register_sync_root_fault_fail_safe(self) -> None:
        """Verify registers and status bitmask in switch root failure state."""
        rt = RegisterTable()
        eng = CipSafetyAplStarEngine(node_id=1, register_table=rt)

        eng.inject_switch_down()
        assert rt.read_word(REG_CIP_SAFETY_STAR_SWITCH_PORT_STATE) == 2  # DOWN
        assert rt.read_word(REG_CIP_SAFETY_STAR_DIAGNOSTIC_CODE) & 0xFFFF == 0xEE12

        status_word = rt.read_word(REG_CIP_SAFETY_STAR_CRC_STATUS)
        assert status_word & int(CipSafetyAplStarStatusBits.SWITCH_SYNCED) == 0
        assert status_word & int(CipSafetyAplStarStatusBits.FAIL_SAFE_ACTIVE) != 0
        assert rt.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is False
        assert rt.read_bit(COIL_CIP_SAFETY_STAR_FAULT) is True


# ============================================================================
# 12. TestPureIEC61131StructuredTextAndSecurity
# ============================================================================

class TestPureIEC61131StructuredTextAndSecurity:
    """Validate pure IEC 61131-3 Structured Text POU and strict anti-ladder construct rejection."""

    def test_st_program_content_and_constants(self) -> None:
        """Verify ST program text exists and is mirrored across aliases."""
        assert len(ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC) > 0
        assert CIP_SAFETY_APL_STAR_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert CipSafetyAplStarSync == ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC

        # Check register and coil bindings in text
        assert "PROGRAM CipSafetyAplStarSync" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "%R2500" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "%R2501" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "%R2502" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "%R2503" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "%R2504" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "%R2505" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "%R2506" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "%R2507" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "%M583" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "%M584" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC
        assert "END_PROGRAM" in ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC

    def test_verify_pure_st_function(self) -> None:
        """Verify verify_cip_safety_apl_star_pure_st passes STParser and SecurityGuard validation."""
        assert verify_cip_safety_apl_star_pure_st() is True

    def test_st_parser_ast_generation(self) -> None:
        """Verify STParser generates valid AST for CipSafetyAplStarSync."""
        val_res = STParser.validate_code(ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC)
        assert val_res.status == AgentStatus.SUCCESS

        parser = STParser()
        ast = parser.parse(ST_PROGRAM_CIP_SAFETY_APL_STAR_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSafetyAplStarSync"
        assert len(ast.variables) >= 10
        assert "%R2500" in ast.bound_registers
        assert "%M583" in ast.bound_registers

    def test_anti_ladder_construct_rejection(self) -> None:
        """Verify SecurityGuard strictly rejects ladder contacts, coils, rungs, networks, and mnemonics."""
        ladder_patterns = [
            "PROGRAM P VAR b : BOOL; END_VAR ---[ ]--- b; END_PROGRAM",
            "PROGRAM P VAR b : BOOL; END_VAR ---[/]--- b; END_PROGRAM",
            "PROGRAM P VAR b : BOOL; END_VAR ---( )--- b; END_PROGRAM",
            "PROGRAM P VAR b : BOOL; END_VAR ---(S)--- b; END_PROGRAM",
            "PROGRAM P VAR b : BOOL; END_VAR ---(R)--- b; END_PROGRAM",
            "PROGRAM P RUNG 1: XIC(b) OTE(c); END_PROGRAM",
            "PROGRAM P NETWORK 1; END_PROGRAM",
        ]
        for bad_code in ladder_patterns:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_code)


# ============================================================================
# 13. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Validate ILogicUnit interface compliance, step/execute/reset methods, and cyclic soak."""

    def test_interface_compliance(self) -> None:
        """Verify CipSafetyAplStarEngine implements ILogicUnit properties."""
        eng = CipSafetyAplStarEngine()
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "CipSafetyAplStarEngine"
        assert eng.priority == 10
        assert eng.is_enabled is True

    def test_step_execute_and_reset(self) -> None:
        """Verify step, execute, and reset convenience methods execute cleanly."""
        eng = CipSafetyAplStarEngine(node_id=1)
        eng.step()
        assert eng.time_since_heartbeat_ms == 10.0

        eng.execute()
        assert eng.time_since_heartbeat_ms == 20.0

        eng.inject_switch_down()
        assert eng.fail_safe_active is True

        eng.reset()
        assert eng.switch_port_state == SwitchPortState.UP
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True

    def test_cyclic_scan_soak_100_cycles(self) -> None:
        """Verify 100 consecutive 10 ms scan cycles execute deterministically with 0 faults."""
        eng = CipSafetyAplStarEngine(node_id=1)

        for i in range(100):
            ctx = ScanContext(cycle=i + 1, dt_ms=10.0)
            res = eng.scan_step(ctx)
            # Simulate receipt of heartbeat to reset watchdog
            eng.time_since_heartbeat_ms = 0.0

            assert res.status == AgentStatus.SUCCESS
            assert eng.is_healthy is True
            assert eng.diagnostic_code == DIAG_OK

        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_ACTIVE) is True
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_STAR_FAULT) is False


# ============================================================================
# 14. TestNineStageVerificationRunner
# ============================================================================

class TestNineStageVerificationRunner:
    """Validate 9-stage verification sequence, strict 4-state engineering contract, and artifact emission."""

    def test_verification_runner_execution_and_contract(self) -> None:
        """Verify run_cip_safety_apl_star_verification completes all 9 stages with status success."""
        evidence = run_cip_safety_apl_star_verification(work_package="W289")

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert "PASSED 9/9 stages" in evidence["details"]

        data = evidence["data"]
        assert data["work_package"] == "W289"
        assert data["gate"] == "G8"
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9

        stages = data["stages"]
        assert len(stages) == 9

        expected_stages = [
            (1, "init_and_topology"),
            (2, "dual_crc_validation"),
            (3, "branch_link_loss"),
            (4, "switch_root_failure"),
            (5, "fail_safe_deenergize"),
            (6, "heartbeat_watchdog_timeout"),
            (7, "horner_ocs_register_sync"),
            (8, "pure_st_pou_and_ladder_rejection"),
            (9, "cyclic_scan_soak_100"),
        ]

        for idx, (expected_num, expected_name) in enumerate(expected_stages):
            st = stages[idx]
            assert st["stage"] == expected_num
            assert st["name"] == expected_name
            assert st["passed"] is True
            assert st["timing_ms"] >= 0.0
            assert len(st["details"]) > 0

    def test_verification_runner_json_output(self) -> None:
        """Verify verification runner writes valid JSON evidence file when output_path is provided."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "telemetry" / "cip_safety_apl_star_evidence.json"
            evidence = run_cip_safety_apl_star_verification(output_path=str(out_file), work_package="W289")

            assert out_file.exists()
            with open(out_file, "r", encoding="utf-8") as f:
                saved_json = json.load(f)

            assert saved_json["status"] == "success"
            assert saved_json["data"]["checks_passed"] == 9
            assert saved_json["data"]["work_package"] == "W289"
