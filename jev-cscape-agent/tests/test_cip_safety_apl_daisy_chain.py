"""Comprehensive Unit Test Suite for Wave W292 CIP Safety Over Ethernet-APL Daisy-Chain Spur Protocol Engine.

Work Package: W292 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Ethernet-APL Daisy-Chain Spur Topology (10BASE-T1L / IEEE 802.3cg) for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 14 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnosticCodes: Protocol constants, diagnostic codes (0x0000, 0xEE21..0xEE27),
   signed/unsigned equality, string & repr representations, register mappings (%R2530..%R2537),
   coil mappings (%M590..%M591), status bits, and enums.
2. TestDualSafetyCrcCalculation: CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B inverted data) calculations,
   determinism, 16-bit range bounds, seed variation, bit-flip corruption detection across payload and header fields.
3. TestCipSafetyAplDaisyChainFrameModel: Frame encapsulation, CRC computation, frame validation, payload bit-tamper
   detection, sequence number tampering, timestamp tampering, SNN tampering, and binary serialization/deserialization.
4. TestAplDaisyChainNodeModel: Node model defaults, role assignment, port states, error counters, and active flags.
5. TestDaisyChainTopologyAndPortTransitions: Line topology node initialization, port state transitions
   (UP -> DOWN -> ISOLATED), and clear_faults restoration.
6. TestUpstreamLinkLossAndSafeState: Upstream link loss surveillance, transition to fail-safe safe state,
   diagnostic code 0xEE21 assertion, safe output de-energization, and link restoration.
7. TestDownstreamLinkLossAndNodeIsolation: Downstream link loss surveillance, isolation of downstream nodes
   (K+1..N) while keeping upstream nodes (1..K-1) operational, diagnostic code 0xEE22 assertion, and recovery.
8. TestHopLatencyAccumulationAndLimitExceedance: Per-hop forwarding latency monitoring (~8us/hop),
   cumulative latency accumulation, hop limit (8 hops) enforcement, and limit exceedance trip (0xEE26).
9. TestHeartbeatWatchdogSurveillance: Heartbeat watchdog surveillance (< 200 ms), watchdog timeout
   forcing fail-safe safe state, diagnostic code 0xEE25 assertion, and watchdog reset on frame receipt.
10. TestSafetyFrameTransmissionAndTamperDetection: Transmission sequence increments, frame validation,
    SNN mismatch fail-safe trip (0xEE27), CRC-S1 fault (0xEE23), and CRC-S2 fault (0xEE24).
11. TestHornerOcsRegisterSpaceSynchronization: Bit-exact synchronization to Horner OCS analog registers
    (%R2530..%R2537) and discrete coils (%M590..%M591), bit-packing, operational states, privilege mode support,
    and coil mutual exclusivity.
12. TestPureIEC61131StructuredTextAndSecurity: Pure IEC 61131-3 Structured Text POU CipSafetyAplDaisyChainSync
    syntax validation via STParser and SecurityGuard, variable address bindings, and strict rejection of ladder logic
    constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
13. TestILogicUnitComplianceAndSoak: ILogicUnit interface compliance (scan_step, step, execute, reset),
    ScanContext propagation, ExecutionResult contracts, and 100-cycle continuous scan soak execution.
14. TestNineStageVerificationRunner: Complete 9-stage verification suite run_cip_safety_apl_daisy_chain_verification,
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
from jev_cscape.telemetry.cip_safety_apl_daisy_chain import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_APL_DAISY_CHAIN_CLASS_ID,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    DEFAULT_NODE_ID,
    DEFAULT_PER_HOP_LATENCY_US,
    DEFAULT_MAX_HOPS,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CRC_INIT,
    REG_CIP_SAFETY_DAISY_STATUS,
    REG_CIP_SAFETY_DAISY_UPSTREAM_PORT,
    REG_CIP_SAFETY_DAISY_DOWNSTREAM_PORT,
    REG_CIP_SAFETY_DAISY_HOP_COUNT,
    REG_CIP_SAFETY_DAISY_CUMULATIVE_LATENCY_US,
    REG_CIP_SAFETY_DAISY_SEQUENCE_COUNTER,
    REG_CIP_SAFETY_DAISY_CRC_STATUS,
    REG_CIP_SAFETY_DAISY_DIAGNOSTIC_CODE,
    COIL_CIP_SAFETY_DAISY_ACTIVE,
    COIL_CIP_SAFETY_DAISY_FAULT,
    REG_DAISY_STATUS,
    REG_DAISY_UPSTREAM_PORT,
    REG_DAISY_DOWNSTREAM_PORT,
    REG_DAISY_HOP_COUNT,
    REG_DAISY_CUMULATIVE_LATENCY_US,
    REG_DAISY_SEQUENCE_COUNTER,
    REG_DAISY_CRC_STATUS,
    REG_DAISY_DIAGNOSTIC_CODE,
    COIL_DAISY_ACTIVE,
    COIL_DAISY_FAULT,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_UPSTREAM_LINK_LOSS,
    DIAG_ERR_DOWNSTREAM_LINK_LOSS,
    DIAG_ERR_CRC_S1_FAULT,
    DIAG_ERR_CRC_S2_FAULT,
    DIAG_ERR_HEARTBEAT_TIMEOUT,
    DIAG_ERR_HOP_LIMIT_EXCEEDED,
    DIAG_ERR_FAIL_SAFE_TRIP,
    CipSafetyAplDaisyChainDiagnosticCode,
    AplDaisyChainDiagnosticCode,
    DaisyOperationalState,
    CipSafetyAplDaisyChainState,
    AplDaisyChainOperationalState,
    DaisyChainState,
    UpstreamPortState,
    CipSafetyUpstreamPortState,
    DownstreamPortState,
    CipSafetyDownstreamPortState,
    PortState,
    DaisyPortState,
    DaisyRole,
    DaisyTopologyState,
    CipSafetyAplDaisyChainStatusBits,
    CipSafetyDaisyChainStatusBits,
    DaisyStatusBits,
    CipSafetyAplDaisyChainError,
    UpstreamLinkLossError,
    DownstreamLinkLossError,
    CrcS1FaultError,
    CrcS2FaultError,
    HeartbeatTimeoutError,
    HopLimitExceededError,
    FailSafeTripError,
    calculate_crc_s1,
    calculate_crc_s2,
    compute_crc_s1,
    compute_crc_s2,
    CipSafetyAplDaisyChainFrame,
    AplDaisyChainNode,
    DaisyChainNode,
    DaisyNode,
    ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC,
    CIP_SAFETY_APL_DAISY_CHAIN_PURE_ST_POU,
    CipSafetyAplDaisyChainSync,
    verify_cip_safety_apl_daisy_chain_pure_st,
    CipSafetyAplDaisyChainEngine,
    run_cip_safety_apl_daisy_chain_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnosticCodes
# ============================================================================

class TestConstantsEnumsAndDiagnosticCodes:
    """Validate ODVA CIP Safety Over Ethernet-APL Daisy-Chain constants, register maps, and diagnostic codes."""

    def test_register_and_coil_mappings(self) -> None:
        """Verify exact canonical register addresses %R2530..%R2537 and coils %M590..%M591."""
        assert REG_CIP_SAFETY_DAISY_STATUS == "%R2530"
        assert REG_CIP_SAFETY_DAISY_UPSTREAM_PORT == "%R2531"
        assert REG_CIP_SAFETY_DAISY_DOWNSTREAM_PORT == "%R2532"
        assert REG_CIP_SAFETY_DAISY_HOP_COUNT == "%R2533"
        assert REG_CIP_SAFETY_DAISY_CUMULATIVE_LATENCY_US == "%R2534"
        assert REG_CIP_SAFETY_DAISY_SEQUENCE_COUNTER == "%R2535"
        assert REG_CIP_SAFETY_DAISY_CRC_STATUS == "%R2536"
        assert REG_CIP_SAFETY_DAISY_DIAGNOSTIC_CODE == "%R2537"

        assert COIL_CIP_SAFETY_DAISY_ACTIVE == "%M590"
        assert COIL_CIP_SAFETY_DAISY_FAULT == "%M591"

        # Compatibility aliases
        assert REG_DAISY_STATUS == "%R2530"
        assert REG_DAISY_UPSTREAM_PORT == "%R2531"
        assert REG_DAISY_DOWNSTREAM_PORT == "%R2532"
        assert REG_DAISY_HOP_COUNT == "%R2533"
        assert REG_DAISY_CUMULATIVE_LATENCY_US == "%R2534"
        assert REG_DAISY_SEQUENCE_COUNTER == "%R2535"
        assert REG_DAISY_CRC_STATUS == "%R2536"
        assert REG_DAISY_DIAGNOSTIC_CODE == "%R2537"

        assert COIL_DAISY_ACTIVE == "%M590"
        assert COIL_DAISY_FAULT == "%M591"

    def test_diagnostic_codes_0xee21_to_0xee27(self) -> None:
        """Verify diagnostic code numerical assignments (0x0000, 0xEE21..0xEE27)."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_UPSTREAM_LINK_LOSS == 0xEE21
        assert DIAG_ERR_DOWNSTREAM_LINK_LOSS == 0xEE22
        assert DIAG_ERR_CRC_S1_FAULT == 0xEE23
        assert DIAG_ERR_CRC_S2_FAULT == 0xEE24
        assert DIAG_ERR_HEARTBEAT_TIMEOUT == 0xEE25
        assert DIAG_ERR_HOP_LIMIT_EXCEEDED == 0xEE26
        assert DIAG_ERR_FAIL_SAFE_TRIP == 0xEE27

        # Type aliases
        assert CipSafetyAplDaisyChainDiagnosticCode is DiagnosticCode
        assert AplDaisyChainDiagnosticCode is DiagnosticCode

        # Class attributes on DiagnosticCode
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.UPSTREAM_LINK_LOSS == 0xEE21
        assert DiagnosticCode.DOWNSTREAM_LINK_LOSS == 0xEE22
        assert DiagnosticCode.CRC_S1_FAULT == 0xEE23
        assert DiagnosticCode.CRC_S2_FAULT == 0xEE24
        assert DiagnosticCode.HEARTBEAT_TIMEOUT == 0xEE25
        assert DiagnosticCode.HOP_LIMIT_EXCEEDED == 0xEE26
        assert DiagnosticCode.FAIL_SAFE_TRIP == 0xEE27

    def test_diagnostic_code_integer_and_bitwise_behavior(self) -> None:
        """Verify DiagnosticCode supports signed/unsigned equality, string, repr, and bitwise operations."""
        code = DIAG_ERR_UPSTREAM_LINK_LOSS  # 0xEE21
        assert int(code) == 0xEE21
        assert code == 0xEE21
        # Signed 16-bit representation: 0xEE21 - 0x10000 = -4575
        assert code == -4575
        assert (code & 0xFFFF) == 0xEE21
        assert (code & 0xFF00) == 0xEE00
        assert (0xFFFF & code) == 0xEE21
        assert str(code) == "0xEE21"
        assert repr(code) == "DiagnosticCode(0xEE21)"

        ok = DIAG_OK
        assert int(ok) == 0x0000
        assert ok == 0
        assert str(ok) == "0x0000"

    def test_operational_and_port_state_enums(self) -> None:
        """Verify DaisyOperationalState, UpstreamPortState, DownstreamPortState, and PortState values."""
        assert DaisyOperationalState.INIT == 0
        assert DaisyOperationalState.OPERATIONAL == 1
        assert DaisyOperationalState.DEGRADED == 2
        assert DaisyOperationalState.FAIL_SAFE == 3

        assert UpstreamPortState.UP == 1
        assert UpstreamPortState.DOWN == 2
        assert UpstreamPortState.FAULT == 3

        assert DownstreamPortState.UP == 1
        assert DownstreamPortState.DOWN == 2
        assert DownstreamPortState.ISOLATED == 3

        assert PortState.DOWN == 0
        assert PortState.LINK_UP == 1
        assert PortState.BLOCKED == 2
        assert PortState.FORWARDING == 3

        # Aliases
        assert CipSafetyAplDaisyChainState is DaisyOperationalState
        assert AplDaisyChainOperationalState is DaisyOperationalState
        assert DaisyChainState is DaisyOperationalState
        assert CipSafetyUpstreamPortState is UpstreamPortState
        assert CipSafetyDownstreamPortState is DownstreamPortState
        assert DaisyPortState is PortState

    def test_status_bits_and_aliases(self) -> None:
        """Verify CipSafetyAplDaisyChainStatusBits bit positions and aliases."""
        assert CipSafetyAplDaisyChainStatusBits.CRC_S1_VALID == 0x01
        assert CipSafetyAplDaisyChainStatusBits.CRC_S2_VALID == 0x02
        assert CipSafetyAplDaisyChainStatusBits.UPSTREAM_UP == 0x04
        assert CipSafetyAplDaisyChainStatusBits.DOWNSTREAM_UP == 0x08
        assert CipSafetyAplDaisyChainStatusBits.FAIL_SAFE_ACTIVE == 0x10

        assert CipSafetyDaisyChainStatusBits is CipSafetyAplDaisyChainStatusBits
        assert DaisyStatusBits is CipSafetyAplDaisyChainStatusBits

    def test_exceptions_hierarchy(self) -> None:
        """Verify exception classes inherit from CipSafetyAplDaisyChainError."""
        assert issubclass(UpstreamLinkLossError, CipSafetyAplDaisyChainError)
        assert issubclass(DownstreamLinkLossError, CipSafetyAplDaisyChainError)
        assert issubclass(CrcS1FaultError, CipSafetyAplDaisyChainError)
        assert issubclass(CrcS2FaultError, CipSafetyAplDaisyChainError)
        assert issubclass(HeartbeatTimeoutError, CipSafetyAplDaisyChainError)
        assert issubclass(HopLimitExceededError, CipSafetyAplDaisyChainError)
        assert issubclass(FailSafeTripError, CipSafetyAplDaisyChainError)

    def test_class_ids_and_default_parameters(self) -> None:
        """Verify ODVA CIP Safety Volume 5 Class IDs and default protocol constants."""
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_APL_DAISY_CHAIN_CLASS_ID == 0x3F

        assert DEFAULT_SAFETY_NETWORK_NUMBER == 0x1A2B
        assert DEFAULT_SNN == 0x1A2B
        assert DEFAULT_NODE_ID == 1
        assert DEFAULT_PER_HOP_LATENCY_US == 8
        assert DEFAULT_MAX_HOPS == 8
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 200.0

        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CRC_INIT == 0xFFFF


# ============================================================================
# 2. TestDualSafetyCrcCalculation
# ============================================================================

class TestDualSafetyCrcCalculation:
    """Validate dual CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B) calculation and tamper detection."""

    def test_crc_s1_polynomial_and_initial_seed(self) -> None:
        """Verify CRC-S1 calculation is deterministic, bounded to 16 bits, and uses seed 0xFFFF."""
        payload = b"\x01\x02\x03\x04"
        crc1 = calculate_crc_s1(payload)
        crc2 = calculate_crc_s1(payload)
        assert crc1 == crc2
        assert 0 <= crc1 <= 0xFFFF
        assert compute_crc_s1(payload) == crc1

    def test_crc_s2_polynomial_and_inverted_data(self) -> None:
        """Verify CRC-S2 calculates over inverted sequence, timestamp, and SNN."""
        seq = 100
        ts = 1_000_000
        snn = 0x1A2B
        crc1 = calculate_crc_s2(seq, ts, snn)
        crc2 = calculate_crc_s2(seq, ts, snn)
        assert crc1 == crc2
        assert 0 <= crc1 <= 0xFFFF
        assert compute_crc_s2(seq, ts, snn) == crc1

    def test_crc_s1_single_bit_flip_tamper_detection(self) -> None:
        """Verify every single bit flip in 4-byte payload generates a different CRC-S1."""
        base_payload = b"\x12\x34\x56\x78"
        base_crc = calculate_crc_s1(base_payload)

        for byte_idx in range(len(base_payload)):
            for bit_idx in range(8):
                ba = bytearray(base_payload)
                ba[byte_idx] ^= (1 << bit_idx)
                corrupted_crc = calculate_crc_s1(bytes(ba))
                assert corrupted_crc != base_crc, f"CRC-S1 failed to detect bit flip at byte {byte_idx}, bit {bit_idx}"

    def test_crc_s2_header_field_tamper_detection(self) -> None:
        """Verify bit flips in sequence number, timestamp, or SNN alter CRC-S2."""
        base_seq = 42
        base_ts = 250_000
        base_snn = 0x1A2B
        base_crc = calculate_crc_s2(base_seq, base_ts, base_snn)

        # Alter sequence number
        assert calculate_crc_s2(base_seq ^ 1, base_ts, base_snn) != base_crc
        # Alter timestamp
        assert calculate_crc_s2(base_seq, base_ts ^ 1, base_snn) != base_crc
        # Alter SNN
        assert calculate_crc_s2(base_seq, base_ts, base_snn ^ 1) != base_crc

    def test_crc_s1_s2_seed_variation(self) -> None:
        """Verify non-standard initial seeds produce distinct CRC values."""
        payload = b"\xAA\xBB\xCC\xDD"
        crc_default = calculate_crc_s1(payload, init=0xFFFF)
        crc_custom = calculate_crc_s1(payload, init=0x0000)
        assert crc_default != crc_custom

    def test_crc_s1_s2_argument_polymorphism(self) -> None:
        """Verify CRC functions support keyword arguments, multiple chunks, and raw byte formats."""
        chunk1 = b"\x01\x02"
        chunk2 = b"\x03\x04"
        crc_chunks = calculate_crc_s1(chunk1, chunk2)
        crc_direct = calculate_crc_s1(b"\x01\x02\x03\x04")
        assert crc_chunks == crc_direct

        # Keyword arguments
        crc_kw = calculate_crc_s1(payload=b"\x01\x02\x03\x04")
        assert crc_kw == crc_direct

        crc_s2_kw = calculate_crc_s2(
            sequence_number=10,
            timestamp_us=5000,
            safety_network_number=0x1A2B,
        )
        crc_s2_pos = calculate_crc_s2(10, 5000, 0x1A2B)
        assert crc_s2_kw == crc_s2_pos


# ============================================================================
# 3. TestCipSafetyAplDaisyChainFrameModel
# ============================================================================

class TestCipSafetyAplDaisyChainFrameModel:
    """Validate frame encapsulation, validation, binary serialization, and bit tampering."""

    def test_frame_defaults_and_initialization(self) -> None:
        """Verify default frame properties."""
        frame = CipSafetyAplDaisyChainFrame()
        assert frame.node_id == 1
        assert frame.target_node == 2
        assert frame.hop_count == 1
        assert frame.sequence_number == 0
        assert frame.safety_network_number == DEFAULT_SAFETY_NETWORK_NUMBER
        assert frame.cumulative_latency_us == DEFAULT_PER_HOP_LATENCY_US
        assert frame.crc_s1 == 0
        assert frame.crc_s2 == 0

    def test_frame_crc_computation_and_validity(self) -> None:
        """Verify compute_crcs populates valid CRCs and is_valid returns True."""
        frame = CipSafetyAplDaisyChainFrame(
            node_id=2,
            target_node=3,
            hop_count=2,
            sequence_number=15,
            timestamp_us=123456,
            safety_network_number=0x1A2B,
            payload=b"\xCA\xFE\xBA\xBE",
        )
        assert frame.is_valid() is False  # uncomputed

        frame.compute_crcs()
        assert frame.crc_s1 != 0
        assert frame.crc_s2 != 0
        assert frame.is_valid() is True

    def test_frame_binary_serialization_and_deserialization(self) -> None:
        """Verify frame binary serialize and deserialize preserve all fields exactly."""
        original = CipSafetyAplDaisyChainFrame(
            node_id=3,
            target_node=4,
            hop_count=3,
            sequence_number=999,
            timestamp_us=456789,
            safety_network_number=0x1A2B,
            payload=b"\xDE\xAD\xBE\xEF\x01\x02",
            cumulative_latency_us=24,
            per_hop_latency_us=8,
        )
        original.compute_crcs()

        raw_bytes = original.serialize()
        assert len(raw_bytes) >= 18

        restored = CipSafetyAplDaisyChainFrame.deserialize(raw_bytes)
        assert restored.node_id == original.node_id
        assert restored.target_node == original.target_node
        assert restored.hop_count == original.hop_count
        assert restored.sequence_number == original.sequence_number
        assert restored.timestamp_us == original.timestamp_us
        assert restored.safety_network_number == original.safety_network_number
        assert restored.payload == original.payload
        assert restored.crc_s1 == original.crc_s1
        assert restored.crc_s2 == original.crc_s2
        assert restored.cumulative_latency_us == original.cumulative_latency_us
        assert restored.is_valid() is True

    def test_frame_bit_tampering_payload_and_crcs(self) -> None:
        """Verify mutating payload or CRCs invalidates frame integrity."""
        frame = CipSafetyAplDaisyChainFrame(
            payload=b"\x01\x02\x03\x04",
            sequence_number=1,
            timestamp_us=100,
            safety_network_number=0x1A2B,
        )
        frame.compute_crcs()
        assert frame.is_valid() is True

        # Mutate payload
        frame.mutate_payload(byte_offset=0, bit_pos=0)
        assert frame.is_valid() is False

        # Re-compute and mutate CRC-S1
        frame.compute_crcs()
        frame.mutate_crc_s1()
        assert frame.is_valid() is False

        # Re-compute and mutate CRC-S2
        frame.compute_crcs()
        frame.mutate_crc_s2()
        assert frame.is_valid() is False

    def test_frame_hop_forwarding_latency_increment(self) -> None:
        """Verify frame.forward increments hop_count and cumulative_latency_us."""
        frame = CipSafetyAplDaisyChainFrame(hop_count=1, cumulative_latency_us=8)
        frame.forward(per_hop_latency_us=8)
        assert frame.hop_count == 2
        assert frame.cumulative_latency_us == 16

        frame.forward(per_hop_latency_us=8)
        assert frame.hop_count == 3
        assert frame.cumulative_latency_us == 24


# ============================================================================
# 4. TestAplDaisyChainNodeModel
# ============================================================================

class TestAplDaisyChainNodeModel:
    """Validate AplDaisyChainNode attributes, aliases, and topology roles."""

    def test_node_initialization_and_attributes(self) -> None:
        """Verify node defaults and property assignments."""
        node = AplDaisyChainNode(node_id=2, hop_position=2)
        assert node.node_id == 2
        assert node.hop_position == 2
        assert node.role == DaisyRole.INSTRUMENT
        assert node.upstream_state == UpstreamPortState.UP
        assert node.downstream_state == DownstreamPortState.UP
        assert node.is_connected is True
        assert node.is_isolated is False
        assert node.cumulative_latency_us == DEFAULT_PER_HOP_LATENCY_US
        assert node.errors_count == 0

    def test_node_aliases_and_roles(self) -> None:
        """Verify type aliases DaisyChainNode and DaisyNode match AplDaisyChainNode."""
        assert DaisyChainNode is AplDaisyChainNode
        assert DaisyNode is AplDaisyChainNode
        assert DaisyRole.FIELD_SWITCH == "FIELD_SWITCH"
        assert DaisyRole.ROOT_NODE == "ROOT_NODE"
        assert DaisyRole.INTERMEDIATE_NODE == "INTERMEDIATE_NODE"
        assert DaisyRole.TAIL_NODE == "TAIL_NODE"


# ============================================================================
# 5. TestDaisyChainTopologyAndPortTransitions
# ============================================================================

class TestDaisyChainTopologyAndPortTransitions:
    """Validate daisy-chain spur topology initial state and port state transitions."""

    def test_daisy_chain_nominal_topology_initialization(self) -> None:
        """Verify engine initializes in OPERATIONAL state with healthy ports."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1, hop_count=1, chain_length=4)
        assert eng.node_id == 1
        assert eng.hop_count == 1
        assert eng.chain_length == 4
        assert len(eng.nodes) == 4
        assert eng.upstream_port_state == UpstreamPortState.UP
        assert eng.downstream_port_state == DownstreamPortState.UP
        assert eng.operational_state == DaisyOperationalState.OPERATIONAL
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True
        assert eng.fail_safe_active is False

    def test_port_state_transitions(self) -> None:
        """Verify transition between UP and DOWN states."""
        eng = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2)
        assert eng.upstream_port_state == UpstreamPortState.UP
        assert eng.downstream_port_state == DownstreamPortState.UP

        eng.inject_downstream_loss()
        assert eng.downstream_port_state == DownstreamPortState.DOWN
        assert eng.operational_state == DaisyOperationalState.DEGRADED

        eng.restore_downstream()
        assert eng.downstream_port_state == DownstreamPortState.UP
        assert eng.operational_state == DaisyOperationalState.OPERATIONAL

    def test_clear_faults_and_restoration(self) -> None:
        """Verify clear_faults restores nominal state when ports are healthy."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1)
        eng.trip_fail_safe(DIAG_ERR_FAIL_SAFE_TRIP)
        assert eng.fail_safe_active is True
        assert eng.operational_state == DaisyOperationalState.FAIL_SAFE

        eng.clear_faults()
        assert eng.fail_safe_active is False
        assert eng.operational_state == DaisyOperationalState.OPERATIONAL
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True


# ============================================================================
# 6. TestUpstreamLinkLossAndSafeState
# ============================================================================

class TestUpstreamLinkLossAndSafeState:
    """Validate upstream link loss detection, fail-safe safe state, and recovery."""

    def test_upstream_link_loss_trips_0xee21_and_failsafe(self) -> None:
        """Verify upstream link loss asserts 0xEE21 and trips fail-safe."""
        eng = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2)
        assert eng.is_healthy is True

        eng.inject_upstream_loss()
        assert eng.upstream_port_state == UpstreamPortState.DOWN
        assert eng.operational_state == DaisyOperationalState.FAIL_SAFE
        assert eng.diagnostic_code == DIAG_ERR_UPSTREAM_LINK_LOSS
        assert eng.diagnostic_code == 0xEE21
        assert eng.fail_safe_active is True
        assert eng.is_healthy is False
        assert eng.upstream_loss_count == 1

    def test_upstream_link_loss_deenergizes_safe_outputs(self) -> None:
        """Verify safe outputs are clamped to zero bytes on upstream loss."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1)
        assert eng.safe_output_data != b"\x00\x00\x00\x00"

        eng.inject_upstream_loss()
        assert eng.safe_output_data == b"\x00\x00\x00\x00"

    def test_restore_upstream_link(self) -> None:
        """Verify restoring upstream link recovers node to OPERATIONAL and DIAG_OK."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1)
        eng.inject_upstream_loss()
        assert eng.fail_safe_active is True

        eng.restore_upstream()
        assert eng.upstream_port_state == UpstreamPortState.UP
        assert eng.operational_state == DaisyOperationalState.OPERATIONAL
        assert eng.diagnostic_code == DIAG_OK
        assert eng.fail_safe_active is False
        assert eng.is_healthy is True
        assert eng.safe_output_data == b"\x01\x02\x03\x04"


# ============================================================================
# 7. TestDownstreamLinkLossAndNodeIsolation
# ============================================================================

class TestDownstreamLinkLossAndNodeIsolation:
    """Validate downstream link loss, isolation of K+1..N, and keeping 1..K-1 operational."""

    def test_downstream_link_loss_trips_0xee22_and_degraded_state(self) -> None:
        """Verify downstream link break triggers DEGRADED mode and 0xEE22."""
        eng = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2, chain_length=4)
        eng.inject_downstream_loss()

        assert eng.downstream_port_state == DownstreamPortState.DOWN
        assert eng.operational_state == DaisyOperationalState.DEGRADED
        assert eng.diagnostic_code == DIAG_ERR_DOWNSTREAM_LINK_LOSS
        assert eng.diagnostic_code == 0xEE22
        assert eng.downstream_loss_count == 1

    def test_downstream_node_isolation_k_plus_1_to_n(self) -> None:
        """Verify in-line break at hop 2 isolates nodes 3 and 4 while node 1 is unaffected."""
        eng = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2, chain_length=4)
        eng.inject_downstream_loss()

        # Nodes at hop > 2 are isolated
        assert eng.nodes[3].is_isolated is True
        assert eng.nodes[3].upstream_state == UpstreamPortState.DOWN
        assert eng.nodes[4].is_isolated is True
        assert eng.nodes[4].upstream_state == UpstreamPortState.DOWN

        # Node 1 at hop 1 is NOT isolated
        assert eng.nodes[1].is_isolated is False
        assert eng.nodes[1].upstream_state == UpstreamPortState.UP

    def test_restore_downstream_link_clears_isolation(self) -> None:
        """Verify restoring downstream link clears isolation on downstream nodes."""
        eng = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2, chain_length=4)
        eng.inject_downstream_loss()
        assert eng.nodes[3].is_isolated is True

        eng.restore_downstream()
        assert eng.downstream_port_state == DownstreamPortState.UP
        assert eng.operational_state == DaisyOperationalState.OPERATIONAL
        assert eng.diagnostic_code == DIAG_OK
        assert eng.nodes[3].is_isolated is False
        assert eng.nodes[4].is_isolated is False
        assert eng.nodes[3].upstream_state == UpstreamPortState.UP

    def test_combined_upstream_and_downstream_loss(self) -> None:
        """Verify upstream loss takes priority over downstream loss (forcing FAIL_SAFE)."""
        eng = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2, chain_length=4)
        eng.inject_downstream_loss()
        assert eng.operational_state == DaisyOperationalState.DEGRADED

        eng.inject_upstream_loss()
        assert eng.operational_state == DaisyOperationalState.FAIL_SAFE
        assert eng.diagnostic_code == DIAG_ERR_UPSTREAM_LINK_LOSS
        assert eng.fail_safe_active is True


# ============================================================================
# 8. TestHopLatencyAccumulationAndLimitExceedance
# ============================================================================

class TestHopLatencyAccumulationAndLimitExceedance:
    """Validate per-hop latency accumulation (~8us/hop) and hop limit (>8 hops) exceedance."""

    def test_hop_latency_tracking_nominal(self) -> None:
        """Verify cumulative latency increases proportionally with hop count."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1, per_hop_latency_us=8)

        for hop in range(1, 9):
            eng.set_hop_count(hop)
            assert eng.hop_count == hop
            assert eng.cumulative_latency_us == hop * 8
            assert eng.operational_state == DaisyOperationalState.OPERATIONAL
            assert eng.diagnostic_code == DIAG_OK
            assert eng.is_healthy is True

    def test_hop_limit_exceedance_trips_0xee26(self) -> None:
        """Verify exceeding max hops (>8 hops) trips DIAG_ERR_HOP_LIMIT_EXCEEDED (0xEE26)."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1, max_hops=8)
        eng.set_hop_count(8)
        assert eng.is_healthy is True

        # Hop 9 exceeds limit
        eng.set_hop_count(9)
        assert eng.hop_count == 9
        assert eng.cumulative_latency_us == 72
        assert eng.operational_state == DaisyOperationalState.FAIL_SAFE
        assert eng.diagnostic_code == DIAG_ERR_HOP_LIMIT_EXCEEDED
        assert eng.diagnostic_code == 0xEE26
        assert eng.fail_safe_active is True
        assert eng.is_healthy is False

    def test_reducing_hop_count_clears_limit_exceeded(self) -> None:
        """Verify reducing hop count back within allowable limits restores operational state."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1, max_hops=8)
        eng.set_hop_count(9)
        assert eng.diagnostic_code == DIAG_ERR_HOP_LIMIT_EXCEEDED

        eng.set_hop_count(5)
        assert eng.hop_count == 5
        assert eng.diagnostic_code == DIAG_OK
        assert eng.operational_state == DaisyOperationalState.OPERATIONAL
        assert eng.is_healthy is True


# ============================================================================
# 9. TestHeartbeatWatchdogSurveillance
# ============================================================================

class TestHeartbeatWatchdogSurveillance:
    """Validate heartbeat watchdog timer (< 200ms) surveillance and timeout handling."""

    def test_heartbeat_watchdog_timeout_trips_0xee25(self) -> None:
        """Verify silence > 200 ms trips fail-safe and sets diagnostic code 0xEE25."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1, watchdog_timeout_ms=200.0)
        assert eng.is_healthy is True

        # Scan step with dt = 250 ms (exceeds 200 ms)
        res = eng.scan_step(dt_ms=250.0)
        assert res.status == AgentStatus.FAILED
        assert eng.operational_state == DaisyOperationalState.FAIL_SAFE
        assert eng.diagnostic_code == DIAG_ERR_HEARTBEAT_TIMEOUT
        assert eng.diagnostic_code == 0xEE25
        assert eng.fail_safe_active is True
        assert eng.is_healthy is False

    def test_feed_heartbeat_and_feed_watchdog_prevents_timeout(self) -> None:
        """Verify calling feed_heartbeat resets time_since_last_heartbeat_ms."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1, watchdog_timeout_ms=200.0)

        # Accumulate 150 ms
        eng.scan_step(dt_ms=150.0)
        assert eng.time_since_last_heartbeat_ms == 150.0
        assert eng.is_healthy is True

        # Feed watchdog
        eng.feed_heartbeat()
        assert eng.time_since_last_heartbeat_ms == 0.0

        # Feed alias
        eng.scan_step(dt_ms=100.0)
        eng.feed_watchdog()
        assert eng.time_since_last_heartbeat_ms == 0.0

    def test_receiving_valid_frame_resets_watchdog(self) -> None:
        """Verify receiving a valid safety frame resets the watchdog timer."""
        eng = CipSafetyAplDaisyChainEngine(node_id=2, watchdog_timeout_ms=200.0)
        eng.scan_step(dt_ms=120.0)
        assert eng.time_since_last_heartbeat_ms == 120.0

        frame = eng.send_safety_frame(payload=b"\x01\x02\x03\x04")
        ok = eng.receive_safety_frame(frame)
        assert ok is True
        assert eng.time_since_last_heartbeat_ms == 0.0


# ============================================================================
# 10. TestSafetyFrameTransmissionAndTamperDetection
# ============================================================================

class TestSafetyFrameTransmissionAndTamperDetection:
    """Validate frame transmission, reception, and bit-tamper detection across line spur."""

    def test_send_safety_frame_sequence_counter_increment(self) -> None:
        """Verify send_safety_frame increments sequence_counter and populates last_tx_frame."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1)
        assert eng.sequence_counter == 0

        frame1 = eng.send_safety_frame(payload=b"\xAA\xBB\xCC\xDD", target_node=2)
        assert frame1.sequence_number == 0
        assert eng.sequence_counter == 1
        assert eng.last_tx_frame is frame1
        assert frame1.is_valid() is True

        frame2 = eng.send_safety_frame(payload=b"\xEE\xFF\x00\x11", target_node=3)
        assert frame2.sequence_number == 1
        assert eng.sequence_counter == 2
        assert frame2.is_valid() is True

    def test_receive_valid_safety_frame_updates_output(self) -> None:
        """Verify receiving valid frame succeeds and updates safe_output_data."""
        sender = CipSafetyAplDaisyChainEngine(node_id=1)
        receiver = CipSafetyAplDaisyChainEngine(node_id=2)

        frame = sender.send_safety_frame(payload=b"\x11\x22\x33\x44")
        success = receiver.receive_safety_frame(frame)
        assert success is True
        assert receiver.safe_output_data == b"\x11\x22\x33\x44"
        assert receiver.last_crc_s1_valid is True
        assert receiver.last_crc_s2_valid is True
        assert receiver.is_healthy is True

    def test_receive_frame_corrupted_crc_s1_trips_0xee23(self) -> None:
        """Verify receiving frame with corrupted CRC-S1 asserts 0xEE23 and trips fail-safe."""
        sender = CipSafetyAplDaisyChainEngine(node_id=1)
        receiver = CipSafetyAplDaisyChainEngine(node_id=2)

        frame = sender.send_safety_frame(payload=b"\x12\x34\x56\x78")
        frame.mutate_crc_s1()

        success = receiver.receive_safety_frame(frame)
        assert success is False
        assert receiver.last_crc_s1_valid is False
        assert receiver.operational_state == DaisyOperationalState.FAIL_SAFE
        assert receiver.diagnostic_code == DIAG_ERR_CRC_S1_FAULT
        assert receiver.diagnostic_code == 0xEE23
        assert receiver.fail_safe_active is True

    def test_receive_frame_corrupted_crc_s2_trips_0xee24(self) -> None:
        """Verify receiving frame with corrupted CRC-S2 asserts 0xEE24 and trips fail-safe."""
        sender = CipSafetyAplDaisyChainEngine(node_id=1)
        receiver = CipSafetyAplDaisyChainEngine(node_id=2)

        frame = sender.send_safety_frame(payload=b"\x12\x34\x56\x78")
        frame.mutate_crc_s2()

        success = receiver.receive_safety_frame(frame)
        assert success is False
        assert receiver.last_crc_s2_valid is False
        assert receiver.operational_state == DaisyOperationalState.FAIL_SAFE
        assert receiver.diagnostic_code == DIAG_ERR_CRC_S2_FAULT
        assert receiver.diagnostic_code == 0xEE24
        assert receiver.fail_safe_active is True

    def test_receive_frame_snn_mismatch_trips_0xee27(self) -> None:
        """Verify receiving frame with mismatched SNN trips fail-safe with 0xEE27."""
        sender = CipSafetyAplDaisyChainEngine(node_id=1, safety_network_number=0x1111)
        receiver = CipSafetyAplDaisyChainEngine(node_id=2, safety_network_number=0x2222)

        frame = sender.send_safety_frame(payload=b"\x01\x02\x03\x04")
        success = receiver.receive_safety_frame(frame)
        assert success is False
        assert receiver.operational_state == DaisyOperationalState.FAIL_SAFE
        assert receiver.diagnostic_code == DIAG_ERR_FAIL_SAFE_TRIP
        assert receiver.diagnostic_code == 0xEE27

    def test_receive_frame_hop_limit_trips_0xee26(self) -> None:
        """Verify frame with hop count exceeding max hops trips 0xEE26."""
        receiver = CipSafetyAplDaisyChainEngine(node_id=2, max_hops=8)
        frame = CipSafetyAplDaisyChainFrame(
            node_id=1,
            target_node=2,
            hop_count=9,  # exceeds 8
            payload=b"\x01\x02\x03\x04",
            safety_network_number=DEFAULT_SAFETY_NETWORK_NUMBER,
        )
        frame.compute_crcs()

        success = receiver.receive_safety_frame(frame)
        assert success is False
        assert receiver.operational_state == DaisyOperationalState.FAIL_SAFE
        assert receiver.diagnostic_code == DIAG_ERR_HOP_LIMIT_EXCEEDED
        assert receiver.diagnostic_code == 0xEE26

    def test_receive_frame_blocked_when_upstream_down(self) -> None:
        """Verify receiving frame returns False if upstream port is down."""
        receiver = CipSafetyAplDaisyChainEngine(node_id=2)
        receiver.inject_upstream_loss()
        assert receiver.upstream_port_state == UpstreamPortState.DOWN

        frame = CipSafetyAplDaisyChainFrame(payload=b"\x01\x02\x03\x04")
        frame.compute_crcs()
        assert receiver.receive_safety_frame(frame) is False


# ============================================================================
# 11. TestHornerOcsRegisterSpaceSynchronization
# ============================================================================

class TestHornerOcsRegisterSpaceSynchronization:
    """Validate bit-exact synchronization to Horner OCS analog registers and discrete coils."""

    def test_registers_nominal_synchronization(self) -> None:
        """Verify registers %R2530..%R2537 and coils %M590..%M591 under nominal operation."""
        rt = RegisterTable()
        eng = CipSafetyAplDaisyChainEngine(
            node_id=2,
            hop_count=2,
            per_hop_latency_us=8,
            register_table=rt,
        )
        eng.sync_to_registers(rt)

        # %R2530: High byte = Node ID (2), Low byte = Operational State (1 = OPERATIONAL) -> 0x0201
        assert rt.read_word(REG_CIP_SAFETY_DAISY_STATUS) == 0x0201

        # %R2531: Upstream port (1 = UP)
        assert rt.read_word(REG_CIP_SAFETY_DAISY_UPSTREAM_PORT) == 1

        # %R2532: Downstream port (1 = UP)
        assert rt.read_word(REG_CIP_SAFETY_DAISY_DOWNSTREAM_PORT) == 1

        # %R2533: Hop count (2)
        assert rt.read_word(REG_CIP_SAFETY_DAISY_HOP_COUNT) == 2

        # %R2534: Cumulative latency (16 us)
        assert rt.read_word(REG_CIP_SAFETY_DAISY_CUMULATIVE_LATENCY_US) == 16

        # %R2535: Sequence counter (0)
        assert rt.read_word(REG_CIP_SAFETY_DAISY_SEQUENCE_COUNTER) == 0

        # %R2536: CRC & Status Word (Bit 0: S1 valid, Bit 1: S2 valid, Bit 2: Upstream up, Bit 3: Downstream up) -> 0x000F
        assert rt.read_word(REG_CIP_SAFETY_DAISY_CRC_STATUS) == 0x000F

        # %R2537: Diagnostic code (0x0000 OK)
        assert rt.read_word(REG_CIP_SAFETY_DAISY_DIAGNOSTIC_CODE) == 0x0000

        # Discrete Coils %M590..%M591
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) is True
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_FAULT) is False

    def test_registers_sync_after_upstream_loss(self) -> None:
        """Verify register table reflects upstream loss and fail-safe trip."""
        rt = RegisterTable()
        eng = CipSafetyAplDaisyChainEngine(node_id=1, register_table=rt)
        eng.inject_upstream_loss()

        # %R2530: Low byte = 3 (FAIL_SAFE)
        assert (rt.read_word(REG_CIP_SAFETY_DAISY_STATUS) & 0xFF) == 3

        # %R2531: Upstream port = 2 (DOWN)
        assert rt.read_word(REG_CIP_SAFETY_DAISY_UPSTREAM_PORT) == 2

        # %R2536: Bit 4 set (FAIL_SAFE_ACTIVE), Bit 2 cleared (Upstream not up)
        status_word = rt.read_word(REG_CIP_SAFETY_DAISY_CRC_STATUS)
        assert (status_word & (1 << 4)) != 0
        assert (status_word & (1 << 2)) == 0

        # %R2537: Diagnostic code = 0xEE21
        assert (rt.read_word(REG_CIP_SAFETY_DAISY_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE21

        # Coils
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) is False
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_FAULT) is True

    def test_registers_sync_after_downstream_loss(self) -> None:
        """Verify register table reflects downstream loss and DEGRADED state."""
        rt = RegisterTable()
        eng = CipSafetyAplDaisyChainEngine(node_id=1, register_table=rt)
        eng.inject_downstream_loss()

        # %R2530: Low byte = 2 (DEGRADED)
        assert (rt.read_word(REG_CIP_SAFETY_DAISY_STATUS) & 0xFF) == 2

        # %R2532: Downstream port = 2 (DOWN)
        assert rt.read_word(REG_CIP_SAFETY_DAISY_DOWNSTREAM_PORT) == 2

        # %R2537: Diagnostic code = 0xEE22
        assert (rt.read_word(REG_CIP_SAFETY_DAISY_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE22

        # Degraded is not full fault, but active is false because not nominal
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) is False
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_FAULT) is True

    def test_coils_mutual_exclusivity_m590_m591(self) -> None:
        """Verify coils %M590 (ACTIVE) and %M591 (FAULT) are strictly mutually exclusive."""
        rt = RegisterTable()
        eng = CipSafetyAplDaisyChainEngine(node_id=1, register_table=rt)

        # 1. Nominal
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) is True
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_FAULT) is False
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) != rt.read_bit(COIL_CIP_SAFETY_DAISY_FAULT)

        # 2. Upstream loss
        eng.inject_upstream_loss()
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) is False
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_FAULT) is True
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) != rt.read_bit(COIL_CIP_SAFETY_DAISY_FAULT)

        # 3. Restored
        eng.restore_upstream()
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) is True
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_FAULT) is False
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) != rt.read_bit(COIL_CIP_SAFETY_DAISY_FAULT)

    def test_privilege_mode_compatibility(self) -> None:
        """Verify sync_to_registers works cleanly with USER and SYSTEM privilege modes."""
        rt = RegisterTable()
        eng = CipSafetyAplDaisyChainEngine(node_id=1, register_table=rt)

        eng.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert rt.read_word(REG_CIP_SAFETY_DAISY_STATUS) == 0x0101
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) is True

        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word(REG_CIP_SAFETY_DAISY_STATUS) == 0x0101
        assert rt.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) is True


# ============================================================================
# 12. TestPureIEC61131StructuredTextAndSecurity
# ============================================================================

class TestPureIEC61131StructuredTextAndSecurity:
    """Validate Pure IEC 61131-3 Structured Text POU and anti-ladder construct rejection."""

    def test_pure_st_pou_syntax_and_program_name(self) -> None:
        """Verify ST POU string contains PROGRAM CipSafetyAplDaisyChainSync and required tokens."""
        assert "PROGRAM CipSafetyAplDaisyChainSync" in ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC
        assert "VAR" in ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC
        assert "END_VAR" in ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC
        assert "END_PROGRAM" in ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC

        assert CIP_SAFETY_APL_DAISY_CHAIN_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC
        assert CipSafetyAplDaisyChainSync == ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC

    def test_all_10_registers_bound_in_pou(self) -> None:
        """Verify all 8 analog registers and 2 discrete coils are declared in POU variable table."""
        expected = [
            "%R2530", "%R2531", "%R2532", "%R2533",
            "%R2534", "%R2535", "%R2536", "%R2537",
            "%M590", "%M591",
        ]
        for reg in expected:
            assert reg in ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC, f"Missing register {reg} in ST POU"

    def test_verify_cip_safety_apl_daisy_chain_pure_st_returns_true(self) -> None:
        """Verify verify_cip_safety_apl_daisy_chain_pure_st returns True."""
        assert verify_cip_safety_apl_daisy_chain_pure_st() is True

    def test_st_parser_ast_validation(self) -> None:
        """Verify STParser parses POU into a valid PROGRAM AST with correct bindings."""
        parser = STParser()
        ast = parser.parse(ST_PROGRAM_CIP_SAFETY_APL_DAISY_CHAIN_SYNC)

        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSafetyAplDaisyChainSync"
        assert len(ast.variables) >= 10
        assert "%R2530" in ast.bound_registers
        assert "%M590" in ast.bound_registers
        assert "%M591" in ast.bound_registers

    def test_anti_ladder_rejection_contacts(self) -> None:
        """Verify SecurityGuard strictly rejects ladder contacts (---[ ]---, ---[/]---)."""
        bad_contacts = [
            "PROGRAM P VAR b : BOOL; END_VAR ---[ ]--- b; END_PROGRAM",
            "PROGRAM P VAR b : BOOL; END_VAR ---[/]--- b; END_PROGRAM",
        ]
        for code in bad_contacts:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(code)

    def test_anti_ladder_rejection_coils(self) -> None:
        """Verify SecurityGuard strictly rejects ladder coils (---( )---, ---(S)---, ---(R)---)."""
        bad_coils = [
            "PROGRAM P VAR b : BOOL; END_VAR ---( )--- b; END_PROGRAM",
            "PROGRAM P VAR b : BOOL; END_VAR ---(S)--- b; END_PROGRAM",
            "PROGRAM P VAR b : BOOL; END_VAR ---(R)--- b; END_PROGRAM",
        ]
        for code in bad_coils:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(code)

    def test_anti_ladder_rejection_rungs_and_networks(self) -> None:
        """Verify SecurityGuard strictly rejects ladder RUNG and NETWORK delimiters."""
        bad_structures = [
            "PROGRAM P RUNG 1: x := 1; END_PROGRAM",
            "PROGRAM P NETWORK 1; x := 1; END_PROGRAM",
        ]
        for code in bad_structures:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(code)

    def test_anti_ladder_rejection_mnemonics(self) -> None:
        """Verify SecurityGuard strictly rejects ladder mnemonics (XIC, OTE)."""
        bad_mnemonics = [
            "PROGRAM P XIC(b); OTE(c); END_PROGRAM",
        ]
        for code in bad_mnemonics:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(code)


# ============================================================================
# 13. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Validate ILogicUnit interface compliance, step/execute/reset, and continuous scan soak."""

    def test_ilogicunit_interface_properties(self) -> None:
        """Verify CipSafetyAplDaisyChainEngine implements ILogicUnit properties."""
        eng = CipSafetyAplDaisyChainEngine()
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "CipSafetyAplDaisyChainEngine"
        assert eng.priority == 10
        assert eng.is_enabled is True

    def test_scan_step_with_float_and_context(self) -> None:
        """Verify scan_step executes cleanly with float dt and ScanContext."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1)

        # 1. Call with float dt
        res1 = eng.scan_step(0.010)
        assert res1.status == AgentStatus.SUCCESS
        assert eng.cycles_count == 1
        assert eng.time_since_last_heartbeat_ms == 10.0

        # 2. Call with ScanContext
        ctx = ScanContext(cycle=2, dt_ms=10.0)
        res2 = eng.scan_step(ctx)
        assert res2.status == AgentStatus.SUCCESS
        assert eng.cycles_count == 2
        assert eng.time_since_last_heartbeat_ms == 20.0

    def test_step_and_execute_methods(self) -> None:
        """Verify step and execute delegate to scan_step."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1)

        eng.step(0.010)
        assert eng.cycles_count == 1
        assert eng.time_since_last_heartbeat_ms == 10.0

        res = eng.execute()
        assert res.status == AgentStatus.SUCCESS
        assert eng.cycles_count == 2
        assert eng.time_since_last_heartbeat_ms == 20.0

    def test_reset_restores_nominal_state(self) -> None:
        """Verify reset restores all engine attributes to clean initial defaults."""
        eng = CipSafetyAplDaisyChainEngine(node_id=2, hop_count=2)
        eng.inject_upstream_loss()
        eng.scan_step(dt_ms=50.0)
        assert eng.fail_safe_active is True
        assert eng.cycles_count == 1

        eng.reset()
        assert eng.hop_count == 1
        assert eng.upstream_port_state == UpstreamPortState.UP
        assert eng.downstream_port_state == DownstreamPortState.UP
        assert eng.operational_state == DaisyOperationalState.OPERATIONAL
        assert eng.diagnostic_code == DIAG_OK
        assert eng.fail_safe_active is False
        assert eng.sequence_counter == 0
        assert eng.cycles_count == 0
        assert eng.time_since_last_heartbeat_ms == 0.0
        assert eng.is_healthy is True

    def test_100_cycle_continuous_scan_soak(self) -> None:
        """Verify 100 consecutive 10 ms scan cycles execute deterministically with 0 faults."""
        eng = CipSafetyAplDaisyChainEngine(node_id=1)

        for i in range(100):
            ctx = ScanContext(cycle=i + 1, dt_ms=10.0)
            res = eng.scan_step(ctx)
            # Simulate receipt of heartbeat on each cycle to refresh watchdog
            eng.feed_heartbeat()

            assert res.status == AgentStatus.SUCCESS
            assert eng.is_healthy is True
            assert eng.diagnostic_code == DIAG_OK

        assert eng.cycles_count == 100
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_DAISY_ACTIVE) is True
        assert eng.reg_table.read_bit(COIL_CIP_SAFETY_DAISY_FAULT) is False


# ============================================================================
# 14. TestNineStageVerificationRunner
# ============================================================================

class TestNineStageVerificationRunner:
    """Validate 9-stage verification runner execution, strict 4-state contract, and evidence emission."""

    def test_nine_stage_runner_execution_and_contract(self) -> None:
        """Verify run_cip_safety_apl_daisy_chain_verification returns status success and 9/9 stages pass."""
        evidence = run_cip_safety_apl_daisy_chain_verification(work_package="W292")

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert "PASSED 9/9 stages" in evidence["details"]
        assert evidence["stages_passed"] == 9
        assert evidence["total_stages"] == 9

        data = evidence["data"]
        assert data["work_package"] == "W292"
        assert data["gate"] == "G8"
        assert data["checks_passed"] == 9
        assert data["total_checks"] == 9

        stages = data["stages"]
        assert len(stages) == 9

        expected_stages = [
            (1, "init_and_topology"),
            (2, "dual_crc_validation"),
            (3, "upstream_link_loss"),
            (4, "downstream_link_loss"),
            (5, "hop_latency_accumulation"),
            (6, "fail_safe_deenergize"),
            (7, "heartbeat_watchdog_timeout"),
            (8, "horner_ocs_register_sync"),
            (9, "pure_st_pou_and_ladder_rejection"),
        ]

        for idx, (expected_num, expected_name) in enumerate(expected_stages):
            st = stages[idx]
            assert st["stage"] == expected_num
            assert st["name"] == expected_name
            assert st["passed"] is True
            assert st["timing_ms"] >= 0.0
            assert len(st["details"]) > 0

    def test_nine_stage_runner_json_evidence_emission(self) -> None:
        """Verify runner writes valid JSON evidence file to specified output_path."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "telemetry" / "cip_safety_apl_daisy_chain_evidence.json"
            evidence = run_cip_safety_apl_daisy_chain_verification(
                output_path=str(out_file),
                work_package="W292",
            )

            assert out_file.exists()
            with open(out_file, "r", encoding="utf-8") as f:
                saved_json = json.load(f)

            assert saved_json["status"] == "success"
            assert saved_json["stages_passed"] == 9
            assert saved_json["data"]["checks_passed"] == 9
            assert saved_json["data"]["work_package"] == "W292"
