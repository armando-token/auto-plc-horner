"""Comprehensive Unit Test Suite for Wave W283 CIP Safety Over Ethernet-APL Multi-Drop Trunk Protocol Engine.

Work Package: W283 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Ethernet-APL Multi-Drop Trunk (10BASE-T1S / 2-WISE Intrinsically Safe) for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 14 Mandatory Test Classes:
1. TestImportsConstantsAndDiagnosticCodes: Class IDs, nominal limits, Z0=100 Ohm, RT=100 Ohm,
   reflection threshold (0.15), PLCA timing defaults, CRC polynomials (0x5935, 0x755B inverted),
   diagnostic code signed/unsigned comparisons, bitwise ops, hashing, status bits, register mappings
   (%R2440..%R2447), coil mappings (%M569..%M570), and state machine enums.
2. TestAplMultidropNodeModel: AplMultidropNode model initialization, coordinator flag, spur cable
   impedance, reflection coefficient calculation, slot arbitration, and serialization.
3. TestAplMultidropTrunkStateModel: AplMultidropTrunkState model initialization, PLCA cycle timing property,
   line reflection calculation, health evaluation, node registry, and dictionary serialization.
4. TestPlcaBusTimingAndArbitration: PLCA round-robin transmit opportunity (TO) slot allocation, modulo cycle
   timing, coordinator beacon synchronization, allowed transmission, and collision blocking.
5. TestDualSafetyCrcAndFrameIntegrity: Dual safety checksums (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B inverted),
   deterministic calculation, payload mutation detection, sequence tampering, SNN mismatch, and pack/unpack.
6. TestImpedanceAndReflectionSurveillance: Characteristic impedance Z0=100 Ohm, termination resistance RT=100 Ohm,
   reflection coefficient Gamma = |ZL - Z0| / (ZL + Z0), nominal matched line, mild spur deviation (<=15%),
   high reflection alert (0xED02 REFLECTION_MISMATCH) tripping DEGRADED state, and recovery.
7. TestBusCollisionAndTrunkFaultDetection: Simulated bus collision (0xED01), trunk short circuit (0 Ohm),
   trunk partition (0xED05), transition to FAIL_SAFE, slot sync loss, deassertion of %M569, assertion of %M570,
   and recovery via reset.
8. TestSafetyWatchdogAndFailSafeTransitions: Safety communication watchdog surveillance (200 ms nominal),
   watchdog feed mechanism, silence expiration transition to FAIL_SAFE with zeroed safe outputs (SIL 3 safe state),
   foreign SNN rejection, corrupted CRC rejection, and valid frame processing.
9. TestHornerOcsRegisterSpaceSynchronization: Bit-exact synchronization to Horner OCS analog registers
   (%R2440..%R2447) and discrete coils (%M569..%M570), bit-packing, scaled reflection percentage,
   privilege modes (PrivilegeMode.SYSTEM), and safe write wrappers.
10. TestPureStructuredTextAndSecurity: Pure IEC 61131-3 Structured Text POU CipSafetyAplMultidropSync
    validation using STParser and SecurityGuard, bound registers (%R2440..%R2447, %M569..%M570).
11. TestAntiLadderConstructRejection: Strict rejection of ladder logic constructs (contacts, coils,
    rungs, networks, mnemonics) with LadderForbiddenError.
12. TestILogicUnitCompliance: ILogicUnit interface compliance (scan_step, step, execute, reset),
    metadata properties, cyclic scan counting, execution result contracts, and multi-cycle soak.
13. TestExceptionsAndVerificationRunner: Protocol exception hierarchy, 9-stage verification suite
    run_cip_safety_apl_multidrop_verification, strict 4-state contract validation, and JSON evidence emission.
14. TestComplexScenariosAndStateTransitions: End-to-end multi-state lifecycle transitions, multi-node
    arbitration clusters, rapid impedance fluctuation hysteresis, and simultaneous fault precedence.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_apl_multidrop import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_APL_MULTIDROP_CLASS_ID,
    CIP_SAFETY_MULTIDROP_CLASS_ID,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    DEFAULT_NODE_ID,
    DEFAULT_MAX_NODES,
    DEFAULT_PLCA_TO_TIMER_US,
    DEFAULT_PLCA_BEACON_TIMER_US,
    NOMINAL_TRUNK_IMPEDANCE_OHM,
    DEFAULT_LINE_IMPEDANCE_OHM,
    NOMINAL_BUS_TERMINATION_OHM,
    MAX_REFLECTION_COEFF_THRESHOLD,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DEFAULT_BASE_TIMEOUT_MS,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_POLY_1021,
    CRC_POLY_8408,
    CIP_SAFETY_CRC_INIT,
    CRC_STATUS_S1_OK,
    CRC_STATUS_S2_OK,
    CRC_STATUS_SLOT_SYNCED,
    CRC_STATUS_NOMINAL,
    REG_CIP_SAFETY_MULTIDROP_STATE,
    REG_CIP_SAFETY_MULTIDROP_PLCA_CONFIG,
    REG_CIP_SAFETY_MULTIDROP_PLCA_CYCLE_US,
    REG_CIP_SAFETY_MULTIDROP_REFLECTION_PCT,
    REG_CIP_SAFETY_MULTIDROP_LINE_IMPEDANCE_OHM,
    REG_CIP_SAFETY_MULTIDROP_SEQUENCE_COUNTER,
    REG_CIP_SAFETY_MULTIDROP_CRC_STATUS,
    REG_CIP_SAFETY_MULTIDROP_DIAGNOSTIC_CODE,
    REG_MULTIDROP_STATE,
    REG_MULTIDROP_PLCA_CONFIG,
    REG_MULTIDROP_PLCA_CYCLE,
    REG_MULTIDROP_REFLECTION,
    REG_MULTIDROP_LINE_IMPEDANCE,
    REG_MULTIDROP_SEQUENCE,
    REG_MULTIDROP_CRC_STATUS,
    REG_MULTIDROP_DIAGNOSTIC_CODE,
    COIL_CIP_SAFETY_MULTIDROP_ACTIVE,
    COIL_CIP_SAFETY_MULTIDROP_FAULT,
    COIL_MULTIDROP_TRUNK_ACTIVE,
    COIL_MULTIDROP_TRUNK_FAULT,
    COIL_MULTIDROP_BUS_COLLISION,
    CipSafetyAplMultidropState,
    AplMultidropState,
    CipSafetyAplMultidropDiagnosticCode,
    AplMultidropDiagnosticCode,
    DiagnosticCode,
    DIAG_OK,
    DIAG_BUS_COLLISION,
    DIAG_REFLECTION_MISMATCH,
    DIAG_CRC_S1_FAULT,
    DIAG_CRC_S2_FAULT,
    DIAG_TRUNK_PARTITION,
    DIAG_TERMINATION_FAULT,
    DIAG_PLCA_BEACON_LOSS,
    AplMultidropStatusBits,
    CipSafetyAplMultidropStatusBits,
    CipSafetyAplMultidropError,
    BusCollisionError,
    ReflectionMismatchError,
    TrunkPartitionError,
    PlcaConfig,
    AplMultidropNode,
    AplMultidropTrunkState,
    CipSafetyAplMultidropFrame,
    create_valid_frame,
    create_valid_packet,
    compute_crc16,
    compute_crc_s1,
    compute_crc_s2,
    compute_reflection_coefficient,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CipSafetyAplMultidropEngine,
    CIPSafetyAplMultidropEngine,
    CIPSafetyAPLMultidropEngine,
    ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC,
    CIP_SAFETY_APL_MULTIDROP_PURE_ST_POU,
    CIP_SAFETY_APL_MULTIDROP_SYNC_POU,
    CipSafetyAplMultidropSync,
    verify_cip_safety_apl_multidrop_pure_st,
    run_cip_safety_apl_multidrop_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnosticCodes
# ============================================================================

class TestConstantsEnumsAndDiagnosticCodes:
    """Verifies module constants, protocol class IDs, diagnostic codes, and bitmasks."""

    def test_imports_and_all_symbols(self) -> None:
        """Verify all public symbols are importable from jev_cscape.telemetry."""
        from jev_cscape.telemetry import (
            CipSafetyAplMultidropEngine as Eng,
            AplMultidropNode as Node,
            AplMultidropTrunkState as Trunk,
            AplMultidropStatusBits as Bits,
            CipSafetyAplMultidropState as State,
            CipSafetyAplMultidropDiagnosticCode as Diag,
        )
        assert Eng is CipSafetyAplMultidropEngine
        assert Node is AplMultidropNode
        assert Trunk is AplMultidropTrunkState
        assert Bits is AplMultidropStatusBits
        assert State is CipSafetyAplMultidropState
        assert Diag is CipSafetyAplMultidropDiagnosticCode

    def test_cip_safety_class_ids(self) -> None:
        """Verify ODVA CIP Safety Object Class IDs."""
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_APL_MULTIDROP_CLASS_ID == 0x3E
        assert CIP_SAFETY_MULTIDROP_CLASS_ID == 0x3E

    def test_physical_and_timing_constants(self) -> None:
        """Verify physical trunk parameters and PLCA defaults."""
        assert NOMINAL_TRUNK_IMPEDANCE_OHM == 100.0
        assert DEFAULT_LINE_IMPEDANCE_OHM == 100.0
        assert NOMINAL_BUS_TERMINATION_OHM == 100.0
        assert MAX_REFLECTION_COEFF_THRESHOLD == 0.15
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 200.0
        assert DEFAULT_BASE_TIMEOUT_MS == 200.0
        assert DEFAULT_NODE_ID == 1
        assert DEFAULT_MAX_NODES == 8
        assert DEFAULT_PLCA_TO_TIMER_US == 32
        assert DEFAULT_PLCA_BEACON_TIMER_US == 20
        assert DEFAULT_SAFETY_NETWORK_NUMBER == 0x00012345
        assert DEFAULT_SNN == 0x00012345

    def test_crc_constants_and_seeds(self) -> None:
        """Verify ODVA CIP Safety dual CRC polynomials and initial seeds."""
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_POLY_1021 == 0x1021
        assert CRC_POLY_8408 == 0x8408
        assert CIP_SAFETY_CRC_INIT == 0xFFFF

    def test_diagnostic_code_enum_values(self) -> None:
        """Verify diagnostic code integer values matching specification."""
        assert int(CipSafetyAplMultidropDiagnosticCode.OK) == 0x0000
        assert int(CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION) == 0xED01
        assert int(CipSafetyAplMultidropDiagnosticCode.REFLECTION_MISMATCH) == 0xED02
        assert int(CipSafetyAplMultidropDiagnosticCode.CRC_S1_FAULT) == 0xED03
        assert int(CipSafetyAplMultidropDiagnosticCode.CRC_S2_FAULT) == 0xED04
        assert int(CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION) == 0xED05
        assert int(CipSafetyAplMultidropDiagnosticCode.TERMINATION_FAULT) == 0xED06
        assert int(CipSafetyAplMultidropDiagnosticCode.PLCA_BEACON_LOSS) == 0xED07

    def test_diagnostic_code_signed_unsigned_and_bitwise(self) -> None:
        """Verify signed/unsigned 16-bit comparisons and bitwise operators for diagnostic codes."""
        diag = CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION
        assert diag == 0xED01
        # Signed 16-bit representation: 0xED01 - 0x10000 = -4863
        assert diag == -4863
        assert (diag & 0xFF00) == 0xED00
        assert (diag | 0x00FE) == 0xEDFF
        assert (0xED01 & diag) == 0xED01
        assert (0x0000 | diag) == 0xED01
        assert hash(diag) == hash(0xED01)
        assert "0xED01" in str(diag)
        assert repr(diag).startswith("CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION")
        assert diag != 0x0000
        assert diag != "INVALID"

    def test_status_bits_enum(self) -> None:
        """Verify CRC and PLCA slot status bits bitmask constants."""
        assert CRC_STATUS_S1_OK == 0x0001
        assert CRC_STATUS_S2_OK == 0x0002
        assert CRC_STATUS_SLOT_SYNCED == 0x0004
        assert CRC_STATUS_NOMINAL == 0x0007

        assert int(AplMultidropStatusBits.S1_OK) == 0x0001
        assert int(AplMultidropStatusBits.S2_OK) == 0x0002
        assert int(AplMultidropStatusBits.SLOT_SYNCED) == 0x0004
        assert int(AplMultidropStatusBits.NOMINAL) == 0x0007
        assert CipSafetyAplMultidropStatusBits is AplMultidropStatusBits

    def test_register_and_coil_address_constants(self) -> None:
        """Verify Horner OCS register space addresses %R2440..%R2447 and %M569..%M570."""
        assert REG_CIP_SAFETY_MULTIDROP_STATE == "%R2440"
        assert REG_CIP_SAFETY_MULTIDROP_PLCA_CONFIG == "%R2441"
        assert REG_CIP_SAFETY_MULTIDROP_PLCA_CYCLE_US == "%R2442"
        assert REG_CIP_SAFETY_MULTIDROP_REFLECTION_PCT == "%R2443"
        assert REG_CIP_SAFETY_MULTIDROP_LINE_IMPEDANCE_OHM == "%R2444"
        assert REG_CIP_SAFETY_MULTIDROP_SEQUENCE_COUNTER == "%R2445"
        assert REG_CIP_SAFETY_MULTIDROP_CRC_STATUS == "%R2446"
        assert REG_CIP_SAFETY_MULTIDROP_DIAGNOSTIC_CODE == "%R2447"

        assert REG_MULTIDROP_STATE == "%R2440"
        assert REG_MULTIDROP_PLCA_CONFIG == "%R2441"
        assert REG_MULTIDROP_PLCA_CYCLE == "%R2442"
        assert REG_MULTIDROP_REFLECTION == "%R2443"
        assert REG_MULTIDROP_LINE_IMPEDANCE == "%R2444"
        assert REG_MULTIDROP_SEQUENCE == "%R2445"
        assert REG_MULTIDROP_CRC_STATUS == "%R2446"
        assert REG_MULTIDROP_DIAGNOSTIC_CODE == "%R2447"

        assert COIL_CIP_SAFETY_MULTIDROP_ACTIVE == "%M569"
        assert COIL_CIP_SAFETY_MULTIDROP_FAULT == "%M570"
        assert COIL_MULTIDROP_TRUNK_ACTIVE == "%M569"
        assert COIL_MULTIDROP_TRUNK_FAULT == "%M570"
        assert COIL_MULTIDROP_BUS_COLLISION == "%M570"

    def test_state_enum_values_and_aliases(self) -> None:
        """Verify state machine enum codes and backward-compatibility aliases."""
        assert CipSafetyAplMultidropState.INIT == 0
        assert CipSafetyAplMultidropState.OPERATIONAL == 1
        assert CipSafetyAplMultidropState.DEGRADED == 2
        assert CipSafetyAplMultidropState.FAIL_SAFE == 3

        assert CipSafetyAplMultidropState.SafeInit == 0
        assert CipSafetyAplMultidropState.SafeOperational == 1
        assert CipSafetyAplMultidropState.SafeDegraded == 2
        assert CipSafetyAplMultidropState.SafeFailSafe == 3
        assert CipSafetyAplMultidropState.TRIPPED == 3

        assert AplMultidropState is CipSafetyAplMultidropState
        assert AplMultidropDiagnosticCode is CipSafetyAplMultidropDiagnosticCode
        assert DiagnosticCode is CipSafetyAplMultidropDiagnosticCode


# ============================================================================
# 2. TestAplMultidropNodeModel
# ============================================================================

class TestAplMultidropNodeModel:
    """Verifies AplMultidropNode model behavior and PLCA slot checks."""

    def test_node_default_initialization(self) -> None:
        """Verify default attributes for a standard worker node."""
        node = AplMultidropNode()
        assert node.node_id == DEFAULT_NODE_ID
        assert node.plca_slot == DEFAULT_NODE_ID
        assert node.is_coordinator is False
        assert node.spur_impedance_ohm == 100.0
        assert node.reflection_coefficient == 0.0
        assert node.is_active is True
        assert node.tx_sequence == 0
        assert node.rx_sequence == 0
        assert node.safe_payload == b"\x00\x00\x00\x00"

    def test_node_coordinator_initialization(self) -> None:
        """Verify attributes for PLCA Coordinator node (Node 0)."""
        coord = AplMultidropNode(node_id=0, plca_slot=0, is_coordinator=True)
        assert coord.node_id == 0
        assert coord.plca_slot == 0
        assert coord.is_coordinator is True
        assert coord.can_transmit_in_slot(0) is True
        assert coord.can_transmit_in_slot(1) is False

    def test_node_reflection_calculation(self) -> None:
        """Verify reflection calculation on spur cable."""
        node = AplMultidropNode(spur_impedance_ohm=100.0)
        assert node.calculate_reflection(100.0) == 0.0

        node.spur_impedance_ohm = 80.0
        # Gamma = |80 - 100| / (80 + 100) = 20 / 180 = 0.1111...
        refl = node.calculate_reflection(100.0)
        assert pytest.approx(refl, rel=1e-3) == 0.1111

        node.spur_impedance_ohm = 50.0
        # Gamma = |50 - 100| / (50 + 100) = 50 / 150 = 0.3333...
        assert pytest.approx(node.calculate_reflection(100.0), rel=1e-3) == 0.3333

        node.spur_impedance_ohm = 0.0
        assert node.calculate_reflection(100.0) == 1.0

    def test_node_plca_slot_arbitration(self) -> None:
        """Verify round-robin slot arbitration check on node."""
        node = AplMultidropNode(node_id=3)
        assert node.can_transmit_in_slot(3, max_nodes=8) is True
        assert node.can_transmit_in_slot(11, max_nodes=8) is True  # 11 % 8 == 3
        assert node.can_transmit_in_slot(2, max_nodes=8) is False
        assert node.can_transmit_in_slot(0, max_nodes=8) is False

    def test_node_to_dict_serialization(self) -> None:
        """Verify node dictionary serialization format."""
        node = AplMultidropNode(
            node_id=2,
            plca_slot=2,
            spur_impedance_ohm=90.0,
            last_seen_ms=12345.0,
            tx_sequence=42,
            rx_sequence=41,
        )
        d = node.to_dict()
        assert d["node_id"] == 2
        assert d["plca_slot"] == 2
        assert d["is_coordinator"] is False
        assert d["spur_impedance_ohm"] == 90.0
        assert d["last_seen_ms"] == 12345.0
        assert d["tx_sequence"] == 42
        assert d["rx_sequence"] == 41


# ============================================================================
# 3. TestAplMultidropTrunkStateModel
# ============================================================================

class TestAplMultidropTrunkStateModel:
    """Verifies AplMultidropTrunkState model behavior and health evaluation."""

    def test_trunk_state_defaults(self) -> None:
        """Verify default trunk state parameters."""
        trunk = AplMultidropTrunkState()
        assert trunk.state == CipSafetyAplMultidropState.OPERATIONAL
        assert trunk.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.OK
        assert trunk.z0_ohm == 100.0
        assert trunk.rt_ohm == 100.0
        assert trunk.line_impedance_ohm == 100.0
        assert trunk.reflection_coefficient == 0.0
        assert trunk.reflection_threshold == 0.15
        assert trunk.max_nodes == 8
        assert trunk.to_timer_us == 32
        assert trunk.beacon_timer_us == 20
        assert trunk.coil_trunk_active is True
        assert trunk.coil_trunk_fault is False
        assert len(trunk.nodes) == 0

    def test_trunk_state_cycle_time_property(self) -> None:
        """Verify PLCA cycle time calculation property."""
        trunk = AplMultidropTrunkState(max_nodes=8, to_timer_us=32, beacon_timer_us=20)
        assert trunk.plca_cycle_time_us == (8 * 32 + 20)  # 276 us

        trunk_custom = AplMultidropTrunkState(max_nodes=16, to_timer_us=50, beacon_timer_us=30)
        assert trunk_custom.plca_cycle_time_us == (16 * 50 + 30)  # 830 us

    def test_trunk_state_reflection_calculation(self) -> None:
        """Verify line reflection calculation and storage."""
        trunk = AplMultidropTrunkState(z0_ohm=100.0)
        assert trunk.calculate_reflection(100.0) == 0.0

        # ZL = 65 Ohm -> Gamma = |65 - 100| / (65 + 100) = 35 / 165 = 0.2121
        refl = trunk.calculate_reflection(65.0)
        assert pytest.approx(refl, rel=1e-3) == 0.2121
        assert trunk.reflection_coefficient == refl

        # Open circuit (ZL = 1000 Ohm)
        refl_open = trunk.calculate_reflection(1000.0)
        assert refl_open > 0.80

    def test_trunk_state_evaluate_health(self) -> None:
        """Verify evaluate_health logic across states and diagnostic codes."""
        trunk = AplMultidropTrunkState()
        assert trunk.evaluate_health() is True

        # DEGRADED with REFLECTION_MISMATCH remains healthy for safety communication
        trunk.state = CipSafetyAplMultidropState.DEGRADED
        trunk.diagnostic_code = CipSafetyAplMultidropDiagnosticCode.REFLECTION_MISMATCH
        assert trunk.evaluate_health() is True

        # FAIL_SAFE trips health
        trunk.state = CipSafetyAplMultidropState.FAIL_SAFE
        assert trunk.evaluate_health() is False

        # Collision trips health
        trunk.state = CipSafetyAplMultidropState.OPERATIONAL
        trunk.diagnostic_code = CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION
        assert trunk.evaluate_health() is False

    def test_trunk_state_register_and_get_node(self) -> None:
        """Verify node registration and retrieval in trunk state."""
        trunk = AplMultidropTrunkState()
        n0 = AplMultidropNode(node_id=0, is_coordinator=True)
        n1 = AplMultidropNode(node_id=1)
        n2 = AplMultidropNode(node_id=2)

        trunk.register_node(n0)
        trunk.register_node(n1)
        trunk.register_node(n2)

        assert len(trunk.nodes) == 3
        assert trunk.get_node(0) is n0
        assert trunk.get_node(1) is n1
        assert trunk.get_node(2) is n2
        assert trunk.get_node(99) is None

    def test_trunk_state_to_dict_serialization(self) -> None:
        """Verify dictionary serialization of trunk state."""
        trunk = AplMultidropTrunkState()
        trunk.register_node(AplMultidropNode(node_id=1))
        d = trunk.to_dict()
        assert d["state"] == 1
        assert d["state_name"] == "OPERATIONAL"
        assert d["diagnostic_code"] == "0x0000"
        assert d["z0_ohm"] == 100.0
        assert d["rt_ohm"] == 100.0
        assert d["plca_cycle_time_us"] == 276
        assert d["coil_trunk_active"] is True
        assert d["coil_trunk_fault"] is False
        assert d["nodes_count"] == 1


# ============================================================================
# 4. TestPlcaBusTimingAndArbitration
# ============================================================================

class TestPlcaBusTimingAndArbitration:
    """Verifies IEEE 802.3cg Clause 148 PLCA timing, slot allocation, and collision avoidance."""

    def test_plca_config_defaults(self) -> None:
        """Verify PlcaConfig default parameters."""
        cfg = PlcaConfig()
        assert cfg.node_id == 1
        assert cfg.max_nodes == 8
        assert cfg.to_timer_us == 32
        assert cfg.beacon_timer_us == 20
        assert cfg.is_coordinator is False
        assert cfg.cycle_time_us == (8 * 32 + 20)

    def test_plca_config_custom_cluster(self) -> None:
        """Verify PlcaConfig with custom cluster parameters."""
        cfg = PlcaConfig(
            node_id=5,
            max_nodes=16,
            to_timer_us=40,
            beacon_timer_us=24,
            is_coordinator=False,
        )
        assert cfg.node_id == 5
        assert cfg.max_nodes == 16
        assert cfg.cycle_time_us == (16 * 40 + 24)  # 664 us

    def test_plca_slot_arbitration_round_robin(self) -> None:
        """Verify round-robin slot arbitration for local node."""
        eng = CipSafetyAplMultidropEngine()
        eng.configure_plca(node_id=2, max_nodes=8)

        # Slot 2 is assigned
        assert eng.can_transmit_in_slot(2) is True
        # Slot 10 is next cycle (10 % 8 == 2)
        assert eng.can_transmit_in_slot(10) is True
        # Slot 18 is subsequent cycle (18 % 8 == 2)
        assert eng.can_transmit_in_slot(18) is True

        # Other slots are strictly forbidden
        assert eng.can_transmit_in_slot(0) is False
        assert eng.can_transmit_in_slot(1) is False
        assert eng.can_transmit_in_slot(3) is False
        assert eng.can_transmit_in_slot(7) is False

    def test_plca_transmit_in_assigned_slot(self) -> None:
        """Verify transmitting in assigned slot increments sequence and updates slot."""
        eng = CipSafetyAplMultidropEngine()
        eng.configure_plca(node_id=1, max_nodes=8)

        frame = eng.transmit_frame(payload_bytes=b"\x12\x34\x56\x78", slot=1)
        assert frame.is_valid()
        assert frame.plca_slot == 1
        assert eng.tx_sequence == 1
        assert eng.frames_transmitted == 1

        frame2 = eng.transmit_frame(payload_bytes=b"\x99\x88\x77\x66", slot=1)
        assert frame2.sequence_number == 2
        assert eng.tx_sequence == 2
        assert eng.frames_transmitted == 2

    def test_plca_transmit_out_of_slot_collision(self) -> None:
        """Verify transmitting out of slot raises BusCollisionError."""
        eng = CipSafetyAplMultidropEngine()
        eng.configure_plca(node_id=1, max_nodes=8)

        with pytest.raises(BusCollisionError) as exc_info:
            eng.transmit_frame(payload_bytes=b"\xAA\xBB\xCC\xDD", slot=3)
        assert "PLCA collision avoidance" in str(exc_info.value)
        assert "slot 3" in str(exc_info.value)

    def test_plca_reconfiguration(self) -> None:
        """Verify configure_plca updates parameters and synchronizes to registers."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        eng.configure_plca(node_id=4, max_nodes=12, to_timer_us=25, is_coordinator=False)
        assert eng.local_node_id == 4
        assert eng.max_nodes == 12
        assert eng.plca_cycle_time_us == (12 * 25 + 20)  # 320 us

        # %R2441: upper byte max_nodes (12), lower byte plca_slot (4) -> (12 << 8) | 4 = 3076
        assert rt.read_uword("%R2441") == 3076
        # %R2442: 320 us
        assert rt.read_uword("%R2442") == 320


# ============================================================================
# 5. TestDualSafetyCrcAndFrameIntegrity
# ============================================================================

class TestDualSafetyCrcAndFrameIntegrity:
    """Verifies CRC-S1, CRC-S2, bit-tampering detection, and packet serialization."""

    def test_crc_s1_determinism_and_polynomial(self) -> None:
        """Verify CRC-S1 calculation determinism and polynomial (0x5935)."""
        payload1 = b"\x01\x02\x03\x04"
        payload2 = b"\x05\x06\x07\x08"

        c1 = compute_crc_s1(payload1)
        c2 = compute_crc_s1(payload1)
        assert c1 == c2
        assert 0 <= c1 <= 0xFFFF

        c3 = compute_crc_s1(payload2)
        assert c1 != c3

    def test_crc_s2_determinism_and_inversion(self) -> None:
        """Verify CRC-S2 calculation incorporates SNN, sequence, timestamp, and inverted data."""
        snn = 0x00012345
        seq = 10
        ts = 5000
        crc_s1 = 0xABCD

        c1 = compute_crc_s2(snn, seq, ts, crc_s1)
        c2 = compute_crc_s2(snn, seq, ts, crc_s1)
        assert c1 == c2
        assert 0 <= c1 <= 0xFFFF

        # Changing sequence changes CRC-S2
        c3 = compute_crc_s2(snn, seq + 1, ts, crc_s1)
        assert c1 != c3

    def test_crc_s1_and_crc_s2_distinct(self) -> None:
        """Verify CRC-S1 and CRC-S2 yield distinct polynomials and values."""
        payload = b"\x11\x22\x33\x44"
        crc1 = compute_crc_s1(payload)
        crc2 = compute_crc_s2(DEFAULT_SAFETY_NETWORK_NUMBER, 1, 1000, crc1)
        assert crc1 != crc2
        assert crc1 != 0
        assert crc2 != 0

    def test_create_valid_frame_checksums(self) -> None:
        """Verify factory function calculates valid CRC-S1 and CRC-S2 checksums."""
        frame = create_valid_frame(
            safety_network_number=0x00012345,
            node_id=1,
            plca_slot=1,
            sequence_number=100,
            timestamp_ms=2500,
            payload_bytes=b"\xCA\xFE\xBA\xBE",
        )
        assert frame.verify_crc_s1() is True
        assert frame.verify_crc_s2() is True
        assert frame.is_valid() is True
        v1, v2 = frame.verify_crcs()
        assert v1 is True and v2 is True

    def test_frame_single_bit_tamper_payload(self) -> None:
        """Verify single-bit mutation in payload is caught by CRC-S1."""
        frame = create_valid_frame(payload_bytes=b"\x01\x02\x03\x04")
        assert frame.is_valid() is True

        # Mutate 1 bit in byte 0
        frame.mutate_payload(byte_offset=0, bit_pos=2)
        assert frame.verify_crc_s1() is False
        assert frame.is_valid() is False
        # CRC-S2 should still match header values (header wasn't mutated)
        assert frame.verify_crc_s2() is True

    def test_frame_tamper_sequence_number(self) -> None:
        """Verify sequence number mutation is caught by CRC-S2."""
        frame = create_valid_frame(sequence_number=10)
        assert frame.is_valid() is True

        frame.sequence_number = 11
        assert frame.verify_crc_s1() is True  # Payload intact
        assert frame.verify_crc_s2() is False  # Header sequence mutated
        assert frame.is_valid() is False

    def test_frame_tamper_snn(self) -> None:
        """Verify safety network number mutation is caught by CRC-S2."""
        frame = create_valid_frame(safety_network_number=0x11223344)
        assert frame.is_valid() is True

        frame.safety_network_number = 0x99887766
        assert frame.verify_crc_s2() is False
        assert frame.is_valid() is False

    def test_frame_tamper_timestamp(self) -> None:
        """Verify timestamp mutation is caught by CRC-S2."""
        frame = create_valid_frame(timestamp_ms=1000)
        assert frame.is_valid() is True

        frame.timestamp_ms = 9999
        assert frame.verify_crc_s2() is False
        assert frame.is_valid() is False

    def test_frame_pack_and_unpack_roundtrip(self) -> None:
        """Verify binary wire serialization roundtrip."""
        original = create_valid_frame(
            safety_network_number=0x12345678,
            node_id=2,
            plca_slot=2,
            sequence_number=42,
            timestamp_ms=987654,
            payload_bytes=b"\xDE\xAD\xBE\xEF\x00\x01",
        )
        wire_bytes = original.pack()
        assert len(wire_bytes) == (14 + len(original.payload_bytes) + 4)

        restored = CipSafetyAplMultidropFrame.unpack(wire_bytes)
        assert restored.safety_network_number == original.safety_network_number
        assert restored.node_id == original.node_id
        assert restored.plca_slot == original.plca_slot
        assert restored.sequence_number == original.sequence_number
        assert restored.timestamp_ms == original.timestamp_ms
        assert restored.payload_bytes == original.payload_bytes
        assert restored.crc_s1 == original.crc_s1
        assert restored.crc_s2 == original.crc_s2
        assert restored.is_valid() is True

    def test_frame_unpack_invalid_bytes(self) -> None:
        """Verify unpacking truncated frames raises ValueError."""
        with pytest.raises(ValueError) as exc:
            CipSafetyAplMultidropFrame.unpack(b"\x00" * 10)
        assert "Packet too short" in str(exc.value)

        # Truncated payload
        header = struct.pack(">IBBHIH", 0x1234, 1, 1, 1, 1000, 10)  # says payload is 10 bytes
        with pytest.raises(ValueError) as exc2:
            CipSafetyAplMultidropFrame.unpack(header + b"\x00" * 5)
        assert "Incomplete frame data" in str(exc2.value)


# ============================================================================
# 6. TestImpedanceAndReflectionSurveillance
# ============================================================================

class TestImpedanceAndReflectionSurveillance:
    """Verifies line impedance surveillance, reflection coefficient calculation, and alerts."""

    def test_reflection_coefficient_formula(self) -> None:
        """Verify mathematical formula Gamma = |ZL - Z0| / (ZL + Z0)."""
        # Exactly matched
        assert compute_reflection_coefficient(100.0, 100.0) == 0.0

        # ZL = 120, Z0 = 100 -> |20| / 220 = 0.090909...
        assert pytest.approx(compute_reflection_coefficient(120.0, 100.0), rel=1e-3) == 0.0909

        # ZL = 80, Z0 = 100 -> |-20| / 180 = 0.111111...
        assert pytest.approx(compute_reflection_coefficient(80.0, 100.0), rel=1e-3) == 0.1111

    def test_reflection_exact_match(self) -> None:
        """Verify zero reflection under nominal 100 Ohm matched impedance."""
        eng = CipSafetyAplMultidropEngine(line_impedance_ohm=100.0)
        assert eng.reflection_coefficient == 0.0
        assert eng.state == CipSafetyAplMultidropState.OPERATIONAL
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.OK

    def test_reflection_boundary_cases(self) -> None:
        """Verify short circuit (0 Ohm) and near-open circuit reflections."""
        assert compute_reflection_coefficient(0.0, 100.0) == 1.0
        assert compute_reflection_coefficient(0.0, 0.0) == 1.0
        assert compute_reflection_coefficient(10000.0, 100.0) > 0.98

    def test_mild_impedance_deviation_within_threshold(self) -> None:
        """Verify impedance deviation within 15% threshold keeps OPERATIONAL state."""
        eng = CipSafetyAplMultidropEngine()
        # ZL = 88 Ohm -> Gamma = |88 - 100| / 188 = 12 / 188 = 0.0638 <= 0.15
        refl = eng.update_bus_impedance(88.0)
        assert refl <= 0.15
        assert eng.state == CipSafetyAplMultidropState.OPERATIONAL
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.OK
        assert eng.is_healthy is True

    def test_high_reflection_alert_0xED02(self) -> None:
        """Verify reflection exceeding 15% trips DEGRADED state with REFLECTION_MISMATCH (0xED02)."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        # ZL = 60 Ohm -> Gamma = |60 - 100| / 160 = 40 / 160 = 0.25 > 0.15
        refl = eng.update_bus_impedance(60.0)
        assert refl > 0.15
        assert eng.state == CipSafetyAplMultidropState.DEGRADED
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.REFLECTION_MISMATCH
        assert eng.is_healthy is True  # Degraded link maintained for safety communication

        # Register sync verification
        # %R2440: ((1 << 8) | 2) = 258 (Node 1, DEGRADED)
        assert rt.read_uword("%R2440") == 258
        # %R2443: scaled 0.25 -> 250
        assert rt.read_uword("%R2443") == 250
        # %R2444: 60 Ohm
        assert rt.read_uword("%R2444") == 60
        # %R2447: 0xED02
        assert rt.read_uword("%R2447") == 0xED02
        # %M569 remains True (link active), %M570 asserted (alarm active)
        assert rt.read_bit("%M569") is True
        assert rt.read_bit("%M570") is True

    def test_high_reflection_recovery_to_operational(self) -> None:
        """Verify restoring matched impedance clears DEGRADED state back to OPERATIONAL."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        eng.update_bus_impedance(55.0)
        assert eng.state == CipSafetyAplMultidropState.DEGRADED

        # Restoring nominal line
        eng.update_bus_impedance(100.0)
        assert eng.state == CipSafetyAplMultidropState.OPERATIONAL
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.OK
        assert rt.read_uword("%R2440") == 257
        assert rt.read_uword("%R2447") == 0x0000
        assert rt.read_bit("%M569") is True
        assert rt.read_bit("%M570") is False

    def test_severe_open_circuit_reflection(self) -> None:
        """Verify open circuit spur (ZL=1000 Ohm) causes high reflection."""
        eng = CipSafetyAplMultidropEngine()
        refl = eng.update_bus_impedance(1000.0)
        assert refl > 0.80
        assert eng.state == CipSafetyAplMultidropState.DEGRADED
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.REFLECTION_MISMATCH


# ============================================================================
# 7. TestBusCollisionAndTrunkFaultDetection
# ============================================================================

class TestBusCollisionAndTrunkFaultDetection:
    """Verifies bus collision, short circuit, and %M570 discrete fault coil assertion."""

    def test_bus_collision_simulation(self) -> None:
        """Verify simulated collision trips FAIL_SAFE state with 0xED01 and clears slot sync."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)
        eng.safe_outputs = b"\x11\x22\x33\x44"

        eng.simulate_collision()
        assert eng.state == CipSafetyAplMultidropState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION
        assert eng.is_fail_safe is True
        assert (eng.crc_status & CRC_STATUS_SLOT_SYNCED) == 0
        assert eng.safe_outputs == b"\x00\x00\x00\x00"  # De-energized safe outputs

    def test_bus_collision_coil_assertion(self) -> None:
        """Verify %M569 deasserted and %M570 asserted in RegisterTable upon collision."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)
        eng.simulate_collision()

        assert rt.read_bit("%M569") is False
        assert rt.read_bit("%M570") is True
        assert rt.read_uword("%R2447") == 0xED01

    def test_trunk_short_circuit(self) -> None:
        """Verify trunk short circuit (0 Ohm) sets Gamma=1.0 and trips FAIL_SAFE."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        eng.simulate_trunk_short()
        assert eng.line_impedance_ohm == 0.0
        assert eng.reflection_coefficient == 1.0
        assert eng.state == CipSafetyAplMultidropState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION
        assert rt.read_bit("%M569") is False
        assert rt.read_bit("%M570") is True
        assert rt.read_uword("%R2444") == 0

    def test_trunk_partition_simulation(self) -> None:
        """Verify simulated trunk partition trips FAIL_SAFE with 0xED05."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        eng.simulate_trunk_partition()
        assert eng.state == CipSafetyAplMultidropState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION
        assert eng.crc_status == 0x0000
        assert rt.read_bit("%M569") is False
        assert rt.read_bit("%M570") is True
        assert rt.read_uword("%R2447") == 0xED05

    def test_reset_clears_fault_coils(self) -> None:
        """Verify calling reset() restores OPERATIONAL state and clears %M570."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        eng.simulate_collision()
        assert rt.read_bit("%M570") is True

        eng.reset()
        assert eng.state == CipSafetyAplMultidropState.OPERATIONAL
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.OK
        assert eng.is_healthy is True
        assert rt.read_bit("%M569") is True
        assert rt.read_bit("%M570") is False
        assert rt.read_uword("%R2447") == 0x0000


# ============================================================================
# 8. TestSafetyWatchdogAndFailSafeTransitions
# ============================================================================

class TestSafetyWatchdogAndFailSafeTransitions:
    """Verifies watchdog surveillance, silence expiration, and safe de-energization."""

    def test_watchdog_nominal_feeding(self) -> None:
        """Verify feeding watchdog keeps engine healthy across scan cycles."""
        eng = CipSafetyAplMultidropEngine(watchdog_timeout_ms=200.0)
        for _ in range(50):
            eng.feed_watchdog()
            eng.scan_step(0.010)  # 10 ms per scan step
            assert eng.is_healthy is True
            assert eng.state == CipSafetyAplMultidropState.OPERATIONAL

    def test_watchdog_timeout_transition(self) -> None:
        """Verify watchdog silence exceeding timeout transitions to FAIL_SAFE with TRUNK_PARTITION."""
        eng = CipSafetyAplMultidropEngine(watchdog_timeout_ms=150.0)
        assert eng.state == CipSafetyAplMultidropState.OPERATIONAL

        # Advance 200 ms without feeding (200 ms >= 150 ms timeout)
        eng.scan_step(0.200)
        assert eng.state == CipSafetyAplMultidropState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION
        assert eng.is_healthy is False

    def test_watchdog_safe_outputs_zeroed(self) -> None:
        """Verify safe outputs are zeroed upon watchdog timeout (SIL 3 safe state)."""
        eng = CipSafetyAplMultidropEngine(watchdog_timeout_ms=100.0)
        eng.safe_outputs = b"\xFF\xAA\x55\xCC"

        eng.scan_step(0.120)  # 120 ms > 100 ms
        assert eng.safe_outputs == b"\x00\x00\x00\x00"

    def test_foreign_snn_frame_triggers_fail_safe(self) -> None:
        """Verify frame received from foreign Safety Network Number is rejected into FAIL_SAFE."""
        eng = CipSafetyAplMultidropEngine(safety_network_number=0x00012345)
        foreign = create_valid_frame(safety_network_number=0x99998888)

        result = eng.process_frame(foreign)
        assert result is False
        assert eng.state == CipSafetyAplMultidropState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.TRUNK_PARTITION
        assert eng.safe_outputs == b"\x00\x00\x00\x00"

    def test_corrupted_crc_s1_triggers_fail_safe(self) -> None:
        """Verify frame with corrupted payload CRC-S1 triggers FAIL_SAFE with 0xED03."""
        eng = CipSafetyAplMultidropEngine()
        frame = create_valid_frame()
        frame.mutate_payload(byte_offset=0, bit_pos=1)

        result = eng.process_frame(frame)
        assert result is False
        assert eng.state == CipSafetyAplMultidropState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.CRC_S1_FAULT
        assert (eng.crc_status & CRC_STATUS_S1_OK) == 0

    def test_corrupted_crc_s2_triggers_fail_safe(self) -> None:
        """Verify frame with corrupted sequence header CRC-S2 triggers FAIL_SAFE with 0xED04."""
        eng = CipSafetyAplMultidropEngine()
        frame = create_valid_frame(sequence_number=50)
        frame.sequence_number = 51  # mutated sequence

        result = eng.process_frame(frame)
        assert result is False
        assert eng.state == CipSafetyAplMultidropState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.CRC_S2_FAULT
        assert (eng.crc_status & CRC_STATUS_S2_OK) == 0

    def test_valid_frame_feeds_watchdog_and_updates_rx(self) -> None:
        """Verify valid incoming frame processes cleanly and resets watchdog timer."""
        eng = CipSafetyAplMultidropEngine()
        eng.watchdog_timer_ms = 180.0

        valid = create_valid_frame(
            safety_network_number=eng.safety_network_number,
            node_id=2,
            plca_slot=2,
            sequence_number=500,
            payload_bytes=b"\x01\x02\x03\x04",
        )
        assert eng.process_frame(valid) is True
        assert eng.watchdog_timer_ms == 0.0
        assert eng.rx_sequence == 500
        assert eng.current_plca_slot == 2
        assert eng.safe_inputs == b"\x01\x02\x03\x04"
        assert eng.crc_status == CRC_STATUS_NOMINAL
        assert eng.frames_processed == 1


# ============================================================================
# 9. TestHornerOcsRegisterSpaceSynchronization
# ============================================================================

class TestHornerOcsRegisterSpaceSynchronization:
    """Verifies bit-exact synchronization across %R2440..%R2447 and %M569..%M570."""

    def test_register_table_nominal_sync(self) -> None:
        """Verify nominal register table values match specification."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt, auto_activate=True)

        # %R2440: (node_id 1 << 8) | state 1 = 257
        assert rt.read_uword("%R2440") == 257
        # %R2441: (max_nodes 8 << 8) | slot 1 = 2049
        assert rt.read_uword("%R2441") == 2049
        # %R2442: cycle time 276 us
        assert rt.read_uword("%R2442") == 276
        # %R2443: reflection 0
        assert rt.read_uword("%R2443") == 0
        # %R2444: line impedance 100 Ohm
        assert rt.read_uword("%R2444") == 100
        # %R2445: TX sequence 0
        assert rt.read_uword("%R2445") == 0
        # %R2446: CRC status nominal 0x0007
        assert rt.read_uword("%R2446") == 7
        # %R2447: Diagnostic OK 0x0000
        assert rt.read_uword("%R2447") == 0
        # %M569: Trunk Active (True)
        assert rt.read_bit("%M569") is True
        # %M570: Trunk Fault (False)
        assert rt.read_bit("%M570") is False

    def test_r2440_packing_node_id_and_state(self) -> None:
        """Verify %R2440 packs upper byte node_id and lower byte state code."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        eng.configure_plca(node_id=5, max_nodes=8)
        # Node 5, State 1 -> (5 << 8) | 1 = 1281
        assert rt.read_uword("%R2440") == 1281

        eng.simulate_collision()
        # Node 5, State 3 (FAIL_SAFE) -> (5 << 8) | 3 = 1283
        assert rt.read_uword("%R2440") == 1283

    def test_r2441_packing_max_nodes_and_slot(self) -> None:
        """Verify %R2441 packs upper byte max_nodes and lower byte current slot."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        eng.configure_plca(node_id=2, max_nodes=16)
        # Max nodes 16, slot 2 -> (16 << 8) | 2 = 4098
        assert rt.read_uword("%R2441") == 4098

    def test_r2442_plca_cycle_time(self) -> None:
        """Verify %R2442 stores calculated PLCA cycle time in us."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        eng.configure_plca(node_id=1, max_nodes=10, to_timer_us=30)
        # Cycle time = 10 * 30 + 20 = 320 us
        assert rt.read_uword("%R2442") == 320

    def test_r2443_scaled_reflection_pct(self) -> None:
        """Verify %R2443 scales reflection coefficient to 0..1000."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        # ZL = 70 Ohm -> Gamma = 30 / 170 = 0.17647 -> round(0.17647 * 1000) = 176
        eng.update_bus_impedance(70.0)
        assert rt.read_uword("%R2443") == 176

    def test_r2444_line_impedance_ohms(self) -> None:
        """Verify %R2444 reflects line impedance in Ohms."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        eng.update_bus_impedance(115.0)
        assert rt.read_uword("%R2444") == 115

    def test_r2445_sequence_counter(self) -> None:
        """Verify %R2445 tracks transmission sequence counter."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        for _ in range(5):
            eng.transmit_frame()
        assert rt.read_uword("%R2445") == 5

    def test_r2446_crc_status_word(self) -> None:
        """Verify %R2446 reflects CRC and slot synchronization status bitmask."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        assert rt.read_uword("%R2446") == 0x0007
        eng.simulate_collision()
        assert (rt.read_uword("%R2446") & CRC_STATUS_SLOT_SYNCED) == 0

    def test_r2447_diagnostic_code(self) -> None:
        """Verify %R2447 reflects current diagnostic code."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        assert rt.read_uword("%R2447") == 0x0000
        eng.update_bus_impedance(60.0)
        assert rt.read_uword("%R2447") == 0xED02
        eng.simulate_collision()
        assert rt.read_uword("%R2447") == 0xED01

    def test_m569_m570_truth_table_consistency(self) -> None:
        """Verify discrete coil truth table across all operational states."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        # 1. OPERATIONAL: Active=True, Fault=False
        eng.reset()
        assert rt.read_bit("%M569") is True
        assert rt.read_bit("%M570") is False

        # 2. DEGRADED: Active=True (link maintained), Fault=True (alarm asserted)
        eng.update_bus_impedance(60.0)
        assert rt.read_bit("%M569") is True
        assert rt.read_bit("%M570") is True

        # 3. FAIL_SAFE: Active=False, Fault=True
        eng.simulate_collision()
        assert rt.read_bit("%M569") is False
        assert rt.read_bit("%M570") is True

    def test_safe_write_wrappers_signed_wrapping(self) -> None:
        """Verify safe_write_word, safe_write_uword, and safe_write_bit privilege modes."""
        rt = RegisterTable()
        safe_write_uword(rt, "%R2440", 0xED01, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_uword("%R2440") == 0xED01

        safe_write_word(rt, "%R2441", 32767, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word("%R2441") == 32767

        safe_write_bit(rt, "%M569", True, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_bit("%M569") is True
        safe_write_bit(rt, "%M569", False, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_bit("%M569") is False


# ============================================================================
# 10. TestPureStructuredTextAndSecurity
# ============================================================================

class TestPureStructuredTextAndSecurity:
    """Verifies Pure IEC 61131-3 ST POU validation, AST generation, and bound registers."""

    def test_pure_st_pou_string_constants(self) -> None:
        """Verify pure ST POU string constants exist and are populated."""
        assert isinstance(ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC, str)
        assert len(ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC) > 100
        assert CIP_SAFETY_APL_MULTIDROP_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC
        assert CIP_SAFETY_APL_MULTIDROP_SYNC_POU == ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC
        assert CipSafetyAplMultidropSync == ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC

    def test_st_parser_ast_program_type(self) -> None:
        """Verify STParser parses POU as POUType.PROGRAM."""
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSafetyAplMultidropSync"

    def test_st_parser_bound_registers(self) -> None:
        """Verify all Horner OCS registers and coils are mapped in POU AST."""
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC)
        expected_regs = {
            "%R2440", "%R2441", "%R2442", "%R2443",
            "%R2444", "%R2445", "%R2446", "%R2447",
            "%M569", "%M570",
        }
        bound = set(ast.bound_registers)
        assert expected_regs.issubset(bound)

    def test_verify_pure_st_function(self) -> None:
        """Verify verify_cip_safety_apl_multidrop_pure_st helper returns True for nominal POU."""
        assert verify_cip_safety_apl_multidrop_pure_st() is True
        assert verify_cip_safety_apl_multidrop_pure_st(ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC) is True
        assert verify_cip_safety_apl_multidrop_pure_st("INVALID POU CONTENT") is False

    def test_security_guard_assert_pure_st(self) -> None:
        """Verify SecurityGuard asserts pure ST with zero exceptions."""
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_MULTIDROP_SYNC)


# ============================================================================
# 11. TestAntiLadderConstructRejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Verifies fail-closed rejection of ladder logic constructs (Gate G1/G3 compliance)."""

    def test_reject_ladder_open_contact(self) -> None:
        """Reject normally-open contact construct ---[ ]---."""
        code = "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[ ]--- x; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_reject_ladder_closed_contact(self) -> None:
        """Reject normally-closed contact construct ---[/]---."""
        code = "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[/]--- x; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_reject_ladder_coil(self) -> None:
        """Reject output coil construct ---( )---."""
        code = "PROGRAM LadderTest VAR y : BOOL; END_VAR ---( )--- y; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_reject_ladder_set_reset_coils(self) -> None:
        """Reject set/reset coil constructs ---(S)--- and ---(R)---."""
        code_s = "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(S)--- y; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code_s)

        code_r = "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(R)--- y; END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code_r)

    def test_reject_ladder_rung_delimiters(self) -> None:
        """Reject ladder RUNG delimiter tokens."""
        code = "PROGRAM LadderTest RUNG 1 END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_reject_ladder_network_delimiters(self) -> None:
        """Reject ladder NETWORK delimiter tokens."""
        code = "PROGRAM LadderTest NETWORK 1 END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_reject_ladder_xic_mnemonic(self) -> None:
        """Reject ladder XIC mnemonic."""
        code = "PROGRAM LadderTest XIC(Contact1); END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_reject_ladder_ote_mnemonic(self) -> None:
        """Reject ladder OTE mnemonic."""
        code = "PROGRAM LadderTest OTE(Coil1); END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)


# ============================================================================
# 12. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Verifies ILogicUnit interface compliance, scan cycles, and multi-cycle soak."""

    def test_ilogic_unit_inheritance(self) -> None:
        """Verify CipSafetyAplMultidropEngine implements ILogicUnit."""
        eng = CipSafetyAplMultidropEngine()
        assert isinstance(eng, ILogicUnit)

    def test_ilogic_unit_properties(self) -> None:
        """Verify ILogicUnit contract properties."""
        eng = CipSafetyAplMultidropEngine()
        assert eng.name == "CIP_SAFETY_APL_MULTIDROP"
        assert eng.priority == 10
        assert eng.is_enabled is True
        assert eng.is_healthy is True
        assert eng.is_fail_safe is False

    def test_scan_step_cycles_and_execution(self) -> None:
        """Verify scan_step advances cycle count and watchdog timer."""
        eng = CipSafetyAplMultidropEngine()
        assert eng.cycles_count == 0

        eng.scan_step(0.010)
        assert eng.cycles_count == 1
        assert eng.watchdog_timer_ms == 10.0

        eng.scan_step(0.020)
        assert eng.cycles_count == 2
        assert eng.watchdog_timer_ms == 30.0

    def test_step_alias_method(self) -> None:
        """Verify step() delegates directly to scan_step()."""
        eng = CipSafetyAplMultidropEngine()
        eng.step(0.015)
        assert eng.cycles_count == 1
        assert eng.watchdog_timer_ms == 15.0

    def test_execute_method_healthy(self) -> None:
        """Verify execute() returns SUCCESS when engine is healthy."""
        eng = CipSafetyAplMultidropEngine()
        res = eng.execute()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert "healthy" in res.details

    def test_execute_method_tripped(self) -> None:
        """Verify execute() returns FAILED and error code when FAIL_SAFE."""
        eng = CipSafetyAplMultidropEngine()
        eng.simulate_collision()

        res = eng.execute()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "0xED01"
        assert "BUS_COLLISION" in res.details

    def test_100_cycle_soak_and_memory_stability(self) -> None:
        """Verify 100 consecutive scan steps execute deterministically without memory leak."""
        tracemalloc.start()
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt)

        for _ in range(100):
            eng.feed_watchdog()
            eng.transmit_frame(payload_bytes=b"\x01\x02\x03\x04")
            eng.scan_step(0.010)
            assert eng.is_healthy is True

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert eng.cycles_count == 100
        assert eng.frames_transmitted == 100
        assert peak < 1024 * 1024  # Less than 1MB peak allocation


# ============================================================================
# 13. TestExceptionsAndVerificationRunner
# ============================================================================

class TestExceptionsAndVerificationRunner:
    """Verifies exception classes and 9-stage verification runner with strict contract output."""

    def test_exception_hierarchy(self) -> None:
        """Verify all custom exceptions inherit from CipSafetyAplMultidropError."""
        assert issubclass(BusCollisionError, CipSafetyAplMultidropError)
        assert issubclass(ReflectionMismatchError, CipSafetyAplMultidropError)
        assert issubclass(TrunkPartitionError, CipSafetyAplMultidropError)
        assert issubclass(CipSafetyAplMultidropError, Exception)

    def test_runner_all_9_stages(self) -> None:
        """Verify run_cip_safety_apl_multidrop_verification executes all 9 stages successfully."""
        evidence = run_cip_safety_apl_multidrop_verification()
        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["stages_passed"] == 9
        assert evidence["total_stages"] == 9
        assert len(evidence["data"]["stages"]) == 9

        for stage in evidence["data"]["stages"]:
            assert stage["passed"] is True
            assert stage["timing_ms"] >= 0.0

    def test_runner_strict_4_state_contract(self) -> None:
        """Verify runner output matches strict 4-state contract schema."""
        evidence = run_cip_safety_apl_multidrop_verification()
        assert "status" in evidence
        assert evidence["status"] in ("success", "failed", "blocked", "inconclusive")
        assert "error_code" in evidence
        assert "details" in evidence
        assert "data" in evidence
        assert evidence["data"]["work_package"] == "W283"
        assert "%R2440..%R2447" in evidence["data"]["registers"]

    def test_runner_file_output_persistence(self) -> None:
        """Verify runner correctly writes JSON evidence artifact to disk."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            evidence = run_cip_safety_apl_multidrop_verification(output_path=tmp_path)
            assert tmp_path.exists()
            with open(tmp_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["stages_passed"] == 9
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


# ============================================================================
# 14. TestComplexScenariosAndStateTransitions
# ============================================================================

class TestComplexScenariosAndStateTransitions:
    """Verifies complex end-to-end multi-state scenarios and recovery sequences."""

    def test_cascade_recovery_flow(self) -> None:
        """Verify complete state cycle: INIT -> OPERATIONAL -> DEGRADED -> FAIL_SAFE -> reset()."""
        rt = RegisterTable()
        eng = CipSafetyAplMultidropEngine(register_table=rt, auto_activate=False)

        # 1. INIT
        assert eng.state == CipSafetyAplMultidropState.INIT
        assert rt.read_uword("%R2440") == 256  # Node 1, State 0

        # 2. OPERATIONAL
        eng.reset()
        assert eng.state == CipSafetyAplMultidropState.OPERATIONAL
        assert rt.read_uword("%R2440") == 257

        # 3. DEGRADED (Impedance mismatch)
        eng.update_bus_impedance(62.0)
        assert eng.state == CipSafetyAplMultidropState.DEGRADED
        assert rt.read_uword("%R2440") == 258

        # 4. FAIL_SAFE (Trunk short)
        eng.simulate_trunk_short()
        assert eng.state == CipSafetyAplMultidropState.FAIL_SAFE
        assert rt.read_uword("%R2440") == 259
        assert rt.read_bit("%M570") is True

        # 5. Recovery via reset()
        eng.reset()
        assert eng.state == CipSafetyAplMultidropState.OPERATIONAL
        assert rt.read_uword("%R2440") == 257
        assert rt.read_bit("%M570") is False

    def test_plca_multi_node_arbitration_cluster(self) -> None:
        """Verify cluster of multiple nodes transmitting within their allotted slots."""
        cluster_size = 4
        nodes = [
            CipSafetyAplMultidropEngine(
                plca_config=PlcaConfig(node_id=i, max_nodes=cluster_size, is_coordinator=(i == 0))
            )
            for i in range(cluster_size)
        ]

        # Simulate 2 round-robin PLCA cycles (slots 0..7)
        for cycle in range(2):
            for slot in range(cluster_size):
                active_slot = cycle * cluster_size + slot
                for i, n in enumerate(nodes):
                    if i == (active_slot % cluster_size):
                        # Node i is arbitrated
                        assert n.can_transmit_in_slot(active_slot) is True
                        frame = n.transmit_frame(slot=active_slot)
                        assert frame.plca_slot == active_slot
                    else:
                        # Other nodes cannot transmit
                        assert n.can_transmit_in_slot(active_slot) is False
                        with pytest.raises(BusCollisionError):
                            n.transmit_frame(slot=active_slot)

    def test_rapid_impedance_oscillation_hysteresis(self) -> None:
        """Verify engine safely handles fluctuating impedance across the 15% threshold."""
        eng = CipSafetyAplMultidropEngine()
        impedance_sequence = [100.0, 95.0, 85.0, 60.0, 62.0, 88.0, 100.0, 50.0, 100.0]

        for z in impedance_sequence:
            refl = eng.update_bus_impedance(z)
            if refl > 0.15:
                assert eng.state == CipSafetyAplMultidropState.DEGRADED
                assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.REFLECTION_MISMATCH
            else:
                assert eng.state == CipSafetyAplMultidropState.OPERATIONAL
                assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.OK

    def test_simultaneous_collision_and_reflection(self) -> None:
        """Verify collision fault takes precedence over reflection degradation."""
        eng = CipSafetyAplMultidropEngine()
        # Degrade line first
        eng.update_bus_impedance(55.0)
        assert eng.state == CipSafetyAplMultidropState.DEGRADED

        # Collision occurs
        eng.simulate_collision()
        assert eng.state == CipSafetyAplMultidropState.FAIL_SAFE
        assert eng.diagnostic_code == CipSafetyAplMultidropDiagnosticCode.BUS_COLLISION
