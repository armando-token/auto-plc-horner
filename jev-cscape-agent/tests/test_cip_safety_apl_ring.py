"""Comprehensive Unit Test Suite for Wave W313 CIP Safety Over Ethernet-APL Redundant Ring Protocol Engine.

Work Package: W313 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Ethernet-APL Redundant Ring (DLR) Topology for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 14 Mandatory Test Classes (85+ Tests):
1. TestProtocolConstantsEnumsAndDiagnostics: Canonical registers (%R2740..%R2747), coils (%M639..%M640),
   aliases, protocol constants, enums (RingTopologyState, SupervisorRole, AplRingStatusBits),
   and signed 16-bit safe comparisons for DiagnosticCode (0x0000, 0xEE81..0xEE85).
2. TestDualSafetyCrcMathematics: CRC-S1 (poly 0x5935, init 0x0000) and CRC-S2 (poly 0x755B, init 0x0000)
   polynomial mathematics, single-bit perturbation detection, EPID hashing and CRC32.
3. TestPacketModelAndBinarySerialization: CIPAPLRingPacket dataclass, property aliases,
   inverted header computation, CRC validation, binary pack/unpack roundtrip, and tampering detection.
4. TestAplRingTopologyTrackingAndBeacons: Engine initialization, supervisor and client roles,
   connect/disconnect state transitions, beacon timing, transition counts, and frame sequence counters.
5. TestRingBreakDetectionAndFaultLocation: Port 1 and Port 2 break detection, transition to RING_FAULT (0xEE83),
   fault location tracking in %R2742, and clean ring restoration.
6. TestDualPortLinkDownCriticalSafetyTrip: Dual port PHY link down triggering critical SAFETY_TRIP (0xEE82),
   fault location 3 (both ports down), de-assertion of online and assertion of tripped, and recovery.
7. TestBeaconTimeoutSurveillanceAndTrip: Beacon frame timeout (> 400 us loss) tripping DIAG_ERR_BEACON_TIMEOUT (0xEE81),
   accumulation in scan cycles, reset on ingress packets, and coil interlocks.
8. TestSupervisorCollisionPrecedenceConflict: Multiple active supervisor collision detection (0xEE85),
   precedence conflict handling, and session identification.
9. TestCrcCorruptionInjectionAndTrip: Dual CRC corruption injection (0xEE84), payload tampering,
   and monotonic packet loss counter increments.
10. TestSafeStopInterlockAndCoils: Fail-safe interlock asserting %M640 (SAFETY_TRIP) and de-asserting %M639 (ONLINE)
    across all 5 diagnostic trip conditions, coil mutual exclusivity, and healthy restoration upon fault clearance.
11. TestHornerRegisterTableSynchronization: Bit-exact synchronization to Horner OCS registers (%R2740..%R2747)
    and coils (%M639..%M640), status register packing, link qualities, privilege modes, and write helpers.
12. TestPureIEC61131StructuredTextAndSecurity: Pure IEC 61131-3 ST POU CipSafetyAplRingSync validation
    via STParser and SecurityGuard, AST bound registers, and strict interception of 9 ladder logic constructs.
13. TestILogicUnitComplianceAndSimulationSoak: ILogicUnit interface compliance, variable scan_step argument
    handling, step/execute/reset methods, and 100-cycle continuous simulation soak with bounded memory.
14. TestVerificationRunner9StagesAndCli: Complete 9-stage verification suite run_cip_safety_apl_ring_verification,
    strict 4-state engineering contract validation, JSON evidence emission rules, and CLI interop.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List
import pytest
import zlib

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_apl_ring import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_RING_CLASS_ID,
    CIP_DLR_CLASS_ID,
    CIP_APL_RING_CLASS_ID,
    PORT1_PRIMARY,
    PORT2_SECONDARY,
    PORT1,
    PORT2,
    NOMINAL_BEACON_INTERVAL_US,
    DEFAULT_BEACON_INTERVAL_US,
    MIN_BEACON_INTERVAL_US,
    MAX_BEACON_INTERVAL_US,
    BEACON_TIMEOUT_THRESHOLD_US,
    DEFAULT_BEACON_TIMEOUT_US,
    NOMINAL_BEACON_TIMEOUT_US,
    NOMINAL_LINK_QUALITY,
    DEFAULT_LINK_QUALITY,
    MIN_ALLOWED_LINK_QUALITY,
    DEFAULT_SESSION_ID,
    DEFAULT_SUPERVISOR_PRECEDENCE,
    DEFAULT_SAFETY_EPID,
    DEFAULT_EPID,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S_INIT,
    CRC_INIT,
    CRC16_CCITT_POLY,
    CRC16_CCITT_INIT,
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
    REG_APL_RING_STATUS,
    REG_APL_RING_SUPERVISOR_STATE,
    REG_APL_RING_FAULT_LOCATION,
    REG_APL_RING_TRANSITION_COUNT,
    REG_APL_RING_BEACON_INTERVAL_US,
    REG_APL_RING_DIAGNOSTIC_CODE,
    REG_APL_RING_PORT1_LINK_QUALITY,
    REG_APL_RING_PORT2_LINK_QUALITY,
    COIL_APL_RING_ONLINE,
    COIL_APL_RING_SAFETY_TRIP,
    COIL_CIP_APL_RING_TRIP,
    COIL_APL_RING_TRIP,
    COIL_CIP_APL_RING_HEALTHY,
    COIL_APL_RING_HEALTHY,
    COIL_APL_RING_ACTIVE,
    COIL_APL_RING_FAULT,
    REG_CIP_SAFETY_RING_STATUS,
    REG_CIP_SAFETY_RING_MRP_STATE,
    REG_CIP_SAFETY_RING_RECOVERY_TIME_MS,
    REG_CIP_SAFETY_RING_PORT1_STATE,
    REG_CIP_SAFETY_RING_PORT2_STATE,
    REG_CIP_SAFETY_RING_SEQUENCE_COUNTER,
    REG_CIP_SAFETY_RING_CRC_STATUS,
    REG_CIP_SAFETY_RING_DIAGNOSTIC_CODE,
    COIL_CIP_SAFETY_RING_ACTIVE,
    COIL_CIP_SAFETY_RING_FAULT,
    RingTopologyState,
    CipSafetyAplRingTopologyState,
    APLRingTopologyState,
    CIPAPLRingTopologyState,
    AplRingTopologyState,
    SupervisorRole,
    CipSafetyAplSupervisorRole,
    APLSupervisorRole,
    CIPAPLSupervisorRole,
    AplSupervisorRole,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_BEACON_TIMEOUT,
    DIAG_ERR_DUAL_PORT_LINK_DOWN,
    DIAG_ERR_RING_FAULT_DETECTED,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_ERR_SUPERVISOR_COLLISION,
    DIAG_BEACON_TIMEOUT,
    DIAG_DUAL_PORT_LINK_DOWN,
    DIAG_RING_FAULT_DETECTED,
    DIAG_DUAL_CRC_SAFETY_FAULT,
    DIAG_SUPERVISOR_COLLISION,
    DIAG_CRC_FAULT,
    DIAG_ERR_CRC_FAULT,
    DIAG_RING_FAULT,
    DIAG_LINK_DOWN,
    DIAG_ERR_RING_BREAK,
    DIAG_ERR_PORT_LINK_LOSS,
    DIAG_ERR_CRC_S1_FAULT,
    DIAG_ERR_CRC_S2_FAULT,
    DIAG_ERR_BEACON_LOSS,
    DIAG_ERR_FAIL_SAFE_TRIP,
    AplRingStatusBits,
    CipSafetyAplRingStatusBits,
    CipSafetyRingStatusBits,
    RingRole,
    PortState,
    CIPAPLRingSafetyError,
    APLRingBeaconTimeoutError,
    APLRingDualPortLinkDownError,
    APLRingFaultDetectedError,
    APLRingDualCrcSafetyFaultError,
    APLRingSupervisorCollisionError,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    calculate_cip_safety_crc_s1,
    calculate_cip_safety_crc_s2,
    calculate_crc_s1,
    calculate_crc_s2,
    compute_epid_hash,
    compute_epid_crc32,
    calculate_crc16_ccitt,
    verify_dual_crc_s,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPAPLRingPacket,
    CipSafetyAplRingPacket,
    APLRingPacket,
    CIPAPLRingSafetyPacket,
    APLRingSafetyPacket,
    CipAplRingPacket,
    CipSafetyAplRingFrame,
    create_valid_apl_ring_packet,
    create_valid_cip_apl_ring_packet,
    create_valid_cip_safety_apl_ring_packet,
    ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC,
    CIP_SAFETY_APL_RING_SYNC_POU,
    CIP_SAFETY_APL_RING_PURE_ST_POU,
    CIP_SAFETY_APL_RING_POU,
    PURE_ST_POU,
    CipSafetyAplRingSync,
    CipSafetyAplRingSyncPOU,
    verify_cip_safety_apl_ring_pure_st,
    verify_apl_ring_pure_st,
    CIPAPLRingSafetyEngine,
    CipSafetyAplRingEngine,
    CIPAPLRingEngine,
    CIPSafetyAPLRingEngine,
    APLRingSafetyEngine,
    APLRingEngine,
    AplRingNode,
    run_cip_safety_apl_ring_verification,
)


# ============================================================================
# 1. TestProtocolConstantsEnumsAndDiagnostics
# ============================================================================

class TestProtocolConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety Over Ethernet-APL Redundant Ring constants, registers, coils, and diagnostics."""

    def test_canonical_registers(self) -> None:
        """Validate canonical Horner OCS analog registers %R2740..%R2747."""
        assert REG_CIP_APL_RING_STATUS == "%R2740"
        assert REG_CIP_APL_RING_SUPERVISOR_STATE == "%R2741"
        assert REG_CIP_APL_RING_FAULT_LOCATION == "%R2742"
        assert REG_CIP_APL_RING_TRANSITION_COUNT == "%R2743"
        assert REG_CIP_APL_RING_BEACON_INTERVAL_US == "%R2744"
        assert REG_CIP_APL_RING_DIAGNOSTIC_CODE == "%R2745"
        assert REG_CIP_APL_RING_PORT1_LINK_QUALITY == "%R2746"
        assert REG_CIP_APL_RING_PORT2_LINK_QUALITY == "%R2747"

    def test_canonical_coils(self) -> None:
        """Validate canonical Horner OCS discrete coils %M639..%M640."""
        assert COIL_CIP_APL_RING_ONLINE == "%M639"
        assert COIL_CIP_APL_RING_SAFETY_TRIP == "%M640"

    def test_register_and_coil_aliases(self) -> None:
        """Validate register and coil extended and backwards compatibility aliases."""
        assert REG_APL_RING_STATUS == "%R2740"
        assert REG_APL_RING_SUPERVISOR_STATE == "%R2741"
        assert REG_APL_RING_FAULT_LOCATION == "%R2742"
        assert REG_APL_RING_TRANSITION_COUNT == "%R2743"
        assert REG_APL_RING_BEACON_INTERVAL_US == "%R2744"
        assert REG_APL_RING_DIAGNOSTIC_CODE == "%R2745"
        assert REG_APL_RING_PORT1_LINK_QUALITY == "%R2746"
        assert REG_APL_RING_PORT2_LINK_QUALITY == "%R2747"

        assert COIL_APL_RING_ONLINE == "%M639"
        assert COIL_APL_RING_SAFETY_TRIP == "%M640"
        assert COIL_CIP_APL_RING_TRIP == "%M640"
        assert COIL_CIP_APL_RING_HEALTHY == "%M639"
        assert COIL_APL_RING_HEALTHY == "%M639"
        assert COIL_APL_RING_ACTIVE == "%M639"
        assert COIL_APL_RING_FAULT == "%M640"

        # Legacy W286 aliases preserved for compatibility
        assert REG_CIP_SAFETY_RING_STATUS == "%R2470"
        assert COIL_CIP_SAFETY_RING_ACTIVE == "%M576"
        assert COIL_CIP_SAFETY_RING_FAULT == "%M577"

    def test_protocol_constants_and_defaults(self) -> None:
        """Validate ODVA CIP Safety and DLR protocol identifiers and timing constants."""
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_RING_CLASS_ID == 0x3B
        assert CIP_DLR_CLASS_ID == 0x47
        assert CIP_APL_RING_CLASS_ID == 0x47

        assert PORT1_PRIMARY == 1
        assert PORT2_SECONDARY == 2
        assert PORT1 == 1
        assert PORT2 == 2

        assert NOMINAL_BEACON_INTERVAL_US == 400
        assert DEFAULT_BEACON_INTERVAL_US == 400
        assert BEACON_TIMEOUT_THRESHOLD_US == 400
        assert DEFAULT_BEACON_TIMEOUT_US == 400

        assert NOMINAL_LINK_QUALITY == 100
        assert DEFAULT_LINK_QUALITY == 100
        assert MIN_ALLOWED_LINK_QUALITY == 1

        assert DEFAULT_SESSION_ID == 0x4150
        assert DEFAULT_SUPERVISOR_PRECEDENCE == 100
        assert DEFAULT_SAFETY_EPID == "HORNER-OCS-APL-RING-SIL3"
        assert DEFAULT_EPID == "HORNER-OCS-APL-RING-SIL3"

    def test_ring_topology_state_enum(self) -> None:
        """Validate RingTopologyState IntEnum states and aliases."""
        assert RingTopologyState.NORMAL_RING == 0
        assert RingTopologyState.RING_FAULT == 1
        assert RingTopologyState.LINEAR_TOPOLOGY == 2
        assert RingTopologyState.SUPERVISOR_ACTIVE == 3
        assert RingTopologyState.SAFETY_TRIP == 4

        # Verify aliases
        assert RingTopologyState.CLOSED == 0
        assert RingTopologyState.OPEN == 1
        assert RingTopologyState.LINEAR == 2
        assert RingTopologyState.SUPERVISOR == 3
        assert RingTopologyState.TRIP == 4

        # Enum identity aliases
        assert CipSafetyAplRingTopologyState is RingTopologyState
        assert APLRingTopologyState is RingTopologyState
        assert CIPAPLRingTopologyState is RingTopologyState
        assert AplRingTopologyState is RingTopologyState

    def test_supervisor_role_enum(self) -> None:
        """Validate SupervisorRole IntEnum states and aliases."""
        assert SupervisorRole.BACKUP == 0
        assert SupervisorRole.ACTIVE_SUPERVISOR == 1
        assert SupervisorRole.NON_SUPERVISOR == 2

        # Aliases
        assert SupervisorRole.BACKUP_SUPERVISOR == 0
        assert SupervisorRole.ACTIVE == 1
        assert SupervisorRole.PRIMARY == 1
        assert SupervisorRole.NON_SUPERVISOR_NODE == 2
        assert SupervisorRole.CLIENT == 2

        assert CipSafetyAplSupervisorRole is SupervisorRole
        assert APLSupervisorRole is SupervisorRole
        assert CIPAPLSupervisorRole is SupervisorRole
        assert AplSupervisorRole is SupervisorRole

    def test_diagnostic_codes_values(self) -> None:
        """Validate DiagnosticCode values and naming."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_BEACON_TIMEOUT == 0xEE81
        assert DIAG_ERR_DUAL_PORT_LINK_DOWN == 0xEE82
        assert DIAG_ERR_RING_FAULT_DETECTED == 0xEE83
        assert DIAG_ERR_DUAL_CRC_SAFETY_FAULT == 0xEE84
        assert DIAG_ERR_SUPERVISOR_COLLISION == 0xEE85

        # Aliases
        assert DIAG_BEACON_TIMEOUT == 0xEE81
        assert DIAG_DUAL_PORT_LINK_DOWN == 0xEE82
        assert DIAG_RING_FAULT_DETECTED == 0xEE83
        assert DIAG_DUAL_CRC_SAFETY_FAULT == 0xEE84
        assert DIAG_SUPERVISOR_COLLISION == 0xEE85
        assert DIAG_CRC_FAULT == 0xEE84
        assert DIAG_RING_FAULT == 0xEE83
        assert DIAG_LINK_DOWN == 0xEE82

    def test_diagnostic_codes_safe_signed_comparisons(self) -> None:
        """Validate that DiagnosticCode safely supports signed and unsigned 16-bit comparisons."""
        # 0xEE81 in signed 16-bit is 0xEE81 - 0x10000 = -4479
        diag_beacon = DIAG_ERR_BEACON_TIMEOUT
        assert diag_beacon == 0xEE81
        assert diag_beacon == -4479
        assert int(diag_beacon) == 0xEE81
        assert (diag_beacon & 0xFFFF) == 0xEE81
        assert (0xEE81 & diag_beacon) == 0xEE81
        assert diag_beacon != 0x0000
        assert diag_beacon != DIAG_OK

        # 0xEE82 signed is -4478
        assert DIAG_ERR_DUAL_PORT_LINK_DOWN == 0xEE82
        assert DIAG_ERR_DUAL_PORT_LINK_DOWN == -4478

        # 0xEE83 signed is -4477
        assert DIAG_ERR_RING_FAULT_DETECTED == 0xEE83
        assert DIAG_ERR_RING_FAULT_DETECTED == -4477

        # 0xEE84 signed is -4476
        assert DIAG_ERR_DUAL_CRC_SAFETY_FAULT == 0xEE84
        assert DIAG_ERR_DUAL_CRC_SAFETY_FAULT == -4476

        # 0xEE85 signed is -4475
        assert DIAG_ERR_SUPERVISOR_COLLISION == 0xEE85
        assert DIAG_ERR_SUPERVISOR_COLLISION == -4475

        # Str, repr, hash
        assert "0x0000" in str(DIAG_OK)
        assert "0xEE81" in str(diag_beacon)
        assert "DIAG_ERR_BEACON_TIMEOUT" in repr(diag_beacon)
        assert hash(diag_beacon) == hash(0xEE81)

    def test_apl_ring_status_bits(self) -> None:
        """Validate AplRingStatusBits IntFlag bit positions."""
        assert AplRingStatusBits.ONLINE == 1 << 0
        assert AplRingStatusBits.SUPERVISOR_ACTIVE == 1 << 1
        assert AplRingStatusBits.RING_NORMAL == 1 << 2
        assert AplRingStatusBits.RING_FAULT == 1 << 3
        assert AplRingStatusBits.PORT1_LINK_UP == 1 << 4
        assert AplRingStatusBits.PORT2_LINK_UP == 1 << 5
        assert AplRingStatusBits.SAFETY_TRIPPED == 1 << 6
        assert AplRingStatusBits.BEACON_OK == 1 << 7

        assert CipSafetyAplRingStatusBits is AplRingStatusBits
        assert CipSafetyRingStatusBits is AplRingStatusBits


# ============================================================================
# 2. TestDualSafetyCrcMathematics
# ============================================================================

class TestDualSafetyCrcMathematics:
    """Validate dual CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B) mathematics and perturbation sensitivity."""

    def test_crc_polynomial_constants(self) -> None:
        """Validate CRC polynomials and default initial seeds."""
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0x0000
        assert CRC_S_INIT == 0x0000
        assert CRC_INIT == 0x0000

    def test_crc_s1_determinism_and_bounds(self) -> None:
        """Validate CRC-S1 computation determinism and 16-bit bounds."""
        payload = b"\x10\x20\x30\x40\x50"
        crc1 = compute_crc_s1(payload)
        crc2 = compute_crc_s1(payload)
        assert crc1 == crc2
        assert 0 <= crc1 <= 0xFFFF
        assert compute_crc_s1(payload_bytes=payload) == crc1
        assert calculate_crc_s1(payload) == crc1

    def test_crc_s1_empty_payload(self) -> None:
        """Validate CRC-S1 on empty byte string returns initial seed."""
        assert compute_crc_s1(b"") == 0x0000
        assert compute_crc_s1(b"", initial_seed=0x1234) == 0x1234

    def test_crc_s1_bit_perturbation_detection(self) -> None:
        """Validate that flipping each individual bit in payload alters CRC-S1."""
        base_payload = b"\x01\x02\x03\x04\x05\x06"
        base_crc = compute_crc_s1(base_payload)

        for byte_idx in range(len(base_payload)):
            for bit_idx in range(8):
                corrupted = bytearray(base_payload)
                corrupted[byte_idx] ^= (1 << bit_idx)
                mutated_crc = compute_crc_s1(bytes(corrupted))
                assert mutated_crc != base_crc, f"Failed detection at byte {byte_idx}, bit {bit_idx}"

    def test_crc_s2_inverted_header_calculation(self) -> None:
        """Validate CRC-S2 computation with inverted header fields."""
        c2 = compute_crc_s2(
            session_id=DEFAULT_SESSION_ID,
            sequence_number=1,
            timestamp_us=400,
            ring_state=0,
            supervisor_precedence=100,
            port_id=1,
        )
        assert 0 <= c2 <= 0xFFFF
        assert calculate_crc_s2(
            session_id=DEFAULT_SESSION_ID,
            sequence_number=1,
            timestamp_us=400,
            ring_state=0,
            supervisor_precedence=100,
            port_id=1,
        ) == c2

    def test_crc_s2_header_perturbation_detection(self) -> None:
        """Validate that mutating any header field produces distinct CRC-S2."""
        base_c2 = compute_crc_s2(
            session_id=DEFAULT_SESSION_ID,
            sequence_number=10,
            timestamp_us=1000,
            ring_state=0,
            supervisor_precedence=100,
            port_id=1,
        )

        c2_seq = compute_crc_s2(
            session_id=DEFAULT_SESSION_ID,
            sequence_number=11,
            timestamp_us=1000,
            ring_state=0,
            supervisor_precedence=100,
            port_id=1,
        )
        assert c2_seq != base_c2

        c2_ts = compute_crc_s2(
            session_id=DEFAULT_SESSION_ID,
            sequence_number=10,
            timestamp_us=1001,
            ring_state=0,
            supervisor_precedence=100,
            port_id=1,
        )
        assert c2_ts != base_c2

        c2_prec = compute_crc_s2(
            session_id=DEFAULT_SESSION_ID,
            sequence_number=10,
            timestamp_us=1000,
            ring_state=0,
            supervisor_precedence=101,
            port_id=1,
        )
        assert c2_prec != base_c2

    def test_crc_s1_and_crc_s2_polynomial_distinctness(self) -> None:
        """Validate that CRC-S1 (0x5935) and CRC-S2 (0x755B) yield distinct values on identical input."""
        test_bytes = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        c1 = compute_crc_s1(test_bytes)
        c2 = compute_crc_s2(data=test_bytes)
        assert c1 != c2

    def test_epid_hashing_and_crc32(self) -> None:
        """Validate Electronic Product ID (EPID) 16-bit and 32-bit checksum calculations."""
        epid = "HORNER-OCS-APL-RING-SIL3"
        h16 = compute_epid_hash(epid)
        h32 = compute_epid_crc32(epid)
        assert 0 <= h16 <= 0xFFFF
        assert 0 <= h32 <= 0xFFFFFFFF
        assert (h32 & 0xFFFF) == h16
        assert h32 == (zlib.crc32(epid.encode("utf-8")) & 0xFFFFFFFF)

    def test_verify_dual_crc_s_and_crc16_ccitt(self) -> None:
        """Validate verify_dual_crc_s helper and CCITT compatibility CRC."""
        payload = b"\x01\x02\x03\x04"
        inverted = b"\xFE\xFD\xFC\xFB"
        c1 = compute_crc_s1(payload)
        c2 = compute_crc_s2(inverted)
        assert verify_dual_crc_s(payload, inverted, c1, c2) is True
        assert verify_dual_crc_s(payload, inverted, c1 ^ 1, c2) is False
        assert verify_dual_crc_s(payload, inverted, c1, c2 ^ 1) is False

        ccitt = calculate_crc16_ccitt(payload)
        assert 0 <= ccitt <= 0xFFFF


# ============================================================================
# 3. TestPacketModelAndBinarySerialization
# ============================================================================

class TestPacketModelAndBinarySerialization:
    """Validate CIPAPLRingPacket dataclass, binary packing/unpacking, and tamper detection."""

    def test_packet_defaults_and_construction(self) -> None:
        """Validate CIPAPLRingPacket default fields and auto CRC generation."""
        pkt = CIPAPLRingPacket()
        assert pkt.session_id == DEFAULT_SESSION_ID
        assert pkt.sequence_number == 0
        assert pkt.timestamp_us == 0
        assert pkt.ring_state == RingTopologyState.NORMAL_RING
        assert pkt.supervisor_precedence == DEFAULT_SUPERVISOR_PRECEDENCE
        assert pkt.port_id == PORT1_PRIMARY
        assert pkt.payload_bytes == b"\x01\x02\x03\x04"
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0

    def test_packet_property_aliases(self) -> None:
        """Validate property getters and setters for packet attributes."""
        pkt = CIPAPLRingPacket()
        pkt.payload = b"\xDE\xAD\xBE\xEF"
        assert pkt.payload_bytes == b"\xDE\xAD\xBE\xEF"
        pkt.sequence = 77
        assert pkt.sequence_number == 77
        pkt.timestamp = 9999
        assert pkt.timestamp_us == 9999
        pkt.precedence = 250
        assert pkt.supervisor_precedence == 250

    def test_packet_inverted_header_generation(self) -> None:
        """Validate bitwise inversion of header fields for CRC-S2."""
        pkt = CIPAPLRingPacket(
            session_id=0x1122,
            sequence_number=0x3344,
            timestamp_us=0x55667788,
            ring_state=RingTopologyState.NORMAL_RING,
            supervisor_precedence=100,
            port_id=1,
        )
        inv = pkt.get_inverted_header()
        assert len(inv) == 11
        # Check first byte: session_id high byte 0x11 inverted is ~0x11 & 0xFF = 0xEE
        assert inv[0] == 0xEE
        assert inv[1] == 0xDD

    def test_packet_crc_computation_and_validation(self) -> None:
        """Validate compute_crcs and validate_crcs on valid and corrupted packets."""
        pkt = CIPAPLRingPacket(payload_bytes=b"\xCA\xFE\xBA\xBE")
        c1, c2 = pkt.compute_crcs()
        assert pkt.crc_s1 == c1
        assert pkt.crc_s2 == c2
        assert pkt.validate_crcs() is True
        assert pkt.is_valid() is True

    def test_packet_pack_and_unpack_roundtrip(self) -> None:
        """Validate binary struct serialization pack() and unpack() round-trip."""
        original = create_valid_apl_ring_packet(
            payload_bytes=b"\x12\x34\x56\x78\x90",
            sequence=101,
            timestamp_us=40000,
            ring_state=RingTopologyState.SUPERVISOR_ACTIVE,
            supervisor_precedence=120,
            port_id=PORT2_SECONDARY,
        )
        raw_bytes = original.pack()
        assert len(raw_bytes) == struct.calcsize("!H H I B B B H H H") + len(original.payload_bytes)

        unpacked = CIPAPLRingPacket.unpack(raw_bytes)
        assert unpacked.session_id == original.session_id
        assert unpacked.sequence_number == original.sequence_number
        assert unpacked.timestamp_us == original.timestamp_us
        assert unpacked.ring_state == original.ring_state
        assert unpacked.supervisor_precedence == original.supervisor_precedence
        assert unpacked.port_id == original.port_id
        assert unpacked.payload_bytes == original.payload_bytes
        assert unpacked.crc_s1 == original.crc_s1
        assert unpacked.crc_s2 == original.crc_s2
        assert unpacked.validate_crcs() is True

    def test_packet_unpack_short_data_raises_value_error(self) -> None:
        """Validate that unpack raises ValueError when data is truncated."""
        with pytest.raises(ValueError, match="too short"):
            CIPAPLRingPacket.unpack(b"\x00" * 5)

    def test_packet_payload_tamper_detection(self) -> None:
        """Validate that changing payload bytes invalidates CRC-S1."""
        pkt = create_valid_apl_ring_packet(payload_bytes=b"\x01\x02\x03\x04")
        assert pkt.validate_crcs() is True
        pkt.payload_bytes = b"\x01\x02\x03\x05"
        assert pkt.validate_crcs() is False

    def test_packet_header_tamper_detection(self) -> None:
        """Validate that mutating sequence number or timestamp invalidates CRC-S2."""
        pkt = create_valid_apl_ring_packet()
        assert pkt.validate_crcs() is True
        pkt.sequence_number += 1
        assert pkt.validate_crcs() is False

        pkt2 = create_valid_apl_ring_packet()
        pkt2.timestamp_us += 1
        assert pkt2.validate_crcs() is False

    def test_create_valid_packet_helper(self) -> None:
        """Validate create_valid_apl_ring_packet helper constructor and aliases."""
        p1 = create_valid_apl_ring_packet(b"\x55", sequence=4, port_id=PORT2_SECONDARY)
        assert p1.port_id == PORT2_SECONDARY
        assert p1.validate_crcs() is True

        p2 = create_valid_cip_apl_ring_packet(payload=b"\x66")
        assert p2.payload_bytes == b"\x66"
        assert p2.validate_crcs() is True


# ============================================================================
# 4. TestAplRingTopologyTrackingAndBeacons
# ============================================================================

class TestAplRingTopologyTrackingAndBeacons:
    """Validate ring topology state tracking, supervisor/client modes, and beacon interval."""

    def test_engine_supervisor_initialization(self) -> None:
        """Validate engine defaults for active supervisor."""
        eng = CIPAPLRingSafetyEngine(supervisor_role=SupervisorRole.ACTIVE_SUPERVISOR)
        assert eng.supervisor_role == SupervisorRole.ACTIVE_SUPERVISOR
        assert eng.ring_state == RingTopologyState.NORMAL_RING
        assert eng.beacon_interval_us == 400
        assert eng.beacon_timeout_us == 400
        assert eng.port1_link_quality == 100
        assert eng.port2_link_quality == 100
        assert eng.online is True
        assert eng.tripped is False

    def test_engine_non_supervisor_initialization(self) -> None:
        """Validate engine configuration for non-supervisor (client) node."""
        eng = CIPAPLRingSafetyEngine(supervisor_role=SupervisorRole.NON_SUPERVISOR)
        assert eng.supervisor_role == SupervisorRole.NON_SUPERVISOR
        assert eng.ring_state == RingTopologyState.NORMAL_RING

    def test_connect_and_disconnect_state_transitions(self) -> None:
        """Validate connect transitions to SUPERVISOR_ACTIVE and disconnect to LINEAR_TOPOLOGY."""
        eng = CIPAPLRingSafetyEngine(supervisor_role=SupervisorRole.ACTIVE_SUPERVISOR)
        eng.connect()
        assert eng.ring_state == RingTopologyState.SUPERVISOR_ACTIVE
        assert eng.online is True

        eng.disconnect()
        assert eng.ring_state == RingTopologyState.LINEAR_TOPOLOGY
        assert eng.online is False

    def test_beacon_timing_and_counters(self) -> None:
        """Validate beacon interval tracking and transmitted frame counters."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        assert eng.beacon_interval_us == 400

        pkt = eng.send_packet()
        assert eng.beacon_frames_sent == 1
        assert eng.tx_frame_count == 1
        assert eng.sequence_number == 1
        assert pkt.validate_crcs() is True

    def test_transition_count_monotonic_tracking(self) -> None:
        """Validate transition_count increments when ring topology changes."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        initial = eng.transition_count
        eng.inject_port_fault(1)
        assert eng.transition_count == initial + 1

    def test_packet_reception_updates_rx_counters(self) -> None:
        """Validate ingress packet processing increments rx_frame_count and resets beacon timer."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.beacon_timer_us = 200.0

        pkt = create_valid_apl_ring_packet(sequence=5)
        success = eng.receive_packet(pkt)
        assert success is True
        assert eng.rx_frame_count == 1
        assert eng.beacon_timer_us == 0.0


# ============================================================================
# 5. TestRingBreakDetectionAndFaultLocation
# ============================================================================

class TestRingBreakDetectionAndFaultLocation:
    """Validate single port break detection, transition to RING_FAULT (0xEE83), and fault localization."""

    def test_port1_break_triggers_ring_fault_0xEE83(self) -> None:
        """Validate Port 1 break triggers RING_FAULT, 0xEE83, and fault location 1."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_port_fault(1)
        assert eng.ring_state == RingTopologyState.RING_FAULT
        assert eng.diagnostic_code == DIAG_ERR_RING_FAULT_DETECTED
        assert eng.diagnostic_code == 0xEE83
        assert eng.fault_location == 1
        assert eng.port1_link_quality == 0
        assert eng.port2_link_quality == 100

    def test_port2_break_triggers_ring_fault_0xEE83(self) -> None:
        """Validate Port 2 break triggers RING_FAULT, 0xEE83, and fault location 2."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_port_fault(2)
        assert eng.ring_state == RingTopologyState.RING_FAULT
        assert eng.diagnostic_code == DIAG_ERR_RING_FAULT_DETECTED
        assert eng.diagnostic_code == 0xEE83
        assert eng.fault_location == 2
        assert eng.port1_link_quality == 100
        assert eng.port2_link_quality == 0

    def test_invalid_port_raises_value_error(self) -> None:
        """Validate that inject_port_fault rejects invalid port numbers."""
        eng = CIPAPLRingSafetyEngine()
        with pytest.raises(ValueError, match="Invalid port"):
            eng.inject_port_fault(3)

    def test_inject_ring_break_compatibility_alias(self) -> None:
        """Validate inject_ring_break helper defaults to Port 1 break."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_ring_break()
        assert eng.ring_state == RingTopologyState.RING_FAULT
        assert eng.diagnostic_code == DIAG_ERR_RING_FAULT_DETECTED
        assert eng.fault_location == 1

    def test_restore_ring_restores_closed_state(self) -> None:
        """Validate restore_ring clears faults and restores nominal topology."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_port_fault(1)
        eng.restore_ring()
        assert eng.diagnostic_code == DIAG_OK
        assert eng.fault_location == 0
        assert eng.port1_link_quality == 100
        assert eng.online is True

    def test_clear_fault_restores_healthy_supervisor(self) -> None:
        """Validate clear_fault restores SUPERVISOR_ACTIVE and resets timers."""
        eng = CIPAPLRingSafetyEngine(supervisor_role=SupervisorRole.ACTIVE_SUPERVISOR)
        eng.connect()
        eng.inject_port_fault(2)
        eng.clear_fault()
        assert eng.ring_state == RingTopologyState.SUPERVISOR_ACTIVE
        assert eng.diagnostic_code == DIAG_OK
        assert eng.online is True
        assert eng.tripped is False


# ============================================================================
# 6. TestDualPortLinkDownCriticalSafetyTrip
# ============================================================================

class TestDualPortLinkDownCriticalSafetyTrip:
    """Validate dual port PHY link down triggering critical SAFETY_TRIP (0xEE82)."""

    def test_dual_port_down_triggers_safety_trip_0xEE82(self) -> None:
        """Validate simultaneous failure of Port 1 and Port 2 trips 0xEE82."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_port_fault(1)
        eng.inject_port_fault(2)
        assert eng.ring_state == RingTopologyState.SAFETY_TRIP
        assert eng.diagnostic_code == DIAG_ERR_DUAL_PORT_LINK_DOWN
        assert eng.diagnostic_code == 0xEE82
        assert eng.fault_location == 3  # Both ports down
        assert eng.port1_link_quality == 0
        assert eng.port2_link_quality == 0

    def test_dual_port_down_deasserts_online_and_asserts_tripped(self) -> None:
        """Validate online becomes False and tripped becomes True on dual port loss."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_port_fault(1)
        eng.inject_port_fault(2)
        assert eng.online is False
        assert eng.is_online is False
        assert eng.tripped is True
        assert eng.is_tripped is True
        assert eng.is_safe_stop_tripped is True

    def test_dual_port_down_register_table_reflection(self) -> None:
        """Validate register table bit-exact reflection of dual port trip."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()
        eng.inject_port_fault(1)
        eng.inject_port_fault(2)
        eng.sync_to_registers(rt)

        assert (rt.read_word(REG_CIP_APL_RING_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE82
        assert rt.read_word(REG_CIP_APL_RING_FAULT_LOCATION) == 3
        assert rt.read_word(REG_CIP_APL_RING_PORT1_LINK_QUALITY) == 0
        assert rt.read_word(REG_CIP_APL_RING_PORT2_LINK_QUALITY) == 0
        assert rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is True
        assert rt.read_bit(COIL_CIP_APL_RING_ONLINE) is False

    def test_dual_port_down_recovery_via_clear_fault(self) -> None:
        """Validate clear_fault fully re-energizes both ports and resets trip."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_port_fault(1)
        eng.inject_port_fault(2)
        eng.clear_fault()
        assert eng.diagnostic_code == DIAG_OK
        assert eng.fault_location == 0
        assert eng.port1_link_quality == 100
        assert eng.port2_link_quality == 100
        assert eng.online is True
        assert eng.tripped is False


# ============================================================================
# 7. TestBeaconTimeoutSurveillanceAndTrip
# ============================================================================

class TestBeaconTimeoutSurveillanceAndTrip:
    """Validate beacon frame timeout surveillance (> 400 us loss) and trip 0xEE81."""

    def test_inject_beacon_timeout_trips_0xEE81(self) -> None:
        """Validate inject_beacon_timeout triggers SAFETY_TRIP and 0xEE81."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_beacon_timeout()
        assert eng.ring_state == RingTopologyState.SAFETY_TRIP
        assert eng.diagnostic_code == DIAG_ERR_BEACON_TIMEOUT
        assert eng.diagnostic_code == 0xEE81
        assert eng.online is False
        assert eng.tripped is True

    def test_scan_step_beacon_timeout_accumulation(self) -> None:
        """Validate scan_step accumulation exceeding 400 us triggers timeout trip."""
        eng = CIPAPLRingSafetyEngine(beacon_timeout_us=400)
        eng.connect()
        # Single cycle of 500 us (0.0005 s)
        res = eng.scan_step(dt=0.0005)
        assert res.status == AgentStatus.SUCCESS
        assert eng.diagnostic_code == DIAG_ERR_BEACON_TIMEOUT
        assert eng.ring_state == RingTopologyState.SAFETY_TRIP
        assert eng.tripped is True

    def test_continuous_packet_reception_prevents_beacon_timeout(self) -> None:
        """Validate that incoming valid packets reset beacon timer and prevent trip."""
        eng = CIPAPLRingSafetyEngine(beacon_timeout_us=400)
        eng.connect()
        for _ in range(10):
            pkt = eng.send_packet()
            eng.receive_packet(pkt)
            eng.scan_step(dt_us=100.0)
            assert eng.diagnostic_code == DIAG_OK
            assert eng.online is True

    def test_beacon_timeout_interlock_coils(self) -> None:
        """Validate coil assertion %M640 and de-assertion %M639 on beacon timeout."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()
        eng.inject_beacon_timeout()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is True
        assert rt.read_bit(COIL_CIP_APL_RING_ONLINE) is False
        assert (rt.read_word(REG_CIP_APL_RING_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE81

    def test_beacon_timeout_recovery_clears_timer(self) -> None:
        """Validate clear_fault clears beacon timer and restores online state."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_beacon_timeout()
        assert eng.beacon_timer_us > 400.0
        eng.clear_fault()
        assert eng.beacon_timer_us == 0.0
        assert eng.diagnostic_code == DIAG_OK
        assert eng.online is True


# ============================================================================
# 8. TestSupervisorCollisionPrecedenceConflict
# ============================================================================

class TestSupervisorCollisionPrecedenceConflict:
    """Validate multiple active supervisor collision and precedence conflict trip 0xEE85."""

    def test_inject_supervisor_collision_trips_0xEE85(self) -> None:
        """Validate inject_supervisor_collision triggers SAFETY_TRIP and 0xEE85."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_supervisor_collision()
        assert eng.ring_state == RingTopologyState.SAFETY_TRIP
        assert eng.diagnostic_code == DIAG_ERR_SUPERVISOR_COLLISION
        assert eng.diagnostic_code == 0xEE85
        assert eng.tripped is True

    def test_receive_packet_collision_from_higher_precedence_supervisor(self) -> None:
        """Validate ingress packet from another supervisor with equal or higher precedence trips 0xEE85."""
        eng = CIPAPLRingSafetyEngine(
            supervisor_role=SupervisorRole.ACTIVE_SUPERVISOR,
            supervisor_precedence=100,
            session_id=0x1111,
        )
        eng.connect()
        collision_pkt = create_valid_apl_ring_packet(
            session_id=0x2222,  # Different supervisor
            supervisor_precedence=150,  # Higher precedence
        )
        assert eng.receive_packet(collision_pkt) is False
        assert eng.diagnostic_code == DIAG_ERR_SUPERVISOR_COLLISION
        assert eng.ring_state == RingTopologyState.SAFETY_TRIP

    def test_receive_packet_same_session_no_collision(self) -> None:
        """Validate ingress packet from own supervisor session does not trip collision."""
        eng = CIPAPLRingSafetyEngine(
            supervisor_role=SupervisorRole.ACTIVE_SUPERVISOR,
            supervisor_precedence=100,
            session_id=0x1111,
        )
        eng.connect()
        own_pkt = create_valid_apl_ring_packet(
            session_id=0x1111,
            supervisor_precedence=100,
        )
        assert eng.receive_packet(own_pkt) is True
        assert eng.diagnostic_code == DIAG_OK

    def test_receive_packet_lower_precedence_no_collision(self) -> None:
        """Validate ingress packet with lower precedence supervisor does not trip active supervisor."""
        eng = CIPAPLRingSafetyEngine(
            supervisor_role=SupervisorRole.ACTIVE_SUPERVISOR,
            supervisor_precedence=100,
            session_id=0x1111,
        )
        eng.connect()
        sub_pkt = create_valid_apl_ring_packet(
            session_id=0x2222,
            supervisor_precedence=50,  # Lower precedence
        )
        assert eng.receive_packet(sub_pkt) is True
        assert eng.diagnostic_code == DIAG_OK

    def test_collision_recovery_via_clear_fault(self) -> None:
        """Validate recovery from collision fault restores healthy supervisor."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_supervisor_collision()
        eng.clear_fault()
        assert eng.diagnostic_code == DIAG_OK
        assert eng.online is True


# ============================================================================
# 9. TestCrcCorruptionInjectionAndTrip
# ============================================================================

class TestCrcCorruptionInjectionAndTrip:
    """Validate dual CRC corruption injection and trip 0xEE84."""

    def test_inject_crc_fault_trips_0xEE84(self) -> None:
        """Validate inject_crc_fault triggers SAFETY_TRIP and 0xEE84."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        eng.inject_crc_fault()
        assert eng.ring_state == RingTopologyState.SAFETY_TRIP
        assert eng.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert eng.diagnostic_code == 0xEE84
        assert eng.packet_loss_counter == 1
        assert eng.tripped is True

    def test_receive_packet_corrupted_crc_s1_fails(self) -> None:
        """Validate corrupted CRC-S1 in ingress packet is rejected and trips 0xEE84."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        pkt = create_valid_apl_ring_packet()
        pkt.crc_s1 ^= 0xFFFF
        assert eng.receive_packet(pkt) is False
        assert eng.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert eng.packet_loss_counter == 1

    def test_receive_packet_corrupted_crc_s2_fails(self) -> None:
        """Validate corrupted CRC-S2 in ingress packet is rejected and trips 0xEE84."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        pkt = create_valid_apl_ring_packet()
        pkt.crc_s2 ^= 0xFFFF
        assert eng.receive_packet(pkt) is False
        assert eng.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert eng.packet_loss_counter == 1

    def test_receive_packet_tampered_payload_fails(self) -> None:
        """Validate payload bit alteration without recomputing CRC is caught by receive_packet."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        pkt = create_valid_apl_ring_packet(b"\x01\x02\x03\x04")
        pkt.payload_bytes = b"\x01\x02\x03\x05"
        assert eng.receive_packet(pkt) is False
        assert eng.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT

    def test_crc_fault_packet_loss_counter_monotonic(self) -> None:
        """Validate packet_loss_counter increments on repeated CRC corruption."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        pkt = create_valid_apl_ring_packet()
        pkt.crc_s1 ^= 0x01
        eng.receive_packet(pkt)
        eng.receive_packet(pkt)
        eng.receive_packet(pkt)
        assert eng.packet_loss_counter == 3


# ============================================================================
# 10. TestSafeStopInterlockAndCoils
# ============================================================================

class TestSafeStopInterlockAndCoils:
    """Validate safe stop coil interlock (%M640 asserted, %M639 de-asserted) across all fault trips."""

    def test_healthy_baseline_coil_state(self) -> None:
        """Validate healthy baseline asserts %M639 and de-asserts %M640."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_RING_ONLINE) is True
        assert rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is False

    def test_safe_stop_interlock_beacon_timeout(self) -> None:
        """Validate beacon timeout trips %M640 and clears %M639."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()
        eng.inject_beacon_timeout()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_RING_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is True

    def test_safe_stop_interlock_dual_port_down(self) -> None:
        """Validate dual port down trips %M640 and clears %M639."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()
        eng.inject_port_fault(1)
        eng.inject_port_fault(2)
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_RING_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is True

    def test_safe_stop_interlock_ring_fault(self) -> None:
        """Validate single port ring break trips %M640 and clears %M639."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()
        eng.inject_port_fault(1)
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_RING_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is True

    def test_safe_stop_interlock_crc_fault(self) -> None:
        """Validate dual CRC corruption trips %M640 and clears %M639."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()
        eng.inject_crc_fault()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_RING_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is True

    def test_safe_stop_interlock_supervisor_collision(self) -> None:
        """Validate supervisor collision trips %M640 and clears %M639."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()
        eng.inject_supervisor_collision()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_RING_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is True

    def test_coil_mutual_exclusivity(self) -> None:
        """Validate %M639 and %M640 are never simultaneously True across state transitions."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()

        fault_triggers = [
            eng.inject_beacon_timeout,
            lambda: (eng.inject_port_fault(1), eng.inject_port_fault(2)),
            eng.inject_crc_fault,
            eng.inject_supervisor_collision,
            lambda: eng.inject_port_fault(1),
        ]
        for trigger in fault_triggers:
            trigger()
            eng.sync_to_registers(rt)
            b_online = rt.read_bit(COIL_CIP_APL_RING_ONLINE)
            b_trip = rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP)
            assert not (b_online and b_trip), "Safety invariant violated: both coils asserted simultaneously"
            eng.clear_fault()

    def test_fault_clearance_restores_healthy_coils(self) -> None:
        """Validate clear_fault re-asserts %M639 and de-asserts %M640."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()
        eng.inject_crc_fault()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is True

        eng.clear_fault()
        eng.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_RING_ONLINE) is True
        assert rt.read_bit(COIL_CIP_APL_RING_SAFETY_TRIP) is False


# ============================================================================
# 11. TestHornerRegisterTableSynchronization
# ============================================================================

class TestHornerRegisterTableSynchronization:
    """Validate bit-exact synchronization to Horner OCS registers (%R2740..%R2747, %M639..%M640)."""

    def test_healthy_register_sync(self) -> None:
        """Validate register sync in nominal healthy supervisor state."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()
        eng.sync_to_registers(rt)

        reg_status = rt.read_word(REG_CIP_APL_RING_STATUS) & 0xFFFF
        assert (reg_status >> 8) == int(RingTopologyState.SUPERVISOR_ACTIVE)
        assert (reg_status & 0xFF) == int(SupervisorRole.ACTIVE_SUPERVISOR)

        assert (rt.read_word(REG_CIP_APL_RING_SUPERVISOR_STATE) & 0xFFFF) == int(SupervisorRole.ACTIVE_SUPERVISOR)
        assert rt.read_word(REG_CIP_APL_RING_FAULT_LOCATION) == 0
        assert rt.read_word(REG_CIP_APL_RING_TRANSITION_COUNT) == 0
        assert rt.read_word(REG_CIP_APL_RING_BEACON_INTERVAL_US) == 400
        assert (rt.read_word(REG_CIP_APL_RING_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert rt.read_word(REG_CIP_APL_RING_PORT1_LINK_QUALITY) == 100
        assert rt.read_word(REG_CIP_APL_RING_PORT2_LINK_QUALITY) == 100

    def test_status_register_packing(self) -> None:
        """Validate %R2740 byte packing: high byte topology state, low byte supervisor role."""
        eng = CIPAPLRingSafetyEngine(
            ring_state=RingTopologyState.RING_FAULT,
            supervisor_role=SupervisorRole.NON_SUPERVISOR,
        )
        assert eng.status_register_value == ((int(RingTopologyState.RING_FAULT) << 8) | int(SupervisorRole.NON_SUPERVISOR))

    def test_diagnostic_code_register_sync_all_codes(self) -> None:
        """Validate %R2745 reflects all diagnostic error codes bit-exact."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        codes = [
            DIAG_ERR_BEACON_TIMEOUT,
            DIAG_ERR_DUAL_PORT_LINK_DOWN,
            DIAG_ERR_RING_FAULT_DETECTED,
            DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
            DIAG_ERR_SUPERVISOR_COLLISION,
        ]
        for c in codes:
            eng.trip_safety(c)
            eng.sync_to_registers(rt)
            assert (rt.read_word(REG_CIP_APL_RING_DIAGNOSTIC_CODE) & 0xFFFF) == int(c)

    def test_link_quality_registers_sync(self) -> None:
        """Validate %R2746 and %R2747 reflect port quality percentages."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.port1_link_quality = 85
        eng.port2_link_quality = 92
        eng.sync_to_registers(rt)
        assert rt.read_word(REG_CIP_APL_RING_PORT1_LINK_QUALITY) == 85
        assert rt.read_word(REG_CIP_APL_RING_PORT2_LINK_QUALITY) == 92

    def test_register_sync_privilege_modes(self) -> None:
        """Validate sync_to_registers works with both USER and SYSTEM privilege modes."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine()
        eng.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert (rt.read_word(REG_CIP_APL_RING_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert (rt.read_word(REG_CIP_APL_RING_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

    def test_safe_write_helpers(self) -> None:
        """Validate safe_write_word, safe_write_uword, and safe_write_bit helpers."""
        rt = RegisterTable()
        safe_write_word(rt, "%R2745", 0xEE81)
        assert (rt.read_word("%R2745") & 0xFFFF) == 0xEE81

        safe_write_uword(rt, "%R2744", 400)
        assert rt.read_word("%R2744") == 400

        safe_write_bit(rt, "%M639", True)
        assert rt.read_bit("%M639") is True
        safe_write_bit(rt, "%M639", False)
        assert rt.read_bit("%M639") is False


# ============================================================================
# 12. TestPureIEC61131StructuredTextAndSecurity
# ============================================================================

class TestPureIEC61131StructuredTextAndSecurity:
    """Validate pure ST POU CipSafetyAplRingSync and SecurityGuard anti-ladder rejection."""

    def test_st_program_constants_and_content(self) -> None:
        """Validate ST POU string definition, program name, and register bindings."""
        assert "PROGRAM CipSafetyAplRingSync" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        assert "%R2740" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        assert "%R2741" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        assert "%R2742" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        assert "%R2743" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        assert "%R2744" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        assert "%R2745" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        assert "%R2746" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        assert "%R2747" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        assert "%M639" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC
        assert "%M640" in ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC

    def test_verify_pure_st_function_returns_true(self) -> None:
        """Validate verify_cip_safety_apl_ring_pure_st validates AST and register bindings."""
        assert verify_cip_safety_apl_ring_pure_st() is True
        assert verify_apl_ring_pure_st() is True

    def test_st_parser_ast_pou_type_and_bound_registers(self) -> None:
        """Validate STParser generates PROGRAM AST and binds all 8 analog and 2 discrete registers."""
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2740", "%R2741", "%R2742", "%R2743",
            "%R2744", "%R2745", "%R2746", "%R2747",
            "%M639", "%M640",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_security_guard_assert_pure_st_content(self) -> None:
        """Validate SecurityGuard asserts valid pure ST without raising."""
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_RING_SYNC)

    def test_anti_ladder_contacts_rejection(self) -> None:
        """Validate rejection of normally open and normally closed ladder contacts."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR x : BOOL; END_VAR ---[ ]--- x; END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR x : BOOL; END_VAR ---[/]--- x; END_PROGRAM")

    def test_anti_ladder_coils_rejection(self) -> None:
        """Validate rejection of ladder normal, negated, set, and reset coils."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR y : BOOL; END_VAR ---( )--- y; END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR y : BOOL; END_VAR ---(/)--- y; END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR y : BOOL; END_VAR ---(S)--- y; END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR y : BOOL; END_VAR ---(R)--- y; END_PROGRAM")

    def test_anti_ladder_rungs_and_networks_rejection(self) -> None:
        """Validate rejection of ladder rung and network delimiters."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P RUNG 1 END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P NETWORK 10 END_PROGRAM")

    def test_anti_ladder_mnemonics_rejection(self) -> None:
        """Validate rejection of ladder mnemonics XIC, XIO, OTE, OTL, OTU."""
        mnemonics = ["XIC(StartPB);", "XIO(StopPB);", "OTE(MotorCoil);", "OTL(LatchCoil);", "OTU(UnlatchCoil);"]
        for m in mnemonics:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(f"PROGRAM P {m} END_PROGRAM")


# ============================================================================
# 13. TestILogicUnitComplianceAndSimulationSoak
# ============================================================================

class TestILogicUnitComplianceAndSimulationSoak:
    """Validate ILogicUnit interface compliance and 100-cycle simulation soak with memory check."""

    def test_ilogic_unit_properties(self) -> None:
        """Validate ILogicUnit interface properties on CIPAPLRingSafetyEngine."""
        eng = CIPAPLRingSafetyEngine()
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "CIPAPLRingSafetyEngine"
        assert eng.priority >= 1
        assert eng.is_enabled is True
        eng.is_enabled = False
        assert eng.is_enabled is False
        eng.is_enabled = True

    def test_scan_step_with_various_arguments(self) -> None:
        """Validate scan_step accepts variable argument formats (dt_s, dt_ms, dt_us, ScanContext)."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()

        res1 = eng.scan_step()
        assert res1.status == AgentStatus.SUCCESS

        res2 = eng.scan_step(dt=0.0004)
        assert res2.status == AgentStatus.SUCCESS

        res3 = eng.scan_step(dt_ms=0.4)
        assert res3.status == AgentStatus.SUCCESS

        res4 = eng.scan_step(dt_us=400.0)
        assert res4.status == AgentStatus.SUCCESS

        res5 = eng.scan_step(ScanContext(cycle=1, dt=0.0004))
        assert res5.status == AgentStatus.SUCCESS
        assert "ring_state" in res5.data

    def test_step_and_execute_aliases(self) -> None:
        """Validate step() and execute() aliases return ExecutionResult."""
        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        res_step = eng.step(dt=0.0004)
        assert res_step.status == AgentStatus.SUCCESS
        res_exec = eng.execute()
        assert res_exec.status == AgentStatus.SUCCESS

    def test_100_cycle_continuous_soak(self) -> None:
        """Validate 100 continuous simulation scan cycles with live packet exchange."""
        rt = RegisterTable()
        eng = CIPAPLRingSafetyEngine(register_table=rt)
        eng.connect()

        for cycle in range(1, 101):
            tx_pkt = eng.send_packet()
            eng.receive_packet(tx_pkt)
            res = eng.scan_step(dt=0.0004)
            assert res.status == AgentStatus.SUCCESS
            assert eng.online is True
            assert eng.tripped is False

        assert eng.tx_frame_count == 100
        assert eng.rx_frame_count == 100
        assert eng.packet_loss_counter == 0
        assert eng.diagnostic_code == DIAG_OK

    def test_soak_memory_growth_bounded(self) -> None:
        """Validate memory stability over 100 simulation cycles with tracemalloc."""
        tracemalloc.start()
        mem_start, _ = tracemalloc.get_traced_memory()

        eng = CIPAPLRingSafetyEngine()
        eng.connect()
        for _ in range(100):
            tx = eng.send_packet()
            eng.receive_packet(tx)
            eng.scan_step(dt=0.0004)

        mem_end, _ = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        heap_growth_kb = (mem_end - mem_start) / 1024.0
        assert heap_growth_kb < 1024.0, f"Excessive memory growth during soak: {heap_growth_kb:.2f} KB"


# ============================================================================
# 14. TestVerificationRunner9StagesAndCli
# ============================================================================

class TestVerificationRunner9StagesAndCli:
    """Validate run_cip_safety_apl_ring_verification 9-stage suite, 4-state contract, and evidence."""

    def test_runner_passes_all_9_stages(self) -> None:
        """Validate all 9 verification stages pass deterministically."""
        res = run_cip_safety_apl_ring_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9

    def test_runner_evidence_data_integrity(self) -> None:
        """Validate evidence dictionary metadata, work package, gate, and stages log."""
        res = run_cip_safety_apl_ring_verification()
        data = res["data"]
        assert data["work_package"] == "W313"
        assert data["gate"] == "G8"
        assert len(data["stages"]) == 9
        for s in data["stages"]:
            assert s["passed"] is True
            assert s["timing_ms"] >= 0.0

    def test_runner_no_file_written_when_output_path_is_none(self) -> None:
        """Validate that runner avoids disk writes when output_path is None."""
        res = run_cip_safety_apl_ring_verification(output_path=None)
        assert res["status"] == "success"

    def test_runner_writes_file_when_output_path_specified(self) -> None:
        """Validate runner writes valid JSON evidence file when output_path is provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "test_apl_ring_evidence.json"
            res = run_cip_safety_apl_ring_verification(output_path=ev_path)
            assert res["status"] == "success"
            assert ev_path.exists()
            with open(ev_path, encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["total_stages"] == 9

    def test_quick_mode_verification(self) -> None:
        """Validate quick mode executes and passes all stages."""
        res = run_cip_safety_apl_ring_verification(quick=True)
        assert res["status"] == "success"
        assert res["stages_passed"] == 9

    def test_module_cli_direct_execution(self) -> None:
        """Verify executing module CLI directly with tempfile output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "module_apl_ring_evidence.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "jev_cscape.telemetry.cip_safety_apl_ring",
                    "--output",
                    str(tmp_out),
                    "--quick",
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            assert proc.returncode == 0
            evidence = json.loads(proc.stdout)
            assert evidence["status"] == "success"
            assert tmp_out.exists()

    def test_script_runner_interop_cli(self) -> None:
        """Verify interop with scripts/run_cip_safety_apl_ring_verification.py CLI."""
        scripts_runner_path = Path(__file__).resolve().parent.parent / "scripts" / "run_cip_safety_apl_ring_verification.py"
        assert scripts_runner_path.exists()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "test_apl_ring_script_evidence.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(scripts_runner_path),
                    "--output",
                    str(tmp_out),
                    "--quick",
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            assert proc.returncode == 0
            evidence = json.loads(proc.stdout)
            assert evidence["status"] == "success"
            assert evidence["stages_passed"] == 9
            assert tmp_out.exists()

