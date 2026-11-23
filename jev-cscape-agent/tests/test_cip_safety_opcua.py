"""Comprehensive Unit Test Suite for Wave W262 CIP Safety Over OPC UA Part 15 Protocol Engine.

Work Package: W262 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety OPC UA Safety Part 15 / PubSub Interoperability for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 12 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit values, string representations,
   bitwise operations, hashing, enums, register names, coil addresses, and class IDs.
2. TestDualCrcAndSpduFraming: CRC-S1 (0x5935), CRC-S2 (0x755B), dual CRC verification, diversified sequence
   counters (~seq & 0xFFFF), frame serialization, and single-bit mutation corruption detection.
3. TestStateTransitions: Progression across OPCUASafetyState (IDLE -> RESOLVING -> CONNECTED -> OPERATIONAL -> SAFE_STOP),
   property setters, and recovery resets.
4. TestSpduCrcErrorTrip: Dual CRC corruption, sequence counter inversion failure, endpoint ID mismatch (0xEE41),
   register reflection, and recovery reset.
5. TestSafetyDelayTimeoutTrip: Safety transit delay watchdog surveillance, nominal tracking (1200 us),
   boundary limit (< 5000 us), trip threshold (>= 5000 us -> 0xEE42 SAFETY_DELAY_TIMEOUT), register reflection, and recovery reset.
6. TestNonceMismatchTrip: Challenge-response session nonce surveillance, rogue node rejection, replay attack detection
   (sequence <= last_seq -> 0xEE43 NONCE_MISMATCH), register reflection, and recovery reset.
7. TestPublisherOfflineTrip: Publisher heartbeat silence surveillance (< 50.0 ms), silence watchdog trip
   (>= 50.0 ms -> 0xEE44 PUBLISHER_OFFLINE), packet arrival timer reset, register reflection, and recovery reset.
8. TestRegisterSynchronization: %R2230..%R2237 and %M520..%M521 bit-exact synchronization, PrivilegeMode.SYSTEM,
   lost SPDU count (%R2234), TX packet count (%R2235), quality bits (%R2236), and safe write wrappers.
9. TestPureSTAndSecurity: STParser & SecurityGuard verification of CipSafetyOpcUaSync POU, AST variable memory_address
   and bound registers validation.
10. TestAntiLadderConstructRejection: Rejection of ladder logic constructs (contacts, coils, rungs, networks, mnemonics)
    with LadderForbiddenError.
11. TestILogicUnitComplianceAndSoak: ILogicUnit interface compliance (scan_step, step, execute, reset),
    properties validation, 100-cycle continuous soak simulation, and heap boundedness (< 100 KB growth).
12. TestExceptionsAndVerificationRunner: Exception inheritance hierarchy, 10-stage runner execution,
    strict 4-state contract validation, and evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_opcua import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    OPCUA_SAFETY_PART15_CLASS_ID,
    CIP_SAFETY_OPCUA_CLASS_ID,
    NOMINAL_OPCUA_SAFETY_CONSUMER_ID,
    DEFAULT_SAFETY_CONSUMER_ID,
    DEFAULT_CONSUMER_ID,
    NOMINAL_OPCUA_SAFETY_PROVIDER_ID,
    DEFAULT_SAFETY_PROVIDER_ID,
    DEFAULT_PROVIDER_ID,
    NOMINAL_OPCUA_SAFETY_DELAY_US,
    DEFAULT_SAFETY_DELAY_US,
    DEFAULT_DELAY_US,
    MIN_SAFETY_DELAY_US,
    MAX_ALLOWED_SAFETY_DELAY_US,
    SAFETY_DELAY_WATCHDOG_LIMIT_US,
    NOMINAL_OPCUA_SAFETY_LOST_SPDU_COUNT,
    DEFAULT_LOST_SPDU_COUNT,
    NOMINAL_OPCUA_SAFETY_TX_PACKET_COUNT,
    DEFAULT_TX_PACKET_COUNT,
    NOMINAL_OPCUA_SAFETY_QUALITY_BITS,
    DEFAULT_QUALITY_BITS,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    HEARTBEAT_TIMEOUT_MS,
    DEFAULT_SESSION_NONCE,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S_INIT,
    REG_OPCUA_SAFETY_LINK_STATE,
    REG_OPCUA_SAFETY_CONSUMER_ID,
    REG_OPCUA_SAFETY_PROVIDER_ID,
    REG_OPCUA_SAFETY_DELAY_US,
    REG_OPCUA_SAFETY_LOST_SPDU_COUNT,
    REG_OPCUA_SAFETY_TX_PACKET_COUNT,
    REG_OPCUA_SAFETY_QUALITY_BITS,
    REG_OPCUA_SAFETY_DIAGNOSTIC_CODE,
    COIL_OPCUA_SAFETY_LINK_HEALTHY,
    COIL_OPCUA_SAFETY_STOP_TRIPPED,
    REG_OPCUA_SAFETY_STATE,
    REG_OPCUA_LINK_STATE,
    REG_SAFETY_LINK_STATE,
    REG_OPCUA_STATE,
    REG_SAFETY_STATE,
    REG_SAFETY_CONSUMER_ID,
    REG_CONSUMER_ID,
    REG_SAFETY_PROVIDER_ID,
    REG_PROVIDER_ID,
    REG_SAFETY_DELAY_US,
    REG_OPCUA_DELAY_US,
    REG_SAFETY_DELAY,
    REG_DELAY_US,
    REG_LOST_SPDU_COUNT,
    REG_SAFETY_LOST_SPDU_COUNT,
    REG_LOST_SPDUS,
    REG_TX_PACKET_COUNT,
    REG_SAFETY_TX_PACKET_COUNT,
    REG_SAFETY_TX_COUNT,
    REG_TX_COUNT,
    REG_QUALITY_BITS,
    REG_SAFETY_QUALITY_BITS,
    REG_OPCUA_QUALITY_BITS,
    REG_SAFETY_DIAGNOSTIC_CODE,
    REG_OPCUA_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_DIAGNOSTIC_CODE,
    COIL_SAFETY_LINK_HEALTHY,
    COIL_OPCUA_LINK_HEALTHY,
    COIL_LINK_HEALTHY,
    COIL_OPCUA_HEALTHY,
    COIL_SAFETY_STOP_TRIPPED,
    COIL_OPCUA_STOP_TRIPPED,
    COIL_STOP_TRIPPED,
    COIL_OPCUA_SAFETY_TRIPPED,
    OPCUASafetyState,
    CIPSafetyOPCUAState,
    SafeOPCUAState,
    OpcUaSafetyState,
    CipSafetyOpcuaState,
    CipSafetyOpcUaState,
    SafetyLinkState,
    DiagnosticCode,
    DIAG_OK,
    DIAG_SPDU_CRC_ERROR,
    DIAG_SAFETY_DELAY_TIMEOUT,
    DIAG_NONCE_MISMATCH,
    DIAG_PUBLISHER_OFFLINE,
    DiagnosticStatusCode,
    CIPSafetyOPCUADiagnosticCode,
    OPCUASafetyDiagnosticCode,
    OpcUaSafetyDiagnosticCode,
    CipSafetyOpcuaDiagnosticCode,
    CIPSafetyOPCUAError,
    CipSafetyOpcuaError,
    OPCUASafetyError,
    SPDUCrcError,
    SpduCrcError,
    SafetyDelayTimeoutError,
    DelayTimeoutError,
    NonceMismatchError,
    ChallengeResponseError,
    PublisherOfflineError,
    ProviderOfflineError,
    CIP_SAFETY_OPCUA_PURE_ST_POU,
    CIP_SAFETY_OPCUA_SYNC_POU,
    CIP_SAFETY_OPCUA_POU,
    PURE_ST_POU,
    CipSafetyOpcUaSync,
    CipSafetyOpcuaSyncPOU,
    verify_cip_safety_opcua_pure_st,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    verify_dual_crc_s,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPSafetyOPCUASPDU,
    CipSafetyOpcuaSpdu,
    OPCUASafetySPDU,
    CIPSafetySPDU,
    PubSubSafetyPDU,
    SPDU,
    create_valid_spdu,
    create_valid_cip_safety_opcua_spdu,
    CIPSafetyOPCUAEngine,
    CipSafetyOpcuaEngine,
    CIPSafetyOpcUaEngine,
    CipSafetyOpcUaEngine,
    CIP_SAFETY_OPCUA_ENGINE,
    OPCUASafetyEngine,
    OpcUaSafetyEngine,
    run_cip_safety_opcua_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety OPC UA Part 15 constants, enums, register names, and diagnostic codes."""

    def test_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert OPCUA_SAFETY_PART15_CLASS_ID == 0x15
        assert CIP_SAFETY_OPCUA_CLASS_ID == 0x3F

    def test_crc_polynomial_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S_INIT == 0xFFFF

    def test_timing_and_nominal_defaults(self) -> None:
        assert NOMINAL_OPCUA_SAFETY_CONSUMER_ID == 101
        assert DEFAULT_SAFETY_CONSUMER_ID == 101
        assert DEFAULT_CONSUMER_ID == 101

        assert NOMINAL_OPCUA_SAFETY_PROVIDER_ID == 202
        assert DEFAULT_SAFETY_PROVIDER_ID == 202
        assert DEFAULT_PROVIDER_ID == 202

        assert NOMINAL_OPCUA_SAFETY_DELAY_US == 1200
        assert DEFAULT_SAFETY_DELAY_US == 1200
        assert DEFAULT_DELAY_US == 1200
        assert MIN_SAFETY_DELAY_US == 100
        assert MAX_ALLOWED_SAFETY_DELAY_US == 5000
        assert SAFETY_DELAY_WATCHDOG_LIMIT_US == 5000

        assert NOMINAL_OPCUA_SAFETY_LOST_SPDU_COUNT == 0
        assert DEFAULT_LOST_SPDU_COUNT == 0

        assert NOMINAL_OPCUA_SAFETY_TX_PACKET_COUNT == 100
        assert DEFAULT_TX_PACKET_COUNT == 100

        assert NOMINAL_OPCUA_SAFETY_QUALITY_BITS == 0x0003
        assert DEFAULT_QUALITY_BITS == 0x0003

        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 50.0
        assert HEARTBEAT_TIMEOUT_MS == 50.0
        assert DEFAULT_SESSION_NONCE == 0x1A2B3C4D

    def test_register_and_coil_constants(self) -> None:
        assert REG_OPCUA_SAFETY_LINK_STATE == "%R2230"
        assert REG_OPCUA_SAFETY_CONSUMER_ID == "%R2231"
        assert REG_OPCUA_SAFETY_PROVIDER_ID == "%R2232"
        assert REG_OPCUA_SAFETY_DELAY_US == "%R2233"
        assert REG_OPCUA_SAFETY_LOST_SPDU_COUNT == "%R2234"
        assert REG_OPCUA_SAFETY_TX_PACKET_COUNT == "%R2235"
        assert REG_OPCUA_SAFETY_QUALITY_BITS == "%R2236"
        assert REG_OPCUA_SAFETY_DIAGNOSTIC_CODE == "%R2237"

        assert COIL_OPCUA_SAFETY_LINK_HEALTHY == "%M520"
        assert COIL_OPCUA_SAFETY_STOP_TRIPPED == "%M521"

        # Verify aliases
        assert REG_OPCUA_SAFETY_STATE == "%R2230"
        assert REG_SAFETY_LINK_STATE == "%R2230"
        assert REG_SAFETY_CONSUMER_ID == "%R2231"
        assert REG_CONSUMER_ID == "%R2231"
        assert REG_SAFETY_PROVIDER_ID == "%R2232"
        assert REG_PROVIDER_ID == "%R2232"
        assert REG_DELAY_US == "%R2233"
        assert REG_LOST_SPDU_COUNT == "%R2234"
        assert REG_TX_PACKET_COUNT == "%R2235"
        assert REG_QUALITY_BITS == "%R2236"
        assert REG_DIAGNOSTIC_CODE == "%R2237"
        assert COIL_SAFETY_LINK_HEALTHY == "%M520"
        assert COIL_SAFETY_STOP_TRIPPED == "%M521"

    def test_diagnostic_code_values_and_representations(self) -> None:
        # DiagnosticCode.OK (0x0000)
        assert int(DiagnosticCode.OK) == 0x0000
        assert DiagnosticCode.OK == 0
        assert "0x0000" in str(DiagnosticCode.OK)
        assert "OK" in str(DiagnosticCode.OK)
        assert "0x0000" in repr(DiagnosticCode.OK)

        # DiagnosticCode.SPDU_CRC_ERROR (0xEE41 = 60993 unsigned, -4543 signed)
        assert int(DiagnosticCode.SPDU_CRC_ERROR) == 0xEE41
        assert DiagnosticCode.SPDU_CRC_ERROR == 0xEE41
        assert DiagnosticCode.SPDU_CRC_ERROR == 60993
        assert DiagnosticCode.SPDU_CRC_ERROR == -4543
        assert "0xEE41" in str(DiagnosticCode.SPDU_CRC_ERROR)
        assert "SPDU_CRC_ERROR" in str(DiagnosticCode.SPDU_CRC_ERROR)
        assert "0xEE41" in repr(DiagnosticCode.SPDU_CRC_ERROR)

        # DiagnosticCode.SAFETY_DELAY_TIMEOUT (0xEE42 = 60994 unsigned, -4542 signed)
        assert int(DiagnosticCode.SAFETY_DELAY_TIMEOUT) == 0xEE42
        assert DiagnosticCode.SAFETY_DELAY_TIMEOUT == 0xEE42
        assert DiagnosticCode.SAFETY_DELAY_TIMEOUT == 60994
        assert DiagnosticCode.SAFETY_DELAY_TIMEOUT == -4542
        assert "0xEE42" in str(DiagnosticCode.SAFETY_DELAY_TIMEOUT)
        assert "SAFETY_DELAY_TIMEOUT" in str(DiagnosticCode.SAFETY_DELAY_TIMEOUT)
        assert "0xEE42" in repr(DiagnosticCode.SAFETY_DELAY_TIMEOUT)

        # DiagnosticCode.NONCE_MISMATCH (0xEE43 = 60995 unsigned, -4541 signed)
        assert int(DiagnosticCode.NONCE_MISMATCH) == 0xEE43
        assert DiagnosticCode.NONCE_MISMATCH == 0xEE43
        assert DiagnosticCode.NONCE_MISMATCH == 60995
        assert DiagnosticCode.NONCE_MISMATCH == -4541
        assert "0xEE43" in str(DiagnosticCode.NONCE_MISMATCH)
        assert "NONCE_MISMATCH" in str(DiagnosticCode.NONCE_MISMATCH)
        assert "0xEE43" in repr(DiagnosticCode.NONCE_MISMATCH)

        # DiagnosticCode.PUBLISHER_OFFLINE (0xEE44 = 60996 unsigned, -4540 signed)
        assert int(DiagnosticCode.PUBLISHER_OFFLINE) == 0xEE44
        assert DiagnosticCode.PUBLISHER_OFFLINE == 0xEE44
        assert DiagnosticCode.PUBLISHER_OFFLINE == 60996
        assert DiagnosticCode.PUBLISHER_OFFLINE == -4540
        assert "0xEE44" in str(DiagnosticCode.PUBLISHER_OFFLINE)
        assert "PUBLISHER_OFFLINE" in str(DiagnosticCode.PUBLISHER_OFFLINE)
        assert "0xEE44" in repr(DiagnosticCode.PUBLISHER_OFFLINE)

    def test_diagnostic_code_bitwise_and_hashing(self) -> None:
        code = DiagnosticCode.SPDU_CRC_ERROR
        assert (code & 0xFFFF) == 0xEE41
        assert (code & 0xFF00) == 0xEE00
        assert (0xFFFF & code) == 0xEE41
        assert hash(code) == hash(0xEE41)

        code_set = {
            DiagnosticCode.OK,
            DiagnosticCode.SPDU_CRC_ERROR,
            DiagnosticCode.SAFETY_DELAY_TIMEOUT,
            DiagnosticCode.NONCE_MISMATCH,
            DiagnosticCode.PUBLISHER_OFFLINE,
        }
        assert len(code_set) == 5

    def test_diagnostic_code_aliases_and_module_exports(self) -> None:
        assert DIAG_OK == DiagnosticCode.OK
        assert DIAG_SPDU_CRC_ERROR == DiagnosticCode.SPDU_CRC_ERROR
        assert DIAG_SAFETY_DELAY_TIMEOUT == DiagnosticCode.SAFETY_DELAY_TIMEOUT
        assert DIAG_NONCE_MISMATCH == DiagnosticCode.NONCE_MISMATCH
        assert DIAG_PUBLISHER_OFFLINE == DiagnosticCode.PUBLISHER_OFFLINE

        assert DiagnosticCode.SAFETY_OK == DiagnosticCode.OK
        assert DiagnosticCode.OPCUA_OK == DiagnosticCode.OK
        assert DiagnosticCode.CRC_ERROR == DiagnosticCode.SPDU_CRC_ERROR
        assert DiagnosticCode.ERR_CRC == DiagnosticCode.SPDU_CRC_ERROR
        assert DiagnosticCode.DELAY_TIMEOUT == DiagnosticCode.SAFETY_DELAY_TIMEOUT
        assert DiagnosticCode.ERR_DELAY_TIMEOUT == DiagnosticCode.SAFETY_DELAY_TIMEOUT
        assert DiagnosticCode.NONCE_ERROR == DiagnosticCode.NONCE_MISMATCH
        assert DiagnosticCode.ERR_NONCE == DiagnosticCode.NONCE_MISMATCH
        assert DiagnosticCode.OFFLINE == DiagnosticCode.PUBLISHER_OFFLINE
        assert DiagnosticCode.ERR_OFFLINE == DiagnosticCode.PUBLISHER_OFFLINE

    def test_opcua_safety_state_enum(self) -> None:
        assert OPCUASafetyState.IDLE == 0
        assert OPCUASafetyState.PUBLISHER_RESOLVING == 1
        assert OPCUASafetyState.SUBSCRIBER_CONNECTED == 2
        assert OPCUASafetyState.SAFE_COMMUNICATION_OPERATIONAL == 3
        assert OPCUASafetyState.SAFE_STOP_TRIPPED == 4

        # Aliases
        assert OPCUASafetyState.RESOLVING == 1
        assert OPCUASafetyState.CONNECTED == 2
        assert OPCUASafetyState.OPERATIONAL == 3
        assert OPCUASafetyState.SAFE_STOP == 4
        assert OPCUASafetyState.TRIPPED == 4

        # Type aliases
        assert CIPSafetyOPCUAState is OPCUASafetyState
        assert SafeOPCUAState is OPCUASafetyState
        assert OpcUaSafetyState is OPCUASafetyState


# ============================================================================
# 2. TestDualCrcAndSpduFraming
# ============================================================================

class TestDualCrcAndSpduFraming:
    """Validate dual CRC-S1/S2 calculation, SPDU framing, sequence diversification, and mutation detection."""

    def test_compute_crc_s1_and_s2(self) -> None:
        sample = b"HornerOCS-OPCUA-Safety-SPDU-2026"
        c1 = compute_crc_s1(sample)
        c2 = compute_crc_s2(sample)

        assert isinstance(c1, int)
        assert isinstance(c2, int)
        assert 0 <= c1 <= 0xFFFF
        assert 0 <= c2 <= 0xFFFF
        assert c1 != c2
        assert calc_crc_s1(sample) == c1
        assert calc_crc_s2(sample) == c2

    def test_verify_dual_crc_s(self) -> None:
        data1 = b"SafeHeaderData1"
        data2 = b"SafeHeaderData2"
        c1 = compute_crc_s1(data1)
        c2 = compute_crc_s2(data2)

        assert verify_dual_crc_s(data1, data2, c1, c2) is True
        assert verify_dual_crc_s(data1, data2, c1 ^ 0x01, c2) is False
        assert verify_dual_crc_s(data1, data2, c1, c2 ^ 0x01) is False

    def test_spdu_construction_and_crc_calculation(self) -> None:
        spdu = CIPSafetyOPCUASPDU(
            consumer_id=101,
            provider_id=202,
            sequence_number=1,
            nonce=DEFAULT_SESSION_NONCE,
            safety_delay_us=1200,
            quality_bits=0x0003,
            safety_data=b"\x01\x02\x03\x04",
        )
        assert spdu.sequence_diversified == ((~1) & 0xFFFF)
        spdu.calculate_crcs()

        assert spdu.crc_s1 != 0
        assert spdu.crc_s2 != 0
        assert spdu.verify_crcs() is True
        assert spdu.verify_sequence() is True
        assert spdu.verify_nonce(DEFAULT_SESSION_NONCE) is True

    def test_spdu_single_bit_mutation_detection(self) -> None:
        spdu = create_valid_spdu(sequence_number=10, safety_data=b"\x10\x20\x30\x40")
        assert spdu.verify_crcs() is True

        # Mutate payload
        spdu.mutate_bit(byte_offset=1, bit_pos=3)
        assert spdu.verify_crcs() is False

    def test_spdu_sequence_inversion_verification(self) -> None:
        spdu = create_valid_spdu(sequence_number=42)
        assert spdu.sequence_diversified == ((~42) & 0xFFFF)
        assert spdu.verify_sequence() is True

        # Corrupt diversified sequence
        spdu.sequence_diversified = 42
        assert spdu.verify_sequence() is False

    def test_spdu_binary_serialization_and_deserialization_roundtrip(self) -> None:
        spdu = create_valid_spdu(
            consumer_id=101,
            provider_id=202,
            sequence_number=77,
            nonce=0xCAFE1234,
            safety_delay_us=1450,
            quality_bits=0x0003,
            safety_data=b"\xDE\xAD\xBE\xEF\x00\xFF",
        )
        raw_bytes = spdu.serialize()
        assert isinstance(raw_bytes, bytes)
        assert len(raw_bytes) > 0

        deser = CIPSafetyOPCUASPDU.deserialize(raw_bytes)
        assert deser.consumer_id == 101
        assert deser.provider_id == 202
        assert deser.sequence_number == 77
        assert deser.nonce == 0xCAFE1234
        assert deser.safety_delay_us == 1450
        assert deser.quality_bits == 0x0003
        assert deser.safety_data == b"\xDE\xAD\xBE\xEF\x00\xFF"
        assert deser.crc_s1 == spdu.crc_s1
        assert deser.crc_s2 == spdu.crc_s2
        assert deser.verify_crcs() is True
        assert deser.verify_sequence() is True


# ============================================================================
# 3. TestStateTransitions
# ============================================================================

class TestStateTransitions:
    """Validate OPC UA Safety Consumer/Provider state transitions: IDLE -> RESOLVING -> CONNECTED -> OPERATIONAL -> SAFE_STOP."""

    def test_nominal_state_progression(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=False)

        # 1. Starts in IDLE
        assert engine.state == OPCUASafetyState.IDLE
        assert engine.link_healthy is False
        assert engine.stop_tripped is False
        assert rt.read_word("%R2230") == 0
        assert rt.read_bit("%M520") is False

        # 2. Resolve publisher -> PUBLISHER_RESOLVING (1)
        res_res = engine.resolve_publisher("opc.tcp://192.168.1.100:4840")
        assert res_res is True
        assert engine.state == OPCUASafetyState.PUBLISHER_RESOLVING
        assert engine.state == OPCUASafetyState.RESOLVING
        assert rt.read_word("%R2230") == 1
        assert rt.read_bit("%M520") is False

        # 3. Connect subscriber -> SUBSCRIBER_CONNECTED (2)
        res_conn = engine.connect_subscriber(session_nonce=0x98765432)
        assert res_conn is True
        assert engine.state == OPCUASafetyState.SUBSCRIBER_CONNECTED
        assert engine.state == OPCUASafetyState.CONNECTED
        assert engine.session_nonce == 0x98765432
        assert rt.read_word("%R2230") == 2
        assert rt.read_bit("%M520") is False

        # 4. Enter operational -> SAFE_COMMUNICATION_OPERATIONAL (3)
        res_op = engine.enter_operational()
        assert res_op is True
        assert engine.state == OPCUASafetyState.SAFE_COMMUNICATION_OPERATIONAL
        assert engine.state == OPCUASafetyState.OPERATIONAL
        assert engine.link_healthy is True
        assert engine.is_healthy is True
        assert engine.stop_tripped is False
        assert rt.read_word("%R2230") == 3
        assert rt.read_bit("%M520") is True
        assert rt.read_bit("%M521") is False

        # 5. Fault trip -> SAFE_STOP_TRIPPED (4)
        engine.trip_fault(DiagnosticCode.SPDU_CRC_ERROR)
        assert engine.state == OPCUASafetyState.SAFE_STOP_TRIPPED
        assert engine.state == OPCUASafetyState.SAFE_STOP
        assert engine.link_healthy is False
        assert engine.is_healthy is False
        assert engine.stop_tripped is True
        assert rt.read_word("%R2230") == 4
        assert rt.read_bit("%M520") is False
        assert rt.read_bit("%M521") is True

    def test_state_setters_and_aliases(self) -> None:
        engine = CIPSafetyOPCUAEngine(auto_activate=True)
        assert engine.state == OPCUASafetyState.SAFE_COMMUNICATION_OPERATIONAL

        engine.state = OPCUASafetyState.IDLE
        assert engine.state == OPCUASafetyState.IDLE
        assert engine.safety_state == OPCUASafetyState.IDLE
        assert engine.link_state == OPCUASafetyState.IDLE

        engine.safety_state = OPCUASafetyState.PUBLISHER_RESOLVING
        assert engine.state == OPCUASafetyState.PUBLISHER_RESOLVING

        engine.link_state = OPCUASafetyState.SUBSCRIBER_CONNECTED
        assert engine.state == OPCUASafetyState.SUBSCRIBER_CONNECTED

    def test_transitions_blocked_when_tripped(self) -> None:
        engine = CIPSafetyOPCUAEngine(auto_activate=True)
        engine.trip_fault(DiagnosticCode.SAFETY_DELAY_TIMEOUT)
        assert engine.stop_tripped is True

        # State transitions blocked until reset
        assert engine.resolve_publisher() is False
        assert engine.connect_subscriber() is False
        assert engine.enter_operational() is False

        # Reset allows recovery
        engine.reset()
        assert engine.stop_tripped is False
        assert engine.state == OPCUASafetyState.SAFE_COMMUNICATION_OPERATIONAL


# ============================================================================
# 4. TestSpduCrcErrorTrip
# ============================================================================

class TestSpduCrcErrorTrip:
    """Validate SPDU dual CRC-S corruption, sequence counter inversion failure, and 0xEE41 trip."""

    def test_corrupted_spdu_crc_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        spdu = engine.create_spdu(safety_data=b"\x01\x02\x03\x04")
        spdu.mutate_bit(byte_offset=0, bit_pos=1)

        result = engine.process_incoming_spdu(spdu)
        assert result is False
        assert engine.diagnostic_code == DiagnosticCode.SPDU_CRC_ERROR
        assert engine.diagnostic_code == 0xEE41
        assert engine.state == OPCUASafetyState.SAFE_STOP_TRIPPED
        assert engine.link_healthy is False
        assert engine.stop_tripped is True
        assert engine.lost_spdu_count == 1

        assert rt.read_word("%R2230") == 4
        assert rt.read_uword("%R2237") == 0xEE41
        assert rt.read_bit("%M520") is False
        assert rt.read_bit("%M521") is True

    def test_diversified_sequence_counter_corruption_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        spdu = engine.create_spdu(seq=10)
        spdu.sequence_diversified = 10  # Corrupt diversified sequence

        result = engine.process_incoming_spdu(spdu)
        assert result is False
        assert engine.diagnostic_code == DiagnosticCode.SPDU_CRC_ERROR
        assert engine.diagnostic_code == 0xEE41
        assert engine.stop_tripped is True
        assert rt.read_uword("%R2237") == 0xEE41

    def test_endpoint_id_mismatch_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        spdu = engine.create_spdu(consumer_id=999)  # Wrong consumer ID

        result = engine.process_incoming_spdu(spdu)
        assert result is False
        assert engine.diagnostic_code == DiagnosticCode.SPDU_CRC_ERROR
        assert engine.diagnostic_code == 0xEE41
        assert engine.stop_tripped is True

    def test_direct_trip_spdu_crc_error(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        engine.trip_spdu_crc_error("Test manual trip")
        assert engine.diagnostic_code == 0xEE41
        assert engine.stop_tripped is True
        assert rt.read_uword("%R2237") == 0xEE41

        # Operator reset
        engine.reset()
        assert engine.diagnostic_code == 0x0000
        assert engine.stop_tripped is False
        assert rt.read_uword("%R2237") == 0x0000


# ============================================================================
# 5. TestSafetyDelayTimeoutTrip
# ============================================================================

class TestSafetyDelayTimeoutTrip:
    """Validate safety delay threshold surveillance and 0xEE42 trip."""

    def test_delay_overrun_packet_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        # Send SPDU with delay exceeding 5000 us limit
        bad_delay_spdu = engine.create_spdu(delay_us=5500)
        result = engine.process_incoming_spdu(bad_delay_spdu)

        assert result is False
        assert engine.diagnostic_code == DiagnosticCode.SAFETY_DELAY_TIMEOUT
        assert engine.diagnostic_code == 0xEE42
        assert engine.state == OPCUASafetyState.SAFE_STOP_TRIPPED
        assert engine.stop_tripped is True
        assert engine.delay_us == 5500

        assert rt.read_word("%R2230") == 4
        assert rt.read_word("%R2233") == 5500
        assert rt.read_uword("%R2237") == 0xEE42
        assert rt.read_bit("%M520") is False
        assert rt.read_bit("%M521") is True

    def test_update_safety_delay_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        # Nominal update
        engine.update_safety_delay(1500)
        assert engine.delay_us == 1500
        assert engine.diagnostic_code == 0x0000
        assert rt.read_word("%R2233") == 1500

        # Trip update >= 5000 us
        engine.update_safety_delay(5000)
        assert engine.diagnostic_code == 0xEE42
        assert engine.stop_tripped is True
        assert rt.read_uword("%R2237") == 0xEE42

    def test_direct_trip_safety_delay_timeout_and_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        engine.trip_safety_delay_timeout("Delay watchdog timeout")
        assert engine.diagnostic_code == 0xEE42
        assert engine.stop_tripped is True
        assert rt.read_uword("%R2237") == 0xEE42

        engine.reset()
        assert engine.diagnostic_code == 0x0000
        assert engine.delay_us == NOMINAL_OPCUA_SAFETY_DELAY_US
        assert engine.stop_tripped is False
        assert rt.read_uword("%R2237") == 0x0000


# ============================================================================
# 6. TestNonceMismatchTrip
# ============================================================================

class TestNonceMismatchTrip:
    """Validate challenge-response session nonce surveillance, replay detection, and 0xEE43 trip."""

    def test_nonce_mismatch_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        # SPDU with rogue session nonce
        rogue_spdu = engine.create_spdu(nonce=0xDEADBEEF)
        result = engine.process_incoming_spdu(rogue_spdu)

        assert result is False
        assert engine.diagnostic_code == DiagnosticCode.NONCE_MISMATCH
        assert engine.diagnostic_code == 0xEE43
        assert engine.state == OPCUASafetyState.SAFE_STOP_TRIPPED
        assert engine.stop_tripped is True
        assert engine.lost_spdu_count == 1

        assert rt.read_word("%R2230") == 4
        assert rt.read_uword("%R2237") == 0xEE43
        assert rt.read_bit("%M520") is False
        assert rt.read_bit("%M521") is True

    def test_replay_attack_sequence_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        # Process first valid packet (sequence 10)
        pkt1 = engine.create_spdu(seq=10)
        assert engine.process_incoming_spdu(pkt1) is True

        # Replay same packet (sequence 10 <= 10)
        replay_pkt = engine.create_spdu(seq=10)
        result = engine.process_incoming_spdu(replay_pkt)

        assert result is False
        assert engine.diagnostic_code == DiagnosticCode.NONCE_MISMATCH
        assert engine.diagnostic_code == 0xEE43
        assert engine.stop_tripped is True
        assert rt.read_uword("%R2237") == 0xEE43

    def test_direct_trip_nonce_mismatch_and_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        engine.trip_nonce_mismatch("Nonce mismatch simulated")
        assert engine.diagnostic_code == 0xEE43
        assert engine.stop_tripped is True
        assert rt.read_uword("%R2237") == 0xEE43

        engine.reset()
        assert engine.diagnostic_code == 0x0000
        assert engine.stop_tripped is False
        assert rt.read_uword("%R2237") == 0x0000


# ============================================================================
# 7. TestPublisherOfflineTrip
# ============================================================================

class TestPublisherOfflineTrip:
    """Validate publisher heartbeat silence surveillance (< 50.0 ms) and 0xEE44 trip."""

    def test_publisher_heartbeat_silence_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(
            register_table=rt,
            auto_activate=True,
            watchdog_timeout_ms=50.0,
        )

        # Execute 40 ms of scan cycles (below 50 ms limit)
        for _ in range(40):
            engine.scan_step(0.001)

        assert engine.state == OPCUASafetyState.SAFE_COMMUNICATION_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.stop_tripped is False

        # Execute 15 ms more (total 55 ms >= 50 ms timeout)
        for _ in range(15):
            engine.scan_step(0.001)

        assert engine.state == OPCUASafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == DiagnosticCode.PUBLISHER_OFFLINE
        assert engine.diagnostic_code == 0xEE44
        assert engine.stop_tripped is True
        assert engine.link_healthy is False

        assert rt.read_word("%R2230") == 4
        assert rt.read_uword("%R2237") == 0xEE44
        assert rt.read_bit("%M520") is False
        assert rt.read_bit("%M521") is True

    def test_incoming_packet_resets_silence_timer(self) -> None:
        engine = CIPSafetyOPCUAEngine(auto_activate=True, watchdog_timeout_ms=50.0)

        # Advance 30 ms
        for _ in range(30):
            engine.scan_step(0.001)

        # Send packet to refresh heartbeat
        pkt = engine.create_spdu(seq=1)
        assert engine.process_incoming_spdu(pkt) is True
        assert engine._time_since_last_spdu_ms == 0.0

        # Advance another 30 ms (total 60 ms elapsed, but only 30 ms since last packet)
        for _ in range(30):
            engine.scan_step(0.001)

        assert engine.state == OPCUASafetyState.SAFE_COMMUNICATION_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.stop_tripped is False

    def test_direct_trip_publisher_offline_and_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        engine.trip_publisher_offline("Publisher silence timeout")
        assert engine.diagnostic_code == 0xEE44
        assert engine.stop_tripped is True
        assert rt.read_uword("%R2237") == 0xEE44

        engine.reset()
        assert engine.diagnostic_code == 0x0000
        assert engine.stop_tripped is False
        assert rt.read_uword("%R2237") == 0x0000


# ============================================================================
# 8. TestRegisterSynchronization
# ============================================================================

class TestRegisterSynchronization:
    """Validate Horner OCS register space %R2230..%R2237 and %M520..%M521 synchronization."""

    def test_nominal_register_table_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        assert rt.read_word("%R2230") == 3
        assert rt.read_word("%R2231") == 101
        assert rt.read_word("%R2232") == 202
        assert rt.read_word("%R2233") == 1200
        assert rt.read_word("%R2234") == 0
        assert rt.read_word("%R2235") == 100
        assert rt.read_uword("%R2236") == 0x0003
        assert rt.read_uword("%R2237") == 0x0000
        assert rt.read_bit("%M520") is True
        assert rt.read_bit("%M521") is False

    def test_sequential_diagnostic_trips_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        trips = [
            (DiagnosticCode.SPDU_CRC_ERROR, 0xEE41),
            (DiagnosticCode.SAFETY_DELAY_TIMEOUT, 0xEE42),
            (DiagnosticCode.NONCE_MISMATCH, 0xEE43),
            (DiagnosticCode.PUBLISHER_OFFLINE, 0xEE44),
        ]

        for code, expected_hex in trips:
            engine.trip_fault(code)
            assert rt.read_word("%R2230") == 4
            assert rt.read_uword("%R2237") == expected_hex
            assert rt.read_bit("%M520") is False
            assert rt.read_bit("%M521") is True

            engine.reset()
            assert rt.read_word("%R2230") == 3
            assert rt.read_uword("%R2237") == 0x0000
            assert rt.read_bit("%M520") is True
            assert rt.read_bit("%M521") is False

    def test_property_setters_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        engine.consumer_id = 303
        assert rt.read_word("%R2231") == 303

        engine.provider_id = 404
        assert rt.read_word("%R2232") == 404

        engine.delay_us = 1600
        assert rt.read_word("%R2233") == 1600

        engine.lost_spdu_count = 5
        assert rt.read_word("%R2234") == 5

        engine.tx_packet_count = 250
        assert rt.read_word("%R2235") == 250

        engine.quality_bits = 0x0007
        assert rt.read_uword("%R2236") == 0x0007

    def test_safe_write_wrappers(self) -> None:
        rt = RegisterTable()

        # Word wrapping test (> 32767 wraps to negative signed)
        safe_write_word(rt, "%R2230", 40000)
        assert rt.read_word("%R2230") == 40000 - 65536

        # UWord test
        safe_write_uword(rt, "%R2237", 0xEE41)
        assert rt.read_uword("%R2237") == 0xEE41

        # Bit test
        safe_write_bit(rt, "%M520", True)
        assert rt.read_bit("%M520") is True
        safe_write_bit(rt, "%M520", False)
        assert rt.read_bit("%M520") is False


# ============================================================================
# 9. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 ST POU verification with SecurityGuard and STParser."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_cip_safety_opcua_pure_st() is True
        assert verify_cip_safety_opcua_pure_st(CIP_SAFETY_OPCUA_PURE_ST_POU) is True
        assert verify_cip_safety_opcua_pure_st(CIP_SAFETY_OPCUA_SYNC_POU) is True
        assert verify_cip_safety_opcua_pure_st(CIP_SAFETY_OPCUA_POU) is True
        assert verify_cip_safety_opcua_pure_st(PURE_ST_POU) is True
        assert verify_cip_safety_opcua_pure_st(CipSafetyOpcUaSync) is True
        assert verify_cip_safety_opcua_pure_st(CipSafetyOpcuaSyncPOU) is True

    def test_security_guard_and_st_parser(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_OPCUA_PURE_ST_POU)
        res = STParser.validate_code(CIP_SAFETY_OPCUA_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CIP_SAFETY_OPCUA_PURE_ST_POU)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2230", "%R2231", "%R2232", "%R2233",
            "%R2234", "%R2235", "%R2236", "%R2237",
            "%M520", "%M521",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_ast_variable_memory_address_mappings(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_OPCUA_PURE_ST_POU)
        var_map = {
            v.name: getattr(v, "memory_address", getattr(v, "address_binding", None))
            for v in ast.variables
        }

        assert var_map["LinkState"] == "%R2230"
        assert var_map["ConsumerId"] == "%R2231"
        assert var_map["ProviderId"] == "%R2232"
        assert var_map["DelayUs"] == "%R2233"
        assert var_map["LostSpduCount"] == "%R2234"
        assert var_map["TxPacketCount"] == "%R2235"
        assert var_map["QualityBits"] == "%R2236"
        assert var_map["DiagnosticCode"] == "%R2237"
        assert var_map["LinkHealthy"] == "%M520"
        assert var_map["StopTripped"] == "%M521"

    def test_invalid_pou_fails_verification(self) -> None:
        invalid_pou = "PROGRAM CorruptPOU VAR X : INT; END_VAR X := 10; END_PROGRAM"
        assert verify_cip_safety_opcua_pure_st(invalid_pou) is False


# ============================================================================
# 10. TestAntiLadderConstructRejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Verify security guard immediately rejects ladder constructs with LadderForbiddenError."""

    @pytest.mark.parametrize(
        "construct",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(S)---",
            "---(R)---",
            "RUNG 10",
            "NETWORK 1",
            "XIC(Channel1);",
            "OTE(Coil1);",
            "OTL(Latch1);",
            "OTU(Unlatch1);",
        ],
    )
    def test_ladder_constructs_rejected(self, construct: str) -> None:
        snippet = f"PROGRAM TestLadder\n VAR b : BOOL; END_VAR\n {construct}\n END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 11. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Verify ILogicUnit compliance: properties, scan_step, step, execute, reset, and 100-cycle soak."""

    def test_ilogicunit_interface_properties(self) -> None:
        engine = CIPSafetyOPCUAEngine(auto_activate=True)
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "CIPSafetyOPCUAEngine"
        assert engine.priority == 10
        assert engine.is_enabled is True
        assert engine.is_healthy is True
        assert engine.is_tripped is False
        assert engine.state == OPCUASafetyState.SAFE_COMMUNICATION_OPERATIONAL

    def test_scan_step_and_step(self) -> None:
        engine = CIPSafetyOPCUAEngine(auto_activate=True)
        assert engine.cycles_count == 0
        engine.scan_step(0.001)
        assert engine.cycles_count == 1

        engine.step(0.001)
        assert engine.cycles_count == 2

    def test_execute_scan_context(self) -> None:
        engine = CIPSafetyOPCUAEngine(auto_activate=True)
        ctx = ScanContext(cycle=1, dt_ms=1.0)
        engine.execute(ctx)
        assert engine.cycles_count == 1

    def test_100_cycle_soak_stability(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyOPCUAEngine(register_table=rt, auto_activate=True)

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        for cycle_i in range(1, 101):
            pkt = engine.create_spdu(seq=cycle_i)
            engine.process_incoming_spdu(pkt)
            engine.scan_step(0.001)

        snapshot_after = tracemalloc.take_snapshot()
        stats = snapshot_after.compare_to(snapshot_before, "lineno")
        heap_growth_kb = sum(st.size_diff for st in stats if st.size_diff > 0) / 1024.0
        tracemalloc.stop()

        assert engine.cycles_count == 100
        assert heap_growth_kb < 100.0
        assert engine.state == OPCUASafetyState.SAFE_COMMUNICATION_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.link_healthy is True
        assert engine.stop_tripped is False
        assert rt.read_word("%R2230") == 3
        assert rt.read_uword("%R2237") == 0x0000


# ============================================================================
# 12. TestExceptionsAndVerificationRunner
# ============================================================================

class TestExceptionsAndVerificationRunner:
    """Verify custom exception inheritance, 10-stage verification runner, and strict 4-state contract."""

    def test_exception_inheritance_hierarchy(self) -> None:
        assert issubclass(SPDUCrcError, CIPSafetyOPCUAError)
        assert issubclass(SafetyDelayTimeoutError, CIPSafetyOPCUAError)
        assert issubclass(NonceMismatchError, CIPSafetyOPCUAError)
        assert issubclass(PublisherOfflineError, CIPSafetyOPCUAError)
        assert issubclass(CIPSafetyOPCUAError, Exception)

        # Aliases
        assert SpduCrcError is SPDUCrcError
        assert DelayTimeoutError is SafetyDelayTimeoutError
        assert ChallengeResponseError is NonceMismatchError
        assert ProviderOfflineError is PublisherOfflineError

    def test_verification_runner_execution(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name

        try:
            result = run_cip_safety_opcua_verification(output_path=temp_path)
            assert isinstance(result, dict)
            assert result["status"] == "success"
            assert result["error_code"] is None
            assert result["stages_passed"] == 10
            assert result["total_stages"] == 10
            assert result["work_package"] == "W262"

            # Verify saved JSON evidence
            with open(temp_path, "r", encoding="utf-8") as f:
                saved_evidence = json.load(f)
            assert saved_evidence["status"] == "success"
            assert saved_evidence["stages_passed"] == 10
        finally:
            Path(temp_path).unlink(missing_ok=True)
