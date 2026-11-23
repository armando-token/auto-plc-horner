"""Comprehensive Unit and Integration Test Suite for SERCOS III Optical Dual-Ring Protocol Engine.

Work Package: W145 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Architectural Alignment (following tests/test_devicenet_safety.py):
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1060..%R1067, %M247..%M248).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Phase progression state machine (CP0->CP1->CP2->CP3->CP4) and invalid transition rejection.
4. Section 4: Optical dual-ring topology, cable break detection, and seamless loopback recovery (< 25 µs).
5. Section 5: Master Synchronization Telegram (MST) sub-microsecond jitter tracking (< 100 ns).
6. Section 6: Process safety trips (0xAA01, 0xAA02, 0xAA03, 0xAA04) and Horner coil assertion (%M247, %M248).
7. Section 7: Horner OCS register space synchronization (%R1060..%R1067, %M247..%M248).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import struct
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.sercos3_ring import (
    PURE_ST_POU,
    SERCOS3_AT_HDR_SIZE,
    SERCOS3_AT_RECORD_SIZE,
    SERCOS3_DEFAULT_CYCLE_TIME_US,
    SERCOS3_DEFAULT_OPTICAL_POWER_DBM,
    SERCOS3_ETHERTYPE,
    SERCOS3_JITTER_THRESHOLD_NS,
    SERCOS3_LOOPBACK_MAX_TIME_US,
    SERCOS3_LOSS_OF_LIGHT_THRESHOLD_DBM,
    SERCOS3_MAX_DRIVES,
    SERCOS3_MAX_SLAVES,
    SERCOS3_MDT_HDR_SIZE,
    SERCOS3_MDT_RECORD_SIZE,
    SERCOS3_MST_SIZE,
    SERCOS3_PURE_ST_POU,
    SERCOS3_RING_PURE_ST_POU,
    SERCOS3_RING_SYNC_POU,
    SERCOS3_SPEED_BPS,
    SERCOS_III_REDUNDANCY_SYNC_POU,
    Sercos3ATRecord,
    Sercos3ATTelegram,
    Sercos3CommunicationPhase,
    Sercos3DiagnosticCode,
    Sercos3DriveDescriptor,
    Sercos3DriveOpMode,
    Sercos3MDTRecord,
    Sercos3MDTTelegram,
    Sercos3MSTTelegram,
    Sercos3OpticalPort,
    Sercos3OpticalRingRedundancyManager,
    Sercos3RingMasterEngine,
    Sercos3RingStatusBits,
    Sercos3RingTopology,
    Sercos3StatusBits,
    Sercos3TelegramType,
    run_sercos3_ring_verification,
    scale_axis_position_to_int16,
    verify_sercos3_ring_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def sercos_master(register_table: RegisterTable) -> Sercos3RingMasterEngine:
    """Provides a fresh Sercos3RingMasterEngine with 4 configured optical servo drives."""
    engine = Sercos3RingMasterEngine(
        reg_table=register_table,
        cycle_time_us=SERCOS3_DEFAULT_CYCLE_TIME_US,
    )
    for i in range(1, 5):
        engine.configure_drive(
            Sercos3DriveDescriptor(drive_address=i, drive_name=f"OpticalAxis_{i}")
        )
    return engine


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================


class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Structured Text POUs and AST symbol binding."""

    def test_verify_sercos3_ring_pure_st_function(self) -> None:
        """Verify helper function passes cleanly."""
        assert verify_sercos3_ring_pure_st() is True

    def test_pure_st_sercos3_sync_ast_parsing(self) -> None:
        """Parse SERCOS3_RING_SYNC_POU and assert AST attributes and register bindings."""
        SecurityGuard.assert_pure_st_content(SERCOS3_RING_SYNC_POU)
        res = STParser.validate_code(SERCOS3_RING_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(SERCOS3_RING_SYNC_POU)
        assert ast is not None
        assert ast.name == "Sercos3RingSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1060", "%R1061", "%R1062", "%R1063",
            "%R1064", "%R1065", "%R1066", "%R1067",
            "%M247", "%M248",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "CommunicationPhase",
            "RingStatusWord",
            "CycleTimeMicroseconds",
            "MstSyncJitterNanoseconds",
            "MDTTelegramCounter",
            "ATTelegramCounter",
            "RingBreakRecoveryTimeMicroseconds",
            "DiagnosticStatusCode",
            "Sercos3MasterPermissive",
            "RingBreakLoopbackTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pure_st_redundancy_sync_alias_ast_parsing(self) -> None:
        """Parse SERCOS_III_REDUNDANCY_SYNC_POU and assert AST attributes."""
        SecurityGuard.assert_pure_st_content(SERCOS_III_REDUNDANCY_SYNC_POU)
        res = STParser.validate_code(SERCOS_III_REDUNDANCY_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(SERCOS_III_REDUNDANCY_SYNC_POU)
        assert ast is not None
        assert ast.name == "SercosIiiRedundancySync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1060", "%R1061", "%R1062", "%R1063",
            "%R1064", "%R1065", "%R1066", "%R1067",
            "%M247", "%M248",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_pure_st_pou_aliases(self) -> None:
        """Verify alias constants point to valid pure ST POU definitions."""
        assert SERCOS3_RING_PURE_ST_POU == SERCOS3_RING_SYNC_POU
        assert SERCOS3_PURE_ST_POU == SERCOS3_RING_SYNC_POU
        assert PURE_ST_POU == SERCOS3_RING_SYNC_POU

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify all pure ST POU variants pass SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(SERCOS3_RING_SYNC_POU)
        SecurityGuard.assert_pure_st_content(SERCOS_III_REDUNDANCY_SYNC_POU)
        SecurityGuard.assert_pure_st_content(SERCOS3_RING_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(SERCOS3_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(PURE_ST_POU)


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================


class TestSection2AntiLadderSecurity:
    """Tests for SecurityGuard strict rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "sample",
        [
            "PROGRAM BadContacts\nVAR Flag: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM",
            "PROGRAM BadNegative\nVAR Flag: BOOL; END_VAR\n---[/]---\nEND_PROGRAM",
            "PROGRAM BadRung\nVAR Flag: BOOL; END_VAR\nRUNG 1: XIC %M247 OTE %M248 END_RUNG\nEND_PROGRAM",
            "PROGRAM BadCoil\nVAR Out: BOOL; END_VAR\n---(S)---\nEND_PROGRAM",
            "PROGRAM BadReset\nVAR Out: BOOL; END_VAR\n---(R)---\nEND_PROGRAM",
            "PROGRAM BadMnemonic\nVAR Out: BOOL; END_VAR\nXIO %M247\nEND_PROGRAM",
            "PROGRAM BadLatch\nVAR Out: BOOL; END_VAR\nOTL %M248\nEND_PROGRAM",
            "PROGRAM BadUnlatch\nVAR Out: BOOL; END_VAR\nOTU %M248\nEND_PROGRAM",
            "PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, sample: str) -> None:
        """Verify embedded ladder constructs raise LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)

        res = STParser.validate_code(sample)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: Phase Progression State Machine & Invalid Transition Rejection
# ============================================================================


class TestSection3PhaseProgressionStateMachine:
    """Tests for SERCOS III Phase Progression (CP0 -> CP1 -> CP2 -> CP3 -> CP4) and Fault Rejection."""

    def test_sequential_phase_progression_cp0_to_cp4(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """Verify standard sequential progression through CP0 -> CP1 -> CP2 -> CP3 -> CP4."""
        master = sercos_master
        master.start_engine()
        assert master.current_phase == Sercos3CommunicationPhase.CP0
        assert master.reg_table.read_word("%R1060") == int(Sercos3CommunicationPhase.CP0)

        assert master.transition_to_phase(Sercos3CommunicationPhase.CP1) is True
        assert master.current_phase == Sercos3CommunicationPhase.CP1
        assert master.reg_table.read_word("%R1060") == int(Sercos3CommunicationPhase.CP1)

        assert master.transition_to_phase(Sercos3CommunicationPhase.CP2) is True
        assert master.current_phase == Sercos3CommunicationPhase.CP2
        assert master.reg_table.read_word("%R1060") == int(Sercos3CommunicationPhase.CP2)

        assert master.transition_to_phase(Sercos3CommunicationPhase.CP3) is True
        assert master.current_phase == Sercos3CommunicationPhase.CP3
        assert master.reg_table.read_word("%R1060") == int(Sercos3CommunicationPhase.CP3)

        assert master.transition_to_phase(Sercos3CommunicationPhase.CP4) is True
        assert master.current_phase == Sercos3CommunicationPhase.CP4
        assert master.reg_table.read_word("%R1060") == int(Sercos3CommunicationPhase.CP4)
        assert master.master_permissive is True
        assert master.reg_table.read_bit("%M247") is True
        assert master.reg_table.read_bit("%M248") is False

    @pytest.mark.parametrize(
        "start_phase,target_phase",
        [
            (Sercos3CommunicationPhase.CP0, Sercos3CommunicationPhase.CP2),
            (Sercos3CommunicationPhase.CP0, Sercos3CommunicationPhase.CP3),
            (Sercos3CommunicationPhase.CP0, Sercos3CommunicationPhase.CP4),
            (Sercos3CommunicationPhase.CP1, Sercos3CommunicationPhase.CP3),
            (Sercos3CommunicationPhase.CP1, Sercos3CommunicationPhase.CP4),
            (Sercos3CommunicationPhase.CP2, Sercos3CommunicationPhase.CP4),
            (Sercos3CommunicationPhase.CP3, Sercos3CommunicationPhase.CP1),
        ],
    )
    def test_invalid_phase_jump_rejection_0xAA02(
        self,
        sercos_master: Sercos3RingMasterEngine,
        start_phase: Sercos3CommunicationPhase,
        target_phase: Sercos3CommunicationPhase,
    ) -> None:
        """Verify illegal non-sequential phase transitions trigger 0xAA02 (SERCOS_ERR_PHASE_ADVANCE_FAILED)."""
        master = sercos_master
        master.start_engine()
        master.current_phase = start_phase

        res = master.transition_to_phase(target_phase)
        assert res is False
        assert master.diagnostic_code == Sercos3DiagnosticCode.SERCOS_ERR_PHASE_ADVANCE_FAILED
        assert master.reg_table.read_uword("%R1067") == 0xAA02
        assert master.is_safety_tripped is True
        assert master.reg_table.read_bit("%M247") is False

    def test_parameter_verification_failure_rejects_cp2_to_cp3(
        self, sercos_master: Sercos3RingMasterEngine
    ) -> None:
        """Verify invalid parameter on any servo drive blocks CP2 -> CP3 and asserts 0xAA02."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)

        # Inject parameter validation error on drive 2
        master.configured_drives[2].parameter_validation_error = True
        res = master.transition_to_phase(Sercos3CommunicationPhase.CP3)

        assert res is False
        assert master.current_phase == Sercos3CommunicationPhase.CP2
        assert master.diagnostic_code == Sercos3DiagnosticCode.SERCOS_ERR_PHASE_ADVANCE_FAILED
        assert master.reg_table.read_uword("%R1067") == 0xAA02
        assert master.is_safety_tripped is True
        assert master.reg_table.read_bit("%M247") is False

    def test_reset_to_cp0_permitted_from_any_phase(
        self, sercos_master: Sercos3RingMasterEngine
    ) -> None:
        """Verify transitioning back to CP0 is always permitted from any phase."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)
        master.transition_to_phase(Sercos3CommunicationPhase.CP3)
        master.transition_to_phase(Sercos3CommunicationPhase.CP4)

        assert master.current_phase == Sercos3CommunicationPhase.CP4
        res = master.transition_to_phase(Sercos3CommunicationPhase.CP0)
        assert res is True
        assert master.current_phase == Sercos3CommunicationPhase.CP0
        assert master.reg_table.read_word("%R1060") == int(Sercos3CommunicationPhase.CP0)
        assert master.master_permissive is False

    def test_transition_without_configured_drives_rejected(
        self, register_table: RegisterTable
    ) -> None:
        """Verify transitioning beyond CP0 with zero configured drives is rejected."""
        empty_master = Sercos3RingMasterEngine(reg_table=register_table)
        empty_master.start_engine()
        assert empty_master.transition_to_phase(Sercos3CommunicationPhase.CP1) is False
        assert empty_master.diagnostic_code == Sercos3DiagnosticCode.SERCOS_ERR_PHASE_ADVANCE_FAILED
        assert empty_master.is_safety_tripped is True

    def test_transition_with_offline_drive_rejected(
        self, sercos_master: Sercos3RingMasterEngine
    ) -> None:
        """Verify transitioning to CP3/CP4 with an offline drive is rejected."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)
        master.configured_drives[3].is_online = False

        assert master.transition_to_phase(Sercos3CommunicationPhase.CP3) is False
        assert master.diagnostic_code == Sercos3DiagnosticCode.SERCOS_ERR_PHASE_ADVANCE_FAILED
        assert master.is_safety_tripped is True


# ============================================================================
# Section 4: Optical Dual-Ring Topology & Seamless Loopback Recovery (< 25 µs)
# ============================================================================


class TestSection4OpticalDualRingTopologyAndLoopback:
    """Tests for Optical Dual-Ring Redundancy, Cable Break Detection, and Loopback Switching."""

    def test_initial_intact_ring_topology(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """Verify initial network topology is intact closed optical ring with 0x0007 status word."""
        master = sercos_master
        master.start_engine()
        assert master.redundancy_mgr.topology_state == Sercos3RingTopology.RING_CLOSED
        status_word = master.reg_table.read_uword("%R1061")
        assert status_word == 0x0007  # Primary OK (1) | Secondary OK (2) | Redundancy Active (4)
        assert bool(status_word & Sercos3RingStatusBits.PRIMARY_OK) is True
        assert bool(status_word & Sercos3RingStatusBits.SECONDARY_OK) is True
        assert bool(status_word & Sercos3RingStatusBits.REDUNDANCY_ACTIVE) is True
        assert bool(status_word & Sercos3RingStatusBits.LOOPBACK_ACTIVE) is False
        assert master.reg_table.read_word("%R1066") == 0

    def test_cable_severance_engages_seamless_loopback(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """Verify cable severance engages optical loopback and records recovery latency < 25 µs."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)
        master.transition_to_phase(Sercos3CommunicationPhase.CP3)
        master.transition_to_phase(Sercos3CommunicationPhase.CP4)

        recovery_latency_us = master.sever_cable(drive_a=2, drive_b=3)
        assert recovery_latency_us < SERCOS3_LOOPBACK_MAX_TIME_US
        assert master.redundancy_mgr.topology_state == Sercos3RingTopology.LOOPBACK_ENGAGED

        # Status word reflections
        status_word = master.reg_table.read_uword("%R1061")
        assert bool(status_word & Sercos3RingStatusBits.LOOPBACK_ACTIVE) is True
        assert bool(status_word & Sercos3RingStatusBits.REDUNDANCY_ACTIVE) is False
        assert master.reg_table.read_uword("%R1067") == 0xAA01
        assert master.reg_table.read_bit("%M248") is True
        assert master.reg_table.read_word("%R1066") == round(recovery_latency_us)

    def test_communication_continues_in_loopback_mode(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """Verify real-time cyclic motion and setpoints flow seamlessly during loopback."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)
        master.transition_to_phase(Sercos3CommunicationPhase.CP3)
        master.transition_to_phase(Sercos3CommunicationPhase.CP4)

        master.sever_cable(drive_a=1, drive_b=2)

        master.configured_drives[1].target_position = 200
        master.configured_drives[2].target_position = 400

        pre_mdt = master.mdt_telegram_counter
        pre_at = master.at_telegram_counter

        result = master.execute_motion_cycle()
        assert result["polled_drives"] == 4
        assert master.mdt_telegram_counter == pre_mdt + 1
        assert master.at_telegram_counter == pre_at + 1
        assert master.configured_drives[1].actual_position > 0
        assert master.configured_drives[2].actual_position > 0

    def test_cable_restoration_restores_closed_ring(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """Verify restoring severed cable returns network to healthy closed ring."""
        master = sercos_master
        master.start_engine()
        master.sever_cable(drive_a=3, drive_b=4)
        assert master.redundancy_mgr.topology_state == Sercos3RingTopology.LOOPBACK_ENGAGED

        master.restore_cable()
        assert master.redundancy_mgr.topology_state == Sercos3RingTopology.RING_CLOSED
        status_word = master.reg_table.read_uword("%R1061")
        assert status_word == 0x0007
        assert master.reg_table.read_word("%R1066") == 0
        assert master.reg_table.read_bit("%M248") is False

    def test_dual_ring_collapse_triggers_0xAA04_and_clears_m247(
        self, sercos_master: Sercos3RingMasterEngine
    ) -> None:
        """Verify dual optical ring severance collapses network, tripping 0xAA04 and clearing %M247."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)
        master.transition_to_phase(Sercos3CommunicationPhase.CP3)
        master.transition_to_phase(Sercos3CommunicationPhase.CP4)

        master.sever_dual_ring()
        assert master.redundancy_mgr.topology_state == Sercos3RingTopology.DUAL_RING_COLLAPSED
        assert master.diagnostic_code == Sercos3DiagnosticCode.SERCOS_ERR_DUAL_RING_COLLAPSE
        assert master.reg_table.read_uword("%R1067") == 0xAA04
        assert master.reg_table.read_bit("%M247") is False


# ============================================================================
# Section 5: Master Synchronization Telegram (MST) & Sub-Microsecond Jitter Tracking
# ============================================================================


class TestSection5MSTSubMicrosecondJitterTracking:
    """Tests for MST telegram serialization, CRC32, and sub-microsecond jitter tracking (< 100 ns)."""

    def test_mst_serialization_and_crc32_integrity(self) -> None:
        """Verify MST telegram serialization and deserialization with CRC32 verification."""
        mst = Sercos3MSTTelegram(
            phase=Sercos3CommunicationPhase.CP4,
            cycle_counter=100,
            master_time_ns=100_000_000,
            sync_jitter_ns=55,
        )
        raw = mst.serialize()
        assert len(raw) == SERCOS3_MST_SIZE + 4

        dec = Sercos3MSTTelegram.deserialize(raw)
        assert dec.phase == Sercos3CommunicationPhase.CP4
        assert dec.cycle_counter == 100
        assert dec.master_time_ns == 100_000_000
        assert dec.sync_jitter_ns == 55
        assert dec.ethertype == SERCOS3_ETHERTYPE

    def test_mst_corrupted_crc32_rejected(self) -> None:
        """Verify bit flip in MST payload triggers CRC32 mismatch exception."""
        mst = Sercos3MSTTelegram(
            phase=Sercos3CommunicationPhase.CP4,
            cycle_counter=50,
            master_time_ns=50_000_000,
            sync_jitter_ns=30,
        )
        raw = bytearray(mst.serialize())
        raw[5] ^= 0x01  # Corrupt payload byte

        with pytest.raises(ValueError, match="CRC32 mismatch"):
            Sercos3MSTTelegram.deserialize(bytes(raw))

    def test_mst_buffer_too_small_rejected(self) -> None:
        """Verify truncated buffer raises ValueError."""
        with pytest.raises(ValueError, match="too small"):
            Sercos3MSTTelegram.deserialize(b"\x00\x01\x02")

    def test_nominal_jitter_tracking_strictly_under_100_nanoseconds(
        self, sercos_master: Sercos3RingMasterEngine
    ) -> None:
        """Verify nominal jitter values (< 100 ns) keep master healthy and update %R1063."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)
        master.transition_to_phase(Sercos3CommunicationPhase.CP3)
        master.transition_to_phase(Sercos3CommunicationPhase.CP4)

        for jitter in [20, 35, 68, 85, 95]:
            res = master.execute_motion_cycle(simulated_jitter_ns=jitter)
            assert res.get("sync_jitter_ns") == jitter
            assert master.mst_sync_jitter_ns == jitter
            assert master.reg_table.read_word("%R1063") == jitter
            assert master.diagnostic_code == Sercos3DiagnosticCode.OK
            assert master.reg_table.read_uword("%R1067") == 0x0000

    def test_jitter_excursion_over_100_nanoseconds_trips_0xAA03(
        self, sercos_master: Sercos3RingMasterEngine
    ) -> None:
        """Verify MST clock sync jitter exceeding 100 ns triggers 0xAA03 safety trip."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)
        master.transition_to_phase(Sercos3CommunicationPhase.CP3)
        master.transition_to_phase(Sercos3CommunicationPhase.CP4)

        # Exceed 100 ns threshold: 135 ns
        res = master.execute_motion_cycle(simulated_jitter_ns=135)
        assert res.get("status") == "jitter_tripped"
        assert master.diagnostic_code == Sercos3DiagnosticCode.SERCOS_ERR_MST_JITTER_EXCESS
        assert master.is_safety_tripped is True
        assert master.reg_table.read_uword("%R1067") == 0xAA03


# ============================================================================
# Section 6: Process Safety Trips (0xAA01..0xAA04) & Horner Coil Assertion
# ============================================================================


class TestSection6ProcessSafetyTrips:
    """Tests for Process Safety Trips (0xAA01, 0xAA02, 0xAA03, 0xAA04) and Horner Coils (%M247, %M248)."""

    def test_trip_0xaa01_optical_ring_break(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """0xAA01: Cable break engages loopback, asserts %M248, and sets %R1067."""
        master = sercos_master
        master.start_engine()
        master.trigger_safety_trip(Sercos3DiagnosticCode.SERCOS_ERR_RING_BREAK)

        assert master.is_safety_tripped is True
        assert master.diagnostic_code == Sercos3DiagnosticCode.SERCOS_ERR_RING_BREAK
        assert master.reg_table.read_uword("%R1067") == 0xAA01
        assert master.reg_table.read_bit("%M248") is True

    def test_trip_0xaa02_phase_advance_failed(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """0xAA02: Phase transition or parameter fault clears %M247 and sets %R1067."""
        master = sercos_master
        master.start_engine()
        master.trigger_safety_trip(Sercos3DiagnosticCode.SERCOS_ERR_PHASE_ADVANCE_FAILED)

        assert master.is_safety_tripped is True
        assert master.diagnostic_code == Sercos3DiagnosticCode.SERCOS_ERR_PHASE_ADVANCE_FAILED
        assert master.reg_table.read_uword("%R1067") == 0xAA02
        assert master.reg_table.read_bit("%M247") is False

    def test_trip_0xaa03_mst_clock_jitter_excess(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """0xAA03: MST jitter > 100 ns sets %R1067."""
        master = sercos_master
        master.start_engine()
        master.trigger_safety_trip(Sercos3DiagnosticCode.SERCOS_ERR_MST_JITTER_EXCESS)

        assert master.is_safety_tripped is True
        assert master.diagnostic_code == Sercos3DiagnosticCode.SERCOS_ERR_MST_JITTER_EXCESS
        assert master.reg_table.read_uword("%R1067") == 0xAA03

    def test_trip_0xaa04_dual_ring_collapse(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """0xAA04: Dual optical ring collapse clears %M247 and sets %R1067."""
        master = sercos_master
        master.start_engine()
        master.trigger_safety_trip(Sercos3DiagnosticCode.SERCOS_ERR_DUAL_RING_COLLAPSE)

        assert master.is_safety_tripped is True
        assert master.diagnostic_code == Sercos3DiagnosticCode.SERCOS_ERR_DUAL_RING_COLLAPSE
        assert master.reg_table.read_uword("%R1067") == 0xAA04
        assert master.reg_table.read_bit("%M247") is False

    def test_operator_manual_reset_handshake(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """Verify operator reset handshake clears safety trip and restores healthy state."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)
        master.transition_to_phase(Sercos3CommunicationPhase.CP3)
        master.transition_to_phase(Sercos3CommunicationPhase.CP4)

        master.trigger_safety_trip(Sercos3DiagnosticCode.SERCOS_ERR_PHASE_ADVANCE_FAILED)
        assert master.reg_table.read_bit("%M247") is False

        master.reset_safety()
        assert master.is_safety_tripped is False
        assert master.diagnostic_code == Sercos3DiagnosticCode.OK
        assert master.reg_table.read_uword("%R1067") == 0x0000
        assert master.reg_table.read_bit("%M247") is True


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R1060..%R1067)
# ============================================================================


class TestSection7HornerOCSMemoryIntegration:
    """Tests for Horner OCS memory map %R1060..%R1067 and %M247..%M248."""

    def test_full_register_map_and_scaling(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """Verify full register synchronization and scaling."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)
        master.transition_to_phase(Sercos3CommunicationPhase.CP3)
        master.transition_to_phase(Sercos3CommunicationPhase.CP4)

        master.configured_drives[1].target_position = 1000
        master.configured_drives[2].target_position = 2000
        master.execute_motion_cycle(simulated_jitter_ns=50)

        rt = master.reg_table
        assert rt.read_word("%R1060") == int(Sercos3CommunicationPhase.CP4)
        assert rt.read_uword("%R1061") == 0x0007
        assert rt.read_word("%R1062") == master.cycle_time_us
        assert rt.read_word("%R1063") == 50
        assert rt.read_word("%R1064") == master.mdt_telegram_counter
        assert rt.read_word("%R1065") == master.at_telegram_counter
        assert rt.read_word("%R1066") == 0
        assert rt.read_uword("%R1067") == 0x0000
        assert rt.read_bit("%M247") is True
        assert rt.read_bit("%M248") is False

    def test_axis_position_scaling_and_clamping(self) -> None:
        """Verify scale_axis_position_to_int16 scaling and clamping boundaries."""
        assert scale_axis_position_to_int16(55.4) == 554
        assert scale_axis_position_to_int16(-12.8) == -128
        assert scale_axis_position_to_int16(5000.0) == 32767
        assert scale_axis_position_to_int16(-5000.0) == -32768

    def test_idn_service_channel_access(self, sercos_master: Sercos3RingMasterEngine) -> None:
        """Verify IDN read/write transactions exercise service channel."""
        master = sercos_master
        master.start_engine()
        master.transition_to_phase(Sercos3CommunicationPhase.CP1)
        master.transition_to_phase(Sercos3CommunicationPhase.CP2)

        val = master.read_drive_idn(1, "S-0-0100")
        assert val == 100

        master.write_drive_idn(1, "S-0-0100", 250)
        assert master.read_drive_idn(1, "S-0-0100") == 250


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration & Evidence Persistence
# ============================================================================


class TestSection8VerificationSuiteIntegration:
    """Tests for the complete 9-stage verification suite and evidence persistence."""

    def test_run_sercos3_ring_verification_success(self) -> None:
        """Verify the 9-stage verification returns a clean SUCCESS status."""
        result = run_sercos3_ring_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9
        for t in result["data"]["tests"]:
            assert t["passed"] is True

    def test_run_sercos3_ring_verification_writes_evidence(self, tmp_path: Path) -> None:
        """Verify verification writes valid JSON evidence matching contract schema."""
        evidence_file = tmp_path / "sercos3_ring_evidence.json"
        result = run_sercos3_ring_verification(output_path=evidence_file)

        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W145"
        assert data["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
        assert "Optical Fiber Ring Redundancy" in data["data"]["component"]
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["tests"]) == 9

        reg_map = data["data"]["register_map"]
        assert reg_map["communication_phase"] == "%R1060"
        assert reg_map["ring_status_word"] == "%R1061"
        assert reg_map["cycle_time_microseconds"] == "%R1062"
        assert reg_map["mst_sync_jitter_nanoseconds"] == "%R1063"
        assert reg_map["mdt_telegram_counter"] == "%R1064"
        assert reg_map["at_telegram_counter"] == "%R1065"
        assert reg_map["ring_break_recovery_time_microseconds"] == "%R1066"
        assert reg_map["diagnostic_status_code"] == "%R1067"
        assert reg_map["sercos3_master_permissive_coil"] == "%M247"
        assert reg_map["ring_break_loopback_trip_coil"] == "%M248"

    def test_evidence_metrics_schema(self) -> None:
        """Verify evidence metrics dictionary has all expected fields."""
        result = run_sercos3_ring_verification()
        metrics = result["data"]["metrics"]
        assert metrics["speed_bps"] == 100_000_000
        assert metrics["loopback_recovery_us"] < 25.0
        assert metrics["mst_sync_jitter_ns"] < 100
        assert metrics["configured_drives"] == 4
