"""Unit Test Suite for Industrial SERCOS III Master Protocol Engine.

Work Package: W115 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Pure ST POU AST validation and anti-ladder check (verify_sercos_pure_st).
2. MST, MDT, AT telegram framing and slot validation.
3. Communication phase transitions (CP0 -> CP1 -> CP2 -> CP3 -> CP4).
4. IDN parameterization service (S-0-xxxx and P-0-xxxx).
5. Cyclic synchronous position/velocity exchange in CP4.
6. Seamless ring break loopback recovery (< 25 us).
7. Clock synchronization and jitter surveillance.
8. Drive communication timeout and fault tripping.
9. Horner OCS register space synchronization (%R760..%R767, %M177..%M178).
10. Anti-ladder security guard rejection (LadderForbiddenError on contacts/coils).
11. End-to-end 9-stage verification suite (run_sercos_verification).
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
import struct

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.sercos import (
    SERCOS_AT_HDR_SIZE,
    SERCOS_AT_RECORD_SIZE,
    SERCOS_DEFAULT_CYCLE_TIME_US,
    SERCOS_ETHERTYPE,
    SERCOS_JITTER_THRESHOLD_NS,
    SERCOS_LOOPBACK_MAX_TIME_US,
    SERCOS_MAX_DRIVES,
    SERCOS_MDT_HDR_SIZE,
    SERCOS_MDT_RECORD_SIZE,
    SERCOS_MISSED_CYCLE_TIMEOUT_THRESHOLD,
    SERCOS_MST_SIZE,
    SERCOS_PURE_ST_POU,
    SERCOS_SPEED_BPS,
    SercosATRecord,
    SercosATTelegram,
    SercosCommunicationPhase,
    SercosDiagnosticCode,
    SercosDriveDescriptor,
    SercosDriveOpMode,
    SercosMDTRecord,
    SercosMDTTelegram,
    SercosMSTTelegram,
    SercosMasterEngine,
    SercosRingTopology,
    SercosStatusBits,
    SercosTelegramType,
    run_sercos_verification,
    verify_sercos_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def sercos_engine(register_table: RegisterTable) -> SercosMasterEngine:
    """Provide a fresh SercosMasterEngine with 4 configured drives."""
    eng = SercosMasterEngine(
        reg_table=register_table,
        cycle_time_us=SERCOS_DEFAULT_CYCLE_TIME_US,
    )
    for i in range(1, 5):
        eng.configure_drive(SercosDriveDescriptor(drive_address=i, drive_name=f"Axis_{i}"))
    return eng


# ============================================================================
# 1. Pure ST POU AST Validation & Anti-Ladder Check
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Pure ST POU compliance and anti-ladder security."""

    def test_verify_sercos_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_sercos_pure_st() is True

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Parse SERCOS_PURE_ST_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(SERCOS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "SercosIIIMotionSync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "SercosStatusWord",
            "ConfiguredDrivesCount",
            "ActiveDriveMaskLow",
            "ActiveDriveMaskHigh",
            "CycleTimeUs",
            "SyncJitterNanoseconds",
            "TotalMotionCyclesExecuted",
            "DiagnosticEventCode",
            "SercosNormalActive",
            "SercosMotionFaultTrip",
            "MasterActive",
            "RingClosed",
            "Cp4Operational",
            "CyclicSyncActive",
            "LoopbackEngaged",
            "DiagnosticTrip",
        }
        assert expected_vars.issubset(var_names)

        expected_bound_regs = {
            "%R760", "%R761", "%R762", "%R763", "%R764",
            "%R765", "%R766", "%R767", "%M177", "%M178",
        }
        assert expected_bound_regs.issubset(set(pou.bound_registers))

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify pure ST POU passes SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(SERCOS_PURE_ST_POU)


# ============================================================================
# 2. MST, MDT, AT Telegram Framing & Slot Validation
# ============================================================================

class TestSection2TelegramFramingAndSlots:
    """Tests for Ethernet II telegram framing, slot codecs, and CRC validation."""

    def test_mst_serialization_and_deserialization(self) -> None:
        """Verify MST telegram serialization and deserialization roundtrip."""
        mst = SercosMSTTelegram(
            phase=SercosCommunicationPhase.CP4,
            cycle_counter=100,
            master_time_ns=1_000_000_000,
            sync_jitter_ns=180,
            ethertype=SERCOS_ETHERTYPE,
        )
        raw = mst.serialize()
        assert len(raw) == SERCOS_MST_SIZE + 4  # Body + CRC32
        assert raw[:2] == struct.pack(">H", SERCOS_ETHERTYPE)

        decoded = SercosMSTTelegram.deserialize(raw)
        assert decoded.phase == SercosCommunicationPhase.CP4
        assert decoded.cycle_counter == 100
        assert decoded.master_time_ns == 1_000_000_000
        assert decoded.sync_jitter_ns == 180
        assert decoded.ethertype == SERCOS_ETHERTYPE

    def test_mst_invalid_crc_rejected(self) -> None:
        """Verify MST deserialization rejects corrupted CRC32."""
        mst = SercosMSTTelegram(SercosCommunicationPhase.CP4, 1, 1000, 100)
        raw = bytearray(mst.serialize())
        raw[-1] ^= 0xFF
        with pytest.raises(ValueError, match="CRC32 mismatch"):
            SercosMSTTelegram.deserialize(bytes(raw))

    def test_mst_invalid_ethertype_rejected(self) -> None:
        """Verify MST deserialization rejects invalid EtherType."""
        mst = SercosMSTTelegram(SercosCommunicationPhase.CP4, 1, 1000, 100)
        raw = bytearray(mst.serialize())
        raw[0] = 0x12
        raw[1] = 0x34
        # Recalculate CRC for modified body to reach EtherType check
        import zlib
        body = raw[:-4]
        crc = zlib.crc32(body) & 0xFFFFFFFF
        raw[-4:] = struct.pack(">I", crc)
        with pytest.raises(ValueError, match="Invalid EtherType"):
            SercosMSTTelegram.deserialize(bytes(raw))

    def test_mst_buffer_underflow_rejected(self) -> None:
        """Verify truncated MST raw buffer raises ValueError."""
        with pytest.raises(ValueError, match="too small"):
            SercosMSTTelegram.deserialize(b"\x00" * 10)

    def test_mdt_record_and_telegram_codecs(self) -> None:
        """Verify MDT telegram packing and unpacking with multi-drive slots."""
        records = [
            SercosMDTRecord(
                drive_address=1,
                control_word=0x000F,
                op_mode=SercosDriveOpMode.POSITION_CONTROL,
                target_position=10000,
                target_velocity=500,
                target_torque=25,
            ),
            SercosMDTRecord(
                drive_address=2,
                control_word=0x0007,
                op_mode=SercosDriveOpMode.VELOCITY_CONTROL,
                target_position=0,
                target_velocity=1200,
                target_torque=10,
            ),
        ]
        mdt = SercosMDTTelegram(
            phase=SercosCommunicationPhase.CP4,
            cycle_counter=250,
            records=records,
        )
        raw = mdt.serialize()
        expected_len = SERCOS_MDT_HDR_SIZE + (2 * SERCOS_MDT_RECORD_SIZE) + 4
        assert len(raw) == expected_len

        dec = SercosMDTTelegram.deserialize(raw)
        assert dec.phase == SercosCommunicationPhase.CP4
        assert dec.cycle_counter == 250
        assert len(dec.records) == 2
        assert dec.records[0].drive_address == 1
        assert dec.records[0].target_position == 10000
        assert dec.records[1].drive_address == 2
        assert dec.records[1].target_velocity == 1200

    def test_mdt_invalid_crc_rejected(self) -> None:
        """Verify MDT deserialization rejects corrupted CRC32."""
        mdt = SercosMDTTelegram(SercosCommunicationPhase.CP4, 1, [])
        raw = bytearray(mdt.serialize())
        raw[-1] ^= 0xAA
        with pytest.raises(ValueError, match="CRC32 mismatch"):
            SercosMDTTelegram.deserialize(bytes(raw))

    def test_at_record_and_telegram_codecs(self) -> None:
        """Verify AT telegram packing and unpacking with multi-drive slots."""
        records = [
            SercosATRecord(
                drive_address=1,
                status_word=0x0007,
                actual_position=9980,
                actual_velocity=495,
                actual_torque=24,
                error_code=0x0000,
            ),
            SercosATRecord(
                drive_address=2,
                status_word=0x0005,
                actual_position=0,
                actual_velocity=1198,
                actual_torque=9,
                error_code=0x0000,
            ),
        ]
        at = SercosATTelegram(
            phase=SercosCommunicationPhase.CP4,
            cycle_counter=250,
            records=records,
        )
        raw = at.serialize()
        expected_len = SERCOS_AT_HDR_SIZE + (2 * SERCOS_AT_RECORD_SIZE) + 4
        assert len(raw) == expected_len

        dec = SercosATTelegram.deserialize(raw)
        assert dec.phase == SercosCommunicationPhase.CP4
        assert dec.cycle_counter == 250
        assert len(dec.records) == 2
        assert dec.records[0].drive_address == 1
        assert dec.records[0].actual_position == 9980
        assert dec.records[1].drive_address == 2
        assert dec.records[1].actual_velocity == 1198

    def test_at_invalid_crc_rejected(self) -> None:
        """Verify AT deserialization rejects corrupted CRC32."""
        at = SercosATTelegram(SercosCommunicationPhase.CP4, 1, [])
        raw = bytearray(at.serialize())
        raw[-1] ^= 0x55
        with pytest.raises(ValueError, match="CRC32 mismatch"):
            SercosATTelegram.deserialize(bytes(raw))


# ============================================================================
# 3. Communication Phase Transitions (CP0 -> CP1 -> CP2 -> CP3 -> CP4)
# ============================================================================

class TestSection3CommunicationPhaseTransitions:
    """Tests for strictly sequential phase progression and error fallbacks."""

    def test_valid_sequential_transitions_cp0_to_cp4(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify sequential progression CP0 -> CP1 -> CP2 -> CP3 -> CP4."""
        sercos_engine.start_engine()
        assert sercos_engine.current_phase == SercosCommunicationPhase.CP0

        # CP0 -> CP1
        assert sercos_engine.transition_to_phase(SercosCommunicationPhase.CP1) is True
        assert sercos_engine.current_phase == SercosCommunicationPhase.CP1

        # CP1 -> CP2
        assert sercos_engine.transition_to_phase(SercosCommunicationPhase.CP2) is True
        assert sercos_engine.current_phase == SercosCommunicationPhase.CP2

        # CP2 -> CP3
        assert sercos_engine.transition_to_phase(SercosCommunicationPhase.CP3) is True
        assert sercos_engine.current_phase == SercosCommunicationPhase.CP3

        # CP3 -> CP4
        assert sercos_engine.transition_to_phase(SercosCommunicationPhase.CP4) is True
        assert sercos_engine.current_phase == SercosCommunicationPhase.CP4
        assert bool(sercos_engine.status_bits & SercosStatusBits.CP4_OPERATIONAL) is True
        assert bool(sercos_engine.status_bits & SercosStatusBits.CYCLIC_SYNC_ACTIVE) is True

    def test_illegal_phase_skip_cp0_to_cp3_rejected(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify skipping from CP0 directly to CP3 is rejected with 0x8C04."""
        sercos_engine.start_engine()
        assert sercos_engine.transition_to_phase(SercosCommunicationPhase.CP3) is False
        assert sercos_engine.current_phase == SercosCommunicationPhase.CP0
        assert sercos_engine.diagnostic_code == SercosDiagnosticCode.PHASE_TRANSITION_FAULT
        assert int(sercos_engine.diagnostic_code) == 0x8C04
        assert bool(sercos_engine.status_bits & SercosStatusBits.DRIVE_FAULT_ALARM) is True

    def test_illegal_phase_skip_cp1_to_cp4_rejected(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify skipping from CP1 directly to CP4 is rejected."""
        sercos_engine.start_engine()
        sercos_engine.transition_to_phase(SercosCommunicationPhase.CP1)
        assert sercos_engine.transition_to_phase(SercosCommunicationPhase.CP4) is False
        assert sercos_engine.current_phase == SercosCommunicationPhase.CP1

    def test_reset_to_cp0_permitted_from_any_phase(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify falling back to CP0 is always permitted and resets flags."""
        sercos_engine.start_engine()
        sercos_engine.transition_to_phase(SercosCommunicationPhase.CP1)
        sercos_engine.transition_to_phase(SercosCommunicationPhase.CP2)
        sercos_engine.transition_to_phase(SercosCommunicationPhase.CP3)
        sercos_engine.transition_to_phase(SercosCommunicationPhase.CP4)
        assert sercos_engine.current_phase == SercosCommunicationPhase.CP4

        # Reset to CP0
        assert sercos_engine.transition_to_phase(SercosCommunicationPhase.CP0) is True
        assert sercos_engine.current_phase == SercosCommunicationPhase.CP0
        assert bool(sercos_engine.status_bits & SercosStatusBits.CP4_OPERATIONAL) is False
        assert bool(sercos_engine.status_bits & SercosStatusBits.CYCLIC_SYNC_ACTIVE) is False


# ============================================================================
# 4. IDN Parameterization Service (S-0-xxxx & P-0-xxxx)
# ============================================================================

class TestSection4IDNParameterizationService:
    """Tests for IDN parameter reading, writing, and CP2 parameter verification."""

    def test_read_standard_and_product_idns(self, sercos_engine: SercosMasterEngine) -> None:
        """Verify reading configured standard (S) and product-specific (P) IDNs."""
        sercos_engine.start_engine()
        # S-0-0032: Operation mode (Position Control = 1)
        val_mode = sercos_engine.read_drive_idn(drive_address=1, idn="S-0-0032")
        assert val_mode == int(SercosDriveOpMode.POSITION_CONTROL)

        # S-0-0100: Kp gain (default 250)
        val_kp = sercos_engine.read_drive_idn(drive_address=1, idn="S-0-0100")
        assert val_kp == 250

        # P-0-0010: Product identifier string
        val_prod = sercos_engine.read_drive_idn(drive_address=1, idn="P-0-0010")
        assert "Horner" in val_prod

        # P-0-0020: Bus DC link voltage
        val_dc = sercos_engine.read_drive_idn(drive_address=1, idn="P-0-0020")
        assert val_dc == 400

    def test_write_idn_and_read_back(self, sercos_engine: SercosMasterEngine) -> None:
        """Verify writing parameter value and verifying it persists."""
        sercos_engine.start_engine()
        sercos_engine.write_drive_idn(drive_address=1, idn="S-0-0100", value=350)
        assert sercos_engine.read_drive_idn(drive_address=1, idn="S-0-0100") == 350

    def test_read_nonexistent_idn_raises_key_error(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify querying non-existent IDN raises KeyError."""
        sercos_engine.start_engine()
        with pytest.raises(KeyError, match="IDN S-0-9999 not found"):
            sercos_engine.read_drive_idn(drive_address=1, idn="S-0-9999")

    def test_parameter_verification_failure_halts_cp3_transition(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify failing drive parameter verification halts transition to CP3 with 0x8C04."""
        sercos_engine.start_engine()
        sercos_engine.transition_to_phase(SercosCommunicationPhase.CP1)
        sercos_engine.transition_to_phase(SercosCommunicationPhase.CP2)

        # Inject invalid parameter state on drive 2
        sercos_engine.configured_drives[2].parameter_verification_failed = True

        assert sercos_engine.transition_to_phase(SercosCommunicationPhase.CP3) is False
        assert sercos_engine.current_phase == SercosCommunicationPhase.CP2
        assert sercos_engine.diagnostic_code == SercosDiagnosticCode.PHASE_TRANSITION_FAULT
        assert sercos_engine.reg_table.read_uword("%R767") == 0x8C04
        assert sercos_engine.reg_table.read_bit("%M178") is True


# ============================================================================
# 5. Cyclic Synchronous Position/Velocity Exchange in CP4
# ============================================================================

class TestSection5CyclicSynchronousExchangeInCP4:
    """Tests for real-time cyclic motion setpoint exchange and closed-loop response."""

    def test_cyclic_motion_execution_and_drive_convergence(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify multi-drive position convergence across cyclic scans in CP4."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        # Command setpoints to Axis 1 and Axis 2
        sercos_engine.configured_drives[1].target_position = 1000
        sercos_engine.configured_drives[1].control_word = 0x000F
        sercos_engine.configured_drives[2].target_position = 2000
        sercos_engine.configured_drives[2].control_word = 0x000F

        # Execute 5 motion cycles
        for _ in range(5):
            res = sercos_engine.execute_motion_cycle()
            assert res["phase"] == int(SercosCommunicationPhase.CP4)
            assert res["polled_drives"] == 4

        # Verify actual positions advanced towards targets
        act1 = sercos_engine.configured_drives[1].actual_position
        act2 = sercos_engine.configured_drives[2].actual_position
        assert act1 > 0
        assert act2 > 0
        assert act1 == 1000  # Axis 1 reached 1000 (step = min(abs(err), 250) * 4+ cycles)
        assert sercos_engine.total_motion_cycles_executed == 5
        assert sercos_engine.reg_table.read_uword("%R766") == 5

    def test_velocity_control_mode_dynamics(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify velocity control mode updates actual velocity and position."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        drive = sercos_engine.configured_drives[3]
        drive.op_mode = SercosDriveOpMode.VELOCITY_CONTROL
        drive.target_velocity = 800

        sercos_engine.execute_motion_cycle()
        assert drive.actual_velocity == 800
        assert drive.actual_position > 0


# ============================================================================
# 6. Seamless Ring Break Loopback Recovery (< 25 us)
# ============================================================================

class TestSection6SeamlessRingBreakLoopbackRecovery:
    """Tests for cable severance loopback recovery latency and communication continuity."""

    def test_cable_sever_triggers_loopback_under_25_us(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify severing cable between adjacent drives engages loopback in < 25 us."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        rec_time = sercos_engine.sever_cable(drive_a=2, drive_b=3)
        assert rec_time < SERCOS_LOOPBACK_MAX_TIME_US
        assert sercos_engine.loopback_engaged is True
        assert sercos_engine.ring_closed is False
        assert bool(sercos_engine.status_bits & SercosStatusBits.LOOPBACK_ENGAGED) is True
        assert bool(sercos_engine.status_bits & SercosStatusBits.RING_CLOSED) is False
        assert sercos_engine.diagnostic_code == SercosDiagnosticCode.RING_BREAK_LOOPBACK
        assert int(sercos_engine.diagnostic_code) == 0x8C02
        assert sercos_engine.reg_table.read_uword("%R767") == 0x8C02

    def test_loopback_maintains_telegram_exchange_to_all_drives(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify all 4 drives remain polled without data loss under loopback."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        sercos_engine.sever_cable(drive_a=2, drive_b=3)
        res = sercos_engine.execute_motion_cycle()
        assert res["polled_drives"] == 4
        assert res["loopback_engaged"] is True

    def test_cable_restoration_clears_loopback(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify restoring cable returns network to closed ring mode."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        sercos_engine.sever_cable(drive_a=2, drive_b=3)
        assert sercos_engine.loopback_engaged is True

        sercos_engine.restore_cable()
        assert sercos_engine.loopback_engaged is False
        assert sercos_engine.ring_closed is True
        assert bool(sercos_engine.status_bits & SercosStatusBits.LOOPBACK_ENGAGED) is False
        assert bool(sercos_engine.status_bits & SercosStatusBits.RING_CLOSED) is True
        assert sercos_engine.diagnostic_code == SercosDiagnosticCode.OK
        assert sercos_engine.reg_table.read_uword("%R767") == 0x0000


# ============================================================================
# 7. Clock Synchronization & Jitter Surveillance
# ============================================================================

class TestSection7ClockSyncAndJitterSurveillance:
    """Tests for MST sub-microsecond clock synchronization and 1.0 us jitter alarm."""

    def test_nominal_jitter_produces_no_warning(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify nominal 180 ns jitter (< 1000 ns) produces no warning."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        sercos_engine.execute_motion_cycle(simulated_jitter_ns=180)
        assert sercos_engine.sync_jitter_ns == 180
        assert bool(sercos_engine.status_bits & SercosStatusBits.JITTER_WARNING) is False
        assert sercos_engine.diagnostic_code == SercosDiagnosticCode.OK
        assert sercos_engine.reg_table.read_uword("%R765") == 180

    def test_excessive_jitter_triggers_alarm_0x8C03(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify jitter > 1000 ns (e.g. 1350 ns) triggers CLOCK_JITTER_EXCEEDED (0x8C03)."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        sercos_engine.execute_motion_cycle(simulated_jitter_ns=1350)
        assert sercos_engine.sync_jitter_ns == 1350
        assert bool(sercos_engine.status_bits & SercosStatusBits.JITTER_WARNING) is True
        assert sercos_engine.diagnostic_code == SercosDiagnosticCode.CLOCK_JITTER_EXCEEDED
        assert int(sercos_engine.diagnostic_code) == 0x8C03
        assert sercos_engine.reg_table.read_uword("%R767") == 0x8C03
        assert (sercos_engine.reg_table.read_uword("%R760") & int(SercosStatusBits.JITTER_WARNING)) != 0

    def test_jitter_clears_upon_scan_recovery(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify returning to nominal jitter clears warning and restores OK code."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        sercos_engine.execute_motion_cycle(simulated_jitter_ns=1400)
        assert bool(sercos_engine.status_bits & SercosStatusBits.JITTER_WARNING) is True

        sercos_engine.execute_motion_cycle(simulated_jitter_ns=200)
        assert bool(sercos_engine.status_bits & SercosStatusBits.JITTER_WARNING) is False
        assert sercos_engine.diagnostic_code == SercosDiagnosticCode.OK


# ============================================================================
# 8. Drive Communication Timeout & Fault Tripping
# ============================================================================

class TestSection8DriveTimeoutAndFaultTripping:
    """Tests for missed cycle watchdog and fault tripping."""

    def test_missed_cycles_watchdog_threshold(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify 1 or 2 missed cycles does not disconnect; 3 missed cycles marks offline."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        # 1 missed cycle
        sercos_engine.simulate_drive_missed_cycles(drive_address=4, cycles=1)
        assert sercos_engine.configured_drives[4].is_online is True

        # 2 missed cycles total
        sercos_engine.simulate_drive_missed_cycles(drive_address=4, cycles=1)
        assert sercos_engine.configured_drives[4].is_online is True

        # 3 missed cycles total (threshold reached)
        sercos_engine.simulate_drive_missed_cycles(drive_address=4, cycles=1)
        assert sercos_engine.configured_drives[4].is_online is False
        assert bool(sercos_engine.status_bits & SercosStatusBits.DRIVE_FAULT_ALARM) is True
        assert sercos_engine.diagnostic_code == SercosDiagnosticCode.DRIVE_COMM_TIMEOUT
        assert int(sercos_engine.diagnostic_code) == 0x8C01
        assert sercos_engine.reg_table.read_uword("%R767") == 0x8C01

    def test_drive_timeout_trips_fault_coil_m178_and_clears_m177(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify drive timeout latches %M178=TRUE and %M177=FALSE."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        sercos_engine.execute_motion_cycle()
        assert sercos_engine.reg_table.read_bit("%M177") is True
        assert sercos_engine.reg_table.read_bit("%M178") is False

        sercos_engine.simulate_drive_missed_cycles(drive_address=4, cycles=3)
        sercos_engine.execute_motion_cycle()

        assert sercos_engine.reg_table.read_bit("%M177") is False
        assert sercos_engine.reg_table.read_bit("%M178") is True

    def test_drive_recovery_restores_normal_operation(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify recovering drive clears trip and restores %M177=TRUE."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        sercos_engine.simulate_drive_missed_cycles(drive_address=4, cycles=3)
        sercos_engine.execute_motion_cycle()
        assert sercos_engine.reg_table.read_bit("%M178") is True

        sercos_engine.recover_drive(drive_address=4)
        sercos_engine.execute_motion_cycle()

        assert sercos_engine.configured_drives[4].is_online is True
        assert sercos_engine.reg_table.read_bit("%M177") is True
        assert sercos_engine.reg_table.read_bit("%M178") is False
        assert sercos_engine.diagnostic_code == SercosDiagnosticCode.OK


# ============================================================================
# 9. Horner OCS Register Space Synchronization (%R760..%R767, %M177..%M178)
# ============================================================================

class TestSection9HornerRegisterSynchronization:
    """Tests for %R760..%R767 and %M177..%M178 memory synchronization."""

    def test_status_word_r760_bitmask_synchronization(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify %R760 accurately reflects SercosStatusWord."""
        sercos_engine.start_engine()
        r760 = sercos_engine.reg_table.read_uword("%R760")
        assert (r760 & int(SercosStatusBits.MASTER_ACTIVE)) != 0
        assert (r760 & int(SercosStatusBits.RING_CLOSED)) != 0

    def test_configured_drives_count_r761(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify %R761 reflects configured drive count."""
        assert sercos_engine.reg_table.read_word("%R761") == 4
        sercos_engine.configure_drive(SercosDriveDescriptor(drive_address=5))
        assert sercos_engine.reg_table.read_word("%R761") == 5

    def test_active_drive_masks_r762_and_r763(self) -> None:
        """Verify %R762 (drives 1..16) and %R763 (drives 17..32) bitmasks."""
        engine = SercosMasterEngine(reg_table=RegisterTable())
        # Configure drives 1, 16, 17, 32
        for d in [1, 16, 17, 32]:
            engine.configure_drive(SercosDriveDescriptor(drive_address=d))

        low_mask = engine.reg_table.read_uword("%R762")
        high_mask = engine.reg_table.read_uword("%R763")

        assert low_mask == (1 << 0) | (1 << 15)   # 0x8001
        assert high_mask == (1 << 0) | (1 << 15)  # 0x8001

    def test_cycle_time_r764_and_motion_cycles_r766(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify %R764 (Cycle Time) and %R766 (Total Cycles)."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        assert sercos_engine.reg_table.read_word("%R764") == SERCOS_DEFAULT_CYCLE_TIME_US
        assert sercos_engine.reg_table.read_word("%R766") == 0

        sercos_engine.execute_motion_cycle()
        assert sercos_engine.reg_table.read_word("%R766") == 1

        sercos_engine.execute_motion_cycle()
        assert sercos_engine.reg_table.read_word("%R766") == 2

    def test_sync_jitter_r765(self, sercos_engine: SercosMasterEngine) -> None:
        """Verify %R765 reflects measured jitter."""
        sercos_engine.start_engine()
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)

        sercos_engine.execute_motion_cycle(simulated_jitter_ns=350)
        assert sercos_engine.reg_table.read_word("%R765") == 350

    def test_discrete_coils_truth_table_m177_and_m178(
        self, sercos_engine: SercosMasterEngine
    ) -> None:
        """Verify truth table for %M177 (Normal Active) and %M178 (Motion Fault Trip)."""
        # Initially not started
        assert sercos_engine.reg_table.read_bit("%M177") is False
        assert sercos_engine.reg_table.read_bit("%M178") is False

        # Started in CP0 -> %M177=False (not in CP4)
        sercos_engine.start_engine()
        assert sercos_engine.reg_table.read_bit("%M177") is False

        # Advanced to CP4 -> %M177=True, %M178=False
        for p in (SercosCommunicationPhase.CP1, SercosCommunicationPhase.CP2,
                  SercosCommunicationPhase.CP3, SercosCommunicationPhase.CP4):
            sercos_engine.transition_to_phase(p)
        assert sercos_engine.reg_table.read_bit("%M177") is True
        assert sercos_engine.reg_table.read_bit("%M178") is False

        # Loopback engaged -> %M177 drops to False
        sercos_engine.sever_cable(1, 2)
        assert sercos_engine.reg_table.read_bit("%M177") is False


# ============================================================================
# 10. Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection10AntiLadderSecurityGuard:
    """Tests for rejection of ladder logic constructs, coils, and mnemonics."""

    def test_ladder_contacts_rejected(self) -> None:
        """Verify ladder contacts '---[ ]---' trigger LadderForbiddenError."""
        bad_pou = SERCOS_PURE_ST_POU + "\n---[ ]---"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_pou)

    def test_ladder_negative_contacts_rejected(self) -> None:
        """Verify ladder negative contacts '---[/]---' trigger LadderForbiddenError."""
        bad_pou = SERCOS_PURE_ST_POU + "\n---[/]---"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_pou)

    def test_ladder_coils_rejected(self) -> None:
        """Verify ladder coils '---( )---' trigger LadderForbiddenError."""
        bad_pou = SERCOS_PURE_ST_POU + "\n---( )---"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_pou)

    def test_ladder_rungs_and_networks_rejected(self) -> None:
        """Verify RUNG and NETWORK delimiters trigger LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(SERCOS_PURE_ST_POU + "\nRUNG 1: XIC Start")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(SERCOS_PURE_ST_POU + "\nNETWORK 1")

    def test_st_parser_validate_code_ladder_rejection(self) -> None:
        """Verify STParser.validate_code catches ladder constructs with ERR_LADDER_FORBIDDEN."""
        res = STParser.validate_code("PROGRAM BadLadder\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM")
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 11. End-to-End Deterministic Verification Suite
# ============================================================================

class TestSection11EndToEndVerificationSuite:
    """Tests for the complete verification suite runner."""

    def test_run_sercos_verification_returns_strict_4_state_success(self) -> None:
        """Verify run_sercos_verification returns strict 4-state contract success."""
        evidence = run_sercos_verification()
        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert "SERCOS III" in evidence["details"]

        checks_passed = evidence["data"]["checks_passed"]
        total_checks = evidence["data"]["total_checks"]
        assert checks_passed == total_checks == 9

        tests = evidence["data"]["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True

    def test_run_sercos_verification_emits_json_artifact(self, tmp_path: Path) -> None:
        """Verify verification suite writes valid JSON evidence artifact to disk."""
        out_file = tmp_path / "sercos_evidence.json"
        evidence = run_sercos_verification(str(out_file))

        assert out_file.is_file()
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W115"
        assert data["data"]["register_map"]["status_word"] == "%R760"
        assert data["data"]["register_map"]["configured_drives_count"] == "%R761"
        assert data["data"]["register_map"]["fault_trip_coil"] == "%M178"
