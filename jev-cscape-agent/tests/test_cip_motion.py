"""Comprehensive Unit and Integration Test Suite for Industrial CIP Motion Engine.

Work Package: W154 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Architectural Alignment (following tests/test_opensafety.py):
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1150..%R1157, %M268..%M269).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: CIP Motion drive state machine transitions and trajectory interpolation (linear/S-curve).
4. Section 4: IEEE 1588 / CIP Sync cyclic synchronization and clock jitter surveillance.
5. Section 5: Following error tracking and dynamic lag compensation.
6. Section 6: Process safety trips (0xB301, 0xB302, 0xB303, 0xB304) and Horner coil assertion (%M268, %M269).
7. Section 7: Horner OCS register space synchronization (%R1150..%R1157, %M268..%M269).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
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
from jev_cscape.telemetry.cip_motion import (
    AXIS_INTERPOLATOR_PURE_ST_POU,
    AXIS_INTERPOLATOR_SYNC_POU,
    CIP_MOTION_AXIS_SYNC_POU,
    CIP_MOTION_DEFAULT_AXIS_ID,
    CIP_MOTION_DEFAULT_CYCLE_TIME_MS,
    CIP_MOTION_DEFAULT_FOLLOWING_ERROR_TOLERANCE_MM,
    CIP_MOTION_DEFAULT_MAX_ACCEL_MMS2,
    CIP_MOTION_DEFAULT_MAX_ALLOWABLE_VELOCITY_MMS,
    CIP_MOTION_DEFAULT_MAX_CURRENT_AMPS,
    CIP_MOTION_DEFAULT_MAX_DECEL_MMS2,
    CIP_MOTION_DEFAULT_MAX_JERK_MMS3,
    CIP_MOTION_DEFAULT_MAX_VELOCITY_MMS,
    CIP_MOTION_DEFAULT_WATCHDOG_TIMEOUT_MS,
    CIP_MOTION_MAX_SYNC_JITTER_NS,
    CIP_MOTION_NOMINAL_SYNC_JITTER_NS,
    CIP_MOTION_PURE_ST_POU,
    CIP_MOTION_SYNC_POU,
    CIPMOTION_SYNC_POU,
    PURE_ST_POU,
    AxisInterpolator,
    AxisInterpolatorEngine,
    AxisInterpolatorSync,
    CipMotionAxisConfig,
    CipMotionAxisState,
    CipMotionDiagnosticCode,
    CipMotionEngine,
    CipMotionStatusBits,
    CIPMotionAxisState,
    CIPMotionDiagnosticCode,
    CIPMotionDriveState,
    CIPMotionEngine,
    CIPMotionStatusBits,
    InterpolationProfileType,
    InterpolatorProfileType,
    TrajectoryPoint,
    run_cip_motion_verification,
    scale_current_to_int16,
    scale_error_to_int16,
    scale_motion_pv_to_int16,
    scale_pos_to_int16,
    scale_position_to_int16,
    scale_vel_to_int16,
    verify_cip_motion_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def cip_motion_engine(register_table: RegisterTable) -> CipMotionEngine:
    """Provides a fresh CipMotionEngine with default axis configuration."""
    config = CipMotionAxisConfig(
        axis_id=CIP_MOTION_DEFAULT_AXIS_ID,
        axis_name="Test_Motion_Axis_1",
        profile_type=InterpolationProfileType.S_CURVE,
        max_velocity_mms=CIP_MOTION_DEFAULT_MAX_VELOCITY_MMS,
        max_allowable_velocity_mms=CIP_MOTION_DEFAULT_MAX_ALLOWABLE_VELOCITY_MMS,
        max_acceleration_mms2=CIP_MOTION_DEFAULT_MAX_ACCEL_MMS2,
        max_deceleration_mms2=CIP_MOTION_DEFAULT_MAX_DECEL_MMS2,
        max_jerk_mms3=CIP_MOTION_DEFAULT_MAX_JERK_MMS3,
        following_error_tolerance_mm=CIP_MOTION_DEFAULT_FOLLOWING_ERROR_TOLERANCE_MM,
        max_drive_current_amps=CIP_MOTION_DEFAULT_MAX_CURRENT_AMPS,
        cycle_time_ms=CIP_MOTION_DEFAULT_CYCLE_TIME_MS,
        max_sync_jitter_ns=CIP_MOTION_MAX_SYNC_JITTER_NS,
        watchdog_timeout_ms=CIP_MOTION_DEFAULT_WATCHDOG_TIMEOUT_MS,
    )
    return CipMotionEngine(config=config, register_table=register_table, initial_position_mm=0.0)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Structured Text POUs and AST symbol binding."""

    def test_verify_cip_motion_pure_st_function(self) -> None:
        """Verify helper validation function passes cleanly."""
        assert verify_cip_motion_pure_st() is True

    def test_pure_st_cip_motion_sync_ast_parsing(self) -> None:
        """Parse CIP_MOTION_SYNC_POU and assert AST attributes and register bindings."""
        SecurityGuard.assert_pure_st_content(CIP_MOTION_SYNC_POU)
        res = STParser.validate_code(CIP_MOTION_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CIP_MOTION_SYNC_POU)
        assert ast is not None
        assert ast.name == "CipMotionSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1150", "%R1151", "%R1152", "%R1153",
            "%R1154", "%R1155", "%R1156", "%R1157",
            "%M268", "%M269",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "AxisActualPositionScaled",
            "AxisCommandPositionScaled",
            "AxisActualVelocityScaled",
            "AxisFollowingErrorScaled",
            "AxisDriveCurrentAmpsScaled",
            "CIPSyncJitterNanoseconds",
            "InterpolatorTrajectoryStep",
            "DiagnosticStatusCode",
            "AxisDriveReadyPermissive",
            "MotionFollowingErrorTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pure_st_axis_interpolator_sync_ast_parsing(self) -> None:
        """Parse AXIS_INTERPOLATOR_SYNC_POU and assert AST attributes."""
        SecurityGuard.assert_pure_st_content(AXIS_INTERPOLATOR_SYNC_POU)
        res = STParser.validate_code(AXIS_INTERPOLATOR_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(AXIS_INTERPOLATOR_SYNC_POU)
        assert ast is not None
        assert ast.name == "AxisInterpolatorSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1150", "%R1151", "%R1152", "%R1153",
            "%R1154", "%R1155", "%R1156", "%R1157",
            "%M268", "%M269",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_pou_aliases_consistency(self) -> None:
        """Verify backwards compatibility aliases point to the correct POU definitions."""
        assert CIP_MOTION_AXIS_SYNC_POU == AXIS_INTERPOLATOR_SYNC_POU
        assert CIPMOTION_SYNC_POU == CIP_MOTION_SYNC_POU
        assert CIP_MOTION_PURE_ST_POU == CIP_MOTION_SYNC_POU
        assert AXIS_INTERPOLATOR_PURE_ST_POU == AXIS_INTERPOLATOR_SYNC_POU
        assert PURE_ST_POU == CIP_MOTION_SYNC_POU


# ============================================================================
# Section 2: Anti-Ladder Logic Security Interception
# ============================================================================

class TestSection2AntiLadderGuards:
    """Tests for interception and rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "bad_code, expected_reason",
        [
            ("PROGRAM BadContact\nVAR X: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM", "ladder contact"),
            ("PROGRAM BadNegContact\nVAR X: BOOL; END_VAR\n---[/]---\nEND_PROGRAM", "ladder negative contact"),
            ("PROGRAM BadCoil\nVAR X: BOOL; END_VAR\n---( )---\nEND_PROGRAM", "ladder coil"),
            ("PROGRAM BadRung\nVAR X: BOOL; END_VAR\nRUNG 1\nEND_PROGRAM", "rung keyword"),
            ("PROGRAM BadMnemonic\nVAR X: BOOL; END_VAR\nXIC %M268\nOTE %M269\nEND_PROGRAM", "ladder mnemonic"),
            ("PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM", "network keyword"),
        ],
    )
    def test_security_guard_rejects_ladder_syntax(self, bad_code: str, expected_reason: str) -> None:
        """Asserts SecurityGuard raises LadderForbiddenError for ladder logic elements."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_code)

    def test_st_parser_returns_failed_on_ladder_logic(self) -> None:
        """Asserts STParser.validate_code returns FAILED with ERR_LADDER_FORBIDDEN."""
        ladder_snippet = "PROGRAM IllegalMotion\nVAR S: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM"
        res = STParser.validate_code(ladder_snippet)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"
        assert res.data.get("ladder_rejected") is True


# ============================================================================
# Section 3: CIP Motion Drive State Machine Transitions & Interpolation
# ============================================================================

class TestSection3DriveStateMachineAndInterpolation:
    """Tests for ODVA CIP Motion axis state machine and linear/S-curve trajectory generation."""

    def test_state_machine_nominal_lifecycle(self, cip_motion_engine: CipMotionEngine) -> None:
        """Verify DISABLED -> STANDSTILL -> ACCELERATING -> CONSTANT_SPEED -> STANDSTILL -> DISABLED."""
        # Initial: DISABLED
        assert cip_motion_engine.state == CipMotionAxisState.DISABLED
        assert cip_motion_engine.drive_ready is False

        # Enable -> STANDSTILL
        res_en = cip_motion_engine.enable()
        assert res_en.status == AgentStatus.SUCCESS
        assert cip_motion_engine.state == CipMotionAxisState.STANDSTILL
        assert cip_motion_engine.drive_ready is True
        assert cip_motion_engine.reg_table.read_bit("%M268") is True

        # Move initiation
        res_move = cip_motion_engine.move_absolute(150.0)
        assert res_move.status == AgentStatus.SUCCESS
        assert cip_motion_engine.state == CipMotionAxisState.ACCELERATING

        # Stop command returns axis to STANDSTILL
        res_stop = cip_motion_engine.stop()
        assert res_stop.status == AgentStatus.SUCCESS
        assert cip_motion_engine.state == CipMotionAxisState.STANDSTILL
        assert cip_motion_engine.command_velocity == 0.0

        # Disable command returns to DISABLED
        res_dis = cip_motion_engine.disable()
        assert res_dis.status == AgentStatus.SUCCESS
        assert cip_motion_engine.state == CipMotionAxisState.DISABLED
        assert cip_motion_engine.drive_ready is False
        assert cip_motion_engine.reg_table.read_bit("%M268") is False

    def test_move_rejected_when_disabled_or_faulted(self, cip_motion_engine: CipMotionEngine) -> None:
        """Verify move_absolute/move_relative commands are rejected when axis is DISABLED or FAULT_STOP."""
        # Axis is DISABLED
        res1 = cip_motion_engine.move_absolute(50.0)
        assert res1.status == AgentStatus.BLOCKED
        assert res1.error_code == "ERR_AXIS_DISABLED"

        # Enable then fault
        cip_motion_engine.enable()
        cip_motion_engine.fault_stop(CipMotionDiagnosticCode.CIP_ERR_DRIVE_FAULT)
        assert cip_motion_engine.state == CipMotionAxisState.FAULT_STOP

        res2 = cip_motion_engine.move_absolute(50.0)
        assert res2.status == AgentStatus.BLOCKED
        assert res2.error_code == "ERR_AXIS_FAULTED"

    def test_linear_trapezoidal_trajectory_interpolation(self) -> None:
        """Verify linear (trapezoidal) trajectory planner obeys velocity and accel bounds."""
        interpolator = AxisInterpolator(
            max_velocity_mms=100.0,
            max_acceleration_mms2=200.0,
            max_deceleration_mms2=200.0,
            cycle_time_ms=2.0,
        )
        points = interpolator.plan_trajectory(
            start_pos=0.0,
            target_pos=80.0,
            profile_type=InterpolationProfileType.LINEAR,
        )

        assert len(points) > 10
        assert points[0].position == 0.0
        assert abs(points[-1].position - 80.0) < 1e-4

        # Verify kinematic bounds
        for p in points:
            assert abs(p.velocity) <= 100.0 + 1e-3
            assert abs(p.acceleration) <= 200.0 + 1e-3

    def test_scurve_jerk_limited_trajectory_interpolation(self) -> None:
        """Verify S-curve trajectory planner provides bounded jerk and continuous acceleration."""
        interpolator = AxisInterpolator(
            max_velocity_mms=150.0,
            max_acceleration_mms2=300.0,
            max_deceleration_mms2=300.0,
            max_jerk_mms3=1500.0,
            cycle_time_ms=2.0,
        )
        points = interpolator.plan_trajectory(
            start_pos=10.0,
            target_pos=110.0,
            profile_type=InterpolationProfileType.S_CURVE,
        )

        assert len(points) > 10
        assert abs(points[0].position - 10.0) < 1e-4
        assert abs(points[-1].position - 110.0) < 1e-4

        # Verify jerk and acceleration bounds
        for p in points:
            assert abs(p.velocity) <= 150.0 + 1e-3
            assert abs(p.acceleration) <= 300.0 + 1e-3
            assert abs(p.jerk) <= 1500.0 + 1e-3

    def test_relative_motion_target_accumulation(self, cip_motion_engine: CipMotionEngine) -> None:
        """Verify relative move plans trajectory relative to current commanded position."""
        cip_motion_engine.enable()
        cip_motion_engine.command_position = 25.0
        cip_motion_engine.actual_position = 25.0

        res = cip_motion_engine.move_relative(50.0)
        assert res.status == AgentStatus.SUCCESS
        assert res.data["target_position"] == 75.0


# ============================================================================
# Section 4: IEEE 1588 / CIP Sync Cyclic Synchronization & Jitter
# ============================================================================

class TestSection4CIPSyncClockJitter:
    """Tests for IEEE 1588 / CIP Sync cyclic clock jitter and watchdog temporal surveillance."""

    def test_nominal_cyclic_sync_jitter_tracking(self, cip_motion_engine: CipMotionEngine) -> None:
        """Verify IEEE 1588 cyclic sync packets update jitter register %R1155 (< 100 ns)."""
        cip_motion_engine.enable()

        jitters = [20.0, 35.0, 42.0, 15.0, 48.0]
        for j in jitters:
            res = cip_motion_engine.receive_sync_packet(jitter_ns=j)
            assert res.status == AgentStatus.SUCCESS
            cip_motion_engine.step_cycle(delta_ms=2.0)

            # %R1155 must reflect scaled integer nanoseconds
            assert cip_motion_engine.reg_table.read_word("%R1155") == int(round(j))

        assert cip_motion_engine.max_observed_jitter_ns == 48.0

    def test_cyclic_sync_loss_watchdog_timeout_0xB304(self, cip_motion_engine: CipMotionEngine) -> None:
        """Verify silence watchdog timeout (> 50.0 ms) triggers CIP_ERR_COMM_LOSS (0xB304)."""
        cip_motion_engine.enable()
        cip_motion_engine.receive_sync_packet()
        assert cip_motion_engine.reg_table.read_bit("%M268") is True

        # Advance elapsed time beyond 50.0 ms watchdog without receiving sync packet
        res_timeout = cip_motion_engine.step_cycle(delta_ms=60.0)
        assert res_timeout.status == AgentStatus.FAILED
        assert res_timeout.error_code == "CIP_ERR_COMM_LOSS"

        rt = cip_motion_engine.reg_table
        assert cip_motion_engine.state == CipMotionAxisState.FAULT_STOP
        assert cip_motion_engine.diagnostic_code == CipMotionDiagnosticCode.CIP_ERR_COMM_LOSS
        assert rt.read_uword("%R1157") == 0xB304
        assert rt.read_bit("%M268") is False
        assert rt.read_bit("%M269") is True


# ============================================================================
# Section 5: Following Error Tracking & Dynamic Lag Compensation
# ============================================================================

class TestSection5FollowingErrorAndLag:
    """Tests for following error surveillance, dynamic lag compensation, and tolerance trip."""

    def test_nominal_following_error_tracking(self, cip_motion_engine: CipMotionEngine) -> None:
        """Verify following error calculation and %R1153 register synchronization."""
        cip_motion_engine.enable()
        cip_motion_engine.command_position = 100.0
        cip_motion_engine.actual_position = 99.88  # Error = 0.12 mm

        cip_motion_engine.step_cycle(
            delta_ms=2.0,
            actual_pos_override=99.88,
            actual_vel_override=20.0,
        )

        # Following error = 100.0 - 99.88 = 0.12 mm
        assert abs(cip_motion_engine.following_error - 0.12) < 1e-4
        # Scaled x100 in %R1153 -> 12
        assert cip_motion_engine.reg_table.read_word("%R1153") == 12

    def test_following_error_tolerance_excursion_trip_0xB302(
        self, cip_motion_engine: CipMotionEngine
    ) -> None:
        """Verify tracking error exceeding tolerance (0.80 mm > 0.50 mm) trips 0xB302."""
        cip_motion_engine.enable()
        cip_motion_engine.command_position = 50.0

        # Inject actual position with 0.80 mm error
        res_trip = cip_motion_engine.step_cycle(
            delta_ms=2.0,
            actual_pos_override=49.20,
            actual_vel_override=10.0,
        )

        assert res_trip.status == AgentStatus.FAILED
        assert res_trip.error_code == "CIP_ERR_FOLLOWING_ERROR"

        rt = cip_motion_engine.reg_table
        assert cip_motion_engine.state == CipMotionAxisState.FAULT_STOP
        assert cip_motion_engine.diagnostic_code == CipMotionDiagnosticCode.CIP_ERR_FOLLOWING_ERROR
        assert rt.read_uword("%R1157") == 0xB302
        assert rt.read_bit("%M268") is False
        assert rt.read_bit("%M269") is True
        assert rt.read_word("%R1153") == 80  # 0.80 mm scaled x100

    def test_servo_compliance_lag_simulation(self, cip_motion_engine: CipMotionEngine) -> None:
        """Verify dynamic velocity-proportional servo lag model generates realistic following error."""
        cip_motion_engine.enable()
        cip_motion_engine.move_absolute(100.0)

        # Execute 15 steps
        for _ in range(15):
            cip_motion_engine.receive_sync_packet()
            cip_motion_engine.step_cycle(delta_ms=2.0)

        # In motion: following error should be non-zero but bounded strictly below tolerance
        assert cip_motion_engine.following_error > 0.0
        assert cip_motion_engine.following_error < cip_motion_engine.config.following_error_tolerance_mm
        assert cip_motion_engine.diagnostic_code == CipMotionDiagnosticCode.OK


# ============================================================================
# Section 6: Process Safety Trips (0xB301..0xB304) & Horner Coils
# ============================================================================

class TestSection6ProcessSafetyTrips:
    """Tests for Process Safety Trips (0xB301, 0xB302, 0xB303, 0xB304) and Horner Coils (%M268, %M269)."""

    def test_trip_0xb301_axis_overspeed(self, cip_motion_engine: CipMotionEngine) -> None:
        """0xB301 Axis overspeed (> 250 mm/s) clears %M268, sets %R1157, and stops drive."""
        cip_motion_engine.enable()
        cip_motion_engine.receive_sync_packet()

        res = cip_motion_engine.step_cycle(delta_ms=2.0, inject_overspeed=True)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "CIP_ERR_AXIS_OVERSPEED"

        rt = cip_motion_engine.reg_table
        assert cip_motion_engine.diagnostic_code == CipMotionDiagnosticCode.CIP_ERR_AXIS_OVERSPEED
        assert rt.read_uword("%R1157") == 0xB301
        assert rt.read_bit("%M268") is False
        assert cip_motion_engine.state == CipMotionAxisState.FAULT_STOP

    def test_trip_0xb302_following_error(self, cip_motion_engine: CipMotionEngine) -> None:
        """0xB302 Following error excursion asserts %M269, clears %M268, and sets %R1157."""
        cip_motion_engine.enable()
        cip_motion_engine.receive_sync_packet()

        bad_pos = cip_motion_engine.command_position - 1.50
        res = cip_motion_engine.step_cycle(delta_ms=2.0, actual_pos_override=bad_pos, actual_vel_override=20.0)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "CIP_ERR_FOLLOWING_ERROR"

        rt = cip_motion_engine.reg_table
        assert cip_motion_engine.diagnostic_code == CipMotionDiagnosticCode.CIP_ERR_FOLLOWING_ERROR
        assert rt.read_uword("%R1157") == 0xB302
        assert rt.read_bit("%M268") is False
        assert rt.read_bit("%M269") is True

    def test_trip_0xb303_drive_inverter_fault(self, cip_motion_engine: CipMotionEngine) -> None:
        """0xB303 Inverter current trip (> 25 A) asserts %M269, clears %M268, and sets %R1157."""
        cip_motion_engine.enable()
        cip_motion_engine.receive_sync_packet()

        res = cip_motion_engine.step_cycle(delta_ms=2.0, current_amps=30.0)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "CIP_ERR_DRIVE_FAULT"

        rt = cip_motion_engine.reg_table
        assert cip_motion_engine.diagnostic_code == CipMotionDiagnosticCode.CIP_ERR_DRIVE_FAULT
        assert rt.read_uword("%R1157") == 0xB303
        assert rt.read_bit("%M268") is False
        assert rt.read_bit("%M269") is True

    def test_trip_0xb304_communication_loss(self, cip_motion_engine: CipMotionEngine) -> None:
        """0xB304 Cyclic sync loss timeout asserts %M269, clears %M268, and sets %R1157."""
        cip_motion_engine.enable()
        cip_motion_engine.receive_sync_packet()

        # Step 70 ms with no sync update
        res = cip_motion_engine.step_cycle(delta_ms=70.0)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "CIP_ERR_COMM_LOSS"

        rt = cip_motion_engine.reg_table
        assert cip_motion_engine.diagnostic_code == CipMotionDiagnosticCode.CIP_ERR_COMM_LOSS
        assert rt.read_uword("%R1157") == 0xB304
        assert rt.read_bit("%M268") is False
        assert rt.read_bit("%M269") is True

    def test_operator_manual_reset_handshake(self, cip_motion_engine: CipMotionEngine) -> None:
        """Verify operator reset handshake clears fault latch, resets %M269, and restores %M268."""
        cip_motion_engine.enable()
        cip_motion_engine.fault_stop(CipMotionDiagnosticCode.CIP_ERR_FOLLOWING_ERROR)

        rt = cip_motion_engine.reg_table
        assert rt.read_bit("%M269") is True
        assert rt.read_bit("%M268") is False
        assert rt.read_uword("%R1157") == 0xB302

        # Operator manual reset
        res_reset = cip_motion_engine.reset_fault(force=True)
        assert res_reset.status == AgentStatus.SUCCESS
        assert cip_motion_engine.diagnostic_code == CipMotionDiagnosticCode.OK
        assert rt.read_uword("%R1157") == 0x0000
        assert rt.read_bit("%M269") is False
        assert rt.read_bit("%M268") is True
        assert cip_motion_engine.state == CipMotionAxisState.STANDSTILL


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R1150..%R1157)
# ============================================================================

class TestSection7HornerRegisterSpaceSync:
    """Tests for complete register table mapping verification (%R1150..%R1157, %M268..%M269)."""

    def test_scale_helper_functions(self) -> None:
        """Verify scale helpers clamp and scale correctly into signed 16-bit ranges."""
        assert scale_pos_to_int16(125.0) == 1250
        assert scale_pos_to_int16(-45.5) == -455
        assert scale_pos_to_int16(5000.0) == 32767
        assert scale_pos_to_int16(-5000.0) == -32768

        assert scale_vel_to_int16(50.0) == 500
        assert scale_error_to_int16(0.12) == 12
        assert scale_current_to_int16(8.5) == 85

        # Check aliases
        assert scale_motion_pv_to_int16(125.0) == 1250
        assert scale_position_to_int16(125.0) == 1250

    def test_full_register_map_integrity(self, cip_motion_engine: CipMotionEngine) -> None:
        """Assert each Horner mapped register reflects internal engine kinematics and status."""
        cip_motion_engine.enable()
        cip_motion_engine.receive_sync_packet(jitter_ns=42.0)

        # Preset deterministic values
        cip_motion_engine.command_position = 120.0
        cip_motion_engine.actual_position = 119.9
        cip_motion_engine.actual_velocity = 45.0
        cip_motion_engine.following_error = 0.10
        cip_motion_engine.drive_current_amps = 7.4
        cip_motion_engine.trajectory_step = 28
        cip_motion_engine._sync_registers()

        rt = cip_motion_engine.reg_table
        assert rt.read_word("%R1150") == 1199   # 119.9 mm scaled x10 -> 1199
        assert rt.read_word("%R1151") == 1200   # 120.0 mm scaled x10 -> 1200
        assert rt.read_word("%R1152") == 450    # 45.0 mm/s scaled x10 -> 450
        assert rt.read_word("%R1153") == 10     # 0.10 mm scaled x100 -> 10
        assert rt.read_word("%R1154") == 74     # 7.4 A scaled x10 -> 74
        assert rt.read_word("%R1155") == 42     # 42 ns jitter
        assert rt.read_word("%R1156") == 28     # Step 28
        assert rt.read_uword("%R1157") == 0x0000
        assert rt.read_bit("%M268") is True
        assert rt.read_bit("%M269") is False

    def test_register_synchronization_on_step(self, cip_motion_engine: CipMotionEngine) -> None:
        """Verify registers update dynamically during motion execution."""
        cip_motion_engine.enable()
        cip_motion_engine.move_absolute(60.0)

        cip_motion_engine.receive_sync_packet(jitter_ns=30.0)
        cip_motion_engine.step_cycle(delta_ms=2.0)

        rt = cip_motion_engine.reg_table
        assert rt.read_word("%R1156") >= 1
        assert rt.read_bit("%M268") is True
        assert rt.read_bit("%M269") is False


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration Test
# ============================================================================

class TestSection8VerificationSuite:
    """Tests for run_cip_motion_verification output and evidence file emission."""

    def test_run_cip_motion_verification_success(self, tmp_path: Path) -> None:
        """Runs the 9-stage verification suite and verifies strict 4-state contract JSON."""
        evidence_file = tmp_path / "cip_motion_evidence.json"
        res = run_cip_motion_verification(output_path=str(evidence_file))

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["tests"]) == 9

        # Ensure all 9 individual stages passed
        for stage_test in res["data"]["tests"]:
            assert stage_test["passed"] is True

        # Verify evidence file written and valid
        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W154"

    def test_evidence_register_map_completeness(self, tmp_path: Path) -> None:
        """Verify evidence output contains all Horner registers (%R1150..%R1157, %M268..%M269)."""
        evidence_file = tmp_path / "cip_motion_evidence_map.json"
        res = run_cip_motion_verification(output_path=str(evidence_file))

        values = res["data"]["register_map"]["values"]
        assert "%R1150" in values
        assert "%R1151" in values
        assert "%R1152" in values
        assert "%R1153" in values
        assert "%R1154" in values
        assert "%R1155" in values
        assert "%R1156" in values
        assert "%R1157" in values
        assert "%M268" in values
        assert "%M269" in values
