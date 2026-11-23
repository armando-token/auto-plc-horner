"""Comprehensive Unit & Benchmark Tests for In-Memory Scan Cycle Simulation Engine (W018 / Gate G4).

Validates:
1. Virtual clock zero-drift integer arithmetic and IEC time formatting.
2. Single-step execution and custom scan delta_t.
3. Multi-cycle deterministic execution and trace capture.
4. Horner %S1 first scan transition (True on scan 0, False on scan 1+).
5. Horner %S7 always True (ALW_ON) and %S8 always False (ALW_OFF).
6. Clock pulse square waves (%S3 10ms, %S4 100ms, %S5 1s).
7. System registers %SR1 (cycle count) and %SR5 (scan duration).
8. Read-only protection for %SR registers and %S bits.
9. Logic callback execution, priority ordering, and I/O transformation.
10. Memory staging isolation (input latching, output staging, read-your-own-writes).
11. Fault containment, transactional rollback of staged writes, and recovery.
12. Benchmark: 1,000 cycles in < 200ms in FAST mode.
13. Telemetry trace, memory diffing, history queries, and Gate G4 evidence export.
"""

import time
from typing import Any, Dict, List
import pytest

from jev_cscape.simulation.engine import (
    CycleList,
    CycleSnapshot,
    PacingMode,
    ScanPhase,
    SimulationBackend,
    SimulationEngine,
    SimulationFaultError,
    SimulationState,
    VirtualClock,
)
from jev_cscape.simulation.models import TraceConfig
from jev_cscape.contracts import AgentStatus


@pytest.fixture
def engine() -> SimulationEngine:
    """Fixture providing a fresh default simulation engine."""
    return SimulationEngine(default_dt_ms=10.0, backend=SimulationBackend.EMULATED)


# ============================================================================
# 1. Virtual Clock & Timing
# ============================================================================

class TestVirtualClock:
    """Validates deterministic integer virtual clock advancement."""

    def test_virtual_clock_zero_drift_over_10000_cycles(self):
        clock = VirtualClock(default_dt_ms=10.0)
        assert clock.cycle_count == 0
        assert clock.elapsed_ms == 0.0

        for i in range(1, 10001):
            cycle, elapsed_ms, dt = clock.advance()
            assert cycle == i
            assert dt == 10.0

        assert clock.cycle_count == 10000
        assert clock.elapsed_us == 100_000_000
        assert clock.elapsed_ms == 100000.0
        assert clock.elapsed_seconds == 100.0
        assert clock.format_iec_time() == "T#1m40s"

    def test_virtual_clock_reset(self):
        clock = VirtualClock(default_dt_ms=10.0)
        clock.advance(25.0)
        clock.advance(15.0)
        assert clock.cycle_count == 2
        assert clock.elapsed_ms == 40.0

        clock.reset()
        assert clock.cycle_count == 0
        assert clock.elapsed_ms == 0.0
        assert clock.elapsed_us == 0
        assert clock.format_iec_time() == "T#0ms"

    def test_virtual_clock_invalid_dt(self):
        with pytest.raises(ValueError, match="default_dt_ms must be positive"):
            VirtualClock(default_dt_ms=0)
        with pytest.raises(ValueError, match="default_dt_ms must be positive"):
            VirtualClock(default_dt_ms=-5.0)

        clock = VirtualClock(default_dt_ms=10.0)
        with pytest.raises(ValueError, match="Scan step delta_t must be positive"):
            clock.advance(0)
        with pytest.raises(ValueError, match="Scan step delta_t must be positive"):
            clock.advance(-10.0)


# ============================================================================
# 2. Single-Step Execution
# ============================================================================

class TestSingleStepExecution:
    """Validates discrete single-step scan cycle semantics."""

    def test_engine_initial_state(self, engine: SimulationEngine):
        assert engine.cycle_count == 0
        assert engine.elapsed_time_ms == 0.0
        assert engine.state == SimulationState.IDLE
        assert engine.backend == SimulationBackend.EMULATED
        assert len(engine.trace) == 0

    def test_single_step_advances_cycle_and_time(self, engine: SimulationEngine):
        snap = engine.step()
        assert snap.cycle == 0
        assert snap.time_ms == 10.0
        assert snap.dt_ms == 10.0
        assert engine.cycle_count == 1
        assert engine.elapsed_time_ms == 10.0
        assert engine.state == SimulationState.RUNNING
        assert len(engine.trace) == 1
        assert engine.trace[0] == snap

    def test_single_step_custom_dt(self, engine: SimulationEngine):
        snap1 = engine.step(dt_ms=25.0)
        assert snap1.dt_ms == 25.0
        assert snap1.time_ms == 25.0
        assert engine.elapsed_time_ms == 25.0
        assert snap1.system_registers["%SR5"] == 25

        snap2 = engine.step(dt_ms=15.0)
        assert snap2.cycle == 1
        assert snap2.dt_ms == 15.0
        assert snap2.time_ms == 40.0
        assert engine.elapsed_time_ms == 40.0
        assert snap2.system_registers["%SR5"] == 15

    def test_snapshot_immutability(self, engine: SimulationEngine):
        engine.set_register("%R1", 100)
        snap = engine.step()
        assert snap.registers.get("%R1") == 100

        # Modifying snapshot dictionary must not mutate engine internal memory
        snap.registers["%R1"] = 999
        assert engine.read_register("%R1") == 100


# ============================================================================
# 3. Multi-Cycle Execution
# ============================================================================

class TestMultiCycleExecution:
    """Validates multi-cycle execution loops, timing, and determinism."""

    def test_run_cycles_count_and_timing(self, engine: SimulationEngine):
        snaps = engine.run_cycles(10, dt_ms=10.0)
        assert len(snaps) == 10
        assert engine.cycle_count == 10
        assert engine.elapsed_time_ms == 100.0
        assert snaps[0].cycle == 0
        assert snaps[0].time_ms == 10.0
        assert snaps[9].cycle == 9
        assert snaps[9].time_ms == 100.0
        assert len(engine.trace) == 10

    def test_multi_cycle_determinism(self):
        engine1 = SimulationEngine(default_dt_ms=10.0)
        engine2 = SimulationEngine(default_dt_ms=10.0)

        def logic(eng: SimulationEngine):
            count = eng.read_register("%R10") or 0
            eng.write_register("%R10", count + 5)

        engine1.register_logic_callback(logic)
        engine2.register_logic_callback(logic)

        trace1 = engine1.run_cycles(20)
        trace2 = engine2.run_cycles(20)

        assert len(trace1) == len(trace2)
        for s1, s2 in zip(trace1, trace2):
            assert s1.cycle == s2.cycle
            assert s1.time_ms == s2.time_ms
            assert s1.registers == s2.registers
            assert s1.system_bits == s2.system_bits

    def test_run_cycles_invalid_counts(self, engine: SimulationEngine):
        snaps = engine.run_cycles(0)
        assert snaps == []
        assert engine.cycle_count == 0

        with pytest.raises(ValueError, match="Count must be non-negative"):
            engine.run_cycles(-5)


# ============================================================================
# 4. %S1 First Scan Transition
# ============================================================================

class TestFirstScanBitS1:
    """Validates %S1 (First Scan Flag): True exclusively on cycle 0, False on 1+."""

    def test_s1_true_on_scan_0_false_on_scan_1_plus(self, engine: SimulationEngine):
        snap0 = engine.step()
        assert snap0.system_bits["%S1"] is True
        assert engine.read_system_bit(1) is True

        snap1 = engine.step()
        assert snap1.system_bits["%S1"] is False
        assert engine.read_system_bit(1) is False

        for _ in range(2, 10):
            snap_i = engine.step()
            assert snap_i.system_bits["%S1"] is False
            assert engine.read_system_bit(1) is False

    def test_s1_initialization_in_logic_callback(self, engine: SimulationEngine):
        def startup_logic(eng: SimulationEngine):
            if eng.read_system_bit(1):
                eng.write_register("%R1", 1000)
            else:
                curr = eng.read_register("%R1")
                eng.write_register("%R1", curr + 10)

        engine.register_logic_callback(startup_logic)

        engine.step()  # Scan 0
        assert engine.read_register("%R1") == 1000

        engine.step()  # Scan 1
        assert engine.read_register("%R1") == 1010

        engine.step()  # Scan 2
        assert engine.read_register("%R1") == 1020

    def test_reset_restores_first_scan_pulse(self, engine: SimulationEngine):
        engine.run_cycles(5)
        assert engine.read_system_bit(1) is False

        engine.reset()
        assert engine.cycle_count == 0
        assert engine.elapsed_time_ms == 0.0

        snap = engine.step()
        assert snap.cycle == 0
        assert snap.system_bits["%S1"] is True

    def test_s1_cannot_be_tampered_by_user_logic(self, engine: SimulationEngine):
        def tamper_logic(eng: SimulationEngine):
            eng.write_register("%S1", True)

        engine.register_logic_callback(tamper_logic)
        engine.step()  # scan 0: %S1 True
        snap1 = engine.step()  # scan 1: %S1 must remain False
        assert snap1.system_bits["%S1"] is False


# ============================================================================
# 5. %S7 Always True & %S8 Always False
# ============================================================================

class TestAlwaysOnAlwaysOffBits:
    """Validates Horner standard %S7 (ALW_ON) and %S8 (ALW_OFF) invariants."""

    def test_s7_always_true_across_cycles(self, engine: SimulationEngine):
        snaps = engine.run_cycles(30, dt_ms=10.0)
        for s in snaps:
            assert s.system_bits["%S7"] is True
            assert engine.read_system_bit(7) is True

    def test_s8_always_false_across_cycles(self, engine: SimulationEngine):
        snaps = engine.run_cycles(30, dt_ms=10.0)
        for s in snaps:
            assert s.system_bits["%S8"] is False
            assert engine.read_system_bit(8) is False

    def test_s7_s8_branching_in_logic(self, engine: SimulationEngine):
        def logic(eng: SimulationEngine):
            if eng.read_system_bit(7):
                eng.write_register("%M1", True)
            if eng.read_system_bit(8):
                eng.write_register("%M2", True)

        engine.register_logic_callback(logic)
        engine.step()
        assert engine.read_register("%M1") is True
        assert engine.read_register("%M2") is None or engine.read_register("%M2") is False

    def test_s7_s8_tamper_resistance(self, engine: SimulationEngine):
        def tamper(eng: SimulationEngine):
            eng.write_register("%S7", False)
            eng.write_register("%S8", True)

        engine.register_logic_callback(tamper)
        snap = engine.step()
        assert snap.system_bits["%S7"] is True
        assert snap.system_bits["%S8"] is False


# ============================================================================
# 6. Clock Pulse Transitions (%S3, %S4, %S5)
# ============================================================================

class TestClockPulseTransitions:
    """Validates square wave clock pulse generation: %S3 (10ms), %S4 (100ms), %S5 (1s)."""

    def test_s3_10ms_clock_transitions(self, engine: SimulationEngine):
        s3_values = []
        for _ in range(6):  # 10, 20, 30, 40, 50, 60ms
            snap = engine.step(dt_ms=10.0)
            s3_values.append(snap.system_bits["%S3"])

        assert s3_values == [True, False, True, False, True, False]

    def test_s4_100ms_clock_transitions(self, engine: SimulationEngine):
        s4_values = []
        for _ in range(5):  # 100, 200, 300, 400, 500ms
            snap = engine.step(dt_ms=100.0)
            s4_values.append(snap.system_bits["%S4"])

        assert s4_values == [True, False, True, False, True]

    def test_s5_1s_clock_transitions(self, engine: SimulationEngine):
        s5_values = []
        for _ in range(4):  # 1000, 2000, 3000, 4000ms
            snap = engine.step(dt_ms=1000.0)
            s5_values.append(snap.system_bits["%S5"])

        assert s5_values == [True, False, True, False]

    def test_clock_pulse_with_irregular_dt(self, engine: SimulationEngine):
        snap1 = engine.step(dt_ms=25.0)  # t=25ms -> 25/10=2 -> False
        assert snap1.system_bits["%S3"] is False

        snap2 = engine.step(dt_ms=25.0)  # t=50ms -> 50/10=5 -> True
        assert snap2.system_bits["%S3"] is True

        snap3 = engine.step(dt_ms=25.0)  # t=75ms -> 75/10=7 -> True
        assert snap3.system_bits["%S3"] is True

        snap4 = engine.step(dt_ms=25.0)  # t=100ms -> 100/10=10 -> False, 100/100=1 -> True
        assert snap4.system_bits["%S3"] is False
        assert snap4.system_bits["%S4"] is True


# ============================================================================
# 7. System Registers (%SR1, %SR5) & Protection
# ============================================================================

class TestSystemRegisters:
    """Validates %SR1 scan counter, %SR5 scan duration, and read-only protection."""

    def test_sr1_and_sr5_mechanics(self, engine: SimulationEngine):
        assert engine.read_word("%SR1") == 0
        assert engine.read_word("%SR5") == 10

        for c in range(1, 6):
            engine.step()
            assert engine.read_word("%SR1") == c
            assert engine.read_word("%SR5") == 10

    def test_sr1_rollover(self, engine: SimulationEngine):
        engine.virtual_clock._cycle_count = 65535
        engine.cycle_count = 65535
        engine.step()
        assert engine.read_word("%SR1") == 0
        assert engine.virtual_clock.cycle_count == 65536

    def test_read_only_protection(self, engine: SimulationEngine):
        with pytest.raises(PermissionError, match="READ-ONLY"):
            engine.write_word("%SR1", 500)

        with pytest.raises(PermissionError, match="read-only"):
            engine.write_bit("%S1", True)


# ============================================================================
# 8. Logic Callback Execution
# ============================================================================

class TestLogicCallbackExecution:
    """Validates execution and ordering of user logic callbacks."""

    def test_callback_invoked_each_cycle(self, engine: SimulationEngine):
        invocations = []

        def spy_callback(eng: SimulationEngine):
            invocations.append((eng.cycle_count, eng.elapsed_time_ms))

        engine.register_logic_callback(spy_callback)
        engine.run_cycles(4, dt_ms=10.0)

        assert len(invocations) == 4
        assert invocations == [(0, 10.0), (1, 20.0), (2, 30.0), (3, 40.0)]

    def test_callback_io_transformation(self, engine: SimulationEngine):
        def motor_interlock(eng: SimulationEngine):
            start = eng.read_register("%I1")
            stop = eng.read_register("%I2")
            prev_run = eng.read_register("%Q1") or False
            new_run = (start or prev_run) and not stop
            eng.write_register("%Q1", new_run)

        engine.register_logic_callback(motor_interlock)

        # Start pressed
        engine.set_input("%I1", True)
        engine.set_input("%I2", False)
        engine.step()
        assert engine.read_register("%Q1") is True

        # Start released, latch maintained
        engine.set_input("%I1", False)
        engine.step()
        assert engine.read_register("%Q1") is True

        # Stop pressed, latch drops
        engine.set_input("%I2", True)
        engine.step()
        assert engine.read_register("%Q1") is False

    def test_multiple_callbacks_ordered_execution(self, engine: SimulationEngine):
        log = []

        def logic_stage1(eng: SimulationEngine):
            log.append("stage1")
            eng.write_register("%R10", 100)

        def logic_stage2(eng: SimulationEngine):
            log.append("stage2")
            val = eng.read_register("%R10")
            eng.write_register("%R20", val * 2)

        engine.register_logic_callback(logic_stage1)
        engine.register_logic_callback(logic_stage2)
        engine.step()

        assert log == ["stage1", "stage2"]
        assert engine.read_register("%R10") == 100
        assert engine.read_register("%R20") == 200


# ============================================================================
# 9. Memory Staging Isolation & Double-Buffering
# ============================================================================

class TestMemoryStagingIsolation:
    """Validates 3-phase memory staging: Latched Inputs -> Logic Staging -> Committed Outputs."""

    def test_input_latching_isolation(self, engine: SimulationEngine):
        engine.set_input("%I1", True)
        observed_during_logic = []

        def logic(eng: SimulationEngine):
            observed_during_logic.append(eng.read_register("%I1"))
            # External source mutates input mid-cycle
            eng.set_input("%I1", False)
            # Active cycle must still see latched True
            observed_during_logic.append(eng.read_register("%I1"))

        engine.register_logic_callback(logic)
        engine.step()

        assert observed_during_logic == [True, True]

        # Next cycle observes the newly latched False
        engine.step()
        assert engine.read_register("%I1") is False

    def test_output_staging_isolation_uncommitted_until_commit(self, engine: SimulationEngine):
        engine.write_register("%Q1", False)
        engine.step()
        assert engine.get_committed_output("%Q1") is False

        staging_check = {}

        def logic(eng: SimulationEngine):
            eng.write_register("%Q1", True)
            # Committed output before commit is still False
            staging_check["committed_before_finish"] = eng.get_committed_output("%Q1")
            # Logic can read its own uncommitted write (staging overlay)
            staging_check["staged_read"] = eng.read_register("%Q1")

        engine.register_logic_callback(logic)
        engine.step()

        assert staging_check["committed_before_finish"] is False
        assert staging_check["staged_read"] is True
        assert engine.get_committed_output("%Q1") is True

    def test_read_your_own_writes_in_logic(self, engine: SimulationEngine):
        def accumulator(eng: SimulationEngine):
            eng.write_register("%M10", 50)
            assert eng.read_register("%M10") == 50
            eng.write_register("%M10", 75)
            assert eng.read_register("%M10") == 75

        engine.register_logic_callback(accumulator)
        engine.step()
        assert engine.read_register("%M10") == 75


# ============================================================================
# 10. Fault Recovery & Transactional Rollback
# ============================================================================

class TestFaultRecovery:
    """Validates transactional rollback and fault handling in simulation cycles."""

    def test_logic_exception_halts_cycle_safely(self, engine: SimulationEngine):
        def faulty_logic(eng: SimulationEngine):
            raise ZeroDivisionError("Division by zero in PID calculation")

        engine.register_logic_callback(faulty_logic)

        with pytest.raises(SimulationFaultError, match="Division by zero in PID calculation"):
            engine.step()

        assert engine.state == SimulationState.FAULTED
        assert engine.last_fault is not None
        assert "ZeroDivisionError" in repr(engine.last_fault)

    def test_fault_rolls_back_staged_outputs(self, engine: SimulationEngine):
        # Scan 0: successful baseline write
        engine.write_register("%Q10", 100)
        engine.step()
        assert engine.read_register("%Q10") == 100

        # Scan 1: logic writes to staged memory, then throws
        def crashing_logic(eng: SimulationEngine):
            eng.write_register("%Q10", 999)  # Staged write
            raise RuntimeError("Hardware sensor failure")

        engine.register_logic_callback(crashing_logic)

        with pytest.raises(SimulationFaultError, match="Hardware sensor failure"):
            engine.step()

        # Staged write of 999 must have been rolled back; retains committed 100
        assert engine.read_register("%Q10") == 100
        assert engine.get_committed_output("%Q10") == 100

    def test_engine_refuses_step_while_faulted(self, engine: SimulationEngine):
        def fault_logic(eng: SimulationEngine):
            raise ValueError("Invalid parameter")

        engine.register_logic_callback(fault_logic)
        with pytest.raises(SimulationFaultError):
            engine.step()

        assert engine.state == SimulationState.FAULTED

        with pytest.raises(SimulationFaultError, match="Cannot step while in FAULTED state"):
            engine.step()

    def test_fault_recovery_and_resumption(self, engine: SimulationEngine):
        def fault_once(eng: SimulationEngine):
            if eng.cycle_count == 0:
                raise ValueError("Scan 0 error")
            eng.write_register("%R50", 1234)

        engine.register_logic_callback(fault_once)

        with pytest.raises(SimulationFaultError):
            engine.step()
        assert engine.state == SimulationState.FAULTED

        # Recover engine
        engine.clear_fault()
        assert engine.state == SimulationState.IDLE
        assert engine.last_fault is None

        # Next step should succeed
        snap = engine.step()
        assert snap.state == SimulationState.RUNNING
        assert engine.read_register("%R50") == 1234

    def test_reset_clears_fault_and_restores_clean_slate(self, engine: SimulationEngine):
        def fault_logic(eng: SimulationEngine):
            raise RuntimeError("Fatal system fault")

        engine.register_logic_callback(fault_logic)
        with pytest.raises(SimulationFaultError):
            engine.step()

        engine.reset()
        assert engine.cycle_count == 0
        assert engine.elapsed_time_ms == 0.0
        assert engine.state == SimulationState.IDLE
        assert engine.last_fault is None
        assert len(engine.trace) == 0


# ============================================================================
# 11. Benchmark: 1,000 Cycles Under 200ms
# ============================================================================

def test_benchmark_1000_cycles_under_200ms():
    """Benchmark: 1,000 cycles must execute in < 200ms in FAST mode without drift."""
    engine = SimulationEngine(default_dt_ms=10.0, pacing_mode=PacingMode.FAST)

    wall_t0 = time.perf_counter()
    result = engine.run_cycles(1000)
    wall_duration_s = time.perf_counter() - wall_t0

    assert result.status == AgentStatus.SUCCESS
    assert result.data["cycles_executed"] == 1000
    assert result.data["virtual_elapsed_ms"] == 10000.0
    assert result.data["sr1_scan_counter"] == 1000
    assert result.data["sr5_scan_duration"] == 10

    # Must execute well under 200ms
    assert wall_duration_s < 0.200, (
        f"Benchmark failed: 1,000 cycles took {wall_duration_s * 1000.0:.2f}ms (limit: 200ms)"
    )

    assert engine.virtual_clock.elapsed_ms == 10000.0
    assert engine.virtual_clock.format_iec_time() == "T#10s"


# ============================================================================
# 12. Simulation Trace & Gate G4 Evidence Export
# ============================================================================

class TestSimulationTraceAndEvidence:
    """Validates telemetry sliding buffer, diffing, and Gate G4 evidence export."""

    def test_trace_fifo_buffer_limit(self):
        engine = SimulationEngine(
            default_dt_ms=10.0,
            trace_config=TraceConfig(buffer_size=10, preserve_baseline=True),
        )
        engine.run_cycles(50)

        assert len(engine.trace) == 10
        assert engine.trace.total_cycles_recorded == 50
        # Baseline snapshot preserved
        assert engine.trace.first().cycle == 0

    def test_memory_diffing_and_transitions(self):
        engine = SimulationEngine(default_dt_ms=10.0)

        def ramping_logic(eng: SimulationEngine):
            eng.write_register("%R100", eng.cycle_count * 10)
            if eng.cycle_count == 3:
                eng.write_register("%M1", True)

        engine.register_logic_callback(ramping_logic)
        engine.run_cycles(5)

        # Diff between cycle 1 and cycle 3
        diff = engine.trace.diff_cycles(1, 3)
        assert "%R100" in diff.registers
        assert diff.registers["%R100"].old_value == 10
        assert diff.registers["%R100"].new_value == 30

        # Transition detection
        transitions = engine.trace.find_transitions("%M1")
        assert len(transitions) == 1
        assert transitions[0]["cycle"] == 3
        assert transitions[0]["new_value"] is True

    def test_export_g4_evidence(self, tmp_path):
        engine = SimulationEngine(default_dt_ms=10.0)
        engine.run_cycles(10)

        out_path = tmp_path / "closed_loop_evidence.json"
        evidence = engine.export_g4_evidence(
            filepath=out_path,
            invariants={"zero_drift": True, "fail_closed": True},
        )

        assert evidence["gate"] == "G4"
        assert evidence["work_package"] == "W018"
        assert evidence["status"] == "success"
        assert evidence["mode"] == "offline/mock"
        assert evidence["classification"] == "TESTED_MOCK [offline/DEV only]"
        assert evidence["simulation_backend"] == "EMULATED"
        assert evidence["trace_summary"]["total_cycles_recorded"] == 10
        assert out_path.exists()
