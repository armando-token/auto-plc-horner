"""Unit Test Suite for IEC 61131-3 Standard Function Blocks.

Work Package: W020 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Validates deterministic timing diagrams, pulse semantics, edge detection,
counter limits, zero drift, and SimulationEngine / Horner register integration
for TON, TOF, TP, CTU, CTD, CTUD.
"""

import pytest

from jev_cscape.simulation.engine import SimulationEngine
from jev_cscape.simulation.standard_blocks import (
    CTD,
    CTU,
    CTUD,
    FunctionBlockLogicUnit,
    TOF,
    TON,
    TP,
)


class TestTimerOnDelayTON:
    """Validate IEC 61131-3 TON timing diagram and reset semantics."""

    def test_ton_normal_delay_completion(self):
        timer = TON(name="T1", pt_ms=100.0)

        # Step 1-9: IN=True, advancing 10ms each (10ms .. 90ms)
        for i in range(1, 10):
            q, et = timer.execute(in_val=True, dt_ms=10.0)
            assert q is False
            assert et == pytest.approx(i * 10.0)

        # Step 10: 100ms reached -> Q becomes True
        q, et = timer.execute(in_val=True, dt_ms=10.0)
        assert q is True
        assert et == 100.0

        # Step 11: Extra time -> ET clamped at PT
        q, et = timer.execute(in_val=True, dt_ms=10.0)
        assert q is True
        assert et == 100.0

    def test_ton_aborted_before_preset(self):
        timer = TON(name="T1", pt_ms=100.0)

        # Advance 50ms
        for _ in range(5):
            timer.execute(in_val=True, dt_ms=10.0)
        assert timer.et_ms == 50.0
        assert timer.q is False

        # IN drops to False -> immediate reset
        q, et = timer.execute(in_val=False, dt_ms=10.0)
        assert q is False
        assert et == 0.0

    def test_ton_re_assertion_after_completion(self):
        timer = TON(name="T1", pt_ms=50.0)

        for _ in range(5):
            timer.execute(in_val=True, dt_ms=10.0)
        assert timer.q is True

        # Drop IN to False
        timer.execute(in_val=False, dt_ms=10.0)
        assert timer.q is False
        assert timer.et_ms == 0.0

        # Re-assert IN -> restart timing from 0
        q, et = timer.execute(in_val=True, dt_ms=10.0)
        assert q is False
        assert et == 10.0


class TestTimerOffDelayTOF:
    """Validate IEC 61131-3 TOF timing diagram and re-trigger semantics."""

    def test_tof_normal_off_delay_completion(self):
        timer = TOF(name="T_OFF", pt_ms=100.0)

        # When IN is True, Q is True, ET is 0
        q, et = timer.execute(in_val=True, dt_ms=10.0)
        assert q is True
        assert et == 0.0

        # IN goes False -> countdown begins, Q remains True
        for i in range(1, 10):
            q, et = timer.execute(in_val=False, dt_ms=10.0)
            assert q is True
            assert et == pytest.approx(i * 10.0)

        # At 100ms -> Q falls to False
        q, et = timer.execute(in_val=False, dt_ms=10.0)
        assert q is False
        assert et == 100.0

    def test_tof_re_assert_before_expiry(self):
        timer = TOF(name="T_OFF", pt_ms=100.0)
        timer.execute(in_val=True, dt_ms=10.0)

        # Run 50ms of countdown
        for _ in range(5):
            timer.execute(in_val=False, dt_ms=10.0)
        assert timer.q is True
        assert timer.et_ms == 50.0

        # IN goes True again before expiry -> ET resets to 0, Q stays True
        q, et = timer.execute(in_val=True, dt_ms=10.0)
        assert q is True
        assert et == 0.0


class TestPulseTimerTP:
    """Validate IEC 61131-3 TP pulse timer mechanics."""

    def test_tp_exact_pulse_duration(self):
        timer = TP(name="T_PULSE", pt_ms=50.0)

        # Rising edge of IN starts pulse
        q, et = timer.execute(in_val=True, dt_ms=10.0)
        assert q is True
        assert et == 10.0

        # IN drops to False immediately on next cycle (momentary button press)
        # Q MUST remain True until PT expires!
        for i in range(2, 5):
            q, et = timer.execute(in_val=False, dt_ms=10.0)
            assert q is True
            assert et == pytest.approx(i * 10.0)

        # Cycle 5 (50ms) -> pulse ends, Q becomes False
        q, et = timer.execute(in_val=False, dt_ms=10.0)
        assert q is False
        assert et == 0.0  # Reset because IN was already False

    def test_tp_pulse_with_in_held_high(self):
        timer = TP(name="T_PULSE", pt_ms=30.0)

        # IN remains True continuously
        timer.execute(in_val=True, dt_ms=10.0)
        timer.execute(in_val=True, dt_ms=10.0)
        q, et = timer.execute(in_val=True, dt_ms=10.0)
        assert q is False  # Expired
        assert et == 30.0  # Stays at PT while IN is high

        # Further cycles while IN is high do not restart timer
        q, et = timer.execute(in_val=True, dt_ms=10.0)
        assert q is False
        assert et == 30.0

        # When IN finally drops to False, ET resets to 0
        q, et = timer.execute(in_val=False, dt_ms=10.0)
        assert q is False
        assert et == 0.0


class TestCounters:
    """Validate IEC 61131-3 CTU, CTD, and CTUD counters."""

    def test_ctu_up_counter(self):
        counter = CTU(name="CTU1", pv=3)

        # Pulse 1: False -> True
        q, cv = counter.execute(cu_val=True)
        assert cv == 1
        assert q is False

        # Holding CU True does NOT increment (edge detection)
        q, cv = counter.execute(cu_val=True)
        assert cv == 1

        # CU False
        counter.execute(cu_val=False)

        # Pulse 2
        counter.execute(cu_val=True)
        assert counter.cv == 2
        assert counter.q is False
        counter.execute(cu_val=False)

        # Pulse 3 -> CV reaches PV, Q becomes True
        q, cv = counter.execute(cu_val=True)
        assert cv == 3
        assert q is True

        # Reset forces CV to 0 and Q to False
        q, cv = counter.execute(cu_val=False, reset_val=True)
        assert cv == 0
        assert q is False

    def test_ctd_down_counter(self):
        counter = CTD(name="CTD1", pv=3)
        assert counter.cv == 3
        assert counter.q is False

        # Pulse 1 down
        counter.execute(cd_val=True)
        assert counter.cv == 2
        assert counter.q is False
        counter.execute(cd_val=False)

        # Pulse 2 down
        counter.execute(cd_val=True)
        assert counter.cv == 1
        counter.execute(cd_val=False)

        # Pulse 3 down -> reaches 0, Q becomes True
        q, cv = counter.execute(cd_val=True)
        assert cv == 0
        assert q is True

        # Further pulses do not go negative
        counter.execute(cd_val=False)
        q, cv = counter.execute(cd_val=True)
        assert cv == 0
        assert q is True

        # Load restores PV
        counter.execute(cd_val=False, load_val=True)
        assert counter.cv == 3
        assert counter.q is False

    def test_ctud_up_down_counter(self):
        counter = CTUD(name="CTUD1", pv=2)
        assert counter.cv == 0
        assert counter.qd is True  # CV <= 0
        assert counter.qu is False

        # Count up
        counter.execute(cu_val=True, cd_val=False)
        assert counter.cv == 1
        assert counter.qd is False
        assert counter.qu is False
        counter.execute(cu_val=False, cd_val=False)

        # Count up to 2 -> reaches PV
        qu, qd, cv = counter.execute(cu_val=True, cd_val=False)
        assert cv == 2
        assert qu is True
        assert qd is False
        counter.execute(cu_val=False, cd_val=False)

        # Count down
        qu, qd, cv = counter.execute(cu_val=False, cd_val=True)
        assert cv == 1
        assert qu is False
        assert qd is False


class TestSimulationEngineIntegration:
    """Validate FunctionBlockLogicUnit integration with SimulationEngine and Horner registers."""

    def test_ton_bound_to_horner_registers(self):
        engine = SimulationEngine(default_dt_ms=10.0)

        # Create TON: IN bound to %I1, PT bound to %R101, Q bound to %Q1, ET bound to %R102
        ton = TON(name="TimerInflow", pt_ms=50.0, in_reg="%I1", pt_reg="%R101", q_reg="%Q1", et_reg="%R102")
        unit = FunctionBlockLogicUnit(ton)
        engine.attach_logic_unit(unit)

        # Configure PT via register %R101 = 50ms
        engine.set_register("%R101", 50)
        # Assert initial output Q is False
        assert engine.read_bit("%Q1") is False

        # Step 1: Input %I1 is False -> nothing happens
        engine.step()
        assert engine.get_committed_output("%Q1") is False
        assert engine.read_word("%R102") == 0

        # Set %I1 = True
        engine.set_input("%I1", True)

        # Step 2-5: Accumulating (10ms .. 40ms)
        for _ in range(4):
            engine.step()
            assert engine.get_committed_output("%Q1") is False

        # Step 6: 50ms reached -> %Q1 committed to True, %R102 = 50
        engine.step()
        assert engine.get_committed_output("%Q1") is True
        assert engine.read_word("%R102") == 50

        # Turn %I1 off -> next scan immediately resets %Q1 to False and %R102 to 0
        engine.set_input("%I1", False)
        engine.step()
        assert engine.get_committed_output("%Q1") is False
        assert engine.read_word("%R102") == 0

    def test_ctu_bound_to_horner_registers(self):
        engine = SimulationEngine(default_dt_ms=10.0)

        # Create CTU: CU bound to %I2, PV bound to %R201, Q bound to %Q2, CV bound to %R202
        ctu = CTU(name="PartCounter", pv=2, cu_reg="%I2", pv_reg="%R201", q_reg="%Q2", cv_reg="%R202")
        engine.attach_logic_unit(FunctionBlockLogicUnit(ctu))
        engine.set_register("%R201", 2)

        # Cycle 1: pulse high on %I2
        engine.set_input("%I2", True)
        engine.step()
        assert engine.read_word("%R202") == 1
        assert engine.get_committed_output("%Q2") is False

        # Cycle 2: drop low
        engine.set_input("%I2", False)
        engine.step()
        assert engine.read_word("%R202") == 1

        # Cycle 3: pulse high -> reaches PV (2)
        engine.set_input("%I2", True)
        engine.step()
        assert engine.read_word("%R202") == 2
        assert engine.get_committed_output("%Q2") is True
