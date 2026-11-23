"""Comprehensive Unit Test Suite for Closed-Loop Plant Model (Tank Level System).

Work Package: W021 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Validates:
1. Tank configuration boundaries and parameter validation.
2. Hydrodynamic mass conservation: delta_V_stored == V_in - V_out across dynamic profiles.
3. Torricelli drain without inflow: matching exact analytical quadratic trajectory and empty time.
4. Constant inflow with zero outflow: pure linear volume integration and overflow handling.
5. Steady-state equilibrium: convergence from initial conditions below and above steady state.
6. Actuator slew rate limiting: ramp profiles, step responses, and chatter attenuation.
7. Alarm trip points with hysteresis: deadband integrity, chatter prevention, and state latching.
8. Closed-loop Horner OCS engine integration: %AI1 sensor counts, %AQ1 actuator commands,
   %Q1/%I1 pump feedback, alarm reflection, and multi-cycle setpoint regulation.
9. Power failure fail-safe behavior and deterministic sensor noise repeatability.
"""

import math
import pytest

from jev_cscape.simulation.engine import SimulationEngine
from jev_cscape.simulation.plant_model import (
    FailAction,
    PlantModelLogicUnit,
    ResolutionMode,
    ScalingConverter,
    TankConfig,
    TankLevelPlantModel,
    TankState,
    ValveActuatorDynamics,
    PumpActuatorDynamics,
)


@pytest.fixture
def default_config() -> TankConfig:
    return TankConfig(
        tank_area=1.0,
        max_height=100.0,
        initial_level=0.0,
        k_drain=0.5,
        max_inflow_rate=10.0,
        inflow_slew_rate=20.0,  # 20% / second -> 5s for 0..100%
        outflow_slew_rate=50.0,
        hi_hi_limit=90.0,
        hi_limit=75.0,
        lo_limit=25.0,
        lo_lo_limit=10.0,
        alarm_hysteresis=2.0,
    )


@pytest.fixture
def plant(default_config: TankConfig) -> TankLevelPlantModel:
    return TankLevelPlantModel(config=default_config)


# ============================================================================
# 1. Configuration & Parameter Validation
# ============================================================================

class TestTankConfigAndValidation:

    def test_default_config_values(self, default_config: TankConfig):
        assert default_config.tank_area == 1.0
        assert default_config.max_height == 100.0
        assert default_config.initial_level == 0.0
        assert default_config.k_drain == 0.5
        assert default_config.inflow_slew_rate == 20.0
        assert default_config.alarm_hysteresis == 2.0

    def test_invalid_tank_area_rejected(self):
        with pytest.raises(ValueError):
            TankConfig(tank_area=0.0)
        with pytest.raises(ValueError):
            TankConfig(tank_area=-2.5)

    def test_invalid_max_height_rejected(self):
        with pytest.raises(ValueError):
            TankConfig(max_height=0.0)
        with pytest.raises(ValueError):
            TankConfig(max_height=-50.0)

    def test_invalid_initial_level_out_of_bounds(self):
        with pytest.raises(ValueError):
            TankConfig(initial_level=-1.0)
        with pytest.raises(ValueError):
            TankConfig(initial_level=120.0, max_height=100.0)

    def test_invalid_slew_rate_rejected(self):
        with pytest.raises(ValueError):
            TankConfig(inflow_slew_rate=0.0)
        with pytest.raises(ValueError):
            TankConfig(inflow_slew_rate=-10.0)

    def test_plant_reset_restores_initial_state(self, plant: TankLevelPlantModel):
        plant.step(dt_s=1.0, inflow_cmd=100.0, drain_open=False)
        assert plant.level > 0.0

        plant.reset(initial_level=15.0)
        assert plant.level == 15.0
        assert plant.state.total_inflow_volume == 0.0
        assert plant.state.total_outflow_volume == 0.0
        assert plant.state.total_spilled_volume == 0.0


# ============================================================================
# 2. Hydrodynamic Mass Conservation
# ============================================================================

class TestMassConservation:

    def test_mass_conservation_constant_inflow_outflow(self, plant: TankLevelPlantModel):
        plant.reset(initial_level=30.0)
        initial_vol = plant.volume

        dt_s = 0.010
        for _ in range(500):
            plant.step(dt_s=dt_s, inflow_cmd=50.0, drain_open=True)

        final_vol = plant.volume
        delta_vol = final_vol - initial_vol
        net_flow_vol = plant.state.total_inflow_volume - plant.state.total_outflow_volume

        residual = abs(delta_vol - net_flow_vol)
        assert residual < 1e-4
        assert plant.mass_balance_error() < 1e-4

    def test_mass_conservation_sinusoidal_inflow_profile(self, plant: TankLevelPlantModel):
        plant.reset(initial_level=40.0)
        initial_vol = plant.volume

        dt_s = 0.010
        for i in range(1000):
            t = i * dt_s
            cmd = 50.0 + 40.0 * math.sin(2.0 * math.pi * 0.2 * t)
            plant.step(dt_s=dt_s, inflow_cmd=cmd, drain_open=True)

        delta_vol = plant.volume - initial_vol
        net_flow_vol = plant.state.total_inflow_volume - plant.state.total_outflow_volume
        assert abs(delta_vol - net_flow_vol) < 1e-4
        assert plant.mass_balance_error() < 1e-4

    def test_mass_conservation_with_overflow_spill(self):
        cfg = TankConfig(tank_area=1.0, max_height=10.0, initial_level=8.0, max_inflow_rate=10.0)
        p = TankLevelPlantModel(cfg)

        dt_s = 0.1
        for _ in range(50):
            p.step(dt_s=dt_s, inflow_cmd=100.0, drain_open=False)

        assert p.level == 10.0
        assert p.state.total_spilled_volume > 0.0

        expected_stored = (10.0 - 8.0) * cfg.tank_area
        total_accounted = expected_stored + p.state.total_spilled_volume
        assert total_accounted == pytest.approx(p.state.total_inflow_volume, rel=1e-3)


# ============================================================================
# 3. Torricelli Drain Without Inflow
# ============================================================================

class TestTorricelliDrainWithoutInflow:

    def test_torricelli_analytical_trajectory_and_empty_time(self):
        cfg = TankConfig(
            tank_area=1.0,
            max_height=100.0,
            initial_level=64.0,
            k_drain=0.5,
            inflow_slew_rate=100.0,
        )
        p = TankLevelPlantModel(cfg)

        t_empty_analytical = p.theoretical_empty_time(64.0)
        assert t_empty_analytical == 32.0

        dt_s = 0.010
        total_steps = int(35.0 / dt_s)

        sampled_levels: dict[float, float] = {}
        for step in range(total_steps):
            current_time = round(step * dt_s, 3)
            if current_time in [4.0, 8.0, 16.0, 24.0, 32.0, 34.0]:
                sampled_levels[current_time] = p.level
            p.step(dt_s=dt_s, inflow_cmd=0.0, drain_open=True)

        assert sampled_levels[4.0] == pytest.approx(49.0, abs=0.25)
        assert sampled_levels[8.0] == pytest.approx(36.0, abs=0.25)
        assert sampled_levels[16.0] == pytest.approx(16.0, abs=0.25)
        assert sampled_levels[24.0] == pytest.approx(4.0, abs=0.25)
        assert sampled_levels[32.0] == pytest.approx(0.0, abs=0.1)
        assert sampled_levels[34.0] == 0.0
        assert p.outflow_rate == 0.0

    def test_torricelli_drain_area_scaling(self):
        cfg = TankConfig(tank_area=2.0, max_height=100.0, initial_level=64.0, k_drain=0.5)
        p = TankLevelPlantModel(cfg)
        assert p.theoretical_empty_time(64.0) == 64.0

        dt_s = 0.05
        for _ in range(int(32.0 / dt_s)):
            p.step(dt_s=dt_s, inflow_cmd=0.0, drain_open=True)
        assert p.level == pytest.approx(16.0, abs=0.3)

    def test_torricelli_discharge_scaling_with_k_drain(self):
        cfg = TankConfig(tank_area=1.0, max_height=100.0, initial_level=64.0, k_drain=1.0)
        p = TankLevelPlantModel(cfg)
        assert p.theoretical_empty_time(64.0) == 16.0


# ============================================================================
# 4. Constant Inflow With No Outflow
# ============================================================================

class TestConstantInflowNoOutflow:

    def test_linear_level_rise_exact_rate(self):
        cfg = TankConfig(
            tank_area=2.0,
            max_height=100.0,
            initial_level=10.0,
            max_inflow_rate=10.0,
            inflow_slew_rate=10000.0,
        )
        p = TankLevelPlantModel(cfg)

        dt_s = 0.010
        for _ in range(400):
            p.step(dt_s=dt_s, inflow_cmd=50.0, drain_open=False)

        assert p.level == pytest.approx(20.0, abs=1e-3)
        assert p.volume == pytest.approx(40.0, abs=1e-3)

    def test_overflow_saturation_clamping(self):
        cfg = TankConfig(
            tank_area=1.0,
            max_height=50.0,
            initial_level=45.0,
            max_inflow_rate=10.0,
            inflow_slew_rate=1000.0,
        )
        p = TankLevelPlantModel(cfg)

        dt_s = 0.1
        for _ in range(20):
            p.step(dt_s=dt_s, inflow_cmd=100.0, drain_open=False)

        assert p.level == 50.0
        assert p.state.total_spilled_volume == pytest.approx(15.0, abs=1e-3)

    def test_zero_inflow_preserves_constant_level(self):
        cfg = TankConfig(tank_area=1.0, max_height=100.0, initial_level=42.5)
        p = TankLevelPlantModel(cfg)

        for _ in range(100):
            p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)

        assert p.level == 42.5
        assert p.volume == 42.5


# ============================================================================
# 5. Steady-State Equilibrium
# ============================================================================

class TestSteadyStateEquilibrium:

    def test_steady_state_calculation_and_convergence_from_below(self):
        cfg = TankConfig(
            tank_area=1.0,
            max_height=100.0,
            initial_level=0.0,
            k_drain=0.5,
            max_inflow_rate=10.0,
            inflow_slew_rate=1000.0,
        )
        p = TankLevelPlantModel(cfg)

        h_ss_theoretical = p.theoretical_steady_state_level(qin=2.5)
        assert h_ss_theoretical == 25.0

        dt_s = 0.05
        for _ in range(int(120.0 / dt_s)):
            p.step(dt_s=dt_s, inflow_cmd=25.0, drain_open=True)

        assert p.level == pytest.approx(25.0, abs=0.2)
        assert p.inflow_rate == pytest.approx(2.5, abs=1e-3)
        assert p.outflow_rate == pytest.approx(2.5, abs=0.1)

    def test_steady_state_convergence_from_above(self):
        cfg = TankConfig(
            tank_area=1.0,
            max_height=100.0,
            initial_level=70.0,
            k_drain=0.5,
            max_inflow_rate=10.0,
            inflow_slew_rate=1000.0,
        )
        p = TankLevelPlantModel(cfg)

        dt_s = 0.05
        for _ in range(int(120.0 / dt_s)):
            p.step(dt_s=dt_s, inflow_cmd=25.0, drain_open=True)

        assert p.level == pytest.approx(25.0, abs=0.2)

    def test_equilibrium_step_response_to_higher_setpoint(self):
        cfg = TankConfig(
            tank_area=1.0,
            max_height=100.0,
            initial_level=25.0,
            k_drain=0.5,
            max_inflow_rate=10.0,
            inflow_slew_rate=1000.0,
        )
        p = TankLevelPlantModel(cfg)

        dt_s = 0.05
        for _ in range(int(200.0 / dt_s)):
            p.step(dt_s=dt_s, inflow_cmd=40.0, drain_open=True)

        assert p.level == pytest.approx(64.0, abs=0.5)


# ============================================================================
# 6. Actuator Slew Rate Limiting & Dynamics
# ============================================================================

class TestActuatorRateLimiting:

    def test_actuator_ramp_up_step_response(self):
        cfg = TankConfig(inflow_slew_rate=20.0)
        p = TankLevelPlantModel(cfg)

        assert p.state.actuator_inflow_pos == 0.0

        for _ in range(100):
            p.step(dt_s=0.010, inflow_cmd=100.0)
        assert p.state.actuator_inflow_pos == pytest.approx(20.0, abs=0.1)

        for _ in range(200):
            p.step(dt_s=0.010, inflow_cmd=100.0)
        assert p.state.actuator_inflow_pos == pytest.approx(60.0, abs=0.1)

        for _ in range(200):
            p.step(dt_s=0.010, inflow_cmd=100.0)
        assert p.state.actuator_inflow_pos == pytest.approx(100.0, abs=0.1)

        for _ in range(100):
            p.step(dt_s=0.010, inflow_cmd=100.0)
        assert p.state.actuator_inflow_pos == 100.0

    def test_actuator_ramp_down_step_response(self):
        cfg = TankConfig(inflow_slew_rate=20.0)
        p = TankLevelPlantModel(cfg)

        for _ in range(500):
            p.step(dt_s=0.010, inflow_cmd=100.0)
        assert p.state.actuator_inflow_pos == 100.0

        for _ in range(250):
            p.step(dt_s=0.010, inflow_cmd=0.0)
        assert p.state.actuator_inflow_pos == pytest.approx(50.0, abs=0.1)

        for _ in range(250):
            p.step(dt_s=0.010, inflow_cmd=0.0)
        assert p.state.actuator_inflow_pos == pytest.approx(0.0, abs=0.1)

    def test_actuator_attenuates_high_frequency_command_chatter(self):
        cfg = TankConfig(inflow_slew_rate=20.0)
        p = TankLevelPlantModel(cfg)

        dt_s = 0.010
        positions = []
        for i in range(100):
            cmd = 100.0 if (i % 2 == 0) else 0.0
            p.step(dt_s=dt_s, inflow_cmd=cmd)
            positions.append(p.state.actuator_inflow_pos)

        for i in range(1, len(positions)):
            assert abs(positions[i] - positions[i - 1]) <= 0.2001

    def test_pump_inertia_exponential_response(self):
        pump = PumpActuatorDynamics(tau_accel=1.5, tau_coast=2.5)
        pump.set_command(100.0, run_cmd=True)

        dt_s = 0.010
        # Step 1.5 seconds (1 time constant) -> should reach 1 - exp(-1) ~= 63.2%
        for _ in range(150):
            pump.step(dt_s)

        assert pump.speed == pytest.approx(63.2, abs=1.0)
        assert pump.is_running is True


# ============================================================================
# 7. Alarm Trip Points With Hysteresis
# ============================================================================

class TestAlarmTripPointsWithHysteresis:

    def test_high_alarm_trip_and_clear_with_hysteresis(self):
        cfg = TankConfig(hi_limit=75.0, alarm_hysteresis=2.0)
        p = TankLevelPlantModel(cfg)

        # 1. Below trip point
        p.set_level_for_test(74.5)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.hi_alarm is False

        # 2. Reaches trip point
        p.set_level_for_test(75.0)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.hi_alarm is True

        # 3. Higher level stays tripped
        p.set_level_for_test(78.0)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.hi_alarm is True

        # 4. Inside deadband [73.0, 75.0] remains tripped!
        p.set_level_for_test(74.0)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.hi_alarm is True

        p.set_level_for_test(73.1)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.hi_alarm is True

        # 5. Drops below 73.0 clears alarm
        p.set_level_for_test(72.9)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.hi_alarm is False

        # 6. Inside deadband from below remains clear
        p.set_level_for_test(74.0)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.hi_alarm is False

    def test_low_alarm_trip_and_clear_with_hysteresis(self):
        cfg = TankConfig(lo_limit=25.0, alarm_hysteresis=2.0, initial_level=30.0)
        p = TankLevelPlantModel(cfg)

        p.set_level_for_test(26.0)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.lo_alarm is False

        p.set_level_for_test(25.0)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.lo_alarm is True

        p.set_level_for_test(20.0)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.lo_alarm is True

        # Inside deadband [25.0, 27.0] remains tripped
        p.set_level_for_test(26.0)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.lo_alarm is True

        # Rises above 27.0 clears alarm
        p.set_level_for_test(27.1)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.lo_alarm is False

    def test_high_high_and_low_low_trip_points(self):
        cfg = TankConfig(hi_hi_limit=90.0, lo_lo_limit=10.0, alarm_hysteresis=2.0)
        p = TankLevelPlantModel(cfg)

        p.set_level_for_test(91.0)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.hi_hi_alarm is True
        assert p.state.hi_alarm is True

        p.set_level_for_test(9.0)
        p.step(dt_s=0.01, inflow_cmd=0.0, drain_open=False)
        assert p.state.lo_lo_alarm is True
        assert p.state.lo_alarm is True


# ============================================================================
# 8. Closed-Loop Engine Integration
# ============================================================================

class TestClosedLoopEngineIntegration:

    def test_sensor_scaling_to_raw_ai1_counts(self):
        cfg = TankConfig(tank_area=1.0, max_height=100.0)
        p = TankLevelPlantModel(cfg)

        p.set_level_for_test(0.0)
        assert p.raw_ai_counts == 0

        p.set_level_for_test(50.0)
        assert p.raw_ai_counts == 16000

        p.set_level_for_test(100.0)
        assert p.raw_ai_counts == 32000

    def test_engine_closed_loop_feedback_regulation(self):
        engine = SimulationEngine(default_dt_ms=10.0)
        cfg = TankConfig(
            tank_area=1.0,
            max_height=100.0,
            initial_level=0.0,
            k_drain=0.5,
            max_inflow_rate=10.0,
            inflow_slew_rate=100.0,
        )
        plant_model = TankLevelPlantModel(cfg)
        unit = PlantModelLogicUnit(plant_model)
        engine.attach_logic_unit(unit)

        setpoint = 50.0
        kp = 3.0

        def controller_logic(eng: SimulationEngine):
            raw_ai = eng.read_word("%AI1")
            pv = (raw_ai / 32000.0) * 100.0
            error = setpoint - pv
            out_pct = max(0.0, min(100.0, error * kp + (0.5 * math.sqrt(pv) / 10.0 * 100.0)))
            raw_aq = int(round((out_pct / 100.0) * 32000.0))
            eng.write_word("%AQ1", raw_aq)

        engine.register_logic_callback(controller_logic)

        for _ in range(1500):
            engine.step()

        pv_final = (engine.read_word("%AI1") / 32000.0) * 100.0
        assert pv_final == pytest.approx(50.0, abs=2.5)

    def test_engine_high_alarm_trip_under_elevated_setpoint(self):
        engine = SimulationEngine(default_dt_ms=10.0)
        cfg = TankConfig(hi_limit=75.0, initial_level=70.0, max_inflow_rate=20.0, inflow_slew_rate=500.0)
        plant_model = TankLevelPlantModel(cfg)
        engine.attach_logic_unit(PlantModelLogicUnit(plant_model))

        # Register callback to hold %AQ1 at 32000 (100% inflow)
        engine.register_logic_callback(lambda eng: eng.write_word("%AQ1", 32000))

        # Run until level crosses 75.0%
        for _ in range(200):
            engine.step()
            if engine.read_bit("%M1") is True:
                break

        assert engine.read_bit("%M1") is True
        assert plant_model.level >= 75.0
        # Step once more to latch the newly pending AI1 counts
        engine.step()
        raw_ai = engine.read_word("%AI1")
        assert (raw_ai / 32000.0) * 100.0 >= 75.0

    def test_engine_reset_restores_plant_model_initial_conditions(self):
        engine = SimulationEngine(default_dt_ms=10.0)
        plant_model = TankLevelPlantModel()
        engine.attach_logic_unit(PlantModelLogicUnit(plant_model))

        engine.set_register("%AQ1", 32000)
        for _ in range(50):
            engine.step()
        assert plant_model.level > 0.0

        engine.reset()
        assert engine.cycle_count == 0
        assert engine.elapsed_time_ms == 0.0
        assert plant_model.level == 0.0
        assert engine.read_word("%AI1") == 0


# ============================================================================
# 9. Fail-Safe & Deterministic Noise Repeatability
# ============================================================================

class TestFailSafeAndDisturbances:

    def test_power_failure_valve_fail_closed(self):
        valve = ValveActuatorDynamics(slew_rate_up=20.0, slew_rate_fail=50.0)
        valve.position = 75.0
        valve.target_position = 75.0

        # Cut power
        valve.power_available = False
        dt_s = 0.1

        # Closes at 50%/s -> 75% takes 1.5 seconds (15 steps of 0.1s)
        for _ in range(15):
            valve.step(dt_s)

        assert valve.position == pytest.approx(0.0, abs=1e-3)
        assert valve.is_closed is True

    def test_deterministic_sensor_noise_repeatability(self):
        # Two runs with identical seed produce bit-for-bit identical sequences
        cfg1 = TankConfig(random_seed=42, sensor_noise_sigma=1.0)
        p1 = TankLevelPlantModel(cfg1)

        cfg2 = TankConfig(random_seed=42, sensor_noise_sigma=1.0)
        p2 = TankLevelPlantModel(cfg2)

        p1_levels = []
        p2_levels = []
        for _ in range(100):
            p1.step(dt_s=0.010, inflow_cmd=50.0)
            p2.step(dt_s=0.010, inflow_cmd=50.0)
            p1_levels.append(p1.level)
            p2_levels.append(p2.level)

        assert p1_levels == p2_levels
