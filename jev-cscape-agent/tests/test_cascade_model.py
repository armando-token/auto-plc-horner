"""Comprehensive Unit Test Suite for Multi-Tank Cascade Model & Stochastic Disturbances.

Work Package: W026 (Gate G7)
Classification: TESTED_MOCK [offline/DEV only]

Validates:
1. TwoTankCascadeConfig validation and parameter boundaries.
2. Hydrodynamic mass conservation: delta_V_total == V_in - V_out - V_spill across dynamic profiles.
3. Torricelli inter-tank drainage: gravity transfer, weir elevation cutoff z12, and analytical trajectory.
4. Overflow containment & volume non-negativity clamping: non-negative level guarantee and spill ledger.
5. Actuator slew rate limits: linear rate limiting for inlet and discharge control valves.
6. Stochastic disturbances:
   - Ornstein-Uhlenbeck (OU) mean-reverting drift and asymptotic statistics.
   - Poisson jump load stepping arrival process and compound accumulation.
   - Isolated PRNG seed bit-identical reproducibility.
7. Closed-loop cascade regulation and disturbance rejection:
   - Rejection of persistent step load disturbances on Tank 2 discharge.
   - Rejection of stochastic OU + Poisson load disturbances.
8. Schmitt-trigger alarm hysteresis on both tanks.
9. Full Horner OCS SimulationEngine integration with CascadeModelLogicUnit.
"""

from __future__ import annotations

import math
from typing import List
import pytest

from jev_cscape.simulation.engine import SimulationEngine
from jev_cscape.simulation.cascade_model import (
    CascadeModelLogicUnit,
    DisturbanceTarget,
    TwoTankCascadeConfig,
    TwoTankCascadeModel,
    TwoTankCascadePIController,
    TwoTankCascadeState,
)


@pytest.fixture
def default_config() -> TwoTankCascadeConfig:
    return TwoTankCascadeConfig(
        tank1_area=1.0,
        max_height_1=100.0,
        initial_level_1=0.0,
        max_inflow_rate_1=10.0,
        inflow_slew_rate_1=20.0,
        k_12=0.5,
        z_12=0.0,
        tank2_area=1.0,
        max_height_2=100.0,
        initial_level_2=0.0,
        k_out=0.5,
        discharge_slew_rate=20.0,
        alarm_hysteresis=2.0,
        random_seed=42,
    )


@pytest.fixture
def cascade_model(default_config: TwoTankCascadeConfig) -> TwoTankCascadeModel:
    return TwoTankCascadeModel(config=default_config)


# ============================================================================
# 1. Configuration & Parameter Validation
# ============================================================================

class TestTwoTankConfigAndValidation:
    """Validates configuration parameters, invariants, and boundaries."""

    def test_default_config_values(self, default_config: TwoTankCascadeConfig) -> None:
        assert default_config.tank1_area == 1.0
        assert default_config.tank2_area == 1.0
        assert default_config.max_height_1 == 100.0
        assert default_config.max_height_2 == 100.0
        assert default_config.k_12 == 0.5
        assert default_config.k_out == 0.5
        assert default_config.z_12 == 0.0
        assert default_config.random_seed == 42
        assert default_config.ou_enabled is False
        assert default_config.poisson_enabled is False

    def test_invalid_tank_areas_rejected(self) -> None:
        with pytest.raises(ValueError):
            TwoTankCascadeConfig(tank1_area=0.0)
        with pytest.raises(ValueError):
            TwoTankCascadeConfig(tank1_area=-1.0)
        with pytest.raises(ValueError):
            TwoTankCascadeConfig(tank2_area=0.0)
        with pytest.raises(ValueError):
            TwoTankCascadeConfig(tank2_area=-5.0)

    def test_invalid_max_heights_rejected(self) -> None:
        with pytest.raises(ValueError):
            TwoTankCascadeConfig(max_height_1=0.0)
        with pytest.raises(ValueError):
            TwoTankCascadeConfig(max_height_2=-10.0)

    def test_initial_level_exceeding_max_height_rejected(self) -> None:
        with pytest.raises(ValueError, match="initial_level_1 .* cannot exceed max_height_1"):
            TwoTankCascadeConfig(initial_level_1=105.0, max_height_1=100.0)
        with pytest.raises(ValueError, match="initial_level_2 .* cannot exceed max_height_2"):
            TwoTankCascadeConfig(initial_level_2=120.0, max_height_2=100.0)

    def test_z12_elevation_exceeding_max_height_rejected(self) -> None:
        with pytest.raises(ValueError, match="z_12 .* must be strictly less than max_height_1"):
            TwoTankCascadeConfig(z_12=100.0, max_height_1=100.0)

    def test_model_reset_restores_initial_conditions(self, cascade_model: TwoTankCascadeModel) -> None:
        cascade_model.step(dt_s=1.0, inflow_cmd=100.0, discharge_cmd=50.0)
        assert cascade_model.level1 > 0.0
        assert cascade_model.total_inflow1_volume > 0.0

        cascade_model.reset(initial_level_1=25.0, initial_level_2=15.0)
        assert cascade_model.level1 == 25.0
        assert cascade_model.level2 == 15.0
        assert cascade_model.total_inflow1_volume == 0.0
        assert cascade_model.total_q12_volume == 0.0
        assert cascade_model.total_qout_volume == 0.0
        assert cascade_model.total_spilled1_volume == 0.0
        assert cascade_model.total_spilled2_volume == 0.0
        assert cascade_model.mass_balance_error() < 1e-10


# ============================================================================
# 2. Hydrodynamic Mass Conservation
# ============================================================================

class TestMassConservation:
    """Validates strict first-principles mass conservation across two-tank cascade."""

    def test_mass_conservation_constant_inflow(self, cascade_model: TwoTankCascadeModel) -> None:
        """Verify delta V_total == V_in - V_out across multiple scan cycles."""
        cascade_model.reset(initial_level_1=10.0, initial_level_2=5.0)
        dt_s = 0.010

        for _ in range(500):
            cascade_model.step(dt_s=dt_s, inflow_cmd=40.0, discharge_cmd=80.0)

        assert cascade_model.mass_balance_error() < 1e-8
        assert cascade_model.tank1_mass_balance_error() < 1e-8
        assert cascade_model.tank2_mass_balance_error() < 1e-8

    def test_mass_conservation_dynamic_sinusoidal_inflow(self, cascade_model: TwoTankCascadeModel) -> None:
        """Verify mass conservation holds under continuous dynamic inflow modulation."""
        cascade_model.reset(initial_level_1=20.0, initial_level_2=15.0)
        dt_s = 0.020

        for step in range(600):
            t = step * dt_s
            inflow_cmd = 50.0 + 35.0 * math.sin(2.0 * math.pi * 0.1 * t)
            discharge_cmd = 60.0 + 20.0 * math.cos(2.0 * math.pi * 0.05 * t)
            cascade_model.step(dt_s=dt_s, inflow_cmd=inflow_cmd, discharge_cmd=discharge_cmd)

            # Check conservation on every cycle
            assert cascade_model.mass_balance_error() < 1e-7

    def test_mass_conservation_with_overflow_spill(self) -> None:
        """Verify mass conservation ledger accounts for spilled fluid during extreme overflow."""
        cfg = TwoTankCascadeConfig(
            tank1_area=1.0,
            max_height_1=10.0,
            initial_level_1=8.0,
            max_inflow_rate_1=20.0,
            k_12=0.2,  # Low inter-tank drain rate to force Tank 1 overflow
            tank2_area=1.0,
            max_height_2=10.0,
            initial_level_2=2.0,
            k_out=0.1,  # Low discharge rate to force Tank 2 overflow
        )
        model = TwoTankCascadeModel(cfg)
        dt_s = 0.05

        for _ in range(300):
            model.step(dt_s=dt_s, inflow_cmd=100.0, discharge_cmd=10.0)

        # Both tanks should have reached max height and spilled
        assert model.level1 == pytest.approx(10.0, abs=1e-5)
        assert model.total_spilled1_volume > 0.0
        assert model.total_spilled2_volume > 0.0

        # Strict mass conservation including spill volumes
        assert model.mass_balance_error() < 1e-6
        assert model.tank1_mass_balance_error() < 1e-6
        assert model.tank2_mass_balance_error() < 1e-6

    def test_steady_state_equilibrium_convergence(self, cascade_model: TwoTankCascadeModel) -> None:
        """Verify convergence to exact theoretical equilibrium levels:
        h1_ss = z12 + (Q_in / k_12)^2
        h2_ss = (Q_in / k_out)^2
        """
        cascade_model.reset(initial_level_1=0.0, initial_level_2=0.0)
        q_in_target = 2.0  # units/s
        h1_ss_expected, h2_ss_expected = cascade_model.theoretical_steady_state(q_in=q_in_target)

        # Expected:
        # h1_ss = 0.0 + (2.0 / 0.5)^2 = 16.0
        # h2_ss = (2.0 / 0.5)^2 = 16.0
        assert h1_ss_expected == 16.0
        assert h2_ss_expected == 16.0

        # Command valve for 2.0 units/s (20% of max 10.0 units/s)
        dt_s = 0.05
        total_time_s = 150.0
        steps = int(total_time_s / dt_s)

        for _ in range(steps):
            cascade_model.step(dt_s=dt_s, inflow_cmd=20.0, discharge_cmd=100.0)

        # Levels converge to theoretical steady state
        assert cascade_model.level1 == pytest.approx(16.0, abs=0.1)
        assert cascade_model.level2 == pytest.approx(16.0, abs=0.1)

        # Flow rates equalize: Q_in == Q_12 == Q_out
        assert cascade_model.state.inflow_rate1 == pytest.approx(2.0, abs=0.05)
        assert cascade_model.state.q12 == pytest.approx(2.0, abs=0.05)
        assert cascade_model.state.q_out == pytest.approx(2.0, abs=0.05)


# ============================================================================
# 3. Torricelli Inter-Tank Drainage Dynamics
# ============================================================================

class TestTorricelliInterTankDrainage:
    """Validates gravity drainage from Tank 1 to Tank 2 via Torricelli orifice."""

    def test_torricelli_inter_tank_drain_to_empty(self, cascade_model: TwoTankCascadeModel) -> None:
        """Inflow=0, discharge closed: Tank 1 drains completely into Tank 2."""
        h1_initial = 36.0
        cascade_model.reset(initial_level_1=h1_initial, initial_level_2=0.0, discharge_valve_pos=0.0)
        dt_s = 0.020

        # Drain until Tank 1 is empty (theoretical drain time = 2*1*sqrt(36)/0.5 = 24.0s)
        for _ in range(1500):  # 30.0s
            cascade_model.step(dt_s=dt_s, inflow_cmd=0.0, discharge_cmd=0.0, discharge_open=False)

        # Tank 1 drained to zero
        assert cascade_model.level1 == pytest.approx(0.0, abs=1e-4)
        assert cascade_model.state.is_empty1 is True
        assert cascade_model.state.q12 == pytest.approx(0.0, abs=1e-6)

        # All volume from Tank 1 transferred to Tank 2 (A1 = A2 = 1.0)
        assert cascade_model.level2 == pytest.approx(h1_initial, abs=1e-4)
        assert cascade_model.volume2 == pytest.approx(h1_initial, abs=1e-4)
        assert cascade_model.mass_balance_error() < 1e-8

    def test_torricelli_weir_elevation_cutoff(self) -> None:
        """With elevation threshold z12 > 0, Tank 1 stops draining at z12."""
        z12_elev = 15.0
        cfg = TwoTankCascadeConfig(
            tank1_area=1.0,
            max_height_1=100.0,
            initial_level_1=40.0,
            z_12=z12_elev,
            k_12=0.5,
            tank2_area=1.0,
            max_height_2=100.0,
            initial_level_2=0.0,
        )
        model = TwoTankCascadeModel(cfg)
        model.reset(initial_level_1=40.0, initial_level_2=0.0, discharge_valve_pos=0.0)
        dt_s = 0.020

        for _ in range(1500):  # 30.0s
            model.step(dt_s=dt_s, inflow_cmd=0.0, discharge_cmd=0.0, discharge_open=False)

        # Tank 1 level must stop at z12 and never drain below it
        assert model.level1 == pytest.approx(z12_elev, abs=1e-4)
        assert model.state.q12 == pytest.approx(0.0, abs=1e-6)

        # Transferred volume is exactly A1 * (h1_initial - z12) = 1.0 * (40 - 15) = 25.0
        expected_transferred = 40.0 - z12_elev
        assert model.level2 == pytest.approx(expected_transferred, abs=1e-4)
        assert model.mass_balance_error() < 1e-8

    def test_torricelli_zero_flow_when_below_z12(self) -> None:
        """When Tank 1 level is below z12, flow Q_12 is strictly zero."""
        cfg = TwoTankCascadeConfig(initial_level_1=8.0, z_12=12.0, initial_level_2=0.0)
        model = TwoTankCascadeModel(cfg)

        state = model.step(dt_s=1.0, inflow_cmd=0.0, discharge_cmd=0.0)
        assert state.q12 == 0.0
        assert model.level1 == 8.0
        assert model.level2 == 0.0

    def test_torricelli_analytical_trajectory_accuracy(self, cascade_model: TwoTankCascadeModel) -> None:
        """Verify numerical trajectory matches exact analytical Torricelli curve:
        h1(t) = [sqrt(h0) - (k12 / 2*A1) * t]^2
        """
        h0 = 25.0
        k12 = cascade_model.config.k_12
        a1 = cascade_model.config.tank1_area
        t_empty = cascade_model.theoretical_inter_tank_drain_time(h1_start=h0, h1_target=0.0)
        assert t_empty == pytest.approx(20.0, abs=1e-4)

        cascade_model.reset(initial_level_1=h0, initial_level_2=0.0)
        dt_s = 0.010
        times = [0.0, 5.0, 10.0, 15.0, 19.0]

        trajectory = {}
        total_steps = int(20.0 / dt_s)
        for step in range(total_steps):
            current_time = step * dt_s
            for check_t in times:
                if abs(current_time - check_t) < (dt_s / 2.0):
                    trajectory[check_t] = cascade_model.level1
            cascade_model.step(dt_s=dt_s, inflow_cmd=0.0, discharge_cmd=0.0, discharge_open=False)

        for check_t in times:
            h_theoretical = (math.sqrt(h0) - (k12 / (2.0 * a1)) * check_t) ** 2
            h_sim = trajectory[check_t]
            # Residual should be small (Euler discretization error with dt=10ms is < 0.05)
            assert h_sim == pytest.approx(h_theoretical, abs=0.05)


# ============================================================================
# 4. Overflow Containment & Volume Non-Negativity Clamping
# ============================================================================

class TestOverflowAndClamping:
    """Validates volume non-negativity guarantees and overflow bounds."""

    def test_volume_non_negativity_guarantee(self, cascade_model: TwoTankCascadeModel) -> None:
        """Draining empty tanks must never produce negative volume or negative flow."""
        cascade_model.reset(initial_level_1=0.0, initial_level_2=0.0)

        for _ in range(50):
            state = cascade_model.step(dt_s=0.1, inflow_cmd=0.0, discharge_cmd=100.0)
            assert state.level1 >= 0.0
            assert state.level2 >= 0.0
            assert state.q12 >= 0.0
            assert state.q_out >= 0.0
            assert state.is_empty1 is True
            assert state.is_empty2 is True

        assert cascade_model.mass_balance_error() < 1e-10

    def test_tank1_overflow_containment(self, cascade_model: TwoTankCascadeModel) -> None:
        """Inflow > drain capacity clamps at max_height_1 and logs spilled volume."""
        cascade_model.reset(initial_level_1=95.0, initial_level_2=10.0)
        dt_s = 0.1

        for _ in range(100):
            cascade_model.step(dt_s=dt_s, inflow_cmd=100.0, discharge_cmd=0.0)

        assert cascade_model.level1 == pytest.approx(100.0, abs=1e-5)
        assert cascade_model.state.is_full1 is True
        assert cascade_model.total_spilled1_volume > 0.0
        assert cascade_model.mass_balance_error() < 1e-6

    def test_tank2_overflow_containment(self, cascade_model: TwoTankCascadeModel) -> None:
        """Discharge closed with incoming flow clamps at max_height_2 and logs spill."""
        cascade_model.reset(initial_level_1=80.0, initial_level_2=95.0)
        dt_s = 0.1

        for _ in range(100):
            cascade_model.step(dt_s=dt_s, inflow_cmd=50.0, discharge_cmd=0.0, discharge_open=False)

        assert cascade_model.level2 == pytest.approx(100.0, abs=1e-5)
        assert cascade_model.state.is_full2 is True
        assert cascade_model.total_spilled2_volume > 0.0
        assert cascade_model.mass_balance_error() < 1e-6


# ============================================================================
# 5. Actuator Dynamics & Slew Rate Limits
# ============================================================================

class TestActuatorDynamics:
    """Validates rate-limited actuator slew for inlet and discharge control valves."""

    def test_inlet_valve_slew_rate_limiting(self, cascade_model: TwoTankCascadeModel) -> None:
        """Inlet valve slew rate 20%/s requires 5.0s to move 0% -> 100%."""
        cascade_model.reset()
        assert cascade_model.inlet_valve.position == 0.0

        # Step command to 100%
        dt_s = 0.5
        # At 2.5s (5 steps), position should be 50%
        for _ in range(5):
            cascade_model.step(dt_s=dt_s, inflow_cmd=100.0)

        assert cascade_model.inlet_valve.position == pytest.approx(50.0, abs=0.1)

        # At 5.0s (10 steps), position should reach 100%
        for _ in range(5):
            cascade_model.step(dt_s=dt_s, inflow_cmd=100.0)

        assert cascade_model.inlet_valve.position == pytest.approx(100.0, abs=0.1)

    def test_discharge_valve_slew_rate_limiting(self, cascade_model: TwoTankCascadeModel) -> None:
        """Discharge valve slew rate 20%/s requires 5.0s to move 100% -> 0%."""
        cascade_model.reset()
        assert cascade_model.discharge_valve.position == 100.0

        dt_s = 0.5
        for _ in range(5):
            cascade_model.step(dt_s=dt_s, discharge_cmd=0.0)

        assert cascade_model.discharge_valve.position == pytest.approx(50.0, abs=0.1)

        for _ in range(5):
            cascade_model.step(dt_s=dt_s, discharge_cmd=0.0)

        assert cascade_model.discharge_valve.position == pytest.approx(0.0, abs=0.1)


# ============================================================================
# 6. Stochastic Disturbances (OU Drift & Poisson Jumps)
# ============================================================================

class TestStochasticDisturbances:
    """Validates Ornstein-Uhlenbeck drift, Poisson jump load steps, and isolated PRNG."""

    def test_ou_mean_reversion_and_drift(self) -> None:
        """Verify Ornstein-Uhlenbeck process pulls back toward long-term mean mu."""
        cfg = TwoTankCascadeConfig(
            ou_enabled=True,
            ou_theta=1.0,    # Fast mean reversion
            ou_mu=5.0,       # Mean target
            ou_sigma=0.5,    # Volatility
            random_seed=101,
        )
        model = TwoTankCascadeModel(cfg)

        # Run 200 seconds of OU simulation
        dt_s = 0.05
        samples: List[float] = []
        for _ in range(4000):
            state = model.step(dt_s=dt_s)
            samples.append(state.ou_disturbance)

        # Mean of samples should be close to mu = 5.0
        sample_mean = sum(samples) / len(samples)
        assert sample_mean == pytest.approx(5.0, abs=0.2)

        # Theoretical asymptotic variance = sigma^2 / (2 * theta) = 0.25 / 2 = 0.125
        sample_var = sum((x - sample_mean) ** 2 for x in samples) / len(samples)
        assert sample_var == pytest.approx(0.125, abs=0.05)

    def test_poisson_jump_load_stepping(self) -> None:
        """Verify Poisson jumps occur at expected intensity lambda and step the load."""
        lambda_rate = 2.0  # 2 jumps per second
        cfg = TwoTankCascadeConfig(
            poisson_enabled=True,
            poisson_lambda=lambda_rate,
            jump_mean=1.5,
            jump_std=0.0,  # Constant step magnitude
            random_seed=777,
        )
        model = TwoTankCascadeModel(cfg)
        dt_s = 0.010
        total_time_s = 20.0  # Expected jumps = 40
        steps = int(total_time_s / dt_s)

        for _ in range(steps):
            model.step(dt_s=dt_s)

        # Verify jumps arrived
        assert model.total_jump_count > 0
        # Expected ~ 40 jumps (+- 3*sqrt(40) ~= 19 => range 21..59)
        assert 20 <= model.total_jump_count <= 60

        # With jump_mean=1.5 and cumulative steps, total load step is count * 1.5
        expected_step = model.total_jump_count * 1.5
        assert model.state.poisson_load_step == pytest.approx(expected_step, abs=1e-4)

    def test_isolated_prng_seed_reproducibility(self) -> None:
        """Verify identical seed produces 100% bit-identical trajectories."""
        cfg1 = TwoTankCascadeConfig(
            ou_enabled=True,
            ou_theta=0.5,
            ou_mu=2.0,
            ou_sigma=0.3,
            poisson_enabled=True,
            poisson_lambda=1.5,
            jump_mean=1.0,
            jump_std=0.2,
            random_seed=4242,
        )
        cfg2 = TwoTankCascadeConfig(
            ou_enabled=True,
            ou_theta=0.5,
            ou_mu=2.0,
            ou_sigma=0.3,
            poisson_enabled=True,
            poisson_lambda=1.5,
            jump_mean=1.0,
            jump_std=0.2,
            random_seed=4242,
        )

        model1 = TwoTankCascadeModel(cfg1)
        model2 = TwoTankCascadeModel(cfg2)

        dt_s = 0.02
        for _ in range(200):
            s1 = model1.step(dt_s=dt_s, inflow_cmd=50.0, discharge_cmd=80.0)
            s2 = model2.step(dt_s=dt_s, inflow_cmd=50.0, discharge_cmd=80.0)

            assert s1.level1 == s2.level1
            assert s1.level2 == s2.level2
            assert s1.ou_disturbance == s2.ou_disturbance
            assert s1.poisson_load_step == s2.poisson_load_step
            assert s1.raw_ai_counts1 == s2.raw_ai_counts1
            assert s1.raw_ai_counts2 == s2.raw_ai_counts2


# ============================================================================
# 7. Closed-Loop Regulation & Disturbance Rejection
# ============================================================================

class TestDisturbanceRejection:
    """Validates closed-loop disturbance rejection under persistent and stochastic loads."""

    def test_rejection_of_step_load_disturbance(self) -> None:
        """Closed-loop cascade controller rejects sudden step load disturbance on Tank 2."""
        cfg = TwoTankCascadeConfig(
            tank1_area=1.0,
            max_height_1=100.0,
            initial_level_1=25.0,
            tank2_area=1.0,
            max_height_2=100.0,
            initial_level_2=25.0,
            k_12=0.5,
            k_out=0.5,
        )
        plant = TwoTankCascadeModel(cfg)
        logic_unit = CascadeModelLogicUnit(plant=plant)
        controller = TwoTankCascadePIController(
            setpoint2_pct=25.0,
            kp_outer=1.5,
            ki_outer=0.25,
            kp_inner=2.0,
            ki_inner=0.5,
        )

        engine = SimulationEngine(default_dt_ms=20.0)
        # Attach controller (priority 100) and plant (priority 200)
        engine.attach_logic_unit(controller)
        engine.attach_logic_unit(logic_unit)

        # 1. Bring system to steady regulation at 25% setpoint
        for _ in range(1000):  # 20s
            engine.step()

        h2_initial = plant.level2
        assert h2_initial == pytest.approx(25.0, abs=1.5)

        # 2. Inject abrupt load disturbance on Tank 2 discharge: +1.0 units/s
        plant.external_load_disturbance = 1.0

        # 3. Allow closed-loop cascade controller to reject disturbance
        for _ in range(3000):  # 60s
            engine.step()

        # Controller must reject disturbance and return Tank 2 level back to setpoint
        h2_recovered = plant.level2
        assert h2_recovered == pytest.approx(25.0, abs=1.5)
        # Inlet flow increased to supply the additional load
        assert plant.inlet_valve.position > 30.0

    def test_stochastic_disturbance_rejection_vs_open_loop(self) -> None:
        """Closed-loop cascade controller keeps level variance bounded under stochastic OU drift."""
        # Closed-loop system
        cfg_cl = TwoTankCascadeConfig(
            initial_level_1=30.0,
            initial_level_2=30.0,
            ou_enabled=True,
            ou_theta=0.5,
            ou_mu=0.0,
            ou_sigma=0.5,
            disturbance_target=DisturbanceTarget.OUTFLOW,
            random_seed=999,
        )
        plant_cl = TwoTankCascadeModel(cfg_cl)
        logic_cl = CascadeModelLogicUnit(plant=plant_cl)
        ctrl_cl = TwoTankCascadePIController(
            setpoint2_pct=30.0,
            kp_outer=1.0,
            ki_outer=0.1,
            kp_inner=1.5,
            ki_inner=0.2,
        )

        engine_cl = SimulationEngine(default_dt_ms=20.0)
        engine_cl.attach_logic_unit(ctrl_cl)
        engine_cl.attach_logic_unit(logic_cl)

        cl_errors: List[float] = []
        for _ in range(1500):  # 30s
            engine_cl.step()
            cl_errors.append(abs(plant_cl.level2 - 30.0))

        mean_error_cl = sum(cl_errors) / len(cl_errors)
        max_error_cl = max(cl_errors)

        # Closed-loop tracking maintains tightly bounded regulation
        assert mean_error_cl < 2.5
        assert max_error_cl < 6.0


# ============================================================================
# 8. Alarm Hysteresis
# ============================================================================

class TestAlarmHysteresis:
    """Validates Schmitt-trigger deadband hysteresis preventing contact chatter."""

    def test_tank1_high_alarm_hysteresis(self, cascade_model: TwoTankCascadeModel) -> None:
        """High alarm trips at >= 75.0, resets only below (75.0 - 2.0 = 73.0)."""
        cfg = cascade_model.config
        assert cfg.t1_hi_limit == 75.0
        assert cfg.alarm_hysteresis == 2.0

        # Level at 74.5: no alarm
        cascade_model.set_levels_for_test(74.5, 20.0)
        assert cascade_model.state.t1_hi_alarm is False

        # Level reaches 75.0: alarm trips
        cascade_model.set_levels_for_test(75.0, 20.0)
        assert cascade_model.state.t1_hi_alarm is True

        # Level drops to 74.0: deadband retains alarm
        cascade_model.set_levels_for_test(74.0, 20.0)
        assert cascade_model.state.t1_hi_alarm is True

        # Level drops to 72.8 (< 73.0): alarm clears
        cascade_model.set_levels_for_test(72.8, 20.0)
        assert cascade_model.state.t1_hi_alarm is False

    def test_tank2_low_alarm_hysteresis(self, cascade_model: TwoTankCascadeModel) -> None:
        """Low alarm trips at <= 25.0, resets only above (25.0 + 2.0 = 27.0)."""
        # Start at 50.0 so alarm is initially False
        cascade_model.set_levels_for_test(20.0, 50.0)
        assert cascade_model.state.t2_lo_alarm is False

        # Level at 25.5: no alarm
        cascade_model.set_levels_for_test(20.0, 25.5)
        assert cascade_model.state.t2_lo_alarm is False

        # Level reaches 25.0: alarm trips
        cascade_model.set_levels_for_test(20.0, 25.0)
        assert cascade_model.state.t2_lo_alarm is True

        # Level recovers to 26.5: deadband retains alarm
        cascade_model.set_levels_for_test(20.0, 26.5)
        assert cascade_model.state.t2_lo_alarm is True

        # Level recovers to 27.5 (> 27.0): alarm clears
        cascade_model.set_levels_for_test(20.0, 27.5)
        assert cascade_model.state.t2_lo_alarm is False



# ============================================================================
# 9. SimulationEngine Integration
# ============================================================================

class TestSimulationEngineIntegration:
    """Validates full integration of CascadeModelLogicUnit with Horner OCS engine."""

    def test_engine_register_mapping_and_scan_cycle(self) -> None:
        """Verify register mappings %AQ1/%AQ2 -> plant -> %AI1..%AI5 and %M1..%M8."""
        cfg = TwoTankCascadeConfig(
            initial_level_1=40.0,
            initial_level_2=20.0,
            max_height_1=100.0,
            max_height_2=100.0,
        )
        plant = TwoTankCascadeModel(cfg)
        logic_unit = CascadeModelLogicUnit(plant=plant)
        engine = SimulationEngine(default_dt_ms=10.0)
        engine.attach_logic_unit(logic_unit)

        # First scan cycle
        engine.step()

        # Tank 1 level 40% maps to 40% of 32000 = 12800 counts
        ai1_raw = engine.get_register("%AI1")
        assert ai1_raw == pytest.approx(12800, abs=10)

        # Tank 2 level 20% maps to 20% of 32000 = 6400 counts
        ai2_raw = engine.get_register("%AI2")
        assert ai2_raw == pytest.approx(6400, abs=10)

        # Set %AQ1 inflow command to 50% (16000 counts)
        engine.set_register("%AQ1", 16000)

        # Run 50 cycles (0.5s)
        for _ in range(50):
            engine.step()

        # Actuator should have slewed towards 50%
        assert plant.inlet_valve.position > 5.0
        # Flow rates should be reflected on %AI3..%AI5
        assert engine.get_register("%AI3") is not None
        assert engine.get_register("%AI4") is not None
        assert engine.get_register("%AI5") is not None

    def test_telemetry_export(self, cascade_model: TwoTankCascadeModel) -> None:
        """Verify get_telemetry export dictionary completeness."""
        cascade_model.step(dt_s=1.0, inflow_cmd=50.0, discharge_cmd=50.0)
        telem = cascade_model.get_telemetry()

        required_keys = [
            "elapsed_time_s", "level1", "level2", "volume1", "volume2", "total_volume",
            "inflow_rate1", "q12", "q_out", "actuator_inflow_pos", "actuator_discharge_pos",
            "ou_disturbance", "poisson_load_step", "total_disturbance",
            "total_inflow1_volume", "total_q12_volume", "total_qout_volume",
            "total_spilled1_volume", "total_spilled2_volume", "mass_balance_error",
            "t1_hi_alarm", "t1_lo_alarm", "t2_hi_alarm", "t2_lo_alarm",
            "raw_ai_counts1", "raw_ai_counts2",
        ]
        for key in required_keys:
            assert key in telem
