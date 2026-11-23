"""First-Principles Multi-Tank Cascade Process Emulation with Stochastic Disturbances.

Work Package: W026 (Gate G7)
Classification: TESTED_MOCK [offline/DEV only]

Provides a deterministic, continuous-time (discretized to scan cycle dt) physical
plant process model of an industrial two-tank cascade liquid level system:
1. Two-tank mass conservation:
   dh1/dt = (Q_in1 - Q_12) / A1
   dh2/dt = (Q_12 - Q_out) / A2
2. Inter-tank gravity Torricelli drainage:
   Q_12 = k_12 * sqrt(max(0, h1 - z12))
3. Modulated Torricelli discharge from Tank 2:
   Q_out = k_out * (valve_discharge_pos / 100.0) * sqrt(max(0, h2))
4. Actuator dynamics: rate-limited control valves for inlet and discharge (slew rate limiting).
5. Physical volume non-negativity clamping (h1 >= 0, h2 >= 0) and overflow containment
   (h1 <= H_max1, h2 <= H_max2) with spilled volume accounting.
6. Stochastic disturbance injection:
   - Ornstein-Uhlenbeck (OU) mean-reverting drift: dX_t = theta * (mu - X_t) dt + sigma * dW_t
   - Poisson jump load stepping: compound Poisson arrival process with isolated PRNG seed
7. Schmitt-trigger alarm hysteresis for Low-Low, Low, High, High-High level limits.
8. Bidirectional Horner OCS register bindings (%AI1..%AI5, %AQ1..%AQ2, %Q1..%Q2, %M1..%M8).
9. CascadeModelLogicUnit implementing ILogicUnit for SimulationEngine Phase 2 execution.
10. Built-in CascadePIController for closed-loop regulation and disturbance rejection.
"""

from __future__ import annotations

from enum import Enum
import math
import random
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.plant_model import (
    FailAction,
    ResolutionMode,
    ScalingConverter,
    ValveActuatorDynamics,
)


class DisturbanceTarget(str, Enum):
    """Target injection point for stochastic disturbance."""
    OUTFLOW = "OUTFLOW"      # Injected into Tank 2 discharge (unmeasured load draw)
    INFLOW = "INFLOW"        # Injected into Tank 1 inlet (supply pressure fluctuation)
    INTER_TANK = "INTER_TANK"  # Injected into inter-tank transfer pipe
    BOTH = "BOTH"            # Inflow and outflow disturbances


class TwoTankCascadeConfig(BaseModel):
    """Configuration parameters for two-tank cascade physical simulation."""

    # Tank 1 Parameters
    tank1_area: float = Field(default=1.0, gt=0.0, description="Tank 1 cross-sectional area (m^2)")
    max_height_1: float = Field(default=100.0, gt=0.0, description="Tank 1 maximum height/range (units or %)")
    initial_level_1: float = Field(default=0.0, ge=0.0, description="Initial liquid level in Tank 1")
    max_inflow_rate_1: float = Field(default=10.0, gt=0.0, description="Max inlet flow rate at 100% actuator (units/s)")
    inflow_slew_rate_1: float = Field(default=20.0, gt=0.0, description="Tank 1 inlet valve slew rate (%/s)")

    # Inter-Tank Gravity Drain Parameters (Torricelli)
    k_12: float = Field(default=0.5, ge=0.0, description="Inter-tank Torricelli discharge coefficient")
    z_12: float = Field(default=0.0, ge=0.0, description="Inter-tank transfer port elevation in Tank 1")

    # Tank 2 Parameters
    tank2_area: float = Field(default=1.0, gt=0.0, description="Tank 2 cross-sectional area (m^2)")
    max_height_2: float = Field(default=100.0, gt=0.0, description="Tank 2 maximum height/range (units or %)")
    initial_level_2: float = Field(default=0.0, ge=0.0, description="Initial liquid level in Tank 2")

    # Tank 2 Discharge Parameters
    k_out: float = Field(default=0.5, ge=0.0, description="Tank 2 discharge Torricelli coefficient")
    discharge_slew_rate: float = Field(default=20.0, gt=0.0, description="Tank 2 discharge valve slew rate (%/s)")

    # Stochastic Disturbance - Ornstein-Uhlenbeck (OU) Mean-Reverting Drift
    ou_enabled: bool = Field(default=False, description="Enable Ornstein-Uhlenbeck stochastic drift")
    ou_theta: float = Field(default=0.1, ge=0.0, description="OU mean-reversion rate parameter (speed of pull)")
    ou_mu: float = Field(default=0.0, description="OU long-term equilibrium mean")
    ou_sigma: float = Field(default=0.0, ge=0.0, description="OU volatility / diffusion coefficient")

    # Stochastic Disturbance - Poisson Jump Load Stepping
    poisson_enabled: bool = Field(default=False, description="Enable Poisson jump load step events")
    poisson_lambda: float = Field(default=0.0, ge=0.0, description="Poisson jump arrival intensity (jumps/s)")
    jump_mean: float = Field(default=0.0, description="Mean jump step magnitude")
    jump_std: float = Field(default=0.0, ge=0.0, description="Jump step magnitude standard deviation")
    jump_decay_rate: float = Field(default=0.0, ge=0.0, description="Optional jump load decay rate (1/s, 0=persistent step)")
    poisson_cumulative: bool = Field(default=True, description="Whether jumps accumulate into load step state")

    # Disturbance Application Target
    disturbance_target: DisturbanceTarget = Field(
        default=DisturbanceTarget.OUTFLOW,
        description="Target point where OU and Poisson disturbances are injected",
    )

    # PRNG Seed & Sensor Noise
    random_seed: int = Field(default=42, description="Isolated PRNG seed for deterministic repeatability")
    sensor_noise_sigma_1: float = Field(default=0.0, ge=0.0, description="Tank 1 level sensor Gaussian noise std dev")
    sensor_noise_sigma_2: float = Field(default=0.0, ge=0.0, description="Tank 2 level sensor Gaussian noise std dev")

    # Alarm Thresholds - Tank 1
    t1_hi_hi_limit: float = Field(default=90.0, description="Tank 1 High-High alarm limit")
    t1_hi_limit: float = Field(default=75.0, description="Tank 1 High alarm limit")
    t1_lo_limit: float = Field(default=25.0, description="Tank 1 Low alarm limit")
    t1_lo_lo_limit: float = Field(default=10.0, description="Tank 1 Low-Low alarm limit")

    # Alarm Thresholds - Tank 2
    t2_hi_hi_limit: float = Field(default=90.0, description="Tank 2 High-High alarm limit")
    t2_hi_limit: float = Field(default=75.0, description="Tank 2 High alarm limit")
    t2_lo_limit: float = Field(default=25.0, description="Tank 2 Low alarm limit")
    t2_lo_lo_limit: float = Field(default=10.0, description="Tank 2 Low-Low alarm limit")

    alarm_hysteresis: float = Field(default=2.0, ge=0.0, description="Deadband hysteresis to prevent alarm chatter")

    # Horner OCS Register Bindings
    ai_level1_reg: Optional[str] = "%AI1"
    ai_level2_reg: Optional[str] = "%AI2"
    ai_inflow1_reg: Optional[str] = "%AI3"
    ai_q12_reg: Optional[str] = "%AI4"
    ai_qout_reg: Optional[str] = "%AI5"
    aq_inflow1_cmd_reg: Optional[str] = "%AQ1"
    aq_discharge_cmd_reg: Optional[str] = None
    q_inlet_cmd_reg: Optional[str] = None
    q_discharge_cmd_reg: Optional[str] = None
    t1_hi_alarm_reg: Optional[str] = "%M1"
    t1_lo_alarm_reg: Optional[str] = "%M2"
    t1_hi_hi_alarm_reg: Optional[str] = "%M3"
    t1_lo_lo_alarm_reg: Optional[str] = "%M4"
    t2_hi_alarm_reg: Optional[str] = "%M5"
    t2_lo_alarm_reg: Optional[str] = "%M6"
    t2_hi_hi_alarm_reg: Optional[str] = "%M7"
    t2_lo_lo_alarm_reg: Optional[str] = "%M8"

    def model_post_init(self, __context: Any) -> None:
        if self.initial_level_1 > self.max_height_1:
            raise ValueError(f"initial_level_1 ({self.initial_level_1}) cannot exceed max_height_1 ({self.max_height_1})")
        if self.initial_level_2 > self.max_height_2:
            raise ValueError(f"initial_level_2 ({self.initial_level_2}) cannot exceed max_height_2 ({self.max_height_2})")
        if self.z_12 >= self.max_height_1:
            raise ValueError(f"Inter-tank port elevation z_12 ({self.z_12}) must be strictly less than max_height_1 ({self.max_height_1})")
        if self.t1_hi_limit <= self.t1_lo_limit:
            raise ValueError("t1_hi_limit must be greater than t1_lo_limit")
        if self.t2_hi_limit <= self.t2_lo_limit:
            raise ValueError("t2_hi_limit must be greater than t2_lo_limit")


class TwoTankCascadeState(BaseModel):
    """Immutable state snapshot of two-tank cascade model after scan cycle."""
    level1: float
    level2: float
    volume1: float
    volume2: float
    total_volume: float
    inflow_rate1: float
    q12: float
    q_out: float
    actuator_inflow_pos: float
    actuator_discharge_pos: float
    ou_disturbance: float
    poisson_load_step: float
    total_disturbance: float
    total_inflow1_volume: float
    total_q12_volume: float
    total_qout_volume: float
    total_spilled1_volume: float
    total_spilled2_volume: float
    raw_ai_counts1: int
    raw_ai_counts2: int
    t1_hi_alarm: bool
    t1_lo_alarm: bool
    t1_hi_hi_alarm: bool
    t1_lo_lo_alarm: bool
    t2_hi_alarm: bool
    t2_lo_alarm: bool
    t2_hi_hi_alarm: bool
    t2_lo_lo_alarm: bool
    is_empty1: bool = False
    is_full1: bool = False
    is_empty2: bool = False
    is_full2: bool = False


class TwoTankCascadeModel:
    """Deterministic, first-principles two-tank cascade liquid level system model.

    Features:
    - First-principles continuous-time mass conservation for both tanks.
    - Inter-tank gravity Torricelli drainage: Q_12 = k_12 * sqrt(max(0, h1 - z12)).
    - Torricelli discharge flow: Q_out = k_out * (valve_pos / 100) * sqrt(max(0, h2)).
    - Actuator rate limits (slew rates for inlet and discharge valves).
    - Physical volume-availability clamping (guaranteed non-negative levels h1 >= 0, h2 >= 0).
    - Overflow containment (h1 <= H_max1, h2 <= H_max2) with spilled volume accounting.
    - Stochastic disturbances: Ornstein-Uhlenbeck drift and Poisson jump load stepping with isolated PRNG.
    - Schmitt-trigger alarm hysteresis for discrete limit detection.
    """

    def __init__(self, config: Optional[TwoTankCascadeConfig] = None) -> None:
        self.config: TwoTankCascadeConfig = config or TwoTankCascadeConfig()

        # Levels and volumes
        self.level1: float = float(self.config.initial_level_1)
        self.level2: float = float(self.config.initial_level_2)
        self.initial_level_1: float = self.level1
        self.initial_level_2: float = self.level2

        # Actuators
        self.inlet_valve = ValveActuatorDynamics(
            slew_rate_up=self.config.inflow_slew_rate_1,
            slew_rate_down=self.config.inflow_slew_rate_1,
        )
        self.discharge_valve = ValveActuatorDynamics(
            slew_rate_up=self.config.discharge_slew_rate,
            slew_rate_down=self.config.discharge_slew_rate,
        )
        # Default discharge valve open to 100% position initially
        self.discharge_valve.position = 100.0
        self.discharge_valve.target_position = 100.0

        # Alarms - Tank 1
        self._t1_hi_alarm: bool = False
        self._t1_lo_alarm: bool = False
        self._t1_hi_hi_alarm: bool = False
        self._t1_lo_lo_alarm: bool = False

        # Alarms - Tank 2
        self._t2_hi_alarm: bool = False
        self._t2_lo_alarm: bool = False
        self._t2_hi_hi_alarm: bool = False
        self._t2_lo_lo_alarm: bool = False

        # Volume accumulators
        self.total_inflow1_volume: float = 0.0
        self.total_q12_volume: float = 0.0
        self.total_qout_volume: float = 0.0
        self.total_spilled1_volume: float = 0.0
        self.total_spilled2_volume: float = 0.0
        self.elapsed_time_s: float = 0.0

        # Isolated PRNG for deterministic noise and stochastic disturbances
        self._rng = random.Random(self.config.random_seed)

        # Stochastic process states
        self._ou_state: float = float(self.config.ou_mu)
        self._poisson_load_step: float = 0.0
        self._last_jump: float = 0.0
        self.total_jump_count: int = 0

        # Manual / external disturbance offsets
        self.external_load_disturbance: float = 0.0
        self.supply_pressure_factor: float = 1.0

        # Initialize alarms and snapshot
        self._update_alarms()
        self._state = self._build_state(0.0, 0.0, 0.0)

    @property
    def volume1(self) -> float:
        return self.level1 * self.config.tank1_area

    @property
    def volume2(self) -> float:
        return self.level2 * self.config.tank2_area

    @property
    def total_volume(self) -> float:
        return self.volume1 + self.volume2

    @property
    def state(self) -> TwoTankCascadeState:
        return self._state

    @property
    def raw_ai_counts1(self) -> int:
        h_meas = self._get_measured_level_1()
        return ScalingConverter.level_to_raw_ai(
            h_meas, h_max=self.config.max_height_1, mode=ResolutionMode.COUNTS_32000
        )

    @property
    def raw_ai_counts2(self) -> int:
        h_meas = self._get_measured_level_2()
        return ScalingConverter.level_to_raw_ai(
            h_meas, h_max=self.config.max_height_2, mode=ResolutionMode.COUNTS_32000
        )

    def _get_measured_level_1(self) -> float:
        if self.config.sensor_noise_sigma_1 <= 0.0:
            return self.level1
        noise = self._rng.normalvariate(0.0, self.config.sensor_noise_sigma_1)
        return max(0.0, min(self.config.max_height_1, self.level1 + noise))

    def _get_measured_level_2(self) -> float:
        if self.config.sensor_noise_sigma_2 <= 0.0:
            return self.level2
        noise = self._rng.normalvariate(0.0, self.config.sensor_noise_sigma_2)
        return max(0.0, min(self.config.max_height_2, self.level2 + noise))

    def set_levels_for_test(self, h1: float, h2: float) -> None:
        """Helper to inject specific tank levels for unit testing."""
        self.level1 = max(0.0, min(self.config.max_height_1, float(h1)))
        self.level2 = max(0.0, min(self.config.max_height_2, float(h2)))
        self._update_alarms()
        self._state = self._build_state(self._state.inflow_rate1, self._state.q12, self._state.q_out)

    def theoretical_steady_state(self, q_in: float, discharge_valve_pct: float = 100.0) -> Tuple[float, float]:
        """Compute theoretical equilibrium levels (h1_ss, h2_ss) for given constant inflow.

        At steady state: Q_in == Q_12 == Q_out.
        Q_12 = k_12 * sqrt(h1 - z12)  =>  h1_ss = z12 + (Q_in / k_12)^2
        Q_out = k_out * (valve/100) * sqrt(h2)  =>  h2_ss = (Q_in / (k_out * valve/100))^2
        """
        if self.config.k_12 <= 0.0:
            h1_ss = float("inf")
        else:
            h1_ss = self.config.z_12 + (float(q_in) / self.config.k_12) ** 2

        effective_k_out = self.config.k_out * (discharge_valve_pct / 100.0)
        if effective_k_out <= 0.0:
            h2_ss = float("inf")
        else:
            h2_ss = (float(q_in) / effective_k_out) ** 2

        return h1_ss, h2_ss

    def theoretical_inter_tank_drain_time(self, h1_start: Optional[float] = None, h1_target: Optional[float] = None) -> float:
        """Exact analytical Torricelli drain time for Tank 1 emptying into Tank 2 with zero inflow.

        dh1/dt = - (k_12 / A1) * sqrt(h1 - z12)
        t = (2 * A1 / k_12) * [sqrt(h1_start - z12) - sqrt(h1_target - z12)]
        """
        h_start = self.level1 if h1_start is None else float(h1_start)
        h_target = self.config.z_12 if h1_target is None else float(h1_target)

        head_start = max(0.0, h_start - self.config.z_12)
        head_target = max(0.0, h_target - self.config.z_12)

        if self.config.k_12 <= 0.0 or head_start <= 0.0:
            return float("inf")
        if head_target > head_start:
            return float("nan")

        return (2.0 * self.config.tank1_area / self.config.k_12) * (math.sqrt(head_start) - math.sqrt(head_target))

    def mass_balance_error(self) -> float:
        """Returns system-wide mass conservation error across both tanks.

        Delta stored volume == V_in - V_out - V_spilled1 - V_spilled2.
        """
        stored_vol = self.total_volume
        initial_vol = (self.initial_level_1 * self.config.tank1_area) + (self.initial_level_2 * self.config.tank2_area)
        delta_stored = stored_vol - initial_vol
        net_transferred = (
            self.total_inflow1_volume
            - self.total_qout_volume
            - self.total_spilled1_volume
            - self.total_spilled2_volume
        )
        return abs(delta_stored - net_transferred)

    def tank1_mass_balance_error(self) -> float:
        """Returns mass conservation error for Tank 1."""
        delta_v1 = self.volume1 - (self.initial_level_1 * self.config.tank1_area)
        net_v1 = self.total_inflow1_volume - self.total_q12_volume - self.total_spilled1_volume
        return abs(delta_v1 - net_v1)

    def tank2_mass_balance_error(self) -> float:
        """Returns mass conservation error for Tank 2."""
        delta_v2 = self.volume2 - (self.initial_level_2 * self.config.tank2_area)
        net_v2 = self.total_q12_volume - self.total_qout_volume - self.total_spilled2_volume
        return abs(delta_v2 - net_v2)

    def _sample_poisson_count(self, lam_dt: float) -> int:
        """Sample number of Poisson jump events in time interval dt using isolated PRNG."""
        if lam_dt <= 0.0:
            return 0
        if lam_dt < 30.0:
            l_val = math.exp(-lam_dt)
            k = 0
            p = 1.0
            while True:
                k += 1
                p *= self._rng.random()
                if p <= l_val:
                    break
            return k - 1
        else:
            # Gaussian approximation for large lambda * dt
            norm = self._rng.normalvariate(lam_dt, math.sqrt(lam_dt))
            return max(0, int(round(norm)))

    def _update_stochastic_disturbances(self, dt_s: float) -> Tuple[float, float, float]:
        """Update Ornstein-Uhlenbeck drift and Poisson jump load steps over interval dt_s.

        Returns (ou_val, poisson_step_val, total_disturbance).
        """
        if dt_s <= 0.0:
            return self._ou_state, self._poisson_load_step, self._ou_state + self._poisson_load_step

        # 1. Ornstein-Uhlenbeck process update:
        # dX_t = theta * (mu - X_t) dt + sigma * dW_t
        if self.config.ou_enabled and self.config.ou_sigma > 0.0:
            theta = self.config.ou_theta
            mu = self.config.ou_mu
            sigma = self.config.ou_sigma

            if theta > 1e-6:
                # Exact Gaussian transition step
                decay = math.exp(-theta * dt_s)
                variance = (sigma ** 2 / (2.0 * theta)) * (1.0 - math.exp(-2.0 * theta * dt_s))
                std_dev = math.sqrt(max(0.0, variance))
                z = self._rng.normalvariate(0.0, 1.0)
                self._ou_state = (self._ou_state * decay) + (mu * (1.0 - decay)) + (std_dev * z)
            else:
                # Pure Brownian motion with zero mean reversion
                z = self._rng.normalvariate(0.0, 1.0)
                self._ou_state += sigma * math.sqrt(dt_s) * z
        elif self.config.ou_enabled:
            # Deterministic mean-reverting drift
            decay = math.exp(-self.config.ou_theta * dt_s)
            self._ou_state = (self._ou_state * decay) + (self.config.ou_mu * (1.0 - decay))
        else:
            self._ou_state = 0.0

        # 2. Poisson jump load stepping update:
        if self.config.poisson_enabled and self.config.poisson_lambda > 0.0:
            # Optional exponential decay of existing jump load
            if self.config.jump_decay_rate > 0.0:
                self._poisson_load_step *= math.exp(-self.config.jump_decay_rate * dt_s)

            # Sample jump occurrences in dt_s
            lam_dt = self.config.poisson_lambda * dt_s
            num_jumps = self._sample_poisson_count(lam_dt)

            if num_jumps > 0:
                self.total_jump_count += num_jumps
                jump_sum = 0.0
                for _ in range(num_jumps):
                    if self.config.jump_std > 0.0:
                        jump_mag = self._rng.normalvariate(self.config.jump_mean, self.config.jump_std)
                    else:
                        jump_mag = self.config.jump_mean
                    jump_sum += jump_mag

                self._last_jump = jump_sum
                if self.config.poisson_cumulative:
                    self._poisson_load_step += jump_sum
                else:
                    self._poisson_load_step = jump_sum
        elif not self.config.poisson_enabled:
            self._poisson_load_step = 0.0
            self._last_jump = 0.0

        total_disturbance = self._ou_state + self._poisson_load_step + self.external_load_disturbance
        return self._ou_state, self._poisson_load_step, total_disturbance

    def _update_alarms(self) -> None:
        """Evaluate Schmitt-trigger hysteresis limit switches for both tanks."""
        cfg = self.config
        hyst = cfg.alarm_hysteresis

        # Tank 1 Alarms
        h1 = self.level1
        if h1 >= cfg.t1_hi_limit:
            self._t1_hi_alarm = True
        elif h1 < (cfg.t1_hi_limit - hyst):
            self._t1_hi_alarm = False

        if h1 >= cfg.t1_hi_hi_limit:
            self._t1_hi_hi_alarm = True
        elif h1 < (cfg.t1_hi_hi_limit - hyst):
            self._t1_hi_hi_alarm = False

        if h1 <= cfg.t1_lo_limit:
            self._t1_lo_alarm = True
        elif h1 > (cfg.t1_lo_limit + hyst):
            self._t1_lo_alarm = False

        if h1 <= cfg.t1_lo_lo_limit:
            self._t1_lo_lo_alarm = True
        elif h1 > (cfg.t1_lo_lo_limit + hyst):
            self._t1_lo_lo_alarm = False

        # Tank 2 Alarms
        h2 = self.level2
        if h2 >= cfg.t2_hi_limit:
            self._t2_hi_alarm = True
        elif h2 < (cfg.t2_hi_limit - hyst):
            self._t2_hi_alarm = False

        if h2 >= cfg.t2_hi_hi_limit:
            self._t2_hi_hi_alarm = True
        elif h2 < (cfg.t2_hi_hi_limit - hyst):
            self._t2_hi_hi_alarm = False

        if h2 <= cfg.t2_lo_limit:
            self._t2_lo_alarm = True
        elif h2 > (cfg.t2_lo_limit + hyst):
            self._t2_lo_alarm = False

        if h2 <= cfg.t2_lo_lo_limit:
            self._t2_lo_lo_alarm = True
        elif h2 > (cfg.t2_lo_lo_limit + hyst):
            self._t2_lo_lo_alarm = False

    def _build_state(self, q_in1: float, q12: float, q_out: float) -> TwoTankCascadeState:
        return TwoTankCascadeState(
            level1=self.level1,
            level2=self.level2,
            volume1=self.volume1,
            volume2=self.volume2,
            total_volume=self.total_volume,
            inflow_rate1=q_in1,
            q12=q12,
            q_out=q_out,
            actuator_inflow_pos=self.inlet_valve.position,
            actuator_discharge_pos=self.discharge_valve.position,
            ou_disturbance=self._ou_state,
            poisson_load_step=self._poisson_load_step,
            total_disturbance=self._ou_state + self._poisson_load_step + self.external_load_disturbance,
            total_inflow1_volume=self.total_inflow1_volume,
            total_q12_volume=self.total_q12_volume,
            total_qout_volume=self.total_qout_volume,
            total_spilled1_volume=self.total_spilled1_volume,
            total_spilled2_volume=self.total_spilled2_volume,
            raw_ai_counts1=self.raw_ai_counts1,
            raw_ai_counts2=self.raw_ai_counts2,
            t1_hi_alarm=self._t1_hi_alarm,
            t1_lo_alarm=self._t1_lo_alarm,
            t1_hi_hi_alarm=self._t1_hi_hi_alarm,
            t1_lo_lo_alarm=self._t1_lo_lo_alarm,
            t2_hi_alarm=self._t2_hi_alarm,
            t2_lo_alarm=self._t2_lo_alarm,
            t2_hi_hi_alarm=self._t2_hi_hi_alarm,
            t2_lo_lo_alarm=self._t2_lo_lo_alarm,
            is_empty1=self.level1 <= 0.001,
            is_full1=self.level1 >= (self.config.max_height_1 - 0.001),
            is_empty2=self.level2 <= 0.001,
            is_full2=self.level2 >= (self.config.max_height_2 - 0.001),
        )

    def step(
        self,
        dt_s: float,
        inflow_cmd: float = 0.0,
        discharge_cmd: float = 100.0,
        inlet_run: bool = True,
        discharge_open: bool = True,
    ) -> TwoTankCascadeState:
        """Advance physical simulation across discrete time interval dt_s.

        Args:
            dt_s: Time step in seconds.
            inflow_cmd: Inlet valve command (0..100%).
            discharge_cmd: Discharge valve command (0..100%).
            inlet_run: Boolean permissive/pump enable for Tank 1 inlet.
            discharge_open: Boolean permissive for Tank 2 discharge valve.

        Returns:
            TwoTankCascadeState snapshot after step completion.
        """
        if dt_s <= 0.0:
            return self._state

        # 1. Update stochastic disturbances
        ou_val, poisson_val, total_dist = self._update_stochastic_disturbances(dt_s)

        # 2. Update Actuators with slew rate limits
        target_inlet = float(inflow_cmd) if inlet_run else 0.0
        self.inlet_valve.set_command(target_inlet)
        inlet_pos = self.inlet_valve.step(dt_s)

        target_discharge = float(discharge_cmd) if discharge_open else 0.0
        self.discharge_valve.set_command(target_discharge)
        discharge_pos = self.discharge_valve.step(dt_s)

        # 3. Calculate Tank 1 Inflow
        q_in_base = (
            self.config.max_inflow_rate_1
            * (inlet_pos / 100.0)
            * math.sqrt(max(0.0, self.supply_pressure_factor))
        )
        if self.config.disturbance_target in (DisturbanceTarget.INFLOW, DisturbanceTarget.BOTH):
            q_in1 = max(0.0, q_in_base + total_dist)
        else:
            q_in1 = max(0.0, q_in_base)

        # 4. Inter-tank Torricelli flow: Q_12 = k_12 * sqrt(max(0, h1 - z12))
        head_12 = max(0.0, self.level1 - self.config.z_12)
        q12_unconstrained = self.config.k_12 * math.sqrt(head_12)

        if self.config.disturbance_target == DisturbanceTarget.INTER_TANK:
            q12_unconstrained = max(0.0, q12_unconstrained + total_dist)

        # Volume-availability constraint for Tank 1:
        # Maximum water that can leave Tank 1 in dt_s is current volume + inflow
        avail_vol_1 = self.volume1 + (q_in1 * dt_s)
        max_possible_q12 = avail_vol_1 / dt_s if dt_s > 0.0 else 0.0
        q12 = max(0.0, min(q12_unconstrained, max_possible_q12))

        # 5. Integrate Tank 1 mass conservation: dh1/dt = (Q_in1 - Q_12) / A1
        delta_v1 = (q_in1 - q12) * dt_s
        new_vol_1 = self.volume1 + delta_v1
        max_vol_1 = self.config.max_height_1 * self.config.tank1_area

        if new_vol_1 > max_vol_1:
            spill1 = new_vol_1 - max_vol_1
            self.total_spilled1_volume += spill1
            new_vol_1 = max_vol_1
        elif new_vol_1 < 0.0:
            new_vol_1 = 0.0

        self.level1 = new_vol_1 / self.config.tank1_area

        # 6. Tank 2 Discharge Flow: Q_out = k_out * (valve/100) * sqrt(max(0, h2))
        if not discharge_open or discharge_pos <= 0.0:
            q_out_base = 0.0
        else:
            q_out_base = (
                self.config.k_out
                * (discharge_pos / 100.0)
                * math.sqrt(max(0.0, self.level2))
            )

        if not discharge_open:
            q_out_unconstrained = 0.0
        elif self.config.disturbance_target in (DisturbanceTarget.OUTFLOW, DisturbanceTarget.BOTH):
            q_out_unconstrained = q_out_base + total_dist
        else:
            q_out_unconstrained = q_out_base + self.external_load_disturbance

        # Volume-availability constraint for Tank 2:
        # Inflow into Tank 2 is q12. Maximum water that can leave Tank 2 is volume + q12*dt
        avail_vol_2 = self.volume2 + (q12 * dt_s)
        max_possible_qout = avail_vol_2 / dt_s if dt_s > 0.0 else 0.0
        q_out = max(0.0, min(q_out_unconstrained, max_possible_qout))

        # 7. Integrate Tank 2 mass conservation: dh2/dt = (Q_12 - Q_out) / A2
        delta_v2 = (q12 - q_out) * dt_s
        new_vol_2 = self.volume2 + delta_v2
        max_vol_2 = self.config.max_height_2 * self.config.tank2_area

        if new_vol_2 > max_vol_2:
            spill2 = new_vol_2 - max_vol_2
            self.total_spilled2_volume += spill2
            new_vol_2 = max_vol_2
        elif new_vol_2 < 0.0:
            new_vol_2 = 0.0

        self.level2 = new_vol_2 / self.config.tank2_area

        # 8. Accumulate totals
        self.total_inflow1_volume += q_in1 * dt_s
        self.total_q12_volume += q12 * dt_s
        self.total_qout_volume += q_out * dt_s
        self.elapsed_time_s += dt_s

        # 9. Update alarms and state snapshot
        self._update_alarms()
        self._state = self._build_state(q_in1, q12, q_out)
        return self._state

    def reset(
        self,
        initial_level_1: Optional[float] = None,
        initial_level_2: Optional[float] = None,
        discharge_valve_pos: Optional[float] = None,
    ) -> None:
        """Reset simulation states to initial conditions."""
        self.level1 = float(self.config.initial_level_1 if initial_level_1 is None else initial_level_1)
        self.level2 = float(self.config.initial_level_2 if initial_level_2 is None else initial_level_2)
        self.initial_level_1 = self.level1
        self.initial_level_2 = self.level2

        self.inlet_valve.reset()
        self.discharge_valve.reset()
        init_pos = 100.0 if discharge_valve_pos is None else float(discharge_valve_pos)
        self.discharge_valve.position = init_pos
        self.discharge_valve.target_position = init_pos

        self._t1_hi_alarm = False
        self._t1_lo_alarm = False
        self._t1_hi_hi_alarm = False
        self._t1_lo_lo_alarm = False
        self._t2_hi_alarm = False
        self._t2_lo_alarm = False
        self._t2_hi_hi_alarm = False
        self._t2_lo_lo_alarm = False

        self.total_inflow1_volume = 0.0
        self.total_q12_volume = 0.0
        self.total_qout_volume = 0.0
        self.total_spilled1_volume = 0.0
        self.total_spilled2_volume = 0.0
        self.elapsed_time_s = 0.0

        self._rng = random.Random(self.config.random_seed)
        self._ou_state = float(self.config.ou_mu)
        self._poisson_load_step = 0.0
        self._last_jump = 0.0
        self.total_jump_count = 0
        self.external_load_disturbance = 0.0
        self.supply_pressure_factor = 1.0

        self._update_alarms()
        self._state = self._build_state(0.0, 0.0, 0.0)

    def get_telemetry(self) -> Dict[str, Any]:
        """Export comprehensive telemetry dictionary."""
        return {
            "elapsed_time_s": round(self.elapsed_time_s, 4),
            "level1": round(self.level1, 4),
            "level2": round(self.level2, 4),
            "volume1": round(self.volume1, 4),
            "volume2": round(self.volume2, 4),
            "total_volume": round(self.total_volume, 4),
            "inflow_rate1": round(self._state.inflow_rate1, 4),
            "q12": round(self._state.q12, 4),
            "q_out": round(self._state.q_out, 4),
            "actuator_inflow_pos": round(self.inlet_valve.position, 2),
            "actuator_discharge_pos": round(self.discharge_valve.position, 2),
            "ou_disturbance": round(self._ou_state, 4),
            "poisson_load_step": round(self._poisson_load_step, 4),
            "total_disturbance": round(self._state.total_disturbance, 4),
            "total_inflow1_volume": round(self.total_inflow1_volume, 4),
            "total_q12_volume": round(self.total_q12_volume, 4),
            "total_qout_volume": round(self.total_qout_volume, 4),
            "total_spilled1_volume": round(self.total_spilled1_volume, 4),
            "total_spilled2_volume": round(self.total_spilled2_volume, 4),
            "mass_balance_error": self.mass_balance_error(),
            "t1_hi_alarm": self._t1_hi_alarm,
            "t1_lo_alarm": self._t1_lo_alarm,
            "t1_hi_hi_alarm": self._t1_hi_hi_alarm,
            "t1_lo_lo_alarm": self._t1_lo_lo_alarm,
            "t2_hi_alarm": self._t2_hi_alarm,
            "t2_lo_alarm": self._t2_lo_alarm,
            "t2_hi_hi_alarm": self._t2_hi_hi_alarm,
            "t2_lo_lo_alarm": self._t2_lo_lo_alarm,
            "raw_ai_counts1": self.raw_ai_counts1,
            "raw_ai_counts2": self.raw_ai_counts2,
        }


class CascadeModelLogicUnit(ILogicUnit):
    """Adapter coupling TwoTankCascadeModel into SimulationEngine Phase 2 execution.

    Coordinates controller register inputs (%AQ1, %AQ2, %Q1, %Q2) with physical process
    emulation and maps sensor feedback (%AI1..%AI5) and alarm flags (%M1..%M8).
    """

    def __init__(
        self,
        plant: Optional[TwoTankCascadeModel] = None,
        name: str = "TwoTankCascadeLogicUnit",
        priority: int = 200,
    ) -> None:
        self._name = name
        self._priority = priority
        self._enabled = True
        self.plant: TwoTankCascadeModel = plant or TwoTankCascadeModel()

    @property
    def name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def execute(self, ctx: ScanContext) -> None:
        cfg = self.plant.config

        # 1. Read controller outputs
        inflow_cmd = 0.0
        if cfg.aq_inflow1_cmd_reg:
            raw_inflow = ctx.get_register(cfg.aq_inflow1_cmd_reg)
            if raw_inflow is not None:
                inflow_cmd = (float(raw_inflow) / 32000.0) * 100.0

        discharge_cmd = 100.0
        if cfg.aq_discharge_cmd_reg:
            raw_discharge = ctx.get_register(cfg.aq_discharge_cmd_reg)
            if raw_discharge is not None:
                discharge_cmd = (float(raw_discharge) / 32000.0) * 100.0

        inlet_run = True
        if cfg.q_inlet_cmd_reg:
            q_val = ctx.get_register(cfg.q_inlet_cmd_reg)
            if q_val is not None:
                inlet_run = bool(q_val)

        discharge_open = True
        if cfg.q_discharge_cmd_reg:
            qd_val = ctx.get_register(cfg.q_discharge_cmd_reg)
            if qd_val is not None:
                discharge_open = bool(qd_val)

        dt_s = ctx.dt_ms / 1000.0

        # 2. Advance cascade simulation
        state = self.plant.step(
            dt_s=dt_s,
            inflow_cmd=inflow_cmd,
            discharge_cmd=discharge_cmd,
            inlet_run=inlet_run,
            discharge_open=discharge_open,
        )

        # 3. Write sensor measurements and alarms to register table
        if cfg.ai_level1_reg:
            ctx.set_register(cfg.ai_level1_reg, state.raw_ai_counts1)
        if cfg.ai_level2_reg:
            ctx.set_register(cfg.ai_level2_reg, state.raw_ai_counts2)
        if cfg.ai_inflow1_reg:
            # Scale flow rate to counts (0..max_inflow => 0..32000)
            raw_inflow_rate = round((state.inflow_rate1 / cfg.max_inflow_rate_1) * 32000)
            ctx.set_register(cfg.ai_inflow1_reg, max(0, min(32000, raw_inflow_rate)))
        if cfg.ai_q12_reg:
            # Scale Q12 (0..max_inflow => 0..32000)
            raw_q12 = round((state.q12 / cfg.max_inflow_rate_1) * 32000)
            ctx.set_register(cfg.ai_q12_reg, max(0, min(32000, raw_q12)))
        if cfg.ai_qout_reg:
            # Scale Qout (0..max_inflow => 0..32000)
            raw_qout = round((state.q_out / cfg.max_inflow_rate_1) * 32000)
            ctx.set_register(cfg.ai_qout_reg, max(0, min(32000, raw_qout)))

        # Tank 1 Alarms
        if cfg.t1_hi_alarm_reg:
            ctx.set_register(cfg.t1_hi_alarm_reg, state.t1_hi_alarm)
        if cfg.t1_lo_alarm_reg:
            ctx.set_register(cfg.t1_lo_alarm_reg, state.t1_lo_alarm)
        if cfg.t1_hi_hi_alarm_reg:
            ctx.set_register(cfg.t1_hi_hi_alarm_reg, state.t1_hi_hi_alarm)
        if cfg.t1_lo_lo_alarm_reg:
            ctx.set_register(cfg.t1_lo_lo_alarm_reg, state.t1_lo_lo_alarm)

        # Tank 2 Alarms
        if cfg.t2_hi_alarm_reg:
            ctx.set_register(cfg.t2_hi_alarm_reg, state.t2_hi_alarm)
        if cfg.t2_lo_alarm_reg:
            ctx.set_register(cfg.t2_lo_alarm_reg, state.t2_lo_alarm)
        if cfg.t2_hi_hi_alarm_reg:
            ctx.set_register(cfg.t2_hi_hi_alarm_reg, state.t2_hi_hi_alarm)
        if cfg.t2_lo_lo_alarm_reg:
            ctx.set_register(cfg.t2_lo_lo_alarm_reg, state.t2_lo_lo_alarm)

    def reset(self) -> None:
        self.plant.reset()


class TwoTankCascadePIController(ILogicUnit):
    """IEC 61131-3 Cascade Proportional-Integral (PI) Level Controller.

    Implements a classic master-slave cascade architecture:
    - Master (Outer Loop): Regulates Tank 2 level (%AI2) to desired setpoint by computing
      the setpoint for Tank 1 level.
    - Slave (Inner Loop): Regulates Tank 1 level (%AI1) to master setpoint by driving
      inlet actuator (%AQ1).
    - Includes anti-windup clamping and disturbance rejection.
    """

    def __init__(
        self,
        setpoint2_pct: float = 50.0,
        kp_outer: float = 1.5,
        ki_outer: float = 0.2,
        kp_inner: float = 2.0,
        ki_inner: float = 0.5,
        ai_level1_channel: str = "%AI1",
        ai_level2_channel: str = "%AI2",
        aq_inflow_channel: str = "%AQ1",
        q_inlet_cmd_channel: Optional[str] = "%Q1",
        name: str = "Cascade_PI_Level_Controller",
        priority: int = 100,
    ) -> None:
        self._name = name
        self._priority = priority
        self._enabled = True

        self.setpoint2_pct = float(setpoint2_pct)
        self.kp_outer = float(kp_outer)
        self.ki_outer = float(ki_outer)
        self.kp_inner = float(kp_inner)
        self.ki_inner = float(ki_inner)

        self.ai_level1_channel = ai_level1_channel
        self.ai_level2_channel = ai_level2_channel
        self.aq_inflow_channel = aq_inflow_channel
        self.q_inlet_cmd_channel = q_inlet_cmd_channel

        self.integral_outer: float = 0.0
        self.integral_inner: float = 0.0
        self.last_pv1_pct: float = self.setpoint2_pct
        self.last_pv2_pct: float = self.setpoint2_pct
        self.last_cv_pct: float = self.setpoint2_pct
        self.target_sp1_pct: float = self.setpoint2_pct

    @property
    def name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def execute(self, ctx: ScanContext) -> None:
        dt_s = ctx.dt_ms / 1000.0
        if dt_s <= 0.0:
            return

        # Read process variables (raw counts 0..32000 => 0..100%)
        raw_ai1 = ctx.get_register(self.ai_level1_channel)
        raw_ai2 = ctx.get_register(self.ai_level2_channel)

        if raw_ai1 is not None:
            pv1 = (float(raw_ai1) / 32000.0) * 100.0
            self.last_pv1_pct = pv1
        else:
            pv1 = self.last_pv1_pct

        if raw_ai2 is not None:
            pv2 = (float(raw_ai2) / 32000.0) * 100.0
            self.last_pv2_pct = pv2
        else:
            pv2 = self.last_pv2_pct

        # --- Master Loop: Tank 2 Level Control ---
        err_outer = self.setpoint2_pct - pv2
        p_outer = self.kp_outer * err_outer
        # Integrate with anti-windup clamping
        self.integral_outer += self.ki_outer * err_outer * dt_s
        self.integral_outer = max(-50.0, min(50.0, self.integral_outer))

        sp1 = self.setpoint2_pct + p_outer + self.integral_outer
        self.target_sp1_pct = max(0.0, min(100.0, sp1))

        # --- Slave Loop: Tank 1 Level Control ---
        err_inner = self.target_sp1_pct - pv1
        p_inner = self.kp_inner * err_inner
        self.integral_inner += self.ki_inner * err_inner * dt_s
        self.integral_inner = max(-50.0, min(50.0, self.integral_inner))

        cv = self.target_sp1_pct + p_inner + self.integral_inner
        cv_clamped = max(0.0, min(100.0, cv))
        self.last_cv_pct = cv_clamped

        # Convert to raw counts and write to %AQ1
        raw_aq = round((cv_clamped / 100.0) * 32000.0)
        ctx.set_register(self.aq_inflow_channel, max(0, min(32000, raw_aq)))

        if self.q_inlet_cmd_channel:
            ctx.set_register(self.q_inlet_cmd_channel, True)

    def reset(self) -> None:
        self.integral_outer = 0.0
        self.integral_inner = 0.0
        self.last_pv1_pct = self.setpoint2_pct
        self.last_pv2_pct = self.setpoint2_pct
        self.last_cv_pct = self.setpoint2_pct
        self.target_sp1_pct = self.setpoint2_pct
