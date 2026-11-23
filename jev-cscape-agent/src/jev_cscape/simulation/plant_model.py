"""First-Principles Closed-Loop Plant Process Emulation: Tank Level System.

Work Package: W021 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Provides a deterministic, continuous-time (discretized to scan cycle dt) physical
plant process model of an industrial buffer tank liquid level system with:
1. First-principles mass conservation ODE: dh/dt = (Q_in - Q_out) / A.
2. Torricelli gravity drainage and pump discharge dynamics.
3. Actuator dynamics: rate-limited control valve slew rate (e.g. 0 to 100% over 5s)
   and pump inertia / coast-down lag.
4. Physical volume-availability clamping (guaranteed non-negative level h >= 0)
   and overflow containment (h <= H_max) with spilled volume ledger.
5. Discrete level switches (Low-Low, Low, High, High-High) with Schmitt-trigger
   hysteresis deadband to prevent contact chatter.
6. Deterministic sensor noise injection with isolated PRNG seed for 100% reproducibility.
7. Bidirectional engineering scaling between physical units and Horner OCS raw registers
   (%AI1: 0..32000 counts, %AQ1: 0..32000 counts, %I1..%I5, %Q1..%Q2, %M1..%M4).
8. PlantModelLogicUnit adapter implementing ILogicUnit for SimulationEngine integration.
"""

from __future__ import annotations

from enum import Enum
import math
import random
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from jev_cscape.simulation.engine import ILogicUnit, ScanContext


class ResolutionMode(str, Enum):
    """Horner OCS analog I/O integer resolution scaling standard."""
    COUNTS_32000 = "COUNTS_32000"  # Standard Horner 15-bit unipolar range: 0..32000
    COUNTS_10000 = "COUNTS_10000"  # Centi-unit / percentage scaled range: 0..10000


class AlarmDirection(str, Enum):
    """Direction of level excursion that triggers the alarm."""
    LOW = "LOW"
    HIGH = "HIGH"


class SwitchPolarity(str, Enum):
    """Discrete limit switch contact wiring polarity."""
    NORMALLY_OPEN = "NORMALLY_OPEN"      # Active-High: True on Alarm
    NORMALLY_CLOSED = "NORMALLY_CLOSED"  # Active-Low: False on Alarm (Fail-Safe)


class FailAction(str, Enum):
    """Actuator behavior on signal loss or power failure."""
    FAIL_CLOSED = "FAIL_CLOSED"
    FAIL_OPEN = "FAIL_OPEN"
    FAIL_LAST = "FAIL_LAST"


class TankConfig(BaseModel):
    """Configuration parameters for tank level physical simulation."""
    tank_area: float = Field(default=1.0, gt=0.0, description="Tank cross-sectional area (m^2)")
    max_height: float = Field(default=100.0, gt=0.0, description="Maximum height/range (units or %)")
    initial_level: float = Field(default=0.0, ge=0.0, description="Initial liquid level")
    k_drain: float = Field(default=0.5, ge=0.0, description="Torricelli discharge coefficient")
    max_inflow_rate: float = Field(default=10.0, gt=0.0, description="Max inflow at 100% actuator (units/s)")
    max_outflow_rate: float = Field(default=10.0, gt=0.0, description="Max pump outflow (units/s)")
    inflow_slew_rate: float = Field(default=20.0, gt=0.0, description="Actuator rate limit (%/s)")
    outflow_slew_rate: float = Field(default=50.0, gt=0.0, description="Pump rate limit (%/s)")
    pump_tau_accel: float = Field(default=1.5, ge=0.0, description="Pump acceleration lag (s)")
    pump_tau_coast: float = Field(default=2.5, ge=0.0, description="Pump coast-down lag (s)")

    # Alarm thresholds
    hi_hi_limit: float = Field(default=90.0)
    hi_limit: float = Field(default=75.0)
    lo_limit: float = Field(default=25.0)
    lo_lo_limit: float = Field(default=10.0)
    alarm_hysteresis: float = Field(default=2.0, ge=0.0, description="Deadband to prevent alarm chatter")

    # Noise & random seed
    random_seed: int = Field(default=42, description="Isolated PRNG seed for deterministic repeatability")
    sensor_noise_sigma: float = Field(default=0.0, ge=0.0, description="Sensor noise std dev")

    # Horner OCS Register Bindings
    ai_level_reg: Optional[str] = "%AI1"
    ai_inflow_reg: Optional[str] = "%AI2"
    ai_outflow_reg: Optional[str] = "%AI3"
    aq_inflow_cmd_reg: Optional[str] = "%AQ1"
    aq_pump_speed_reg: Optional[str] = "%AQ2"
    q_pump_cmd_reg: Optional[str] = "%Q1"
    q_inlet_solenoid_reg: Optional[str] = "%Q2"
    i_pump_running_reg: Optional[str] = "%I1"
    i_low_level_reg: Optional[str] = "%I2"
    i_high_level_reg: Optional[str] = "%I3"
    hi_alarm_reg: Optional[str] = "%M1"
    lo_alarm_reg: Optional[str] = "%M2"
    hi_hi_alarm_reg: Optional[str] = "%M3"
    lo_lo_alarm_reg: Optional[str] = "%M4"

    def model_post_init(self, __context: Any) -> None:
        if self.initial_level > self.max_height:
            raise ValueError(f"initial_level ({self.initial_level}) cannot exceed max_height ({self.max_height})")


class TankState(BaseModel):
    """Immutable state snapshot of tank physical model after scan cycle."""
    level: float
    volume: float
    inflow_rate: float
    outflow_rate: float
    actuator_inflow_pos: float
    actuator_outflow_pos: float
    hi_alarm: bool
    lo_alarm: bool
    hi_hi_alarm: bool
    lo_lo_alarm: bool
    raw_ai_counts: int
    total_inflow_volume: float
    total_outflow_volume: float
    total_spilled_volume: float
    pump_running: bool = False
    is_empty: bool = False
    is_full: bool = False


class ScalingConverter:
    """Pure mathematical bidirectional engineering unit scaling functions."""

    @staticmethod
    def get_raw_bounds(mode: ResolutionMode) -> Tuple[int, int]:
        if mode == ResolutionMode.COUNTS_10000:
            return 0, 10000
        return 0, 32000

    @classmethod
    def level_to_raw_ai(
        cls,
        level: float,
        h_max: float = 100.0,
        h_min: float = 0.0,
        mode: ResolutionMode = ResolutionMode.COUNTS_32000,
    ) -> int:
        r_min, r_max = cls.get_raw_bounds(mode)
        span_h = h_max - h_min
        if span_h <= 0.0:
            raise ValueError("h_max must be greater than h_min")
        clamped_h = max(h_min, min(h_max, float(level)))
        norm = (clamped_h - h_min) / span_h
        raw = round(r_min + (norm * (r_max - r_min)))
        return max(r_min, min(r_max, raw))

    @classmethod
    def raw_ai_to_level(
        cls,
        raw_val: int,
        h_max: float = 100.0,
        h_min: float = 0.0,
        mode: ResolutionMode = ResolutionMode.COUNTS_32000,
    ) -> float:
        r_min, r_max = cls.get_raw_bounds(mode)
        span_h = h_max - h_min
        clamped_raw = max(r_min, min(r_max, int(raw_val)))
        norm = (clamped_raw - r_min) / float(r_max - r_min)
        return h_min + (norm * span_h)

    @classmethod
    def raw_aq_to_stroke_pct(
        cls,
        raw_val: int,
        mode: ResolutionMode = ResolutionMode.COUNTS_32000,
    ) -> float:
        r_min, r_max = cls.get_raw_bounds(mode)
        clamped_raw = max(r_min, min(r_max, int(raw_val)))
        return ((clamped_raw - r_min) / float(r_max - r_min)) * 100.0

    @classmethod
    def stroke_pct_to_raw_aq(
        cls,
        pct: float,
        mode: ResolutionMode = ResolutionMode.COUNTS_32000,
    ) -> int:
        r_min, r_max = cls.get_raw_bounds(mode)
        clamped_pct = max(0.0, min(100.0, float(pct)))
        raw = round(r_min + ((clamped_pct / 100.0) * (r_max - r_min)))
        return max(r_min, min(r_max, raw))


class ValveActuatorDynamics:
    """First-principles physical model of a control valve with slew rate limiting."""

    def __init__(
        self,
        slew_rate_up: float = 20.0,
        slew_rate_down: float = 20.0,
        slew_rate_fail: float = 50.0,
        fail_action: FailAction = FailAction.FAIL_CLOSED,
    ) -> None:
        self.slew_rate_up = float(slew_rate_up)
        self.slew_rate_down = float(slew_rate_down)
        self.slew_rate_fail = float(slew_rate_fail)
        self.fail_action = fail_action
        self.position: float = 0.0
        self.target_position: float = 0.0
        self.power_available: bool = True
        self.travel_time_s: float = 0.0
        self.travel_fault: bool = False
        self.last_actual_slew: float = 0.0

    @property
    def is_open(self) -> bool:
        return self.position >= 99.5

    @property
    def is_closed(self) -> bool:
        return self.position <= 0.5

    @property
    def is_traveling(self) -> bool:
        return not self.is_open and not self.is_closed

    def set_command(self, cmd_percent: float) -> None:
        self.target_position = max(0.0, min(100.0, float(cmd_percent)))

    def step(self, dt_s: float) -> float:
        if dt_s <= 0:
            return self.position

        if not self.power_available:
            effective_target = 0.0 if self.fail_action == FailAction.FAIL_CLOSED else 100.0
            rate = self.slew_rate_fail
        else:
            effective_target = self.target_position
            diff = effective_target - self.position
            rate = self.slew_rate_up if diff >= 0 else self.slew_rate_down

        diff = effective_target - self.position
        if abs(diff) <= 1e-6:
            self.position = effective_target
            self.last_actual_slew = 0.0
            self.travel_time_s = 0.0
        elif diff > 0:
            max_step = rate * dt_s
            actual_step = min(diff, max_step)
            self.position += actual_step
            self.last_actual_slew = actual_step / dt_s
            self.travel_time_s += dt_s
        else:
            max_step = rate * dt_s
            actual_step = min(abs(diff), max_step)
            self.position -= actual_step
            self.last_actual_slew = -actual_step / dt_s
            self.travel_time_s += dt_s

        self.position = max(0.0, min(100.0, self.position))
        return self.position

    def reset(self) -> None:
        self.position = 0.0
        self.target_position = 0.0
        self.power_available = True
        self.travel_time_s = 0.0
        self.travel_fault = False
        self.last_actual_slew = 0.0


class PumpActuatorDynamics:
    """First-principles centrifugal pump dynamics with acceleration/coast-down lag."""

    def __init__(self, tau_accel: float = 1.5, tau_coast: float = 2.5) -> None:
        self.tau_accel = float(tau_accel)
        self.tau_coast = float(tau_coast)
        self.speed: float = 0.0
        self.target_speed: float = 0.0
        self.run_command: bool = False
        self.power_available: bool = True
        self.cavitation_active: bool = False

    @property
    def is_running(self) -> bool:
        return self.speed >= 5.0

    def set_command(self, speed_percent: float, run_cmd: bool = True) -> None:
        self.target_speed = max(0.0, min(100.0, float(speed_percent)))
        self.run_command = bool(run_cmd)

    def step(self, dt_s: float, current_level: float = 50.0) -> float:
        if dt_s <= 0:
            return self.speed

        if current_level < 0.001:
            self.cavitation_active = True
        else:
            self.cavitation_active = False

        if not self.power_available or not self.run_command or self.cavitation_active:
            effective_target = 0.0
            tau = self.tau_coast
        else:
            effective_target = self.target_speed
            tau = self.tau_accel if effective_target > self.speed else self.tau_coast

        if tau > 1e-4:
            alpha = 1.0 - math.exp(-dt_s / tau)
        else:
            alpha = 1.0

        self.speed += alpha * (effective_target - self.speed)
        self.speed = max(0.0, min(100.0, self.speed))
        return self.speed

    def reset(self) -> None:
        self.speed = 0.0
        self.target_speed = 0.0
        self.run_command = False
        self.power_available = True
        self.cavitation_active = False


class TankLevelPlantModel:
    """First-principles physical plant model for a tank level system with Torricelli drain."""

    def __init__(self, config: Optional[TankConfig] = None) -> None:
        self.config: TankConfig = config or TankConfig()
        self.level: float = float(self.config.initial_level)
        self.initial_level: float = self.level
        self.valve = ValveActuatorDynamics(
            slew_rate_up=self.config.inflow_slew_rate,
            slew_rate_down=self.config.inflow_slew_rate,
        )
        self.pump = PumpActuatorDynamics(
            tau_accel=self.config.pump_tau_accel,
            tau_coast=self.config.pump_tau_coast,
        )

        # Alarm hysteresis states
        self._hi_alarm: bool = False
        self._lo_alarm: bool = False
        self._hi_hi_alarm: bool = False
        self._lo_lo_alarm: bool = False

        # Accumulators
        self.total_inflow_volume: float = 0.0
        self.total_outflow_volume: float = 0.0
        self.total_spilled_volume: float = 0.0
        self.elapsed_time_s: float = 0.0

        # PRNG
        self._rng = random.Random(self.config.random_seed)

        # Disturbance
        self.outflow_demand_disturbance: float = 0.0
        self.supply_pressure_factor: float = 1.0

        # Initial state update
        self._update_alarms()
        self._state = self._build_state(0.0, 0.0)

    @property
    def volume(self) -> float:
        return self.level * self.config.tank_area

    @property
    def inflow_rate(self) -> float:
        return self._state.inflow_rate

    @property
    def outflow_rate(self) -> float:
        return self._state.outflow_rate

    @property
    def state(self) -> TankState:
        return self._state

    @property
    def raw_ai_counts(self) -> int:
        return ScalingConverter.level_to_raw_ai(
            self.level, h_max=self.config.max_height, mode=ResolutionMode.COUNTS_32000
        )

    def set_level_for_test(self, level: float) -> None:
        """Helper to inject specific test level for threshold / invariant assertions."""
        self.level = max(0.0, min(self.config.max_height, float(level)))
        self._update_alarms()
        self._state = self._build_state(self.inflow_rate, self.outflow_rate)

    def theoretical_empty_time(self, h0: Optional[float] = None) -> float:
        """Exact analytical Torricelli drain emptying time: t_empty = 2*A*sqrt(h0) / k_drain."""
        h = self.level if h0 is None else float(h0)
        if self.config.k_drain <= 0 or h <= 0:
            return float("inf")
        return (2.0 * self.config.tank_area * math.sqrt(h)) / self.config.k_drain

    def theoretical_steady_state_level(self, qin: float) -> float:
        """Equilibrium level where Q_in == Q_drain: h_ss = (qin / k_drain)^2."""
        if self.config.k_drain <= 0:
            return float("inf")
        return (float(qin) / self.config.k_drain) ** 2

    def mass_balance_error(self) -> float:
        """Returns difference between delta stored volume and net volume transferred."""
        stored_vol = self.volume
        initial_vol = self.initial_level * self.config.tank_area
        delta_stored = stored_vol - initial_vol
        net_transferred = self.total_inflow_volume - self.total_outflow_volume - self.total_spilled_volume
        return abs(delta_stored - net_transferred)

    def _update_alarms(self) -> None:
        """Evaluate alarms with Schmitt-trigger hysteresis deadband."""
        cfg = self.config
        hyst = cfg.alarm_hysteresis
        h = self.level

        # High Alarm (trip >= hi_limit, clear < hi_limit - hyst)
        if h >= cfg.hi_limit:
            self._hi_alarm = True
        elif h < (cfg.hi_limit - hyst):
            self._hi_alarm = False

        # High-High Alarm
        if h >= cfg.hi_hi_limit:
            self._hi_hi_alarm = True
        elif h < (cfg.hi_hi_limit - hyst):
            self._hi_hi_alarm = False

        # Low Alarm (trip <= lo_limit, clear > lo_limit + hyst)
        if h <= cfg.lo_limit:
            self._lo_alarm = True
        elif h > (cfg.lo_limit + hyst):
            self._lo_alarm = False

        # Low-Low Alarm
        if h <= cfg.lo_lo_limit:
            self._lo_lo_alarm = True
        elif h > (cfg.lo_lo_limit + hyst):
            self._lo_lo_alarm = False

    def _build_state(self, q_in: float, q_out: float) -> TankState:
        return TankState(
            level=self.level,
            volume=self.volume,
            inflow_rate=q_in,
            outflow_rate=q_out,
            actuator_inflow_pos=self.valve.position,
            actuator_outflow_pos=self.pump.speed,
            hi_alarm=self._hi_alarm,
            lo_alarm=self._lo_alarm,
            hi_hi_alarm=self._hi_hi_alarm,
            lo_lo_alarm=self._lo_lo_alarm,
            raw_ai_counts=self.raw_ai_counts,
            total_inflow_volume=self.total_inflow_volume,
            total_outflow_volume=self.total_outflow_volume,
            total_spilled_volume=self.total_spilled_volume,
            pump_running=self.pump.is_running,
            is_empty=self.level <= 0.001,
            is_full=self.level >= (self.config.max_height - 0.001),
        )

    def step(
        self,
        dt_s: float,
        inflow_cmd: float = 0.0,
        outflow_cmd: float = 0.0,
        drain_open: bool = True,
        pump_run: bool = False,
    ) -> TankState:
        """Advance physical simulation across discrete time interval dt_s."""
        if dt_s <= 0.0:
            return self._state

        # 1. Update actuators
        self.valve.set_command(inflow_cmd)
        valve_pos = self.valve.step(dt_s)

        self.pump.set_command(outflow_cmd, run_cmd=pump_run)
        pump_spd = self.pump.step(dt_s, current_level=self.level)

        # 2. Inflow rate
        q_in = (
            self.config.max_inflow_rate
            * (valve_pos / 100.0)
            * math.sqrt(max(0.0, self.supply_pressure_factor))
        )

        # 3. Outflow components
        q_drain = 0.0
        if drain_open and self.level > 0.0:
            q_drain = self.config.k_drain * math.sqrt(self.level)

        q_pump = 0.0
        if self.level > 0.0:
            q_pump = self.config.max_outflow_rate * (pump_spd / 100.0)

        unconstrained_q_out = q_drain + q_pump + self.outflow_demand_disturbance

        # 4. Volume-availability constraint (ensures h >= 0 without negative level)
        available_vol = (self.level * self.config.tank_area) + (q_in * dt_s)
        max_possible_outflow = available_vol / dt_s if dt_s > 0 else 0.0
        q_out = min(unconstrained_q_out, max_possible_outflow)

        # 5. Integrate mass conservation ODE
        delta_v = (q_in - q_out) * dt_s
        new_vol = (self.level * self.config.tank_area) + delta_v
        max_vol = self.config.max_height * self.config.tank_area

        if new_vol > max_vol:
            spill = new_vol - max_vol
            self.total_spilled_volume += spill
            new_vol = max_vol
        elif new_vol < 0.0:
            new_vol = 0.0

        self.level = new_vol / self.config.tank_area
        self.total_inflow_volume += q_in * dt_s
        self.total_outflow_volume += q_out * dt_s
        self.elapsed_time_s += dt_s

        # 6. Update alarms and state
        self._update_alarms()
        self._state = self._build_state(q_in, q_out)
        return self._state

    def reset(self, initial_level: Optional[float] = None) -> None:
        """Reset simulation states to clean baseline conditions."""
        self.level = float(self.config.initial_level if initial_level is None else initial_level)
        self.initial_level = self.level
        self.valve.reset()
        self.pump.reset()
        self._hi_alarm = False
        self._lo_alarm = False
        self._hi_hi_alarm = False
        self._lo_lo_alarm = False
        self.total_inflow_volume = 0.0
        self.total_outflow_volume = 0.0
        self.total_spilled_volume = 0.0
        self.elapsed_time_s = 0.0
        self.outflow_demand_disturbance = 0.0
        self.supply_pressure_factor = 1.0
        self._rng = random.Random(self.config.random_seed)
        self._update_alarms()
        self._state = self._build_state(0.0, 0.0)

    def get_telemetry(self) -> Dict[str, Any]:
        """Export comprehensive telemetry dictionary."""
        return {
            "elapsed_time_s": round(self.elapsed_time_s, 4),
            "level": round(self.level, 4),
            "volume": round(self.volume, 4),
            "raw_ai_counts": self.raw_ai_counts,
            "inflow_rate": round(self.inflow_rate, 4),
            "outflow_rate": round(self.outflow_rate, 4),
            "actuator_valve_pct": round(self.valve.position, 2),
            "actuator_pump_pct": round(self.pump.speed, 2),
            "pump_running": self.pump.is_running,
            "hi_alarm": self._hi_alarm,
            "lo_alarm": self._lo_alarm,
            "hi_hi_alarm": self._hi_hi_alarm,
            "lo_lo_alarm": self._lo_lo_alarm,
            "total_inflow_volume": round(self.total_inflow_volume, 4),
            "total_outflow_volume": round(self.total_outflow_volume, 4),
            "total_spilled_volume": round(self.total_spilled_volume, 4),
            "mass_balance_error": self.mass_balance_error(),
        }


# Type alias for compatibility with subagent specs
TankPlantModel = TankLevelPlantModel


class PlantModelLogicUnit(ILogicUnit):
    """Adapter coupling TankLevelPlantModel into SimulationEngine Phase 2 execution."""

    def __init__(
        self,
        plant: Optional[TankLevelPlantModel] = None,
        name: str = "TankLevelPlantModel",
        priority: int = 200,
    ) -> None:
        self._name = name
        self._priority = priority
        self._enabled = True
        self.plant: TankLevelPlantModel = plant or TankLevelPlantModel()

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
        if cfg.aq_inflow_cmd_reg:
            raw_aq = ctx.get_register(cfg.aq_inflow_cmd_reg)
            if raw_aq is not None:
                inflow_cmd = (float(raw_aq) / 32000.0) * 100.0

        outflow_cmd = 0.0
        if cfg.aq_pump_speed_reg:
            raw_pump = ctx.get_register(cfg.aq_pump_speed_reg)
            if raw_pump is not None:
                outflow_cmd = (float(raw_pump) / 32000.0) * 100.0

        pump_run = False
        if cfg.q_pump_cmd_reg:
            pump_run = bool(ctx.get_register(cfg.q_pump_cmd_reg))

        drain_open = True
        dt_s = ctx.dt_ms / 1000.0

        # 2. Advance plant simulation
        state = self.plant.step(
            dt_s=dt_s,
            inflow_cmd=inflow_cmd,
            outflow_cmd=outflow_cmd,
            drain_open=drain_open,
            pump_run=pump_run,
        )

        # 3. Write sensor inputs & alarms to register context
        if cfg.ai_level_reg:
            ctx.set_register(cfg.ai_level_reg, state.raw_ai_counts)
        if cfg.i_pump_running_reg:
            ctx.set_register(cfg.i_pump_running_reg, state.pump_running)
        if cfg.hi_alarm_reg:
            ctx.set_register(cfg.hi_alarm_reg, state.hi_alarm)
        if cfg.lo_alarm_reg:
            ctx.set_register(cfg.lo_alarm_reg, state.lo_alarm)
        if cfg.hi_hi_alarm_reg:
            ctx.set_register(cfg.hi_hi_alarm_reg, state.hi_hi_alarm)
        if cfg.lo_lo_alarm_reg:
            ctx.set_register(cfg.lo_lo_alarm_reg, state.lo_lo_alarm)

    def reset(self) -> None:
        self.plant.reset()


# Type alias for compatibility
TankPlantLogicUnit = PlantModelLogicUnit
