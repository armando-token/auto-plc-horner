"""First-Principles Plant Thermal Dynamics & Heat Exchanger ODE Simulation.

Work Package: W053 (Gate G7 / G4)
Classification: PRODUCTION [first-principles thermodynamics & closed-loop simulation]

Provides:
- ThermalConfig: Thermodynamic physical parameters (tank geometry, fluid properties, heat transfer coefficients).
- CounterFlowHeatExchanger: Rigorous NTU-epsilon counter-current shell-and-tube heat exchanger model.
- HeaterActuator: First-order thermal lag heater actuator with saturation and dry-run safety trip.
- RTDSensorModel: First-order thermowell thermal lag, Gaussian noise, and Namur NE43 signal conditioning.
- TankThermalPlantModel: Non-linear energy balance ODE solver coupled with liquid volume/height.
- ThermalModelLogicUnit: ILogicUnit implementation for Horner OCS SimulationEngine scan cycle integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import random
import time
from typing import Any, Dict, List, Optional, Tuple

from jev_cscape.simulation.engine import ILogicUnit
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.scaling_bridge import (
    NamurNE43Validator,
    OPCQualityFlag,
    QualityCode,
    encode_quality_word,
)


@dataclass
class HeatExchangerConfig:
    """Parameters for Counter-Flow Shell-and-Tube Heat Exchanger."""
    U_hx: float = 1200.0           # Overall heat transfer coefficient [W / (m^2 * K)]
    A_hx: float = 2.5              # Heat transfer surface area [m^2]
    cp_hot: float = 4184.0         # Specific heat capacity of hot fluid [J / (kg * K)] (water)
    cp_cold: float = 4184.0        # Specific heat capacity of cold fluid [J / (kg * K)] (water)


@dataclass
class HeatExchangerState:
    """State snapshot for Counter-Flow Heat Exchanger."""
    T_hot_in: float
    T_hot_out: float
    T_cold_in: float
    T_cold_out: float
    m_dot_hot: float
    m_dot_cold: float
    q_hx: float
    epsilon: float
    NTU: float
    energy_residual: float


class CounterFlowHeatExchanger:
    """Counter-flow shell-and-tube heat exchanger using the NTU-epsilon method."""

    def __init__(self, config: Optional[HeatExchangerConfig] = None) -> None:
        self.config = config or HeatExchangerConfig()

    def step(
        self,
        T_hot_in: float,
        T_cold_in: float,
        m_dot_hot: float,
        m_dot_cold: float,
    ) -> HeatExchangerState:
        """Calculates heat transfer rate and stream outlet temperatures."""
        cp_h = self.config.cp_hot
        cp_c = self.config.cp_cold

        C_h = max(0.0, m_dot_hot) * cp_h
        C_c = max(0.0, m_dot_cold) * cp_c

        # Guard against zero flow
        if C_h < 1e-6 or C_c < 1e-6:
            return HeatExchangerState(
                T_hot_in=T_hot_in,
                T_hot_out=T_hot_in,
                T_cold_in=T_cold_in,
                T_cold_out=T_cold_in,
                m_dot_hot=m_dot_hot,
                m_dot_cold=m_dot_cold,
                q_hx=0.0,
                epsilon=0.0,
                NTU=0.0,
                energy_residual=0.0,
            )

        C_min = min(C_h, C_c)
        C_max = max(C_h, C_c)
        C_r = C_min / C_max

        UA = self.config.U_hx * self.config.A_hx
        NTU = UA / C_min

        # Counter-flow effectiveness with removable singularity at C_r == 1.0
        if abs(1.0 - C_r) < 1e-6:
            epsilon = NTU / (1.0 + NTU)
        else:
            exp_term = math.exp(-NTU * (1.0 - C_r))
            epsilon = (1.0 - exp_term) / (1.0 - C_r * exp_term)

        # Bound effectiveness physically [0, 1]
        epsilon = max(0.0, min(1.0, epsilon))

        # Heat transfer rate
        q_max = C_min * (T_hot_in - T_cold_in)
        q_hx = epsilon * q_max

        # Outlet temperatures
        T_hot_out = T_hot_in - (q_hx / C_h)
        T_cold_out = T_cold_in + (q_hx / C_c)

        # Energy residual balance: Q_h - Q_c
        Q_dot_h = C_h * (T_hot_in - T_hot_out)
        Q_dot_c = C_c * (T_cold_out - T_cold_in)
        residual = abs(Q_dot_h - Q_dot_c)

        return HeatExchangerState(
            T_hot_in=T_hot_in,
            T_hot_out=T_hot_out,
            T_cold_in=T_cold_in,
            T_cold_out=T_cold_out,
            m_dot_hot=m_dot_hot,
            m_dot_cold=m_dot_cold,
            q_hx=q_hx,
            epsilon=epsilon,
            NTU=NTU,
            energy_residual=residual,
        )


@dataclass
class HeaterActuator:
    """Heating element actuator with first-order thermal lag and dry-run safety trip."""
    Q_max: float = 15000.0         # Maximum heater power [W] (15 kW)
    tau_heater: float = 2.0        # Thermal time constant [s]
    current_power: float = 0.0     # Current actual thermal output [W]

    def step(self, cmd_percent: float, dt: float, liquid_height: float, h_min: float = 0.005) -> float:
        """Advance heater power by dt seconds with dry-run interlock."""
        # Dry-run protection: clamp target power to 0 if liquid level is below safety minimum
        if liquid_height < h_min:
            target_power = 0.0
        else:
            pct = max(0.0, min(100.0, cmd_percent))
            target_power = (pct / 100.0) * self.Q_max

        if self.tau_heater > 0.0 and dt > 0.0:
            alpha = 1.0 - math.exp(-dt / self.tau_heater)
            self.current_power += (target_power - self.current_power) * alpha
        else:
            self.current_power = target_power

        self.current_power = max(0.0, min(self.Q_max, self.current_power))
        return self.current_power


@dataclass
class RTDSensorModel:
    """RTD Pt100 temperature sensor with thermowell thermal lag, noise, and Namur NE43 conversion."""
    name: str = "RTD1"
    tau_sensor: float = 2.0        # Thermowell lag time constant [s]
    sigma_noise: float = 0.05      # Gaussian noise std dev [°C]
    t_min: float = 0.0             # Calibrated min span [°C]
    t_max: float = 150.0           # Calibrated max span [°C]
    seed: int = 42

    current_measured_temp: float = 20.0
    current_ma: float = 4.0
    current_raw_counts: int = 0
    burnout_fault: bool = False
    short_fault: bool = False

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    def step(self, fluid_temp: float, dt: float) -> Tuple[float, float, int, QualityCode, int]:
        """Advance sensor lag and compute mA and ADC counts.

        Returns (measured_temp, mA, raw_counts, QualityCode, 16_bit_quality_word).
        """
        if self.burnout_fault:
            self.current_ma = 2.5
            self.current_raw_counts = -3000
            qw = encode_quality_word(
                QualityCode.BAD,
                substatus=OPCQualityFlag.SENSOR_FAILURE,
                extended_flags=OPCQualityFlag.BURNOUT | OPCQualityFlag.UNDERFLOW,
            )
            return self.current_measured_temp, self.current_ma, self.current_raw_counts, QualityCode.BAD, qw

        if self.short_fault:
            self.current_ma = 22.5
            self.current_raw_counts = 35000
            qw = encode_quality_word(
                QualityCode.BAD,
                substatus=OPCQualityFlag.SENSOR_FAILURE,
                extended_flags=OPCQualityFlag.SHORT_CIRCUIT | OPCQualityFlag.OVERFLOW,
            )
            return self.current_measured_temp, self.current_ma, self.current_raw_counts, QualityCode.BAD, qw

        # First-order thermowell lag
        if self.tau_sensor > 0.0 and dt > 0.0:
            alpha = 1.0 - math.exp(-dt / self.tau_sensor)
            self.current_measured_temp += (fluid_temp - self.current_measured_temp) * alpha
        else:
            self.current_measured_temp = fluid_temp

        # Add zero-mean Gaussian thermal noise
        noise = self._rng.gauss(0.0, self.sigma_noise) if self.sigma_noise > 0.0 else 0.0
        noisy_t = self.current_measured_temp + noise

        # 4-20mA current conversion
        span_t = self.t_max - self.t_min
        frac = (noisy_t - self.t_min) / span_t if span_t > 0 else 0.0
        self.current_ma = 4.0 + frac * 16.0

        # 15-bit ADC counts (0..32000 for 4..20mA)
        self.current_raw_counts = int(round(frac * 32000.0))

        # Namur NE43 validation
        namur_res = NamurNE43Validator.validate_current(self.current_ma)
        return noisy_t, self.current_ma, self.current_raw_counts, namur_res.quality_code, namur_res.quality_word


@dataclass
class ThermalConfig:
    """Physical configuration for Liquid Tank Thermal Model."""
    tank_area: float = 1.5         # Tank cross-sectional area [m^2]
    liquid_density: float = 1000.0 # Fluid density rho [kg / m^3]
    cp_fluid: float = 4184.0       # Fluid specific heat capacity [J / (kg * K)]
    U_ambient: float = 15.0        # Ambient overall heat transfer coeff [W / (m^2 * K)]
    A_ambient: float = 6.0         # Ambient heat transfer surface area [m^2]
    T_ambient: float = 20.0        # Ambient environmental temperature [°C]
    h_min: float = 0.001           # Singularity prevention clamp height [m] (1 mm)
    T_min: float = 0.0             # Minimum physical temperature [°C]
    T_max: float = 100.0           # Maximum physical temperature [°C]
    T_initial: float = 25.0        # Initial fluid bulk temperature [°C]


class TankThermalPlantModel:
    """Non-linear lumped-parameter energy balance ODE plant model.

    Governing ODE:
    d(m * Cp * T) / dt = m_dot_in * Cp * T_in - m_dot_out * Cp * T + Q_heat - U * A * (T - T_amb)
    Which reduces by mass balance cancellation to:
    dT/dt = (m_dot_in * Cp * (T_in - T) + Q_heat - U * A * (T - T_amb)) / (rho * A_tank * h_eff * Cp)
    """

    def __init__(self, config: Optional[ThermalConfig] = None) -> None:
        self.config = config or ThermalConfig()
        self.temperature: float = self.config.T_initial
        self.heater = HeaterActuator()
        self.rtd1 = RTDSensorModel(name="RTD1", tau_sensor=2.0, sigma_noise=0.05, seed=101)
        self.rtd2 = RTDSensorModel(name="RTD2", tau_sensor=2.5, sigma_noise=0.05, seed=202)
        self.heat_exchanger = CounterFlowHeatExchanger()

    def step(
        self,
        dt: float,
        liquid_height: float,
        inflow_rate_lps: float,
        T_inflow: float,
        heater_cmd_pct: float,
    ) -> Dict[str, Any]:
        """Advance thermal model by dt seconds.

        inflow_rate_lps: Inflow in Liters per second (1 L/s = 1 kg/s for water).
        """
        # Mass flow rate [kg / s]
        m_dot_in = max(0.0, inflow_rate_lps) * (self.config.liquid_density / 1000.0)

        # Advance heater actuator
        q_heat = self.heater.step(
            cmd_percent=heater_cmd_pct,
            dt=dt,
            liquid_height=liquid_height,
            h_min=self.config.h_min * 5.0,  # 5mm cutoff for heater immersion
        )

        # Ambient heat dissipation: Q_loss = U * A * (T - T_amb)
        q_loss = self.config.U_ambient * self.config.A_ambient * (self.temperature - self.config.T_ambient)

        # Inflow enthalpy exchange: Q_inflow = m_dot_in * Cp * (T_in - T)
        cp = self.config.cp_fluid
        q_inflow = m_dot_in * cp * (T_inflow - self.temperature)

        # Effective liquid mass with singularity guard
        h_eff = max(self.config.h_min, liquid_height)
        m_eff = self.config.liquid_density * self.config.tank_area * h_eff
        thermal_capacitance = m_eff * cp

        # Net thermal power and temperature derivative
        q_net = q_inflow + q_heat - q_loss
        dT_dt = q_net / thermal_capacitance if thermal_capacitance > 0 else 0.0

        # Advance bulk liquid temperature
        self.temperature += dT_dt * dt
        self.temperature = max(self.config.T_min, min(self.config.T_max, self.temperature))

        # Sensor measurements
        t1, ma1, raw1, qc1, qw1 = self.rtd1.step(self.temperature, dt)
        t2, ma2, raw2, qc2, qw2 = self.rtd2.step(self.temperature, dt)

        # Dual-sensor divergence check and voted control temperature
        divergence = abs(t1 - t2)
        divergence_fault = divergence > 5.0  # > 5.0 °C threshold

        # Primary or failover selection
        if qc1 == QualityCode.GOOD:
            t_ctrl = t1
            backup_active = False
            primary_qw = qw1
        elif qc2 == QualityCode.GOOD:
            t_ctrl = t2
            backup_active = True
            primary_qw = qw2
        else:
            t_ctrl = (t1 + t2) / 2.0
            backup_active = True
            primary_qw = encode_quality_word(QualityCode.BAD, substatus=OPCQualityFlag.SENSOR_FAILURE)

        return {
            "temperature": self.temperature,
            "dT_dt": dT_dt,
            "q_heat": q_heat,
            "q_loss": q_loss,
            "q_inflow": q_inflow,
            "m_eff": m_eff,
            "t_rtd1": t1,
            "ma_rtd1": ma1,
            "raw_rtd1": raw1,
            "quality_rtd1": qc1.value,
            "t_rtd2": t2,
            "ma_rtd2": ma2,
            "raw_rtd2": raw2,
            "quality_rtd2": qc2.value,
            "divergence": divergence,
            "divergence_fault": divergence_fault,
            "t_ctrl": t_ctrl,
            "backup_active": backup_active,
            "quality_word": primary_qw,
        }


class ThermalModelLogicUnit(ILogicUnit):
    """Horner OCS SimulationEngine logic unit synchronizing thermal physics with OCS registers."""

    def __init__(
        self,
        plant_model: Optional[TankThermalPlantModel] = None,
        setpoint_c: float = 65.0,
        priority: int = 210,
    ) -> None:
        self.plant = plant_model or TankThermalPlantModel()
        self.setpoint_c = setpoint_c
        self._name = "ThermalModelLogicUnit"
        self._priority = priority
        self._enabled = True

    @property
    def name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def reset(self) -> None:
        self.plant = TankThermalPlantModel()

    def execute(self, ctx: Any) -> None:
        """ScanContext execution adapter."""
        dt = ctx.dt_ms / 1000.0 if hasattr(ctx, "dt_ms") else 0.01
        # Retrieve level
        raw_level = ctx.get_register("%AI1") if hasattr(ctx, "get_register") else 16000
        liquid_height = (raw_level / 32000.0) * 2.0 if raw_level > 0 else 1.0

        raw_heater = ctx.get_register("%AQ2") if hasattr(ctx, "get_register") else 0
        heater_cmd_pct = (raw_heater / 32000.0) * 100.0 if raw_heater > 0 else 0.0

        step_res = self.plant.step(
            dt=dt,
            liquid_height=liquid_height,
            inflow_rate_lps=0.5,
            T_inflow=20.0,
            heater_cmd_pct=heater_cmd_pct,
        )

        if hasattr(ctx, "set_register"):
            ctx.set_register("%AI3", step_res["raw_rtd1"])
            ctx.set_register("%AI4", step_res["raw_rtd2"])
            ctx.set_register("%R152", int(round(step_res["t_rtd1"] * 10.0)))
            ctx.set_register("%R153", int(round(step_res["t_rtd2"] * 10.0)))
            ctx.set_register("%R154", int(round(step_res["t_ctrl"] * 10.0)))
            ctx.set_register("%R155", int(round(heater_cmd_pct * 10.0)))

    def execute_logic(self, reg_table: RegisterTable, dt: float) -> None:
        """Phase 2 SOLVE_LOGIC execution."""
        # Read liquid height and inflow from tank registers (or use defaults)
        raw_level = reg_table.read_word("%AI1")
        liquid_height = (raw_level / 32000.0) * 2.0 if raw_level > 0 else 1.0  # 0..2.0m span

        # Read heating demand from %AQ2 (0..32000 counts -> 0..100.0%)
        raw_heater = reg_table.read_word("%AQ2")
        heater_cmd_pct = (raw_heater / 32000.0) * 100.0 if raw_heater > 0 else 0.0

        # Read setpoint from %R151 (tenths of °C)
        sp_reg = reg_table.read_word("%R151")
        if sp_reg > 0:
            self.setpoint_c = sp_reg / 10.0
        else:
            reg_table.write_word("%R151", int(round(self.setpoint_c * 10.0)), privilege=PrivilegeMode.SYSTEM)

        # Advance thermal model
        step_res = self.plant.step(
            dt=dt,
            liquid_height=liquid_height,
            inflow_rate_lps=0.5,
            T_inflow=20.0,
            heater_cmd_pct=heater_cmd_pct,
        )

        # Write RTD sensor counts to %AI3 and %AI4
        reg_table.write_word("%AI3", step_res["raw_rtd1"], privilege=PrivilegeMode.SYSTEM)
        reg_table.write_word("%AI4", step_res["raw_rtd2"], privilege=PrivilegeMode.SYSTEM)

        # Write temperatures (tenths of °C) to %R152, %R153, %R154
        reg_table.write_word("%R152", int(round(step_res["t_rtd1"] * 10.0)), privilege=PrivilegeMode.SYSTEM)
        reg_table.write_word("%R153", int(round(step_res["t_rtd2"] * 10.0)), privilege=PrivilegeMode.SYSTEM)
        reg_table.write_word("%R154", int(round(step_res["t_ctrl"] * 10.0)), privilege=PrivilegeMode.SYSTEM)

        # Write actual heater demand % to %R155 (tenths of %)
        reg_table.write_word("%R155", int(round(heater_cmd_pct * 10.0)), privilege=PrivilegeMode.SYSTEM)

        # Temperature limits
        t_high = 80.0
        t_hihi = 95.0
        t_low = 10.0

        is_high = step_res["t_ctrl"] > t_high
        is_hihi = step_res["t_ctrl"] > t_hihi
        is_low = step_res["t_ctrl"] < t_low
        is_dry_run = liquid_height < 0.005 and heater_cmd_pct > 0.0

        # Update discrete alarm coils %M5..%M8
        reg_table.write_bit("%M5", is_high, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_bit("%M6", is_low, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_bit("%M7", is_hihi, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_bit("%M8", is_dry_run, privilege=PrivilegeMode.SYSTEM)

        # Build 16-bit status word %R150
        status_word = 0
        if heater_cmd_pct > 0.0:
            status_word |= (1 << 0)  # %R150.1: HEATER_RUNNING
        if step_res["quality_rtd1"] == QualityCode.GOOD.value:
            status_word |= (1 << 1)  # %R150.2: RTD1_HEALTHY
        if self.plant.rtd1.burnout_fault:
            status_word |= (1 << 2)  # %R150.3: RTD1_BURNOUT
        if self.plant.rtd1.short_fault:
            status_word |= (1 << 3)  # %R150.4: RTD1_SHORT
        if step_res["quality_rtd2"] == QualityCode.GOOD.value:
            status_word |= (1 << 4)  # %R150.5: RTD2_HEALTHY
        if self.plant.rtd2.burnout_fault:
            status_word |= (1 << 5)  # %R150.6: RTD2_BURNOUT
        if self.plant.rtd2.short_fault:
            status_word |= (1 << 6)  # %R150.7: RTD2_SHORT
        if step_res["divergence_fault"]:
            status_word |= (1 << 7)  # %R150.8: SENSOR_DIVERGENCE
        if is_high:
            status_word |= (1 << 8)  # %R150.9: TEMP_HIGH
        if is_hihi:
            status_word |= (1 << 9)  # %R150.10: TEMP_HIHI_TRIP
        if is_low:
            status_word |= (1 << 10) # %R150.11: TEMP_LOW
        if step_res["backup_active"]:
            status_word |= (1 << 13) # %R150.14: BACKUP_SENSOR_ACTIVE
        if is_hihi or step_res["divergence_fault"] or self.plant.rtd1.burnout_fault:
            status_word |= (1 << 15) # %R150.16: COMMON_FAULT_SUMMARY

        reg_table.write_word("%R150", status_word, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_word("%R159", step_res["quality_word"] & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
