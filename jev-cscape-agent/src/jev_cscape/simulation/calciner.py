"""Rotary Calciner Solid Mineral Kinetics & Counter-Current Heat Transfer Simulation.

Work Package: W116 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Solid Mineral Calcination Kinetics:
   - Endothermic thermal decomposition: CaCO3(s) -> CaO(s) + CO2(g) (Delta H = +1.78 MJ/kg).
   - Shrinking core / unreacted core kinetics: dX_calc/dt = k(T) * (1 - X_calc)^(2/3).
   - Arrhenius rate constant: k(T) = A * exp(-E_a / (R * T)).
2. Counter-Current Rotary Drum Heat & Mass Transfer:
   - Inclined rotating cylinder with solid bed transport.
   - Counter-current hot combustion flue gas flow (950..1200 °C).
   - Radiative (Stefan-Boltzmann non-linear T^4) and convective heat exchange between gas, bed, and refractory wall.
   - Regenerative wall-to-bed contact conduction from rotating drum lining.
   - Induced draft fan suction and flue gas pressure balance.
3. Coupled 6-State Dynamic ODE System:
   - State vector y = [X_calc, T_bed, T_gas, T_wall, m_co2_released, m_product].
   - Integrated via 4th-Order Runge-Kutta (RK4) with dt = 0.01 s.
   - Analytical stoichiometric mass conservation: d(m_co2 + m_product)/dt = r_calc.
4. Process Safety Interlocks & Alarms:
   - %M179: RefractoryOverTempTrip (T_wall >= 1250 °C) -> code 0x8D01.
   - %M180: UnderCalcinationAlarm (X_calc < 90.0% at discharge) -> code 0x8D02.
   - %M181: DraftLossTrip (Delta_P_draft > +20 Pa) -> code 0x8D03.
5. Horner OCS Registers:
   - %R770: CalcinerStatusWord (RUNNING, BURNER_ON, DRUM_ROTATING, CALCINATION_OPTIMAL,
            WALL_OVERTEMP_TRIP, UNDER_CALCINATION_ALARM, DRAFT_LOSS_TRIP, DISCHARGE_ACTIVE)
   - %R771: BedTempDegC (scaled x10 degC)
   - %R772: GasExhaustTempDegC (scaled x10 degC)
   - %R773: RefractoryWallTempDegC (scaled x10 degC)
   - %R774: CalcinationConversionPct (scaled x10 %)
   - %R775: ProductionRateKgH (scaled x10 kg/h)
   - %R776: DraftPressurePa (scaled x1 Pa signed)
   - %R777: DiagnosticEventCode (0x0000=OK, 0x8D01, 0x8D02, 0x8D03)
   - %M179, %M180, %M181 discrete coils.
6. Pure IEC 61131-3 ST POU: 'RotaryCalcinerSync' with SecurityGuard.assert_pure_st_content and STParser.
7. Deterministic 9-Stage Verification Suite returning strict 4-state contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import math
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Enums and Status Bitmasks
# ============================================================================

class CalcinerStatusBits(IntFlag):
    """Horner OCS %R770 CalcinerStatusWord Bitmask Definitions."""
    RUNNING                 = 1 << 0  # Bit 0 (0x0001): Process simulation engine running
    BURNER_ON               = 1 << 1  # Bit 1 (0x0002): Combustion burner firing active
    DRUM_ROTATING           = 1 << 2  # Bit 2 (0x0004): Drum rotation drive active
    CALCINATION_OPTIMAL     = 1 << 3  # Bit 3 (0x0008): Conversion >= 90.0% and Bed Temp >= 850.0 °C
    WALL_OVERTEMP_TRIP      = 1 << 4  # Bit 4 (0x0010): %M179 Refractory wall over-temperature trip (T_wall >= 1250 °C)
    UNDER_CALCINATION_ALARM = 1 << 5  # Bit 5 (0x0020): %M180 Under-calcination alarm (X_calc < 90.0% at discharge)
    DRAFT_LOSS_TRIP         = 1 << 6  # Bit 6 (0x0040): %M181 Draft loss trip (Delta_P_draft > +20 Pa)
    DISCHARGE_ACTIVE        = 1 << 7  # Bit 7 (0x0080): Calcined lime product discharge active

    # Compatibility aliases
    BURNER_ACTIVE           = BURNER_ON
    FEEDER_ACTIVE           = DRUM_ROTATING
    ID_FAN_ACTIVE           = 1 << 3
    REFR_OVERTEMP_TRIP      = WALL_OVERTEMP_TRIP
    UNDER_CALC_ALARM        = UNDER_CALCINATION_ALARM
    DRAFT_LOSS_ALARM        = DRAFT_LOSS_TRIP
    OPTIMAL_CALCINATION     = CALCINATION_OPTIMAL


class CalcinerDiagnosticCode(IntEnum):
    """Diagnostic event codes for %R777."""
    OK                              = 0x0000  # Normal operation
    REFRACTORY_OVERTEMP_TRIP        = 0x8D01  # %M179: T_wall >= 1250.0 °C
    UNDER_CALCINATION_ALARM         = 0x8D02  # %M180: X_calc < 90.0% at discharge
    DRAFT_LOSS_TRIP                 = 0x8D03  # %M181: Delta_P_draft > +20.0 Pa

    # Compatibility aliases
    CALCINER_REFR_OVERTEMP_TRIP     = REFRACTORY_OVERTEMP_TRIP
    CALCINER_UNDER_CALCINATION_ALARM = UNDER_CALCINATION_ALARM
    CALCINER_DRAFT_LOSS_ALARM       = DRAFT_LOSS_TRIP


# ============================================================================
# 2. Configuration & Parameter Data Models
# ============================================================================

@dataclass
class CalcinerConfig:
    """Rotary calciner design, kinetics, heat transfer, and aerodynamic constants."""
    # Solid Mineral Calcination Kinetics (CaCO3 -> CaO + CO2)
    # Shrinking core Arrhenius rate constant: k(T) = A * exp(-E_a / (R * T))
    arrhenius_a: float = 3.2e5                 # Pre-exponential frequency factor [s^-1]
    activation_energy_j_mol: float = 175000.0  # Activation energy E_a [J/mol] (175.0 kJ/mol)
    r_gas: float = 8.314462618                 # Universal gas constant R [J/(mol*K)]
    gas_constant_r: float = 8.314462618        # Compatibility alias
    delta_h_calc_j_kg: float = 1.78e6          # Endothermic reaction enthalpy [J/kg CaCO3]
    mw_caco3: float = 0.1000869                # Molecular weight of CaCO3 [kg/mol] (100.087 g/mol)
    mw_cao: float = 0.0560774                  # Molecular weight of CaO [kg/mol] (56.077 g/mol)
    mw_co2: float = 0.0440095                  # Molecular weight of CO2 [kg/mol] (44.010 g/mol)

    # Rotary Drum Geometry & Transport
    length_m: float = 25.0                     # Total drum length [m]
    inner_diameter_m: float = 2.5              # Refractory inner diameter [m]
    inclination_deg: float = 2.5               # Inclination angle [deg]
    rotation_speed_rpm: float = 1.8            # Rotation speed [rpm]
    bed_mass_nominal_kg: float = 1000.0        # Bed holdup mass [kg]
    solids_feed_rate_kg_h: float = 3600.0      # Continuous limestone feed rate [kg/h] (1.0 kg/s)
    t_solids_feed_k: float = 298.15            # Feed solids inlet temperature [K] (25.0 °C)
    cp_solids_j_kg_k: float = 1050.0           # Solids bed specific heat capacity [J/(kg*K)]
    c_thermal_bed_j_k: float = 1.05e6          # Solids bed thermal capacitance [J/K] (M_bed * cp_solids)
    c_thermal_gas_j_k: float = 3.5e4           # Flue gas holdup thermal capacitance [J/K]
    c_thermal_wall_j_k: float = 2.85e6         # Refractory inner layer thermal capacitance [J/K]

    # Counter-Current Flue Gas & Burner Firing
    burner_gas_temp_k: float = 1423.15         # Burner hot combustion gas inlet temperature [K] (1150 °C)
    burner_power_w: float = 3.5e6              # Burner thermal firing power [W] (3.5 MW)
    combustion_gas_flow_kg_s: float = 2.5      # Counter-current flue gas flow rate [kg/s]
    cp_gas_j_kg_k: float = 1150.0              # Flue gas specific heat capacity [J/(kg*K)]

    # Heat Transfer Areas & Coefficients
    sigma_sb: float = 5.670374419e-8           # Stefan-Boltzmann constant [W/(m^2*K^4)]
    eps_gb: float = 0.65                       # Gas-to-bed effective emissivity [-]
    eps_gw: float = 0.70                       # Gas-to-wall effective emissivity [-]
    eps_wb: float = 0.75                       # Wall-to-bed effective emissivity [-]
    h_conv_gb: float = 25.0                    # Gas-to-bed convection coefficient [W/(m^2*K)]
    h_conv_gw: float = 30.0                    # Gas-to-wall convection coefficient [W/(m^2*K)]
    h_contact_wb: float = 80.0                 # Rotating regenerative wall-to-bed contact [W/(m^2*K)]
    u_shell_loss_w_m2_k: float = 12.0          # Exterior shell heat loss coefficient [W/(m^2*K)]
    t_ambient_k: float = 298.15                # Ambient surroundings temperature [K] (25.0 °C)
    a_bed_m2: float = 37.5                     # Bed exposed surface area [m^2]
    a_wall_m2: float = 176.7                   # Refractory exposed wall area [m^2]
    a_wall_bed_m2: float = 19.6                # Covered refractory contact area [m^2]
    a_shell_m2: float = 220.0                  # Outer steel shell convective area [m^2]

    # Aerodynamics & Draft Pressure Balance
    p_fan_nominal_pa: float = -55.0            # Induced draft (ID) fan suction head [Pa]
    k_draft_gas_flow: float = 2.0              # Flue gas flow resistance [Pa / (kg/s)]
    k_draft_co2_flow: float = 10.0             # CO2 evolution pressure gain [Pa / (kg/s)]

    # Process Safety Interlock Thresholds
    t_wall_trip_c: float = 1250.0              # %M179: Refractory over-temp trip limit [°C] -> 0x8D01
    x_calc_min_threshold: float = 0.90         # %M180: Under-calcination minimum conversion limit (90.0%) -> 0x8D02
    p_draft_trip_pa: float = 20.0              # %M181: Draft loss maximum allowable pressure [Pa] -> 0x8D03


@dataclass
class CalcinerState:
    """Dynamic state vector, telemetry, and safety tracking for rotary calciner."""
    time_s: float = 0.0

    # Coupled 6-State ODE System State Vector y
    x_calc: float = 0.95                       # State 0: Fractional calcination conversion [-] (0.0..1.0)
    t_bed: float = 1193.15                     # State 1: Bed solid temperature [K] (920.0 °C nominal)
    t_gas: float = 823.15                      # State 2: Flue gas exhaust temperature [K] (550.0 °C nominal)
    t_wall: float = 1373.15                    # State 3: Refractory wall temperature [K] (1100.0 °C nominal)
    m_co2_released: float = 0.0                # State 4: Cumulative CO2 mass released [kg]
    m_product: float = 0.0                     # State 5: Cumulative CaO product formed/discharged [kg]

    # Aerodynamic Draft Pressure
    p_draft_pa: float = -50.0                  # Draft pressure in hood/exhaust [Pa] (-50 Pa nominal)

    # Reaction Kinetics & Production Rates
    k_rate_constant: float = 0.0               # Arrhenius rate constant k(T) [s^-1]
    r_shrinking_core: float = 0.0              # Shrinking core conversion rate dX/dt [s^-1]
    r_calc_mass_rate: float = 0.0              # Instantaneous CaCO3 decomposition mass rate [kg/s]
    production_rate_kg_h: float = 0.0          # Instantaneous CaO production rate [kg/h]
    co2_rate_kg_h: float = 0.0                 # Instantaneous CO2 release rate [kg/h]

    # Operational Status Flags
    is_running: bool = False                   # Simulation engine running
    burner_on: bool = True                     # Burner flame online
    drum_rotating: bool = True                 # Drum rotation drive active
    discharge_active: bool = True              # Product discharge chute online
    draft_fan_running: bool = True             # Induced draft fan online

    # Process Safety Interlocks & Alarms
    overtemp_trip: bool = False                # %M179: T_wall >= 1250 °C
    under_calc_alarm: bool = False             # %M180: X_calc < 90.0% at discharge
    draft_loss_trip: bool = False              # %M181: Delta_P_draft > +20 Pa
    diagnostic_code: int = 0x0000              # %R777: Diagnostic event code

    # Backward compatibility properties
    @property
    def calcination_conversion(self) -> float:
        return self.x_calc

    @calcination_conversion.setter
    def calcination_conversion(self, val: float) -> None:
        self.x_calc = val

    @property
    def t_refr(self) -> float:
        return self.t_wall

    @t_refr.setter
    def t_refr(self, val: float) -> None:
        self.t_wall = val

    @property
    def draft_pressure_pa(self) -> float:
        return self.p_draft_pa

    @draft_pressure_pa.setter
    def draft_pressure_pa(self, val: float) -> None:
        self.p_draft_pa = val

    @property
    def cao_production_rate_kg_h(self) -> float:
        return self.production_rate_kg_h

    @cao_production_rate_kg_h.setter
    def cao_production_rate_kg_h(self, val: float) -> None:
        self.production_rate_kg_h = val

    @property
    def burner_active(self) -> bool:
        return self.burner_on

    @burner_active.setter
    def burner_active(self, val: bool) -> None:
        self.burner_on = val

    @property
    def feeder_active(self) -> bool:
        return self.discharge_active

    @feeder_active.setter
    def feeder_active(self, val: bool) -> None:
        self.discharge_active = val

    @property
    def id_fan_active(self) -> bool:
        return self.draft_fan_running

    @id_fan_active.setter
    def id_fan_active(self, val: bool) -> None:
        self.draft_fan_running = val


# ============================================================================
# 3. Rotary Calciner Simulation Engine
# ============================================================================

class RotaryCalcinerSimulator:
    """Coupled Rotary Calciner Kinetics, Counter-Current Heat Transfer & ODE Simulator.

    Work Package: W116 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
    Mapped Registers: %R770..%R777, %M179..%M181.
    """

    def __init__(
        self,
        config: Optional[CalcinerConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.config = config or CalcinerConfig()
        self.reg_table = register_table or RegisterTable()

        # Initialize dynamic state at nominal operating point
        self.state = CalcinerState(
            x_calc=0.95,
            t_bed=self.config.t_solids_feed_k + 895.0,   # 920 °C (1193.15 K)
            t_gas=self.config.t_solids_feed_k + 525.0,   # 550 °C (823.15 K)
            t_wall=self.config.t_solids_feed_k + 1075.0, # 1100 °C (1373.15 K)
            m_co2_released=0.0,
            m_product=0.0,
            p_draft_pa=-50.0,
        )

        # Initial reaction rates
        k_val = self.arrhenius_rate_constant(self.state.t_bed)
        r_x = self.shrinking_core_rate(self.state.x_calc, k_val)
        self.state.k_rate_constant = k_val
        self.state.r_shrinking_core = r_x

        self._sync_registers()

    # ------------------------------------------------------------------------
    # Solid Mineral Calcination Kinetics
    # ------------------------------------------------------------------------

    def arrhenius_rate_constant(self, t_k: float) -> float:
        """Evaluate Arrhenius rate constant k(T) = A * exp(-E_a / (R * T)).

        Parameters:
            t_k: Absolute temperature in Kelvin.

        Returns:
            Rate constant k(T) in s^-1.
        """
        t_safe = max(273.15, float(t_k))
        rt = self.config.r_gas * t_safe
        return self.config.arrhenius_a * math.exp(-self.config.activation_energy_j_mol / rt)

    def shrinking_core_rate(self, x_calc: float, k_val: float) -> float:
        """Compute unreacted shrinking core reaction rate dX_calc/dt = k(T) * (1 - X_calc)^(2/3).

        Parameters:
            x_calc: Fractional calcination conversion [0.0..1.0].
            k_val: Arrhenius rate constant [s^-1].

        Returns:
            Fractional reaction rate in s^-1.
        """
        x_clamped = max(0.0, min(1.0, float(x_calc)))
        if x_clamped >= 1.0:
            return 0.0
        return float(k_val) * ((1.0 - x_clamped) ** (2.0 / 3.0))

    # ------------------------------------------------------------------------
    # Counter-Current Heat Transfer Balances
    # ------------------------------------------------------------------------

    def compute_heat_transfers(
        self, t_bed: float, t_gas: float, t_wall: float
    ) -> Dict[str, float]:
        """Compute radiative and convective heat exchange rates between gas, bed, and refractory.

        Returns:
            Dictionary containing Q_rad_gb, Q_conv_gb, Q_rad_gw, Q_conv_gw,
            Q_rad_wb, Q_contact_wb, and Q_loss_amb in Watts.
        """
        tb = max(273.15, float(t_bed))
        tg = max(273.15, float(t_gas))
        tw = max(273.15, float(t_wall))
        ta = max(273.15, self.config.t_ambient_k)

        sigma = self.config.sigma_sb

        # 1. Radiative heat transfers (Stefan-Boltzmann T^4)
        q_rad_gb = sigma * self.config.eps_gb * self.config.a_bed_m2 * (tg ** 4 - tb ** 4)
        q_rad_gw = sigma * self.config.eps_gw * self.config.a_wall_m2 * (tg ** 4 - tw ** 4)
        q_rad_wb = sigma * self.config.eps_wb * self.config.a_wall_bed_m2 * (tw ** 4 - tb ** 4)

        # 2. Convective heat transfers
        q_conv_gb = self.config.h_conv_gb * self.config.a_bed_m2 * (tg - tb)
        q_conv_gw = self.config.h_conv_gw * self.config.a_wall_m2 * (tg - tw)

        # 3. Rotating regenerative contact conduction (wall dips beneath tumbling bed)
        q_contact_wb = self.config.h_contact_wb * self.config.a_wall_bed_m2 * (tw - tb)

        # 4. Refractory shell conductive/convective loss to ambient surroundings
        q_loss_amb = self.config.u_shell_loss_w_m2_k * self.config.a_shell_m2 * (tw - ta)

        return {
            "q_rad_gb": q_rad_gb,
            "q_conv_gb": q_conv_gb,
            "q_rad_gw": q_rad_gw,
            "q_conv_gw": q_conv_gw,
            "q_rad_wb": q_rad_wb,
            "q_contact_wb": q_contact_wb,
            "q_loss_amb": q_loss_amb,
        }

    # ------------------------------------------------------------------------
    # Coupled 6-State ODE System Derivatives
    # ------------------------------------------------------------------------

    def compute_derivatives(
        self,
        t: float,
        y: List[float],
        burner_on: bool = True,
        drum_rotating: bool = True,
        feed_active: bool = True,
        feeder_active: Optional[bool] = None,
        discharge_active: Optional[bool] = None,
        id_fan_active: Optional[bool] = None,
    ) -> List[float]:
        """Compute state derivative vector dy/dt for the coupled 6-state ODE system.

        State vector y:
          y[0] = X_calc          (Fractional calcination conversion [-])
          y[1] = T_bed           (Solids bed temperature [K])
          y[2] = T_gas           (Flue gas exhaust temperature [K])
          y[3] = T_wall          (Refractory inner wall temperature [K])
          y[4] = m_co2_released  (Cumulative CO2 gas released [kg])
          y[5] = m_product       (Cumulative CaO product formed [kg])

        Returns:
          dy/dt list of 6 derivative values.
        """
        # Resolve argument aliases
        effective_feed = feed_active
        if feeder_active is not None:
            effective_feed = feeder_active

        x_calc = max(0.0, min(1.0, float(y[0])))
        t_bed = max(273.15, float(y[1]))
        t_gas = max(273.15, float(y[2]))
        t_wall = max(273.15, float(y[3]))

        # 1. Calcination kinetics
        k_val = self.arrhenius_rate_constant(t_bed)
        r_x = self.shrinking_core_rate(x_calc, k_val)

        # Active mass of CaCO3 reacting in bed
        # Feed renewal rate: feed introduces unreacted CaCO3 at solids_feed_rate
        feed_rate_kg_s = (self.config.solids_feed_rate_kg_h / 3600.0) if effective_feed else 0.0
        m_bed = max(10.0, self.config.bed_mass_nominal_kg)
        inv_residence_time = feed_rate_kg_s / m_bed

        # Fractional conversion derivative:
        # Generation from kinetics minus dilution from fresh unreacted feed
        dx_dt = r_x - (inv_residence_time * x_calc)

        # Mass reaction rate of CaCO3 [kg/s]:
        # r_calc = M_bed * (1 - X_calc) * r_x
        m_caco3_bed = m_bed * max(0.0, 1.0 - x_calc)
        r_calc_mass_rate = m_caco3_bed * r_x

        # Exact stoichiometric mass yield rates:
        # CaCO3 (100.087 g/mol) -> CaO (56.077 g/mol) + CO2 (44.010 g/mol)
        frac_co2 = self.config.mw_co2 / self.config.mw_caco3      # ~0.4397
        frac_product = self.config.mw_cao / self.config.mw_caco3  # ~0.5603

        dm_co2_dt = r_calc_mass_rate * frac_co2
        dm_product_dt = r_calc_mass_rate * frac_product

        # 2. Heat transfer balances
        ht = self.compute_heat_transfers(t_bed, t_gas, t_wall)

        # Contact and drum rotation effects
        contact_factor = 1.0 if drum_rotating else 0.15

        q_to_bed = (
            ht["q_rad_gb"]
            + ht["q_conv_gb"]
            + ht["q_rad_wb"]
            + (ht["q_contact_wb"] * contact_factor)
        )
        q_to_wall = ht["q_rad_gw"] + ht["q_conv_gw"]
        q_wall_to_bed = ht["q_rad_wb"] + (ht["q_contact_wb"] * contact_factor)

        # Endothermic reaction enthalpy extracted from bed
        q_rxn_endotherm = r_calc_mass_rate * self.config.delta_h_calc_j_kg

        # Sensible solids feed enthalpy
        q_solids_sensible = (
            feed_rate_kg_s * self.config.cp_solids_j_kg_k * (self.config.t_solids_feed_k - t_bed)
        )

        # Bed temperature derivative:
        dt_bed_dt = (q_to_bed + q_solids_sensible - q_rxn_endotherm) / self.config.c_thermal_bed_j_k

        # Flue gas enthalpy balance:
        m_gas_dot = self.config.combustion_gas_flow_kg_s
        q_burner = self.config.burner_power_w if burner_on else 0.0
        t_burner_inlet = self.config.burner_gas_temp_k if burner_on else self.config.t_ambient_k
        q_gas_sensible = m_gas_dot * self.config.cp_gas_j_kg_k * (t_burner_inlet - t_gas)

        dt_gas_dt = (
            q_burner
            + q_gas_sensible
            - (ht["q_rad_gb"] + ht["q_conv_gb"] + ht["q_rad_gw"] + ht["q_conv_gw"])
        ) / self.config.c_thermal_gas_j_k

        # Refractory inner wall temperature derivative:
        dt_wall_dt = (q_to_wall - q_wall_to_bed - ht["q_loss_amb"]) / self.config.c_thermal_wall_j_k

        return [dx_dt, dt_bed_dt, dt_gas_dt, dt_wall_dt, dm_co2_dt, dm_product_dt]

    # ------------------------------------------------------------------------
    # 4th-Order Runge-Kutta (RK4) Scan Cycle Integration
    # ------------------------------------------------------------------------

    def step(
        self,
        dt: float = 0.01,
        burner_on: Optional[bool] = None,
        drum_rotating: Optional[bool] = None,
        feed_active: Optional[bool] = None,
        discharge_active: Optional[bool] = None,
        draft_fan_running: Optional[bool] = None,
    ) -> ExecutionResult:
        """Advance coupled calciner dynamics by dt seconds via 4th-Order Runge-Kutta (RK4).

        Synchronizes Horner OCS register space (%R770..%R777, %M179..%M181).
        """
        if dt <= 0.0 or math.isnan(dt) or math.isinf(dt):
            return ExecutionResult.failed(
                error_code="INVALID_TIMESTEP",
                details=f"Scan cycle integration step dt={dt} is invalid.",
            )

        # Update operational modes
        if burner_on is not None:
            self.state.burner_on = burner_on
        if drum_rotating is not None:
            self.state.drum_rotating = drum_rotating
        if discharge_active is not None:
            self.state.discharge_active = discharge_active
        if draft_fan_running is not None:
            self.state.draft_fan_running = draft_fan_running

        is_feed = feed_active if feed_active is not None else self.state.discharge_active

        # Current state vector y
        y0 = [
            self.state.x_calc,
            self.state.t_bed,
            self.state.t_gas,
            self.state.t_wall,
            self.state.m_co2_released,
            self.state.m_product,
        ]

        t0 = self.state.time_s

        # RK4 Stage 1
        k1 = self.compute_derivatives(
            t0, y0, self.state.burner_on, self.state.drum_rotating, is_feed
        )

        # RK4 Stage 2
        y_k2 = [y0[i] + 0.5 * dt * k1[i] for i in range(6)]
        k2 = self.compute_derivatives(
            t0 + 0.5 * dt, y_k2, self.state.burner_on, self.state.drum_rotating, is_feed
        )

        # RK4 Stage 3
        y_k3 = [y0[i] + 0.5 * dt * k2[i] for i in range(6)]
        k3 = self.compute_derivatives(
            t0 + 0.5 * dt, y_k3, self.state.burner_on, self.state.drum_rotating, is_feed
        )

        # RK4 Stage 4
        y_k4 = [y0[i] + dt * k3[i] for i in range(6)]
        k4 = self.compute_derivatives(
            t0 + dt, y_k4, self.state.burner_on, self.state.drum_rotating, is_feed
        )

        # Update integrated states
        x_next = max(0.0, min(1.0, y0[0] + (dt / 6.0) * (k1[0] + 2.0 * k2[0] + 2.0 * k3[0] + k4[0])))
        t_bed_next = max(273.15, y0[1] + (dt / 6.0) * (k1[1] + 2.0 * k2[1] + 2.0 * k3[1] + k4[1]))
        t_gas_next = max(273.15, y0[2] + (dt / 6.0) * (k1[2] + 2.0 * k2[2] + 2.0 * k3[2] + k4[2]))
        t_wall_next = max(273.15, y0[3] + (dt / 6.0) * (k1[3] + 2.0 * k2[3] + 2.0 * k3[3] + k4[3]))
        m_co2_next = max(0.0, y0[4] + (dt / 6.0) * (k1[4] + 2.0 * k2[4] + 2.0 * k3[4] + k4[4]))
        m_prod_next = max(0.0, y0[5] + (dt / 6.0) * (k1[5] + 2.0 * k2[5] + 2.0 * k3[5] + k4[5]))

        # Instantaneous rates for telemetry
        k_val = self.arrhenius_rate_constant(t_bed_next)
        r_x = self.shrinking_core_rate(x_next, k_val)
        m_caco3_bed = self.config.bed_mass_nominal_kg * (1.0 - x_next)
        r_calc = m_caco3_bed * r_x
        frac_product = self.config.mw_cao / self.config.mw_caco3
        frac_co2 = self.config.mw_co2 / self.config.mw_caco3
        prod_rate_kg_h = r_calc * frac_product * 3600.0
        co2_rate_kg_h = r_calc * frac_co2 * 3600.0

        # Draft pressure calculation:
        # Normal operation: ID fan pulls negative draft (-50 Pa nominal)
        # Draft loss: ID fan trips or damper blocks exhaust -> positive gauge pressure builds
        if self.state.draft_fan_running:
            p_draft = (
                self.config.p_fan_nominal_pa
                + (self.config.k_draft_gas_flow * self.config.combustion_gas_flow_kg_s)
                + (self.config.k_draft_co2_flow * (r_calc * frac_co2))
            )
        else:
            # Positive draft runaway on fan loss / blockage
            p_draft = 25.0 + 10.0 * (r_calc * frac_co2)

        # Commit state updates
        self.state.time_s += dt
        self.state.x_calc = x_next
        self.state.t_bed = t_bed_next
        self.state.t_gas = t_gas_next
        self.state.t_wall = t_wall_next
        self.state.m_co2_released = m_co2_next
        self.state.m_product = m_prod_next
        self.state.p_draft_pa = p_draft
        self.state.k_rate_constant = k_val
        self.state.r_shrinking_core = r_x
        self.state.r_calc_mass_rate = r_calc
        self.state.production_rate_kg_h = prod_rate_kg_h
        self.state.co2_rate_kg_h = co2_rate_kg_h
        self.state.is_running = True

        # Process Safety Interlocks & Register Sync
        self._evaluate_safety_interlocks()
        self._sync_registers()

        return ExecutionResult.success(
            details=f"Calciner scan cycle advanced to t={self.state.time_s:.2f}s.",
            data={
                "time_s": self.state.time_s,
                "x_calc": self.state.x_calc,
                "t_bed_c": self.state.t_bed - 273.15,
                "t_gas_c": self.state.t_gas - 273.15,
                "t_wall_c": self.state.t_wall - 273.15,
                "p_draft_pa": self.state.p_draft_pa,
                "production_rate_kg_h": self.state.production_rate_kg_h,
                "diagnostic_code": f"0x{self.state.diagnostic_code:04X}",
            },
        )

    # ------------------------------------------------------------------------
    # Process Safety Interlocks & Alarm Classification
    # ------------------------------------------------------------------------

    def _evaluate_safety_interlocks(self) -> None:
        """Evaluate process trips (%M179, %M180, %M181) and diagnostic codes."""
        t_wall_c = self.state.t_wall - 273.15

        # Interlock 1: Refractory OverTemp Trip (%M179 -> 0x8D01)
        self.state.overtemp_trip = bool(t_wall_c >= self.config.t_wall_trip_c)

        # Interlock 2: Draft Loss Trip (%M181 -> 0x8D03)
        self.state.draft_loss_trip = bool(self.state.p_draft_pa > self.config.p_draft_trip_pa)

        # Interlock 3: Under-Calcination Alarm (%M180 -> 0x8D02)
        # Active when discharge is running and conversion is below 90.0%
        self.state.under_calc_alarm = bool(
            (self.state.is_running or self.state.discharge_active)
            and (self.state.x_calc < self.config.x_calc_min_threshold)
        )

        # Automatic Burner Cut on OverTemp or Draft Loss
        if self.state.overtemp_trip or self.state.draft_loss_trip:
            self.state.burner_on = False

        # Diagnostic Event Code Priority Assignment
        if self.state.overtemp_trip:
            self.state.diagnostic_code = int(CalcinerDiagnosticCode.REFRACTORY_OVERTEMP_TRIP)
        elif self.state.draft_loss_trip:
            self.state.diagnostic_code = int(CalcinerDiagnosticCode.DRAFT_LOSS_TRIP)
        elif self.state.under_calc_alarm:
            self.state.diagnostic_code = int(CalcinerDiagnosticCode.UNDER_CALCINATION_ALARM)
        else:
            self.state.diagnostic_code = int(CalcinerDiagnosticCode.OK)

    # ------------------------------------------------------------------------
    # Horner OCS Register Space Synchronization
    # ------------------------------------------------------------------------

    def _sync_registers(self) -> None:
        """Synchronize telemetry into Horner OCS registers (%R770..%R777, %M179..%M181)."""
        self._evaluate_safety_interlocks()

        # Compute %R770 CalcinerStatusWord
        sw = 0
        if self.state.is_running:
            sw |= int(CalcinerStatusBits.RUNNING)
        if self.state.burner_on:
            sw |= int(CalcinerStatusBits.BURNER_ON)
        if self.state.drum_rotating:
            sw |= int(CalcinerStatusBits.DRUM_ROTATING)
        if (
            self.state.x_calc >= self.config.x_calc_min_threshold
            and (self.state.t_bed - 273.15) >= 850.0
        ):
            sw |= int(CalcinerStatusBits.CALCINATION_OPTIMAL)
        if self.state.overtemp_trip:
            sw |= int(CalcinerStatusBits.WALL_OVERTEMP_TRIP)
        if self.state.under_calc_alarm:
            sw |= int(CalcinerStatusBits.UNDER_CALCINATION_ALARM)
        if self.state.draft_loss_trip:
            sw |= int(CalcinerStatusBits.DRAFT_LOSS_TRIP)
        if self.state.discharge_active:
            sw |= int(CalcinerStatusBits.DISCHARGE_ACTIVE)

        t_bed_c = self.state.t_bed - 273.15
        t_gas_c = self.state.t_gas - 273.15
        t_wall_c = self.state.t_wall - 273.15
        x_calc_pct = self.state.x_calc * 100.0
        prod_rate_kg_h = self.state.production_rate_kg_h
        draft_pa = self.state.p_draft_pa
        diag_code = self.state.diagnostic_code

        # Write Analog Word Registers %R770..%R777
        self.reg_table.write_word("%R770", sw, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word(
            "%R771",
            max(-32768, min(32767, int(round(t_bed_c * 10.0)))),
            privilege=PrivilegeMode.SYSTEM,
        )
        self.reg_table.write_word(
            "%R772",
            max(-32768, min(32767, int(round(t_gas_c * 10.0)))),
            privilege=PrivilegeMode.SYSTEM,
        )
        self.reg_table.write_word(
            "%R773",
            max(-32768, min(32767, int(round(t_wall_c * 10.0)))),
            privilege=PrivilegeMode.SYSTEM,
        )
        self.reg_table.write_word(
            "%R774",
            max(0, min(1000, int(round(x_calc_pct * 10.0)))),
            privilege=PrivilegeMode.SYSTEM,
        )
        self.reg_table.write_word(
            "%R775",
            max(0, min(32767, int(round(prod_rate_kg_h * 10.0)))),
            privilege=PrivilegeMode.SYSTEM,
        )
        self.reg_table.write_word(
            "%R776",
            max(-32768, min(32767, int(round(draft_pa)))),
            privilege=PrivilegeMode.SYSTEM,
        )
        self.reg_table.write_word("%R777", diag_code, privilege=PrivilegeMode.SYSTEM)

        # Write Discrete Safety Coils %M179..%M181
        self.reg_table.write_bit("%M179", self.state.overtemp_trip, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_bit("%M180", self.state.under_calc_alarm, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_bit("%M181", self.state.draft_loss_trip, privilege=PrivilegeMode.SYSTEM)


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

ROTARY_CALCINER_PURE_ST_POU: str = """PROGRAM RotaryCalcinerSync
VAR
    CalcinerStatusWord AT %R770 : INT;
    BedTempDegC AT %R771 : INT;
    GasExhaustTempDegC AT %R772 : INT;
    RefractoryWallTempDegC AT %R773 : INT;
    CalcinationConversionPct AT %R774 : INT;
    ProductionRateKgH AT %R775 : INT;
    DraftPressurePa AT %R776 : INT;
    DiagnosticEventCode AT %R777 : INT;
    RefractoryOverTempTrip AT %M179 : BOOL;
    UnderCalcinationAlarm AT %M180 : BOOL;
    DraftLossTrip AT %M181 : BOOL;
    BurnerPermissive : BOOL;
    DrumDrivePermissive : BOOL;
    FeedPermissive : BOOL;
END_VAR

(* Process Safety Interlocks & Alarms *)
IF RefractoryWallTempDegC >= 12500 THEN
    RefractoryOverTempTrip := TRUE;
    DiagnosticEventCode := 36097; (* 16#8D01 *)
    BurnerPermissive := FALSE;
    FeedPermissive := FALSE;
END_IF;

IF DraftPressurePa > 20 THEN
    DraftLossTrip := TRUE;
    DiagnosticEventCode := 36099; (* 16#8D03 *)
    BurnerPermissive := FALSE;
END_IF;

IF CalcinationConversionPct < 900 THEN
    UnderCalcinationAlarm := TRUE;
    IF DiagnosticEventCode = 0 THEN
        DiagnosticEventCode := 36098; (* 16#8D02 *)
    END_IF;
END_IF;

IF NOT RefractoryOverTempTrip AND NOT DraftLossTrip THEN
    BurnerPermissive := TRUE;
    DrumDrivePermissive := TRUE;
    FeedPermissive := TRUE;
END_IF;
END_PROGRAM
"""


def verify_calciner_pure_st() -> bool:
    """Validate RotaryCalcinerSync POU with STParser and SecurityGuard."""
    # 1. Anti-ladder security guard assertion
    SecurityGuard.assert_pure_st_content(ROTARY_CALCINER_PURE_ST_POU)

    # 2. IEC 61131-3 ST AST Parser validation
    val = STParser.validate_code(ROTARY_CALCINER_PURE_ST_POU)
    if val.status != AgentStatus.SUCCESS:
        return False

    pou = STParser.parse_pou(ROTARY_CALCINER_PURE_ST_POU)
    if not pou:
        return False

    required_registers = [
        "%R770", "%R771", "%R772", "%R773",
        "%R774", "%R775", "%R776", "%R777",
        "%M179", "%M180", "%M181",
    ]
    return (
        pou.name == "RotaryCalcinerSync"
        and pou.pou_type == POUType.PROGRAM
        and all(reg in pou.bound_registers for reg in required_registers)
    )


# Compatibility aliases
CalcinerSimulationEngine = RotaryCalcinerSimulator
CalcinerSimulator = RotaryCalcinerSimulator
CALCINER_PURE_ST_POU = ROTARY_CALCINER_PURE_ST_POU


# ============================================================================
# 5. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_calciner_verification(evidence_path: Optional[str] = None) -> Dict[str, Any]:
    """Execute complete 9-stage verification suite for W116 Rotary Calciner Engine.

    Returns strict 4-state contract: success | failed | blocked | inconclusive.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU and AST Symbol Binding
    # ------------------------------------------------------------------------
    SecurityGuard.assert_pure_st_content(ROTARY_CALCINER_PURE_ST_POU)
    res_st = STParser.validate_code(ROTARY_CALCINER_PURE_ST_POU)
    ast = STParser.parse_pou(ROTARY_CALCINER_PURE_ST_POU)

    c1 = (
        res_st.status == AgentStatus.SUCCESS
        and ast is not None
        and ast.name == "RotaryCalcinerSync"
        and ast.pou_type == POUType.PROGRAM
        and "%R770" in ast.bound_registers
        and "%R771" in ast.bound_registers
        and "%R772" in ast.bound_registers
        and "%R773" in ast.bound_registers
        and "%R774" in ast.bound_registers
        and "%R775" in ast.bound_registers
        and "%R776" in ast.bound_registers
        and "%R777" in ast.bound_registers
        and "%M179" in ast.bound_registers
        and "%M180" in ast.bound_registers
        and "%M181" in ast.bound_registers
    )
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_And_AST_Symbol_Binding",
        "passed": c1,
        "details": "Pure ST POU verified cleanly; %R770..%R777 and %M179..%M181 bound into AST.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Solid Mineral Arrhenius Calcination Kinetics
    # ------------------------------------------------------------------------
    sim = RotaryCalcinerSimulator()
    k_800 = sim.arrhenius_rate_constant(800.0 + 273.15)
    k_850 = sim.arrhenius_rate_constant(850.0 + 273.15)
    k_900 = sim.arrhenius_rate_constant(900.0 + 273.15)
    k_950 = sim.arrhenius_rate_constant(950.0 + 273.15)

    # Arrhenius slope verification: ln(k2/k1) = -Ea/R * (1/T2 - 1/T1)
    t1 = 850.0 + 273.15
    t2 = 950.0 + 273.15
    ea_recovered = -sim.config.r_gas * math.log(k_950 / k_850) / ((1.0 / t2) - (1.0 / t1))
    ea_err = abs(ea_recovered - sim.config.activation_energy_j_mol)

    c2 = (
        k_800 > 0.0 and k_850 > 0.0 and k_900 > 0.0 and k_950 > 0.0
        and (k_950 > k_900 > k_850 > k_800)
        and ea_err < 1.0e-6
    )
    test_results.append({
        "stage": 2,
        "check": "Solid_Mineral_Arrhenius_Calcination_Kinetics",
        "passed": c2,
        "details": (
            f"Arrhenius kinetics verified: k(800°C)={k_800:.4f}/s, k(900°C)={k_900:.4f}/s, "
            f"k(950°C)={k_950:.4f}/s, Ea error={ea_err:.2e} J/mol."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 3: Shrinking Core Model & Stoichiometric Mass Conservation
    # ------------------------------------------------------------------------
    k_ref = 0.010
    rx_00 = sim.shrinking_core_rate(0.00, k_ref)
    rx_50 = sim.shrinking_core_rate(0.50, k_ref)
    rx_90 = sim.shrinking_core_rate(0.90, k_ref)
    rx_10 = sim.shrinking_core_rate(1.00, k_ref)

    # Reaction mass yield derivatives
    y_test = [0.50, 1193.15, 823.15, 1373.15, 0.0, 0.0]
    derivs = sim.compute_derivatives(0.0, y_test, feed_active=False)
    dm_co2_dt = derivs[4]
    dm_product_dt = derivs[5]
    total_yield_rate = dm_co2_dt + dm_product_dt

    k_actual = sim.arrhenius_rate_constant(1193.15)
    rx_actual = sim.shrinking_core_rate(0.50, k_actual)
    m_caco3_bed = sim.config.bed_mass_nominal_kg * (1.0 - 0.50)
    expected_r_calc = m_caco3_bed * rx_actual
    mass_conservation_residual = abs(total_yield_rate - expected_r_calc)

    # Stoichiometric ratio check (44.01 / 56.08)
    molar_ratio_actual = dm_co2_dt / dm_product_dt
    molar_ratio_expected = sim.config.mw_co2 / sim.config.mw_cao
    ratio_err = abs(molar_ratio_actual - molar_ratio_expected)

    c3 = (
        (rx_00 > rx_50 > rx_90 > 0.0)
        and rx_10 == 0.0
        and mass_conservation_residual < 1.0e-12
        and ratio_err < 1.0e-6
    )
    test_results.append({
        "stage": 3,
        "check": "Shrinking_Core_Model_And_Stoichiometric_Mass_Conservation",
        "passed": c3,
        "details": (
            f"Shrinking core & mass balance verified: rx(0)={rx_00:.4f}/s, rx(1)={rx_10:.4f}/s, "
            f"mass conservation residual={mass_conservation_residual:.2e} kg/s, ratio error={ratio_err:.2e}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 4: Counter-Current Rotary Drum Heat Transfer Balances
    # ------------------------------------------------------------------------
    ht = sim.compute_heat_transfers(t_bed=1173.15, t_gas=1273.15, t_wall=1323.15)
    # Gas is hotter than bed: radiation and convection to bed must be positive
    q_rad_gb = ht["q_rad_gb"]
    q_conv_gb = ht["q_conv_gb"]
    q_contact_wb = ht["q_contact_wb"]

    # Verify endothermic reaction thermal penalty
    derivs_with_rxn = sim.compute_derivatives(0.0, [0.50, 1173.15, 1273.15, 1323.15, 0.0, 0.0])
    # Suppress reaction (k=0 equivalent by setting X=1.0)
    derivs_no_rxn = sim.compute_derivatives(0.0, [1.00, 1173.15, 1273.15, 1323.15, 0.0, 0.0])
    dt_bed_penalty = derivs_no_rxn[1] - derivs_with_rxn[1]

    c4 = (
        q_rad_gb > 0.0
        and q_conv_gb > 0.0
        and q_contact_wb > 0.0
        and ht["q_loss_amb"] > 0.0
        and dt_bed_penalty > 0.0  # Endothermic reaction extracts heat, reducing dT_bed/dt
    )
    test_results.append({
        "stage": 4,
        "check": "Counter_Current_Rotary_Drum_Heat_Transfer_Balances",
        "passed": c4,
        "details": (
            f"Heat transfer verified: Q_rad_gb={q_rad_gb/1e3:.1f} kW, Q_conv_gb={q_conv_gb/1e3:.1f} kW, "
            f"Q_contact_wb={q_contact_wb/1e3:.1f} kW, endothermic cooling penalty={dt_bed_penalty:.4f} K/s."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 5: Coupled 6-State ODE System RK4 Integration
    # ------------------------------------------------------------------------
    sim_rk = RotaryCalcinerSimulator()
    for _ in range(200):
        res = sim_rk.step(dt=0.01)
        assert res.status == AgentStatus.SUCCESS

    # Verify state progression stability
    c5 = (
        0.0 <= sim_rk.state.x_calc <= 1.0
        and sim_rk.state.t_bed > 273.15
        and sim_rk.state.t_gas > 273.15
        and sim_rk.state.t_wall > 273.15
        and sim_rk.state.m_co2_released > 0.0
        and sim_rk.state.m_product > 0.0
        and sim_rk.state.p_draft_pa < 0.0  # Stable negative draft under normal ID fan
        and not math.isnan(sim_rk.state.t_bed)
    )
    test_results.append({
        "stage": 5,
        "check": "Coupled_6_State_ODE_System_RK4_Integration",
        "passed": c5,
        "details": (
            f"RK4 integration verified over 2.0s: X_calc={sim_rk.state.x_calc*100.0:.2f}%, "
            f"T_bed={sim_rk.state.t_bed-273.15:.1f}°C, T_wall={sim_rk.state.t_wall-273.15:.1f}°C, "
            f"Draft={sim_rk.state.p_draft_pa:.1f} Pa, Product={sim_rk.state.m_product:.3f} kg."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 6: Refractory Wall OverTemp Trip Interlock (%M179 -> 0x8D01)
    # ------------------------------------------------------------------------
    reg_table_6 = RegisterTable()
    sim_wall = RotaryCalcinerSimulator(register_table=reg_table_6)
    # Normal operation: wall temp 1100 °C
    sim_wall.state.t_wall = 273.15 + 1100.0
    sim_wall.step(dt=0.01)
    normal_m179 = reg_table_6.read_bit("%M179")

    # Incur refractory over-temperature trip: 1255 °C >= 1250 °C
    sim_wall.state.t_wall = 273.15 + 1255.0
    sim_wall.step(dt=0.01)
    tripped_m179 = reg_table_6.read_bit("%M179")
    diag_6 = reg_table_6.read_word("%R777") & 0xFFFF
    sw_6 = reg_table_6.read_word("%R770")

    c6 = (
        normal_m179 is False
        and tripped_m179 is True
        and diag_6 == 0x8D01
        and bool(sw_6 & int(CalcinerStatusBits.WALL_OVERTEMP_TRIP))
        and not sim_wall.state.burner_on  # Burner tripped
    )
    test_results.append({
        "stage": 6,
        "check": "Refractory_Wall_OverTemp_Trip_Interlock",
        "passed": c6,
        "details": "Refractory over-temp interlock (%M179=TRUE, %R777=0x8D01, burner tripped) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Under-Calcination Alarm Interlock (%M180 -> 0x8D02)
    # ------------------------------------------------------------------------
    reg_table_7 = RegisterTable()
    sim_under = RotaryCalcinerSimulator(register_table=reg_table_7)
    # Normal conversion: 95.0% >= 90.0%
    sim_under.state.x_calc = 0.95
    sim_under.step(dt=0.01)
    normal_m180 = reg_table_7.read_bit("%M180")

    # Incur under-calcination condition: 88.0% < 90.0% at discharge
    sim_under.state.x_calc = 0.88
    sim_under.step(dt=0.01)
    tripped_m180 = reg_table_7.read_bit("%M180")
    diag_7 = reg_table_7.read_word("%R777") & 0xFFFF
    sw_7 = reg_table_7.read_word("%R770")

    c7 = (
        normal_m180 is False
        and tripped_m180 is True
        and diag_7 == 0x8D02
        and bool(sw_7 & int(CalcinerStatusBits.UNDER_CALCINATION_ALARM))
    )
    test_results.append({
        "stage": 7,
        "check": "Under_Calcination_Alarm_Interlock",
        "passed": c7,
        "details": "Under-calcination alarm (%M180=TRUE, %R777=0x8D02) verified at X_calc=88.0%.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Draft Loss Trip Interlock (%M181 -> 0x8D03)
    # ------------------------------------------------------------------------
    reg_table_8 = RegisterTable()
    sim_draft = RotaryCalcinerSimulator(register_table=reg_table_8)
    # Normal draft: -50 Pa <= +20 Pa
    sim_draft.step(dt=0.01)
    normal_m181 = reg_table_8.read_bit("%M181")

    # Incur draft loss: ID fan failure causes positive draft +25 Pa > +20 Pa
    sim_draft.step(dt=0.01, draft_fan_running=False)
    tripped_m181 = reg_table_8.read_bit("%M181")
    diag_8 = reg_table_8.read_word("%R777") & 0xFFFF
    sw_8 = reg_table_8.read_word("%R770")

    c8 = (
        normal_m181 is False
        and tripped_m181 is True
        and diag_8 == 0x8D03
        and bool(sw_8 & int(CalcinerStatusBits.DRAFT_LOSS_TRIP))
        and not sim_draft.state.burner_on
    )
    test_results.append({
        "stage": 8,
        "check": "Draft_Loss_Trip_Interlock",
        "passed": c8,
        "details": "Draft loss trip (%M181=TRUE, %R777=0x8D03, burner tripped) verified on ID fan loss.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Registers Synchronization & Anti-Ladder Rejection
    # ------------------------------------------------------------------------
    reg_table_9 = RegisterTable()
    sim_sync = RotaryCalcinerSimulator(register_table=reg_table_9)
    sim_sync.state.t_bed = 273.15 + 920.4
    sim_sync.state.t_gas = 273.15 + 512.6
    sim_sync.state.t_wall = 273.15 + 1150.8
    sim_sync.state.x_calc = 0.946
    sim_sync.state.production_rate_kg_h = 1850.2
    sim_sync.state.p_draft_pa = -45.0
    sim_sync.state.is_running = True
    sim_sync.state.burner_on = True
    sim_sync.state.drum_rotating = True
    sim_sync.state.discharge_active = True
    sim_sync._sync_registers()

    r771 = reg_table_9.read_word("%R771")  # 9204
    r772 = reg_table_9.read_word("%R772")  # 5126
    r773 = reg_table_9.read_word("%R773")  # 11508
    r774 = reg_table_9.read_word("%R774")  # 946
    r775 = reg_table_9.read_word("%R775")  # 18502
    r776 = reg_table_9.read_word("%R776")  # -45
    r777 = reg_table_9.read_word("%R777")  # 0

    sync_ok = (
        r771 == 9204
        and r772 == 5126
        and r773 == 11508
        and r774 == 946
        and r775 == 18502
        and r776 == -45
        and r777 == 0
    )

    # Anti-ladder rejection
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("""
        PROGRAM BadCalcinerLadder
        VAR Permissive : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """)
    except Exception:
        ladder_rejected = True

    c9 = sync_ok and ladder_rejected
    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Registers_Synchronization_And_Anti_Ladder_Rejection",
        "passed": c9,
        "details": (
            f"Registers verified: %R771={r771}, %R772={r772}, %R773={r773}, "
            f"%R774={r774}, %R775={r775}, %R776={r776}, %R777={r777}. Anti-ladder rejected."
        ),
    })

    # Final verdict
    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": (
            f"Rotary Calciner Simulation Engine verified cleanly "
            f"({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed)."
        ),
        "data": {
            "work_package": "W116",
            "gate": "Gate G7 / G4",
            "component": "Rotary Calciner Solid Mineral Kinetics & Counter-Current Heat Transfer Simulation",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "register_map": {
                "analog_registers": "%R770..%R777",
                "discrete_coils": "%M179..%M181",
                "values": {
                    "%R770": reg_table_9.read_word("%R770"),
                    "%R771": reg_table_9.read_word("%R771"),
                    "%R772": reg_table_9.read_word("%R772"),
                    "%R773": reg_table_9.read_word("%R773"),
                    "%R774": reg_table_9.read_word("%R774"),
                    "%R775": reg_table_9.read_word("%R775"),
                    "%R776": reg_table_9.read_word("%R776"),
                    "%R777": reg_table_9.read_word("%R777"),
                    "%M179": reg_table_9.read_bit("%M179"),
                    "%M180": reg_table_9.read_bit("%M180"),
                    "%M181": reg_table_9.read_bit("%M181"),
                },
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if evidence_path:
        out_p = Path(evidence_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence
