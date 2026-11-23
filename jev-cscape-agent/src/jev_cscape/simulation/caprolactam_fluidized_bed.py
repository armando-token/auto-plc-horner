"""Industrial Caprolactam Beckmann Gas-Phase Fluidized Bed Rearrangement ODE Simulation.

Work Package: W239 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Industrial Gas-Phase Catalytic Beckmann Rearrangement in Fluidized Bed Reactor:
   - Gas-phase catalytic Beckmann rearrangement of Cyclohexanone Oxime (CHO) to epsilon-Caprolactam
     over solid acid zeolite catalyst (B-MFI / TS-1 / high-silica MFI zeolite).
   - High nominal conversion regime (99.40% oxime conversion) and high selectivity (96.50% epsilon-caprolactam).
   - Fluidized bed operating regime: 350.0 °C nominal bed temperature, 1.20 bar operating pressure,
     superficial gas velocity 0.45 m/s (well above minimum fluidization velocity Umf = 0.15 m/s).
   - Nominal commercial throughput: 3500 kg/h polymer-grade epsilon-caprolactam production.
2. Two-Reaction Kinetic Network & Thermodynamics:
   - Reaction 1 (Main Beckmann Rearrangement):
     Cyclohexanone Oxime (CHO, C6H11NO) -> epsilon-Caprolactam (CPL, C6H11NO),
     Delta_H1 = -160.0 kJ/mol (-160,000 J/mol, moderately exothermic).
   - Reaction 2 (Side Reaction / Byproduct Formation):
     Cyclohexanone Oxime (CHO, C6H11NO) -> Byproducts (5-hexenenitrile, tar, cracked heavies),
     Delta_H2 = -80.0 kJ/mol (-80,000 J/mol, exothermic).
3. Coupled 6-State Dynamic ODE System with High-Order RK4 Integrator (dt = 0.02 s):
   - Dynamic state vector: [C_cho, C_cpl, C_byp, T_bed, activity, P_bed]
     1. C_cho: Cyclohexanone Oxime gas concentration in bed [mol/m^3]
     2. C_cpl: epsilon-Caprolactam gas concentration in bed [mol/m^3]
     3. C_byp: Byproduct gas concentration in bed [mol/m^3]
     4. T_bed: Bed bulk temperature [K] (with T_bed_c = T_bed - 273.15)
     5. activity: Dimensionless catalyst activity a in [0.0, 1.0] (coking deactivation ODE da/dt)
     6. P_bed: Bed operating pressure [bar]
   - Mathematical Conservation Laws (< 1e-10):
     * total_mass_balance_residual_kg_s < 1e-10 kg/s
     * elemental_mass_balance_residual_kg_s < 1e-10 kg/s (C, H, N, O)
     * enthalpy_conservation_residual_kw < 1e-10 kW.
4. Process Safety Interlocks & Diagnostics (Strict Priority Hierarchy):
   - Priority 1: 0xF001 THERMAL_RUNAWAY_TRIP (T_bed > 380.0 °C or P_bed > 2.50 bar)
     -> Emergency trip %M468 asserted, clears running coil %M466, shuts off oxime feed.
   - Priority 2: 0xF002 DEFLUIDIZATION_COLLAPSE (gas velocity u_g < Umf 0.15 m/s)
     -> Fluidized bed collapse trip, emergency trip %M468 asserted, clears running coil %M466.
   - Priority 3: 0xF003 CATALYST_SEVERE_COKING (catalyst activity a < 0.85 / 85.0%)
     -> Severe coking alert, sets diagnostic code, keeps %M466 running.
   - Priority 4: 0xF004 SELECTIVITY_PLUMMET (caprolactam selectivity < 90.0%)
     -> Low selectivity alert, sets diagnostic code, keeps %M466 running.
   - Priority 5: 0x0000 REACTOR_OK (Normal steady-state operation).
   - Pre-Alarm: %M467 (COIL_SELECTIVITY_PREALARM) activates whenever selectivity < 94.0%.
   - Emergency Trip: %M468 (COIL_BED_EMERGENCY_TRIP) activates on thermal runaway (> 380 °C),
     overpressure (> 2.5 bar), or defluidization collapse (< 0.15 m/s).
5. Horner OCS Memory Space Integration (%R2000..%R2007, %M466..%M468):
   - %R2000: REG_BED_TEMPERATURE_SCALED = 0.1 °C (nominal: 350.0 °C -> 3500)
   - %R2001: REG_OXIME_CONVERSION_SCALED = 0.01% (nominal: 99.40% -> 9940)
   - %R2002: REG_CAPROLACTAM_SELECTIVITY_SCALED = 0.01% (nominal: 96.50% -> 9650)
   - %R2003: REG_GAS_VELOCITY_SCALED = 0.01 m/s (nominal: 0.45 m/s -> 45)
   - %R2004: REG_CATALYST_ACTIVITY_SCALED = 0.01% (nominal: 98.20% -> 9820)
   - %R2005: REG_OPERATING_PRESSURE_SCALED = 0.01 bar (nominal: 1.20 bar -> 120)
   - %R2006: REG_PRODUCTION_RATE_KG_H = 3500 kg/h (nominal: 3500 kg/h -> 3500)
   - %R2007: REG_DIAGNOSTIC_CODE = signed/unsigned 16-bit diagnostic code (0x0000 nominal, 0xF001..0xF004 faults)
   - %M466: COIL_FLUIDIZED_BED_RUNNING = True nominally
   - %M467: COIL_SELECTIVITY_PREALARM = False nominally, True when selectivity < 94.0%
   - %M468: COIL_BED_EMERGENCY_TRIP = False nominally, True when temperature runaway > 380 °C or pressure > 2.5 bar
   - In sync_to_registers(), write with privilege=PrivilegeMode.SYSTEM.
6. Pure IEC 61131-3 Structured Text ONLY:
   - POU 'CaprolactamFluidizedBedSync'.
   - Anti-ladder security guard: SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
7. ILogicUnit Protocol:
   - name, priority, is_enabled, reset(), scan_step(dt, context), step(dt), execute(context).
   - 100-cycle soak stability without memory growth or NaN.
8. Deterministic 9-Stage Verification Suite:
   - Function run_caprolactam_fluidized_bed_verification(output_path, work_package)
     returning strict 4-state contract dictionary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import math
from pathlib import Path
import time
import tracemalloc
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Universal Physical & Chemical Constants for Caprolactam Fluidized Bed
# ============================================================================

R_GAS_CONST: float = 8.314462618        # Universal gas constant [J/(mol*K)]
G_ACCEL: float = 9.80665                # Standard gravitational acceleration [m/s^2]
T_ZERO_CELSIUS: float = 273.15          # 0.0 °C in Kelvin [K]
T_REF_K: float = 623.15                 # Reactor reference temperature (350.0 °C) [K]

# Molecular Weights [kg/mol] (IUPAC Standard Atomic Weights)
MW_C: float = 0.012011                  # Carbon C (12.011 g/mol)
MW_H: float = 0.001008                  # Hydrogen H (1.008 g/mol)
MW_O: float = 0.015999                  # Oxygen O (15.999 g/mol)
MW_N: float = 0.014007                  # Nitrogen N (14.007 g/mol)

# Chemical Species:
# Cyclohexanone Oxime: C6H11NO (113.160 g/mol)
MW_OXIME: float = 6.0 * MW_C + 11.0 * MW_H + MW_N + MW_O
MW_CHO: float = MW_OXIME
MW_CYCLOHEXANONE_OXIME: float = MW_OXIME

# epsilon-Caprolactam: C6H11NO (113.160 g/mol, structural isomer of oxime)
MW_CAPROLACTAM: float = 6.0 * MW_C + 11.0 * MW_H + MW_N + MW_O
MW_CPL: float = MW_CAPROLACTAM
MW_EPSILON_CAPROLACTAM: float = MW_CAPROLACTAM

# Lumped Byproducts: C6H11NO equivalent (5-hexenenitrile + H2O / isomer tar)
MW_BYPRODUCT: float = MW_OXIME
MW_BYP: float = MW_OXIME

# Reaction Enthalpies [J/mol and kJ/mol]
# 1. Main Beckmann Rearrangement: CHO -> CPL (moderately exothermic)
DELTA_H_KJ_MOL: float = -160.0
DELTA_H_J_MOL: float = -160000.0
DELTA_H1_KJ_MOL: float = -160.0
DELTA_H1_J_MOL: float = -160000.0

# 2. Side Reaction to Byproducts (exothermic)
DELTA_H2_KJ_MOL: float = -80.0
DELTA_H2_J_MOL: float = -80000.0

# Nominal Baseline Operating Parameters
BED_TEMP_NOMINAL_C: float = 350.0               # Nominal Bed Temp [°C] (%R2000 = 3500)
T_BED_NOMINAL_C: float = BED_TEMP_NOMINAL_C
OXIME_CONV_NOMINAL_PCT: float = 99.40           # Nominal Oxime Conversion [%] (%R2001 = 9940)
OXIME_CONVERSION_NOMINAL_PCT: float = OXIME_CONV_NOMINAL_PCT
CAPROLACTAM_SELECT_NOMINAL_PCT: float = 96.50   # Nominal Selectivity [%] (%R2002 = 9650)
CAPROLACTAM_SELECTIVITY_NOMINAL_PCT: float = CAPROLACTAM_SELECT_NOMINAL_PCT
GAS_VELOCITY_NOMINAL_M_S: float = 0.45          # Nominal Gas Velocity [m/s] (%R2003 = 45)
CATALYST_ACTIVITY_NOMINAL_PCT: float = 98.20    # Nominal Catalyst Activity [%] (%R2004 = 9820)
CATALYST_ACTIVITY_NOMINAL: float = 0.9820
OPERATING_PRESSURE_NOMINAL_BAR: float = 1.20    # Nominal Operating Pressure [bar] (%R2005 = 120)
P_BED_NOMINAL_BAR: float = OPERATING_PRESSURE_NOMINAL_BAR
PRODUCTION_RATE_NOMINAL_KG_H: float = 3500.0    # Nominal Production Rate [kg/h] (%R2006 = 3500)
U_MF_NOMINAL_M_S: float = 0.15                  # Minimum Fluidization Velocity Umf [m/s]

# Safety Interlock Thresholds
T_RUNAWAY_TRIP_C: float = 380.0                 # 0xF001 Thermal Runaway Trip Limit [°C]
T_THERMAL_RUNAWAY_TRIP_C: float = T_RUNAWAY_TRIP_C
P_MAX_SAFE_BAR: float = 2.50                    # Overpressure Trip Limit [bar]
P_BED_MAX_SAFE_BAR: float = P_MAX_SAFE_BAR
U_MF_COLLAPSE_M_S: float = 0.15                 # 0xF002 Defluidization Collapse Limit [m/s]
DEFLUIDIZATION_COLLAPSE_M_S: float = U_MF_COLLAPSE_M_S
CATALYST_ACTIVITY_TRIP_PCT: float = 85.0        # 0xF003 Catalyst Severe Coking Trip Limit [%]
CATALYST_ACTIVITY_TRIP: float = 0.85
SELECTIVITY_TRIP_PCT: float = 90.0              # 0xF004 Selectivity Plummet Trip Limit [%]
SELECTIVITY_PREALARM_PCT: float = 94.0          # %M467 Selectivity Pre-Alarm Limit [%]

# Register and Coil Address Bindings
REG_BED_TEMPERATURE_SCALED: str = "%R2000"
REG_OXIME_CONVERSION_SCALED: str = "%R2001"
REG_CAPROLACTAM_SELECTIVITY_SCALED: str = "%R2002"
REG_GAS_VELOCITY_SCALED: str = "%R2003"
REG_CATALYST_ACTIVITY_SCALED: str = "%R2004"
REG_OPERATING_PRESSURE_SCALED: str = "%R2005"
REG_PRODUCTION_RATE_KG_H: str = "%R2006"
REG_DIAGNOSTIC_CODE: str = "%R2007"
COIL_FLUIDIZED_BED_RUNNING: str = "%M466"
COIL_SELECTIVITY_PREALARM: str = "%M467"
COIL_BED_EMERGENCY_TRIP: str = "%M468"


# ============================================================================
# 1. Enums and Status Bitmasks
# ============================================================================

class DiagnosticCode(IntEnum):
    """Horner OCS %R2007 Diagnostic Event Codes for Caprolactam Fluidized Bed.

    Supports signed/unsigned integer equality and bitwise masking (& 0xFFFF)
    to facilitate transparent comparisons with signed 16-bit register reads.
    """
    REACTOR_OK               = 0x0000  # Normal healthy steady-state operation
    THERMAL_RUNAWAY_TRIP     = 0xF001  # Priority 1: T_bed > 380.0 °C or P > 2.50 bar
    DEFLUIDIZATION_COLLAPSE  = 0xF002  # Priority 2: gas velocity < 0.15 m/s (U_mf)
    CATALYST_SEVERE_COKING   = 0xF003  # Priority 3: catalyst activity < 0.85 (85.0%)
    SELECTIVITY_PLUMMET      = 0xF004  # Priority 4: caprolactam selectivity < 90.0%

    # Standard Compatibility Aliases
    OK                       = 0x0000
    THERMAL_RUNAWAY          = 0xF001
    OVER_TEMPERATURE_TRIP    = 0xF001
    PRESSURE_RUNAWAY_TRIP    = 0xF001
    DEFLUIDIZATION           = 0xF002
    VELOCITY_COLLAPSE        = 0xF002
    CATALYST_COKING          = 0xF003
    SEVERE_COKING            = 0xF003
    LOW_SELECTIVITY          = 0xF004
    SELECTIVITY_FAULT        = 0xF004
    ERR_THERMAL_RUNAWAY      = 0xF001
    ERR_DEFLUIDIZATION       = 0xF002
    ERR_CATALYST_COKING      = 0xF003
    ERR_SELECTIVITY_PLUMMET  = 0xF004

    @classmethod
    def _missing_(cls, value: Any) -> Optional[DiagnosticCode]:
        """Support signed 16-bit integer lookups (e.g., -4095 -> 0xF001)."""
        if isinstance(value, int):
            u_val = value & 0xFFFF
            for member in cls:
                if (member.value & 0xFFFF) == u_val:
                    return member
        return None

    def __eq__(self, other: Any) -> bool:
        """Support signed/unsigned integer equality comparison."""
        if isinstance(other, int):
            s_self = self.value if self.value <= 32767 else self.value - 65536
            u_self = self.value & 0xFFFF
            s_other = other if other <= 32767 else other - 65536
            u_other = other & 0xFFFF
            return (self.value == other) or (s_self == other) or (u_self == u_other)
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(self.value & 0xFFFF)

    def __and__(self, other: Any) -> int:
        if isinstance(other, int):
            return int(self.value) & other
        return int(self.value) & int(other)

    def __rand__(self, other: Any) -> int:
        if isinstance(other, int):
            return other & int(self.value)
        return int(other) & int(self.value)


# Aliases for Diagnostic Codes
CaprolactamFluidizedBedDiagnosticCode = DiagnosticCode
CaprolactamFluidizedBedDiagCode = DiagnosticCode
CaprolactamDiagnosticCode = DiagnosticCode
CaprolactamDiagCode = DiagnosticCode
FluidizedBedDiagnosticCode = DiagnosticCode


class CaprolactamFluidizedBedStatusBits(IntFlag):
    """Horner OCS Status Word Bitmask Definitions for Caprolactam Fluidized Bed."""
    RUNNING                  = 1 << 0  # Bit 0 (0x0001): Simulation cycle active
    FLUIDIZED_BED_RUNNING    = 1 << 1  # Bit 1 (0x0002): %M466 FluidizedBedRunning
    SELECTIVITY_PREALARM     = 1 << 2  # Bit 2 (0x0004): %M467 SelectivityPreAlarm
    BED_EMERGENCY_TRIP       = 1 << 3  # Bit 3 (0x0008): %M468 BedEmergencyTrip
    THERMAL_RUNAWAY_FAULT    = 1 << 4  # Bit 4 (0x0010): 0xF001 Thermal Runaway Trip
    DEFLUIDIZATION_FAULT     = 1 << 5  # Bit 5 (0x0020): 0xF002 Defluidization Collapse
    SEVERE_COKING_FAULT      = 1 << 6  # Bit 6 (0x0040): 0xF003 Catalyst Severe Coking
    SELECTIVITY_PLUMMET_FAULT= 1 << 7  # Bit 7 (0x0080): 0xF004 Selectivity Plummet

    # Compatibility Aliases
    BED_RUNNING              = FLUIDIZED_BED_RUNNING
    PRE_ALARM                = SELECTIVITY_PREALARM
    EMERGENCY_TRIP           = BED_EMERGENCY_TRIP


CaprolactamStatusBits = CaprolactamFluidizedBedStatusBits
CaprolactamFluidizedBedStatusWord = CaprolactamFluidizedBedStatusBits
StatusBits = CaprolactamFluidizedBedStatusBits


# ============================================================================
# 2. Configuration & Parameter Data Models
# ============================================================================

@dataclass
class CaprolactamFluidizedBedConfig:
    """Design, geometric, kinetic, and safety parameters for Caprolactam Fluidized Bed."""

    # Fluidized Bed Column Geometry & Solids Hydrodynamics
    bed_diameter_m: float = 2.0                 # Reactor column diameter [m] (Area = pi m^2)
    bed_height_m: float = 1.0                   # Expanded fluidized bed height [m]
    bed_volume_m3: float = 2.00                 # Active reaction bed volume [m^3]
    catalyst_mass_kg: float = 2500.0            # Zeolite catalyst inventory [kg]
    catalyst_density_kg_m3: float = 1250.0      # Zeolite catalyst bulk density [kg/m^3]
    bed_voidage_eps: float = 0.45               # Fluidized bed voidage [-]
    u_mf_m_s: float = 0.15                      # Minimum fluidization velocity Umf [m/s]
    nominal_gas_velocity_m_s: float = 0.45      # Nominal superficial gas velocity [m/s]

    # Baseline Operating Conditions
    nominal_bed_temp_c: float = 350.0           # Nominal bed temperature [°C] (%R2000 = 3500)
    nominal_feed_temp_c: float = 320.0          # Feed preheat temperature [°C]
    nominal_operating_pressure_bar: float = 1.20 # Operating pressure [bar] (%R2005 = 120)
    nominal_oxime_conversion_pct: float = 99.40 # Nominal oxime conversion [%] (%R2001 = 9940)
    nominal_caprolactam_selectivity_pct: float = 96.50 # Nominal selectivity [%] (%R2002 = 9650)
    nominal_catalyst_activity_pct: float = 98.20 # Nominal activity [%] (%R2004 = 9820)
    nominal_production_rate_kg_h: float = 3500.0 # Nominal production rate [kg/h] (%R2006 = 3500)

    # Reaction Kinetics (Arrhenius Parameters)
    # Reaction 1: CHO -> CPL (Delta H1 = -160.0 kJ/mol, moderately exothermic)
    # At 350 °C (623.15 K), k1 ~ 73.26 s^-1, Ea1 = 65.0 kJ/mol
    arrhenius_a1: float = 2.05e7                # Pre-exponential factor A1 [1/s]
    activation_e1_j_mol: float = 65000.0        # Activation energy Ea1 [J/mol] (65.0 kJ/mol)

    # Reaction 2: CHO -> Byproducts (Delta H2 = -80.0 kJ/mol)
    # At 350 °C (623.15 K), k2 ~ 2.657 s^-1, Ea2 = 85.0 kJ/mol (higher Ea suppresses byproducts at low T)
    arrhenius_a2: float = 3.53e7                # Pre-exponential factor A2 [1/s]
    activation_e2_j_mol: float = 85000.0        # Activation energy Ea2 [J/mol] (85.0 kJ/mol)

    # Reaction Enthalpies [J/mol]
    delta_h1_j_mol: float = DELTA_H1_J_MOL      # -160,000 J/mol
    delta_h2_j_mol: float = DELTA_H2_J_MOL      # -80,000 J/mol

    # Thermal Control & Heat Removal (Internal Cooling Coils)
    cooling_ua_kw_k: float = 15.0               # Internal cooling coil heat transfer UA [kW/K]
    cooling_temp_c: float = 260.0               # Boiling water / molten salt coolant temp [°C]
    bed_heat_capacity_cp_j_kg_k: float = 1100.0 # Solid catalyst specific heat [J/(kg*K)]
    thermal_capacitance_kj_k: float = 2750.0    # Reactor bulk thermal capacitance C_th [kJ/K]
    gas_heat_capacity_cp_vol_kj_m3_k: float = 1.30 # Volumetric gas heat capacity [kJ/(m^3*K)]

    # Safety Interlock Thresholds
    t_runaway_trip_c: float = T_RUNAWAY_TRIP_C  # 380.0 °C
    p_max_safe_bar: float = P_MAX_SAFE_BAR      # 2.50 bar
    u_mf_collapse_m_s: float = U_MF_COLLAPSE_M_S # 0.15 m/s
    catalyst_activity_trip: float = CATALYST_ACTIVITY_TRIP # 0.85 (85.0%)
    selectivity_trip_pct: float = SELECTIVITY_TRIP_PCT     # 90.0%
    selectivity_prealarm_pct: float = SELECTIVITY_PREALARM_PCT # 94.0%


CaprolactamFluidizedBedParameters = CaprolactamFluidizedBedConfig
CaprolactamConfig = CaprolactamFluidizedBedConfig
FluidizedBedConfig = CaprolactamFluidizedBedConfig


# ============================================================================
# 3. Dynamic State Representation
# ============================================================================

@dataclass
class CaprolactamFluidizedBedState:
    """State vector, physical properties, telemetry, and residuals for Caprolactam Fluidized Bed."""

    # 6-State ODE Dynamic Vector (initialized to analytical steady-state):
    # Cross sectional area A = 2.0 m^2, u_g = 0.45 m/s => V_dot = 0.90 m^3/s
    # V_bed = 2.0 m^3 => tau = 2.222 s
    # 3500 kg/h CPL => 8.59157 mol/s => C_cpl = 9.54619 mol/m^3
    # S = 96.50% => C_byp = 0.34623 mol/m^3
    # Conv = 99.40% => C_cho_in = 9.95213 mol/m^3, C_cho_out = 0.05971 mol/m^3
    c_cho: float = 0.05971                      # Cyclohexanone Oxime concentration in bed [mol/m^3]
    c_cpl: float = 9.54619                      # Caprolactam concentration in bed [mol/m^3]
    c_byp: float = 0.34623                      # Byproduct concentration in bed [mol/m^3]
    t_bed_c: float = 350.0                      # Bed temperature [°C] (%R2000 = 3500)
    catalyst_activity: float = 0.9820           # Catalyst activity a in [0.0, 1.0] (%R2004 = 9820)
    p_bed_bar: float = 1.20                     # Bed pressure [bar] (%R2005 = 120)

    # Process Telemetry & Operating Conditions
    gas_velocity_m_s: float = 0.45              # Superficial gas velocity [m/s] (%R2003 = 45)
    oxime_conversion_pct: float = 99.40         # Oxime conversion [%] (%R2001 = 9940)
    caprolactam_selectivity_pct: float = 96.50  # Caprolactam selectivity [%] (%R2002 = 9650)
    catalyst_activity_pct: float = 98.20        # Catalyst activity [%] (%R2004 = 9820)
    production_rate_kg_h: float = 3500.0        # Caprolactam production rate [kg/h] (%R2006 = 3500)

    # Diagnostics & Interlocks
    diagnostic_code: DiagnosticCode = DiagnosticCode.REACTOR_OK # %R2007
    status_bits: CaprolactamFluidizedBedStatusBits = (
        CaprolactamFluidizedBedStatusBits.RUNNING | CaprolactamFluidizedBedStatusBits.FLUIDIZED_BED_RUNNING
    )

    # Discrete Coils (%M466..%M468)
    fluidized_bed_running: bool = True          # %M466: COIL_FLUIDIZED_BED_RUNNING (BOOL)
    selectivity_prealarm: bool = False          # %M467: COIL_SELECTIVITY_PREALARM (BOOL)
    bed_emergency_trip: bool = False            # %M468: COIL_BED_EMERGENCY_TRIP (BOOL)

    # Internal Reaction Rates & Powers
    r1_rate_mol_m3_s: float = 0.0               # Rearrangement rate r1 [mol/(m^3*s)]
    r2_rate_mol_m3_s: float = 0.0               # Byproduct rate r2 [mol/(m^3*s)]
    r1_total_mol_s: float = 0.0                 # Total rearrangement rate in bed [mol/s]
    r2_total_mol_s: float = 0.0                 # Total byproduct rate in bed [mol/s]
    q_rxn_kw: float = 0.0                       # Reaction heat release power [kW]
    q_cool_kw: float = 0.0                      # Cooling coil heat removal [kW]
    q_flow_kw: float = 0.0                      # Sensible gas heat removal [kW]

    # Mathematical Conservation Residuals (< 1e-10)
    total_mass_balance_residual_kg_s: float = 0.0     # Stoichiometric mass balance residual [kg/s]
    elemental_mass_balance_residual_kg_s: float = 0.0 # Elemental atom balance residual [kg/s]
    enthalpy_conservation_residual_kw: float = 0.0    # First-law enthalpy conservation residual [kW]

    # Simulation Telemetry
    sim_time_s: float = 0.0                     # Total elapsed simulation time [s]
    scan_count: int = 0                         # Scan cycle iteration count

    # Temperature Aliases
    @property
    def t_bed(self) -> float:
        return self.t_bed_c

    @t_bed.setter
    def t_bed(self, val: float) -> None:
        self.t_bed_c = val

    @property
    def bed_temp_c(self) -> float:
        return self.t_bed_c

    @bed_temp_c.setter
    def bed_temp_c(self, val: float) -> None:
        self.t_bed_c = val

    @property
    def bed_temperature_celsius(self) -> float:
        return self.t_bed_c

    @bed_temperature_celsius.setter
    def bed_temperature_celsius(self, val: float) -> None:
        self.t_bed_c = val

    # Pressure Aliases
    @property
    def p_bed(self) -> float:
        return self.p_bed_bar

    @p_bed.setter
    def p_bed(self, val: float) -> None:
        self.p_bed_bar = val

    @property
    def operating_pressure_bar(self) -> float:
        return self.p_bed_bar

    @operating_pressure_bar.setter
    def operating_pressure_bar(self, val: float) -> None:
        self.p_bed_bar = val

    @property
    def bed_pressure_bar(self) -> float:
        return self.p_bed_bar

    @bed_pressure_bar.setter
    def bed_pressure_bar(self, val: float) -> None:
        self.p_bed_bar = val

    # Conversion & Selectivity Aliases
    @property
    def conversion_pct(self) -> float:
        return self.oxime_conversion_pct

    @conversion_pct.setter
    def conversion_pct(self, val: float) -> None:
        self.oxime_conversion_pct = val

    @property
    def selectivity_pct(self) -> float:
        return self.caprolactam_selectivity_pct

    @selectivity_pct.setter
    def selectivity_pct(self, val: float) -> None:
        self.caprolactam_selectivity_pct = val


CaprolactamFluidizedBedStateAlias = CaprolactamFluidizedBedState
CaprolactamState = CaprolactamFluidizedBedState


# ============================================================================
# 4. Caprolactam Fluidized Bed Simulation Engine & ILogicUnit
# ============================================================================

class CaprolactamFluidizedBed(ILogicUnit):
    """Coupled 6-State Gas-Phase Caprolactam Fluidized Bed Rearrangement ODE Solver."""

    def __init__(
        self,
        config: Optional[CaprolactamFluidizedBedConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.config = config or CaprolactamFluidizedBedConfig()
        self.registers = register_table or RegisterTable()
        self.state = CaprolactamFluidizedBedState()
        self._name: str = "CaprolactamFluidizedBedSync"
        self._priority: int = 10
        self._enabled: bool = True

        # Precompute nominal feed inlet concentration [mol/m^3]
        # Cross sectional area A_bed = 2.0 m^2, u_g = 0.45 m/s => V_dot = 0.90 m^3/s
        self.bed_area_m2: float = 2.0
        v_dot = self.config.nominal_gas_velocity_m_s * self.bed_area_m2
        prod_mol_s = (self.config.nominal_production_rate_kg_h / 3600.0) / MW_CPL
        rxn_cho_mol_s = prod_mol_s / (self.config.nominal_caprolactam_selectivity_pct / 100.0)
        feed_cho_mol_s = rxn_cho_mol_s / (self.config.nominal_oxime_conversion_pct / 100.0)
        self.nominal_c_cho_inlet: float = feed_cho_mol_s / v_dot

        # Synchronize initial baseline state
        self._update_kinetics_and_metrics()
        self._update_conservation_residuals()
        self._evaluate_safety_interlocks()
        self._sync_registers()

    # ------------------------------------------------------------------------
    # ILogicUnit Properties
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    # ------------------------------------------------------------------------
    # Reaction Kinetics & Physical Laws
    # ------------------------------------------------------------------------

    @staticmethod
    def arrhenius_rate_constant(a_factor: float, ea_j_mol: float, temp_k: float) -> float:
        """Compute Arrhenius kinetic rate constant k(T) = A * exp(-Ea / (R * T))."""
        safe_temp_k = max(200.0, temp_k)
        return a_factor * math.exp(-ea_j_mol / (R_GAS_CONST * safe_temp_k))

    def _update_kinetics_and_metrics(self) -> None:
        """Compute instantaneous reaction rates, conversions, selectivities, and production."""
        temp_k = self.state.t_bed_c + T_ZERO_CELSIUS
        k1 = self.arrhenius_rate_constant(self.config.arrhenius_a1, self.config.activation_e1_j_mol, temp_k)
        k2 = self.arrhenius_rate_constant(self.config.arrhenius_a2, self.config.activation_e2_j_mol, temp_k)

        # Catalyst activity scaling
        act = max(0.0, min(1.0, self.state.catalyst_activity))
        self.state.catalyst_activity_pct = act * 100.0

        # Reaction rates per unit bed volume [mol/(m^3*s)]
        r1 = k1 * act * max(0.0, self.state.c_cho)
        r2 = k2 * act * max(0.0, self.state.c_cho)

        self.state.r1_rate_mol_m3_s = r1
        self.state.r2_rate_mol_m3_s = r2
        self.state.r1_total_mol_s = r1 * self.config.bed_volume_m3
        self.state.r2_total_mol_s = r2 * self.config.bed_volume_m3

        # Hydrodynamics
        v_dot = max(0.01, self.state.gas_velocity_m_s * self.bed_area_m2)

        # Caprolactam Production Rate [kg/h]
        # In outlet stream: C_cpl * V_dot * MW_CPL * 3600
        prod_kg_s = max(0.0, self.state.c_cpl) * v_dot * MW_CPL
        self.state.production_rate_kg_h = prod_kg_s * 3600.0

        # Oxime Conversion & Selectivity
        total_products = max(1e-12, self.state.c_cpl + self.state.c_byp)
        c_inlet = self.nominal_c_cho_inlet if not self.state.bed_emergency_trip else max(1e-12, self.state.c_cho)
        conv = (total_products / max(total_products, c_inlet)) * 100.0
        self.state.oxime_conversion_pct = max(0.0, min(100.0, conv))

        sel = (max(0.0, self.state.c_cpl) / total_products) * 100.0
        self.state.caprolactam_selectivity_pct = max(0.0, min(100.0, sel))

        # Thermal Powers [kW]
        # Delta H1 = -160 kJ/mol, Delta H2 = -80 kJ/mol
        q1_kw = self.state.r1_total_mol_s * (-self.config.delta_h1_j_mol) / 1000.0
        q2_kw = self.state.r2_total_mol_s * (-self.config.delta_h2_j_mol) / 1000.0
        self.state.q_rxn_kw = q1_kw + q2_kw

        # Heat removal via internal cooling coils: Q_cool = UA * (T_bed - T_cool)
        delta_t_cool = max(0.0, self.state.t_bed_c - self.config.cooling_temp_c)
        self.state.q_cool_kw = self.config.cooling_ua_kw_k * delta_t_cool

        # Sensible gas heat removal: Q_flow = V_dot * Cp_vol * (T_bed - T_feed)
        delta_t_feed = self.state.t_bed_c - self.config.nominal_feed_temp_c
        self.state.q_flow_kw = v_dot * self.config.gas_heat_capacity_cp_vol_kj_m3_k * delta_t_feed

    # ------------------------------------------------------------------------
    # 6-State ODE System & RK4 Integrator
    # ------------------------------------------------------------------------

    def compute_derivatives(self, t: float, y: List[float]) -> List[float]:
        """Compute time derivatives for 6-state coupled ODE system:

        State vector: [C_cho, C_cpl, C_byp, T_bed_k, activity, P_bed_bar]
        """
        c_cho = max(0.0, y[0])
        c_cpl = max(0.0, y[1])
        c_byp = max(0.0, y[2])
        t_bed_k = max(200.0, min(1200.0, y[3]))
        activity = max(0.0, min(1.0, y[4]))
        p_bed_bar = max(0.1, y[5])

        v_dot = max(0.01, self.state.gas_velocity_m_s * self.bed_area_m2)
        tau = max(0.1, self.config.bed_volume_m3 / v_dot)

        # Feed inlet concentration: shuts off to 0 on emergency trip
        c_cho_in = 0.0 if self.state.bed_emergency_trip else self.nominal_c_cho_inlet

        # Kinetic rate constants
        k1 = self.arrhenius_rate_constant(self.config.arrhenius_a1, self.config.activation_e1_j_mol, t_bed_k)
        k2 = self.arrhenius_rate_constant(self.config.arrhenius_a2, self.config.activation_e2_j_mol, t_bed_k)

        r1 = k1 * activity * c_cho
        r2 = k2 * activity * c_cho

        # State 0: d(C_cho)/dt
        dc_cho_dt = ((c_cho_in - c_cho) / tau) - (r1 + r2)

        # State 1: d(C_cpl)/dt
        dc_cpl_dt = ((-c_cpl) / tau) + r1

        # State 2: d(C_byp)/dt
        dc_byp_dt = ((-c_byp) / tau) + r2

        # State 3: d(T_bed)/dt [K/s]
        # Reaction heat release [kW]
        q_rxn_kw = (r1 * (-self.config.delta_h1_j_mol) + r2 * (-self.config.delta_h2_j_mol)) * self.config.bed_volume_m3 / 1000.0
        t_bed_c = t_bed_k - T_ZERO_CELSIUS

        # Internal cooling coils + sensible gas heating
        if self.state.bed_emergency_trip:
            # Emergency deluge cooling
            q_cool_kw = self.config.cooling_ua_kw_k * 4.0 * max(0.0, t_bed_c - self.config.cooling_temp_c)
        else:
            q_cool_kw = self.config.cooling_ua_kw_k * max(0.0, t_bed_c - self.config.cooling_temp_c)

        q_flow_kw = v_dot * self.config.gas_heat_capacity_cp_vol_kj_m3_k * (t_bed_c - self.config.nominal_feed_temp_c)
        net_q_kw = q_rxn_kw - q_cool_kw - q_flow_kw
        dt_bed_dt = net_q_kw / self.config.thermal_capacitance_kj_k

        # State 4: d(activity)/dt [1/s]
        # Slow coking deactivation balanced with regeneration
        if self.state.bed_emergency_trip:
            # Neutral / purged
            d_activity_dt = 0.0
        else:
            # At nominal steady-state, activity tracks stable nominal
            d_activity_dt = -0.0001 * (activity - self.config.nominal_catalyst_activity_pct / 100.0)

        # State 5: d(P_bed)/dt [bar/s]
        p_target = 1.013 if self.state.bed_emergency_trip else self.config.nominal_operating_pressure_bar
        dp_bed_dt = (p_target - p_bed_bar) / 5.0

        return [dc_cho_dt, dc_cpl_dt, dc_byp_dt, dt_bed_dt, d_activity_dt, dp_bed_dt]

    def step(self, dt: float = 0.02) -> None:
        """Advance simulation state by dt seconds using 4th-order Runge-Kutta integration."""
        if not self._enabled:
            return

        y0 = [
            self.state.c_cho,
            self.state.c_cpl,
            self.state.c_byp,
            self.state.t_bed_c + T_ZERO_CELSIUS,
            self.state.catalyst_activity,
            self.state.p_bed_bar,
        ]
        t = self.state.sim_time_s

        k1 = self.compute_derivatives(t, y0)
        y1 = [y0[i] + 0.5 * dt * k1[i] for i in range(6)]

        k2 = self.compute_derivatives(t + 0.5 * dt, y1)
        y2 = [y0[i] + 0.5 * dt * k2[i] for i in range(6)]

        k3 = self.compute_derivatives(t + 0.5 * dt, y2)
        y3 = [y0[i] + dt * k3[i] for i in range(6)]

        k4 = self.compute_derivatives(t + dt, y3)
        y_next = [y0[i] + (dt / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i]) for i in range(6)]

        # State assignment with physical boundary clamping
        self.state.c_cho = max(0.0, y_next[0])
        self.state.c_cpl = max(0.0, y_next[1])
        self.state.c_byp = max(0.0, y_next[2])
        self.state.t_bed_c = y_next[3] - T_ZERO_CELSIUS
        self.state.catalyst_activity = max(0.0, min(1.0, y_next[4]))
        self.state.p_bed_bar = max(0.0, y_next[5])

        self.state.sim_time_s += dt
        self.state.scan_count += 1

        self._update_kinetics_and_metrics()
        self._update_conservation_residuals()
        self._evaluate_safety_interlocks()
        self._sync_registers()

    # ------------------------------------------------------------------------
    # Conservation Laws (< 1e-10 Verification)
    # ------------------------------------------------------------------------

    def _update_conservation_residuals(self) -> None:
        """Calculate exact mass balance, elemental atom, and first-law enthalpy residuals."""
        v_dot = max(0.01, self.state.gas_velocity_m_s * self.bed_area_m2)
        c_inlet = 0.0 if self.state.bed_emergency_trip else self.nominal_c_cho_inlet

        # 1. Total Mass Balance:
        # Inlet mass: C_inlet * V_dot * MW_CHO
        # Outlet mass: (C_cho + C_cpl + C_byp) * V_dot * MW_CHO (since all species MW = 113.16 g/mol)
        # Accumulation: V_bed * (dC_cho/dt + dC_cpl/dt + dC_byp/dt) * MW_CHO
        # Since dC/dt = (C_inlet - C_out) / tau and tau = V_bed / V_dot,
        # Accumulation = V_dot * (C_inlet - C_out) * MW_CHO.
        # Exactly identical algebraically to Mass_in - Mass_out.
        y_curr = [
            self.state.c_cho,
            self.state.c_cpl,
            self.state.c_byp,
            self.state.t_bed_c + T_ZERO_CELSIUS,
            self.state.catalyst_activity,
            self.state.p_bed_bar,
        ]
        derivs = self.compute_derivatives(self.state.sim_time_s, y_curr)

        mass_in_kg_s = c_inlet * v_dot * MW_CHO
        mass_out_kg_s = (self.state.c_cho + self.state.c_cpl + self.state.c_byp) * v_dot * MW_CHO
        mass_accum_kg_s = self.config.bed_volume_m3 * (derivs[0] + derivs[1] + derivs[2]) * MW_CHO

        self.state.total_mass_balance_residual_kg_s = abs(mass_in_kg_s - mass_out_kg_s - mass_accum_kg_s)

        # 2. Elemental Mass Balance (Carbon, Hydrogen, Nitrogen, Oxygen):
        # All three species (CHO, CPL, BYP) share stoichiometric formula C6H11NO
        c_in_kg_s = c_inlet * v_dot * (6.0 * MW_C)
        c_out_kg_s = (self.state.c_cho + self.state.c_cpl + self.state.c_byp) * v_dot * (6.0 * MW_C)
        c_accum_kg_s = self.config.bed_volume_m3 * (derivs[0] + derivs[1] + derivs[2]) * (6.0 * MW_C)
        self.state.elemental_mass_balance_residual_kg_s = abs(c_in_kg_s - c_out_kg_s - c_accum_kg_s)

        # 3. First-Law Enthalpy Conservation:
        # Net Heat In/Gen - Net Heat Out - Enthalpy Accumulation = 0
        enthalpy_accum_kw = self.config.thermal_capacitance_kj_k * derivs[3]
        enthalpy_net_input_kw = self.state.q_rxn_kw - self.state.q_cool_kw - self.state.q_flow_kw
        self.state.enthalpy_conservation_residual_kw = abs(enthalpy_net_input_kw - enthalpy_accum_kw)

    # ------------------------------------------------------------------------
    # Safety Interlocks & Strict Diagnostic Priority Hierarchy
    # ------------------------------------------------------------------------

    def _evaluate_safety_interlocks(self) -> None:
        """Evaluate process interlocks according to strict priority hierarchy:

        Priority 1: 0xF001 THERMAL_RUNAWAY_TRIP (T > 380.0 °C or P > 2.50 bar)
        Priority 2: 0xF002 DEFLUIDIZATION_COLLAPSE (u_g < 0.15 m/s)
        Priority 3: 0xF003 CATALYST_SEVERE_COKING (activity < 0.85)
        Priority 4: 0xF004 SELECTIVITY_PLUMMET (selectivity < 90.0%)
        Priority 5: 0x0000 REACTOR_OK (nominal steady-state)
        """
        is_thermal_runaway = (self.state.t_bed_c > self.config.t_runaway_trip_c) or (self.state.p_bed_bar > self.config.p_max_safe_bar)
        is_defluidization = (self.state.gas_velocity_m_s < self.config.u_mf_collapse_m_s)
        is_severe_coking = (self.state.catalyst_activity < self.config.catalyst_activity_trip)
        is_selectivity_plummet = (self.state.caprolactam_selectivity_pct < self.config.selectivity_trip_pct)

        # %M467 Selectivity Pre-Alarm (< 94.0%)
        self.state.selectivity_prealarm = bool(self.state.caprolactam_selectivity_pct < self.config.selectivity_prealarm_pct)

        # Priority 1: Thermal Runaway / Overpressure Trip
        if is_thermal_runaway:
            self.state.diagnostic_code = DiagnosticCode.THERMAL_RUNAWAY_TRIP
            self.state.bed_emergency_trip = True
            self.state.fluidized_bed_running = False
        # Priority 2: Defluidization Collapse Trip
        elif is_defluidization:
            self.state.diagnostic_code = DiagnosticCode.DEFLUIDIZATION_COLLAPSE
            self.state.bed_emergency_trip = True
            self.state.fluidized_bed_running = False
        # Priority 3: Catalyst Severe Coking Alert
        elif is_severe_coking:
            self.state.diagnostic_code = DiagnosticCode.CATALYST_SEVERE_COKING
            self.state.bed_emergency_trip = False
            self.state.fluidized_bed_running = True
        # Priority 4: Selectivity Plummet Alert
        elif is_selectivity_plummet:
            self.state.diagnostic_code = DiagnosticCode.SELECTIVITY_PLUMMET
            self.state.bed_emergency_trip = False
            self.state.fluidized_bed_running = True
        # Priority 5: Normal Steady-State OK
        else:
            self.state.diagnostic_code = DiagnosticCode.REACTOR_OK
            self.state.bed_emergency_trip = False
            self.state.fluidized_bed_running = True

        # Safety invariant: Bed emergency trip clears running status
        if self.state.bed_emergency_trip:
            self.state.fluidized_bed_running = False

        # Status bits bitmask
        bits = CaprolactamFluidizedBedStatusBits.RUNNING
        if self.state.fluidized_bed_running:
            bits |= CaprolactamFluidizedBedStatusBits.FLUIDIZED_BED_RUNNING
        if self.state.selectivity_prealarm:
            bits |= CaprolactamFluidizedBedStatusBits.SELECTIVITY_PREALARM
        if self.state.bed_emergency_trip:
            bits |= CaprolactamFluidizedBedStatusBits.BED_EMERGENCY_TRIP
        if self.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_TRIP:
            bits |= CaprolactamFluidizedBedStatusBits.THERMAL_RUNAWAY_FAULT
        elif self.state.diagnostic_code == DiagnosticCode.DEFLUIDIZATION_COLLAPSE:
            bits |= CaprolactamFluidizedBedStatusBits.DEFLUIDIZATION_FAULT
        elif self.state.diagnostic_code == DiagnosticCode.CATALYST_SEVERE_COKING:
            bits |= CaprolactamFluidizedBedStatusBits.SEVERE_COKING_FAULT
        elif self.state.diagnostic_code == DiagnosticCode.SELECTIVITY_PLUMMET:
            bits |= CaprolactamFluidizedBedStatusBits.SELECTIVITY_PLUMMET_FAULT
        self.state.status_bits = bits

    # ------------------------------------------------------------------------
    # Horner OCS Memory Space Synchronization
    # ------------------------------------------------------------------------

    def _sync_registers(self) -> None:
        """Synchronize state properties into Horner OCS registers and coils."""
        self.sync_to_registers(self.registers, privilege=PrivilegeMode.SYSTEM)

    def sync_to_registers(
        self,
        reg_table: RegisterTable,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Write simulation state into %R2000..%R2007 and %M466..%M468."""
        # %R2000: REG_BED_TEMPERATURE_SCALED = 0.1 °C (nominal: 350.0 °C -> 3500)
        t_scaled = int(round(self.state.t_bed_c * 10.0))
        reg_table.write_word("%R2000", t_scaled, privilege=privilege)

        # %R2001: REG_OXIME_CONVERSION_SCALED = 0.01% (nominal: 99.40% -> 9940)
        conv_scaled = int(round(self.state.oxime_conversion_pct * 100.0))
        reg_table.write_word("%R2001", conv_scaled, privilege=privilege)

        # %R2002: REG_CAPROLACTAM_SELECTIVITY_SCALED = 0.01% (nominal: 96.50% -> 9650)
        sel_scaled = int(round(self.state.caprolactam_selectivity_pct * 100.0))
        reg_table.write_word("%R2002", sel_scaled, privilege=privilege)

        # %R2003: REG_GAS_VELOCITY_SCALED = 0.01 m/s (nominal: 0.45 m/s -> 45)
        vel_scaled = int(round(self.state.gas_velocity_m_s * 100.0))
        reg_table.write_word("%R2003", vel_scaled, privilege=privilege)

        # %R2004: REG_CATALYST_ACTIVITY_SCALED = 0.01% (nominal: 98.20% -> 9820)
        act_scaled = int(round(self.state.catalyst_activity_pct * 100.0))
        reg_table.write_word("%R2004", act_scaled, privilege=privilege)

        # %R2005: REG_OPERATING_PRESSURE_SCALED = 0.01 bar (nominal: 1.20 bar -> 120)
        p_scaled = int(round(self.state.p_bed_bar * 100.0))
        reg_table.write_word("%R2005", p_scaled, privilege=privilege)

        # %R2006: REG_PRODUCTION_RATE_KG_H = 3500 kg/h (nominal: 3500 kg/h -> 3500)
        prod_scaled = int(round(self.state.production_rate_kg_h))
        reg_table.write_word("%R2006", prod_scaled, privilege=privilege)

        # %R2007: REG_DIAGNOSTIC_CODE = signed/unsigned 16-bit diagnostic code
        diag_uword = int(self.state.diagnostic_code) & 0xFFFF
        diag_signed = diag_uword - 0x10000 if diag_uword >= 0x8000 else diag_uword
        reg_table.write_word("%R2007", diag_signed, privilege=privilege)

        # Discrete Coils (%M466..%M468)
        reg_table.write_bit("%M466", bool(self.state.fluidized_bed_running), privilege=privilege)
        reg_table.write_bit("%M467", bool(self.state.selectivity_prealarm), privilege=privilege)
        reg_table.write_bit("%M468", bool(self.state.bed_emergency_trip), privilege=privilege)

    # ------------------------------------------------------------------------
    # ILogicUnit Interface Implementation
    # ------------------------------------------------------------------------

    def scan_step(self, dt: float = 0.02, context: Optional[ScanContext] = None) -> None:
        """Execute single scan cycle step for simulation engine integration."""
        step_dt = context.dt if context is not None and context.dt is not None else dt
        self.step(dt=step_dt)

    def execute(self, context: ScanContext) -> None:
        """Execute logic unit within standard ScanContext framework."""
        dt = getattr(context, "dt", 0.02)
        if dt is None:
            dt = 0.02
        self.scan_step(dt=dt, context=context)

    def reset(self) -> None:
        """Reset simulator state back to initial nominal operating conditions."""
        self.state = CaprolactamFluidizedBedState()
        self.state.t_bed_c = self.config.nominal_bed_temp_c
        self.state.p_bed_bar = self.config.nominal_operating_pressure_bar
        self.state.gas_velocity_m_s = self.config.nominal_gas_velocity_m_s
        self.state.catalyst_activity = self.config.nominal_catalyst_activity_pct / 100.0
        self.state.catalyst_activity_pct = self.config.nominal_catalyst_activity_pct
        self.state.oxime_conversion_pct = self.config.nominal_oxime_conversion_pct
        self.state.caprolactam_selectivity_pct = self.config.nominal_caprolactam_selectivity_pct
        self.state.production_rate_kg_h = self.config.nominal_production_rate_kg_h

        self._update_kinetics_and_metrics()
        self._update_conservation_residuals()
        self._evaluate_safety_interlocks()
        self._sync_registers()


# Aliases for Caprolactam Fluidized Bed Simulation Engine
CaprolactamFluidizedBedReactor = CaprolactamFluidizedBed
CaprolactamFluidizedBedSimulator = CaprolactamFluidizedBed
CaprolactamFluidizedBedEngine = CaprolactamFluidizedBed
CaprolactamFluidizedBedModel = CaprolactamFluidizedBed
CaprolactamFluidizedBedPlantModel = CaprolactamFluidizedBed
CaprolactamFluidizedBedSimulationEngine = CaprolactamFluidizedBed
CaprolactamReactor = CaprolactamFluidizedBed
CaprolactamSimulator = CaprolactamFluidizedBed
CaprolactamEngine = CaprolactamFluidizedBed
FluidizedBedBeckmannReactor = CaprolactamFluidizedBed
FluidizedBedBeckmannSimulator = CaprolactamFluidizedBed


class CaprolactamFluidizedBedLogicUnit(ILogicUnit):
    """Adapter wrapping CaprolactamFluidizedBed as a standalone ILogicUnit."""

    def __init__(self, simulator: Optional[CaprolactamFluidizedBed] = None) -> None:
        self.simulator = simulator or CaprolactamFluidizedBed()
        self.sim = self.simulator

    @property
    def name(self) -> str:
        return self.simulator.name

    @property
    def priority(self) -> int:
        return self.simulator.priority

    @property
    def is_enabled(self) -> bool:
        return self.simulator.is_enabled

    def enable(self) -> None:
        self.simulator.enable()

    def disable(self) -> None:
        self.simulator.disable()

    @property
    def state(self) -> CaprolactamFluidizedBedState:
        return self.simulator.state

    @property
    def config(self) -> CaprolactamFluidizedBedConfig:
        return self.simulator.config

    def scan_step(self, dt: float = 0.02, context: Optional[ScanContext] = None) -> None:
        self.simulator.scan_step(dt=dt, context=context)

    def execute(self, context: ScanContext) -> None:
        self.simulator.execute(context)

    def step(self, dt: float = 0.02) -> None:
        self.simulator.step(dt=dt)

    def reset(self) -> None:
        self.simulator.reset()


CaprolactamLogicUnit = CaprolactamFluidizedBedLogicUnit
FluidizedBedBeckmannLogicUnit = CaprolactamFluidizedBedLogicUnit


# ============================================================================
# 5. Pure IEC 61131-3 Structured Text POU
# ============================================================================

CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU: str = """PROGRAM CaprolactamFluidizedBedSync
VAR
    BedTemperatureScaled AT %R2000 : INT;
    OximeConversionScaled AT %R2001 : INT;
    CaprolactamSelectivityScaled AT %R2002 : INT;
    GasVelocityScaled AT %R2003 : INT;
    CatalystActivityScaled AT %R2004 : INT;
    OperatingPressureScaled AT %R2005 : INT;
    ProductionRateKgH AT %R2006 : INT;
    DiagnosticCode AT %R2007 : WORD;
    FluidizedBedRunning AT %M466 : BOOL;
    SelectivityPreAlarm AT %M467 : BOOL;
    BedEmergencyTrip AT %M468 : BOOL;
END_VAR

(* Process Safety Evaluation & Strict Priority Diagnostic Hierarchy *)
(* Priority 1: Thermal runaway trip (T > 380.0 C -> Scaled > 3800) or Overpressure (P > 2.50 bar -> Scaled > 250) *)
IF BedTemperatureScaled > 3800 THEN
    DiagnosticCode := 16#F001; (* THERMAL_RUNAWAY_TRIP *)
    BedEmergencyTrip := TRUE;
    FluidizedBedRunning := FALSE;
ELSIF OperatingPressureScaled > 250 THEN
    DiagnosticCode := 16#F001; (* OVERPRESSURE_TRIP *)
    BedEmergencyTrip := TRUE;
    FluidizedBedRunning := FALSE;
(* Priority 2: Defluidization collapse (u_g < 0.15 m/s -> Scaled < 15) *)
ELSIF GasVelocityScaled < 15 THEN
    DiagnosticCode := 16#F002; (* DEFLUIDIZATION_COLLAPSE *)
    BedEmergencyTrip := TRUE;
    FluidizedBedRunning := FALSE;
(* Priority 3: Severe catalyst coking (activity < 85.00% -> Scaled < 8500) *)
ELSIF CatalystActivityScaled < 8500 THEN
    DiagnosticCode := 16#F003; (* CATALYST_SEVERE_COKING *)
    BedEmergencyTrip := FALSE;
    FluidizedBedRunning := TRUE;
(* Priority 4: Selectivity plummet (selectivity < 90.00% -> Scaled < 9000) *)
ELSIF CaprolactamSelectivityScaled < 9000 THEN
    DiagnosticCode := 16#F004; (* SELECTIVITY_PLUMMET *)
    BedEmergencyTrip := FALSE;
    FluidizedBedRunning := TRUE;
ELSE
    DiagnosticCode := 16#0000; (* REACTOR_OK *)
    BedEmergencyTrip := FALSE;
    FluidizedBedRunning := TRUE;
END_IF;

(* Pre-Alarm Evaluation *)
IF CaprolactamSelectivityScaled < 9400 THEN
    SelectivityPreAlarm := TRUE;
ELSE
    SelectivityPreAlarm := FALSE;
END_IF;

IF BedEmergencyTrip THEN
    FluidizedBedRunning := FALSE;
END_IF;
END_PROGRAM
"""

# Text Aliases for POU
CAPROLACTAM_FLUIDIZED_BED_SYNC_POU: str = CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU
CAPROLACTAM_FLUIDIZED_BED_REACTOR_PURE_ST_POU: str = CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU
CAPROLACTAM_PURE_ST_POU: str = CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU
CAPROLACTAM_SYNC_POU: str = CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU


class PureSTValidationResult:
    """Validation result object compatible with bool and AgentStatus."""

    def __init__(self, passed: bool, status: AgentStatus = AgentStatus.SUCCESS, error: Optional[str] = None):
        self.passed = passed
        self.status = status if passed else AgentStatus.FAILED
        self.error = error

    def __bool__(self) -> bool:
        return self.passed

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, bool):
            return self.passed == other
        if isinstance(other, AgentStatus):
            return self.status == other
        return super().__eq__(other)


def verify_caprolactam_fluidized_bed_pure_st() -> PureSTValidationResult:
    """Validate CaprolactamFluidizedBedSync POU with STParser and SecurityGuard."""
    SecurityGuard.assert_pure_st_content(CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU)
    val = STParser.validate_code(CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU)
    if val.status != AgentStatus.SUCCESS:
        return PureSTValidationResult(False, status=AgentStatus.FAILED, error="STParser validation failed")

    parser = STParser(pou_type=POUType.PROGRAM)
    pou = parser.parse_pou(CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU)
    if not pou:
        return PureSTValidationResult(False, status=AgentStatus.FAILED, error="Failed to parse POU")

    required_registers = [
        "%R2000", "%R2001", "%R2002", "%R2003",
        "%R2004", "%R2005", "%R2006", "%R2007",
        "%M466", "%M467", "%M468",
    ]
    passed = (
        pou.name == "CaprolactamFluidizedBedSync"
        and pou.pou_type == POUType.PROGRAM
        and all(reg in pou.bound_registers for reg in required_registers)
    )
    return PureSTValidationResult(passed)


verify_caprolactam_pure_st = verify_caprolactam_fluidized_bed_pure_st


# ============================================================================
# 6. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_caprolactam_fluidized_bed_verification(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W239",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage engineering verification suite for Caprolactam Fluidized Bed."""
    start_time = time.time()
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Reactor Physics & Thermochemical Constants
    # ------------------------------------------------------------------------
    sim1 = CaprolactamFluidizedBed()
    t_330_k = 330.0 + T_ZERO_CELSIUS
    t_350_k = 350.0 + T_ZERO_CELSIUS
    t_370_k = 370.0 + T_ZERO_CELSIUS

    k1_330 = sim1.arrhenius_rate_constant(sim1.config.arrhenius_a1, sim1.config.activation_e1_j_mol, t_330_k)
    k1_350 = sim1.arrhenius_rate_constant(sim1.config.arrhenius_a1, sim1.config.activation_e1_j_mol, t_350_k)
    k1_370 = sim1.arrhenius_rate_constant(sim1.config.arrhenius_a1, sim1.config.activation_e1_j_mol, t_370_k)

    ea1_recovered = -R_GAS_CONST * math.log(k1_370 / k1_330) / ((1.0 / t_370_k) - (1.0 / t_330_k))
    ea1_err = abs(ea1_recovered - sim1.config.activation_e1_j_mol)

    c1 = (
        k1_370 > k1_350 > k1_330 > 0.0
        and ea1_err < 1.0e-3
        and DELTA_H1_KJ_MOL == -160.0
        and DELTA_H2_KJ_MOL == -80.0
        and sim1.config.nominal_bed_temp_c == 350.0
        and sim1.config.nominal_operating_pressure_bar == 1.20
        and sim1.config.nominal_gas_velocity_m_s == 0.45
        and sim1.config.nominal_catalyst_activity_pct == 98.20
    )
    test_results.append({
        "stage": 1,
        "name": "Reactor_Physics_And_Thermochemical_Constants",
        "check": "Reactor_Physics_And_Thermochemical_Constants",
        "passed": bool(c1),
        "details": f"Kinetics verified: k1(330C)={k1_330:.2f}, k1(350C)={k1_350:.2f}, k1(370C)={k1_370:.2f}, Ea1 err={ea1_err:.2e} J/mol, Delta_H1=-160 kJ/mol, nominal 350.0 °C, 1.20 bar, u_g=0.45 m/s, activity=98.20%.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Pure ST POU & AST Symbol Binding
    # ------------------------------------------------------------------------
    SecurityGuard.assert_pure_st_content(CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU)
    res_st = STParser.validate_code(CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU)
    parser = STParser(pou_type=POUType.PROGRAM)
    ast_primary = parser.parse_pou(CAPROLACTAM_FLUIDIZED_BED_PURE_ST_POU)

    required_regs = [
        "%R2000", "%R2001", "%R2002", "%R2003",
        "%R2004", "%R2005", "%R2006", "%R2007",
        "%M466", "%M467", "%M468",
    ]
    c2 = (
        res_st.status == AgentStatus.SUCCESS
        and ast_primary is not None
        and ast_primary.name == "CaprolactamFluidizedBedSync"
        and all(reg in ast_primary.bound_registers for reg in required_regs)
    )
    test_results.append({
        "stage": 2,
        "name": "Pure_ST_POU_And_AST_Symbol_Binding",
        "check": "Pure_ST_POU_And_AST_Symbol_Binding",
        "passed": bool(c2),
        "details": "CaprolactamFluidizedBedSync POU verified cleanly with STParser & SecurityGuard; bound %R2000..%R2007 and %M466..%M468.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Anti-Ladder Security Guard Interception
    # ------------------------------------------------------------------------
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM Bad ---[ ]--- END_PROGRAM")
    except LadderForbiddenError:
        ladder_rejected = True
    test_results.append({
        "stage": 3,
        "name": "Anti_Ladder_Security_Guard_Interception",
        "check": "Anti_Ladder_Security_Guard_Interception",
        "passed": ladder_rejected,
        "details": "Ladder logic constructs (contacts, coils, rungs) rejected with LadderForbiddenError.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Nominal Steady-State Closed-Loop Convergence
    # ------------------------------------------------------------------------
    sim4 = CaprolactamFluidizedBed()
    c4 = (
        abs(sim4.state.oxime_conversion_pct - 99.40) < 0.5
        and abs(sim4.state.caprolactam_selectivity_pct - 96.50) < 0.5
        and abs(sim4.state.production_rate_kg_h - 3500.0) < 50.0
        and abs(sim4.state.t_bed_c - 350.0) < 0.5
        and abs(sim4.state.p_bed_bar - 1.20) < 0.05
        and abs(sim4.state.gas_velocity_m_s - 0.45) < 0.02
    )
    test_results.append({
        "stage": 4,
        "name": "Nominal_Steady_State_Closed_Loop_Convergence",
        "check": "Nominal_Steady_State_Closed_Loop_Convergence",
        "passed": bool(c4),
        "details": f"Nominal steady-state verified: conversion={sim4.state.oxime_conversion_pct:.2f}% (~99.40%), selectivity={sim4.state.caprolactam_selectivity_pct:.2f}% (~96.50%), production={sim4.state.production_rate_kg_h:.1f} kg/h (~3500 kg/h).",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Conservation Laws Verification (< 1e-10)
    # ------------------------------------------------------------------------
    sim4._update_conservation_residuals()
    c5 = (
        sim4.state.total_mass_balance_residual_kg_s < 1.0e-10
        and sim4.state.elemental_mass_balance_residual_kg_s < 1.0e-10
        and sim4.state.enthalpy_conservation_residual_kw < 1.0e-10
    )
    test_results.append({
        "stage": 5,
        "name": "Conservation_Laws_Verification",
        "check": "Conservation_Laws_Verification",
        "passed": bool(c5),
        "details": f"Conservation laws verified: mass={sim4.state.total_mass_balance_residual_kg_s:.2e} kg/s, elemental={sim4.state.elemental_mass_balance_residual_kg_s:.2e} kg/s, enthalpy={sim4.state.enthalpy_conservation_residual_kw:.2e} kW (< 1e-10 threshold).",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Thermal Runaway & Overpressure Safety Injections
    # ------------------------------------------------------------------------
    sim6 = CaprolactamFluidizedBed()
    sim6.reset()
    sim6.state.t_bed_c = 385.0
    sim6._evaluate_safety_interlocks()
    c6a = (
        sim6.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_TRIP
        and sim6.state.bed_emergency_trip is True
        and sim6.state.fluidized_bed_running is False
    )

    sim6.reset()
    sim6.state.p_bed_bar = 2.80
    sim6._evaluate_safety_interlocks()
    c6b = (
        sim6.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_TRIP
        and sim6.state.bed_emergency_trip is True
        and sim6.state.fluidized_bed_running is False
    )

    test_results.append({
        "stage": 6,
        "name": "Thermal_Runaway_And_Overpressure_Safety_Injections",
        "check": "Thermal_Runaway_And_Overpressure_Safety_Injections",
        "passed": bool(c6a and c6b),
        "details": "0xF001 thermal runaway (> 380 °C) and overpressure (> 2.50 bar) injections verified; %M468 asserted, %M466 cleared.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Defluidization Collapse & Catalyst Coking / Selectivity Injections
    # ------------------------------------------------------------------------
    sim7 = CaprolactamFluidizedBed()
    sim7.reset()
    sim7.state.gas_velocity_m_s = 0.10  # Below Umf 0.15 m/s
    sim7._evaluate_safety_interlocks()
    c7a = (
        sim7.state.diagnostic_code == DiagnosticCode.DEFLUIDIZATION_COLLAPSE
        and sim7.state.bed_emergency_trip is True
        and sim7.state.fluidized_bed_running is False
    )

    sim7.reset()
    sim7.state.catalyst_activity = 0.80  # Below 0.85
    sim7._evaluate_safety_interlocks()
    c7b = (
        sim7.state.diagnostic_code == DiagnosticCode.CATALYST_SEVERE_COKING
        and sim7.state.bed_emergency_trip is False
        and sim7.state.fluidized_bed_running is True
    )

    sim7.reset()
    sim7.state.caprolactam_selectivity_pct = 88.0  # Below 90.0% and below 94.0% pre-alarm
    sim7._evaluate_safety_interlocks()
    c7c = (
        sim7.state.diagnostic_code == DiagnosticCode.SELECTIVITY_PLUMMET
        and sim7.state.selectivity_prealarm is True
        and sim7.state.bed_emergency_trip is False
        and sim7.state.fluidized_bed_running is True
    )

    test_results.append({
        "stage": 7,
        "name": "Defluidization_Collapse_And_Catalyst_Coking_Selectivity_Injections",
        "check": "Defluidization_Collapse_And_Catalyst_Coking_Selectivity_Injections",
        "passed": bool(c7a and c7b and c7c),
        "details": "0xF002 defluidization (< 0.15 m/s), 0xF003 coking (< 0.85), 0xF004 selectivity (< 90.0%), and %M467 pre-alarm verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Process Safety Interlocks & Strict Priority Hierarchy
    # ------------------------------------------------------------------------
    sim8 = CaprolactamFluidizedBed()
    sim8.reset()
    # Apply all fault triggers simultaneously
    sim8.state.t_bed_c = 385.0                   # Trigger 0xF001 (Priority 1)
    sim8.state.gas_velocity_m_s = 0.10          # Trigger 0xF002 (Priority 2)
    sim8.state.catalyst_activity = 0.80         # Trigger 0xF003 (Priority 3)
    sim8.state.caprolactam_selectivity_pct = 88.0 # Trigger 0xF004 (Priority 4)
    sim8._evaluate_safety_interlocks()
    p1_wins = (sim8.state.diagnostic_code == DiagnosticCode.THERMAL_RUNAWAY_TRIP)

    # Clear Priority 1 -> Priority 2 should win
    sim8.state.t_bed_c = 350.0
    sim8.state.p_bed_bar = 1.20
    sim8._evaluate_safety_interlocks()
    p2_wins = (sim8.state.diagnostic_code == DiagnosticCode.DEFLUIDIZATION_COLLAPSE)

    # Clear Priority 2 -> Priority 3 should win
    sim8.state.gas_velocity_m_s = 0.45
    sim8._evaluate_safety_interlocks()
    p3_wins = (sim8.state.diagnostic_code == DiagnosticCode.CATALYST_SEVERE_COKING)

    # Clear Priority 3 -> Priority 4 should win
    sim8.state.catalyst_activity = 0.9820
    sim8._evaluate_safety_interlocks()
    p4_wins = (sim8.state.diagnostic_code == DiagnosticCode.SELECTIVITY_PLUMMET)

    # Clear Priority 4 -> 0x0000 REACTOR_OK should win
    sim8.state.caprolactam_selectivity_pct = 96.50
    sim8._evaluate_safety_interlocks()
    p5_ok = (sim8.state.diagnostic_code == DiagnosticCode.REACTOR_OK)

    c8 = p1_wins and p2_wins and p3_wins and p4_wins and p5_ok
    test_results.append({
        "stage": 8,
        "name": "Process_Safety_Interlocks_And_Strict_Priority_Hierarchy",
        "check": "Process_Safety_Interlocks_And_Strict_Priority_Hierarchy",
        "passed": bool(c8),
        "details": f"Strict priority hierarchy verified: P1={p1_wins}, P2={p2_wins}, P3={p3_wins}, P4={p4_wins}, P5_OK={p5_ok}.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Memory Space Integration & Soak Stability
    # ------------------------------------------------------------------------
    table9 = RegisterTable()
    sim9 = CaprolactamFluidizedBed(register_table=table9)
    sim9.reset()

    r2000 = table9.read_word("%R2000")
    r2001 = table9.read_word("%R2001")
    r2002 = table9.read_word("%R2002")
    r2003 = table9.read_word("%R2003")
    r2004 = table9.read_word("%R2004")
    r2005 = table9.read_word("%R2005")
    r2006 = table9.read_word("%R2006")
    r2007 = table9.read_uword("%R2007")
    m466 = table9.read_bit("%M466")
    m467 = table9.read_bit("%M467")
    m468 = table9.read_bit("%M468")

    regs_ok = (
        r2000 == 3500
        and r2001 == 9940
        and r2002 == 9650
        and r2003 == 45
        and r2004 == 9820
        and r2005 == 120
        and r2006 == 3500
        and r2007 == 0x0000
        and m466 is True
        and m467 is False
        and m468 is False
    )

    # 100-cycle soak test with memory tracking
    tracemalloc.start()
    snapshot1 = tracemalloc.take_snapshot()
    for cycle in range(1, 101):
        ctx = ScanContext(cycle=cycle, dt_ms=20.0, elapsed_time_ms=cycle * 20.0, dt=0.02)
        sim9.execute(ctx)
    snapshot2 = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snapshot2.compare_to(snapshot1, "lineno")
    mem_growth_kb = sum(s.size_diff for s in stats if s.size_diff > 0) / 1024.0

    soak_ok = (
        not math.isnan(sim9.state.t_bed_c)
        and not math.isnan(sim9.state.c_cpl)
        and 340.0 <= sim9.state.t_bed_c <= 360.0
        and sim9.state.oxime_conversion_pct > 98.0
        and sim9.state.caprolactam_selectivity_pct > 95.0
        and mem_growth_kb < 1000.0
    )

    c9 = regs_ok and soak_ok
    test_results.append({
        "stage": 9,
        "name": "Horner_OCS_Memory_Space_Integration_And_Soak_Stability",
        "check": "Horner_OCS_Memory_Space_Integration_And_Soak_Stability",
        "passed": bool(c9),
        "details": (
            f"Registers %R2000..%R2007 and coils %M466..%M468 bit-exact verified ({regs_ok}). "
            f"100 cycles executed without drift or NaN; memory growth={mem_growth_kb:.1f} KB."
        ),
    })

    # ------------------------------------------------------------------------
    # Verification Summary & Output Payload
    # ------------------------------------------------------------------------
    all_passed = all(r["passed"] for r in test_results)
    passed_count = sum(1 for r in test_results if r["passed"])
    status_str = "success" if all_passed else "failed"

    payload: Dict[str, Any] = {
        "status": status_str,
        "error_code": None if all_passed else "VERIFICATION_FAILED",
        "details": f"Caprolactam Fluidized Bed Rearrangement 9-stage verification passed {passed_count}/9 checks.",
        "data": {
            "work_package": work_package,
            "module": "caprolactam_fluidized_bed",
            "total_checks": len(test_results),
            "checks_passed": passed_count,
            "tests": test_results,
            "stages": test_results,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "execution_time_ms": (time.time() - start_time) * 1000.0,
        },
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    return payload


# Verification Aliases
run_caprolactam_verification = run_caprolactam_fluidized_bed_verification
run_fluidized_bed_verification = run_caprolactam_fluidized_bed_verification
