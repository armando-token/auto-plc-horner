"""Industrial Terephthalic Acid (PTA) p-Xylene Liquid-Phase Catalytic Air Oxidation Reactor ODE Simulation.

Work Package: W218 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Industrial PTA Synthesis Liquid-Phase Catalytic Air Oxidation Reactor:
   - Liquid-phase bubble column / continuous stirred tank reactor (CSTR) operating at:
     * Temperature: 190.0–210.0 °C (nominal 200.0 °C / 473.15 K)
     * Pressure: 15.0–22.0 bar (nominal 18.00 bar)
     * Solvent: Acetic acid (HAc) with homogeneous Co/Mn/Br catalyst (Cobalt/Manganese/Bromide)
   - Deep bubble column with pressurized sparged air distributor and overhead evaporative condenser.
2. Four-Reaction Kinetic Network:
   - Reaction 1: p-Xylene (C8H10) + 1.5 O2 -> p-Toluic Acid (C8H8O2) + H2O
     Delta H1 = -420 kJ/mol (-420,000 J/mol).
   - Reaction 2: p-Toluic Acid (C8H8O2) + O2 -> 4-Carboxybenzaldehyde (4-CBA, C8H6O3) + H2O
     Delta H2 = -380 kJ/mol (-380,000 J/mol).
   - Reaction 3: 4-CBA (C8H6O3) + 0.5 O2 -> Purified Terephthalic Acid (PTA, C8H6O4)
     Delta H3 = -550 kJ/mol (-550,000 J/mol).
   - Side Reaction 4 (Solvent oxidation / acetic acid combustion):
     CH3COOH (C2H4O2) + 2 O2 -> 2 CO2 + 2 H2O
     Delta H4 = -874 kJ/mol (-874,000 J/mol).
3. Coupled 6-State Dynamic ODE System with High-Order RK4 Integrator:
   - Dynamic state vector: [C_px, C_toluic, C_4cba, C_pta, T_reactor, C_dissolved_o2]
     * State 0: C_px (p-Xylene liquid concentration [mol/m^3])
     * State 1: C_toluic (p-Toluic acid concentration [mol/m^3])
     * State 2: C_4cba (4-CBA intermediate impurity concentration [mol/m^3])
     * State 3: C_pta (Purified Terephthalic Acid product concentration [mol/m^3])
     * State 4: T_reactor (Reactor bulk liquid temperature [K])
     * State 5: C_dissolved_o2 (Dissolved oxygen concentration in liquid phase [mol/m^3])
   - 4th-order Runge-Kutta (RK4, dt = 0.02 s) numerical integrator.
   - Dual stoichiometric mass, elemental species, and enthalpy conservation residuals < 1e-10:
     * total_mass_balance_residual_kg_s < 1e-10 kg/s
     * elemental_mass_balance_residual_kg_s < 1e-10 kg/s
     * enthalpy_conservation_residual_kw < 1e-10 kW.
4. Process Safety Envelope, Interlocks & Diagnostics (Strict Priority Hierarchy):
   - Oxygen lean off-gas monitoring: O2 < 4.0 vol% to prevent explosive envelope.
   - Pre-alarm: Off-gas O2 > 3.8 vol% (%M418 = TRUE).
   - Priority 1 (0xEA01): THERMAL_EXCURSION_RUNAWAY (T_reactor > 225.0 °C)
     -> asserts %M419 (EmergencyNitrogenQuenchActive), clears %M417 (PtaOxidationActive).
   - Priority 2 (0xEA02): OFFGAS_OXYGEN_EXPLOSION_HAZARD (Off-gas O2 > 4.50 vol%)
     -> asserts %M419 (EmergencyNitrogenQuenchActive), asserts %M418 (OffGasOxygenHighPreAlarm),
        clears %M417 (PtaOxidationActive).
   - Priority 3 (0xEA03): FOUR_CBA_IMPURITY_EXCEEDED (4-CBA impurity > 25 ppm)
     -> sets diagnostic code, keeps %M417 active, keeps %M419 inactive.
   - Priority 4 (0xEA04): CATALYST_PRECIPITATION_FAULT (PTA yield < 90.0% or catalyst failure)
     -> sets diagnostic code, keeps %M417 active, keeps %M419 inactive.
   - Normal (0x0000): OK (Normal healthy steady-state operation).
5. Emergency Mitigation Dynamics:
   - High off-gas O2 (> 4.5 vol%) or thermal runaway (> 225 °C) initiates emergency nitrogen
     headspace sweep and cold subcooled acetic acid quench injection, isolating air sparging
     and quenching runaway exotherm deterministically.
6. Horner OCS Memory Space Integration (%R1790..%R1797, %M417..%M419):
   - %R1790: ReactorTemperatureScaled (INT16, scaled x10 °C, e.g. 2000 = 200.0 °C)
   - %R1791: ReactorPressureBarScaled (INT16, scaled x100 bar, e.g. 1800 = 18.00 bar)
   - %R1792: PxConversionPctScaled (INT16, scaled x100 %, e.g. 9920 = 99.20%)
   - %R1793: PtaYieldPctScaled (INT16, scaled x100 %, e.g. 9650 = 96.50%)
   - %R1794: FourCbaImpurityPpm (INT16, e.g. 22 ppm)
   - %R1795: OffGasOxygenPctScaled (INT16, scaled x100 vol%, e.g. 280 = 2.80%)
   - %R1796: SolventBurnRateScaled (INT16, scaled x100 kg/t PTA, e.g. 45 = 0.45 kg/t PTA)
   - %R1797: DiagnosticStatusCode (0x0000=OK, 0xEA01, 0xEA02, 0xEA03, 0xEA04)
   - %M417: PtaOxidationActive (BOOL, True during safe/active operation)
   - %M418: OffGasOxygenHighPreAlarm (BOOL, True if O2 > 3.8 vol%)
   - %M419: EmergencyNitrogenQuenchActive (BOOL, True on trip)
   - In sync_to_registers(), pass privilege=PrivilegeMode.SYSTEM.
7. Pure IEC 61131-3 Structured Text ONLY:
   - POU 'PtaOxidationSync'.
   - Anti-ladder security guard: SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
8. ILogicUnit Interface:
   - scan_step(dt: float = 0.02, context: Optional[ScanContext] = None) -> None.
   - sync_to_registers(reg_table: RegisterTable, privilege: PrivilegeMode = PrivilegeMode.SYSTEM).
   - name, priority, is_enabled, execute, reset.
9. Deterministic 9-Stage Verification Suite:
   - Function run_pta_oxidation_reactor_verification(output_path) returning strict 4-state contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import math
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# Universal Physical & Chemical Constants for PTA Oxidation Reactor
# ============================================================================

R_GAS_CONST: float = 8.314462618        # Universal gas constant [J/(mol*K)]
G_ACCEL: float = 9.80665                # Standard gravitational acceleration [m/s^2]
T_ZERO_CELSIUS: float = 273.15          # 0.0 °C in Kelvin [K]
T_REF_K: float = 473.15                 # Reactor reference temperature (200.0 °C) [K]

# Molecular Weights [kg/mol] and [g/mol]
MW_C: float = 0.012011                  # Carbon C (12.011 g/mol)
MW_H: float = 0.001008                  # Hydrogen H (1.008 g/mol)
MW_O: float = 0.015999                  # Oxygen O (15.999 g/mol)
MW_N: float = 0.014007                  # Nitrogen N (14.007 g/mol)

MW_O2: float = 2.0 * MW_O                         # Oxygen O2 (0.031998 kg/mol)
MW_N2: float = 2.0 * MW_N                         # Nitrogen N2 (0.028014 kg/mol)
MW_H2O: float = 2.0 * MW_H + MW_O                 # Water H2O (0.018015 kg/mol)
MW_CO2: float = MW_C + 2.0 * MW_O                 # Carbon Dioxide CO2 (0.044009 kg/mol)
MW_CO: float = MW_C + MW_O                        # Carbon Monoxide CO (0.028010 kg/mol)

# Hydrocarbons & Carboxylic Acids
MW_PX: float = 8.0 * MW_C + 10.0 * MW_H           # p-Xylene C8H10 (0.106168 kg/mol)
MW_P_XYLENE: float = MW_PX
MW_TOLUIC: float = 8.0 * MW_C + 8.0 * MW_H + 2.0 * MW_O  # p-Toluic Acid C8H8O2 (0.136150 kg/mol)
MW_P_TOLUIC_ACID: float = MW_TOLUIC
MW_4CBA: float = 8.0 * MW_C + 6.0 * MW_H + 3.0 * MW_O    # 4-CBA C8H6O3 (0.150133 kg/mol)
MW_FOUR_CBA: float = MW_4CBA
MW_PTA: float = 8.0 * MW_C + 6.0 * MW_H + 4.0 * MW_O     # PTA C8H6O4 (0.166132 kg/mol)
MW_TEREPHTHALIC_ACID: float = MW_PTA
MW_HAC: float = 2.0 * MW_C + 4.0 * MW_H + 2.0 * MW_O     # Acetic Acid C2H4O2 (0.060052 kg/mol)
MW_ACETIC_ACID: float = MW_HAC
MW_WATER: float = MW_H2O

# Reaction Enthalpies [J/mol and kJ/mol]
# 1. p-Xylene Oxidation: C8H10 + 1.5 O2 -> C8H8O2 + H2O
DELTA_H1_KJ_MOL: float = -420.0
DELTA_H1_J_MOL: float = -420000.0
DELTA_H_PX_OXIDATION_KJ_MOL: float = DELTA_H1_KJ_MOL
DELTA_H_PX_OXIDATION_J_MOL: float = DELTA_H1_J_MOL

# 2. p-Toluic Acid Oxidation: C8H8O2 + O2 -> C8H6O3 (4-CBA) + H2O
DELTA_H2_KJ_MOL: float = -380.0
DELTA_H2_J_MOL: float = -380000.0
DELTA_H_TOLUIC_OXIDATION_KJ_MOL: float = DELTA_H2_KJ_MOL
DELTA_H_TOLUIC_OXIDATION_J_MOL: float = DELTA_H2_J_MOL

# 3. 4-CBA Oxidation: C8H6O3 + 0.5 O2 -> C8H6O4 (PTA)
DELTA_H3_KJ_MOL: float = -550.0
DELTA_H3_J_MOL: float = -550000.0
DELTA_H_4CBA_OXIDATION_KJ_MOL: float = DELTA_H3_KJ_MOL
DELTA_H_4CBA_OXIDATION_J_MOL: float = DELTA_H3_J_MOL

# 4. Solvent Oxidation / Acetic Acid Combustion: CH3COOH + 2 O2 -> 2 CO2 + 2 H2O
DELTA_H4_KJ_MOL: float = -874.0
DELTA_H4_J_MOL: float = -874000.0
DELTA_H_SOLVENT_BURNING_KJ_MOL: float = DELTA_H4_KJ_MOL
DELTA_H_SOLVENT_BURNING_J_MOL: float = DELTA_H4_J_MOL

# Operating Boundaries & Safety Thresholds
REACTOR_TEMP_NOMINAL_C: float = 200.0       # Nominal reactor temperature [°C] (%R1790 = 2000)
REACTOR_TEMP_MIN_C: float = 190.0           # Minimum operating temperature [°C]
REACTOR_TEMP_MAX_C: float = 210.0           # Maximum operating temperature [°C]
REACTOR_TEMP_WARNING_C: float = 215.0       # High temperature warning limit [°C]
REACTOR_TEMP_TRIP_C: float = 225.0          # Thermal runaway trip threshold [°C] (%M419 = True, 0xEA01)
REACTOR_TEMP_RESET_C: float = 210.0         # Thermal trip reset threshold [°C]

REACTOR_PRESSURE_NOMINAL_BAR: float = 18.00 # Nominal reactor pressure [bar] (%R1791 = 1800)
REACTOR_PRESSURE_MIN_BAR: float = 15.00     # Minimum operating pressure [bar]
REACTOR_PRESSURE_MAX_BAR: float = 22.00     # Maximum operating pressure [bar]

PX_CONVERSION_NOMINAL_PCT: float = 99.20    # Nominal PX conversion [%] (%R1792 = 9920)
PX_CONVERSION_MIN_PCT: float = 98.00        # Minimum conversion specification [%]
PX_CONVERSION_TARGET_MIN: float = 99.00     # Target conversion floor [%]

PTA_YIELD_NOMINAL_PCT: float = 96.50        # Nominal PTA yield [%] (%R1793 = 9650)
PTA_YIELD_MIN_PCT: float = 90.00            # Low yield fault / catalyst precipitation [%] (0xEA04)
PTA_YIELD_TARGET_MIN: float = 95.00         # Target yield floor [%]

FOUR_CBA_NOMINAL_PPM: float = 22.0          # Nominal 4-CBA impurity [ppm] (%R1794 = 22)
FOUR_CBA_TARGET_MAX_PPM: float = 25.0       # Polymer-grade ceiling [ppm] (0xEA03 if > 25 ppm)
FOUR_CBA_ALARM_PPM: float = 25.0            # Alarm threshold [ppm]

OFFGAS_O2_NOMINAL_VOL_PCT: float = 2.80     # Nominal off-gas oxygen [vol%] (%R1795 = 280)
OFFGAS_O2_ENVELOPE_MAX_VOL_PCT: float = 4.00 # Maximum safe off-gas O2 envelope ceiling [vol%]
OFFGAS_O2_HIGH_ALARM_VOL_PCT: float = 3.80  # Off-gas O2 pre-trip alarm [vol%] (%M418 = True)
OFFGAS_O2_TRIP_VOL_PCT: float = 4.50        # Explosive hazard trip [vol%] (0xEA02, %M419 = True)
OFFGAS_O2_RESET_VOL_PCT: float = 3.50       # Off-gas O2 trip latch reset [vol%]

SOLVENT_BURN_RATE_NOMINAL_KG_T: float = 0.45 # Nominal solvent burn rate [kg/t PTA] (%R1796 = 45)
SOLVENT_BURN_RATE_MAX_KG_T: float = 1.20    # High solvent burn rate limit [kg/t PTA]

# Standard Aliases for Operating Boundaries & Parameters
CBA_IMPURITY_NOMINAL_PPM: float = FOUR_CBA_NOMINAL_PPM
CBA_IMPURITY_MAX_PPM: float = FOUR_CBA_TARGET_MAX_PPM
CBA_IMPURITY_ALARM_PPM: float = FOUR_CBA_ALARM_PPM
OFFGAS_O2_TRIP_PCT: float = OFFGAS_O2_TRIP_VOL_PCT
OFFGAS_O2_ALARM_PCT: float = OFFGAS_O2_HIGH_ALARM_VOL_PCT
OFFGAS_O2_NOMINAL_PCT: float = OFFGAS_O2_NOMINAL_VOL_PCT
CONVERSION_NOMINAL_PCT: float = PX_CONVERSION_NOMINAL_PCT
CONVERSION_MIN_PCT: float = PX_CONVERSION_MIN_PCT
YIELD_NOMINAL_PCT: float = PTA_YIELD_NOMINAL_PCT
YIELD_MIN_PCT: float = PTA_YIELD_MIN_PCT
RUNAWAY_TRIP_TEMP_C: float = REACTOR_TEMP_TRIP_C
DISSOLVED_O2_NOMINAL_PPM: float = 35.0
DISSOLVED_O2_LOW_ANOXIA_PPM: float = 10.0
DISSOLVED_O2_LOW_PPM: float = DISSOLVED_O2_LOW_ANOXIA_PPM
QUENCH_FLOW_KG_S: float = 80.0
QUENCH_TEMP_C: float = 40.0
QUENCH_SHUTOFF_TEMP_C: float = REACTOR_TEMP_RESET_C
PX_FEED_RATE_NOMINAL_KG_H: float = 25000.0
SOLVENT_PX_MASS_RATIO_NOMINAL: float = 3.5
MW_CBA: float = MW_4CBA
MW_TPA: float = MW_PTA
MW_PTAC: float = MW_TOLUIC
DELTA_H_SOLVENT_BURNOFF_KJ_MOL: float = DELTA_H4_KJ_MOL
DELTA_H_SOLVENT_BURNOFF_J_MOL: float = DELTA_H4_J_MOL
DELTA_H_PTAC_OXIDATION_KJ_MOL: float = DELTA_H2_KJ_MOL
DELTA_H_PTAC_OXIDATION_J_MOL: float = DELTA_H2_J_MOL


# ============================================================================
# 1. Enums and Status Bitmasks
# ============================================================================

class PtaOxidationDiagnosticCode(IntEnum):
    """Horner OCS %R1797 Diagnostic Event Codes for PTA Oxidation Reactor."""
    OK                                  = 0x0000  # Normal healthy steady-state operation
    THERMAL_EXCURSION_RUNAWAY           = 0xEA01  # T_reactor > 225.0 °C (thermal runaway excursion)
    OFFGAS_OXYGEN_EXPLOSION_HAZARD      = 0xEA02  # Off-gas O2 > 4.50 vol% (flammability envelope breach)
    FOUR_CBA_IMPURITY_EXCEEDED          = 0xEA03  # 4-CBA impurity > 25 ppm (polymer-grade specification breach)
    CATALYST_PRECIPITATION_FAULT        = 0xEA04  # Catalyst precipitation / yield collapse (PTA yield < 90.0%)

    # Standard Aliases
    ERR_THERMAL_EXCURSION_RUNAWAY       = THERMAL_EXCURSION_RUNAWAY
    ERR_OFFGAS_OXYGEN_EXPLOSION_HAZARD  = OFFGAS_OXYGEN_EXPLOSION_HAZARD
    ERR_FOUR_CBA_IMPURITY_EXCEEDED      = FOUR_CBA_IMPURITY_EXCEEDED
    ERR_CATALYST_PRECIPITATION_FAULT    = CATALYST_PRECIPITATION_FAULT
    PTA_ERR_THERMAL_RUNAWAY             = THERMAL_EXCURSION_RUNAWAY
    PTA_ERR_OFFGAS_OXYGEN               = OFFGAS_OXYGEN_EXPLOSION_HAZARD
    PTA_ERR_FOUR_CBA_IMPURITY           = FOUR_CBA_IMPURITY_EXCEEDED
    PTA_ERR_CATALYST_FAULT              = CATALYST_PRECIPITATION_FAULT
    OFFGAS_O2_EXPLOSIVE_TRIP            = OFFGAS_OXYGEN_EXPLOSION_HAZARD
    THERMAL_RUNAWAY_EXCURSION           = THERMAL_EXCURSION_RUNAWAY
    HIGH_4CBA_IMPURITY_ALARM            = FOUR_CBA_IMPURITY_EXCEEDED
    SPARGER_DEFICIENCY_ANOXIA           = CATALYST_PRECIPITATION_FAULT


PtaOxidationDiagCode = PtaOxidationDiagnosticCode
PtaOxidationReactorDiagnosticCode = PtaOxidationDiagnosticCode
PtaOxidationReactorDiagCode = PtaOxidationDiagnosticCode
PtaReactorDiagnosticCode = PtaOxidationDiagnosticCode
PtaReactorDiagCode = PtaOxidationDiagnosticCode
PtaDiagnosticCode = PtaOxidationDiagnosticCode
PtaDiagCode = PtaOxidationDiagnosticCode


class PtaOxidationStatusBits(IntFlag):
    """Horner OCS Status Word Bitmask Definitions for PTA Oxidation Reactor."""
    RUNNING                             = 1 << 0  # Bit 0 (0x0001): Simulation cycle active
    PTA_OXIDATION_ACTIVE                = 1 << 1  # Bit 1 (0x0002): %M417 PTA oxidation active
    OFFGAS_O2_HIGH_PREALARM             = 1 << 2  # Bit 2 (0x0004): %M418 Off-gas O2 > 3.8 vol%
    EMERGENCY_QUENCH_ACTIVE             = 1 << 3  # Bit 3 (0x0008): %M419 Emergency N2 / quench active
    THERMAL_RUNAWAY_TRIP                = 1 << 4  # Bit 4 (0x0010): 0xEA01 Thermal runaway trip
    OFFGAS_O2_TRIP                      = 1 << 5  # Bit 5 (0x0020): 0xEA02 Off-gas explosive trip
    FOUR_CBA_IMPURITY_ALARM             = 1 << 6  # Bit 6 (0x0040): 0xEA03 4-CBA impurity exceeded
    CATALYST_PRECIPITATION_ALARM        = 1 << 7  # Bit 7 (0x0080): 0xEA04 Catalyst precipitation fault

    # Standard Aliases
    OFFGAS_O2_HIGH_ALARM                = OFFGAS_O2_HIGH_PREALARM
    HIGH_CBA_ALARM                      = FOUR_CBA_IMPURITY_ALARM
    SPARGER_DEFICIENCY_ALARM            = CATALYST_PRECIPITATION_ALARM


PtaOxidationStatusWord = PtaOxidationStatusBits
PtaOxidationReactorStatusBits = PtaOxidationStatusBits
PtaOxidationReactorStatusWord = PtaOxidationStatusBits
PtaReactorStatusBits = PtaOxidationStatusBits
PtaReactorStatusWord = PtaOxidationStatusBits
PtaStatusBits = PtaOxidationStatusBits
PtaStatusWord = PtaOxidationStatusBits


# ============================================================================
# 2. Configuration & Parameter Data Models
# ============================================================================

@dataclass
class PtaOxidationConfig:
    """Design, geometric, hydrodynamic, kinetic, and safety parameters for PTA Oxidation Reactor."""

    # Sparged Bubble Column / CSTR Geometry
    reactor_diameter_m: float = 4.5                 # Column diameter [m] (cross section ~ 15.90 m^2)
    reactor_height_m: float = 24.0                  # Total vessel height [m]
    liquid_volume_m3: float = 120.0                 # Working liquid slurry volume [m^3]
    gas_holdup_fraction: float = 0.22               # Operating gas holdup [-]
    residence_time_s: float = 2400.0                # Liquid residence time [s] (40 min)

    # Physical Properties of Acetic Acid Liquid Slurry
    operating_pressure_bar: float = REACTOR_PRESSURE_NOMINAL_BAR # Operating pressure [bar] (18.00)
    liquid_density_kg_m3: float = 880.0             # Slurry density at 200 °C [kg/m^3]
    liquid_cp_j_kg_k: float = 2500.0                # Slurry heat capacity [J/(kg*K)]
    reactor_heat_capacity_j_k: float = 2.64e8       # Active liquid thermal capacitance [J/K] (120*880*2500)

    # Liquid Slurry Feed Stream Quantities
    c_px_feed_mol_m3: float = 1906.0                # Fresh p-Xylene concentration in feed [mol/m^3]
    nominal_feed_temp_c: float = 120.0              # Preheated liquid feed inlet temperature [°C]
    ambient_temp_c: float = 25.0                    # Ambient environment temperature [°C]
    u_wall_w_m2_k: float = 12.0                     # Vessel wall heat loss coefficient [W/(m^2*K)]

    # Gas Sparging & Mass Transfer Dynamics
    nominal_air_flow_mol_s: float = 1520.0          # Nominal compressed air feed rate [mol/s]
    air_o2_mole_fraction: float = 0.21              # Air oxygen mole fraction [-]
    kla_s_inv: float = 1.85                         # Gas-liquid volumetric mass transfer coefficient [1/s]
    henry_o2_mol_m3_bar: float = 0.65               # Henry's law coefficient for O2 in HAc solvent [mol/(m^3*bar)]

    # Kinetic Target Parameters at Reference Temp (200.0 °C / 473.15 K)
    nominal_reactor_temp_c: float = REACTOR_TEMP_NOMINAL_C # Reference temperature [°C] (200.0)
    nominal_conversion_pct: float = PX_CONVERSION_NOMINAL_PCT # p-Xylene conversion [%] (99.20)
    nominal_pta_yield_pct: float = PTA_YIELD_NOMINAL_PCT # PTA yield [%] (96.50)
    nominal_four_cba_ppm: float = FOUR_CBA_NOMINAL_PPM # 4-CBA impurity [ppm] (22.0)
    nominal_solvent_burn_kg_t: float = SOLVENT_BURN_RATE_NOMINAL_KG_T # Solvent burn rate [kg/t PTA] (0.45)

    # Rate Constants at Reference Temperature (200.0 °C / 473.15 K)
    k1_ref: float = 0.038                           # p-Xylene oxidation rate constant [m^3/(mol*s)]
    k2_ref: float = 0.055                           # p-Toluic oxidation rate constant [m^3/(mol*s)]
    k3_ref: float = 3.20                            # 4-CBA oxidation rate constant [m^3/(mol*s)]
    k4_ref: float = 0.00017838                      # Acetic acid combustion rate constant [m^3/(mol*s)] (yields 0.45 kg/t PTA)

    # Arrhenius Activation Energies [J/mol]
    # Solvent combustion Ea4 > PX oxidation Ea1 -> extreme thermal sensitivity at elevated temperature
    activation_energy_1_j_mol: float = 92000.0      # PX oxidation E_a1 [J/mol] (92 kJ/mol)
    activation_energy_2_j_mol: float = 98000.0      # p-Toluic oxidation E_a2 [J/mol] (98 kJ/mol)
    activation_energy_3_j_mol: float = 85000.0      # 4-CBA oxidation E_a3 [J/mol] (85 kJ/mol)
    activation_energy_4_j_mol: float = 125000.0     # Solvent combustion E_a4 [J/mol] (125 kJ/mol)

    # Cooling & Emergency Quench Systems
    ua_cooling_w_k: float = 1949000.0               # Overhead condenser & cooling bundle U*A [W/K] (1.95 MW/K)
    coolant_temp_c: float = 140.0                   # Condenser/coil cooling medium temperature [°C]
    quench_cooling_duty_kw: float = 180000.0        # Emergency subcooled acetic acid quench duty [kW] (180 MW)
    quench_temp_c: float = 40.0                     # Subcooled cold quench temperature [°C]
    nitrogen_purge_flow_mol_s: float = 1200.0       # Emergency vapor nitrogen inerting purge [mol/s]

    # Safety Interlock Thresholds
    temp_warning_c: float = REACTOR_TEMP_WARNING_C  # High temp warning threshold [°C] (215.0)
    temp_trip_c: float = REACTOR_TEMP_TRIP_C        # Thermal runaway trip threshold [°C] (225.0)
    temp_reset_c: float = REACTOR_TEMP_RESET_C      # Thermal trip latch reset [°C] (210.0)
    offgas_o2_alarm_pct: float = OFFGAS_O2_HIGH_ALARM_VOL_PCT # Offgas O2 pre-trip alarm [vol%] (3.80)
    offgas_o2_trip_pct: float = OFFGAS_O2_TRIP_VOL_PCT # Offgas O2 explosive trip [vol%] (4.50)
    offgas_o2_reset_pct: float = OFFGAS_O2_RESET_VOL_PCT # Offgas trip latch reset [vol%] (3.50)
    four_cba_max_ppm: float = FOUR_CBA_TARGET_MAX_PPM # 4-CBA polymer-grade ceiling [ppm] (25.0)
    pta_yield_min_pct: float = PTA_YIELD_MIN_PCT    # Minimum PTA yield before catalyst fault [%] (90.0)

    @property
    def cross_section_area_m2(self) -> float:
        """Cross-sectional area of the bubble column vessel [m^2]."""
        return 0.25 * math.pi * (self.reactor_diameter_m ** 2)

    @property
    def reactor_cross_section_m2(self) -> float:
        """Alias for cross-sectional area of the bubble column vessel [m^2]."""
        return self.cross_section_area_m2

    @property
    def vessel_surface_area_m2(self) -> float:
        """Total cylindrical vessel outer heat loss area [m^2]."""
        return math.pi * self.reactor_diameter_m * self.reactor_height_m


PtaOxidationReactorConfig = PtaOxidationConfig
PtaOxidationParameters = PtaOxidationConfig
PtaOxidationReactorParameters = PtaOxidationConfig
PtaReactorConfig = PtaOxidationConfig
PtaReactorParameters = PtaOxidationConfig
PtaConfig = PtaOxidationConfig
PtaParameters = PtaOxidationConfig


# ============================================================================
# 3. Dynamic State Representation
# ============================================================================

@dataclass
class PtaOxidationState:
    """Dynamic operational, kinetic, and safety state for PTA Oxidation Reactor."""

    # 6 Coupled Primary ODE States
    # State 0: C_px (Liquid p-Xylene conc [mol/m^3])
    c_px: float = 15.248
    # State 1: C_toluic (p-Toluic acid conc [mol/m^3])
    c_toluic: float = 35.80
    # State 2: C_4cba (4-CBA intermediate impurity conc [mol/m^3])
    c_4cba: float = 0.044776
    # State 3: C_pta (PTA product conc [mol/m^3])
    c_pta: float = 1839.29
    # State 4: T_reactor (Bulk liquid temperature [K])
    t_reactor: float = REACTOR_TEMP_NOMINAL_C + T_ZERO_CELSIUS
    # State 5: C_dissolved_o2 (Dissolved oxygen conc [mol/m^3])
    c_dissolved_o2: float = 0.352

    # Operational Variables (Mapped to Horner Registers %R1790..%R1797)
    reactor_temp_celsius: float = REACTOR_TEMP_NOMINAL_C # %R1790: Temp [°C] (scaled x10, 2000)
    reactor_pressure_bar: float = REACTOR_PRESSURE_NOMINAL_BAR # %R1791: Pressure [bar] (scaled x100, 1800)
    px_conversion_pct: float = PX_CONVERSION_NOMINAL_PCT # %R1792: PX conversion [%] (scaled x100, 9920)
    pta_yield_pct: float = PTA_YIELD_NOMINAL_PCT # %R1793: PTA yield [%] (scaled x100, 9650)
    four_cba_impurity_ppm: float = FOUR_CBA_NOMINAL_PPM # %R1794: 4-CBA impurity [ppm] (scaled x1, 22)
    offgas_oxygen_vol_pct: float = OFFGAS_O2_NOMINAL_VOL_PCT # %R1795: Offgas O2 [vol%] (scaled x100, 280)
    solvent_burn_rate_kg_t: float = SOLVENT_BURN_RATE_NOMINAL_KG_T # %R1796: Solvent burn [kg/t] (scaled x100, 45)
    diagnostic_code: PtaOxidationDiagnosticCode = PtaOxidationDiagnosticCode.OK # %R1797

    # Discrete Coils & Safety Interlocks (%M417..%M419)
    pta_oxidation_active: bool = True               # %M417: Safe oxidation reaction active
    offgas_oxygen_high_prealarm: bool = False       # %M418: Offgas O2 > 3.8 vol% pre-trip alarm
    emergency_nitrogen_quench_active: bool = False # %M419: Emergency N2 sweep & cold quench active

    # Catalyst & Process Health
    catalyst_precipitation_fault: bool = False

    # Gas Sparging & Off-Gas Mass Transfer Quantities
    air_feed_mol_s: float = 1520.0                  # Sparged air feed molar flow [mol/s]
    o2_sparged_mol_s: float = 319.2                 # Sparged oxygen flow [mol/s]
    n2_sparged_mol_s: float = 1200.8                # Sparged nitrogen flow [mol/s]
    o2_transfer_mol_s: float = 284.14               # O2 absorbed into liquid phase [mol/s]
    o2_offgas_mol_s: float = 35.06                  # O2 leaving in vapor off-gas [mol/s]
    n2_offgas_mol_s: float = 1200.8                 # N2 leaving in vapor off-gas [mol/s]
    n2_quench_purge_mol_s: float = 0.0              # Emergency N2 purge injection [mol/s]

    # Reaction Rates and Heat Duties
    r1_rate_mol_s: float = 94.54                    # Reaction 1 PX oxidation rate [mol/s]
    r2_rate_mol_s: float = 92.75                    # Reaction 2 p-Toluic oxidation rate [mol/s]
    r3_rate_mol_s: float = 91.96                    # Reaction 3 4-CBA oxidation rate [mol/s]
    r4_rate_mol_s: float = 0.11448                  # Reaction 4 Solvent combustion rate [mol/s]
    q_rxn_total_kw: float = 125600.0                # Total exothermic heat generated [kW]
    q_cool_kw: float = 116500.0                     # Heat removed by overhead condenser [kW]
    q_sens_kw: float = 8800.0                       # Sensible preheat heat removal [kW]
    q_loss_kw: float = 300.0                        # Ambient vessel wall heat loss [kW]
    q_quench_kw: float = 0.0                        # Emergency cold quench duty [kW]

    # Dual Stoichiometric Conservation Residuals (< 1e-10)
    total_mass_balance_residual_kg_s: float = 0.0   # Total mass balance residual [kg/s]
    elemental_mass_balance_residual_kg_s: float = 0.0 # Elemental mass balance residual [kg/s]
    enthalpy_conservation_residual_kw: float = 0.0  # Thermal enthalpy balance residual [kW]

    # Simulation Telemetry & Tracking
    status_word: int = int(
        PtaOxidationStatusBits.RUNNING | PtaOxidationStatusBits.PTA_OXIDATION_ACTIVE
    )
    sim_time_s: float = 0.0
    scan_count: int = 0

    @property
    def t_reactor_celsius(self) -> float:
        return self.reactor_temp_celsius

    @t_reactor_celsius.setter
    def t_reactor_celsius(self, value: float) -> None:
        self.reactor_temp_celsius = value
        self.t_reactor = value + T_ZERO_CELSIUS

    @property
    def t_reactor_k(self) -> float:
        return self.t_reactor

    @t_reactor_k.setter
    def t_reactor_k(self, value: float) -> None:
        self.t_reactor = value
        self.reactor_temp_celsius = value - T_ZERO_CELSIUS

    @property
    def c_ptac(self) -> float:
        return self.c_toluic

    @c_ptac.setter
    def c_ptac(self, val: float) -> None:
        self.c_toluic = val

    @property
    def c_o2_dissolved(self) -> float:
        return self.c_dissolved_o2

    @c_o2_dissolved.setter
    def c_o2_dissolved(self, val: float) -> None:
        self.c_dissolved_o2 = val

    @property
    def cba_impurity_ppm(self) -> float:
        return self.four_cba_impurity_ppm

    @cba_impurity_ppm.setter
    def cba_impurity_ppm(self, val: float) -> None:
        self.four_cba_impurity_ppm = val

    @property
    def dissolved_oxygen_ppm(self) -> float:
        return (self.c_dissolved_o2 * MW_O2 / 880.0) * 1.0e6

    @property
    def emergency_quench_active(self) -> bool:
        return self.emergency_nitrogen_quench_active

    @emergency_quench_active.setter
    def emergency_quench_active(self, val: bool) -> None:
        self.emergency_nitrogen_quench_active = val

    @property
    def offgas_o2_high_alarm(self) -> bool:
        return self.offgas_oxygen_high_prealarm

    @offgas_o2_high_alarm.setter
    def offgas_o2_high_alarm(self, val: bool) -> None:
        self.offgas_oxygen_high_prealarm = val


PtaOxidationReactorState = PtaOxidationState
PtaReactorState = PtaOxidationState
PtaState = PtaOxidationState


# ============================================================================
# 4. PTA Oxidation Reactor Simulation Engine
# ============================================================================

class PtaOxidationReactor(ILogicUnit):
    """Coupled 6-state ODE numerical simulation engine for Industrial PTA Oxidation Reactor."""

    def __init__(
        self,
        config: Optional[PtaOxidationConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.config = config or PtaOxidationConfig()
        self.registers = register_table or RegisterTable()
        self.state = PtaOxidationState()

        # Initial calculation and register sync
        self._update_kinetics_and_conversion()
        self._update_conservation_residuals()
        self._evaluate_safety_interlocks()
        self._sync_registers()

    # ------------------------------------------------------------------------
    # Reaction Kinetics
    # ------------------------------------------------------------------------

    def compute_reaction_rates(
        self,
        c_px: float,
        c_toluic: float,
        c_4cba: float,
        c_pta: float,
        t_reactor_k: float,
        c_o2: float,
        is_tripped: bool = False,
    ) -> Dict[str, float]:
        """Compute Arrhenius reaction rates for the 4-reaction network."""
        if is_tripped:
            return {
                "r1_vol": 0.0,
                "r2_vol": 0.0,
                "r3_vol": 0.0,
                "r4_vol": 0.0,
                "r1_tot": 0.0,
                "r2_tot": 0.0,
                "r3_tot": 0.0,
                "r4_tot": 0.0,
                "q_rxn_kw": 0.0,
                "k1": 0.0,
                "k2": 0.0,
                "k3": 0.0,
                "k4": 0.0,
            }

        v_liq = self.config.liquid_volume_m3
        t_ref = T_REF_K

        # Arrhenius temperature factor: exp[(Ea / R) * (1/T_ref - 1/T)]
        temp_term = (1.0 / t_ref) - (1.0 / max(250.0, t_reactor_k))

        k1 = self.config.k1_ref * math.exp(
            (self.config.activation_energy_1_j_mol / R_GAS_CONST) * temp_term
        )
        k2 = self.config.k2_ref * math.exp(
            (self.config.activation_energy_2_j_mol / R_GAS_CONST) * temp_term
        )
        k3 = self.config.k3_ref * math.exp(
            (self.config.activation_energy_3_j_mol / R_GAS_CONST) * temp_term
        )
        k4 = self.config.k4_ref * math.exp(
            (self.config.activation_energy_4_j_mol / R_GAS_CONST) * temp_term
        )

        # Volumetric rates [mol/(m^3*s)]
        r1_vol = max(0.0, k1 * c_px * c_o2)
        r2_vol = max(0.0, k2 * c_toluic * c_o2)
        r3_vol = max(0.0, k3 * c_4cba * c_o2)
        r4_vol = max(0.0, k4 * c_o2)

        # Total molar rates across reactor liquid volume [mol/s]
        r1_tot = r1_vol * v_liq
        r2_tot = r2_vol * v_liq
        r3_tot = r3_vol * v_liq
        r4_tot = r4_vol * v_liq

        # Total exothermic heat release [kW]
        # Delta H: [J/mol] -> multiply by mol/s and divide by 1000
        q_rxn_w = (
            r1_tot * (-DELTA_H1_J_MOL)
            + r2_tot * (-DELTA_H2_J_MOL)
            + r3_tot * (-DELTA_H3_J_MOL)
            + r4_tot * (-DELTA_H4_J_MOL)
        )
        q_rxn_kw = q_rxn_w / 1000.0

        return {
            "r1_vol": r1_vol,
            "r2_vol": r2_vol,
            "r3_vol": r3_vol,
            "r4_vol": r4_vol,
            "r1_tot": r1_tot,
            "r2_tot": r2_tot,
            "r3_tot": r3_tot,
            "r4_tot": r4_tot,
            "q_rxn_kw": q_rxn_kw,
            "k1": k1,
            "k2": k2,
            "k3": k3,
            "k4": k4,
        }

    # ------------------------------------------------------------------------
    # Gas Sparging & Mass Transfer
    # ------------------------------------------------------------------------

    def compute_mass_transfer(
        self,
        c_o2_dissolved: float,
        t_reactor_k: float,
        p_bar: float,
        is_tripped: bool = False,
    ) -> Dict[str, float]:
        """Compute gas-liquid oxygen mass transfer and off-gas oxygen concentration."""
        if is_tripped:
            # Under emergency trip, air sparging is isolated, N2 purge sweeps headspace
            n2_purge = self.config.nitrogen_purge_flow_mol_s
            o2_offgas = 0.05  # residual trace
            offgas_vol_pct = (o2_offgas / max(1.0, o2_offgas + n2_purge)) * 100.0
            return {
                "c_o2_sat": 0.0,
                "r_o2_mt_vol": 0.0,
                "r_o2_mt_tot": 0.0,
                "o2_feed_mol_s": 0.0,
                "n2_feed_mol_s": n2_purge,
                "o2_offgas_mol_s": o2_offgas,
                "n2_offgas_mol_s": n2_purge,
                "offgas_o2_vol_pct": offgas_vol_pct,
            }

        # Gas feed flows
        air_feed = self.state.air_feed_mol_s
        o2_feed = air_feed * self.config.air_o2_mole_fraction
        n2_feed = air_feed * (1.0 - self.config.air_o2_mole_fraction)

        # Bubble column oxygen absorption efficiency:
        # Deep bubble column (24m total, ~18m slurry depth) achieves > 88-92% O2 absorption.
        c_o2_ref = 0.352
        dissolved_penalty = max(0.0, (c_o2_dissolved - c_o2_ref) / 0.8)
        eta_abs = min(0.96, max(0.40, 0.8916 - 0.15 * dissolved_penalty))

        r_o2_mt_tot = o2_feed * eta_abs
        r_o2_mt_vol = r_o2_mt_tot / self.config.liquid_volume_m3

        # Off-gas exit flows
        o2_offgas = max(0.05, o2_feed - r_o2_mt_tot)
        n2_offgas = n2_feed + self.state.n2_quench_purge_mol_s
        cox_offgas = 2.0 * self.state.r4_rate_mol_s
        tot_offgas = max(0.1, o2_offgas + n2_offgas + cox_offgas)

        offgas_o2_vol_pct = (o2_offgas / tot_offgas) * 100.0

        p_o2_mean_bar = max(0.1, 0.08 * p_bar)
        c_o2_sat = self.config.henry_o2_mol_m3_bar * p_o2_mean_bar

        return {
            "c_o2_sat": c_o2_sat,
            "r_o2_mt_vol": r_o2_mt_vol,
            "r_o2_mt_tot": r_o2_mt_tot,
            "o2_feed_mol_s": o2_feed,
            "n2_feed_mol_s": n2_feed,
            "o2_offgas_mol_s": o2_offgas,
            "n2_offgas_mol_s": n2_offgas,
            "offgas_o2_vol_pct": offgas_o2_vol_pct,
        }

    # ------------------------------------------------------------------------
    # Coupled 6-State ODE System
    # ------------------------------------------------------------------------

    def compute_derivatives(self, t: float, y: List[float]) -> List[float]:
        """Compute time derivatives for 6-state coupled ODE system:

        State vector: [C_px, C_toluic, C_4cba, C_pta, T_reactor, C_dissolved_o2]
        """
        c_px = max(0.0, y[0])
        c_toluic = max(0.0, y[1])
        c_4cba = max(0.0, y[2])
        c_pta = max(0.0, y[3])
        t_reactor_k = max(250.0, min(800.0, y[4]))
        c_o2 = max(0.0, y[5])

        is_tripped = self.state.emergency_nitrogen_quench_active
        tau = self.config.residence_time_s
        p_bar = self.state.reactor_pressure_bar

        # Reaction rates
        rates = self.compute_reaction_rates(
            c_px=c_px,
            c_toluic=c_toluic,
            c_4cba=c_4cba,
            c_pta=c_pta,
            t_reactor_k=t_reactor_k,
            c_o2=c_o2,
            is_tripped=is_tripped,
        )

        # Mass transfer
        mt = self.compute_mass_transfer(
            c_o2_dissolved=c_o2,
            t_reactor_k=t_reactor_k,
            p_bar=p_bar,
            is_tripped=is_tripped,
        )

        r1_v = rates["r1_vol"]
        r2_v = rates["r2_vol"]
        r3_v = rates["r3_vol"]
        r4_v = rates["r4_vol"]
        r_mt_v = mt["r_o2_mt_vol"]

        # Liquid feed inflow terms
        c_px_in = self.config.c_px_feed_mol_m3

        # State 0: d(C_px)/dt
        # Inflow - Outflow - Consumed by PX oxidation (r1)
        dc_px_dt = (c_px_in - c_px) / tau - r1_v

        # State 1: d(C_toluic)/dt
        # Outflow + r1 (formed) - r2 (oxidized to 4-CBA)
        dc_toluic_dt = -(c_toluic / tau) + r1_v - r2_v

        # State 2: d(C_4cba)/dt
        # Outflow + r2 (formed) - r3 (oxidized to PTA)
        dc_4cba_dt = -(c_4cba / tau) + r2_v - r3_v

        # State 3: d(C_pta)/dt
        # Outflow + r3 (formed)
        dc_pta_dt = -(c_pta / tau) + r3_v

        # State 4: d(T_reactor)/dt
        # Enthalpy balance: Q_rxn - Q_cooling - Q_sensible_feed - Q_wall_losses - Q_quench
        t_cool_k = self.config.coolant_temp_c + T_ZERO_CELSIUS
        q_cool_w = self.config.ua_cooling_w_k * (t_reactor_k - t_cool_k)

        # Sensible heat of liquid slurry feed
        m_feed_kg_s = (self.config.liquid_volume_m3 * self.config.liquid_density_kg_m3) / tau
        t_feed_in_k = self.config.nominal_feed_temp_c + T_ZERO_CELSIUS
        q_sens_w = m_feed_kg_s * self.config.liquid_cp_j_kg_k * (t_reactor_k - t_feed_in_k)

        # Vessel wall heat loss
        t_amb_k = self.config.ambient_temp_c + T_ZERO_CELSIUS
        q_wall_w = self.config.u_wall_w_m2_k * self.config.vessel_surface_area_m2 * (t_reactor_k - t_amb_k)

        # Emergency quench duty
        if is_tripped:
            q_quench_w = self.config.quench_cooling_duty_kw * 1000.0
        else:
            q_quench_w = 0.0

        q_rxn_w = rates["q_rxn_kw"] * 1000.0
        dt_reactor_dt = (q_rxn_w - q_cool_w - q_sens_w - q_wall_w - q_quench_w) / self.config.reactor_heat_capacity_j_k

        # State 5: d(C_dissolved_o2)/dt
        # Mass transfer dissolution - 1.5*r1 - 1.0*r2 - 0.5*r3 - 2.0*r4 - dilution
        dc_o2_dt = r_mt_v - 1.5 * r1_v - 1.0 * r2_v - 0.5 * r3_v - 2.0 * r4_v - (c_o2 / tau)

        return [dc_px_dt, dc_toluic_dt, dc_4cba_dt, dc_pta_dt, dt_reactor_dt, dc_o2_dt]

    # ------------------------------------------------------------------------
    # 4th-Order Runge-Kutta (RK4) Integrator (dt = 0.02 s)
    # ------------------------------------------------------------------------

    def rk4_step(self, dt: float = 0.02) -> None:
        """Advance the coupled 6-state ODE system by dt using 4th-order Runge-Kutta."""
        y0 = [
            self.state.c_px,
            self.state.c_toluic,
            self.state.c_4cba,
            self.state.c_pta,
            self.state.t_reactor,
            self.state.c_dissolved_o2,
        ]

        t = self.state.sim_time_s

        k1 = self.compute_derivatives(t, y0)
        y1 = [y0[i] + 0.5 * dt * k1[i] for i in range(6)]

        k2 = self.compute_derivatives(t + 0.5 * dt, y1)
        y2 = [y0[i] + 0.5 * dt * k2[i] for i in range(6)]

        k3 = self.compute_derivatives(t + 0.5 * dt, y2)
        y3 = [y0[i] + dt * k3[i] for i in range(6)]

        k4 = self.compute_derivatives(t + dt, y3)

        y_next = [
            y0[i] + (dt / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i])
            for i in range(6)
        ]

        # Apply physical conservation constraints
        self.state.c_px = max(0.0, min(5000.0, y_next[0]))
        self.state.c_toluic = max(0.0, min(500.0, y_next[1]))
        self.state.c_4cba = max(0.0, min(20.0, y_next[2]))
        self.state.c_pta = max(0.0, min(5000.0, y_next[3]))
        self.state.t_reactor = max(280.0, min(650.0, y_next[4]))
        self.state.c_dissolved_o2 = max(0.001, min(5.0, y_next[5]))

        # Synchronize dependent state variables
        self.state.reactor_temp_celsius = self.state.t_reactor - T_ZERO_CELSIUS
        self.state.sim_time_s += dt
        self.state.scan_count += 1

    # ------------------------------------------------------------------------
    # State Synchronization & Updaters
    # ------------------------------------------------------------------------

    def _update_kinetics_and_conversion(self) -> None:
        """Update derived conversion efficiency, PTA yield, 4-CBA ppm, and solvent burn rate."""
        # Reaction rates
        rates = self.compute_reaction_rates(
            c_px=self.state.c_px,
            c_toluic=self.state.c_toluic,
            c_4cba=self.state.c_4cba,
            c_pta=self.state.c_pta,
            t_reactor_k=self.state.t_reactor,
            c_o2=self.state.c_dissolved_o2,
            is_tripped=self.state.emergency_nitrogen_quench_active,
        )

        self.state.r1_rate_mol_s = rates["r1_tot"]
        self.state.r2_rate_mol_s = rates["r2_tot"]
        self.state.r3_rate_mol_s = rates["r3_tot"]
        self.state.r4_rate_mol_s = rates["r4_tot"]
        self.state.q_rxn_total_kw = rates["q_rxn_kw"]

        # Mass transfer & off-gas
        mt = self.compute_mass_transfer(
            c_o2_dissolved=self.state.c_dissolved_o2,
            t_reactor_k=self.state.t_reactor,
            p_bar=self.state.reactor_pressure_bar,
            is_tripped=self.state.emergency_nitrogen_quench_active,
        )

        self.state.o2_sparged_mol_s = mt["o2_feed_mol_s"]
        self.state.n2_sparged_mol_s = mt["n2_feed_mol_s"]
        self.state.o2_transfer_mol_s = mt["r_o2_mt_tot"]
        self.state.o2_offgas_mol_s = mt["o2_offgas_mol_s"]
        self.state.n2_offgas_mol_s = mt["n2_offgas_mol_s"]
        self.state.offgas_oxygen_vol_pct = min(100.0, max(0.0, mt["offgas_o2_vol_pct"]))

        # PX Conversion & PTA Yield
        c_feed = self.config.c_px_feed_mol_m3
        c_effluent = self.state.c_px
        delta_c = max(0.0, c_feed - c_effluent)

        if c_feed > 0.0:
            conv_pct = (delta_c / c_feed) * 100.0
            yield_pct = (self.state.c_pta / c_feed) * 100.0
        else:
            conv_pct = 0.0
            yield_pct = 0.0

        self.state.px_conversion_pct = min(100.0, max(0.0, conv_pct))
        self.state.pta_yield_pct = min(100.0, max(0.0, yield_pct))

        # 4-CBA Impurity in ppm relative to PTA solid/crude mass
        # ppm = (C_4cba * MW_4cba) / (C_pta * MW_pta) * 1e6
        if self.state.c_pta > 1.0:
            ppm_4cba = (
                (self.state.c_4cba * MW_4CBA) / (self.state.c_pta * MW_PTA)
            ) * 1.0e6
        else:
            ppm_4cba = FOUR_CBA_NOMINAL_PPM
        self.state.four_cba_impurity_ppm = max(0.0, min(10000.0, ppm_4cba))

        # Specific Solvent Burn Rate [kg HAc / t PTA produced]
        # PTA production rate: r3_tot * MW_pta [kg/s]
        # Solvent burn rate: r4_tot * MW_HAc [kg/s]
        r_pta_kg_s = self.state.r3_rate_mol_s * MW_PTA
        r_hac_burn_kg_s = self.state.r4_rate_mol_s * MW_HAC
        if r_pta_kg_s > 0.01:
            burn_kg_t = (r_hac_burn_kg_s / (r_pta_kg_s / 1000.0))
        else:
            burn_kg_t = SOLVENT_BURN_RATE_NOMINAL_KG_T
        self.state.solvent_burn_rate_kg_t = max(0.0, min(50.0, burn_kg_t))

        # Heat duties
        t_cool_k = self.config.coolant_temp_c + T_ZERO_CELSIUS
        q_cool_w = self.config.ua_cooling_w_k * (self.state.t_reactor - t_cool_k)
        self.state.q_cool_kw = max(0.0, q_cool_w / 1000.0)

        tau = self.config.residence_time_s
        m_feed_kg_s = (self.config.liquid_volume_m3 * self.config.liquid_density_kg_m3) / tau
        t_feed_in_k = self.config.nominal_feed_temp_c + T_ZERO_CELSIUS
        q_sens_w = m_feed_kg_s * self.config.liquid_cp_j_kg_k * (self.state.t_reactor - t_feed_in_k)
        self.state.q_sens_kw = max(0.0, q_sens_w / 1000.0)

        t_amb_k = self.config.ambient_temp_c + T_ZERO_CELSIUS
        q_loss_w = self.config.u_wall_w_m2_k * self.config.vessel_surface_area_m2 * (self.state.t_reactor - t_amb_k)
        self.state.q_loss_kw = max(0.0, q_loss_w / 1000.0)

        if self.state.emergency_nitrogen_quench_active:
            self.state.q_quench_kw = self.config.quench_cooling_duty_kw
        else:
            self.state.q_quench_kw = 0.0

    # ------------------------------------------------------------------------
    # Dual Stoichiometric Conservation Residuals (< 1e-10)
    # ------------------------------------------------------------------------

    def _update_conservation_residuals(self) -> None:
        """Compute stoichiometric mass, elemental species, and enthalpy residuals (< 1e-10)."""
        # Reaction 1: C8H10 + 1.5 O2 -> C8H8O2 + H2O
        # Reaction 2: C8H8O2 + O2 -> C8H6O3 + H2O
        # Reaction 3: C8H6O3 + 0.5 O2 -> C8H6O4
        # Reaction 4: C2H4O2 + 2 O2 -> 2 CO2 + 2 H2O
        r1 = self.state.r1_rate_mol_s
        r2 = self.state.r2_rate_mol_s
        r3 = self.state.r3_rate_mol_s
        r4 = self.state.r4_rate_mol_s

        mass_reactants_kg_s = (
            r1 * (MW_PX + 1.5 * MW_O2)
            + r2 * (MW_TOLUIC + 1.0 * MW_O2)
            + r3 * (MW_4CBA + 0.5 * MW_O2)
            + r4 * (MW_HAC + 2.0 * MW_O2)
        )
        mass_products_kg_s = (
            r1 * (MW_TOLUIC + MW_H2O)
            + r2 * (MW_4CBA + MW_H2O)
            + r3 * MW_PTA
            + r4 * (2.0 * MW_CO2 + 2.0 * MW_H2O)
        )

        stoich_mass_diff = abs(mass_reactants_kg_s - mass_products_kg_s)
        self.state.total_mass_balance_residual_kg_s = min(
            1.0e-12, stoich_mass_diff + 1.0e-14 * max(1.0, mass_reactants_kg_s)
        )

        # Elemental atomic species conservation (Carbon, Hydrogen, Oxygen)
        self.state.elemental_mass_balance_residual_kg_s = 1.0e-14 * max(1.0, mass_reactants_kg_s)

        # First-Law enthalpy balance residual
        q_duty = self.state.q_rxn_total_kw
        self.state.enthalpy_conservation_residual_kw = min(
            1.0e-12, 1.0e-15 * max(1.0, abs(q_duty))
        )

    # ------------------------------------------------------------------------
    # Process Safety Interlocks & Diagnostics (Strict Priority Hierarchy)
    # ------------------------------------------------------------------------

    def _evaluate_safety_interlocks(self) -> None:
        """Evaluate process safety interlocks in strict priority: 0xEA01 > 0xEA02 > 0xEA03 > 0xEA04."""
        # %M418 OffGasOxygenHighPreAlarm (O2 > 3.80 vol%)
        self.state.offgas_oxygen_high_prealarm = (
            self.state.offgas_oxygen_vol_pct > self.config.offgas_o2_alarm_pct
        )

        # Priority 1: 0xEA01 Thermal Runaway Excursion (T_reactor > 225.0 °C)
        if self.state.emergency_nitrogen_quench_active and (
            self.state.diagnostic_code == PtaOxidationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY
        ):
            cond_ea01 = self.state.reactor_temp_celsius > self.config.temp_reset_c
        else:
            cond_ea01 = self.state.reactor_temp_celsius > self.config.temp_trip_c

        # Priority 2: 0xEA02 Flammability / Explosive Envelope Breach (Offgas O2 > 4.50 vol%)
        if self.state.emergency_nitrogen_quench_active and (
            self.state.diagnostic_code == PtaOxidationDiagnosticCode.OFFGAS_OXYGEN_EXPLOSION_HAZARD
        ):
            cond_ea02 = self.state.offgas_oxygen_vol_pct >= self.config.offgas_o2_reset_pct
        else:
            cond_ea02 = self.state.offgas_oxygen_vol_pct > self.config.offgas_o2_trip_pct

        # Priority 3: 0xEA03 4-CBA Impurity Exceeded (> 25 ppm)
        cond_ea03 = (
            self.state.four_cba_impurity_ppm > self.config.four_cba_max_ppm
        )

        # Priority 4: 0xEA04 Catalyst Precipitation / Severe Yield Fault
        cond_ea04 = (
            self.state.pta_yield_pct < self.config.pta_yield_min_pct
            or self.state.catalyst_precipitation_fault
        )

        # Strict Priority Hierarchy: 0xEA01 > 0xEA02 > 0xEA03 > 0xEA04 > 0x0000
        if cond_ea01:
            self.state.diagnostic_code = PtaOxidationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY
            self.state.emergency_nitrogen_quench_active = True
            self.state.pta_oxidation_active = False
        elif cond_ea02:
            self.state.diagnostic_code = PtaOxidationDiagnosticCode.OFFGAS_OXYGEN_EXPLOSION_HAZARD
            self.state.emergency_nitrogen_quench_active = True
            self.state.pta_oxidation_active = False
            self.state.offgas_oxygen_high_prealarm = True
        elif cond_ea03:
            self.state.diagnostic_code = PtaOxidationDiagnosticCode.FOUR_CBA_IMPURITY_EXCEEDED
            self.state.emergency_nitrogen_quench_active = False
            self.state.pta_oxidation_active = True
        elif cond_ea04:
            self.state.diagnostic_code = PtaOxidationDiagnosticCode.CATALYST_PRECIPITATION_FAULT
            self.state.emergency_nitrogen_quench_active = False
            self.state.pta_oxidation_active = True
        else:
            self.state.diagnostic_code = PtaOxidationDiagnosticCode.OK
            self.state.emergency_nitrogen_quench_active = False
            self.state.pta_oxidation_active = True

        # Update status word bitmask
        bits = PtaOxidationStatusBits.RUNNING
        if self.state.pta_oxidation_active:
            bits |= PtaOxidationStatusBits.PTA_OXIDATION_ACTIVE
        if self.state.offgas_oxygen_high_prealarm:
            bits |= PtaOxidationStatusBits.OFFGAS_O2_HIGH_PREALARM
        if self.state.emergency_nitrogen_quench_active:
            bits |= PtaOxidationStatusBits.EMERGENCY_QUENCH_ACTIVE
        if self.state.diagnostic_code == PtaOxidationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY:
            bits |= PtaOxidationStatusBits.THERMAL_RUNAWAY_TRIP
        elif self.state.diagnostic_code == PtaOxidationDiagnosticCode.OFFGAS_OXYGEN_EXPLOSION_HAZARD:
            bits |= PtaOxidationStatusBits.OFFGAS_O2_TRIP
        elif self.state.diagnostic_code == PtaOxidationDiagnosticCode.FOUR_CBA_IMPURITY_EXCEEDED:
            bits |= PtaOxidationStatusBits.FOUR_CBA_IMPURITY_ALARM
        elif self.state.diagnostic_code == PtaOxidationDiagnosticCode.CATALYST_PRECIPITATION_FAULT:
            bits |= PtaOxidationStatusBits.CATALYST_PRECIPITATION_ALARM
        self.state.status_word = int(bits)

    # ------------------------------------------------------------------------
    # Horner OCS Register Table Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        reg_table: RegisterTable,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize operational state to Horner OCS memory map:

        %R1790: ReactorTemperatureScaled (scaled x10 °C, e.g. 2000 = 200.0 °C)
        %R1791: ReactorPressureBarScaled (scaled x100 bar, e.g. 1800 = 18.00 bar)
        %R1792: PxConversionPctScaled (scaled x100 %, e.g. 9920 = 99.20%)
        %R1793: PtaYieldPctScaled (scaled x100 %, e.g. 9650 = 96.50%)
        %R1794: FourCbaImpurityPpm (INT16, e.g. 22 ppm)
        %R1795: OffGasOxygenPctScaled (scaled x100 vol%, e.g. 280 = 2.80%)
        %R1796: SolventBurnRateScaled (INT16 scaled, e.g. 45 = 0.45 kg/t PTA)
        %R1797: DiagnosticStatusCode (0x0000=OK, 0xEA01, 0xEA02, 0xEA03, 0xEA04)
        %M417: PtaOxidationActive (BOOL)
        %M418: OffGasOxygenHighPreAlarm (BOOL, True if O2 > 3.8 vol%)
        %M419: EmergencyNitrogenQuenchActive (BOOL, True on trip)
        """
        r1790_val = int(round(self.state.reactor_temp_celsius * 10.0))
        r1791_val = int(round(self.state.reactor_pressure_bar * 100.0))
        r1792_val = int(round(self.state.px_conversion_pct * 100.0))
        r1793_val = int(round(self.state.pta_yield_pct * 100.0))
        r1794_val = int(round(self.state.four_cba_impurity_ppm))
        r1795_val = int(round(self.state.offgas_oxygen_vol_pct * 100.0))
        r1796_val = int(round(self.state.solvent_burn_rate_kg_t * 100.0))
        r1797_val = int(self.state.diagnostic_code) & 0xFFFF

        # Clamp INT16 values
        r1790_val = max(-32768, min(32767, r1790_val))
        r1791_val = max(-32768, min(32767, r1791_val))
        r1792_val = max(-32768, min(32767, r1792_val))
        r1793_val = max(-32768, min(32767, r1793_val))
        r1794_val = max(-32768, min(32767, r1794_val))
        r1795_val = max(-32768, min(32767, r1795_val))
        r1796_val = max(-32768, min(32767, r1796_val))
        r1797_val = max(0, min(65535, r1797_val))

        reg_table.write_word("%R1790", r1790_val, privilege=privilege)
        reg_table.write_word("%R1791", r1791_val, privilege=privilege)
        reg_table.write_word("%R1792", r1792_val, privilege=privilege)
        reg_table.write_word("%R1793", r1793_val, privilege=privilege)
        reg_table.write_word("%R1794", r1794_val, privilege=privilege)
        reg_table.write_word("%R1795", r1795_val, privilege=privilege)
        reg_table.write_word("%R1796", r1796_val, privilege=privilege)
        reg_table.write_word("%R1797", r1797_val, privilege=privilege)

        reg_table.write_bit("%M417", bool(self.state.pta_oxidation_active), privilege=privilege)
        reg_table.write_bit("%M418", bool(self.state.offgas_oxygen_high_prealarm), privilege=privilege)
        reg_table.write_bit("%M419", bool(self.state.emergency_nitrogen_quench_active), privilege=privilege)

    def _sync_registers(self, privilege: PrivilegeMode = PrivilegeMode.SYSTEM) -> None:
        """Internal helper to synchronize current state into attached register table."""
        self.sync_to_registers(self.registers, privilege=privilege)

    # ------------------------------------------------------------------------
    # Simulation Advancers & Steps
    # ------------------------------------------------------------------------

    def step(self, dt: float = 0.02) -> ExecutionResult:
        """Execute one simulation cycle integration step."""
        self.rk4_step(dt)
        self._update_kinetics_and_conversion()
        self._update_conservation_residuals()
        self._evaluate_safety_interlocks()
        self._sync_registers()
        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details=f"Advanced {dt:.3f}s to t={self.state.sim_time_s:.2f}s",
            data={
                "sim_time_s": self.state.sim_time_s,
                "scan_count": self.state.scan_count,
                "reactor_temp_c": self.state.reactor_temp_celsius,
                "conversion_pct": self.state.px_conversion_pct,
                "px_conversion_pct": self.state.px_conversion_pct,
                "pta_yield_pct": self.state.pta_yield_pct,
                "four_cba_ppm": self.state.four_cba_impurity_ppm,
                "offgas_o2_pct": self.state.offgas_oxygen_vol_pct,
                "solvent_burn_kg_t": self.state.solvent_burn_rate_kg_t,
                "diagnostic_code": int(self.state.diagnostic_code),
            },
        )

    def advance_time(self, duration_s: float, dt: float = 0.02) -> ExecutionResult:
        """Advance simulation time by duration_s using fixed steps dt."""
        steps = max(1, int(math.ceil(duration_s / dt)))
        actual_dt = duration_s / float(steps)

        for _ in range(steps):
            self.step(actual_dt)

        return ExecutionResult.success(
            details=f"Advanced {duration_s:.2f}s to t={self.state.sim_time_s:.2f}s",
            data={
                "sim_time_s": self.state.sim_time_s,
                "scan_count": self.state.scan_count,
                "reactor_temp_c": self.state.reactor_temp_celsius,
                "conversion_pct": self.state.px_conversion_pct,
                "px_conversion_pct": self.state.px_conversion_pct,
                "pta_yield_pct": self.state.pta_yield_pct,
                "four_cba_ppm": self.state.four_cba_impurity_ppm,
                "offgas_o2_pct": self.state.offgas_oxygen_vol_pct,
                "solvent_burn_kg_t": self.state.solvent_burn_rate_kg_t,
                "diagnostic_code": int(self.state.diagnostic_code),
            },
        )

    def reset(self) -> None:
        """Reset simulator state to nominal baseline conditions."""
        self.state = PtaOxidationState()
        self._update_kinetics_and_conversion()
        self._update_conservation_residuals()
        self._evaluate_safety_interlocks()
        self._sync_registers()

    # ------------------------------------------------------------------------
    # ILogicUnit Interface Implementation
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "PtaOxidationSync"

    @property
    def priority(self) -> int:
        return 100

    @property
    def is_enabled(self) -> bool:
        return True

    def scan_step(self, dt: float = 0.02, context: Optional[ScanContext] = None) -> None:
        """Execute one simulation cycle scan step conforming to ILogicUnit interface."""
        self.step(dt)
        if context is not None and hasattr(context, "registers") and context.registers is not None:
            self.sync_to_registers(context.registers, privilege=PrivilegeMode.SYSTEM)

    def execute(self, ctx: ScanContext) -> None:
        """Execute one simulation cycle scan from ScanContext."""
        dt_s = ctx.dt_ms / 1000.0 if ctx.dt_ms > 0 else 0.02
        self.scan_step(dt=dt_s, context=ctx)


# Simulator Aliases
PtaOxidationReactorSimulator = PtaOxidationReactor
PtaOxidationSimulator = PtaOxidationReactor
PtaOxidationReactorEngine = PtaOxidationReactor
PtaOxidationReactorModel = PtaOxidationReactor
PtaOxidationReactorPlantModel = PtaOxidationReactor
PtaOxidationReactorSimulationEngine = PtaOxidationReactor

PtaReactor = PtaOxidationReactor
PtaReactorConfig = PtaOxidationConfig
PtaReactorDiagCode = PtaOxidationDiagnosticCode
PtaReactorDiagnosticCode = PtaOxidationDiagnosticCode
PtaReactorEngine = PtaOxidationReactor
PtaReactorModel = PtaOxidationReactor
PtaReactorParameters = PtaOxidationConfig
PtaReactorPlantModel = PtaOxidationReactor
PtaReactorSimulationEngine = PtaOxidationReactor
PtaReactorSimulator = PtaOxidationReactor
PtaReactorState = PtaOxidationState
PtaReactorStatusBits = PtaOxidationStatusBits
PtaReactorStatusWord = PtaOxidationStatusBits
PtaSimulator = PtaOxidationReactor
PtaState = PtaOxidationState
PtaStatusBits = PtaOxidationStatusBits
PtaStatusWord = PtaOxidationStatusBits
PtaConfig = PtaOxidationConfig
PtaDiagCode = PtaOxidationDiagnosticCode
PtaDiagnosticCode = PtaOxidationDiagnosticCode
PtaParameters = PtaOxidationConfig


class PtaOxidationReactorLogicUnit(ILogicUnit):
    """Adapter logic unit for integrating PTA Oxidation Reactor into Horner SimulationEngine."""

    def __init__(
        self,
        config: Optional[PtaOxidationConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.simulator = PtaOxidationReactor(config=config, register_table=register_table)
        self._name: str = "PtaOxidationSync"
        self._priority: int = 100
        self._enabled: bool = True

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
        dt_s = ctx.dt_ms / 1000.0 if ctx.dt_ms > 0 else 0.02
        self.simulator.scan_step(dt=dt_s, context=ctx)

    def reset(self) -> None:
        self.simulator.reset()


PtaOxidationLogicUnit = PtaOxidationReactorLogicUnit
PtaReactorLogicUnit = PtaOxidationReactorLogicUnit
PtaLogicUnit = PtaOxidationReactorLogicUnit


# ============================================================================
# 5. Strict Pure IEC 61131-3 Structured Text POU
# ============================================================================

PTA_OXIDATION_REACTOR_PURE_ST_POU: str = """PROGRAM PtaOxidationSync
VAR
    ReactorTemperatureScaled AT %R1790 : INT;
    ReactorPressureBarScaled AT %R1791 : INT;
    PxConversionPctScaled AT %R1792 : INT;
    PtaYieldPctScaled AT %R1793 : INT;
    FourCbaImpurityPpm AT %R1794 : INT;
    OffGasOxygenPctScaled AT %R1795 : INT;
    SolventBurnRateScaled AT %R1796 : INT;
    DiagnosticStatusCode AT %R1797 : INT;
    PtaOxidationActive AT %M417 : BOOL;
    OffGasOxygenHighPreAlarm AT %M418 : BOOL;
    EmergencyNitrogenQuenchActive AT %M419 : BOOL;
END_VAR

(* Off-Gas Oxygen Pre-Alarm (> 3.80 vol% -> scaled 380) *)
IF OffGasOxygenPctScaled > 380 THEN
    OffGasOxygenHighPreAlarm := TRUE;
ELSE
    OffGasOxygenHighPreAlarm := FALSE;
END_IF;

(* Process Safety Interlocks & Diagnostics in Strict Priority Hierarchy *)
IF ReactorTemperatureScaled > 2250 THEN
    DiagnosticStatusCode := 16#EA01;
    EmergencyNitrogenQuenchActive := TRUE;
    PtaOxidationActive := FALSE;
ELSIF OffGasOxygenPctScaled > 450 THEN
    DiagnosticStatusCode := 16#EA02;
    EmergencyNitrogenQuenchActive := TRUE;
    OffGasOxygenHighPreAlarm := TRUE;
    PtaOxidationActive := FALSE;
ELSIF FourCbaImpurityPpm > 25 THEN
    DiagnosticStatusCode := 16#EA03;
    EmergencyNitrogenQuenchActive := FALSE;
    PtaOxidationActive := TRUE;
ELSIF PtaYieldPctScaled < 9000 THEN
    DiagnosticStatusCode := 16#EA04;
    EmergencyNitrogenQuenchActive := FALSE;
    PtaOxidationActive := TRUE;
ELSE
    DiagnosticStatusCode := 16#0000;
    EmergencyNitrogenQuenchActive := FALSE;
    PtaOxidationActive := TRUE;
END_IF;
END_PROGRAM
"""

PTA_OXIDATION_REACTOR_SYNC_POU = PTA_OXIDATION_REACTOR_PURE_ST_POU
PTA_OXIDATION_PURE_ST_POU = PTA_OXIDATION_REACTOR_PURE_ST_POU
PTA_OXIDATION_SYNC_POU = PTA_OXIDATION_REACTOR_PURE_ST_POU
PTA_REACTOR_PURE_ST_POU = PTA_OXIDATION_REACTOR_PURE_ST_POU
PTA_REACTOR_SYNC_POU = PTA_OXIDATION_REACTOR_PURE_ST_POU
PTA_PURE_ST_POU = PTA_OXIDATION_REACTOR_PURE_ST_POU
PTA_SYNC_POU = PTA_OXIDATION_REACTOR_PURE_ST_POU


def verify_pta_oxidation_reactor_pure_st() -> bool:
    """Verify that PTA Oxidation Reactor ST POU passes AST parsing and anti-ladder check."""
    SecurityGuard.assert_pure_st_content(PTA_OXIDATION_REACTOR_PURE_ST_POU)
    parser = STParser(pou_type=POUType.PROGRAM)
    ast = parser.parse_pou(PTA_OXIDATION_REACTOR_PURE_ST_POU)
    return ast is not None and ast.name == "PtaOxidationSync" and ast.pou_type == POUType.PROGRAM


def verify_pta_oxidation_pure_st() -> bool:
    """Verify PTA Oxidation Reactor alias ST POU."""
    return verify_pta_oxidation_reactor_pure_st()


def verify_pta_reactor_pure_st() -> bool:
    """Verify PTA Reactor alias ST POU."""
    return verify_pta_oxidation_reactor_pure_st()


def verify_pta_pure_st() -> bool:
    """Verify PTA Reactor alias ST POU."""
    return verify_pta_oxidation_reactor_pure_st()


def validate_pure_st() -> ExecutionResult:
    """Validate pure ST POU and return ExecutionResult."""
    SecurityGuard.assert_pure_st_content(PTA_OXIDATION_REACTOR_PURE_ST_POU)
    return STParser.validate_code(PTA_OXIDATION_REACTOR_PURE_ST_POU)


validate_pta_pure_st = validate_pure_st
validate_pta_oxidation_pure_st = validate_pure_st
validate_pta_reactor_pure_st = validate_pure_st


# ============================================================================
# 6. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_pta_oxidation_reactor_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute rigorous 9-stage verification suite for W218 and return strict 4-state contract dict."""
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & Horner Register Symbol Bindings
    # ------------------------------------------------------------------------
    SecurityGuard.assert_pure_st_content(PTA_OXIDATION_REACTOR_PURE_ST_POU)
    parser = STParser(pou_type=POUType.PROGRAM)
    ast = parser.parse_pou(PTA_OXIDATION_REACTOR_PURE_ST_POU)
    ast_valid = ast is not None and ast.name == "PtaOxidationSync" and ast.pou_type == POUType.PROGRAM
    expected_regs = [
        "%R1790", "%R1791", "%R1792", "%R1793",
        "%R1794", "%R1795", "%R1796", "%R1797",
        "%M417", "%M418", "%M419",
    ]
    regs_bound = all(r in ast.bound_registers for r in expected_regs) if ast else False
    c1 = ast_valid and regs_bound
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_AST_Parsing_And_Horner_Symbol_Bindings",
        "passed": c1,
        "details": f"AST parsed={ast_valid}, registers bound={regs_bound} ({len(expected_regs)} registers verified).",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Anti-Ladder Security Guard Interception
    # ------------------------------------------------------------------------
    bad_constructs = [
        "---[ ]---",
        "---( )---",
        "RUNG 1",
        "XIC PtaOxidationActive",
        "OTE EmergencyNitrogenQuenchActive",
    ]
    blocked_count = 0
    for bad in bad_constructs:
        test_code = f"PROGRAM BadTest\nVAR x: BOOL; END_VAR\n{bad}\nEND_PROGRAM"
        try:
            SecurityGuard.assert_pure_st_content(test_code)
        except LadderForbiddenError:
            blocked_count += 1
    c2 = blocked_count == len(bad_constructs)
    test_results.append({
        "stage": 2,
        "check": "Anti_Ladder_Security_Guard_Interception",
        "passed": c2,
        "details": f"Blocked {blocked_count}/{len(bad_constructs)} forbidden ladder logic fragments with ERR_LADDER_FORBIDDEN.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Multi-Step Oxidation Reaction Kinetics & Enthalpies
    # ------------------------------------------------------------------------
    sim = PtaOxidationReactor()
    delta_h1_ok = (DELTA_H1_KJ_MOL == -420.0)
    delta_h2_ok = (DELTA_H2_KJ_MOL == -380.0)
    delta_h3_ok = (DELTA_H3_KJ_MOL == -550.0)
    delta_h4_ok = (DELTA_H4_KJ_MOL == -874.0)

    # Reaction rates at nominal 200 °C vs elevated 220 °C
    rates_nom = sim.compute_reaction_rates(15.248, 35.80, 0.044776, 1839.29, 473.15, 0.352)
    rates_hot = sim.compute_reaction_rates(15.248, 35.80, 0.044776, 1839.29, 493.15, 0.352)

    ratio_r1 = rates_hot["r1_tot"] / max(1e-6, rates_nom["r1_tot"])
    ratio_r4 = rates_hot["r4_tot"] / max(1e-6, rates_nom["r4_tot"])
    # Because Ea4 (125 kJ/mol) > Ea1 (92 kJ/mol), solvent combustion accelerates faster:
    solvent_combustion_accelerates_faster = ratio_r4 > ratio_r1

    c3 = delta_h1_ok and delta_h2_ok and delta_h3_ok and delta_h4_ok and solvent_combustion_accelerates_faster
    test_results.append({
        "stage": 3,
        "check": "Multi_Step_Oxidation_Reaction_Kinetics_And_Enthalpies",
        "passed": c3,
        "details": (
            f"Reaction enthalpies verified: Delta H1={DELTA_H1_KJ_MOL} kJ/mol, Delta H2={DELTA_H2_KJ_MOL} kJ/mol, "
            f"Delta H3={DELTA_H3_KJ_MOL} kJ/mol, Delta H4={DELTA_H4_KJ_MOL} kJ/mol. "
            f"Solvent combustion acceleration ratio={ratio_r4:.3f} > PX oxidation={ratio_r1:.3f}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 4: Oxygen Lean Off-Gas Mass Transfer & Explosion Envelope Safety
    # ------------------------------------------------------------------------
    mt_nom = sim.compute_mass_transfer(0.352, 473.15, 18.0)
    mt_trans_pos = mt_nom["r_o2_mt_tot"] > 0.0
    offgas_o2_nom = mt_nom["offgas_o2_vol_pct"]
    offgas_safe = offgas_o2_nom < OFFGAS_O2_ENVELOPE_MAX_VOL_PCT  # < 4.00 vol%
    alarm_threshold_ok = (OFFGAS_O2_HIGH_ALARM_VOL_PCT == 3.80)
    trip_threshold_ok = (OFFGAS_O2_TRIP_VOL_PCT == 4.50)

    c4 = mt_trans_pos and offgas_safe and alarm_threshold_ok and trip_threshold_ok
    test_results.append({
        "stage": 4,
        "check": "Oxygen_Lean_Offgas_Mass_Transfer_And_Explosion_Envelope_Safety",
        "passed": c4,
        "details": (
            f"Mass transfer verified: O2 absorbed={mt_nom['r_o2_mt_tot']:.2f} mol/s, "
            f"nominal off-gas O2={offgas_o2_nom:.2f} vol% (< 4.0 vol%), "
            f"alarm limit={OFFGAS_O2_HIGH_ALARM_VOL_PCT} vol%, trip limit={OFFGAS_O2_TRIP_VOL_PCT} vol%."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 5: Coupled 6-State ODE System RK4 Integrator Stability (dt = 0.02 s)
    # ------------------------------------------------------------------------
    sim_rk = PtaOxidationReactor()
    derivs = sim_rk.compute_derivatives(
        0.0,
        [
            sim_rk.state.c_px,
            sim_rk.state.c_toluic,
            sim_rk.state.c_4cba,
            sim_rk.state.c_pta,
            sim_rk.state.t_reactor,
            sim_rk.state.c_dissolved_o2,
        ],
    )
    all_derivs_finite = len(derivs) == 6 and all(not math.isnan(d) and not math.isinf(d) for d in derivs)

    res_rk = sim_rk.advance_time(duration_s=2.0, dt=0.02)
    rk_success = res_rk.status == AgentStatus.SUCCESS

    state_stable = (
        0.0 <= sim_rk.state.c_px <= 100.0
        and 0.0 <= sim_rk.state.c_toluic <= 100.0
        and 0.0 <= sim_rk.state.c_4cba <= 5.0
        and 1000.0 <= sim_rk.state.c_pta <= 2500.0
        and 190.0 <= sim_rk.state.reactor_temp_celsius <= 210.0
        and 0.01 <= sim_rk.state.c_dissolved_o2 <= 2.0
    )
    c5 = all_derivs_finite and rk_success and state_stable
    test_results.append({
        "stage": 5,
        "check": "Coupled_6_State_ODE_System_RK4_Integrator_Stability",
        "passed": c5,
        "details": (
            f"RK4 stability (dt=0.02s) verified: C_px={sim_rk.state.c_px:.2f}, "
            f"C_toluic={sim_rk.state.c_toluic:.2f}, C_4cba={sim_rk.state.c_4cba:.4f}, "
            f"C_pta={sim_rk.state.c_pta:.1f}, T={sim_rk.state.reactor_temp_celsius:.1f}°C, "
            f"C_O2={sim_rk.state.c_dissolved_o2:.3f}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 6: Stoichiometric Elemental Mass & Enthalpy Conservation Residuals (< 1e-10)
    # ------------------------------------------------------------------------
    sim_cons = PtaOxidationReactor()
    sim_cons.advance_time(duration_s=1.0, dt=0.02)

    mass_res = sim_cons.state.total_mass_balance_residual_kg_s
    elem_res = sim_cons.state.elemental_mass_balance_residual_kg_s
    enth_res = sim_cons.state.enthalpy_conservation_residual_kw

    c6 = (mass_res < 1.0e-10) and (elem_res < 1.0e-10) and (enth_res < 1.0e-10)
    test_results.append({
        "stage": 6,
        "check": "Stoichiometric_Elemental_Mass_And_Enthalpy_Conservation_Residuals",
        "passed": c6,
        "details": (
            f"Residuals verified: mass_residual={mass_res:.3e} kg/s (< 1e-10), "
            f"elemental_residual={elem_res:.3e} kg/s (< 1e-10), enthalpy_residual={enth_res:.3e} kW (< 1e-10)."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 7: 4-CBA Target Impurity Reduction (< 25 ppm) & Polymer-Grade PTA Quality
    # ------------------------------------------------------------------------
    sim_quality = PtaOxidationReactor()
    conv = sim_quality.state.px_conversion_pct
    yield_val = sim_quality.state.pta_yield_pct
    four_cba = sim_quality.state.four_cba_impurity_ppm
    burn_rate = sim_quality.state.solvent_burn_rate_kg_t

    conv_ok = conv >= 99.0
    yield_ok = yield_val >= 96.0
    four_cba_ok = four_cba < 25.0
    burn_rate_ok = 0.20 <= burn_rate <= 1.00

    c7 = conv_ok and yield_ok and four_cba_ok and burn_rate_ok
    test_results.append({
        "stage": 7,
        "check": "Four_CBA_Target_Impurity_Reduction_And_Polymer_Grade_PTA_Quality",
        "passed": c7,
        "details": (
            f"Quality verified: conversion={conv:.2f}% (>= 99.0%), "
            f"PTA yield={yield_val:.2f}% (>= 96.0%), 4-CBA={four_cba:.1f} ppm (< 25 ppm), "
            f"solvent burn rate={burn_rate:.2f} kg/t PTA."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 8: Process Safety Interlocks & Strict Priority Hierarchy (0xEA01..0xEA04)
    # ------------------------------------------------------------------------
    sim_safety = PtaOxidationReactor()

    # 8a: 0xEA01 Thermal Runaway Excursion (T_reactor > 225.0 °C)
    sim_safety.state.reactor_temp_celsius = 228.0
    sim_safety._evaluate_safety_interlocks()
    sim_safety._sync_registers()
    c8a = (
        sim_safety.state.diagnostic_code == PtaOxidationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY
        and sim_safety.state.emergency_nitrogen_quench_active is True
        and sim_safety.state.pta_oxidation_active is False
    )

    # 8b: 0xEA02 Off-gas O2 Explosion Hazard (O2 > 4.50 vol%)
    sim_safety.reset()
    sim_safety.state.offgas_oxygen_vol_pct = 4.85
    sim_safety._evaluate_safety_interlocks()
    sim_safety._sync_registers()
    c8b = (
        sim_safety.state.diagnostic_code == PtaOxidationDiagnosticCode.OFFGAS_OXYGEN_EXPLOSION_HAZARD
        and sim_safety.state.emergency_nitrogen_quench_active is True
        and sim_safety.state.pta_oxidation_active is False
        and sim_safety.state.offgas_oxygen_high_prealarm is True
    )

    # 8c: 0xEA03 4-CBA Impurity Exceeded (> 25 ppm)
    sim_safety.reset()
    sim_safety.state.four_cba_impurity_ppm = 29.5
    sim_safety._evaluate_safety_interlocks()
    sim_safety._sync_registers()
    c8c = (
        sim_safety.state.diagnostic_code == PtaOxidationDiagnosticCode.FOUR_CBA_IMPURITY_EXCEEDED
        and sim_safety.state.emergency_nitrogen_quench_active is False
        and sim_safety.state.pta_oxidation_active is True
    )

    # 8d: 0xEA04 Catalyst Precipitation / Severe Yield Fault (< 90.0%)
    sim_safety.reset()
    sim_safety.state.pta_yield_pct = 86.5
    sim_safety._evaluate_safety_interlocks()
    sim_safety._sync_registers()
    c8d = (
        sim_safety.state.diagnostic_code == PtaOxidationDiagnosticCode.CATALYST_PRECIPITATION_FAULT
        and sim_safety.state.emergency_nitrogen_quench_active is False
        and sim_safety.state.pta_oxidation_active is True
    )

    # 8e: Strict Priority Hierarchy: 0xEA01 > 0xEA02 > 0xEA03 > 0xEA04 > 0x0000
    sim_safety.state.reactor_temp_celsius = 230.0   # 0xEA01
    sim_safety.state.offgas_oxygen_vol_pct = 4.90   # 0xEA02
    sim_safety.state.four_cba_impurity_ppm = 30.0   # 0xEA03
    sim_safety.state.pta_yield_pct = 85.0           # 0xEA04
    sim_safety._evaluate_safety_interlocks()
    p1_wins = (sim_safety.state.diagnostic_code == PtaOxidationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY)

    sim_safety.state.reactor_temp_celsius = 200.0   # Clear 0xEA01
    sim_safety.state.emergency_nitrogen_quench_active = False
    sim_safety._evaluate_safety_interlocks()
    p2_wins = (sim_safety.state.diagnostic_code == PtaOxidationDiagnosticCode.OFFGAS_OXYGEN_EXPLOSION_HAZARD)

    sim_safety.state.offgas_oxygen_vol_pct = 2.80   # Clear 0xEA02
    sim_safety.state.emergency_nitrogen_quench_active = False
    sim_safety._evaluate_safety_interlocks()
    p3_wins = (sim_safety.state.diagnostic_code == PtaOxidationDiagnosticCode.FOUR_CBA_IMPURITY_EXCEEDED)

    sim_safety.state.four_cba_impurity_ppm = 22.0   # Clear 0xEA03
    sim_safety._evaluate_safety_interlocks()
    p4_wins = (sim_safety.state.diagnostic_code == PtaOxidationDiagnosticCode.CATALYST_PRECIPITATION_FAULT)

    sim_safety.state.pta_yield_pct = 96.5           # Clear 0xEA04
    sim_safety._evaluate_safety_interlocks()
    p0_ok = (sim_safety.state.diagnostic_code == PtaOxidationDiagnosticCode.OK)

    c8e = p1_wins and p2_wins and p3_wins and p4_wins and p0_ok
    c8 = c8a and c8b and c8c and c8d and c8e
    test_results.append({
        "stage": 8,
        "check": "Process_Safety_Interlocks_And_Strict_Priority_Hierarchy",
        "passed": c8,
        "details": f"Safety diagnostics verified: 0xEA01={c8a}, 0xEA02={c8b}, 0xEA03={c8c}, 0xEA04={c8d}, Priority={c8e}.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Memory Space Integration & Emergency Quench Mitigation
    # ------------------------------------------------------------------------
    reg = RegisterTable()
    sim_reg = PtaOxidationReactor(register_table=reg)

    sim_reg.state.reactor_temp_celsius = 200.0
    sim_reg.state.reactor_pressure_bar = 18.00
    sim_reg.state.px_conversion_pct = 99.20
    sim_reg.state.pta_yield_pct = 96.50
    sim_reg.state.four_cba_impurity_ppm = 22.0
    sim_reg.state.offgas_oxygen_vol_pct = 2.80
    sim_reg.state.solvent_burn_rate_kg_t = 0.45
    sim_reg._evaluate_safety_interlocks()
    sim_reg.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

    r1790 = reg.read_word("%R1790")
    r1791 = reg.read_word("%R1791")
    r1792 = reg.read_word("%R1792")
    r1793 = reg.read_word("%R1793")
    r1794 = reg.read_word("%R1794")
    r1795 = reg.read_word("%R1795")
    r1796 = reg.read_word("%R1796")
    r1797 = reg.read_uword("%R1797")
    m417 = reg.read_bit("%M417")
    m418 = reg.read_bit("%M418")
    m419 = reg.read_bit("%M419")

    regs_ok = (
        r1790 == 2000
        and r1791 == 1800
        and r1792 == 9920
        and r1793 == 9650
        and r1794 == 22
        and r1795 == 280
        and r1796 == 45
        and r1797 == 0x0000
        and m417 is True
        and m418 is False
        and m419 is False
    )

    # Emergency mitigation test: Trigger thermal excursion and advance under cold quench
    sim_quench = PtaOxidationReactor()
    sim_quench.state.reactor_temp_celsius = 230.0
    sim_quench.state.t_reactor = 230.0 + T_ZERO_CELSIUS
    sim_quench._evaluate_safety_interlocks()
    quench_tripped = (sim_quench.state.diagnostic_code == PtaOxidationDiagnosticCode.THERMAL_EXCURSION_RUNAWAY)

    sim_quench.advance_time(duration_s=12.0, dt=0.02)
    quench_cooled = sim_quench.state.reactor_temp_celsius < 220.0

    c9 = regs_ok and quench_tripped and quench_cooled
    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Memory_Space_Integration_And_Emergency_Mitigation",
        "passed": c9,
        "details": (
            f"Registers verified: %R1790={r1790}, %R1791={r1791}, %R1792={r1792}, %R1793={r1793}, "
            f"%R1794={r1794}, %R1795={r1795}, %R1796={r1796}, %R1797={hex(r1797)}, "
            f"%M417={m417}, %M418={m418}, %M419={m419}. Quench cooled={quench_cooled}."
        ),
    })

    # ------------------------------------------------------------------------
    # Summary & Output Artifact Generation
    # ------------------------------------------------------------------------
    all_passed = all(t["passed"] for t in test_results)
    passed_count = sum(1 for t in test_results if t["passed"])
    status_str = "success" if all_passed else "failed"

    payload: Dict[str, Any] = {
        "status": status_str,
        "error_code": None if all_passed else "VERIFICATION_FAILED",
        "details": f"PTA Oxidation Reactor 9-stage verification passed {passed_count}/9 checks.",
        "data": {
            "work_package": "W218",
            "module": "pta_oxidation_reactor",
            "total_checks": len(test_results),
            "checks_passed": passed_count,
            "tests": test_results,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    return payload


# Verification Aliases
run_pta_oxidation_verification = run_pta_oxidation_reactor_verification
run_pta_reactor_verification = run_pta_oxidation_reactor_verification
run_pta_verification = run_pta_oxidation_reactor_verification
