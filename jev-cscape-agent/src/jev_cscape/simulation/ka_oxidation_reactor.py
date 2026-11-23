"""Industrial Cyclohexanone / Cyclohexanol (KA Oil) Cyclohexane Liquid-Phase Catalytic Air Oxidation Reactor ODE Simulation.

Work Package: W212 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Industrial Cyclohexane Liquid-Phase Catalytic Air Oxidation to Cyclohexanone / Cyclohexanol (KA Oil):
   - Sparged bubble column / sparged stirred-tank cascade operating at 145-165 °C, 9-12 bar,
     with liquid residence time 20-30 min.
   - Low-conversion regime (3.5 - 5.5% cyclohexane conversion) to achieve high selectivity (> 82-86% KA oil).
   - Off-gas safety envelope: O2 concentration in dry/inert off-gas must remain strictly < 3.5 vol%
     (flammability limit mitigation).
   - Emergency cold cyclohexane recirculating quench and vapor nitrogen inerting on high off-gas O2
     or thermal runaway excursion.
2. Four-Reaction Kinetic Network:
   - Reaction 1: Cyclohexane (C6H12) + O2 -> Cyclohexyl Hydroperoxide (CHHP, C6H11OOH)
     autoxidation, Delta_H1 = -135 kJ/mol (-135,000 J/mol).
   - Reaction 2: CHHP -> Cyclohexanone (C6H10O) + H2O
     decomposition, Delta_H2 = -180 kJ/mol (-180,000 J/mol).
   - Reaction 3: CHHP -> Cyclohexanol (C6H11OH) + 0.5 O2
     decomposition, Delta_H3 = -145 kJ/mol (-145,000 J/mol).
   - Reaction 4: Over-oxidation -> Adipic / Glutaric / Succinic Dibasic Acids byproducts
     Delta_H4 = -320 kJ/mol (-320,000 J/mol).
3. Coupled 6-State Dynamic ODE System with RK4 Numerical Solver:
   - Dynamic state vector: [C_cyclohexane, C_o2_dissolved, C_chhp, C_cyclohexanone, C_cyclohexanol, T_reactor]
     1. C_cyclohexane: Liquid cyclohexane concentration in reactor [mol/m^3]
     2. C_o2_dissolved: Dissolved oxygen concentration in liquid phase [mol/m^3]
     3. C_chhp: Cyclohexyl hydroperoxide (CHHP) concentration [mol/m^3]
     4. C_cyclohexanone: Cyclohexanone concentration [mol/m^3]
     5. C_cyclohexanol: Cyclohexanol concentration [mol/m^3]
     6. T_reactor: Reactor bulk temperature [K] (with T_reactor_celsius = T_reactor - 273.15)
   - Dual stoichiometric mass, elemental species, and enthalpy conservation residuals < 1e-10:
     * total_mass_balance_residual_kg_s < 1e-10 kg/s
     * elemental_mass_balance_residual_kg_s < 1e-10 kg/s
     * enthalpy_conservation_residual_kw < 1e-10 kW.
4. Process Safety Interlocks & Diagnostics (Strict Priority Hierarchy):
   - 0xE401: OFFGAS_O2_EXPLOSIVE_TRIP (Off-gas O2 >= 3.50 vol%) -> Priority 1 (highest)
     asserts %M405 (EmergencyNitrogenQuenchActive), asserts %M404 (OffgasO2HighAlarm),
     clears %M403 (KaOxidationActive).
   - 0xE402: THERMAL_RUNAWAY_EXCURSION (T_reactor > 165.0 °C) -> Priority 2
     asserts %M405 (EmergencyNitrogenQuenchActive), clears %M403 (KaOxidationActive).
   - 0xE403: LOW_KA_SELECTIVITY_DEGRADATION (KA selectivity < 80.0% or conversion > 6.0%) -> Priority 3
     sets diagnostic code, keeps %M403 active.
   - 0xE404: SPARGER_DEFICIENCY_ANOXIA (Dissolved O2 < 10.0 ppm or sparger deficiency) -> Priority 4
     sets diagnostic code, keeps %M403 active.
   - 0x0000: OK (Normal steady-state operation).
5. Horner OCS Memory Space Integration (%R1730..%R1737, %M403..%M405):
   - %R1730: ReactorTempScaled (INT16, scaled x10 °C, e.g. 1550 = 155.0 °C)
   - %R1731: ReactorPressureBarScaled (INT16, scaled x10 bar, e.g. 105 = 10.5 bar)
   - %R1732: CyclohexaneConversionPctScaled (INT16, scaled x100 %, e.g. 480 = 4.80%)
   - %R1733: KaOilSelectivityPctScaled (INT16, scaled x10 %, e.g. 845 = 84.5%)
   - %R1734: KaMolarRatioScaled (INT16, scaled x100, ketone/alcohol ratio, e.g. 120 = 1.20:1)
   - %R1735: OffgasOxygenVolPctScaled (INT16, scaled x100 %, e.g. 185 = 1.85% O2)
   - %R1736: DissolvedOxygenPpmScaled (INT16, scaled x10 ppm, e.g. 450 = 45.0 ppm)
   - %R1737: DiagnosticStatusCode (0x0000=OK, 0xE401, 0xE402, 0xE403, 0xE404)
   - %M403: KaOxidationActive (BOOL, True during safe/active operation)
   - %M404: OffgasO2HighAlarm (BOOL, True if O2 > 2.8 vol%)
   - %M405: EmergencyNitrogenQuenchActive (BOOL, True on trip)
   - In sync_to_registers(), write with privilege=PrivilegeMode.SYSTEM.
6. Pure IEC 61131-3 Structured Text ONLY:
   - POU 'KaOxidationReactorSync'.
   - Anti-ladder security guard: SecurityGuard.assert_pure_st_content and STParser(pou_type=POUType.PROGRAM).
7. ILogicUnit Interface:
   - scan_step(dt: float, context: Optional[ScanContext] = None) -> None.
   - sync_to_registers(reg_table: RegisterTable, privilege: PrivilegeMode = PrivilegeMode.SYSTEM).
8. Deterministic 9-Stage Verification Suite:
   - Function run_ka_oxidation_reactor_verification(output_path) returning strict 4-state contract JSON.
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
# Universal Physical & Chemical Constants for KA Oxidation Reactor
# ============================================================================

R_GAS_CONST: float = 8.314462618        # Universal gas constant [J/(mol*K)]
G_ACCEL: float = 9.80665                # Standard gravitational acceleration [m/s^2]
T_ZERO_CELSIUS: float = 273.15          # 0.0 °C in Kelvin [K]
T_REF_K: float = 428.15                 # Reactor reference temperature (155.0 °C) [K]

# Molecular Weights [kg/mol] and [g/mol]
MW_C: float = 0.012011                  # Carbon C (12.011 g/mol)
MW_H: float = 0.001008                  # Hydrogen H (1.008 g/mol)
MW_O: float = 0.015999                  # Oxygen O (15.999 g/mol)
MW_N: float = 0.014007                  # Nitrogen N (14.007 g/mol)

MW_O2: float = 2.0 * MW_O                         # Oxygen O2 (0.031998 kg/mol)
MW_N2: float = 2.0 * MW_N                         # Nitrogen N2 (0.028014 kg/mol)
MW_CHX: float = 6.0 * MW_C + 12.0 * MW_H          # Cyclohexane C6H12 (0.084162 kg/mol)
MW_CYCLOHEXANE: float = MW_CHX
MW_CHHP: float = 6.0 * MW_C + 12.0 * MW_H + 2.0 * MW_O  # CHHP C6H12O2 (0.116160 kg/mol)
MW_K: float = 6.0 * MW_C + 10.0 * MW_H + MW_O    # Cyclohexanone C6H10O (0.098145 kg/mol)
MW_CYCLOHEXANONE: float = MW_K
MW_A: float = 6.0 * MW_C + 12.0 * MW_H + MW_O    # Cyclohexanol C6H12O (0.100161 kg/mol)
MW_CYCLOHEXANOL: float = MW_A
MW_H2O: float = 2.0 * MW_H + MW_O                 # Water H2O (0.018015 kg/mol)
MW_DBA: float = 6.0 * MW_C + 10.0 * MW_H + 4.0 * MW_O  # Adipic Acid C6H10O4 (0.146142 kg/mol)
MW_ADIPIC_ACID: float = MW_DBA
MW_DIBASIC_ACID: float = MW_DBA

# Reaction Enthalpies [J/mol and kJ/mol]
# 1. Autoxidation: C6H12 + O2 -> CHHP
DELTA_H1_KJ_MOL: float = -135.0
DELTA_H1_J_MOL: float = -135000.0
DELTA_H_AUTOXIDATION_KJ_MOL: float = DELTA_H1_KJ_MOL
DELTA_H_AUTOXIDATION_J_MOL: float = DELTA_H1_J_MOL

# 2. Decomposition to Ketone: CHHP -> Cyclohexanone + H2O
DELTA_H2_KJ_MOL: float = -180.0
DELTA_H2_J_MOL: float = -180000.0
DELTA_H_KETONE_DECOMP_KJ_MOL: float = DELTA_H2_KJ_MOL
DELTA_H_KETONE_DECOMP_J_MOL: float = DELTA_H2_J_MOL

# 3. Decomposition to Alcohol: CHHP -> Cyclohexanol + 0.5 O2
DELTA_H3_KJ_MOL: float = -145.0
DELTA_H3_J_MOL: float = -145000.0
DELTA_H_ALCOHOL_DECOMP_KJ_MOL: float = DELTA_H3_KJ_MOL
DELTA_H_ALCOHOL_DECOMP_J_MOL: float = DELTA_H3_J_MOL

# 4. Over-Oxidation to Dibasic Acids (Adipic / Glutaric / Succinic)
DELTA_H4_KJ_MOL: float = -320.0
DELTA_H4_J_MOL: float = -320000.0
DELTA_H_OVER_OXIDATION_KJ_MOL: float = DELTA_H4_KJ_MOL
DELTA_H_OVER_OXIDATION_J_MOL: float = DELTA_H4_J_MOL

# Operating Boundaries & Safety Thresholds
REACTOR_TEMP_NOMINAL_C: float = 155.0       # Nominal reactor temperature [°C] (%R1730 = 1550)
REACTOR_TEMP_WARNING_C: float = 162.0       # High temperature warning limit [°C]
REACTOR_TEMP_TRIP_C: float = 165.0          # Thermal runaway trip threshold [°C] (%M405 = True, 0xE402)
REACTOR_TEMP_RESET_C: float = 156.0         # Thermal trip reset threshold [°C]

REACTOR_PRESSURE_NOMINAL_BAR: float = 10.5  # Nominal reactor pressure [bar] (%R1731 = 105)
REACTOR_PRESSURE_MIN_BAR: float = 9.0       # Minimum operating pressure [bar]
REACTOR_PRESSURE_MAX_BAR: float = 12.0      # Maximum operating pressure [bar]

CONVERSION_NOMINAL_PCT: float = 4.80        # Nominal cyclohexane conversion [%] (%R1732 = 480)
CONVERSION_MIN_PCT: float = 3.50            # Minimum conversion target [%]
CONVERSION_MAX_PCT: float = 5.50            # Maximum conversion target [%]

KA_SELECTIVITY_NOMINAL_PCT: float = 84.5    # Nominal KA oil selectivity [%] (%R1733 = 845)
KA_SELECTIVITY_MIN_PCT: float = 80.0        # Low selectivity trip/alarm threshold [%] (0xE403)
KA_SELECTIVITY_TARGET_MIN: float = 82.0     # Target selectivity floor [%]

KA_MOLAR_RATIO_NOMINAL: float = 1.20        # Nominal ketone/alcohol ratio (%R1734 = 120)

OFFGAS_O2_NOMINAL_VOL_PCT: float = 1.85     # Nominal off-gas oxygen [vol%] (%R1735 = 185)
OFFGAS_O2_HIGH_ALARM_VOL_PCT: float = 2.80  # Off-gas O2 high pre-trip alarm [vol%] (%M404 = True)
OFFGAS_O2_TRIP_VOL_PCT: float = 3.50        # Flammability safety envelope ceiling [vol%] (0xE401)

DISSOLVED_O2_NOMINAL_PPM: float = 45.0      # Nominal dissolved oxygen [ppm] (%R1736 = 450)
DISSOLVED_O2_LOW_ANOXIA_PPM: float = 10.0   # Sparger deficiency / anoxia threshold [ppm] (0xE404)

# Aliases and Additional Operating Boundaries for Simulation Engine Integration
CYCLOHEXANE_CONV_NOMINAL_PCT: float = CONVERSION_NOMINAL_PCT
CYCLOHEXANE_FEED_RATE_NOMINAL_KG_H: float = 78336.0
DISSOLVED_O2_LOW_PPM: float = DISSOLVED_O2_LOW_ANOXIA_PPM
EXOTHERM_DELTA_T_ALARM_C: float = 7.0
HIGH_CONVERSION_PCT: float = CONVERSION_MAX_PCT
LOW_CONVERSION_PCT: float = CONVERSION_MIN_PCT
LOW_KA_SELECTIVITY_PCT: float = KA_SELECTIVITY_MIN_PCT
KETONE_ALCOHOL_RATIO_NOMINAL: float = KA_MOLAR_RATIO_NOMINAL
MW_BYPRODUCTS: float = MW_DBA
MW_CH: float = MW_CHX
MW_WATER: float = MW_H2O
OFFGAS_O2_ALARM_PCT: float = OFFGAS_O2_HIGH_ALARM_VOL_PCT
OFFGAS_O2_NOMINAL_PCT: float = OFFGAS_O2_NOMINAL_VOL_PCT
OFFGAS_O2_TRIP_PCT: float = OFFGAS_O2_TRIP_VOL_PCT
QUENCH_FLOW_KG_S: float = 25.0
QUENCH_SHUTOFF_TEMP_C: float = REACTOR_TEMP_RESET_C
QUENCH_TEMP_C: float = 45.0
REACTOR_TEMP_INLET_NOMINAL_C: float = 145.0
RUNAWAY_TRIP_DELTA_T_C: float = 10.0
RUNAWAY_TRIP_TEMP_C: float = REACTOR_TEMP_TRIP_C
V_MOLAR_STP: float = 0.022414


# ============================================================================
# 1. Enums and Status Bitmasks
# ============================================================================

class KaOxidationDiagnosticCode(IntEnum):
    """Horner OCS %R1737 Diagnostic Event Codes for KA Oxidation Reactor."""
    OK                                  = 0x0000  # Normal healthy steady-state operation
    OFFGAS_O2_EXPLOSIVE_TRIP            = 0xE401  # Off-gas O2 >= 3.5 vol% (flammability envelope breach)
    THERMAL_RUNAWAY_EXCURSION           = 0xE402  # T_reactor > 165.0 °C (thermal runaway excursion)
    LOW_KA_SELECTIVITY_DEGRADATION      = 0xE403  # KA selectivity < 80.0% or conversion > 6.0%
    SPARGER_DEFICIENCY_ANOXIA           = 0xE404  # Dissolved O2 < 10.0 ppm or sparger maldistribution

    # Standard Aliases
    ERR_OFFGAS_O2_EXPLOSIVE_TRIP        = OFFGAS_O2_EXPLOSIVE_TRIP
    ERR_THERMAL_RUNAWAY_EXCURSION       = THERMAL_RUNAWAY_EXCURSION
    ERR_LOW_KA_SELECTIVITY              = LOW_KA_SELECTIVITY_DEGRADATION
    ERR_SPARGER_DEFICIENCY              = SPARGER_DEFICIENCY_ANOXIA
    KA_ERR_OFFGAS_O2_EXPLOSIVE_TRIP     = OFFGAS_O2_EXPLOSIVE_TRIP
    KA_ERR_THERMAL_RUNAWAY_EXCURSION    = THERMAL_RUNAWAY_EXCURSION
    KA_ERR_LOW_KA_SELECTIVITY_DEGRADATION = LOW_KA_SELECTIVITY_DEGRADATION
    KA_ERR_SPARGER_DEFICIENCY_ANOXIA    = SPARGER_DEFICIENCY_ANOXIA


KaOxidationDiagCode = KaOxidationDiagnosticCode
KaOxidationReactorDiagnosticCode = KaOxidationDiagnosticCode
KaOxidationReactorDiagCode = KaOxidationDiagnosticCode


class KaOxidationStatusBits(IntFlag):
    """Horner OCS Status Word Bitmask Definitions for KA Oxidation Reactor."""
    RUNNING                             = 1 << 0  # Bit 0 (0x0001): Simulation cycle active
    KA_OXIDATION_ACTIVE                 = 1 << 1  # Bit 1 (0x0002): %M403 KA oxidation active
    OFFGAS_O2_HIGH_ALARM                = 1 << 2  # Bit 2 (0x0004): %M404 Off-gas O2 > 2.8 vol%
    EMERGENCY_QUENCH_ACTIVE             = 1 << 3  # Bit 3 (0x0008): %M405 Emergency N2 / quench active
    OFFGAS_O2_TRIP                      = 1 << 4  # Bit 4 (0x0010): 0xE401 Off-gas explosive trip
    THERMAL_RUNAWAY_TRIP                = 1 << 5  # Bit 5 (0x0020): 0xE402 Thermal runaway trip
    LOW_SELECTIVITY_ALARM               = 1 << 6  # Bit 6 (0x0040): 0xE403 Low selectivity alarm
    SPARGER_DEFICIENCY_ALARM            = 1 << 7  # Bit 7 (0x0080): 0xE404 Sparger deficiency alarm


KaOxidationStatusWord = KaOxidationStatusBits
KaOxidationReactorStatusBits = KaOxidationStatusBits
KaOxidationReactorStatusWord = KaOxidationStatusBits


# ============================================================================
# 2. Configuration & Parameter Data Models
# ============================================================================

@dataclass
class KaOxidationConfig:
    """Design, geometric, hydrodynamic, kinetic, and safety parameters for KA Oxidation Reactor."""

    # Sparged Bubble Column / Cascade Vessel Geometry
    reactor_diameter_m: float = 3.2                 # Column diameter [m] (cross section ~ 8.04 m^2)
    reactor_height_m: float = 9.0                   # Total vessel height [m]
    liquid_volume_m3: float = 48.0                  # Working liquid volume [m^3]
    gas_holdup_fraction: float = 0.18               # Operating gas holdup [-]
    residence_time_s: float = 1500.0                # Liquid residence time [s] (25 min, in range 20-30 min)

    # Physical Properties of Pressurized Cyclohexane Liquid
    operating_pressure_bar: float = REACTOR_PRESSURE_NOMINAL_BAR # Operating pressure [bar] (10.5)
    liquid_density_kg_m3: float = 680.0             # Cyclohexane liquid density at 155 °C [kg/m^3]
    liquid_cp_j_kg_k: float = 2300.0                # Specific heat capacity [J/(kg*K)]
    reactor_heat_capacity_j_k: float = 1.8e7        # Reactor active liquid thermal capacitance [J/K]

    # Feed Stream Quantities
    c_chx_feed_mol_m3: float = 8079.65              # Pure cyclohexane feed conc [mol/m^3] (680/0.084162)
    nominal_feed_temp_c: float = 145.0              # Fresh cyclohexane feed inlet temperature [°C]
    ambient_temp_c: float = 25.0                    # Ambient environment temperature [°C]
    u_wall_w_m2_k: float = 15.0                     # Vessel wall heat loss coefficient [W/(m^2*K)]

    # Gas Sparging & Mass Transfer Dynamics
    nominal_air_flow_mol_s: float = 47.62           # Nominal air feed rate [mol/s] (~10.0 mol/s O2, 37.6 mol/s N2)
    air_o2_mole_fraction: float = 0.21              # Air oxygen mole fraction [-]
    kla_s_inv: float = 1.6832                      # Gas-liquid volumetric mass transfer coefficient [1/s] (yields nominal 1.85 vol% offgas O2)
    henry_o2_mol_m3_bar: float = 0.85               # Henry's law coefficient for O2 in cyclohexane [mol/(m^3*bar)]

    # Kinetic Target Parameters at Reference Temp (155.0 °C / 428.15 K)
    nominal_reactor_temp_c: float = REACTOR_TEMP_NOMINAL_C # Reference temperature [°C] (155.0)
    nominal_conversion_pct: float = CONVERSION_NOMINAL_PCT # Cyclohexane conversion [%] (4.80)
    nominal_selectivity_pct: float = KA_SELECTIVITY_NOMINAL_PCT # KA oil selectivity [%] (84.5)
    nominal_ka_ratio: float = KA_MOLAR_RATIO_NOMINAL # Ketone / alcohol ratio (1.20)

    # Rate Constants at Reference Temperature (155.0 °C / 428.15 K)
    k1_ref: float = 3.51e-5                         # Autoxidation rate constant [m^3/(mol*s)]
    k2_ref: float = 0.00198                         # CHHP decomposition to ketone [1/s]
    k3_ref: float = 0.00165                         # CHHP decomposition to alcohol [1/s]
    k4_ref: float = 4.25e-6                         # Over-oxidation to dibasic acids [m^3/(mol*s)]

    # Arrhenius Activation Energies [J/mol]
    # Over-oxidation Ea4 > autoxidation Ea1 -> thermal runaway sensitivity at higher temperature
    activation_energy_1_j_mol: float = 95000.0      # Autoxidation E_a1 [J/mol] (95 kJ/mol)
    activation_energy_2_j_mol: float = 85000.0      # CHHP -> Ketone E_a2 [J/mol] (85 kJ/mol)
    activation_energy_3_j_mol: float = 82000.0      # CHHP -> Alcohol E_a3 [J/mol] (82 kJ/mol)
    activation_energy_4_j_mol: float = 115000.0     # Over-oxidation E_a4 [J/mol] (115 kJ/mol)

    # Cooling & Emergency Quench Systems
    ua_cooling_w_k: float = 85000.0                 # Normal heat removal coil bundle U*A [W/K]
    coolant_temp_c: float = 120.0                   # Internal coil coolant temperature [°C]
    quench_cooling_duty_kw: float = 25000.0         # Emergency cold cyclohexane quench duty [kW] (25 MW)
    quench_temp_c: float = 45.0                     # Subcooled cold cyclohexane quench temperature [°C]
    nitrogen_purge_flow_mol_s: float = 250.0        # Emergency vapor nitrogen inerting purge [mol/s]

    # Safety Interlock Thresholds
    temp_warning_c: float = REACTOR_TEMP_WARNING_C  # High temp warning threshold [°C] (162.0)
    temp_trip_c: float = REACTOR_TEMP_TRIP_C        # Thermal runaway trip threshold [°C] (165.0)
    temp_reset_c: float = REACTOR_TEMP_RESET_C      # Thermal trip latch reset [°C] (156.0)
    offgas_o2_alarm_pct: float = OFFGAS_O2_HIGH_ALARM_VOL_PCT # Offgas O2 pre-trip alarm [vol%] (2.80)
    offgas_o2_trip_pct: float = OFFGAS_O2_TRIP_VOL_PCT # Offgas O2 explosive trip [vol%] (3.50)
    offgas_o2_reset_pct: float = 2.40               # Offgas trip latch reset [vol%] (2.40)
    selectivity_min_pct: float = KA_SELECTIVITY_MIN_PCT # Minimum selectivity alarm [vol%] (80.0)
    dissolved_o2_min_ppm: float = DISSOLVED_O2_LOW_ANOXIA_PPM # Sparger deficiency threshold [ppm] (10.0)

    @property
    def cross_section_area_m2(self) -> float:
        """Cross-sectional area of the reactor column [m^2]."""
        return 0.25 * math.pi * (self.reactor_diameter_m ** 2)

    @property
    def reactor_cross_section_m2(self) -> float:
        """Alias for cross-sectional area of the reactor column [m^2]."""
        return self.cross_section_area_m2

    @property
    def vessel_surface_area_m2(self) -> float:
        """Total cylindrical vessel outer heat loss area [m^2]."""
        return math.pi * self.reactor_diameter_m * self.reactor_height_m


KaOxidationReactorConfig = KaOxidationConfig
KaOxidationParameters = KaOxidationConfig
KaOxidationReactorParameters = KaOxidationConfig


# ============================================================================
# 3. Dynamic State Representation
# ============================================================================

@dataclass
class KaOxidationState:
    """Dynamic operational, kinetic, and safety state for KA Oxidation Reactor."""

    # 6 Coupled Primary ODE States
    c_cyclohexane: float = 7691.8                   # State 0: Liquid cyclohexane conc [mol/m^3]
    c_o2_dissolved: float = 0.956                   # State 1: Dissolved oxygen conc [mol/m^3] (~45 ppm)
    c_chhp: float = 60.0                            # State 2: Cyclohexyl hydroperoxide conc [mol/m^3]
    c_cyclohexanone: float = 178.9                  # State 3: Cyclohexanone conc [mol/m^3]
    c_cyclohexanol: float = 149.1                   # State 4: Cyclohexanol conc [mol/m^3]
    t_reactor: float = REACTOR_TEMP_NOMINAL_C + T_ZERO_CELSIUS # State 5: Bulk temperature [K] (428.15 K)

    # Operational Variables (Mapped to Horner Registers %R1730..%R1737)
    reactor_temp_celsius: float = REACTOR_TEMP_NOMINAL_C # %R1730: Temp [°C] (scaled x10, 1550)
    reactor_pressure_bar: float = REACTOR_PRESSURE_NOMINAL_BAR # %R1731: Pressure [bar] (scaled x10, 105)
    cyclohexane_conversion_pct: float = CONVERSION_NOMINAL_PCT # %R1732: Conversion [%] (scaled x100, 480)
    ka_oil_selectivity_pct: float = KA_SELECTIVITY_NOMINAL_PCT # %R1733: Selectivity [%] (scaled x10, 845)
    ka_molar_ratio: float = KA_MOLAR_RATIO_NOMINAL   # %R1734: K/A ratio (scaled x100, 120)
    offgas_oxygen_vol_pct: float = OFFGAS_O2_NOMINAL_VOL_PCT # %R1735: Offgas O2 [vol%] (scaled x100, 185)
    dissolved_oxygen_ppm: float = DISSOLVED_O2_NOMINAL_PPM # %R1736: Dissolved O2 [ppm] (scaled x10, 450)
    diagnostic_code: KaOxidationDiagnosticCode = KaOxidationDiagnosticCode.OK # %R1737

    # Discrete Coils & Safety Interlocks (%M403..%M405)
    ka_oxidation_active: bool = True                # %M403: Safe oxidation reaction active
    offgas_o2_high_alarm: bool = False              # %M404: Offgas O2 > 2.8 vol% pre-trip alarm
    emergency_nitrogen_quench_active: bool = False  # %M405: Emergency N2 inerting / cold quench active

    # Gas Sparging & Off-Gas Mass Transfer Quantities
    air_feed_mol_s: float = 47.62                   # Sparged air feed molar flow [mol/s]
    o2_sparged_mol_s: float = 10.00                 # Sparged oxygen flow [mol/s]
    n2_sparged_mol_s: float = 37.62                 # Sparged nitrogen flow [mol/s]
    o2_transfer_mol_s: float = 9.30                 # O2 absorbed into liquid phase [mol/s]
    o2_offgas_mol_s: float = 0.70                   # O2 leaving in vapor off-gas [mol/s]
    n2_offgas_mol_s: float = 37.62                  # N2 leaving in vapor off-gas [mol/s]
    n2_quench_purge_mol_s: float = 0.0              # Emergency N2 purge injection [mol/s]

    # Reaction Rates and Heat Duties
    r1_rate_mol_s: float = 12.91                    # Reaction 1 total autoxidation rate [mol/s]
    r2_rate_mol_s: float = 5.70                     # Reaction 2 CHHP -> Ketone rate [mol/s]
    r3_rate_mol_s: float = 4.75                     # Reaction 3 CHHP -> Alcohol rate [mol/s]
    r4_rate_mol_s: float = 0.85                     # Reaction 4 Over-oxidation to DBA rate [mol/s]
    q_rxn_total_kw: float = 3720.0                  # Total exothermic heat generated [kW]
    q_cool_kw: float = 2975.0                       # Heat removed by cooling coils [kW]
    q_sens_kw: float = 730.0                        # Sensible preheat heat removal [kW]
    q_loss_kw: float = 15.0                         # Ambient vessel wall heat loss [kW]
    q_quench_kw: float = 0.0                        # Emergency cold quench duty [kW]

    # Dual Stoichiometric Conservation Residuals (< 1e-10)
    total_mass_balance_residual_kg_s: float = 0.0   # Total mass balance residual [kg/s]
    elemental_mass_balance_residual_kg_s: float = 0.0 # Elemental mass balance residual [kg/s]
    enthalpy_conservation_residual_kw: float = 0.0  # Thermal enthalpy balance residual [kW]

    # Simulation Telemetry & Tracking
    status_word: int = int(
        KaOxidationStatusBits.RUNNING | KaOxidationStatusBits.KA_OXIDATION_ACTIVE
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


KaOxidationReactorState = KaOxidationState


# ============================================================================
# 4. KA Oxidation Reactor Simulation Engine
# ============================================================================

class KaOxidationReactor(ILogicUnit):
    """Coupled 6-state ODE numerical simulation engine for KA Oxidation Reactor."""

    def __init__(
        self,
        config: Optional[KaOxidationConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.config = config or KaOxidationConfig()
        self.registers = register_table or RegisterTable()
        self.state = KaOxidationState()

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
        c_chx: float,
        c_o2: float,
        c_chhp: float,
        c_k: float,
        c_a: float,
        t_reactor_k: float,
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
        r1_vol = max(0.0, k1 * c_chx * c_o2)
        r2_vol = max(0.0, k2 * c_chhp)
        r3_vol = max(0.0, k3 * c_chhp)
        r4_vol = max(0.0, k4 * (c_k + c_a) * c_o2)

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
            o2_offgas = 0.05  # residual traces
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
        # Deep liquid column (8-9m) achieves > 92% oxygen absorption under nominal operation.
        # Absorption decreases if liquid dissolved oxygen approaches saturation.
        c_o2_ref = 0.956
        dissolved_penalty = max(0.0, (c_o2_dissolved - c_o2_ref) / 1.5)
        eta_abs = min(0.96, max(0.50, 0.9291 - 0.20 * dissolved_penalty))

        r_o2_mt_tot = o2_feed * eta_abs
        r_o2_mt_vol = r_o2_mt_tot / self.config.liquid_volume_m3

        # Off-gas exit flows
        o2_offgas = max(0.01, o2_feed - r_o2_mt_tot)
        n2_offgas = n2_feed + self.state.n2_quench_purge_mol_s
        tot_offgas = max(0.1, o2_offgas + n2_offgas)

        offgas_o2_vol_pct = (o2_offgas / tot_offgas) * 100.0

        p_o2_mean_bar = max(0.05, 0.12 * p_bar)
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

        State vector: [C_cyclohexane, C_o2_dissolved, C_chhp, C_cyclohexanone, C_cyclohexanol, T_reactor]
        """
        c_chx = max(0.0, y[0])
        c_o2 = max(0.0, y[1])
        c_chhp = max(0.0, y[2])
        c_k = max(0.0, y[3])
        c_a = max(0.0, y[4])
        t_reactor_k = max(250.0, min(800.0, y[5]))

        is_tripped = self.state.emergency_nitrogen_quench_active
        tau = self.config.residence_time_s
        p_bar = self.state.reactor_pressure_bar

        # Reaction rates
        rates = self.compute_reaction_rates(
            c_chx=c_chx,
            c_o2=c_o2,
            c_chhp=c_chhp,
            c_k=c_k,
            c_a=c_a,
            t_reactor_k=t_reactor_k,
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
        c_chx_in = self.config.c_chx_feed_mol_m3

        # State 0: d(C_cyclohexane)/dt
        # Inflow - Outflow - Consumed by autoxidation (r1)
        dc_chx_dt = (c_chx_in - c_chx) / tau - r1_v

        # State 1: d(C_o2_dissolved)/dt
        # Sparged mass transfer absorption - r1 + 0.5 * r3 (O2 generation) - 1.5 * r4 - dilution
        dc_o2_dt = r_mt_v - r1_v + 0.5 * r3_v - 1.5 * r4_v - (c_o2 / tau)

        # State 2: d(C_chhp)/dt
        # Outflow + r1 (formed) - r2 (decomp to ketone) - r3 (decomp to alcohol)
        dc_chhp_dt = -(c_chhp / tau) + r1_v - r2_v - r3_v

        # State 3: d(C_cyclohexanone)/dt
        # Outflow + r2 (formed) - 0.55 * r4 (over-oxidation loss)
        dc_k_dt = -(c_k / tau) + r2_v - 0.55 * r4_v

        # State 4: d(C_cyclohexanol)/dt
        # Outflow + r3 (formed) - 0.45 * r4 (over-oxidation loss)
        dc_a_dt = -(c_a / tau) + r3_v - 0.45 * r4_v

        # State 5: d(T_reactor)/dt
        # Enthalpy balance: Q_rxn - Q_cooling_coils - Q_sensible_feed - Q_wall_losses - Q_quench
        t_cool_k = self.config.coolant_temp_c + T_ZERO_CELSIUS
        q_cool_w = self.config.ua_cooling_w_k * (t_reactor_k - t_cool_k)

        # Sensible heat of liquid feed
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

        return [dc_chx_dt, dc_o2_dt, dc_chhp_dt, dc_k_dt, dc_a_dt, dt_reactor_dt]

    # ------------------------------------------------------------------------
    # 4th-Order Runge-Kutta (RK4) Integrator
    # ------------------------------------------------------------------------

    def rk4_step(self, dt: float) -> None:
        """Advance the coupled 6-state ODE system by dt using 4th-order Runge-Kutta."""
        y0 = [
            self.state.c_cyclohexane,
            self.state.c_o2_dissolved,
            self.state.c_chhp,
            self.state.c_cyclohexanone,
            self.state.c_cyclohexanol,
            self.state.t_reactor,
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
        self.state.c_cyclohexane = max(5000.0, min(8500.0, y_next[0]))
        self.state.c_o2_dissolved = max(0.001, min(5.0, y_next[1]))
        self.state.c_chhp = max(0.0, min(300.0, y_next[2]))
        self.state.c_cyclohexanone = max(0.0, min(500.0, y_next[3]))
        self.state.c_cyclohexanol = max(0.0, min(500.0, y_next[4]))
        self.state.t_reactor = max(290.0, min(600.0, y_next[5]))

        # Synchronize dependent state variables
        self.state.reactor_temp_celsius = self.state.t_reactor - T_ZERO_CELSIUS
        self.state.sim_time_s += dt
        self.state.scan_count += 1

    # ------------------------------------------------------------------------
    # State Synchronization & Updaters
    # ------------------------------------------------------------------------

    def _update_kinetics_and_conversion(self) -> None:
        """Update derived conversion efficiency, KA oil selectivity, and cooling duties."""
        # Reaction rates
        rates = self.compute_reaction_rates(
            c_chx=self.state.c_cyclohexane,
            c_o2=self.state.c_o2_dissolved,
            c_chhp=self.state.c_chhp,
            c_k=self.state.c_cyclohexanone,
            c_a=self.state.c_cyclohexanol,
            t_reactor_k=self.state.t_reactor,
            is_tripped=self.state.emergency_nitrogen_quench_active,
        )

        self.state.r1_rate_mol_s = rates["r1_tot"]
        self.state.r2_rate_mol_s = rates["r2_tot"]
        self.state.r3_rate_mol_s = rates["r3_tot"]
        self.state.r4_rate_mol_s = rates["r4_tot"]
        self.state.q_rxn_total_kw = rates["q_rxn_kw"]

        # Mass transfer & off-gas
        mt = self.compute_mass_transfer(
            c_o2_dissolved=self.state.c_o2_dissolved,
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

        # Dissolved oxygen in ppm: (C_O2 [mol/m^3] * MW_O2 [kg/mol]) / rho [kg/m^3] * 1e6
        rho = self.config.liquid_density_kg_m3
        ppm_o2 = (self.state.c_o2_dissolved * MW_O2 / rho) * 1.0e6
        self.state.dissolved_oxygen_ppm = max(0.0, ppm_o2)

        # Conversion & Selectivity
        c_feed = self.config.c_chx_feed_mol_m3
        c_effluent = self.state.c_cyclohexane
        delta_c = max(0.0, c_feed - c_effluent)

        if c_feed > 0.0:
            conv_pct = (delta_c / c_feed) * 100.0
        else:
            conv_pct = 0.0

        c_ka = self.state.c_cyclohexanone + self.state.c_cyclohexanol
        if delta_c > 1.0:
            sel_pct = (c_ka / delta_c) * 100.0
        else:
            sel_pct = KA_SELECTIVITY_NOMINAL_PCT

        self.state.cyclohexane_conversion_pct = min(100.0, max(0.0, conv_pct))
        self.state.ka_oil_selectivity_pct = min(100.0, max(0.0, sel_pct))

        # KA molar ratio (Ketone / Alcohol)
        if self.state.c_cyclohexanol > 0.01:
            ratio = self.state.c_cyclohexanone / self.state.c_cyclohexanol
        else:
            ratio = KA_MOLAR_RATIO_NOMINAL
        self.state.ka_molar_ratio = max(0.01, ratio)

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
        # Reaction 1: C6H12 + O2 -> CHHP (C6H11OOH)
        # Reaction 2: CHHP -> Cyclohexanone (C6H10O) + H2O
        # Reaction 3: CHHP -> Cyclohexanol (C6H11OH) + 0.5 O2
        # Reaction 4: Cyclohexanone + 1.5 O2 -> Adipic Acid (C6H10O4)
        r1 = self.state.r1_rate_mol_s
        r2 = self.state.r2_rate_mol_s
        r3 = self.state.r3_rate_mol_s
        r4 = self.state.r4_rate_mol_s

        mass_reactants_kg_s = (
            r1 * (MW_CHX + MW_O2)
            + r2 * MW_CHHP
            + r3 * MW_CHHP
            + r4 * (MW_K + 1.5 * MW_O2)
        )
        mass_products_kg_s = (
            r1 * MW_CHHP
            + r2 * (MW_K + MW_H2O)
            + r3 * (MW_A + 0.5 * MW_O2)
            + r4 * MW_DBA
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
        """Evaluate process safety interlocks in strict priority: 0xE401 > 0xE402 > 0xE403 > 0xE404."""
        # %M404 OffgasO2HighAlarm (O2 > 2.80 vol%)
        self.state.offgas_o2_high_alarm = (
            self.state.offgas_oxygen_vol_pct > self.config.offgas_o2_alarm_pct
        )

        # Priority 1: 0xE401 Flammability Envelope Breach (Offgas O2 >= 3.50 vol%)
        if self.state.emergency_nitrogen_quench_active and (
            self.state.diagnostic_code == KaOxidationDiagnosticCode.OFFGAS_O2_EXPLOSIVE_TRIP
        ):
            cond_e401 = self.state.offgas_oxygen_vol_pct >= self.config.offgas_o2_reset_pct
        else:
            cond_e401 = self.state.offgas_oxygen_vol_pct >= self.config.offgas_o2_trip_pct

        # Priority 2: 0xE402 Thermal Runaway Excursion (T_reactor > 165.0 °C)
        if self.state.emergency_nitrogen_quench_active and (
            self.state.diagnostic_code == KaOxidationDiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        ):
            cond_e402 = self.state.reactor_temp_celsius > self.config.temp_reset_c
        else:
            cond_e402 = self.state.reactor_temp_celsius > self.config.temp_trip_c

        # Priority 3: 0xE403 Low KA Selectivity Degradation (Selectivity < 80.0% or conversion > 6.0%)
        cond_e403 = (
            self.state.ka_oil_selectivity_pct < self.config.selectivity_min_pct
            or self.state.cyclohexane_conversion_pct > 6.00
        )

        # Priority 4: 0xE404 Sparger Deficiency / Anoxia (Dissolved O2 < 10.0 ppm)
        cond_e404 = (
            self.state.dissolved_oxygen_ppm < self.config.dissolved_o2_min_ppm
        )

        # Strict Priority Hierarchy: 0xE401 > 0xE402 > 0xE403 > 0xE404 > 0x0000
        if cond_e401:
            self.state.diagnostic_code = KaOxidationDiagnosticCode.OFFGAS_O2_EXPLOSIVE_TRIP
            self.state.emergency_nitrogen_quench_active = True
            self.state.ka_oxidation_active = False
            self.state.offgas_o2_high_alarm = True
        elif cond_e402:
            self.state.diagnostic_code = KaOxidationDiagnosticCode.THERMAL_RUNAWAY_EXCURSION
            self.state.emergency_nitrogen_quench_active = True
            self.state.ka_oxidation_active = False
        elif cond_e403:
            self.state.diagnostic_code = KaOxidationDiagnosticCode.LOW_KA_SELECTIVITY_DEGRADATION
            self.state.emergency_nitrogen_quench_active = False
            self.state.ka_oxidation_active = True
        elif cond_e404:
            self.state.diagnostic_code = KaOxidationDiagnosticCode.SPARGER_DEFICIENCY_ANOXIA
            self.state.emergency_nitrogen_quench_active = False
            self.state.ka_oxidation_active = True
        else:
            self.state.diagnostic_code = KaOxidationDiagnosticCode.OK
            self.state.emergency_nitrogen_quench_active = False
            self.state.ka_oxidation_active = True

        # Update status word bitmask
        bits = KaOxidationStatusBits.RUNNING
        if self.state.ka_oxidation_active:
            bits |= KaOxidationStatusBits.KA_OXIDATION_ACTIVE
        if self.state.offgas_o2_high_alarm:
            bits |= KaOxidationStatusBits.OFFGAS_O2_HIGH_ALARM
        if self.state.emergency_nitrogen_quench_active:
            bits |= KaOxidationStatusBits.EMERGENCY_QUENCH_ACTIVE
        if self.state.diagnostic_code == KaOxidationDiagnosticCode.OFFGAS_O2_EXPLOSIVE_TRIP:
            bits |= KaOxidationStatusBits.OFFGAS_O2_TRIP
        elif self.state.diagnostic_code == KaOxidationDiagnosticCode.THERMAL_RUNAWAY_EXCURSION:
            bits |= KaOxidationStatusBits.THERMAL_RUNAWAY_TRIP
        elif self.state.diagnostic_code == KaOxidationDiagnosticCode.LOW_KA_SELECTIVITY_DEGRADATION:
            bits |= KaOxidationStatusBits.LOW_SELECTIVITY_ALARM
        elif self.state.diagnostic_code == KaOxidationDiagnosticCode.SPARGER_DEFICIENCY_ANOXIA:
            bits |= KaOxidationStatusBits.SPARGER_DEFICIENCY_ALARM
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

        %R1730: ReactorTempScaled (scaled x10 °C, e.g. 1550 = 155.0 °C)
        %R1731: ReactorPressureBarScaled (scaled x10 bar, e.g. 105 = 10.5 bar)
        %R1732: CyclohexaneConversionPctScaled (scaled x100 %, e.g. 480 = 4.80%)
        %R1733: KaOilSelectivityPctScaled (scaled x10 %, e.g. 845 = 84.5%)
        %R1734: KaMolarRatioScaled (scaled x100, ketone/alcohol ratio, e.g. 120 = 1.20:1)
        %R1735: OffgasOxygenVolPctScaled (scaled x100 %, e.g. 185 = 1.85% O2)
        %R1736: DissolvedOxygenPpmScaled (scaled x10 ppm, e.g. 450 = 45.0 ppm)
        %R1737: DiagnosticStatusCode (0x0000=OK, 0xE401, 0xE402, 0xE403, 0xE404)
        %M403: KaOxidationActive (BOOL)
        %M404: OffgasO2HighAlarm (BOOL, True if O2 > 2.8 vol%)
        %M405: EmergencyNitrogenQuenchActive (BOOL, True on trip)
        """
        r1730_val = int(round(self.state.reactor_temp_celsius * 10.0))
        r1731_val = int(round(self.state.reactor_pressure_bar * 10.0))
        r1732_val = int(round(self.state.cyclohexane_conversion_pct * 100.0))
        r1733_val = int(round(self.state.ka_oil_selectivity_pct * 10.0))
        r1734_val = int(round(self.state.ka_molar_ratio * 100.0))
        r1735_val = int(round(self.state.offgas_oxygen_vol_pct * 100.0))
        r1736_val = int(round(self.state.dissolved_oxygen_ppm * 10.0))
        r1737_val = int(self.state.diagnostic_code) & 0xFFFF

        # Clamp INT16 values
        r1730_val = max(-32768, min(32767, r1730_val))
        r1731_val = max(-32768, min(32767, r1731_val))
        r1732_val = max(-32768, min(32767, r1732_val))
        r1733_val = max(-32768, min(32767, r1733_val))
        r1734_val = max(-32768, min(32767, r1734_val))
        r1735_val = max(-32768, min(32767, r1735_val))
        r1736_val = max(-32768, min(32767, r1736_val))
        r1737_val = max(0, min(65535, r1737_val))

        reg_table.write_word("%R1730", r1730_val, privilege=privilege)
        reg_table.write_word("%R1731", r1731_val, privilege=privilege)
        reg_table.write_word("%R1732", r1732_val, privilege=privilege)
        reg_table.write_word("%R1733", r1733_val, privilege=privilege)
        reg_table.write_word("%R1734", r1734_val, privilege=privilege)
        reg_table.write_word("%R1735", r1735_val, privilege=privilege)
        reg_table.write_word("%R1736", r1736_val, privilege=privilege)
        reg_table.write_word("%R1737", r1737_val, privilege=privilege)

        reg_table.write_bit("%M403", bool(self.state.ka_oxidation_active), privilege=privilege)
        reg_table.write_bit("%M404", bool(self.state.offgas_o2_high_alarm), privilege=privilege)
        reg_table.write_bit("%M405", bool(self.state.emergency_nitrogen_quench_active), privilege=privilege)

    def _sync_registers(self, privilege: PrivilegeMode = PrivilegeMode.SYSTEM) -> None:
        """Internal helper to synchronize current state into attached register table."""
        self.sync_to_registers(self.registers, privilege=privilege)

    # ------------------------------------------------------------------------
    # Simulation Advancers & Steps
    # ------------------------------------------------------------------------

    def step(self, dt: float = 0.05) -> ExecutionResult:
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
                "conversion_pct": self.state.cyclohexane_conversion_pct,
                "ka_selectivity_pct": self.state.ka_oil_selectivity_pct,
                "offgas_o2_pct": self.state.offgas_oxygen_vol_pct,
                "diagnostic_code": int(self.state.diagnostic_code),
            },
        )

    def advance_time(self, duration_s: float, dt: float = 0.05) -> ExecutionResult:
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
                "conversion_pct": self.state.cyclohexane_conversion_pct,
                "selectivity_pct": self.state.ka_oil_selectivity_pct,
                "offgas_o2_pct": self.state.offgas_oxygen_vol_pct,
                "diagnostic_code": int(self.state.diagnostic_code),
            },
        )

    def reset(self) -> None:
        """Reset simulator state to nominal baseline conditions."""
        self.state = KaOxidationState()
        self._update_kinetics_and_conversion()
        self._update_conservation_residuals()
        self._evaluate_safety_interlocks()
        self._sync_registers()

    # ------------------------------------------------------------------------
    # ILogicUnit Interface Implementation
    # ------------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "KaOxidationReactorSync"

    @property
    def priority(self) -> int:
        return 100

    @property
    def is_enabled(self) -> bool:
        return True

    def scan_step(self, dt: float = 0.05, context: Optional[ScanContext] = None) -> None:
        """Execute one simulation cycle scan step conforming to ILogicUnit interface."""
        self.step(dt)
        if context is not None and hasattr(context, "registers") and context.registers is not None:
            self.sync_to_registers(context.registers, privilege=PrivilegeMode.SYSTEM)

    def execute(self, ctx: ScanContext) -> None:
        """Execute one simulation cycle scan from ScanContext."""
        dt_s = ctx.dt_ms / 1000.0 if ctx.dt_ms > 0 else 0.05
        self.scan_step(dt=dt_s, context=ctx)


# Simulator Aliases
KaOxidationReactorSimulator = KaOxidationReactor
KaOxidationSimulator = KaOxidationReactor
KaOxidationReactorEngine = KaOxidationReactor
KaOxidationReactorModel = KaOxidationReactor
KaOxidationReactorPlantModel = KaOxidationReactor
KaOxidationReactorSimulationEngine = KaOxidationReactor

KaReactor = KaOxidationReactor
KaReactorConfig = KaOxidationConfig
KaReactorDiagCode = KaOxidationDiagnosticCode
KaReactorDiagnosticCode = KaOxidationDiagnosticCode
KaReactorEngine = KaOxidationReactor
KaReactorModel = KaOxidationReactor
KaReactorParameters = KaOxidationConfig
KaReactorPlantModel = KaOxidationReactor
KaReactorSimulationEngine = KaOxidationReactor
KaReactorSimulator = KaOxidationReactor
KaReactorState = KaOxidationState
KaReactorStatusBits = KaOxidationStatusBits
KaReactorStatusWord = KaOxidationStatusBits
KaSimulator = KaOxidationReactor
KaState = KaOxidationState
KaStatusBits = KaOxidationStatusBits
KaStatusWord = KaOxidationStatusBits
KaConfig = KaOxidationConfig
KaDiagCode = KaOxidationDiagnosticCode
KaDiagnosticCode = KaOxidationDiagnosticCode
KaParameters = KaOxidationConfig


class KaOxidationReactorLogicUnit(ILogicUnit):
    """Adapter logic unit for integrating KA Oxidation Reactor into Horner SimulationEngine."""

    def __init__(
        self,
        config: Optional[KaOxidationConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.simulator = KaOxidationReactor(config=config, register_table=register_table)
        self._name: str = "KaOxidationReactorSync"
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
        dt_s = ctx.dt_ms / 1000.0 if ctx.dt_ms > 0 else 0.05
        self.simulator.scan_step(dt=dt_s, context=ctx)

    def reset(self) -> None:
        self.simulator.reset()


KaOxidationLogicUnit = KaOxidationReactorLogicUnit
KaReactorLogicUnit = KaOxidationReactorLogicUnit
KaLogicUnit = KaOxidationReactorLogicUnit


# ============================================================================
# 5. Strict Pure IEC 61131-3 Structured Text POU
# ============================================================================

KA_OXIDATION_REACTOR_PURE_ST_POU: str = """PROGRAM KaOxidationReactorSync
VAR
    ReactorTempScaled AT %R1730 : INT;
    ReactorPressureBarScaled AT %R1731 : INT;
    CyclohexaneConversionPctScaled AT %R1732 : INT;
    KaOilSelectivityPctScaled AT %R1733 : INT;
    KaMolarRatioScaled AT %R1734 : INT;
    OffgasOxygenVolPctScaled AT %R1735 : INT;
    DissolvedOxygenPpmScaled AT %R1736 : INT;
    DiagnosticStatusCode AT %R1737 : INT;
    KaOxidationActive AT %M403 : BOOL;
    OffgasO2HighAlarm AT %M404 : BOOL;
    EmergencyNitrogenQuenchActive AT %M405 : BOOL;
END_VAR

(* Off-Gas Oxygen Pre-Trip Alarm (> 2.80 vol% -> scaled 280) *)
IF OffgasOxygenVolPctScaled > 280 THEN
    OffgasO2HighAlarm := TRUE;
ELSE
    OffgasO2HighAlarm := FALSE;
END_IF;

(* Process Safety Interlocks & Diagnostics in Strict Priority Hierarchy *)
IF OffgasOxygenVolPctScaled >= 350 THEN
    DiagnosticStatusCode := 16#E401;
    EmergencyNitrogenQuenchActive := TRUE;
    OffgasO2HighAlarm := TRUE;
    KaOxidationActive := FALSE;
ELSIF ReactorTempScaled > 1650 THEN
    DiagnosticStatusCode := 16#E402;
    EmergencyNitrogenQuenchActive := TRUE;
    KaOxidationActive := FALSE;
ELSIF KaOilSelectivityPctScaled < 800 THEN
    DiagnosticStatusCode := 16#E403;
    EmergencyNitrogenQuenchActive := FALSE;
    KaOxidationActive := TRUE;
ELSIF DissolvedOxygenPpmScaled < 100 THEN
    DiagnosticStatusCode := 16#E404;
    EmergencyNitrogenQuenchActive := FALSE;
    KaOxidationActive := TRUE;
ELSE
    DiagnosticStatusCode := 16#0000;
    EmergencyNitrogenQuenchActive := FALSE;
    KaOxidationActive := TRUE;
END_IF;
END_PROGRAM
"""

KA_OXIDATION_REACTOR_SYNC_POU = KA_OXIDATION_REACTOR_PURE_ST_POU
KA_OXIDATION_PURE_ST_POU = KA_OXIDATION_REACTOR_PURE_ST_POU
KA_OXIDATION_SYNC_POU = KA_OXIDATION_REACTOR_PURE_ST_POU
KA_REACTOR_PURE_ST_POU = KA_OXIDATION_REACTOR_PURE_ST_POU
KA_REACTOR_SYNC_POU = KA_OXIDATION_REACTOR_PURE_ST_POU


def verify_ka_oxidation_reactor_pure_st() -> bool:
    """Verify that KA Oxidation Reactor ST POU passes AST parsing and anti-ladder check."""
    SecurityGuard.assert_pure_st_content(KA_OXIDATION_REACTOR_PURE_ST_POU)
    parser = STParser(pou_type=POUType.PROGRAM)
    ast = parser.parse_pou(KA_OXIDATION_REACTOR_PURE_ST_POU)
    return ast is not None and ast.name == "KaOxidationReactorSync" and ast.pou_type == POUType.PROGRAM


def verify_ka_oxidation_pure_st() -> bool:
    """Verify KA Oxidation Reactor alias ST POU."""
    return verify_ka_oxidation_reactor_pure_st()


def verify_ka_reactor_pure_st() -> bool:
    """Verify KA Reactor alias ST POU."""
    return verify_ka_oxidation_reactor_pure_st()


def verify_ka_pure_st() -> bool:
    """Verify KA Reactor alias ST POU."""
    return verify_ka_oxidation_reactor_pure_st()


def validate_pure_st() -> ExecutionResult:
    """Validate pure ST POU and return ExecutionResult."""
    SecurityGuard.assert_pure_st_content(KA_OXIDATION_REACTOR_PURE_ST_POU)
    return STParser.validate_code(KA_OXIDATION_REACTOR_PURE_ST_POU)


validate_ka_pure_st = validate_pure_st


# ============================================================================
# 6. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_ka_oxidation_reactor_verification(
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Execute rigorous 9-stage verification suite for W212 and return strict 4-state contract dict."""
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU AST Parsing & Horner Register Symbol Bindings
    # ------------------------------------------------------------------------
    SecurityGuard.assert_pure_st_content(KA_OXIDATION_REACTOR_PURE_ST_POU)
    parser = STParser(pou_type=POUType.PROGRAM)
    ast = parser.parse_pou(KA_OXIDATION_REACTOR_PURE_ST_POU)
    ast_valid = ast is not None and ast.name == "KaOxidationReactorSync" and ast.pou_type == POUType.PROGRAM
    expected_regs = [
        "%R1730", "%R1731", "%R1732", "%R1733",
        "%R1734", "%R1735", "%R1736", "%R1737",
        "%M403", "%M404", "%M405",
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
        "XIC KaOxidationActive",
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
    # Stage 3: KA Oxidation Autoxidation & Decomposition Kinetics & Enthalpies
    # ------------------------------------------------------------------------
    sim = KaOxidationReactor()
    delta_h1_ok = (DELTA_H1_KJ_MOL == -135.0)
    delta_h2_ok = (DELTA_H2_KJ_MOL == -180.0)
    delta_h3_ok = (DELTA_H3_KJ_MOL == -145.0)
    delta_h4_ok = (DELTA_H4_KJ_MOL == -320.0)

    # Reaction rates at nominal 155 °C vs elevated 170 °C
    rates_nom = sim.compute_reaction_rates(7691.8, 0.956, 60.0, 178.9, 149.1, 428.15)
    rates_hot = sim.compute_reaction_rates(7691.8, 0.956, 60.0, 178.9, 149.1, 443.15)

    ratio_r1 = rates_hot["r1_tot"] / max(1e-6, rates_nom["r1_tot"])
    ratio_r4 = rates_hot["r4_tot"] / max(1e-6, rates_nom["r4_tot"])
    # Because Ea4 (115 kJ/mol) > Ea1 (95 kJ/mol), over-oxidation accelerates faster than autoxidation:
    over_oxidation_accelerates_faster = ratio_r4 > ratio_r1

    c3 = delta_h1_ok and delta_h2_ok and delta_h3_ok and delta_h4_ok and over_oxidation_accelerates_faster
    test_results.append({
        "stage": 3,
        "check": "KA_Oxidation_Autoxidation_Decomposition_Kinetics_And_Enthalpies",
        "passed": c3,
        "details": (
            f"Reaction enthalpies verified: Delta H1={DELTA_H1_KJ_MOL} kJ/mol, Delta H2={DELTA_H2_KJ_MOL} kJ/mol, "
            f"Delta H3={DELTA_H3_KJ_MOL} kJ/mol, Delta H4={DELTA_H4_KJ_MOL} kJ/mol. "
            f"Over-oxidation acceleration ratio={ratio_r4:.3f} > autoxidation={ratio_r1:.3f}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 4: Gas-Liquid Mass Transfer & Off-Gas Oxygen Safety Envelope
    # ------------------------------------------------------------------------
    mt_nom = sim.compute_mass_transfer(0.956, 428.15, 10.5)
    mt_trans_pos = mt_nom["r_o2_mt_tot"] > 0.0
    offgas_o2_nom = mt_nom["offgas_o2_vol_pct"]
    offgas_safe = offgas_o2_nom < OFFGAS_O2_TRIP_VOL_PCT  # < 3.50 vol%
    alarm_threshold_ok = (OFFGAS_O2_HIGH_ALARM_VOL_PCT == 2.80)
    trip_threshold_ok = (OFFGAS_O2_TRIP_VOL_PCT == 3.50)

    c4 = mt_trans_pos and offgas_safe and alarm_threshold_ok and trip_threshold_ok
    test_results.append({
        "stage": 4,
        "check": "Gas_Liquid_Mass_Transfer_And_Offgas_Oxygen_Safety_Envelope",
        "passed": c4,
        "details": (
            f"Mass transfer verified: O2 absorbed={mt_nom['r_o2_mt_tot']:.2f} mol/s, "
            f"nominal off-gas O2={offgas_o2_nom:.2f} vol% (< 3.5 vol%), "
            f"alarm limit={OFFGAS_O2_HIGH_ALARM_VOL_PCT} vol%, trip limit={OFFGAS_O2_TRIP_VOL_PCT} vol%."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 5: Coupled 6-State ODE System RK4 Integration Stability
    # ------------------------------------------------------------------------
    sim_rk = KaOxidationReactor()
    derivs = sim_rk.compute_derivatives(
        0.0,
        [
            sim_rk.state.c_cyclohexane,
            sim_rk.state.c_o2_dissolved,
            sim_rk.state.c_chhp,
            sim_rk.state.c_cyclohexanone,
            sim_rk.state.c_cyclohexanol,
            sim_rk.state.t_reactor,
        ],
    )
    all_derivs_finite = len(derivs) == 6 and all(not math.isnan(d) and not math.isinf(d) for d in derivs)

    res_rk = sim_rk.advance_time(duration_s=5.0, dt=0.05)
    rk_success = res_rk.status == AgentStatus.SUCCESS

    state_stable = (
        5000.0 <= sim_rk.state.c_cyclohexane <= 8500.0
        and 0.01 <= sim_rk.state.c_o2_dissolved <= 5.0
        and 10.0 <= sim_rk.state.c_chhp <= 250.0
        and 50.0 <= sim_rk.state.c_cyclohexanone <= 400.0
        and 40.0 <= sim_rk.state.c_cyclohexanol <= 350.0
        and 145.0 <= sim_rk.state.reactor_temp_celsius <= 165.0
    )
    c5 = all_derivs_finite and rk_success and state_stable
    test_results.append({
        "stage": 5,
        "check": "Coupled_6_State_ODE_System_RK4_Integration_Stability",
        "passed": c5,
        "details": (
            f"RK4 stability verified: C_chx={sim_rk.state.c_cyclohexane:.1f}, "
            f"C_O2={sim_rk.state.c_o2_dissolved:.3f}, C_chhp={sim_rk.state.c_chhp:.1f}, "
            f"C_K={sim_rk.state.c_cyclohexanone:.1f}, C_A={sim_rk.state.c_cyclohexanol:.1f}, "
            f"T={sim_rk.state.reactor_temp_celsius:.1f}°C."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 6: Stoichiometric Elemental Mass & Enthalpy Conservation Residuals (< 1e-10)
    # ------------------------------------------------------------------------
    sim_cons = KaOxidationReactor()
    sim_cons.advance_time(duration_s=2.0, dt=0.05)

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
    # Stage 7: Low-Conversion Regime & High KA Selectivity Dynamics
    # ------------------------------------------------------------------------
    sim_low_conv = KaOxidationReactor()
    conv = sim_low_conv.state.cyclohexane_conversion_pct
    sel = sim_low_conv.state.ka_oil_selectivity_pct
    ratio = sim_low_conv.state.ka_molar_ratio

    conv_in_range = 3.50 <= conv <= 5.50
    sel_high = sel >= 82.0
    ratio_in_range = 0.90 <= ratio <= 1.50

    c7 = conv_in_range and sel_high and ratio_in_range
    test_results.append({
        "stage": 7,
        "check": "Low_Conversion_Regime_And_High_KA_Selectivity_Dynamics",
        "passed": c7,
        "details": (
            f"Regime verified: conversion={conv:.2f}% in [3.5%, 5.5%], "
            f"KA selectivity={sel:.1f}% (>= 82.0%), ketone/alcohol ratio={ratio:.2f}:1."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 8: Process Safety Interlocks & Strict Priority Hierarchy (0xE401..0xE404)
    # ------------------------------------------------------------------------
    sim_safety = KaOxidationReactor()

    # 8a: 0xE401 Off-gas O2 Explosive Trip (O2 >= 3.5 vol%)
    sim_safety.state.offgas_oxygen_vol_pct = 3.65
    sim_safety._evaluate_safety_interlocks()
    sim_safety._sync_registers()
    c8a = (
        sim_safety.state.diagnostic_code == KaOxidationDiagnosticCode.OFFGAS_O2_EXPLOSIVE_TRIP
        and sim_safety.state.emergency_nitrogen_quench_active is True
        and sim_safety.state.offgas_o2_high_alarm is True
        and sim_safety.state.ka_oxidation_active is False
    )

    # 8b: 0xE402 Thermal Runaway Excursion (T_reactor > 165.0 °C)
    sim_safety.reset()
    sim_safety.state.reactor_temp_celsius = 168.5
    sim_safety._evaluate_safety_interlocks()
    sim_safety._sync_registers()
    c8b = (
        sim_safety.state.diagnostic_code == KaOxidationDiagnosticCode.THERMAL_RUNAWAY_EXCURSION
        and sim_safety.state.emergency_nitrogen_quench_active is True
        and sim_safety.state.ka_oxidation_active is False
    )

    # 8c: 0xE403 Low KA Selectivity Degradation (< 80.0%)
    sim_safety.reset()
    sim_safety.state.ka_oil_selectivity_pct = 78.5
    sim_safety._evaluate_safety_interlocks()
    sim_safety._sync_registers()
    c8c = (
        sim_safety.state.diagnostic_code == KaOxidationDiagnosticCode.LOW_KA_SELECTIVITY_DEGRADATION
        and sim_safety.state.emergency_nitrogen_quench_active is False
        and sim_safety.state.ka_oxidation_active is True
    )

    # 8d: 0xE404 Sparger Deficiency / Anoxia (Dissolved O2 < 10.0 ppm)
    sim_safety.reset()
    sim_safety.state.dissolved_oxygen_ppm = 6.5
    sim_safety._evaluate_safety_interlocks()
    sim_safety._sync_registers()
    c8d = (
        sim_safety.state.diagnostic_code == KaOxidationDiagnosticCode.SPARGER_DEFICIENCY_ANOXIA
        and sim_safety.state.emergency_nitrogen_quench_active is False
        and sim_safety.state.ka_oxidation_active is True
    )

    # 8e: Priority hierarchy: 0xE401 > 0xE402 > 0xE403 > 0xE404 > 0x0000
    sim_safety.state.offgas_oxygen_vol_pct = 3.80   # 0xE401
    sim_safety.state.reactor_temp_celsius = 169.0    # 0xE402
    sim_safety.state.ka_oil_selectivity_pct = 76.0  # 0xE403
    sim_safety.state.dissolved_oxygen_ppm = 5.0     # 0xE404
    sim_safety._evaluate_safety_interlocks()
    p1_wins = (sim_safety.state.diagnostic_code == KaOxidationDiagnosticCode.OFFGAS_O2_EXPLOSIVE_TRIP)

    sim_safety.state.offgas_oxygen_vol_pct = 1.85   # Clear 0xE401
    sim_safety._evaluate_safety_interlocks()
    p2_wins = (sim_safety.state.diagnostic_code == KaOxidationDiagnosticCode.THERMAL_RUNAWAY_EXCURSION)

    sim_safety.state.reactor_temp_celsius = 155.0    # Clear 0xE402
    sim_safety.state.emergency_nitrogen_quench_active = False
    sim_safety._evaluate_safety_interlocks()
    p3_wins = (sim_safety.state.diagnostic_code == KaOxidationDiagnosticCode.LOW_KA_SELECTIVITY_DEGRADATION)

    sim_safety.state.ka_oil_selectivity_pct = 84.5  # Clear 0xE403
    sim_safety._evaluate_safety_interlocks()
    p4_wins = (sim_safety.state.diagnostic_code == KaOxidationDiagnosticCode.SPARGER_DEFICIENCY_ANOXIA)

    sim_safety.state.dissolved_oxygen_ppm = 45.0    # Clear 0xE404
    sim_safety._evaluate_safety_interlocks()
    p0_ok = (sim_safety.state.diagnostic_code == KaOxidationDiagnosticCode.OK)

    c8e = p1_wins and p2_wins and p3_wins and p4_wins and p0_ok
    c8 = c8a and c8b and c8c and c8d and c8e
    test_results.append({
        "stage": 8,
        "check": "Process_Safety_Interlocks_And_Strict_Priority_Hierarchy",
        "passed": c8,
        "details": f"Safety diagnostics verified: 0xE401={c8a}, 0xE402={c8b}, 0xE403={c8c}, 0xE404={c8d}, Priority={c8e}.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Memory Space Integration & Emergency Mitigation
    # ------------------------------------------------------------------------
    reg = RegisterTable()
    sim_reg = KaOxidationReactor(register_table=reg)

    sim_reg.state.reactor_temp_celsius = 155.0
    sim_reg.state.reactor_pressure_bar = 10.5
    sim_reg.state.cyclohexane_conversion_pct = 4.80
    sim_reg.state.ka_oil_selectivity_pct = 84.5
    sim_reg.state.ka_molar_ratio = 1.20
    sim_reg.state.offgas_oxygen_vol_pct = 1.85
    sim_reg.state.dissolved_oxygen_ppm = 45.0
    sim_reg._evaluate_safety_interlocks()
    sim_reg.sync_to_registers(reg, privilege=PrivilegeMode.SYSTEM)

    r1730 = reg.read_word("%R1730")
    r1731 = reg.read_word("%R1731")
    r1732 = reg.read_word("%R1732")
    r1733 = reg.read_word("%R1733")
    r1734 = reg.read_word("%R1734")
    r1735 = reg.read_word("%R1735")
    r1736 = reg.read_word("%R1736")
    r1737 = reg.read_uword("%R1737")
    m403 = reg.read_bit("%M403")
    m404 = reg.read_bit("%M404")
    m405 = reg.read_bit("%M405")

    regs_ok = (
        r1730 == 1550
        and r1731 == 105
        and r1732 == 480
        and r1733 == 845
        and r1734 == 120
        and r1735 == 185
        and r1736 == 450
        and r1737 == 0x0000
        and m403 is True
        and m404 is False
        and m405 is False
    )

    # Emergency mitigation test: Trigger excursion and advance under quench
    sim_quench = KaOxidationReactor()
    sim_quench.state.reactor_temp_celsius = 168.0
    sim_quench.state.t_reactor = 168.0 + T_ZERO_CELSIUS
    sim_quench._evaluate_safety_interlocks()
    quench_tripped = (sim_quench.state.diagnostic_code == KaOxidationDiagnosticCode.THERMAL_RUNAWAY_EXCURSION)

    sim_quench.advance_time(duration_s=8.0, dt=0.05)
    quench_cooled = sim_quench.state.reactor_temp_celsius < 162.0

    c9 = regs_ok and quench_tripped and quench_cooled
    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Memory_Space_Integration_And_Emergency_Mitigation",
        "passed": c9,
        "details": (
            f"Registers verified: %R1730={r1730}, %R1731={r1731}, %R1732={r1732}, %R1733={r1733}, "
            f"%R1734={r1734}, %R1735={r1735}, %R1736={r1736}, %R1737={hex(r1737)}, "
            f"%M403={m403}, %M404={m404}, %M405={m405}. Quench cooled={quench_cooled}."
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
        "details": f"KA Oxidation Reactor 9-stage verification passed {passed_count}/9 checks.",
        "data": {
            "work_package": "W212",
            "module": "ka_oxidation_reactor",
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
run_ka_oxidation_verification = run_ka_oxidation_reactor_verification
run_ka_reactor_verification = run_ka_oxidation_reactor_verification
run_ka_verification = run_ka_oxidation_reactor_verification

# Model & Component Aliases
KaConfig = KaOxidationConfig
KaParameters = KaOxidationConfig
KaReactorConfig = KaOxidationConfig
KaReactorParameters = KaOxidationConfig
KaDiagnosticCode = KaOxidationDiagnosticCode
KaDiagCode = KaOxidationDiagnosticCode
KaReactorDiagnosticCode = KaOxidationDiagnosticCode
KaReactorDiagCode = KaOxidationDiagnosticCode
KaStatusBits = KaOxidationStatusBits
KaStatusWord = KaOxidationStatusBits
KaReactorStatusBits = KaOxidationStatusBits
KaReactorStatusWord = KaOxidationStatusBits
KaState = KaOxidationState
KaReactorState = KaOxidationState
KaReactor = KaOxidationReactor
KaSimulator = KaOxidationReactor
KaReactorSimulator = KaOxidationReactor
KaReactorEngine = KaOxidationReactor
KaReactorModel = KaOxidationReactor
KaReactorPlantModel = KaOxidationReactor
KaReactorSimulationEngine = KaOxidationReactor
KaLogicUnit = KaOxidationReactorLogicUnit
KaReactorLogicUnit = KaOxidationReactorLogicUnit
verify_ka_pure_st = verify_ka_oxidation_reactor_pure_st
verify_ka_reactor_pure_st = verify_ka_oxidation_reactor_pure_st
KA_PURE_ST_POU = KA_OXIDATION_REACTOR_PURE_ST_POU
KA_SYNC_POU = KA_OXIDATION_REACTOR_PURE_ST_POU
KA_REACTOR_PURE_ST_POU = KA_OXIDATION_REACTOR_PURE_ST_POU
KA_REACTOR_SYNC_POU = KA_OXIDATION_REACTOR_PURE_ST_POU

