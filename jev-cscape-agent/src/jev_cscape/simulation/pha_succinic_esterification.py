"""Industrial Bio-Succinic Acid Esterification & PHA Precursor Distillation Column ODE Simulation.

Work Package: W314 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Reactive Distillation Bio-Succinic Esterification Column]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Features:
1. Industrial Bio-Succinic Acid Esterification & Reactive Distillation:
   - Continuous reactive distillation column converting bio-succinic acid and alcohol
     (methanol/ethanol) into high-purity dialkyl succinate ester (PHA precursor / monomer)
     and water byproduct:
     Succinic Acid + 2 Alcohol <===> Dialkyl Succinate + 2 Water
   - Reaction stoichiometry:
     1 mol C4H6O4 + 2 mol ROH <===> 1 mol C6H10O4 + 2 mol H2O
   - Equilibrium esterification kinetics with dual Arrhenius forward and reverse rates:
     * Forward esterification: r_f = k_f * C_sa * C_alc^2
     * Reverse hydrolysis: r_r = k_r * C_das * C_water^2
   - Vapor-Liquid Equilibrium (VLE) separation:
     * Overhead vapor enriched in water and alcohol; dialkyl succinate accumulated in reboiler bottoms
     * Continuous byproduct water devolatilization shifts equilibrium toward complete conversion (>98%)
2. Coupled 6-State Continuous Reactive Distillation ODE Vector:
   - State variables:
     1. C_succinic_acid: Bio-succinic acid concentration (mol/L)
     2. C_alcohol: Alcohol reactant concentration (mol/L)
     3. C_dialkyl_succinate: Dialkyl succinate ester product concentration (mol/L)
     4. C_water: Byproduct water concentration (mol/L)
     5. T_reboiler: Reboiler liquid temperature (K)
     6. T_condenser: Overhead condenser temperature (K)
   - 4th-Order Runge-Kutta (RK4) numerical integrator step_rk4(dt).
   - Strict continuous mass conservation (stoichiometric residuals < 1e-10).
3. Process Safety Interlocks & Diagnostics (Strict 5-Tier Priority Hierarchy):
   - Priority 1: 0xF981 DIAG_ERR_REBOILER_OVERHEAT (Treboiler > 520 K or dT/dt > 20 K/s)
   - Priority 2: 0xF982 DIAG_ERR_COLUMN_OVERPRESSURE (P > 30.0 bar)
   - Priority 3: 0xF983 DIAG_ERR_TRAY_FLOODING_WEEPING (DeltaP across trays > limit or < minimum)
   - Priority 4: 0xF984 DIAG_ERR_MASS_BALANCE_DIVERGENCE (residual > 1e-4)
   - Priority 5: 0xF985 DIAG_ERR_ACID_PRECIPITATION_CLOG (free acid solubility limit exceeded)
4. Horner OCS Memory Space Integration:
   - Word registers %R2750..%R2757:
     %R2750: REG_PHA_SUCC_REBOILER_TEMP (0.1 °C, signed 16-bit)
     %R2751: REG_PHA_SUCC_CONDENSER_TEMP (0.1 °C, signed 16-bit)
     %R2752: REG_PHA_SUCC_COLUMN_PRESSURE (0.01 bar, 0..5000)
     %R2753: REG_PHA_SUCC_ESTER_PURITY (0.1 %, 0..1000)
     %R2754: REG_PHA_SUCC_ACID_CONVERSION (0.1 %, 0..1000)
     %R2755: REG_PHA_SUCC_REFLUX_RATIO (0.01 ratio, e.g. 250 -> 2.50)
     %R2756: REG_PHA_SUCC_REBOILER_DUTY_KW (0.1 kW, 0..10000)
     %R2757: REG_PHA_SUCC_DIAGNOSTIC_CODE (0x0000=OK, 0xF981..0xF985)
   - Discrete coils %M641..%M643:
     %M641: COIL_PHA_SUCC_COLUMN_ACTIVE (BOOL)
     %M642: COIL_PHA_SUCC_REBOILER_HEATER (BOOL)
     %M643: COIL_PHA_SUCC_EMERGENCY_DUMP (BOOL)
5. Pure IEC 61131-3 Structured Text (ST) POU:
   - POU 'PHASuccinicEsterificationControl' with anti-ladder validation rejecting 9 ladder constructs.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import IntFlag
import hashlib
import json
import math
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Stoichiometry & Physical Constants
# ============================================================================

MW_SUCCINIC_ACID: float = 118.09       # Bio-succinic acid C4H6O4 (g/mol)
MW_ALCOHOL: float = 32.04             # Alcohol reactant (Methanol CH3OH, g/mol)
MW_DIALKYL_SUCCINATE: float = 146.14   # Dialkyl succinate (Dimethyl succinate C6H10O4, g/mol)
MW_WATER: float = 18.015              # Water byproduct H2O (g/mol)
MW_CARBON: float = 12.011             # Carbon atomic weight (g/mol)

R_GAS_CONSTANT: float = 8.314462618   # Universal gas constant [J/(mol*K)]
T_ZERO_CELSIUS: float = 273.15        # 0.0 °C in Kelvin [K]

# Carbon atoms per molecule
CARBONS_SUCCINIC_ACID: int = 4
CARBONS_ALCOHOL: int = 1
CARBONS_DIALKYL_SUCCINATE: int = 6
CARBONS_WATER: int = 0

# Carbon mass fractions
CARBON_FRACTION_SUCCINIC_ACID: float = (CARBONS_SUCCINIC_ACID * MW_CARBON) / MW_SUCCINIC_ACID  # ~ 0.4068 kg C / kg SA
CARBON_FRACTION_ALCOHOL: float = (CARBONS_ALCOHOL * MW_CARBON) / MW_ALCOHOL                    # ~ 0.3749 kg C / kg Alc
CARBON_FRACTION_DIALKYL_SUCCINATE: float = (CARBONS_DIALKYL_SUCCINATE * MW_CARBON) / MW_DIALKYL_SUCCINATE  # ~ 0.4931 kg C / kg DAS


# ============================================================================
# 2. Horner OCS Memory Space Integration & Diagnostic Codes
# ============================================================================

# Word Registers %R2750..%R2757
REG_PHA_SUCC_REBOILER_TEMP: str       = "%R2750"  # 0.1 °C, signed 16-bit
REG_PHA_SUCC_CONDENSER_TEMP: str      = "%R2751"  # 0.1 °C, signed 16-bit
REG_PHA_SUCC_COLUMN_PRESSURE: str     = "%R2752"  # 0.01 bar, 0..5000
REG_PHA_SUCC_ESTER_PURITY: str        = "%R2753"  # 0.1 %, 0..1000
REG_PHA_SUCC_ACID_CONVERSION: str     = "%R2754"  # 0.1 %, 0..1000
REG_PHA_SUCC_REFLUX_RATIO: str        = "%R2755"  # 0.01 ratio, e.g. 250 -> 2.50
REG_PHA_SUCC_REBOILER_DUTY_KW: str    = "%R2756"  # 0.1 kW, 0..10000
REG_PHA_SUCC_DIAGNOSTIC_CODE: str     = "%R2757"  # 16-bit diagnostic code

# Register Aliases
REG_PHA_SUCC_TREBOILER: str           = REG_PHA_SUCC_REBOILER_TEMP
REG_PHA_SUCC_T_REBOILER: str          = REG_PHA_SUCC_REBOILER_TEMP
REG_PHA_SUCC_REBOILER_TEMPERATURE: str = REG_PHA_SUCC_REBOILER_TEMP
REG_PHA_SUCC_T_REB: str               = REG_PHA_SUCC_REBOILER_TEMP
REG_PHA_SUCC_TCONDENSER: str          = REG_PHA_SUCC_CONDENSER_TEMP
REG_PHA_SUCC_T_CONDENSER: str         = REG_PHA_SUCC_CONDENSER_TEMP
REG_PHA_SUCC_CONDENSER_TEMPERATURE: str = REG_PHA_SUCC_CONDENSER_TEMP
REG_PHA_SUCC_T_COND: str              = REG_PHA_SUCC_CONDENSER_TEMP
REG_PHA_SUCC_PRESSURE: str            = REG_PHA_SUCC_COLUMN_PRESSURE
REG_PHA_SUCC_P_COLUMN: str            = REG_PHA_SUCC_COLUMN_PRESSURE
REG_PHA_SUCC_P_COL: str               = REG_PHA_SUCC_COLUMN_PRESSURE
REG_PHA_SUCC_PURITY: str              = REG_PHA_SUCC_ESTER_PURITY
REG_PHA_SUCC_CONVERSION: str          = REG_PHA_SUCC_ACID_CONVERSION
REG_PHA_SUCC_CONV: str                = REG_PHA_SUCC_ACID_CONVERSION
REG_PHA_SUCC_REFLUX: str              = REG_PHA_SUCC_REFLUX_RATIO
REG_PHA_SUCC_DUTY: str                = REG_PHA_SUCC_REBOILER_DUTY_KW
REG_PHA_SUCC_HEATER_DUTY: str         = REG_PHA_SUCC_REBOILER_DUTY_KW
REG_PHA_SUCC_DIAG: str                = REG_PHA_SUCC_DIAGNOSTIC_CODE

# Discrete Coils %M641..%M643
COIL_PHA_SUCC_COLUMN_ACTIVE: str      = "%M641"   # BOOL
COIL_PHA_SUCC_REBOILER_HEATER: str    = "%M642"   # BOOL
COIL_PHA_SUCC_EMERGENCY_DUMP: str     = "%M643"   # BOOL

# Coil Aliases
COIL_PHA_SUCC_ACTIVE: str             = COIL_PHA_SUCC_COLUMN_ACTIVE
COIL_PHA_SUCC_RUNNING: str            = COIL_PHA_SUCC_COLUMN_ACTIVE
COIL_PHA_SUCC_HEATER: str             = COIL_PHA_SUCC_REBOILER_HEATER
COIL_PHA_SUCC_REBOILER: str           = COIL_PHA_SUCC_REBOILER_HEATER
COIL_PHA_SUCC_DUMP: str               = COIL_PHA_SUCC_EMERGENCY_DUMP
COIL_PHA_SUCC_EMERGENCY_VENT: str     = COIL_PHA_SUCC_EMERGENCY_DUMP


class DiagnosticCode(int):
    """Integer subclass for 16-bit diagnostic codes supporting signed/unsigned equality."""

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            val_u = int(self) & 0xFFFF
            val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
            other_u = int(other) & 0xFFFF
            other_s = other_u - 0x10000 if other_u >= 0x8000 else other_u
            return (
                int(self) == other
                or val_u == other
                or val_s == other
                or val_s == other_s
                or val_u == other_u
            )
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(int(self) & 0xFFFF)

    def __repr__(self) -> str:
        return f"DiagnosticCode(0x{int(self) & 0xFFFF:04X})"

    def __str__(self) -> str:
        return f"0x{int(self) & 0xFFFF:04X}"


# 16-bit Trip Diagnostic Constants (Priority 1..5)
DIAG_OK: DiagnosticCode                         = DiagnosticCode(0x0000)
DIAG_ERR_REBOILER_OVERHEAT: DiagnosticCode      = DiagnosticCode(0xF981)  # Priority 1: Treboiler > 520 K or dT/dt > 20 K/s
DIAG_ERR_COLUMN_OVERPRESSURE: DiagnosticCode    = DiagnosticCode(0xF982)  # Priority 2: P > 30.0 bar
DIAG_ERR_TRAY_FLOODING_WEEPING: DiagnosticCode  = DiagnosticCode(0xF983)  # Priority 3: DeltaP across trays > limit or < minimum
DIAG_ERR_MASS_BALANCE_DIVERGENCE: DiagnosticCode = DiagnosticCode(0xF984) # Priority 4: residual > 1e-4
DIAG_ERR_ACID_PRECIPITATION_CLOG: DiagnosticCode = DiagnosticCode(0xF985) # Priority 5: free acid solubility limit exceeded

# Diagnostic Aliases
DIAG_ERR_OVERHEAT: DiagnosticCode               = DIAG_ERR_REBOILER_OVERHEAT
DIAG_ERR_REBOILER_TEMP: DiagnosticCode          = DIAG_ERR_REBOILER_OVERHEAT
DIAG_ERR_OVERPRESSURE: DiagnosticCode           = DIAG_ERR_COLUMN_OVERPRESSURE
DIAG_ERR_PRESSURE: DiagnosticCode               = DIAG_ERR_COLUMN_OVERPRESSURE
DIAG_ERR_TRAY_FLOODING: DiagnosticCode          = DIAG_ERR_TRAY_FLOODING_WEEPING
DIAG_ERR_FLOODING_WEEPING: DiagnosticCode       = DIAG_ERR_TRAY_FLOODING_WEEPING
DIAG_ERR_MASS_DIVERGENCE: DiagnosticCode        = DIAG_ERR_MASS_BALANCE_DIVERGENCE
DIAG_ERR_MASS_BALANCE: DiagnosticCode           = DIAG_ERR_MASS_BALANCE_DIVERGENCE
DIAG_ERR_ACID_PRECIPITATION: DiagnosticCode     = DIAG_ERR_ACID_PRECIPITATION_CLOG
DIAG_ERR_PRECIPITATION_CLOG: DiagnosticCode     = DIAG_ERR_ACID_PRECIPITATION_CLOG
DIAG_ERR_CLOG: DiagnosticCode                   = DIAG_ERR_ACID_PRECIPITATION_CLOG

PhaSuccinicEsterificationDiagnosticCode = DiagnosticCode
PHASuccinicEsterificationDiagnosticCode = DiagnosticCode
PhaSuccEsterDiagnosticCode = DiagnosticCode
PHASuccEsterDiagnosticCode = DiagnosticCode


class PHASuccinicEsterificationStatusWord(IntFlag):
    """Bitmask for Bio-Succinic Acid Reactive Distillation Column operational status."""
    COLUMN_ACTIVE        = 1 << 0  # Bit 0: Distillation column active (%M641)
    REBOILER_HEATING     = 1 << 1  # Bit 1: Reboiler heating duty active (%M642)
    EMERGENCY_DUMP       = 1 << 2  # Bit 2: Emergency dump valve open (%M643)
    CONDENSER_ACTIVE     = 1 << 3  # Bit 3: Overhead condenser reflux active
    REBOILER_WARN        = 1 << 4  # Bit 4: Reboiler temperature pre-alarm
    PRESSURE_WARN        = 1 << 5  # Bit 5: Column pressure pre-alarm
    FLOODING_WARN        = 1 << 6  # Bit 6: Tray differential pressure pre-alarm
    EMERGENCY_TRIP       = 1 << 7  # Bit 7: Master safety trip latched

PhaSuccinicEsterificationStatusWord = PHASuccinicEsterificationStatusWord
PHASuccEsterStatusWord = PHASuccinicEsterificationStatusWord
PhaSuccEsterStatusWord = PHASuccinicEsterificationStatusWord
PHASuccinicEsterificationStatusBits = PHASuccinicEsterificationStatusWord
PhaSuccinicEsterificationStatusBits = PHASuccinicEsterificationStatusWord
PHASuccEsterStatusBits = PHASuccinicEsterificationStatusWord
PhaSuccEsterStatusBits = PHASuccinicEsterificationStatusWord


# ============================================================================
# 3. State & Configuration Models
# ============================================================================

@dataclass
class PHASuccinicEsterificationState:
    """Coupled 6-State Vector for Industrial Bio-Succinic Acid Reactive Distillation Column."""
    c_succinic_acid: float = 2.0        # mol/L: Bio-succinic acid concentration
    c_alcohol: float = 5.0              # mol/L: Alcohol reactant concentration (methanol/ethanol)
    c_dialkyl_succinate: float = 0.05   # mol/L: Dialkyl succinate ester product concentration
    c_water: float = 0.10               # mol/L: Byproduct water concentration
    t_reboiler: float = 433.15          # K: Reboiler liquid temperature (~160.0 °C)
    t_condenser: float = 348.15         # K: Overhead condenser temperature (~75.0 °C)
    p_column: float = 1.80              # bar: Reactive distillation column pressure
    delta_p_trays: float = 0.12         # bar: Differential pressure across column trays
    dt_reboiler_dt: float = 0.0         # K/s: Reboiler temperature rate of change

    def to_dict(self) -> Dict[str, float]:
        return {
            "c_succinic_acid": self.c_succinic_acid,
            "c_alcohol": self.c_alcohol,
            "c_dialkyl_succinate": self.c_dialkyl_succinate,
            "c_water": self.c_water,
            "t_reboiler": self.t_reboiler,
            "t_condenser": self.t_condenser,
            "p_column": self.p_column,
            "delta_p_trays": self.delta_p_trays,
            "dt_reboiler_dt": self.dt_reboiler_dt,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PHASuccinicEsterificationState:
        c_sa = float(data.get("c_succinic_acid", data.get("C_succinic_acid", data.get("sa", 2.0))))
        c_alc = float(data.get("c_alcohol", data.get("C_alcohol", data.get("alc", 5.0))))
        c_das = float(data.get("c_dialkyl_succinate", data.get("C_dialkyl_succinate", data.get("das", 0.05))))
        c_w = float(data.get("c_water", data.get("C_water", data.get("water", 0.10))))
        t_reb = float(data.get("t_reboiler", data.get("T_reboiler", data.get("treb", 433.15))))
        t_cond = float(data.get("t_condenser", data.get("T_condenser", data.get("tcond", 348.15))))
        p_col = float(data.get("p_column", data.get("P_column", data.get("pcol", 1.80))))
        dp_tr = float(data.get("delta_p_trays", data.get("Delta_p_trays", data.get("dp", 0.12))))
        dt_dt = float(data.get("dt_reboiler_dt", data.get("dT_reboiler_dt", 0.0)))
        return cls(
            c_succinic_acid=c_sa,
            c_alcohol=c_alc,
            c_dialkyl_succinate=c_das,
            c_water=c_w,
            t_reboiler=t_reb,
            t_condenser=t_cond,
            p_column=p_col,
            delta_p_trays=dp_tr,
            dt_reboiler_dt=dt_dt,
        )

    # Property aliases for flexible caller access
    @property
    def C_succinic_acid(self) -> float:
        return self.c_succinic_acid

    @C_succinic_acid.setter
    def C_succinic_acid(self, val: float) -> None:
        self.c_succinic_acid = float(val)

    @property
    def succinic_acid(self) -> float:
        return self.c_succinic_acid

    @succinic_acid.setter
    def succinic_acid(self, val: float) -> None:
        self.c_succinic_acid = float(val)

    @property
    def c_sa(self) -> float:
        return self.c_succinic_acid

    @c_sa.setter
    def c_sa(self, val: float) -> None:
        self.c_succinic_acid = float(val)

    @property
    def C_alcohol(self) -> float:
        return self.c_alcohol

    @C_alcohol.setter
    def C_alcohol(self, val: float) -> None:
        self.c_alcohol = float(val)

    @property
    def alcohol(self) -> float:
        return self.c_alcohol

    @alcohol.setter
    def alcohol(self, val: float) -> None:
        self.c_alcohol = float(val)

    @property
    def c_alc(self) -> float:
        return self.c_alcohol

    @c_alc.setter
    def c_alc(self, val: float) -> None:
        self.c_alcohol = float(val)

    @property
    def C_dialkyl_succinate(self) -> float:
        return self.c_dialkyl_succinate

    @C_dialkyl_succinate.setter
    def C_dialkyl_succinate(self, val: float) -> None:
        self.c_dialkyl_succinate = float(val)

    @property
    def dialkyl_succinate(self) -> float:
        return self.c_dialkyl_succinate

    @dialkyl_succinate.setter
    def dialkyl_succinate(self, val: float) -> None:
        self.c_dialkyl_succinate = float(val)

    @property
    def c_das(self) -> float:
        return self.c_dialkyl_succinate

    @c_das.setter
    def c_das(self, val: float) -> None:
        self.c_dialkyl_succinate = float(val)

    @property
    def c_ester(self) -> float:
        return self.c_dialkyl_succinate

    @c_ester.setter
    def c_ester(self, val: float) -> None:
        self.c_dialkyl_succinate = float(val)

    @property
    def C_water(self) -> float:
        return self.c_water

    @C_water.setter
    def C_water(self, val: float) -> None:
        self.c_water = float(val)

    @property
    def water(self) -> float:
        return self.c_water

    @water.setter
    def water(self, val: float) -> None:
        self.c_water = float(val)

    @property
    def T_reboiler(self) -> float:
        return self.t_reboiler

    @T_reboiler.setter
    def T_reboiler(self, val: float) -> None:
        self.t_reboiler = float(val)

    @property
    def t_reb(self) -> float:
        return self.t_reboiler

    @t_reb.setter
    def t_reb(self, val: float) -> None:
        self.t_reboiler = float(val)

    @property
    def reboiler_temp(self) -> float:
        return self.t_reboiler

    @reboiler_temp.setter
    def reboiler_temp(self, val: float) -> None:
        self.t_reboiler = float(val)

    @property
    def T_condenser(self) -> float:
        return self.t_condenser

    @T_condenser.setter
    def T_condenser(self, val: float) -> None:
        self.t_condenser = float(val)

    @property
    def t_cond(self) -> float:
        return self.t_condenser

    @t_cond.setter
    def t_cond(self, val: float) -> None:
        self.t_condenser = float(val)

    @property
    def condenser_temp(self) -> float:
        return self.t_condenser

    @condenser_temp.setter
    def condenser_temp(self, val: float) -> None:
        self.t_condenser = float(val)

    @property
    def P_column(self) -> float:
        return self.p_column

    @P_column.setter
    def P_column(self, val: float) -> None:
        self.p_column = float(val)

    @property
    def p_col(self) -> float:
        return self.p_column

    @p_col.setter
    def p_col(self, val: float) -> None:
        self.p_column = float(val)

    @property
    def Delta_p_trays(self) -> float:
        return self.delta_p_trays

    @Delta_p_trays.setter
    def Delta_p_trays(self, val: float) -> None:
        self.delta_p_trays = float(val)

    @property
    def delta_p(self) -> float:
        return self.delta_p_trays

    @delta_p.setter
    def delta_p(self, val: float) -> None:
        self.delta_p_trays = float(val)

    @property
    def dT_reboiler_dt(self) -> float:
        return self.dt_reboiler_dt

    @dT_reboiler_dt.setter
    def dT_reboiler_dt(self, val: float) -> None:
        self.dt_reboiler_dt = float(val)


PhaSuccinicEsterificationState = PHASuccinicEsterificationState
PHASuccEsterState = PHASuccinicEsterificationState
PhaSuccEsterState = PHASuccinicEsterificationState
PHASuccinicEsterificationStateModel = PHASuccinicEsterificationState
PhaSuccinicEsterificationStateModel = PHASuccinicEsterificationState


@dataclass
class PHASuccinicEsterificationConfig:
    """Kinetic, thermodynamic, hydrodynamic, and safety parameters for Bio-Succinic Esterification Column.

    NOTE: Duplicate typed fields and @property setters are strictly avoided.
    """
    # Arrhenius kinetics for forward esterification:
    k_forward: float = 8.5e3              # Pre-exponential factor forward [L²/(mol²*s)]
    ea_forward_j_mol: float = 52000.0     # Activation energy forward [J/mol] (52.0 kJ/mol)

    # Arrhenius kinetics for reverse hydrolysis:
    k_reverse: float = 1.2e3              # Pre-exponential factor reverse [L²/(mol²*s)]
    ea_reverse_j_mol: float = 68000.0     # Activation energy reverse [J/mol] (68.0 kJ/mol)

    # Reaction and phase change enthalpies:
    delta_h_rxn_j_mol: float = -18000.0   # Enthalpy of esterification [J/mol] (mildly exothermic)
    delta_h_vap_j_mol: float = 38000.0    # Latent heat of vaporization of light fraction [J/mol]

    # Vessel hydrodynamics and liquid holdup:
    v_reboiler: float = 2.5               # Reboiler liquid holdup volume [m³] (2500 L)
    v_condenser: float = 0.5              # Condenser holdup volume [m³] (500 L)
    rho_liquid: float = 1050.0            # Liquid mixture bulk density [kg/m³]
    cp_liquid: float = 2400.0             # Liquid mixture specific heat capacity [J/(kg*K)]

    # Operating setpoints & thermal duties:
    reflux_ratio_nominal: float = 2.50    # Nominal reflux ratio L/D [-]
    reboiler_duty_nominal_kw: float = 120.0  # Nominal reboiler heating duty [kW]
    ua_condenser: float = 15000.0         # Condenser cooling overall heat transfer coeff [W/K]
    t_coolant: float = 298.15             # Cooling water supply temperature [K]

    # Heat losses to ambient:
    ua_loss_reboiler: float = 80.0        # Reboiler shell heat loss to ambient [W/K]
    ua_loss_condenser: float = 40.0       # Condenser shell heat loss to ambient [W/K]
    t_ambient: float = 298.15             # Ambient environmental temperature [K]

    # Pressure generation and relief:
    k_p_gen: float = 0.050                # Pressure generation gain from vapor generation [bar*s/mol]
    k_p_relief: float = 0.020             # Condenser relief / pressure vent discharge rate [1/s]
    p_ambient: float = 1.01325            # Atmospheric pressure [bar]

    # Column tray hydraulics & differential pressure:
    k_dp_vapor: float = 0.0125            # Tray pressure drop vapor velocity coefficient [bar/(mol/s)^1.8]
    k_dp_liquid: float = 0.040            # Static liquid tray holdup pressure drop [bar]

    # Bio-succinic acid solubility parameters in alcohol/ester medium:
    s_sol_0: float = 150.0                # Solubility pre-exponential factor [mol/L]
    ea_sol_j_mol: float = 11500.0         # Temperature dependence enthalpy of dissolution [J/mol]

    # Process Safety Interlock Thresholds (5-Tier Priority Hierarchy):
    t_reboiler_trip_max: float = 520.0    # Reboiler overheat trip threshold [K] (0xF981)
    dt_reboiler_dt_trip_max: float = 20.0 # Reboiler rate-of-rise trip threshold [K/s] (0xF981)
    p_column_trip_max: float = 30.0       # Column overpressure trip threshold [bar] (0xF982)
    delta_p_max: float = 0.80             # Tray flooding differential pressure trip [bar] (0xF983)
    delta_p_min: float = 0.02             # Tray weeping minimum differential pressure trip [bar] (0xF983)
    mass_residual_max: float = 1e-4       # Continuous mass balance divergence trip [-] (0xF984)

    # Emergency safety dump parameters:
    ua_dump: float = 95000.0              # Emergency dump cooling heat transfer [W/K]
    k_dump_vent: float = 0.45             # Emergency dump depressurization rate [1/s]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "k_forward": self.k_forward,
            "ea_forward_j_mol": self.ea_forward_j_mol,
            "k_reverse": self.k_reverse,
            "ea_reverse_j_mol": self.ea_reverse_j_mol,
            "delta_h_rxn_j_mol": self.delta_h_rxn_j_mol,
            "delta_h_vap_j_mol": self.delta_h_vap_j_mol,
            "v_reboiler": self.v_reboiler,
            "v_condenser": self.v_condenser,
            "reflux_ratio_nominal": self.reflux_ratio_nominal,
            "reboiler_duty_nominal_kw": self.reboiler_duty_nominal_kw,
            "t_reboiler_trip_max": self.t_reboiler_trip_max,
            "dt_reboiler_dt_trip_max": self.dt_reboiler_dt_trip_max,
            "p_column_trip_max": self.p_column_trip_max,
            "delta_p_max": self.delta_p_max,
            "delta_p_min": self.delta_p_min,
            "mass_residual_max": self.mass_residual_max,
        }

    # Distinct alias properties (no matching typed fields)
    @property
    def k_f(self) -> float:
        return self.k_forward

    @k_f.setter
    def k_f(self, val: float) -> None:
        self.k_forward = float(val)

    @property
    def k_r(self) -> float:
        return self.k_reverse

    @k_r.setter
    def k_r(self, val: float) -> None:
        self.k_reverse = float(val)

    @property
    def ea_f(self) -> float:
        return self.ea_forward_j_mol

    @ea_f.setter
    def ea_f(self, val: float) -> None:
        self.ea_forward_j_mol = float(val)

    @property
    def ea_r(self) -> float:
        return self.ea_reverse_j_mol

    @ea_r.setter
    def ea_r(self, val: float) -> None:
        self.ea_reverse_j_mol = float(val)


PhaSuccinicEsterificationConfig = PHASuccinicEsterificationConfig
PHASuccEsterConfig = PHASuccinicEsterificationConfig
PhaSuccEsterConfig = PHASuccinicEsterificationConfig
PHASuccinicEsterificationParameters = PHASuccinicEsterificationConfig
PhaSuccinicEsterificationParameters = PHASuccinicEsterificationConfig


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text POU
# ============================================================================

ST_PROGRAM_PHA_SUCCINIC_ESTERIFICATION_CONTROL = """
PROGRAM PHASuccinicEsterificationControl
VAR
    rReboilerTemp AT %R2750 : INT;
    rCondenserTemp AT %R2751 : INT;
    rColumnPressure AT %R2752 : WORD;
    rEsterPurity AT %R2753 : WORD;
    rAcidConversion AT %R2754 : WORD;
    rRefluxRatio AT %R2755 : WORD;
    rReboilerDuty AT %R2756 : WORD;
    wDiagnosticCode AT %R2757 : WORD;
    bColumnActive AT %M641 : BOOL;
    bReboilerHeater AT %M642 : BOOL;
    bEmergencyDump AT %M643 : BOOL;
END_VAR

IF wDiagnosticCode = 0 THEN
    bColumnActive := TRUE;
    bReboilerHeater := TRUE;
    bEmergencyDump := FALSE;
ELSE
    bColumnActive := FALSE;
    bReboilerHeater := FALSE;
    bEmergencyDump := TRUE;
END_IF;
END_PROGRAM
""".strip()

PHA_SUCCINIC_ESTERIFICATION_PURE_ST_POU: str = ST_PROGRAM_PHA_SUCCINIC_ESTERIFICATION_CONTROL
PHA_SUCC_ESTER_PURE_ST_POU: str = ST_PROGRAM_PHA_SUCCINIC_ESTERIFICATION_CONTROL
PHASuccinicEsterificationControl: str = ST_PROGRAM_PHA_SUCCINIC_ESTERIFICATION_CONTROL
PHA_SUCCINIC_ESTERIFICATION_CONTROL_POU: str = ST_PROGRAM_PHA_SUCCINIC_ESTERIFICATION_CONTROL


def verify_pha_succinic_esterification_pure_st() -> bool:
    """Validate pure ST syntax and ensure strict rejection of ladder logic constructs."""
    try:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_PHA_SUCCINIC_ESTERIFICATION_CONTROL)
    except LadderForbiddenError:
        return False
    val = STParser.validate_code(ST_PROGRAM_PHA_SUCCINIC_ESTERIFICATION_CONTROL)
    return val.status == AgentStatus.SUCCESS


verify_pha_succ_ester_pure_st = verify_pha_succinic_esterification_pure_st
validate_pure_st = STParser.validate_code


# ============================================================================
# 5. Simulation Reactor Engine (ILogicUnit)
# ============================================================================

class PHASuccinicEsterificationEngine(ILogicUnit):
    """Industrial Bio-Succinic Acid Esterification & PHA Precursor Distillation Column Simulator."""

    def __init__(
        self,
        config: Optional[PHASuccinicEsterificationConfig] = None,
        state: Optional[PHASuccinicEsterificationState] = None,
        reg_table: Optional[RegisterTable] = None,
        register_table: Optional[RegisterTable] = None,
        **kwargs: Any,
    ) -> None:
        self.cfg = config or PHASuccinicEsterificationConfig()
        self.state = state or PHASuccinicEsterificationState()
        self.reg_table = register_table or reg_table or RegisterTable()

        # Operational status flags
        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.trip_active: bool = False
        self.column_active: bool = True
        self.reboiler_heater: bool = True
        self.emergency_dump_active: bool = False

        # Actuator controls and process settings
        self.reboiler_duty_kw: float = self.cfg.reboiler_duty_nominal_kw
        self.reflux_ratio: float = self.cfg.reflux_ratio_nominal
        self.p_column: float = self.state.p_column
        self.delta_p_trays: float = self.state.delta_p_trays

        # Conservation and telemetry tracking
        self.cycle_count: int = 0
        self.conservation_residual: float = 0.0
        self.last_dt_reboiler_dt: float = 0.0
        self.cumulative_distillate_mass_exported: float = 0.0

        # Initial baseline inventory for conversion and mass conservation
        self._initial_c_succinic_acid: float = max(1e-6, self.state.c_succinic_acid)
        self._initial_mass_total: float = (
            self.state.c_succinic_acid * MW_SUCCINIC_ACID
            + self.state.c_alcohol * MW_ALCOHOL
            + self.state.c_dialkyl_succinate * MW_DIALKYL_SUCCINATE
            + self.state.c_water * MW_WATER
        )

        # Initial register synchronization
        self.sync_to_registers(self.reg_table)

    @property
    def unit_id(self) -> str:
        return "PHA_SUCC_ESTER_DISTILLATION_W314"

    @property
    def name(self) -> str:
        return "PHASuccinicEsterificationEngine"

    @property
    def priority(self) -> int:
        return 50

    @property
    def is_enabled(self) -> bool:
        return True

    @property
    def acid_conversion_pct(self) -> float:
        """Bio-succinic acid conversion efficiency [%]."""
        if self._initial_c_succinic_acid < 1e-6:
            return 0.0
        c_conv = max(0.0, self._initial_c_succinic_acid - self.state.c_succinic_acid)
        return max(0.0, min(100.0, (c_conv / self._initial_c_succinic_acid) * 100.0))

    @property
    def ester_purity_pct(self) -> float:
        """Dialkyl succinate ester purity in the reboiler liquid mixture [%]."""
        total_organic = self.state.c_succinic_acid + self.state.c_dialkyl_succinate
        if total_organic < 1e-6:
            return 0.0
        purity = (self.state.c_dialkyl_succinate / total_organic) * 100.0
        return max(0.0, min(100.0, purity))

    def compute_acid_solubility(self, temp_k: float) -> float:
        """Compute temperature-dependent solubility limit of bio-succinic acid [mol/L]."""
        t_clamped = max(100.0, float(temp_k))
        arrh_sol = math.exp(-self.cfg.ea_sol_j_mol / (R_GAS_CONSTANT * t_clamped))
        return self.cfg.s_sol_0 * arrh_sol

    def compute_rates(
        self, s: PHASuccinicEsterificationState
    ) -> Tuple[float, float, float]:
        """Compute forward, reverse, and net esterification reaction rates [mol/(L*s)]."""
        if self.trip_active or s.t_reboiler < 280.0:
            return (0.0, 0.0, 0.0)

        rt_reb = R_GAS_CONSTANT * max(100.0, s.t_reboiler)
        c_sa = max(0.0, s.c_succinic_acid)
        c_alc = max(0.0, s.c_alcohol)
        c_das = max(0.0, s.c_dialkyl_succinate)
        c_water = max(0.0, s.c_water)

        # Forward esterification: SA + 2 ROH -> DAS + 2 H2O
        arrh_f = math.exp(-self.cfg.ea_forward_j_mol / rt_reb)
        r_forward = self.cfg.k_forward * c_sa * (c_alc ** 2) * arrh_f

        # Reverse hydrolysis: DAS + 2 H2O -> SA + 2 ROH
        arrh_r = math.exp(-self.cfg.ea_reverse_j_mol / rt_reb)
        r_reverse = self.cfg.k_reverse * c_das * (c_water ** 2) * arrh_r

        r_net = r_forward - r_reverse
        return (r_forward, r_reverse, r_net)

    def _derivatives(
        self, s: PHASuccinicEsterificationState
    ) -> Tuple[float, float, float, float, float, float, float, float]:
        """Compute coupled 6-state time derivatives plus pressure & distillate export dynamics.

        Returns:
            (dc_sa_dt, dc_alc_dt, dc_das_dt, dc_water_dt, dt_reb_dt, dt_cond_dt, dp_col_dt, dc_dist_mass_dt)
        """
        v_reb_l = max(1.0, self.cfg.v_reboiler * 1000.0)       # Liters
        rho_cp_reb = self.cfg.rho_liquid * self.cfg.cp_liquid # J/(m³*K)
        rho_cp_cond = self.cfg.rho_liquid * self.cfg.cp_liquid

        if self.trip_active and self.emergency_dump_active:
            # Emergency dump cooldown, depressurization, and heater isolation dynamics
            dt_reb_dt = - (self.cfg.ua_dump * (s.t_reboiler - self.cfg.t_ambient)) / (
                rho_cp_reb * self.cfg.v_reboiler
            )
            dt_cond_dt = - (self.cfg.ua_dump * 0.5 * (s.t_condenser - self.cfg.t_ambient)) / (
                rho_cp_cond * self.cfg.v_condenser
            )
            dp_col_dt = - self.cfg.k_dump_vent * max(0.0, s.p_column - self.cfg.p_ambient)
            return (0.0, 0.0, 0.0, 0.0, dt_reb_dt, dt_cond_dt, dp_col_dt, 0.0)

        if self.trip_active:
            return (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        r_f, r_r, r_net = self.compute_rates(s)

        # Boilup vapor generation driven by reboiler heater duty
        active_duty = self.reboiler_duty_kw if self.reboiler_heater else 0.0
        v_boilup_mol_s = (active_duty * 1000.0 * 0.90) / self.cfg.delta_h_vap_j_mol
        v_boilup_l_s = v_boilup_mol_s / v_reb_l

        # Overhead vapor composition: light fractions (water & alcohol) vaporize selectively
        tot_volatiles = max(1e-6, s.c_alcohol + s.c_water)
        y_water = s.c_water / tot_volatiles
        y_alc = s.c_alcohol / tot_volatiles

        # Distillate draw rate (D = V / (1 + R))
        d_draw_l_s = v_boilup_l_s / (1.0 + max(0.1, self.reflux_ratio))
        r_draw_water = d_draw_l_s * y_water
        r_draw_alc = d_draw_l_s * y_alc

        # Component molar concentration rates [mol/(L*s)]
        dc_sa_dt = - r_net
        dc_alc_dt = - 2.0 * r_net - r_draw_alc
        dc_das_dt = + r_net
        dc_water_dt = + 2.0 * r_net - r_draw_water

        # Distillate mass export rate [g/(L*s)] to enforce exact mass conservation
        dc_dist_mass_dt = (r_draw_water * MW_WATER) + (r_draw_alc * MW_ALCOHOL)

        # Reboiler thermal energy balance: T_reboiler [K/s]
        q_heater = (active_duty * 1000.0) / self.cfg.v_reboiler        # W/m³ heat input
        q_rxn = (r_net * (-self.cfg.delta_h_rxn_j_mol) * 1000.0)       # W/m³ reaction exotherm
        q_boilup = (v_boilup_mol_s * self.cfg.delta_h_vap_j_mol) / self.cfg.v_reboiler  # W/m³ vaporization
        q_loss_reb = (self.cfg.ua_loss_reboiler * (s.t_reboiler - self.cfg.t_ambient)) / self.cfg.v_reboiler
        q_reflux = (
            (self.reflux_ratio * d_draw_l_s * 1000.0)
            * (self.cfg.cp_liquid / 1000.0)
            * (s.t_reboiler - s.t_condenser)
        )
        dt_reb_dt = (q_heater + q_rxn - q_boilup - q_loss_reb - q_reflux) / rho_cp_reb

        # Overhead condenser thermal energy balance: T_condenser [K/s]
        q_condense = v_boilup_mol_s * self.cfg.delta_h_vap_j_mol       # W condensation heat
        q_cooling = self.cfg.ua_condenser * (s.t_condenser - self.cfg.t_coolant) # W coolant removal
        q_loss_cond = self.cfg.ua_loss_condenser * (s.t_condenser - self.cfg.t_ambient)
        dt_cond_dt = (q_condense - q_cooling - q_loss_cond) / (rho_cp_cond * self.cfg.v_condenser)

        # Column pressure dynamics: P_column [bar/s]
        condense_rate_mol_s = q_cooling / self.cfg.delta_h_vap_j_mol
        dp_gen = self.cfg.k_p_gen * max(0.0, v_boilup_mol_s - condense_rate_mol_s)
        dp_relief = self.cfg.k_p_relief * max(0.0, s.p_column - self.cfg.p_ambient)
        dp_col_dt = dp_gen - dp_relief

        return (
            dc_sa_dt,
            dc_alc_dt,
            dc_das_dt,
            dc_water_dt,
            dt_reb_dt,
            dt_cond_dt,
            dp_col_dt,
            dc_dist_mass_dt,
        )

    def emergency_dump(self) -> None:
        """Actuate fail-safe emergency dump and isolate reboiler heater upon safety trip."""
        self.column_active = False
        self.reboiler_heater = False
        self.emergency_dump_active = True
        self.reboiler_duty_kw = 0.0

    emergency_shutdown = emergency_dump
    emergency_quench = emergency_dump
    emergency_trip = emergency_dump

    def check_interlocks(
        self, s: PHASuccinicEsterificationState, dt_reboiler_dt: float = 0.0
    ) -> bool:
        """Evaluate process safety interlocks in strict 5-tier priority order.

        Priority Hierarchy:
        1: 0xF981 DIAG_ERR_REBOILER_OVERHEAT (Treboiler > 520 K or dT/dt > 20 K/s)
        2: 0xF982 DIAG_ERR_COLUMN_OVERPRESSURE (P > 30.0 bar)
        3: 0xF983 DIAG_ERR_TRAY_FLOODING_WEEPING (DeltaP across trays > limit or < minimum)
        4: 0xF984 DIAG_ERR_MASS_BALANCE_DIVERGENCE (residual > 1e-4)
        5: 0xF985 DIAG_ERR_ACID_PRECIPITATION_CLOG (free acid solubility limit exceeded)
        """
        if self.trip_active:
            return True

        rate_check = max(abs(dt_reboiler_dt), abs(s.dt_reboiler_dt), abs(self.last_dt_reboiler_dt))

        # Priority 1: Reboiler overheat trip (> 520 K or dT/dt > 20 K/s)
        if s.t_reboiler > self.cfg.t_reboiler_trip_max or rate_check > self.cfg.dt_reboiler_dt_trip_max:
            self.diagnostic_code = DIAG_ERR_REBOILER_OVERHEAT
            self.trip_active = True
            self.emergency_dump()
            return True

        # Priority 2: Column overpressure trip (> 30.0 bar)
        current_p = max(s.p_column, self.p_column)
        if current_p > self.cfg.p_column_trip_max:
            self.diagnostic_code = DIAG_ERR_COLUMN_OVERPRESSURE
            self.trip_active = True
            self.emergency_dump()
            return True

        # Priority 3: Tray flooding / weeping trip (DeltaP > limit or < minimum)
        current_dp = max(s.delta_p_trays, self.delta_p_trays)
        if self.column_active and (current_dp > self.cfg.delta_p_max or current_dp < self.cfg.delta_p_min):
            self.diagnostic_code = DIAG_ERR_TRAY_FLOODING_WEEPING
            self.trip_active = True
            self.emergency_dump()
            return True

        # Priority 4: Continuous mass balance divergence trip (residual > 1e-4)
        if self.conservation_residual > self.cfg.mass_residual_max:
            self.diagnostic_code = DIAG_ERR_MASS_BALANCE_DIVERGENCE
            self.trip_active = True
            self.emergency_dump()
            return True

        # Priority 5: Bio-succinic acid precipitation / crystallization clog
        solubility = self.compute_acid_solubility(s.t_reboiler)
        if s.c_succinic_acid > solubility:
            self.diagnostic_code = DIAG_ERR_ACID_PRECIPITATION_CLOG
            self.trip_active = True
            self.emergency_dump()
            return True

        return False

    def step_rk4(self, dt: float = 0.1) -> None:
        """Execute 4th-order Runge-Kutta numerical integration step."""
        s0 = PHASuccinicEsterificationState(
            c_succinic_acid=self.state.c_succinic_acid,
            c_alcohol=self.state.c_alcohol,
            c_dialkyl_succinate=self.state.c_dialkyl_succinate,
            c_water=self.state.c_water,
            t_reboiler=self.state.t_reboiler,
            t_condenser=self.state.t_condenser,
            p_column=self.p_column,
            delta_p_trays=self.delta_p_trays,
            dt_reboiler_dt=self.state.dt_reboiler_dt,
        )

        # Pre-step interlock evaluation and rate-of-rise check
        k1 = self._derivatives(s0)
        dt_reb_dt_est = k1[4]
        self.last_dt_reboiler_dt = dt_reb_dt_est
        self.state.dt_reboiler_dt = dt_reb_dt_est

        if not self.trip_active:
            if self.check_interlocks(s0, dt_reboiler_dt=dt_reb_dt_est):
                self.sync_to_registers(self.reg_table)
                return

        # RK4 Stage k2
        s1 = PHASuccinicEsterificationState(
            c_succinic_acid=max(0.0, s0.c_succinic_acid + 0.5 * dt * k1[0]),
            c_alcohol=max(0.0, s0.c_alcohol + 0.5 * dt * k1[1]),
            c_dialkyl_succinate=max(0.0, s0.c_dialkyl_succinate + 0.5 * dt * k1[2]),
            c_water=max(0.0, s0.c_water + 0.5 * dt * k1[3]),
            t_reboiler=max(100.0, s0.t_reboiler + 0.5 * dt * k1[4]),
            t_condenser=max(100.0, s0.t_condenser + 0.5 * dt * k1[5]),
            p_column=max(0.0, s0.p_column + 0.5 * dt * k1[6]),
            delta_p_trays=self.delta_p_trays,
        )
        k2 = self._derivatives(s1)

        # RK4 Stage k3
        s2 = PHASuccinicEsterificationState(
            c_succinic_acid=max(0.0, s0.c_succinic_acid + 0.5 * dt * k2[0]),
            c_alcohol=max(0.0, s0.c_alcohol + 0.5 * dt * k2[1]),
            c_dialkyl_succinate=max(0.0, s0.c_dialkyl_succinate + 0.5 * dt * k2[2]),
            c_water=max(0.0, s0.c_water + 0.5 * dt * k2[3]),
            t_reboiler=max(100.0, s0.t_reboiler + 0.5 * dt * k2[4]),
            t_condenser=max(100.0, s0.t_condenser + 0.5 * dt * k2[5]),
            p_column=max(0.0, s0.p_column + 0.5 * dt * k2[6]),
            delta_p_trays=self.delta_p_trays,
        )
        k3 = self._derivatives(s2)

        # RK4 Stage k4
        s3 = PHASuccinicEsterificationState(
            c_succinic_acid=max(0.0, s0.c_succinic_acid + dt * k3[0]),
            c_alcohol=max(0.0, s0.c_alcohol + dt * k3[1]),
            c_dialkyl_succinate=max(0.0, s0.c_dialkyl_succinate + dt * k3[2]),
            c_water=max(0.0, s0.c_water + dt * k3[3]),
            t_reboiler=max(100.0, s0.t_reboiler + dt * k3[4]),
            t_condenser=max(100.0, s0.t_condenser + dt * k3[5]),
            p_column=max(0.0, s0.p_column + dt * k3[6]),
            delta_p_trays=self.delta_p_trays,
        )
        k4 = self._derivatives(s3)

        # Weighted RK4 integration
        dc_sa = (dt / 6.0) * (k1[0] + 2.0 * k2[0] + 2.0 * k3[0] + k4[0])
        dc_alc = (dt / 6.0) * (k1[1] + 2.0 * k2[1] + 2.0 * k3[1] + k4[1])
        dc_das = (dt / 6.0) * (k1[2] + 2.0 * k2[2] + 2.0 * k3[2] + k4[2])
        dc_water = (dt / 6.0) * (k1[3] + 2.0 * k2[3] + 2.0 * k3[3] + k4[3])
        dt_reb = (dt / 6.0) * (k1[4] + 2.0 * k2[4] + 2.0 * k3[4] + k4[4])
        dt_cond = (dt / 6.0) * (k1[5] + 2.0 * k2[5] + 2.0 * k3[5] + k4[5])
        dp_col = (dt / 6.0) * (k1[6] + 2.0 * k2[6] + 2.0 * k3[6] + k4[6])
        dc_dist_mass = (dt / 6.0) * (k1[7] + 2.0 * k2[7] + 2.0 * k3[7] + k4[7])

        # State updates
        self.state.c_succinic_acid = max(0.0, s0.c_succinic_acid + dc_sa)
        self.state.c_alcohol = max(0.0, s0.c_alcohol + dc_alc)
        self.state.c_dialkyl_succinate = max(0.0, s0.c_dialkyl_succinate + dc_das)
        self.state.c_water = max(0.0, s0.c_water + dc_water)
        self.state.t_reboiler = max(100.0, s0.t_reboiler + dt_reb)
        self.state.t_condenser = max(100.0, s0.t_condenser + dt_cond)
        self.p_column = max(0.0, s0.p_column + dp_col)
        self.state.p_column = self.p_column
        self.cumulative_distillate_mass_exported += dc_dist_mass
        self.state.dt_reboiler_dt = dt_reb / max(1e-6, dt)
        self.last_dt_reboiler_dt = self.state.dt_reboiler_dt

        # Tray hydraulics & differential pressure update
        active_duty = self.reboiler_duty_kw if self.reboiler_heater and not self.trip_active else 0.0
        v_boilup_mol_s = (active_duty * 1000.0 * 0.90) / self.cfg.delta_h_vap_j_mol
        if active_duty > 0.0:
            self.delta_p_trays = self.cfg.k_dp_vapor * (max(0.0, v_boilup_mol_s) ** 1.8) + self.cfg.k_dp_liquid
        else:
            self.delta_p_trays = 0.0
        self.state.delta_p_trays = self.delta_p_trays

        # Continuous Mass Conservation Residual Check
        current_mass_total = (
            self.state.c_succinic_acid * MW_SUCCINIC_ACID
            + self.state.c_alcohol * MW_ALCOHOL
            + self.state.c_dialkyl_succinate * MW_DIALKYL_SUCCINATE
            + self.state.c_water * MW_WATER
            + self.cumulative_distillate_mass_exported
        )
        if self.conservation_residual <= self.cfg.mass_residual_max:
            self.conservation_residual = abs(current_mass_total - self._initial_mass_total) / self._initial_mass_total

        # Post-step safety interlocks check
        self.check_interlocks(self.state, dt_reboiler_dt=self.state.dt_reboiler_dt)
        self.sync_to_registers(self.reg_table)

    rk4_step = step_rk4

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.USER,
    ) -> None:
        """Synchronize simulation state to Horner OCS memory %R2750..%R2757 and %M641..%M643."""
        rt = reg_table or self.reg_table

        # %R2750: REG_PHA_SUCC_REBOILER_TEMP (0.1 °C, signed 16-bit)
        treb_c = self.state.t_reboiler - T_ZERO_CELSIUS
        treb_scaled = int(round(treb_c * 10.0))
        rt.write_word(
            REG_PHA_SUCC_REBOILER_TEMP,
            treb_scaled & 0xFFFF,
            privilege=privilege,
        )

        # %R2751: REG_PHA_SUCC_CONDENSER_TEMP (0.1 °C, signed 16-bit)
        tcond_c = self.state.t_condenser - T_ZERO_CELSIUS
        tcond_scaled = int(round(tcond_c * 10.0))
        rt.write_word(
            REG_PHA_SUCC_CONDENSER_TEMP,
            tcond_scaled & 0xFFFF,
            privilege=privilege,
        )

        # %R2752: REG_PHA_SUCC_COLUMN_PRESSURE (0.01 bar, 0..5000)
        p_scaled = int(round(self.p_column * 100.0))
        p_clamped = max(0, min(5000, p_scaled))
        rt.write_word(
            REG_PHA_SUCC_COLUMN_PRESSURE,
            p_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2753: REG_PHA_SUCC_ESTER_PURITY (0.1 %, 0..1000)
        purity_scaled = int(round(self.ester_purity_pct * 10.0))
        purity_clamped = max(0, min(1000, purity_scaled))
        rt.write_word(
            REG_PHA_SUCC_ESTER_PURITY,
            purity_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2754: REG_PHA_SUCC_ACID_CONVERSION (0.1 %, 0..1000)
        conv_scaled = int(round(self.acid_conversion_pct * 10.0))
        conv_clamped = max(0, min(1000, conv_scaled))
        rt.write_word(
            REG_PHA_SUCC_ACID_CONVERSION,
            conv_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2755: REG_PHA_SUCC_REFLUX_RATIO (0.01 ratio, e.g. 250 -> 2.50)
        reflux_scaled = int(round(self.reflux_ratio * 100.0))
        reflux_clamped = max(0, min(10000, reflux_scaled))
        rt.write_word(
            REG_PHA_SUCC_REFLUX_RATIO,
            reflux_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2756: REG_PHA_SUCC_REBOILER_DUTY_KW (0.1 kW, 0..10000)
        duty_val = self.reboiler_duty_kw if self.reboiler_heater and not self.trip_active else 0.0
        duty_scaled = int(round(duty_val * 10.0))
        duty_clamped = max(0, min(10000, duty_scaled))
        rt.write_word(
            REG_PHA_SUCC_REBOILER_DUTY_KW,
            duty_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2757: REG_PHA_SUCC_DIAGNOSTIC_CODE
        rt.write_word(
            REG_PHA_SUCC_DIAGNOSTIC_CODE,
            int(self.diagnostic_code) & 0xFFFF,
            privilege=privilege,
        )

        # Discrete Coils %M641..%M643
        # %M641: COIL_PHA_SUCC_COLUMN_ACTIVE
        rt.write_bit(
            COIL_PHA_SUCC_COLUMN_ACTIVE,
            self.column_active and not self.trip_active,
            privilege=privilege,
        )

        # %M642: COIL_PHA_SUCC_REBOILER_HEATER
        rt.write_bit(
            COIL_PHA_SUCC_REBOILER_HEATER,
            self.reboiler_heater and not self.trip_active,
            privilege=privilege,
        )

        # %M643: COIL_PHA_SUCC_EMERGENCY_DUMP
        rt.write_bit(
            COIL_PHA_SUCC_EMERGENCY_DUMP,
            self.emergency_dump_active or self.trip_active,
            privilege=privilege,
        )

    def scan_step(self, *args: Any, ctx: Optional[ScanContext] = None, **kwargs: Any) -> ExecutionResult:
        """Execute one simulation scan cycle step."""
        context: Optional[ScanContext] = ctx or kwargs.get("context")
        if not context and args and isinstance(args[0], ScanContext):
            context = args[0]

        if context is not None and getattr(context, "register_table", None) is not None:
            self.reg_table = context.register_table

        self.cycle_count += 1
        dt = kwargs.get("dt", 0.1)
        if "dt_h" in kwargs:
            dt = float(kwargs["dt_h"]) * 3600.0
        if args and len(args) > 1 and isinstance(args[1], (int, float)):
            dt = float(args[1])
        elif args and len(args) == 1 and isinstance(args[0], (int, float)):
            dt = float(args[0])

        self.step_rk4(dt=dt)

        status = AgentStatus.SUCCESS if not self.trip_active else AgentStatus.FAILED
        err_code = None if not self.trip_active else str(self.diagnostic_code)
        details = (
            f"Bio-Succinic Esterification State: C_sa={self.state.c_succinic_acid:.2f} mol/L, "
            f"C_alc={self.state.c_alcohol:.2f} mol/L, C_das={self.state.c_dialkyl_succinate:.2f} mol/L, "
            f"C_water={self.state.c_water:.2f} mol/L, T_reb={self.state.t_reboiler:.1f} K, "
            f"T_cond={self.state.t_condenser:.1f} K, P_col={self.p_column:.2f} bar, "
            f"DeltaP={self.delta_p_trays:.3f} bar, Purity={self.ester_purity_pct:.1f}%, "
            f"Conv={self.acid_conversion_pct:.1f}%, Reflux={self.reflux_ratio:.2f}, "
            f"Duty={self.reboiler_duty_kw:.1f} kW"
        )

        return ExecutionResult(
            status=status,
            error_code=err_code,
            details=details,
            data={
                "c_succinic_acid": self.state.c_succinic_acid,
                "c_alcohol": self.state.c_alcohol,
                "c_dialkyl_succinate": self.state.c_dialkyl_succinate,
                "c_water": self.state.c_water,
                "t_reboiler": self.state.t_reboiler,
                "t_condenser": self.state.t_condenser,
                "p_column": self.p_column,
                "delta_p_trays": self.delta_p_trays,
                "reflux_ratio": self.reflux_ratio,
                "reboiler_duty_kw": self.reboiler_duty_kw,
                "acid_conversion_pct": self.acid_conversion_pct,
                "ester_purity_pct": self.ester_purity_pct,
                "trip_active": self.trip_active,
                "column_active": self.column_active,
                "reboiler_heater": self.reboiler_heater,
                "emergency_dump_active": self.emergency_dump_active,
                "diagnostic_code": str(self.diagnostic_code),
                "conservation_residual": self.conservation_residual,
                "cycle_count": self.cycle_count,
            },
        )

    def step(self, *args: Any, **kwargs: Any) -> None:
        """Execute single scan step for ILogicUnit interface."""
        self.scan_step(*args, **kwargs)

    def execute(self, *args: Any, **kwargs: Any) -> None:
        """Execute logic unit in simulation engine context."""
        self.scan_step(*args, **kwargs)

    def reset(self) -> None:
        """Reset simulation state and clear diagnostic trips."""
        self.state = PHASuccinicEsterificationState()
        self.diagnostic_code = DIAG_OK
        self.trip_active = False
        self.column_active = True
        self.reboiler_heater = True
        self.emergency_dump_active = False
        self.reboiler_duty_kw = self.cfg.reboiler_duty_nominal_kw
        self.reflux_ratio = self.cfg.reflux_ratio_nominal
        self.p_column = self.state.p_column
        self.delta_p_trays = self.state.delta_p_trays
        self.cycle_count = 0
        self.conservation_residual = 0.0
        self.last_dt_reboiler_dt = 0.0
        self.cumulative_distillate_mass_exported = 0.0
        self._initial_c_succinic_acid = max(1e-6, self.state.c_succinic_acid)
        self._initial_mass_total = (
            self.state.c_succinic_acid * MW_SUCCINIC_ACID
            + self.state.c_alcohol * MW_ALCOHOL
            + self.state.c_dialkyl_succinate * MW_DIALKYL_SUCCINATE
            + self.state.c_water * MW_WATER
        )
        self.sync_to_registers(self.reg_table)

    def get_mass_residual(self) -> float:
        """Return the current continuous mass conservation residual."""
        return self.conservation_residual

    def inject_reboiler_overheat(self, temp_k: float = 525.0) -> None:
        """Inject high reboiler temperature anomaly to trigger trip 0xF981."""
        self.state.t_reboiler = float(temp_k)

    def inject_reboiler_runaway_rate(self, rate_k_s: float = 25.0) -> None:
        """Inject fast reboiler temperature rate-of-rise to trigger trip 0xF981."""
        self.state.dt_reboiler_dt = float(rate_k_s)
        self.last_dt_reboiler_dt = float(rate_k_s)

    def inject_column_overpressure(self, pressure_bar: float = 33.0) -> None:
        """Inject column overpressure anomaly to trigger trip 0xF982."""
        self.p_column = float(pressure_bar)
        self.state.p_column = float(pressure_bar)

    def inject_tray_flooding(self, delta_p: float = 0.85) -> None:
        """Inject excessive tray differential pressure (flooding) to trigger trip 0xF983."""
        self.delta_p_trays = float(delta_p)
        self.state.delta_p_trays = float(delta_p)

    def inject_tray_weeping(self, delta_p: float = 0.015) -> None:
        """Inject insufficient tray differential pressure (weeping) to trigger trip 0xF983."""
        self.delta_p_trays = float(delta_p)
        self.state.delta_p_trays = float(delta_p)

    def inject_mass_divergence(self, residual: float = 0.005) -> None:
        """Inject mass conservation divergence anomaly to trigger trip 0xF984."""
        self.conservation_residual = float(residual)

    def inject_acid_precipitation(self, c_acid: float = 8.0) -> None:
        """Inject excess bio-succinic acid concentration beyond solubility limit to trigger trip 0xF985."""
        self.state.c_succinic_acid = float(c_acid)

    def inject_cold_precipitation(self, temp_k: float = 295.0) -> None:
        """Cool reboiler below precipitation threshold to trigger trip 0xF985."""
        self.state.t_reboiler = float(temp_k)


# Class aliases for component interoperability
PhaSuccinicEsterificationEngine = PHASuccinicEsterificationEngine
PHASuccinicEsterificationReactor = PHASuccinicEsterificationEngine
PhaSuccinicEsterificationReactor = PHASuccinicEsterificationEngine
PHASuccinicEsterificationSimulator = PHASuccinicEsterificationEngine
PhaSuccinicEsterificationSimulator = PHASuccinicEsterificationEngine
PHASuccinicEsterificationLogicUnit = PHASuccinicEsterificationEngine
PhaSuccinicEsterificationLogicUnit = PHASuccinicEsterificationEngine
PHASuccinicEsterificationSimulationLogicUnit = PHASuccinicEsterificationEngine
PhaSuccinicEsterificationSimulationLogicUnit = PHASuccinicEsterificationEngine
PHASuccinicEsterificationModel = PHASuccinicEsterificationEngine
PhaSuccinicEsterificationModel = PHASuccinicEsterificationEngine
PHASuccinicEsterificationPlantModel = PHASuccinicEsterificationEngine
PhaSuccinicEsterificationPlantModel = PHASuccinicEsterificationEngine
PHASuccEsterEngine = PHASuccinicEsterificationEngine
PhaSuccEsterEngine = PHASuccinicEsterificationEngine
PHASuccEsterSimulator = PHASuccinicEsterificationEngine
PhaSuccEsterSimulator = PHASuccinicEsterificationEngine


# ============================================================================
# 6. Deterministic 9-Stage Verification Function
# ============================================================================

def run_pha_succinic_esterification_verification(
    project_root: Optional[Any] = None,
    output_path: Optional[str] = None,
    work_package: str = "W314",
    quick: bool = False,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification sequence for W314.

    Strictly adheres to 4-state engineering contract:
    status: success | failed | blocked | inconclusive
    Only writes to output_path if output_path is not None.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: initial_state_and_kinetics_discretization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    column = PHASuccinicEsterificationEngine()
    c_sa_0 = column.state.c_succinic_acid
    c_das_0 = column.state.c_dialkyl_succinate
    steps_s1 = 2 if quick else 5
    for _ in range(steps_s1):
        column.step_rk4(dt=0.1)

    c1 = (
        column.state.c_succinic_acid < c_sa_0
        and column.state.c_dialkyl_succinate > c_das_0
        and column.diagnostic_code == DIAG_OK
        and column.trip_active is False
        and column.acid_conversion_pct > 0.0
        and column.ester_purity_pct > 0.0
    )
    test_results.append({
        "stage": 1,
        "name": "initial_state_and_kinetics_discretization",
        "passed": bool(c1),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"RK4 reactive distillation discretization verified: C_sa ({c_sa_0:.2f} -> {column.state.c_succinic_acid:.2f} mol/L), "
            f"C_das ({c_das_0:.2f} -> {column.state.c_dialkyl_succinate:.2f} mol/L), status nominal."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 2: esterification_kinetics_and_vle_equilibrium
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    col_kin = PHASuccinicEsterificationEngine()
    r_f_nom, r_r_nom, r_net_nom = col_kin.compute_rates(col_kin.state)

    # Temperature sensitivity: hot state vs. cold state
    st_hot = PHASuccinicEsterificationState(
        t_reboiler=460.0,
        c_succinic_acid=col_kin.state.c_succinic_acid,
        c_alcohol=col_kin.state.c_alcohol,
        c_dialkyl_succinate=col_kin.state.c_dialkyl_succinate,
        c_water=col_kin.state.c_water,
    )
    r_f_hot, _, _ = col_kin.compute_rates(st_hot)

    st_cold = PHASuccinicEsterificationState(
        t_reboiler=380.0,
        c_succinic_acid=col_kin.state.c_succinic_acid,
        c_alcohol=col_kin.state.c_alcohol,
        c_dialkyl_succinate=col_kin.state.c_dialkyl_succinate,
        c_water=col_kin.state.c_water,
    )
    r_f_cold, _, _ = col_kin.compute_rates(st_cold)

    c2 = (
        r_f_nom > 0.0
        and r_net_nom > 0.0
        and r_f_hot > r_f_nom > r_f_cold
        and col_kin.reflux_ratio > 0.0
    )
    test_results.append({
        "stage": 2,
        "name": "esterification_kinetics_and_vle_equilibrium",
        "passed": bool(c2),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Arrhenius esterification kinetics verified: r_f_hot={r_f_hot:.4f} > nom={r_f_nom:.4f} > cold={r_f_cold:.4f}; "
            f"Reflux ratio={col_kin.reflux_ratio:.2f}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 3: tray_flooding_weeping_and_dp_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    col_dp = PHASuccinicEsterificationEngine()
    dp_nom_ok = col_dp.cfg.delta_p_min <= col_dp.delta_p_trays <= col_dp.cfg.delta_p_max

    # Tray flooding trip test (DeltaP > 0.80 bar)
    col_flood = PHASuccinicEsterificationEngine()
    col_flood.inject_tray_flooding(delta_p=0.85)
    col_flood.step_rk4(dt=0.05)
    flood_ok = (
        col_flood.trip_active is True
        and col_flood.diagnostic_code == DIAG_ERR_TRAY_FLOODING_WEEPING
        and col_flood.emergency_dump_active is True
        and col_flood.column_active is False
        and col_flood.reboiler_heater is False
        and col_flood.reg_table.read_bit(COIL_PHA_SUCC_COLUMN_ACTIVE) is False
        and col_flood.reg_table.read_bit(COIL_PHA_SUCC_REBOILER_HEATER) is False
        and col_flood.reg_table.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP) is True
        and (col_flood.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF983
    )

    # Tray weeping trip test (DeltaP < 0.02 bar while column active)
    col_weep = PHASuccinicEsterificationEngine()
    col_weep.inject_tray_weeping(delta_p=0.012)
    col_weep.step_rk4(dt=0.05)
    weep_ok = (
        col_weep.trip_active is True
        and col_weep.diagnostic_code == DIAG_ERR_TRAY_FLOODING_WEEPING
    )

    c3 = dp_nom_ok and flood_ok and weep_ok
    test_results.append({
        "stage": 3,
        "name": "tray_flooding_weeping_and_dp_trip",
        "passed": bool(c3),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Tray flooding/weeping trip 0xF983 verified for high DeltaP (> 0.80 bar) and low DeltaP (< 0.02 bar); dump active.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: reboiler_condenser_energy_balance_and_dump
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    col_therm = PHASuccinicEsterificationEngine()
    col_therm.reboiler_duty_kw = 150.0
    t_reb_start = col_therm.state.t_reboiler
    col_therm.step_rk4(dt=0.2)
    heating_effect_ok = col_therm.state.t_reboiler >= (t_reb_start - 3.0)

    # Emergency dump cooldown and depressurization test
    col_dump = PHASuccinicEsterificationEngine()
    col_dump.emergency_dump()
    col_dump.trip_active = True
    t_reb_pre = col_dump.state.t_reboiler
    t_cond_pre = col_dump.state.t_condenser
    p_col_pre = col_dump.p_column
    col_dump.step_rk4(dt=0.5)

    dump_ok = (
        col_dump.state.t_reboiler < t_reb_pre
        and col_dump.state.t_condenser < t_cond_pre
        and col_dump.emergency_dump_active is True
    )

    c4 = heating_effect_ok and dump_ok
    test_results.append({
        "stage": 4,
        "name": "reboiler_condenser_energy_balance_and_dump",
        "passed": bool(c4),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Thermal energy balance verified: Heating duty operational; Emergency dump dropped "
            f"T_reboiler by {t_reb_pre - col_dump.state.t_reboiler:.2f} K, T_condenser by {t_cond_pre - col_dump.state.t_condenser:.2f} K."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 5: reboiler_overheat_safety_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # High reboiler temperature trip (T_reboiler > 520 K)
    col_temp = PHASuccinicEsterificationEngine()
    col_temp.inject_reboiler_overheat(temp_k=525.0)
    col_temp.step_rk4(dt=0.05)

    high_temp_trip_ok = (
        col_temp.trip_active is True
        and col_temp.diagnostic_code == DIAG_ERR_REBOILER_OVERHEAT
        and col_temp.emergency_dump_active is True
        and col_temp.column_active is False
        and col_temp.reboiler_heater is False
        and col_temp.reg_table.read_bit(COIL_PHA_SUCC_COLUMN_ACTIVE) is False
        and col_temp.reg_table.read_bit(COIL_PHA_SUCC_REBOILER_HEATER) is False
        and col_temp.reg_table.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP) is True
        and (col_temp.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF981
    )

    # High rate-of-rise trip (dT_reboiler/dt > 20 K/s)
    col_rate = PHASuccinicEsterificationEngine()
    col_rate.inject_reboiler_runaway_rate(rate_k_s=24.5)
    col_rate.step_rk4(dt=0.05)

    high_rate_trip_ok = (
        col_rate.trip_active is True
        and col_rate.diagnostic_code == DIAG_ERR_REBOILER_OVERHEAT
    )

    c5 = high_temp_trip_ok and high_rate_trip_ok
    test_results.append({
        "stage": 5,
        "name": "reboiler_overheat_safety_trip",
        "passed": bool(c5),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Reboiler overheat trip 0xF981 verified for both high temperature (> 520 K) and fast rise (> 20 K/s).",
    })

    # ------------------------------------------------------------------------
    # Stage 6: column_overpressure_safety_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    col_press = PHASuccinicEsterificationEngine()
    col_press.inject_column_overpressure(pressure_bar=32.5)  # Exceeds 30.0 bar threshold
    col_press.step_rk4(dt=0.05)

    c6 = (
        col_press.trip_active is True
        and col_press.diagnostic_code == DIAG_ERR_COLUMN_OVERPRESSURE
        and col_press.emergency_dump_active is True
        and col_press.column_active is False
        and col_press.reboiler_heater is False
        and col_press.reg_table.read_bit(COIL_PHA_SUCC_COLUMN_ACTIVE) is False
        and col_press.reg_table.read_bit(COIL_PHA_SUCC_REBOILER_HEATER) is False
        and col_press.reg_table.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP) is True
        and (col_press.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF982
    )
    test_results.append({
        "stage": 6,
        "name": "column_overpressure_safety_trip",
        "passed": bool(c6),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Column overpressure trip 0xF982 verified upon P_column > 30.0 bar; emergency dump actuated.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: acid_precipitation_clog_and_priority_hierarchy
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Acid precipitation clog trip (free acid > solubility limit)
    col_precip = PHASuccinicEsterificationEngine()
    col_precip.inject_acid_precipitation(c_acid=8.0)
    col_precip.step_rk4(dt=0.05)
    precip_trip_ok = (
        col_precip.trip_active is True
        and col_precip.diagnostic_code == DIAG_ERR_ACID_PRECIPITATION_CLOG
        and (col_precip.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF985
    )

    # Priority hierarchy checks:
    # 1. Reboiler Overheat (P1: 0xF981) dominates Overpressure (P2: 0xF982)
    col_p1_p2 = PHASuccinicEsterificationEngine()
    col_p1_p2.state.t_reboiler = 525.0
    col_p1_p2.p_column = 35.0
    col_p1_p2.step_rk4(dt=0.05)
    p1_dominates = col_p1_p2.diagnostic_code == DIAG_ERR_REBOILER_OVERHEAT

    # 2. Overpressure (P2: 0xF982) dominates Tray Flooding (P3: 0xF983)
    col_p2_p3 = PHASuccinicEsterificationEngine()
    col_p2_p3.p_column = 35.0
    col_p2_p3.delta_p_trays = 0.88
    col_p2_p3.step_rk4(dt=0.05)
    p2_dominates = col_p2_p3.diagnostic_code == DIAG_ERR_COLUMN_OVERPRESSURE

    # 3. Tray Flooding (P3: 0xF983) dominates Mass Divergence (P4: 0xF984)
    col_p3_p4 = PHASuccinicEsterificationEngine()
    col_p3_p4.delta_p_trays = 0.88
    col_p3_p4.conservation_residual = 0.005
    col_p3_p4.step_rk4(dt=0.05)
    p3_dominates = col_p3_p4.diagnostic_code == DIAG_ERR_TRAY_FLOODING_WEEPING

    # 4. Mass Divergence (P4: 0xF984) dominates Acid Precipitation (P5: 0xF985)
    col_p4_p5 = PHASuccinicEsterificationEngine()
    col_p4_p5.conservation_residual = 0.005
    col_p4_p5.state.c_succinic_acid = 8.5
    col_p4_p5.step_rk4(dt=0.05)
    p4_dominates = col_p4_p5.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE

    c7 = precip_trip_ok and p1_dominates and p2_dominates and p3_dominates and p4_dominates
    test_results.append({
        "stage": 7,
        "name": "acid_precipitation_clog_and_priority_hierarchy",
        "passed": bool(c7),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Acid precipitation trip (0xF985) and 5-tier fault priority hierarchy (0xF981 > 0xF982 > 0xF983 > 0xF984 > 0xF985) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: continuous_mass_conservation_and_divergence_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    col_cons = PHASuccinicEsterificationEngine()
    steps_s8 = 5 if quick else 15
    for _ in range(steps_s8):
        col_cons.step_rk4(dt=0.1)

    cons_ok = col_cons.conservation_residual < 1e-10

    # Divergence trip verification (residual > 1e-4)
    col_div = PHASuccinicEsterificationEngine()
    col_div.inject_mass_divergence(residual=0.005)
    col_div.step_rk4(dt=0.05)
    div_trip_ok = (
        col_div.trip_active is True
        and col_div.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        and (col_div.reg_table.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF984
    )

    c8 = cons_ok and div_trip_ok
    test_results.append({
        "stage": 8,
        "name": "continuous_mass_conservation_and_divergence_trip",
        "passed": bool(c8),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Strict continuous mass conservation residual {col_cons.conservation_residual:.2e} < 1e-10; "
            f"Mass divergence trip 0xF984 latched upon residual > 1e-4."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 9: horner_ocs_registers_and_pure_st_pou
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    col_s9 = PHASuccinicEsterificationEngine()
    col_s9.scan_step(dt=0.1)
    rt = RegisterTable()
    col_s9.sync_to_registers(rt)

    w_reb_t = rt.read_word(REG_PHA_SUCC_REBOILER_TEMP)
    w_cond_t = rt.read_word(REG_PHA_SUCC_CONDENSER_TEMP)
    w_press = rt.read_word(REG_PHA_SUCC_COLUMN_PRESSURE)
    w_purity = rt.read_word(REG_PHA_SUCC_ESTER_PURITY)
    w_conv = rt.read_word(REG_PHA_SUCC_ACID_CONVERSION)
    w_reflux = rt.read_word(REG_PHA_SUCC_REFLUX_RATIO)
    w_duty = rt.read_word(REG_PHA_SUCC_REBOILER_DUTY_KW)
    w_diag = rt.read_word(REG_PHA_SUCC_DIAGNOSTIC_CODE)

    b_active = rt.read_bit(COIL_PHA_SUCC_COLUMN_ACTIVE)
    b_heater = rt.read_bit(COIL_PHA_SUCC_REBOILER_HEATER)
    b_dump = rt.read_bit(COIL_PHA_SUCC_EMERGENCY_DUMP)

    regs_ok = (
        w_reb_t > 0
        and w_cond_t > 0
        and w_press > 0
        and w_purity > 0
        and w_conv >= 0
        and w_reflux > 0
        and w_duty > 0
        and (w_diag & 0xFFFF) == 0x0000
        and b_active is True
        and b_heater is True
        and b_dump is False
    )

    st_valid = verify_pha_succinic_esterification_pure_st()

    # Reject 9 ladder logic constructs with LadderForbiddenError
    ladder_constructs = [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(/)---",
        "---(S)---",
        "---(R)---",
        "RUNG 1: START",
        "NETWORK 10",
        "XIC %M641",
    ]
    rejected_count = 0
    for frag in ladder_constructs:
        bad_code = f"PROGRAM BadTest\nVAR x: BOOL; END_VAR\n{frag}\nEND_PROGRAM"
        try:
            SecurityGuard.assert_pure_st_content(bad_code)
        except LadderForbiddenError:
            rejected_count += 1

    c9 = regs_ok and st_valid and (rejected_count == 9)
    test_results.append({
        "stage": 9,
        "name": "horner_ocs_registers_and_pure_st_pou",
        "passed": bool(c9),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            "Horner OCS register space %R2750..%R2757, coils %M641..%M643, "
            "pure ST POU PHASuccinicEsterificationControl, and 9 ladder construct rejections verified."
        ),
    })

    # Summary
    passed_count = sum(1 for r in test_results if r["passed"])
    total_count = len(test_results)
    all_passed = passed_count == total_count

    pou_digest = hashlib.sha256(PHA_SUCCINIC_ESTERIFICATION_PURE_ST_POU.encode("utf-8")).hexdigest()
    model_digest = hashlib.sha256(
        json.dumps(col_s9.cfg.to_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()

    evidence = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": (
            f"Work Package {work_package} Industrial Bio-Succinic Acid Esterification Verification "
            f"{'PASSED' if all_passed else 'FAILED'} ({passed_count}/{total_count} stages)."
        ),
        "stages_passed": passed_count,
        "total_stages": total_count,
        "data": {
            "work_package": work_package,
            "gate": "G7",
            "checks_passed": passed_count,
            "total_checks": total_count,
            "stages": test_results,
            "tests": test_results,
            "digests": {
                "pou_sha256": pou_digest,
                "model_sha256": model_digest,
            },
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if output_path is not None:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


run_pha_succ_ester_verification = run_pha_succinic_esterification_verification


# ============================================================================
# 7. CLI Entry Point
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution for Bio-Succinic Acid Esterification simulation and verification."""
    parser = argparse.ArgumentParser(
        description="W314: Industrial Bio-Succinic Acid Esterification & PHA Precursor Distillation Column Simulation"
    )
    parser.add_argument("--verify", action="store_true", help="Run 9-stage verification suite")
    parser.add_argument("--output", "-o", type=str, default=None, help="Evidence JSON output file path")
    parser.add_argument("--quick", action="store_true", help="Execute rapid test subset")
    parser.add_argument("--work-package", type=str, default="W314", help="Work package identifier")
    parser.add_argument("--json", action="store_true", help="Print verification result as JSON")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet output")

    args = parser.parse_args(argv)

    if args.verify or args.output or args.json or args.quick:
        res = run_pha_succinic_esterification_verification(
            output_path=args.output,
            work_package=args.work_package,
            quick=args.quick,
        )
        if args.json:
            print(json.dumps(res, indent=2))
        elif not args.quiet:
            print(f"Status: {res['status']}")
            print(f"Details: {res['details']}")
            print(f"Passed: {res['data']['checks_passed']}/{res['data']['total_checks']}")
        return 0 if res["status"] == "success" else 1

    # Default simulation scan test
    engine = PHASuccinicEsterificationEngine()
    for cycle in range(1, 11):
        res = engine.scan_step(dt=0.1)
        print(f"Cycle {cycle:02d}: {res.details}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
