"""Industrial Catalytic Polyhydroxyalkanoate Hydrogenation & 1,4-Butanediol Precursor Fixed-Bed ODE Simulation.

Work Package: W317 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Fixed-Bed Catalytic PHA Hydrogenation & 1,4-BDO Synthesis]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Features:
1. Industrial Catalytic PHA Hydrogenation & 1,4-Butanediol (1,4-BDO) Synthesis:
   - High-pressure fixed-bed catalytic reactor converting dialkyl succinate ester
     (bio-succinic PHA precursor / monomer) into gamma-butyrolactone (GBL) intermediate
     and downstream 1,4-butanediol (1,4-BDO) desired product:
     Step 1: Succinate Ester + 2 H2  <===>  GBL Intermediate + 2 ROH (Alcohol)
     Step 2: GBL Intermediate + 2 H2 <===>  1,4-Butanediol (1,4-BDO)
     Overall: Succinate Ester + 4 H2  ===>  1,4-Butanediol + 2 ROH
   - Heterogeneous Langmuir-Hinshelwood catalytic hydrogenation kinetics with
     multi-component adsorption competition and catalyst coking/deactivation:
     * Step 1 rate: r1 = (k1 * a_cat * C_se * C_h2) / (1 + K_se*C_se + K_gbl*C_gbl + K_bdo*C_bdo + K_h2*C_h2)^2
     * Step 2 rate: r2 = (k2 * a_cat * C_gbl * C_h2) / (1 + K_se*C_se + K_gbl*C_gbl + K_bdo*C_bdo + K_h2*C_h2)^2
     * Catalyst coking: da_cat/dt = - kd * a_cat * exp(-Ead / (R*T)) * (C_se + 0.5*C_gbl)
2. Coupled 6-State Continuous Fixed-Bed ODE Vector:
   - State variables:
     1. C_succinate_ester: Dialkyl succinate ester concentration (mol/L)
     2. C_gbl_intermediate: Gamma-butyrolactone intermediate concentration (mol/L)
     3. C_bdo_product: 1,4-Butanediol product concentration (mol/L)
     4. C_h2_dissolved: Dissolved hydrogen concentration governed by Henry's law (mol/L)
     5. T_bed_kelvin: Catalytic fixed-bed reaction zone temperature (K)
     6. a_catalyst: Catalyst relative activity (fraction 0..1)
   - 4th-Order Runge-Kutta (RK4) numerical integrator step_rk4(dt).
   - Strict continuous carbon backbone mass conservation (residuals < 1e-10).
3. Process Safety Interlocks & Diagnostics (Strict 5-Tier Priority Hierarchy):
   - Priority 1: 0xF991 DIAG_ERR_THERMAL_RUNAWAY (T > 550 K or dT/dt > 15 K/s)
   - Priority 2: 0xF992 DIAG_ERR_OVERPRESSURE_RUPTURE (P > 80.0 bar)
   - Priority 3: 0xF993 DIAG_ERR_CATALYST_COKING (Activity < 30.0%)
   - Priority 4: 0xF994 DIAG_ERR_HYDROGEN_STARVATION (H2/Substrate ratio < stoichiometric minimum)
   - Priority 5: 0xF995 DIAG_ERR_MASS_BALANCE_DIVERGENCE (residual > 1e-4)
4. Horner OCS Memory Space Integration:
   - Word registers %R2780..%R2787:
     %R2780: REG_PHA_H2_REACTOR_TEMP (0.1 °C, signed 16-bit)
     %R2781: REG_PHA_H2_REACTOR_PRESSURE (0.01 bar, 0..10000)
     %R2782: REG_PHA_H2_CONVERSION_EFFICIENCY (0.1 %, 0..1000)
     %R2783: REG_PHA_H2_BDO_SELECTIVITY (0.1 %, 0..1000)
     %R2784: REG_PHA_H2_SPACE_VELOCITY_LHSV (0.01 h^-1, 0..10000)
     %R2785: REG_PHA_H2_CATALYST_ACTIVITY (0.1 %, 0..1000)
     %R2786: REG_PHA_H2_HYDROGEN_FLOW_SLPM (0.1 SLPM)
     %R2787: REG_PHA_H2_DIAGNOSTIC_CODE (0x0000=OK, 0xF991..0xF995)
   - Discrete coils %M648..%M650:
     %M648: COIL_PHA_H2_REACTOR_ACTIVE (BOOL)
     %M649: COIL_PHA_H2_HYDROGEN_FEED_VALVE (BOOL)
     %M650: COIL_PHA_H2_EMERGENCY_DEPRESSURIZE (BOOL)
5. Pure IEC 61131-3 Structured Text (ST) POU:
   - POU 'PHAHydrogenationBDOControl' with anti-ladder validation rejecting 9 ladder constructs.
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

MW_SUCCINATE_ESTER: float = 146.14     # Dimethyl succinate C6H10O4 (g/mol)
MW_GBL: float             = 86.09      # gamma-Butyrolactone C4H6O2 (g/mol)
MW_BDO: float             = 90.12      # 1,4-Butanediol C4H10O2 (g/mol)
MW_H2: float              = 2.016      # Hydrogen gas H2 (g/mol)
MW_METHANOL: float        = 32.04      # Byproduct alcohol CH3OH (g/mol)
MW_CARBON: float          = 12.011     # Carbon atomic weight (g/mol)

R_GAS_CONSTANT: float     = 8.314462618 # Universal gas constant [J/(mol*K)]
T_ZERO_CELSIUS: float     = 273.15     # 0.0 °C in Kelvin [K]


# ============================================================================
# 2. Horner OCS Memory Space Integration & Diagnostic Codes
# ============================================================================

# Word Registers %R2780..%R2787
REG_PHA_H2_REACTOR_TEMP: str           = "%R2780"  # 0.1 °C, signed 16-bit
REG_PHA_H2_REACTOR_PRESSURE: str       = "%R2781"  # 0.01 bar, 0..10000
REG_PHA_H2_CONVERSION_EFFICIENCY: str  = "%R2782"  # 0.1 %, 0..1000
REG_PHA_H2_BDO_SELECTIVITY: str        = "%R2783"  # 0.1 %, 0..1000
REG_PHA_H2_SPACE_VELOCITY_LHSV: str    = "%R2784"  # 0.01 h^-1, 0..10000
REG_PHA_H2_CATALYST_ACTIVITY: str      = "%R2785"  # 0.1 %, 0..1000
REG_PHA_H2_HYDROGEN_FLOW_SLPM: str     = "%R2786"  # 0.1 SLPM
REG_PHA_H2_DIAGNOSTIC_CODE: str        = "%R2787"  # 16-bit diagnostic code

# Register Aliases
REG_PHA_H2_TEMP: str                   = REG_PHA_H2_REACTOR_TEMP
REG_PHA_H2_T_BED: str                  = REG_PHA_H2_REACTOR_TEMP
REG_PHA_H2_REACTOR_TEMPERATURE: str    = REG_PHA_H2_REACTOR_TEMP
REG_PHA_H2_PRESSURE: str               = REG_PHA_H2_REACTOR_PRESSURE
REG_PHA_H2_P_REACTOR: str              = REG_PHA_H2_REACTOR_PRESSURE
REG_PHA_H2_CONVERSION: str             = REG_PHA_H2_CONVERSION_EFFICIENCY
REG_PHA_H2_EFFICIENCY: str             = REG_PHA_H2_CONVERSION_EFFICIENCY
REG_PHA_H2_SELECTIVITY: str            = REG_PHA_H2_BDO_SELECTIVITY
REG_PHA_H2_LHSV: str                   = REG_PHA_H2_SPACE_VELOCITY_LHSV
REG_PHA_H2_ACTIVITY: str               = REG_PHA_H2_CATALYST_ACTIVITY
REG_PHA_H2_FLOW: str                   = REG_PHA_H2_HYDROGEN_FLOW_SLPM
REG_PHA_H2_DIAG: str                   = REG_PHA_H2_DIAGNOSTIC_CODE

# Discrete Coils %M648..%M650
COIL_PHA_H2_REACTOR_ACTIVE: str        = "%M648"   # BOOL
COIL_PHA_H2_HYDROGEN_FEED_VALVE: str   = "%M649"   # BOOL
COIL_PHA_H2_EMERGENCY_DEPRESSURIZE: str = "%M650"  # BOOL

# Coil Aliases
COIL_PHA_H2_ACTIVE: str                = COIL_PHA_H2_REACTOR_ACTIVE
COIL_PHA_H2_RUNNING: str               = COIL_PHA_H2_REACTOR_ACTIVE
COIL_PHA_H2_VALVE: str                 = COIL_PHA_H2_HYDROGEN_FEED_VALVE
COIL_PHA_H2_FEED: str                  = COIL_PHA_H2_HYDROGEN_FEED_VALVE
COIL_PHA_H2_DEPRESSURIZE: str          = COIL_PHA_H2_EMERGENCY_DEPRESSURIZE
COIL_PHA_H2_VENT: str                  = COIL_PHA_H2_EMERGENCY_DEPRESSURIZE


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
DIAG_ERR_THERMAL_RUNAWAY: DiagnosticCode         = DiagnosticCode(0xF991)  # Priority 1: T > 550 K or dT/dt > 15 K/s
DIAG_ERR_OVERPRESSURE_RUPTURE: DiagnosticCode    = DiagnosticCode(0xF992)  # Priority 2: P > 80.0 bar
DIAG_ERR_CATALYST_COKING: DiagnosticCode         = DiagnosticCode(0xF993)  # Priority 3: Activity < 30.0%
DIAG_ERR_HYDROGEN_STARVATION: DiagnosticCode     = DiagnosticCode(0xF994)  # Priority 4: H2/Substrate ratio < stoichiometric minimum
DIAG_ERR_MASS_BALANCE_DIVERGENCE: DiagnosticCode = DiagnosticCode(0xF995)  # Priority 5: residual > 1e-4

# Diagnostic Aliases
DIAG_ERR_RUNAWAY: DiagnosticCode                 = DIAG_ERR_THERMAL_RUNAWAY
DIAG_ERR_OVERHEAT: DiagnosticCode                = DIAG_ERR_THERMAL_RUNAWAY
DIAG_ERR_OVERPRESSURE: DiagnosticCode            = DIAG_ERR_OVERPRESSURE_RUPTURE
DIAG_ERR_PRESSURE: DiagnosticCode                = DIAG_ERR_OVERPRESSURE_RUPTURE
DIAG_ERR_COKING: DiagnosticCode                  = DIAG_ERR_CATALYST_COKING
DIAG_ERR_DEACTIVATED: DiagnosticCode             = DIAG_ERR_CATALYST_COKING
DIAG_ERR_STARVATION: DiagnosticCode              = DIAG_ERR_HYDROGEN_STARVATION
DIAG_ERR_H2_STARVATION: DiagnosticCode           = DIAG_ERR_HYDROGEN_STARVATION
DIAG_ERR_MASS_DIVERGENCE: DiagnosticCode         = DIAG_ERR_MASS_BALANCE_DIVERGENCE
DIAG_ERR_MASS_BALANCE: DiagnosticCode            = DIAG_ERR_MASS_BALANCE_DIVERGENCE

PHAHydrogenationBDODiagnosticCode = DiagnosticCode
PhaHydrogenationBDODiagnosticCode = DiagnosticCode
PHAH2BDODiagnosticCode = DiagnosticCode
PhaH2BDODiagnosticCode = DiagnosticCode


class PHAHydrogenationBDOStatusWord(IntFlag):
    """Bitmask for Fixed-Bed Catalytic Hydrogenation Reactor operational status."""
    REACTOR_ACTIVE        = 1 << 0  # Bit 0: Fixed-bed reactor active (%M648)
    H2_FEED_VALVE         = 1 << 1  # Bit 1: Hydrogen feed supply valve open (%M649)
    EMERGENCY_DEPRESS     = 1 << 2  # Bit 2: Emergency depressurization valve open (%M650)
    COOLING_JACKET        = 1 << 3  # Bit 3: Bed cooling jacket operational
    TEMP_WARN             = 1 << 4  # Bit 4: Bed temperature pre-alarm
    PRESSURE_WARN         = 1 << 5  # Bit 5: Reactor pressure pre-alarm
    CATALYST_WARN         = 1 << 6  # Bit 6: Catalyst activity degradation pre-alarm
    EMERGENCY_TRIP        = 1 << 7  # Bit 7: Master safety trip latched

PhaHydrogenationBDOStatusWord = PHAHydrogenationBDOStatusWord
PHAH2BDOStatusWord = PHAHydrogenationBDOStatusWord
PhaH2BDOStatusWord = PHAHydrogenationBDOStatusWord
PHAHydrogenationBDOStatusBits = PHAHydrogenationBDOStatusWord
PhaHydrogenationBDOStatusBits = PHAHydrogenationBDOStatusWord
PHAH2BDOStatusBits = PHAHydrogenationBDOStatusWord
PhaH2BDOStatusBits = PHAHydrogenationBDOStatusWord


# ============================================================================
# 3. State & Configuration Models
# ============================================================================

@dataclass
class PHAHydrogenationBDOState:
    """Coupled 6-State Continuous Fixed-Bed ODE Vector for PHA Hydrogenation & 1,4-BDO Synthesis."""
    c_succinate_ester: float = 3.0       # mol/L: Dialkyl succinate ester substrate concentration
    c_gbl_intermediate: float = 0.05     # mol/L: Gamma-butyrolactone intermediate concentration
    c_bdo_product: float = 0.02          # mol/L: 1,4-Butanediol desired product concentration
    c_h2_dissolved: float = 0.39         # mol/L: Dissolved hydrogen concentration (Henry's law at 50 bar)
    t_bed_kelvin: float = 473.15         # K: Fixed-bed catalytic reaction zone temperature (~200.0 °C)
    a_catalyst: float = 1.0              # fraction 0..1: Catalyst relative activity (1.0 = 100%)
    p_reactor: float = 50.0              # bar: Reactor operating pressure
    h2_flow_slpm: float = 750.0          # SLPM: Hydrogen feed flow rate
    space_velocity_lhsv: float = 1.50    # h^-1: Liquid hourly space velocity
    dt_bed_dt: float = 0.0               # K/s: Catalyst bed temperature rate of change

    def to_dict(self) -> Dict[str, float]:
        return {
            "c_succinate_ester": self.c_succinate_ester,
            "c_gbl_intermediate": self.c_gbl_intermediate,
            "c_bdo_product": self.c_bdo_product,
            "c_h2_dissolved": self.c_h2_dissolved,
            "t_bed_kelvin": self.t_bed_kelvin,
            "a_catalyst": self.a_catalyst,
            "p_reactor": self.p_reactor,
            "h2_flow_slpm": self.h2_flow_slpm,
            "space_velocity_lhsv": self.space_velocity_lhsv,
            "dt_bed_dt": self.dt_bed_dt,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PHAHydrogenationBDOState:
        c_se = float(data.get("c_succinate_ester", data.get("C_succinate_ester", data.get("se", 3.0))))
        c_gbl = float(data.get("c_gbl_intermediate", data.get("C_gbl_intermediate", data.get("gbl", 0.05))))
        c_bdo = float(data.get("c_bdo_product", data.get("C_bdo_product", data.get("bdo", 0.02))))
        c_h2 = float(data.get("c_h2_dissolved", data.get("C_h2_dissolved", data.get("h2", 0.39))))
        t_bed = float(data.get("t_bed_kelvin", data.get("T_bed_kelvin", data.get("t_bed", 473.15))))
        a_cat = float(data.get("a_catalyst", data.get("a_cat", 1.0)))
        p_re = float(data.get("p_reactor", data.get("P_reactor", data.get("p_bar", 50.0))))
        flow = float(data.get("h2_flow_slpm", data.get("H2_flow_slpm", 750.0)))
        lhsv = float(data.get("space_velocity_lhsv", data.get("LHSV", 1.50)))
        dt_dt = float(data.get("dt_bed_dt", data.get("dT_bed_dt", 0.0)))
        return cls(
            c_succinate_ester=c_se,
            c_gbl_intermediate=c_gbl,
            c_bdo_product=c_bdo,
            c_h2_dissolved=c_h2,
            t_bed_kelvin=t_bed,
            a_catalyst=a_cat,
            p_reactor=p_re,
            h2_flow_slpm=flow,
            space_velocity_lhsv=lhsv,
            dt_bed_dt=dt_dt,
        )

    # Distinct property aliases
    @property
    def C_succinate_ester(self) -> float:
        return self.c_succinate_ester

    @C_succinate_ester.setter
    def C_succinate_ester(self, val: float) -> None:
        self.c_succinate_ester = float(val)

    @property
    def succinate_ester(self) -> float:
        return self.c_succinate_ester

    @succinate_ester.setter
    def succinate_ester(self, val: float) -> None:
        self.c_succinate_ester = float(val)

    @property
    def c_se(self) -> float:
        return self.c_succinate_ester

    @c_se.setter
    def c_se(self, val: float) -> None:
        self.c_succinate_ester = float(val)

    @property
    def C_se(self) -> float:
        return self.c_succinate_ester

    @C_se.setter
    def C_se(self, val: float) -> None:
        self.c_succinate_ester = float(val)

    @property
    def C_gbl_intermediate(self) -> float:
        return self.c_gbl_intermediate

    @C_gbl_intermediate.setter
    def C_gbl_intermediate(self, val: float) -> None:
        self.c_gbl_intermediate = float(val)

    @property
    def gbl_intermediate(self) -> float:
        return self.c_gbl_intermediate

    @gbl_intermediate.setter
    def gbl_intermediate(self, val: float) -> None:
        self.c_gbl_intermediate = float(val)

    @property
    def c_gbl(self) -> float:
        return self.c_gbl_intermediate

    @c_gbl.setter
    def c_gbl(self, val: float) -> None:
        self.c_gbl_intermediate = float(val)

    @property
    def C_gbl(self) -> float:
        return self.c_gbl_intermediate

    @C_gbl.setter
    def C_gbl(self, val: float) -> None:
        self.c_gbl_intermediate = float(val)

    @property
    def C_bdo_product(self) -> float:
        return self.c_bdo_product

    @C_bdo_product.setter
    def C_bdo_product(self, val: float) -> None:
        self.c_bdo_product = float(val)

    @property
    def bdo_product(self) -> float:
        return self.c_bdo_product

    @bdo_product.setter
    def bdo_product(self, val: float) -> None:
        self.c_bdo_product = float(val)

    @property
    def c_bdo(self) -> float:
        return self.c_bdo_product

    @c_bdo.setter
    def c_bdo(self, val: float) -> None:
        self.c_bdo_product = float(val)

    @property
    def C_bdo(self) -> float:
        return self.c_bdo_product

    @C_bdo.setter
    def C_bdo(self, val: float) -> None:
        self.c_bdo_product = float(val)

    @property
    def C_h2_dissolved(self) -> float:
        return self.c_h2_dissolved

    @C_h2_dissolved.setter
    def C_h2_dissolved(self, val: float) -> None:
        self.c_h2_dissolved = float(val)

    @property
    def c_h2(self) -> float:
        return self.c_h2_dissolved

    @c_h2.setter
    def c_h2(self, val: float) -> None:
        self.c_h2_dissolved = float(val)

    @property
    def C_h2(self) -> float:
        return self.c_h2_dissolved

    @C_h2.setter
    def C_h2(self, val: float) -> None:
        self.c_h2_dissolved = float(val)

    @property
    def T_bed_kelvin(self) -> float:
        return self.t_bed_kelvin

    @T_bed_kelvin.setter
    def T_bed_kelvin(self, val: float) -> None:
        self.t_bed_kelvin = float(val)

    @property
    def T_bed(self) -> float:
        return self.t_bed_kelvin

    @T_bed.setter
    def T_bed(self, val: float) -> None:
        self.t_bed_kelvin = float(val)

    @property
    def t_bed(self) -> float:
        return self.t_bed_kelvin

    @t_bed.setter
    def t_bed(self, val: float) -> None:
        self.t_bed_kelvin = float(val)

    @property
    def bed_temp(self) -> float:
        return self.t_bed_kelvin

    @bed_temp.setter
    def bed_temp(self, val: float) -> None:
        self.t_bed_kelvin = float(val)

    @property
    def a_cat(self) -> float:
        return self.a_catalyst

    @a_cat.setter
    def a_cat(self, val: float) -> None:
        self.a_catalyst = float(val)

    @property
    def catalyst_activity(self) -> float:
        return self.a_catalyst

    @catalyst_activity.setter
    def catalyst_activity(self, val: float) -> None:
        self.a_catalyst = float(val)

    @property
    def P_reactor(self) -> float:
        return self.p_reactor

    @P_reactor.setter
    def P_reactor(self, val: float) -> None:
        self.p_reactor = float(val)

    @property
    def reactor_pressure(self) -> float:
        return self.p_reactor

    @reactor_pressure.setter
    def reactor_pressure(self, val: float) -> None:
        self.p_reactor = float(val)

    @property
    def H2_flow_slpm(self) -> float:
        return self.h2_flow_slpm

    @H2_flow_slpm.setter
    def H2_flow_slpm(self, val: float) -> None:
        self.h2_flow_slpm = float(val)

    @property
    def LHSV(self) -> float:
        return self.space_velocity_lhsv

    @LHSV.setter
    def LHSV(self, val: float) -> None:
        self.space_velocity_lhsv = float(val)

    @property
    def dT_bed_dt(self) -> float:
        return self.dt_bed_dt

    @dT_bed_dt.setter
    def dT_bed_dt(self, val: float) -> None:
        self.dt_bed_dt = float(val)


PhaHydrogenationBDOState = PHAHydrogenationBDOState
PHAH2BDOState = PHAHydrogenationBDOState
PhaH2BDOState = PHAHydrogenationBDOState
PHAHydrogenationBDOStateModel = PHAHydrogenationBDOState
PhaHydrogenationBDOStateModel = PHAHydrogenationBDOState


@dataclass
class PHAHydrogenationBDOConfig:
    """Kinetic, thermodynamic, hydrodynamic, and safety parameters for PHA Hydrogenation & 1,4-BDO Reactor.

    NOTE: Duplicate typed fields and @property setters are strictly avoided.
    """
    # Langmuir-Hinshelwood kinetics for Step 1: Succinate Ester + 2 H2 -> GBL + 2 ROH
    k1_forward: float = 4.0e4             # Pre-exponential factor step 1 [L/(mol*s)]
    ea1_j_mol: float = 48000.0            # Activation energy step 1 [J/mol] (48.0 kJ/mol)

    # Langmuir-Hinshelwood kinetics for Step 2: GBL + 2 H2 -> 1,4-BDO
    k2_forward: float = 5.0e4             # Pre-exponential factor step 2 [L/(mol*s)]
    ea2_j_mol: float = 52000.0            # Activation energy step 2 [J/mol] (52.0 kJ/mol)

    # Catalyst deactivation / coking kinetics:
    k_coking: float = 5.0e-5              # Catalyst deactivation factor [L/(mol*s)]
    ea_coking_j_mol: float = 38000.0      # Deactivation activation energy [J/mol]

    # Langmuir adsorption equilibrium constants [L/mol]
    k_adsorb_se: float = 0.45             # Adsorption constant for succinate ester
    k_adsorb_gbl: float = 0.30            # Adsorption constant for GBL intermediate
    k_adsorb_bdo: float = 0.20            # Adsorption constant for 1,4-BDO product
    k_adsorb_h2: float = 0.15             # Adsorption constant for dissolved H2

    # Reaction enthalpies [J/mol] (exothermic hydrogenation)
    delta_h_rxn1_j_mol: float = -65000.0  # Enthalpy step 1 (SE -> GBL) [J/mol]
    delta_h_rxn2_j_mol: float = -60000.0  # Enthalpy step 2 (GBL -> BDO) [J/mol]

    # Reactor geometry & physical properties
    v_bed_m3: float = 0.10                # Fixed-bed catalyst volume [m³] (100 L)
    rho_liquid: float = 1020.0            # Liquid mixture bulk density [kg/m³]
    cp_liquid: float = 2200.0             # Liquid mixture specific heat capacity [J/(kg*K)]
    space_velocity_nominal: float = 1.50  # Nominal liquid hourly space velocity [h^-1]
    h2_flow_nominal_slpm: float = 750.0   # Nominal hydrogen gas feed rate [SLPM]

    # Thermal balances & heat exchange
    ua_jacket: float = 2400.0             # Bed cooling jacket overall heat transfer coeff [W/K]
    t_coolant: float = 363.15             # Cooling medium supply temperature [K] (90.0 °C)
    t_feed: float = 453.15                # Liquid feed inlet temperature [K] (180.0 °C)
    ua_loss: float = 25.0                 # Ambient thermal heat loss coefficient [W/K]
    t_ambient: float = 298.15             # Ambient environmental temperature [K]

    # Gas solubility & mass transfer
    henry_constant_h2: float = 0.0078     # Henry's law solubility constant [mol/(L*bar)]
    kla_mass_transfer: float = 2.0        # Gas-liquid mass transfer rate [1/s]
    nominal_pressure_bar: float = 50.0    # Operating pressure [bar]
    p_ambient_bar: float = 1.01325        # Ambient atmospheric pressure [bar]

    # Safety Interlock Thresholds (5-Tier Priority Hierarchy):
    t_bed_trip_max: float = 550.0         # Priority 1: Overheat trip threshold [K] (0xF991)
    dt_bed_dt_trip_max: float = 15.0      # Priority 1: Temperature rate-of-rise trip [K/s] (0xF991)
    p_reactor_trip_max: float = 80.0      # Priority 2: Overpressure rupture trip [bar] (0xF992)
    catalyst_activity_min: float = 0.30   # Priority 3: Catalyst coking minimum activity [-] (0xF993)
    h2_substrate_ratio_min: float = 2.0   # Priority 4: Hydrogen starvation minimum ratio [-] (0xF994)
    mass_residual_max: float = 1e-4       # Priority 5: Mass conservation residual trip [-] (0xF995)

    # Emergency action parameters
    k_depressurize: float = 0.40          # Emergency depressurization rate [1/s]
    ua_emergency_quench: float = 35000.0  # Emergency quench cooling heat transfer [W/K]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "k1_forward": self.k1_forward,
            "ea1_j_mol": self.ea1_j_mol,
            "k2_forward": self.k2_forward,
            "ea2_j_mol": self.ea2_j_mol,
            "k_coking": self.k_coking,
            "ea_coking_j_mol": self.ea_coking_j_mol,
            "delta_h_rxn1_j_mol": self.delta_h_rxn1_j_mol,
            "delta_h_rxn2_j_mol": self.delta_h_rxn2_j_mol,
            "v_bed_m3": self.v_bed_m3,
            "space_velocity_nominal": self.space_velocity_nominal,
            "h2_flow_nominal_slpm": self.h2_flow_nominal_slpm,
            "t_bed_trip_max": self.t_bed_trip_max,
            "dt_bed_dt_trip_max": self.dt_bed_dt_trip_max,
            "p_reactor_trip_max": self.p_reactor_trip_max,
            "catalyst_activity_min": self.catalyst_activity_min,
            "h2_substrate_ratio_min": self.h2_substrate_ratio_min,
            "mass_residual_max": self.mass_residual_max,
        }

    # Distinct alias properties (no matching typed fields)
    @property
    def k1(self) -> float:
        return self.k1_forward

    @k1.setter
    def k1(self, val: float) -> None:
        self.k1_forward = float(val)

    @property
    def k2(self) -> float:
        return self.k2_forward

    @k2.setter
    def k2(self, val: float) -> None:
        self.k2_forward = float(val)

    @property
    def ea1(self) -> float:
        return self.ea1_j_mol

    @ea1.setter
    def ea1(self, val: float) -> None:
        self.ea1_j_mol = float(val)

    @property
    def ea2(self) -> float:
        return self.ea2_j_mol

    @ea2.setter
    def ea2(self, val: float) -> None:
        self.ea2_j_mol = float(val)


PhaHydrogenationBDOConfig = PHAHydrogenationBDOConfig
PHAH2BDOConfig = PHAHydrogenationBDOConfig
PhaH2BDOConfig = PHAHydrogenationBDOConfig
PHAHydrogenationBDOParameters = PHAHydrogenationBDOConfig
PhaHydrogenationBDOParameters = PHAHydrogenationBDOConfig


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text POU
# ============================================================================

ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL = """
PROGRAM PHAHydrogenationBDOControl
VAR
    rReactorTemp AT %R2780 : INT;
    rReactorPressure AT %R2781 : WORD;
    rConversionEff AT %R2782 : WORD;
    rBDOSelectivity AT %R2783 : WORD;
    rSpaceVelocity AT %R2784 : WORD;
    rCatalystActivity AT %R2785 : WORD;
    rH2FlowRate AT %R2786 : WORD;
    wDiagnosticCode AT %R2787 : WORD;
    bReactorActive AT %M648 : BOOL;
    bH2FeedValve AT %M649 : BOOL;
    bEmergencyDepressurize AT %M650 : BOOL;
END_VAR

IF wDiagnosticCode = 0 THEN
    bReactorActive := TRUE;
    bH2FeedValve := TRUE;
    bEmergencyDepressurize := FALSE;
ELSE
    bReactorActive := FALSE;
    bH2FeedValve := FALSE;
    bEmergencyDepressurize := TRUE;
END_IF;
END_PROGRAM
""".strip()

PHA_HYDROGENATION_BDO_PURE_ST_POU: str = ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL
PHA_H2_BDO_PURE_ST_POU: str = ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL
PHAHydrogenationBDOControl: str = ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL
PHA_HYDROGENATION_BDO_CONTROL_POU: str = ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL


def verify_pha_hydrogenation_bdo_pure_st() -> bool:
    """Validate pure ST syntax and ensure strict rejection of ladder logic constructs."""
    try:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL)
    except LadderForbiddenError:
        return False
    val = STParser.validate_code(ST_PROGRAM_PHA_HYDROGENATION_BDO_CONTROL)
    return val.status == AgentStatus.SUCCESS


verify_pha_h2_bdo_pure_st = verify_pha_hydrogenation_bdo_pure_st


# ============================================================================
# 5. Simulation Fixed-Bed Reactor Engine (ILogicUnit)
# ============================================================================

class PHAHydrogenationBDOEngine(ILogicUnit):
    """Industrial Catalytic PHA Hydrogenation & 1,4-Butanediol Precursor Fixed-Bed ODE Simulator."""

    def __init__(
        self,
        config: Optional[PHAHydrogenationBDOConfig] = None,
        state: Optional[PHAHydrogenationBDOState] = None,
        reg_table: Optional[RegisterTable] = None,
        register_table: Optional[RegisterTable] = None,
        **kwargs: Any,
    ) -> None:
        self.cfg = config or PHAHydrogenationBDOConfig()
        self.state = state or PHAHydrogenationBDOState()
        self.reg_table = register_table or reg_table or RegisterTable()

        # Operational status flags
        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.trip_active: bool = False
        self.reactor_active: bool = True
        self.h2_feed_valve: bool = True
        self.emergency_depressurize_active: bool = False

        # Conservation and telemetry tracking
        self.cycle_count: int = 0
        self.conservation_residual: float = 0.0
        self.last_dt_bed_dt: float = 0.0
        self._forced_h2_substrate_ratio: Optional[float] = None

        # Baseline inventory for conversion and carbon skeleton conservation
        self._initial_c_succinate_ester: float = max(1e-6, self.state.c_succinate_ester)
        self._initial_c_bdo_product: float = self.state.c_bdo_product
        self._initial_c4: float = (
            self.state.c_succinate_ester
            + self.state.c_gbl_intermediate
            + self.state.c_bdo_product
        )

        # Initial register synchronization
        self.sync_to_registers(self.reg_table)

    @property
    def unit_id(self) -> str:
        return "PHA_H2_BDO_REACTOR_W317"

    @property
    def name(self) -> str:
        return "PHAHydrogenationBDOEngine"

    @property
    def priority(self) -> int:
        return 50

    @property
    def is_enabled(self) -> bool:
        return True

    @property
    def conversion_efficiency_pct(self) -> float:
        """Dialkyl succinate ester substrate conversion efficiency [%]."""
        if self._initial_c_succinate_ester < 1e-6:
            return 0.0
        c_conv = max(0.0, self._initial_c_succinate_ester - self.state.c_succinate_ester)
        return max(0.0, min(100.0, (c_conv / self._initial_c_succinate_ester) * 100.0))

    @property
    def bdo_selectivity_pct(self) -> float:
        """1,4-Butanediol selectivity relative to converted succinate ester / products [%]."""
        c_conv = max(0.0, self._initial_c_succinate_ester - self.state.c_succinate_ester)
        if c_conv > 1e-4:
            c_prod = max(0.0, self.state.c_bdo_product - self._initial_c_bdo_product)
            sel = (c_prod / c_conv) * 100.0
            return max(0.0, min(100.0, sel))
        tot_prod = self.state.c_gbl_intermediate + self.state.c_bdo_product
        if tot_prod < 1e-6:
            return 0.0
        sel = (self.state.c_bdo_product / tot_prod) * 100.0
        return max(0.0, min(100.0, sel))

    @property
    def h2_substrate_ratio(self) -> float:
        """Molar feed ratio of hydrogen supply to succinate ester substrate."""
        if self._forced_h2_substrate_ratio is not None:
            return self._forced_h2_substrate_ratio
        h2_mol_s = self.state.h2_flow_slpm / (60.0 * 22.414)
        v_bed_l = self.cfg.v_bed_m3 * 1000.0
        liquid_l_s = (max(0.01, self.state.space_velocity_lhsv) * v_bed_l) / 3600.0
        substrate_mol_s = liquid_l_s * max(0.01, self.state.c_succinate_ester)
        if substrate_mol_s < 1e-6:
            return 10.0
        return h2_mol_s / substrate_mol_s

    def compute_rates(
        self, s: PHAHydrogenationBDOState
    ) -> Tuple[float, float]:
        """Compute Langmuir-Hinshelwood catalytic hydrogenation reaction rates [mol/(L*s)].

        Returns:
            (r1, r2): Step 1 (SE -> GBL) and Step 2 (GBL -> 1,4-BDO) rates.
        """
        if self.trip_active or s.t_bed_kelvin < 250.0:
            return (0.0, 0.0)

        rt = R_GAS_CONSTANT * max(100.0, s.t_bed_kelvin)
        c_se = max(0.0, s.c_succinate_ester)
        c_gbl = max(0.0, s.c_gbl_intermediate)
        c_bdo = max(0.0, s.c_bdo_product)
        c_h2 = max(0.0, s.c_h2_dissolved)
        a_cat = max(0.0, min(1.0, s.a_catalyst))

        # Competitive adsorption denominator
        den = (
            1.0
            + self.cfg.k_adsorb_se * c_se
            + self.cfg.k_adsorb_gbl * c_gbl
            + self.cfg.k_adsorb_bdo * c_bdo
            + self.cfg.k_adsorb_h2 * c_h2
        )
        den_sq = den ** 2

        # Step 1: SE + 2 H2 -> GBL + 2 ROH
        k1_arrh = self.cfg.k1_forward * math.exp(-self.cfg.ea1_j_mol / rt)
        r1 = (k1_arrh * a_cat * c_se * c_h2) / den_sq

        # Step 2: GBL + 2 H2 -> 1,4-BDO
        k2_arrh = self.cfg.k2_forward * math.exp(-self.cfg.ea2_j_mol / rt)
        r2 = (k2_arrh * a_cat * c_gbl * c_h2) / den_sq

        return (r1, r2)

    def _derivatives(
        self, s: PHAHydrogenationBDOState
    ) -> Tuple[float, float, float, float, float, float, float]:
        """Compute coupled 6-state time derivatives plus reactor pressure dynamics.

        Returns:
            (dc_se_dt, dc_gbl_dt, dc_bdo_dt, dc_h2_dt, dt_bed_dt, da_cat_dt, dp_reactor_dt)
        """
        rho_cp = self.cfg.rho_liquid * self.cfg.cp_liquid

        if self.trip_active and self.emergency_depressurize_active:
            # Emergency trip: Rapid depressurization, thermal quench, zero forward reactions
            q_quench = (
                self.cfg.ua_emergency_quench * (s.t_bed_kelvin - self.cfg.t_ambient)
            ) / self.cfg.v_bed_m3
            dt_bed_dt = - q_quench / rho_cp
            dp_reactor_dt = - self.cfg.k_depressurize * max(0.0, s.p_reactor - self.cfg.p_ambient_bar)
            dc_h2_dt = - 0.5 * s.c_h2_dissolved
            return (0.0, 0.0, 0.0, dc_h2_dt, dt_bed_dt, 0.0, dp_reactor_dt)

        if self.trip_active:
            return (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        r1, r2 = self.compute_rates(s)

        # Carbon backbone species conservation:
        # dc_se_dt + dc_gbl_dt + dc_bdo_dt = -r1 + (r1 - r2) + r2 = 0
        dc_se_dt = - r1
        dc_gbl_dt = + r1 - r2
        dc_bdo_dt = + r2

        # Dissolved hydrogen mass transfer and consumption
        r_h2_cons = 2.0 * r1 + 2.0 * r2
        c_h2_sat = self.cfg.henry_constant_h2 * max(0.0, s.p_reactor)
        if self.h2_feed_valve:
            r_h2_transfer = self.cfg.kla_mass_transfer * (c_h2_sat - max(0.0, s.c_h2_dissolved))
        else:
            r_h2_transfer = 0.0
        dc_h2_dt = r_h2_transfer - r_h2_cons

        # Catalyst coking / deactivation
        rt = R_GAS_CONSTANT * max(100.0, s.t_bed_kelvin)
        kd_arrh = self.cfg.k_coking * math.exp(-self.cfg.ea_coking_j_mol / rt)
        r_deact = kd_arrh * s.a_catalyst * (s.c_succinate_ester + 0.5 * s.c_gbl_intermediate)
        da_cat_dt = - r_deact

        # Thermal energy balance for fixed-bed reaction zone:
        q_rxn = (
            r1 * (-self.cfg.delta_h_rxn1_j_mol)
            + r2 * (-self.cfg.delta_h_rxn2_j_mol)
        ) * 1000.0  # W/m³ exotherm
        q_cool = (self.cfg.ua_jacket * (s.t_bed_kelvin - self.cfg.t_coolant)) / self.cfg.v_bed_m3
        q_loss = (self.cfg.ua_loss * (s.t_bed_kelvin - self.cfg.t_ambient)) / self.cfg.v_bed_m3
        v_flow_m3_s = (max(0.0, s.space_velocity_lhsv) * self.cfg.v_bed_m3) / 3600.0
        q_feed = (
            v_flow_m3_s * self.cfg.rho_liquid * self.cfg.cp_liquid * (self.cfg.t_feed - s.t_bed_kelvin)
        ) / self.cfg.v_bed_m3
        dt_bed_dt = (q_rxn - q_cool - q_loss + q_feed) / rho_cp

        # Pressure dynamics in nominal operation
        dp_reactor_dt = 0.0

        return (
            dc_se_dt,
            dc_gbl_dt,
            dc_bdo_dt,
            dc_h2_dt,
            dt_bed_dt,
            da_cat_dt,
            dp_reactor_dt,
        )

    def emergency_shutdown(self) -> None:
        """Actuate fail-safe emergency depressurization and isolate H2 feed valve upon safety trip."""
        self.reactor_active = False
        self.h2_feed_valve = False
        self.emergency_depressurize_active = True
        self.state.h2_flow_slpm = 0.0

    emergency_depressurize = emergency_shutdown
    emergency_trip = emergency_shutdown
    emergency_quench = emergency_shutdown

    def check_interlocks(
        self, s: PHAHydrogenationBDOState, dt_bed_dt: float = 0.0
    ) -> bool:
        """Evaluate process safety interlocks in strict 5-tier priority order.

        Priority Hierarchy:
        1: 0xF991 DIAG_ERR_THERMAL_RUNAWAY (T > 550 K or dT/dt > 15 K/s)
        2: 0xF992 DIAG_ERR_OVERPRESSURE_RUPTURE (P > 80.0 bar)
        3: 0xF993 DIAG_ERR_CATALYST_COKING (Activity < 30.0%)
        4: 0xF994 DIAG_ERR_HYDROGEN_STARVATION (H2/Substrate ratio < stoichiometric minimum)
        5: 0xF995 DIAG_ERR_MASS_BALANCE_DIVERGENCE (residual > 1e-4)
        """
        if self.trip_active:
            return True

        rate_check = max(abs(dt_bed_dt), abs(s.dt_bed_dt), abs(self.last_dt_bed_dt))

        # Priority 1: Thermal runaway trip (T > 550 K or dT/dt > 15 K/s)
        if s.t_bed_kelvin > self.cfg.t_bed_trip_max or rate_check > self.cfg.dt_bed_dt_trip_max:
            self.diagnostic_code = DIAG_ERR_THERMAL_RUNAWAY
            self.trip_active = True
            self.emergency_shutdown()
            return True

        # Priority 2: Overpressure rupture trip (P > 80.0 bar)
        if s.p_reactor > self.cfg.p_reactor_trip_max:
            self.diagnostic_code = DIAG_ERR_OVERPRESSURE_RUPTURE
            self.trip_active = True
            self.emergency_shutdown()
            return True

        # Priority 3: Catalyst coking trip (Activity < 30.0% / 0.30)
        if s.a_catalyst < self.cfg.catalyst_activity_min:
            self.diagnostic_code = DIAG_ERR_CATALYST_COKING
            self.trip_active = True
            self.emergency_shutdown()
            return True

        # Priority 4: Hydrogen starvation trip (H2/Substrate ratio < stoichiometric minimum)
        if self.h2_substrate_ratio < self.cfg.h2_substrate_ratio_min:
            self.diagnostic_code = DIAG_ERR_HYDROGEN_STARVATION
            self.trip_active = True
            self.emergency_shutdown()
            return True

        # Priority 5: Continuous mass balance divergence trip (residual > 1e-4)
        if self.conservation_residual > self.cfg.mass_residual_max:
            self.diagnostic_code = DIAG_ERR_MASS_BALANCE_DIVERGENCE
            self.trip_active = True
            self.emergency_shutdown()
            return True

        return False

    def step_rk4(self, dt: float = 0.1) -> None:
        """Execute 4th-order Runge-Kutta numerical integration step."""
        s0 = PHAHydrogenationBDOState(
            c_succinate_ester=self.state.c_succinate_ester,
            c_gbl_intermediate=self.state.c_gbl_intermediate,
            c_bdo_product=self.state.c_bdo_product,
            c_h2_dissolved=self.state.c_h2_dissolved,
            t_bed_kelvin=self.state.t_bed_kelvin,
            a_catalyst=self.state.a_catalyst,
            p_reactor=self.state.p_reactor,
            h2_flow_slpm=self.state.h2_flow_slpm,
            space_velocity_lhsv=self.state.space_velocity_lhsv,
            dt_bed_dt=self.state.dt_bed_dt,
        )

        # Pre-step interlock evaluation and rate-of-rise check
        k1 = self._derivatives(s0)
        dt_est = k1[4]
        self.last_dt_bed_dt = dt_est
        self.state.dt_bed_dt = dt_est

        if not self.trip_active:
            if self.check_interlocks(s0, dt_bed_dt=dt_est):
                self.sync_to_registers(self.reg_table)
                return

        # RK4 Stage k2
        s1 = PHAHydrogenationBDOState(
            c_succinate_ester=max(0.0, s0.c_succinate_ester + 0.5 * dt * k1[0]),
            c_gbl_intermediate=max(0.0, s0.c_gbl_intermediate + 0.5 * dt * k1[1]),
            c_bdo_product=max(0.0, s0.c_bdo_product + 0.5 * dt * k1[2]),
            c_h2_dissolved=max(0.0, s0.c_h2_dissolved + 0.5 * dt * k1[3]),
            t_bed_kelvin=max(100.0, s0.t_bed_kelvin + 0.5 * dt * k1[4]),
            a_catalyst=max(0.0, min(1.0, s0.a_catalyst + 0.5 * dt * k1[5])),
            p_reactor=max(0.0, s0.p_reactor + 0.5 * dt * k1[6]),
            h2_flow_slpm=s0.h2_flow_slpm,
            space_velocity_lhsv=s0.space_velocity_lhsv,
        )
        k2 = self._derivatives(s1)

        # RK4 Stage k3
        s2 = PHAHydrogenationBDOState(
            c_succinate_ester=max(0.0, s0.c_succinate_ester + 0.5 * dt * k2[0]),
            c_gbl_intermediate=max(0.0, s0.c_gbl_intermediate + 0.5 * dt * k2[1]),
            c_bdo_product=max(0.0, s0.c_bdo_product + 0.5 * dt * k2[2]),
            c_h2_dissolved=max(0.0, s0.c_h2_dissolved + 0.5 * dt * k2[3]),
            t_bed_kelvin=max(100.0, s0.t_bed_kelvin + 0.5 * dt * k2[4]),
            a_catalyst=max(0.0, min(1.0, s0.a_catalyst + 0.5 * dt * k2[5])),
            p_reactor=max(0.0, s0.p_reactor + 0.5 * dt * k2[6]),
            h2_flow_slpm=s0.h2_flow_slpm,
            space_velocity_lhsv=s0.space_velocity_lhsv,
        )
        k3 = self._derivatives(s2)

        # RK4 Stage k4
        s3 = PHAHydrogenationBDOState(
            c_succinate_ester=max(0.0, s0.c_succinate_ester + dt * k3[0]),
            c_gbl_intermediate=max(0.0, s0.c_gbl_intermediate + dt * k3[1]),
            c_bdo_product=max(0.0, s0.c_bdo_product + dt * k3[2]),
            c_h2_dissolved=max(0.0, s0.c_h2_dissolved + dt * k3[3]),
            t_bed_kelvin=max(100.0, s0.t_bed_kelvin + dt * k3[4]),
            a_catalyst=max(0.0, min(1.0, s0.a_catalyst + dt * k3[5])),
            p_reactor=max(0.0, s0.p_reactor + dt * k3[6]),
            h2_flow_slpm=s0.h2_flow_slpm,
            space_velocity_lhsv=s0.space_velocity_lhsv,
        )
        k4 = self._derivatives(s3)

        # Weighted RK4 integration
        dc_se = (dt / 6.0) * (k1[0] + 2.0 * k2[0] + 2.0 * k3[0] + k4[0])
        dc_gbl = (dt / 6.0) * (k1[1] + 2.0 * k2[1] + 2.0 * k3[1] + k4[1])
        dc_bdo = (dt / 6.0) * (k1[2] + 2.0 * k2[2] + 2.0 * k3[2] + k4[2])
        dc_h2 = (dt / 6.0) * (k1[3] + 2.0 * k2[3] + 2.0 * k3[3] + k4[3])
        dt_bed = (dt / 6.0) * (k1[4] + 2.0 * k2[4] + 2.0 * k3[4] + k4[4])
        da_cat = (dt / 6.0) * (k1[5] + 2.0 * k2[5] + 2.0 * k3[5] + k4[5])
        dp_re = (dt / 6.0) * (k1[6] + 2.0 * k2[6] + 2.0 * k3[6] + k4[6])

        # State updates
        self.state.c_succinate_ester = max(0.0, s0.c_succinate_ester + dc_se)
        self.state.c_gbl_intermediate = max(0.0, s0.c_gbl_intermediate + dc_gbl)
        self.state.c_bdo_product = max(0.0, s0.c_bdo_product + dc_bdo)
        self.state.c_h2_dissolved = max(0.0, s0.c_h2_dissolved + dc_h2)
        self.state.t_bed_kelvin = max(100.0, s0.t_bed_kelvin + dt_bed)
        self.state.a_catalyst = max(0.0, min(1.0, s0.a_catalyst + da_cat))
        self.state.p_reactor = max(0.0, s0.p_reactor + dp_re)
        self.state.dt_bed_dt = dt_bed / max(1e-6, dt)
        self.last_dt_bed_dt = self.state.dt_bed_dt

        # Continuous Carbon Backbone Conservation Residual Check
        current_c4 = (
            self.state.c_succinate_ester
            + self.state.c_gbl_intermediate
            + self.state.c_bdo_product
        )
        if self.conservation_residual <= self.cfg.mass_residual_max:
            self.conservation_residual = abs(current_c4 - self._initial_c4) / self._initial_c4

        # Post-step safety interlocks check
        self.check_interlocks(self.state, dt_bed_dt=self.state.dt_bed_dt)
        self.sync_to_registers(self.reg_table)

    rk4_step = step_rk4

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.USER,
    ) -> None:
        """Synchronize simulation state to Horner OCS memory %R2780..%R2787 and %M648..%M650."""
        rt = reg_table or self.reg_table

        # %R2780: REG_PHA_H2_REACTOR_TEMP (0.1 °C, signed 16-bit)
        t_celsius = self.state.t_bed_kelvin - T_ZERO_CELSIUS
        t_scaled = int(round(t_celsius * 10.0))
        rt.write_word(
            REG_PHA_H2_REACTOR_TEMP,
            t_scaled & 0xFFFF,
            privilege=privilege,
        )

        # %R2781: REG_PHA_H2_REACTOR_PRESSURE (0.01 bar, 0..10000)
        p_scaled = int(round(self.state.p_reactor * 100.0))
        p_clamped = max(0, min(10000, p_scaled))
        rt.write_word(
            REG_PHA_H2_REACTOR_PRESSURE,
            p_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2782: REG_PHA_H2_CONVERSION_EFFICIENCY (0.1 %, 0..1000)
        conv_scaled = int(round(self.conversion_efficiency_pct * 10.0))
        conv_clamped = max(0, min(1000, conv_scaled))
        rt.write_word(
            REG_PHA_H2_CONVERSION_EFFICIENCY,
            conv_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2783: REG_PHA_H2_BDO_SELECTIVITY (0.1 %, 0..1000)
        sel_scaled = int(round(self.bdo_selectivity_pct * 10.0))
        sel_clamped = max(0, min(1000, sel_scaled))
        rt.write_word(
            REG_PHA_H2_BDO_SELECTIVITY,
            sel_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2784: REG_PHA_H2_SPACE_VELOCITY_LHSV (0.01 h^-1)
        lhsv_scaled = int(round(self.state.space_velocity_lhsv * 100.0))
        lhsv_clamped = max(0, min(10000, lhsv_scaled))
        rt.write_word(
            REG_PHA_H2_SPACE_VELOCITY_LHSV,
            lhsv_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2785: REG_PHA_H2_CATALYST_ACTIVITY (0.1 %, 0..1000)
        act_scaled = int(round(self.state.a_catalyst * 1000.0))
        act_clamped = max(0, min(1000, act_scaled))
        rt.write_word(
            REG_PHA_H2_CATALYST_ACTIVITY,
            act_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2786: REG_PHA_H2_HYDROGEN_FLOW_SLPM (0.1 SLPM)
        flow_val = self.state.h2_flow_slpm if self.h2_feed_valve and not self.trip_active else 0.0
        flow_scaled = int(round(flow_val * 10.0))
        flow_clamped = max(0, min(65535, flow_scaled))
        rt.write_word(
            REG_PHA_H2_HYDROGEN_FLOW_SLPM,
            flow_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2787: REG_PHA_H2_DIAGNOSTIC_CODE
        rt.write_word(
            REG_PHA_H2_DIAGNOSTIC_CODE,
            int(self.diagnostic_code) & 0xFFFF,
            privilege=privilege,
        )

        # Discrete Coils %M648..%M650
        # %M648: COIL_PHA_H2_REACTOR_ACTIVE
        rt.write_bit(
            COIL_PHA_H2_REACTOR_ACTIVE,
            self.reactor_active and not self.trip_active,
            privilege=privilege,
        )

        # %M649: COIL_PHA_H2_HYDROGEN_FEED_VALVE
        rt.write_bit(
            COIL_PHA_H2_HYDROGEN_FEED_VALVE,
            self.h2_feed_valve and not self.trip_active,
            privilege=privilege,
        )

        # %M650: COIL_PHA_H2_EMERGENCY_DEPRESSURIZE
        rt.write_bit(
            COIL_PHA_H2_EMERGENCY_DEPRESSURIZE,
            self.emergency_depressurize_active or self.trip_active,
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
            f"PHA Hydrogenation Fixed-Bed: C_se={self.state.c_succinate_ester:.2f} mol/L, "
            f"C_gbl={self.state.c_gbl_intermediate:.2f} mol/L, C_bdo={self.state.c_bdo_product:.2f} mol/L, "
            f"C_h2={self.state.c_h2_dissolved:.3f} mol/L, T_bed={self.state.t_bed_kelvin:.1f} K, "
            f"P_re={self.state.p_reactor:.2f} bar, a_cat={self.state.a_catalyst:.3f}, "
            f"Conv={self.conversion_efficiency_pct:.1f}%, Sel={self.bdo_selectivity_pct:.1f}%, "
            f"H2_Flow={self.state.h2_flow_slpm:.1f} SLPM"
        )

        return ExecutionResult(
            status=status,
            error_code=err_code,
            details=details,
            data={
                "c_succinate_ester": self.state.c_succinate_ester,
                "c_gbl_intermediate": self.state.c_gbl_intermediate,
                "c_bdo_product": self.state.c_bdo_product,
                "c_h2_dissolved": self.state.c_h2_dissolved,
                "t_bed_kelvin": self.state.t_bed_kelvin,
                "a_catalyst": self.state.a_catalyst,
                "p_reactor": self.state.p_reactor,
                "h2_flow_slpm": self.state.h2_flow_slpm,
                "space_velocity_lhsv": self.state.space_velocity_lhsv,
                "conversion_efficiency_pct": self.conversion_efficiency_pct,
                "bdo_selectivity_pct": self.bdo_selectivity_pct,
                "h2_substrate_ratio": self.h2_substrate_ratio,
                "trip_active": self.trip_active,
                "reactor_active": self.reactor_active,
                "h2_feed_valve": self.h2_feed_valve,
                "emergency_depressurize_active": self.emergency_depressurize_active,
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
        self.state = PHAHydrogenationBDOState()
        self.diagnostic_code = DIAG_OK
        self.trip_active = False
        self.reactor_active = True
        self.h2_feed_valve = True
        self.emergency_depressurize_active = False
        self.cycle_count = 0
        self.conservation_residual = 0.0
        self.last_dt_bed_dt = 0.0
        self._forced_h2_substrate_ratio = None
        self._initial_c_succinate_ester = max(1e-6, self.state.c_succinate_ester)
        self._initial_c_bdo_product = self.state.c_bdo_product
        self._initial_c4 = (
            self.state.c_succinate_ester
            + self.state.c_gbl_intermediate
            + self.state.c_bdo_product
        )
        self.sync_to_registers(self.reg_table)

    def get_mass_residual(self) -> float:
        """Return the current continuous carbon backbone conservation residual."""
        return self.conservation_residual

    def inject_thermal_runaway(self, temp_k: float = 555.0) -> None:
        """Inject high fixed-bed temperature anomaly to trigger trip 0xF991."""
        self.state.t_bed_kelvin = float(temp_k)

    def inject_temperature_rate_runaway(self, rate_k_s: float = 18.0) -> None:
        """Inject fast temperature rate-of-rise to trigger trip 0xF991."""
        self.state.dt_bed_dt = float(rate_k_s)
        self.last_dt_bed_dt = float(rate_k_s)

    def inject_overpressure(self, pressure_bar: float = 85.0) -> None:
        """Inject reactor overpressure rupture anomaly to trigger trip 0xF992."""
        self.state.p_reactor = float(pressure_bar)

    def inject_catalyst_coking(self, activity: float = 0.25) -> None:
        """Inject catalyst deactivation / coking anomaly to trigger trip 0xF993."""
        self.state.a_catalyst = float(activity)

    def inject_hydrogen_starvation(self, ratio: float = 1.0) -> None:
        """Inject hydrogen starvation condition (H2/Substrate ratio < stoichiometric minimum) to trigger 0xF994."""
        self._forced_h2_substrate_ratio = float(ratio)

    def inject_mass_divergence(self, residual: float = 0.005) -> None:
        """Inject continuous mass conservation divergence anomaly to trigger trip 0xF995."""
        self.conservation_residual = float(residual)

    def clear_injections(self) -> None:
        """Clear forced fault injections."""
        self._forced_h2_substrate_ratio = None


# Interoperability aliases
PhaHydrogenationBDOEngine = PHAHydrogenationBDOEngine
PHAHydrogenationBDOSimulator = PHAHydrogenationBDOEngine
PhaHydrogenationBDOSimulator = PHAHydrogenationBDOEngine
PHAHydrogenationBDOReactor = PHAHydrogenationBDOEngine
PhaHydrogenationBDOReactor = PHAHydrogenationBDOEngine
PHAHydrogenationBDOLogicUnit = PHAHydrogenationBDOEngine
PhaHydrogenationBDOLogicUnit = PHAHydrogenationBDOEngine
PHAH2BDOEngine = PHAHydrogenationBDOEngine
PhaH2BDOEngine = PHAHydrogenationBDOEngine
PHAH2BDOSimulator = PHAHydrogenationBDOEngine
PhaH2BDOSimulator = PHAHydrogenationBDOEngine


# ============================================================================
# 6. Deterministic 9-Stage Verification Function
# ============================================================================

def run_pha_hydrogenation_bdo_verification(
    project_root: Optional[Any] = None,
    output_path: Optional[str] = None,
    work_package: str = "W317",
    quick: bool = False,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification sequence for W317.

    Strictly adheres to 4-state engineering contract:
    status: success | failed | blocked | inconclusive
    Only writes to output_path if output_path is not None.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: initial_state_and_rk4_discretization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    reactor = PHAHydrogenationBDOEngine()
    c_se_0 = reactor.state.c_succinate_ester
    c_gbl_0 = reactor.state.c_gbl_intermediate
    c_bdo_0 = reactor.state.c_bdo_product
    steps_s1 = 2 if quick else 5
    for _ in range(steps_s1):
        reactor.step_rk4(dt=0.1)

    c1 = (
        reactor.state.c_succinate_ester < c_se_0
        and reactor.state.c_gbl_intermediate > c_gbl_0
        and reactor.state.c_bdo_product > c_bdo_0
        and reactor.diagnostic_code == DIAG_OK
        and reactor.trip_active is False
        and reactor.conversion_efficiency_pct > 0.0
        and reactor.bdo_selectivity_pct > 0.0
        and reactor.state.a_catalyst > 0.90
    )
    test_results.append({
        "stage": 1,
        "name": "initial_state_and_rk4_discretization",
        "passed": bool(c1),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"RK4 fixed-bed hydrogenation verified: C_se ({c_se_0:.2f} -> {reactor.state.c_succinate_ester:.2f} mol/L), "
            f"C_gbl ({c_gbl_0:.2f} -> {reactor.state.c_gbl_intermediate:.2f} mol/L), "
            f"C_bdo ({c_bdo_0:.2f} -> {reactor.state.c_bdo_product:.2f} mol/L), Conv={reactor.conversion_efficiency_pct:.1f}%."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 2: langmuir_hinshelwood_kinetics_and_temperature_sensitivity
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_kin = PHAHydrogenationBDOEngine()
    r1_nom, r2_nom = re_kin.compute_rates(re_kin.state)

    st_hot = PHAHydrogenationBDOState(
        t_bed_kelvin=500.0,
        c_succinate_ester=re_kin.state.c_succinate_ester,
        c_gbl_intermediate=re_kin.state.c_gbl_intermediate,
        c_bdo_product=re_kin.state.c_bdo_product,
        c_h2_dissolved=re_kin.state.c_h2_dissolved,
    )
    r1_hot, r2_hot = re_kin.compute_rates(st_hot)

    st_cold = PHAHydrogenationBDOState(
        t_bed_kelvin=420.0,
        c_succinate_ester=re_kin.state.c_succinate_ester,
        c_gbl_intermediate=re_kin.state.c_gbl_intermediate,
        c_bdo_product=re_kin.state.c_bdo_product,
        c_h2_dissolved=re_kin.state.c_h2_dissolved,
    )
    r1_cold, r2_cold = re_kin.compute_rates(st_cold)

    c2 = (
        r1_nom > 0.0
        and r2_nom > 0.0
        and r1_hot > r1_nom > r1_cold
        and r2_hot > r2_nom > r2_cold
        and re_kin.h2_substrate_ratio > re_kin.cfg.h2_substrate_ratio_min
    )
    test_results.append({
        "stage": 2,
        "name": "langmuir_hinshelwood_kinetics_and_temperature_sensitivity",
        "passed": bool(c2),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Langmuir-Hinshelwood Arrhenius kinetics verified: r1_hot={r1_hot:.4f} > nom={r1_nom:.4f} > cold={r1_cold:.4f}; "
            f"r2_hot={r2_hot:.4f} > nom={r2_nom:.4f} > cold={r2_cold:.4f}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 3: catalyst_deactivation_and_coking_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_coking = PHAHydrogenationBDOEngine()
    re_coking.inject_catalyst_coking(activity=0.25)  # < 0.30 threshold
    re_coking.step_rk4(dt=0.05)

    c3 = (
        re_coking.trip_active is True
        and re_coking.diagnostic_code == DIAG_ERR_CATALYST_COKING
        and re_coking.emergency_depressurize_active is True
        and re_coking.reactor_active is False
        and re_coking.h2_feed_valve is False
        and re_coking.reg_table.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is False
        and re_coking.reg_table.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False
        and re_coking.reg_table.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True
        and (re_coking.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF993
        and re_coking.reg_table.read_word(REG_PHA_H2_CATALYST_ACTIVITY) == 250
    )
    test_results.append({
        "stage": 3,
        "name": "catalyst_deactivation_and_coking_trip",
        "passed": bool(c3),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Catalyst deactivation/coking trip 0xF993 verified for a_cat < 30.0%; depressurization actuated.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: hydrogen_starvation_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_starv = PHAHydrogenationBDOEngine()
    re_starv.inject_hydrogen_starvation(ratio=1.2)  # < 2.0 minimum
    re_starv.step_rk4(dt=0.05)

    c4 = (
        re_starv.trip_active is True
        and re_starv.diagnostic_code == DIAG_ERR_HYDROGEN_STARVATION
        and re_starv.emergency_depressurize_active is True
        and re_starv.reg_table.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is False
        and re_starv.reg_table.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False
        and re_starv.reg_table.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True
        and (re_starv.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF994
    )
    test_results.append({
        "stage": 4,
        "name": "hydrogen_starvation_trip",
        "passed": bool(c4),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Hydrogen starvation trip 0xF994 verified for H2/Substrate ratio < stoichiometric minimum.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: thermal_runaway_safety_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # High temperature trip (T > 550 K)
    re_temp = PHAHydrogenationBDOEngine()
    re_temp.inject_thermal_runaway(temp_k=555.0)
    re_temp.step_rk4(dt=0.05)

    high_temp_trip_ok = (
        re_temp.trip_active is True
        and re_temp.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        and re_temp.emergency_depressurize_active is True
        and re_temp.reactor_active is False
        and re_temp.h2_feed_valve is False
        and re_temp.reg_table.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is False
        and re_temp.reg_table.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False
        and re_temp.reg_table.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True
        and (re_temp.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF991
    )

    # Fast rate-of-rise trip (dT/dt > 15 K/s)
    re_rate = PHAHydrogenationBDOEngine()
    re_rate.inject_temperature_rate_runaway(rate_k_s=18.5)
    re_rate.step_rk4(dt=0.05)

    high_rate_trip_ok = (
        re_rate.trip_active is True
        and re_rate.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
    )

    c5 = high_temp_trip_ok and high_rate_trip_ok
    test_results.append({
        "stage": 5,
        "name": "thermal_runaway_safety_trip",
        "passed": bool(c5),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Thermal runaway trip 0xF991 verified for both high temperature (> 550 K) and fast rise (> 15 K/s).",
    })

    # ------------------------------------------------------------------------
    # Stage 6: overpressure_rupture_safety_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_press = PHAHydrogenationBDOEngine()
    re_press.inject_overpressure(pressure_bar=84.5)  # Exceeds 80.0 bar threshold
    re_press.step_rk4(dt=0.05)

    c6 = (
        re_press.trip_active is True
        and re_press.diagnostic_code == DIAG_ERR_OVERPRESSURE_RUPTURE
        and re_press.emergency_depressurize_active is True
        and re_press.reactor_active is False
        and re_press.h2_feed_valve is False
        and re_press.reg_table.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is False
        and re_press.reg_table.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False
        and re_press.reg_table.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True
        and (re_press.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF992
    )
    test_results.append({
        "stage": 6,
        "name": "overpressure_rupture_safety_trip",
        "passed": bool(c6),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Overpressure rupture trip 0xF992 verified upon P > 80.0 bar; emergency depressurization actuated.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: priority_hierarchy_enforcement
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Thermal Runaway (P1: 0xF991) dominates Overpressure (P2: 0xF992)
    re_p1_p2 = PHAHydrogenationBDOEngine()
    re_p1_p2.state.t_bed_kelvin = 555.0
    re_p1_p2.state.p_reactor = 85.0
    re_p1_p2.step_rk4(dt=0.05)
    p1_dominates = re_p1_p2.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY

    # 2. Overpressure (P2: 0xF992) dominates Catalyst Coking (P3: 0xF993)
    re_p2_p3 = PHAHydrogenationBDOEngine()
    re_p2_p3.state.p_reactor = 85.0
    re_p2_p3.state.a_catalyst = 0.20
    re_p2_p3.step_rk4(dt=0.05)
    p2_dominates = re_p2_p3.diagnostic_code == DIAG_ERR_OVERPRESSURE_RUPTURE

    # 3. Catalyst Coking (P3: 0xF993) dominates Hydrogen Starvation (P4: 0xF994)
    re_p3_p4 = PHAHydrogenationBDOEngine()
    re_p3_p4.state.a_catalyst = 0.20
    re_p3_p4.inject_hydrogen_starvation(ratio=1.0)
    re_p3_p4.step_rk4(dt=0.05)
    p3_dominates = re_p3_p4.diagnostic_code == DIAG_ERR_CATALYST_COKING

    # 4. Hydrogen Starvation (P4: 0xF994) dominates Mass Divergence (P5: 0xF995)
    re_p4_p5 = PHAHydrogenationBDOEngine()
    re_p4_p5.inject_hydrogen_starvation(ratio=1.0)
    re_p4_p5.conservation_residual = 0.005
    re_p4_p5.step_rk4(dt=0.05)
    p4_dominates = re_p4_p5.diagnostic_code == DIAG_ERR_HYDROGEN_STARVATION

    c7 = p1_dominates and p2_dominates and p3_dominates and p4_dominates
    test_results.append({
        "stage": 7,
        "name": "priority_hierarchy_enforcement",
        "passed": bool(c7),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "5-tier fault priority hierarchy (0xF991 > 0xF992 > 0xF993 > 0xF994 > 0xF995) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: continuous_mass_conservation_and_divergence_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_cons = PHAHydrogenationBDOEngine()
    steps_s8 = 5 if quick else 15
    for _ in range(steps_s8):
        re_cons.step_rk4(dt=0.1)

    cons_ok = re_cons.conservation_residual < 1e-10

    # Divergence trip verification (residual > 1e-4)
    re_div = PHAHydrogenationBDOEngine()
    re_div.inject_mass_divergence(residual=0.005)
    re_div.step_rk4(dt=0.05)
    div_trip_ok = (
        re_div.trip_active is True
        and re_div.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        and (re_div.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF995
    )

    c8 = cons_ok and div_trip_ok
    test_results.append({
        "stage": 8,
        "name": "continuous_mass_conservation_and_divergence_trip",
        "passed": bool(c8),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Strict continuous carbon backbone mass conservation residual {re_cons.conservation_residual:.2e} < 1e-10; "
            f"Mass divergence trip 0xF995 latched upon residual > 1e-4."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 9: horner_ocs_registers_and_pure_st_pou
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_s9 = PHAHydrogenationBDOEngine()
    re_s9.scan_step(dt=0.1)
    rt = RegisterTable()
    re_s9.sync_to_registers(rt)

    w_temp = rt.read_word(REG_PHA_H2_REACTOR_TEMP)
    w_press = rt.read_word(REG_PHA_H2_REACTOR_PRESSURE)
    w_conv = rt.read_word(REG_PHA_H2_CONVERSION_EFFICIENCY)
    w_sel = rt.read_word(REG_PHA_H2_BDO_SELECTIVITY)
    w_lhsv = rt.read_word(REG_PHA_H2_SPACE_VELOCITY_LHSV)
    w_act = rt.read_word(REG_PHA_H2_CATALYST_ACTIVITY)
    w_flow = rt.read_word(REG_PHA_H2_HYDROGEN_FLOW_SLPM)
    w_diag = rt.read_word(REG_PHA_H2_DIAGNOSTIC_CODE)

    b_active = rt.read_bit(COIL_PHA_H2_REACTOR_ACTIVE)
    b_feed = rt.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE)
    b_depress = rt.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE)

    regs_ok = (
        w_temp > 0
        and w_press > 0
        and w_conv >= 0
        and w_sel >= 0
        and w_lhsv > 0
        and w_act > 0
        and w_flow > 0
        and (w_diag & 0xFFFF) == 0x0000
        and b_active is True
        and b_feed is True
        and b_depress is False
    )

    st_valid = verify_pha_hydrogenation_bdo_pure_st()

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
        "XIC %M648",
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
            "Horner OCS register space %R2780..%R2787, coils %M648..%M650, "
            "pure ST POU PHAHydrogenationBDOControl, and 9 ladder construct rejections verified."
        ),
    })

    # Summary
    passed_count = sum(1 for r in test_results if r["passed"])
    total_count = len(test_results)
    all_passed = passed_count == total_count

    pou_digest = hashlib.sha256(PHA_HYDROGENATION_BDO_PURE_ST_POU.encode("utf-8")).hexdigest()
    model_digest = hashlib.sha256(
        json.dumps(re_s9.cfg.to_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()

    evidence = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": (
            f"Work Package {work_package} Industrial PHA Hydrogenation & 1,4-BDO Verification "
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


run_pha_h2_bdo_verification = run_pha_hydrogenation_bdo_verification


# ============================================================================
# 7. CLI Entry Point
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution for PHA Hydrogenation & 1,4-BDO synthesis simulation and verification."""
    parser = argparse.ArgumentParser(
        description="W317: Industrial Catalytic Polyhydroxyalkanoate Hydrogenation & 1,4-Butanediol Precursor Fixed-Bed ODE Simulation"
    )
    parser.add_argument("--verify", action="store_true", help="Run 9-stage verification suite")
    parser.add_argument("--output", "-o", type=str, default=None, help="Evidence JSON output file path")
    parser.add_argument("--quick", action="store_true", help="Execute rapid test subset")
    parser.add_argument("--work-package", type=str, default="W317", help="Work package identifier")
    parser.add_argument("--json", action="store_true", help="Print verification result as JSON")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet output")

    args = parser.parse_args(argv)

    if args.verify or args.output or args.json or args.quick:
        res = run_pha_hydrogenation_bdo_verification(
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
    engine = PHAHydrogenationBDOEngine()
    for cycle in range(1, 11):
        res = engine.scan_step(dt=0.1)
        print(f"Cycle {cycle:02d}: {res.details}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
