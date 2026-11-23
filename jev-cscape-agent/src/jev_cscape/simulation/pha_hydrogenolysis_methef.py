"""Industrial Catalytic Polyhydroxyalkanoate Hydrogenolysis & 2-Methyltetrahydrofuran (2-MeTHF) Synthesis CSTR ODE Simulation.

Work Package: W326 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [CSTR Catalytic PHA Hydrogenolysis & 2-MeTHF Synthesis]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Features:
1. Industrial Catalytic PHA Hydrogenolysis & 2-Methyltetrahydrofuran (2-MeTHF) Synthesis:
   - Continuous Stirred-Tank Reactor (CSTR) converting bio-derived levulinate / methylsuccinate
     ester precursor into 2-methyltetrahydrofuran (2-MeTHF) green solvent with water coproduct
     and competitive consecutive/parallel byproduct 1,4-pentanediol:
     Step 1 (Main Hydrogenation): Precursor + H2  ===>  2-Methyltetrahydrofuran (2-MeTHF) + H2O
     Step 2 (Competitive Byproduct): Precursor + H2  ===>  1,4-Pentanediol (+ H2O)
   - Solid supported catalytic hydrogenation kinetics with multi-component adsorption
     competition (Langmuir-Hinshelwood) and thermal catalyst sintering/deactivation:
     * Step 1 rate: r1 = (k1 * a_cat * C_prec) / (1 + K_prec*C_prec + K_meth*C_meth + K_pent*C_pent + K_w*C_w)^2
     * Step 2 rate: r2 = (k2 * a_cat * C_prec) / (1 + K_prec*C_prec + K_meth*C_meth + K_pent*C_pent + K_w*C_w)^2
     * Catalyst sintering: da_cat/dt = - kd * a_cat * exp(-Ed / (R*T)) * (T / T_ref)
2. Coupled 6-State Continuous CSTR ODE Vector:
   - State variables:
     1. C_precursor_feed: Precursor ester concentration (mol/L)
     2. C_methef_product: 2-Methyltetrahydrofuran product concentration (mol/L)
     3. C_pentanediol_byproduct: 1,4-Pentanediol byproduct concentration (mol/L)
     4. C_water_coproduct: Coproduct water concentration (mol/L)
     5. T_reactor_kelvin: CSTR reaction mixture temperature (K)
     6. a_catalyst: Catalyst relative activity (fraction 0..1)
   - 4th-Order Runge-Kutta (RK4) numerical integrator step_rk4(dt).
   - Strict continuous carbon backbone mass conservation (residuals < 1e-10).
3. Process Safety Interlocks & Diagnostics (Strict 5-Tier Priority Hierarchy):
   - Priority 1: 0xF9C1 DIAG_ERR_THERMAL_RUNAWAY (T > 530 K or dT/dt > 12.0 K/s)
   - Priority 2: 0xF9C2 DIAG_ERR_OVERPRESSURE_QUENCH (P > 50.0 bar)
   - Priority 3: 0xF9C3 DIAG_ERR_CATALYST_SINTERING (Activity < 35.0%)
   - Priority 4: 0xF9C4 DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE (Byproduct yield > 25.0%)
   - Priority 5: 0xF9C5 DIAG_ERR_MASS_BALANCE_DIVERGENCE (residual > 1e-4)
4. Horner OCS Memory Space Integration:
   - Word registers %R2870..%R2877:
     %R2870: REG_PHA_METH_REACTOR_TEMP (0.1 °C, signed 16-bit)
     %R2871: REG_PHA_METH_REACTOR_PRESSURE (0.01 bar, 0..10000)
     %R2872: REG_PHA_METH_PRECURSOR_CONVERSION (0.1 %, 0..1000)
     %R2873: REG_PHA_METH_SELECTIVITY_PERCENT (0.1 %, 0..1000)
     %R2874: REG_PHA_METH_FEED_FLOW_RATE (0.1 L/min)
     %R2875: REG_PHA_METH_CATALYST_ACTIVITY (0.1 %, 0..1000)
     %R2876: REG_PHA_METH_COOLING_DUTY_KW (0.1 kW)
     %R2877: REG_PHA_METH_DIAGNOSTIC_CODE (0x0000=OK, 0xF9C1..0xF9C5)
   - Discrete coils %M669..%M671:
     %M669: COIL_PHA_METH_REACTOR_ACTIVE (BOOL)
     %M670: COIL_PHA_METH_FEED_PUMP (BOOL)
     %M671: COIL_PHA_METH_EMERGENCY_QUENCH (BOOL)
5. Pure IEC 61131-3 Structured Text (ST) POU:
   - POU 'PHAHydrogenolysisMethefControl' with anti-ladder validation rejecting 9 ladder constructs.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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

MW_PRECURSOR: float       = 130.14    # Levulinate/methylsuccinate ester precursor C6H10O3 (g/mol)
MW_METHEF: float          = 86.13     # 2-Methyltetrahydrofuran (2-MeTHF) C5H10O (g/mol)
MW_PENTANEDIOL: float     = 104.15    # 1,4-Pentanediol byproduct C5H12O2 (g/mol)
MW_WATER: float           = 18.015    # Water H2O (g/mol)
MW_HYDROGEN: float        = 2.016     # Hydrogen H2 (g/mol)
MW_CARBON: float          = 12.011    # Carbon atomic weight (g/mol)

MW_METH_EF: float         = MW_METHEF
MW_2_METHYL_THF: float    = MW_METHEF
MW_2METHEF: float         = MW_METHEF
MW_LEVULINATE: float      = MW_PRECURSOR
MW_BYPRODUCT: float       = MW_PENTANEDIOL

R_GAS_CONSTANT: float     = 8.314462618  # Universal gas constant [J/(mol*K)]
T_ZERO_CELSIUS: float     = 273.15       # 0.0 °C in Kelvin [K]


# ============================================================================
# 2. Horner OCS Memory Space Integration & Diagnostic Codes
# ============================================================================

# Word Registers %R2870..%R2877
REG_PHA_METH_REACTOR_TEMP: str           = "%R2870"  # 0.1 °C, signed 16-bit
REG_PHA_METH_REACTOR_PRESSURE: str       = "%R2871"  # 0.01 bar, 0..10000
REG_PHA_METH_PRECURSOR_CONVERSION: str   = "%R2872"  # 0.1 %, 0..1000
REG_PHA_METH_SELECTIVITY_PERCENT: str    = "%R2873"  # 0.1 %, 0..1000
REG_PHA_METH_FEED_FLOW_RATE: str         = "%R2874"  # 0.1 L/min
REG_PHA_METH_CATALYST_ACTIVITY: str      = "%R2875"  # 0.1 %, 0..1000
REG_PHA_METH_COOLING_DUTY_KW: str        = "%R2876"  # 0.1 kW
REG_PHA_METH_DIAGNOSTIC_CODE: str        = "%R2877"  # 16-bit diagnostic code

# Register Aliases
REG_PHA_METH_TEMP: str                   = REG_PHA_METH_REACTOR_TEMP
REG_PHA_METH_T_REACTOR: str              = REG_PHA_METH_REACTOR_TEMP
REG_PHA_METH_REACTOR_TEMPERATURE: str    = REG_PHA_METH_REACTOR_TEMP
REG_PHA_METH_PRESSURE: str               = REG_PHA_METH_REACTOR_PRESSURE
REG_PHA_METH_P_REACTOR: str              = REG_PHA_METH_REACTOR_PRESSURE
REG_PHA_METH_CONVERSION: str             = REG_PHA_METH_PRECURSOR_CONVERSION
REG_PHA_METH_CONV: str                   = REG_PHA_METH_PRECURSOR_CONVERSION
REG_PHA_METH_SELECTIVITY: str            = REG_PHA_METH_SELECTIVITY_PERCENT
REG_PHA_METH_SEL: str                    = REG_PHA_METH_SELECTIVITY_PERCENT
REG_PHA_METH_FLOW: str                   = REG_PHA_METH_FEED_FLOW_RATE
REG_PHA_METH_FEED_FLOW: str              = REG_PHA_METH_FEED_FLOW_RATE
REG_PHA_METH_ACTIVITY: str               = REG_PHA_METH_CATALYST_ACTIVITY
REG_PHA_METH_CATALYST: str               = REG_PHA_METH_CATALYST_ACTIVITY
REG_PHA_METH_COOLING: str                = REG_PHA_METH_COOLING_DUTY_KW
REG_PHA_METH_DUTY: str                   = REG_PHA_METH_COOLING_DUTY_KW
REG_PHA_METH_DIAG: str                   = REG_PHA_METH_DIAGNOSTIC_CODE

# Discrete Coils %M669..%M671
COIL_PHA_METH_REACTOR_ACTIVE: str        = "%M669"   # BOOL
COIL_PHA_METH_FEED_PUMP: str             = "%M670"   # BOOL
COIL_PHA_METH_EMERGENCY_QUENCH: str      = "%M671"   # BOOL

# Coil Aliases
COIL_PHA_METH_ACTIVE: str                = COIL_PHA_METH_REACTOR_ACTIVE
COIL_PHA_METH_RUNNING: str               = COIL_PHA_METH_REACTOR_ACTIVE
COIL_PHA_METH_PUMP: str                  = COIL_PHA_METH_FEED_PUMP
COIL_PHA_METH_FEED: str                  = COIL_PHA_METH_FEED_PUMP
COIL_PHA_METH_QUENCH: str                = COIL_PHA_METH_EMERGENCY_QUENCH
COIL_PHA_METH_EMERGENCY: str             = COIL_PHA_METH_EMERGENCY_QUENCH


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


# 16-bit Trip Diagnostic Constants (Strict 5-Tier Priority Hierarchy)
DIAG_OK: DiagnosticCode                                = DiagnosticCode(0x0000)
DIAG_ERR_THERMAL_RUNAWAY: DiagnosticCode               = DiagnosticCode(0xF9C1)  # Priority 1: T > 530 K or dT/dt > 12.0 K/s
DIAG_ERR_OVERPRESSURE_QUENCH: DiagnosticCode           = DiagnosticCode(0xF9C2)  # Priority 2: P > 50.0 bar
DIAG_ERR_CATALYST_SINTERING: DiagnosticCode            = DiagnosticCode(0xF9C3)  # Priority 3: Activity < 35.0%
DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE: DiagnosticCode   = DiagnosticCode(0xF9C4)  # Priority 4: Byproduct yield > 25.0%
DIAG_ERR_MASS_BALANCE_DIVERGENCE: DiagnosticCode       = DiagnosticCode(0xF9C5)  # Priority 5: residual > 1e-4

# Diagnostic Aliases
DIAG_ERR_RUNAWAY: DiagnosticCode                       = DIAG_ERR_THERMAL_RUNAWAY
DIAG_ERR_THERMAL: DiagnosticCode                       = DIAG_ERR_THERMAL_RUNAWAY
DIAG_ERR_OVERHEAT: DiagnosticCode                      = DIAG_ERR_THERMAL_RUNAWAY
DIAG_ERR_OVERPRESSURE: DiagnosticCode                  = DIAG_ERR_OVERPRESSURE_QUENCH
DIAG_ERR_PRESSURE: DiagnosticCode                      = DIAG_ERR_OVERPRESSURE_QUENCH
DIAG_ERR_QUENCH: DiagnosticCode                        = DIAG_ERR_OVERPRESSURE_QUENCH
DIAG_ERR_SINTERING: DiagnosticCode                     = DIAG_ERR_CATALYST_SINTERING
DIAG_ERR_CATALYST: DiagnosticCode                      = DIAG_ERR_CATALYST_SINTERING
DIAG_ERR_DEACTIVATION: DiagnosticCode                  = DIAG_ERR_CATALYST_SINTERING
DIAG_ERR_BYPRODUCT_SPIKE: DiagnosticCode               = DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE
DIAG_ERR_PENTANEDIOL_SPIKE: DiagnosticCode             = DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE
DIAG_ERR_BYPRODUCT: DiagnosticCode                     = DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE
DIAG_ERR_MASS_DIVERGENCE: DiagnosticCode               = DIAG_ERR_MASS_BALANCE_DIVERGENCE
DIAG_ERR_MASS_BALANCE: DiagnosticCode                  = DIAG_ERR_MASS_BALANCE_DIVERGENCE

PHAHydrogenolysisMethefDiagnosticCode = DiagnosticCode
PhaHydrogenolysisMethefDiagnosticCode = DiagnosticCode
PHAMethefDiagnosticCode = DiagnosticCode
PhaMethefDiagnosticCode = DiagnosticCode


class PHAHydrogenolysisMethefStatusWord(IntFlag):
    """Bitmask for CSTR Catalytic Hydrogenolysis & 2-MeTHF Synthesis operational status."""
    REACTOR_ACTIVE        = 1 << 0  # Bit 0: CSTR reactor active (%M669)
    FEED_PUMP             = 1 << 1  # Bit 1: Precursor feed pump running (%M670)
    EMERGENCY_QUENCH      = 1 << 2  # Bit 2: Emergency quench active (%M671)
    COOLING_ACTIVE        = 1 << 3  # Bit 3: Cooling duty active
    TEMP_WARN             = 1 << 4  # Bit 4: Reactor temperature pre-alarm
    PRESSURE_WARN         = 1 << 5  # Bit 5: Reactor pressure pre-alarm
    CATALYST_WARN         = 1 << 6  # Bit 6: Catalyst sintering degradation pre-alarm
    EMERGENCY_TRIP        = 1 << 7  # Bit 7: Master safety trip latched


PhaHydrogenolysisMethefStatusWord = PHAHydrogenolysisMethefStatusWord
PHAMethefStatusWord = PHAHydrogenolysisMethefStatusWord
PhaMethefStatusWord = PHAHydrogenolysisMethefStatusWord
PHAHydrogenolysisMethefStatusBits = PHAHydrogenolysisMethefStatusWord
PhaHydrogenolysisMethefStatusBits = PHAHydrogenolysisMethefStatusWord
PHAMethefStatusBits = PHAHydrogenolysisMethefStatusWord
PhaMethefStatusBits = PHAHydrogenolysisMethefStatusWord


# ============================================================================
# 3. State & Configuration Models
# ============================================================================

@dataclass
class PHAHydrogenolysisMethefState:
    """Coupled 6-State Continuous CSTR ODE Vector for PHA Hydrogenolysis & 2-MeTHF Synthesis."""
    c_precursor_feed: float = 3.80             # mol/L: Levulinate/methylsuccinate ester precursor concentration
    c_methef_product: float = 0.15             # mol/L: 2-Methyltetrahydrofuran product concentration
    c_pentanediol_byproduct: float = 0.05      # mol/L: 1,4-Pentanediol byproduct concentration
    c_water_coproduct: float = 0.20            # mol/L: Coproduct water concentration
    t_reactor_kelvin: float = 463.15           # K: CSTR reaction zone temperature (~190.0 °C)
    a_catalyst: float = 1.00                   # fraction 0..1: Catalyst relative activity (1.0 = 100%)
    p_reactor: float = 25.0                    # bar: Operating pressure
    feed_flow_rate_l_min: float = 60.0         # L/min: Precursor feed flow rate
    cooling_duty_kw: float = 45.0              # kW: Reactor cooling duty
    dt_reactor_dt: float = 0.0                 # K/s: Temperature rate of change

    def to_dict(self) -> Dict[str, float]:
        return {
            "c_precursor_feed": self.c_precursor_feed,
            "c_methef_product": self.c_methef_product,
            "c_pentanediol_byproduct": self.c_pentanediol_byproduct,
            "c_water_coproduct": self.c_water_coproduct,
            "t_reactor_kelvin": self.t_reactor_kelvin,
            "a_catalyst": self.a_catalyst,
            "p_reactor": self.p_reactor,
            "feed_flow_rate_l_min": self.feed_flow_rate_l_min,
            "cooling_duty_kw": self.cooling_duty_kw,
            "dt_reactor_dt": self.dt_reactor_dt,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PHAHydrogenolysisMethefState:
        c_prec = float(data.get("c_precursor_feed", data.get("C_precursor_feed", data.get("precursor_feed", 3.80))))
        c_meth = float(data.get("c_methef_product", data.get("C_methef_product", data.get("methef", 0.15))))
        c_pent = float(data.get("c_pentanediol_byproduct", data.get("C_pentanediol_byproduct", data.get("pentanediol", 0.05))))
        c_w = float(data.get("c_water_coproduct", data.get("C_water_coproduct", data.get("water", 0.20))))
        t_rxn = float(data.get("t_reactor_kelvin", data.get("T_reactor_kelvin", data.get("temp_k", 463.15))))
        a_cat = float(data.get("a_catalyst", data.get("a_cat", 1.00)))
        p_rxn = float(data.get("p_reactor", data.get("P_reactor", data.get("pressure_bar", 25.0))))
        flow = float(data.get("feed_flow_rate_l_min", data.get("feed_flow_rate", 60.0)))
        duty = float(data.get("cooling_duty_kw", data.get("cooling_duty", 45.0)))
        dt_dt = float(data.get("dt_reactor_dt", data.get("dT_reactor_dt", 0.0)))
        return cls(
            c_precursor_feed=c_prec,
            c_methef_product=c_meth,
            c_pentanediol_byproduct=c_pent,
            c_water_coproduct=c_w,
            t_reactor_kelvin=t_rxn,
            a_catalyst=a_cat,
            p_reactor=p_rxn,
            feed_flow_rate_l_min=flow,
            cooling_duty_kw=duty,
            dt_reactor_dt=dt_dt,
        )

    # Distinct property aliases
    @property
    def C_precursor_feed(self) -> float:
        return self.c_precursor_feed

    @C_precursor_feed.setter
    def C_precursor_feed(self, val: float) -> None:
        self.c_precursor_feed = float(val)

    @property
    def precursor_feed(self) -> float:
        return self.c_precursor_feed

    @precursor_feed.setter
    def precursor_feed(self, val: float) -> None:
        self.c_precursor_feed = float(val)

    @property
    def c_precursor(self) -> float:
        return self.c_precursor_feed

    @c_precursor.setter
    def c_precursor(self, val: float) -> None:
        self.c_precursor_feed = float(val)

    @property
    def C_precursor(self) -> float:
        return self.c_precursor_feed

    @C_precursor.setter
    def C_precursor(self, val: float) -> None:
        self.c_precursor_feed = float(val)

    @property
    def C_methef_product(self) -> float:
        return self.c_methef_product

    @C_methef_product.setter
    def C_methef_product(self, val: float) -> None:
        self.c_methef_product = float(val)

    @property
    def methef_product(self) -> float:
        return self.c_methef_product

    @methef_product.setter
    def methef_product(self, val: float) -> None:
        self.c_methef_product = float(val)

    @property
    def c_methef(self) -> float:
        return self.c_methef_product

    @c_methef.setter
    def c_methef(self, val: float) -> None:
        self.c_methef_product = float(val)

    @property
    def C_methef(self) -> float:
        return self.c_methef_product

    @C_methef.setter
    def C_methef(self, val: float) -> None:
        self.c_methef_product = float(val)

    @property
    def c_meth_ef(self) -> float:
        return self.c_methef_product

    @c_meth_ef.setter
    def c_meth_ef(self, val: float) -> None:
        self.c_methef_product = float(val)

    @property
    def C_meth_ef(self) -> float:
        return self.c_methef_product

    @C_meth_ef.setter
    def C_meth_ef(self, val: float) -> None:
        self.c_methef_product = float(val)

    @property
    def C_pentanediol_byproduct(self) -> float:
        return self.c_pentanediol_byproduct

    @C_pentanediol_byproduct.setter
    def C_pentanediol_byproduct(self, val: float) -> None:
        self.c_pentanediol_byproduct = float(val)

    @property
    def pentanediol_byproduct(self) -> float:
        return self.c_pentanediol_byproduct

    @pentanediol_byproduct.setter
    def pentanediol_byproduct(self, val: float) -> None:
        self.c_pentanediol_byproduct = float(val)

    @property
    def c_pentanediol(self) -> float:
        return self.c_pentanediol_byproduct

    @c_pentanediol.setter
    def c_pentanediol(self, val: float) -> None:
        self.c_pentanediol_byproduct = float(val)

    @property
    def C_pentanediol(self) -> float:
        return self.c_pentanediol_byproduct

    @C_pentanediol.setter
    def C_pentanediol(self, val: float) -> None:
        self.c_pentanediol_byproduct = float(val)

    @property
    def c_byproduct(self) -> float:
        return self.c_pentanediol_byproduct

    @c_byproduct.setter
    def c_byproduct(self, val: float) -> None:
        self.c_pentanediol_byproduct = float(val)

    @property
    def C_byproduct(self) -> float:
        return self.c_pentanediol_byproduct

    @C_byproduct.setter
    def C_byproduct(self, val: float) -> None:
        self.c_pentanediol_byproduct = float(val)

    @property
    def C_water_coproduct(self) -> float:
        return self.c_water_coproduct

    @C_water_coproduct.setter
    def C_water_coproduct(self, val: float) -> None:
        self.c_water_coproduct = float(val)

    @property
    def water_coproduct(self) -> float:
        return self.c_water_coproduct

    @water_coproduct.setter
    def water_coproduct(self, val: float) -> None:
        self.c_water_coproduct = float(val)

    @property
    def c_water(self) -> float:
        return self.c_water_coproduct

    @c_water.setter
    def c_water(self, val: float) -> None:
        self.c_water_coproduct = float(val)

    @property
    def C_water(self) -> float:
        return self.c_water_coproduct

    @C_water.setter
    def C_water(self, val: float) -> None:
        self.c_water_coproduct = float(val)

    @property
    def c_h2o(self) -> float:
        return self.c_water_coproduct

    @c_h2o.setter
    def c_h2o(self, val: float) -> None:
        self.c_water_coproduct = float(val)

    @property
    def T_reactor_kelvin(self) -> float:
        return self.t_reactor_kelvin

    @T_reactor_kelvin.setter
    def T_reactor_kelvin(self, val: float) -> None:
        self.t_reactor_kelvin = float(val)

    @property
    def T_reactor(self) -> float:
        return self.t_reactor_kelvin

    @T_reactor.setter
    def T_reactor(self, val: float) -> None:
        self.t_reactor_kelvin = float(val)

    @property
    def t_reactor(self) -> float:
        return self.t_reactor_kelvin

    @t_reactor.setter
    def t_reactor(self, val: float) -> None:
        self.t_reactor_kelvin = float(val)

    @property
    def reactor_temp(self) -> float:
        return self.t_reactor_kelvin

    @reactor_temp.setter
    def reactor_temp(self, val: float) -> None:
        self.t_reactor_kelvin = float(val)

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
    def feed_flow(self) -> float:
        return self.feed_flow_rate_l_min

    @feed_flow.setter
    def feed_flow(self, val: float) -> None:
        self.feed_flow_rate_l_min = float(val)

    @property
    def feed_flow_rate(self) -> float:
        return self.feed_flow_rate_l_min

    @feed_flow_rate.setter
    def feed_flow_rate(self, val: float) -> None:
        self.feed_flow_rate_l_min = float(val)

    @property
    def cooling_duty(self) -> float:
        return self.cooling_duty_kw

    @cooling_duty.setter
    def cooling_duty(self, val: float) -> None:
        self.cooling_duty_kw = float(val)

    @property
    def duty_kw(self) -> float:
        return self.cooling_duty_kw

    @duty_kw.setter
    def duty_kw(self, val: float) -> None:
        self.cooling_duty_kw = float(val)

    @property
    def dT_reactor_dt(self) -> float:
        return self.dt_reactor_dt

    @dT_reactor_dt.setter
    def dT_reactor_dt(self, val: float) -> None:
        self.dt_reactor_dt = float(val)


PhaHydrogenolysisMethefState = PHAHydrogenolysisMethefState
PHAMethefState = PHAHydrogenolysisMethefState
PhaMethefState = PHAHydrogenolysisMethefState
PHAHydrogenolysisMethefStateModel = PHAHydrogenolysisMethefState
PhaHydrogenolysisMethefStateModel = PHAHydrogenolysisMethefState


@dataclass
class PHAHydrogenolysisMethefConfig:
    """Kinetic, thermodynamic, hydrodynamic, and safety parameters for PHA Hydrogenolysis & 2-MeTHF Reactor.

    NOTE: Duplicate typed fields and @property setters are strictly avoided.
    """
    # Catalytic hydrogenation kinetics for Step 1: Precursor -> 2-MeTHF + H2O
    k1_forward: float = 6.8e4             # Pre-exponential factor step 1 [L/(mol*s)]
    ea1_j_mol: float = 58000.0            # Activation energy step 1 [J/mol] (58.0 kJ/mol)

    # Catalytic competitive hydrogenation kinetics for Step 2: Precursor -> 1,4-Pentanediol
    k2_forward: float = 2.1e4             # Pre-exponential factor step 2 [L/(mol*s)]
    ea2_j_mol: float = 64000.0            # Activation energy step 2 [J/mol] (64.0 kJ/mol)

    # Catalyst sintering / thermal deactivation kinetics:
    k_sinter: float = 2.5e-5              # Catalyst sintering rate factor [1/s]
    ea_sinter_j_mol: float = 46000.0      # Sintering activation energy [J/mol]

    # Langmuir adsorption equilibrium constants [L/mol]
    k_adsorb_precursor: float = 0.40      # Adsorption constant for precursor ester
    k_adsorb_methef: float = 0.25         # Adsorption constant for 2-MeTHF product
    k_adsorb_pentanediol: float = 0.20    # Adsorption constant for pentanediol byproduct
    k_adsorb_water: float = 0.15          # Adsorption constant for water coproduct

    # Reaction enthalpies [J/mol] (Exothermic catalytic hydrogenation)
    delta_h_rxn1_j_mol: float = -52000.0  # Enthalpy step 1 (Precursor -> 2-MeTHF + H2O) [J/mol]
    delta_h_rxn2_j_mol: float = -42000.0  # Enthalpy step 2 (Precursor -> Pentanediol) [J/mol]

    # CSTR geometry & physical properties
    v_reactor_m3: float = 0.50            # CSTR reaction volume [m³] (500 L)
    rho_liquid: float = 980.0             # Reaction mixture bulk density [kg/m³]
    cp_liquid: float = 2200.0             # Reaction mixture heat capacity [J/(kg*K)]
    nominal_flow_l_min: float = 60.0      # Nominal feed flow rate [L/min]
    nominal_pressure_bar: float = 25.0    # Operating pressure [bar]
    nominal_cooling_duty_kw: float = 45.0 # Nominal cooling duty [kW]

    # Thermal balances & heat exchange
    ua_jacket: float = 450.0              # Jacket heat transfer coefficient [W/K]
    t_coolant_nominal: float = 353.15     # Nominal coolant temperature [K] (80.0 °C)
    t_feed: float = 373.15                # Feed inlet preheat temperature [K] (100.0 °C)
    ua_loss: float = 35.0                 # Ambient heat loss coefficient [W/K]
    t_ambient: float = 298.15             # Ambient environmental temperature [K]

    # Safety Interlock Thresholds (Strict 5-Tier Priority Hierarchy):
    t_reactor_trip_max: float = 530.0     # Priority 1: Thermal runaway max temperature [K] (0xF9C1)
    dt_reactor_dt_trip_max: float = 12.0  # Priority 1: Temperature rate-of-rise max [K/s] (0xF9C1)
    p_reactor_trip_max: float = 50.0      # Priority 2: Overpressure quench threshold [bar] (0xF9C2)
    catalyst_activity_min: float = 0.35   # Priority 3: Catalyst sintering minimum activity [-] (0xF9C3)
    byproduct_yield_max_pct: float = 25.0 # Priority 4: Max pentanediol yield [%] (0xF9C4)
    mass_residual_max: float = 1e-4       # Priority 5: Mass conservation residual trip [-] (0xF9C5)

    # Emergency quench parameters
    k_quench_depressurize: float = 0.50   # Quench depressurization rate [1/s]
    ua_emergency_quench: float = 60000.0  # Emergency quench heat transfer [W/K]
    t_quench_fluid: float = 288.15        # Quench fluid supply temperature [K] (15.0 °C)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "k1_forward": self.k1_forward,
            "ea1_j_mol": self.ea1_j_mol,
            "k2_forward": self.k2_forward,
            "ea2_j_mol": self.ea2_j_mol,
            "k_sinter": self.k_sinter,
            "ea_sinter_j_mol": self.ea_sinter_j_mol,
            "delta_h_rxn1_j_mol": self.delta_h_rxn1_j_mol,
            "delta_h_rxn2_j_mol": self.delta_h_rxn2_j_mol,
            "v_reactor_m3": self.v_reactor_m3,
            "nominal_flow_l_min": self.nominal_flow_l_min,
            "nominal_pressure_bar": self.nominal_pressure_bar,
            "t_reactor_trip_max": self.t_reactor_trip_max,
            "dt_reactor_dt_trip_max": self.dt_reactor_dt_trip_max,
            "p_reactor_trip_max": self.p_reactor_trip_max,
            "catalyst_activity_min": self.catalyst_activity_min,
            "byproduct_yield_max_pct": self.byproduct_yield_max_pct,
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


PhaHydrogenolysisMethefConfig = PHAHydrogenolysisMethefConfig
PHAMethefConfig = PHAHydrogenolysisMethefConfig
PhaMethefConfig = PHAHydrogenolysisMethefConfig
PHAHydrogenolysisMethefParameters = PHAHydrogenolysisMethefConfig
PhaHydrogenolysisMethefParameters = PHAHydrogenolysisMethefConfig


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text POU
# ============================================================================

ST_PROGRAM_PHA_HYDROGENOLYSIS_METHEF_CONTROL = """
PROGRAM PHAHydrogenolysisMethefControl
VAR
    rReactorTemp AT %R2870 : INT;
    rReactorPressure AT %R2871 : WORD;
    rPrecursorConversion AT %R2872 : WORD;
    rSelectivityPercent AT %R2873 : WORD;
    rFeedFlowRate AT %R2874 : WORD;
    rCatalystActivity AT %R2875 : WORD;
    rCoolingDutyKW AT %R2876 : WORD;
    wDiagnosticCode AT %R2877 : WORD;
    bReactorActive AT %M669 : BOOL;
    bFeedPump AT %M670 : BOOL;
    bEmergencyQuench AT %M671 : BOOL;
END_VAR

IF wDiagnosticCode = 0 THEN
    bReactorActive := TRUE;
    bFeedPump := TRUE;
    bEmergencyQuench := FALSE;
ELSE
    bReactorActive := FALSE;
    bFeedPump := FALSE;
    bEmergencyQuench := TRUE;
END_IF;
END_PROGRAM
""".strip()

PHA_HYDROGENOLYSIS_METHEF_PURE_ST_POU: str = ST_PROGRAM_PHA_HYDROGENOLYSIS_METHEF_CONTROL
PHA_METHEF_PURE_ST_POU: str = ST_PROGRAM_PHA_HYDROGENOLYSIS_METHEF_CONTROL
PHAHydrogenolysisMethefControl: str = ST_PROGRAM_PHA_HYDROGENOLYSIS_METHEF_CONTROL
PHA_HYDROGENOLYSIS_METHEF_CONTROL_POU: str = ST_PROGRAM_PHA_HYDROGENOLYSIS_METHEF_CONTROL
PHA_METHEF_CONTROL_POU: str = ST_PROGRAM_PHA_HYDROGENOLYSIS_METHEF_CONTROL


def verify_pha_hydrogenolysis_methef_pure_st() -> bool:
    """Validate pure ST syntax and ensure strict rejection of ladder logic constructs."""
    try:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_PHA_HYDROGENOLYSIS_METHEF_CONTROL)
    except LadderForbiddenError:
        return False
    val = STParser.validate_code(ST_PROGRAM_PHA_HYDROGENOLYSIS_METHEF_CONTROL)
    return val.status == AgentStatus.SUCCESS


verify_pha_methef_pure_st = verify_pha_hydrogenolysis_methef_pure_st


# ============================================================================
# 5. Simulation CSTR Engine (ILogicUnit)
# ============================================================================

class PHAHydrogenolysisMethefEngine(ILogicUnit):
    """Industrial Catalytic PHA Hydrogenolysis & 2-MeTHF Synthesis CSTR ODE Simulator."""

    def __init__(
        self,
        config: Optional[PHAHydrogenolysisMethefConfig] = None,
        state: Optional[PHAHydrogenolysisMethefState] = None,
        reg_table: Optional[RegisterTable] = None,
        register_table: Optional[RegisterTable] = None,
        **kwargs: Any,
    ) -> None:
        self.cfg = config or PHAHydrogenolysisMethefConfig()
        self.state = state or PHAHydrogenolysisMethefState()
        self.reg_table = register_table or reg_table or RegisterTable()

        # Operational status flags
        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.trip_active: bool = False
        self.reactor_active: bool = True
        self.feed_pump: bool = True
        self.emergency_quench_active: bool = False

        # Heat exchange & fault injection operational state
        self.t_coolant: float = self.cfg.t_coolant_nominal
        self._byproduct_spike_injected: bool = False

        # Conservation and telemetry tracking
        self.cycle_count: int = 0
        self.conservation_residual: float = 0.0
        self.last_dt_reactor_dt: float = 0.0

        # Baseline inventory for conversion, yield, and C5 carbon backbone conservation
        self._initial_c_precursor: float = max(1e-6, self.state.c_precursor_feed)
        self._initial_c_methef: float = self.state.c_methef_product
        self._initial_c_pentanediol: float = self.state.c_pentanediol_byproduct
        self._initial_c5: float = (
            self.state.c_precursor_feed
            + self.state.c_methef_product
            + self.state.c_pentanediol_byproduct
        )

        # Initial register synchronization
        self.sync_to_registers(self.reg_table)

    @property
    def unit_id(self) -> str:
        return "PHA_METHEF_CSTR_W326"

    @property
    def name(self) -> str:
        return "PHAHydrogenolysisMethefEngine"

    @property
    def priority(self) -> int:
        return 50

    @property
    def is_enabled(self) -> bool:
        return True

    @property
    def precursor_conversion_pct(self) -> float:
        """Precursor ester conversion efficiency [%]."""
        if self._initial_c_precursor < 1e-6:
            return 0.0
        c_conv = max(0.0, self._initial_c_precursor - self.state.c_precursor_feed)
        return max(0.0, min(100.0, (c_conv / self._initial_c_precursor) * 100.0))

    @property
    def conversion_pct(self) -> float:
        """Alias for precursor conversion efficiency [%]."""
        return self.precursor_conversion_pct

    @property
    def methef_selectivity_pct(self) -> float:
        """2-Methyltetrahydrofuran (2-MeTHF) selectivity relative to converted precursor [%]."""
        c_conv = max(0.0, self._initial_c_precursor - self.state.c_precursor_feed)
        if c_conv > 1e-4:
            c_prod = max(0.0, self.state.c_methef_product - self._initial_c_methef)
            sel = (c_prod / c_conv) * 100.0
            return max(0.0, min(100.0, sel))
        tot_prod = (
            max(0.0, self.state.c_methef_product - self._initial_c_methef)
            + max(0.0, self.state.c_pentanediol_byproduct - self._initial_c_pentanediol)
        )
        if tot_prod < 1e-6:
            # Baseline selectivity based on current concentrations
            tot_c = self.state.c_methef_product + self.state.c_pentanediol_byproduct
            if tot_c < 1e-6:
                return 85.0
            return max(0.0, min(100.0, (self.state.c_methef_product / tot_c) * 100.0))
        sel = (max(0.0, self.state.c_methef_product - self._initial_c_methef) / tot_prod) * 100.0
        return max(0.0, min(100.0, sel))

    @property
    def selectivity_pct(self) -> float:
        """Alias for 2-MeTHF selectivity [%]."""
        return self.methef_selectivity_pct

    @property
    def pentanediol_byproduct_yield_pct(self) -> float:
        """1,4-Pentanediol byproduct yield relative to initial precursor [%]."""
        if self._initial_c_precursor < 1e-6:
            return 0.0
        c_byprod = max(0.0, self.state.c_pentanediol_byproduct - self._initial_c_pentanediol)
        return max(0.0, min(100.0, (c_byprod / self._initial_c_precursor) * 100.0))

    @property
    def byproduct_yield_pct(self) -> float:
        """Alias for pentanediol byproduct yield [%]."""
        return self.pentanediol_byproduct_yield_pct

    def compute_rates(
        self, s: PHAHydrogenolysisMethefState
    ) -> Tuple[float, float]:
        """Compute competitive catalytic hydrogenation reaction rates [mol/(L*s)].

        Returns:
            (r1, r2): Step 1 (Precursor -> 2-MeTHF) and Step 2 (Precursor -> Pentanediol) rates.
        """
        if self.trip_active or s.t_reactor_kelvin < 250.0:
            return (0.0, 0.0)

        rt = R_GAS_CONSTANT * max(100.0, s.t_reactor_kelvin)
        c_prec = max(0.0, s.c_precursor_feed)
        c_meth = max(0.0, s.c_methef_product)
        c_pent = max(0.0, s.c_pentanediol_byproduct)
        c_w = max(0.0, s.c_water_coproduct)
        a_cat = max(0.0, min(1.0, s.a_catalyst))

        # Competitive adsorption denominator (Langmuir-Hinshelwood)
        den = (
            1.0
            + self.cfg.k_adsorb_precursor * c_prec
            + self.cfg.k_adsorb_methef * c_meth
            + self.cfg.k_adsorb_pentanediol * c_pent
            + self.cfg.k_adsorb_water * c_w
        )
        den_sq = den ** 2

        # Step 1: Precursor -> 2-MeTHF + H2O
        k1_arrh = self.cfg.k1_forward * math.exp(-self.cfg.ea1_j_mol / rt)
        r1 = (k1_arrh * a_cat * c_prec) / den_sq

        # Step 2: Precursor -> 1,4-Pentanediol
        k2_arrh = self.cfg.k2_forward * math.exp(-self.cfg.ea2_j_mol / rt)
        r2 = (k2_arrh * a_cat * c_prec) / den_sq

        return (r1, r2)

    def _derivatives(
        self, s: PHAHydrogenolysisMethefState
    ) -> Tuple[float, float, float, float, float, float, float]:
        """Compute coupled 6-state time derivatives plus reactor pressure dynamics.

        Returns:
            (dc_prec_dt, dc_meth_dt, dc_pent_dt, dc_water_dt, dt_reactor_dt, da_cat_dt, dp_reactor_dt)
        """
        c_thermal = self.cfg.v_reactor_m3 * self.cfg.rho_liquid * self.cfg.cp_liquid

        if self.trip_active and self.emergency_quench_active:
            # Emergency quench: Rapid depressurization, cryogenic/cold quench, zero forward reactions
            q_quench = self.cfg.ua_emergency_quench * (s.t_reactor_kelvin - self.cfg.t_quench_fluid)
            dt_reactor_dt = - q_quench / c_thermal
            dp_reactor_dt = - self.cfg.k_quench_depressurize * max(0.0, s.p_reactor - 1.01325)
            return (0.0, 0.0, 0.0, 0.0, dt_reactor_dt, 0.0, dp_reactor_dt)

        if self.trip_active:
            return (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        r1, r2 = self.compute_rates(s)

        # C5 Carbon backbone species conservation:
        # dc_prec_dt + dc_meth_dt + dc_pent_dt = (-r1 - r2) + r1 + r2 = 0
        dc_prec_dt = - r1 - r2
        dc_meth_dt = + r1
        dc_pent_dt = + r2

        # Coproduct water production
        dc_water_dt = + r1 + r2

        # Catalyst sintering / thermal deactivation
        rt = R_GAS_CONSTANT * max(100.0, s.t_reactor_kelvin)
        kd_arrh = self.cfg.k_sinter * math.exp(-self.cfg.ea_sinter_j_mol / rt)
        r_sinter = kd_arrh * s.a_catalyst * (s.t_reactor_kelvin / 450.0)
        da_cat_dt = - r_sinter

        # Thermal energy balance for CSTR reactor with cooling duty:
        q_rxn = (
            r1 * (-self.cfg.delta_h_rxn1_j_mol)
            + r2 * (-self.cfg.delta_h_rxn2_j_mol)
        ) * 1000.0  # W/m³
        q_cooling_w = s.cooling_duty_kw * 1000.0
        q_jacket = self.cfg.ua_jacket * (s.t_reactor_kelvin - self.t_coolant)
        q_loss = self.cfg.ua_loss * (s.t_reactor_kelvin - self.cfg.t_ambient)
        v_flow_m3_s = (max(0.0, s.feed_flow_rate_l_min) * 1e-3) / 60.0
        q_flow = (
            v_flow_m3_s * self.cfg.rho_liquid * self.cfg.cp_liquid * (self.cfg.t_feed - s.t_reactor_kelvin)
        )
        q_net = (q_rxn * self.cfg.v_reactor_m3) - q_cooling_w - q_jacket - q_loss + q_flow
        dt_reactor_dt = q_net / c_thermal

        # Pressure dynamics in nominal operation
        dp_reactor_dt = 0.0

        return (
            dc_prec_dt,
            dc_meth_dt,
            dc_pent_dt,
            dc_water_dt,
            dt_reactor_dt,
            da_cat_dt,
            dp_reactor_dt,
        )

    def emergency_shutdown(self) -> None:
        """Actuate fail-safe emergency quench and isolate feed pump upon safety trip."""
        self.reactor_active = False
        self.feed_pump = False
        self.emergency_quench_active = True
        self.state.feed_flow_rate_l_min = 0.0
        self.state.cooling_duty_kw = self.cfg.nominal_cooling_duty_kw * 2.0

    emergency_quench = emergency_shutdown
    emergency_trip = emergency_shutdown

    def check_interlocks(
        self, s: PHAHydrogenolysisMethefState, dt_reactor_dt: float = 0.0
    ) -> bool:
        """Evaluate process safety interlocks in strict 5-tier priority order.

        Priority Hierarchy:
        1: 0xF9C1 DIAG_ERR_THERMAL_RUNAWAY (T > 530 K or dT/dt > 12.0 K/s)
        2: 0xF9C2 DIAG_ERR_OVERPRESSURE_QUENCH (P > 50.0 bar)
        3: 0xF9C3 DIAG_ERR_CATALYST_SINTERING (Activity < 35.0%)
        4: 0xF9C4 DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE (Byproduct yield > 25.0%)
        5: 0xF9C5 DIAG_ERR_MASS_BALANCE_DIVERGENCE (residual > 1e-4)
        """
        if self.trip_active:
            return True

        rate_check = max(abs(dt_reactor_dt), abs(s.dt_reactor_dt), abs(self.last_dt_reactor_dt))

        # Priority 1: Thermal runaway trip (T > 530 K or dT/dt > 12.0 K/s)
        if s.t_reactor_kelvin > self.cfg.t_reactor_trip_max or rate_check > self.cfg.dt_reactor_dt_trip_max:
            self.diagnostic_code = DIAG_ERR_THERMAL_RUNAWAY
            self.trip_active = True
            self.emergency_shutdown()
            return True

        # Priority 2: Overpressure quench trip (P > 50.0 bar)
        if s.p_reactor > self.cfg.p_reactor_trip_max:
            self.diagnostic_code = DIAG_ERR_OVERPRESSURE_QUENCH
            self.trip_active = True
            self.emergency_shutdown()
            return True

        # Priority 3: Catalyst sintering trip (Activity < 35.0% / 0.35)
        if s.a_catalyst < self.cfg.catalyst_activity_min:
            self.diagnostic_code = DIAG_ERR_CATALYST_SINTERING
            self.trip_active = True
            self.emergency_shutdown()
            return True

        # Priority 4: Pentanediol byproduct spike trip (Byproduct yield > 25.0%)
        if (
            self.pentanediol_byproduct_yield_pct > self.cfg.byproduct_yield_max_pct
            or self._byproduct_spike_injected
        ):
            self.diagnostic_code = DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE
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
        s0 = PHAHydrogenolysisMethefState(
            c_precursor_feed=self.state.c_precursor_feed,
            c_methef_product=self.state.c_methef_product,
            c_pentanediol_byproduct=self.state.c_pentanediol_byproduct,
            c_water_coproduct=self.state.c_water_coproduct,
            t_reactor_kelvin=self.state.t_reactor_kelvin,
            a_catalyst=self.state.a_catalyst,
            p_reactor=self.state.p_reactor,
            feed_flow_rate_l_min=self.state.feed_flow_rate_l_min,
            cooling_duty_kw=self.state.cooling_duty_kw,
            dt_reactor_dt=self.state.dt_reactor_dt,
        )

        # Pre-step interlock evaluation and rate-of-rise check
        k1 = self._derivatives(s0)
        dt_est = k1[4]
        self.last_dt_reactor_dt = dt_est
        self.state.dt_reactor_dt = dt_est

        if not self.trip_active:
            if self.check_interlocks(s0, dt_reactor_dt=dt_est):
                self.sync_to_registers(self.reg_table)
                return

        # RK4 Stage k2
        s1 = PHAHydrogenolysisMethefState(
            c_precursor_feed=max(0.0, s0.c_precursor_feed + 0.5 * dt * k1[0]),
            c_methef_product=max(0.0, s0.c_methef_product + 0.5 * dt * k1[1]),
            c_pentanediol_byproduct=max(0.0, s0.c_pentanediol_byproduct + 0.5 * dt * k1[2]),
            c_water_coproduct=max(0.0, s0.c_water_coproduct + 0.5 * dt * k1[3]),
            t_reactor_kelvin=max(100.0, s0.t_reactor_kelvin + 0.5 * dt * k1[4]),
            a_catalyst=max(0.0, min(1.0, s0.a_catalyst + 0.5 * dt * k1[5])),
            p_reactor=max(0.0, s0.p_reactor + 0.5 * dt * k1[6]),
            feed_flow_rate_l_min=s0.feed_flow_rate_l_min,
            cooling_duty_kw=s0.cooling_duty_kw,
        )
        k2 = self._derivatives(s1)

        # RK4 Stage k3
        s2 = PHAHydrogenolysisMethefState(
            c_precursor_feed=max(0.0, s0.c_precursor_feed + 0.5 * dt * k2[0]),
            c_methef_product=max(0.0, s0.c_methef_product + 0.5 * dt * k2[1]),
            c_pentanediol_byproduct=max(0.0, s0.c_pentanediol_byproduct + 0.5 * dt * k2[2]),
            c_water_coproduct=max(0.0, s0.c_water_coproduct + 0.5 * dt * k2[3]),
            t_reactor_kelvin=max(100.0, s0.t_reactor_kelvin + 0.5 * dt * k2[4]),
            a_catalyst=max(0.0, min(1.0, s0.a_catalyst + 0.5 * dt * k2[5])),
            p_reactor=max(0.0, s0.p_reactor + 0.5 * dt * k2[6]),
            feed_flow_rate_l_min=s0.feed_flow_rate_l_min,
            cooling_duty_kw=s0.cooling_duty_kw,
        )
        k3 = self._derivatives(s2)

        # RK4 Stage k4
        s3 = PHAHydrogenolysisMethefState(
            c_precursor_feed=max(0.0, s0.c_precursor_feed + dt * k3[0]),
            c_methef_product=max(0.0, s0.c_methef_product + dt * k3[1]),
            c_pentanediol_byproduct=max(0.0, s0.c_pentanediol_byproduct + dt * k3[2]),
            c_water_coproduct=max(0.0, s0.c_water_coproduct + dt * k3[3]),
            t_reactor_kelvin=max(100.0, s0.t_reactor_kelvin + dt * k3[4]),
            a_catalyst=max(0.0, min(1.0, s0.a_catalyst + dt * k3[5])),
            p_reactor=max(0.0, s0.p_reactor + dt * k3[6]),
            feed_flow_rate_l_min=s0.feed_flow_rate_l_min,
            cooling_duty_kw=s0.cooling_duty_kw,
        )
        k4 = self._derivatives(s3)

        # Weighted RK4 integration
        dc_prec = (dt / 6.0) * (k1[0] + 2.0 * k2[0] + 2.0 * k3[0] + k4[0])
        dc_meth = (dt / 6.0) * (k1[1] + 2.0 * k2[1] + 2.0 * k3[1] + k4[1])
        dc_pent = (dt / 6.0) * (k1[2] + 2.0 * k2[2] + 2.0 * k3[2] + k4[2])
        dc_w = (dt / 6.0) * (k1[3] + 2.0 * k2[3] + 2.0 * k3[3] + k4[3])
        dt_rxn = (dt / 6.0) * (k1[4] + 2.0 * k2[4] + 2.0 * k3[4] + k4[4])
        da_cat = (dt / 6.0) * (k1[5] + 2.0 * k2[5] + 2.0 * k3[5] + k4[5])
        dp_rxn = (dt / 6.0) * (k1[6] + 2.0 * k2[6] + 2.0 * k3[6] + k4[6])

        # State updates
        self.state.c_precursor_feed = max(0.0, s0.c_precursor_feed + dc_prec)
        self.state.c_methef_product = max(0.0, s0.c_methef_product + dc_meth)
        self.state.c_pentanediol_byproduct = max(0.0, s0.c_pentanediol_byproduct + dc_pent)
        self.state.c_water_coproduct = max(0.0, s0.c_water_coproduct + dc_w)
        self.state.t_reactor_kelvin = max(100.0, s0.t_reactor_kelvin + dt_rxn)
        self.state.a_catalyst = max(0.0, min(1.0, s0.a_catalyst + da_cat))
        self.state.p_reactor = max(0.0, s0.p_reactor + dp_rxn)
        self.state.dt_reactor_dt = dt_rxn / max(1e-6, dt)
        self.last_dt_reactor_dt = self.state.dt_reactor_dt

        # Continuous C5 Carbon Backbone Conservation Residual Check
        current_c5 = (
            self.state.c_precursor_feed
            + self.state.c_methef_product
            + self.state.c_pentanediol_byproduct
        )
        if self.conservation_residual <= self.cfg.mass_residual_max:
            self.conservation_residual = abs(current_c5 - self._initial_c5) / self._initial_c5

        # Post-step safety interlocks check
        self.check_interlocks(self.state, dt_reactor_dt=self.state.dt_reactor_dt)
        self.sync_to_registers(self.reg_table)

    rk4_step = step_rk4

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.USER,
    ) -> None:
        """Synchronize simulation state to Horner OCS memory %R2870..%R2877 and %M669..%M671."""
        rt = reg_table or self.reg_table

        # %R2870: REG_PHA_METH_REACTOR_TEMP (0.1 °C, signed 16-bit)
        t_celsius = self.state.t_reactor_kelvin - T_ZERO_CELSIUS
        t_scaled = int(round(t_celsius * 10.0))
        rt.write_word(
            REG_PHA_METH_REACTOR_TEMP,
            t_scaled & 0xFFFF,
            privilege=privilege,
        )

        # %R2871: REG_PHA_METH_REACTOR_PRESSURE (0.01 bar, 0..10000)
        p_scaled = int(round(self.state.p_reactor * 100.0))
        p_clamped = max(0, min(10000, p_scaled))
        rt.write_word(
            REG_PHA_METH_REACTOR_PRESSURE,
            p_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2872: REG_PHA_METH_PRECURSOR_CONVERSION (0.1 %, 0..1000)
        conv_scaled = int(round(self.precursor_conversion_pct * 10.0))
        conv_clamped = max(0, min(1000, conv_scaled))
        rt.write_word(
            REG_PHA_METH_PRECURSOR_CONVERSION,
            conv_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2873: REG_PHA_METH_SELECTIVITY_PERCENT (0.1 %, 0..1000)
        sel_scaled = int(round(self.methef_selectivity_pct * 10.0))
        sel_clamped = max(0, min(1000, sel_scaled))
        rt.write_word(
            REG_PHA_METH_SELECTIVITY_PERCENT,
            sel_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2874: REG_PHA_METH_FEED_FLOW_RATE (0.1 L/min)
        flow_val = (
            self.state.feed_flow_rate_l_min
            if self.feed_pump and not self.trip_active
            else 0.0
        )
        flow_scaled = int(round(flow_val * 10.0))
        flow_clamped = max(0, min(65535, flow_scaled))
        rt.write_word(
            REG_PHA_METH_FEED_FLOW_RATE,
            flow_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2875: REG_PHA_METH_CATALYST_ACTIVITY (0.1 %, 0..1000)
        act_scaled = int(round(self.state.a_catalyst * 1000.0))
        act_clamped = max(0, min(1000, act_scaled))
        rt.write_word(
            REG_PHA_METH_CATALYST_ACTIVITY,
            act_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2876: REG_PHA_METH_COOLING_DUTY_KW (0.1 kW)
        duty_val = (
            self.state.cooling_duty_kw
            if self.reactor_active and not self.trip_active
            else (self.cfg.nominal_cooling_duty_kw * 2.0 if self.emergency_quench_active else 0.0)
        )
        duty_scaled = int(round(duty_val * 10.0))
        duty_clamped = max(0, min(65535, duty_scaled))
        rt.write_word(
            REG_PHA_METH_COOLING_DUTY_KW,
            duty_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2877: REG_PHA_METH_DIAGNOSTIC_CODE
        rt.write_word(
            REG_PHA_METH_DIAGNOSTIC_CODE,
            int(self.diagnostic_code) & 0xFFFF,
            privilege=privilege,
        )

        # Discrete Coils %M669..%M671
        # %M669: COIL_PHA_METH_REACTOR_ACTIVE
        rt.write_bit(
            COIL_PHA_METH_REACTOR_ACTIVE,
            self.reactor_active and not self.trip_active,
            privilege=privilege,
        )

        # %M670: COIL_PHA_METH_FEED_PUMP
        rt.write_bit(
            COIL_PHA_METH_FEED_PUMP,
            self.feed_pump and not self.trip_active,
            privilege=privilege,
        )

        # %M671: COIL_PHA_METH_EMERGENCY_QUENCH
        rt.write_bit(
            COIL_PHA_METH_EMERGENCY_QUENCH,
            self.emergency_quench_active or self.trip_active,
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
            f"PHA Hydrogenolysis 2-MeTHF CSTR: C_prec={self.state.c_precursor_feed:.2f} mol/L, "
            f"C_meth={self.state.c_methef_product:.2f} mol/L, C_pent={self.state.c_pentanediol_byproduct:.2f} mol/L, "
            f"C_w={self.state.c_water_coproduct:.2f} mol/L, T_rxn={self.state.t_reactor_kelvin:.1f} K, "
            f"P_rxn={self.state.p_reactor:.2f} bar, a_cat={self.state.a_catalyst:.3f}, "
            f"Conv={self.precursor_conversion_pct:.1f}%, Sel={self.methef_selectivity_pct:.1f}%, "
            f"Cooling={self.state.cooling_duty_kw:.1f} kW"
        )

        return ExecutionResult(
            status=status,
            error_code=err_code,
            details=details,
            data={
                "c_precursor_feed": self.state.c_precursor_feed,
                "c_methef_product": self.state.c_methef_product,
                "c_pentanediol_byproduct": self.state.c_pentanediol_byproduct,
                "c_water_coproduct": self.state.c_water_coproduct,
                "t_reactor_kelvin": self.state.t_reactor_kelvin,
                "a_catalyst": self.state.a_catalyst,
                "p_reactor": self.state.p_reactor,
                "feed_flow_rate_l_min": self.state.feed_flow_rate_l_min,
                "cooling_duty_kw": self.state.cooling_duty_kw,
                "precursor_conversion_pct": self.precursor_conversion_pct,
                "methef_selectivity_pct": self.methef_selectivity_pct,
                "pentanediol_byproduct_yield_pct": self.pentanediol_byproduct_yield_pct,
                "trip_active": self.trip_active,
                "reactor_active": self.reactor_active,
                "feed_pump": self.feed_pump,
                "emergency_quench_active": self.emergency_quench_active,
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
        self.state = PHAHydrogenolysisMethefState()
        self.diagnostic_code = DIAG_OK
        self.trip_active = False
        self.reactor_active = True
        self.feed_pump = True
        self.emergency_quench_active = False
        self.t_coolant = self.cfg.t_coolant_nominal
        self._byproduct_spike_injected = False
        self.cycle_count = 0
        self.conservation_residual = 0.0
        self.last_dt_reactor_dt = 0.0
        self._initial_c_precursor = max(1e-6, self.state.c_precursor_feed)
        self._initial_c_methef = self.state.c_methef_product
        self._initial_c_pentanediol = self.state.c_pentanediol_byproduct
        self._initial_c5 = (
            self.state.c_precursor_feed
            + self.state.c_methef_product
            + self.state.c_pentanediol_byproduct
        )
        self.sync_to_registers(self.reg_table)

    def get_mass_residual(self) -> float:
        """Return the current continuous carbon backbone conservation residual."""
        return self.conservation_residual

    def inject_thermal_runaway(self, temp_k: float = 535.0) -> None:
        """Inject high CSTR temperature anomaly to trigger trip 0xF9C1."""
        self.state.t_reactor_kelvin = float(temp_k)

    def inject_temperature_rate_excursion(self, rate_k_s: float = 15.0) -> None:
        """Inject fast temperature rate-of-rise to trigger trip 0xF9C1."""
        self.state.dt_reactor_dt = float(rate_k_s)
        self.last_dt_reactor_dt = float(rate_k_s)

    def inject_overpressure(self, pressure_bar: float = 55.0) -> None:
        """Inject reactor overpressure anomaly to trigger trip 0xF9C2."""
        self.state.p_reactor = float(pressure_bar)

    def inject_catalyst_sintering(self, activity: float = 0.30) -> None:
        """Inject catalyst sintering anomaly (activity < 35.0%) to trigger trip 0xF9C3."""
        self.state.a_catalyst = float(activity)

    def inject_byproduct_spike(self, yield_pct: float = 28.0) -> None:
        """Inject pentanediol byproduct spike (yield > 25.0%) to trigger trip 0xF9C4."""
        self._byproduct_spike_injected = True
        c_byprod = self._initial_c_precursor * (yield_pct / 100.0)
        self.state.c_pentanediol_byproduct = self._initial_c_pentanediol + c_byprod
        # Conserve C5 carbon backbone
        self.state.c_precursor_feed = max(
            0.0, self._initial_c5 - self.state.c_methef_product - self.state.c_pentanediol_byproduct
        )

    def inject_mass_divergence(self, residual: float = 0.005) -> None:
        """Inject continuous mass conservation divergence anomaly to trigger trip 0xF9C5."""
        self.conservation_residual = float(residual)

    def clear_injections(self) -> None:
        """Clear forced fault injections."""
        self._byproduct_spike_injected = False
        self.t_coolant = self.cfg.t_coolant_nominal

    # Fault injection aliases
    inject_thermal_excursion = inject_thermal_runaway
    inject_high_temperature = inject_thermal_runaway
    inject_rate_of_rise = inject_temperature_rate_excursion
    inject_overpressure_quench = inject_overpressure
    inject_pressure = inject_overpressure
    inject_catalyst_deactivation = inject_catalyst_sintering
    inject_pentanediol_spike = inject_byproduct_spike
    inject_pentanediol_byproduct_spike = inject_byproduct_spike
    inject_mass_balance_divergence = inject_mass_divergence


# Interoperability aliases
PhaHydrogenolysisMethefEngine = PHAHydrogenolysisMethefEngine
PHAHydrogenolysisMethefSimulator = PHAHydrogenolysisMethefEngine
PhaHydrogenolysisMethefSimulator = PHAHydrogenolysisMethefEngine
PHAHydrogenolysisMethefReactor = PHAHydrogenolysisMethefEngine
PhaHydrogenolysisMethefReactor = PHAHydrogenolysisMethefEngine
PHAHydrogenolysisMethefLogicUnit = PHAHydrogenolysisMethefEngine
PhaHydrogenolysisMethefLogicUnit = PHAHydrogenolysisMethefEngine
PHAMethefEngine = PHAHydrogenolysisMethefEngine
PhaMethefEngine = PHAHydrogenolysisMethefEngine
PHAMethefSimulator = PHAHydrogenolysisMethefEngine
PhaMethefSimulator = PHAHydrogenolysisMethefEngine


# ============================================================================
# 6. Deterministic 9-Stage Verification Function
# ============================================================================

def run_pha_hydrogenolysis_methef_verification(
    project_root: Optional[Any] = None,
    output_path: Optional[str] = None,
    work_package: str = "W326",
    quick: bool = False,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification sequence for W326.

    Strictly adheres to 4-state engineering contract:
    status: success | failed | blocked | inconclusive
    Only writes to output_path if output_path is not None.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: initial_state_and_rk4_discretization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    reactor = PHAHydrogenolysisMethefEngine()
    c_prec_0 = reactor.state.c_precursor_feed
    c_meth_0 = reactor.state.c_methef_product
    c_w_0 = reactor.state.c_water_coproduct
    c_pent_0 = reactor.state.c_pentanediol_byproduct
    steps_s1 = 2 if quick else 5
    for _ in range(steps_s1):
        reactor.step_rk4(dt=0.1)

    c1 = (
        reactor.state.c_precursor_feed < c_prec_0
        and reactor.state.c_methef_product > c_meth_0
        and reactor.state.c_water_coproduct > c_w_0
        and reactor.state.c_pentanediol_byproduct >= c_pent_0
        and reactor.diagnostic_code == DIAG_OK
        and reactor.trip_active is False
        and reactor.precursor_conversion_pct > 0.0
        and reactor.methef_selectivity_pct > 0.0
        and reactor.state.a_catalyst > 0.90
    )
    test_results.append({
        "stage": 1,
        "name": "initial_state_and_rk4_discretization",
        "passed": bool(c1),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"RK4 CSTR hydrogenation verified: C_prec ({c_prec_0:.2f} -> {reactor.state.c_precursor_feed:.2f} mol/L), "
            f"C_meth ({c_meth_0:.2f} -> {reactor.state.c_methef_product:.2f} mol/L), "
            f"Conv={reactor.precursor_conversion_pct:.1f}%, Sel={reactor.methef_selectivity_pct:.1f}%."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 2: hydrogenation_kinetics_and_temperature_sensitivity
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_kin = PHAHydrogenolysisMethefEngine()
    r1_nom, r2_nom = re_kin.compute_rates(re_kin.state)

    st_hot = PHAHydrogenolysisMethefState(
        t_reactor_kelvin=495.0,
        c_precursor_feed=re_kin.state.c_precursor_feed,
        c_methef_product=re_kin.state.c_methef_product,
        c_pentanediol_byproduct=re_kin.state.c_pentanediol_byproduct,
        c_water_coproduct=re_kin.state.c_water_coproduct,
    )
    r1_hot, r2_hot = re_kin.compute_rates(st_hot)

    st_cold = PHAHydrogenolysisMethefState(
        t_reactor_kelvin=435.0,
        c_precursor_feed=re_kin.state.c_precursor_feed,
        c_methef_product=re_kin.state.c_methef_product,
        c_pentanediol_byproduct=re_kin.state.c_pentanediol_byproduct,
        c_water_coproduct=re_kin.state.c_water_coproduct,
    )
    r1_cold, r2_cold = re_kin.compute_rates(st_cold)

    c2 = (
        r1_nom > 0.0
        and r2_nom > 0.0
        and r1_hot > r1_nom > r1_cold
        and r2_hot > r2_nom > r2_cold
    )
    test_results.append({
        "stage": 2,
        "name": "hydrogenation_kinetics_and_temperature_sensitivity",
        "passed": bool(c2),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Arrhenius hydrogenation kinetics verified: r1_hot={r1_hot:.4f} > nom={r1_nom:.4f} > cold={r1_cold:.4f}; "
            f"r2_hot={r2_hot:.4f} > nom={r2_nom:.4f} > cold={r2_cold:.4f}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 3: catalyst_sintering_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_sint = PHAHydrogenolysisMethefEngine()
    re_sint.inject_catalyst_sintering(activity=0.30)  # < 0.35 threshold
    re_sint.step_rk4(dt=0.05)

    c3 = (
        re_sint.trip_active is True
        and re_sint.diagnostic_code == DIAG_ERR_CATALYST_SINTERING
        and re_sint.emergency_quench_active is True
        and re_sint.reactor_active is False
        and re_sint.feed_pump is False
        and re_sint.reg_table.read_bit(COIL_PHA_METH_REACTOR_ACTIVE) is False
        and re_sint.reg_table.read_bit(COIL_PHA_METH_FEED_PUMP) is False
        and re_sint.reg_table.read_bit(COIL_PHA_METH_EMERGENCY_QUENCH) is True
        and (re_sint.reg_table.read_word(REG_PHA_METH_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9C3
        and re_sint.reg_table.read_word(REG_PHA_METH_CATALYST_ACTIVITY) == 300
    )
    test_results.append({
        "stage": 3,
        "name": "catalyst_sintering_trip",
        "passed": bool(c3),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Catalyst sintering trip 0xF9C3 verified for activity < 35.0%; emergency quench actuated.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: pentanediol_byproduct_spike_safety_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_byprod = PHAHydrogenolysisMethefEngine()
    re_byprod.inject_byproduct_spike(yield_pct=28.0)  # > 25.0% threshold
    re_byprod.step_rk4(dt=0.05)

    c4 = (
        re_byprod.trip_active is True
        and re_byprod.diagnostic_code == DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE
        and re_byprod.emergency_quench_active is True
        and re_byprod.reactor_active is False
        and re_byprod.feed_pump is False
        and re_byprod.reg_table.read_bit(COIL_PHA_METH_REACTOR_ACTIVE) is False
        and re_byprod.reg_table.read_bit(COIL_PHA_METH_FEED_PUMP) is False
        and re_byprod.reg_table.read_bit(COIL_PHA_METH_EMERGENCY_QUENCH) is True
        and (re_byprod.reg_table.read_word(REG_PHA_METH_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9C4
    )
    test_results.append({
        "stage": 4,
        "name": "pentanediol_byproduct_spike_safety_trip",
        "passed": bool(c4),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Pentanediol byproduct spike trip 0xF9C4 verified for byproduct yield > 25.0%.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: thermal_runaway_safety_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # High temperature excursion (T > 530 K)
    re_temp = PHAHydrogenolysisMethefEngine()
    re_temp.inject_thermal_runaway(temp_k=535.0)
    re_temp.step_rk4(dt=0.05)

    high_temp_trip_ok = (
        re_temp.trip_active is True
        and re_temp.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        and re_temp.emergency_quench_active is True
        and re_temp.reactor_active is False
        and re_temp.feed_pump is False
        and re_temp.reg_table.read_bit(COIL_PHA_METH_REACTOR_ACTIVE) is False
        and re_temp.reg_table.read_bit(COIL_PHA_METH_FEED_PUMP) is False
        and re_temp.reg_table.read_bit(COIL_PHA_METH_EMERGENCY_QUENCH) is True
        and (re_temp.reg_table.read_word(REG_PHA_METH_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9C1
    )

    # Fast rate-of-rise excursion (dT/dt > 12.0 K/s)
    re_rate = PHAHydrogenolysisMethefEngine()
    re_rate.inject_temperature_rate_excursion(rate_k_s=15.0)
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
        "details": "Thermal runaway trip 0xF9C1 verified for both high temperature (> 530 K) and fast rise (> 12.0 K/s).",
    })

    # ------------------------------------------------------------------------
    # Stage 6: overpressure_quench_safety_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_press = PHAHydrogenolysisMethefEngine()
    re_press.inject_overpressure(pressure_bar=55.0)  # Exceeds 50.0 bar threshold
    re_press.step_rk4(dt=0.05)

    c6 = (
        re_press.trip_active is True
        and re_press.diagnostic_code == DIAG_ERR_OVERPRESSURE_QUENCH
        and re_press.emergency_quench_active is True
        and re_press.reactor_active is False
        and re_press.feed_pump is False
        and re_press.reg_table.read_bit(COIL_PHA_METH_REACTOR_ACTIVE) is False
        and re_press.reg_table.read_bit(COIL_PHA_METH_FEED_PUMP) is False
        and re_press.reg_table.read_bit(COIL_PHA_METH_EMERGENCY_QUENCH) is True
        and (re_press.reg_table.read_word(REG_PHA_METH_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9C2
    )
    test_results.append({
        "stage": 6,
        "name": "overpressure_quench_safety_trip",
        "passed": bool(c6),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Overpressure quench trip 0xF9C2 verified upon P > 50.0 bar; emergency quench actuated.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: priority_hierarchy_enforcement
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Thermal Runaway (P1: 0xF9C1) dominates Overpressure Quench (P2: 0xF9C2)
    re_p1_p2 = PHAHydrogenolysisMethefEngine()
    re_p1_p2.state.t_reactor_kelvin = 535.0
    re_p1_p2.state.p_reactor = 55.0
    re_p1_p2.step_rk4(dt=0.05)
    p1_dominates = re_p1_p2.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY

    # 2. Overpressure Quench (P2: 0xF9C2) dominates Catalyst Sintering (P3: 0xF9C3)
    re_p2_p3 = PHAHydrogenolysisMethefEngine()
    re_p2_p3.state.p_reactor = 55.0
    re_p2_p3.state.a_catalyst = 0.20
    re_p2_p3.step_rk4(dt=0.05)
    p2_dominates = re_p2_p3.diagnostic_code == DIAG_ERR_OVERPRESSURE_QUENCH

    # 3. Catalyst Sintering (P3: 0xF9C3) dominates Pentanediol Spike (P4: 0xF9C4)
    re_p3_p4 = PHAHydrogenolysisMethefEngine()
    re_p3_p4.state.a_catalyst = 0.20
    re_p3_p4.inject_byproduct_spike(yield_pct=28.0)
    re_p3_p4.step_rk4(dt=0.05)
    p3_dominates = re_p3_p4.diagnostic_code == DIAG_ERR_CATALYST_SINTERING

    # 4. Pentanediol Spike (P4: 0xF9C4) dominates Mass Balance Divergence (P5: 0xF9C5)
    re_p4_p5 = PHAHydrogenolysisMethefEngine()
    re_p4_p5.inject_byproduct_spike(yield_pct=28.0)
    re_p4_p5.conservation_residual = 0.005
    re_p4_p5.step_rk4(dt=0.05)
    p4_dominates = re_p4_p5.diagnostic_code == DIAG_ERR_PENTANEDIOL_BYPRODUCT_SPIKE

    c7 = p1_dominates and p2_dominates and p3_dominates and p4_dominates
    test_results.append({
        "stage": 7,
        "name": "priority_hierarchy_enforcement",
        "passed": bool(c7),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "5-tier fault priority hierarchy (0xF9C1 > 0xF9C2 > 0xF9C3 > 0xF9C4 > 0xF9C5) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: continuous_mass_conservation_and_divergence_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_cons = PHAHydrogenolysisMethefEngine()
    steps_s8 = 5 if quick else 15
    for _ in range(steps_s8):
        re_cons.step_rk4(dt=0.1)

    cons_ok = re_cons.conservation_residual < 1e-10

    # Divergence trip verification (residual > 1e-4)
    re_div = PHAHydrogenolysisMethefEngine()
    re_div.inject_mass_divergence(residual=0.005)
    re_div.step_rk4(dt=0.05)
    div_trip_ok = (
        re_div.trip_active is True
        and re_div.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        and (re_div.reg_table.read_word(REG_PHA_METH_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9C5
    )

    c8 = cons_ok and div_trip_ok
    test_results.append({
        "stage": 8,
        "name": "continuous_mass_conservation_and_divergence_trip",
        "passed": bool(c8),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Strict continuous C5 carbon backbone mass conservation residual {re_cons.conservation_residual:.2e} < 1e-10; "
            f"Mass divergence trip 0xF9C5 latched upon residual > 1e-4."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 9: horner_ocs_registers_and_pure_st_pou
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_s9 = PHAHydrogenolysisMethefEngine()
    re_s9.scan_step(dt=0.1)
    rt = RegisterTable()
    re_s9.sync_to_registers(rt)

    w_temp = rt.read_word(REG_PHA_METH_REACTOR_TEMP)
    w_press = rt.read_word(REG_PHA_METH_REACTOR_PRESSURE)
    w_conv = rt.read_word(REG_PHA_METH_PRECURSOR_CONVERSION)
    w_sel = rt.read_word(REG_PHA_METH_SELECTIVITY_PERCENT)
    w_flow = rt.read_word(REG_PHA_METH_FEED_FLOW_RATE)
    w_act = rt.read_word(REG_PHA_METH_CATALYST_ACTIVITY)
    w_duty = rt.read_word(REG_PHA_METH_COOLING_DUTY_KW)
    w_diag = rt.read_word(REG_PHA_METH_DIAGNOSTIC_CODE)

    b_active = rt.read_bit(COIL_PHA_METH_REACTOR_ACTIVE)
    b_pump = rt.read_bit(COIL_PHA_METH_FEED_PUMP)
    b_quench = rt.read_bit(COIL_PHA_METH_EMERGENCY_QUENCH)

    regs_ok = (
        w_temp > 0
        and w_press > 0
        and w_conv >= 0
        and w_sel >= 0
        and w_flow > 0
        and w_act > 0
        and w_duty > 0
        and (w_diag & 0xFFFF) == 0x0000
        and b_active is True
        and b_pump is True
        and b_quench is False
    )

    st_valid = verify_pha_hydrogenolysis_methef_pure_st()

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
        "XIC %M669",
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
            "Horner OCS register space %R2870..%R2877, coils %M669..%M671, "
            "pure ST POU PHAHydrogenolysisMethefControl, and 9 ladder construct rejections verified."
        ),
    })

    # Summary
    passed_count = sum(1 for r in test_results if r["passed"])
    total_count = len(test_results)
    all_passed = passed_count == total_count

    pou_digest = hashlib.sha256(PHA_HYDROGENOLYSIS_METHEF_PURE_ST_POU.encode("utf-8")).hexdigest()
    model_digest = hashlib.sha256(
        json.dumps(re_s9.cfg.to_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()

    evidence = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": (
            f"Work Package {work_package} Industrial PHA Hydrogenolysis & 2-MeTHF Verification "
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


run_pha_methef_verification = run_pha_hydrogenolysis_methef_verification


# ============================================================================
# 7. CLI Entry Point
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution for PHA Hydrogenolysis & 2-MeTHF simulation and verification."""
    parser = argparse.ArgumentParser(
        description="W326: Industrial Catalytic Polyhydroxyalkanoate Hydrogenolysis & 2-Methyltetrahydrofuran (2-MeTHF) Synthesis CSTR ODE Simulation"
    )
    parser.add_argument("--verify", action="store_true", help="Run 9-stage verification suite")
    parser.add_argument("--output", "-o", type=str, default=None, help="Evidence JSON output file path")
    parser.add_argument("--quick", action="store_true", help="Execute rapid test subset")
    parser.add_argument("--work-package", type=str, default="W326", help="Work package identifier")
    parser.add_argument("--json", action="store_true", help="Print verification result as JSON")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet output")

    args = parser.parse_args(argv)

    if args.verify or args.output or args.json or args.quick:
        res = run_pha_hydrogenolysis_methef_verification(
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
    engine = PHAHydrogenolysisMethefEngine()
    for cycle in range(1, 11):
        res = engine.scan_step(dt=0.1)
        print(f"Cycle {cycle:02d}: {res.details}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
