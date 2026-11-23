"""Industrial Catalytic Polyhydroxyalkanoate Hydrogenolysis & Tetrahydrofuran (THF) Dehydration Fixed-Bed ODE Simulation.

Work Package: W323 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Fixed-Bed Catalytic PHA Hydrogenolysis & THF Dehydration]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Features:
1. Industrial Catalytic PHA Hydrogenolysis & Tetrahydrofuran (THF) Dehydration:
   - Fixed-Bed Catalytic Reactor converting bio-derived 1,4-butanediol (1,4-BDO, from PHA hydrogenolysis)
     into tetrahydrofuran (THF) desired product with water byproduct and heavy oligomer coproduct:
     Step 1 (Main Dehydration): 1,4-Butanediol  ===>  Tetrahydrofuran (THF) + H2O
     Step 2 (Secondary Oligomerization): THF / BDO  ===>  Heavy Polyether Oligomers (+ H2O)
   - Solid acid-catalyzed Langmuir-Hinshelwood dehydration kinetics with
     multi-component adsorption competition and catalyst coking/deactivation:
     * Step 1 rate: r1 = (k1 * a_cat * C_bdo) / (1 + K_bdo*C_bdo + K_thf*C_thf + K_w*C_w + K_olig*C_olig)^2
     * Step 2 rate: r2 = (k2 * a_cat * C_thf) / (1 + K_bdo*C_bdo + K_thf*C_thf + K_w*C_w + K_olig*C_olig)^2
     * Catalyst coking: da_cat/dt = - kd * a_cat * exp(-Ed / (R*T)) * (C_bdo + 0.5*C_thf)
2. Coupled 6-State Continuous Fixed-Bed ODE Vector:
   - State variables:
     1. C_bdo_feed: 1,4-Butanediol feed concentration (mol/L)
     2. C_thf_product: Tetrahydrofuran product concentration (mol/L)
     3. C_water_byproduct: Coproduct water concentration (mol/L)
     4. C_oligomer_heavy: Heavy polyether oligomer byproduct concentration (mol/L)
     5. T_reactor_kelvin: Fixed-bed reaction zone temperature (K)
     6. a_acid_catalyst: Acid catalyst relative activity (fraction 0..1)
   - 4th-Order Runge-Kutta (RK4) numerical integrator step_rk4(dt).
   - Strict continuous carbon backbone mass conservation (residuals < 1e-10).
3. Process Safety Interlocks & Diagnostics (Strict 5-Tier Priority Hierarchy):
   - Priority 1: 0xF9B1 DIAG_ERR_THERMAL_EXCURSION (T > 540 K or dT/dt > 15 K/s)
   - Priority 2: 0xF9B2 DIAG_ERR_OVERPRESSURE_VENT (P > 45.0 bar)
   - Priority 3: 0xF9B3 DIAG_ERR_CATALYST_COKING (Activity < 30.0%)
   - Priority 4: 0xF9B4 DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP (Yield < 50.0% at conversion > 70.0%)
   - Priority 5: 0xF9B5 DIAG_ERR_MASS_BALANCE_DIVERGENCE (residual > 1e-4)
4. Horner OCS Memory Space Integration:
   - Word registers %R2840..%R2847:
     %R2840: REG_PHA_THF_REACTOR_TEMP (0.1 °C, signed 16-bit)
     %R2841: REG_PHA_THF_REACTOR_PRESSURE (0.01 bar, 0..10000)
     %R2842: REG_PHA_THF_BDO_CONVERSION (0.1 %, 0..1000)
     %R2843: REG_PHA_THF_YIELD_PERCENT (0.1 %, 0..1000)
     %R2844: REG_PHA_THF_FEED_FLOW_RATE (0.1 L/min)
     %R2845: REG_PHA_THF_ACID_CATALYST_ACTIVITY (0.1 %, 0..1000)
     %R2846: REG_PHA_THF_REBOILER_DUTY_KW (0.1 kW)
     %R2847: REG_PHA_THF_DIAGNOSTIC_CODE (0x0000=OK, 0xF9B1..0xF9B5)
   - Discrete coils %M662..%M664:
     %M662: COIL_PHA_THF_REACTOR_ACTIVE (BOOL)
     %M663: COIL_PHA_THF_FEED_PUMP (BOOL)
     %M664: COIL_PHA_THF_EMERGENCY_VENT (BOOL)
5. Pure IEC 61131-3 Structured Text (ST) POU:
   - POU 'PHAHydrogenolysisTHFControl' with anti-ladder validation rejecting 9 ladder constructs.
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

MW_BDO: float           = 90.12    # 1,4-Butanediol C4H10O2 (g/mol)
MW_THF: float           = 72.11    # Tetrahydrofuran C4H8O (g/mol)
MW_WATER: float         = 18.015   # Water H2O (g/mol)
MW_OLIGOMER: float      = 162.23   # Heavy polyether oligomer dimer C8H18O3 (g/mol)
MW_CARBON: float        = 12.011   # Carbon atomic weight (g/mol)

R_GAS_CONSTANT: float   = 8.314462618  # Universal gas constant [J/(mol*K)]
T_ZERO_CELSIUS: float   = 273.15   # 0.0 °C in Kelvin [K]


# ============================================================================
# 2. Horner OCS Memory Space Integration & Diagnostic Codes
# ============================================================================

# Word Registers %R2840..%R2847
REG_PHA_THF_REACTOR_TEMP: str           = "%R2840"  # 0.1 °C, signed 16-bit
REG_PHA_THF_REACTOR_PRESSURE: str       = "%R2841"  # 0.01 bar, 0..10000
REG_PHA_THF_BDO_CONVERSION: str         = "%R2842"  # 0.1 %, 0..1000
REG_PHA_THF_YIELD_PERCENT: str          = "%R2843"  # 0.1 %, 0..1000
REG_PHA_THF_FEED_FLOW_RATE: str         = "%R2844"  # 0.1 L/min
REG_PHA_THF_ACID_CATALYST_ACTIVITY: str = "%R2845"  # 0.1 %, 0..1000
REG_PHA_THF_REBOILER_DUTY_KW: str       = "%R2846"  # 0.1 kW
REG_PHA_THF_DIAGNOSTIC_CODE: str        = "%R2847"  # 16-bit diagnostic code

# Register Aliases
REG_PHA_THF_TEMP: str                   = REG_PHA_THF_REACTOR_TEMP
REG_PHA_THF_T_REACTOR: str              = REG_PHA_THF_REACTOR_TEMP
REG_PHA_THF_REACTOR_TEMPERATURE: str    = REG_PHA_THF_REACTOR_TEMP
REG_PHA_THF_PRESSURE: str               = REG_PHA_THF_REACTOR_PRESSURE
REG_PHA_THF_P_REACTOR: str              = REG_PHA_THF_REACTOR_PRESSURE
REG_PHA_THF_CONVERSION: str             = REG_PHA_THF_BDO_CONVERSION
REG_PHA_THF_CONV: str                   = REG_PHA_THF_BDO_CONVERSION
REG_PHA_THF_YIELD: str                  = REG_PHA_THF_YIELD_PERCENT
REG_PHA_THF_FLOW: str                   = REG_PHA_THF_FEED_FLOW_RATE
REG_PHA_THF_FEED_FLOW: str              = REG_PHA_THF_FEED_FLOW_RATE
REG_PHA_THF_ACTIVITY: str               = REG_PHA_THF_ACID_CATALYST_ACTIVITY
REG_PHA_THF_CATALYST_ACTIVITY: str      = REG_PHA_THF_ACID_CATALYST_ACTIVITY
REG_PHA_THF_REBOILER: str               = REG_PHA_THF_REBOILER_DUTY_KW
REG_PHA_THF_DUTY: str                   = REG_PHA_THF_REBOILER_DUTY_KW
REG_PHA_THF_DIAG: str                   = REG_PHA_THF_DIAGNOSTIC_CODE

# Discrete Coils %M662..%M664
COIL_PHA_THF_REACTOR_ACTIVE: str        = "%M662"   # BOOL
COIL_PHA_THF_FEED_PUMP: str             = "%M663"   # BOOL
COIL_PHA_THF_EMERGENCY_VENT: str        = "%M664"   # BOOL

# Coil Aliases
COIL_PHA_THF_ACTIVE: str                = COIL_PHA_THF_REACTOR_ACTIVE
COIL_PHA_THF_RUNNING: str               = COIL_PHA_THF_REACTOR_ACTIVE
COIL_PHA_THF_PUMP: str                  = COIL_PHA_THF_FEED_PUMP
COIL_PHA_THF_FEED: str                  = COIL_PHA_THF_FEED_PUMP
COIL_PHA_THF_VENT: str                  = COIL_PHA_THF_EMERGENCY_VENT
COIL_PHA_THF_EMERGENCY: str             = COIL_PHA_THF_EMERGENCY_VENT


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
DIAG_ERR_THERMAL_EXCURSION: DiagnosticCode             = DiagnosticCode(0xF9B1)  # Priority 1: T > 540 K or dT/dt > 15 K/s
DIAG_ERR_OVERPRESSURE_VENT: DiagnosticCode             = DiagnosticCode(0xF9B2)  # Priority 2: P > 45.0 bar
DIAG_ERR_CATALYST_COKING: DiagnosticCode               = DiagnosticCode(0xF9B3)  # Priority 3: Activity < 30.0%
DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP: DiagnosticCode  = DiagnosticCode(0xF9B4)  # Priority 4: Yield < 50.0% at conv > 70.0%
DIAG_ERR_MASS_BALANCE_DIVERGENCE: DiagnosticCode       = DiagnosticCode(0xF9B5)  # Priority 5: residual > 1e-4

# Diagnostic Aliases
DIAG_ERR_EXCURSION: DiagnosticCode                     = DIAG_ERR_THERMAL_EXCURSION
DIAG_ERR_THERMAL: DiagnosticCode                       = DIAG_ERR_THERMAL_EXCURSION
DIAG_ERR_RUNAWAY: DiagnosticCode                       = DIAG_ERR_THERMAL_EXCURSION
DIAG_ERR_OVERHEAT: DiagnosticCode                      = DIAG_ERR_THERMAL_EXCURSION
DIAG_ERR_OVERPRESSURE: DiagnosticCode                  = DIAG_ERR_OVERPRESSURE_VENT
DIAG_ERR_PRESSURE: DiagnosticCode                      = DIAG_ERR_OVERPRESSURE_VENT
DIAG_ERR_VENT: DiagnosticCode                          = DIAG_ERR_OVERPRESSURE_VENT
DIAG_ERR_COKING: DiagnosticCode                        = DIAG_ERR_CATALYST_COKING
DIAG_ERR_CATALYST: DiagnosticCode                      = DIAG_ERR_CATALYST_COKING
DIAG_ERR_DEACTIVATION: DiagnosticCode                  = DIAG_ERR_CATALYST_COKING
DIAG_ERR_SELECTIVITY: DiagnosticCode                   = DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP
DIAG_ERR_SELECTIVITY_DROP: DiagnosticCode              = DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP
DIAG_ERR_DEHYDRATION_SELECTIVITY: DiagnosticCode       = DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP
DIAG_ERR_MASS_DIVERGENCE: DiagnosticCode               = DIAG_ERR_MASS_BALANCE_DIVERGENCE
DIAG_ERR_MASS_BALANCE: DiagnosticCode                  = DIAG_ERR_MASS_BALANCE_DIVERGENCE

PHAHydrogenolysisTHFDiagnosticCode = DiagnosticCode
PhaHydrogenolysisTHFDiagnosticCode = DiagnosticCode
PHATHFDiagnosticCode = DiagnosticCode
PhaTHFDiagnosticCode = DiagnosticCode


class PHAHydrogenolysisTHFStatusWord(IntFlag):
    """Bitmask for Fixed-Bed Catalytic Hydrogenolysis & THF Dehydration operational status."""
    REACTOR_ACTIVE        = 1 << 0  # Bit 0: Fixed-bed reactor active (%M662)
    FEED_PUMP             = 1 << 1  # Bit 1: BDO feed pump running (%M663)
    EMERGENCY_VENT        = 1 << 2  # Bit 2: Emergency vent open (%M664)
    REBOILER_HEATING      = 1 << 3  # Bit 3: Reboiler duty active
    TEMP_WARN             = 1 << 4  # Bit 4: Reactor temperature pre-alarm
    PRESSURE_WARN         = 1 << 5  # Bit 5: Reactor pressure pre-alarm
    CATALYST_WARN         = 1 << 6  # Bit 6: Acid catalyst activity degradation pre-alarm
    EMERGENCY_TRIP        = 1 << 7  # Bit 7: Master safety trip latched


PhaHydrogenolysisTHFStatusWord = PHAHydrogenolysisTHFStatusWord
PHATHFStatusWord = PHAHydrogenolysisTHFStatusWord
PhaTHFStatusWord = PHAHydrogenolysisTHFStatusWord
PHAHydrogenolysisTHFStatusBits = PHAHydrogenolysisTHFStatusWord
PhaHydrogenolysisTHFStatusBits = PHAHydrogenolysisTHFStatusWord
PHATHFStatusBits = PHAHydrogenolysisTHFStatusWord
PhaTHFStatusBits = PHAHydrogenolysisTHFStatusWord


# ============================================================================
# 3. State & Configuration Models
# ============================================================================

@dataclass
class PHAHydrogenolysisTHFState:
    """Coupled 6-State Continuous Fixed-Bed ODE Vector for PHA Hydrogenolysis & THF Dehydration."""
    c_bdo_feed: float = 4.50               # mol/L: 1,4-Butanediol feed concentration
    c_thf_product: float = 0.12            # mol/L: Tetrahydrofuran desired product concentration
    c_water_byproduct: float = 0.12        # mol/L: Water byproduct concentration
    c_oligomer_heavy: float = 0.02         # mol/L: Heavy polyether oligomer concentration
    t_reactor_kelvin: float = 443.15       # K: Fixed-bed reaction zone temperature (~170.0 °C)
    a_acid_catalyst: float = 1.00          # fraction 0..1: Acid catalyst relative activity (1.0 = 100%)
    p_reactor: float = 12.0                # bar: Operating pressure
    feed_flow_rate_l_min: float = 85.0     # L/min: Feed pump flow rate
    reboiler_duty_kw: float = 65.0         # kW: Reboiler heat duty
    dt_reactor_dt: float = 0.0             # K/s: Temperature rate of change

    def to_dict(self) -> Dict[str, float]:
        return {
            "c_bdo_feed": self.c_bdo_feed,
            "c_thf_product": self.c_thf_product,
            "c_water_byproduct": self.c_water_byproduct,
            "c_oligomer_heavy": self.c_oligomer_heavy,
            "t_reactor_kelvin": self.t_reactor_kelvin,
            "a_acid_catalyst": self.a_acid_catalyst,
            "p_reactor": self.p_reactor,
            "feed_flow_rate_l_min": self.feed_flow_rate_l_min,
            "reboiler_duty_kw": self.reboiler_duty_kw,
            "dt_reactor_dt": self.dt_reactor_dt,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PHAHydrogenolysisTHFState:
        c_bdo = float(data.get("c_bdo_feed", data.get("C_bdo_feed", data.get("bdo_feed", 4.50))))
        c_thf = float(data.get("c_thf_product", data.get("C_thf_product", data.get("thf", 0.12))))
        c_w = float(data.get("c_water_byproduct", data.get("C_water_byproduct", data.get("water", 0.12))))
        c_olig = float(data.get("c_oligomer_heavy", data.get("C_oligomer_heavy", data.get("oligomer", 0.02))))
        t_rxn = float(data.get("t_reactor_kelvin", data.get("T_reactor_kelvin", data.get("temp_k", 443.15))))
        a_cat = float(data.get("a_acid_catalyst", data.get("a_cat", 1.00)))
        p_rxn = float(data.get("p_reactor", data.get("P_reactor", data.get("pressure_bar", 12.0))))
        flow = float(data.get("feed_flow_rate_l_min", data.get("feed_flow_rate", 85.0)))
        duty = float(data.get("reboiler_duty_kw", data.get("reboiler_duty", 65.0)))
        dt_dt = float(data.get("dt_reactor_dt", data.get("dT_reactor_dt", 0.0)))
        return cls(
            c_bdo_feed=c_bdo,
            c_thf_product=c_thf,
            c_water_byproduct=c_w,
            c_oligomer_heavy=c_olig,
            t_reactor_kelvin=t_rxn,
            a_acid_catalyst=a_cat,
            p_reactor=p_rxn,
            feed_flow_rate_l_min=flow,
            reboiler_duty_kw=duty,
            dt_reactor_dt=dt_dt,
        )

    # Distinct property aliases
    @property
    def C_bdo_feed(self) -> float:
        return self.c_bdo_feed

    @C_bdo_feed.setter
    def C_bdo_feed(self, val: float) -> None:
        self.c_bdo_feed = float(val)

    @property
    def bdo_feed(self) -> float:
        return self.c_bdo_feed

    @bdo_feed.setter
    def bdo_feed(self, val: float) -> None:
        self.c_bdo_feed = float(val)

    @property
    def c_bdo(self) -> float:
        return self.c_bdo_feed

    @c_bdo.setter
    def c_bdo(self, val: float) -> None:
        self.c_bdo_feed = float(val)

    @property
    def C_bdo(self) -> float:
        return self.c_bdo_feed

    @C_bdo.setter
    def C_bdo(self, val: float) -> None:
        self.c_bdo_feed = float(val)

    @property
    def C_thf_product(self) -> float:
        return self.c_thf_product

    @C_thf_product.setter
    def C_thf_product(self, val: float) -> None:
        self.c_thf_product = float(val)

    @property
    def thf_product(self) -> float:
        return self.c_thf_product

    @thf_product.setter
    def thf_product(self, val: float) -> None:
        self.c_thf_product = float(val)

    @property
    def c_thf(self) -> float:
        return self.c_thf_product

    @c_thf.setter
    def c_thf(self, val: float) -> None:
        self.c_thf_product = float(val)

    @property
    def C_thf(self) -> float:
        return self.c_thf_product

    @C_thf.setter
    def C_thf(self, val: float) -> None:
        self.c_thf_product = float(val)

    @property
    def C_water_byproduct(self) -> float:
        return self.c_water_byproduct

    @C_water_byproduct.setter
    def C_water_byproduct(self, val: float) -> None:
        self.c_water_byproduct = float(val)

    @property
    def water_byproduct(self) -> float:
        return self.c_water_byproduct

    @water_byproduct.setter
    def water_byproduct(self, val: float) -> None:
        self.c_water_byproduct = float(val)

    @property
    def c_water(self) -> float:
        return self.c_water_byproduct

    @c_water.setter
    def c_water(self, val: float) -> None:
        self.c_water_byproduct = float(val)

    @property
    def C_water(self) -> float:
        return self.c_water_byproduct

    @C_water.setter
    def C_water(self, val: float) -> None:
        self.c_water_byproduct = float(val)

    @property
    def c_h2o(self) -> float:
        return self.c_water_byproduct

    @c_h2o.setter
    def c_h2o(self, val: float) -> None:
        self.c_water_byproduct = float(val)

    @property
    def C_oligomer_heavy(self) -> float:
        return self.c_oligomer_heavy

    @C_oligomer_heavy.setter
    def C_oligomer_heavy(self, val: float) -> None:
        self.c_oligomer_heavy = float(val)

    @property
    def oligomer_heavy(self) -> float:
        return self.c_oligomer_heavy

    @oligomer_heavy.setter
    def oligomer_heavy(self, val: float) -> None:
        self.c_oligomer_heavy = float(val)

    @property
    def c_oligomer(self) -> float:
        return self.c_oligomer_heavy

    @c_oligomer.setter
    def c_oligomer(self, val: float) -> None:
        self.c_oligomer_heavy = float(val)

    @property
    def C_oligomer(self) -> float:
        return self.c_oligomer_heavy

    @C_oligomer.setter
    def C_oligomer(self, val: float) -> None:
        self.c_oligomer_heavy = float(val)

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
        return self.a_acid_catalyst

    @a_cat.setter
    def a_cat(self, val: float) -> None:
        self.a_acid_catalyst = float(val)

    @property
    def acid_catalyst_activity(self) -> float:
        return self.a_acid_catalyst

    @acid_catalyst_activity.setter
    def acid_catalyst_activity(self, val: float) -> None:
        self.a_acid_catalyst = float(val)

    @property
    def a_catalyst(self) -> float:
        return self.a_acid_catalyst

    @a_catalyst.setter
    def a_catalyst(self, val: float) -> None:
        self.a_acid_catalyst = float(val)

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
    def reboiler_duty(self) -> float:
        return self.reboiler_duty_kw

    @reboiler_duty.setter
    def reboiler_duty(self, val: float) -> None:
        self.reboiler_duty_kw = float(val)

    @property
    def duty_kw(self) -> float:
        return self.reboiler_duty_kw

    @duty_kw.setter
    def duty_kw(self, val: float) -> None:
        self.reboiler_duty_kw = float(val)

    @property
    def dT_reactor_dt(self) -> float:
        return self.dt_reactor_dt

    @dT_reactor_dt.setter
    def dT_reactor_dt(self, val: float) -> None:
        self.dt_reactor_dt = float(val)


PhaHydrogenolysisTHFState = PHAHydrogenolysisTHFState
PHATHFState = PHAHydrogenolysisTHFState
PhaTHFState = PHAHydrogenolysisTHFState
PHAHydrogenolysisTHFStateModel = PHAHydrogenolysisTHFState
PhaHydrogenolysisTHFStateModel = PHAHydrogenolysisTHFState


@dataclass
class PHAHydrogenolysisTHFConfig:
    """Kinetic, thermodynamic, hydrodynamic, and safety parameters for PHA Hydrogenolysis & THF Reactor.

    NOTE: Duplicate typed fields and @property setters are strictly avoided.
    """
    # Catalytic dehydration kinetics for Step 1: 1,4-BDO -> THF + H2O
    k1_forward: float = 5.2e4             # Pre-exponential factor step 1 [L/(mol*s)]
    ea1_j_mol: float = 52000.0            # Activation energy step 1 [J/mol] (52.0 kJ/mol)

    # Catalytic secondary oligomerization kinetics for Step 2: THF -> Heavy Oligomers
    k2_forward: float = 2.4e4             # Pre-exponential factor step 2 [L/(mol*s)]
    ea2_j_mol: float = 62000.0            # Activation energy step 2 [J/mol] (62.0 kJ/mol)

    # Catalyst coking / deactivation kinetics:
    k_deact: float = 3.8e-5               # Catalyst coking rate factor [L/(mol*s)]
    ea_deact_j_mol: float = 41000.0       # Deactivation activation energy [J/mol]

    # Langmuir adsorption equilibrium constants [L/mol]
    k_adsorb_bdo: float = 0.45           # Adsorption constant for 1,4-BDO feed
    k_adsorb_thf: float = 0.30           # Adsorption constant for THF product
    k_adsorb_water: float = 0.20         # Adsorption constant for water byproduct
    k_adsorb_oligomer: float = 0.15      # Adsorption constant for heavy oligomers

    # Reaction enthalpies [J/mol]
    delta_h_rxn1_j_mol: float = -18000.0  # Enthalpy step 1 (BDO -> THF + H2O) [J/mol]
    delta_h_rxn2_j_mol: float = -26000.0  # Enthalpy step 2 (Oligomerization) [J/mol]

    # Reactor geometry & physical properties
    v_reactor_m3: float = 0.35            # Fixed-bed fluid volume [m³] (350 L)
    rho_liquid: float = 1010.0            # Reaction mixture bulk density [kg/m³]
    cp_liquid: float = 2400.0             # Reaction mixture heat capacity [J/(kg*K)]
    nominal_flow_l_min: float = 85.0      # Nominal feed flow rate [L/min]
    nominal_pressure_bar: float = 12.0    # Operating pressure [bar]
    nominal_reboiler_duty_kw: float = 65.0 # Nominal reboiler heating duty [kW]

    # Thermal balances & heat exchange
    ua_jacket: float = 380.0              # Jacket heat transfer coefficient [W/K]
    t_coolant_nominal: float = 373.15     # Nominal coolant / tempering temperature [K]
    t_feed: float = 433.15                # Feed preheat temperature [K] (160.0 °C)
    ua_loss: float = 40.0                 # Ambient thermal heat loss coefficient [W/K]
    t_ambient: float = 298.15             # Ambient environmental temperature [K]

    # Safety Interlock Thresholds (Strict 5-Tier Priority Hierarchy):
    t_reactor_trip_max: float = 540.0     # Priority 1: Thermal excursion max temperature [K] (0xF9B1)
    dt_reactor_dt_trip_max: float = 15.0  # Priority 1: Temperature rate-of-rise max [K/s] (0xF9B1)
    p_reactor_trip_max: float = 45.0      # Priority 2: Overpressure vent threshold [bar] (0xF9B2)
    catalyst_activity_min: float = 0.30   # Priority 3: Catalyst coking minimum activity [-] (0xF9B3)
    conversion_threshold_selectivity_pct: float = 70.0 # Priority 4: Conversion threshold for selectivity check [%]
    yield_min_selectivity_pct: float = 50.0            # Priority 4: Minimum THF yield required [%] (0xF9B4)
    mass_residual_max: float = 1e-4       # Priority 5: Mass conservation residual trip [-] (0xF9B5)

    # Emergency action parameters
    k_vent_depressurize: float = 0.40     # Vent depressurization rate [1/s]
    ua_emergency_quench: float = 50000.0  # Emergency quench heat transfer [W/K]
    t_quench_fluid: float = 293.15        # Quench fluid supply temperature [K]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "k1_forward": self.k1_forward,
            "ea1_j_mol": self.ea1_j_mol,
            "k2_forward": self.k2_forward,
            "ea2_j_mol": self.ea2_j_mol,
            "k_deact": self.k_deact,
            "ea_deact_j_mol": self.ea_deact_j_mol,
            "delta_h_rxn1_j_mol": self.delta_h_rxn1_j_mol,
            "delta_h_rxn2_j_mol": self.delta_h_rxn2_j_mol,
            "v_reactor_m3": self.v_reactor_m3,
            "nominal_flow_l_min": self.nominal_flow_l_min,
            "nominal_pressure_bar": self.nominal_pressure_bar,
            "t_reactor_trip_max": self.t_reactor_trip_max,
            "dt_reactor_dt_trip_max": self.dt_reactor_dt_trip_max,
            "p_reactor_trip_max": self.p_reactor_trip_max,
            "catalyst_activity_min": self.catalyst_activity_min,
            "conversion_threshold_selectivity_pct": self.conversion_threshold_selectivity_pct,
            "yield_min_selectivity_pct": self.yield_min_selectivity_pct,
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


PhaHydrogenolysisTHFConfig = PHAHydrogenolysisTHFConfig
PHATHFConfig = PHAHydrogenolysisTHFConfig
PhaTHFConfig = PHAHydrogenolysisTHFConfig
PHAHydrogenolysisTHFParameters = PHAHydrogenolysisTHFConfig
PhaHydrogenolysisTHFParameters = PHAHydrogenolysisTHFConfig


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text POU
# ============================================================================

ST_PROGRAM_PHA_HYDROGENOLYSIS_THF_CONTROL = """
PROGRAM PHAHydrogenolysisTHFControl
VAR
    rReactorTemp AT %R2840 : INT;
    rReactorPressure AT %R2841 : WORD;
    rBDOConversion AT %R2842 : WORD;
    rYieldPercent AT %R2843 : WORD;
    rFeedFlowRate AT %R2844 : WORD;
    rAcidCatalystActivity AT %R2845 : WORD;
    rReboilerDutyKW AT %R2846 : WORD;
    wDiagnosticCode AT %R2847 : WORD;
    bReactorActive AT %M662 : BOOL;
    bFeedPump AT %M663 : BOOL;
    bEmergencyVent AT %M664 : BOOL;
END_VAR

IF wDiagnosticCode = 0 THEN
    bReactorActive := TRUE;
    bFeedPump := TRUE;
    bEmergencyVent := FALSE;
ELSE
    bReactorActive := FALSE;
    bFeedPump := FALSE;
    bEmergencyVent := TRUE;
END_IF;
END_PROGRAM
""".strip()

PHA_HYDROGENOLYSIS_THF_PURE_ST_POU: str = ST_PROGRAM_PHA_HYDROGENOLYSIS_THF_CONTROL
PHA_THF_PURE_ST_POU: str = ST_PROGRAM_PHA_HYDROGENOLYSIS_THF_CONTROL
PHAHydrogenolysisTHFControl: str = ST_PROGRAM_PHA_HYDROGENOLYSIS_THF_CONTROL
PHA_HYDROGENOLYSIS_THF_CONTROL_POU: str = ST_PROGRAM_PHA_HYDROGENOLYSIS_THF_CONTROL
PHA_THF_CONTROL_POU: str = ST_PROGRAM_PHA_HYDROGENOLYSIS_THF_CONTROL


def verify_pha_hydrogenolysis_thf_pure_st() -> bool:
    """Validate pure ST syntax and ensure strict rejection of ladder logic constructs."""
    try:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_PHA_HYDROGENOLYSIS_THF_CONTROL)
    except LadderForbiddenError:
        return False
    val = STParser.validate_code(ST_PROGRAM_PHA_HYDROGENOLYSIS_THF_CONTROL)
    return val.status == AgentStatus.SUCCESS


verify_pha_thf_pure_st = verify_pha_hydrogenolysis_thf_pure_st


# ============================================================================
# 5. Simulation Fixed-Bed Engine (ILogicUnit)
# ============================================================================

class PHAHydrogenolysisTHFEngine(ILogicUnit):
    """Industrial Catalytic PHA Hydrogenolysis & THF Dehydration Fixed-Bed ODE Simulator."""

    def __init__(
        self,
        config: Optional[PHAHydrogenolysisTHFConfig] = None,
        state: Optional[PHAHydrogenolysisTHFState] = None,
        reg_table: Optional[RegisterTable] = None,
        register_table: Optional[RegisterTable] = None,
        **kwargs: Any,
    ) -> None:
        self.cfg = config or PHAHydrogenolysisTHFConfig()
        self.state = state or PHAHydrogenolysisTHFState()
        self.reg_table = register_table or reg_table or RegisterTable()

        # Operational status flags
        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.trip_active: bool = False
        self.reactor_active: bool = True
        self.feed_pump: bool = True
        self.emergency_vent_active: bool = False

        # Heat exchange & fault injection operational state
        self.t_coolant: float = self.cfg.t_coolant_nominal
        self._selectivity_drop_injected: bool = False

        # Conservation and telemetry tracking
        self.cycle_count: int = 0
        self.conservation_residual: float = 0.0
        self.last_dt_reactor_dt: float = 0.0

        # Baseline inventory for conversion, yield, and carbon backbone conservation
        self._initial_c_bdo: float = max(1e-6, self.state.c_bdo_feed)
        self._initial_c_thf: float = self.state.c_thf_product
        self._initial_c4: float = (
            self.state.c_bdo_feed
            + self.state.c_thf_product
            + self.state.c_oligomer_heavy
        )

        # Initial register synchronization
        self.sync_to_registers(self.reg_table)

    @property
    def unit_id(self) -> str:
        return "PHA_THF_REACTOR_W323"

    @property
    def name(self) -> str:
        return "PHAHydrogenolysisTHFEngine"

    @property
    def priority(self) -> int:
        return 50

    @property
    def is_enabled(self) -> bool:
        return True

    @property
    def bdo_conversion_pct(self) -> float:
        """1,4-Butanediol (1,4-BDO) conversion efficiency [%]."""
        if self._initial_c_bdo < 1e-6:
            return 0.0
        c_conv = max(0.0, self._initial_c_bdo - self.state.c_bdo_feed)
        return max(0.0, min(100.0, (c_conv / self._initial_c_bdo) * 100.0))

    @property
    def conversion_pct(self) -> float:
        """Alias for 1,4-BDO conversion efficiency [%]."""
        return self.bdo_conversion_pct

    @property
    def thf_yield_pct(self) -> float:
        """Tetrahydrofuran (THF) yield relative to initial 1,4-BDO [%]."""
        if self._initial_c_bdo < 1e-6:
            return 0.0
        c_prod = max(0.0, self.state.c_thf_product - self._initial_c_thf)
        return max(0.0, min(100.0, (c_prod / self._initial_c_bdo) * 100.0))

    @property
    def yield_pct(self) -> float:
        """Alias for THF yield [%]."""
        return self.thf_yield_pct

    @property
    def thf_selectivity_pct(self) -> float:
        """Tetrahydrofuran (THF) selectivity relative to converted 1,4-BDO [%]."""
        c_conv = max(0.0, self._initial_c_bdo - self.state.c_bdo_feed)
        if c_conv > 1e-4:
            c_prod = max(0.0, self.state.c_thf_product - self._initial_c_thf)
            sel = (c_prod / c_conv) * 100.0
            return max(0.0, min(100.0, sel))
        tot_prod = self.state.c_thf_product + self.state.c_oligomer_heavy
        if tot_prod < 1e-6:
            return 0.0
        sel = (self.state.c_thf_product / tot_prod) * 100.0
        return max(0.0, min(100.0, sel))

    @property
    def selectivity_pct(self) -> float:
        """Alias for THF selectivity [%]."""
        return self.thf_selectivity_pct

    def compute_rates(
        self, s: PHAHydrogenolysisTHFState
    ) -> Tuple[float, float]:
        """Compute competitive catalytic dehydration reaction rates [mol/(L*s)].

        Returns:
            (r1, r2): Step 1 (BDO -> THF + H2O) and Step 2 (THF -> Oligomer) rates.
        """
        if self.trip_active or s.t_reactor_kelvin < 250.0:
            return (0.0, 0.0)

        rt = R_GAS_CONSTANT * max(100.0, s.t_reactor_kelvin)
        c_bdo = max(0.0, s.c_bdo_feed)
        c_thf = max(0.0, s.c_thf_product)
        c_w = max(0.0, s.c_water_byproduct)
        c_olig = max(0.0, s.c_oligomer_heavy)
        a_cat = max(0.0, min(1.0, s.a_acid_catalyst))

        # Competitive adsorption denominator
        den = (
            1.0
            + self.cfg.k_adsorb_bdo * c_bdo
            + self.cfg.k_adsorb_thf * c_thf
            + self.cfg.k_adsorb_water * c_w
            + self.cfg.k_adsorb_oligomer * c_olig
        )
        den_sq = den ** 2

        # Step 1: 1,4-BDO -> THF + H2O
        k1_arrh = self.cfg.k1_forward * math.exp(-self.cfg.ea1_j_mol / rt)
        r1 = (k1_arrh * a_cat * c_bdo) / den_sq

        # Step 2: THF -> Heavy Polyether Oligomers
        k2_arrh = self.cfg.k2_forward * math.exp(-self.cfg.ea2_j_mol / rt)
        r2 = (k2_arrh * a_cat * c_thf) / den_sq

        return (r1, r2)

    def _derivatives(
        self, s: PHAHydrogenolysisTHFState
    ) -> Tuple[float, float, float, float, float, float, float]:
        """Compute coupled 6-state time derivatives plus reactor pressure dynamics.

        Returns:
            (dc_bdo_dt, dc_thf_dt, dc_water_dt, dc_oligomer_dt, dt_reactor_dt, da_cat_dt, dp_reactor_dt)
        """
        c_thermal = self.cfg.v_reactor_m3 * self.cfg.rho_liquid * self.cfg.cp_liquid

        if self.trip_active and self.emergency_vent_active:
            # Emergency vent: Rapid depressurization, thermal quench, zero forward reactions
            q_quench = self.cfg.ua_emergency_quench * (s.t_reactor_kelvin - self.cfg.t_quench_fluid)
            dt_reactor_dt = - q_quench / c_thermal
            dp_reactor_dt = - self.cfg.k_vent_depressurize * max(0.0, s.p_reactor - 1.01325)
            return (0.0, 0.0, 0.0, 0.0, dt_reactor_dt, 0.0, dp_reactor_dt)

        if self.trip_active:
            return (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

        r1, r2 = self.compute_rates(s)

        # Carbon backbone species conservation:
        # dc_bdo_dt + dc_thf_dt + dc_oligomer_dt = -r1 + (r1 - r2) + r2 = 0
        dc_bdo_dt = - r1
        dc_thf_dt = + r1 - r2
        dc_oligomer_dt = + r2

        # Coproduct water production
        dc_water_dt = + r1

        # Acid catalyst coking / deactivation
        rt = R_GAS_CONSTANT * max(100.0, s.t_reactor_kelvin)
        kd_arrh = self.cfg.k_deact * math.exp(-self.cfg.ea_deact_j_mol / rt)
        r_deact = kd_arrh * s.a_acid_catalyst * (s.c_bdo_feed + 0.5 * s.c_thf_product)
        da_cat_dt = - r_deact

        # Thermal energy balance for fixed-bed reactor with reboiler:
        q_rxn = (
            r1 * (-self.cfg.delta_h_rxn1_j_mol)
            + r2 * (-self.cfg.delta_h_rxn2_j_mol)
        ) * 1000.0  # W/m³
        q_reboiler_w = s.reboiler_duty_kw * 1000.0
        q_cool = self.cfg.ua_jacket * (s.t_reactor_kelvin - self.t_coolant)
        q_loss = self.cfg.ua_loss * (s.t_reactor_kelvin - self.cfg.t_ambient)
        v_flow_m3_s = (max(0.0, s.feed_flow_rate_l_min) * 1e-3) / 60.0
        q_flow = (
            v_flow_m3_s * self.cfg.rho_liquid * self.cfg.cp_liquid * (self.cfg.t_feed - s.t_reactor_kelvin)
        )
        q_net = (q_rxn * self.cfg.v_reactor_m3) + q_reboiler_w - q_cool - q_loss + q_flow
        dt_reactor_dt = q_net / c_thermal

        # Pressure dynamics in nominal operation
        dp_reactor_dt = 0.0

        return (
            dc_bdo_dt,
            dc_thf_dt,
            dc_water_dt,
            dc_oligomer_dt,
            dt_reactor_dt,
            da_cat_dt,
            dp_reactor_dt,
        )

    def emergency_shutdown(self) -> None:
        """Actuate fail-safe emergency vent and isolate feed pump upon safety trip."""
        self.reactor_active = False
        self.feed_pump = False
        self.emergency_vent_active = True
        self.state.feed_flow_rate_l_min = 0.0
        self.state.reboiler_duty_kw = 0.0

    emergency_depressurize = emergency_shutdown
    emergency_trip = emergency_shutdown
    emergency_vent = emergency_shutdown

    def check_interlocks(
        self, s: PHAHydrogenolysisTHFState, dt_reactor_dt: float = 0.0
    ) -> bool:
        """Evaluate process safety interlocks in strict 5-tier priority order.

        Priority Hierarchy:
        1: 0xF9B1 DIAG_ERR_THERMAL_EXCURSION (T > 540 K or dT/dt > 15 K/s)
        2: 0xF9B2 DIAG_ERR_OVERPRESSURE_VENT (P > 45.0 bar)
        3: 0xF9B3 DIAG_ERR_CATALYST_COKING (Activity < 30.0%)
        4: 0xF9B4 DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP (Yield < 50.0% at conversion > 70.0%)
        5: 0xF9B5 DIAG_ERR_MASS_BALANCE_DIVERGENCE (residual > 1e-4)
        """
        if self.trip_active:
            return True

        rate_check = max(abs(dt_reactor_dt), abs(s.dt_reactor_dt), abs(self.last_dt_reactor_dt))

        # Priority 1: Thermal excursion trip (T > 540 K or dT/dt > 15 K/s)
        if s.t_reactor_kelvin > self.cfg.t_reactor_trip_max or rate_check > self.cfg.dt_reactor_dt_trip_max:
            self.diagnostic_code = DIAG_ERR_THERMAL_EXCURSION
            self.trip_active = True
            self.emergency_shutdown()
            return True

        # Priority 2: Overpressure vent trip (P > 45.0 bar)
        if s.p_reactor > self.cfg.p_reactor_trip_max:
            self.diagnostic_code = DIAG_ERR_OVERPRESSURE_VENT
            self.trip_active = True
            self.emergency_shutdown()
            return True

        # Priority 3: Catalyst coking trip (Activity < 30.0% / 0.30)
        if s.a_acid_catalyst < self.cfg.catalyst_activity_min:
            self.diagnostic_code = DIAG_ERR_CATALYST_COKING
            self.trip_active = True
            self.emergency_shutdown()
            return True

        # Priority 4: Dehydration selectivity drop trip (Yield < 50.0% at conversion > 70.0%)
        if (
            (self.bdo_conversion_pct > self.cfg.conversion_threshold_selectivity_pct
             and self.thf_yield_pct < self.cfg.yield_min_selectivity_pct)
            or self._selectivity_drop_injected
        ):
            self.diagnostic_code = DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP
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
        s0 = PHAHydrogenolysisTHFState(
            c_bdo_feed=self.state.c_bdo_feed,
            c_thf_product=self.state.c_thf_product,
            c_water_byproduct=self.state.c_water_byproduct,
            c_oligomer_heavy=self.state.c_oligomer_heavy,
            t_reactor_kelvin=self.state.t_reactor_kelvin,
            a_acid_catalyst=self.state.a_acid_catalyst,
            p_reactor=self.state.p_reactor,
            feed_flow_rate_l_min=self.state.feed_flow_rate_l_min,
            reboiler_duty_kw=self.state.reboiler_duty_kw,
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
        s1 = PHAHydrogenolysisTHFState(
            c_bdo_feed=max(0.0, s0.c_bdo_feed + 0.5 * dt * k1[0]),
            c_thf_product=max(0.0, s0.c_thf_product + 0.5 * dt * k1[1]),
            c_water_byproduct=max(0.0, s0.c_water_byproduct + 0.5 * dt * k1[2]),
            c_oligomer_heavy=max(0.0, s0.c_oligomer_heavy + 0.5 * dt * k1[3]),
            t_reactor_kelvin=max(100.0, s0.t_reactor_kelvin + 0.5 * dt * k1[4]),
            a_acid_catalyst=max(0.0, min(1.0, s0.a_acid_catalyst + 0.5 * dt * k1[5])),
            p_reactor=max(0.0, s0.p_reactor + 0.5 * dt * k1[6]),
            feed_flow_rate_l_min=s0.feed_flow_rate_l_min,
            reboiler_duty_kw=s0.reboiler_duty_kw,
        )
        k2 = self._derivatives(s1)

        # RK4 Stage k3
        s2 = PHAHydrogenolysisTHFState(
            c_bdo_feed=max(0.0, s0.c_bdo_feed + 0.5 * dt * k2[0]),
            c_thf_product=max(0.0, s0.c_thf_product + 0.5 * dt * k2[1]),
            c_water_byproduct=max(0.0, s0.c_water_byproduct + 0.5 * dt * k2[2]),
            c_oligomer_heavy=max(0.0, s0.c_oligomer_heavy + 0.5 * dt * k2[3]),
            t_reactor_kelvin=max(100.0, s0.t_reactor_kelvin + 0.5 * dt * k2[4]),
            a_acid_catalyst=max(0.0, min(1.0, s0.a_acid_catalyst + 0.5 * dt * k2[5])),
            p_reactor=max(0.0, s0.p_reactor + 0.5 * dt * k2[6]),
            feed_flow_rate_l_min=s0.feed_flow_rate_l_min,
            reboiler_duty_kw=s0.reboiler_duty_kw,
        )
        k3 = self._derivatives(s2)

        # RK4 Stage k4
        s3 = PHAHydrogenolysisTHFState(
            c_bdo_feed=max(0.0, s0.c_bdo_feed + dt * k3[0]),
            c_thf_product=max(0.0, s0.c_thf_product + dt * k3[1]),
            c_water_byproduct=max(0.0, s0.c_water_byproduct + dt * k3[2]),
            c_oligomer_heavy=max(0.0, s0.c_oligomer_heavy + dt * k3[3]),
            t_reactor_kelvin=max(100.0, s0.t_reactor_kelvin + dt * k3[4]),
            a_acid_catalyst=max(0.0, min(1.0, s0.a_acid_catalyst + dt * k3[5])),
            p_reactor=max(0.0, s0.p_reactor + dt * k3[6]),
            feed_flow_rate_l_min=s0.feed_flow_rate_l_min,
            reboiler_duty_kw=s0.reboiler_duty_kw,
        )
        k4 = self._derivatives(s3)

        # Weighted RK4 integration
        dc_bdo = (dt / 6.0) * (k1[0] + 2.0 * k2[0] + 2.0 * k3[0] + k4[0])
        dc_thf = (dt / 6.0) * (k1[1] + 2.0 * k2[1] + 2.0 * k3[1] + k4[1])
        dc_w = (dt / 6.0) * (k1[2] + 2.0 * k2[2] + 2.0 * k3[2] + k4[2])
        dc_olig = (dt / 6.0) * (k1[3] + 2.0 * k2[3] + 2.0 * k3[3] + k4[3])
        dt_rxn = (dt / 6.0) * (k1[4] + 2.0 * k2[4] + 2.0 * k3[4] + k4[4])
        da_cat = (dt / 6.0) * (k1[5] + 2.0 * k2[5] + 2.0 * k3[5] + k4[5])
        dp_rxn = (dt / 6.0) * (k1[6] + 2.0 * k2[6] + 2.0 * k3[6] + k4[6])

        # State updates
        self.state.c_bdo_feed = max(0.0, s0.c_bdo_feed + dc_bdo)
        self.state.c_thf_product = max(0.0, s0.c_thf_product + dc_thf)
        self.state.c_water_byproduct = max(0.0, s0.c_water_byproduct + dc_w)
        self.state.c_oligomer_heavy = max(0.0, s0.c_oligomer_heavy + dc_olig)
        self.state.t_reactor_kelvin = max(100.0, s0.t_reactor_kelvin + dt_rxn)
        self.state.a_acid_catalyst = max(0.0, min(1.0, s0.a_acid_catalyst + da_cat))
        self.state.p_reactor = max(0.0, s0.p_reactor + dp_rxn)
        self.state.dt_reactor_dt = dt_rxn / max(1e-6, dt)
        self.last_dt_reactor_dt = self.state.dt_reactor_dt

        # Continuous Carbon Backbone Conservation Residual Check
        current_c4 = (
            self.state.c_bdo_feed
            + self.state.c_thf_product
            + self.state.c_oligomer_heavy
        )
        if self.conservation_residual <= self.cfg.mass_residual_max:
            self.conservation_residual = abs(current_c4 - self._initial_c4) / self._initial_c4

        # Post-step safety interlocks check
        self.check_interlocks(self.state, dt_reactor_dt=self.state.dt_reactor_dt)
        self.sync_to_registers(self.reg_table)

    rk4_step = step_rk4

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.USER,
    ) -> None:
        """Synchronize simulation state to Horner OCS memory %R2840..%R2847 and %M662..%M664."""
        rt = reg_table or self.reg_table

        # %R2840: REG_PHA_THF_REACTOR_TEMP (0.1 °C, signed 16-bit)
        t_celsius = self.state.t_reactor_kelvin - T_ZERO_CELSIUS
        t_scaled = int(round(t_celsius * 10.0))
        rt.write_word(
            REG_PHA_THF_REACTOR_TEMP,
            t_scaled & 0xFFFF,
            privilege=privilege,
        )

        # %R2841: REG_PHA_THF_REACTOR_PRESSURE (0.01 bar, 0..10000)
        p_scaled = int(round(self.state.p_reactor * 100.0))
        p_clamped = max(0, min(10000, p_scaled))
        rt.write_word(
            REG_PHA_THF_REACTOR_PRESSURE,
            p_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2842: REG_PHA_THF_BDO_CONVERSION (0.1 %, 0..1000)
        conv_scaled = int(round(self.bdo_conversion_pct * 10.0))
        conv_clamped = max(0, min(1000, conv_scaled))
        rt.write_word(
            REG_PHA_THF_BDO_CONVERSION,
            conv_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2843: REG_PHA_THF_YIELD_PERCENT (0.1 %, 0..1000)
        yield_scaled = int(round(self.thf_yield_pct * 10.0))
        yield_clamped = max(0, min(1000, yield_scaled))
        rt.write_word(
            REG_PHA_THF_YIELD_PERCENT,
            yield_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2844: REG_PHA_THF_FEED_FLOW_RATE (0.1 L/min)
        flow_val = (
            self.state.feed_flow_rate_l_min
            if self.feed_pump and not self.trip_active
            else 0.0
        )
        flow_scaled = int(round(flow_val * 10.0))
        flow_clamped = max(0, min(65535, flow_scaled))
        rt.write_word(
            REG_PHA_THF_FEED_FLOW_RATE,
            flow_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2845: REG_PHA_THF_ACID_CATALYST_ACTIVITY (0.1 %, 0..1000)
        act_scaled = int(round(self.state.a_acid_catalyst * 1000.0))
        act_clamped = max(0, min(1000, act_scaled))
        rt.write_word(
            REG_PHA_THF_ACID_CATALYST_ACTIVITY,
            act_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2846: REG_PHA_THF_REBOILER_DUTY_KW (0.1 kW)
        duty_val = (
            self.state.reboiler_duty_kw
            if self.reactor_active and not self.trip_active
            else 0.0
        )
        duty_scaled = int(round(duty_val * 10.0))
        duty_clamped = max(0, min(65535, duty_scaled))
        rt.write_word(
            REG_PHA_THF_REBOILER_DUTY_KW,
            duty_clamped & 0xFFFF,
            privilege=privilege,
        )

        # %R2847: REG_PHA_THF_DIAGNOSTIC_CODE
        rt.write_word(
            REG_PHA_THF_DIAGNOSTIC_CODE,
            int(self.diagnostic_code) & 0xFFFF,
            privilege=privilege,
        )

        # Discrete Coils %M662..%M664
        # %M662: COIL_PHA_THF_REACTOR_ACTIVE
        rt.write_bit(
            COIL_PHA_THF_REACTOR_ACTIVE,
            self.reactor_active and not self.trip_active,
            privilege=privilege,
        )

        # %M663: COIL_PHA_THF_FEED_PUMP
        rt.write_bit(
            COIL_PHA_THF_FEED_PUMP,
            self.feed_pump and not self.trip_active,
            privilege=privilege,
        )

        # %M664: COIL_PHA_THF_EMERGENCY_VENT
        rt.write_bit(
            COIL_PHA_THF_EMERGENCY_VENT,
            self.emergency_vent_active or self.trip_active,
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
            f"PHA Hydrogenolysis THF Fixed-Bed: C_bdo={self.state.c_bdo_feed:.2f} mol/L, "
            f"C_thf={self.state.c_thf_product:.2f} mol/L, C_w={self.state.c_water_byproduct:.2f} mol/L, "
            f"C_olig={self.state.c_oligomer_heavy:.2f} mol/L, T_rxn={self.state.t_reactor_kelvin:.1f} K, "
            f"P_rxn={self.state.p_reactor:.2f} bar, a_cat={self.state.a_acid_catalyst:.3f}, "
            f"Conv={self.bdo_conversion_pct:.1f}%, Yield={self.thf_yield_pct:.1f}%, "
            f"Duty={self.state.reboiler_duty_kw:.1f} kW"
        )

        return ExecutionResult(
            status=status,
            error_code=err_code,
            details=details,
            data={
                "c_bdo_feed": self.state.c_bdo_feed,
                "c_thf_product": self.state.c_thf_product,
                "c_water_byproduct": self.state.c_water_byproduct,
                "c_oligomer_heavy": self.state.c_oligomer_heavy,
                "t_reactor_kelvin": self.state.t_reactor_kelvin,
                "a_acid_catalyst": self.state.a_acid_catalyst,
                "p_reactor": self.state.p_reactor,
                "feed_flow_rate_l_min": self.state.feed_flow_rate_l_min,
                "reboiler_duty_kw": self.state.reboiler_duty_kw,
                "bdo_conversion_pct": self.bdo_conversion_pct,
                "thf_yield_pct": self.thf_yield_pct,
                "thf_selectivity_pct": self.thf_selectivity_pct,
                "trip_active": self.trip_active,
                "reactor_active": self.reactor_active,
                "feed_pump": self.feed_pump,
                "emergency_vent_active": self.emergency_vent_active,
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
        self.state = PHAHydrogenolysisTHFState()
        self.diagnostic_code = DIAG_OK
        self.trip_active = False
        self.reactor_active = True
        self.feed_pump = True
        self.emergency_vent_active = False
        self.t_coolant = self.cfg.t_coolant_nominal
        self._selectivity_drop_injected = False
        self.cycle_count = 0
        self.conservation_residual = 0.0
        self.last_dt_reactor_dt = 0.0
        self._initial_c_bdo = max(1e-6, self.state.c_bdo_feed)
        self._initial_c_thf = self.state.c_thf_product
        self._initial_c4 = (
            self.state.c_bdo_feed
            + self.state.c_thf_product
            + self.state.c_oligomer_heavy
        )
        self.sync_to_registers(self.reg_table)

    def get_mass_residual(self) -> float:
        """Return the current continuous carbon backbone conservation residual."""
        return self.conservation_residual

    def inject_thermal_excursion(self, temp_k: float = 545.0) -> None:
        """Inject high fixed-bed temperature anomaly to trigger trip 0xF9B1."""
        self.state.t_reactor_kelvin = float(temp_k)

    def inject_temperature_rate_excursion(self, rate_k_s: float = 18.0) -> None:
        """Inject fast temperature rate-of-rise to trigger trip 0xF9B1."""
        self.state.dt_reactor_dt = float(rate_k_s)
        self.last_dt_reactor_dt = float(rate_k_s)

    def inject_overpressure(self, pressure_bar: float = 48.0) -> None:
        """Inject reactor overpressure vent anomaly to trigger trip 0xF9B2."""
        self.state.p_reactor = float(pressure_bar)

    def inject_catalyst_coking(self, activity: float = 0.25) -> None:
        """Inject catalyst coking anomaly (activity < 30.0%) to trigger trip 0xF9B3."""
        self.state.a_acid_catalyst = float(activity)

    def inject_dehydration_selectivity_drop(
        self, yield_pct: float = 40.0, conv_pct: float = 75.0
    ) -> None:
        """Inject dehydration selectivity drop (Yield < 50% at Conversion > 70%) to trigger trip 0xF9B4."""
        self._selectivity_drop_injected = True
        c_conv = self._initial_c_bdo * (conv_pct / 100.0)
        self.state.c_bdo_feed = max(0.0, self._initial_c_bdo - c_conv)
        c_prod = self._initial_c_bdo * (yield_pct / 100.0)
        self.state.c_thf_product = self._initial_c_thf + c_prod
        # Conserve C4 carbon backbone perfectly
        self.state.c_oligomer_heavy = max(
            0.0, self._initial_c4 - self.state.c_bdo_feed - self.state.c_thf_product
        )

    def inject_mass_divergence(self, residual: float = 0.005) -> None:
        """Inject continuous mass conservation divergence anomaly to trigger trip 0xF9B5."""
        self.conservation_residual = float(residual)

    def clear_injections(self) -> None:
        """Clear forced fault injections."""
        self._selectivity_drop_injected = False
        self.t_coolant = self.cfg.t_coolant_nominal

    # Fault injection aliases
    inject_thermal_runaway = inject_thermal_excursion
    inject_high_temperature = inject_thermal_excursion
    inject_rate_of_rise = inject_temperature_rate_excursion
    inject_overpressure_vent = inject_overpressure
    inject_pressure = inject_overpressure
    inject_catalyst_deactivation = inject_catalyst_coking
    inject_selectivity_drop = inject_dehydration_selectivity_drop
    inject_mass_balance_divergence = inject_mass_divergence


# Interoperability aliases
PhaHydrogenolysisTHFEngine = PHAHydrogenolysisTHFEngine
PHAHydrogenolysisTHFSimulator = PHAHydrogenolysisTHFEngine
PhaHydrogenolysisTHFSimulator = PHAHydrogenolysisTHFEngine
PHAHydrogenolysisTHFReactor = PHAHydrogenolysisTHFEngine
PhaHydrogenolysisTHFReactor = PHAHydrogenolysisTHFEngine
PHAHydrogenolysisTHFLogicUnit = PHAHydrogenolysisTHFEngine
PhaHydrogenolysisTHFLogicUnit = PHAHydrogenolysisTHFEngine
PHATHFEngine = PHAHydrogenolysisTHFEngine
PhaTHFEngine = PHAHydrogenolysisTHFEngine
PHATHFSimulator = PHAHydrogenolysisTHFEngine
PhaTHFSimulator = PHAHydrogenolysisTHFEngine


# ============================================================================
# 6. Deterministic 9-Stage Verification Function
# ============================================================================

def run_pha_hydrogenolysis_thf_verification(
    project_root: Optional[Any] = None,
    output_path: Optional[str] = None,
    work_package: str = "W323",
    quick: bool = False,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification sequence for W323.

    Strictly adheres to 4-state engineering contract:
    status: success | failed | blocked | inconclusive
    Only writes to output_path if output_path is not None.
    """
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: initial_state_and_rk4_discretization
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    reactor = PHAHydrogenolysisTHFEngine()
    c_bdo_0 = reactor.state.c_bdo_feed
    c_thf_0 = reactor.state.c_thf_product
    c_w_0 = reactor.state.c_water_byproduct
    c_olig_0 = reactor.state.c_oligomer_heavy
    steps_s1 = 2 if quick else 5
    for _ in range(steps_s1):
        reactor.step_rk4(dt=0.1)

    c1 = (
        reactor.state.c_bdo_feed < c_bdo_0
        and reactor.state.c_thf_product > c_thf_0
        and reactor.state.c_water_byproduct > c_w_0
        and reactor.state.c_oligomer_heavy >= c_olig_0
        and reactor.diagnostic_code == DIAG_OK
        and reactor.trip_active is False
        and reactor.bdo_conversion_pct > 0.0
        and reactor.thf_yield_pct > 0.0
        and reactor.state.a_acid_catalyst > 0.90
    )
    test_results.append({
        "stage": 1,
        "name": "initial_state_and_rk4_discretization",
        "passed": bool(c1),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"RK4 fixed-bed dehydration verified: C_bdo ({c_bdo_0:.2f} -> {reactor.state.c_bdo_feed:.2f} mol/L), "
            f"C_thf ({c_thf_0:.2f} -> {reactor.state.c_thf_product:.2f} mol/L), "
            f"Conv={reactor.bdo_conversion_pct:.1f}%, Yield={reactor.thf_yield_pct:.1f}%."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 2: dehydration_kinetics_and_temperature_sensitivity
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_kin = PHAHydrogenolysisTHFEngine()
    r1_nom, r2_nom = re_kin.compute_rates(re_kin.state)

    st_hot = PHAHydrogenolysisTHFState(
        t_reactor_kelvin=475.0,
        c_bdo_feed=re_kin.state.c_bdo_feed,
        c_thf_product=re_kin.state.c_thf_product,
        c_water_byproduct=re_kin.state.c_water_byproduct,
        c_oligomer_heavy=re_kin.state.c_oligomer_heavy,
    )
    r1_hot, r2_hot = re_kin.compute_rates(st_hot)

    st_cold = PHAHydrogenolysisTHFState(
        t_reactor_kelvin=415.0,
        c_bdo_feed=re_kin.state.c_bdo_feed,
        c_thf_product=re_kin.state.c_thf_product,
        c_water_byproduct=re_kin.state.c_water_byproduct,
        c_oligomer_heavy=re_kin.state.c_oligomer_heavy,
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
        "name": "dehydration_kinetics_and_temperature_sensitivity",
        "passed": bool(c2),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Arrhenius dehydration kinetics verified: r1_hot={r1_hot:.4f} > nom={r1_nom:.4f} > cold={r1_cold:.4f}; "
            f"r2_hot={r2_hot:.4f} > nom={r2_nom:.4f} > cold={r2_cold:.4f}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 3: catalyst_coking_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_coke = PHAHydrogenolysisTHFEngine()
    re_coke.inject_catalyst_coking(activity=0.25)  # < 0.30 threshold
    re_coke.step_rk4(dt=0.05)

    c3 = (
        re_coke.trip_active is True
        and re_coke.diagnostic_code == DIAG_ERR_CATALYST_COKING
        and re_coke.emergency_vent_active is True
        and re_coke.reactor_active is False
        and re_coke.feed_pump is False
        and re_coke.reg_table.read_bit(COIL_PHA_THF_REACTOR_ACTIVE) is False
        and re_coke.reg_table.read_bit(COIL_PHA_THF_FEED_PUMP) is False
        and re_coke.reg_table.read_bit(COIL_PHA_THF_EMERGENCY_VENT) is True
        and (re_coke.reg_table.read_word(REG_PHA_THF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9B3
        and re_coke.reg_table.read_word(REG_PHA_THF_ACID_CATALYST_ACTIVITY) == 250
    )
    test_results.append({
        "stage": 3,
        "name": "catalyst_coking_trip",
        "passed": bool(c3),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Catalyst coking trip 0xF9B3 verified for activity < 30.0%; emergency vent actuated.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: dehydration_selectivity_drop_safety_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_sel = PHAHydrogenolysisTHFEngine()
    re_sel.inject_dehydration_selectivity_drop(yield_pct=40.0, conv_pct=75.0)  # Yield < 50%, Conv > 70%
    re_sel.step_rk4(dt=0.05)

    c4 = (
        re_sel.trip_active is True
        and re_sel.diagnostic_code == DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP
        and re_sel.emergency_vent_active is True
        and re_sel.reactor_active is False
        and re_sel.feed_pump is False
        and re_sel.reg_table.read_bit(COIL_PHA_THF_REACTOR_ACTIVE) is False
        and re_sel.reg_table.read_bit(COIL_PHA_THF_FEED_PUMP) is False
        and re_sel.reg_table.read_bit(COIL_PHA_THF_EMERGENCY_VENT) is True
        and (re_sel.reg_table.read_word(REG_PHA_THF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9B4
    )
    test_results.append({
        "stage": 4,
        "name": "dehydration_selectivity_drop_safety_trip",
        "passed": bool(c4),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Selectivity drop trip 0xF9B4 verified for Yield < 50.0% at Conversion > 70.0%.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: thermal_excursion_safety_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # High temperature excursion (T > 540 K)
    re_temp = PHAHydrogenolysisTHFEngine()
    re_temp.inject_thermal_excursion(temp_k=545.0)
    re_temp.step_rk4(dt=0.05)

    high_temp_trip_ok = (
        re_temp.trip_active is True
        and re_temp.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION
        and re_temp.emergency_vent_active is True
        and re_temp.reactor_active is False
        and re_temp.feed_pump is False
        and re_temp.reg_table.read_bit(COIL_PHA_THF_REACTOR_ACTIVE) is False
        and re_temp.reg_table.read_bit(COIL_PHA_THF_FEED_PUMP) is False
        and re_temp.reg_table.read_bit(COIL_PHA_THF_EMERGENCY_VENT) is True
        and (re_temp.reg_table.read_word(REG_PHA_THF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9B1
    )

    # Fast rate-of-rise excursion (dT/dt > 15 K/s)
    re_rate = PHAHydrogenolysisTHFEngine()
    re_rate.inject_temperature_rate_excursion(rate_k_s=18.0)
    re_rate.step_rk4(dt=0.05)

    high_rate_trip_ok = (
        re_rate.trip_active is True
        and re_rate.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION
    )

    c5 = high_temp_trip_ok and high_rate_trip_ok
    test_results.append({
        "stage": 5,
        "name": "thermal_excursion_safety_trip",
        "passed": bool(c5),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Thermal excursion trip 0xF9B1 verified for both high temperature (> 540 K) and fast rise (> 15 K/s).",
    })

    # ------------------------------------------------------------------------
    # Stage 6: overpressure_vent_safety_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_press = PHAHydrogenolysisTHFEngine()
    re_press.inject_overpressure(pressure_bar=48.0)  # Exceeds 45.0 bar threshold
    re_press.step_rk4(dt=0.05)

    c6 = (
        re_press.trip_active is True
        and re_press.diagnostic_code == DIAG_ERR_OVERPRESSURE_VENT
        and re_press.emergency_vent_active is True
        and re_press.reactor_active is False
        and re_press.feed_pump is False
        and re_press.reg_table.read_bit(COIL_PHA_THF_REACTOR_ACTIVE) is False
        and re_press.reg_table.read_bit(COIL_PHA_THF_FEED_PUMP) is False
        and re_press.reg_table.read_bit(COIL_PHA_THF_EMERGENCY_VENT) is True
        and (re_press.reg_table.read_word(REG_PHA_THF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9B2
    )
    test_results.append({
        "stage": 6,
        "name": "overpressure_vent_safety_trip",
        "passed": bool(c6),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Overpressure vent trip 0xF9B2 verified upon P > 45.0 bar; emergency vent actuated.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: priority_hierarchy_enforcement
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Thermal Excursion (P1: 0xF9B1) dominates Overpressure (P2: 0xF9B2)
    re_p1_p2 = PHAHydrogenolysisTHFEngine()
    re_p1_p2.state.t_reactor_kelvin = 545.0
    re_p1_p2.state.p_reactor = 50.0
    re_p1_p2.step_rk4(dt=0.05)
    p1_dominates = re_p1_p2.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION

    # 2. Overpressure (P2: 0xF9B2) dominates Catalyst Coking (P3: 0xF9B3)
    re_p2_p3 = PHAHydrogenolysisTHFEngine()
    re_p2_p3.state.p_reactor = 50.0
    re_p2_p3.state.a_acid_catalyst = 0.20
    re_p2_p3.step_rk4(dt=0.05)
    p2_dominates = re_p2_p3.diagnostic_code == DIAG_ERR_OVERPRESSURE_VENT

    # 3. Catalyst Coking (P3: 0xF9B3) dominates Selectivity Drop (P4: 0xF9B4)
    re_p3_p4 = PHAHydrogenolysisTHFEngine()
    re_p3_p4.state.a_acid_catalyst = 0.20
    re_p3_p4.inject_dehydration_selectivity_drop(yield_pct=40.0, conv_pct=75.0)
    re_p3_p4.step_rk4(dt=0.05)
    p3_dominates = re_p3_p4.diagnostic_code == DIAG_ERR_CATALYST_COKING

    # 4. Selectivity Drop (P4: 0xF9B4) dominates Mass Balance Divergence (P5: 0xF9B5)
    re_p4_p5 = PHAHydrogenolysisTHFEngine()
    re_p4_p5.inject_dehydration_selectivity_drop(yield_pct=40.0, conv_pct=75.0)
    re_p4_p5.conservation_residual = 0.005
    re_p4_p5.step_rk4(dt=0.05)
    p4_dominates = re_p4_p5.diagnostic_code == DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP

    c7 = p1_dominates and p2_dominates and p3_dominates and p4_dominates
    test_results.append({
        "stage": 7,
        "name": "priority_hierarchy_enforcement",
        "passed": bool(c7),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "5-tier fault priority hierarchy (0xF9B1 > 0xF9B2 > 0xF9B3 > 0xF9B4 > 0xF9B5) verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: continuous_mass_conservation_and_divergence_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_cons = PHAHydrogenolysisTHFEngine()
    steps_s8 = 5 if quick else 15
    for _ in range(steps_s8):
        re_cons.step_rk4(dt=0.1)

    cons_ok = re_cons.conservation_residual < 1e-10

    # Divergence trip verification (residual > 1e-4)
    re_div = PHAHydrogenolysisTHFEngine()
    re_div.inject_mass_divergence(residual=0.005)
    re_div.step_rk4(dt=0.05)
    div_trip_ok = (
        re_div.trip_active is True
        and re_div.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        and (re_div.reg_table.read_word(REG_PHA_THF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9B5
    )

    c8 = cons_ok and div_trip_ok
    test_results.append({
        "stage": 8,
        "name": "continuous_mass_conservation_and_divergence_trip",
        "passed": bool(c8),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Strict continuous carbon backbone mass conservation residual {re_cons.conservation_residual:.2e} < 1e-10; "
            f"Mass divergence trip 0xF9B5 latched upon residual > 1e-4."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 9: horner_ocs_registers_and_pure_st_pou
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_s9 = PHAHydrogenolysisTHFEngine()
    re_s9.scan_step(dt=0.1)
    rt = RegisterTable()
    re_s9.sync_to_registers(rt)

    w_temp = rt.read_word(REG_PHA_THF_REACTOR_TEMP)
    w_press = rt.read_word(REG_PHA_THF_REACTOR_PRESSURE)
    w_conv = rt.read_word(REG_PHA_THF_BDO_CONVERSION)
    w_yield = rt.read_word(REG_PHA_THF_YIELD_PERCENT)
    w_flow = rt.read_word(REG_PHA_THF_FEED_FLOW_RATE)
    w_act = rt.read_word(REG_PHA_THF_ACID_CATALYST_ACTIVITY)
    w_duty = rt.read_word(REG_PHA_THF_REBOILER_DUTY_KW)
    w_diag = rt.read_word(REG_PHA_THF_DIAGNOSTIC_CODE)

    b_active = rt.read_bit(COIL_PHA_THF_REACTOR_ACTIVE)
    b_pump = rt.read_bit(COIL_PHA_THF_FEED_PUMP)
    b_vent = rt.read_bit(COIL_PHA_THF_EMERGENCY_VENT)

    regs_ok = (
        w_temp > 0
        and w_press > 0
        and w_conv >= 0
        and w_yield >= 0
        and w_flow > 0
        and w_act > 0
        and w_duty > 0
        and (w_diag & 0xFFFF) == 0x0000
        and b_active is True
        and b_pump is True
        and b_vent is False
    )

    st_valid = verify_pha_hydrogenolysis_thf_pure_st()

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
        "XIC %M662",
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
            "Horner OCS register space %R2840..%R2847, coils %M662..%M664, "
            "pure ST POU PHAHydrogenolysisTHFControl, and 9 ladder construct rejections verified."
        ),
    })

    # Summary
    passed_count = sum(1 for r in test_results if r["passed"])
    total_count = len(test_results)
    all_passed = passed_count == total_count

    pou_digest = hashlib.sha256(PHA_HYDROGENOLYSIS_THF_PURE_ST_POU.encode("utf-8")).hexdigest()
    model_digest = hashlib.sha256(
        json.dumps(re_s9.cfg.to_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()

    evidence = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": (
            f"Work Package {work_package} Industrial PHA Hydrogenolysis & THF Verification "
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


run_pha_thf_verification = run_pha_hydrogenolysis_thf_verification


# ============================================================================
# 7. CLI Entry Point
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution for PHA Hydrogenolysis & THF dehydration simulation and verification."""
    parser = argparse.ArgumentParser(
        description="W323: Industrial Catalytic Polyhydroxyalkanoate Hydrogenolysis & Tetrahydrofuran (THF) Dehydration Fixed-Bed ODE Simulation"
    )
    parser.add_argument("--verify", action="store_true", help="Run 9-stage verification suite")
    parser.add_argument("--output", "-o", type=str, default=None, help="Evidence JSON output file path")
    parser.add_argument("--quick", action="store_true", help="Execute rapid test subset")
    parser.add_argument("--work-package", type=str, default="W323", help="Work package identifier")
    parser.add_argument("--json", action="store_true", help="Print verification result as JSON")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet output")

    args = parser.parse_args(argv)

    if args.verify or args.output or args.json or args.quick:
        res = run_pha_hydrogenolysis_thf_verification(
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
    engine = PHAHydrogenolysisTHFEngine()
    for cycle in range(1, 11):
        res = engine.scan_step(dt=0.1)
        print(f"Cycle {cycle:02d}: {res.details}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
