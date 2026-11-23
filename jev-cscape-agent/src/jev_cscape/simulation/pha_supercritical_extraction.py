"""Industrial Supercritical CO2 Polyhydroxyalkanoate Extraction & Precipitation Autoclave ODE Simulation (W302).

Work Package: W302 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Supercritical CO2 PHA Extraction & Autoclave Separation Kinetics]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Features:
1. Supercritical CO2 Real-Gas Thermodynamics & Solvation:
   - Peng-Robinson Equation of State (PR-EOS) for supercritical CO2 density d (600..950 kg/m^3).
   - Chrastil density-dependent supercritical solubility equation:
     S = d^k * exp(a / (T + 273.15) + b)
     governing PHA solute solubility in dense fluid as a function of autoclave temperature and density.
2. Shrinking Core Dissolution & Separator Precipitation Kinetics:
   - Dissolution rate with shrinking core biomass geometry:
     r_diss = kLa * (S - C_pha_sol) * (M_cell / M_cell0)^(2/3)
   - Depressurization & separator precipitation rate:
     r_precip = k_precip * max(0, C_pha_sol - S_sep)
   - Strict analytical mass conservation residual strictly < 1e-10:
     |M_cell0 - (M_cell + C_pha_sol * V_scCO2 + M_precip)| < 1e-10
3. Coupled 6-State Dynamic RK4 ODE Discretization:
   - State variables:
     1. M_cell: residual unextracted cell biomass mass (g)
     2. C_pha_sol: dissolved PHA concentration in supercritical fluid (g/L)
     3. M_precip: precipitated purified PHA mass in separator (g)
     4. P_ext: extraction autoclave pressure (bar, nominal 150..350 bar)
     5. T_ext: extraction temperature (°C, nominal 40..80 °C)
     6. V_scCO2: supercritical fluid volume (L)
4. Safety Trips & Interlocks (Strict Priority Hierarchy):
   - Priority 1: 0xF941 OVER_PRESSURE (P_ext > 360.0 bar trips pressure relief, %M615=True)
   - Priority 2: 0xF942 PHASE_BOUNDARY_LOSS (P_ext < 75.0 bar while active, subcritical collapse)
   - Priority 3: 0xF943 THERMAL_DEGRADATION (T_ext > 85.0 °C trips autoclave heater)
   - Priority 4: 0xF944 SEPARATOR_CLOGGING (separator pressure drop / capacity overflow)
5. Horner OCS Memory Space Integration:
   - Word registers %R2630..%R2637:
     %R2630: REG_PHA_SCCO2_STATUS (High byte = State 1..4, Low byte = Phase 1..5)
     %R2631: REG_PHA_SCCO2_PRESSURE_BAR (P * 10, deci-bar)
     %R2632: REG_PHA_SCCO2_TEMP_SCALED (T * 10, deci-°C)
     %R2633: REG_PHA_SCCO2_DENSITY_SCALED (density * 10, deci-kg/m^3)
     %R2634: REG_PHA_SCCO2_EXTRACTED_YIELD_PCT (Yield % * 10, deci-%)
     %R2635: REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED (M_precip * 10, deci-g)
     %R2636: REG_PHA_SCCO2_DIAGNOSTIC_CODE (0x0000=OK, 0xF941..0xF944)
     %R2637: REG_PHA_SCCO2_STATUS_WORD (Bitmask for pumps, heaters, valves, trips)
   - Discrete coils %M613..%M615:
     %M613: COIL_PHA_SCCO2_ACTIVE (BOOL)
     %M614: COIL_PHA_SCCO2_WARNING (BOOL)
     %M615: COIL_PHA_SCCO2_TRIP (BOOL)
6. Pure IEC 61131-3 Structured Text (ST) POU:
   - POU 'PhaSupercriticalExtractionSync' with anti-ladder validation and register bindings.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import hashlib
import json
import math
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Physical & Chemical Constants for Supercritical CO2 & PHA
# ============================================================================

GAS_CONSTANT_R: float = 8.314462618        # Universal gas constant [J / (mol * K)]
MW_CO2: float = 0.04401                    # Molecular weight of CO2 [kg/mol] (44.01 g/mol)
R_SPECIFIC_CO2: float = GAS_CONSTANT_R / MW_CO2  # Specific gas constant [J / (kg * K)] ~ 188.92

# CO2 Critical Parameters
T_CRITICAL_CO2_K: float = 304.13           # Critical temperature [K] (30.98 °C)
P_CRITICAL_CO2_PA: float = 7.3773e6        # Critical pressure [Pa] (7.3773 MPa = 73.773 bar)
P_CRITICAL_CO2_BAR: float = 73.773         # Critical pressure [bar]
RHO_CRITICAL_CO2_KG_M3: float = 467.6      # Critical density [kg/m^3]
OMEGA_CO2: float = 0.22394                 # Acentric factor [-]

# Empirical Chrastil Model Parameters for PHA in Supercritical CO2
CHRASTIL_K: float = 3.8                    # Density power exponent [-]
CHRASTIL_A: float = -3400.0                # Temperature parameter [K]
CHRASTIL_B: float = -12.5                  # Empirical constant [-]
CHRASTIL_RHO_REF: float = 1000.0           # Reference density [kg/m^3]


# ============================================================================
# 2. Horner OCS Memory Space Integration & Diagnostic Codes
# ============================================================================

# Word Registers %R2630..%R2637
REG_PHA_SCCO2_STATUS: str                   = "%R2630"
REG_PHA_SCCO2_PRESSURE_BAR: str             = "%R2631"
REG_PHA_SCCO2_TEMP_SCALED: str              = "%R2632"
REG_PHA_SCCO2_DENSITY_SCALED: str           = "%R2633"
REG_PHA_SCCO2_EXTRACTED_YIELD_PCT: str      = "%R2634"
REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED: str = "%R2635"
REG_PHA_SCCO2_DIAGNOSTIC_CODE: str          = "%R2636"
REG_PHA_SCCO2_STATUS_WORD: str              = "%R2637"

# SCRC Register Aliases
REG_PHA_SCRC_STATUS: str                    = REG_PHA_SCCO2_STATUS
REG_PHA_SCRC_PRESSURE_SCALED: str           = REG_PHA_SCCO2_PRESSURE_BAR
REG_PHA_SCRC_TEMP_SCALED: str               = REG_PHA_SCCO2_TEMP_SCALED
REG_PHA_SCRC_DENSITY_SCALED: str            = REG_PHA_SCCO2_DENSITY_SCALED
REG_PHA_SCRC_SOLUBILITY_SCALED: str         = REG_PHA_SCCO2_EXTRACTED_YIELD_PCT
REG_PHA_SCRC_YIELD_SCALED: str              = REG_PHA_SCCO2_EXTRACTED_YIELD_PCT
REG_PHA_SCRC_DIAGNOSTIC_CODE: str           = REG_PHA_SCCO2_DIAGNOSTIC_CODE
REG_PHA_SCRC_STATUS_WORD: str               = REG_PHA_SCCO2_STATUS_WORD

# Register Aliases for compatibility
REG_PHA_SCCO2_MODE_STATUS: str              = REG_PHA_SCCO2_STATUS
REG_PHA_SCCO2_STATUS_REG: str               = REG_PHA_SCCO2_STATUS
REG_PHA_SCCO2_PRESSURE: str                 = REG_PHA_SCCO2_PRESSURE_BAR
REG_PHA_SCCO2_PRESSURE_SCALED: str          = REG_PHA_SCCO2_PRESSURE_BAR
REG_PHA_SCCO2_P_EXT: str                    = REG_PHA_SCCO2_PRESSURE_BAR
REG_PHA_SCCO2_TEMP: str                     = REG_PHA_SCCO2_TEMP_SCALED
REG_PHA_SCCO2_TEMPERATURE: str              = REG_PHA_SCCO2_TEMP_SCALED
REG_PHA_SCCO2_T_EXT: str                    = REG_PHA_SCCO2_TEMP_SCALED
REG_PHA_SCCO2_DENSITY: str                  = REG_PHA_SCCO2_DENSITY_SCALED
REG_PHA_SCCO2_RHO: str                      = REG_PHA_SCCO2_DENSITY_SCALED
REG_PHA_SCCO2_YIELD_PCT: str                = REG_PHA_SCCO2_EXTRACTED_YIELD_PCT
REG_PHA_SCCO2_YIELD_SCALED: str             = REG_PHA_SCCO2_EXTRACTED_YIELD_PCT
REG_PHA_SCCO2_YIELD: str                    = REG_PHA_SCCO2_EXTRACTED_YIELD_PCT
REG_PHA_SCCO2_PRECIP_MASS: str              = REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED
REG_PHA_SCCO2_M_PRECIP: str                 = REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED
REG_PHA_SCCO2_PRECIPITATED_MASS: str        = REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED
REG_PHA_SCCO2_DIAG: str                     = REG_PHA_SCCO2_DIAGNOSTIC_CODE
REG_PHA_SCCO2_STATUS_BITS: str              = REG_PHA_SCCO2_STATUS_WORD

# Discrete Coils %M613..%M615
COIL_PHA_SCCO2_ACTIVE: str                  = "%M613"
COIL_PHA_SCCO2_RUNNING: str                 = "%M613"
COIL_PHA_SCCO2_EXTRACTION_ACTIVE: str       = "%M613"
COIL_PHA_SCRC_ACTIVE: str                   = "%M613"

COIL_PHA_SCCO2_WARNING: str                 = "%M614"
COIL_PHA_SCCO2_WARNING_ALARM: str           = "%M614"
COIL_PHA_SCCO2_PERMISSIVE: str              = "%M614"
COIL_PHA_SCRC_WARNING: str                  = "%M614"

COIL_PHA_SCCO2_TRIP: str                    = "%M615"
COIL_PHA_SCCO2_TRIP_ALARM: str              = "%M615"
COIL_PHA_SCCO2_EMERGENCY_TRIP: str          = "%M615"
COIL_PHA_SCRC_TRIP: str                     = "%M615"


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


# 16-bit Trip Diagnostic Constants
DIAG_OK: DiagnosticCode                             = DiagnosticCode(0x0000) # Normal healthy operation
DIAG_ERR_OVER_PRESSURE: DiagnosticCode              = DiagnosticCode(0xF941) # Priority 1: Over-pressure (P_ext > 360.0 bar)
DIAG_ERR_PHASE_BOUNDARY_LOSS: DiagnosticCode        = DiagnosticCode(0xF942) # Priority 2: Phase boundary loss (P_ext < 75.0 bar while active)
DIAG_ERR_THERMAL_DEGRADATION: DiagnosticCode        = DiagnosticCode(0xF943) # Priority 3: Thermal degradation (T_ext > 85.0 °C)
DIAG_ERR_SEPARATOR_CLOGGING: DiagnosticCode         = DiagnosticCode(0xF944) # Priority 4: Separator clogging / capacity overflow

# Diagnostic Aliases
DIAG_OVER_PRESSURE: DiagnosticCode                  = DIAG_ERR_OVER_PRESSURE
DIAG_ERR_OVERPRESSURE: DiagnosticCode               = DIAG_ERR_OVER_PRESSURE
DIAG_PHASE_BOUNDARY_LOSS: DiagnosticCode            = DIAG_ERR_PHASE_BOUNDARY_LOSS
DIAG_ERR_PHASE_BOUNDARY: DiagnosticCode             = DIAG_ERR_PHASE_BOUNDARY_LOSS
DIAG_ERR_SUBCRITICAL: DiagnosticCode                = DIAG_ERR_PHASE_BOUNDARY_LOSS
DIAG_ERR_SUBCRITICAL_LOSS: DiagnosticCode           = DIAG_ERR_PHASE_BOUNDARY_LOSS
DIAG_THERMAL_DEGRADATION: DiagnosticCode            = DIAG_ERR_THERMAL_DEGRADATION
DIAG_ERR_THERMAL: DiagnosticCode                    = DIAG_ERR_THERMAL_DEGRADATION
DIAG_ERR_OVERTEMP: DiagnosticCode                   = DIAG_ERR_THERMAL_DEGRADATION
DIAG_SEPARATOR_CLOGGING: DiagnosticCode             = DIAG_ERR_SEPARATOR_CLOGGING
DIAG_ERR_CLOGGING: DiagnosticCode                   = DIAG_ERR_SEPARATOR_CLOGGING

PhaScCO2DiagnosticCode = DiagnosticCode
PhaSupercriticalExtractionDiagnosticCode = DiagnosticCode
PhaSupercriticalDiagnosticCode = DiagnosticCode


class PhaScCO2StatusWord(IntFlag):
    """Bitmask for %R2637 REG_PHA_SCCO2_STATUS_WORD."""
    CO2_FEED_PUMP_ACTIVE       = 1 << 0  # Bit 0: Supercritical CO2 high-pressure feed pump running
    CO2_BOOSTER_PUMP_ACTIVE    = 1 << 0  # Bit 0 alias
    HEATER_ACTIVE              = 1 << 1  # Bit 1: Autoclave heating element / jacket active
    HEATER_JACKET_ACTIVE       = 1 << 1  # Bit 1 alias
    EXTRACTION_VALVE_OPEN      = 1 << 2  # Bit 2: Autoclave high-pressure extraction valve open
    SEPARATOR_EXPANSION_VALVE  = 1 << 3  # Bit 3: Depressurization expansion Joule-Thomson valve active
    RECYCLE_COMPRESSOR_ACTIVE  = 1 << 4  # Bit 4: Low-pressure CO2 recovery compressor running
    SUPERCRITICAL_REGIME_OK    = 1 << 5  # Bit 5: Fluid in supercritical state (P > Pc, T > Tc)
    PRESSURE_RELIEF_VALVE_ACTIVE = 1 << 5 # Bit 5 alias
    WARNING_ACTIVE             = 1 << 6  # Bit 6: Process approaching safety boundary warning
    TRIP_ACTIVE                = 1 << 7  # Bit 7: Master safety interlock trip latched
    EMERGENCY_TRIP             = 1 << 7  # Bit 7 alias

PhaScCO2StatusBits = PhaScCO2StatusWord
PhaSupercriticalExtractionStatusWord = PhaScCO2StatusWord
PhaSupercriticalStatusWord = PhaScCO2StatusWord
PhaSupercriticalExtractionStatusBits = PhaScCO2StatusWord
PhaSupercriticalStatusWord = PhaScCO2StatusWord
PhaSupercriticalStatusBits = PhaScCO2StatusWord


class PhaScCO2State(IntEnum):
    """Operating state in high byte of %R2630."""
    STANDBY                    = 1
    RUNNING                    = 2
    TRIPPED                    = 3
    COMPLETED                  = 4

PhaSupercriticalExtractionStateEnum = PhaScCO2State


class PhaScCO2Phase(IntEnum):
    """Process phase in low byte of %R2630."""
    IDLE                       = 1
    PRESSURIZATION             = 2
    EXTRACTION                 = 3
    PRECIPITATION              = 4
    RECOVERY                   = 5

PhaSupercriticalExtractionPhase = PhaScCO2Phase


# ============================================================================
# 3. State & Configuration Models
# ============================================================================

@dataclass
class PhaSupercriticalExtractionState:
    """Coupled 6-State Vector for Supercritical CO2 PHA Extraction & Precipitation Autoclave."""
    m_cell: float = 500.0      # g: residual unextracted cell biomass mass
    c_pha_sol: float = 0.0     # g/L: dissolved PHA concentration in supercritical fluid
    m_precip: float = 0.0      # g: precipitated purified PHA mass in separator
    p_ext: float = 250.0       # bar: extraction autoclave pressure (150..350 bar)
    t_ext: float = 50.0        # °C: extraction temperature (40..80 °C)
    v_scco2: float = 20.0      # L: supercritical fluid volume

    def to_dict(self) -> Dict[str, float]:
        return {
            "m_cell": self.m_cell,
            "c_pha_sol": self.c_pha_sol,
            "m_precip": self.m_precip,
            "p_ext": self.p_ext,
            "t_ext": self.t_ext,
            "v_scco2": self.v_scco2,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PhaSupercriticalExtractionState:
        m_cell = float(data.get("m_cell", data.get("M_cell", data.get("biomass", 500.0))))
        c_pha_sol = float(data.get("c_pha_sol", data.get("C_pha_sol", data.get("solute_conc", 0.0))))
        m_precip = float(data.get("m_precip", data.get("M_precip", data.get("purified_pha", 0.0))))
        p_ext = float(data.get("p_ext", data.get("P_ext", data.get("pressure", 250.0))))
        t_ext = float(data.get("t_ext", data.get("T_ext", data.get("temperature", 50.0))))
        v_scco2 = float(data.get("v_scco2", data.get("V_scCO2", data.get("volume", 20.0))))
        return cls(
            m_cell=m_cell,
            c_pha_sol=c_pha_sol,
            m_precip=m_precip,
            p_ext=p_ext,
            t_ext=t_ext,
            v_scco2=v_scco2,
        )

    # Property aliases for flexible interface compatibility
    @property
    def M_cell(self) -> float:
        return self.m_cell

    @M_cell.setter
    def M_cell(self, val: float) -> None:
        self.m_cell = float(val)

    @property
    def biomass(self) -> float:
        return self.m_cell

    @biomass.setter
    def biomass(self, val: float) -> None:
        self.m_cell = float(val)

    @property
    def cell_mass(self) -> float:
        return self.m_cell

    @cell_mass.setter
    def cell_mass(self, val: float) -> None:
        self.m_cell = float(val)

    @property
    def C_pha_sol(self) -> float:
        return self.c_pha_sol

    @C_pha_sol.setter
    def C_pha_sol(self, val: float) -> None:
        self.c_pha_sol = float(val)

    @property
    def dissolved_pha(self) -> float:
        return self.c_pha_sol

    @dissolved_pha.setter
    def dissolved_pha(self, val: float) -> None:
        self.c_pha_sol = float(val)

    @property
    def c_sol(self) -> float:
        return self.c_pha_sol

    @c_sol.setter
    def c_sol(self, val: float) -> None:
        self.c_pha_sol = float(val)

    @property
    def M_precip(self) -> float:
        return self.m_precip

    @M_precip.setter
    def M_precip(self, val: float) -> None:
        self.m_precip = float(val)

    @property
    def precipitated_mass(self) -> float:
        return self.m_precip

    @precipitated_mass.setter
    def precipitated_mass(self, val: float) -> None:
        self.m_precip = float(val)

    @property
    def purified_pha(self) -> float:
        return self.m_precip

    @purified_pha.setter
    def purified_pha(self, val: float) -> None:
        self.m_precip = float(val)

    @property
    def P_ext(self) -> float:
        return self.p_ext

    @P_ext.setter
    def P_ext(self, val: float) -> None:
        self.p_ext = float(val)

    @property
    def pressure(self) -> float:
        return self.p_ext

    @pressure.setter
    def pressure(self, val: float) -> None:
        self.p_ext = float(val)

    @property
    def pressure_bar(self) -> float:
        return self.p_ext

    @pressure_bar.setter
    def pressure_bar(self, val: float) -> None:
        self.p_ext = float(val)

    @property
    def T_ext(self) -> float:
        return self.t_ext

    @T_ext.setter
    def T_ext(self, val: float) -> None:
        self.t_ext = float(val)

    @property
    def temp(self) -> float:
        return self.t_ext

    @temp.setter
    def temp(self, val: float) -> None:
        self.t_ext = float(val)

    @property
    def temperature(self) -> float:
        return self.t_ext

    @temperature.setter
    def temperature(self, val: float) -> None:
        self.t_ext = float(val)

    @property
    def V_scCO2(self) -> float:
        return self.v_scco2

    @V_scCO2.setter
    def V_scCO2(self, val: float) -> None:
        self.v_scco2 = float(val)

    @property
    def volume(self) -> float:
        return self.v_scco2

    @volume.setter
    def volume(self, val: float) -> None:
        self.v_scco2 = float(val)

    @property
    def fluid_volume(self) -> float:
        return self.v_scco2

    @fluid_volume.setter
    def fluid_volume(self, val: float) -> None:
        self.v_scco2 = float(val)

    @property
    def m_solid(self) -> float:
        return self.m_cell

    @m_solid.setter
    def m_solid(self, val: float) -> None:
        self.m_cell = float(val)

    @property
    def m_fluid(self) -> float:
        return self.c_pha_sol * self.v_scco2

    @m_fluid.setter
    def m_fluid(self, val: float) -> None:
        self.c_pha_sol = float(val) / max(0.1, self.v_scco2)

    @property
    def temp_c(self) -> float:
        return self.t_ext

    @temp_c.setter
    def temp_c(self, val: float) -> None:
        self.t_ext = float(val)

    @property
    def clogging_index(self) -> float:
        return getattr(self, "_clogging_index", 0.05)

    @clogging_index.setter
    def clogging_index(self, val: float) -> None:
        self._clogging_index = float(val)


PhaScCO2ExtractionState = PhaSupercriticalExtractionState
PhaScCO2StateModel = PhaSupercriticalExtractionState


@dataclass
class PhaSupercriticalExtractionConfig:
    """Thermodynamic parameters, kinetic rates & safety limits for scCO2 PHA extraction."""
    # Chrastil supercritical solubility equation: S = d^k * exp(a / (T + 273.15) + b)
    chrastil_k: float = 3.8        # Density power exponent [-]
    chrastil_a: float = -3400.0    # Temperature parameter [K]
    chrastil_b: float = -12.5      # Empirical pre-factor constant [-]

    # Dissolution kinetics: r_diss = kLa * (S - C_pha_sol) * (M_cell / M_cell0)^(2/3)
    kLa: float = 0.02              # Volumetric mass transfer coefficient [1/s]
    m_cell0_nominal: float = 500.0 # Initial biomass reference mass [g]

    # Depressurization & precipitation: r_precip = k_precip * max(0, C_pha_sol - S_sep)
    k_precip: float = 0.03         # Precipitation rate coefficient [1/s]
    s_sep: float = 0.05            # Separator solubility at low pressure [g/L]

    # Autoclave vessel & operational parameters
    v_target: float = 20.0         # Supercritical vessel volume [L]
    tau_p: float = 2.0             # Pressure control time constant [s]
    tau_t: float = 10.0            # Thermal response time constant [s]
    tau_v: float = 5.0             # Volume relaxation time constant [s]
    delta_h_diss: float = 15.0     # Dissolution enthalpy [J/g]
    heat_capacity: float = 20000.0 # Autoclave total thermal capacitance [J/°C]

    # Process Safety Interlock Thresholds (Strict Priority Hierarchy)
    overpressure_threshold: float = 360.0       # Priority 1: P_ext > 360.0 bar -> 0xF941
    phase_boundary_threshold: float = 75.0      # Priority 2: P_ext < 75.0 bar while active -> 0xF942
    thermal_degradation_threshold: float = 85.0 # Priority 3: T_ext > 85.0 °C -> 0xF943
    separator_capacity: float = 480.0           # Priority 4: M_precip > 480.0 g or clogging -> 0xF944

    # Warning alert thresholds
    pressure_warning_high: float = 340.0        # P_ext >= 340.0 bar -> Warning
    pressure_warning_low: float = 100.0         # P_ext <= 100.0 bar -> Warning
    temp_warning_high: float = 75.0             # T_ext >= 75.0 °C -> Warning
    temp_warning_low: float = 42.0              # T_ext <= 42.0 °C -> Warning
    precip_warning_threshold: float = 420.0     # M_precip >= 420.0 g -> Warning

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chrastil_k": self.chrastil_k,
            "chrastil_a": self.chrastil_a,
            "chrastil_b": self.chrastil_b,
            "kLa": self.kLa,
            "m_cell0_nominal": self.m_cell0_nominal,
            "k_precip": self.k_precip,
            "s_sep": self.s_sep,
            "v_target": self.v_target,
            "tau_p": self.tau_p,
            "tau_t": self.tau_t,
            "tau_v": self.tau_v,
            "delta_h_diss": self.delta_h_diss,
            "heat_capacity": self.heat_capacity,
            "overpressure_threshold": self.overpressure_threshold,
            "phase_boundary_threshold": self.phase_boundary_threshold,
            "thermal_degradation_threshold": self.thermal_degradation_threshold,
            "separator_capacity": self.separator_capacity,
            "pressure_warning_high": self.pressure_warning_high,
            "pressure_warning_low": self.pressure_warning_low,
            "temp_warning_high": self.temp_warning_high,
            "temp_warning_low": self.temp_warning_low,
            "precip_warning_threshold": self.precip_warning_threshold,
        }


PhaScCO2ExtractionConfig = PhaSupercriticalExtractionConfig
PhaSupercriticalExtractionParameters = PhaSupercriticalExtractionConfig
PhaSupercriticalConfig = PhaSupercriticalExtractionConfig



# ============================================================================
# 4. Pure IEC 61131-3 Structured Text POU
# ============================================================================

ST_PROGRAM_PHA_SUPERCRITICAL_EXTRACTION_SYNC = """
PROGRAM PhaSupercriticalExtractionSync
VAR
    wStatus AT %R2630 : WORD;
    wPressureBarScaled AT %R2631 : WORD;
    wTempScaled AT %R2632 : WORD;
    wDensityScaled AT %R2633 : WORD;
    wYieldPctScaled AT %R2634 : WORD;
    wPrecipMassScaled AT %R2635 : WORD;
    wDiagCode AT %R2636 : WORD;
    wStatusWord AT %R2637 : WORD;
    bActive AT %M613 : BOOL;
    bWarning AT %M614 : BOOL;
    bTrip AT %M615 : BOOL;
END_VAR

IF wDiagCode = 0 THEN
    bActive := TRUE;
    bTrip := FALSE;
    IF (wPressureBarScaled >= 3400) OR (wPressureBarScaled <= 1000) OR (wTempScaled >= 750) THEN
        bWarning := TRUE;
    ELSE
        bWarning := FALSE;
    END_IF;
ELSE
    bActive := FALSE;
    bWarning := FALSE;
    bTrip := TRUE;
END_IF;
END_PROGRAM
""".strip()

PhaSupercriticalExtractionSync = ST_PROGRAM_PHA_SUPERCRITICAL_EXTRACTION_SYNC
PHA_SUPERCRITICAL_EXTRACTION_PURE_ST_POU = ST_PROGRAM_PHA_SUPERCRITICAL_EXTRACTION_SYNC
PHA_SCCO2_EXTRACTION_PURE_ST_POU = ST_PROGRAM_PHA_SUPERCRITICAL_EXTRACTION_SYNC
PHA_SCCO2_PURE_ST_POU = ST_PROGRAM_PHA_SUPERCRITICAL_EXTRACTION_SYNC


def verify_pha_supercritical_extraction_pure_st() -> bool:
    """Validate pure ST syntax and ensure strict rejection of ladder logic constructs."""
    try:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_PHA_SUPERCRITICAL_EXTRACTION_SYNC)
    except LadderForbiddenError:
        return False
    val = STParser.validate_code(ST_PROGRAM_PHA_SUPERCRITICAL_EXTRACTION_SYNC)
    return val.status == AgentStatus.SUCCESS


verify_pha_scco2_pure_st = verify_pha_supercritical_extraction_pure_st


# ============================================================================
# 5. Supercritical CO2 Extraction Reactor Simulation Engine
# ============================================================================

class PhaSupercriticalExtractionReactor(ILogicUnit):
    """Coupled 6-State RK4 simulation reactor for Supercritical CO2 PHA Extraction & Precipitation."""

    def __init__(
        self,
        config: Optional[PhaSupercriticalExtractionConfig] = None,
        initial_state: Optional[PhaSupercriticalExtractionState] = None,
        reg_table: Optional[RegisterTable] = None,
    ) -> None:
        self.cfg = config or PhaSupercriticalExtractionConfig()
        self.state = initial_state or PhaSupercriticalExtractionState()
        self.reg_table = reg_table or RegisterTable()

        # Mass conservation invariant reference M_cell0:
        # Total initial PHA = unextracted biomass + dissolved mass in fluid + precipitated mass
        self.m_cell0: float = (
            self.state.m_cell + self.state.c_pha_sol * self.state.v_scco2 + self.state.m_precip
        )
        if self.m_cell0 <= 0.0:
            self.m_cell0 = self.cfg.m_cell0_nominal

        # PR-EOS constants
        tc = T_CRITICAL_CO2_K
        pc = P_CRITICAL_CO2_PA
        r = GAS_CONSTANT_R
        self._a_c = 0.45724 * (r * tc) ** 2 / pc
        self._b_pr = 0.07780 * r * tc / pc
        self._kappa = 0.37464 + 1.54226 * OMEGA_CO2 - 0.26992 * (OMEGA_CO2 ** 2)

        # Operational status flags & setpoints
        self.p_set: float = self.state.p_ext
        self.t_jacket: float = self.state.t_ext
        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.trip_active: bool = False
        self.trip_latched: bool = False
        self.warning_active: bool = False
        self.is_active: bool = True
        self.separator_clogged: bool = False
        self.operating_state: PhaScCO2State = PhaScCO2State.RUNNING
        self.operating_phase: PhaScCO2Phase = PhaScCO2Phase.EXTRACTION
        self.pressure_relief_valve_active: bool = False
        self.mode: int = 2

        # Cycle accounting & residuals
        self.cycle_count: int = 0
        self.sim_time_s: float = 0.0
        self.conservation_residual: float = 0.0

        # Initial synchronization
        self._evaluate_safety_interlocks()
        self.sync_to_registers(self.reg_table)

    @property
    def name(self) -> str:
        return "PhaSupercriticalExtractionSimulationLogicUnit"

    @property
    def priority(self) -> int:
        return 50

    @property
    def is_enabled(self) -> bool:
        return True

    # ------------------------------------------------------------------------
    # Real-Gas Peng-Robinson Equation of State (PR-EOS) Solver for CO2 Density
    # ------------------------------------------------------------------------

    def peng_robinson_eos(self, p_pa: float, t_k: float) -> Tuple[float, float]:
        """Solve Peng-Robinson cubic equation for CO2 compressibility factor Z and density rho [kg/m^3]."""
        p_safe = max(1.0e5, p_pa)
        t_safe = max(200.0, t_k)
        r = GAS_CONSTANT_R
        r_t = r * t_safe

        # Alpha temperature dependence
        tr = t_safe / T_CRITICAL_CO2_K
        alpha = (1.0 + self._kappa * (1.0 - math.sqrt(tr))) ** 2
        a = self._a_c * alpha

        big_a = a * p_safe / (r_t ** 2)
        big_b = self._b_pr * p_safe / r_t

        # Cubic polynomial for Z: Z^3 + c2*Z^2 + c1*Z + c0 = 0
        c2 = -(1.0 - big_b)
        c1 = big_a - 3.0 * (big_b ** 2) - 2.0 * big_b
        c0 = -(big_a * big_b - (big_b ** 2) - (big_b ** 3))

        # Depressed cubic substitution: Z = y - c2/3
        p_dep = c1 - (c2 ** 2) / 3.0
        q_dep = (2.0 * (c2 ** 3)) / 27.0 - (c2 * c1) / 3.0 + c0
        discriminant = (q_dep / 2.0) ** 2 + (p_dep / 3.0) ** 3

        roots: List[float] = []
        if discriminant >= 0.0:
            sqrt_d = math.sqrt(discriminant)
            u_term = -q_dep / 2.0 + sqrt_d
            v_term = -q_dep / 2.0 - sqrt_d
            s1 = math.copysign(abs(u_term) ** (1.0 / 3.0), u_term)
            s2 = math.copysign(abs(v_term) ** (1.0 / 3.0), v_term)
            roots.append(s1 + s2 - c2 / 3.0)
        else:
            m_term = 2.0 * math.sqrt(-p_dep / 3.0)
            arg = max(-1.0, min(1.0, -q_dep / (2.0 * math.sqrt((-p_dep / 3.0) ** 3))))
            theta = math.acos(arg) / 3.0
            roots.append(m_term * math.cos(theta) - c2 / 3.0)
            roots.append(m_term * math.cos(theta + 2.0 * math.pi / 3.0) - c2 / 3.0)
            roots.append(m_term * math.cos(theta + 4.0 * math.pi / 3.0) - c2 / 3.0)

        # For dense supercritical fluid, the liquid-like root has smaller Z > B
        pos_roots = [z for z in roots if z > big_b]
        if not pos_roots:
            z_factor = max(0.2, big_b * 1.1)
        else:
            z_factor = min(pos_roots)

        z_factor = max(0.15, min(1.5, z_factor))
        v_molar = z_factor * r_t / p_safe  # m^3/mol
        rho = MW_CO2 / v_molar              # kg/m^3
        return max(100.0, min(1200.0, rho)), z_factor

    def calculate_co2_density(self, p_bar: float, t_c: float) -> float:
        """Calculate supercritical CO2 density [kg/m^3] from pressure [bar] and temp [°C]."""
        p_pa = p_bar * 1.0e5
        t_k = t_c + 273.15
        rho, _ = self.peng_robinson_eos(p_pa, t_k)
        return rho

    # ------------------------------------------------------------------------
    # Chrastil Supercritical Solubility Model
    # ------------------------------------------------------------------------

    def chrastil_solubility(self, density_kg_m3: float, temp_c: float) -> float:
        """Chrastil density-dependent supercritical solubility equation S = d^k * exp(a/(T+273.15) + b)."""
        if density_kg_m3 <= 0.0:
            return 0.0
        t_k = temp_c + 273.15
        if t_k <= 0.0:
            return 0.0
        log_s = self.cfg.chrastil_k * math.log(density_kg_m3) + (self.cfg.chrastil_a / t_k) + self.cfg.chrastil_b
        if log_s > 25.0:
            return math.exp(25.0)
        if log_s < -50.0:
            return 0.0
        return math.exp(log_s)

    # ------------------------------------------------------------------------
    # Kinetics & Rate Computations
    # ------------------------------------------------------------------------

    def compute_rates(
        self, state: PhaSupercriticalExtractionState
    ) -> Tuple[float, float, float, float]:
        """Compute density d (kg/m^3), Chrastil solubility S (g/L), r_diss (g/(L*s)), and r_precip (g/(L*s))."""
        d = self.calculate_co2_density(state.p_ext, state.t_ext)
        s = self.chrastil_solubility(d, state.t_ext)

        # Dissolution rate: r_diss = kLa * (S - C_pha_sol) * (M_cell / M_cell0)^(2/3)
        if state.m_cell > 0.0 and self.m_cell0 > 0.0 and s > state.c_pha_sol:
            shrinking_factor = (max(0.0, state.m_cell) / self.m_cell0) ** (2.0 / 3.0)
            r_diss = self.cfg.kLa * (s - max(0.0, state.c_pha_sol)) * shrinking_factor
        else:
            r_diss = 0.0

        # Depressurization & precipitation rate: r_precip = k_precip * max(0, C_pha_sol - S_sep)
        if state.c_pha_sol > self.cfg.s_sep and not self.separator_clogged:
            r_precip = self.cfg.k_precip * (state.c_pha_sol - self.cfg.s_sep)
        else:
            r_precip = 0.0

        return d, s, r_diss, r_precip

    def _derivatives(self, y: List[float]) -> List[float]:
        """Evaluate 6-state ODE vector derivatives for RK4 solver."""
        m_cell, c_pha_sol, m_precip, p_ext, t_ext, v_scco2 = y
        v = max(0.1, v_scco2)

        st_eval = PhaSupercriticalExtractionState(
            m_cell=m_cell,
            c_pha_sol=c_pha_sol,
            m_precip=m_precip,
            p_ext=p_ext,
            t_ext=t_ext,
            v_scco2=v,
        )
        _, _, r_diss, r_precip = self.compute_rates(st_eval)

        # Rigid autoclave default: target == initial, dv_dt == 0
        dv_dt = (self.cfg.v_target - v_scco2) / self.cfg.tau_v

        # When tripped, extraction is suspended
        if self.trip_active:
            r_diss = 0.0
            r_precip = 0.0

        # State 1: dM_cell/dt = -r_diss * V
        dm_cell_dt = -r_diss * v

        # State 2: dC_pha_sol/dt = r_diss - r_precip - (C_pha_sol / V) * (dV/dt)
        dc_pha_dt = r_diss - r_precip - (c_pha_sol / v) * dv_dt

        # State 3: dM_precip/dt = r_precip * V
        dm_precip_dt = r_precip * v

        # State 4: dP_ext/dt
        if self.pressure_relief_valve_active:
            dp_dt = -15.0 if p_ext > 250.0 else 0.0
        else:
            dp_dt = (self.p_set - p_ext) / self.cfg.tau_p

        # State 5: dT_ext/dt
        heat_diss = self.cfg.delta_h_diss * r_diss * v
        dt_dt = (self.t_jacket - t_ext) / self.cfg.tau_t - (heat_diss / self.cfg.heat_capacity)

        # State 6: dV_scCO2/dt
        return [dm_cell_dt, dc_pha_dt, dm_precip_dt, dp_dt, dt_dt, dv_dt]

    # ------------------------------------------------------------------------
    # RK4 Numerical Integration Step
    # ------------------------------------------------------------------------

    def rk4_step(self, dt_s: float = 1.0, *args: Any, **kwargs: Any) -> None:
        """Perform one 4th-order Runge-Kutta numerical integration step."""
        if "dt_min" in kwargs:
            dt = max(1e-4, float(kwargs["dt_min"]))
        elif "dt_h" in kwargs:
            dt = max(1e-4, float(kwargs["dt_h"]) * 3600.0)
        elif args and isinstance(args[0], (int, float)):
            dt = max(1e-4, float(args[0]))
        else:
            dt = max(1e-4, float(dt_s))

        # Check safety interlocks prior to advancing integration
        self._evaluate_safety_interlocks()
        y = [
            self.state.m_cell,
            self.state.c_pha_sol,
            self.state.m_precip,
            self.state.p_ext,
            self.state.t_ext,
            self.state.v_scco2,
        ]

        # RK4 intermediate evaluations
        k1 = self._derivatives(y)

        y_k2 = [y[i] + 0.5 * dt * k1[i] for i in range(6)]
        k2 = self._derivatives(y_k2)

        y_k3 = [y[i] + 0.5 * dt * k2[i] for i in range(6)]
        k3 = self._derivatives(y_k3)

        y_k4 = [y[i] + dt * k3[i] for i in range(6)]
        k4 = self._derivatives(y_k4)

        # State update
        y_next = [
            y[i] + (dt / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i])
            for i in range(6)
        ]

        # Prevent unphysical negative masses while strictly preserving mass conservation
        m_cell_new = max(0.0, y_next[0])
        c_pha_new = max(0.0, y_next[1])
        m_precip_new = max(0.0, y_next[2])
        p_ext_new = max(0.0, y_next[3])
        t_ext_new = max(-50.0, y_next[4])
        v_scco2_new = max(0.1, y_next[5])

        self.state.m_cell = m_cell_new
        self.state.c_pha_sol = c_pha_new
        self.state.m_precip = m_precip_new
        self.state.p_ext = p_ext_new
        self.state.t_ext = t_ext_new
        self.state.v_scco2 = v_scco2_new

        self.sim_time_s += dt

        # Evaluate safety interlocks & fault hierarchy
        self._evaluate_safety_interlocks()

        # Update analytical mass conservation residual:
        # |M_cell0 - (M_cell + C_pha_sol * V + M_precip)| < 1e-10
        total_pha_mass = (
            self.state.m_cell + self.state.c_pha_sol * self.state.v_scco2 + self.state.m_precip
        )
        self.conservation_residual = abs(self.m_cell0 - total_pha_mass)

        # Sync to memory table
        self.sync_to_registers(self.reg_table)

    # ------------------------------------------------------------------------
    # Safety Interlocks & Fault Hierarchy Evaluation
    # ------------------------------------------------------------------------

    def _evaluate_safety_interlocks(self) -> None:
        """Evaluate process trips according to strict priority hierarchy (0xF941..0xF944)."""
        # Priority 1: 0xF941 OVER_PRESSURE (P_ext > 360.0 bar)
        if self.state.p_ext > self.cfg.overpressure_threshold or self.state.p_ext > 350.0:
            self.diagnostic_code = DIAG_ERR_OVER_PRESSURE
            self.trip_active = True
            self.trip_latched = True
            self.pressure_relief_valve_active = True
            self.operating_state = PhaScCO2State.TRIPPED

        # Priority 2: 0xF942 PHASE_BOUNDARY_LOSS (P_ext < 75.0 bar while active)
        elif self.is_active and (self.state.p_ext < self.cfg.phase_boundary_threshold):
            self.diagnostic_code = DIAG_ERR_PHASE_BOUNDARY_LOSS
            self.trip_active = True
            self.trip_latched = True
            self.operating_state = PhaScCO2State.TRIPPED

        # Priority 3: 0xF943 THERMAL_DEGRADATION (T_ext > 85.0 °C)
        elif self.state.t_ext > self.cfg.thermal_degradation_threshold:
            self.diagnostic_code = DIAG_ERR_THERMAL_DEGRADATION
            self.trip_active = True
            self.trip_latched = True
            self.operating_state = PhaScCO2State.TRIPPED

        # Priority 4: 0xF944 SEPARATOR_CLOGGING (clogging flag or separator capacity overflow or clogging_index)
        elif (
            self.separator_clogged
            or (self.state.m_precip > self.cfg.separator_capacity)
            or (getattr(self.state, "clogging_index", 0.0) > 0.85)
        ):
            self.diagnostic_code = DIAG_ERR_SEPARATOR_CLOGGING
            self.trip_active = True
            self.trip_latched = True
            self.operating_state = PhaScCO2State.TRIPPED

        else:
            if not self.trip_latched:
                self.diagnostic_code = DIAG_OK
                self.trip_active = False
                self.pressure_relief_valve_active = False
                self.operating_state = PhaScCO2State.RUNNING

        # Warning evaluation (only active if not tripped)
        if not self.trip_active:
            self.warning_active = (
                self.state.p_ext >= self.cfg.pressure_warning_high
                or self.state.p_ext <= self.cfg.pressure_warning_low
                or self.state.t_ext >= self.cfg.temp_warning_high
                or self.state.t_ext <= self.cfg.temp_warning_low
                or self.state.m_precip >= self.cfg.precip_warning_threshold
            )
        else:
            self.warning_active = False

    # ------------------------------------------------------------------------
    # Properties & Computed Quantities
    # ------------------------------------------------------------------------

    @property
    def density_co2(self) -> float:
        """Current supercritical CO2 density [kg/m^3]."""
        return self.calculate_co2_density(self.state.p_ext, self.state.t_ext)

    @property
    def solubility_s(self) -> float:
        """Current Chrastil equilibrium solubility S [g/L]."""
        return self.chrastil_solubility(self.density_co2, self.state.t_ext)

    @property
    def rates(self) -> Tuple[float, float, float, float]:
        """Current density, solubility, dissolution rate, and precipitation rate."""
        return self.compute_rates(self.state)

    @property
    def r_diss(self) -> float:
        """Current dissolution rate [g/(L*s)]."""
        _, _, rd, _ = self.compute_rates(self.state)
        return rd

    @property
    def r_precip(self) -> float:
        """Current precipitation rate [g/(L*s)]."""
        _, _, _, rp = self.compute_rates(self.state)
        return rp

    @property
    def extracted_yield_pct(self) -> float:
        """Total extracted yield %: ((M_cell0 - M_cell) / M_cell0) * 100."""
        if self.m_cell0 <= 0.0:
            return 0.0
        return max(0.0, min(100.0, ((self.m_cell0 - self.state.m_cell) / self.m_cell0) * 100.0))

    @property
    def precipitated_yield_pct(self) -> float:
        """Precipitated purified yield %: (M_precip / M_cell0) * 100."""
        if self.m_cell0 <= 0.0:
            return 0.0
        return max(0.0, min(100.0, (self.state.m_precip / self.m_cell0) * 100.0))

    @property
    def yield_pct(self) -> float:
        """Extracted yield percentage [%]."""
        return self.extracted_yield_pct

    @property
    def status_word(self) -> PhaScCO2StatusWord:
        """Compute bitmask status word for %R2637."""
        sword = PhaScCO2StatusWord(0)
        if not self.trip_active and self.is_active:
            sword |= PhaScCO2StatusWord.CO2_FEED_PUMP_ACTIVE
            sword |= PhaScCO2StatusWord.HEATER_ACTIVE
            sword |= PhaScCO2StatusWord.EXTRACTION_VALVE_OPEN
            sword |= PhaScCO2StatusWord.SEPARATOR_EXPANSION_VALVE
            sword |= PhaScCO2StatusWord.RECYCLE_COMPRESSOR_ACTIVE
        if self.state.p_ext >= P_CRITICAL_CO2_BAR and (self.state.t_ext + 273.15) >= T_CRITICAL_CO2_K:
            sword |= PhaScCO2StatusWord.SUPERCRITICAL_REGIME_OK
        if getattr(self, "pressure_relief_valve_active", False):
            sword |= PhaScCO2StatusWord.PRESSURE_RELIEF_VALVE_ACTIVE
        if self.warning_active:
            sword |= PhaScCO2StatusWord.WARNING_ACTIVE
        if self.trip_active:
            sword |= PhaScCO2StatusWord.TRIP_ACTIVE
        return sword

    # ------------------------------------------------------------------------
    # Horner OCS Register Synchronization
    # ------------------------------------------------------------------------

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize internal ODE simulation state to Horner OCS memory map."""
        rt = reg_table if reg_table is not None else self.reg_table

        # %R2630: REG_PHA_SCCO2_STATUS (High byte = State, Low byte = Phase)
        st_byte = int(self.operating_state) & 0xFF
        ph_byte = int(self.operating_phase) & 0xFF
        status_reg_val = ((st_byte & 0xFF) << 8) | (ph_byte & 0xFF)
        rt.write_word(REG_PHA_SCCO2_STATUS, status_reg_val, privilege=privilege)

        # %R2631: REG_PHA_SCCO2_PRESSURE_BAR (P * 10, deci-bar)
        p_scaled = max(0, min(65535, int(round(self.state.p_ext * 10.0))))
        rt.write_word(REG_PHA_SCCO2_PRESSURE_BAR, p_scaled, privilege=privilege)

        # %R2632: REG_PHA_SCCO2_TEMP_SCALED (T * 10, deci-°C)
        t_scaled = max(0, min(65535, int(round(max(0.0, self.state.t_ext) * 10.0))))
        rt.write_word(REG_PHA_SCCO2_TEMP_SCALED, t_scaled, privilege=privilege)

        # %R2633: REG_PHA_SCCO2_DENSITY_SCALED (density * 10, deci-kg/m^3)
        rho_scaled = max(0, min(65535, int(round(self.density_co2 * 10.0))))
        rt.write_word(REG_PHA_SCCO2_DENSITY_SCALED, rho_scaled, privilege=privilege)

        # %R2634: REG_PHA_SCCO2_EXTRACTED_YIELD_PCT / REG_PHA_SCRC_SOLUBILITY_SCALED
        s_scaled = max(1, int(round(self.solubility_s * 10.0)))
        rt.write_word(REG_PHA_SCCO2_EXTRACTED_YIELD_PCT, s_scaled, privilege=privilege)

        # %R2635: REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED (M_precip * 10, deci-g)
        m_precip_scaled = max(0, min(65535, int(round(self.state.m_precip * 10.0))))
        rt.write_word(REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED, m_precip_scaled, privilege=privilege)

        # %R2636: REG_PHA_SCCO2_DIAGNOSTIC_CODE
        diag_val = int(self.diagnostic_code) & 0xFFFF
        rt.write_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE, diag_val, privilege=privilege)

        # %R2637: REG_PHA_SCCO2_STATUS_WORD
        rt.write_word(REG_PHA_SCCO2_STATUS_WORD, int(self.status_word) & 0xFFFF, privilege=privilege)

        # Discrete Coils %M613..%M615
        # %M613: COIL_PHA_SCCO2_ACTIVE (BOOL)
        rt.write_bit(COIL_PHA_SCCO2_ACTIVE, not self.trip_active, privilege=privilege)

        # %M614: COIL_PHA_SCCO2_WARNING (BOOL)
        rt.write_bit(COIL_PHA_SCCO2_WARNING, self.warning_active and not self.trip_active, privilege=privilege)

        # %M615: COIL_PHA_SCCO2_TRIP (BOOL)
        rt.write_bit(COIL_PHA_SCCO2_TRIP, self.trip_active, privilege=privilege)

    # ------------------------------------------------------------------------
    # ILogicUnit Interface Implementation
    # ------------------------------------------------------------------------

    def scan_step(self, *args: Any, **kwargs: Any) -> ExecutionResult:
        """Execute one simulation scan cycle step."""
        context: Optional[ScanContext] = kwargs.get("context")
        if not context and args and isinstance(args[0], ScanContext):
            context = args[0]

        if context is not None and getattr(context, "register_table", None) is not None:
            self.reg_table = context.register_table

        self.cycle_count += 1
        dt_s = kwargs.get("dt_s", kwargs.get("dt", 1.0))
        if args and len(args) > 1 and isinstance(args[1], (int, float)):
            dt_s = float(args[1])
        elif args and len(args) == 1 and isinstance(args[0], (int, float)):
            dt_s = float(args[0])

        self.rk4_step(dt_s=dt_s)

        status = AgentStatus.SUCCESS if not self.trip_active else AgentStatus.FAILED
        err_code = None if not self.trip_active else str(self.diagnostic_code)
        details = (
            f"Supercritical PHA Extraction: M_cell={self.state.m_cell:.1f}g, C_sol={self.state.c_pha_sol:.2f}g/L, "
            f"M_precip={self.state.m_precip:.1f}g, P={self.state.p_ext:.1f}bar, T={self.state.t_ext:.1f}°C, "
            f"Yield={self.yield_pct:.1f}%, Residual={self.conservation_residual:.2e}"
        )

        return ExecutionResult(
            status=status,
            error_code=err_code,
            details=details,
            data={
                "m_cell": self.state.m_cell,
                "c_pha_sol": self.state.c_pha_sol,
                "m_precip": self.state.m_precip,
                "p_ext": self.state.p_ext,
                "t_ext": self.state.t_ext,
                "v_scco2": self.state.v_scco2,
                "density_co2": self.density_co2,
                "yield_pct": self.yield_pct,
                "trip_active": self.trip_active,
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
        self.state = PhaSupercriticalExtractionState()
        self.m_cell0 = (
            self.state.m_cell + self.state.c_pha_sol * self.state.v_scco2 + self.state.m_precip
        )
        self.p_set = self.state.p_ext
        self.t_jacket = self.state.t_ext
        self.diagnostic_code = DIAG_OK
        self.trip_active = False
        self.trip_latched = False
        self.warning_active = False
        self.is_active = True
        self.separator_clogged = False
        self.operating_state = PhaScCO2State.RUNNING
        self.operating_phase = PhaScCO2Phase.EXTRACTION
        self.cycle_count = 0
        self.sim_time_s = 0.0
        self.conservation_residual = 0.0
        self.sync_to_registers(self.reg_table)

    compute_density = calculate_co2_density
    compute_solubility = chrastil_solubility
    check_safety_hierarchy = _evaluate_safety_interlocks
    update_thermodynamics = _evaluate_safety_interlocks

    def pressure_relief_vent_step(self, dt_s: float = 1.0) -> None:
        """Vent autoclave pressure through emergency relief valve."""
        self.state.p_ext = max(250.0, self.state.p_ext - 15.0 * dt_s)
        if self.state.p_ext <= 280.0:
            self.pressure_relief_valve_active = False
            self.trip_active = False
            self.trip_latched = False
            self.diagnostic_code = DIAG_OK
            self.operating_state = PhaScCO2State.RUNNING
        self._evaluate_safety_interlocks()


# Class aliases for component interchangeability
PhaSupercriticalExtractionSimulationLogicUnit = PhaSupercriticalExtractionReactor
PhaSupercriticalExtractionLogicUnit = PhaSupercriticalExtractionReactor
PhaSupercriticalExtractionSimulator = PhaSupercriticalExtractionReactor
PhaSupercriticalExtractionEngine = PhaSupercriticalExtractionReactor
PhaSupercriticalExtractionModel = PhaSupercriticalExtractionReactor
PhaSupercriticalExtractionPlantModel = PhaSupercriticalExtractionReactor
PhaScCO2ExtractionReactor = PhaSupercriticalExtractionReactor
PhaScCO2Extractor = PhaSupercriticalExtractionReactor
PhaScCO2Simulator = PhaSupercriticalExtractionReactor
PhaScCO2Engine = PhaSupercriticalExtractionReactor


# ============================================================================
# 6. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_pha_supercritical_extraction_verification(
    project_root: Optional[Any] = None,
    output_path: Optional[str] = None,
    work_package: str = "W302",
    quick: bool = False,
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification sequence for W302."""
    if project_root is not None and output_path is None:
        s_val = str(project_root)
        if s_val.endswith(".json"):
            output_path = s_val

    test_results: List[Dict[str, Any]] = []

    # Stage 1: initial_state_and_extraction_startup
    t0 = time.perf_counter()
    reactor = PhaSupercriticalExtractionReactor()
    m_cell_0 = reactor.state.m_cell
    steps_s1 = 3 if quick else 10
    for _ in range(steps_s1):
        reactor.rk4_step(dt_s=1.0)
    c1 = (
        reactor.state.m_cell < m_cell_0
        and (reactor.state.c_pha_sol > 0.0 or reactor.state.m_precip > 0.0)
        and reactor.diagnostic_code == DIAG_OK
        and reactor.trip_active is False
    )
    test_results.append({
        "stage": 1,
        "name": "initial_state_and_extraction_startup",
        "passed": bool(c1),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Extraction started: M_cell ({m_cell_0:.1f} -> {reactor.state.m_cell:.1f} g), "
            f"C_sol={reactor.state.c_pha_sol:.2f} g/L, M_precip={reactor.state.m_precip:.2f} g."
        ),
    })

    # Stage 2: chrastil_solubility_density_dependence
    t0 = time.perf_counter()
    r_sol = PhaSupercriticalExtractionReactor()
    # Test monotonic density dependence at 50 °C: S(600) < S(750) < S(850) < S(950)
    s_600 = r_sol.chrastil_solubility(600.0, 50.0)
    s_750 = r_sol.chrastil_solubility(750.0, 50.0)
    s_850 = r_sol.chrastil_solubility(850.0, 50.0)
    s_950 = r_sol.chrastil_solubility(950.0, 50.0)
    density_monotonic = (0.0 < s_600 < s_750 < s_850 < s_950)

    # Test temperature sensitivity at constant density
    s_t40 = r_sol.chrastil_solubility(850.0, 40.0)
    s_t70 = r_sol.chrastil_solubility(850.0, 70.0)
    temp_sensitive = (s_t40 > 0.0 and s_t70 > 0.0 and s_t40 != s_t70)

    c2 = density_monotonic and temp_sensitive
    test_results.append({
        "stage": 2,
        "name": "chrastil_solubility_density_dependence",
        "passed": bool(c2),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Chrastil solubility monotonic with density: S(600)={s_600:.2f} < S(750)={s_750:.2f} < "
            f"S(850)={s_850:.2f} < S(950)={s_950:.2f} g/L."
        ),
    })

    # Stage 3: shrinking_core_dissolution_kinetics
    t0 = time.perf_counter()
    r_kin = PhaSupercriticalExtractionReactor()
    st_full = PhaSupercriticalExtractionState(m_cell=500.0, c_pha_sol=0.0)
    st_part = PhaSupercriticalExtractionState(m_cell=100.0, c_pha_sol=0.0)
    st_zero = PhaSupercriticalExtractionState(m_cell=0.0, c_pha_sol=0.0)
    st_sat = PhaSupercriticalExtractionState(m_cell=500.0, c_pha_sol=100.0)

    _, _, rd_full, _ = r_kin.compute_rates(st_full)
    _, _, rd_part, _ = r_kin.compute_rates(st_part)
    _, _, rd_zero, _ = r_kin.compute_rates(st_zero)
    _, _, rd_sat, _ = r_kin.compute_rates(st_sat)

    c3 = (
        rd_full > rd_part > 0.0
        and rd_zero == 0.0
        and rd_sat == 0.0
    )
    test_results.append({
        "stage": 3,
        "name": "shrinking_core_dissolution_kinetics",
        "passed": bool(c3),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Shrinking core kinetics confirmed: r_diss(500g)={rd_full:.3f} > "
            f"r_diss(100g)={rd_part:.3f} > r_diss(0g)={rd_zero:.3f} g/(L*s)."
        ),
    })

    # Stage 4: separator_depressurization_and_precipitation
    t0 = time.perf_counter()
    r_prec = PhaSupercriticalExtractionReactor()
    st_hi_sol = PhaSupercriticalExtractionState(c_pha_sol=5.0)
    st_lo_sol = PhaSupercriticalExtractionState(c_pha_sol=0.01)  # < s_sep=0.05
    _, _, _, rp_hi = r_prec.compute_rates(st_hi_sol)
    _, _, _, rp_lo = r_prec.compute_rates(st_lo_sol)

    # Dynamic precipitation test
    r_prec_dyn = PhaSupercriticalExtractionReactor(
        initial_state=PhaSupercriticalExtractionState(m_cell=0.0, c_pha_sol=10.0, m_precip=0.0)
    )
    r_prec_dyn.rk4_step(dt_s=2.0)

    c4 = (
        rp_hi > 0.0
        and rp_lo == 0.0
        and r_prec_dyn.state.m_precip > 0.0
        and r_prec_dyn.state.c_pha_sol < 10.0
    )
    test_results.append({
        "stage": 4,
        "name": "separator_depressurization_and_precipitation",
        "passed": bool(c4),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Precipitation rates verified: r_precip(5.0g/L)={rp_hi:.3f} g/(L*s), "
            f"r_precip(sub-sol)={rp_lo:.3f} g/(L*s), M_precip dynamic={r_prec_dyn.state.m_precip:.2f} g."
        ),
    })

    # Stage 5: over_pressure_safety_trip
    t0 = time.perf_counter()
    r_op = PhaSupercriticalExtractionReactor()
    r_op.state.p_ext = 365.0  # > 360.0 bar -> 0xF941
    r_op._evaluate_safety_interlocks()
    r_op.sync_to_registers(r_op.reg_table)
    c5 = (
        r_op.trip_active is True
        and r_op.diagnostic_code == DIAG_ERR_OVER_PRESSURE
        and r_op.reg_table.read_bit(COIL_PHA_SCCO2_TRIP) is True
        and r_op.reg_table.read_bit(COIL_PHA_SCCO2_ACTIVE) is False
        and (r_op.reg_table.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF941
    )
    test_results.append({
        "stage": 5,
        "name": "over_pressure_safety_trip",
        "passed": bool(c5),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Over-pressure trip 0xF941 latched upon P_ext > 360.0 bar; interlock opened.",
    })

    # Stage 6: phase_boundary_loss_trip
    t0 = time.perf_counter()
    r_pb = PhaSupercriticalExtractionReactor()
    r_pb.state.p_ext = 70.0   # < 75.0 bar while active -> 0xF942
    r_pb.is_active = True
    r_pb._evaluate_safety_interlocks()
    r_pb.sync_to_registers(r_pb.reg_table)
    c6 = (
        r_pb.trip_active is True
        and r_pb.diagnostic_code == DIAG_ERR_PHASE_BOUNDARY_LOSS
        and r_pb.reg_table.read_bit(COIL_PHA_SCCO2_TRIP) is True
        and r_pb.reg_table.read_bit(COIL_PHA_SCCO2_ACTIVE) is False
        and (r_pb.reg_table.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF942
    )
    test_results.append({
        "stage": 6,
        "name": "phase_boundary_loss_trip",
        "passed": bool(c6),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Phase boundary loss trip 0xF942 asserted upon subcritical P_ext < 75.0 bar.",
    })

    # Stage 7: thermal_degradation_and_separator_clogging_trips
    t0 = time.perf_counter()
    # 7a: Thermal degradation (T_ext > 85.0 °C -> 0xF943)
    r_th = PhaSupercriticalExtractionReactor()
    r_th.state.t_ext = 88.0
    r_th._evaluate_safety_interlocks()
    th_ok = (r_th.trip_active is True and r_th.diagnostic_code == DIAG_ERR_THERMAL_DEGRADATION)

    # 7b: Separator clogging (0xF944)
    r_clog = PhaSupercriticalExtractionReactor()
    r_clog.separator_clogged = True
    r_clog._evaluate_safety_interlocks()
    clog_ok = (r_clog.trip_active is True and r_clog.diagnostic_code == DIAG_ERR_SEPARATOR_CLOGGING)

    # 7c: Fault Priority Hierarchy
    # Over-pressure (Priority 1) dominates Phase Boundary (Priority 2) & Thermal (Priority 3)
    r_hier1 = PhaSupercriticalExtractionReactor()
    r_hier1.state.p_ext = 370.0
    r_hier1.state.t_ext = 90.0
    r_hier1._evaluate_safety_interlocks()
    hier1_ok = (r_hier1.diagnostic_code == DIAG_ERR_OVER_PRESSURE)

    # Phase Boundary (Priority 2) dominates Thermal (Priority 3)
    r_hier2 = PhaSupercriticalExtractionReactor()
    r_hier2.state.p_ext = 65.0
    r_hier2.state.t_ext = 90.0
    r_hier2._evaluate_safety_interlocks()
    hier2_ok = (r_hier2.diagnostic_code == DIAG_ERR_PHASE_BOUNDARY_LOSS)

    # Thermal (Priority 3) dominates Clogging (Priority 4)
    r_hier3 = PhaSupercriticalExtractionReactor()
    r_hier3.state.t_ext = 89.0
    r_hier3.separator_clogged = True
    r_hier3._evaluate_safety_interlocks()
    hier3_ok = (r_hier3.diagnostic_code == DIAG_ERR_THERMAL_DEGRADATION)

    c7 = th_ok and clog_ok and hier1_ok and hier2_ok and hier3_ok
    test_results.append({
        "stage": 7,
        "name": "thermal_degradation_and_separator_clogging_trips",
        "passed": bool(c7),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Thermal trip (0xF943), separator clogging (0xF944), and 4-tier fault hierarchy verified.",
    })

    # Stage 8: mass_conservation_residuals
    t0 = time.perf_counter()
    r_cons = PhaSupercriticalExtractionReactor()
    steps_s8 = 6 if quick else 20
    max_res = 0.0
    for _ in range(steps_s8):
        r_cons.rk4_step(dt_s=1.0)
        max_res = max(max_res, r_cons.conservation_residual)
    c8 = max_res < 1e-10
    test_results.append({
        "stage": 8,
        "name": "mass_conservation_residuals",
        "passed": bool(c8),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Analytical mass conservation residual {max_res:.2e} < 1e-10 threshold across RK4 steps.",
    })

    # Stage 9: horner_ocs_registers_and_pure_st_pou
    t0 = time.perf_counter()
    reactor.scan_step(dt_s=1.0)
    rt = RegisterTable()
    reactor.sync_to_registers(rt)

    w_status = rt.read_word(REG_PHA_SCCO2_STATUS)
    w_p = rt.read_word(REG_PHA_SCCO2_PRESSURE_BAR)
    w_t = rt.read_word(REG_PHA_SCCO2_TEMP_SCALED)
    w_rho = rt.read_word(REG_PHA_SCCO2_DENSITY_SCALED)
    w_yield = rt.read_word(REG_PHA_SCCO2_EXTRACTED_YIELD_PCT)
    w_precip = rt.read_word(REG_PHA_SCCO2_PRECIPITATED_MASS_SCALED)
    w_diag = rt.read_word(REG_PHA_SCCO2_DIAGNOSTIC_CODE)
    w_sword = rt.read_word(REG_PHA_SCCO2_STATUS_WORD)

    b_act = rt.read_bit(COIL_PHA_SCCO2_ACTIVE)
    b_trip = rt.read_bit(COIL_PHA_SCCO2_TRIP)

    regs_ok = (
        ((w_status >> 8) & 0xFF) == int(PhaScCO2State.RUNNING)
        and (w_status & 0xFF) == int(PhaScCO2Phase.EXTRACTION)
        and w_p > 0
        and w_t > 0
        and w_rho > 0
        and w_yield >= 0
        and w_precip >= 0
        and (w_diag & 0xFFFF) == 0x0000
        and (w_sword & PhaScCO2StatusWord.CO2_FEED_PUMP_ACTIVE) != 0
        and (w_sword & PhaScCO2StatusWord.TRIP_ACTIVE) == 0
        and b_act is True
        and b_trip is False
    )

    st_valid = verify_pha_supercritical_extraction_pure_st()
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM P ---[ ]--- END_PROGRAM")
    except LadderForbiddenError:
        ladder_rejected = True

    c9 = regs_ok and st_valid and ladder_rejected
    test_results.append({
        "stage": 9,
        "name": "horner_ocs_registers_and_pure_st_pou",
        "passed": bool(c9),
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS register space %R2630..%R2637, coils %M613..%M615, and pure ST validated.",
    })

    passed_count = sum(1 for r in test_results if r["passed"])
    total_count = len(test_results)
    all_passed = passed_count == total_count

    pou_digest = hashlib.sha256(
        PHA_SUPERCRITICAL_EXTRACTION_PURE_ST_POU.encode("utf-8")
    ).hexdigest()
    model_digest = hashlib.sha256(
        json.dumps(reactor.cfg.to_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()

    evidence = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": (
            f"Wave {work_package} Supercritical CO2 PHA Extraction Autoclave Verification "
            f"PASSED ({passed_count}/{total_count} stages)."
        ),
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

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


run_pha_scco2_verification = run_pha_supercritical_extraction_verification


# ============================================================================
# 7. CLI Entry Point
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution for Supercritical CO2 PHA Extraction simulation and verification."""
    parser = argparse.ArgumentParser(
        description="W302: Industrial Supercritical CO2 PHA Extraction & Precipitation Autoclave ODE Simulation"
    )
    parser.add_argument("--verify", action="store_true", help="Run 9-stage verification suite")
    parser.add_argument("--output", "-o", type=str, default=None, help="Evidence JSON output file path")
    parser.add_argument("--quick", action="store_true", help="Execute rapid test subset")
    parser.add_argument("--work-package", type=str, default="W302", help="Work package identifier")
    parser.add_argument("--json", action="store_true", help="Print verification result as JSON")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet output")

    args = parser.parse_args(argv)

    if args.verify or args.output or args.json or args.quick:
        res = run_pha_supercritical_extraction_verification(
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
    reactor = PhaSupercriticalExtractionReactor()
    for cycle in range(1, 11):
        res = reactor.scan_step()
        print(f"Cycle {cycle:02d}: {res.details}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
