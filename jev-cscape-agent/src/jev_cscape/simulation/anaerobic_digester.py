"""Industrial Anaerobic Digester & Biogas Methanogenesis Dynamics ODE Simulation.

Work Package: W122 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Anaerobic Digester & Methanogenesis Physical & Biochemical Dynamics:
   - Non-linear coupled 6-state dynamic ODE model:
     * S_su: Soluble substrate / COD (g COD/m3)
     * S_vfa: Volatile fatty acids (g COD/m3 = mg/L as acetate equiv)
     * X_ac: Methanogenic biomass (g COD/m3)
     * S_co2: Dissolved carbon dioxide (g/m3)
     * S_ch4: Dissolved methane (g/m3)
     * P_gas: Headspace biogas gauge pressure (mbar)
   - Biological reaction kinetics:
     * Monod substrate utilization: r_su = k_m,su * (S_su / (K_s,su + S_su)) * X_su * f(T)
     * Andrews volatile fatty acid substrate inhibition:
       mu_ac = mu_max,ac * f(T) * I_pH * (S_vfa / (K_s,vfa + S_vfa + (S_vfa^2 / K_i,vfa)))
       Halts methanogenesis at high VFA / sour digester when S_vfa > 4000 mg/L or pH < 6.5.
     * Temperature correction factor: Cardinal / Arrhenius curve for 35-38 °C mesophilic operation.
     * Gas-liquid mass transfer: Two-film Henry's law rate: r_T = kLa * (S_liq - K_H * P_gas).
2. Numerical Integration & Conservation:
   - High-order Runge-Kutta 4th Order (RK4) integrator with adaptive sub-stepping.
   - Analytical stoichiometric carbon mass conservation verification:
     |dM_C,in/dt - dM_C,out/dt - dM_C,acc/dt| < 1e-10 g C/s.
3. Process Safety Interlocks & Diagnostics:
   - %M193: Sour digester acidification trip (pH < 6.5 or S_vfa > 4000 mg/L) -> code 0x9301.
   - %M194: Biogas overpressure trip (P_gas > 50.0 mbar) -> code 0x9302.
   - %M195: Auto-flare command (P_gas > 35.0 mbar).
   - Washout alarm: Biomass washout (X_ac < 250 g COD/m3) -> code 0x9303.
4. Horner OCS Registers:
   - %R830: DigesterStatusWord (RUNNING, FEED_PUMP_ON, HEATING_ACTIVE, METHANOGENESIS_HEALTHY,
            SOUR_DIGESTER_TRIP, OVERPRESSURE_TRIP, FLARE_ACTIVE, WASHOUT_ALARM)
   - %R831: SubstrateCod_mg_L (scaled x1 mg COD/L)
   - %R832: VfaConcentration_mg_L (scaled x1 mg/L)
   - %R833: BiomassConcentration_mg_L (scaled x1 mg/L)
   - %R834: BiogasPressure_mbar (scaled x10 mbar, e.g. 245 = 24.5 mbar)
   - %R835: MethanePct (scaled x10 %, e.g. 645 = 64.5 %)
   - %R836: DigesterPhScaled (scaled x100 pH, e.g. 718 = 7.18)
   - %R837: DiagnosticEventCode (0x0000=OK, 0x9301, 0x9302, 0x9303)
   - %M193, %M194, %M195 discrete coils.
5. Pure IEC 61131-3 ST POU: 'AnaerobicDigesterSync' validated with SecurityGuard and STParser.
6. Deterministic 9-Stage Verification Suite returning strict 4-state contract.
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
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Enums and Status Bitmasks
# ============================================================================

class AnaerobicDigesterStatusBits(IntFlag):
    """Horner OCS %R830 DigesterStatusWord Bitmask Definitions."""
    RUNNING                     = 1 << 0  # Bit 0 (0x0001): Process simulation engine running
    FEED_PUMP_ON                = 1 << 1  # Bit 1 (0x0002): Sludge influent feed pump active
    HEATING_ACTIVE              = 1 << 2  # Bit 2 (0x0004): Heat exchanger / recirculation active
    METHANOGENESIS_HEALTHY      = 1 << 3  # Bit 3 (0x0008): Healthy methanogenesis (pH >= 6.8, VFA <= 1000 mg/L)
    SOUR_DIGESTER_TRIP          = 1 << 4  # Bit 4 (0x0010): %M193 Acidification trip (pH < 6.5 or VFA > 4000 mg/L)
    OVERPRESSURE_TRIP           = 1 << 5  # Bit 5 (0x0020): %M194 Biogas overpressure trip (P_gas > 50 mbar)
    FLARE_ACTIVE                = 1 << 6  # Bit 6 (0x0040): %M195 Auto-flare active (P_gas > 35 mbar)
    WASHOUT_ALARM               = 1 << 7  # Bit 7 (0x0080): Biomass washout alarm (X_ac < 250 mg/L)

    # Compatibility aliases
    SYSTEM_RUNNING              = RUNNING
    PUMP_ACTIVE                 = FEED_PUMP_ON
    HEATER_ACTIVE               = HEATING_ACTIVE
    HEALTHY                     = METHANOGENESIS_HEALTHY
    ACIDIFICATION_TRIP          = SOUR_DIGESTER_TRIP
    BIOGAS_TRIP                 = OVERPRESSURE_TRIP
    AUTO_FLARE                  = FLARE_ACTIVE


DigesterStatusBits = AnaerobicDigesterStatusBits
ADStatusBits = AnaerobicDigesterStatusBits


class AnaerobicDigesterDiagnosticCode(IntEnum):
    """Diagnostic event codes for %R837."""
    OK                              = 0x0000  # Normal operation
    SOUR_DIGESTER_ACIDIFICATION_TRIP = 0x9301  # %M193: pH < 6.5 or VFA > 4000 mg/L
    BIOGAS_OVERPRESSURE_TRIP        = 0x9302  # %M194: P_gas > 50.0 mbar
    BIOMASS_WASHOUT_ALARM           = 0x9303  # X_ac < 250.0 g COD/m3

    # Compatibility aliases
    ACIDIFICATION_TRIP              = SOUR_DIGESTER_ACIDIFICATION_TRIP
    OVERPRESSURE_TRIP               = BIOGAS_OVERPRESSURE_TRIP
    WASHOUT_ALARM                   = BIOMASS_WASHOUT_ALARM


DigesterDiagnosticCode = AnaerobicDigesterDiagnosticCode
ADDiagnosticCode = AnaerobicDigesterDiagnosticCode


# ============================================================================
# 2. Configuration & Parameter Data Models
# ============================================================================

@dataclass
class AnaerobicDigesterConfig:
    """Biochemical, physicochemical, thermodynamic, and vessel geometry configuration."""

    # Digester Geometry & Fluid Volumes
    v_liq_m3: float = 1500.0                   # Active liquid sludge volume [m3]
    v_gas_m3: float = 300.0                    # Biogas headspace volume [m3]
    q_feed_m3_s: float = 0.001736              # Raw sludge influent flow rate [m3/s] (~150 m3/day)
    temp_c: float = 37.0                       # Operating liquid temperature [°C]
    temp_opt_c: float = 37.0                   # Optimal mesophilic temperature [°C]
    temp_sigma_c: float = 3.5                  # Mesophilic temperature bandwidth parameter [°C]
    p_atm_mbar: float = 1013.25                # Ambient atmospheric pressure [mbar]
    r_gas: float = 8.314462618                 # Universal gas constant [J/(mol*K)]

    # Influent Feed Sludge Stream Compositions
    s_su_in_g_m3: float = 20000.0              # Influent soluble substrate COD [g COD/m3] (20 g/L)
    s_vfa_in_g_m3: float = 500.0               # Influent volatile fatty acids [g COD/m3]
    s_co2_in_g_m3: float = 50.0                # Influent dissolved CO2 [g/m3]

    # Carbon Content Conversion Factors (g C per unit mass/COD)
    c_frac_su: float = 0.375                   # Carbon fraction in soluble substrate [g C / g COD]
    c_frac_vfa: float = 0.375                  # Carbon fraction in VFA [g C / g COD] (acetate basis)
    c_frac_x: float = 0.375                    # Carbon fraction in methanogen biomass [g C / g COD]
    c_frac_co2: float = 12.011 / 44.01         # Carbon fraction in CO2 (~0.2729 g C / g CO2)
    c_frac_ch4: float = 12.011 / 16.0425       # Carbon fraction in CH4 (~0.7487 g C / g CH4)

    # Acidogenesis Kinetics (Monod Substrate Uptake)
    k_m_su: float = 2.0 / 86400.0              # Max specific substrate uptake rate [1/s] (2.0 day^-1)
    k_s_su: float = 500.0                      # Substrate half-velocity constant [g COD/m3]
    x_su_eff: float = 1200.0                   # Effective acidogenic biomass concentration [g COD/m3]
    y_vfa_su: float = 0.85                     # Yield of VFA COD from substrate COD [g COD/g COD]

    # Methanogenesis Kinetics (Andrews Substrate Inhibition)
    mu_max_ac: float = 0.35 / 86400.0          # Max specific methanogen growth rate [1/s] (0.35 day^-1)
    k_s_vfa: float = 150.0                     # VFA half-saturation constant [g COD/m3]
    k_i_vfa: float = 3500.0                    # Andrews VFA substrate inhibition constant [g COD/m3]
    y_ac: float = 0.05                         # Methanogen biomass yield [g COD X_ac / g COD VFA]
    b_ac: float = 0.02 / 86400.0               # Biomass decay rate [1/s] (0.02 day^-1)

    # pH & Inhibition Parameters
    ph_base: float = 7.35                      # Baseline neutral digester pH
    ph_buffer_k: float = 650.0                 # Bicarbonate buffer inflection parameter [mg/L VFA]
    ph_crit: float = 6.50                      # Critical acidification threshold pH
    ph_gamma: float = 3.0                      # pH inhibition steepness coefficient

    # Gas-Liquid Mass Transfer (Two-Film & Henry's Law)
    kla_ch4: float = 0.010                     # CH4 liquid-gas transfer coefficient [1/s]
    k_h_ch4: float = 0.022                     # Henry's constant for CH4 [g/(m3*mbar)] at 37 °C
    kla_co2: float = 0.0010                    # CO2 liquid-gas transfer coefficient [1/s]
    k_h_co2: float = 0.600                     # Henry's constant for CO2 [g/(m3*mbar)] at 37 °C
    mw_ch4: float = 16.0425                    # Molecular weight of methane [g/mol]
    mw_co2: float = 44.01                      # Molecular weight of carbon dioxide [g/mol]

    # Headspace Offgas Conductance & Valves
    p_setpoint_mbar: float = 20.0              # Nominal offgas regulator setpoint [mbar]
    k_valve: float = 0.005                     # Nominal biogas draw valve conductance [mol/(s*mbar)]
    k_flare: float = 0.025                     # Emergency auto-flare conductance [mol/(s*mbar)]
    k_relief: float = 0.120                    # High-pressure relief conductance [mol/(s*mbar)]

    # Safety Interlock Thresholds
    vfa_trip_mg_l: float = 4000.0              # %M193: Sour digester VFA threshold [mg/L] -> 0x9301
    ph_trip_low: float = 6.50                  # %M193: Minimum allowable digester pH -> 0x9301
    p_flare_mbar: float = 35.0                 # %M195: Auto-flare trigger pressure [mbar]
    p_trip_mbar: float = 50.0                  # %M194: Biogas overpressure trip [mbar] -> 0x9302
    biomass_washout_limit: float = 250.0       # Minimum methanogen biomass before washout alarm -> 0x9303

    @property
    def dilution_rate_s(self) -> float:
        """Hydraulic dilution rate D = Q_feed / V_liq [1/s]."""
        return self.q_feed_m3_s / max(1.0, self.v_liq_m3)


DigesterConfig = AnaerobicDigesterConfig
ADConfig = AnaerobicDigesterConfig


@dataclass
class AnaerobicDigesterState:
    """Dynamic state vector, diagnostic flags, and mass conservation tracking."""
    time_s: float = 0.0

    # Coupled 6-State ODE System State Vector y:
    s_su_g_m3: float = 1200.0                  # State 0: Soluble substrate COD [g COD/m3]
    s_vfa_g_m3: float = 350.0                  # State 1: Volatile fatty acids [g COD/m3 = mg/L]
    x_ac_g_m3: float = 1800.0                  # State 2: Methanogenic biomass [g COD/m3]
    s_co2_g_m3: float = 250.0                  # State 3: Dissolved carbon dioxide [g/m3]
    s_ch4_g_m3: float = 17.5                   # State 4: Dissolved methane [g/m3]
    p_gas_mbar: float = 24.5                   # State 5: Headspace biogas gauge pressure [mbar]

    # Diagnostic & Auxiliary Biochemical Properties
    ph: float = 7.18                           # Sump digester pH [-]
    mu_ac_rate: float = 0.0                    # Specific methanogen growth rate [1/s]
    f_temp: float = 1.0                        # Mesophilic temperature factor [-]
    i_ph: float = 1.0                          # pH inhibition multiplier [-]
    r_su_g_m3_s: float = 0.0                   # Substrate uptake rate [g COD/(m3*s)]
    r_vfa_cons_g_m3_s: float = 0.0             # VFA consumption rate [g COD/(m3*s)]
    r_t_ch4_g_m3_s: float = 0.0                # CH4 transfer rate into gas [g/(m3*s)]
    r_t_co2_g_m3_s: float = 0.0                # CO2 transfer rate into gas [g/(m3*s)]
    biogas_ch4_pct: float = 65.0               # Biogas methane content [%]
    biogas_co2_pct: float = 35.0               # Biogas CO2 content [%]
    total_gas_offtake_mol_s: float = 0.0       # Total biogas production draw-off [mol/s]

    # Operational Subsystem Actuators
    is_running: bool = False                   # Simulation running
    feed_pump_on: bool = True                  # Sludge feed pump running
    heating_active: bool = True                # Temperature control loop active
    methanogenesis_healthy: bool = True        # Methanogenic digestion healthy

    # Process Safety Interlocks & Diagnostic Codes
    acidification_trip: bool = False           # %M193: pH < 6.5 or VFA > 4000 mg/L -> 0x9301
    overpressure_trip: bool = False            # %M194: P_gas > 50.0 mbar -> 0x9302
    auto_flare_cmd: bool = False               # %M195: P_gas > 35.0 mbar flare command
    biomass_washout_alarm: bool = False        # Washout alarm (X_ac < 250 g COD/m3) -> 0x9303
    diagnostic_code: int = 0x0000              # %R837: Diagnostic event code

    # Stoichiometric Carbon Mass Balance Tracking
    carbon_in_g_s: float = 0.0                 # Total carbon entering in feed [g C/s]
    carbon_out_g_s: float = 0.0                # Total carbon exiting in liquid + offgas [g C/s]
    dcarbon_acc_dt_g_s: float = 0.0            # Net accumulation of carbon in system [g C/s]
    mass_balance_residual_g_s: float = 0.0     # Residual |In - Out - Accumulation| [g C/s]


DigesterState = AnaerobicDigesterState
ADState = AnaerobicDigesterState


# ============================================================================
# 3. Industrial Anaerobic Digester ODE Simulation Engine
# ============================================================================

class AnaerobicDigesterSimulator:
    """Coupled 6-State Industrial Anaerobic Digester ODE Simulation Engine.

    Work Package: W122 (Gate G7 / Gate G4)
    Mapped Registers: %R830..%R837, %M193..%M195.
    """

    def __init__(
        self,
        config: Optional[AnaerobicDigesterConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.config = config or AnaerobicDigesterConfig()
        self.reg_table = register_table or RegisterTable()
        self.reg_table.privilege_mode = PrivilegeMode.SYSTEM
        self.state = AnaerobicDigesterState()

        # Initial register sync
        self._evaluate_safety_interlocks()
        self._sync_registers()

    # ------------------------------------------------------------------------
    # Physics & Biochemical Kinetics
    # ------------------------------------------------------------------------

    def compute_temperature_factor(self, temp_c: Optional[float] = None) -> float:
        """Compute mesophilic temperature factor f(T) using a cardinal Gaussian curve.

        Optimum is at 37 °C (35-38 °C range). Rapidly drops outside [30, 42] °C.
        """
        t = self.config.temp_c if temp_c is None else temp_c
        if t <= 10.0 or t >= 55.0:
            return 0.0
        delta = (t - self.config.temp_opt_c) / max(0.1, self.config.temp_sigma_c)
        return float(math.exp(-(delta ** 2)))

    def compute_ph(self, s_vfa_g_m3: float) -> float:
        """Compute digester liquid pH as a function of VFA and bicarbonate buffer.

        Formulation:
            pH = pH_base - log10(1 + S_vfa / K_buffer)
        At nominal S_vfa = 350 mg/L, pH ≈ 7.18.
        At S_vfa = 4000 mg/L, pH ≈ 6.495 (< 6.50 triggers acidification trip).
        """
        vfa = max(0.0, s_vfa_g_m3)
        ph_val = self.config.ph_base - math.log10(1.0 + (vfa / max(1.0, self.config.ph_buffer_k)))
        return max(3.0, min(10.0, ph_val))

    def compute_ph_inhibition(self, ph: float) -> float:
        """Compute pH inhibition factor I_pH for methanogens.

        Formulation:
            I_pH = 1 / (1 + 10^((pH_crit - pH) * gamma))
        Near pH 7.2: I_pH ≈ 1.0.
        At pH 6.5: I_pH = 0.5.
        Below pH 6.0: I_pH < 0.05 (severe inhibition, halts methanogenesis).
        """
        exponent = (self.config.ph_crit - ph) * self.config.ph_gamma
        exponent = max(-10.0, min(10.0, exponent))
        return 1.0 / (1.0 + (10.0 ** exponent))

    def compute_monod_substrate_uptake(
        self,
        s_su_g_m3: float,
        temp_c: Optional[float] = None,
    ) -> float:
        """Compute Monod specific substrate uptake rate r_su [g COD/(m3*s)].

        Formulation:
            r_su = k_m,su * f(T) * (S_su / (K_s,su + S_su)) * X_su_eff
        """
        f_t = self.compute_temperature_factor(temp_c)
        su = max(0.0, s_su_g_m3)
        monod_term = su / (self.config.k_s_su + su)
        return self.config.k_m_su * f_t * monod_term * self.config.x_su_eff

    def compute_andrews_methanogen_rate(
        self,
        s_vfa_g_m3: float,
        temp_c: Optional[float] = None,
    ) -> Tuple[float, float, float, float]:
        """Compute Andrews specific methanogen growth rate mu_ac [1/s].

        Formulation:
            mu_ac = mu_max,ac * f(T) * I_pH * (S_vfa / (K_s,vfa + S_vfa + (S_vfa^2 / K_i,vfa)))

        Returns:
            Tuple of (mu_ac [1/s], ph [-], f_t [-], i_ph [-]).
        """
        f_t = self.compute_temperature_factor(temp_c)
        ph = self.compute_ph(s_vfa_g_m3)
        i_ph = self.compute_ph_inhibition(ph)

        vfa = max(0.0, s_vfa_g_m3)
        denominator = self.config.k_s_vfa + vfa + ((vfa ** 2) / max(1.0, self.config.k_i_vfa))
        andrews_term = vfa / max(1e-6, denominator)

        mu_ac = self.config.mu_max_ac * f_t * i_ph * andrews_term
        return mu_ac, ph, f_t, i_ph

    def compute_henry_mass_transfer(
        self,
        s_ch4_g_m3: float,
        s_co2_g_m3: float,
        p_gas_mbar: float,
        biogas_ch4_pct: Optional[float] = None,
    ) -> Tuple[float, float, float, float, float, float]:
        """Compute gas-liquid mass transfer rates and gas mole fractions.

        Formulation:
            P_gas_abs = P_atm + max(0, P_gas)
            P_ch4 = P_gas_abs * y_ch4_head
            P_co2 = P_gas_abs * y_co2_head
            r_T,ch4 = kla_ch4 * max(0, S_ch4 - K_H,ch4 * P_ch4)
            r_T,co2 = kla_co2 * max(0, S_co2 - K_H,co2 * P_co2)

        Returns:
            Tuple of (r_t_ch4, r_t_co2, n_ch4_in, n_co2_in, y_ch4, y_co2).
        """
        p_abs = self.config.p_atm_mbar + max(0.0, p_gas_mbar)

        ch4_pct = self.state.biogas_ch4_pct if biogas_ch4_pct is None else biogas_ch4_pct
        y_ch4_head = max(0.10, min(0.90, ch4_pct / 100.0))
        y_co2_head = 1.0 - y_ch4_head

        p_ch4_mbar = p_abs * y_ch4_head
        p_co2_mbar = p_abs * y_co2_head

        s_ch4_sat = self.config.k_h_ch4 * p_ch4_mbar
        s_co2_sat = self.config.k_h_co2 * p_co2_mbar

        r_t_ch4 = self.config.kla_ch4 * max(0.0, s_ch4_g_m3 - s_ch4_sat)
        r_t_co2 = self.config.kla_co2 * max(0.0, s_co2_g_m3 - s_co2_sat)

        v_liq = self.config.v_liq_m3
        n_ch4_in = (r_t_ch4 * v_liq) / max(1e-6, self.config.mw_ch4)  # [mol/s]
        n_co2_in = (r_t_co2 * v_liq) / max(1e-6, self.config.mw_co2)  # [mol/s]
        n_gas_tot = n_ch4_in + n_co2_in

        if n_gas_tot > 1e-9:
            y_ch4 = n_ch4_in / n_gas_tot
            y_co2 = n_co2_in / n_gas_tot
        else:
            y_ch4 = y_ch4_head
            y_co2 = y_co2_head

        return r_t_ch4, r_t_co2, n_ch4_in, n_co2_in, y_ch4, y_co2

    def compute_gas_draw_off(self, p_gas_mbar: float) -> Tuple[float, float, float]:
        """Compute biogas outflow draw rates [mol/s] (nominal, auto-flare, and high-pressure relief).

        Returns:
            Tuple of (n_gas_out_total, n_flare_out, n_relief_out).
        """
        p_g = max(0.0, p_gas_mbar)

        # 1. Normal process draw-off to boiler / CHP
        dp_util = max(0.0, p_g - self.config.p_setpoint_mbar)
        n_util = self.config.k_valve * dp_util

        # 2. Emergency auto-flare (> 35 mbar)
        dp_flare = max(0.0, p_g - self.config.p_flare_mbar)
        n_flare = self.config.k_flare * dp_flare

        # 3. High pressure safety relief (> 50 mbar)
        dp_relief = max(0.0, p_g - self.config.p_trip_mbar)
        n_relief = self.config.k_relief * dp_relief

        n_tot = n_util + n_flare + n_relief
        return n_tot, n_flare, n_relief

    # ------------------------------------------------------------------------
    # Coupled 6-State ODE System & RK4 with Adaptive Sub-stepping
    # ------------------------------------------------------------------------

    def ode_derivatives(self, t: float, y: List[float]) -> List[float]:
        """Compute time derivatives dy/dt for the coupled 6-state ODE system.

        State vector y:
            y[0]: S_su [g COD/m3]
            y[1]: S_vfa [g COD/m3]
            y[2]: X_ac [g COD/m3]
            y[3]: S_co2 [g/m3]
            y[4]: S_ch4 [g/m3]
            y[5]: P_gas [mbar]
        """
        s_su = max(0.0, y[0])
        s_vfa = max(0.0, y[1])
        x_ac = max(0.0, y[2])
        s_co2 = max(0.0, y[3])
        s_ch4 = max(0.0, y[4])
        p_gas = max(0.0, y[5])

        d_dilution = self.config.dilution_rate_s if self.state.feed_pump_on else 0.0

        # Biological kinetics
        r_su = self.compute_monod_substrate_uptake(s_su)
        mu_ac, ph, f_t, i_ph = self.compute_andrews_methanogen_rate(s_vfa)

        # VFA uptake and yields
        r_vfa_cons = (mu_ac / max(1e-6, self.config.y_ac)) * x_ac
        r_decay = self.config.b_ac * x_ac

        # Stoichiometric carbon-balanced yields:
        # Reaction 1: Acidogenesis (Substrate -> VFA + CO2)
        # c_su * r_su = c_vfa * Y_vfa_su * r_su + c_co2 * Y_co2_su * r_su
        y_vfa_su = self.config.y_vfa_su
        y_co2_su = (self.config.c_frac_su - (self.config.c_frac_vfa * y_vfa_su)) / max(1e-6, self.config.c_frac_co2)

        # Reaction 2: Methanogenesis (VFA -> Biomass + CH4 + CO2)
        # Carbon allocation: 5% to biomass, 47.5% to CH4, 47.5% to CO2
        f_c_ch4 = 0.475
        f_c_co2 = 0.475
        y_ch4_mass_rate = (f_c_ch4 * self.config.c_frac_vfa / max(1e-6, self.config.c_frac_ch4)) * r_vfa_cons
        y_co2_mass_rate = (f_c_co2 * self.config.c_frac_vfa / max(1e-6, self.config.c_frac_co2)) * r_vfa_cons

        # Gas-Liquid mass transfer
        r_t_ch4, r_t_co2, n_ch4_in, n_co2_in, _, _ = self.compute_henry_mass_transfer(s_ch4, s_co2, p_gas)

        # Gas draw-off
        n_gas_out_tot, _, _ = self.compute_gas_draw_off(p_gas)

        # 1. dy[0]/dt: Substrate COD derivative [g COD/(m3*s)]
        # Biomass decay lyses back to substrate COD preserving carbon
        d_s_su_dt = (d_dilution * (self.config.s_su_in_g_m3 - s_su)) - r_su + r_decay

        # 2. dy[1]/dt: Volatile Fatty Acids derivative [g COD/(m3*s)]
        d_s_vfa_dt = (d_dilution * (self.config.s_vfa_in_g_m3 - s_vfa)) + (y_vfa_su * r_su) - r_vfa_cons

        # 3. dy[2]/dt: Methanogenic Biomass derivative [g COD/(m3*s)]
        d_x_ac_dt = (mu_ac * x_ac) - r_decay - (d_dilution * x_ac)

        # 4. dy[3]/dt: Dissolved CO2 derivative [g/(m3*s)]
        d_s_co2_dt = (
            (d_dilution * (self.config.s_co2_in_g_m3 - s_co2))
            + (y_co2_su * r_su)
            + y_co2_mass_rate
            - r_t_co2
        )

        # 5. dy[4]/dt: Dissolved CH4 derivative [g/(m3*s)]
        d_s_ch4_dt = (
            -(d_dilution * s_ch4)
            + y_ch4_mass_rate
            - r_t_ch4
        )

        # 6. dy[5]/dt: Headspace Biogas Pressure derivative [mbar/s]
        # P = (n * R * T) / V_gas [Pa], converted to mbar (1 Pa = 0.01 mbar)
        t_kelvin = self.config.temp_c + 273.15
        n_gas_net = (n_ch4_in + n_co2_in) - n_gas_out_tot
        d_p_gas_dt = ((self.config.r_gas * t_kelvin) / max(1.0, self.config.v_gas_m3)) * n_gas_net * 0.01

        return [
            d_s_su_dt,
            d_s_vfa_dt,
            d_x_ac_dt,
            d_s_co2_dt,
            d_s_ch4_dt,
            d_p_gas_dt,
        ]

    def _rk4_single_step(self, t: float, y: List[float], h: float) -> List[float]:
        """Compute a single 4th-Order Runge-Kutta step of size h."""
        k1 = self.ode_derivatives(t, y)
        y_k2 = [y[i] + 0.5 * h * k1[i] for i in range(6)]
        k2 = self.ode_derivatives(t + 0.5 * h, y_k2)
        y_k3 = [y[i] + 0.5 * h * k2[i] for i in range(6)]
        k3 = self.ode_derivatives(t + 0.5 * h, y_k3)
        y_k4 = [y[i] + h * k3[i] for i in range(6)]
        k4 = self.ode_derivatives(t + h, y_k4)

        return [
            y[i] + (h / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i])
            for i in range(6)
        ]

    def advance_time(
        self,
        duration_s: float = 1.0,
        dt: float = 0.1,
        rel_tol: float = 1e-4,
        abs_tol: float = 1e-6,
    ) -> ExecutionResult:
        """Advance simulation time using high-order RK4 with adaptive sub-stepping.

        Args:
            duration_s: Total time duration to advance [s].
            dt: Initial nominal step size [s].
            rel_tol: Relative error tolerance for adaptive sub-stepping.
            abs_tol: Absolute error tolerance for adaptive sub-stepping.
        """
        if duration_s <= 0.0 or dt <= 0.0:
            return ExecutionResult.failed(
                error_code="INVALID_TIMESTEP",
                details=f"Invalid duration ({duration_s}s) or dt ({dt}s); must be strictly positive.",
            )

        t_target = self.state.time_s + duration_s
        h = max(1e-4, min(dt, duration_s))
        h_min = 1e-5
        h_max = max(dt, 0.5)

        y_curr = [
            self.state.s_su_g_m3,
            self.state.s_vfa_g_m3,
            self.state.x_ac_g_m3,
            self.state.s_co2_g_m3,
            self.state.s_ch4_g_m3,
            self.state.p_gas_mbar,
        ]

        t_now = self.state.time_s

        while t_now < t_target - 1e-12:
            step_h = min(h, t_target - t_now)

            # Full step
            y_full = self._rk4_single_step(t_now, y_curr, step_h)

            # Two half steps
            half_h = 0.5 * step_h
            y_mid = self._rk4_single_step(t_now, y_curr, half_h)
            y_two_half = self._rk4_single_step(t_now + half_h, y_mid, half_h)

            # Truncation error estimate (Richardson extrapolation)
            max_err = 0.0
            for i in range(6):
                sc = abs_tol + rel_tol * max(abs(y_curr[i]), abs(y_two_half[i]))
                err = abs(y_two_half[i] - y_full[i]) / max(1e-10, sc)
                if err > max_err:
                    max_err = err

            # Step acceptance criterion
            if max_err <= 1.0 or step_h <= h_min:
                # Accept step using higher order extrapolation
                t_now += step_h
                y_curr = [
                    max(0.0, y_two_half[i] + (y_two_half[i] - y_full[i]) / 15.0)
                    for i in range(6)
                ]

                # Adapt next step size
                if max_err > 0.0:
                    fac = min(2.0, max(0.5, 0.9 * (1.0 / max_err) ** 0.20))
                    h = min(h_max, max(h_min, step_h * fac))
                else:
                    h = min(h_max, step_h * 2.0)
            else:
                # Reject step and shrink
                fac = max(0.2, min(0.8, 0.9 * (1.0 / max_err) ** 0.25))
                h = max(h_min, step_h * fac)

        # Commit final state
        self.state.time_s = t_now
        self.state.s_su_g_m3 = y_curr[0]
        self.state.s_vfa_g_m3 = y_curr[1]
        self.state.x_ac_g_m3 = y_curr[2]
        self.state.s_co2_g_m3 = y_curr[3]
        self.state.s_ch4_g_m3 = y_curr[4]
        self.state.p_gas_mbar = y_curr[5]

        # Update telemetry & kinetics
        mu_ac, ph, f_t, i_ph = self.compute_andrews_methanogen_rate(self.state.s_vfa_g_m3)
        self.state.mu_ac_rate = mu_ac
        self.state.ph = ph
        self.state.f_temp = f_t
        self.state.i_ph = i_ph
        self.state.r_su_g_m3_s = self.compute_monod_substrate_uptake(self.state.s_su_g_m3)
        self.state.r_vfa_cons_g_m3_s = (mu_ac / max(1e-6, self.config.y_ac)) * self.state.x_ac_g_m3

        r_t_ch4, r_t_co2, n_ch4_in, n_co2_in, y_ch4, y_co2 = self.compute_henry_mass_transfer(
            self.state.s_ch4_g_m3, self.state.s_co2_g_m3, self.state.p_gas_mbar
        )
        self.state.r_t_ch4_g_m3_s = r_t_ch4
        self.state.r_t_co2_g_m3_s = r_t_co2
        self.state.biogas_ch4_pct = y_ch4 * 100.0
        self.state.biogas_co2_pct = y_co2 * 100.0

        n_tot_out, _, _ = self.compute_gas_draw_off(self.state.p_gas_mbar)
        self.state.total_gas_offtake_mol_s = n_tot_out

        # Track carbon mass conservation
        self._track_carbon_mass_balance()

        self.state.is_running = True
        self._evaluate_safety_interlocks()
        self._sync_registers()

        return ExecutionResult.success(
            details=f"Anaerobic digester advanced to t={self.state.time_s:.2f}s.",
            data={
                "time_s": self.state.time_s,
                "substrate_cod_mg_l": self.state.s_su_g_m3,
                "vfa_concentration_mg_l": self.state.s_vfa_g_m3,
                "biomass_concentration_mg_l": self.state.x_ac_g_m3,
                "biogas_pressure_mbar": self.state.p_gas_mbar,
                "methane_pct": self.state.biogas_ch4_pct,
                "digester_ph": self.state.ph,
                "diagnostic_code": f"0x{self.state.diagnostic_code:04X}",
                "mass_balance_residual_g_s": self.state.mass_balance_residual_g_s,
            },
        )

    # ------------------------------------------------------------------------
    # Analytical Stoichiometric Carbon Mass Balance Tracking
    # ------------------------------------------------------------------------

    def _track_carbon_mass_balance(self) -> None:
        """Track stoichiometric carbon balance: |dM_C,in/dt - dM_C,out/dt - dM_C,acc/dt| < 1e-10 g C/s.

        All biological reaction yields are stoichiometry-closed on carbon:
        1. Substrate uptake generates VFA and CO2: c_su * r_su = c_vfa * r_vfa,gen + c_co2 * r_co2,gen1.
        2. VFA methanogenesis produces Biomass, CH4, and CO2: c_vfa * r_vfa,cons = c_x * r_x,gen + c_ch4 * r_ch4,gen + c_co2 * r_co2,gen2.
        3. Gas-liquid mass transfer transfers carbon between liquid and headspace.
        4. Offgas draw removes methane and CO2 carbon.
        Residual error is identically zero within floating-point roundoff (< 1e-10 g C/s).
        """
        q_feed = self.config.q_feed_m3_s if self.state.feed_pump_on else 0.0
        v_liq = self.config.v_liq_m3

        # Inflow Carbon [g C/s]
        c_in = q_feed * (
            (self.config.c_frac_su * self.config.s_su_in_g_m3)
            + (self.config.c_frac_vfa * self.config.s_vfa_in_g_m3)
            + (self.config.c_frac_co2 * self.config.s_co2_in_g_m3)
        )

        # Outflow Carbon in liquid effluent [g C/s]
        c_out_liq = q_feed * (
            (self.config.c_frac_su * self.state.s_su_g_m3)
            + (self.config.c_frac_vfa * self.state.s_vfa_g_m3)
            + (self.config.c_frac_x * self.state.x_ac_g_m3)
            + (self.config.c_frac_co2 * self.state.s_co2_g_m3)
            + (self.config.c_frac_ch4 * self.state.s_ch4_g_m3)
        )

        # Outflow Carbon in offgas stream [g C/s]
        # n_tot_out [mol/s] * (y_ch4 * 12.011 + y_co2 * 12.011)
        y_ch4 = self.state.biogas_ch4_pct / 100.0
        y_co2 = self.state.biogas_co2_pct / 100.0
        c_out_gas = self.state.total_gas_offtake_mol_s * (
            (y_ch4 * 12.011) + (y_co2 * 12.011)
        )

        c_out_tot = c_out_liq + c_out_gas

        # Liquid components accumulation:
        y_curr = [
            self.state.s_su_g_m3,
            self.state.s_vfa_g_m3,
            self.state.x_ac_g_m3,
            self.state.s_co2_g_m3,
            self.state.s_ch4_g_m3,
            self.state.p_gas_mbar,
        ]
        dy_dt = self.ode_derivatives(self.state.time_s, y_curr)

        dm_c_liq_acc_dt = v_liq * (
            (self.config.c_frac_su * dy_dt[0])
            + (self.config.c_frac_vfa * dy_dt[1])
            + (self.config.c_frac_x * dy_dt[2])
            + (self.config.c_frac_co2 * dy_dt[3])
            + (self.config.c_frac_ch4 * dy_dt[4])
        )

        # Headspace gas accumulation evaluated consistently with current state:
        r_t_ch4, r_t_co2, n_ch4_in, n_co2_in, y_ch4, y_co2 = self.compute_henry_mass_transfer(
            y_curr[4], y_curr[3], y_curr[5]
        )
        n_tot_out, _, _ = self.compute_gas_draw_off(y_curr[5])
        c_out_gas = n_tot_out * ((y_ch4 * 12.011) + (y_co2 * 12.011))
        c_out_tot = c_out_liq + c_out_gas

        c_gas_in = (n_ch4_in * 12.011) + (n_co2_in * 12.011)
        dm_c_gas_acc_dt = c_gas_in - c_out_gas

        # Total accumulation
        d_c_acc_tot_dt = dm_c_liq_acc_dt + dm_c_gas_acc_dt

        residual = abs(c_in - c_out_tot - d_c_acc_tot_dt)

        self.state.carbon_in_g_s = c_in
        self.state.carbon_out_g_s = c_out_tot
        self.state.dcarbon_acc_dt_g_s = d_c_acc_tot_dt
        self.state.mass_balance_residual_g_s = residual

    # ------------------------------------------------------------------------
    # Process Safety Interlocks & Diagnostics
    # ------------------------------------------------------------------------

    def _evaluate_safety_interlocks(self) -> None:
        """Evaluate process trips (%M193, %M194, %M195) and diagnostic event codes."""
        # %M193: Sour Digester Acidification Trip (pH < 6.50 or VFA > 4000 mg/L) -> code 0x9301
        acid_trip = bool(
            self.state.ph < self.config.ph_trip_low
            or self.state.s_vfa_g_m3 > self.config.vfa_trip_mg_l
        )
        self.state.acidification_trip = acid_trip

        # %M194: Biogas Overpressure Trip (P_gas > 50.0 mbar) -> code 0x9302
        overpress_trip = bool(self.state.p_gas_mbar > self.config.p_trip_mbar)
        self.state.overpressure_trip = overpress_trip

        # %M195: Auto-Flare Command (P_gas > 35.0 mbar)
        flare_cmd = bool(self.state.p_gas_mbar > self.config.p_flare_mbar)
        self.state.auto_flare_cmd = flare_cmd

        # Biomass Washout Alarm (X_ac < 250 g COD/m3) -> code 0x9303
        washout = bool(self.state.x_ac_g_m3 < self.config.biomass_washout_limit)
        self.state.biomass_washout_alarm = washout

        # Healthy Methanogenesis flag
        self.state.methanogenesis_healthy = bool(
            self.state.ph >= 6.80
            and self.state.s_vfa_g_m3 <= 1000.0
            and not acid_trip
            and not overpress_trip
        )

        # Diagnostic Event Code Priority: Overpressure (0x9302) > Acidification (0x9301) > Washout (0x9303) > OK (0x0000)
        if self.state.overpressure_trip:
            self.state.diagnostic_code = int(AnaerobicDigesterDiagnosticCode.BIOGAS_OVERPRESSURE_TRIP)
        elif self.state.acidification_trip:
            self.state.diagnostic_code = int(AnaerobicDigesterDiagnosticCode.SOUR_DIGESTER_ACIDIFICATION_TRIP)
        elif self.state.biomass_washout_alarm:
            self.state.diagnostic_code = int(AnaerobicDigesterDiagnosticCode.BIOMASS_WASHOUT_ALARM)
        else:
            self.state.diagnostic_code = int(AnaerobicDigesterDiagnosticCode.OK)

    # ------------------------------------------------------------------------
    # Horner OCS Register Synchronization
    # ------------------------------------------------------------------------

    def _sync_registers(self) -> None:
        """Synchronize telemetry into Horner OCS registers (%R830..%R837, %M193..%M195)."""
        self._evaluate_safety_interlocks()

        # Compute %R830 DigesterStatusWord
        sw = 0
        if self.state.is_running:
            sw |= int(AnaerobicDigesterStatusBits.RUNNING)
        if self.state.feed_pump_on:
            sw |= int(AnaerobicDigesterStatusBits.FEED_PUMP_ON)
        if self.state.heating_active:
            sw |= int(AnaerobicDigesterStatusBits.HEATING_ACTIVE)
        if self.state.methanogenesis_healthy:
            sw |= int(AnaerobicDigesterStatusBits.METHANOGENESIS_HEALTHY)
        if self.state.acidification_trip:
            sw |= int(AnaerobicDigesterStatusBits.SOUR_DIGESTER_TRIP)
        if self.state.overpressure_trip:
            sw |= int(AnaerobicDigesterStatusBits.OVERPRESSURE_TRIP)
        if self.state.auto_flare_cmd:
            sw |= int(AnaerobicDigesterStatusBits.FLARE_ACTIVE)
        if self.state.biomass_washout_alarm:
            sw |= int(AnaerobicDigesterStatusBits.WASHOUT_ALARM)

        # Scaled analog word registers
        r831_cod = max(0, min(32767, int(round(self.state.s_su_g_m3))))
        r832_vfa = max(0, min(32767, int(round(self.state.s_vfa_g_m3))))
        r833_biomass = max(0, min(32767, int(round(self.state.x_ac_g_m3))))
        r834_pressure = max(0, min(32767, int(round(self.state.p_gas_mbar * 10.0))))
        r835_ch4_pct = max(0, min(1000, int(round(self.state.biogas_ch4_pct * 10.0))))
        r836_ph = max(0, min(1400, int(round(self.state.ph * 100.0))))
        r837_diag = self.state.diagnostic_code

        # Write Analog Word Registers %R830..%R837
        self.reg_table.write_word("%R830", sw, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R831", r831_cod, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R832", r832_vfa, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R833", r833_biomass, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R834", r834_pressure, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R835", r835_ch4_pct, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R836", r836_ph, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R837", r837_diag, privilege=PrivilegeMode.SYSTEM)

        # Write Discrete Safety Coils %M193..%M195
        self.reg_table.write_bit("%M193", self.state.acidification_trip, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_bit("%M194", self.state.overpressure_trip, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_bit("%M195", self.state.auto_flare_cmd, privilege=PrivilegeMode.SYSTEM)


# Backward compatibility aliases
AnaerobicDigesterEngine = AnaerobicDigesterSimulator
DigesterSimulator = AnaerobicDigesterSimulator
ADSimulator = AnaerobicDigesterSimulator
AnaerobicDigesterModel = AnaerobicDigesterSimulator


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

ANAEROBIC_DIGESTER_PURE_ST_POU: str = """PROGRAM AnaerobicDigesterSync
VAR
    DigesterStatusWord AT %R830 : INT;
    SubstrateCod_mg_L AT %R831 : INT;
    VfaConcentration_mg_L AT %R832 : INT;
    BiomassConcentration_mg_L AT %R833 : INT;
    BiogasPressure_mbar AT %R834 : INT;
    MethanePct AT %R835 : INT;
    DigesterPhScaled AT %R836 : INT;
    DiagnosticEventCode AT %R837 : INT;
    AcidificationTrip AT %M193 : BOOL;
    BiogasOverpressureTrip AT %M194 : BOOL;
    AutoFlareCmd AT %M195 : BOOL;
    FeedPumpInhibitCmd : BOOL := FALSE;
    EmergencyPressureReliefCmd : BOOL := FALSE;
    FlareIgnitionActive : BOOL := FALSE;
END_VAR

(* Interlock watchdog for Anaerobic Digester & Biogas Methanogenesis *)
IF AcidificationTrip THEN
    FeedPumpInhibitCmd := TRUE;
ELSE
    FeedPumpInhibitCmd := FALSE;
END_IF;

IF BiogasOverpressureTrip THEN
    EmergencyPressureReliefCmd := TRUE;
ELSE
    EmergencyPressureReliefCmd := FALSE;
END_IF;

IF AutoFlareCmd THEN
    FlareIgnitionActive := TRUE;
ELSE
    FlareIgnitionActive := FALSE;
END_IF;
END_PROGRAM
"""

# Compatibility aliases
DIGESTER_PURE_ST_POU = ANAEROBIC_DIGESTER_PURE_ST_POU
AD_PURE_ST_POU = ANAEROBIC_DIGESTER_PURE_ST_POU


def verify_anaerobic_digester_pure_st() -> bool:
    """Validate Pure ST POU against anti-ladder security guard and AST parser."""
    SecurityGuard.assert_pure_st_content(ANAEROBIC_DIGESTER_PURE_ST_POU)
    res = STParser.validate_code(ANAEROBIC_DIGESTER_PURE_ST_POU)
    if res.status != AgentStatus.SUCCESS:
        return False
    ast = STParser.parse_pou(ANAEROBIC_DIGESTER_PURE_ST_POU)
    if ast is None or ast.name != "AnaerobicDigesterSync":
        return False
    expected = [
        "%R830", "%R831", "%R832", "%R833", "%R834", "%R835", "%R836", "%R837",
        "%M193", "%M194", "%M195",
    ]
    return all(r in ast.bound_registers for r in expected)


def run_anaerobic_digester_verification(
    output_path: Optional[str] = None,
    evidence_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute complete 9-stage verification suite for W122 Anaerobic Digester ODE Simulation.

    Returns:
        Strict 4-state contract dictionary (status, error_code, details, data).
    """
    target_path = output_path or evidence_path
    test_results: List[Dict[str, Any]] = []

    # Stage 1: Pure ST POU Validation & AST Symbol Binding
    try:
        SecurityGuard.assert_pure_st_content(ANAEROBIC_DIGESTER_PURE_ST_POU)
        res_st = STParser.validate_code(ANAEROBIC_DIGESTER_PURE_ST_POU)
        ast = STParser.parse_pou(ANAEROBIC_DIGESTER_PURE_ST_POU)
        c1 = (
            res_st.status == AgentStatus.SUCCESS
            and ast is not None
            and ast.name == "AnaerobicDigesterSync"
            and ast.pou_type == POUType.PROGRAM
            and all(
                r in ast.bound_registers
                for r in [
                    "%R830", "%R831", "%R832", "%R833", "%R834", "%R835", "%R836", "%R837",
                    "%M193", "%M194", "%M195",
                ]
            )
        )
    except Exception:
        c1 = False

    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_And_AST_Symbol_Binding",
        "passed": c1,
        "details": "Pure ST POU validated; %R830..%R837 and %M193..%M195 bound into AST.",
    })

    # Stage 2: Biological Reaction Kinetics: Monod Uptake & Andrews VFA Inhibition
    sim = AnaerobicDigesterSimulator()
    r_su_low = sim.compute_monod_substrate_uptake(200.0)
    r_su_nom = sim.compute_monod_substrate_uptake(2000.0)
    r_su_high = sim.compute_monod_substrate_uptake(10000.0)

    # Monod monotonicity
    c2_monod = 0.0 < r_su_low < r_su_nom < r_su_high

    # Andrews VFA inhibition test
    mu_low, ph_low, _, _ = sim.compute_andrews_methanogen_rate(350.0)
    mu_peak, ph_mid, _, _ = sim.compute_andrews_methanogen_rate(1200.0)
    mu_inhibited, ph_sour, _, _ = sim.compute_andrews_methanogen_rate(4500.0)

    # At 4500 mg/L VFA, growth rate is heavily inhibited compared to mid range, and pH is sour
    c2_andrews = (
        mu_low > 0.0
        and mu_peak > 0.0
        and mu_inhibited < mu_peak
        and ph_sour < 6.50
    )
    c2 = c2_monod and c2_andrews
    test_results.append({
        "stage": 2,
        "check": "Monod_Uptake_And_Andrews_VFA_Inhibition",
        "passed": c2,
        "details": f"Kinetics verified: Monod monotonic (r={r_su_nom:.2e} g/(m3*s)), Andrews inhibition confirmed: mu(1200)={mu_peak:.2e} > mu(4500)={mu_inhibited:.2e} 1/s, sour pH={ph_sour:.2f}.",
    })

    # Stage 3: Mesophilic Temperature Correction Factor (Cardinal Curve 35-38 °C)
    f_37 = sim.compute_temperature_factor(37.0)
    f_35 = sim.compute_temperature_factor(35.0)
    f_38 = sim.compute_temperature_factor(38.0)
    f_cold = sim.compute_temperature_factor(20.0)
    f_hot = sim.compute_temperature_factor(50.0)

    c3 = (
        math.isclose(f_37, 1.0, rel_tol=1e-5)
        and f_35 >= 0.70
        and f_38 >= 0.70
        and f_cold < 0.05
        and f_hot < 0.05
    )
    test_results.append({
        "stage": 3,
        "check": "Mesophilic_Temperature_Correction_Factor",
        "passed": c3,
        "details": f"Temperature curve verified: f(37C)={f_37:.3f}, f(35C)={f_35:.3f}, f(38C)={f_38:.3f}, f(20C)={f_cold:.4e}, f(50C)={f_hot:.4e}.",
    })

    # Stage 4: Gas-Liquid Henry's Law Transfer & Headspace Pressure Dynamics
    r_t_ch4, r_t_co2, n_ch4, n_co2, y_ch4, y_co2 = sim.compute_henry_mass_transfer(
        s_ch4_g_m3=20.0, s_co2_g_m3=300.0, p_gas_mbar=25.0
    )
    n_gas_tot, n_flare, n_relief = sim.compute_gas_draw_off(p_gas_mbar=25.0)
    _, n_flare_active, _ = sim.compute_gas_draw_off(p_gas_mbar=40.0)

    c4 = (
        r_t_ch4 > 0.0
        and r_t_co2 > 0.0
        and n_ch4 > 0.0
        and n_co2 > 0.0
        and 0.50 <= y_ch4 <= 0.80
        and n_gas_tot > 0.0
        and n_flare == 0.0
        and n_flare_active > 0.0
    )
    test_results.append({
        "stage": 4,
        "check": "Gas_Liquid_Henrys_Law_Transfer_And_Headspace_Dynamics",
        "passed": c4,
        "details": f"Henry's law transfer verified: r_T,CH4={r_t_ch4:.3f}, r_T,CO2={r_t_co2:.3f} g/(m3*s), CH4={y_ch4*100:.1f}%, Flare active at 40mbar ({n_flare_active:.3f} mol/s).",
    })

    # Stage 5: High-Order RK4 Integrator with Adaptive Sub-stepping
    sim_rk4 = AnaerobicDigesterSimulator()
    res_rk4 = sim_rk4.advance_time(duration_s=2.0, dt=0.05)
    st_rk4 = sim_rk4.state

    c5 = (
        res_rk4.status == AgentStatus.SUCCESS
        and st_rk4.s_su_g_m3 > 0.0
        and st_rk4.s_vfa_g_m3 > 0.0
        and st_rk4.x_ac_g_m3 > 0.0
        and st_rk4.s_co2_g_m3 > 0.0
        and st_rk4.s_ch4_g_m3 > 0.0
        and st_rk4.p_gas_mbar > 0.0
        and 6.0 <= st_rk4.ph <= 8.0
    )
    test_results.append({
        "stage": 5,
        "check": "High_Order_RK4_With_Adaptive_Substepping",
        "passed": c5,
        "details": f"RK4 integration stable: S_su={st_rk4.s_su_g_m3:.1f}, VFA={st_rk4.s_vfa_g_m3:.1f} mg/L, X_ac={st_rk4.x_ac_g_m3:.1f} mg/L, P_gas={st_rk4.p_gas_mbar:.1f} mbar, pH={st_rk4.ph:.2f}.",
    })

    # Stage 6: Stoichiometric Carbon Mass Conservation Tracking (Residual < 1e-10)
    sim_mass = AnaerobicDigesterSimulator()
    sim_mass.advance_time(duration_s=1.0, dt=0.05)
    res_c = sim_mass.state.mass_balance_residual_g_s

    c6 = res_c < 1e-10
    test_results.append({
        "stage": 6,
        "check": "Stoichiometric_Carbon_Mass_Conservation_Residual",
        "passed": c6,
        "details": f"Mass conservation verified: residual = {res_c:.4e} g C/s (< 1e-10 g C/s).",
    })

    # Stage 7: Process Safety Interlocks: Sour Digester Acidification Trip (%M193, 0x9301)
    sim_acid = AnaerobicDigesterSimulator()
    sim_acid.state.s_vfa_g_m3 = 4500.0  # Exceeds 4000 mg/L limit
    sim_acid.state.ph = sim_acid.compute_ph(4500.0)
    sim_acid._sync_registers()

    c7_m193 = sim_acid.reg_table.read_bit("%M193") is True
    c7_r837 = (sim_acid.reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.SOUR_DIGESTER_ACIDIFICATION_TRIP)
    c7_sw = bool(sim_acid.reg_table.read_word("%R830") & int(AnaerobicDigesterStatusBits.SOUR_DIGESTER_TRIP))

    c7 = c7_m193 and c7_r837 and c7_sw
    test_results.append({
        "stage": 7,
        "check": "Sour_Digester_Acidification_Trip_Interlock",
        "passed": c7,
        "details": f"Acidification interlock verified: %M193={c7_m193}, %R837=0x{sim_acid.state.diagnostic_code:04X}, VFA={sim_acid.state.s_vfa_g_m3} mg/L, pH={sim_acid.state.ph:.2f}.",
    })

    # Stage 8: Biogas Overpressure Trip (%M194, 0x9302), Auto-Flare (%M195), and Washout Alarm (0x9303)
    sim_trip = AnaerobicDigesterSimulator()

    # Test auto-flare (%M195) at 38 mbar
    sim_trip.state.p_gas_mbar = 38.0
    sim_trip._sync_registers()
    c8_flare = (
        sim_trip.reg_table.read_bit("%M195") is True
        and sim_trip.reg_table.read_bit("%M194") is False
    )

    # Test overpressure trip (%M194 -> 0x9302) at 55 mbar
    sim_trip.state.p_gas_mbar = 55.0
    sim_trip._sync_registers()
    c8_overpress = (
        sim_trip.reg_table.read_bit("%M194") is True
        and (sim_trip.reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.BIOGAS_OVERPRESSURE_TRIP)
    )

    # Test biomass washout alarm (0x9303)
    sim_washout = AnaerobicDigesterSimulator()
    sim_washout.state.x_ac_g_m3 = 180.0  # < 250 g COD/m3
    sim_washout._sync_registers()
    c8_washout = (
        sim_washout.state.biomass_washout_alarm is True
        and (sim_washout.reg_table.read_word("%R837") & 0xFFFF) == int(AnaerobicDigesterDiagnosticCode.BIOMASS_WASHOUT_ALARM)
        and bool(sim_washout.reg_table.read_word("%R830") & int(AnaerobicDigesterStatusBits.WASHOUT_ALARM))
    )

    c8 = c8_flare and c8_overpress and c8_washout
    test_results.append({
        "stage": 8,
        "check": "Overpressure_Flare_And_Washout_Interlocks",
        "passed": c8,
        "details": f"Safety trips verified: Flare (%M195)={c8_flare}, Overpressure (%M194, 0x9302)={c8_overpress}, Washout (0x9303)={c8_washout}.",
    })

    # Stage 9: Horner OCS Register Space Sync & Anti-Ladder Security Rejection
    sim_sync = AnaerobicDigesterSimulator()
    sim_sync.advance_time(duration_s=0.5, dt=0.05)
    reg = sim_sync.reg_table

    r830 = reg.read_word("%R830")
    r831 = reg.read_word("%R831")
    r832 = reg.read_word("%R832")
    r833 = reg.read_word("%R833")
    r834 = reg.read_word("%R834")
    r835 = reg.read_word("%R835")
    r836 = reg.read_word("%R836")
    r837 = reg.read_word("%R837")

    c9_regs = (
        (r830 & int(AnaerobicDigesterStatusBits.RUNNING)) != 0
        and (r830 & int(AnaerobicDigesterStatusBits.FEED_PUMP_ON)) != 0
        and (r830 & int(AnaerobicDigesterStatusBits.HEATING_ACTIVE)) != 0
        and (r830 & int(AnaerobicDigesterStatusBits.METHANOGENESIS_HEALTHY)) != 0
        and r831 > 0
        and r832 > 0
        and r833 > 0
        and r834 > 0
        and 500 <= r835 <= 800
        and 650 <= r836 <= 800
        and r837 == 0x0000
    )

    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("""
        PROGRAM BadLadderInterlock
        VAR FlareCoil : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """)
    except LadderForbiddenError:
        ladder_rejected = True

    c9 = c9_regs and ladder_rejected
    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Register_Sync_And_Anti_Ladder_Rejection",
        "passed": c9,
        "details": f"Registers synced: %R830=0x{r830:04X}, %R831={r831}, %R832={r832}, %R833={r833}, %R834={r834}, %R835={r835}, %R836={r836}; Anti-ladder rejection asserted.",
    })

    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Industrial Anaerobic Digester & Biogas Methanogenesis ODE Simulation verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed).",
        "data": {
            "work_package": "W122",
            "gate": "Gate G7 / Gate G4",
            "component": "Industrial Anaerobic Digester & Biogas Methanogenesis ODE Simulator",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "metrics": {
                "substrate_cod_mg_l": sim_sync.state.s_su_g_m3,
                "vfa_concentration_mg_l": sim_sync.state.s_vfa_g_m3,
                "biomass_concentration_mg_l": sim_sync.state.x_ac_g_m3,
                "biogas_pressure_mbar": sim_sync.state.p_gas_mbar,
                "methane_pct": sim_sync.state.biogas_ch4_pct,
                "digester_ph": sim_sync.state.ph,
                "mass_balance_residual_g_s": sim_sync.state.mass_balance_residual_g_s,
            },
            "register_map": {
                "analog_registers": "%R830..%R837",
                "discrete_coils": "%M193..%M195",
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if target_path:
        out_p = Path(target_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence
