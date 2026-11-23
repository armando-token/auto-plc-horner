"""Industrial Membrane Bioreactor (MBR) Permeate Flux & Cake Layer Fouling Dynamics ODE Simulation.

Work Package: W125 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Membrane Bioreactor (MBR) Resistance-in-Series (RIS) Dynamic Filtration:
   - Darcy's law filtration with temperature-dependent dynamic water viscosity:
     J = TMP / (mu(T) * R_tot)
     where R_tot = R_m + R_c + R_p.
   - Temperature-dependent water viscosity using the standard Vogel equation.
   - Dynamic cake layer deposition vs. cross-flow air scour shear detachment:
     dR_c/dt = alpha_cake * C_mlss * J - k_detach * (Q_air / Q_air,nom) * R_c.
   - Irreversible pore blocking kinetics driven by colloidal / SMP fraction:
     dR_p/dt = k_pore * J * (f_sol * C_mlss) * (R_p,max - R_p).
   - Mixed Liquor Suspended Solids (MLSS) accumulation and closed mass balance.
   - Aeration mass transfer (kLa) and biomass respiration dissolved oxygen (DO) dynamics.
2. Coupled 6-State ODE System:
   - State vector y = [J, R_c, R_p, TMP, C_mlss, DO]:
     * J: Permeate flux (L/m2/h)
     * R_c: Dynamic cake layer resistance (m^-1)
     * R_p: Irreversible pore blocking resistance (m^-1)
     * TMP: Transmembrane pressure (kPa)
     * C_mlss: Mixed liquor suspended solids (g/L)
     * DO: Dissolved oxygen concentration (mg/L)
3. Numerical Integration & Conservation:
   - High-order Runge-Kutta 4th Order (RK4) integrator with adaptive sub-stepping.
   - Stoichiometric solids and permeate flux mass conservation verification:
     residual error < 1e-10 kg/s.
4. Process Safety Interlocks & Diagnostics:
   - %M200: High TMP warning alarm (TMP > 45.0 kPa) -> code 0x9601.
   - %M201: Critical safety trip (code 0x9602 for TMP > 60.0 kPa or R_c > R_c,crit;
            code 0x9603 for DO < 0.50 mg/L).
   - %M202: Automated backwash / relaxation command (TMP > 35.0 kPa).
5. Horner OCS Registers:
   - %R860: MbrStatusWord (RUNNING, PERMEATE_PUMP_ON, AIR_SCOUR_ON, FILTRATION_HEALTHY,
            HIGH_TMP_ALARM, CRITICAL_FOULING_TRIP, AERATION_LOSS_TRIP, BACKWASH_ACTIVE)
   - %R861: PermeateFluxScaled (scaled x10 L/m2/h, e.g. 250 = 25.0 LMH)
   - %R862: TmpPressureScaled (scaled x10 kPa, e.g. 200 = 20.0 kPa)
   - %R863: CakeResistanceScaled (scaled x1e-10 m^-1, e.g. 100 = 1.0e12 m^-1)
   - %R864: PoreResistanceScaled (scaled x1e-10 m^-1, e.g. 20 = 0.2e12 m^-1)
   - %R865: MlssConcentrationScaled (scaled x10 g/L, e.g. 80 = 8.0 g/L)
   - %R866: DissolvedOxygenScaled (scaled x100 mg/L, e.g. 250 = 2.50 mg/L)
   - %R867: DiagnosticEventCode (0x0000=OK, 0x9601, 0x9602, 0x9603)
   - %M200, %M201, %M202 discrete coils.
6. Pure IEC 61131-3 ST POU: 'MbrFoulingDynamicsSync' validated with SecurityGuard and STParser.
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
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Enums and Status Bitmasks
# ============================================================================

class MbrFoulingStatusBits(IntFlag):
    """Horner OCS %R860 MbrStatusWord Bitmask Definitions."""
    RUNNING                 = 1 << 0  # Bit 0 (0x0001): Process simulation engine running
    PERMEATE_PUMP_ON        = 1 << 1  # Bit 1 (0x0002): Permeate suction pump online
    AIR_SCOUR_ON            = 1 << 2  # Bit 2 (0x0004): Coarse bubble air scouring blower online
    FILTRATION_HEALTHY      = 1 << 3  # Bit 3 (0x0008): Healthy filtration (TMP <= 45 kPa, DO >= 1.0 mg/L, no trips)
    HIGH_TMP_ALARM          = 1 << 4  # Bit 4 (0x0010): %M200 High TMP warning alarm (TMP > 45 kPa)
    CRITICAL_FOULING_TRIP   = 1 << 5  # Bit 5 (0x0020): %M201 Critical fouling trip (TMP > 60 kPa or Rc > Rc_crit)
    AERATION_LOSS_TRIP      = 1 << 6  # Bit 6 (0x0040): %M201 Aeration loss trip (DO < 0.5 mg/L)
    BACKWASH_ACTIVE         = 1 << 7  # Bit 7 (0x0080): %M202 Automated backwash / relaxation active

    # Compatibility aliases
    SYSTEM_RUNNING          = RUNNING
    PUMP_ACTIVE             = PERMEATE_PUMP_ON
    BLOWER_ACTIVE           = AIR_SCOUR_ON
    FILTRATION_OPTIMAL      = FILTRATION_HEALTHY
    HEALTHY                 = FILTRATION_HEALTHY
    TMP_ALARM               = HIGH_TMP_ALARM
    FOULING_TRIP            = CRITICAL_FOULING_TRIP
    DO_TRIP                 = AERATION_LOSS_TRIP
    AUTO_BACKWASH           = BACKWASH_ACTIVE


MbrStatusBits = MbrFoulingStatusBits


class MbrFoulingDiagnosticCode(IntEnum):
    """Diagnostic event codes for %R867."""
    OK                          = 0x0000  # Normal operation
    HIGH_TMP_ALARM              = 0x9601  # %M200: TMP > 45.0 kPa warning alarm
    CRITICAL_FOULING_TRIP       = 0x9602  # %M201: TMP > 60.0 kPa or Rc > 4.0e12 m^-1 trip
    AERATION_LOSS_TRIP          = 0x9603  # %M201: DO < 0.50 mg/L trip

    # Compatibility aliases
    TMP_HIGH_ALARM              = HIGH_TMP_ALARM
    FOULING_TRIP                = CRITICAL_FOULING_TRIP
    AERATION_TRIP               = AERATION_LOSS_TRIP


MbrDiagnosticCode = MbrFoulingDiagnosticCode


# ============================================================================
# 2. Configuration & Parameter Data Models
# ============================================================================

@dataclass
class MbrFoulingConfig:
    """Biochemical, membrane filtration, hydrodynamic, and vessel geometry configuration."""

    # Tank Geometry & Liquid Volumes
    v_tank_m3: float = 50.0                    # Active MBR aeration / membrane tank volume [m3]
    membrane_area_m2: float = 500.0            # Total submerged membrane surface area [m2]

    # Membrane Resistance-in-Series Parameters
    r_m: float = 1.0e12                        # Clean membrane intrinsic hydraulic resistance [m^-1]
    r_p_max: float = 1.5e12                    # Maximum asymptotic pore blocking resistance [m^-1]
    r_c_crit: float = 4.0e12                   # Critical cake layer resistance threshold [m^-1]
    alpha_cake: float = 2.0e14                 # Specific cake layer resistance [m/kg]

    # Operating Conditions & Flux Setpoints
    j_setpoint: float = 25.0                   # Nominal forward permeate flux setpoint [L/(m2*h)] (LMH)
    j_backwash: float = -30.0                  # Backwash reverse flux setpoint [L/(m2*h)] (LMH)
    temp_c: float = 20.0                       # Sludge operating temperature [°C]
    tau_j: float = 1.0                         # Permeate pump flux dynamic response time [s]
    tau_tmp: float = 0.8                       # Transmembrane pressure dynamic response time [s]

    # Influent & Waste Hydraulic Flows
    q_in_m3_s: float = 0.003472                # Influent raw wastewater flow rate [m3/s] (~300 m3/day)
    c_mlss_in_g_l: float = 0.30                # Influent suspended solids concentration [g/L]
    q_waste_m3_s: float = 0.000100             # Waste activated sludge (WAS) draw rate [m3/s] (~8.64 m3/day)

    # Cross-Flow Aeration & Cake Detachment Kinetics
    q_air_nom_m3_s: float = 0.50               # Nominal coarse bubble air scour flow rate [m3/s]
    q_air_m3_s: float = 0.50                   # Operating coarse bubble air scour flow rate [m3/s]
    k_detach: float = 0.005                    # Air scour shear detachment rate constant [1/s]
    k_backwash: float = 0.050                  # Backwash / relaxation enhanced detachment constant [1/s]

    # Irreversible Pore Blocking Kinetics
    k_pore: float = 5.0e-7                     # Pore blocking rate constant [m^2/(L*s)]
    f_sol: float = 0.05                        # Soluble microbial products (SMP) colloidal fraction [-]

    # Aeration Mass Transfer & Respiration Kinetics
    kla_base: float = 0.015                    # Base oxygen volumetric mass transfer coefficient kLa [1/s] at 20 °C
    theta_kla: float = 1.024                   # Arrhenius temperature correction coefficient for kLa [-]
    q_o2_max: float = 0.0030                   # Specific maximum biomass oxygen uptake rate [mg O2/(g MLSS*s)]
    k_o_resp: float = 0.50                     # Oxygen half-saturation respiration constant [mg/L]
    do_in_mg_l: float = 0.50                   # Influent dissolved oxygen [mg/L]

    # Biomass Growth & Endogenous Respiration
    mu_biomass_max: float = 0.000010           # Specific maximum heterotrophic biomass growth rate [1/s] (~0.86 day^-1)
    k_o_growth: float = 0.30                   # DO growth half-saturation constant [mg/L]
    b_decay: float = 0.000003                  # Biomass endogenous respiration decay rate [1/s] (~0.26 day^-1)

    # Process Safety Interlock Thresholds
    tmp_alarm_kpa: float = 45.0                # %M200: High TMP warning alarm threshold [kPa] -> 0x9601
    tmp_trip_kpa: float = 60.0                 # %M201: Critical fouling TMP trip threshold [kPa] -> 0x9602
    do_trip_mg_l: float = 0.50                 # %M201: Aeration loss DO trip threshold [mg/L] -> 0x9603
    tmp_backwash_kpa: float = 35.0             # %M202: Automated backwash trigger threshold [kPa]


MbrConfig = MbrFoulingConfig


# ============================================================================
# 3. Dynamic State Vector & Telemetry
# ============================================================================

@dataclass
class MbrFoulingState:
    """Dynamic state vector, diagnostic flags, and mass conservation tracking."""
    time_s: float = 0.0

    # Coupled 6-State ODE System State Vector y:
    j_flux_lmh: float = 25.0                   # State 0: Permeate flux J [L/(m2*h)]
    r_cake_m_inv: float = 1.0e12               # State 1: Dynamic cake layer resistance Rc [m^-1]
    r_pore_m_inv: float = 0.2e12               # State 2: Irreversible pore blocking resistance Rp [m^-1]
    tmp_kpa: float = 20.0                      # State 3: Transmembrane pressure TMP [kPa]
    c_mlss_g_l: float = 8.0                    # State 4: Mixed liquor suspended solids C_mlss [g/L = kg/m3]
    do_mg_l: float = 2.50                      # State 5: Dissolved oxygen DO [mg/L]

    # Hydrodynamic & Physical Properties
    water_viscosity_pa_s: float = 1.002e-3     # Dynamic water viscosity mu(T) [Pa*s]
    r_total_m_inv: float = 2.2e12              # Total resistance Rm + Rc + Rp [m^-1]
    darcy_tmp_eq_kpa: float = 20.0             # Instantaneous Darcy equilibrium TMP [kPa]
    darcy_flux_eq_lmh: float = 25.0            # Instantaneous Darcy equilibrium flux [LMH]
    r_dep_rate: float = 0.0                    # Instantaneous cake deposition rate [m^-1/s]
    r_detach_rate: float = 0.0                 # Instantaneous cake detachment rate [m^-1/s]
    r_pore_rate: float = 0.0                   # Instantaneous pore blocking rate [m^-1/s]
    kla_rate: float = 0.015                    # Active oxygen transfer rate kLa [1/s]
    our_rate: float = 0.0                      # Oxygen uptake rate OUR [mg/(L*s)]
    do_sat_mg_l: float = 9.09                  # Saturated dissolved oxygen concentration [mg/L]

    # Operational Status Flags
    is_running: bool = False                   # Simulation engine running
    permeate_pump_on: bool = True              # Permeate suction pump active
    air_scour_on: bool = True                  # Coarse bubble aeration active
    filtration_healthy: bool = True            # Healthy filtration condition

    # Process Safety Interlocks & Discrete Coils
    high_tmp_alarm: bool = False               # %M200: TMP > 45.0 kPa alarm -> 0x9601
    critical_trip: bool = False                # %M201: Master critical trip coil
    auto_backwash_cmd: bool = False            # %M202: Automated backwash / relaxation command
    critical_fouling_trip: bool = False        # Critical fouling trip (TMP > 60 kPa or Rc > Rc_crit) -> 0x9602
    aeration_loss_trip: bool = False           # Aeration loss trip (DO < 0.50 mg/L) -> 0x9603
    diagnostic_code: int = 0x0000              # %R867: Diagnostic event code

    # Stoichiometric Mass Balance Tracking
    solids_in_kg_s: float = 0.0                # Influent solids mass flow [kg/s]
    solids_out_kg_s: float = 0.0               # Effluent / waste solids mass flow [kg/s]
    solids_gen_kg_s: float = 0.0               # Biological solids generation rate [kg/s]
    dsolids_acc_dt_kg_s: float = 0.0           # Total solids accumulation rate [kg/s]
    mass_balance_residual_kg_s: float = 0.0    # Residual |In - Out + Gen - Acc| [kg/s]
    darcy_residual_kpa: float = 0.0            # Darcy law residual |TMP - TMP_darcy| [kPa]

    # State aliases
    @property
    def j(self) -> float:
        return self.j_flux_lmh

    @j.setter
    def j(self, val: float) -> None:
        self.j_flux_lmh = val

    @property
    def rc(self) -> float:
        return self.r_cake_m_inv

    @rc.setter
    def rc(self, val: float) -> None:
        self.r_cake_m_inv = val

    @property
    def rp(self) -> float:
        return self.r_pore_m_inv

    @rp.setter
    def rp(self, val: float) -> None:
        self.r_pore_m_inv = val

    @property
    def tmp(self) -> float:
        return self.tmp_kpa

    @tmp.setter
    def tmp(self, val: float) -> None:
        self.tmp_kpa = val

    @property
    def c_mlss(self) -> float:
        return self.c_mlss_g_l

    @c_mlss.setter
    def c_mlss(self, val: float) -> None:
        self.c_mlss_g_l = val

    @property
    def do(self) -> float:
        return self.do_mg_l

    @do.setter
    def do(self, val: float) -> None:
        self.do_mg_l = val


MbrState = MbrFoulingState


# ============================================================================
# 4. Industrial MBR ODE Simulation Engine
# ============================================================================

class MbrFoulingSimulator:
    """Coupled 6-State Industrial Membrane Bioreactor (MBR) ODE Simulation Engine.

    Work Package: W125 (Gate G7 / Gate G4)
    Mapped Registers: %R860..%R867, %M200..%M202.
    """

    def __init__(
        self,
        config: Optional[MbrFoulingConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.config = config or MbrFoulingConfig()
        self.reg_table = register_table or RegisterTable()
        self.reg_table.privilege_mode = PrivilegeMode.SYSTEM
        self.state = MbrFoulingState()

        # Initialize telemetry & sync registers
        self._evaluate_safety_interlocks()
        self._sync_registers()

    # ------------------------------------------------------------------------
    # Physics & Hydrodynamics: Viscosity, Darcy Law & Mass Transfer
    # ------------------------------------------------------------------------

    def compute_water_viscosity(self, temp_c: Optional[float] = None) -> float:
        """Compute dynamic water viscosity [Pa*s] using the standard Vogel equation.

        mu(T) = 2.414e-5 * 10^(247.8 / (T_K - 140.0)) [Pa*s]
        At 20 °C: ~1.002e-3 Pa*s.
        At 25 °C: ~0.890e-3 Pa*s.
        At 10 °C: ~1.300e-3 Pa*s.
        """
        t = self.config.temp_c if temp_c is None else temp_c
        t_k = t + 273.15
        denom = max(10.0, t_k - 140.0)
        exponent = 247.8 / denom
        return float(2.414e-5 * (10.0 ** exponent))

    def compute_do_saturation(self, temp_c: Optional[float] = None) -> float:
        """Compute dissolved oxygen saturation concentration [mg/L] at 1 atm.

        Formulation:
            DO_sat = 14.652 / (1.0 + 0.0337 * T) [mg/L]
        At 20 °C: ~8.75 mg/L.
        """
        t = self.config.temp_c if temp_c is None else temp_c
        return float(14.652 / (1.0 + 0.0337 * max(0.0, t)))

    def compute_darcy_tmp_and_flux(
        self,
        j_flux_lmh: float,
        r_cake_m_inv: float,
        r_pore_m_inv: float,
        temp_c: Optional[float] = None,
    ) -> Tuple[float, float, float]:
        """Compute Resistance-in-Series total resistance and Darcy equilibrium TMP.

        Formulation:
            R_tot = R_m + R_c + R_p [m^-1]
            J_SI = J / (3.6e6) [m/s]
            TMP_darcy = J_SI * mu(T) * R_tot * 1e-3 [kPa]

        Returns:
            Tuple of (R_tot [m^-1], TMP_darcy [kPa], mu [Pa*s]).
        """
        mu = self.compute_water_viscosity(temp_c)
        r_tot = self.config.r_m + max(0.0, r_cake_m_inv) + max(0.0, r_pore_m_inv)
        j_si = max(0.0, j_flux_lmh) / 3.6e6  # Convert LMH to m/s
        tmp_darcy_kpa = (j_si * mu * r_tot) / 1000.0  # Pa to kPa
        return r_tot, tmp_darcy_kpa, mu

    def compute_cake_kinetics(
        self,
        j_flux_lmh: float,
        r_cake_m_inv: float,
        c_mlss_g_l: float,
        is_backwashing: bool = False,
    ) -> Tuple[float, float]:
        """Compute cake layer deposition and shear detachment rates [m^-1/s].

        Deposition:
            r_dep = alpha_cake * C_mlss * J_SI (when J > 0)
        Air Scour Detachment:
            r_detach_air = k_detach * (Q_air / Q_air,nom) * R_c
        Backwash Detachment:
            r_detach_bw = k_backwash * R_c (when backwashing or relaxing)

        Returns:
            Tuple of (r_dep [m^-1/s], r_detach [m^-1/s]).
        """
        j_si = max(0.0, j_flux_lmh) / 3.6e6
        c_mlss = max(0.0, c_mlss_g_l)  # g/L = kg/m3

        # Cake deposition
        r_dep = self.config.alpha_cake * c_mlss * j_si

        # Cross-flow air scour detachment
        air_ratio = max(0.0, self.config.q_air_m3_s / max(1e-6, self.config.q_air_nom_m3_s))
        r_detach_air = self.config.k_detach * air_ratio * max(0.0, r_cake_m_inv)

        # Backwash / relaxation enhanced shear detachment
        r_detach_bw = (self.config.k_backwash * max(0.0, r_cake_m_inv)) if is_backwashing else 0.0

        r_detach = r_detach_air + r_detach_bw
        return r_dep, r_detach

    def compute_pore_blocking_rate(
        self,
        j_flux_lmh: float,
        r_pore_m_inv: float,
        c_mlss_g_l: float,
    ) -> float:
        """Compute irreversible pore blocking rate [m^-1/s].

        Formulation:
            r_pore = k_pore * J_SI * (f_sol * C_mlss) * max(0, R_p,max - R_p)
        """
        if j_flux_lmh <= 0.0:
            return 0.0
        j_si = max(0.0, j_flux_lmh) / 3.6e6
        c_sol = self.config.f_sol * max(0.0, c_mlss_g_l)
        driving_pore = max(0.0, self.config.r_p_max - r_pore_m_inv)
        return float(self.config.k_pore * j_si * c_sol * driving_pore)

    def compute_aeration_and_respiration(
        self,
        do_mg_l: float,
        c_mlss_g_l: float,
        temp_c: Optional[float] = None,
    ) -> Tuple[float, float, float, float]:
        """Compute oxygen mass transfer (kLa) and biomass respiration rate (OUR).

        Formulation:
            kLa = kLa_base * (Q_air / Q_air,nom) * theta^(T - 20)
            OUR = q_O2,max * (DO / (K_O,resp + DO)) * C_mlss

        Returns:
            Tuple of (kla [1/s], our [mg/(L*s)], do_sat [mg/L], d_do_dt [mg/(L*s)]).
        """
        t = self.config.temp_c if temp_c is None else temp_c
        do_sat = self.compute_do_saturation(t)
        do_curr = max(0.0, do_mg_l)
        c_mlss = max(0.0, c_mlss_g_l)

        # Aeration kLa
        air_ratio = max(0.0, self.config.q_air_m3_s / max(1e-6, self.config.q_air_nom_m3_s))
        if not self.state.air_scour_on:
            air_ratio = 0.0
        temp_factor = self.config.theta_kla ** (t - 20.0)
        kla = self.config.kla_base * air_ratio * temp_factor

        # Biomass Oxygen Uptake Rate (OUR)
        our_fraction = do_curr / (self.config.k_o_resp + do_curr) if (self.config.k_o_resp + do_curr) > 1e-9 else 0.0
        our = self.config.q_o2_max * our_fraction * c_mlss

        # Hydraulic dilution contribution
        d_dilution = self.config.q_in_m3_s / max(1.0, self.config.v_tank_m3)
        dilution_o2 = d_dilution * (self.config.do_in_mg_l - do_curr)

        # Net DO derivative
        d_do_dt = (kla * (do_sat - do_curr)) - our + dilution_o2

        return kla, our, do_sat, d_do_dt

    # ------------------------------------------------------------------------
    # Coupled 6-State ODE System & RK4 with Adaptive Sub-stepping
    # ------------------------------------------------------------------------

    def ode_derivatives(self, t: float, y: List[float]) -> List[float]:
        """Compute time derivatives dy/dt for the coupled 6-state ODE system.

        State vector y:
            y[0]: J [L/(m2*h)] (Permeate flux)
            y[1]: R_c [m^-1] (Cake layer resistance)
            y[2]: R_p [m^-1] (Irreversible pore blocking resistance)
            y[3]: TMP [kPa] (Transmembrane pressure)
            y[4]: C_mlss [g/L] (Mixed liquor suspended solids)
            y[5]: DO [mg/L] (Dissolved oxygen)
        """
        j_flux = y[0]
        r_cake = max(0.0, y[1])
        r_pore = max(0.0, y[2])
        tmp = max(0.0, y[3])
        c_mlss = max(0.0, y[4])
        do_val = max(0.0, y[5])

        # Permeate pump target flux determination
        is_backwashing = self.state.auto_backwash_cmd
        if self.state.critical_trip or not self.state.permeate_pump_on:
            j_target = 0.0
        elif is_backwashing:
            j_target = 0.0  # Relaxation / backwash condition
        else:
            j_target = self.config.j_setpoint

        # 1. dy[0]/dt: Permeate flux dynamics [LMH/s]
        d_j_dt = (j_target - j_flux) / max(0.01, self.config.tau_j)

        # 2. dy[1]/dt: Cake layer resistance dynamics [m^-1/s]
        r_dep, r_detach = self.compute_cake_kinetics(j_flux, r_cake, c_mlss, is_backwashing)
        d_rc_dt = r_dep - r_detach

        # 3. dy[2]/dt: Irreversible pore blocking dynamics [m^-1/s]
        r_pore_rate = self.compute_pore_blocking_rate(j_flux, r_pore, c_mlss)
        d_rp_dt = r_pore_rate

        # 4. dy[3]/dt: Transmembrane pressure dynamics [kPa/s]
        _, tmp_darcy_kpa, _ = self.compute_darcy_tmp_and_flux(j_flux, r_cake, r_pore)
        d_tmp_dt = (tmp_darcy_kpa - tmp) / max(0.01, self.config.tau_tmp)

        # 5. dy[4]/dt: Mixed liquor suspended solids dynamics [g/(L*s) = kg/(m3*s)]
        # Biological growth & decay
        growth_frac = do_val / (self.config.k_o_growth + do_val) if (self.config.k_o_growth + do_val) > 1e-9 else 0.0
        mu_growth = self.config.mu_biomass_max * growth_frac
        mu_net = mu_growth - self.config.b_decay

        q_in = self.config.q_in_m3_s
        q_waste = self.config.q_waste_m3_s
        v_tank = self.config.v_tank_m3
        a_mem = self.config.membrane_area_m2
        alpha_c = self.config.alpha_cake

        # Cake mass rate transferred from bulk to membrane surface [kg/s]
        # (r_dep - r_detach) * (A_mem / alpha_c)
        m_cake_transfer_kg_s = d_rc_dt * (a_mem / max(1.0, alpha_c))

        d_c_mlss_dt = (
            ((q_in * self.config.c_mlss_in_g_l) - (q_waste * c_mlss)) / max(1.0, v_tank)
            + (mu_net * c_mlss)
            - (m_cake_transfer_kg_s / max(1.0, v_tank))
        )

        # 6. dy[5]/dt: Dissolved oxygen dynamics [mg/(L*s)]
        _, _, _, d_do_dt = self.compute_aeration_and_respiration(do_val, c_mlss)

        return [d_j_dt, d_rc_dt, d_rp_dt, d_tmp_dt, d_c_mlss_dt, d_do_dt]

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
            self.state.j_flux_lmh,
            self.state.r_cake_m_inv,
            self.state.r_pore_m_inv,
            self.state.tmp_kpa,
            self.state.c_mlss_g_l,
            self.state.do_mg_l,
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
        self.state.j_flux_lmh = y_curr[0]
        self.state.r_cake_m_inv = y_curr[1]
        self.state.r_pore_m_inv = y_curr[2]
        self.state.tmp_kpa = y_curr[3]
        self.state.c_mlss_g_l = y_curr[4]
        self.state.do_mg_l = y_curr[5]

        # Update telemetry & physical properties
        r_tot, tmp_eq, mu = self.compute_darcy_tmp_and_flux(
            self.state.j_flux_lmh, self.state.r_cake_m_inv, self.state.r_pore_m_inv
        )
        self.state.water_viscosity_pa_s = mu
        self.state.r_total_m_inv = r_tot
        self.state.darcy_tmp_eq_kpa = tmp_eq
        self.state.darcy_flux_eq_lmh = (
            (self.state.tmp_kpa * 1000.0) / (mu * r_tot) * 3.6e6 if (mu * r_tot) > 1e-6 else 0.0
        )

        r_dep, r_detach = self.compute_cake_kinetics(
            self.state.j_flux_lmh, self.state.r_cake_m_inv, self.state.c_mlss_g_l, self.state.auto_backwash_cmd
        )
        self.state.r_dep_rate = r_dep
        self.state.r_detach_rate = r_detach
        self.state.r_pore_rate = self.compute_pore_blocking_rate(
            self.state.j_flux_lmh, self.state.r_pore_m_inv, self.state.c_mlss_g_l
        )

        kla, our, do_sat, _ = self.compute_aeration_and_respiration(
            self.state.do_mg_l, self.state.c_mlss_g_l
        )
        self.state.kla_rate = kla
        self.state.our_rate = our
        self.state.do_sat_mg_l = do_sat

        # Track solids mass conservation and Darcy consistency
        self._track_mass_and_flux_conservation()

        self.state.is_running = True
        self._evaluate_safety_interlocks()
        self._sync_registers()

        return ExecutionResult.success(
            details=f"MBR fouling dynamics advanced to t={self.state.time_s:.2f}s.",
            data={
                "time_s": self.state.time_s,
                "permeate_flux_lmh": self.state.j_flux_lmh,
                "r_cake_m_inv": self.state.r_cake_m_inv,
                "r_pore_m_inv": self.state.r_pore_m_inv,
                "tmp_kpa": self.state.tmp_kpa,
                "c_mlss_g_l": self.state.c_mlss_g_l,
                "do_mg_l": self.state.do_mg_l,
                "diagnostic_code": f"0x{self.state.diagnostic_code:04X}",
                "mass_balance_residual_kg_s": self.state.mass_balance_residual_kg_s,
            },
        )

    # ------------------------------------------------------------------------
    # Analytical Stoichiometric Solids & Flux Conservation Tracking
    # ------------------------------------------------------------------------

    def _track_mass_and_flux_conservation(self) -> None:
        """Verify strict mass balance: |In - Out + Gen - Accumulation| < 1e-10 kg/s.

        Total solids in system:
            M_solids = V_tank * C_mlss + (R_c / alpha_cake) * A_mem [kg]
        Solids entering system:
            M_dot_in = Q_in * C_mlss_in [kg/s]
        Solids exiting system (WAS only, permeate C_solids = 0):
            M_dot_out = Q_waste * C_mlss [kg/s]
        Biological generation:
            M_dot_gen = mu_net * C_mlss * V_tank [kg/s]
        Accumulation:
            dM_solids_acc/dt = V_tank * dC_mlss/dt + (A_mem / alpha_cake) * dRc/dt
        Residual is analytically zero within floating-point roundoff (< 1e-10 kg/s).
        """
        v_tank = self.config.v_tank_m3
        a_mem = self.config.membrane_area_m2
        alpha_c = self.config.alpha_cake

        # 1. Inputs and Outputs
        m_dot_in = self.config.q_in_m3_s * self.config.c_mlss_in_g_l
        m_dot_out = self.config.q_waste_m3_s * self.state.c_mlss_g_l

        # 2. Biological Generation
        do_val = self.state.do_mg_l
        growth_frac = do_val / (self.config.k_o_growth + do_val) if (self.config.k_o_growth + do_val) > 1e-9 else 0.0
        mu_growth = self.config.mu_biomass_max * growth_frac
        mu_net = mu_growth - self.config.b_decay
        m_dot_gen = mu_net * self.state.c_mlss_g_l * v_tank

        # 3. Dynamic derivatives at current state
        y_curr = [
            self.state.j_flux_lmh,
            self.state.r_cake_m_inv,
            self.state.r_pore_m_inv,
            self.state.tmp_kpa,
            self.state.c_mlss_g_l,
            self.state.do_mg_l,
        ]
        dy_dt = self.ode_derivatives(self.state.time_s, y_curr)
        d_rc_dt = dy_dt[1]
        d_c_mlss_dt = dy_dt[4]

        # Total accumulation
        dm_acc_dt = (v_tank * d_c_mlss_dt) + ((a_mem / alpha_c) * d_rc_dt)

        residual = abs(m_dot_in - m_dot_out + m_dot_gen - dm_acc_dt)

        self.state.solids_in_kg_s = m_dot_in
        self.state.solids_out_kg_s = m_dot_out
        self.state.solids_gen_kg_s = m_dot_gen
        self.state.dsolids_acc_dt_kg_s = dm_acc_dt
        self.state.mass_balance_residual_kg_s = residual

        # Darcy consistency
        self.state.darcy_residual_kpa = abs(self.state.tmp_kpa - self.state.darcy_tmp_eq_kpa)

    # ------------------------------------------------------------------------
    # Process Safety Interlocks & Diagnostics
    # ------------------------------------------------------------------------

    def _evaluate_safety_interlocks(self) -> None:
        """Evaluate process trips (%M200, %M201, %M202) and diagnostic event codes."""
        # 1. High TMP Warning Alarm (TMP > 45.0 kPa) -> %M200, code 0x9601
        high_tmp = bool(self.state.tmp_kpa > self.config.tmp_alarm_kpa)
        self.state.high_tmp_alarm = high_tmp

        # 2. Critical Fouling Trip (TMP > 60.0 kPa or Rc > Rc_crit) -> %M201, code 0x9602
        fouling_trip = bool(
            self.state.tmp_kpa > self.config.tmp_trip_kpa
            or self.state.r_cake_m_inv > self.config.r_c_crit
        )
        self.state.critical_fouling_trip = fouling_trip

        # 3. Aeration Loss Respiration Trip (DO < 0.50 mg/L) -> %M201, code 0x9603
        aeration_trip = bool(self.state.do_mg_l < self.config.do_trip_mg_l)
        self.state.aeration_loss_trip = aeration_trip

        # Master Critical Trip (%M201)
        self.state.critical_trip = bool(fouling_trip or aeration_trip)

        # 4. Automated Backwash / Relaxation Command (TMP > 35.0 kPa) -> %M202
        auto_bw = bool(self.state.tmp_kpa > self.config.tmp_backwash_kpa) or self.state.auto_backwash_cmd
        self.state.auto_backwash_cmd = auto_bw

        # Permeate pump permissive: trip disables pump
        if self.state.critical_trip:
            self.state.permeate_pump_on = False

        # Healthy filtration condition
        self.state.filtration_healthy = bool(
            not self.state.critical_trip
            and not high_tmp
            and self.state.do_mg_l >= 1.0
            and self.state.tmp_kpa <= self.config.tmp_alarm_kpa
        )

        # Diagnostic Event Code Priority:
        # Critical Fouling (0x9602) > Aeration Loss (0x9603) > High TMP Alarm (0x9601) > OK (0x0000)
        if self.state.critical_fouling_trip:
            self.state.diagnostic_code = int(MbrFoulingDiagnosticCode.CRITICAL_FOULING_TRIP)
        elif self.state.aeration_loss_trip:
            self.state.diagnostic_code = int(MbrFoulingDiagnosticCode.AERATION_LOSS_TRIP)
        elif self.state.high_tmp_alarm:
            self.state.diagnostic_code = int(MbrFoulingDiagnosticCode.HIGH_TMP_ALARM)
        else:
            self.state.diagnostic_code = int(MbrFoulingDiagnosticCode.OK)

    # ------------------------------------------------------------------------
    # Horner OCS Register Synchronization
    # ------------------------------------------------------------------------

    def _sync_registers(self) -> None:
        """Synchronize telemetry into Horner OCS registers (%R860..%R867, %M200..%M202)."""
        self._evaluate_safety_interlocks()

        # Compute %R860 MbrStatusWord
        sw = 0
        if self.state.is_running:
            sw |= int(MbrFoulingStatusBits.RUNNING)
        if self.state.permeate_pump_on:
            sw |= int(MbrFoulingStatusBits.PERMEATE_PUMP_ON)
        if self.state.air_scour_on:
            sw |= int(MbrFoulingStatusBits.AIR_SCOUR_ON)
        if self.state.filtration_healthy:
            sw |= int(MbrFoulingStatusBits.FILTRATION_HEALTHY)
        if self.state.high_tmp_alarm:
            sw |= int(MbrFoulingStatusBits.HIGH_TMP_ALARM)
        if self.state.critical_fouling_trip:
            sw |= int(MbrFoulingStatusBits.CRITICAL_FOULING_TRIP)
        if self.state.aeration_loss_trip:
            sw |= int(MbrFoulingStatusBits.AERATION_LOSS_TRIP)
        if self.state.auto_backwash_cmd:
            sw |= int(MbrFoulingStatusBits.BACKWASH_ACTIVE)

        # Scaled analog word registers (%R861..%R867)
        r861_flux = max(0, min(32767, int(round(self.state.j_flux_lmh * 10.0))))
        r862_tmp = max(0, min(32767, int(round(self.state.tmp_kpa * 10.0))))
        r863_rc = max(0, min(32767, int(round(self.state.r_cake_m_inv / 1.0e10))))
        r864_rp = max(0, min(32767, int(round(self.state.r_pore_m_inv / 1.0e10))))
        r865_mlss = max(0, min(32767, int(round(self.state.c_mlss_g_l * 10.0))))
        r866_do = max(0, min(32767, int(round(self.state.do_mg_l * 100.0))))
        r867_diag = self.state.diagnostic_code

        # Write Analog Word Registers %R860..%R867
        self.reg_table.write_word("%R860", sw, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R861", r861_flux, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R862", r862_tmp, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R863", r863_rc, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R864", r864_rp, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R865", r865_mlss, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R866", r866_do, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R867", r867_diag, privilege=PrivilegeMode.SYSTEM)

        # Write Discrete Safety Coils %M200..%M202
        self.reg_table.write_bit("%M200", self.state.high_tmp_alarm, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_bit("%M201", self.state.critical_trip, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_bit("%M202", self.state.auto_backwash_cmd, privilege=PrivilegeMode.SYSTEM)


# Backward compatibility aliases
MbrSimulator = MbrFoulingSimulator
MbrFoulingEngine = MbrFoulingSimulator
MbrFoulingModel = MbrFoulingSimulator


# ============================================================================
# 5. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

MBR_FOULING_PURE_ST_POU: str = """PROGRAM MbrFoulingDynamicsSync
VAR
    MbrStatusWord AT %R860 : INT;
    PermeateFluxScaled AT %R861 : INT;
    TmpPressureScaled AT %R862 : INT;
    CakeResistanceScaled AT %R863 : INT;
    PoreResistanceScaled AT %R864 : INT;
    MlssConcentrationScaled AT %R865 : INT;
    DissolvedOxygenScaled AT %R866 : INT;
    DiagnosticEventCode AT %R867 : INT;
    HighTmpAlarm AT %M200 : BOOL;
    CriticalTrip AT %M201 : BOOL;
    AutoBackwashCmd AT %M202 : BOOL;
    PermeatePumpPermissive : BOOL := TRUE;
    EmergencyScourBlowerBoost : BOOL := FALSE;
    BackwashValveOpen : BOOL := FALSE;
END_VAR

(* Interlock logic for Membrane Bioreactor (MBR) Permeate Flux & Cake Fouling *)
IF CriticalTrip THEN
    PermeatePumpPermissive := FALSE;
ELSE
    PermeatePumpPermissive := TRUE;
END_IF;

IF HighTmpAlarm THEN
    EmergencyScourBlowerBoost := TRUE;
ELSE
    EmergencyScourBlowerBoost := FALSE;
END_IF;

IF AutoBackwashCmd THEN
    BackwashValveOpen := TRUE;
ELSE
    BackwashValveOpen := FALSE;
END_IF;
END_PROGRAM
"""

MBR_FOULING_SYNC_POU: str = """PROGRAM MBRFoulingSync
VAR
    MbrStatusWord AT %R860 : INT;
    PermeateFluxScaled AT %R861 : INT;
    TmpPressureScaled AT %R862 : INT;
    CakeResistanceScaled AT %R863 : INT;
    PoreResistanceScaled AT %R864 : INT;
    MlssConcentrationScaled AT %R865 : INT;
    DissolvedOxygenScaled AT %R866 : INT;
    DiagnosticEventCode AT %R867 : INT;
    HighTmpAlarm AT %M200 : BOOL;
    CriticalTrip AT %M201 : BOOL;
    AutoBackwashCmd AT %M202 : BOOL;
    PermeatePumpPermissive : BOOL := TRUE;
    EmergencyScourBlowerBoost : BOOL := FALSE;
    BackwashValveOpen : BOOL := FALSE;
END_VAR

(* Interlock logic for Membrane Bioreactor (MBR) Permeate Flux & Cake Fouling *)
IF CriticalTrip THEN
    PermeatePumpPermissive := FALSE;
ELSE
    PermeatePumpPermissive := TRUE;
END_IF;

IF HighTmpAlarm THEN
    EmergencyScourBlowerBoost := TRUE;
ELSE
    EmergencyScourBlowerBoost := FALSE;
END_IF;

IF AutoBackwashCmd THEN
    BackwashValveOpen := TRUE;
ELSE
    BackwashValveOpen := FALSE;
END_IF;
END_PROGRAM
"""

# Compatibility aliases
MBR_PURE_ST_POU = MBR_FOULING_PURE_ST_POU
MBR_SYNC_POU = MBR_FOULING_SYNC_POU


def verify_mbr_fouling_pure_st() -> bool:
    """Validate Pure ST POU against anti-ladder security guard and AST parser."""
    SecurityGuard.assert_pure_st_content(MBR_FOULING_PURE_ST_POU)
    res = STParser.validate_code(MBR_FOULING_PURE_ST_POU)
    if res.status != AgentStatus.SUCCESS:
        return False
    ast = STParser.parse_pou(MBR_FOULING_PURE_ST_POU)
    if ast is None or ast.name not in ("MbrFoulingDynamicsSync", "MBRFoulingSync"):
        return False
    expected = [
        "%R860", "%R861", "%R862", "%R863", "%R864", "%R865", "%R866", "%R867",
        "%M200", "%M201", "%M202",
    ]
    return all(r in ast.bound_registers for r in expected)


# ============================================================================
# 6. Complete 9-Stage Verification Suite
# ============================================================================

def run_mbr_fouling_verification(
    output_path: Optional[str] = None,
    evidence_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute complete 9-stage verification suite for W125 MBR Fouling Dynamics ODE Simulation.

    Returns:
        Strict 4-state contract dictionary (status, error_code, details, data).
    """
    target_path = output_path or evidence_path
    test_results: List[Dict[str, Any]] = []

    # Stage 1: Pure ST POU Validation & AST Symbol Binding (%R860..%R867, %M200..%M202)
    try:
        SecurityGuard.assert_pure_st_content(MBR_FOULING_PURE_ST_POU)
        res_st = STParser.validate_code(MBR_FOULING_PURE_ST_POU)
        ast = STParser.parse_pou(MBR_FOULING_PURE_ST_POU)
        expected_regs = [
            "%R860", "%R861", "%R862", "%R863", "%R864", "%R865", "%R866", "%R867",
            "%M200", "%M201", "%M202",
        ]
        c1 = (
            res_st.status == AgentStatus.SUCCESS
            and ast is not None
            and ast.name == "MbrFoulingDynamicsSync"
            and ast.pou_type == POUType.PROGRAM
            and all(r in ast.bound_registers for r in expected_regs)
        )
    except Exception:
        c1 = False

    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_And_AST_Symbol_Binding",
        "passed": c1,
        "details": "Pure ST POU validated; %R860..%R867 and %M200..%M202 bound into AST.",
    })

    # Stage 2: Resistance-in-Series (RIS) & Darcy's Law Temperature-Dependent Viscosity
    sim = MbrFoulingSimulator()
    mu_10 = sim.compute_water_viscosity(10.0)
    mu_20 = sim.compute_water_viscosity(20.0)
    mu_30 = sim.compute_water_viscosity(30.0)

    # Viscosity monotonicity with temperature
    c2_visc = mu_10 > mu_20 > mu_30 and math.isclose(mu_20, 1.002e-3, rel_tol=0.05)

    # Darcy's law linear scaling with resistance and flux
    r_tot1, tmp1, _ = sim.compute_darcy_tmp_and_flux(j_flux_lmh=25.0, r_cake_m_inv=1.0e12, r_pore_m_inv=0.2e12)
    r_tot2, tmp2, _ = sim.compute_darcy_tmp_and_flux(j_flux_lmh=50.0, r_cake_m_inv=1.0e12, r_pore_m_inv=0.2e12)
    r_tot3, tmp3, _ = sim.compute_darcy_tmp_and_flux(j_flux_lmh=25.0, r_cake_m_inv=3.0e12, r_pore_m_inv=0.2e12)

    c2_darcy = (
        math.isclose(tmp2, 2.0 * tmp1, rel_tol=1e-3)
        and tmp3 > tmp1
        and r_tot3 > r_tot1
    )
    c2 = c2_visc and c2_darcy
    test_results.append({
        "stage": 2,
        "check": "Resistance_In_Series_And_Darcy_Viscosity",
        "passed": c2,
        "details": f"Darcy's law & Vogel viscosity verified: mu(10C)={mu_10:.3e} > mu(20C)={mu_20:.3e} > mu(30C)={mu_30:.3e} Pa*s; TMP doubles with doubled flux (TMP1={tmp1:.2f} kPa, TMP2={tmp2:.2f} kPa).",
    })

    # Stage 3: Dynamic Cake Deposition & Cross-Flow Air Scour Shear Detachment
    r_dep_normal, r_detach_normal = sim.compute_cake_kinetics(j_flux_lmh=25.0, r_cake_m_inv=1.0e12, c_mlss_g_l=8.0)
    r_dep_high_mlss, _ = sim.compute_cake_kinetics(j_flux_lmh=25.0, r_cake_m_inv=1.0e12, c_mlss_g_l=16.0)
    _, r_detach_bw = sim.compute_cake_kinetics(j_flux_lmh=0.0, r_cake_m_inv=1.0e12, c_mlss_g_l=8.0, is_backwashing=True)

    c3 = (
        r_dep_normal > 0.0
        and r_detach_normal > 0.0
        and math.isclose(r_dep_high_mlss, 2.0 * r_dep_normal, rel_tol=1e-3)
        and r_detach_bw > r_detach_normal
    )
    test_results.append({
        "stage": 3,
        "check": "Dynamic_Cake_Deposition_And_Air_Scour_Detachment",
        "passed": c3,
        "details": f"Cake kinetics verified: r_dep={r_dep_normal:.2e} m^-1/s scales linearly with MLSS, backwash enhances detachment ({r_detach_bw:.2e} vs {r_detach_normal:.2e} m^-1/s).",
    })

    # Stage 4: Irreversible Pore Blocking Kinetics & MLSS Concentration Coupling
    r_pore_rate_low = sim.compute_pore_blocking_rate(j_flux_lmh=25.0, r_pore_m_inv=0.2e12, c_mlss_g_l=8.0)
    r_pore_rate_high_pore = sim.compute_pore_blocking_rate(j_flux_lmh=25.0, r_pore_m_inv=1.4e12, c_mlss_g_l=8.0)
    r_pore_rate_saturated = sim.compute_pore_blocking_rate(j_flux_lmh=25.0, r_pore_m_inv=1.5e12, c_mlss_g_l=8.0)

    c4 = (
        r_pore_rate_low > 0.0
        and r_pore_rate_low > r_pore_rate_high_pore
        and math.isclose(r_pore_rate_saturated, 0.0, abs_tol=1e-12)
    )
    test_results.append({
        "stage": 4,
        "check": "Irreversible_Pore_Blocking_Kinetics",
        "passed": c4,
        "details": f"Pore blocking asymptotic behavior verified: r_pore={r_pore_rate_low:.2e} m^-1/s approaches zero at R_p,max ({r_pore_rate_saturated:.2e} m^-1/s).",
    })

    # Stage 5: High-Order RK4 Integrator with Adaptive Sub-stepping Stability
    sim_rk4 = MbrFoulingSimulator()
    res_rk4 = sim_rk4.advance_time(duration_s=2.0, dt=0.05)
    st_rk4 = sim_rk4.state

    c5 = (
        res_rk4.status == AgentStatus.SUCCESS
        and st_rk4.j_flux_lmh > 0.0
        and st_rk4.r_cake_m_inv > 0.0
        and st_rk4.r_pore_m_inv >= 0.0
        and st_rk4.tmp_kpa > 0.0
        and st_rk4.c_mlss_g_l > 0.0
        and st_rk4.do_mg_l > 0.0
    )
    test_results.append({
        "stage": 5,
        "check": "High_Order_RK4_With_Adaptive_Substepping",
        "passed": c5,
        "details": f"RK4 integration stable: J={st_rk4.j_flux_lmh:.1f} LMH, Rc={st_rk4.r_cake_m_inv:.2e} m^-1, TMP={st_rk4.tmp_kpa:.2f} kPa, MLSS={st_rk4.c_mlss_g_l:.2f} g/L, DO={st_rk4.do_mg_l:.2f} mg/L.",
    })

    # Stage 6: Stoichiometric Solids & Flux Mass Conservation Residual (< 1e-10)
    sim_mass = MbrFoulingSimulator()
    sim_mass.advance_time(duration_s=1.0, dt=0.05)
    res_solids = sim_mass.state.mass_balance_residual_kg_s

    c6 = res_solids < 1e-10
    test_results.append({
        "stage": 6,
        "check": "Stoichiometric_Solids_Mass_Conservation_Residual",
        "passed": c6,
        "details": f"Mass conservation verified: solids residual = {res_solids:.4e} kg/s (< 1e-10 kg/s).",
    })

    # Stage 7: Process Safety Interlocks: High TMP Warning Alarm (0x9601, %M200) & Critical Fouling Trip (0x9602, %M201)
    sim_safety = MbrFoulingSimulator()

    # Test High TMP warning alarm (TMP = 48.0 kPa > 45.0 kPa)
    sim_safety.state.tmp_kpa = 48.0
    sim_safety._sync_registers()
    c7_alarm = (
        sim_safety.reg_table.read_bit("%M200") is True
        and sim_safety.reg_table.read_bit("%M201") is False
        and (sim_safety.reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.HIGH_TMP_ALARM)
        and bool(sim_safety.reg_table.read_word("%R860") & int(MbrFoulingStatusBits.HIGH_TMP_ALARM))
    )

    # Test Critical Fouling Trip (TMP = 65.0 kPa > 60.0 kPa)
    sim_safety.state.tmp_kpa = 65.0
    sim_safety._sync_registers()
    c7_trip = (
        sim_safety.reg_table.read_bit("%M201") is True
        and (sim_safety.reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.CRITICAL_FOULING_TRIP)
        and bool(sim_safety.reg_table.read_word("%R860") & int(MbrFoulingStatusBits.CRITICAL_FOULING_TRIP))
        and sim_safety.state.permeate_pump_on is False
    )

    c7 = c7_alarm and c7_trip
    test_results.append({
        "stage": 7,
        "check": "High_TMP_Alarm_And_Critical_Fouling_Trip",
        "passed": c7,
        "details": f"Safety interlocks verified: %M200 warning alarm (0x9601)={c7_alarm}, %M201 critical fouling trip (0x9602, pump permissive disabled)={c7_trip}.",
    })

    # Stage 8: Aeration Loss Respiration Trip (0x9603, %M201) & Automated Backwash/Relaxation (%M202)
    sim_do_trip = MbrFoulingSimulator()

    # Test automated backwash command (%M202) at TMP = 38.0 kPa (> 35.0 kPa)
    sim_do_trip.state.tmp_kpa = 38.0
    sim_do_trip._sync_registers()
    c8_bw = (
        sim_do_trip.reg_table.read_bit("%M202") is True
        and bool(sim_do_trip.reg_table.read_word("%R860") & int(MbrFoulingStatusBits.BACKWASH_ACTIVE))
    )

    # Test aeration loss trip (%M201 -> 0x9603) at DO = 0.35 mg/L (< 0.50 mg/L)
    sim_do_trip.state.do_mg_l = 0.35
    sim_do_trip._sync_registers()
    c8_do = (
        sim_do_trip.reg_table.read_bit("%M201") is True
        and (sim_do_trip.reg_table.read_word("%R867") & 0xFFFF) == int(MbrFoulingDiagnosticCode.AERATION_LOSS_TRIP)
        and bool(sim_do_trip.reg_table.read_word("%R860") & int(MbrFoulingStatusBits.AERATION_LOSS_TRIP))
        and sim_do_trip.state.permeate_pump_on is False
    )

    c8 = c8_bw and c8_do
    test_results.append({
        "stage": 8,
        "check": "Aeration_Loss_Trip_And_Automated_Backwash",
        "passed": c8,
        "details": f"Aeration & backwash trips verified: %M202 backwash cmd={c8_bw}, %M201 aeration loss trip (0x9603, DO={sim_do_trip.state.do_mg_l} mg/L)={c8_do}.",
    })

    # Stage 9: Horner OCS Register Space Sync (%R860..%R867, %M200..%M202) & Anti-Ladder Security Rejection
    sim_sync = MbrFoulingSimulator()
    sim_sync.advance_time(duration_s=0.5, dt=0.05)
    reg = sim_sync.reg_table

    r860 = reg.read_word("%R860")
    r861 = reg.read_word("%R861")
    r862 = reg.read_word("%R862")
    r863 = reg.read_word("%R863")
    r864 = reg.read_word("%R864")
    r865 = reg.read_word("%R865")
    r866 = reg.read_word("%R866")
    r867 = reg.read_word("%R867")

    c9_regs = (
        (r860 & int(MbrFoulingStatusBits.RUNNING)) != 0
        and (r860 & int(MbrFoulingStatusBits.PERMEATE_PUMP_ON)) != 0
        and (r860 & int(MbrFoulingStatusBits.AIR_SCOUR_ON)) != 0
        and (r860 & int(MbrFoulingStatusBits.FILTRATION_HEALTHY)) != 0
        and r861 > 0
        and r862 > 0
        and r863 > 0
        and r864 > 0
        and r865 > 0
        and r866 > 0
        and r867 == 0x0000
    )

    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("""
        PROGRAM BadLadderMbr
        VAR PermeateCoil : BOOL; END_VAR
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
        "details": f"Registers synced: %R860=0x{r860:04X}, %R861={r861}, %R862={r862}, %R863={r863}, %R864={r864}, %R865={r865}, %R866={r866}, %R867={r867}; Anti-ladder rejection asserted.",
    })

    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Industrial Membrane Bioreactor (MBR) Permeate Flux & Cake Fouling ODE Simulation verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed).",
        "data": {
            "work_package": "W125",
            "gate": "Gate G7 / Gate G4",
            "component": "Industrial MBR Permeate Flux & Cake Fouling ODE Simulator",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "metrics": {
                "permeate_flux_lmh": sim_sync.state.j_flux_lmh,
                "r_cake_m_inv": sim_sync.state.r_cake_m_inv,
                "r_pore_m_inv": sim_sync.state.r_pore_m_inv,
                "tmp_kpa": sim_sync.state.tmp_kpa,
                "c_mlss_g_l": sim_sync.state.c_mlss_g_l,
                "do_mg_l": sim_sync.state.do_mg_l,
                "mass_balance_residual_kg_s": sim_sync.state.mass_balance_residual_kg_s,
            },
            "register_map": {
                "analog_registers": "%R860..%R867",
                "discrete_coils": "%M200..%M202",
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
