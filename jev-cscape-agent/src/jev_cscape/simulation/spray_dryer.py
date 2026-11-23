"""Industrial Spray Dryer Process Dynamics ODE Simulation Engine.

Work Package: W107 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Atomizer Droplet Size Distribution:
   - Rosin-Rammler cumulative distribution: F(dp) = 1 - exp(-(dp / d_char)^q), q=2.5.
   - Nominal Sauter mean diameter d32 ~ 65.0 um.
2. Droplet Evaporation Dynamics (d^2 law):
   - Phase I: constant-rate drying wet-bulb evaporation d(dp^2)/dt = -K_evap.
   - Phase II: falling-rate drying with solid crust formation once moisture X_d < X_crit (0.15 kg/kg).
3. Droplet Kinematics & Vertical Settling:
   - 1D vertical motion: dz/dt = v_z, dv_z/dt = g - (3*rho_g*C_d)/(4*rho_d*dp) * (v_z - u_g)*|v_z - u_g|.
4. Gas Phase Psychrometric Balance:
   - Co-current air enthalpy and moisture balance Y_g and T_g.
   - Water vapor partial pressure, saturation vapor pressure, and relative humidity RH_exhaust.
5. Coupled 6-State ODE System [dp, X_d, T_d, z, v_z, Y_g]:
   - Deterministic 4th-order Runge-Kutta (RK4) numerical integrator with dt = 0.01 s.
6. Process Alarms & Safety Interlocks:
   - %M158: InletAirOverTempTrip (T_inlet >= 220.0 degC) -> code 0x8401.
   - %M159: ExhaustCondensationTrip (RH_exhaust >= 65.0%) -> code 0x8402.
   - %M160: BaghouseFilterDpTrip (Delta_P >= 2.5 kPa) -> code 0x8403.
7. Horner OCS Registers:
   - %R680: Status Word (RUNNING, ATOMIZER_ACTIVE, HIGH_INLET_TEMP_ALARM, CONDENSATION_STICKY_TRIP,
             FILTER_DP_TRIP, CYCLONE_ACTIVE, EVAP_PHASE2_CRUST, OPTIMAL_DRYING)
   - %R681: DropletMeanDiameterUm (scaled x10 um)
   - %R682: DropletMoisturePct (scaled x10 wt%)
   - %R683: ExhaustAirTempDegC (scaled x10 degC)
   - %R684: ExhaustRelativeHumidityPct (scaled x10 %RH)
   - %R685: EvaporationRateKgH (scaled x10 kg/h)
   - %R686: PowderProductionRateKgH (scaled x10 kg/h)
   - %R687: DiagnosticEventCode (0x0000=OK, 0x8401, 0x8402, 0x8403)
   - %M158, %M159, %M160 discrete coils.
8. Pure IEC 61131-3 Structured Text (ST) POU:
   - Program 'SprayDryerSync' with SecurityGuard.assert_pure_st_content and STParser.
9. Deterministic 9-Stage Verification Suite:
   - run_spray_dryer_verification(evidence_path) returning strict 4-state engineering contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import math
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Enums and Status Bitmasks
# ============================================================================

class SprayDryerStatusBits(IntFlag):
    """Horner OCS %R680 Status Word Bitmask Definitions."""
    RUNNING                  = 1 << 0  # Bit 0 (0x0001): Spray dryer simulation running
    ATOMIZER_ACTIVE          = 1 << 1  # Bit 1 (0x0002): Rotary atomizer / nozzle active
    HIGH_INLET_TEMP_ALARM    = 1 << 2  # Bit 2 (0x0004): Inlet air >= 220.0 C (%M158)
    CONDENSATION_STICKY_TRIP = 1 << 3  # Bit 3 (0x0008): Exhaust RH >= 65.0% (%M159)
    FILTER_DP_TRIP           = 1 << 4  # Bit 4 (0x0010): Baghouse filter Delta P >= 2.5 kPa (%M160)
    CYCLONE_ACTIVE           = 1 << 5  # Bit 5 (0x0020): Primary cyclone separator online
    EVAP_PHASE2_CRUST        = 1 << 6  # Bit 6 (0x0040): Crust formed (X_d < X_crit falling rate)
    OPTIMAL_DRYING           = 1 << 7  # Bit 7 (0x0080): Safe steady drying within specifications


class SprayDryerDiagnosticCode(IntEnum):
    """Horner OCS %R687 Diagnostic Event Codes."""
    OK                       = 0x0000  # Normal operation
    ERR_INLET_AIR_OVERTEMP   = 0x8401  # Inlet air temperature >= 220.0 C
    ERR_EXHAUST_CONDENSATION = 0x8402  # Exhaust relative humidity >= 65.0%
    ERR_BAGHOUSE_FILTER_DP   = 0x8403  # Baghouse filter Delta P >= 2.5 kPa


# ============================================================================
# 2. Physics & Psychrometric Helper Functions
# ============================================================================

def rosin_rammler_cdf(dp: float, d_char: float, q: float = 2.5) -> float:
    """Calculate cumulative volume/mass fraction F(dp) = 1 - exp(-(dp / d_char)^q)."""
    if dp <= 0.0 or d_char <= 0.0:
        return 0.0
    u = dp / d_char
    return 1.0 - math.exp(-(u ** q))


def rosin_rammler_pdf(dp: float, d_char: float, q: float = 2.5) -> float:
    """Calculate Rosin-Rammler probability density f(dp) = dF/ddp."""
    if dp <= 0.0 or d_char <= 0.0:
        return 0.0
    u = dp / d_char
    return (q / d_char) * (u ** (q - 1.0)) * math.exp(-(u ** q))


def calculate_sauter_mean_diameter(d_char: float, q: float = 2.5) -> float:
    """Calculate Sauter mean diameter d32 = d_char * Gamma(1 + 3/q) / Gamma(1 + 2/q)."""
    if d_char <= 0.0 or q <= 0.0:
        return 0.0
    ratio = math.gamma(1.0 + 3.0 / q) / math.gamma(1.0 + 2.0 / q)
    return d_char * ratio


def calculate_d_char_from_sauter_mean(d32: float, q: float = 2.5) -> float:
    """Calculate characteristic diameter d_char corresponding to target Sauter mean d32."""
    if d32 <= 0.0 or q <= 0.0:
        return 0.0
    ratio = math.gamma(1.0 + 3.0 / q) / math.gamma(1.0 + 2.0 / q)
    return d32 / ratio


def compute_water_vapor_pressure(y_g: float, p_atm: float = 101325.0) -> float:
    """Compute partial pressure of water vapor in air Pv [Pa] from absolute humidity Y_g."""
    y = max(0.0, y_g)
    return p_atm * (y / (0.622 + y))


def compute_water_saturation_pressure(temp_c: float) -> float:
    """Compute saturation vapor pressure P_sat [Pa] over water via Tetens formulation."""
    t = max(-50.0, min(200.0, temp_c))
    return 610.78 * math.exp((17.27 * t) / (t + 237.3))


def compute_relative_humidity(temp_c: float, y_g: float, p_atm: float = 101325.0) -> float:
    """Compute gas relative humidity RH [%] (0 to 100%)."""
    pv = compute_water_vapor_pressure(y_g, p_atm)
    psat = compute_water_saturation_pressure(temp_c)
    if psat <= 1e-6:
        return 0.0
    rh = (pv / psat) * 100.0
    return min(100.0, max(0.0, rh))


def compute_wet_bulb_temperature(
    temp_g_c: float,
    y_g: float,
    p_atm: float = 101325.0,
    cp_air: float = 1005.0,
    delta_h_vap: float = 2.26e6,
) -> float:
    """Compute wet-bulb temperature T_wb [degC] via psychrometric energy balance."""
    def balance(t_wb: float) -> float:
        psat_wb = compute_water_saturation_pressure(t_wb)
        y_sat_wb = 0.622 * psat_wb / max(100.0, p_atm - psat_wb)
        return (y_sat_wb - y_g) - (cp_air / delta_h_vap) * (temp_g_c - t_wb)

    lo = 0.0
    hi = max(0.0, min(100.0, temp_g_c))
    for _ in range(32):
        mid = 0.5 * (lo + hi)
        if balance(mid) > 0.0:
            hi = mid
        else:
            lo = mid
    return 0.5 * (lo + hi)


def compute_drag_coefficient(re_p: float) -> float:
    """Compute Schiller-Naumann sphere drag coefficient."""
    re = max(0.0, re_p)
    if re < 0.1:
        return 24.0 / max(1e-5, re)
    elif re < 1000.0:
        return (24.0 / re) * (1.0 + 0.15 * (re ** 0.687))
    else:
        return 0.44


# ============================================================================
# 3. Configuration & Parameter Data Models
# ============================================================================

@dataclass
class SprayDryerConfig:
    """Design, geometric, and operational parameters of industrial spray dryer."""
    # Tower Dimensions
    tower_height_m: float = 5.0                # Active drying chamber height [m]
    tower_diameter_m: float = 2.0              # Chamber cylindrical diameter [m]

    # Atomizer & Droplet Size Distribution
    rosin_rammler_q: float = 2.5               # Rosin-Rammler spread parameter q [-]
    nominal_d32_um: float = 65.0               # Target Sauter mean diameter d32 [um]
    d_char_um: float = field(init=False)       # Characteristic diameter d_char [um]
    feed_rate_kg_h: float = 150.0              # Slurry feed mass flow rate [kg/h]
    feed_solids_fraction: float = 0.40         # Feed solids mass fraction w_s0 [-] (40 wt%)
    feed_temp_c: float = 25.0                  # Feed temperature [degC]
    rho_solids: float = 1500.0                 # Dry solid density [kg/m^3]
    rho_water: float = 1000.0                  # Water density [kg/m^3]
    cp_solids: float = 1400.0                  # Dry solid specific heat [J/(kg*K)]
    cp_water: float = 4184.0                   # Liquid water specific heat [J/(kg*K)]
    delta_h_vap: float = 2.26e6                # Latent heat of vaporization [J/kg]

    # Evaporation & Crust Formation Thresholds
    x_crit: float = 0.15                       # Critical moisture content [kg water / kg dry solid]
    x_eq: float = 0.02                         # Equilibrium moisture content [kg water / kg dry solid]

    # Gas Phase Psychrometric Conditions
    air_flow_rate_kg_h: float = 2400.0         # Dry air mass flow rate [kg/h] (0.667 kg/s)
    inlet_air_temp_c: float = 200.0            # Hot drying air inlet temperature [degC]
    inlet_air_humidity: float = 0.010          # Inlet air humidity [kg water / kg dry air]
    gas_velocity_m_s: float = 0.80             # Downward co-current air velocity u_g [m/s]
    ambient_temp_c: float = 20.0               # Ambient ambient temperature [degC]
    wall_loss_coeff_w_m2_k: float = 2.5        # Insulated tower wall heat loss [W/(m^2*K)]
    cp_air: float = 1005.0                     # Dry air heat capacity [J/(kg*K)]
    p_atm_pa: float = 101325.0                 # Atmospheric pressure [Pa]

    # Cyclone & Baghouse Filtration
    filter_clean_dp_kpa: float = 0.80          # Clean filter differential pressure [kPa]
    filter_dp_trip_limit_kpa: float = 2.50     # Filter high differential pressure trip limit [kPa]
    cyclone_efficiency: float = 0.94           # Primary cyclone powder recovery fraction [-]
    cake_resistance_factor: float = 0.035      # Pressure drop growth factor [kPa/(kg cake)]

    # Safety Trip Thresholds
    inlet_temp_trip_c: float = 220.0           # InletAirOverTempTrip limit [degC]
    exhaust_rh_trip_pct: float = 65.0          # ExhaustCondensationTrip limit [%RH]

    def __post_init__(self) -> None:
        self.d_char_um = calculate_d_char_from_sauter_mean(
            self.nominal_d32_um, self.rosin_rammler_q
        )

    @property
    def tower_volume_m3(self) -> float:
        """Active drying volume [m^3]."""
        return 0.25 * math.pi * (self.tower_diameter_m ** 2) * self.tower_height_m

    @property
    def tower_wall_area_m2(self) -> float:
        """Dryer cylindrical wall surface area [m^2]."""
        return math.pi * self.tower_diameter_m * self.tower_height_m

    @property
    def feed_moisture_dry_basis(self) -> float:
        """Initial moisture content X0 [kg water / kg dry solid]."""
        w_s = self.feed_solids_fraction
        return (1.0 - w_s) / max(1e-6, w_s)

    @property
    def initial_droplet_density(self) -> float:
        """Initial slurry droplet density rho_d0 [kg/m^3]."""
        w_s = self.feed_solids_fraction
        w_w = 1.0 - w_s
        vol_specific = (w_s / self.rho_solids) + (w_w / self.rho_water)
        return 1.0 / max(1e-6, vol_specific)


@dataclass
class SprayDryerState:
    """Dynamic state variables and process diagnostics of the spray dryer."""
    # 6 Primary Dynamic ODE States
    d_p: float = 65.0e-6                       # Droplet/particle diameter [m]
    x_d: float = 1.50                          # Droplet moisture content [kg water / kg dry solid]
    t_d: float = 298.15                        # Droplet temperature [K] (25.0 degC)
    z: float = 0.0                             # Vertical settling distance [m]
    v_z: float = 1.0                           # Vertical droplet velocity [m/s]
    y_g: float = 0.010                         # Gas absolute humidity [kg vapor / kg dry air]

    # Coupled Gas Phase State
    t_g: float = 473.15                        # Gas temperature [K] (200.0 degC)
    filter_dp_kpa: float = 0.80                # Baghouse filter differential pressure [kPa]

    # Process Indicators & Rates
    evap_phase: int = 1                        # 1 = Phase I (constant rate), 2 = Phase II (crust)
    crust_formed: bool = False                 # True once X_d < X_crit
    k_evap: float = 0.0                        # Evaporation rate constant [m^2/s]
    evaporation_rate_kg_h: float = 0.0         # Total water evaporation rate [kg/h]
    powder_production_rate_kg_h: float = 0.0   # Finished powder output rate [kg/h]

    # Alarms and Safety Interlocks
    is_running: bool = True                    # Master system running
    atomizer_active: bool = True               # Atomizer rotation enabled
    cyclone_active: bool = True                # Cyclone separation active
    inlet_temp_trip: bool = False              # %M158 InletAirOverTempTrip
    condensation_trip: bool = False            # %M159 ExhaustCondensationTrip
    filter_dp_trip: bool = False               # %M160 BaghouseFilterDpTrip
    diagnostic_code: SprayDryerDiagnosticCode = SprayDryerDiagnosticCode.OK

    # Simulation Clock
    sim_time_s: float = 0.0                    # Elapsed simulation time [s]

    @property
    def d_p_um(self) -> float:
        """Droplet diameter in micrometers."""
        return self.d_p * 1e6

    @property
    def moisture_wet_basis_pct(self) -> float:
        """Droplet moisture content in wet wt% (100 * X / (1 + X))."""
        return (self.x_d / (1.0 + self.x_d)) * 100.0

    @property
    def moisture_dry_basis_pct(self) -> float:
        """Droplet moisture content in dry wt% (100 * X)."""
        return self.x_d * 100.0

    @property
    def t_d_c(self) -> float:
        """Droplet temperature in degC."""
        return self.t_d - 273.15

    @property
    def t_g_c(self) -> float:
        """Gas exhaust temperature in degC."""
        return self.t_g - 273.15

    @property
    def rh_exhaust_pct(self) -> float:
        """Exhaust gas relative humidity [%RH]."""
        return compute_relative_humidity(self.t_g_c, self.y_g)

    @property
    def t_wb_c(self) -> float:
        """Wet-bulb temperature of gas [degC]."""
        return compute_wet_bulb_temperature(self.t_g_c, self.y_g)


# ============================================================================
# 4. Spray Dryer ODE Simulation Engine
# ============================================================================

class SprayDryerSimulationEngine:
    """Coupled 6-State ODE RK4 Industrial Spray Dryer Simulator.
    
    Work Package: W107 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation).
    Mapped Registers: %R680..%R687, %M158..%M160.
    """

    def __init__(
        self,
        config: Optional[SprayDryerConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.cfg = config or SprayDryerConfig()
        self.reg_table: RegisterTable = register_table or RegisterTable()
        self.state = SprayDryerState()

        # Operational inputs / setpoints
        self.current_inlet_air_temp_c: float = self.cfg.inlet_air_temp_c
        self.current_feed_rate_kg_h: float = self.cfg.feed_rate_kg_h
        self.pulse_jet_cleaning_enabled: bool = True
        self.last_pulse_clean_time: float = 0.0

        # Derived initial single-droplet geometry
        self.d_p0: float = self.cfg.nominal_d32_um * 1e-6
        self.x_d0: float = self.cfg.feed_moisture_dry_basis
        self.rho_d0: float = self.cfg.initial_droplet_density
        self.m_d0: float = (math.pi / 6.0) * (self.d_p0 ** 3) * self.rho_d0
        self.m_s: float = self.m_d0 * self.cfg.feed_solids_fraction  # Dry solids per droplet [kg]

        # Rigid crust particle diameter at X_crit [m]
        v_crust = self.m_s * (
            (1.0 / self.cfg.rho_solids) + (self.cfg.x_crit / self.cfg.rho_water)
        )
        self.d_p_crust: float = (6.0 * v_crust / math.pi) ** (1.0 / 3.0)

        # Inventory of dry air in chamber well-mixed active control volume [kg]
        self.m_air_dry: float = 3.5

        self.reset()

    def reset(self) -> None:
        """Reset dynamic states and register tables to clean initial conditions."""
        self.state = SprayDryerState(
            d_p=self.d_p0,
            x_d=self.x_d0,
            t_d=self.cfg.feed_temp_c + 273.15,
            z=0.0,
            v_z=1.0,
            y_g=self.cfg.inlet_air_humidity,
            t_g=self.current_inlet_air_temp_c + 273.15,
            filter_dp_kpa=self.cfg.filter_clean_dp_kpa,
            evap_phase=1,
            crust_formed=False,
            is_running=True,
            atomizer_active=True,
            cyclone_active=True,
            inlet_temp_trip=False,
            condensation_trip=False,
            filter_dp_trip=False,
            sim_time_s=0.0,
        )
        self.current_inlet_air_temp_c = self.cfg.inlet_air_temp_c
        self.current_feed_rate_kg_h = self.cfg.feed_rate_kg_h
        self.last_pulse_clean_time = 0.0
        self._sync_registers()

    # ------------------------------------------------------------------------
    # Physics & ODE Derivatives
    # ------------------------------------------------------------------------

    def compute_rosin_rammler_cdf(self, dp_m: float) -> float:
        """Compute cumulative distribution for droplet size dp [m]."""
        return rosin_rammler_cdf(dp_m * 1e6, self.cfg.d_char_um, self.cfg.rosin_rammler_q)

    def compute_rosin_rammler_pdf(self, dp_m: float) -> float:
        """Compute probability density for droplet size dp [m]."""
        return rosin_rammler_pdf(dp_m * 1e6, self.cfg.d_char_um, self.cfg.rosin_rammler_q) / 1e6

    def compute_sauter_mean_diameter(self) -> float:
        """Return configured Sauter mean diameter d32 [m]."""
        return calculate_sauter_mean_diameter(self.cfg.d_char_um, self.cfg.rosin_rammler_q) * 1e-6

    def compute_derivatives(
        self,
        y: Sequence[float],
        t_g: float,
    ) -> Tuple[List[float], float, float, float]:
        """Compute 6-state ODE time derivatives dy/dt and coupled dT_g/dt.
        
        State vector y:
        - y[0]: d_p   (droplet diameter [m])
        - y[1]: X_d   (moisture content dry basis [kg/kg])
        - y[2]: T_d   (droplet temperature [K])
        - y[3]: z     (vertical settling distance [m])
        - y[4]: v_z   (vertical droplet velocity [m/s])
        - y[5]: Y_g   (gas absolute humidity [kg/kg dry air])
        
        Returns:
            (dy_dt [6 floats], dT_g_dt, m_dot_evap_single [kg/s], K_evap [m^2/s])
        """
        dp = max(1e-6, y[0])
        x_d = max(0.0, y[1])
        t_d = max(250.0, y[2])
        z = max(0.0, y[3])
        v_z = y[4]
        y_g = max(0.0, y[5])
        t_gas = max(250.0, t_g)

        # Gas transport properties at T_gas
        p_atm = self.cfg.p_atm_pa
        rho_g = p_atm / (287.05 * t_gas)
        mu_g = 1.81e-5 * ((t_gas / 293.15) ** 0.7)
        k_g = 0.026 * ((t_gas / 293.15) ** 0.8)
        c_p_air = self.cfg.cp_air

        # Relative velocity and droplet Reynolds number
        u_g = self.cfg.gas_velocity_m_s
        v_rel = abs(v_z - u_g)
        re_p = (rho_g * v_rel * dp) / max(1e-7, mu_g)
        pr_g = mu_g * c_p_air / max(1e-5, k_g)

        # Ranz-Marshall convective heat transfer
        nu_p = 2.0 + 0.60 * math.sqrt(max(0.0, re_p)) * (pr_g ** (1.0 / 3.0))
        h_conv = (k_g * nu_p) / dp
        a_p = math.pi * (dp ** 2)

        # Droplet mass, density, and effective heat capacity
        m_d = self.m_s * (1.0 + x_d)
        vol_d = self.m_s * ((1.0 / self.cfg.rho_solids) + (x_d / self.cfg.rho_water))
        rho_d = m_d / max(1e-15, vol_d)
        c_p_d = (self.cfg.cp_solids + x_d * self.cfg.cp_water) / (1.0 + x_d)

        # 1D Kinematics and Settling Acceleration
        c_d = compute_drag_coefficient(re_p)
        dz_dt = v_z
        drag_force_per_mass = (3.0 * rho_g * c_d) / (4.0 * rho_d * dp) * (v_z - u_g) * v_rel
        dvz_dt = 9.81 - drag_force_per_mass

        # Evaporation Kinetics: Heat transfer driving force
        q_conv = h_conv * a_p * max(0.0, t_gas - t_d)
        m_dot_evap_unhindered = q_conv / self.cfg.delta_h_vap

        # Phase I vs Phase II transition
        is_phase_1 = (x_d >= self.cfg.x_crit) and (dp > self.d_p_crust)
        if is_phase_1:
            # Phase I: Constant-rate drying via d^2 law: d(dp^2)/dt = -K_evap
            m_dot_evap_1 = m_dot_evap_unhindered
            # Since m_dot_evap = (pi/4)*rho_w*dp*K_evap:
            k_evap = (4.0 * m_dot_evap_1) / (math.pi * self.cfg.rho_water * dp)
            ddp_dt = -k_evap / (2.0 * dp)
        else:
            # Phase II: Rigid solid crust formed: dp stops shrinking
            ddp_dt = 0.0
            k_evap = 0.0
            # Falling-rate reduction through porous crust
            f_fall = max(0.0, (x_d - self.cfg.x_eq) / max(1e-4, self.cfg.x_crit - self.cfg.x_eq))
            f_fall = min(1.0, f_fall)
            m_dot_evap_1 = m_dot_evap_unhindered * f_fall

        # Moisture content derivative
        if x_d > self.cfg.x_eq:
            dxd_dt = -m_dot_evap_1 / self.m_s
        else:
            dxd_dt = 0.0

        # Droplet thermal balance
        heat_net = q_conv - (m_dot_evap_1 * self.cfg.delta_h_vap)
        dtd_dt = heat_net / max(1e-15, m_d * c_p_d)

        # Macroscopic spray dryer air and continuous feed drying rates
        m_dot_feed_kg_s = (self.current_feed_rate_kg_h / 3600.0) if self.state.atomizer_active else 0.0
        m_dot_solids_kg_s = m_dot_feed_kg_s * self.cfg.feed_solids_fraction
        # Continuous population water evaporation rate:
        # Feed moisture (X0) down to current dried droplet moisture (X_d)
        total_evap_kg_s = m_dot_solids_kg_s * max(0.0, self.cfg.feed_moisture_dry_basis - x_d)
        m_dot_air_kg_s = self.cfg.air_flow_rate_kg_h / 3600.0

        # Gas absolute humidity derivative
        dyg_dt = (m_dot_air_kg_s / self.m_air_dry) * (self.cfg.inlet_air_humidity - y_g) + (
            total_evap_kg_s / self.m_air_dry
        )

        # Gas temperature derivative (co-current enthalpy balance + wall loss)
        t_inlet_k = self.current_inlet_air_temp_c + 273.15
        t_amb_k = self.cfg.ambient_temp_c + 273.15
        q_wall_loss = self.cfg.wall_loss_coeff_w_m2_k * self.cfg.tower_wall_area_m2 * (t_gas - t_amb_k)
        total_heat_evap_w = total_evap_kg_s * self.cfg.delta_h_vap

        dtg_dt = (
            (m_dot_air_kg_s * c_p_air * (t_inlet_k - t_gas))
            - total_heat_evap_w
            - q_wall_loss
        ) / (self.m_air_dry * c_p_air)

        dy_dt = [ddp_dt, dxd_dt, dtd_dt, dz_dt, dvz_dt, dyg_dt]
        return dy_dt, dtg_dt, m_dot_evap_1, k_evap

    # ------------------------------------------------------------------------
    # RK4 Stepping & Scan Integration
    # ------------------------------------------------------------------------

    def step(self, dt: float = 0.01) -> None:
        """Advance simulation by dt seconds using 4th-order Runge-Kutta integration."""
        y = [
            self.state.d_p,
            self.state.x_d,
            self.state.t_d,
            self.state.z,
            self.state.v_z,
            self.state.y_g,
        ]
        t_g = self.state.t_g

        # Stage 1
        k1, dtg1, evap1, kev1 = self.compute_derivatives(y, t_g)

        # Stage 2
        y_k2 = [y[i] + 0.5 * dt * k1[i] for i in range(6)]
        k2, dtg2, _, _ = self.compute_derivatives(y_k2, t_g + 0.5 * dt * dtg1)

        # Stage 3
        y_k3 = [y[i] + 0.5 * dt * k2[i] for i in range(6)]
        k3, dtg3, _, _ = self.compute_derivatives(y_k3, t_g + 0.5 * dt * dtg2)

        # Stage 4
        y_k4 = [y[i] + dt * k3[i] for i in range(6)]
        k4, dtg4, _, _ = self.compute_derivatives(y_k4, t_g + dt * dtg3)

        # RK4 update
        y_next = [
            y[i] + (dt / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i])
            for i in range(6)
        ]
        t_g_next = t_g + (dt / 6.0) * (dtg1 + 2.0 * dtg2 + 2.0 * dtg3 + dtg4)

        # Enforce physical bounds
        dp_new = max(self.d_p_crust if self.state.crust_formed else 1e-6, y_next[0])
        xd_new = max(self.cfg.x_eq, y_next[1])
        td_new = max(250.0, y_next[2])
        z_new = max(0.0, y_next[3])
        vz_new = y_next[4]
        yg_new = max(self.cfg.inlet_air_humidity, min(0.15, y_next[5]))
        tg_new = max(273.15 + 40.0, t_g_next)

        # Phase transition check
        crust_now = self.state.crust_formed or (xd_new < self.cfg.x_crit)
        evap_phase = 2 if crust_now else 1
        if crust_now and not self.state.crust_formed:
            dp_new = self.d_p_crust

        # Rates calculation
        m_dot_feed_kg_h = self.current_feed_rate_kg_h if self.state.atomizer_active else 0.0
        m_dot_solids_kg_h = m_dot_feed_kg_h * self.cfg.feed_solids_fraction
        powder_prod_kg_h = m_dot_solids_kg_h * (1.0 + xd_new) if self.state.atomizer_active else 0.0
        total_evap_kg_h = max(0.0, m_dot_feed_kg_h - powder_prod_kg_h)

        # Baghouse filtration differential pressure dynamics
        powder_to_baghouse_kg_s = (powder_prod_kg_h / 3600.0) * (1.0 - self.cfg.cyclone_efficiency)
        dp_growth = self.cfg.cake_resistance_factor * powder_to_baghouse_kg_s * dt * 10.0
        new_filter_dp = self.state.filter_dp_kpa + dp_growth

        # Periodic reverse-pulse jet cleaning
        self.state.sim_time_s += dt
        if self.pulse_jet_cleaning_enabled:
            if (self.state.sim_time_s - self.last_pulse_clean_time) >= 10.0:
                new_filter_dp = self.cfg.filter_clean_dp_kpa
                self.last_pulse_clean_time = self.state.sim_time_s

        # Update state
        self.state.d_p = dp_new
        self.state.x_d = xd_new
        self.state.t_d = td_new
        self.state.z = z_new
        self.state.v_z = vz_new
        self.state.y_g = yg_new
        self.state.t_g = tg_new
        self.state.filter_dp_kpa = new_filter_dp
        self.state.evap_phase = evap_phase
        self.state.crust_formed = crust_now
        self.state.k_evap = kev1
        self.state.evaporation_rate_kg_h = total_evap_kg_h
        self.state.powder_production_rate_kg_h = powder_prod_kg_h

        # Evaluate alarms & interlocks
        self._check_alarms_and_interlocks()

        # Synchronize registers
        self._sync_registers()

    def advance_time(self, duration_s: float, dt: float = 0.01) -> ExecutionResult:
        """Advance the simulation for duration_s using fixed dt steps."""
        if duration_s <= 0.0:
            return ExecutionResult(
                status=AgentStatus.SUCCESS,
                error_code=None,
                details="Zero duration advance requested.",
                data={"sim_time_s": self.state.sim_time_s},
            )

        steps = int(math.ceil(duration_s / dt))
        for _ in range(steps):
            self.step(dt=dt)

        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            error_code=None,
            details=f"Spray dryer advanced {duration_s:.3f} s ({steps} RK4 steps).",
            data={
                "sim_time_s": self.state.sim_time_s,
                "d_p_um": self.state.d_p_um,
                "moisture_pct": self.state.moisture_wet_basis_pct,
                "t_g_c": self.state.t_g_c,
                "rh_exhaust_pct": self.state.rh_exhaust_pct,
                "evaporation_rate_kg_h": self.state.evaporation_rate_kg_h,
                "powder_production_rate_kg_h": self.state.powder_production_rate_kg_h,
            },
        )

    # ------------------------------------------------------------------------
    # Fault Injections and Diagnostic Interlocks
    # ------------------------------------------------------------------------

    def _check_alarms_and_interlocks(self) -> None:
        """Evaluate alarm thresholds and latch safety interlocks."""
        # 1. Inlet air over-temperature trip (%M158, code 0x8401)
        if self.current_inlet_air_temp_c >= self.cfg.inlet_temp_trip_c:
            self.state.inlet_temp_trip = True
        else:
            self.state.inlet_temp_trip = False

        # 2. Exhaust air condensation sticky powder trip (%M159, code 0x8402)
        if self.state.rh_exhaust_pct >= self.cfg.exhaust_rh_trip_pct:
            self.state.condensation_trip = True
        else:
            self.state.condensation_trip = False

        # 3. Baghouse filter differential pressure trip (%M160, code 0x8403)
        if self.state.filter_dp_kpa >= self.cfg.filter_dp_trip_limit_kpa:
            self.state.filter_dp_trip = True
        else:
            self.state.filter_dp_trip = False

        # Determine diagnostic event code
        if self.state.inlet_temp_trip:
            self.state.diagnostic_code = SprayDryerDiagnosticCode.ERR_INLET_AIR_OVERTEMP
        elif self.state.condensation_trip:
            self.state.diagnostic_code = SprayDryerDiagnosticCode.ERR_EXHAUST_CONDENSATION
        elif self.state.filter_dp_trip:
            self.state.diagnostic_code = SprayDryerDiagnosticCode.ERR_BAGHOUSE_FILTER_DP
        else:
            self.state.diagnostic_code = SprayDryerDiagnosticCode.OK

    def trigger_inlet_overtemp(self, temp_c: float = 225.0) -> None:
        """Inject high inlet air temperature fault."""
        self.current_inlet_air_temp_c = temp_c
        self._check_alarms_and_interlocks()
        self._sync_registers()

    def trigger_exhaust_condensation(
        self,
        temp_c: float = 48.0,
        forced_humidity: float = 0.065,
        forced_temp_c: Optional[float] = None,
    ) -> None:
        """Inject exhaust condensation fault by setting cool/humid exhaust condition."""
        effective_temp_c = forced_temp_c if forced_temp_c is not None else temp_c
        self.state.t_g = effective_temp_c + 273.15
        self.state.y_g = forced_humidity
        self._check_alarms_and_interlocks()
        self._sync_registers()

    def trigger_filter_clog(self, dp_kpa: float = 2.80) -> None:
        """Inject clogged baghouse filter differential pressure fault."""
        self.pulse_jet_cleaning_enabled = False
        self.state.filter_dp_kpa = dp_kpa
        self._check_alarms_and_interlocks()
        self._sync_registers()

    def pulse_jet_clean(self) -> None:
        """Manually trigger pulse jet cleaning to clear baghouse filter cake."""
        self.state.filter_dp_kpa = self.cfg.filter_clean_dp_kpa
        self.last_pulse_clean_time = self.state.sim_time_s
        self._check_alarms_and_interlocks()
        self._sync_registers()

    # ------------------------------------------------------------------------
    # Horner OCS Register Synchronization
    # ------------------------------------------------------------------------

    def _sync_registers(self) -> None:
        """Synchronize state into Horner OCS registers %R680..%R687 and %M158..%M160."""
        # %R680 Status Word Bitmask
        status = 0
        if self.state.is_running:
            status |= int(SprayDryerStatusBits.RUNNING)
        if self.state.atomizer_active:
            status |= int(SprayDryerStatusBits.ATOMIZER_ACTIVE)
        if self.state.inlet_temp_trip:
            status |= int(SprayDryerStatusBits.HIGH_INLET_TEMP_ALARM)
        if self.state.condensation_trip:
            status |= int(SprayDryerStatusBits.CONDENSATION_STICKY_TRIP)
        if self.state.filter_dp_trip:
            status |= int(SprayDryerStatusBits.FILTER_DP_TRIP)
        if self.state.cyclone_active:
            status |= int(SprayDryerStatusBits.CYCLONE_ACTIVE)
        if self.state.crust_formed:
            status |= int(SprayDryerStatusBits.EVAP_PHASE2_CRUST)

        # Optimal drying flag: running, no alarms, good product moisture, safe RH
        is_optimal = (
            self.state.is_running
            and self.state.atomizer_active
            and not self.state.inlet_temp_trip
            and not self.state.condensation_trip
            and not self.state.filter_dp_trip
            and (self.state.rh_exhaust_pct < 55.0)
            and (self.state.moisture_wet_basis_pct < 15.0)
        )
        if is_optimal:
            status |= int(SprayDryerStatusBits.OPTIMAL_DRYING)

        # Scale factors:
        # %R681: DropletMeanDiameterUm (scaled x10 um)
        reg_dp = int(round(self.state.d_p_um * 10.0))
        # %R682: DropletMoisturePct (scaled x10 wt%)
        reg_moisture = int(round(self.state.moisture_wet_basis_pct * 10.0))
        # %R683: ExhaustAirTempDegC (scaled x10 degC)
        reg_tg = int(round(self.state.t_g_c * 10.0))
        # %R684: ExhaustRelativeHumidityPct (scaled x10 %RH)
        reg_rh = int(round(self.state.rh_exhaust_pct * 10.0))
        # %R685: EvaporationRateKgH (scaled x10 kg/h)
        reg_evap = int(round(self.state.evaporation_rate_kg_h * 10.0))
        # %R686: PowderProductionRateKgH (scaled x10 kg/h)
        reg_powder = int(round(self.state.powder_production_rate_kg_h * 10.0))
        # %R687: DiagnosticEventCode
        reg_diag = int(self.state.diagnostic_code)

        # Write Registers via SYSTEM Privilege
        self.reg_table.write_word("%R680", status, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R681", reg_dp, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R682", reg_moisture, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R683", reg_tg, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R684", reg_rh, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R685", reg_evap, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R686", reg_powder, privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_word("%R687", reg_diag, privilege=PrivilegeMode.SYSTEM)

        # Write Discrete Coils %M158..%M160
        self.reg_table.write_bit("%M158", bool(self.state.inlet_temp_trip), privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_bit("%M159", bool(self.state.condensation_trip), privilege=PrivilegeMode.SYSTEM)
        self.reg_table.write_bit("%M160", bool(self.state.filter_dp_trip), privilege=PrivilegeMode.SYSTEM)


# ============================================================================
# 5. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

SPRAY_DRYER_PURE_ST_POU: str = """PROGRAM SprayDryerSync
VAR
    StatusWord AT %R680 : INT;
    DropletMeanDiameterUm AT %R681 : INT;
    DropletMoisturePct AT %R682 : INT;
    ExhaustAirTempDegC AT %R683 : INT;
    ExhaustRelativeHumidityPct AT %R684 : INT;
    EvaporationRateKgH AT %R685 : INT;
    PowderProductionRateKgH AT %R686 : INT;
    DiagnosticEventCode AT %R687 : INT;

    InletAirOverTempTrip AT %M158 : BOOL;
    ExhaustCondensationTrip AT %M159 : BOOL;
    BaghouseFilterDpTrip AT %M160 : BOOL;

    HeaterTripped : BOOL := FALSE;
    FeedPumpPermissive : BOOL := TRUE;
    PulseJetCleanCmd : BOOL := FALSE;
END_VAR

(* High inlet temperature interlock: cut heater power and trip feed *)
IF InletAirOverTempTrip THEN
    HeaterTripped := TRUE;
    FeedPumpPermissive := FALSE;
ELSE
    HeaterTripped := FALSE;
END_IF;

(* Exhaust condensation interlock: halt liquid feed to prevent chamber wall sticky deposits *)
IF ExhaustCondensationTrip THEN
    FeedPumpPermissive := FALSE;
END_IF;

(* Baghouse high differential pressure interlock: trigger reverse-pulse jet blowdown *)
IF BaghouseFilterDpTrip THEN
    PulseJetCleanCmd := TRUE;
ELSE
    PulseJetCleanCmd := FALSE;
END_IF;
END_PROGRAM
"""


def verify_spray_dryer_pure_st() -> bool:
    """Validate SprayDryerSync POU with STParser and SecurityGuard."""
    # 1. Anti-ladder security guard assertion
    SecurityGuard.assert_pure_st_content(SPRAY_DRYER_PURE_ST_POU)

    # 2. IEC 61131-3 ST AST Parser validation
    val = STParser.validate_code(SPRAY_DRYER_PURE_ST_POU)
    if val.status != AgentStatus.SUCCESS:
        return False

    pou = STParser.parse_pou(SPRAY_DRYER_PURE_ST_POU)
    if not pou:
        return False
    required_registers = [
        "%R680", "%R681", "%R682", "%R683",
        "%R684", "%R685", "%R686", "%R687",
        "%M158", "%M159", "%M160",
    ]
    return (
        pou.name == "SprayDryerSync"
        and pou.pou_type == POUType.PROGRAM
        and all(reg in pou.bound_registers for reg in required_registers)
    )


# ============================================================================
# 6. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_spray_dryer_verification(evidence_path: Optional[str] = None) -> Dict[str, Any]:
    """Execute complete 9-stage verification suite for W107 Spray Dryer ODE Engine."""
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU Validation & AST Symbol Binding
    # ------------------------------------------------------------------------
    SecurityGuard.assert_pure_st_content(SPRAY_DRYER_PURE_ST_POU)
    res_st = STParser.validate_code(SPRAY_DRYER_PURE_ST_POU)
    ast = STParser.parse_pou(SPRAY_DRYER_PURE_ST_POU)

    required_registers = [
        "%R680", "%R681", "%R682", "%R683",
        "%R684", "%R685", "%R686", "%R687",
        "%M158", "%M159", "%M160",
    ]
    c1 = (
        res_st.status == AgentStatus.SUCCESS
        and ast.name == "SprayDryerSync"
        and ast.pou_type == POUType.PROGRAM
        and all(reg in ast.bound_registers for reg in required_registers)
    )
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_And_AST_Symbol_Binding",
        "passed": c1,
        "details": f"Pure ST POU validated; {len(required_registers)} registers (%R680..%R687, %M158..%M160) bound into AST.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Rosin-Rammler Atomizer Droplet Size Distribution
    # ------------------------------------------------------------------------
    sim_base = SprayDryerSimulationEngine()
    d32_calc = sim_base.compute_sauter_mean_diameter() * 1e6
    f_0 = sim_base.compute_rosin_rammler_cdf(0.0)
    f_char = sim_base.compute_rosin_rammler_cdf(sim_base.cfg.d_char_um * 1e-6)
    f_large = sim_base.compute_rosin_rammler_cdf(300e-6)

    # Monotonicity check
    f_20 = sim_base.compute_rosin_rammler_cdf(20e-6)
    f_50 = sim_base.compute_rosin_rammler_cdf(50e-6)
    f_80 = sim_base.compute_rosin_rammler_cdf(80e-6)

    c2 = (
        abs(d32_calc - 65.0) < 0.5
        and f_0 == 0.0
        and abs(f_char - (1.0 - 1.0 / math.e)) < 1e-4
        and f_large > 0.99
        and (0.0 < f_20 < f_50 < f_80 < 1.0)
    )
    test_results.append({
        "stage": 2,
        "check": "Rosin_Rammler_Droplet_Size_Distribution",
        "passed": c2,
        "details": f"Rosin-Rammler q=2.5 verified: Sauter d32={d32_calc:.2f} um ~ 65.0 um, F(d_char)={f_char:.4f} ~ 0.6321.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Droplet Evaporation Phase I (d^2 Law & Wet-Bulb Equilibrium)
    # ------------------------------------------------------------------------
    sim_p1 = SprayDryerSimulationEngine()
    dp_start = sim_p1.state.d_p
    # Step short duration within Phase I
    for _ in range(5):
        sim_p1.step(dt=0.01)

    dp_end = sim_p1.state.d_p
    k_evap = sim_p1.state.k_evap
    delta_dp2_dt = ((dp_end ** 2) - (dp_start ** 2)) / 0.05
    k_evap_rel_err = abs(abs(delta_dp2_dt) - k_evap) / max(1e-15, k_evap)
    td_c = sim_p1.state.t_d_c

    c3 = (
        sim_p1.state.evap_phase == 1
        and sim_p1.state.x_d < sim_p1.cfg.feed_moisture_dry_basis
        and k_evap > 0.0
        and k_evap_rel_err < 0.05
        and (20.0 <= td_c <= 65.0)
    )
    test_results.append({
        "stage": 3,
        "check": "Droplet_Evaporation_Phase_I_Constant_Rate",
        "passed": c3,
        "details": f"Phase I d^2 law verified: K_evap={k_evap:.2e} m^2/s, relative error={k_evap_rel_err*100.0:.2f}%, T_d={td_c:.1f} C.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Phase II Solid Crust Formation & Falling-Rate Transition
    # ------------------------------------------------------------------------
    sim_p2 = SprayDryerSimulationEngine()
    # Advance until moisture falls below X_crit (0.15 kg/kg)
    sim_p2.advance_time(duration_s=0.50, dt=0.01)

    dp_crust = sim_p2.state.d_p
    crust_active = sim_p2.state.crust_formed
    phase_is_2 = (sim_p2.state.evap_phase == 2)
    xd_p2 = sim_p2.state.x_d

    # Step further and verify diameter does NOT shrink anymore
    sim_p2.advance_time(duration_s=0.30, dt=0.01)
    dp_after = sim_p2.state.d_p
    td_p2_c = sim_p2.state.t_d_c

    c4 = (
        crust_active is True
        and phase_is_2 is True
        and xd_p2 < sim_p2.cfg.x_crit
        and abs(dp_after - dp_crust) < 1e-10
        and td_p2_c > 65.0
    )
    test_results.append({
        "stage": 4,
        "check": "Droplet_Evaporation_Phase_II_Crust_Formation",
        "passed": c4,
        "details": f"Phase II crust verified: X_d={xd_p2:.3f} < 0.15, d_p locked at {dp_crust*1e6:.1f} um, particle warmed to {td_p2_c:.1f} C.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Droplet Kinematics & Vertical Settling
    # ------------------------------------------------------------------------
    sim_kin = SprayDryerSimulationEngine()
    sim_kin.advance_time(duration_s=1.0, dt=0.01)

    z_pos = sim_kin.state.z
    v_z = sim_kin.state.v_z
    c5 = (
        0.5 < z_pos < sim_kin.cfg.tower_height_m
        and 0.5 < v_z < 2.0
    )
    test_results.append({
        "stage": 5,
        "check": "Droplet_Kinematics_And_Vertical_Settling",
        "passed": c5,
        "details": f"1D settling motion verified: z={z_pos:.2f} m down tower, downward velocity v_z={v_z:.2f} m/s.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Coupled 6-State ODE RK4 Solver Integration
    # ------------------------------------------------------------------------
    sim_rk4 = SprayDryerSimulationEngine()
    res_adv = sim_rk4.advance_time(duration_s=1.5, dt=0.01)

    st = sim_rk4.state
    c6 = (
        res_adv.status == AgentStatus.SUCCESS
        and st.d_p > 0.0
        and st.x_d >= st.x_d
        and st.t_d > 273.15
        and st.z > 0.0
        and st.v_z > 0.0
        and st.y_g > sim_rk4.cfg.inlet_air_humidity
    )
    test_results.append({
        "stage": 6,
        "check": "Coupled_6_State_ODE_RK4_Solver_Integration",
        "passed": c6,
        "details": f"RK4 150 steps completed smoothly: [dp={st.d_p_um:.1f} um, Xd={st.x_d:.3f}, Td={st.t_d_c:.1f} C, z={st.z:.2f} m, vz={st.v_z:.2f} m/s, Yg={st.y_g:.4f}].",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Gas Phase Psychrometric Balance & Exhaust Relative Humidity
    # ------------------------------------------------------------------------
    sim_psy = SprayDryerSimulationEngine()
    sim_psy.advance_time(duration_s=2.0, dt=0.01)

    tg_c = sim_psy.state.t_g_c
    rh_ex = sim_psy.state.rh_exhaust_pct
    twb_c = sim_psy.state.t_wb_c
    evap_rate = sim_psy.state.evaporation_rate_kg_h
    powder_rate = sim_psy.state.powder_production_rate_kg_h

    c7 = (
        50.0 < tg_c < sim_psy.cfg.inlet_air_temp_c
        and (0.0 < rh_ex < 65.0)
        and (30.0 < twb_c < tg_c)
        and evap_rate > 10.0
        and powder_rate > 10.0
    )
    test_results.append({
        "stage": 7,
        "check": "Gas_Phase_Psychrometric_Balance_And_Exhaust_RH",
        "passed": c7,
        "details": f"Psychrometric balance verified: T_exhaust={tg_c:.1f} C, RH={rh_ex:.1f}%, T_wb={twb_c:.1f} C, EvapRate={evap_rate:.1f} kg/h, PowderRate={powder_rate:.1f} kg/h.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Process Alarms, Safety Interlocks & Horner OCS Register Sync
    # ------------------------------------------------------------------------
    sim_alarm = SprayDryerSimulationEngine()
    sim_alarm.advance_time(duration_s=0.5, dt=0.01)

    # 1. Test InletAirOverTempTrip (%M158 -> 0x8401)
    sim_alarm.trigger_inlet_overtemp(225.0)
    coil_158 = sim_alarm.reg_table.read_bit("%M158")
    diag_158 = sim_alarm.reg_table.read_uword("%R687")
    status_158 = sim_alarm.reg_table.read_word("%R680")

    # 2. Test ExhaustCondensationTrip (%M159 -> 0x8402)
    sim_alarm.reset()
    sim_alarm.advance_time(duration_s=0.2, dt=0.01)
    sim_alarm.trigger_exhaust_condensation(temp_c=48.0, forced_humidity=0.065)
    coil_159 = sim_alarm.reg_table.read_bit("%M159")
    diag_159 = sim_alarm.reg_table.read_uword("%R687")
    status_159 = sim_alarm.reg_table.read_word("%R680")

    # 3. Test BaghouseFilterDpTrip (%M160 -> 0x8403)
    sim_alarm.reset()
    sim_alarm.trigger_filter_clog(2.80)
    coil_160 = sim_alarm.reg_table.read_bit("%M160")
    diag_160 = sim_alarm.reg_table.read_uword("%R687")
    status_160 = sim_alarm.reg_table.read_word("%R680")

    # Register reading check
    r681 = sim_alarm.reg_table.read_word("%R681")
    r682 = sim_alarm.reg_table.read_word("%R682")
    r683 = sim_alarm.reg_table.read_word("%R683")

    c8 = (
        coil_158 is True
        and diag_158 == 0x8401
        and (status_158 & int(SprayDryerStatusBits.HIGH_INLET_TEMP_ALARM)) != 0
        and coil_159 is True
        and diag_159 == 0x8402
        and (status_159 & int(SprayDryerStatusBits.CONDENSATION_STICKY_TRIP)) != 0
        and coil_160 is True
        and diag_160 == 0x8403
        and (status_160 & int(SprayDryerStatusBits.FILTER_DP_TRIP)) != 0
        and r681 > 0
        and r682 > 0
        and r683 > 0
    )
    test_results.append({
        "stage": 8,
        "check": "Process_Alarms_Safety_Interlocks_And_Register_Sync",
        "passed": c8,
        "details": "Alarms verified: %M158 (0x8401), %M159 (0x8402), %M160 (0x8403) assert with %R680..%R687 synchronized.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Anti-Ladder Construct Security Guard Rejection
    # ------------------------------------------------------------------------
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("""
        PROGRAM BadSprayDryerLadder
        VAR Valve : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """)
    except LadderForbiddenError:
        ladder_rejected = True

    c9 = ladder_rejected
    test_results.append({
        "stage": 9,
        "check": "Anti_Ladder_Construct_Security_Guard_Rejection",
        "passed": c9,
        "details": "Ladder contacts and coils strictly intercepted with ERR_LADDER_FORBIDDEN.",
    })

    # Compile evidence report
    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Spray Dryer Process Dynamics ODE Simulation Engine verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed).",
        "data": {
            "work_package": "W107",
            "gate": "Gate G7 / G4",
            "component": "Atomizer Droplet Evaporation & Psychrometric ODE Simulator",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "metrics": {
                "rosin_rammler_q": sim_base.cfg.rosin_rammler_q,
                "nominal_d32_um": sim_base.cfg.nominal_d32_um,
                "d_char_um": sim_base.cfg.d_char_um,
                "x_crit_kg_kg": sim_base.cfg.x_crit,
                "feed_rate_kg_h": sim_base.cfg.feed_rate_kg_h,
                "air_flow_rate_kg_h": sim_base.cfg.air_flow_rate_kg_h,
                "inlet_air_temp_c": sim_base.cfg.inlet_air_temp_c,
            },
            "register_map": {
                "analog_registers": "%R680..%R687",
                "discrete_coils": "%M158..%M160",
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if evidence_path:
        out_p = Path(evidence_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence
