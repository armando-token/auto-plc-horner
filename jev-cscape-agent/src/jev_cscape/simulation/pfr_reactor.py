"""Tubular Catalytic Plug-Flow Reactor (PFR) Exothermic Kinetics & Thermal Runaway ODE.

Work Package: W077 (Gate G7 / G4)
Classification: First-principles continuous chemical reactor dynamic simulation
Horner OCS Register Mappings:
- %R380: Reactor Inlet Feed Concentration C_A_in scaled x100 (mol/m3, nominal 2000 = 20.00 mol/m3)
- %R381: Reactor Outlet Concentration C_A_out scaled x100 (mol/m3)
- %R382: Reactant Conversion X_A % scaled x100 (e.g. 8850 = 88.50%)
- %R383: Maximum Core / Hot-Spot Temperature T_max °C scaled x10 (e.g. 1754 = 175.4 °C)
- %R384: Hot-Spot Axial Position z_hot % scaled x10 (e.g. 350 = 35.0% reactor length)
- %R385: Cooling Jacket Temperature T_cool °C scaled x10 (e.g. 1100 = 110.0 °C)
- %R386: Parametric Runaway Sensitivity Index S x100 (e.g. 135 = 1.35)
- %R387: Status Word (Bit 0: Normal, Bit 1: Hot-Spot Warn, Bit 2: Runaway Alarm, Bit 3: Low Conv Warn, Bit 4: Coolant Flood Active)
- %M88: Enable PFR Simulation Loop
- %M89: Emergency Coolant Flood Override Mode
- %M90: Reset Reactor Alarms
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Dict, List, Optional, Tuple

R_GAS_CONST: float = 8.314462618  # Universal gas constant [J / (mol * K)]


@dataclass
class PFRConfig:
    """Physicochemical and geometric parameters for Tubular Catalytic PFR."""
    length_m: float = 2.0                    # Total reactor length L [m]
    diameter_m: float = 0.05                 # Tube internal diameter D [m]
    velocity_m_s: float = 0.15               # Superficial flow velocity v [m/s]
    density_kg_m3: float = 950.0             # Fluid mixture density rho [kg/m^3]
    cp_j_kg_k: float = 3200.0                # Fluid specific heat capacity Cp [J/(kg*K)]
    k0_inv_s: float = 1.5e9                  # Arrhenius frequency factor k0 [1/s]
    activation_energy_j_mol: float = 68000.0 # Activation energy Ea [J/mol]
    delta_h_rxn_j_mol: float = -85000.0      # Heat of reaction (exothermic) [J/mol]
    u_nominal_w_m2_k: float = 350.0          # Nominal wall heat transfer coeff U [W/(m^2*K)]
    t_coolant_nominal_c: float = 110.0       # Nominal cooling jacket temperature [°C]
    t_coolant_flood_c: float = 40.0          # Emergency coolant flood temperature [°C]
    u_flood_multiplier: float = 3.0          # Heat transfer multiplier during emergency flood
    t_hotspot_warn_c: float = 160.0          # Hot-spot warning limit [°C]
    t_runaway_trip_c: float = 200.0          # Thermal runaway alarm trip limit [°C]
    c_a_inlet_mol_m3: float = 20.0           # Nominal feed inlet concentration [mol/m^3]
    t_inlet_c: float = 115.0                 # Feed inlet temperature [°C]
    n_axial_cells: int = 20                  # Number of axial finite volume cells N


class TubularPFRSimulator:
    """1D Axially Discretized Tubular Catalytic Plug-Flow Reactor ODE Simulator."""

    def __init__(self, config: Optional[PFRConfig] = None) -> None:
        self.cfg = config or PFRConfig()
        self.N = self.cfg.n_axial_cells
        self.dz = self.cfg.length_m / float(self.N)
        self.A_c = (math.pi / 4.0) * (self.cfg.diameter_m ** 2)
        self.v_cell = self.A_c * self.dz
        self.vol_flow = self.cfg.velocity_m_s * self.A_c

        # State arrays in physical units: C_A [mol/m3], T [K]
        self.inlet_c_a = self.cfg.c_a_inlet_mol_m3
        self.inlet_t_k = self.cfg.t_inlet_c + 273.15
        self.coolant_t_k = self.cfg.t_coolant_nominal_c + 273.15

        self.c_a: List[float] = [self.inlet_c_a] * self.N
        self.temperature_k: List[float] = [self.inlet_t_k] * self.N
        self.time_s: float = 0.0

        # Safety & Handshake States
        self.enable_loop: bool = True
        self.emergency_coolant_override: bool = False
        self.reset_alarms: bool = False
        self.hotspot_warn_latched: bool = False
        self.thermal_runaway_latched: bool = False
        self.coolant_flood_active: bool = False

        # Metrics for Horner registers
        self.conversion_pct: float = 0.0
        self.t_max_c: float = self.cfg.t_inlet_c
        self.z_hot_pct: float = 0.0
        self.parametric_sensitivity: float = 1.35
        self.status_word: int = 0x0001

    def compute_reaction_rate(self, c_a: float, t_k: float) -> float:
        """Evaluate 1st-order Arrhenius reaction rate r = k0 * exp(-Ea / RT) * C_A."""
        t_bounded = max(150.0, min(t_k, 1500.0))
        k = self.cfg.k0_inv_s * math.exp(-self.cfg.activation_energy_j_mol / (R_GAS_CONST * t_bounded))
        return k * max(0.0, c_a)

    def evaluate_derivatives(
        self,
        c_a_profile: List[float],
        t_profile: List[float],
        u_eff: float,
        t_cool_k: float,
    ) -> Tuple[List[float], List[float], List[float]]:
        """Evaluate spatial upwind derivatives dC_A/dt and dT/dt across all N cells."""
        dca_dt = [0.0] * self.N
        dt_dt = [0.0] * self.N
        r_a = [0.0] * self.N

        a_surf = 4.0 / self.cfg.diameter_m
        vol_heat_cap = self.cfg.density_kg_m3 * self.cfg.cp_j_kg_k
        heat_rxn_factor = (-self.cfg.delta_h_rxn_j_mol) / vol_heat_cap
        heat_cool_factor = (a_surf * u_eff) / vol_heat_cap
        conv_rate = self.cfg.velocity_m_s / self.dz

        for i in range(self.N):
            c_upstream = self.inlet_c_a if i == 0 else c_a_profile[i - 1]
            t_upstream = self.inlet_t_k if i == 0 else t_profile[i - 1]

            r_i = self.compute_reaction_rate(c_a_profile[i], t_profile[i])
            r_a[i] = r_i

            dca_dt[i] = conv_rate * (c_upstream - c_a_profile[i]) - r_i
            dt_dt[i] = (
                conv_rate * (t_upstream - t_profile[i])
                + heat_rxn_factor * r_i
                - heat_cool_factor * (t_profile[i] - t_cool_k)
            )

        return dca_dt, dt_dt, r_a

    def check_conservation(
        self,
        dca_dt: List[float],
        dt_dt: List[float],
        r_a: List[float],
        u_eff: float,
        t_cool_k: float,
    ) -> Dict[str, Any]:
        """Verify mass and energy balance conservation residuals (< 1e-10)."""
        dn_a_dt = sum(dca_dt[i] * self.v_cell for i in range(self.N))
        n_in = self.vol_flow * self.inlet_c_a
        n_out = self.vol_flow * self.c_a[-1]
        r_total = sum(r_a[i] * self.v_cell for i in range(self.N))
        mass_residual = abs(dn_a_dt - (n_in - n_out - r_total))

        vol_heat_cap = self.cfg.density_kg_m3 * self.cfg.cp_j_kg_k
        de_th_dt = sum(dt_dt[i] * vol_heat_cap * self.v_cell for i in range(self.N))
        h_in = self.vol_flow * vol_heat_cap * self.inlet_t_k
        h_out = self.vol_flow * vol_heat_cap * self.temperature_k[-1]
        q_gen = (-self.cfg.delta_h_rxn_j_mol) * r_total
        q_rem = sum(
            u_eff * (math.pi * self.cfg.diameter_m * self.dz) * (self.temperature_k[i] - t_cool_k)
            for i in range(self.N)
        )
        energy_residual = abs(de_th_dt - (h_in - h_out + q_gen - q_rem))

        return {
            "mass_residual": mass_residual,
            "energy_residual": energy_residual,
            "mass_conserved": mass_residual < 1.0e-10,
            "energy_conserved": energy_residual < 1.0e-10,
        }

    def compute_parametric_sensitivity(self, delta_t_c: float = 1.0) -> float:
        """Estimate parametric runaway sensitivity S = d(T_max)/d(T_cool)."""
        # Baseline hot spot
        t_max_base = max(self.temperature_k)
        u_eff = self.cfg.u_nominal_w_m2_k
        t_cool_perturbed = self.coolant_t_k + delta_t_c

        # Quick derivative projection
        _, dt_pert, _ = self.evaluate_derivatives(self.c_a, self.temperature_k, u_eff, t_cool_perturbed)
        t_est = [self.temperature_k[i] + 0.1 * dt_pert[i] for i in range(self.N)]
        t_max_pert = max(t_est)
        diff = abs(t_max_pert - t_max_base)
        s = max(1.0, min(10.0, 1.0 + diff * 3.5))
        return s

    def step(self, dt_s: float = 0.05) -> Dict[str, Any]:
        """Advance the PFR simulation by one scan cycle dt_s using explicit integration."""
        if self.reset_alarms:
            self.hotspot_warn_latched = False
            self.thermal_runaway_latched = False
            self.reset_alarms = False

        if not self.enable_loop:
            self.status_word = 0
            self.conversion_pct = 0.0
            self.t_max_c = self.coolant_t_k - 273.15
            self.z_hot_pct = 0.0
            return {"status": "disabled", "time_s": self.time_s}

        # CFL stability limit check (dt <= dz / v)
        cfl_limit = self.dz / self.cfg.velocity_m_s
        dt = min(dt_s, cfl_limit * 0.95)

        # Coolant flood override / automatic trip
        current_t_max_c = max(self.temperature_k) - 273.15
        if self.emergency_coolant_override or self.thermal_runaway_latched:
            self.coolant_flood_active = True
        else:
            self.coolant_flood_active = False

        u_eff = self.cfg.u_nominal_w_m2_k * (self.cfg.u_flood_multiplier if self.coolant_flood_active else 1.0)
        t_cool_k = (self.cfg.t_coolant_flood_c if self.coolant_flood_active else self.coolant_t_k - 273.15) + 273.15

        # Evaluate ODE derivatives
        dca, dt_temp, r_a = self.evaluate_derivatives(self.c_a, self.temperature_k, u_eff, t_cool_k)
        conservation = self.check_conservation(dca, dt_temp, r_a, u_eff, t_cool_k)

        # Update state cells
        for i in range(self.N):
            self.c_a[i] = max(0.0, self.c_a[i] + dt * dca[i])
            self.temperature_k[i] = max(150.0, min(1500.0, self.temperature_k[i] + dt * dt_temp[i]))

        self.time_s += dt

        # Output variables
        c_out = self.c_a[-1]
        self.conversion_pct = max(0.0, min(100.0, ((self.inlet_c_a - c_out) / max(1e-6, self.inlet_c_a)) * 100.0))

        # Peak Hot-Spot identification
        t_nodes_c = [t - 273.15 for t in self.temperature_k]
        self.t_max_c = max(t_nodes_c)
        max_idx = t_nodes_c.index(self.t_max_c)
        self.z_hot_pct = ((max_idx + 0.5) / self.N) * 100.0

        # Alarms & Sensitivity
        self.parametric_sensitivity = self.compute_parametric_sensitivity()

        if self.t_max_c >= self.cfg.t_runaway_trip_c:
            self.thermal_runaway_latched = True
        if self.t_max_c >= self.cfg.t_hotspot_warn_c:
            self.hotspot_warn_latched = True

        low_conv = self.conversion_pct < 70.0

        # Status Word synthesis
        # Bit 0: Normal, Bit 1: Warn, Bit 2: Alarm, Bit 3: Low Conv, Bit 4: Flood
        status = 0
        if not self.hotspot_warn_latched and not self.thermal_runaway_latched and not low_conv and not self.coolant_flood_active:
            status |= 0x0001
        if self.hotspot_warn_latched:
            status |= 0x0002
        if self.thermal_runaway_latched:
            status |= 0x0004
        if low_conv:
            status |= 0x0008
        if self.coolant_flood_active:
            status |= 0x0010

        self.status_word = status

        return {
            "time_s": self.time_s,
            "c_a_out": c_out,
            "conversion_pct": self.conversion_pct,
            "t_max_c": self.t_max_c,
            "z_hot_pct": self.z_hot_pct,
            "sensitivity": self.parametric_sensitivity,
            "status_word": self.status_word,
            "conservation": conservation,
        }

    def sync_to_register_table(self, reg_table: Any) -> None:
        """Write PFR simulation outputs to Horner OCS RegisterTable."""
        write_fn = getattr(reg_table, "write_register", getattr(reg_table, "write", None))
        if write_fn is None:
            return
        write_fn("%R380", int(round(self.inlet_c_a * 100.0)))
        write_fn("%R381", int(round(self.c_a[-1] * 100.0)))
        write_fn("%R382", int(round(self.conversion_pct * 100.0)))
        write_fn("%R383", int(round(self.t_max_c * 10.0)))
        write_fn("%R384", int(round(self.z_hot_pct * 10.0)))
        write_fn("%R385", int(round((self.coolant_t_k - 273.15) * 10.0)))
        write_fn("%R386", int(round(self.parametric_sensitivity * 100.0)))
        write_fn("%R387", self.status_word)
        write_fn("%M88", self.enable_loop)
        write_fn("%M89", self.emergency_coolant_override)
        write_fn("%M90", self.reset_alarms)

    def sync_from_register_table(self, reg_table: Any) -> None:
        """Read process controls from Horner OCS RegisterTable."""
        read_fn = getattr(reg_table, "read_register", getattr(reg_table, "read", None))
        if read_fn is None:
            return
        r380 = read_fn("%R380")
        if r380 is not None and int(r380) > 0:
            self.inlet_c_a = int(r380) / 100.0
        r385 = read_fn("%R385")
        if r385 is not None and int(r385) > 0:
            self.coolant_t_k = (int(r385) / 10.0) + 273.15

        self.enable_loop = bool(read_fn("%M88"))
        self.emergency_coolant_override = bool(read_fn("%M89"))
        self.reset_alarms = bool(read_fn("%M90"))


# ---------------------------------------------------------------------------
# Pure Structured Text POU Definition
# ---------------------------------------------------------------------------

PFR_REACTOR_ST_CODE = """PROGRAM W077_TubularPlugFlowReactor
VAR
    Reactor_Inlet_Conc AT %R380 : INT;
    Reactor_Outlet_Conc AT %R381 : INT;
    Reactant_Conversion AT %R382 : INT;
    Max_Core_Temp AT %R383 : INT;
    Hot_Spot_Axial_Pos AT %R384 : INT;
    Cooling_Jacket_Temp AT %R385 : INT;
    Runaway_Sensitivity AT %R386 : INT;
    Reactor_Status_Word AT %R387 : INT;

    Enable_PFR_Loop AT %M88 : BOOL;
    Emergency_Coolant_Override AT %M89 : BOOL;
    Reset_Reactor_Alarms AT %M90 : BOOL;

    Thermal_Runaway_Latched : BOOL := FALSE;
    Hot_Spot_Warning_Latched : BOOL := FALSE;
    Emergency_Coolant_Active : BOOL := FALSE;
    Low_Conversion_Warning : BOOL := FALSE;
    Effective_Cooling_Temp : INT := 1100;
    Delta_T_Reaction : INT := 0;
    Reaction_Rate_Factor : INT := 0;
END_VAR

IF Reset_Reactor_Alarms THEN
    Thermal_Runaway_Latched := FALSE;
    Hot_Spot_Warning_Latched := FALSE;
    Reset_Reactor_Alarms := FALSE;
END_IF;

IF Enable_PFR_Loop THEN
    IF Emergency_Coolant_Override OR Thermal_Runaway_Latched THEN
        Emergency_Coolant_Active := TRUE;
        Effective_Cooling_Temp := 400;
    ELSE
        Emergency_Coolant_Active := FALSE;
        Effective_Cooling_Temp := Cooling_Jacket_Temp;
    END_IF;

    IF Emergency_Coolant_Active THEN
        Max_Core_Temp := Effective_Cooling_Temp + ((Reactor_Inlet_Conc * 15) / 1000);
        Hot_Spot_Axial_Pos := 800;
        Reactor_Outlet_Conc := (Reactor_Inlet_Conc * 750) / 1000;
        Runaway_Sensitivity := 105;
    ELSE
        Reaction_Rate_Factor := (Effective_Cooling_Temp - 800) / 10;
        IF Reaction_Rate_Factor < 10 THEN
            Reaction_Rate_Factor := 10;
        END_IF;

        Delta_T_Reaction := ((Reactor_Inlet_Conc * Reaction_Rate_Factor) / 100);
        Max_Core_Temp := Effective_Cooling_Temp + Delta_T_Reaction;

        IF Effective_Cooling_Temp >= 1400 THEN
            Hot_Spot_Axial_Pos := 180;
            Runaway_Sensitivity := 420;
        ELSIF Effective_Cooling_Temp >= 1200 THEN
            Hot_Spot_Axial_Pos := 260;
            Runaway_Sensitivity := 240;
        ELSE
            Hot_Spot_Axial_Pos := 350;
            Runaway_Sensitivity := 135;
        END_IF;

        IF Max_Core_Temp > 2000 THEN
            Reactor_Outlet_Conc := (Reactor_Inlet_Conc * 15) / 1000;
        ELSIF Max_Core_Temp > 1600 THEN
            Reactor_Outlet_Conc := (Reactor_Inlet_Conc * 115) / 1000;
        ELSE
            Reactor_Outlet_Conc := (Reactor_Inlet_Conc * 220) / 1000;
        END_IF;
    END_IF;

    IF Reactor_Inlet_Conc > 0 THEN
        Reactant_Conversion := ((Reactor_Inlet_Conc - Reactor_Outlet_Conc) * 10000) / Reactor_Inlet_Conc;
    ELSE
        Reactant_Conversion := 0;
    END_IF;

    IF Max_Core_Temp > 2000 THEN
        Thermal_Runaway_Latched := TRUE;
    END_IF;

    IF Max_Core_Temp > 1600 THEN
        Hot_Spot_Warning_Latched := TRUE;
    ELSE
        Hot_Spot_Warning_Latched := FALSE;
    END_IF;

    Low_Conversion_Warning := Reactant_Conversion < 7000;
ELSE
    Emergency_Coolant_Active := FALSE;
    Reactor_Outlet_Conc := Reactor_Inlet_Conc;
    Reactant_Conversion := 0;
    Max_Core_Temp := Cooling_Jacket_Temp;
    Hot_Spot_Axial_Pos := 0;
    Runaway_Sensitivity := 100;
    Low_Conversion_Warning := FALSE;
END_IF;

Reactor_Status_Word := 0;
IF Enable_PFR_Loop AND NOT Hot_Spot_Warning_Latched AND NOT Thermal_Runaway_Latched AND NOT Low_Conversion_Warning AND NOT Emergency_Coolant_Active THEN
    Reactor_Status_Word := Reactor_Status_Word OR 1;
END_IF;
IF Hot_Spot_Warning_Latched THEN
    Reactor_Status_Word := Reactor_Status_Word OR 2;
END_IF;
IF Thermal_Runaway_Latched THEN
    Reactor_Status_Word := Reactor_Status_Word OR 4;
END_IF;
IF Low_Conversion_Warning THEN
    Reactor_Status_Word := Reactor_Status_Word OR 8;
END_IF;
IF Emergency_Coolant_Active THEN
    Reactor_Status_Word := Reactor_Status_Word OR 16;
END_IF;
END_PROGRAM
"""
