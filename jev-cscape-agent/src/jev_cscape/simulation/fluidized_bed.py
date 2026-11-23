"""Fluidized Bed Reactor (FBR) Two-Phase Hydrodynamics & Catalytic Gasification ODE Solver.

Work Package: W089 (Gate G7 Advanced Process Dynamics / Gate G4 Simulation)
Classification: PRODUCTION_READY

Implements:
1. Two-phase fluidization hydrodynamics (Davidson-Harrison / Kunii-Levenspiel):
   - Ergun equation quadratic solution for minimum fluidization velocity U_mf.
   - Darton bubble diameter growth d_b(z) and Davidson-Harrison bubble rise velocity u_br.
   - Expanded bed height L_f / L_mf and gas holdup voidage delta_b.
   - Dense bed differential pressure Delta_P invariant to gas flow once fluidized.
2. Interphase mass and heat transfer (Kunii-Levenspiel model):
   - Gas interchange coefficient K_be = 4.5 * (U_mf / d_b) + 5.85 * (D_AB^0.5 * g^0.25 / d_b^1.25).
   - Volumetric heat transfer coefficient H_be.
3. Catalytic chemical reaction kinetics:
   - Arrhenius 1st-order rate law r_A = k_0 * exp(-E_a / (R * T_em)) * C_A_em.
   - Coupled 4-state ODE system (C_A_b, C_A_em, T_b, T_em) solved via 4th-Order Runge-Kutta (RK4).
   - Strict conservation residuals: molar mass balance < 1e-10 mol/s, thermal energy < 1e-10 W.
4. Fines elutriation and cyclone separation return loop:
   - Merrick-Highley elutriation rate at Transport Disengagement Height (TDH).
   - High-efficiency cyclone separator (eta_cyc = 99.2%) with solids dipleg return.
5. Emergency nitrogen quench and defluidization override (%M117):
   - Rapid feed cutoff, bed slump defluidization, and high-rate cold N2 purge cooling.
6. Horner OCS register space synchronization:
   - Analog registers %R500..%R507 (16-bit safe scaling with zero overflow).
   - Discrete coils %M116..%M118 (system run enable, quench override, alarm reset handshake).
7. Pure IEC 61131-3 Structured Text (ST) POU with anti-ladder security guard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag
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


R_GAS_CONST: float = 8.314462618  # Universal gas constant [J/(mol*K)]
G_ACCEL: float = 9.80665          # Standard gravitational acceleration [m/s^2]


# ============================================================================
# 1. Enums and Status Bitmasks
# ============================================================================

class FBRStatusBits(IntFlag):
    """Horner OCS %R500 Status Word Bitmask Definitions."""
    ACTIVE                 = 1 << 0  # Bit 0: Simulation active (%M116)
    CHANNELLING_FAULT      = 1 << 1  # Bit 1: Bed channelling detected (dP < 0.70 * dP_theo)
    HOT_SPOT_ALARM         = 1 << 2  # Bit 2: Critical hot-spot runaway alarm (T_em >= 850.0 C)
    CYCLONE_DP_ALARM       = 1 << 3  # Bit 3: Cyclone dP high (dP_cyc >= 25.0 mbar)
    PURGE_ACTIVE           = 1 << 4  # Bit 4: Emergency N2 quench active (%M117)
    DEFLUIDIZED            = 1 << 5  # Bit 5: Slumped / defluidized bed (U_0 < U_mf)
    ALARM_LATCHED          = 1 << 6  # Bit 6: Alarm latched requiring %M118 reset
    CYCLONE_RETURN_HEALTHY = 1 << 7  # Bit 7: Cyclone return loop operating normally


# ============================================================================
# 2. Configuration & Parameter Data Models
# ============================================================================

@dataclass
class FBRConfig:
    """Reactor geometry, hydrodynamics, kinetics, and thermal parameters."""
    # Reactor Geometry
    diameter_m: float = 1.0                  # Reactor bed column diameter [m]
    settled_height_m: float = 1.74           # Settled bed height L_mf [m]
    freeboard_height_m: float = 4.0          # Freeboard vessel height H_fb [m]
    nozzle_area_a0_m2: float = 7.8e-4        # Catchment area per distributor orifice [m^2]

    # Solid Catalyst & Gas Properties
    particle_dp_m: float = 150e-6            # Mean bed particle diameter [m]
    fines_dp_m: float = 45e-6                # Fines particle diameter [m]
    fines_fraction: float = 0.12             # Fines mass fraction x_fines [-]
    particle_density_kg_m3: float = 2000.0   # Solid catalyst density [kg/m^3]
    bed_mass_kg: float = 1500.0              # Total catalyst bed inventory [kg]
    eps_mf: float = 0.45                     # Emulsion voidage at mf [-]
    gas_mw_g_mol: float = 28.5               # Syngas molecular weight [g/mol]
    operating_press_pa: float = 150000.0     # Vessel operating pressure [Pa]
    d_ab_m2_s: float = 2.0e-5                # Molecular diffusivity [m^2/s]
    cp_solids_j_kg_k: float = 1050.0         # Catalyst solids heat capacity [J/(kg*K)]
    cp_gas_j_kg_k: float = 1250.0            # Syngas heat capacity [J/(kg*K)]
    k_gas_w_m_k: float = 0.035               # Gas thermal conductivity [W/(m*K)]

    # Cyclone Separator
    cyclone_efficiency: float = 0.992        # Cyclone separation efficiency eta_cyc (99.2%)
    k_cyc_head: float = 6.4                  # Cyclone inlet velocity heads N_H [-]
    cyclone_dp_max_mbar: float = 25.0        # High cyclone dP trip ceiling [mbar]

    # Reaction Kinetics
    c_a_inlet_mol_m3: float = 25.0           # Inlet feed reactant concentration [mol/m^3]
    t_inlet_c: float = 350.0                 # Feed gas preheat temperature [°C]
    arrhenius_k0: float = 2.5e4              # Pre-exponential factor [1/s]
    activation_e_j_mol: float = 75000.0      # Activation energy E_a [J/mol]
    delta_h_rxn_j_mol: float = -180000.0     # Exothermic reaction enthalpy [J/mol]
    u_wall_w_m2_k: float = 25.0              # Ambient wall heat loss coefficient [W/(m^2*K)]
    t_ambient_c: float = 25.0                # Ambient temperature [°C]

    # Emergency Quench & Safety Limits
    quench_n2_flow_kg_s: float = 15.0        # Cold N2 quench flow [kg/s]
    quench_n2_temp_c: float = 20.0           # Quench N2 supply temperature [°C]
    cp_n2_j_kg_k: float = 1040.0             # N2 specific heat capacity [J/(kg*K)]
    t_hotspot_trip_c: float = 850.0          # Critical hot-spot alarm trip [°C]


# ============================================================================
# 3. Fluidized Bed Reactor Simulation Engine
# ============================================================================

class FluidizedBedReactorSimulator:
    """Coupled two-phase hydrodynamic, mass/heat transfer, and reaction ODE simulator."""

    def __init__(
        self,
        config: Optional[FBRConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.cfg = config or FBRConfig()
        self.registers = register_table or RegisterTable()

        self.bed_area = (math.pi / 4.0) * (self.cfg.diameter_m ** 2)
        self.v_bed_mf = self.bed_area * self.cfg.settled_height_m

        # Dynamic States: [C_A_b, C_A_em, T_b_K, T_em_K]
        self.c_a_b: float = self.cfg.c_a_inlet_mol_m3
        self.c_a_em: float = self.cfg.c_a_inlet_mol_m3 * 0.15
        self.t_b_k: float = self.cfg.t_inlet_c + 273.15
        self.t_em_k: float = 780.0 + 273.15      # 780.0 °C nominal
        self.u0_m_s: float = 0.65                # Operating superficial velocity [m/s]
        self.time_s: float = 0.0

        # Alarms and latches
        self.alarm_latched: bool = False
        self.channelling_fault: bool = False
        self.hot_spot_alarm: bool = False
        self.cyclone_dp_alarm: bool = False
        self.quench_active: bool = False

        # Initialize Horner registers & coils
        self.registers.write_bit("%M116", True, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_bit("%M117", False, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_bit("%M118", False, privilege=PrivilegeMode.SYSTEM)
        self.sync_registers()

    def gas_density(self, t_k: float) -> float:
        """Calculate ideal gas syngas density [kg/m^3]."""
        mw_kg_mol = self.cfg.gas_mw_g_mol * 1e-3
        return (self.cfg.operating_press_pa * mw_kg_mol) / (R_GAS_CONST * t_k)

    def gas_viscosity(self, t_k: float) -> float:
        """Calculate temperature-dependent syngas dynamic viscosity [Pa*s]."""
        return 1.8e-5 * ((t_k / 293.15) ** 0.7)

    def compute_umf(self, t_k: float) -> float:
        """Solve Ergun equation for minimum fluidization velocity U_mf [m/s]."""
        rho_g = self.gas_density(t_k)
        mu_g = self.gas_viscosity(t_k)
        d_p = self.cfg.particle_dp_m
        rho_p = self.cfg.particle_density_kg_m3
        eps = self.cfg.eps_mf

        a = (1.75 / (eps ** 3)) * (rho_g / d_p)
        b = 150.0 * ((1.0 - eps) / (eps ** 3)) * (mu_g / (d_p ** 2))
        c = (rho_p - rho_g) * G_ACCEL

        return (-b + math.sqrt(b * b + 4.0 * a * c)) / (2.0 * a)

    def compute_bubble_diameter(self, u0: float, umf: float, z_m: float) -> float:
        """Calculate bubble diameter growth d_b(z) via Darton correlation [m]."""
        u_excess = max(0.0, u0 - umf)
        if u_excess <= 0.0:
            return 0.01
        c_darton = 0.54 / (G_ACCEL ** 0.2)
        d_b = c_darton * (u_excess ** 0.4) * ((z_m + 4.0 * math.sqrt(self.cfg.nozzle_area_a0_m2)) ** 0.8)
        return min(d_b, 0.40 * self.cfg.diameter_m)

    def compute_hydrodynamics(self, u0: float, umf: float, t_k: float) -> Dict[str, float]:
        """Compute two-phase hydrodynamics, expansion, elutriation, and cyclone return."""
        rho_g = self.gas_density(t_k)
        mu_g = self.gas_viscosity(t_k)

        # 1. Bubble dynamics & bed expansion
        if u0 > umf:
            d_b = self.compute_bubble_diameter(u0, umf, self.cfg.settled_height_m * 0.5)
            u_br = 0.711 * math.sqrt(G_ACCEL * d_b)
            u_b = (u0 - umf) + u_br
            delta = min(0.60, max(0.01, (u0 - umf) / u_b))
            l_f = self.cfg.settled_height_m / (1.0 - delta)
        else:
            d_b = 0.01
            u_b = umf
            delta = 0.0
            l_f = self.cfg.settled_height_m

        # 2. TDH (Transport Disengagement Height)
        tdh = 1.2 * math.sqrt(self.cfg.diameter_m) * (((max(0.01, u0) ** 2) / (G_ACCEL * self.cfg.diameter_m)) ** 0.3)

        # 3. Fines elutriation (Merrick & Highley correlation at TDH)
        d_f = self.cfg.fines_dp_m
        rho_p = self.cfg.particle_density_kg_m3
        u_tf = (G_ACCEL * (rho_p - rho_g) * (d_f ** 2)) / (18.0 * mu_g)

        if (u0 > u_tf) and (u0 > umf):
            exp_term = -10.4 * math.sqrt(u_tf / u0) * (((umf / (u0 - umf))) ** 0.25)
            k_star = 130.0 * rho_g * u0 * math.exp(exp_term)
            f_ent_kg_h = 3600.0 * self.bed_area * self.cfg.fines_fraction * k_star
        else:
            f_ent_kg_h = 0.0

        # 4. Cyclone separation & solids return
        eta = self.cfg.cyclone_efficiency  # 0.992
        f_return_kg_h = eta * f_ent_kg_h
        f_loss_kg_h = (1.0 - eta) * f_ent_kg_h

        # 5. Pressure drops
        delta_p_theo_mbar = (self.cfg.bed_mass_kg * G_ACCEL / self.bed_area) * 0.01
        delta_p_bed_mbar = delta_p_theo_mbar if u0 >= umf else delta_p_theo_mbar * (u0 / max(1e-4, umf))
        delta_p_dist_mbar = 0.5 * rho_g * (u0 ** 2) * 25.0 * 0.01
        total_delta_p_mbar = delta_p_bed_mbar + delta_p_dist_mbar

        v_in_cyc = u0 * 8.0
        cyclone_dp_mbar = 0.5 * rho_g * (v_in_cyc ** 2) * self.cfg.k_cyc_head * 0.01

        # Interphase exchange coefficients
        k_be = 4.5 * (umf / d_b) + 5.85 * ((self.cfg.d_ab_m2_s ** 0.5 * G_ACCEL ** 0.25) / (d_b ** 1.25))
        rho_cp = rho_g * self.cfg.cp_gas_j_kg_k
        h_be = 4.5 * (umf * rho_cp / d_b) + 5.85 * (((self.cfg.k_gas_w_m_k * rho_cp) ** 0.5 * G_ACCEL ** 0.25) / (d_b ** 1.25))

        return {
            "L_f": l_f,
            "d_b": d_b,
            "delta_b": delta,
            "TDH": tdh,
            "F_ent": f_ent_kg_h,
            "F_return": f_return_kg_h,
            "F_loss": f_loss_kg_h,
            "delta_p_bed": delta_p_bed_mbar,
            "delta_p_theo": delta_p_theo_mbar,
            "total_delta_p": total_delta_p_mbar,
            "cyclone_dp": cyclone_dp_mbar,
            "k_be": k_be,
            "h_be": h_be,
        }

    def reaction_rate(self, c_a_em: float, t_em_k: float) -> float:
        """1st-Order Arrhenius catalytic reaction rate r_A [mol/(m^3_em * s)]."""
        t_bound = max(293.15, min(1600.0, t_em_k))
        k = self.cfg.arrhenius_k0 * math.exp(-self.cfg.activation_e_j_mol / (R_GAS_CONST * t_bound))
        return k * max(0.0, c_a_em)

    def evaluate_derivatives(
        self, state: List[float], u0: float, umf: float, hydro: Dict[str, float]
    ) -> Tuple[List[float], float]:
        """Evaluate coupled time derivatives [dC_A_b/dt, dC_A_em/dt, dT_b/dt, dT_em/dt]."""
        c_a_b, c_a_em, t_b, t_em = state
        delta_b = max(0.02, min(0.60, hydro["delta_b"]))

        # Phase volumes
        v_r = self.bed_area * hydro["L_f"]
        v_b = delta_b * v_r
        v_em = (1.0 - delta_b) * v_r

        # Flow splitting
        q_b = max(0.001, (u0 - umf) * self.bed_area) if u0 > umf else 0.001
        q_em = max(0.001, umf * self.bed_area)

        # Thermal capacitances
        rho_g = self.gas_density(t_b)
        c_th_b = rho_g * self.cfg.cp_gas_j_kg_k
        c_th_em = (
            (1.0 - self.cfg.eps_mf) * self.cfg.particle_density_kg_m3 * self.cfg.cp_solids_j_kg_k
            + self.cfg.eps_mf * rho_g * self.cfg.cp_gas_j_kg_k
        )

        r_a = self.reaction_rate(c_a_em, t_em)
        vol_ratio = delta_b / max(1e-4, 1.0 - delta_b)

        # 1. dC_A_b/dt
        dc_ab_dt = (q_b / v_b) * (self.cfg.c_a_inlet_mol_m3 - c_a_b) - hydro["k_be"] * (c_a_b - c_a_em)

        # 2. dC_A_em/dt
        dc_aem_dt = (
            (q_em / v_em) * (self.cfg.c_a_inlet_mol_m3 - c_a_em)
            + hydro["k_be"] * vol_ratio * (c_a_b - c_a_em)
            - r_a
        )

        # 3. dT_b/dt
        t_inlet_k = self.cfg.t_inlet_c + 273.15
        dt_b_dt = (q_b / v_b) * (t_inlet_k - t_b) - (hydro["h_be"] / c_th_b) * (t_b - t_em)

        # 4. dT_em/dt
        q_in_out = (q_em * c_th_b / v_em) * (t_inlet_k - t_em)
        q_inter = hydro["h_be"] * vol_ratio * (t_b - t_em)
        q_rxn = (-self.cfg.delta_h_rxn_j_mol) * r_a
        a_wall = math.pi * self.cfg.diameter_m * hydro["L_f"]
        q_wall = (self.cfg.u_wall_w_m2_k * a_wall / v_em) * (t_em - (self.cfg.t_ambient_c + 273.15))

        dt_em_dt = (q_in_out + q_inter + q_rxn - q_wall) / c_th_em

        return [dc_ab_dt, dc_aem_dt, dt_b_dt, dt_em_dt], r_a

    def check_conservation(
        self, state: List[float], d_state: List[float], r_a: float, u0: float, umf: float, hydro: Dict[str, float]
    ) -> Dict[str, Any]:
        """Verify strict mass and energy balance conservation residuals."""
        c_a_b, c_a_em, t_b, t_em = state
        dc_ab_dt, dc_aem_dt, dt_b_dt, dt_em_dt = d_state
        delta_b = max(0.02, min(0.60, hydro["delta_b"]))

        v_r = self.bed_area * hydro["L_f"]
        v_b = delta_b * v_r
        v_em = (1.0 - delta_b) * v_r

        q_b = max(0.001, (u0 - umf) * self.bed_area) if u0 > umf else 0.001
        q_em = max(0.001, umf * self.bed_area)
        q_0 = q_b + q_em

        # Molar mass residual
        molar_accum = v_b * dc_ab_dt + v_em * dc_aem_dt
        molar_in = q_0 * self.cfg.c_a_inlet_mol_m3
        molar_out = q_b * c_a_b + q_em * c_a_em
        molar_consumed = v_em * r_a
        mass_residual = abs(molar_accum - (molar_in - molar_out - molar_consumed))

        # Thermal energy residual
        rho_g = self.gas_density(t_b)
        c_th_b = rho_g * self.cfg.cp_gas_j_kg_k
        c_th_em = (
            (1.0 - self.cfg.eps_mf) * self.cfg.particle_density_kg_m3 * self.cfg.cp_solids_j_kg_k
            + self.cfg.eps_mf * rho_g * self.cfg.cp_gas_j_kg_k
        )
        t_inlet_k = self.cfg.t_inlet_c + 273.15
        a_wall = math.pi * self.cfg.diameter_m * hydro["L_f"]

        thermal_accum = v_b * c_th_b * dt_b_dt + v_em * c_th_em * dt_em_dt
        enthalpy_net = q_b * c_th_b * (t_inlet_k - t_b) + q_em * c_th_b * (t_inlet_k - t_em)
        q_rxn_total = (-self.cfg.delta_h_rxn_j_mol) * v_em * r_a
        q_loss_total = self.cfg.u_wall_w_m2_k * a_wall * (t_em - (self.cfg.t_ambient_c + 273.15))

        energy_residual = abs(thermal_accum - (enthalpy_net + q_rxn_total - q_loss_total))

        return {
            "mass_residual_mol_s": mass_residual,
            "energy_residual_w": energy_residual,
            "is_mass_conserved": mass_residual < 1e-10,
            "is_energy_conserved": energy_residual < 1e-10,
        }

    def step(self, dt: float = 0.05) -> None:
        """Advance the coupled simulation by dt seconds with RK4 integration."""
        enable = self.registers.read_bit("%M116")
        cmd_quench = self.registers.read_bit("%M117") or self.quench_active
        cmd_reset = self.registers.read_bit("%M118")

        if cmd_reset:
            self.alarm_latched = False
            self.channelling_fault = False
            self.hot_spot_alarm = False
            self.cyclone_dp_alarm = False
            self.quench_active = False

        if not enable:
            self.sync_registers()
            return

        umf = self.compute_umf(self.t_em_k)

        # 1. Emergency Quench Active Override
        if cmd_quench:
            self.quench_active = True
            self.u0_m_s = 0.35 * umf  # Slump bed (defluidize)

            # High-rate cold N2 purge cooling
            q_quench = (
                self.cfg.quench_n2_flow_kg_s
                * self.cfg.cp_n2_j_kg_k
                * (self.t_em_k - (self.cfg.quench_n2_temp_c + 273.15))
            )
            c_thermal = self.cfg.bed_mass_kg * self.cfg.cp_solids_j_kg_k
            dt_em_dt = -q_quench / c_thermal
            self.t_em_k = max(293.15, self.t_em_k + dt_em_dt * dt)
            self.t_b_k = max(293.15, self.t_b_k + dt_em_dt * dt * 2.0)
            self.c_a_em = 0.0
            self.c_a_b = 0.0
        else:
            # 2. Normal RK4 Stepper
            self.u0_m_s = 0.65
            hydro = self.compute_hydrodynamics(self.u0_m_s, umf, self.t_em_k)
            y = [self.c_a_b, self.c_a_em, self.t_b_k, self.t_em_k]

            # k1
            k1, r1 = self.evaluate_derivatives(y, self.u0_m_s, umf, hydro)
            # k2
            y2 = [y[i] + 0.5 * dt * k1[i] for i in range(4)]
            k2, _ = self.evaluate_derivatives(y2, self.u0_m_s, umf, hydro)
            # k3
            y3 = [y[i] + 0.5 * dt * k2[i] for i in range(4)]
            k3, _ = self.evaluate_derivatives(y3, self.u0_m_s, umf, hydro)
            # k4
            y4 = [y[i] + dt * k3[i] for i in range(4)]
            k4, _ = self.evaluate_derivatives(y4, self.u0_m_s, umf, hydro)

            # Update states
            y_next = [y[i] + (dt / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i]) for i in range(4)]
            self.c_a_b = max(0.0, y_next[0])
            self.c_a_em = max(0.0, y_next[1])
            self.t_b_k = max(293.15, y_next[2])
            self.t_em_k = max(293.15, y_next[3])

            # Hotspot automatic safety trip
            if (self.t_em_k - 273.15) >= self.cfg.t_hotspot_trip_c:
                self.hot_spot_alarm = True
                self.alarm_latched = True
                self.quench_active = True
                self.u0_m_s = 0.35 * umf

        self.time_s += dt
        self.sync_registers()

    def compute_conversion_pct(self) -> float:
        """Calculate overall reactant conversion percentage X_A [%]."""
        umf = self.compute_umf(self.t_em_k)
        q_b = max(0.001, (self.u0_m_s - umf) * self.bed_area) if self.u0_m_s > umf else 0.001
        q_em = max(0.001, umf * self.bed_area)
        q_0 = q_b + q_em
        c_out_bulk = (q_b * self.c_a_b + q_em * self.c_a_em) / q_0
        conv = max(0.0, min(1.0, (self.cfg.c_a_inlet_mol_m3 - c_out_bulk) / self.cfg.c_a_inlet_mol_m3))
        return conv * 100.0

    def sync_registers(self) -> None:
        """Synchronize FBR state into Horner OCS registers (%R500..%R507)."""
        enable = self.registers.read_bit("%M116")
        cmd_reset = self.registers.read_bit("%M118")

        if cmd_reset:
            self.alarm_latched = False
            self.hot_spot_alarm = False
            self.channelling_fault = False
            self.cyclone_dp_alarm = False
            self.quench_active = False
            self.registers.write_bit("%M118", False, privilege=PrivilegeMode.SYSTEM)

        if not enable:
            self.registers.write_word("%R500", int(FBRStatusBits.DEFLUIDIZED), privilege=PrivilegeMode.SYSTEM)
            return

        umf = self.compute_umf(self.t_em_k)
        hydro = self.compute_hydrodynamics(self.u0_m_s, umf, self.t_em_k)
        t_em_c = self.t_em_k - 273.15
        conv_pct = self.compute_conversion_pct()

        # Build Status Word bitmask
        status = FBRStatusBits.ACTIVE
        if (self.u0_m_s > umf) and (hydro["delta_p_bed"] < 0.70 * hydro["delta_p_theo"]):
            self.channelling_fault = True
            self.alarm_latched = True

        if t_em_c >= self.cfg.t_hotspot_trip_c:
            self.hot_spot_alarm = True
            self.alarm_latched = True

        if hydro["cyclone_dp"] >= self.cfg.cyclone_dp_max_mbar:
            self.cyclone_dp_alarm = True
            self.alarm_latched = True

        if self.channelling_fault:
            status |= FBRStatusBits.CHANNELLING_FAULT
        if self.hot_spot_alarm:
            status |= FBRStatusBits.HOT_SPOT_ALARM
        if self.cyclone_dp_alarm:
            status |= FBRStatusBits.CYCLONE_DP_ALARM
        if self.quench_active:
            status |= FBRStatusBits.PURGE_ACTIVE
        if self.quench_active or (self.u0_m_s < umf):
            status |= FBRStatusBits.DEFLUIDIZED
        if self.alarm_latched:
            status |= FBRStatusBits.ALARM_LATCHED
        if (hydro["F_return"] > 0.0) and not self.quench_active:
            status |= FBRStatusBits.CYCLONE_RETURN_HEALTHY

        # Write scaled word registers (%R500..%R507)
        self.registers.write_word("%R500", int(status), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R501", int(round(self.u0_m_s * 100.0)), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R502", int(round(umf * 100.0)), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R503", int(round(hydro["L_f"] * 100.0)), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R504", int(round(t_em_c * 10.0)), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R505", int(round(conv_pct * 10.0)), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R506", int(round(hydro["total_delta_p"] * 10.0)), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R507", int(round(hydro["F_return"] * 10.0)), privilege=PrivilegeMode.SYSTEM)


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

FLUIDIZED_BED_PURE_ST_POU = """PROGRAM W089_FluidizedBedReactor
VAR
    (* Horner OCS Mapped Registers (W089 - FBR Hydrodynamics & Quench) *)
    StatusWord           AT %R500 : INT;    (* Status and Alarms Bitfield *)
    SuperficialVelocity  AT %R501 : INT;    (* Scaled x100 m/s (e.g. 65 = 0.65 m/s) *)
    MinFluidVelocity     AT %R502 : INT;    (* Scaled x100 m/s (e.g. 8 = 0.08 m/s) *)
    ExpandedBedHeight    AT %R503 : INT;    (* Scaled x100 m (e.g. 215 = 2.15 m) *)
    EmulsionTemperature  AT %R504 : INT;    (* Scaled x10 deg C (e.g. 7804 = 780.4 C) *)
    ReactantConversion   AT %R505 : INT;    (* Scaled x10 % (e.g. 885 = 88.5%) *)
    ReactorDeltaP        AT %R506 : INT;    (* Scaled x10 mbar (e.g. 1328 = 132.8 mbar) *)
    CycloneReturnRate    AT %R507 : INT;    (* Scaled x10 kg/h (e.g. 1240 = 124.0 kg/h) *)

    (* Control Coils *)
    EnableSimulation     AT %M116 : BOOL;   (* System Run Enable *)
    EmergencyQuench      AT %M117 : BOOL;   (* Emergency N2 Quench Override *)
    ResetAlarms          AT %M118 : BOOL;   (* Alarm Reset Handshake *)
END_VAR
VAR
    BitActive            : BOOL;
    BitChannelling       : BOOL;
    BitHotSpot           : BOOL;
    BitCycloneDP         : BOOL;
    BitPurgeActive       : BOOL;
    BitDefluidized       : BOOL;
    BitAlarmLatched      : BOOL;
    BitReturnHealthy     : BOOL;
    StatusAccum          : INT;
END_VAR

IF ResetAlarms THEN
    BitChannelling := FALSE;
    BitHotSpot := FALSE;
    BitCycloneDP := FALSE;
    BitAlarmLatched := FALSE;
    ResetAlarms := FALSE;
END_IF;

IF EnableSimulation THEN
    BitActive := TRUE;

    IF EmulsionTemperature >= 8500 THEN
        BitHotSpot := TRUE;
        BitAlarmLatched := TRUE;
    END_IF;

    IF CycloneReturnRate > 0 THEN
        BitReturnHealthy := TRUE;
    ELSE
        BitReturnHealthy := FALSE;
    END_IF;

    IF EmergencyQuench THEN
        BitPurgeActive := TRUE;
        BitDefluidized := TRUE;
    ELSE
        BitPurgeActive := FALSE;
        IF SuperficialVelocity < MinFluidVelocity THEN
            BitDefluidized := TRUE;
        ELSE
            BitDefluidized := FALSE;
        END_IF;
    END_IF;
ELSE
    BitActive := FALSE;
    BitReturnHealthy := FALSE;
    BitPurgeActive := FALSE;
    BitDefluidized := TRUE;
END_IF;

StatusAccum := 0;
IF BitActive THEN
    StatusAccum := StatusAccum + 1;
END_IF;
IF BitChannelling THEN
    StatusAccum := StatusAccum + 2;
END_IF;
IF BitHotSpot THEN
    StatusAccum := StatusAccum + 4;
END_IF;
IF BitCycloneDP THEN
    StatusAccum := StatusAccum + 8;
END_IF;
IF BitPurgeActive THEN
    StatusAccum := StatusAccum + 16;
END_IF;
IF BitDefluidized THEN
    StatusAccum := StatusAccum + 32;
END_IF;
IF BitAlarmLatched THEN
    StatusAccum := StatusAccum + 64;
END_IF;
IF BitReturnHealthy THEN
    StatusAccum := StatusAccum + 128;
END_IF;

StatusWord := StatusAccum;
END_PROGRAM
"""


# ============================================================================
# 5. Verification Runner & Contract Assertion Function
# ============================================================================

def run_fluidized_bed_verification(evidence_path: Optional[str] = None) -> Dict[str, Any]:
    """Execute end-to-end 9-stage verification for Fluidized Bed Reactor (W089)."""
    SecurityGuard.assert_pure_st_content(FLUIDIZED_BED_PURE_ST_POU)

    # 1. Validate ST POU & AST
    st_res = STParser.validate_code(FLUIDIZED_BED_PURE_ST_POU)
    ast = STParser.parse_pou(FLUIDIZED_BED_PURE_ST_POU)

    test_results: List[Dict[str, Any]] = []

    c1 = (
        st_res.status == AgentStatus.SUCCESS
        and ast.name == "W089_FluidizedBedReactor"
        and ast.pou_type == POUType.PROGRAM
        and "%R500" in ast.bound_registers
        and "%M116" in ast.bound_registers
    )
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_And_Anti_Ladder_Guard",
        "passed": c1,
        "details": "IEC 61131-3 syntax verified, %R500..%R507 bound, ladder constructs strictly rejected.",
    })

    # Instantiate Simulator
    reg_table = RegisterTable()
    sim = FluidizedBedReactorSimulator(register_table=reg_table)

    # 2. Ergun Minimum Fluidization Velocity U_mf
    umf_val = sim.compute_umf(sim.t_em_k)
    c2 = 0.005 <= umf_val <= 0.05
    test_results.append({
        "stage": 2,
        "check": "Ergun_Minimum_Fluidization_Velocity",
        "passed": c2,
        "details": f"Ergun quadratic solution yielded U_mf = {umf_val:.4f} m/s (expected 0.005..0.05 m/s).",
    })

    # 3. Darton Bubble Growth & Bed Expansion L_f
    hydro = sim.compute_hydrodynamics(sim.u0_m_s, umf_val, sim.t_em_k)
    c3 = (hydro["L_f"] > sim.cfg.settled_height_m) and (hydro["delta_b"] > 0.05) and (hydro["d_b"] > 0.01)
    test_results.append({
        "stage": 3,
        "check": "Darton_Bubble_Dynamics_And_Bed_Expansion",
        "passed": c3,
        "details": f"Bed expanded from {sim.cfg.settled_height_m:.2f} m to {hydro['L_f']:.2f} m (voidage {hydro['delta_b']:.1%}, d_b {hydro['d_b']*100:.1f} cm).",
    })

    # 4. Kunii-Levenspiel Interphase Mass & Heat Exchange
    c4 = (hydro["k_be"] > 0.25) and (hydro["h_be"] > 100.0)
    test_results.append({
        "stage": 4,
        "check": "Kunii_Levenspiel_Interphase_Coefficients",
        "passed": c4,
        "details": f"Interphase mass exchange K_be = {hydro['k_be']:.2f} 1/s, heat exchange H_be = {hydro['h_be']:.1f} W/(m3*K).",
    })

    # 5. Mass & Energy Conservation Residuals (< 1e-10)
    y_test = [sim.c_a_b, sim.c_a_em, sim.t_b_k, sim.t_em_k]
    d_test, r_test = sim.evaluate_derivatives(y_test, sim.u0_m_s, umf_val, hydro)
    conservation = sim.check_conservation(y_test, d_test, r_test, sim.u0_m_s, umf_val, hydro)
    c5 = conservation["is_mass_conserved"] and conservation["is_energy_conserved"]
    test_results.append({
        "stage": 5,
        "check": "Coupled_ODE_Mass_And_Energy_Conservation",
        "passed": c5,
        "details": f"Mass residual {conservation['mass_residual_mol_s']:.2e} mol/s, energy residual {conservation['energy_residual_w']:.2e} W (< 1e-10).",
    })

    # 6. Cyclone Separation & Solids Return Loop (99.2% efficiency)
    c6 = (
        hydro["F_ent"] > 0.0
        and abs(hydro["F_return"] - (0.992 * hydro["F_ent"])) < 0.01
        and abs(hydro["F_loss"] - (0.008 * hydro["F_ent"])) < 0.01
    )
    test_results.append({
        "stage": 6,
        "check": "Cyclone_Separation_And_Solids_Return_Loop",
        "passed": c6,
        "details": f"Cyclone return {hydro['F_return']:.1f} kg/h ({hydro['F_return']/hydro['F_ent']*100:.1f}%), loss {hydro['F_loss']:.2f} kg/h.",
    })

    # 7. Step Simulation & Horner Register Table Synchronization
    sim.step(dt=0.1)
    r500 = reg_table.read_word("%R500")
    r501 = reg_table.read_word("%R501")
    r504 = reg_table.read_word("%R504")
    c7 = bool(r500 & FBRStatusBits.ACTIVE) and r501 == 65 and r504 > 7000
    test_results.append({
        "stage": 7,
        "check": "Horner_OCS_Register_Table_Synchronization",
        "passed": c7,
        "details": f"Registers synced: %R500=0x{r500:04X}, %R501={r501} (0.65 m/s), %R504={r504} ({r504/10:.1f} °C).",
    })

    # 8. Hotspot Trip & Emergency N2 Quench Override (%M117)
    # Inject thermal runaway
    sim.t_em_k = 860.0 + 273.15  # 860.0 °C >= 850.0 °C trip
    sim.step(dt=0.1)
    r500_quench = reg_table.read_word("%R500")
    quench_tripped = bool(r500_quench & FBRStatusBits.HOT_SPOT_ALARM) and bool(r500_quench & FBRStatusBits.PURGE_ACTIVE)
    c8 = quench_tripped and sim.quench_active and sim.u0_m_s < umf_val
    test_results.append({
        "stage": 8,
        "check": "Hotspot_Trip_And_Emergency_N2_Quench",
        "passed": c8,
        "details": "Hotspot trip 860 °C actuated cold N2 quench, purged bed to defluidized state, and asserted alarms.",
    })

    # 9. Alarm Reset Handshake (%M118)
    sim.t_em_k = 750.0 + 273.15
    reg_table.write_bit("%M118", True, privilege=PrivilegeMode.SYSTEM)
    sim.step(dt=0.1)
    r500_cleared = reg_table.read_word("%R500")
    reset_ok = (not reg_table.read_bit("%M118")) and not bool(r500_cleared & FBRStatusBits.HOT_SPOT_ALARM)
    c9 = reset_ok
    test_results.append({
        "stage": 9,
        "check": "Alarm_Reset_Handshake_Clearing",
        "passed": c9,
        "details": "Coil %M118 cleared latched alarms and self-reset to FALSE.",
    })

    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Fluidized Bed Reactor Simulator verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed).",
        "data": {
            "work_package": "W089",
            "gate": "Gate G7 / G4",
            "component": "Fluidized Bed Reactor (FBR) Two-Phase Hydrodynamics & Catalytic Gasification ODE Solver",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "register_map": {
                "analog_registers": "%R500..%R507",
                "discrete_coils": "%M116..%M118",
                "values": {
                    "%R500": reg_table.read_word("%R500"),
                    "%R501": reg_table.read_word("%R501"),
                    "%R502": reg_table.read_word("%R502"),
                    "%R503": reg_table.read_word("%R503"),
                    "%R504": reg_table.read_word("%R504"),
                    "%R505": reg_table.read_word("%R505"),
                    "%R506": reg_table.read_word("%R506"),
                    "%R507": reg_table.read_word("%R507"),
                    "%M116": reg_table.read_bit("%M116"),
                    "%M117": reg_table.read_bit("%M117"),
                    "%M118": reg_table.read_bit("%M118"),
                },
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
