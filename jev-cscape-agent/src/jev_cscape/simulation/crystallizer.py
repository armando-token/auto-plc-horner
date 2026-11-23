"""Crystallizer Population Balance Equations (PBE) & Method of Moments (MOM) ODE Solver.

Work Package: W083 (Gate G7 Advanced Process Dynamics / Gate G4 Simulation)
Theory:
- Population balance modeling of batch vacuum evaporative crystallization
- Method of moments: mu_0 (count), mu_1 (length), mu_2 (area), mu_3 (volume/mass), mu_4
- Relative supersaturation S = (C - C*(T)) / C*(T)
- Primary & secondary nucleation kinetics B(S) = k_b * S^b + k_sec * M_T^0.8 * S^b2
- Crystal linear growth rate G(S) = k_g * S^g
- Magma density M_T = rho_crystal * k_v * mu_3
- Characteristic crystal size metrics: L_10 (number mean), L_43 (mass mean), CV (polydispersity)
- Fines dissolution loop selective elutriation (L <= L_cut)
- Slurry energy balance with vacuum evaporative cooling (Clapeyron P_sat)
- 4th-Order Runge-Kutta (RK4) scan cycle integration
- Horner OCS register mapping (%R440..%R447, %M102..%M104)
- Pure Structured Text (ST) POU definition & ladder logic rejection guard
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag
import json
import math
import os
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Physical Parameters & Enums
# ============================================================================

class CrystallizerStatusBits(IntFlag):
    """Bit definitions for %R447 Status Word."""
    ACTIVE = 1 << 0                   # Bit 0: Crystallizer simulation active
    METASTABLE_NORMAL = 1 << 1        # Bit 1: Operating inside metastable zone
    HIGH_SUPERSAT_ALARM = 1 << 2      # Bit 2: Relative supersaturation S > 12.0%
    LOW_SIZE_WARNING = 1 << 3         # Bit 3: Mean size L_10 < 150.0 um
    HIGH_CV_WARNING = 1 << 4          # Bit 4: Polydispersity CV > 50.0%
    FINES_DISSOLUTION_ACTIVE = 1 << 5 # Bit 5: Fines dissolution loop active


@dataclass
class CrystallizerParameters:
    """Physicochemical and design parameters for batch vacuum crystallization."""
    rho_crystal: float = 1580.0       # Crystal density [kg/m^3]
    k_v: float = 0.5236               # Volumetric shape factor (pi/6 for spheres) [-]
    rho_solvent: float = 1000.0       # Solvent density (water) [kg/m^3]
    rho_slurry: float = 1250.0        # Slurry mean density [kg/m^3]
    cp_slurry: float = 3600.0         # Slurry specific heat capacity [J/(kg*K)]
    delta_h_vap: float = 2.26e6       # Latent heat of vaporization [J/kg]
    m_w: float = 0.018015             # Molecular weight of solvent [kg/mol]
    r_gas: float = 8.314462618        # Universal gas constant [J/(mol*K)]
    p_0: float = 101325.0             # Atmospheric reference pressure [Pa]
    t_0: float = 373.15               # Reference boiling point at 1 atm [K] (100 °C)

    # Kinetics
    k_g: float = 1.2e-7               # Growth rate constant [m/s]
    g_exp: float = 1.0                # Growth order [-]
    k_b: float = 5.0e5                # Primary nucleation constant [#/ (m^3 * s)]
    b_exp: float = 1.8                # Primary nucleation order [-]
    k_b_sec: float = 1.0e5            # Secondary nucleation constant [#/ (kg * s)]
    b_sec_exp: float = 1.2            # Secondary nucleation order [-]

    # Equipment & Vacuum
    u_a: float = 6000.0               # Overall heat transfer coefficient * Area [W/K]
    t_jacket: float = 345.15          # Heating jacket temperature [K] (72.0 °C)
    p_vac: float = 16000.0            # Condenser vacuum pressure setpoint [Pa] (16 kPa)
    k_evap: float = 2.5e-4            # Evaporation rate coefficient [kg / (s * Pa)]
    q_fines: float = 0.003            # Fines recycle volumetric flow rate [m^3/s]
    l_cut: float = 35.0e-6            # Classifier hydraulic cutoff size [m] (35 um)


# ============================================================================
# 2. Pure ST POU Definition (IEC 61131-3)
# ============================================================================

CRYSTALLIZER_PURE_ST_POU = """PROGRAM W083_CrystallizerPopulationBalance
VAR
    (* Horner OCS Mapped Registers (W083 - Batch Crystallizer Method of Moments) *)
    SoluteConcentration AT %R440 : INT;  (* Scaled x100 g/L (e.g. 32050 = 320.50 g/L) *)
    SlurryTemperature AT %R441 : INT;    (* Scaled x10 degC (e.g. 452 = 45.2 degC) *)
    Supersaturation AT %R442 : INT;      (* Scaled x100 % (e.g. 540 = 5.40%) *)
    MeanCrystalSize AT %R443 : INT;      (* Scaled x10 um (e.g. 2854 = 285.4 um) *)
    MagmaDensity AT %R444 : INT;         (* Scaled x10 g/L (e.g. 1450 = 145.0 g/L) *)
    CoefficientVariation AT %R445 : INT; (* Scaled x10 % (e.g. 385 = 38.5%) *)
    NumberDensityZero AT %R446 : INT;    (* Scaled x10 count index *)
    StatusWord AT %R447 : INT;

    (* Control Coils *)
    EnableSimulation AT %M102 : BOOL;
    EmergencyFinesDissolve AT %M103 : BOOL;
    ResetAlarms AT %M104 : BOOL;

    (* Internal State Flags *)
    BitActive : BOOL;
    BitMetastable : BOOL;
    BitHighSupersat : BOOL;
    BitLowSize : BOOL;
    BitHighCV : BOOL;
    BitFinesActive : BOOL;
    CalculatedStatus : INT;
END_VAR

(* 1. Alarm Reset Handshake *)
IF ResetAlarms THEN
    BitHighSupersat := FALSE;
    BitLowSize := FALSE;
    BitHighCV := FALSE;
    ResetAlarms := FALSE;
END_IF;

(* 2. Main Crystallizer Diagnostic Evaluation *)
IF EnableSimulation THEN
    BitActive := TRUE;

    (* Supersaturation evaluation (> 12.00% alarm threshold) *)
    IF Supersaturation > 1200 THEN
        BitHighSupersat := TRUE;
        BitMetastable := FALSE;
    ELSIF Supersaturation > 100 THEN
        BitHighSupersat := FALSE;
        BitMetastable := TRUE;
    ELSE
        BitHighSupersat := FALSE;
        BitMetastable := FALSE;
    END_IF;

    (* Mean Crystal Size check (< 150.0 um warning) *)
    IF MeanCrystalSize < 1500 THEN
        BitLowSize := TRUE;
    ELSE
        BitLowSize := FALSE;
    END_IF;

    (* Polydispersity CV check (> 50.0% warning) *)
    IF CoefficientVariation > 500 THEN
        BitHighCV := TRUE;
    ELSE
        BitHighCV := FALSE;
    END_IF;

    (* Fines dissolution state *)
    IF EmergencyFinesDissolve THEN
        BitFinesActive := TRUE;
    ELSE
        BitFinesActive := FALSE;
    END_IF;

    (* Build %R447 Status Word *)
    CalculatedStatus := 0;
    IF BitActive THEN
        CalculatedStatus := CalculatedStatus + 1;
    END_IF;
    IF BitMetastable THEN
        CalculatedStatus := CalculatedStatus + 2;
    END_IF;
    IF BitHighSupersat THEN
        CalculatedStatus := CalculatedStatus + 4;
    END_IF;
    IF BitLowSize THEN
        CalculatedStatus := CalculatedStatus + 8;
    END_IF;
    IF BitHighCV THEN
        CalculatedStatus := CalculatedStatus + 16;
    END_IF;
    IF BitFinesActive THEN
        CalculatedStatus := CalculatedStatus + 32;
    END_IF;

    StatusWord := CalculatedStatus;
ELSE
    BitActive := FALSE;
    StatusWord := 0;
END_IF;
END_PROGRAM
"""


# ============================================================================
# 3. Method of Moments ODE Numerical Model
# ============================================================================

class CrystallizerModel:
    """Coupled dynamic PBE Method of Moments & thermal ODE solver."""

    def __init__(
        self,
        params: Optional[CrystallizerParameters] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.params = params or CrystallizerParameters()
        self.registers = register_table or RegisterTable()

        # State vector: [mu0, mu1, mu2, mu3, mu4, C, T_K, V_L]
        # Seed initialization defaults: 100 um uniform seeds, 4.0 m3 initial volume
        seed_size = 100.0e-6
        seed_count = 1.0e10
        self.mu0 = seed_count
        self.mu1 = seed_count * seed_size
        self.mu2 = seed_count * (seed_size ** 2)
        self.mu3 = seed_count * (seed_size ** 3)
        self.mu4 = seed_count * (seed_size ** 4)
        self.c_solute = 285.0       # kg/m3 (solute concentration, 285.0 g/L -> 28500 scaled x100)
        self.temp_k = 323.15         # 50.0 °C
        self.v_liquid = 4.0          # m3

        self.time_s: float = 0.0
        self.fines_dissolve_override: bool = False

        # Enable simulation coil by default
        self.registers.write_bit("%M102", True, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_bit("%M103", False, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_bit("%M104", False, privilege=PrivilegeMode.SYSTEM)
        self.sync_registers()

    def solubility(self, temp_k: float) -> float:
        """Equilibrium solute solubility C*(T) [kg/m^3]."""
        temp_c = temp_k - 273.15
        return 150.0 + 1.5 * temp_c + 0.01 * (temp_c ** 2)

    def clapeyron_p_sat(self, temp_k: float) -> float:
        """Solvent saturation vapor pressure via Clausius-Clapeyron [Pa]."""
        p = self.params
        exponent = - (p.delta_h_vap * p.m_w / p.r_gas) * (1.0 / temp_k - 1.0 / p.t_0)
        return p.p_0 * math.exp(exponent)

    def compute_fines_fractions(self, l_10: float) -> Tuple[float, float, float, float, float]:
        """Analytical incomplete gamma fractions for exponential CSD cutoff x = L_cut / L_10."""
        x = min(12.0, self.params.l_cut / max(1e-9, l_10))
        exp_neg_x = math.exp(-x)
        f0 = 1.0 - exp_neg_x
        f1 = 1.0 - (1.0 + x) * exp_neg_x
        f2 = 1.0 - (1.0 + x + 0.5 * (x ** 2)) * exp_neg_x
        f3 = 1.0 - (1.0 + x + 0.5 * (x ** 2) + (x ** 3) / 6.0) * exp_neg_x
        f4 = 1.0 - (1.0 + x + 0.5 * (x ** 2) + (x ** 3) / 6.0 + (x ** 4) / 24.0) * exp_neg_x
        return f0, f1, f2, f3, f4

    def derivatives(self, state: Sequence[float]) -> List[float]:
        """Calculates state derivatives [dmu0/dt, dmu1/dt, dmu2/dt, dmu3/dt, dmu4/dt, dC/dt, dT/dt, dVL/dt]."""
        p = self.params
        mu0, mu1, mu2, mu3, mu4, c_sol, t_k, v_liq = state

        c_star = self.solubility(t_k)
        s_rel = max(0.0, (c_sol - c_star) / c_star)
        m_t = p.rho_crystal * p.k_v * max(0.0, mu3)

        # Kinetic Rates
        growth_rate = p.k_g * (s_rel ** p.g_exp)
        b_prim = p.k_b * (s_rel ** p.b_exp)
        b_sec = p.k_b_sec * (m_t ** 0.8) * (s_rel ** p.b_sec_exp)
        nucleation_rate = b_prim + b_sec

        # Fines Dissolution Loop
        l_10 = (mu1 / mu0) if mu0 > 1e-12 else 1e-6
        f0, f1, f2, f3, f4 = self.compute_fines_fractions(l_10)

        # Multiplier when emergency fines dissolve coil %M103 is active
        fines_mult = 3.0 if self.fines_dissolve_override else 1.0
        tau_fines_inv = (p.q_fines * fines_mult) / max(0.05, v_liq)
        r_diss0 = tau_fines_inv * mu0 * f0
        r_diss1 = tau_fines_inv * mu1 * f1
        r_diss2 = tau_fines_inv * mu2 * f2
        r_diss3 = tau_fines_inv * mu3 * f3
        r_diss4 = tau_fines_inv * mu4 * f4

        dmu0_dt = nucleation_rate - r_diss0
        dmu1_dt = 1.0 * growth_rate * mu0 - r_diss1
        dmu2_dt = 2.0 * growth_rate * mu1 - r_diss2
        dmu3_dt = 3.0 * growth_rate * mu2 - r_diss3
        dmu4_dt = 4.0 * growth_rate * mu3 - r_diss4

        # Evaporative Solvent Loss
        p_sat = self.clapeyron_p_sat(t_k)
        m_dot_evap = max(0.0, p.k_evap * (p_sat - p.p_vac))
        dv_liquid_dt = - m_dot_evap / p.rho_solvent

        # Solute Mass Balance
        growth_consumption = 3.0 * p.rho_crystal * p.k_v * growth_rate * mu2
        c_evap_concentration = c_sol * (m_dot_evap / (p.rho_solvent * max(0.01, v_liq)))
        c_diss_recycle = p.rho_crystal * p.k_v * r_diss3
        dc_dt = - growth_consumption + c_evap_concentration + c_diss_recycle

        # Slurry Energy Balance
        q_jacket = p.u_a * (p.t_jacket - t_k)
        m_slurry = v_liq * p.rho_slurry
        thermal_capacitance = m_slurry * p.cp_slurry
        dtemp_dt = (q_jacket - m_dot_evap * p.delta_h_vap) / max(1.0, thermal_capacitance)

        return [dmu0_dt, dmu1_dt, dmu2_dt, dmu3_dt, dmu4_dt, dc_dt, dtemp_dt, dv_liquid_dt]

    def step_rk4(self, dt: float) -> None:
        """Advances simulation by dt using classical 4th-Order Runge-Kutta."""
        if not self.registers.read_bit("%M102"):
            return  # Simulation disabled

        self.fines_dissolve_override = self.registers.read_bit("%M103")

        y = [self.mu0, self.mu1, self.mu2, self.mu3, self.mu4, self.c_solute, self.temp_k, self.v_liquid]
        n_dim = len(y)

        k1 = self.derivatives(y)
        y_k1 = [y[i] + 0.5 * dt * k1[i] for i in range(n_dim)]
        k2 = self.derivatives(y_k1)
        y_k2 = [y[i] + 0.5 * dt * k2[i] for i in range(n_dim)]
        k3 = self.derivatives(y_k2)
        y_k3 = [y[i] + dt * k3[i] for i in range(n_dim)]
        k4 = self.derivatives(y_k3)

        y_next = [y[i] + (dt / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i]) for i in range(n_dim)]

        self.mu0 = max(0.0, y_next[0])
        self.mu1 = max(0.0, y_next[1])
        self.mu2 = max(0.0, y_next[2])
        self.mu3 = max(0.0, y_next[3])
        self.mu4 = max(0.0, y_next[4])
        self.c_solute = max(0.0, y_next[5])
        self.temp_k = max(273.15, y_next[6])
        self.v_liquid = max(0.01, y_next[7])

        self.time_s += dt
        self.sync_registers()

    def get_metrics(self) -> Dict[str, float]:
        """Calculates process indicators and size distributions."""
        c_star = self.solubility(self.temp_k)
        s_rel = max(0.0, (self.c_solute - c_star) / c_star)
        magma_density = self.params.rho_crystal * self.params.k_v * max(0.0, self.mu3)

        l_10 = (self.mu1 / self.mu0) if self.mu0 > 1e-12 else 0.0
        l_43 = (self.mu4 / self.mu3) if self.mu3 > 1e-16 else 0.0

        if self.mu0 > 1e-12 and self.mu1 > 1e-12:
            cv_sq = max(0.0, (self.mu2 * self.mu0) / (self.mu1 ** 2) - 1.0)
            cv_percent = math.sqrt(cv_sq) * 100.0
        else:
            cv_percent = 0.0

        temp_c = self.temp_k - 273.15

        return {
            "time_s": self.time_s,
            "T_C": temp_c,
            "C_solute": self.c_solute,
            "C_star": c_star,
            "S_rel_pct": s_rel * 100.0,
            "M_T": magma_density,
            "L_10_um": l_10 * 1e6,
            "L_43_um": l_43 * 1e6,
            "CV_pct": cv_percent,
            "V_L_m3": self.v_liquid,
            "mu0": self.mu0,
        }

    def sync_registers(self) -> None:
        """Pushes state metrics to Horner OCS registers %R440..%R447."""
        metrics = self.get_metrics()
        active = self.registers.read_bit("%M102")

        if self.registers.read_bit("%M104"):
            self.registers.write_bit("%M104", False, privilege=PrivilegeMode.SYSTEM)

        # Registers:
        # %R440: Solute Concentration C scaled x100 (g/L)
        r440 = int(round(metrics["C_solute"] * 100.0)) & 0xFFFF
        # %R441: Slurry Temp °C scaled x10
        r441 = int(round(metrics["T_C"] * 10.0)) & 0xFFFF
        # %R442: Relative Supersaturation S % scaled x100
        r442 = int(round(metrics["S_rel_pct"] * 100.0)) & 0xFFFF
        # %R443: Mean Crystal Size L_10 um scaled x10
        r443 = int(round(metrics["L_10_um"] * 10.0)) & 0xFFFF
        # %R444: Magma Density M_T g/L scaled x10
        r444 = int(round(metrics["M_T"] * 10.0)) & 0xFFFF
        # %R445: CV % scaled x10
        r445 = int(round(metrics["CV_pct"] * 10.0)) & 0xFFFF
        # %R446: mu_0 scaled index
        r446 = int(round(min(65535.0, metrics["mu0"] / 1e8))) & 0xFFFF

        # %R447 Status Word
        status_word = 0
        if active:
            status_word |= CrystallizerStatusBits.ACTIVE
            if 0.5 <= metrics["S_rel_pct"] <= 12.0:
                status_word |= CrystallizerStatusBits.METASTABLE_NORMAL
            if metrics["S_rel_pct"] > 12.0:
                status_word |= CrystallizerStatusBits.HIGH_SUPERSAT_ALARM
            if metrics["L_10_um"] < 150.0:
                status_word |= CrystallizerStatusBits.LOW_SIZE_WARNING
            if metrics["CV_pct"] > 50.0:
                status_word |= CrystallizerStatusBits.HIGH_CV_WARNING
            if self.fines_dissolve_override or self.registers.read_bit("%M103"):
                status_word |= CrystallizerStatusBits.FINES_DISSOLUTION_ACTIVE

        self.registers.write_word("%R440", r440, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R441", r441, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R442", r442, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R443", r443, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R444", r444, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R445", r445, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R446", r446, privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R447", status_word, privilege=PrivilegeMode.SYSTEM)


# ============================================================================
# 4. Verification Harness (G7 / G4 Evidence)
# ============================================================================

def run_crystallizer_verification(output_evidence_path: str = "artifacts/simulation/crystallizer_evidence.json") -> Dict[str, Any]:
    """Executes the full Crystallizer PBE Method of Moments ODE verification suite."""
    tests_record: List[Dict[str, Any]] = []

    # 1. Pure ST POU Validation
    val_st = STParser.validate_code(CRYSTALLIZER_PURE_ST_POU)
    SecurityGuard.assert_pure_st_content(CRYSTALLIZER_PURE_ST_POU)
    st_passed = (val_st.status == AgentStatus.SUCCESS)
    tests_record.append({
        "check": "Pure_ST_POU_Validation",
        "pou_name": "W083_CrystallizerPopulationBalance",
        "passed": st_passed,
    })

    # 2. Ladder Logic Rejection Guard
    forbidden_samples = [
        "PROGRAM Bad (* ---[ ]--- *) END_PROGRAM",
        "PROGRAM Bad (* ---[/]--- *) END_PROGRAM",
        "PROGRAM Bad (* ---( )--- *) END_PROGRAM",
        "PROGRAM Bad RUNG 1: XIC %M102 OTE %M103 END_RUNG END_PROGRAM",
    ]
    ladder_rejected = True
    for sample in forbidden_samples:
        try:
            SecurityGuard.assert_pure_st_content(sample)
            ladder_rejected = False
        except LadderForbiddenError:
            pass
    tests_record.append({
        "check": "Forbidden_Ladder_Construct_Rejection",
        "passed": ladder_rejected,
    })

    # 3. Dynamic Batch Growth Verification
    model = CrystallizerModel()
    m0 = model.get_metrics()
    assert m0["L_10_um"] == 100.0
    assert m0["M_T"] > 8.0

    # Step simulation forward 1800 seconds (30 minutes)
    for _ in range(1800):
        model.step_rk4(dt=1.0)
    m1800 = model.get_metrics()

    growth_passed = (
        m1800["L_10_um"] > m0["L_10_um"]  # Crystal mean size increased
        and m1800["M_T"] > m0["M_T"]        # Magma density increased
        and m1800["V_L_m3"] < m0["V_L_m3"]  # Solvent evaporated
        and 50.0 <= m1800["T_C"] <= 60.0    # Vacuum flash boiling temperature stable
    )
    tests_record.append({
        "check": "Dynamic_Crystal_Growth_and_Evaporative_Cooling",
        "initial_l10_um": m0["L_10_um"],
        "final_l10_um": m1800["L_10_um"],
        "initial_mt": m0["M_T"],
        "final_mt": m1800["M_T"],
        "passed": growth_passed,
    })

    # 4. Register Mapping & Alarm Bitfield Verification
    rt = model.registers
    r440 = rt.read_word("%R440")
    r441 = rt.read_word("%R441")
    r443 = rt.read_word("%R443")
    r447 = rt.read_word("%R447")

    reg_passed = (
        r440 > 25000        # Solute concentration scaled x100 (e.g. 28500 = 285.00 g/L)
        and r441 > 500       # Slurry temp > 50.0 °C scaled x10
        and r443 > 1400      # L10 > 140 um scaled x10
        and (r447 & CrystallizerStatusBits.ACTIVE) != 0
        and (r447 & CrystallizerStatusBits.METASTABLE_NORMAL) != 0
    )
    tests_record.append({
        "check": "Horner_OCS_Register_Mapping_Sync",
        "R440_solute": r440,
        "R441_temp": r441,
        "R443_l10": r443,
        "R447_status": r447,
        "passed": reg_passed,
    })

    # 5. Emergency Fines Dissolution Override
    rt.write_bit("%M103", True, privilege=PrivilegeMode.SYSTEM)
    for _ in range(60):
        model.step_rk4(dt=1.0)
    status_fines = rt.read_word("%R447")
    fines_passed = (status_fines & CrystallizerStatusBits.FINES_DISSOLUTION_ACTIVE) != 0
    tests_record.append({
        "check": "Emergency_Fines_Dissolution_Override",
        "passed": fines_passed,
    })

    all_passed = all(t["passed"] for t in tests_record)
    status_str = "success" if all_passed else "failed"

    evidence: Dict[str, Any] = {
        "status": status_str,
        "error_code": None if all_passed else "CRYSTALLIZER_VERIFICATION_FAILED",
        "details": f"Crystallizer PBE MOM ODE verification: {sum(1 for t in tests_record if t['passed'])}/{len(tests_record)} checks passed.",
        "data": {
            "model": "Batch Vacuum Evaporative Crystallizer (PBE Method of Moments)",
            "tests": tests_record,
            "register_map": {
                "analog_registers": "%R440..%R447",
                "discrete_coils": "%M102..%M104",
            },
            "timestamp": time.time(),
        },
    }

    os.makedirs(os.path.dirname(output_evidence_path), exist_ok=True)
    with open(output_evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence
