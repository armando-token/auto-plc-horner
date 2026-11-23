"""Non-Linear Chemical Reactor pH Neutralization Titration ODE Solver (W071 / Gate G7 / Gate G4).

Implements aqueous electroneutrality charge balance, non-stiff reaction invariant
ODE for continuous stirred tank reactors (CSTR), dynamic mixing and sensor electrode
diffusion delay (tau_mix), non-linear process gain scheduling, and Horner OCS register
synchronization (%R320..%R327, %M74..%M76).
"""

from __future__ import annotations

import dataclasses
from enum import Enum
import json
import math
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Physics & Chemical Equilibrium Constants
# ============================================================================

KW_25C: float = 1.0e-14
LN10: float = math.log(10.0)


def solve_ph_analytical(delta_c: float, kw: float = KW_25C) -> float:
    """Exact algebraic conversion of reaction invariant Delta_C = [Base] - [Acid] to pH.

    Solves electroneutrality quadratic: [H+]^2 + Delta_C * [H+] - Kw = 0.
    Uses conjugate root branching to strictly eliminate catastrophic floating-point cancellation:
    - Basic branch (Delta_C >= 0): [H+] = 2*Kw / (Delta_C + sqrt(Delta_C^2 + 4*Kw))
    - Acidic branch (Delta_C < 0):  [H+] = (-Delta_C + sqrt(Delta_C^2 + 4*Kw)) / 2
    """
    if delta_c >= 0.0:
        h_conc = (2.0 * kw) / (delta_c + math.sqrt(delta_c * delta_c + 4.0 * kw))
    else:
        h_conc = (-delta_c + math.sqrt(delta_c * delta_c + 4.0 * kw)) / 2.0
    h_conc = max(1.0e-15, h_conc)
    return -math.log10(h_conc)


def compute_buffer_capacity(ph: float, kw: float = KW_25C) -> float:
    """Computes differential buffer capacity beta = d(C_base)/dpH in mol/(L * pH)."""
    h_conc = 10.0 ** (-ph)
    oh_conc = kw / h_conc
    return LN10 * (h_conc + oh_conc)


def compute_process_gain(ph: float, kw: float = KW_25C) -> float:
    """Computes instantaneous process gain K_p = dpH/d(Delta_C) in pH / (mol/L)."""
    beta = compute_buffer_capacity(ph, kw)
    return 1.0 / max(1.0e-12, beta)


# ============================================================================
# 2. CSTR Plant Dynamic ODE & Simulation Engine
# ============================================================================

@dataclasses.dataclass
class CSTRNeutralizationConfig:
    tank_area_m2: float = 0.05          # Tank cross-sectional area (m^2)
    max_volume_l: float = 10.0          # Tank maximum physical volume (L)
    nominal_volume_l: float = 2.0       # Nominal liquid volume (L)
    k_weir: float = 2.0                 # Discharge weir constant

    c_acid_in_m: float = 0.005          # Influent acid stream (0.005 M HCl, pH 2.3)
    c_base_dosing_m: float = 0.05       # Dosing reagent base (0.05 M NaOH)

    tau_mix_s: float = 0.5              # Mixing lag + sensor delay constant (s)
    kw: float = KW_25C                  # Water dissociation constant at 25 C


class CSTRNeutralizationPlant:
    """Continuous Stirred Tank Reactor (CSTR) for chemical pH neutralization."""

    def __init__(self, config: Optional[CSTRNeutralizationConfig] = None) -> None:
        self.cfg = config or CSTRNeutralizationConfig()
        self.reset()

    def reset(self) -> None:
        self.volume_l: float = self.cfg.nominal_volume_l
        self.delta_c: float = -self.cfg.c_acid_in_m
        self.delta_c_meas: float = self.delta_c
        self.t_s: float = 0.0

    def calc_outflow_l_min(self, volume_l: float) -> float:
        """Passive overflow weir discharge flow in L/min."""
        head_vol = max(0.0, volume_l - self.cfg.nominal_volume_l)
        return self.cfg.k_weir * math.sqrt(head_vol)

    def step(
        self,
        dt_s: float,
        acid_inflow_l_min: float,
        base_dosing_l_h: float,
    ) -> Dict[str, float]:
        """Advances CSTR neutralization ODE across discrete scan step dt_s (RK4 integration).

        acid_inflow_l_min: Influent process waste acid in L/min
        base_dosing_l_h: Metering reagent pump command in L/h
        """
        # Convert base flow to L/min
        f_base_l_min = base_dosing_l_h / 60.0
        f_acid_l_min = acid_inflow_l_min

        def derivatives(v: float, dc: float, dc_m: float) -> Tuple[float, float, float]:
            v_clamped = max(0.5, v)
            f_out = self.calc_outflow_l_min(v)
            # Volume ODE (L/min) -> convert to L/s
            dv_dt = (f_acid_l_min + f_base_l_min - f_out) / 60.0

            # Concentration invariant ODE: d(V*dc)/dt
            # in mol/s per liter
            inflow_moles_sec = (f_base_l_min * self.cfg.c_base_dosing_m - f_acid_l_min * self.cfg.c_acid_in_m) / 60.0
            convective_moles_sec = (f_acid_l_min + f_base_l_min) * dc / 60.0
            ddc_dt = (inflow_moles_sec - convective_moles_sec) / v_clamped

            # Sensor mixing lag ODE
            ddc_m_dt = (dc - dc_m) / self.cfg.tau_mix_s
            return dv_dt, ddc_dt, ddc_m_dt

        # RK4 Integration
        k1_v, k1_dc, k1_dcm = derivatives(self.volume_l, self.delta_c, self.delta_c_meas)

        v2 = max(0.5, self.volume_l + 0.5 * dt_s * k1_v)
        dc2 = self.delta_c + 0.5 * dt_s * k1_dc
        dcm2 = self.delta_c_meas + 0.5 * dt_s * k1_dcm
        k2_v, k2_dc, k2_dcm = derivatives(v2, dc2, dcm2)

        v3 = max(0.5, self.volume_l + 0.5 * dt_s * k2_v)
        dc3 = self.delta_c + 0.5 * dt_s * k2_dc
        dcm3 = self.delta_c_meas + 0.5 * dt_s * k2_dcm
        k3_v, k3_dc, k3_dcm = derivatives(v3, dc3, dcm3)

        v4 = max(0.5, self.volume_l + dt_s * k3_v)
        dc4 = self.delta_c + dt_s * k3_dc
        dcm4 = self.delta_c_meas + dt_s * k3_dcm
        k4_v, k4_dc, k4_dcm = derivatives(v4, dc4, dcm4)

        self.volume_l = min(self.cfg.max_volume_l, max(0.5, self.volume_l + (dt_s / 6.0) * (k1_v + 2 * k2_v + 2 * k3_v + k4_v)))
        self.delta_c = self.delta_c + (dt_s / 6.0) * (k1_dc + 2 * k2_dc + 2 * k3_dc + k4_dc)
        self.delta_c_meas = self.delta_c_meas + (dt_s / 6.0) * (k1_dcm + 2 * k2_dcm + 2 * k3_dcm + k4_dcm)
        self.t_s += dt_s

        ph_bulk = solve_ph_analytical(self.delta_c, self.cfg.kw)
        ph_meas = solve_ph_analytical(self.delta_c_meas, self.cfg.kw)
        beta = compute_buffer_capacity(ph_meas, self.cfg.kw)
        gain = compute_process_gain(ph_meas, self.cfg.kw)

        return {
            "time_s": self.t_s,
            "volume_l": self.volume_l,
            "delta_c": self.delta_c,
            "ph_bulk": ph_bulk,
            "ph_meas": ph_meas,
            "buffer_beta": beta,
            "process_gain": gain,
        }


# ============================================================================
# 3. Pure ST POU Block & Horner OCS Register Integration
# ============================================================================

W071_PURE_ST_POU = """PROGRAM W071_pHNeutralizationTitration
VAR
    Process_pH AT %R320 : INT;
    pH_Setpoint AT %R321 : INT;
    Base_Dosing_Pump_Cmd AT %R322 : INT;
    Acid_Inflow_Rate AT %R323 : INT;
    Tank_Volume AT %R324 : INT;
    Buffer_Capacity_Beta AT %R325 : INT;
    Process_Gain_Derivative AT %R326 : INT;
    Status_Word AT %R327 : INT;

    Enable_Neutralization AT %M74 : BOOL;
    Auto_Dosing_Mode AT %M75 : BOOL;
    Reset_Alarms AT %M76 : BOOL;

    Acidic_Alarm_Latched : BOOL := FALSE;
    Alkaline_Alarm_Latched : BOOL := FALSE;
    Tank_High_Latched : BOOL := FALSE;
    pH_Error : INT := 0;
    Control_Effort : INT := 0;
END_VAR

(* 1. Alarm Reset Handshake *)
IF Reset_Alarms THEN
    Acidic_Alarm_Latched := FALSE;
    Alkaline_Alarm_Latched := FALSE;
    Tank_High_Latched := FALSE;
    Reset_Alarms := FALSE;
END_IF;

(* 2. Dynamic Threshold Alarms and Latches *)
IF Process_pH < 500 THEN
    Acidic_Alarm_Latched := TRUE;
END_IF;

IF Process_pH > 900 THEN
    Alkaline_Alarm_Latched := TRUE;
END_IF;

IF Tank_Volume >= 4500 THEN
    Tank_High_Latched := TRUE;
END_IF;

(* 3. Closed-Loop Titration Control *)
IF Enable_Neutralization THEN
    IF Auto_Dosing_Mode THEN
        pH_Error := pH_Setpoint - Process_pH;
        IF pH_Error > 0 THEN
            (* Acidic solution requires base addition.
               Gain adaptation: when buffer capacity is low, slope is steep -> lower gain;
               when buffer capacity is high, slope is flat -> higher gain. *)
            Control_Effort := (pH_Error * Buffer_Capacity_Beta) / 100;
            IF Control_Effort > 1000 THEN
                Base_Dosing_Pump_Cmd := 1000;
            ELSIF Control_Effort < 0 THEN
                Base_Dosing_Pump_Cmd := 0;
            ELSE
                Base_Dosing_Pump_Cmd := Control_Effort;
            END_IF;
        ELSE
            Base_Dosing_Pump_Cmd := 0;
        END_IF;
    END_IF;
ELSE
    Base_Dosing_Pump_Cmd := 0;
END_IF;

(* 4. Bit Packing for %R327 Status Word *)
Status_Word := 0;
IF (Process_pH >= 650) AND (Process_pH <= 750) THEN
    Status_Word := Status_Word OR 1;
END_IF;
IF Acidic_Alarm_Latched THEN
    Status_Word := Status_Word OR 2;
END_IF;
IF Alkaline_Alarm_Latched THEN
    Status_Word := Status_Word OR 4;
END_IF;
IF Base_Dosing_Pump_Cmd > 0 THEN
    Status_Word := Status_Word OR 8;
END_IF;
IF Tank_High_Latched THEN
    Status_Word := Status_Word OR 16;
END_IF;
IF Enable_Neutralization THEN
    Status_Word := Status_Word OR 32;
END_IF;
IF Auto_Dosing_Mode THEN
    Status_Word := Status_Word OR 64;
END_IF;
IF Acidic_Alarm_Latched OR Alkaline_Alarm_Latched OR Tank_High_Latched THEN
    Status_Word := Status_Word OR 128;
END_IF;
END_PROGRAM"""


class PHNeutralizationController:
    """Closed-loop supervisor linking CSTR simulation and Horner OCS registers."""

    def __init__(
        self,
        plant: Optional[CSTRNeutralizationPlant] = None,
        registers: Optional[RegisterTable] = None,
    ) -> None:
        self.plant = plant or CSTRNeutralizationPlant()
        self.registers = registers or RegisterTable()

        # Latched alarms
        self.acidic_alarm_latched = False
        self.alkaline_alarm_latched = False
        self.tank_high_latched = False

        # Initialize registers
        self.registers.write_word("%R320", 230, privilege=PrivilegeMode.SYSTEM)   # 2.30 pH
        self.registers.write_word("%R321", 700, privilege=PrivilegeMode.SYSTEM)   # Setpoint 7.00 pH
        self.registers.write_word("%R322", 0, privilege=PrivilegeMode.SYSTEM)     # Base pump 0.0 L/h
        self.registers.write_word("%R323", 10, privilege=PrivilegeMode.SYSTEM)    # Acid inflow 1.0 L/min
        self.registers.write_word("%R324", 20, privilege=PrivilegeMode.SYSTEM)    # 2.0 L
        self.registers.write_word("%R325", 50, privilege=PrivilegeMode.SYSTEM)    # Beta 0.050
        self.registers.write_word("%R326", 2000, privilege=PrivilegeMode.SYSTEM)  # Kp
        self.registers.write_bit("%M74", True, privilege=PrivilegeMode.SYSTEM)    # Enable loop
        self.registers.write_bit("%M75", True, privilege=PrivilegeMode.SYSTEM)    # Auto dosing
        self.registers.write_bit("%M76", False, privilege=PrivilegeMode.SYSTEM)   # Reset

    def scan_step(self, dt_s: float = 0.5) -> Dict[str, Any]:
        """Executes one scan cycle: reads registers, steps plant ODE, updates diagnostics."""
        reset = self.registers.read_bit("%M76")
        if reset:
            self.acidic_alarm_latched = False
            self.alkaline_alarm_latched = False
            self.tank_high_latched = False
            self.registers.write_bit("%M76", False, privilege=PrivilegeMode.SYSTEM)

        enable = self.registers.read_bit("%M74")
        auto_mode = self.registers.read_bit("%M75")
        sp_ph = self.registers.read_word("%R321") / 100.0
        acid_inflow = self.registers.read_word("%R323") / 10.0

        # Current measured pH from previous scan
        curr_ph = self.registers.read_word("%R320") / 100.0

        # Titration dosing algorithm
        base_cmd_lh = 0.0
        if enable and auto_mode:
            ph_err = sp_ph - curr_ph
            if ph_err > 0:
                stoich_base_lh = (acid_inflow * self.plant.cfg.c_acid_in_m / self.plant.cfg.c_base_dosing_m) * 60.0
                base_cmd_lh = max(0.0, min(100.0, stoich_base_lh + ph_err * 6.0))
            else:
                base_cmd_lh = 0.0
        elif enable and not auto_mode:
            base_cmd_lh = self.registers.read_word("%R322") / 10.0

        # Step plant ODE
        sim_res = self.plant.step(dt_s=dt_s, acid_inflow_l_min=acid_inflow, base_dosing_l_h=base_cmd_lh)

        meas_ph = sim_res["ph_meas"]
        vol_l = sim_res["volume_l"]
        beta = sim_res["buffer_beta"]
        gain = sim_res["process_gain"]

        # Latched alarms
        if meas_ph < 5.0:
            self.acidic_alarm_latched = True
        if meas_ph > 9.0:
            self.alkaline_alarm_latched = True
        if vol_l >= 450.0:
            self.tank_high_latched = True

        # Status word bit synthesis
        status_word = 0
        if 6.5 <= meas_ph <= 7.5:
            status_word |= 0x0001
        if self.acidic_alarm_latched:
            status_word |= 0x0002
        if self.alkaline_alarm_latched:
            status_word |= 0x0004
        if base_cmd_lh > 0.0:
            status_word |= 0x0008
        if self.tank_high_latched:
            status_word |= 0x0010
        if enable:
            status_word |= 0x0020
        if auto_mode:
            status_word |= 0x0040
        if self.acidic_alarm_latched or self.alkaline_alarm_latched or self.tank_high_latched:
            status_word |= 0x0080

        # Update registers
        self.registers.write_word("%R320", int(round(meas_ph * 100)), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R322", int(round(base_cmd_lh * 10)), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R324", int(round(vol_l * 10)), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R325", int(round(beta * 1000)), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R326", min(10000, int(round(gain / 100))), privilege=PrivilegeMode.SYSTEM)
        self.registers.write_word("%R327", status_word, privilege=PrivilegeMode.SYSTEM)

        return {
            "time_s": sim_res["time_s"],
            "ph_bulk": sim_res["ph_bulk"],
            "ph_meas": meas_ph,
            "volume_l": vol_l,
            "base_dosing_l_h": base_cmd_lh,
            "status_word": status_word,
        }


# ============================================================================
# 4. Verification & Signoff Evidence Exporter
# ============================================================================

def verify_ph_neutralization_and_export_evidence(
    output_evidence_path: str = "artifacts/simulation/ph_neutralization_evidence.json",
) -> Dict[str, Any]:
    """Performs full verification of the CSTR pH neutralization ODE and Pure ST POU,
    exporting evidence for Gate G7 / Gate G4 signoff.
    """
    os.makedirs(os.path.dirname(output_evidence_path), exist_ok=True)
    tests_record: List[Dict[str, Any]] = []

    # 1. Pure ST POU Validation
    val_st = STParser.validate_code(W071_PURE_ST_POU)
    SecurityGuard.assert_pure_st_content(W071_PURE_ST_POU)
    tests_record.append({
        "check": "Pure_ST_POU_Validation",
        "pou_name": "W071_pHNeutralizationTitration",
        "passed": val_st.status == AgentStatus.SUCCESS,
    })

    # 2. Analytical Solver Equivalence Precision
    ph_equiv = solve_ph_analytical(0.0)
    equiv_passed = abs(ph_equiv - 7.000) < 1.0e-6
    tests_record.append({
        "check": "Equivalence_Point_Precision",
        "expected_ph": 7.000,
        "actual_ph": round(ph_equiv, 4),
        "passed": equiv_passed,
    })

    # 3. Dynamic Titration Convergence (Acidic -> Neutral)
    controller = PHNeutralizationController()
    reached_neutral = False
    # Step simulation across 160 cycles at dt = 0.5s (80 seconds)
    for _ in range(160):
        step_res = controller.scan_step(dt_s=0.5)
        if 6.0 <= step_res["ph_meas"] <= 8.5:
            reached_neutral = True

    tests_record.append({
        "check": "Dynamic_Titration_Neutralization",
        "initial_ph": 2.30,
        "final_ph": round(step_res["ph_meas"], 2),
        "reached_neutral": reached_neutral,
        "status_word": step_res["status_word"],
        "passed": reached_neutral,
    })

    # 4. Process Gain Non-Linearity Ratio
    gain_ph7 = compute_process_gain(7.0)
    gain_ph2 = compute_process_gain(2.0)
    ratio = gain_ph7 / gain_ph2
    ratio_passed = ratio > 10000.0
    tests_record.append({
        "check": "Nonlinear_Process_Gain_Ratio",
        "gain_ph7": round(gain_ph7, 1),
        "gain_ph2": round(gain_ph2, 1),
        "ratio": round(ratio, 1),
        "passed": ratio_passed,
    })

    # 5. Alarm Reset Handshake
    test_ctrl = PHNeutralizationController()
    test_ctrl.acidic_alarm_latched = True
    test_ctrl.plant.delta_c = 0.0
    test_ctrl.plant.delta_c_meas = 0.0
    test_ctrl.registers.write_word("%R320", 700, privilege=PrivilegeMode.SYSTEM)
    test_ctrl.registers.write_bit("%M76", True, privilege=PrivilegeMode.SYSTEM)
    test_ctrl.scan_step(dt_s=0.5)
    alarm_reset_passed = (
        not test_ctrl.acidic_alarm_latched
        and not test_ctrl.alkaline_alarm_latched
        and test_ctrl.registers.read_bit("%M76") is False
    )
    tests_record.append({
        "check": "Alarm_Reset_Handshake",
        "passed": alarm_reset_passed,
    })

    all_passed = all(t["passed"] for t in tests_record)
    status_str = "success" if all_passed else "failed"

    evidence: Dict[str, Any] = {
        "status": status_str,
        "error_code": None if all_passed else "PH_NEUTRALIZATION_VERIFICATION_FAILED",
        "details": f"pH neutralization ODE verification: {sum(1 for t in tests_record if t['passed'])}/{len(tests_record)} checks passed.",
        "data": {
            "simulation": "Non-Linear Chemical Reactor pH Neutralization Titration CSTR ODE",
            "tests": tests_record,
            "register_map": {
                "analog_registers": "%R320..%R327",
                "discrete_coils": "%M74..%M76",
            },
            "timestamp": time.time(),
        },
    }

    with open(output_evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    return evidence
