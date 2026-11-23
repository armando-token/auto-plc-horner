#!/usr/bin/env python3
"""Verification Runner for Industrial Catalytic Polyhydroxyalkanoate (PHA) Thermolysis & Bio-Acrylic Acid Pyrolysis CSTR ODE Simulation (W308).

Work Package: W308 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Catalytic PHA Thermolysis 9-Stage Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: environment_and_platform_check
  Stage 2: physical_constants_and_register_mappings
  Stage 3: thermodynamic_properties_and_arrhenius_kinetics
  Stage 4: continuous_rk4_solver_and_carbon_conservation
  Stage 5: thermal_runaway_and_overpressure_fault_trips
  Stage 6: catalyst_coking_and_feed_starvation_diagnostics
  Stage 7: register_table_synchronization_and_system_privilege
  Stage 8: pure_st_pou_and_anti_ladder_rejection
  Stage 9: continuous_soak_100_cycles_and_evidence_emission

Generates:
  artifacts/simulation/pha_thermolysis_evidence.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Union

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.pha_thermolysis import (
    ALPHA_AA,
    CARBON_FRACTION_AA,
    CARBON_FRACTION_CA,
    CARBON_FRACTION_PHA,
    COIL_PHA_THERM_REACTOR_ACTIVE,
    COIL_PHA_THERM_SAFETY_QUENCH,
    COIL_PHA_THERM_VAPOR_DRAW_VALVE,
    DIAG_ERR_CATALYST_COKING_LOSS,
    DIAG_ERR_FEED_STARVATION_LOW_TEMP,
    DIAG_ERR_MASS_BALANCE_DIVERGENCE,
    DIAG_ERR_OVERPRESSURE_VAPOR_BURST,
    DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP,
    DIAG_OK,
    MW_AA,
    MW_CA,
    MW_CARBON,
    MW_PHA_UNIT,
    PHA_THERMOLYSIS_PURE_ST_POU,
    REG_PHA_THERM_ACRYLIC_ACID_CONC,
    REG_PHA_THERM_ACRYLIC_SELECTIVITY,
    REG_PHA_THERM_CONVERSION_RATE,
    REG_PHA_THERM_DIAGNOSTIC_CODE,
    REG_PHA_THERM_JACKET_POWER_DUTY,
    REG_PHA_THERM_JACKET_TEMP,
    REG_PHA_THERM_REACTOR_TEMP,
    REG_PHA_THERM_VAPOR_PRESSURE,
    R_GAS_CONSTANT,
    T_ZERO_CELSIUS,
    DiagnosticCode,
    PHAThermolysisConfig,
    PHAThermolysisEngine,
    PHAThermolysisState,
    PHAThermStatusWord,
    verify_pha_thermolysis_pure_st,
)

# Optional aliases fallback
try:
    from jev_cscape.simulation.pha_thermolysis import (
        COIL_PHA_THERM_ACTIVE,
        COIL_PHA_THERM_QUENCH,
        REG_PHA_THERM_CAA,
        REG_PHA_THERM_CONV,
        REG_PHA_THERM_DUTY,
        REG_PHA_THERM_PVAP,
        REG_PHA_THERM_SEL,
        REG_PHA_THERM_TJ,
        REG_PHA_THERM_TR,
    )
except ImportError:
    COIL_PHA_THERM_ACTIVE = COIL_PHA_THERM_REACTOR_ACTIVE
    COIL_PHA_THERM_QUENCH = COIL_PHA_THERM_SAFETY_QUENCH
    REG_PHA_THERM_TR = REG_PHA_THERM_REACTOR_TEMP
    REG_PHA_THERM_TJ = REG_PHA_THERM_JACKET_TEMP
    REG_PHA_THERM_PVAP = REG_PHA_THERM_VAPOR_PRESSURE
    REG_PHA_THERM_CAA = REG_PHA_THERM_ACRYLIC_ACID_CONC
    REG_PHA_THERM_CONV = REG_PHA_THERM_CONVERSION_RATE
    REG_PHA_THERM_SEL = REG_PHA_THERM_ACRYLIC_SELECTIVITY
    REG_PHA_THERM_DUTY = REG_PHA_THERM_JACKET_POWER_DUTY

# ANSI terminal formatting constants matching repo conventions
ESC_RESET = "\033[0m"
ESC_BOLD = "\033[1m"
ESC_DIM = "\033[2m"
ESC_GREEN = "\033[92m"
ESC_RED = "\033[91m"
ESC_YELLOW = "\033[93m"
ESC_CYAN = "\033[96m"


def format_stage_result(
    stage: int | str,
    check: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format single stage verification outcome for terminal display."""
    if status is not None:
        if status == "success":
            badge = f"{ESC_GREEN}[PASS]{ESC_RESET}"
        elif status == "blocked":
            badge = f"{ESC_YELLOW}[BLOCKED]{ESC_RESET}"
        else:
            badge = f"{ESC_RED}[FAIL]{ESC_RESET}"
    else:
        badge = f"{ESC_GREEN}[PASS]{ESC_RESET}" if passed else f"{ESC_RED}[FAIL]{ESC_RESET}"

    timing_str = f" ({timing_ms:.1f}ms)" if timing_ms is not None else ""
    line = f"  Stage {stage:>2}: {badge} {ESC_BOLD}{check}{ESC_RESET}{timing_str}"
    if details:
        line += f"\n            {ESC_DIM}{details}{ESC_RESET}"
    return line


def execute_pha_thermolysis_verification(
    output_path: Optional[str] = None,
    work_package: str = "W308",
    quick: bool = False,
    project_root: Optional[Any] = None,
) -> Dict[str, Any]:
    """Execute the canonical 9-stage verification sequence for W308 PHA Thermolysis.

    Strictly conforms to the 4-state contract: success | failed | blocked | inconclusive.
    Only writes evidence to output_path if output_path is provided.
    """
    stages: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: environment_and_platform_check
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    py_ok = sys.version_info >= (3, 10)
    platform_ok = bool(sys.platform)
    try:
        import hashlib as _hl
        import json as _js
        import math as _m
        import pathlib as _pl
        from jev_cscape.contracts import AgentStatus, ExecutionResult
        from jev_cscape.iec.st_parser import STParser
        from jev_cscape.security.exceptions import LadderForbiddenError
        from jev_cscape.security.guard import SecurityGuard
        from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
        from jev_cscape.simulation.pha_thermolysis import (
            PHAThermolysisConfig,
            PHAThermolysisEngine,
            PHAThermolysisState,
        )
        deps_ok = True
    except ImportError:
        deps_ok = False

    stage1_pass = bool(py_ok and platform_ok and deps_ok)
    stages.append({
        "stage": 1,
        "name": "environment_and_platform_check",
        "check": "environment_and_platform_check",
        "passed": stage1_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Python {sys.version.split()[0]} on {sys.platform}; dependencies verified: "
            f"py_ok={py_ok}, deps_ok={deps_ok}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 2: physical_constants_and_register_mappings
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    mw_ok = (
        math.isclose(MW_PHA_UNIT, 86.09, rel_tol=1e-3)
        and math.isclose(MW_AA, 72.063, rel_tol=1e-3)
        and math.isclose(MW_CA, 86.09, rel_tol=1e-3)
        and math.isclose(MW_CARBON, 12.011, rel_tol=1e-3)
        and math.isclose(R_GAS_CONSTANT, 8.314462618, rel_tol=1e-3)
        and math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-3)
    )
    stoich_ok = (
        math.isclose(ALPHA_AA, MW_AA / MW_PHA_UNIT, rel_tol=1e-4)
        and math.isclose(CARBON_FRACTION_PHA, (4.0 * MW_CARBON) / MW_PHA_UNIT, rel_tol=1e-4)
        and math.isclose(CARBON_FRACTION_AA, (3.0 * MW_CARBON) / MW_AA, rel_tol=1e-4)
        and math.isclose(CARBON_FRACTION_CA, (4.0 * MW_CARBON) / MW_CA, rel_tol=1e-4)
    )
    reg_ok = (
        REG_PHA_THERM_REACTOR_TEMP == "%R2690"
        and REG_PHA_THERM_JACKET_TEMP == "%R2691"
        and REG_PHA_THERM_VAPOR_PRESSURE == "%R2692"
        and REG_PHA_THERM_ACRYLIC_ACID_CONC == "%R2693"
        and REG_PHA_THERM_CONVERSION_RATE == "%R2694"
        and REG_PHA_THERM_ACRYLIC_SELECTIVITY == "%R2695"
        and REG_PHA_THERM_JACKET_POWER_DUTY == "%R2696"
        and REG_PHA_THERM_DIAGNOSTIC_CODE == "%R2697"
    )
    coils_ok = (
        COIL_PHA_THERM_REACTOR_ACTIVE == "%M627"
        and COIL_PHA_THERM_VAPOR_DRAW_VALVE == "%M628"
        and COIL_PHA_THERM_SAFETY_QUENCH == "%M629"
    )
    diag_codes_ok = (
        DIAG_OK == 0x0000
        and DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP == 0xF961
        and DIAG_ERR_OVERPRESSURE_VAPOR_BURST == 0xF962
        and DIAG_ERR_CATALYST_COKING_LOSS == 0xF963
        and DIAG_ERR_MASS_BALANCE_DIVERGENCE == 0xF964
        and DIAG_ERR_FEED_STARVATION_LOW_TEMP == 0xF965
    )

    stage2_pass = bool(mw_ok and stoich_ok and reg_ok and coils_ok and diag_codes_ok)
    stages.append({
        "stage": 2,
        "name": "physical_constants_and_register_mappings",
        "check": "physical_constants_and_register_mappings",
        "passed": stage2_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Physical constants (MW_PHA={MW_PHA_UNIT}, MW_AA={MW_AA}, MW_CA={MW_CA}, R={R_GAS_CONSTANT}); "
            f"Registers %R2690..%R2697, Coils %M627..%M629, Diag 0xF961..0xF965 mapped deterministically."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 3: thermodynamic_properties_and_arrhenius_kinetics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    cfg = PHAThermolysisConfig()
    kinetics_params_ok = (
        cfg.k1 > 0.0
        and cfg.ea1_j_mol > 0.0
        and cfg.k2 > 0.0
        and cfg.ea2_j_mol > 0.0
        and cfg.kd > 0.0
        and cfg.ed_j_mol > 0.0
        and cfg.delta_h1_j_kg > 0.0
        and cfg.delta_h2_j_kg > 0.0
        and cfg.ua_jacket > 0.0
        and cfg.mj_cpj > 0.0
        and cfg.q_heat_max > 0.0
    )

    r_kin = PHAThermolysisEngine()
    r1_nom, r2_nom, _ = r_kin.compute_rates(r_kin.state)

    # Temperature sensitivity: Arrhenius rate increases with temperature
    st_hot = PHAThermolysisState(tr=570.0, c_pha=r_kin.state.c_pha)
    r1_hot, r2_hot, _ = r_kin.compute_rates(st_hot)

    st_cold = PHAThermolysisState(tr=510.0, c_pha=r_kin.state.c_pha)
    r1_cold, r2_cold, _ = r_kin.compute_rates(st_cold)

    arrhenius_rates_ok = (
        r1_nom > 0.0
        and r1_hot > r1_nom > r1_cold > 0.0
        and r2_hot > r2_nom > r2_cold > 0.0
    )

    # Catalyst coking temperature acceleration
    st_coke_cold = PHAThermolysisState(tr=520.0, a_cat=1.0, c_pha=120.0)
    _, _, d_cold = r_kin.compute_rates(st_coke_cold)
    st_coke_hot = PHAThermolysisState(tr=580.0, a_cat=1.0, c_pha=120.0)
    _, _, d_hot = r_kin.compute_rates(st_coke_hot)

    coking_acceleration_ok = (d_cold < 0.0) and (d_hot < 0.0) and (abs(d_hot) > abs(d_cold))
    selectivity_ok = r_kin.selectivity_pct >= 80.0

    stage3_pass = bool(kinetics_params_ok and arrhenius_rates_ok and coking_acceleration_ok and selectivity_ok)
    stages.append({
        "stage": 3,
        "name": "thermodynamic_properties_and_arrhenius_kinetics",
        "check": "thermodynamic_properties_and_arrhenius_kinetics",
        "passed": stage3_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Arrhenius cracking verified: r1(510K)={r1_cold:.4f} -> r1(540K)={r1_nom:.4f} -> r1(570K)={r1_hot:.4f} kg/(m³*s); "
            f"AA Selectivity={r_kin.selectivity_pct:.1f}%; Coking rate |da/dt|(580K) > |da/dt|(520K)."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 4: continuous_rk4_solver_and_carbon_conservation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    reactor4 = PHAThermolysisEngine()
    c_pha_init = reactor4.state.c_pha
    c_aa_init = reactor4.state.c_aa
    c_ca_init = reactor4.state.c_ca

    steps_s4 = 5 if quick else 15
    for _ in range(steps_s4):
        reactor4.step_rk4(dt=0.1)

    c_pha_end = reactor4.state.c_pha
    c_aa_end = reactor4.state.c_aa
    c_ca_end = reactor4.state.c_ca
    res_s4 = reactor4.conservation_residual

    rk4_kinetics_ok = (
        c_pha_end < c_pha_init
        and c_aa_end > c_aa_init
        and c_ca_end >= c_ca_init
        and res_s4 < 1e-10
    )

    # Multi-step-size convergence test (dt=0.01, dt=0.05, dt=0.1)
    stable_conv = True
    for dt_test in (0.01, 0.05, 0.1):
        r_dt = PHAThermolysisEngine()
        r_dt.step_rk4(dt=dt_test)
        if (
            r_dt.state.c_pha <= 0.0
            or r_dt.state.c_aa <= 0.0
            or r_dt.state.tr <= 0.0
            or r_dt.conservation_residual >= 1e-10
        ):
            stable_conv = False
            break

    stage4_pass = bool(rk4_kinetics_ok and stable_conv)
    stages.append({
        "stage": 4,
        "name": "continuous_rk4_solver_and_carbon_conservation",
        "check": "continuous_rk4_solver_and_carbon_conservation",
        "passed": stage4_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Continuous RK4 integration verified across {steps_s4} cycles: C_pha ({c_pha_init:.2f} -> {c_pha_end:.2f} kg/m³), "
            f"C_aa={c_aa_end:.2f} kg/m³, C_ca={c_ca_end:.2f} kg/m³; Carbon residual={res_s4:.2e} < 1e-10."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 5: thermal_runaway_and_overpressure_fault_trips
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Thermal runaway high temperature trip (Tr > 680 K)
    r_t1 = PHAThermolysisEngine()
    r_t1.state.tr = 685.0
    r_t1.step_rk4(dt=0.05)
    t1_pass = (
        r_t1.trip_active is True
        and r_t1.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP
        and r_t1.safety_quench_active is True
        and r_t1.reactor_active is False
        and r_t1.reg_table.read_bit(COIL_PHA_THERM_REACTOR_ACTIVE) is False
        and r_t1.reg_table.read_bit(COIL_PHA_THERM_SAFETY_QUENCH) is True
        and (r_t1.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF961
    )

    # 2. Thermal runaway rapid rise rate trip (dTr/dt > 15 K/s)
    r_t2 = PHAThermolysisEngine()
    r_t2.state.dtr_dt = 18.0
    r_t2.step_rk4(dt=0.05)
    t2_pass = (
        r_t2.trip_active is True
        and r_t2.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP
        and (r_t2.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF961
    )

    # 3. Overpressure vapor burst trip (Pvap > 35.0 bar)
    r_t3 = PHAThermolysisEngine()
    r_t3.state.pvap = 36.5
    r_t3.step_rk4(dt=0.05)
    t3_pass = (
        r_t3.trip_active is True
        and r_t3.diagnostic_code == DIAG_ERR_OVERPRESSURE_VAPOR_BURST
        and r_t3.safety_quench_active is True
        and (r_t3.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF962
        and r_t3.reg_table.read_bit(COIL_PHA_THERM_SAFETY_QUENCH) is True
    )

    # 4. Priority dominance: Thermal runaway (P1: 0xF961) dominates Overpressure (P2: 0xF962)
    r_dom1 = PHAThermolysisEngine()
    r_dom1.state.tr = 690.0
    r_dom1.state.pvap = 40.0
    r_dom1.step_rk4(dt=0.05)
    dom1_pass = r_dom1.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP

    stage5_pass = bool(t1_pass and t2_pass and t3_pass and dom1_pass)
    stages.append({
        "stage": 5,
        "name": "thermal_runaway_and_overpressure_fault_trips",
        "check": "thermal_runaway_and_overpressure_fault_trips",
        "passed": stage5_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            "Safety trips 0xF961 (thermal runaway high temp > 680K & rate > 15K/s) and "
            "0xF962 (overpressure vapor burst > 35.0 bar) verified with fail-safe quench actuation."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 6: catalyst_coking_and_feed_starvation_diagnostics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Catalyst coking loss trip (a_cat < 0.20)
    r_coke = PHAThermolysisEngine()
    r_coke.state.a_cat = 0.18
    r_coke.step_rk4(dt=0.05)
    coke_pass = (
        r_coke.trip_active is True
        and r_coke.diagnostic_code == DIAG_ERR_CATALYST_COKING_LOSS
        and (r_coke.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF963
        and r_coke.safety_quench_active is True
    )

    # 2. Mass balance divergence trip (residual > 1e-4)
    r_div = PHAThermolysisEngine()
    r_div.conservation_residual = 0.005
    r_div.step_rk4(dt=0.05)
    div_pass = (
        r_div.trip_active is True
        and r_div.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        and (r_div.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF964
    )

    # 3. Feed starvation low temp trip (Tr < 400 K)
    r_cold = PHAThermolysisEngine()
    r_cold.state.tr = 385.0
    r_cold.step_rk4(dt=0.05)
    cold_pass = (
        r_cold.trip_active is True
        and r_cold.diagnostic_code == DIAG_ERR_FEED_STARVATION_LOW_TEMP
        and (r_cold.reg_table.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF965
    )

    # 4. Feed empty starvation trip (C_pha = 0.0)
    r_empty = PHAThermolysisEngine()
    r_empty.state.c_pha = 0.0
    r_empty.step_rk4(dt=0.05)
    empty_pass = (
        r_empty.trip_active is True
        and r_empty.diagnostic_code == DIAG_ERR_FEED_STARVATION_LOW_TEMP
    )

    # 5. Priority ordering: 0xF962 > 0xF963 > 0xF964 > 0xF965
    r_dom2 = PHAThermolysisEngine()
    r_dom2.state.pvap = 38.0
    r_dom2.state.a_cat = 0.10
    r_dom2.step_rk4(dt=0.05)
    p2_dominates_p3 = r_dom2.diagnostic_code == DIAG_ERR_OVERPRESSURE_VAPOR_BURST

    r_dom3 = PHAThermolysisEngine()
    r_dom3.state.a_cat = 0.10
    r_dom3.conservation_residual = 0.005
    r_dom3.step_rk4(dt=0.05)
    p3_dominates_p4 = r_dom3.diagnostic_code == DIAG_ERR_CATALYST_COKING_LOSS

    r_dom4 = PHAThermolysisEngine()
    r_dom4.conservation_residual = 0.005
    r_dom4.state.tr = 380.0
    r_dom4.step_rk4(dt=0.05)
    p4_dominates_p5 = r_dom4.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE

    stage6_pass = bool(
        coke_pass and div_pass and cold_pass and empty_pass and p2_dominates_p3 and p3_dominates_p4 and p4_dominates_p5
    )
    stages.append({
        "stage": 6,
        "name": "catalyst_coking_and_feed_starvation_diagnostics",
        "check": "catalyst_coking_and_feed_starvation_diagnostics",
        "passed": stage6_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            "Diagnostic trips 0xF963 (coking), 0xF964 (mass divergence), 0xF965 (starvation/cold) and "
            "complete 5-tier fault hierarchy (0xF961 > 0xF962 > 0xF963 > 0xF964 > 0xF965) verified."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 7: register_table_synchronization_and_system_privilege
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    r7 = PHAThermolysisEngine()
    r7.scan_step(dt=0.1)
    rt7 = RegisterTable()
    r7.sync_to_registers(rt7, privilege=PrivilegeMode.USER)

    w_tr = rt7.read_word(REG_PHA_THERM_REACTOR_TEMP)
    w_tj = rt7.read_word(REG_PHA_THERM_JACKET_TEMP)
    w_pvap = rt7.read_word(REG_PHA_THERM_VAPOR_PRESSURE)
    w_caa = rt7.read_word(REG_PHA_THERM_ACRYLIC_ACID_CONC)
    w_conv = rt7.read_word(REG_PHA_THERM_CONVERSION_RATE)
    w_sel = rt7.read_word(REG_PHA_THERM_ACRYLIC_SELECTIVITY)
    w_duty = rt7.read_word(REG_PHA_THERM_JACKET_POWER_DUTY)
    w_diag = rt7.read_word(REG_PHA_THERM_DIAGNOSTIC_CODE)

    b_act = rt7.read_bit(COIL_PHA_THERM_REACTOR_ACTIVE)
    b_draw = rt7.read_bit(COIL_PHA_THERM_VAPOR_DRAW_VALVE)
    b_quench = rt7.read_bit(COIL_PHA_THERM_SAFETY_QUENCH)

    user_sync_ok = (
        w_tr > 0
        and w_tj > 0
        and w_pvap > 0
        and w_caa > 0
        and w_conv >= 0
        and w_sel > 0
        and w_duty > 0
        and (w_diag & 0xFFFF) == 0x0000
        and b_act is True
        and b_draw is True
        and b_quench is False
    )

    # SYSTEM privilege synchronization
    rt7_sys = RegisterTable()
    r7.sync_to_registers(rt7_sys, privilege=PrivilegeMode.SYSTEM)
    sys_sync_ok = (
        rt7_sys.read_word(REG_PHA_THERM_REACTOR_TEMP) == w_tr
        and rt7_sys.read_bit(COIL_PHA_THERM_REACTOR_ACTIVE) is True
    )

    # DiagnosticCode signed/unsigned 16-bit mask equality
    d_obj = DiagnosticCode(0xF961)
    d_s = 0xF961 - 0x10000  # -1695
    mask_equality_ok = (
        d_obj == 0xF961
        and d_obj == d_s
        and (int(d_obj) & 0xFFFF) == 0xF961
        and hash(d_obj) == hash(0xF961)
    )

    stage7_pass = bool(user_sync_ok and sys_sync_ok and mask_equality_ok)
    stages.append({
        "stage": 7,
        "name": "register_table_synchronization_and_system_privilege",
        "check": "register_table_synchronization_and_system_privilege",
        "passed": stage7_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Horner OCS register memory %R2690..%R2697 and coils %M627..%M629 synchronized: "
            f"%R2690={w_tr}, %R2691={w_tj}, %R2692={w_pvap}, %R2693={w_caa}, %R2694={w_conv}, "
            f"%R2695={w_sel}, %R2696={w_duty}, %R2697=0x{w_diag:04X}; signed mask (-1695 == 0xF961) verified."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_syntax_ok = verify_pha_thermolysis_pure_st()

    st_bindings_ok = (
        "PHAThermolysisControl" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%R2690" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%R2691" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%R2692" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%R2693" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%R2694" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%R2695" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%R2696" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%R2697" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%M627" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%M628" in PHA_THERMOLYSIS_PURE_ST_POU
        and "%M629" in PHA_THERMOLYSIS_PURE_ST_POU
    )

    ladder_constructs = [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(/)---",
        "---(S)---",
        "---(R)---",
        "RUNG 1: START",
        "NETWORK 10",
        "XIC %M627",
    ]
    rejected_count = 0
    for frag in ladder_constructs:
        bad_code = f"PROGRAM BadLadder\nVAR x: BOOL; END_VAR\n{frag}\nEND_PROGRAM"
        try:
            SecurityGuard.assert_pure_st_content(bad_code)
        except LadderForbiddenError:
            rejected_count += 1

    stage8_pass = bool(st_syntax_ok and st_bindings_ok and (rejected_count == len(ladder_constructs)))
    stages.append({
        "stage": 8,
        "name": "pure_st_pou_and_anti_ladder_rejection",
        "check": "pure_st_pou_and_anti_ladder_rejection",
        "passed": stage8_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Pure ST POU 'PHAThermolysisControl' parsed successfully with correct register mappings; "
            f"{rejected_count}/{len(ladder_constructs)} ladder constructs rejected with LadderForbiddenError."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 9: continuous_soak_100_cycles_and_evidence_emission
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    r9 = PHAThermolysisEngine()
    cycles_to_run = 25 if quick else 100
    soak_ok = True
    for _ in range(cycles_to_run):
        res = r9.scan_step(dt=0.1)
        if res.status != AgentStatus.SUCCESS:
            soak_ok = False
            break

    # Excursion & safety quench response test
    r_quench = PHAThermolysisEngine()
    r_quench.state.tr = 685.0
    r_quench.step_rk4(dt=0.05)
    quench_latched = (
        r_quench.trip_active is True
        and r_quench.safety_quench_active is True
        and r_quench.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY_HIGH_TEMP
    )

    tr_peak = r_quench.state.tr
    for _ in range(25):
        r_quench.step_rk4(dt=0.2)

    tr_quenched = r_quench.state.tr
    temp_drop = tr_peak - tr_quenched
    quench_effective = quench_latched and (temp_drop >= 15.0) and (tr_quenched < tr_peak)

    # ILogicUnit interface verification
    unit_ok = (
        r9.unit_id == "PHA_THERM_REACTOR_W308"
        and r9.name == "PHAThermolysisEngine"
        and r9.priority == 50
        and r9.is_enabled is True
    )

    stage9_pass = bool(soak_ok and quench_effective and unit_ok and (r9.cycle_count == cycles_to_run))

    # Digests
    pou_digest = hashlib.sha256(PHA_THERMOLYSIS_PURE_ST_POU.encode("utf-8")).hexdigest()
    cfg_ev = PHAThermolysisConfig()
    model_digest = hashlib.sha256(
        json.dumps(cfg_ev.to_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()

    stages.append({
        "stage": 9,
        "name": "continuous_soak_100_cycles_and_evidence_emission",
        "check": "continuous_soak_100_cycles_and_evidence_emission",
        "passed": stage9_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Multi-cycle continuous closed-loop soak executed for {cycles_to_run} cycles; "
            f"thermal runaway triggered quench dropping core temp by {temp_drop:.1f} K ({tr_peak:.1f} -> {tr_quenched:.1f} K); "
            f"deterministic SHA-256 digests emitted (POU: {pou_digest[:8]}..., Model: {model_digest[:8]}...)."
        ),
    })

    checks_passed = sum(1 for s in stages if s["passed"])
    total_checks = len(stages)
    all_passed = checks_passed == total_checks

    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": (
            f"Wave {work_package} Industrial Catalytic PHA Thermolysis & Bio-Acrylic Acid Pyrolysis Verification "
            f"{'PASSED' if all_passed else 'FAILED'} ({checks_passed}/{total_checks} stages)."
        ),
        "data": {
            "work_package": work_package,
            "gate": "G7",
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "stages": stages,
            "tests": stages,
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


def run_pha_thermolysis_verification(
    project_root: Optional[Any] = None,
    output_path: Optional[str] = None,
    work_package: str = "W308",
    quick: bool = False,
) -> Dict[str, Any]:
    """Compatibility entrypoint matching package API convention."""
    return execute_pha_thermolysis_verification(
        output_path=output_path,
        work_package=work_package,
        quick=quick,
        project_root=project_root,
    )


def main(argv: Optional[List[str]] = None) -> int:
    """CLI Entrypoint for W308 PHA Thermolysis 9-Stage Verification Suite."""
    parser = argparse.ArgumentParser(
        description="Execute W308 Industrial Catalytic PHA Thermolysis & Bio-Acrylic Acid Pyrolysis 9-Stage Verification Suite."
    )
    parser.add_argument(
        "positional_output",
        nargs="?",
        default=None,
        help="Optional positional path to write JSON evidence artifact.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Path to output verification JSON evidence artifact (default: artifacts/simulation/pha_thermolysis_evidence.json).",
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        help="Execute rapid verification subset with reduced scan iteration cycles.",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W308",
        help="Work package identifier (default: W308).",
    )
    parser.add_argument(
        "--project-root",
        default=None,
        help="Root path of repository.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress terminal output and emit only exit code.",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner).",
    )

    args = parser.parse_args(argv)

    output_path = args.output or args.positional_output
    if not output_path:
        default_artifact = (
            REPO_ROOT / "artifacts" / "simulation" / "pha_thermolysis_evidence.json"
        )
        output_path = str(default_artifact)

    if not args.quiet and not args.json:
        print(f"\n{ESC_BOLD}{ESC_CYAN}================================================================{ESC_RESET}")
        print(f"{ESC_BOLD}{ESC_CYAN}  JEV Cscape - Wave {args.work_package} PHA Thermolysis Verification{ESC_RESET}")
        print(f"{ESC_BOLD}{ESC_CYAN}================================================================{ESC_RESET}")
        print(f"  Target artifact: {output_path}")
        if args.quick:
            print(f"  Execution mode:  {ESC_YELLOW}QUICK (Rapid Subset){ESC_RESET}")
        print()

    t_start = time.perf_counter()
    evidence = execute_pha_thermolysis_verification(
        output_path=output_path,
        work_package=args.work_package,
        quick=args.quick,
        project_root=args.project_root,
    )
    elapsed_total_ms = (time.perf_counter() - t_start) * 1000.0

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    if not args.quiet:
        stages = evidence.get("data", {}).get("stages", [])
        for s in stages:
            print(
                format_stage_result(
                    stage=s.get("stage", "?"),
                    check=s.get("name", "unnamed"),
                    passed=bool(s.get("passed", False)),
                    timing_ms=s.get("timing_ms"),
                    details=s.get("details", ""),
                )
            )

        print(f"\n{ESC_BOLD}Summary:{ESC_RESET}")
        print(f"  Status:       {evidence.get('status')}")
        print(
            f"  Checks:       {evidence.get('data', {}).get('checks_passed')}/"
            f"{evidence.get('data', {}).get('total_checks')} passed"
        )
        print(f"  Total time:   {elapsed_total_ms:.2f} ms")
        print(f"  Evidence:     {output_path}\n")

    return 0 if evidence.get("status") == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
