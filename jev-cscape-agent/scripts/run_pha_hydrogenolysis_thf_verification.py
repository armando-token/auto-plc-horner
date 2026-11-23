#!/usr/bin/env python3
"""Verification Runner for Industrial Catalytic PHA Hydrogenolysis & Tetrahydrofuran (THF) Dehydration Fixed-Bed ODE Simulation (W323).

Work Package: W323 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Fixed-Bed Catalytic PHA Hydrogenolysis & THF Dehydration 9-Stage Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: environment_and_platform_check
  Stage 2: physical_constants_and_register_mappings
  Stage 3: catalytic_dehydration_kinetics_and_thf_selectivity
  Stage 4: continuous_rk4_solver_and_mass_conservation
  Stage 5: thermal_excursion_and_overpressure_trips
  Stage 6: catalyst_coking_and_selectivity_loss_diagnostics
  Stage 7: register_table_synchronization_and_system_privilege
  Stage 8: pure_st_pou_and_anti_ladder_rejection
  Stage 9: continuous_soak_100_cycles_and_evidence_emission

Generates:
  artifacts/simulation/pha_hydrogenolysis_thf_evidence.json
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

from jev_cscape.simulation.pha_hydrogenolysis_thf import (
    COIL_PHA_THF_EMERGENCY_VENT,
    COIL_PHA_THF_FEED_PUMP,
    COIL_PHA_THF_REACTOR_ACTIVE,
    DIAG_ERR_CATALYST_COKING,
    DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP,
    DIAG_ERR_MASS_BALANCE_DIVERGENCE,
    DIAG_ERR_OVERPRESSURE_VENT,
    DIAG_ERR_THERMAL_EXCURSION,
    DIAG_OK,
    MW_BDO,
    MW_CARBON,
    MW_OLIGOMER,
    MW_THF,
    MW_WATER,
    PHA_HYDROGENOLYSIS_THF_PURE_ST_POU,
    REG_PHA_THF_ACID_CATALYST_ACTIVITY,
    REG_PHA_THF_BDO_CONVERSION,
    REG_PHA_THF_DIAGNOSTIC_CODE,
    REG_PHA_THF_FEED_FLOW_RATE,
    REG_PHA_THF_REACTOR_PRESSURE,
    REG_PHA_THF_REACTOR_TEMP,
    REG_PHA_THF_REBOILER_DUTY_KW,
    REG_PHA_THF_YIELD_PERCENT,
    R_GAS_CONSTANT,
    T_ZERO_CELSIUS,
    DiagnosticCode,
    PHAHydrogenolysisTHFConfig,
    PHAHydrogenolysisTHFEngine,
    PHAHydrogenolysisTHFState,
    PHAHydrogenolysisTHFStatusWord,
    verify_pha_hydrogenolysis_thf_pure_st,
)

# Optional aliases fallback
try:
    from jev_cscape.simulation.pha_hydrogenolysis_thf import (
        COIL_PHA_THF_ACTIVE,
        COIL_PHA_THF_FEED,
        COIL_PHA_THF_VENT,
        REG_PHA_THF_ACTIVITY,
        REG_PHA_THF_CONVERSION,
        REG_PHA_THF_DUTY,
        REG_PHA_THF_DIAG,
        REG_PHA_THF_FLOW,
        REG_PHA_THF_PRESSURE,
        REG_PHA_THF_TEMP,
        REG_PHA_THF_YIELD,
    )
except ImportError:
    COIL_PHA_THF_ACTIVE = COIL_PHA_THF_REACTOR_ACTIVE
    COIL_PHA_THF_FEED = COIL_PHA_THF_FEED_PUMP
    COIL_PHA_THF_VENT = COIL_PHA_THF_EMERGENCY_VENT
    REG_PHA_THF_TEMP = REG_PHA_THF_REACTOR_TEMP
    REG_PHA_THF_PRESSURE = REG_PHA_THF_REACTOR_PRESSURE
    REG_PHA_THF_CONVERSION = REG_PHA_THF_BDO_CONVERSION
    REG_PHA_THF_YIELD = REG_PHA_THF_YIELD_PERCENT
    REG_PHA_THF_FLOW = REG_PHA_THF_FEED_FLOW_RATE
    REG_PHA_THF_ACTIVITY = REG_PHA_THF_ACID_CATALYST_ACTIVITY
    REG_PHA_THF_DUTY = REG_PHA_THF_REBOILER_DUTY_KW
    REG_PHA_THF_DIAG = REG_PHA_THF_DIAGNOSTIC_CODE

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


def execute_pha_hydrogenolysis_thf_verification(
    output_path: Optional[str] = None,
    work_package: str = "W323",
    quick: bool = False,
    project_root: Optional[Any] = None,
) -> Dict[str, Any]:
    """Execute the canonical 9-stage verification sequence for W323 PHA Hydrogenolysis & THF.

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
        from jev_cscape.simulation.pha_hydrogenolysis_thf import (
            PHAHydrogenolysisTHFConfig,
            PHAHydrogenolysisTHFEngine,
            PHAHydrogenolysisTHFState,
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
        math.isclose(MW_BDO, 90.12, rel_tol=1e-3)
        and math.isclose(MW_THF, 72.11, rel_tol=1e-3)
        and math.isclose(MW_WATER, 18.015, rel_tol=1e-3)
        and math.isclose(MW_OLIGOMER, 162.23, rel_tol=1e-3)
        and math.isclose(MW_CARBON, 12.011, rel_tol=1e-3)
        and math.isclose(R_GAS_CONSTANT, 8.314462618, rel_tol=1e-4)
        and math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-4)
    )

    # Stoichiometric mass conservation checks
    # Step 1: 1,4-BDO == THF + H2O
    r1_mw = MW_BDO
    p1_mw = MW_THF + MW_WATER
    stoich1_ok = math.isclose(r1_mw, p1_mw, rel_tol=1e-3)

    # Step 2: 2 BDO == Oligomer Dimer + H2O
    r2_mw = 2.0 * MW_BDO
    p2_mw = MW_OLIGOMER + MW_WATER
    stoich2_ok = math.isclose(r2_mw, p2_mw, rel_tol=1e-3)

    reg_ok = (
        REG_PHA_THF_REACTOR_TEMP == "%R2840"
        and REG_PHA_THF_REACTOR_PRESSURE == "%R2841"
        and REG_PHA_THF_BDO_CONVERSION == "%R2842"
        and REG_PHA_THF_YIELD_PERCENT == "%R2843"
        and REG_PHA_THF_FEED_FLOW_RATE == "%R2844"
        and REG_PHA_THF_ACID_CATALYST_ACTIVITY == "%R2845"
        and REG_PHA_THF_REBOILER_DUTY_KW == "%R2846"
        and REG_PHA_THF_DIAGNOSTIC_CODE == "%R2847"
    )
    coils_ok = (
        COIL_PHA_THF_REACTOR_ACTIVE == "%M662"
        and COIL_PHA_THF_FEED_PUMP == "%M663"
        and COIL_PHA_THF_EMERGENCY_VENT == "%M664"
    )
    diag_codes_ok = (
        DIAG_OK == 0x0000
        and DIAG_ERR_THERMAL_EXCURSION == 0xF9B1
        and DIAG_ERR_OVERPRESSURE_VENT == 0xF9B2
        and DIAG_ERR_CATALYST_COKING == 0xF9B3
        and DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP == 0xF9B4
        and DIAG_ERR_MASS_BALANCE_DIVERGENCE == 0xF9B5
    )

    stage2_pass = bool(
        mw_ok
        and stoich1_ok
        and stoich2_ok
        and reg_ok
        and coils_ok
        and diag_codes_ok
    )
    stages.append({
        "stage": 2,
        "name": "physical_constants_and_register_mappings",
        "check": "physical_constants_and_register_mappings",
        "passed": stage2_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Stoichiometric identity MW_BDO={r1_mw:.2f} == MW_THF+MW_H2O={p1_mw:.2f}; "
            f"2*MW_BDO={r2_mw:.2f} == MW_OLIG+MW_H2O={p2_mw:.2f}; "
            f"Registers %R2840..%R2847, coils %M662..%M664, and 5-tier diagnostic codes verified."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 3: catalytic_dehydration_kinetics_and_thf_selectivity
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    cfg = PHAHydrogenolysisTHFConfig()
    cfg_params_ok = (
        cfg.k1_forward > 0.0
        and cfg.ea1_j_mol > 0.0
        and cfg.k2_forward > 0.0
        and cfg.ea2_j_mol > 0.0
        and cfg.k_deact > 0.0
        and cfg.ea_deact_j_mol > 0.0
        and cfg.k_adsorb_bdo > 0.0
        and cfg.k_adsorb_thf > 0.0
        and cfg.k_adsorb_water > 0.0
        and cfg.k_adsorb_oligomer > 0.0
        and cfg.delta_h_rxn1_j_mol < 0.0
        and cfg.delta_h_rxn2_j_mol < 0.0
    )

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

    arrhenius_ok = (
        r1_nom > 0.0
        and r2_nom > 0.0
        and r1_hot > r1_nom > r1_cold > 0.0
        and r2_hot > r2_nom > r2_cold > 0.0
    )

    selectivity_ok = (
        re_kin.thf_selectivity_pct >= 0.0
        and re_kin.bdo_conversion_pct >= 0.0
        and re_kin.thf_yield_pct >= 0.0
    )

    stage3_pass = bool(cfg_params_ok and arrhenius_ok and selectivity_ok)
    stages.append({
        "stage": 3,
        "name": "catalytic_dehydration_kinetics_and_thf_selectivity",
        "check": "catalytic_dehydration_kinetics_and_thf_selectivity",
        "passed": stage3_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Solid acid Langmuir-Hinshelwood kinetics: r1_hot={r1_hot:.4f} > nom={r1_nom:.4f} > cold={r1_cold:.4f}; "
            f"r2_hot={r2_hot:.4f} > nom={r2_nom:.4f} > cold={r2_cold:.4f} mol/(L*s); "
            f"Selectivity={re_kin.thf_selectivity_pct:.1f}%, Conversion={re_kin.bdo_conversion_pct:.1f}%, Yield={re_kin.thf_yield_pct:.1f}%."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 4: continuous_rk4_solver_and_mass_conservation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_rk4 = PHAHydrogenolysisTHFEngine()
    c_bdo_pre = re_rk4.state.c_bdo_feed
    c_thf_pre = re_rk4.state.c_thf_product
    c_w_pre = re_rk4.state.c_water_byproduct
    c_olig_pre = re_rk4.state.c_oligomer_heavy

    steps = 5 if quick else 15
    for _ in range(steps):
        re_rk4.step_rk4(dt=0.1)

    rk4_progress_ok = (
        re_rk4.state.c_bdo_feed < c_bdo_pre
        and re_rk4.state.c_thf_product > c_thf_pre
        and re_rk4.state.c_water_byproduct > c_w_pre
        and re_rk4.state.c_oligomer_heavy >= c_olig_pre
        and re_rk4.bdo_conversion_pct > 0.0
        and re_rk4.thf_yield_pct > 0.0
    )
    cons_ok = re_rk4.conservation_residual < 1e-10

    # Multi-step-size convergence test (dt=0.01, dt=0.05, dt=0.1)
    conv_stable = True
    for dt_test in (0.01, 0.05, 0.1):
        test_re = PHAHydrogenolysisTHFEngine()
        test_re.step_rk4(dt=dt_test)
        if (
            test_re.state.c_bdo_feed <= 0.0
            or test_re.state.t_reactor_kelvin <= 0.0
            or test_re.state.a_acid_catalyst <= 0.0
            or test_re.conservation_residual >= 1e-10
        ):
            conv_stable = False
            break

    stage4_pass = bool(rk4_progress_ok and cons_ok and conv_stable)
    stages.append({
        "stage": 4,
        "name": "continuous_rk4_solver_and_mass_conservation",
        "check": "continuous_rk4_solver_and_mass_conservation",
        "passed": stage4_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"4th-Order RK4 dynamic integration over {steps} steps verified: "
            f"C_bdo ({c_bdo_pre:.2f} -> {re_rk4.state.c_bdo_feed:.2f} mol/L); "
            f"C_thf ({c_thf_pre:.2f} -> {re_rk4.state.c_thf_product:.2f} mol/L); "
            f"Mass conservation residual {re_rk4.conservation_residual:.2e} < 1e-10."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 5: thermal_excursion_and_overpressure_trips
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. High reaction zone temperature trip (T > 540 K)
    re_t = PHAHydrogenolysisTHFEngine()
    re_t.inject_thermal_excursion(temp_k=545.0)
    re_t.step_rk4(dt=0.05)
    trip_t_ok = (
        re_t.trip_active is True
        and re_t.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION
        and re_t.emergency_vent_active is True
        and re_t.reactor_active is False
        and re_t.feed_pump is False
        and re_t.reg_table.read_bit(COIL_PHA_THF_REACTOR_ACTIVE) is False
        and re_t.reg_table.read_bit(COIL_PHA_THF_FEED_PUMP) is False
        and re_t.reg_table.read_bit(COIL_PHA_THF_EMERGENCY_VENT) is True
        and (re_t.reg_table.read_word(REG_PHA_THF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9B1
    )

    # 2. High temperature rate-of-rise trip (dT/dt > 15 K/s)
    re_r = PHAHydrogenolysisTHFEngine()
    re_r.inject_temperature_rate_excursion(rate_k_s=18.0)
    re_r.step_rk4(dt=0.05)
    trip_r_ok = (
        re_r.trip_active is True
        and re_r.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION
    )

    # 3. Priority 2: Reactor overpressure vent trip (P > 45.0 bar)
    re_p = PHAHydrogenolysisTHFEngine()
    re_p.inject_overpressure(pressure_bar=48.0)
    re_p.step_rk4(dt=0.05)
    trip_p_ok = (
        re_p.trip_active is True
        and re_p.diagnostic_code == DIAG_ERR_OVERPRESSURE_VENT
        and re_p.emergency_vent_active is True
        and re_p.reactor_active is False
        and re_p.feed_pump is False
        and re_p.reg_table.read_bit(COIL_PHA_THF_EMERGENCY_VENT) is True
        and (re_p.reg_table.read_word(REG_PHA_THF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9B2
    )

    # 4. Priority dominance: Thermal Excursion (P1) dominates Overpressure (P2)
    re_dom1 = PHAHydrogenolysisTHFEngine()
    re_dom1.state.t_reactor_kelvin = 545.0
    re_dom1.state.p_reactor = 48.0
    re_dom1.step_rk4(dt=0.05)
    p1_dominates_p2 = re_dom1.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION

    stage5_pass = bool(trip_t_ok and trip_r_ok and trip_p_ok and p1_dominates_p2)
    stages.append({
        "stage": 5,
        "name": "thermal_excursion_and_overpressure_trips",
        "check": "thermal_excursion_and_overpressure_trips",
        "passed": stage5_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            "Safety interlocks verified: 0xF9B1 Thermal Excursion and 0xF9B2 Overpressure Vent "
            "trips latched with emergency vent actuation and feed pump isolation."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 6: catalyst_coking_and_selectivity_loss_diagnostics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Catalyst coking trip (activity < 30.0%)
    re_coke = PHAHydrogenolysisTHFEngine()
    re_coke.inject_catalyst_coking(activity=0.25)
    re_coke.step_rk4(dt=0.05)
    coke_ok = (
        re_coke.trip_active is True
        and re_coke.diagnostic_code == DIAG_ERR_CATALYST_COKING
        and re_coke.emergency_vent_active is True
        and (re_coke.reg_table.read_word(REG_PHA_THF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9B3
        and re_coke.reg_table.read_word(REG_PHA_THF_ACID_CATALYST_ACTIVITY) == 250
    )

    # 2. Dehydration selectivity drop trip (Yield < 50.0% at conversion > 70.0%)
    re_sel = PHAHydrogenolysisTHFEngine()
    re_sel.inject_dehydration_selectivity_drop(yield_pct=40.0, conv_pct=75.0)
    re_sel.step_rk4(dt=0.05)
    sel_ok = (
        re_sel.trip_active is True
        and re_sel.diagnostic_code == DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP
        and re_sel.emergency_vent_active is True
        and (re_sel.reg_table.read_word(REG_PHA_THF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9B4
    )

    # 3. Continuous mass balance divergence trip (residual > 1e-4)
    re_div = PHAHydrogenolysisTHFEngine()
    re_div.inject_mass_divergence(residual=0.005)
    re_div.step_rk4(dt=0.05)
    div_ok = (
        re_div.trip_active is True
        and re_div.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        and (re_div.reg_table.read_word(REG_PHA_THF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF9B5
    )

    # 4. Priority hierarchy dominance: P2 > P3 > P4 > P5
    re_dom23 = PHAHydrogenolysisTHFEngine()
    re_dom23.state.p_reactor = 48.0
    re_dom23.state.a_acid_catalyst = 0.20
    re_dom23.step_rk4(dt=0.05)
    p2_dominates_p3 = re_dom23.diagnostic_code == DIAG_ERR_OVERPRESSURE_VENT

    re_dom34 = PHAHydrogenolysisTHFEngine()
    re_dom34.state.a_acid_catalyst = 0.20
    re_dom34.inject_dehydration_selectivity_drop(yield_pct=40.0, conv_pct=75.0)
    re_dom34.step_rk4(dt=0.05)
    p3_dominates_p4 = re_dom34.diagnostic_code == DIAG_ERR_CATALYST_COKING

    re_dom45 = PHAHydrogenolysisTHFEngine()
    re_dom45.inject_dehydration_selectivity_drop(yield_pct=40.0, conv_pct=75.0)
    re_dom45.conservation_residual = 0.005
    re_dom45.step_rk4(dt=0.05)
    p4_dominates_p5 = re_dom45.diagnostic_code == DIAG_ERR_DEHYDRATION_SELECTIVITY_DROP

    stage6_pass = bool(
        coke_ok
        and sel_ok
        and div_ok
        and p2_dominates_p3
        and p3_dominates_p4
        and p4_dominates_p5
    )
    stages.append({
        "stage": 6,
        "name": "catalyst_coking_and_selectivity_loss_diagnostics",
        "check": "catalyst_coking_and_selectivity_loss_diagnostics",
        "passed": stage6_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            "Diagnostic trips 0xF9B3 (coking), 0xF9B4 (selectivity drop), 0xF9B5 (mass divergence) "
            "and full 5-tier fault hierarchy (0xF9B1 > 0xF9B2 > 0xF9B3 > 0xF9B4 > 0xF9B5) verified."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 7: register_table_synchronization_and_system_privilege
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_rt = PHAHydrogenolysisTHFEngine()
    re_rt.scan_step(dt=0.1)

    # USER privilege synchronization
    rt_user = RegisterTable()
    re_rt.sync_to_registers(rt_user, privilege=PrivilegeMode.USER)

    w_temp = rt_user.read_word(REG_PHA_THF_REACTOR_TEMP)
    w_press = rt_user.read_word(REG_PHA_THF_REACTOR_PRESSURE)
    w_conv = rt_user.read_word(REG_PHA_THF_BDO_CONVERSION)
    w_yield = rt_user.read_word(REG_PHA_THF_YIELD_PERCENT)
    w_flow = rt_user.read_word(REG_PHA_THF_FEED_FLOW_RATE)
    w_act = rt_user.read_word(REG_PHA_THF_ACID_CATALYST_ACTIVITY)
    w_duty = rt_user.read_word(REG_PHA_THF_REBOILER_DUTY_KW)
    w_diag = rt_user.read_word(REG_PHA_THF_DIAGNOSTIC_CODE)

    b_act = rt_user.read_bit(COIL_PHA_THF_REACTOR_ACTIVE)
    b_pump = rt_user.read_bit(COIL_PHA_THF_FEED_PUMP)
    b_vent = rt_user.read_bit(COIL_PHA_THF_EMERGENCY_VENT)

    user_sync_ok = (
        w_temp > 0
        and w_press > 0
        and w_conv >= 0
        and w_yield >= 0
        and w_flow > 0
        and w_act > 0
        and w_duty > 0
        and (w_diag & 0xFFFF) == 0x0000
        and b_act is True
        and b_pump is True
        and b_vent is False
    )

    # SYSTEM privilege synchronization
    rt_sys = RegisterTable()
    re_rt.sync_to_registers(rt_sys, privilege=PrivilegeMode.SYSTEM)
    sys_sync_ok = (
        rt_sys.read_word(REG_PHA_THF_REACTOR_TEMP) == w_temp
        and rt_sys.read_bit(COIL_PHA_THF_REACTOR_ACTIVE) is True
    )

    # DiagnosticCode signed/unsigned 16-bit mask equality
    d_obj = DiagnosticCode(0xF9B1)
    d_s = 0xF9B1 - 0x10000  # -1615
    mask_equality_ok = (
        d_obj == 0xF9B1
        and d_obj == d_s
        and (int(d_obj) & 0xFFFF) == 0xF9B1
        and hash(d_obj) == hash(0xF9B1)
    )

    stage7_pass = bool(user_sync_ok and sys_sync_ok and mask_equality_ok)
    stages.append({
        "stage": 7,
        "name": "register_table_synchronization_and_system_privilege",
        "check": "register_table_synchronization_and_system_privilege",
        "passed": stage7_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Horner OCS memory space %R2840..%R2847 and coils %M662..%M664 synchronized: "
            f"%R2840={w_temp}, %R2841={w_press}, %R2842={w_conv}, %R2843={w_yield}, %R2844={w_flow}, "
            f"%R2845={w_act}, %R2846={w_duty}, %R2847=0x{w_diag:04X}; signed mask (-1615 == 0xF9B1) verified."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_syntax_ok = verify_pha_hydrogenolysis_thf_pure_st()

    st_bindings_ok = (
        "PHAHydrogenolysisTHFControl" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%R2840" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%R2841" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%R2842" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%R2843" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%R2844" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%R2845" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%R2846" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%R2847" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%M662" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%M663" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
        and "%M664" in PHA_HYDROGENOLYSIS_THF_PURE_ST_POU
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
        "XIC %M662",
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
            f"Pure ST POU 'PHAHydrogenolysisTHFControl' verified with correct %R and %M bindings; "
            f"{rejected_count}/{len(ladder_constructs)} ladder constructs rejected with LadderForbiddenError."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 9: continuous_soak_100_cycles_and_evidence_emission
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_soak = PHAHydrogenolysisTHFEngine()
    cycles_to_run = 25 if quick else 100
    soak_ok = True
    for _ in range(cycles_to_run):
        res = re_soak.scan_step(dt=0.1)
        if res.status != AgentStatus.SUCCESS:
            soak_ok = False
            break

    # Emergency vent response test
    re_vent_test = PHAHydrogenolysisTHFEngine()
    re_vent_test.inject_thermal_excursion(temp_k=545.0)
    re_vent_test.step_rk4(dt=0.05)
    vent_latched = (
        re_vent_test.trip_active is True
        and re_vent_test.emergency_vent_active is True
        and re_vent_test.feed_pump is False
        and re_vent_test.diagnostic_code == DIAG_ERR_THERMAL_EXCURSION
    )

    t_peak = re_vent_test.state.t_reactor_kelvin
    for _ in range(25):
        re_vent_test.step_rk4(dt=0.2)

    t_quenched = re_vent_test.state.t_reactor_kelvin
    temp_drop = t_peak - t_quenched
    quench_effective = vent_latched and (temp_drop >= 15.0) and (t_quenched < t_peak)

    unit_ok = (
        re_soak.unit_id == "PHA_THF_REACTOR_W323"
        and re_soak.name == "PHAHydrogenolysisTHFEngine"
        and re_soak.priority == 50
        and re_soak.is_enabled is True
    )

    stage9_pass = bool(soak_ok and quench_effective and unit_ok and (re_soak.cycle_count == cycles_to_run))

    # Cryptographic digests
    pou_digest = hashlib.sha256(PHA_HYDROGENOLYSIS_THF_PURE_ST_POU.encode("utf-8")).hexdigest()
    cfg_ev = PHAHydrogenolysisTHFConfig()
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
            f"Multi-cycle continuous fixed-bed dehydration soak executed for {cycles_to_run} cycles; "
            f"emergency quench dropped reactor fluid temp by {temp_drop:.1f} K ({t_peak:.1f} -> {t_quenched:.1f} K); "
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
            f"Wave {work_package} Industrial Catalytic PHA Hydrogenolysis & THF Verification "
            f"{'PASSED' if all_passed else 'FAILED'} ({checks_passed}/{total_checks} stages)."
        ),
        "stages_passed": checks_passed,
        "total_stages": total_checks,
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


def run_pha_hydrogenolysis_thf_verification(
    project_root: Optional[Any] = None,
    output_path: Optional[str] = None,
    work_package: str = "W323",
    quick: bool = False,
) -> Dict[str, Any]:
    """Compatibility entrypoint matching package API convention."""
    return execute_pha_hydrogenolysis_thf_verification(
        output_path=output_path,
        work_package=work_package,
        quick=quick,
        project_root=project_root,
    )


run_pha_thf_verification = run_pha_hydrogenolysis_thf_verification


def main(argv: Optional[List[str]] = None) -> int:
    """CLI Entrypoint for W323 PHA Hydrogenolysis & THF 9-Stage Verification Suite."""
    parser = argparse.ArgumentParser(
        description="Execute W323 Industrial Catalytic PHA Hydrogenolysis & Tetrahydrofuran (THF) Dehydration Fixed-Bed Verification Suite."
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
        help="Path to output verification JSON evidence artifact (default: artifacts/simulation/pha_hydrogenolysis_thf_evidence.json).",
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
        default="W323",
        help="Work package identifier (default: W323).",
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
            REPO_ROOT / "artifacts" / "simulation" / "pha_hydrogenolysis_thf_evidence.json"
        )
        output_path = str(default_artifact)

    if not args.quiet and not args.json:
        print(f"\n{ESC_BOLD}{ESC_CYAN}================================================================{ESC_RESET}")
        print(f"{ESC_BOLD}{ESC_CYAN}  JEV Cscape - Wave {args.work_package} PHA Hydrogenolysis & THF Verification{ESC_RESET}")
        print(f"{ESC_BOLD}{ESC_CYAN}================================================================{ESC_RESET}")
        print(f"  Target artifact: {output_path}")
        if args.quick:
            print(f"  Execution mode:  {ESC_YELLOW}QUICK (Rapid Subset){ESC_RESET}")
        print()

    t_start = time.perf_counter()
    evidence = execute_pha_hydrogenolysis_thf_verification(
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
